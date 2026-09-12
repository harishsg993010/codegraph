# Phase 4 — security layer results

Scope was taint/reachability, entrypoint analysis, and SCA reachability, plus
the two Phase 3 carry-forwards (receiver-type resolution, the scale test).
All delivered. 213 tests, clippy-clean.

---

## Receiver-type resolution

The gap flagged at the end of Phase 3: `self.foo()` only bound when the name was
unique among callables, which under-binds badly in object-oriented code.

Two rules, tried before the name-uniqueness ones because they are more precise:

- **Self receiver** (`self`, `this`, `cls`, `$this`, …): the type is the one
  owning the enclosing method. Confidence `EXTRACTED` — inside the class that
  defines the method, this is as certain as a local call.
- **Named type receiver** (`Type.foo()`): bound only when exactly one type in
  the corpus carries that name. `INFERRED`, since nothing proves the name was
  not shadowed.

On the 17k-file corpus: **+59,783 calls bound**. But the more interesting number
is that `calls_local` *fell* from 156,948 to 111,904 — so ~45,000 calls did not
merely get added, they moved from a weak name-uniqueness guess to the precise
rule. Overall binding went 11.0% → 12.0%.

## Security layer

All three questions are the same primitive asked in different directions, over a
relation-masked call graph:

| question | from | to |
|---|---|---|
| is this reachable at all? | entrypoints | the symbol |
| does untrusted input reach a dangerous call? | sources | sinks |
| does our code reach a vulnerable dependency? | our symbols | the package |

`TaintSpec` names sources, sinks and sanitisers via a small matcher vocabulary
(exact / prefix / contains / in-path / `Type.method`) — deliberately not regular
expressions, because a taint spec gets read and audited by people.

Sanitisers are honoured by **refusing to expand through them during the search**,
not by finding a path and then checking it: a sanitised shortest path does not
mean every path is sanitised, and rejecting on that basis would miss real
findings.

Findings carry `reachable_from_entrypoint`, and that flag discriminates — a test
asserts dead code is excluded. Ranking puts live findings first, then shorter
paths, then higher confidence.

External imports now become `Package` symbols with `depends_on` edges, which is
what makes "we have a vulnerable dependency in the lockfile" answerable as "our
code actually calls into it".

### On a real corpus (322,682 symbols / 679,340 edges)

| spec | pairs | rejected by index | findings | time |
|---|---|---|---|---|
| command-injection | 77,928 | 98.9% | 0 | 336 ms |
| sql-injection | 250,416 | 98.7% | 0 | 1,179 ms |
| path-traversal | 78,300 | 98.5% | 2 | 424 ms |

A quarter of a million source/sink pairs answered in about a second, because the
index rejects ~99% of them without searching. Both path-traversal findings are
real call paths — `upload (fsspec/spec.py:1803) -> open (fsspec/spec.py:1294)`,
3 hops, `Direct`, correctly marked not-reachable-from-an-entrypoint (it is
library code with no application entrypoint).

## The bug that mattered most

The first audit reported findings like:

```
request.py (urllib3/util/request.py:1) -> subprocess (PIL/EpsImagePlugin.py:0)
```

A **file** symbol and a **package** symbol, connected by a chain of *imports*.
Structurally real, analytically meaningless — and exactly the kind of result
that makes a security tool untrustworthy, because it looks like a finding.

The cause was reusing `Relation::TAINT` as the taint flow mask. That mask
includes `imports`, `imports_from`, and `depends_on`, which are file-level
relations. Two fixes:

- `FLOW` is now **calls only** (`calls`, `indirect_call`, `re_exports`), with
  `DEPENDENCY_FLOW` kept separately for SCA, where file imports *are* the
  question. Still a subset of what the reachability index covers, so the fast
  rejection keeps applying — asserted by a test, because silently escaping that
  coverage would disable the filter without any visible symptom.
- Sources and sinks are narrowed to symbols that can execute. A file cannot be a
  taint source.

After the fix, command-injection and sql-injection report **0** findings instead
of 25 and 0 — the 25 were all import chains.

## A second bug, found by reading the output

The dependency list showed `Literal`, `BaseModel`, `Any`, and `TYPE_CHECKING`
among the top "packages", and reported **20,971** distinct dependencies.

`from typing import Literal` carries two things: `module_name` is `typing`,
`name` is `Literal`. My field-priority list tried `name` first, so every
`from X import Y` recorded `Y` as the dependency. `import numpy as np` had the
same shape of problem, recording `numpy as np`.

Fixing the field order cut distinct packages **20,971 → 753**, and the list
became what a Python corpus should show: `typing`, `collections`, `os`, `re`,
`warnings`, `logging`. Edges rose from 599,988 to 679,340, because imports that
had been mis-recorded now resolve to real files.

Worth noting how this was caught: not by a test, but by reading a report and
recognising that `BaseModel` is not a package. Four regression tests now cover it.

## Scale test — the target envelope, finally measured

**5,000,000 symbols / 29,999,994 edges**, synthesised with a call-graph-like
shape (mostly short-range forward edges, occasional recursion):

| | |
|---|---|
| build | 5.7 s symbols + 12.0 s edges + 18.0 s write + 35.4 s compact + 27.6 s index |
| store on disk | **2.03 GB — 58 B/item** |
| cold open, store | **123 ms** |
| cold open, index | **1,068 ms** |

| query | p50 | p99 |
|---|---|---|
| lookup by key | 14.4 µs | 4,403 µs |
| neighbours (1 hop) | 25.1 µs | 951 µs |
| k-hop walk (depth 3) | 260 µs | 2,442 µs |
| blast radius (depth 2) | 38.9 µs | 87.4 µs |
| reachability filter | **0.4 µs** | 0.9 µs |
| taint source → sink | 3.4 µs | 22,568 µs |

Three honest results:

**The size projection was optimistic.** The plan projected ~0.9 GB / 26 B/item
at this scale; the measurement is **2.03 GB / 58 B/item**, about 2.2× over. The
projection counted the node and edge columns and a string arena, and omitted the
reverse CSR, the `EdgeExt` table, section alignment, and the derived index. Still
far better than the ~11.6 GB the document-oriented baseline would need, but the
number to quote is 58 B/item, not 26.

**The p99 tails are page faults, and that is the design working.** A key lookup
binary-searches 5M `u128`s — about 23 random touches across an 80 MB array, each
potentially a cold page. That is what "page-cache-bound" costs, and the p50 of
14 µs shows the warm case.

**Index read is not mmap'd, and it shows.** Store open is 123 ms because the
segment is mapped, not read. The index takes **1,068 ms** because
`IndexData::read` copies every column into a `Vec` — roughly 400–500 MB of heap
for degree, SCC ids, GRAIL labels and postings. That is a real violation of the
"residency is page cache, not heap" premise, in the one component added since it
was written. It is the top Phase 5 item.

### A synthetic-shape trap worth recording

The first scale run reported only **20.1%** rejection and 2.5 ms taint queries.
The cause was my generator: `(i + 1 + rand) % n` wraps around, building one giant
strongly-connected core that real call graphs do not have — 201,013 components
for 1M symbols. Removing the wrap gave 991,257 components and taint p50 of 1.3 µs.

Even then the synthetic rejection rate is ~50%, against 98.5–98.9% on real code.
That gap is *not* a defect: in a forward-biased synthetic DAG roughly half of all
random pairs are genuinely reachable, so there is little left to reject. Measuring
precision made it concrete — of the pairs the filter passes, **0% connect within
12 hops**, because synthetic paths are thousands of hops long.

That last number is a genuine limitation, not just an artifact: **the index
answers "is there any path", while a taint query asks "is there a path within N
hops".** The filter cannot answer the bounded question, so a reachable-but-distant
pair costs a full bounded BFS that finds nothing. Real corpora hide this because
their call paths are short; a very large real monorepo might not.

## Carried into Phase 5

1. **mmap the index.** 1,068 ms and ~500 MB of heap at 5M symbols, in the one
   component that does not follow the store's own zero-copy rule.
2. **Distance-bounded reachability.** The filter is unbounded-reachability only;
   bounded queries fall through to a full BFS.
3. **`compact` still rewrites the whole store** — 35 s at 5M symbols, for a
   one-file change. The segment design exists to avoid exactly this.
4. **Entrypoint detection is name-based** and found 832 entrypoints in a library
   corpus, of which only 1.9% of symbols are reachable. Framework-aware detection
   (decorators, route tables, manifests) would make the live/dead split much
   sharper, and that split is what makes findings triageable.
