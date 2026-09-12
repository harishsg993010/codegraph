# Phase 3 — extraction and resolution results

Exit criterion was: *a clean verification report on the golden corpora at
≥500 files/s*. Throughput met at **562 files/s end to end**. The verification
basis had to change — see below. 184 tests, clippy-clean.

---

## What exists now

| crate | contents |
|---|---|
| `codegraph-index` | **+ persistence**: `.cgidx` files, generation-tagged, checksummed |
| `codegraph-extract` | config-driven walk over 11 Tier-1 languages |
| `codegraph-resolve` | cross-file call and import binding, plus the scan → extract → resolve → compact → index pipeline |

## Throughput — the exit criterion

17,325 files / 238 MB of real Python-dominant source, 12 threads:

| stage | time | rate |
|---|---|---|
| scan | 0.41 s | — |
| extract | 23.5 s | **737 files/s**, 10.1 MB/s |
| resolve | 3.8 s | — |
| compact | 1.0 s | — |
| index | 2.1 s | — |
| **total** | **30.8 s** | **562 files/s** |

Output: 321,929 symbols, 488,606 edges, 35.5 MB of store for 238 MB of source
(**44 B/item, 14.9% of source size**).

For scale: the Python baseline recorded in Phase 0 was 13–21 files/s. This is
**~30× faster end to end**, and it does strictly more work — the baseline number
was extraction alone, this one includes resolution, compaction, and index build.

## Two performance bugs, both mine

The first honest run measured **97 files/s extract and 256 s resolve** — worse
than Phase 0's *parse-only* probe on the same corpus (1,510 files/s). That gap
was the signal; without a prior measurement to compare against, "97 files/s"
would have looked like simply how fast extraction is.

**The walk was O(n·depth).** Scope exit tested containment by walking the node's
entire ancestor chain looking for the open definition — correct, and paid for
*every AST node in the file*. Definitions have byte ranges and the walk visits
nodes in document order, so the test is `node.start_byte() >= open.end_byte`:
one integer compare. **97 → 793 files/s.**

**Import resolution was O(corpus) per import.** The fallback rule — "a unique
file whose path ends with the specifier" — scanned all 17,325 paths for each of
~111,000 imports, with a `format!` allocation inside the loop. That is ~1.9
billion string comparisons and as many allocations, and it was 83% of total
runtime. A stem-keyed basename index makes it a hash lookup. **256 s → 3.8 s.**

Also removed: a `Vec` allocated per call site to count candidates, at 1.5M call
sites.

## A loosening the numbers caught

After the basename index, cross-file calls rose from 9,311 to 13,492. That
looked like a win and was partly a bug: bucketing by stem meant every file in a
bucket already matched the stem, so my confirmation check was always true and
the **directory part of the specifier went unchecked** — `pkg/mod` would bind to
any `mod.py` anywhere in the corpus. Exactly the fabricated-dependency failure
this module's doc comment warns about.

`tail_matches` now requires the full tail on a path boundary, ignoring only the
extension. The count settled at 12,912 — still above the original 9,311, because
the original only stripped `.py` and missed every other language. So the index
was a genuine improvement *and* had a real bug; the count alone could not tell
those apart, which is why the boundary rule now has its own tests.

## Verification: the basis had to change

The plan's exit says "clean verification report on the golden corpora". That is
not runnable as written: the golden corpora are *index outputs* (`graph.json`),
not source trees — the files they describe are not present. Nothing can extract
from them.

So Phase 3 is verified three other ways, and the corpora keep their Phase 1/2
role as store and query fixtures:

1. **Per-language snippets** (12 tests). One snippet per Tier-1 language, each
   with the same shapes, asserted with the *same* assertions. A language whose
   config is subtly wrong fails a shared assertion rather than quietly
   under-extracting.
2. **Config validation against the grammars.** Every configured node kind is
   checked to exist in its grammar, so a typo is dead configuration that fails
   the build rather than silently never firing.
3. **End-to-end** (7 tests): a multi-file project → store → index → answered
   queries, including that two same-named methods stay separately addressable
   from source all the way to a query result.

## Resolution, reported honestly

On the 17k-file corpus, **11.0% of call sites bind to a definition**:

| | count |
|---|---|
| bound, same file | 156,948 |
| bound, cross-file | 12,912 |
| ambiguous — left unbound on purpose | 3,908 |
| unresolved | 1,364,748 |

That ratio is low and mostly correct: the corpus is 17k files of installed
packages, so the overwhelming majority of calls go to the standard library or to
packages outside the indexed set. It is not *entirely* correct — method calls
through a receiver (`self.foo()`, `obj.method()`) are currently only bound when
the name is unique among callables, which under-binds heavily in
object-oriented code. Receiver-type resolution is the largest remaining gap and
is the obvious next piece of resolution work.

The binding rule is deliberately conservative: same file, or one candidate
corpus-wide *and* same language *and* an import that actually connects the two
files. An edge that is missing is a visible gap; an edge that is wrong is
invisible and poisons every downstream query.

## Known limitations, recorded rather than hidden

- **Ruby bare calls.** `helper` with no parentheses and no receiver parses as an
  identifier, indistinguishable from a variable reference without local scope
  tracking. `helper()`, `obj.helper` and `helper arg` are captured. Documented
  where the config lives.
- **No receiver-type resolution**, as above.
- **Rust `use` paths do not resolve to crates.** Cross-crate calls in a Cargo
  workspace go unbound because the resolver has no crate-name → directory map.
- **162 of 17,325 files (0.9%) had a parse error** and were kept anyway — a file
  with a syntax error still yields most of its symbols.

## Carried into Phase 4

1. **Receiver-type resolution** is the single largest correctness gap.
2. **The scale test is still owed.** 321,929 symbols is the largest store built
   so far, an order of magnitude short of the 5M target, and every latency
   number to date comes from corpora that fit in cache.
3. **`compact` still rewrites the whole store**, so an incremental re-index of
   one file costs a full rewrite. The segment design exists to avoid that.
