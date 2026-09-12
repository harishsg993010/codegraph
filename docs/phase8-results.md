# Phase 8 — library summaries, and locals in the store

Phase 7's carry-forward: *the dataflow findings on a Go corpus are
dominated by two sound-but-wrong defaults at unknown calls — every argument
reaches the result, every argument may be written — and the fix is data,
not analysis.* This phase adds that data: a table of **library summaries**
for qualified library functions, for methods by name on any receiver, and
for bare builtins. And, by the user's choice, **locals become stored
symbols**: one row per (callable, name), searchable, with what each is
assigned and where it is read, and the CFG blocks that write and read it.
320 tests, clippy-clean, no segment format change.

---

## What exists now

| crate | change |
|---|---|
| `codegraph-extract` | `summaries.rs`: ~1,150 entries in three tables — qualified (`fmt.Sprintf`, `os.path.join`, `JSON.parse`, `json.Unmarshal`, `assert.Equal`, …), methods by name (`strip`, `append`, `push`, `WriteString`, `Decode`, `get`, `len`, …), bare (`strcpy`, `append`, `len`, `fgets`, `read`, …) — each a *shape*: which inputs reach the result, what is written from what, whether external data enters. `flow.rs` applies the shape at the call: precise writes as weak definitions, the named inputs as the result's sources, and the call marked. Locals: a `RawLocal` per (callable, name), `local_flows` (origin → local, local → sink), and each block's `local_defines` / `local_uses`. |
| `codegraph-resolve` | A summarised external call's stub no longer stands for "every input reaches the result" — facts from its result are dropped, unless the summary brings external data in, in which case the stub's result edges carry no call-site tag (nothing in can pass through). `Local` rows owned by their callable (`contains`, context `local`); `defines`/`uses` from blocks; `local_flow` edges. |
| `codegraph-core` | `SymbolKind::Local`; `Relation::LocalFlow`; mask `LOCALS`. |
| `codegraph-index` / `-query` / `-security` | Locals are in the name tables and never hubs; default walks exclude `local_flow`; a local is never a taint endpoint. |
| `codegraph` CLI | `explain <callable>` lists its locals; `explain <local>` (also as `func.local`) shows its owner, *assigned from*, *read into*, and the blocks that define and use it; `cfg` shows each block's local writes and reads; `index` reports locals, local flows and summarised facts. |

## What the summaries do

The default at an unknown call was, and for an unknown name still is:
the result may carry every input, and (in C, C++, Go, Rust, C#) every
local passed in may have been written, from the call. A summary replaces
that with the function's shape:

| shape | means | examples |
|---|---|---|
| `Args` | every argument reaches the result | `fmt.Sprintf`, `strings.Join`, `os.path.join`, `JSON.parse`, `String.format`, `str()`, `sorted()` |
| `Recv` / `RecvArgs` | the receiver (and arguments) reach the result | `s.strip()`, `x.toString()`, `m.get(k)`, `err.Error()`, `p.then(f)` |
| `Nothing` | nothing does: a boolean, a count, a fresh handle | `len`, `strings.Contains`, `assert.Equal`, `isEmpty`, `int()`, `log.info` |
| `External` | the result is data from outside — nothing in produced it | `os.Getenv`, `os.ReadFile`, `input()`, `fetch`, `File.read` |
| `Mutates` | the receiver is written from the arguments, and returned | `buf.WriteString(x)`, `list.append(x)`, `sb.Append(x)`, `arr.push(x)` |
| `WritesFirst` | argument 0 is written from the rest, and returned | `strcpy`, `strcat`, `memcpy`, `sprintf`, `io.Copy`, `Object.assign` |
| `WritesSecondFromFirst` | argument 1 is written from argument 0 | `json.Unmarshal(data, &v)`, `yaml.Unmarshal` |
| `WritesFirstFromRecv` / `WritesRestFromRecv` | arguments are written from the receiver | `dec.Decode(&v)`, `c.ShouldBind(&form)`, `rows.Scan(&a, &b)` |
| `FillsFirst` / `FillsSecond` / `FillsRest` | a buffer argument is filled with external data | `fgets(buf, n, f)`, `read(fd, buf, n)`, `recv`, `scanf` |

Method shapes are typed by nothing but the name, so each is the union
over the common types that have the method: `get` is `RecvArgs` because
Python's takes a default that may be returned; `add` is `Mutates` because
a builder returns itself and a set returns a boolean, and the union of
those is "the receiver". A shape tighter than the truth would drop a real
flow, and none here is meant to be. A name the table does not know keeps
the default.

Where a summarised name resolves to a corpus function after all, both
apply: the summary's inputs *and* the real callee's return reach the
result. Only an *external* stub loses its "everything reaches the result"
edges.

## The numbers — Gitea, 3,342 files

| | Phase 7 | summaries | + locals |
|---|---|---|---|
| `flows_to` edges | 855k | **634k** (−26 %) | 686k¹ |
| proxies | 54.5k | 37.8k | 86.5k |
| rows | 265k | 248k | 355k (57.8k locals) |
| edges | 1.71 M | 1.47 M | 2.00 M (184k `local_flow`, 100k block `defines`/`uses` on locals) |
| store | 104 + 21 MB | | 94 + 34 MB |
| full index | 13–18 s | | 19–24 s |
| body edit / no-op | 0.4 / 0.16 s | | 0.4 / 0.1 s |

¹ Higher than the summaries-only column because a bug found on the way —
Go `if x := f(); cond {` initialisers were never scanned — is fixed in the
same build: 3,317 more calls bound, and the flows through those `err`s.

Facts dropped because a summarised external call's result is not a value:
**356k** on Gitea. Every `fmt.Errorf`/`Sprintf` result no longer carries
its arguments through the stub, `assert.Equal` writes nothing, `len` and
`strconv.Atoi` produce nothing.

Base + two deltas against a fresh full index, in key space: **identical
edge sets, 1,423,880 edges, 0 dangling** (a first version left 1,292
keyed edges to locals that had no row; see below). Call-graph mode:
the same 26 findings as Phase 6 and 7.

**graphify** (Python, 392 files): 3.1 s, 93.8k symbols + 21.8k proxies,
374k edges (64.5k `flows_to`, 58.7k `local_flow`), 28 MB. Parameters fell
from 13.3k to 9.2k: `def f(path: str)` had been declaring `str` as a
parameter.

## What did not happen

Dataflow findings on Gitea did not fall. With the field-test excludes:
2,593 / 135 / 4,229 (Phase 7) → 2,691 / 173 / 7,877 with summaries →
3,297 / 655 / 12,548 with the initialiser fix. Two reasons, both
measured:

1. **Shorter paths, more pairs.** A path that went `x -> Errorf -> y`
   through a stub is now `x -> y`; with the stub hops gone, more
   (source, sink) pairs fall inside the 12-hop budget.
2. **The noise is the corpus's own, not the library's.** The typical
   finding is `id -> GetUserByID -> LoadResolveDoer -> number -> ToInt64
   -> toNum -> stackNum -> exec`: every hop is a corpus function whose
   return genuinely carries its parameter (`GetUserByID(ctx, id)` returns
   a user built from `id`), joined context-insensitively, ending at a
   sink named `exec` that is a template evaluator. That is the summary
   of *corpus* functions being one edge for every caller, and a spec
   whose sinks are matched by name. Library summaries were never going
   to fix either; they fix what they fix, and the test that says so is
   `library_summaries_stop_the_default_over_approximation` (five shapes
   in Go, each a finding before and not after).

## Locals

A local is a row of its callable — `SymbolKind::Local`, key
`(path, [scope…, callable], name)` — with:

- `contains` from the callable (context `local`);
- `defines` / `uses` from each CFG block that writes or reads it, so
  `cfg` now prints `writes ext, raw` / `reads raw` per block;
- `local_flow` edges: `origin -> local` for everything the local is ever
  assigned (a parameter, a call's result, a module variable, a field —
  the same origins the facts use) and `local -> sink` for every argument,
  return or non-local write it is read into.

`local_flow` is a separate relation, in no reachability mask, on purpose.
A local is one row for every definition of the name, so the view through
it is **flow-insensitive**: `x = a; x = b; sink(x)` shows `a` and `b`
assigned to `x` and `x` read into `sink`, while the `flows_to` facts —
computed through the reaching definitions — say only `b` reaches the
sink. The facts are what `audit` walks; the local view is what `explain`
shows. Locals are never taint endpoints, never hubs, and part of no
file's API: a body edit that adds one is still a one-file update
(`locals_are_stored_but_are_not_api`).

What it costs: 58k rows and 284k edges on Gitea (+34 % rows over the
summaries-only build, +36 % edges), 32k more proxies (a local assigned a
foreign symbol's value is an edge *out of* that symbol, owned by the
observing file — the Phase 7 rule), and a 34 MB index instead of 21 MB
because locals are in the name tables. `search err` on Gitea is now
mostly locals; `explain f.err` picks one by owner.

## Bugs the work turned up

Each of these was invisible until locals were rows: an edge to a local
that was never a row is a dangling keyed edge, and the verification
harness counts those.

- **Go `if x := f(); cond {` and `switch x := f(); x {` initialisers were
  not scanned.** No definition of `err`, no call to `f` — 3,317 calls on
  Gitea bound only now, and every `if err := s.Begin(); err != nil {
  return err }` flow with them.
- **Rust `match` arms bound nothing.** `Some(x) => sink(x)` read `x` as a
  non-local: the scrutinee never reached the sink. Pattern languages
  (Rust, Python, Ruby, C#) now bind lowercase pattern names as locals;
  case *values* (Go `case A:`, Java `case FOO:`) bind nothing — they used
  to produce a phantom weak definition of `A`.
- **Python `def f(path: str)` declared `str` as a parameter.**
- **`&global` passed to a call was a weak definition of a local named
  `global`.** It is a weak definition of the global.
- **`func() {}` declared a closure parameter named `()`.**

## Limits, stated

- A method summary is by name. `x.get(k)` is `RecvArgs` whether `x` is a
  map, a request, or a corpus type with its own `get`; the union is sound
  and no tighter than that.
- The tables cover the standard libraries and the idioms of the corpora
  used here; an unknown name keeps the sound default. Adding a name is one
  line.
- A summarised name that the corpus also defines gets both behaviours.
- Locals are flow-insensitive rows; the facts remain flow-sensitive.
- The Phase 7 limits stand: context-insensitive across calls, no alias
  analysis, predicates decide only literals.

## Carry-forward

- Context sensitivity for corpus functions (call-site tags on
  `flows_to` through corpus callees, as stubs already have) is now the
  dominant source of dataflow noise, and the largest remaining lever.
- Specs whose sinks are matched by name (`exec`, `Execute`, `Open`) need
  qualified sinks — `os/exec.Command`, not `exec` — which the summary
  table's qualifier machinery can now supply.
