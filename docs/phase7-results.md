# Phase 7 — variables, control flow, and interprocedural dataflow

Phase 6 left codegraph a call graph: types and callables, `calls`/`imports`/
`inherits`/`contains`. A security finding meant "a call path exists from a
source *function* to a sink *function*" — necessary for a taint bug, nowhere
near sufficient. This phase adds what a value question needs, across all
eleven Tier-1 languages through the same generic walk: module-level variables
and constants, class fields and parameters as symbols; `references` edges; a
control-flow graph per callable, persisted in the store; reaching definitions
over that CFG; and `flows_to` edges that lift a function's summary into the
graph, so "does the request parameter reach `Popen`'s argument" is
reachability again — with predicate-aware pruning inside a function, so a
definition made under `c` does not reach a use under `not c`. 308 tests,
clippy-clean, no segment format change.

---

## What exists now

| crate | change |
|---|---|
| `codegraph-core` | `SymbolKind::{Parameter, Block}`; `Relation::{FlowsTo, Succeeds, Defines, StandsFor}`; masks `DATA_FLOW`, `CFG`. `TAINT` is **unchanged**, so every call-graph answer is what it was. |
| `codegraph-extract` | `syntax.rs`: one static table per language — declarations, assignments, parameters, calls, member access, branches, loops, switches, try/handlers, jumps, closures, comparisons, literals — validated against each grammar's node types. `flow.rs`: per-callable CFG, defs/uses, reaching definitions with predicate atoms, and the facts a function exports. |
| `codegraph-resolve` | Call binding is separated from edge emission so every fact can name its call. Parameters bound by position or keyword; stubs for external callees, owned by their package row; **proxy rows** (below); `References`, `FlowsTo`, block rows and CFG edges. |
| `codegraph-store` | `PROXY` node flag and `stands_for` storage edge; the view forwards proxies and reads their edges as their symbol's. In-edges now carry their context. |
| `codegraph-index` | Parameters and blocks are structural: never in the name tables, never hubs, and edges touching a block do not count towards degrees. The overlay accounts for proxies. Reachability labels stay over the call graph (below). |
| `codegraph-security` | `Mode::DataFlow`: sources are what a matched symbol *produces* (its return, its parameters), sinks what it *consumes* (its parameters, or the external stub itself); one backward search per sink over `flows_to`, call-site-matched through stubs. |
| `codegraph` CLI / MCP | `audit --mode dataflow`, `cfg <symbol>`, `explain` lists parameters, references and flows; `index` reports the new row and edge classes. |

## The numbers — Gitea, 3,342 files

Release build, warm cache. The Phase 6 baseline for the same tree: 3.4 s,
24.5k symbols, 425k edges, 12.8 MB.

| | now | Phase 6 |
|---|---|---|
| full index, end to end | 13–18 s | 3.4 s |
| — extract / resolve / compact / index | 3–5 s / 6–7 s / 2.5–4 s / 0.3–0.6 s | |
| rows | 265k (210.6k symbols + 54.5k proxies) | 24.5k |
| edges | 1.71 M | 425 k |
| store | 104 MB segment + 21 MB index | 12.8 MB |
| no-op update | 0.16 s | 0.1 s |
| one-line body edit | 0.4–0.6 s, 1 file, 18 KB delta, 9.5 KB overlay | 0.2 s |

(Timings are ranges over several runs on a laptop; the spread is the
machine's, not the code's.) What the rows are: 15.4k variables and
constants, 29.7k parameters, 130k CFG blocks, 11.1k external callee stubs,
54.5k proxies. What the edges are: 855k `flows_to`, 147k `succeeds`, 22.6k
`references`, 30k `uses`, 1.6k `defines`; the 425k the call graph had are
unchanged (50,325 calls bound, exactly as before).

The plan budgeted 2× on throughput; this is 4–5×. Extraction — parse, CFG,
reaching definitions with atoms, facts, in parallel — is 3–5 s of it, of
which the predicate layer is about a third (a `Clashes` table per body and
inline four-atom sets keep it there; the first version, with heap-allocated
atom strings per fact, doubled extraction). The rest is resolution and
compaction, proportional to rows and edges: eleven times the rows, four
times the edges. Blocks are half the rows and `flows_to` is half the edges.
Both are what the user asked for — the CFG persisted in the store, and
value flow as edges — and neither is free to carry.

What the predicates buy on Gitea: 4,230 `flows_to` edges fewer (0.5 %).
The corpus's conditions are `err != nil` — decidable, and pruned where they
contradict — but the flows they could cut are inside functions, and the
noise is between them.

**graphify** (Python, 392 files): 2.0 s, 73.9k symbols + 9.2k proxies,
225k edges, 19 MB.

## Audits

Call-graph mode on Gitea is unchanged: without excludes the three starter
specs report **26 findings, the same set Phase 6 reported** (0 + 10 + 16),
and call binding is 50,325 edges, 31.5 %, as before. With the field-test
excludes:

| spec | pairs | rejected by index | findings | time |
|---|---|---|---|---|
| command-injection | 580 × 10 | 98.1 % | 0 | 100–140 ms |
| sql-injection | 648 × 2 | 90.8 % | 10 | 50–90 ms |
| path-traversal | 737 × 22 | 95.3 % | 1 | 550–935 ms |

(The sql-injection ones are `ServerError -> notFoundInternal -> HTML ->
Execute`, the `Execute` name collision the field test documents; the
sources now include parameters and variables whose names match, which is
why the source counts are higher.) Path-traversal is slower than it was
because each searched node now carries its flow edges too, and the mask
filter reads past them.

Dataflow mode, same excludes, uncapped:

```
command-injection: 1370 sources x 54 sinks, 54 sinks searched, 2593 findings (988 ms)
  ParseAuthorizationRequest (services/packages/auth.go:56) -> exec (modules/templates/eval/eval.go:210)  [11 hops]
      via ParseAuthorizationRequest -> id -> GetUserByID -> LoadResolveDoer -> number -> Errorf -> ToInt64 -> toNum -> v -> Errorf -> toOp -> exec
sql-injection:     1499 sources x 13 sinks, 13 sinks searched, 135 findings (278 ms)
  parseRequestIDFromRequestHeader(req) (services/context/access_log.go:51) -> Execute (external)  [3 hops]
      via req -> Get -> parseRequestIDFromRequestHeader -> Execute
path-traversal:    1727 sources x 82 sinks, 82 sinks searched, 4229 findings (1226 ms)
  UploadFileToServer(ctx) (routers/web/repo/editor_uploader.go:18) -> Open(name) (modules/assetfs/layered.go:74)  [8 hops]
      via ctx -> FormFile -> name -> elem -> Clean -> Join -> PathJoinRel -> name -> name
```

Fast, sound, and on this corpus **noisy**: thousands of (source, sink) pairs
against the call graph's 11, and none of them a vulnerability. Every path
is a real chain of `flows_to` edges; what makes them worthless is the
over-approximation at each unknown call. `fmt.Errorf("…%v", number)` is
modelled as *every argument reaches the result*, so `number` taints the
error, the error is returned, and eleven hops later it is the argument of
`exec`. `assert.Equal(t, resp, id)` is modelled as *a local passed to an
unknown callee may be written by it*, so `resp` reaches `id`. Both rules
are what keeps `strcpy(buf, x); system(buf)` sound in C, and both are wrong
almost every time in Go. The mode does what it is for — it drops the
callers that reach a sink with a constant
(`dataflow_mode_follows_the_value_and_ignores_the_constant_caller`, in
Python, Go and JavaScript), and a real chain shows up as one — but as a
finding list on a Go corpus it needs library summaries (which arguments of
`Errorf` and `Sprintf` reach the result — the formatted ones, into a string
or an error that is rarely a sink — and which of `Equal` — none — and which
a callee writes through — none of these) before it is readable. That is
the carry-forward; the predicates (below) are already in these numbers,
and none of these paths turns on a branch.

On graphify the path-traversal spec reports `handle_upload(paths) -> open`,
four hops: `paths` into `batch_parse`, the comprehension's `path` into
`parse_file`, `open(path)`. That one is exactly right.

## The proof

1. **Every language, one snippet, the same assertions.** For each of python,
   javascript, typescript, tsx, java, c, cpp, go, rust, csharp and ruby: the
   module constant and class field are symbols of the right kind; `m(x, y)`
   has two parameters in order; `m` references the constant and the field;
   the facts `Param(y) -> Arg(helper, 0)`, `CONST -> Arg(helper, 0)` and
   `Param(y) -> Return` exist; a killed definition yields no `Param(x)`.
   Separately: `strcpy(buf, x); system(buf)` in C yields `x -> system`;
   `.forEach(x => sink(x))` and `each { |v| sink(v) }` yield the flow; Go
   named results and bare `return`; Rust `if` tails; Ruby implicit return;
   a loop reaches its fixpoint; exception edges; keyword arguments
   (`crates/codegraph-extract/tests/dataflow.rs`, 15 tests). **Predicates**,
   the same six functions in every language: a contradiction prunes
   (`if c: x = b` … `if not c: sink(x)` carries `a`, not `b`); a disjunction
   and a negated conjunction establish nothing; a join keeps what both arms
   establish; a loop carries a sentinel's atoms round its back edge to a
   fixpoint; integer ranges prune only when empty (`n > 10` … `n < 5`, not
   `n < 20`). Plus: a call invalidates atoms about non-scalars where a
   callee could change them, an address-taken or closure-written local
   gets no atoms, switch arms establish equality, undecidable conditions
   prune nothing, a literal `false` is never taken
   (`crates/codegraph-extract/tests/predicates.rs`, 10 tests).
2. **End to end.** `read_request(req)` → two hops → `Popen` /
   `exec.Command` / `child_process.exec`, in dataflow mode; a sanitiser on
   the path suppresses it; a by-reference write through a library call
   (`strcpy`) is followed; a delta store analyses like its compacted form
   (`crates/codegraph-security/tests/taint.rs`, 20 tests).
3. **Incremental.** Base + deltas against a fresh full index, in key space,
   after a body edit, a rename, an added callee, a new file, a deletion, an
   API change, six updates under the policy, a reopen — and now after a
   callee re-index with a caller's flow *out of* it, a caller re-index that
   removes the flow, and one that restores it, before and after compaction
   (`a_flow_out_of_a_foreign_symbol_belongs_to_the_file_that_observed_it`).
   The layered index's soundness test covers the same sequence.
4. **Gitea.** Full index, one-line body edit, restore, no-op; then the
   verification harness's key-space diff of that store (base + two deltas)
   against a fresh full index: **identical edge sets, 966,079 edges** in the
   harness's collapsed key space. Four rows differ by line number, all inside
   the harness's own 7,123 key collisions (same folded name in one file:
   `EllipsisDisplayStringX` and `ellipsisDisplayStringX`), where it keeps
   whichever it saw last — the Phase 6 caveat, unchanged.

## How it works

**Languages as data.** Nothing in `flow.rs` names a language. Every
capability — what a declaration looks like, where a parameter's name is,
which field holds a loop body, what a `try` handler is, how a comparison is
laid out — is a `Syntax` table entry, one table per grammar, and a test
checks every configured node kind against the grammar's own `node-types`.
The tables encode the grammar facts the plan's appendix lists: Python's
comparison operands are positional, Rust's `unary_expression` has no fields,
C#'s `variable_declarator` initialiser is an unnamed child, Go's `block`
wraps a `statement_list`, C parameters hide behind a declarator chain.

**The per-function analysis.** Each callable body becomes basic blocks with
labelled edges (then/else/case/default/loop/break/continue/exception/
finally/return/goto); every statement in a `try` body is its own block,
because a handler may be entered after any of them. Within a block the ops
are definitions (target, sources, strong or weak), call arguments, and
returns. Locals are collected up front — declarations, loop bindings,
handler bindings, closure parameters — so anything else is a non-local.
Reaching definitions is a bitset fixpoint over GEN/KILL; a definition kills
only when it is a plain local assigned at the body's top level. Everything
uncertain is a **weak** definition — destructuring, by-reference arguments,
a local passed to an unresolved callee, a declaration in a nested block, a
closure's writes — which is the one rule that keeps the analysis sound: it
may report a flow that cannot happen, never lose one that can. Which
non-local values each definition carries (a parameter, a call's result, a
module variable, a field) is a second fixpoint over the definitions rather
than a recursion from each use; the first version recursed and was
exponential on `x = f(a); y = g(x, x)` chains. A function whose fact count
passes 20,000 is summarised as "everything in reaches everything out",
through the function symbol — sound, and the reason no Gitea file takes
longer than the parse.

**Predicates.** Every branch edge of the CFG carries the *atoms* its
condition establishes when taken: `v`, `¬v`, `v == lit`, `v != lit`,
integer `v < n` and friends, `v is null`, `v is not null`, and `never` for
a literal `false`. Only conditions the tables can decide produce any — a
call, a field, two variables compared produce nothing — and De Morgan is
applied to conjunctions only: `a and b` true gives both atoms and false
gives none; `a or b` false gives `¬a` and `¬b` and true gives none; `not`
swaps. A switch arm on a literal gives `v == L`, its default the
negations. A definition starts out under its block's path condition (the
atoms every way into the block agrees on), picks up each edge's atoms as it
crosses, keeps at a join only what every arriving copy holds, and is
dropped where its atoms contradict — the only pruning there is, and
decided by a pairwise table computed once per body. A definition of `v`
invalidates every atom about `v`; so does anything that could change `v`
without a definition in sight: a local whose address is taken or that a
closure or nested function writes gets no atoms at all, and in Python,
Ruby and JavaScript — where a callee can empty the list a condition tested,
or an object's `==` is its own — a call invalidates every atom about a
local that is not a *scalar* (built only from literals and other scalars).
`found = False … found = True` is a scalar and its atoms survive a call in
the loop header; a parameter never is. At most four atoms per definition;
beyond that, new ones are not added, which is the sound direction. The
whole thing rides on the existing bitset reaching-definitions pass: a body
whose edges establish nothing runs exactly the old fixpoint, and one that
does carries a small map of conditional facts beside the bitset.

**Facts to edges.** The resolver binds every call first, then reads the
facts. `Param(i)` is the function's own `Parameter` row; `Arg(call, i)` is
the callee's parameter by position — or by name for keyword arguments, or
the receiver slot for a method's `self` — or, for an unresolved callee, an
external stub. A call's result is the callee symbol, or the stub. The
function symbol stands for its return value at either end.

**Stubs, and call sites.** One stub serves every call of `fmt.Sprintf` in
the corpus, so walking through it naively would join every caller's inputs
to every caller's outputs. Each edge into or out of a stub carries its call
site instead, as `"<leave>><enter>"`, and the search leaves a stub only
along the site it entered on. `y = decode(x); exec(y)` connects `x` to
`exec`; `decode` connects nothing else. Stubs are keyed by qualifier and
name — `assert.Equal` and `require.Equal` are two — but only when the
qualifier is a dotted name: keying on receiver *expressions* minted 245
stubs for `toEqual` alone (`expect(x).toEqual(y)`, one per `x`).

**Who owns an edge.** This is the design decision the phase turned on, found
by the Gitea key-space diff, not by a test. A file records `y := util.F();
sink(y)`: that is an edge *from* `F`, which another file defines. Rows and
their edges belong to a file — that is what lets a delta replace one file's
rows and leave the base alone — so if the edge were written on `F`'s row it
would belong to `F`'s file, and a re-index of *that* file would drop it
(the row is replaced; a dead source's edges die with it), while a re-index of
the observing file would leave it stale. The diff showed exactly this:
twenty-one `flows_to` edges out of `TruncateRunes` gone after its file was
touched. Value flow is the first relation whose source can be in another
file, and the ownership rule had to be stated for it.

The rule: a file writes a flow out of a symbol it does not define on a
**proxy row** of its own — keyed by the file and the symbol, flagged
`PROXY`, linked to the symbol by a `stands_for` storage edge. A proxy is
live with its file like any row, never canonical, and the view forwards it
to the symbol (through the symbol's own forward, if that row has died and
been replaced) and reads its edges as the symbol's. Compaction copies live
proxies as rows, so the ownership survives a merge. The index overlay diffs
a delta proxy against its predecessor like any row and lands the degree
change on the symbol. 54.6k proxies on Gitea — one per (file, foreign
symbol a value leaves) — is the price of the rule, and the full-build and
delta paths are now the same path: a full index also writes proxies, which
is why base + deltas and a fresh index agree edge for edge.

**The reachability labels stay over the call graph.** The plan put the
labels over `TAINT ∪ DATA_FLOW` so one label set would serve both modes, and
predicted the call-graph rejection rate would drop. Measured: a function's
return flowing into another's parameter makes the two reach each other
label-wise, and command-injection went from 95 % rejected to 89 %,
path-traversal from 94.5 % to 47.6 % — 42 ms to 7 s. The labels now cover
`TAINT` only, the rates are back (98 % / 92 % / 95 %), and the dataflow mode
does not use them: it runs **one backward search per sink**, and sinks are
few (13–82 on Gitea against 1,400–1,700 sources). The first version
searched forward from each source and did not finish in ten minutes; the
backward search finishes each spec in under a second. At a stub, the
incoming edges are grouped once by the call site they enter on, so a visit
costs the edges of one call rather than of every call of `Sprintf` in the
corpus.

**The CFG in the store.** Each block is a `Block` row owned by its callable
(`contains`, context = index), `succeeds` edges carry the label and the
condition's text, and a block `defines` / `uses` the non-locals it writes
and reads. `cfg <symbol>` prints it. Blocks are excluded from the symbol-set
comparison that decides whether a change is a body edit — an edit renumbers
them, and nothing outside the function references them — so a body edit is
still a one-file update. Parameters *are* in the comparison: a signature
change is an API change and pulls importers in.

## Limits, stated

- **Context-insensitive across calls.** A callee's `param -> return` summary
  is one edge for every call site. A value that enters a function from one
  caller can leave it towards another's sink. Stubs are the exception, by
  call-site tag.
- **No alias analysis.** `p = &x; *p = v` does not taint `x`. By-reference
  writes are handled by weak definitions (`strcpy(buf, x)` gives `buf` a
  weak definition from the call), not tracked precisely.
- **Field sensitivity only for `self.x`, receiver fields and module-level
  names.** `obj.x = v` taints `obj`.
- **Every argument reaches a call's result**, when the callee is unknown or
  summarised. `fmt.Errorf("…%v", number)` carries `number`. This is the
  over-approximation behind most of the Gitea findings above.
- **Ambiguous callees are stubs.** A call the binder cannot decide between
  two same-named candidates gets no `calls` edge (as before) and, for flow,
  an external stub — so `MakeRequest (external)` can appear in a path even
  though the corpus defines a `MakeRequest`.
- **The 20,000-fact valve** summarises a function through its symbol.
  Sound; loses the per-parameter shape of that function's summary.
- **Predicates decide only what a literal decides.** No relation between
  two variables, no arithmetic, no `len(x) > 0`, no call; a three-atom
  integer contradiction (`v >= 7 ∧ v <= 7 ∧ v != 7`) is not detected. In
  Python, Ruby and JavaScript a call forgets every atom about a non-scalar
  local, so `if c: x = bad()` … `if not c: sink(x)` prunes only when `c`
  is a scalar; in Go, Java, C, C++, C#, Rust it prunes for any local whose
  address is not taken.
- **A local passed to a call is assumed written only in C, C++, Go, Rust
  and C#.** In Python, Ruby, JavaScript and Java a mutable container
  passed to a callee and filled there is not seen to change (the
  receiver of a method call is).
- **Locals never leave the file.** They are analysed, not stored.
- **`goto`** links to every block of the function.

## Carry-forward

- **Library summaries for stubs.** A table of which arguments of a known
  external reach its result (`Errorf`, `Sprintf`, `Equal`, `Join`, …) and
  which it writes through. Without it the dataflow findings on a Go corpus
  are dominated by two sound-but-wrong defaults. This is the single largest
  precision lever and it is data, not analysis.
- Throughput is 4× the Phase 6 baseline against a 2× budget. The cost is in
  resolution and compaction and is proportional to rows and edges; the
  levers are fewer block rows (merge straight-line blocks that no edge
  distinguishes) and fewer flow edges (the call-site dedupe keeps one edge
  per site, which is what makes `assert.Equal` a 121k-degree node).
- Call-graph path search reads past flow edges when filtering by mask; a
  per-relation CSR partition would restore the 42 ms path-traversal audit.
