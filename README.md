# codegraph

A code-graph engine. It reads a source tree, builds a graph of what the code
*is* and what it *does* — symbols, calls, imports, inheritance, control flow,
value flow — stores it in an mmap'd columnar format that updates
incrementally, and answers questions over it from a CLI or an MCP server:
what calls this, what breaks if I change it, does this request parameter
reach `Popen`, and what does my uncommitted edit actually touch.

Eleven languages through one generic tree-sitter walk driven by per-language
syntax tables: Python, JavaScript, TypeScript, TSX, Java, C, C++, Go, Rust,
C#, Ruby.

```
$ codegraph index ./gitea
indexed 3342 files in 19.6s (170 files/s)
  359643 symbols, 2038524 edges, 1 segment(s)

$ codegraph diff ./gitea          # after editing modules/util/truncate.go
1 file(s) changed, 0 deleted, 631 neighbour(s) re-extracted

1 change(s), 1 breaking:

  ~ EllipsisDisplayString (modules/util/truncate.go:50) [function] signature (str, limit) -> (str, limit, mode) — BREAKS 29 dependent(s)
      calls from     UpdateRun (models/actions/run.go:340) [function]
      calls from     UpdateRunner (models/actions/runner.go:335) [function]
      ...
    impact (302 symbol(s)):
      called by        User.ShortName (models/user/user.go:487) [method]
        called by        ShortName (models/organization/org.go:162) [method]
      called by        NewIssue (models/issues/issue_update.go:454) [function]
        flows to         NewIssue(issue) (models/issues/issue_update.go:454) [parameter]
      ...
```

## What is in the graph

**Symbols.** Files, packages, types, functions and methods, **parameters**,
module-level **variables and constants**, class **fields**, and the
**locals** of every callable. External library functions appear as stubs
owned by their package.

**Structure.** `calls`, `imports_from`, `inherits` / `extends` /
`implements` (structural for Go interfaces), `contains`, `method`,
`references` (a function to the variables and fields it reads or writes).

**Control flow.** A CFG per callable, persisted: `Block` rows with
`succeeds` edges carrying the branch label and predicate, and `defines` /
`uses` edges to the variables each block writes and reads.

**Value flow.** Reaching definitions over the CFG — statement order,
branches, loops to a fixpoint, kills, weak definitions for anything
uncertain — **field-sensitive** on locals (`a.x` and `a.y` are different
values), **alias-aware** (`p = &x; *p = v` writes `x`; `b = a; b.x = v`
writes `a.x` where a copy shares the object), and with **predicate-aware
pruning**: a definition made under `c` does not reach a use under `not
c`, whether `c` is a local against a literal, two locals compared, or a
pure test like `len(x) > 0`. Lifted to interprocedural `flows_to` edges —
a parameter into a callee's parameter, a call result into a variable, an
argument into a library stub — and searched **context-sensitively**: every
edge into or out of a callee carries its call site, and a value leaves a
callee only where it entered. **Library summaries** (~1,400 entries, plus
your own in `.codegraph-summaries.json`) say what known calls do with
their inputs — `fmt.Sprintf` formats its arguments, `assert.Equal` does
nothing, `json.Unmarshal` writes its second argument from its first,
`strcpy` writes its first, `os.Getenv` returns external data — so an
unknown call's sound-but-loose default ("everything may reach everything")
applies only where nothing better is known.

The whole analysis is **sound by construction**: it may report a flow that
cannot happen, it does not drop one that can. Every shortcut is taken in
that direction, and the limits are stated in the docs.

## Commands

| command | what it answers |
|---|---|
| `index <src> [--store dir] [--full]` | Build the store. On an existing store this is **incremental**: only changed files and their neighbourhood are re-extracted, into a delta segment; the index gets an overlay, not a rebuild. A one-line edit on a 3,300-file tree is 0.4 s. |
| `search <store> <query>` | Symbols by name, prefix, substring or path. |
| `explain <store> <symbol>` | What a symbol is and what it connects to: members, parameters, locals, callers, callees, references, flows in and out, CFG size. `func.local` and `path:name` disambiguate. |
| `path <store> <a> <b>` | Shortest path between two symbols. |
| `affected <store> <symbol>` | Blast radius: what breaks if this changes. |
| `cfg <store> <callable>` | The stored control-flow graph, with what each block reads and writes. |
| `diff <src> [--depth n] [--fail-on-break]` | What the uncommitted edits do: symbols added, removed, re-signed, redefined or re-bound; the dependents each breaks; a trace of what each reaches through calls, references, imports, subtypes and value flow. Runs on a scratch copy; the store is not modified. |
| `audit <store> [--mode callgraph\|dataflow]` | Taint analyses from starter specs (command injection, SQL injection, path traversal). Call-graph mode: a call path from a source to a sink function. Dataflow mode: a *value* from a source reaching a sink's argument, sanitiser-aware, call-site-matched through callees and library stubs. |
| `deps <store> [package]` | Which of our code reaches an external package. |
| `stats`, `verify`, `compact` | Store statistics; checksum verification; merge every segment into one. |

`codegraph-mcp <store>` serves the same questions as MCP tools (`search`,
`explain`, `cfg`, `affected`, `path`, `neighbors`, `context`, `stats`,
`audit`, `deps`, `diff`) for a model working in the tree.

## Build

Rust 1.85+ (edition 2024).

```
cargo build --release
./target/release/codegraph index <source-dir>
./target/release/codegraph explain <source-dir>/.codegraph <symbol>
cargo test --workspace
```

## Layout

| crate | role |
|---|---|
| `codegraph-core` | Vocabulary: symbol kinds, relations, masks; stable 128-bit symbol keys. |
| `codegraph-extract` | Tree-sitter walk, per-language syntax tables, the per-body flow analysis (`flow.rs`), library summaries. |
| `codegraph-resolve` | Turns extracted facts into a graph: call binding, imports, heritage, stubs, proxies, flows, locals; the incremental pipeline; `diff`. |
| `codegraph-store` | The segment format, the manifest, the store-wide `View` over base and delta segments, compaction. |
| `codegraph-index` | Degrees, hubs, SCC + reachability labels, name and trigram postings; the layered (base + overlay) index. |
| `codegraph-query` | The query engine: search, explain, walks, paths, blast radius, CFG. |
| `codegraph-security` | Taint specs, matchers, call-graph and dataflow analyses, entrypoints. |
| `codegraph-cli`, `codegraph-server` | The `codegraph` CLI and the `codegraph-mcp` server. |
| `codegraph-verify`, `codegraph-probe` | The key-space verification harness (base + deltas must equal a fresh index) and grammar probes. |

## Design notes

Each phase of the work has a results document under `docs/`, with the
design decisions, the measured numbers on real corpora (Gitea, 3,342
files), the bugs each phase surfaced, and the limits stated plainly:

- `docs/segment-format.md` — the on-disk format.
- `docs/phase6-results.md` — incremental updates and the layered index.
- `docs/phase7-results.md` — variables, CFG, predicate-sensitive dataflow,
  the ownership rule for cross-file edges.
- `docs/phase8-results.md` — library summaries; locals in the store.
- `docs/phase9-results.md` — `diff`.
- `docs/phase10-results.md` — context sensitivity, aliasing, field
  sensitivity, richer predicates, user summaries, flow-sensitive locals.

## Limits

Each of these is a bound, stated so the answers can be read correctly;
`docs/phase10-results.md` says what each one was, what it is now, and why
the rest is fundamental.

- **Across calls**: call-site matching to a stack depth of 6; deeper
  recursion re-admits callers. Callees the binder cannot resolve are
  library stubs.
- **Aliasing**: a may-alias class per function — by address (`&x`) and,
  where a copy shares the object, by copy (`b = a`). Not through
  containers, not across calls, not between parameters.
- **Fields**: a local's fields are their own values (`a.x`, `a[]`); `self`
  fields and non-local fields are per field only; array indices are
  folded.
- **Predicates**: locals and pure terms (`len(x)`, `s.isEmpty()`, 73
  names) against literals and each other, integer intervals and
  equalities decided exactly; no arithmetic, no theory beyond that.
- **Library summaries**: ~1,400 built-in entries plus your own in
  `.codegraph-summaries.json`; an unknown name keeps the sound default
  (everything may reach everything).
- **Locals** are one stored row per name; the `local_flow` edges carry
  the definition lines, so `explain` is flow-sensitive without more rows.
- **Sinks by name**: the starter specs match `Exec`, `Open` by name; a
  database `Exec` and a shell `Exec` are one sink until a spec qualifies
  them.

## License

Apache-2.0.
