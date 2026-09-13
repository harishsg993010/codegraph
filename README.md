# codegraph

A code-graph engine. It reads a source tree, builds a graph of what the code
*is* and what it *does* — symbols, calls, imports, inheritance, control flow,
value flow — stores it in an mmap'd columnar format that updates
incrementally, and answers questions over it from a CLI or an MCP server:
what calls this, what breaks if I change it, does this request parameter
reach `Popen`, where is the upload limit enforced, and what does my
uncommitted edit actually touch. Point any command at a source tree: it is
indexed on first use and kept current — through git when git is there —
before every answer after.

Eleven languages through one generic tree-sitter walk driven by per-language
syntax tables: Python, JavaScript, TypeScript, TSX, Java, C, C++, Go, Rust,
C#, Ruby.

## Quick start

```
cargo build --release
codegraph deep ./repo upload size limit        # first use indexes ./repo into ./repo/.codegraph
codegraph explain ./repo SomeFunction          # every later command syncs the store first, then answers
codegraph diff ./repo                          # what the uncommitted edits break, against the last commit
codegraph-mcp ./repo                           # the same as MCP tools; follows the tree as it changes
```

The store is always `<repo>/.codegraph`; in a git checkout it is added to
`.git/info/exclude`. `.codegraphignore` (gitignore syntax) keeps files
out of the graph.

```
$ codegraph deep ./gitea upload size limit -n 2
indexed ./gitea in 18.0s: 3342 files, 352264 symbols, 2299027 edges (store: ./gitea/.codegraph)
2 hit(s) for terms ["upload", "size", "limit"] (246 ms)

  3.38  CheckSizeQuotaExceeded (services/packages/packages.go:362) [function]
          condition `totalSize+uploadSize > setting.Packages.LimitTotalOwnerSize` matches 'upload'
          name matches 'size'
          condition `setting.Packages.LimitTotalOwnerSize > -1` matches 'limit'

  3.38  NewLimitedUploaderKnownSize (services/attachment/attachment.go:48) [function]
          name matches 'upload'
          name matches 'size'
          name matches 'limit'

$ codegraph diff ./gitea          # after adding a parameter in modules/util/truncate.go
1 file(s) changed, 0 deleted, 626 neighbour(s) re-extracted, against HEAD 4f307ec685

1 change(s), 1 breaking:

  ~ EllipsisDisplayString (modules/util/truncate.go:50) [function] signature (str, limit) -> (str, limit, mode) — BREAKS 29 dependent(s)
      calls from     UpdateRun (models/actions/run.go:340) [function]
      calls from     UpdateRunner (models/actions/runner.go:335) [function]
      ...
    impact (267 symbol(s)):
      called by        UpdateRun (models/actions/run.go:340) [function]
        called by        ApproveRuns (services/actions/approve.go:21) [function]
        called by        execRerunPlan (services/actions/rerun.go:195) [function]
      ...

summary: 1 change(s), 1 breaking, 266 symbol(s) affected
(5.7 s)

$ codegraph audit ./gitea --kind taint         # rules from ./gitea/.codegraph-rules.yaml
go-command-injection [ERROR] — A request value reaches a shell command
  1845 sources x 1 sinks, 1 sinks searched, 191 finding(s) (120 ms)
  requestJSONResp (external) -> CommandContext (external)  [3 hops, Inferred, unreachable]
      via requestJSONResp -> resp -> ... -> CommandContext
  ...
go-path-traversal [WARNING] — A request value reaches a file open
  1845 sources x 5 sinks, 5 sinks searched, 43 finding(s) (115 ms)
  ...
```

Gitea is 3,342 Go/JS/TS files. The first command indexes it in 16–20 s;
after a one-line edit the next command updates the store in 0.7 s before
answering; `diff` runs in 0.7 s; base + deltas stay edge-for-edge
identical to a fresh index, which the test suite and `codegraph-verify`
check.

## Nothing to run by hand

Every command takes a source tree (or its store). **The store always
lives at `<tree>/.codegraph`** — one place, so every command, the
watcher and the server find the same graph, and one ignore rule covers
it. A tree with no store is indexed on first use (and, in a git
repository, the store is added to `.git/info/exclude`). From then on **every command
brings the store up to date before it answers** — the change you just
made is in the graph you are asking about — and says so on stderr when
anything changed (`updated in 0.7s: 1 changed, 0 deleted, 1
re-extracted (git)`). `--no-sync` (or `CODEGRAPH_NO_SYNC=1`) answers from
the store as it is. Two processes never write one store at once: writers
take the store's lock; a query that finds it held answers from the store
as it is and says so.

**With git installed and the tree in a repository, an update asks git
what changed**: the store records the commit and the dirty set it
indexed, the next update runs `git rev-parse` and `git status`, and only
the files git names are checked by content hash — O(changes), on git's
own stat cache. **Without git**, or whenever git cannot be sure, the
store's file table does what git's index does — path, size, mtime,
content hash per file — and every file is compared; the graph is the
same either way.

**`.codegraphignore`** keeps files out of the graph: gitignore syntax, at
any directory, `!` re-includes. `.gitignore` and `.git/info/exclude` are
honoured too, git or no git.

```
# .codegraphignore
generated/
fixtures/
!fixtures/real_case.py
*.pb.go
```

For long-running use, **`codegraph watch ./repo`** keeps the store
current as files change, so the next query has nothing to do; and
**`codegraph-mcp ./repo`** syncs at startup and then follows the tree,
serving each new generation without a restart, so a model editing the
tree asks questions of the tree as it is.

## Security rules

Taint questions are written in YAML, in the shape Semgrep users know, and
answered by the value-flow engine rather than by matching text:

```yaml
# .codegraph-rules.yaml — read by every `audit` of this tree
rules:
  - id: go-command-injection
    message: A request value reaches a shell command
    severity: ERROR
    languages: [go]
    metadata: { cwe: CWE-78 }
    paths: { exclude: [_test.go] }
    pattern-sources:
      - pattern: r                 # the *http.Request parameter, by convention
      - pattern: "*Request*"
    pattern-sinks:
      - pattern: exec.Command      # the member `Command` of the package `os/exec`
      - pattern: exec.CommandContext
    pattern-sanitizers:
      - pattern: shellescape.Quote
```

A `pattern` names a symbol: `Name`, `Name*`, `*Name`, `*Name*`,
`Owner.Name`; a source is a function (its return) or a parameter, a sink
a function or library call (its arguments). `codegraph audit ./repo`
reports per rule with severity and message; `--format json` for tooling,
`--fail-on ERROR` for CI. `rules/starter.yaml` is a starting point to
copy; `docs/phase13-results.md` says what a rule can and cannot express.

## What is in the graph

**Symbols.** Files, packages, types, functions and methods, **parameters**,
module-level **variables and constants**, class **fields**, and the
**locals** of every callable. External library functions appear as stubs
owned by their package.

**Structure.** `calls` (to corpus callables, and to library stubs for
calls the corpus does not define, flagged external), `imports_from`,
`inherits` / `extends` / `implements` (structural for Go interfaces),
`contains`, `method`, `references` (a function to the variables and
fields it reads or writes — in a branch condition too).

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

`<store>` below is a store directory or a source tree — a tree is
indexed on first use and synced before every answer.

| command | what it answers |
|---|---|
| `index <src> [--full]` | Build `<src>/.codegraph` explicitly — the other commands do this on first use and keep it current after. On an existing store this is **incremental**: only changed files and their neighbourhood are re-extracted, into a delta segment; the index gets an overlay, not a rebuild. Changed files are found through git when git is there, by a walk otherwise. A one-line edit on a 3,300-file tree is 0.7 s; a full index is 16–20 s. |
| `watch <src> [--debounce-ms n]` | Index, then keep the store current: re-index what changes after each quiet period, one line per round. |
| `search <store> <query>` | Symbols by name, prefix, substring or path. |
| `deep <store> <terms and filters> [--hops n] [--seeds n]` | **Deep search**: find code by what it is connected to. Terms match names and paths by subword, and the inside of functions — locals, parameters, callees, referenced variables, branch conditions; matches spread along calls, references and value flow (`--hops`, default 2, or `hops:N` in the query), so the function that connects two terms scores for both. Filters: `kind:`, `in:`, `calls:`, `called-by:`, `references:`, `referenced-by:`, `reaches:`, `flows-to:`, `flows-from:`. Every hit says why. |
| `explain <store> <symbol>` | What a symbol is and what it connects to: members, parameters, locals, callers, callees, references, flows in and out, CFG size. `func.local` and `path:name` disambiguate. |
| `path <store> <a> <b> [--max-hops n]` | Shortest path between two symbols. |
| `affected <store> <symbol> [--depth n]` | Blast radius: what breaks if this changes. |
| `cfg <store> <callable>` | The stored control-flow graph, with what each block reads and writes. |
| `diff <src> [--depth n] [--max-fanout n] [--max-impact n] [--fail-on-break]` | What the uncommitted edits do, **against the last commit** when git knows the tree (against the store otherwise): symbols added, removed, re-signed, redefined or re-bound; the dependents each breaks; a trace of what each reaches through calls, references, imports, subtypes and value flow. Runs on scratch copies; the store is not modified. |
| `audit <store> [--rules file-or-dir] [--format text\|json] [--fail-on SEVERITY] [--max-hops n] [--context-depth n]` | Taint analyses from **rule files** (YAML, Semgrep-like: `pattern-sources`, `pattern-sinks`, `pattern-sanitizers`, `pattern-not`, `paths`, `languages`, `severity`, `metadata`); `<tree>/.codegraph-rules.yaml` and `.codegraph-rules/` are read without asking, the built-in starter specs run when there are no rules (or with `--presets`). `mode: taint` (default): a *value* from a source reaching a sink's argument, sanitiser-aware, call-site-matched through callees and library stubs. `mode: callgraph`: a call path from a source to a sink function. `--fail-on ERROR` for CI. |
| `deps <store> [package]` | Which of our code reaches an external package. |
| `stats`, `verify`, `compact` | Store statistics; checksum verification; merge every segment into one. |
| `--no-sync` (any command; or `CODEGRAPH_NO_SYNC=1`) | Answer from the store as it is, without bringing it up to date first. |

`codegraph-mcp <store> [--no-watch] [--debounce-ms n]` serves the same
questions as MCP tools (`search`, `deep_search`, `explain`, `cfg`,
`affected`, `path`, `neighbors`, `context`, `stats`, `audit`, `deps`,
`diff`) for a model working in the tree: it takes a store or a tree,
syncs at startup, then watches the tree and serves each new generation
without a restart.

## Build

Rust 1.89+ (edition 2024). `git` is optional: with it on the path, change
detection is O(changes); without it, every file is compared by size,
mtime and hash.

```
cargo build --release
./target/release/codegraph explain <source-dir> <symbol>     # indexes on first use
./target/release/codegraph deep <source-dir> upload limit kind:function
cargo test --workspace
```

The store lives in `<source-dir>/.codegraph`; the test suite needs no
network and skips the git tests when no `git` binary is installed.

## Layout

| crate | role |
|---|---|
| `codegraph-core` | Vocabulary: symbol kinds, relations, masks; stable 128-bit symbol keys. |
| `codegraph-extract` | Tree-sitter walk, per-language syntax tables, the per-body flow analysis (`flow.rs`), library summaries. |
| `codegraph-resolve` | Turns extracted facts into a graph: call binding, imports, heritage, stubs, proxies, flows, locals; the incremental pipeline; the tree (`tree.rs`: ignore rules, git, the `TREE` record) and the watcher (`watch.rs`); `diff`. |
| `codegraph-store` | The segment format, the manifest, the store-wide `View` over base and delta segments, compaction. |
| `codegraph-index` | Degrees, hubs, SCC + reachability labels, name and trigram postings; the layered (base + overlay) index. |
| `codegraph-query` | The query engine: search, deep search (`deep.rs`), explain, walks, paths, blast radius, CFG. |
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
- `docs/phase11-results.md` — `deep` search; condition reads as
  references; `calls` edges to library stubs.
- `docs/phase12-results.md` — index on first use and sync before every
  answer; change detection through git; `.codegraphignore`; `watch`; the
  server following the tree; the store lock.
- `docs/phase13-results.md` — rule files: taint questions in YAML.

## Limits

Each of these is a bound, stated so the answers can be read correctly;
`docs/phase10-results.md` says what each one was, what it is now, and why
the rest is fundamental.

- **Across calls**: call-site matching to a stack depth of 6 by default
  (`context-depth` in a rule, `--context-depth` on `audit`); deeper
  recursion re-admits callers. Callees the binder cannot resolve are
  library stubs. Every search bound — hops, depth, fan-out, spread — is
  a flag or a rule key, never only a constant.
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
- **Sources and sinks by name**: a rule names symbols, not types — every
  `*http.Request` is `r`, `req`, `*Request*` by convention, and a shell
  `Exec` and a database `Exec` are one sink until a rule qualifies them
  (`exec.Command`, `pattern-not`). A rule has no metavariables, no
  `pattern-inside`, no text patterns.
- **Git** accelerates change detection; it does not decide what is
  indexed — `.gitignore` and `.codegraphignore` do, git or no git. Any
  doubt (no record, a rewritten commit, an ignore file changed) falls
  back to the walk, which is always correct.
- **The pre-answer sync** costs a no-op update on every command: ≈ 0.25 s
  of `git` on a 3,300-file tree, a walk without git. `--no-sync` skips
  it; a running `watch` or server leaves it nothing to find. An edit to
  the API of a widely imported file re-extracts every importer, and when
  that exceeds the delta policy's share of the base the next command
  rebuilds the store in full (≈ 20 s on Gitea) rather than write a delta
  that large.
- **Deep search** matches what the graph holds — names, paths, locals,
  parameters (by name, `kind:parameter` to list them), callees,
  referenced variables, branch predicates — not
  string literals or comments; spreading is two hops and never through a
  hub or a library stub.

## License

Apache-2.0.
