# Phase 12 — The tree as a live thing: sync on every answer, git, `.codegraphignore`, `watch`

Four changes to how a store relates to the tree it was built from. With
git installed and the tree in a repository, an update asks git which files
can have changed and checks only those — O(changes), not O(files), on
git's own stat cache. Without git, or when git cannot be sure, the
store's file table does what git's index does: path, size, mtime and
content hash per file, compared the same way. `.codegraphignore` (and
`.gitignore`, git or no git) keeps files out of the graph. And nothing
has to be run by hand: every command takes a store or a source tree,
indexes a tree on first use, and brings the store up to date before it
answers; `codegraph watch` and the MCP server keep a store current
between commands, and a served graph swaps to the new generation without
a restart. 359 tests, clippy-clean.

---

## What it looks like

```
$ codegraph deep ./gitea "rate limit" kind:function -n 1
indexed ./gitea in 18.0s: 3342 files, 352264 symbols, 2299027 edges (store: ./gitea/.codegraph)
1 hit(s) for terms ["rate limit"] with filters Kind(Function) (405 ms)
  0.95  IsRateLimitError (services/migrations/error.go:17) [function]

$ vi modules/util/truncate.go
$ codegraph explain ./gitea EllipsisDisplayString
updated in 0.7s: 1 changed, 0 deleted, 1 re-extracted (git)
EllipsisDisplayString (modules/util/truncate.go:51) [function]
  ...

$ codegraph search ./gitea Ellipsis        # nothing changed: 0.7 s end to end, nothing said
19 matches
  ...
```

The first line of stderr is the bootstrap; the second is the sync every
command does before answering. `(git)`: it ran `git rev-parse` and `git
status` and compared nothing else. A no-op costs ≈ 0.25 s of git and
≈ 0.3 s of opening a 120 MB store and its index. `codegraph index` still
exists for an explicit run and prints the full report:

```
$ codegraph index ./gitea
indexed 0 files in 0.5s (0 files/s)
  up to date (3342 files unchanged, by git); index overlay current
  git: C:/.../targets/gitea at 4f307ec685 (1 dirty); changes are found through git
```

```
$ codegraph watch ./gitea
[03:31:55] up to date: 0 changed, 0 deleted, 0 re-extracted (git) — 352264 symbols, 2299027 edges (0.6s)
  git: C:/.../targets/gitea at 4f307ec685 (1 dirty); changes are found through git
watching ./gitea (store ./gitea/.codegraph); Ctrl-C to stop
[03:32:10] 1 changed, 0 deleted, 1 re-extracted (git) in 0.7s — 352266 symbols, 2299031 edges: modules/util/truncate.go
```

`codegraph-mcp ./gitea` does the same on its own: it takes a store or a
tree, syncs at startup, reads the tree's location from the store,
watches it, and after each quiet period brings the store forward and
serves the new generation. `--no-watch` turns the watch off;
`--debounce-ms` sets the quiet period (default 400).

A `.codegraphignore` is a gitignore file for the graph, at any directory:

```
# .codegraphignore
generated/
fixtures/
!fixtures/real_case.py
*.pb.go
```

## How it works

**Which files** (`tree.rs`). The walk is the `ignore` crate's: it reads
`.gitignore`, `.git/info/exclude`, `.ignore` and `.codegraphignore` at
every level with gitignore semantics — `*`, `**`, anchoring, `!`
re-includes, directory-only patterns — and does so whether or not git is
installed or the tree is a repository (`require_git(false)`). The
built-in skip list (`node_modules`, `target`, `.git`, `.codegraph`, …) is
a floor under that: applied even in a tree with no ignore file, not
overridable by `!`. `is_indexable(root, path)` answers the same question
for one path by walking only the directories on the way down to it, so a
path git names is judged by the rules the scan would have applied.

**What git knows.** At the end of every index or update the store writes
`TREE`, a small JSON record: the absolute source root, the repository
label, and — when `git rev-parse --show-toplevel --show-prefix HEAD`
succeeds — the commit and the dirty set from `git status --porcelain -z
--untracked-files=all` (paths relative to the indexed root; ignored files
are not dirty, and are not indexed either). The next update reads the
record and, if the root is the same, asks git again. The candidates are
`dirty_then ∪ dirty_now ∪ git diff --name-only old..new`. Each candidate
is checked against the store: indexable and present → its content hash
against the stored one; not indexable or gone → deleted if the store has
it. Every other stored file is unchanged by git's word: it was clean at
both commits and unchanged between them. Two `git` processes, no walk.

The fallback is the walk whenever anything is uncertain: no git, no
record, a different root, an unresolvable commit (a rebase rewrote it),
a repository with no commit yet, or an ignore file among the candidates —
an ignore rule can add or remove files git would never mention
(`an_ignore_file_change_falls_back_to_the_walk`). The walk compares every
file by size and mtime, then hash, as before. Both paths produce the same
graph: `a_commit_a_delete_and_an_untracked_file_are_found_through_git_and_match_a_walk`
checks key-space equality against a fresh index after a commit, a
deletion and an untracked file; Gitea's base + deltas after a git-detected
edit and its reversal are edge-for-edge identical to a fresh index, 0
dangling.

`index` also keeps the store out of the repository: on a fresh index of a
tree inside a work tree, the store directory is added to
`.git/info/exclude` unless some rule already ignores it — local to the
clone, never committed, and only once.

**Every command syncs** (`watch.rs`: `locate`, `ensure_current`). What
a command is given is resolved — a store directory, a tree with a
`.codegraph` inside, or a tree with none — and brought current: a fresh
tree is indexed (waiting on the store's lock if another process is
already doing it), a store that records its tree is synced unless
another process holds the lock (then it is read as it is, and stderr
says so), a store from before this version that records no tree is read
as it is. The lock is the OS's advisory lock on `<store>/LOCK`, released
when the holder exits however it exits; `index`, `compact`, `watch`, the
server's sync thread and the pre-query sync all take it, readers never
do — a manifest commit is atomic and segments are written once, so a
reader always sees a whole generation
(`a_locked_store_is_read_as_it_is`,
`a_source_tree_is_indexed_on_first_use_and_kept_current_after`, through
the built binary).

**Watching** (`watch.rs`). `TreeWatcher` is a recursive `notify` watch
with a debounce: events are gathered until the tree has been quiet for
the configured period, then the relevant paths are delivered as one
batch — source files, ignore files, anything that might be a directory;
never the store, never a skipped directory. A watch error (an OS queue
overflow) delivers the root, which the update resolves by hashing.
`sync` is one round: `update_tree` then `open_or_build`. The CLI prints a
line per round; the server swaps in a new engine.

**Serving across generations.** The MCP server holds its engine behind a
lock and hands each call the engine current when the call began; the
sync thread opens the new generation and swaps it in. This surfaced a
Windows fact: a mapped file can be neither overwritten nor renamed over,
and the index files had fixed names (`index.cgidx`, `overlay.cgidx`) that
each generation rewrote — so the first full rebuild under a running
server failed with "a user-mapped section open". Index files are now
named by generation (`index-3.cgidx`, `overlay-5.cgidx`) and written
once; `open_or_build` picks the base that describes the current
generation, or the newest built over the store's first segment, and
removes the rest when nothing maps them (best effort, retried at every
open). The unnumbered names are still read. Segments already worked this
way.

## Numbers — Gitea

| | |
|---|---|
| full index | 15.9–20.9 s (unchanged; the walk is 0.2 s of it) |
| no-op update, by git | 0.5–0.6 s, of which `git` ≈ 0.25 s and opening the store ≈ 0.3 s |
| a query on an unchanged tree, end to end (`search`) | 0.7 s; 0.4 s with `--no-sync` |
| a query after a one-file edit, end to end (`explain`) | 1.0 s |
| one-file edit, by git | 0.7 s |
| files indexed | 3,342 before and after — Gitea's `.gitignore` excludes nothing the skip list did not |
| base + deltas vs fresh, after a git-detected edit and its reversal | identical, 0 dangling |
| `watch`, one-file edit end to end (event → updated store) | ≈ 1.1 s with the 400 ms debounce |

## Limits, stated

- Git accelerates change detection; it does not decide what is indexed.
  A file git tracks but `.codegraphignore` excludes is not indexed; a
  file git ignores is not indexed either, because the scan honours
  `.gitignore`.
- The git path trusts `git status` for tracked files. A file changed and
  restored with its mtime and size intact within git's racy-git window is
  the same edge case git itself has, and the next walk (any fallback
  condition) re-hashes everything.
- The pre-query sync costs a no-op update on every command — ≈ 0.25 s of
  git on Gitea, a walk of the tree without git. `--no-sync` skips it; a
  running `watch` or server makes it a no-op that finds nothing.
- `watch` follows one tree; a store indexed from a different root than
  the one watched falls back to the walk every round and says so
  (`scan`).
- A full rebuild under a running server (the delta policy tripped) takes
  as long as a full index; the old generation is served until it is done.
- The `ignore` crate's global gitignore (`core.excludesFile`) is not
  read; `.git/info/exclude` is.
