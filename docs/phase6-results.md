# Phase 6 — incremental updates

The Phase 5 carry-forward: *`compact` rewrites the whole store — 29 s at 5M
symbols for a one-file change; the segment design exists to avoid this.*
Closed. A one-file change now writes a delta segment beside the base and
leaves the base alone — and the derived index follows the same rule: a base
index plus an overlay, never a rebuild. 279 tests, clippy-clean, no segment
format change (the index file format is bumped to v2; it is derived data).

---

## What exists now

| crate | change |
|---|---|
| `codegraph-store` | **`View`**: one store-wide id space over every live segment, with dead and duplicated rows forwarded to the row that counts. **Tiered compaction**: deltas merge among themselves; the base is not touched by a merge. File metadata (content hash, mtime, size, language) survives compaction — it was being zeroed. `Store::remove_files`. |
| `codegraph-index` | Read through the view. **`Layered` index**: the base `.cgidx` stays; each generation gets a small `overlay.cgidx` with the delta rows' degrees and postings, degree patches for touched base rows, and a sound reachability extension. The query surface (`IndexQuery`) is split from the column layout (`IndexColumns`) so a layered index can answer without contiguous columns. |
| `-query` / `-security` / `-verify` | Read through the view instead of "the one segment". |
| `codegraph-resolve` | Resolution runs over a corpus that is partly fresh extracts and partly context read back from the store; only the fresh files are written. **`update_tree`**: change detection, the re-extraction neighbourhood, deletions, delta build, policy. |
| `codegraph` CLI | `index` is incremental on an existing store; `--full` forces a rebuild; new `compact`. |

## The numbers — Gitea, 3,342 files, 24.5k symbols / 425k edges

Warm page cache, release build.

| operation | time | re-extracted | written |
|---|---|---|---|
| full index | 3.4 s | 3,342 | 12.8 MB base |
| no-op (nothing changed) | **0.1 s** | 0 | nothing |
| one-line body edit, any file — including `models/db/context.go`, which most of Gitea imports | **0.2 s** | 2 | 10–22 KB delta, 380 KB overlay |
| new function in `models/perm/access/repo_permission.go` (137 files have edges into it) | 0.6 s | 138 | 2.0 MB delta |
| new function in `models/db/context.go` | 3.8 s | 3,342 | rebuilt — the neighbourhood exceeded the policy |

Where the 0.2 s goes for a body edit: 0.12 s walking the directory, 0.07 s
resolving the delta against the store, **6 ms** for the index overlay (the
full index rebuild it replaces was 0.28 s). The store write is under 10 ms.
The floor is now the filesystem walk.

## The proof

Two comparisons, both in key space because ids differ between a store that
grew by deltas and one built in a single pass:

1. **Base + two deltas against a fresh full index of the same tree**, through
   the verification harness: identical edge sets, 406,662 edges. (19 symbols
   differ by line number; all are inside the harness's own 242 key collisions
   — same-named symbols in one file, where it keeps whichever it saw last.)
2. **CLI output before and after `compact`** (which forces a fresh base
   index) for `explain`, `affected`, `path`, `search`, `deps`, `stats`,
   `audit`: identical up to the order of id-ordered listings, and the full
   taint finding set (26 findings) identical as a set.

Per-test, `crates/codegraph-resolve/tests/incremental.rs` asserts the same
equivalence after a body edit, a rename, an added callee, an added file, a
deleted file, an API change, six consecutive updates under the policy, and a
reopen — and `crates/codegraph-store/tests/view.rs` pins the forwarding rules
directly.

## How it works

**The view.** A segment knows only its own rows. The view numbers rows densely
across segments, decides which are *canonical* — live under the manifest's
ownership, and not shadowed by a later row for the same key — and forwards the
rest. A CSR target that is dead is followed to its replacement, because the
edge was written *at a symbol* and the symbol still exists. A keyed `EdgeExt`
target is resolved once, at view build, so traversal never touches a key
table. The reverse direction reads the forwarded rows' own reverse CSR, which
is how a re-index of a callee keeps the callers that were never touched.

For a single fully-live segment the view is `O(files)` to build and every
edge question goes straight to the CSR — the Phase 5 fast paths are intact.
The forwarding tables appear only once a store has dead rows or several
segments, and they are proportional to what changed, not to the store.

**The neighbourhood.** A changed file's own edges are recomputed from
scratch. What else can a change alter? Only bindings that name it — and those
are by name, kind, and existence. So if the file's **symbol set is unchanged**
(same keys, same kinds: a body edit), no other file's bindings can move, and
nothing else is re-extracted. If it changed, every file with an edge *into* it
is re-extracted so its bindings are recomputed rather than inherited. Two
exceptions, both because the store does not hold the data: a Go type
implementing one of the file's interfaces is re-extracted regardless (arity
is not stored, and satisfaction is judged on it), and the files holding a
changed file's *supertypes* are re-extracted (whether a base is a `Protocol`
is read off its own declaration).

**The policy.** `CompactPolicy { max_deltas: 4, max_delta_ratio: 0.2 }`. Past
four deltas they are merged among themselves — cost proportional to the
deltas. Once the deltas would hold more than a fifth of the base's rows, the
update is a **full re-index**, not a merge: a merge moves rows, and only a
re-index revisits the bindings a delta cannot. That bounds the staleness a
delta can accumulate to a bounded amount of change.

**The index overlay.** Degrees and postings for delta rows are recomputed —
they are few — and a base row that gained or lost a caller gets a patched
degree. Reachability is the part that cannot be patched exactly: maintaining
transitive closure under insertion is a hard problem, and the GRAIL labels are
a whole-graph artefact. So the overlay keeps the base's labels *sound* rather
than replacing them. A re-indexed symbol inherits the component of its
predecessor (the dead base row with its key), so every path that uses only
edges the base graph had is still answered by the base labels; removed edges
only shrink reachability, and a "maybe" that is really a "no" costs a bounded
BFS, never a wrong answer. Every *new* path must cross an edge the delta
added, so the overlay records two bitsets — the rows that can reach an added
edge's source, and the rows an added edge's target can reach — and answers
`maybe(a, b) = base(a, b) || (A[a] && B[b])`. A body edit adds no edge: its
edges are the same edges re-keyed, and the filter is exactly the base's.
Precision degrades with what was added and the rebuild restores it.

The soundness test (`the_layered_index_is_sound_after_every_kind_of_change`)
checks every live pair against a BFS after a body edit, an added call, a
rename, a delete-and-add, a reopen from disk, and a compaction. Pair-by-pair
precision against a rebuild is deliberately *not* asserted: GRAIL intervals
depend on traversal order, so two sound label sets reject different
unreachable pairs, and a test that expected them to agree would be testing
the traversal order.

**Context, not re-extraction.** Resolving a fresh file needs the corpus — every
name, kind, and path, and the members of every type. All of that is in the
store, so it is read back as context rather than re-parsed: `resolve_into`
sees one `CorpusFile` list and cannot tell fresh from context, which is what
keeps an incremental build's rules identical to a full build's.

## Design decisions worth recording

**`LocalId` is reused for the view's ids.** Its doc says "within one segment",
and the query layer now means "within the view". On a single compacted segment
the two are the same number, which is what every caller was already relying
on; renaming the type would have touched every signature in four crates for
no behavioural change. Recorded here so it is a known reuse, not a drift.

**A dead source is dropped; a dead target is followed.** Found on Gitea, not
by a test: `explain` reported every caller in a re-indexed file twice. The
dead base rows' reverse CSR still lists the file's internal callers, and those
callers' replacements in the delta list them again. The rule that fixes it is
asymmetric on purpose: an edge written *at* a symbol survives the symbol's
re-index, an edge written *by* one is superseded by its replacement's.

**Merge and rebuild are different tiers.** The first version let the store's
own ratio trigger a full *merge* after a delta had grown past it. That is the
wrong operation: it compacts rows but cannot re-resolve, so the documented
staleness would have been baked in permanently. The pipeline owns the ratio
now, and the store's tiered compaction is only asked to merge deltas.

**Package stubs are live everywhere.** A package row is attached to whichever
file first imported it; when that file is re-indexed, the row would die with
it while other importers still point at it. Rows flagged `EXTERNAL` are exempt
from ownership, deduplicated by key across segments, and dropped by a full
merge only when nothing references them.

**A repo tag mismatch is an error, not a silent dangle.** Keys are minted
under the repo tag, so a delta built under a different tag would key every
edge into the store wrongly, and every one would quietly resolve to nothing.
The first file row read back is checked against the tag.

## Things the real corpus caught that the tests did not

1. **The duplicate callers**, above.
2. **The out-neighbourhood was 343 files for a comment.** Re-extracting
   everything a changed file points *at* seemed cheap — "its imports". On Go,
   weak-receiver call bindings fan out to hundreds of files. Only heritage
   targets actually need it.
3. **Two `stat`s per file cost 0.43 s on Windows** — more than the delta
   itself. The directory walk already had the size and mtime; `scan` now
   carries them out.
4. **A panic in `audit` on any delta store.** The sanitiser-aware BFS sized
   its per-id array by the *live symbol count*, which a delta store's id space
   exceeds. The engine now distinguishes `id_space()` from `symbol_count()`,
   and there is a test that runs the analysis on a delta store and compares
   it with the rebuilt one.
5. **A package stub made its importers neighbours.** Deleting a file that
   happened to be a package's first importer pulled every other importer of
   that package into the neighbourhood, and drained the base. Package rows
   are not a file's symbols and are excluded.
6. **Windows will not let a mapped file be rewritten.** `open_or_build` drops
   its mapping before a rebuild, but a process holding the index open — the
   MCP server — will make a concurrent `index` fail to rebuild the base. Not
   new (the old single-file index had the same property), but recorded.

## Stated limits

A delta is exact for everything except what corpus-wide rules could change in
files that neither changed nor share an edge with a changed file:

- a name becoming unique, or ambiguous, corpus-wide, for a caller elsewhere;
- a type *newly* satisfying an unchanged Go interface (arity is not stored);
- a class newly inheriting an unchanged `Protocol` reads as `inherits`.

Each waits for the next full re-index, which the policy schedules. There is a
test asserting the second one is missed by the delta and found by the rebuild,
so the gap is pinned rather than assumed.

Also: a package stub's displayed path is the file that first imported it, and
after a delta that can be a different file than a full build would pick.
Identity is by name either way; only the path shown differs.

Also: the base's hub cutoff is kept across deltas rather than recomputed; a
delta that shifts the 99th-percentile degree does not move it until the next
rebuild.

## Carried forward

1. **Reachability precision under many added edges.** The bitset fallback is
   sound and cheap, but a long run of edits that add calls lets `A` and `B`
   grow until the filter passes most pairs to BFS. The policy's rebuild
   resets it; a smarter trigger would rebuild when the bitsets' product
   covers too much of the graph.
2. **Distance-bounded reachability**, **framework-aware entrypoints**, and
   **PyO3 bindings**: unchanged from Phase 5.
