# Phase 1 — `codegraph-store` results

Exit criterion was: *import a real corpus, round-trip it, verify it*. Met on all
four golden corpora. 72 tests across the workspace.

---

## What exists now

| crate | what it is |
|---|---|
| `codegraph-core` | `SymbolKey`/`FileId`/`LocalId`/`StrId`, and the closed vocabularies (`Relation`, `SymbolKind`, `FileType`, `Confidence`) with pinned on-disk discriminants |
| `codegraph-store` | segment writer + mmap reader, forward CSR, manifest with atomic generation swap, ownership-based liveness, node-link importer |
| `codegraph-verify` | snapshots and diffs **either** a node-link index **or** a store, so the round-trip is provable rather than asserted |

## Exit criterion

Every corpus imported into a fresh store and read back produces a snapshot
identical to the source:

| corpus | symbols | edges | files | diff |
|---|---|---|---|---|
| `httpx` | 144 | 330 | 7 | clean |
| `karpathy-repos` | 145 | 206 | 27 | clean |
| `mixed-corpus` | 22 | 38 | 3 | clean |
| `rsl-siege-manager` | 1,886 | 3,876 | 222 | clean |

Plus: a store reopens with identical contents, re-importing supersedes rather
than accumulates (and the dead segment file is reclaimable), key minting is
deterministic across independent imports, and every imported store passes its
own checksums.

## Size

| corpus | JSON | store | B/item (JSON → store) | ratio |
|---|---|---|---|---|
| `httpx` | 144 KB | 16.5 KB | 305 → 35 | 8.7× |
| `karpathy-repos` | 124 KB | 21.0 KB | 294 → 50 | 5.9× |
| `mixed-corpus` | 18 KB | 4.4 KB | 307 → 73 | 4.2× |
| `rsl-siege-manager` | 2.00 MB | 328 KB | 356 → 57 | 6.3× |

**Read this as a floor, not the projection.** The plan's ~26 B/item target
assumes scale; these corpora are small enough that fixed costs dominate — 18
sections × 64-byte alignment, plus a string arena that cannot amortise when
almost every symbol has a unique name. The 6.3× on the largest corpus is the
honest number to quote today; whether the projection holds is a Phase 2 question
once a corpus big enough to amortise exists.

## Design decisions worth recording

**Ownership, not tombstones.** A segment is immutable, so "this file changed"
cannot be an edit. The manifest instead records per `(file, tier)` which segment
owns those rows; writing a new segment moves ownership and the old rows are
dead. The tier semantics then come free — re-parsing a file moves only its `ast`
ownership, so LLM-derived `semantic` rows keep pointing at the segment that
produced them, with no graph rewrite and no tier-scoped filter pass.

**Externals stay out of the CSR.** An edge whose target is not in this segment
is held in `EdgeExt` with its target's `SymbolKey` unresolved, rather than
occupying a CSR slot with a sentinel. That keeps the CSR dense and is what lets
one file be re-indexed without touching the segments its symbols point at.

**Edges sorted by `(source, rel, target)`.** Within a row, one relation's edges
are a contiguous sub-slice, so a relation-masked scan can binary-search to it
instead of filtering the whole row — which is the difference that matters on a
hub node with tens of thousands of edges.

**The vocabularies are not `FromBytes`.** The first cut derived zerocopy traits
on `Relation` and friends. That is unsound: a `u8` of 200 is not a valid
variant, so claiming every bit pattern is valid would be a hole. Columns store
raw `u8` and convert at the boundary, where an unrecognised value becomes
`Unknown` rather than a conjured variant.

**Durability ordering.** A segment is written and `sync_all`'d before the
manifest names it; the manifest is written and synced before `CURRENT` names it.
A crash at any point leaves `CURRENT` pointing at a generation that is fully on
disk, with at worst an unreferenced segment or manifest — both inert, both swept
later. Directory fsync is best-effort by design: POSIX wants it, Windows has no
equivalent, and failing a commit over it would make the store unusable there.

## Two bugs the tests caught

**A mask inconsistency, caught by an invariant test.** `depends_on` was in the
taint mask but not the blast-radius mask. If a vulnerable dependency propagates
taint to our code, then a change to that dependency reaches it too. The test
asserts the containment relationship rather than the membership lists, so it
caught a case I had not thought about.

**Quadratic disambiguation, caught by a number that looked wrong.** The importer
probed disambiguators from zero on every collision, so placing a group of 33
identically-named symbols cost 528 hash computations — and the reported
"collisions" count was measuring probe attempts, not collisions. It now
remembers the next free disambiguator per base key: linear, and the count reads
32, matching the independent harness exactly. The wrong number was the only
symptom; the quadratic behaviour was invisible at this corpus size and would
have surfaced as a mysterious import slowdown at scale.

## Not built yet (deferred, with reasons)

- **Reverse CSR.** Needs a stable `LocalId` ordering across the whole segment
  set, which is a compaction concern. Blast-radius and reverse reachability need
  it; both are Phase 2.
- **Compaction.** `sweep_dead_segments` reclaims whole dead segments, which is
  enough while every import writes one segment. Merging partially-dead segments
  and promoting `EdgeExt` into the CSR arrives with Phase 2's index build.
- **Store-wide `SymbolKey` table.** `Store::find_symbol` is linear over
  segments — correct, and adequate for a handful. The O(1) mmap'd table is an
  index concern.
- **Hyperedges and side-tables.** Sections are reserved in the format; nothing
  produces them until the extractor and the semantic tier exist.

## Carried into Phase 2

1. The `26 B/item` projection is unverified. Measure it on a corpus large enough
   to amortise the string arena before repeating it as a target.
2. `find_symbol` linear-scans segments. That is the first thing the index build
   should replace.
3. Reverse CSR and `EdgeExt` promotion are both compaction work, and compaction
   does not exist yet — it should be built alongside the index, not after.
