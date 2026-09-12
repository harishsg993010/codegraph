# Phase 2 — index and query results

Exit criterion was: *the full read surface answered from the store, with
recorded p50/p99 latencies*. Met. 135 tests, clippy-clean.

---

## What exists now

| crate | contents |
|---|---|
| `codegraph-store` | **+ compaction**: merges live segments, sorts by `SymbolKey`, promotes external edges into the CSR, builds the reverse CSR |
| `codegraph-index` | degree columns and the hub percentile, Tarjan SCC, GRAIL reachability labels, name index, trigram postings |
| `codegraph-query` | lookup (key/name/prefix/substring), k-hop walk, blast radius, shortest path, taint reachability, hubs, stats, tiered ranking |

## Latency — the exit criterion

`rsl-siege-manager`, 1,886 symbols / 3,876 edges, release build:

| operation | p50 | p99 |
|---|---|---|
| lookup by key | 0.2 µs | 1.6 µs |
| lookup by exact name | 0.5 µs | 1.6 µs |
| lookup by prefix | 0.9 µs | 8.6 µs |
| substring search | 15.3 µs | 589 µs |
| neighbours (1 hop) | 0.5 µs | 3.8 µs |
| k-hop walk (depth 3) | 0.7 µs | 7.5 µs |
| blast radius (depth 2) | 0.5 µs | 9.1 µs |
| shortest path | 1.0 µs | 5.5 µs |
| taint — rejected pair | 0.1 µs | 1.7 µs |
| taint — connecting pair | 1.3 µs | 2.8 µs |
| top-10 hubs | 11.0 µs | 35.1 µs |
| edge histogram | 14.2 µs | 15.4 µs |

Build side: import 68 ms, compact 45 ms, index 23 ms, store open 1.4 ms.

Target was single-digit *milliseconds*; these are single-digit *microseconds*.
Read that as "the shape is right", not as a headline: this corpus fits in L2, so
these numbers say the data structures are correct and allocation-free on the hot
path, not that they hold at 5M symbols. The scale test is still owed.

Both halves of the taint query are reported deliberately. Most random pairs are
unreachable and the label filter answers those without searching (0.1 µs);
quoting only that would flatter the design, so the connecting case — which
actually runs a bidirectional BFS — is measured separately.

## Reachability, validated against brute force

The GRAIL filter gives an exact *negative* and a "maybe" positive. Both
properties were checked against BFS on every corpus:

| corpus | unreachable pairs tested | rejected |
|---|---|---|
| `httpx` | 20,486 | 99.3% |
| `karpathy-repos` | 30,595 | 99.7% |
| `mixed-corpus` | 433 | 99.1% |
| `rsl-siege-manager` | 197,818 | 98.2% |

Zero false negatives — a false negative would make a taint query silently miss a
real path, which is the worst failure this crate could have, so it is asserted
exhaustively rather than sampled.

The real-data rate (98–99.7%) is much better than the synthetic estimate (93.7%)
because real call graphs are sparse and modular. The `k` parameter was chosen
from a measured curve rather than guessed; the table lives in `grail.rs` and the
`calibration` test reproduces it. On call-graph-shaped input the curve flattens
after `k = 3` — going from 4 to 12 buys 1.0 percentage point for three times the
space. On uniformly random DAGs it behaves quite differently and is still
climbing at `k = 12`; that column is kept as a caution, because a corpus
dominated by generated code would need re-measuring rather than assuming.

## Design decisions worth recording

**Reverse CSR as a permutation, not a copy.** It stores, per reverse slot, the
index of the corresponding forward edge — one `u32` instead of duplicating
relation, confidence, flags, and line. Half the space, and the two directions
cannot disagree about an edge's attributes because there is only one copy. A
test asserts forward and reverse describe exactly the same edge set.

**Sorted arrays instead of an FST and roaring bitmaps.** The plan called for
both. Both are smaller; both require a decode step on read. "No decode on read"
is the premise the whole store is built on, and a sorted `[u32]` mmaps directly
as a typed slice. The `fst` dependency was added and then removed once this was
clear.

**Deletion-by-ownership pays off here.** Compaction drops a superseded row by
checking whether the manifest still names its segment as the owner of its file's
tier — no tombstones to scan, no reference counting.

**`in_edges` errors rather than returning empty** when a segment has no reverse
CSR. "Not built" and "no incoming edges" are very different answers, and
conflating them would make a blast-radius query silently return nothing.

## Two bugs the tests caught

**The reachability filter applied to masks it does not cover.** The labels are
built over flow relations only, but `shortest_path` consulted them for *any*
mask — so a `contains` edge at distance 1 was reported as "no path". Caught by
the brute-force comparison on `httpx`, not by any unit test, because it needed a
real graph containing an edge outside the flow mask. The fix is a coverage check
(`RelationMask::is_subset_of`); the filter now only runs when the index actually
covers the query. There is a named regression test.

This is the failure mode this whole layer is most exposed to: an index that
answers a slightly different question than the one asked, and silently returns
fewer results rather than erroring.

**A test that tested nothing.** The multi-segment guard did
`json.replace("nodes", "nodes")` — a no-op — so the second import superseded the
first and the store never had two segments. Clippy's `replacing text with
itself` caught it. It now rewrites the source paths so the two segments cover
different files, and asserts the precondition before asserting the behaviour.

## Not built yet (deferred, with reasons)

- **Index persistence.** The index is rebuilt at open — 23 ms for 1,886 symbols.
  That does not scale: the plan promises a millisecond cold open, and rebuilding
  SCC plus labels plus postings over 5M symbols will not be milliseconds. The
  `.cgix` file is the next piece of work, not an optional extra.
- **Betweenness, MinHash, communities, file-level projection.** In the capability
  matrix, not yet built. None of them block the security layer, which is why they
  were deprioritised behind reachability.
- **Store-wide `SymbolKey` table.** No longer needed for a compacted store —
  `find_symbol` binary-searches the sorted key column, which is why compaction
  sets `KEYS_SORTED`. It comes back if a store ever holds several segments at
  query time.
- **Partial compaction.** `compact` merges everything into one segment. Fine at
  this scale; a large store wants tiered merging so a one-file change does not
  rewrite gigabytes.

## Carried into Phase 3

1. **Persist the index.** Cold open is the promise most at risk.
2. **Run the scale test.** Every latency number here is from a corpus that fits
   in cache. The 5M-symbol synthetic store is what turns these into evidence.
3. **`compact` rewrites the whole store.** Acceptable now, not at scale, and the
   incremental story is what the segment design exists to enable.
