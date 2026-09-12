# Phase 0 — validation results

Phase 0 exists to kill the plan cheaply if its premises are wrong. They are not.
All four gates pass. Recorded here so later phases have something to regress against.

Environment: Windows 11, 12 logical cores, rustc 1.91.1 (MSVC), tree-sitter 0.27.0.

---

## Gate 1 — grammar availability and ABI compatibility ✅

40 languages load against **one** `tree-sitter` 0.27 runtime.

| result | detail |
|---|---|
| grammars linked | 40 (from 39 crates; `typescript` and `ocaml` each expose several) |
| ABI range observed | **14 – 15** |
| runtime accepts | **13 – 15** |
| headroom | one version below, none above — see risk note |

The decisive finding: **36 of 39 crates depend on `tree-sitter-language ^0.1`**, not on
`tree-sitter` directly. That indirection is what lets grammars pinned to different runtime
versions co-exist, and it is why a single-runtime build is viable at all.

Three crates are on the old direct-dependency scheme and were replaced with maintained forks:

| wanted | problem | used instead |
|---|---|---|
| `tree-sitter-kotlin` 0.3.8 | pins `tree-sitter >=0.21, <0.23` | `tree-sitter-kotlin-ng` 1.1 |
| `tree-sitter-sql` 0.0.2 | pins `tree-sitter ^0.19.3`, 10k downloads | `tree-sitter-sequel` 0.3 |
| `tree-sitter-apex` 1.0.0 | pins `tree-sitter ~0.20.0`, 3.5k downloads | `tree-sitter-sfapex` 3.0 |

Not on crates.io at all — all Tier 3, all handled by lexical extractors as the plan anticipated:
**robot**, **astro**, **dm**. `tree-sitter-vue` exists but is 0.0.3 with 29k downloads and is
treated as unmaintained; Vue will be handled by extracting its embedded script block.

> **Risk to carry forward.** ABI 15 is the runtime's current maximum. A grammar that moves to
> ABI 16 before `tree-sitter` does cannot be upgraded, so grammar bumps must be taken as a set,
> with this probe as the gate. Keep `codegraph-probe` in CI for exactly this reason.

## Gate 2 — parse throughput ✅

Corpus: 18,522 files / 248 MB / 52.1M AST nodes, mixed Python-dominant with JSON/YAML/TOML/MD.

| threads | seconds | files/s | MB/s | Mnodes/s |
|---|---|---|---|---|
| 1 | 86.6 | 214 | 2.9 | 0.60 |
| 12 | 16.2 | **1,146** | 15.4 | 3.22 |

On a Python-only slice (17,328 files) the same build reaches **301 files/s** single-threaded and
**1,510 files/s** on 12 threads.

Target was 500–2,000 files/s. **Met**, and met on the pessimistic path: the probe allocates a
fresh `Parser` per file and walks the entire tree afterwards. Reusing a thread-local parser per
language will recover more.

Two honest caveats:

1. This measures **parse + full tree walk**, not extraction. Emitting symbols and edges and
   running resolution will cost more — assume 2–3×, which still clears the 500 files/s floor.
2. Corpus walk was 0.16 s for 18.5k files, i.e. free. It will not stay free at 1M files, but it
   is not the bottleneck at this scale.

173 of 18,522 files (0.9%) produced a tree containing an error node. Normal for a corpus with
vendored and Python-2-era files; worth watching as a rate, not a count.

## Gate 3 — on-disk format pinned ✅

`docs/segment-format.md`. Immutable segments, footer section table, 64-byte-aligned columnar
sections, `#[repr(C)]` PODs read by casting mmap'd bytes with no parse step. Deletion is a
live-set bitmap flip; there is no WAL because a build is re-derivable from the source tree.

## Gate 4 — verification harness standing ✅

`codegraph-verify` normalises an index into a comparison form and diffs two of them. 11 tests.

It keys on **natural identity**, not the index's own node ids, because ids in this problem space
are derived values that get bulk-rewritten by every resolution pass — a diff keyed on them would
measure the id scheme rather than the extraction. A test asserts that renaming every id in an
index produces a clean diff.

The first draft keyed on `(file, bare name)` and that was wrong: it silently collapsed **26% of
symbols** on a real corpus, because a file with five classes has five `__init__` methods and
extractors label them all `.__init__`. The key now recovers the owning scope from `contains` /
`method` edges, so those become `alpha.__init__` and `beta.__init__`. Any collision that still
survives is counted and printed rather than merged in silence.

Golden-corpus baselines, recorded as the Phase 3 target:

| corpus | symbols | edges | files | dangling | collided |
|---|---|---|---|---|---|
| `httpx` | 144 | 330 | 6 | 0 | 0 |
| `karpathy-repos` | 145 | 206 | 26 | 0 | 32 |
| `mixed-corpus` | 22 | 38 | 3 | 0 | 0 |
| `rsl-siege-manager` | 1,886 | 3,876 | 221 | 0 | 0 |

Three of four round-trip exactly. `karpathy-repos` reports 32 collisions, which are 33
malformed nodes in that corpus carrying an empty label *and* an empty path — a data-quality
finding surfaced by the harness rather than hidden by it.

---

## What Phase 0 changed about the plan

Nothing structural. Three details to carry into Phase 1:

1. **Pin grammars as a set, not individually.** The ABI-15 ceiling makes a lone grammar bump a
   potential break. `codegraph-probe` is the gate and belongs in CI.
2. **Budget 2–3× on the throughput number** when extraction lands, and re-measure rather than
   assuming the parse figure carries.
3. **`SymbolKey` must include the owning scope**, not just `(path, name)`. Gate 4 proved that
   empirically before a line of the store was written: without the scope, 26% of a real corpus
   is not addressable.
