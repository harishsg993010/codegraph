# codegraph segment format v1

Status: **pinned for Phase 1**. Changes after Phase 1 require a `format_version` bump
and an entry in the compatibility table at the bottom.

## Design constraints

1. **Readable as typed arrays straight out of the page cache.** No parse step on open. A
   reader `mmap`s the file, validates a header, and casts section bytes to `&[T]`.
2. **Immutable once written.** A segment is never mutated in place. Updates write a new
   segment; deletions flip a bit in a live-set held by the manifest.
3. **Columnar.** A query that needs only `degree` must touch only the `degree` array, not
   stride over a row of unrelated attributes.
4. **Corruption is loud, never silent.** Every section carries a hash; the header carries a
   format version that a reader refuses rather than guesses at.

## Conventions

- **Endianness: little-endian only.** Every target we support (x86-64, aarch64, on Linux /
  macOS / Windows) is LE. A big-endian reader must *refuse* the file, not byte-swap it —
  silently swapping would make a corrupt file look readable. The header carries a byte-order
  mark so this is detected rather than assumed.
- **Alignment: every section starts on a 64-byte boundary.** That is a cache line on every
  target and satisfies the alignment of every POD we store, so the cast to `&[T]` is always
  legal. Padding between sections is zero-filled.
- **All POD structs are `#[repr(C)]`** and validated with `zerocopy`'s `FromBytes` /
  `Immutable` derives. A cast that would be misaligned or short returns an error.
- **Offsets are absolute** from the start of the file, as `u64`.
- **Hashes are blake3, truncated to the low 64 bits.** Full 256-bit hashes cost 4× the table
  space for no benefit here — this detects corruption and truncation, it is not an integrity
  guarantee against an adversary who can rewrite the whole file.

## File layout

```
+--------------------------------------------------+  0
| Header (64 bytes, fixed)                          |
+--------------------------------------------------+  64
| Section 0 payload            (64-byte aligned)    |
| Section 1 payload            (64-byte aligned)    |
| ...                                               |
+--------------------------------------------------+
| Section table  (SectionEntry * n)                 |
+--------------------------------------------------+
| Footer (32 bytes, fixed)                          |
+--------------------------------------------------+  EOF
```

The section table sits near the end, not the start, so a writer can stream section payloads
without knowing their lengths in advance — it learns each length as it finishes writing, and
emits the table last. The footer is fixed-size so a reader can seek to `len - 32` and find it
without scanning.

### Header — 64 bytes at offset 0

| offset | size | field | notes |
|---|---|---|---|
| 0 | 8 | `magic` | `b"CGSEG\0\0\0"` |
| 8 | 4 | `format_version` | `1`. A reader refuses anything it does not know. |
| 12 | 4 | `byte_order` | `0x01020304` written LE. A reader that reads `0x04030201` is big-endian and must refuse. |
| 16 | 8 | `segment_id` | unique within a store; assigned by the writer from the manifest generation counter |
| 24 | 1 | `tier` | `0 = ast`, `1 = semantic` |
| 25 | 1 | `flags` | bit 0: reverse CSR present. bit 1: sorted by `SymbolKey`. |
| 26 | 2 | `_pad` | zero |
| 28 | 4 | `node_count` | |
| 32 | 8 | `edge_count` | |
| 40 | 8 | `created_unix_nanos` | informational only; never used for correctness |
| 48 | 16 | `_reserved` | zero |

### Footer — 32 bytes at `len - 32`

| offset | size | field |
|---|---|---|
| 0 | 8 | `table_offset` |
| 8 | 8 | `table_len` (bytes) |
| 16 | 8 | `table_hash` (blake3-64 of the table bytes) |
| 24 | 8 | `magic_tail` = `b"CGSEGEND"` |

A file whose tail magic is absent was truncated mid-write. That is the expected shape of a
crash during a build, and the reader treats it as "this segment does not exist" — the manifest
will not reference it anyway.

### Section table entry — 40 bytes

```rust
#[repr(C)]
struct SectionEntry {
    kind:       u16,   // SectionKind
    flags:      u16,   // bit 0: payload is compressed (reserved, unused in v1)
    item_count: u32,   // elements, not bytes
    offset:     u64,   // absolute
    len:        u64,   // bytes, excluding trailing alignment padding
    hash:       u64,   // blake3-64 of payload[..len]
    _reserved:  u64,
}
```

Entries are sorted by `kind`, so a reader can binary-search. A `kind` a reader does not
recognise is **skipped, not an error** — that is what lets a v1 reader open a file a later
writer produced with extra sections, as long as `format_version` still reads 1.

## Sections

`SectionKind` is a `u16`. Values are permanent once assigned; a retired section leaves a hole.

### 0x0001 `Strings`

```
payload: [u8]                       // concatenated UTF-8, no separators
```

### 0x0002 `StringOffsets`

```
payload: [u32; n+1]                 // offsets into Strings; string i is [o[i], o[i+1])
```

`StrId(u32)` indexes this. Two-section split rather than length-prefixed strings so the
offsets array is a dense scannable column of its own. Strings are **deduplicated within a
segment** and sorted by first use, not lexically — lexical sorting would help nothing here and
would cost a sort over the whole arena.

### 0x0010 `Files`

```rust
#[repr(C)]
struct FileRow {
    path:         u32,   // StrId, repo-relative, forward slashes, NFC-normalised
    lang:         u8,    // Language enum
    flags:        u8,
    _pad:         u16,
    content_hash: u64,   // blake3-64 of file bytes
    mtime_nanos:  i64,
    size:         u64,
}   // 32 bytes
```

`FileId(u32)` indexes this. Paths are stored repo-relative and NFC-normalised at write time:
absolute paths would make the store non-portable, and macOS's NFD spelling would otherwise make
the same file look like two.

### 0x0020–0x002F `Node*` columns

All node columns have `node_count` elements and are indexed by `LocalId(u32)`.

| kind | name | type | notes |
|---|---|---|---|
| 0x0020 | `NodeKey` | `[u128]` | the `SymbolKey`. Sorted ascending when header flag bit 1 is set, which lets lookup binary-search without the global table. |
| 0x0021 | `NodeFile` | `[u32]` | `FileId` |
| 0x0022 | `NodeName` | `[u32]` | `StrId`, the symbol name as written |
| 0x0023 | `NodeNormName` | `[u32]` | `StrId`, case- and diacritic-folded, `()` stripped — precomputed because every lookup path needs it and folding per query is pure waste |
| 0x0024 | `NodeKind` | `[u8]` | `SymbolKind` enum (function, class, module, package, …) |
| 0x0025 | `NodeFileType` | `[u8]` | code / document / paper / image / rationale / concept |
| 0x0026 | `NodeLine` | `[u32]` | 1-based; `0` means "no location" |
| 0x0027 | `NodeDefFile` | `[u32]` | `FileId` of the definition when it differs from `NodeFile` (header/impl split); `u32::MAX` = same |
| 0x0028 | `NodeDefLine` | `[u32]` | |
| 0x0027 | `NodeHash` | `[u64]` | a hash of the definition's source text with whitespace collapsed (`codegraph_extract::definition_hash`); `0` when not recorded. What `diff` compares to tell an edit from a move. Absent in segments written before it existed; readers treat absence as all zeros. |
| 0x0029 | `NodeFlags` | `[u8]` | bit 0 file-node, bit 1 callable, bit 2 external/stub, bit 3 entrypoint, bit 4 proxy — a stand-in, owned by the file that wrote it, for a symbol defined elsewhere; its `stands_for` edge names the symbol and the view reads its edges as the symbol's |
| 0x002A | `NodeRepo` | `[u16]` | index into the manifest's repo table |

Community, degree, and centrality are **not** here — they are derived, not extracted, and live
in the index sections written at compaction (0x0060+). Keeping them out of the segment means a
freshly written segment is never stale with respect to them.

### 0x0030–0x003F `Edge*` — forward CSR

| kind | name | type | notes |
|---|---|---|---|
| 0x0030 | `EdgeFwdOffsets` | `[u64; node_count+1]` | CSR row offsets |
| 0x0031 | `EdgeFwdTarget` | `[u32; edge_count]` | `LocalId` within this segment, or `u32::MAX` for an external target — see `EdgeExt` |
| 0x0032 | `EdgeFwdRel` | `[u8; edge_count]` | `Relation` enum. **Inline, not a side table** — relation-masked traversal is the hot path for taint, blast-radius and cycle detection, and it must be a byte compare during CSR iteration. |
| 0x0033 | `EdgeFwdConf` | `[u8; edge_count]` | confidence enum |
| 0x0034 | `EdgeFwdFlags` | `[u8; edge_count]` | bit 0 `deferred`, bit 1 `type_only`, bit 2 `external` |
| 0x0035 | `EdgeFwdLine` | `[u32; edge_count]` | the call/import **site**, in the source's own file — not the target's definition line |
| 0x0036 | `EdgeFwdContext` | `[u32; edge_count]` | `StrId`, `u32::MAX` = none |

Within one row, edges are sorted by `(rel, target)`. That makes a relation-masked scan a
contiguous sub-slice found by binary search rather than a filter over the whole row — the
difference matters on a hub node with tens of thousands of edges.

### 0x0040–0x0043 `EdgeRev*` — reverse CSR

Same column set, transposed. Written **only at compaction** (header flag bit 0), because
building it needs the whole segment's edge list and a freshly flushed segment does not have a
stable `LocalId` ordering yet. Reverse blast-radius and reverse reachability both need it.

### 0x0050 `EdgeExt` — cross-segment edges

```rust
#[repr(C)]
struct ExtEdge {
    source:  u32,    // LocalId in this segment
    rel:     u8,
    conf:    u8,
    flags:   u8,
    _pad:    u8,
    line:    u32,
    context: u32,    // StrId
    target:  u128,   // unresolved SymbolKey
}   // 32 bytes
```

An edge whose target is not in this segment. Compaction resolves these through the global
`SymbolKey` table and promotes them into the CSR; until then a query resolves them on the fly.
This is what lets a single file be re-indexed without touching the segments its symbols point at.

### 0x0051 `Hyperedges` / 0x0052 `HyperedgeMembers`

```rust
#[repr(C)]
struct HyperedgeRow {
    id:            u128,  // SymbolKey-shaped, so members and hyperedges share one keyspace
    label:         u32,   // StrId
    rel:           u8,
    conf:          u8,
    _pad:          u16,
    member_offset: u32,   // into HyperedgeMembers
    member_len:    u32,
    file:          u32,   // FileId
}   // 32 bytes
```

`HyperedgeMembers` is `[u32]` of `LocalId`, a flat run-length arena — the same shape as CSR,
for the same reason.

### 0x0060+ — derived index sections

Written at compaction only, never by a flush. Documented in `docs/index-format.md` once
Phase 2 pins them: degree, sampled betweenness, community, SCC id, GRAIL interval labels,
MinHash signature, FST, trigram postings.

They live in **separate files** keyed by manifest generation, not in the segment, because they
are rebuilt on a different cadence than segments are written. Putting them in the segment would
force a segment rewrite every time a derived statistic changed.

## What is deliberately *not* in the format

- **No WAL, no journal.** A build is idempotent and re-derivable from the source tree. A crash
  mid-write leaves a segment with no footer magic, which the manifest never referenced.
- **No per-key tombstones.** Deletion is a bitmap flip in the manifest's live-set.
- **No compression in v1.** The `SectionEntry.flags` bit is reserved for it. Columns of small
  integers compress well, but every scheme costs a decode step on read, and "no decode on read"
  is the whole point. Revisit only with a measured win on a real corpus.
- **No in-segment mutability.** Every field above is write-once.

## Compatibility

| format_version | change | readers |
|---|---|---|
| 1 | initial | — |
