//! Reading a segment.
//!
//! Open validates the header, footer, and section table, then hands out typed
//! slices that borrow the mapping directly. There is no parse step and no
//! per-row deserialisation: a column access is a bounds check and a cast.

use std::path::Path;

use codegraph_core::{FileId, LocalId, Relation, StrId, SymbolKey};
use memmap2::Mmap;
use zerocopy::FromBytes;

use crate::error::{Result, StoreError};
use crate::format::*;

/// A memory-mapped segment.
///
/// Column accessors return `&[T]` borrowed from the mapping, so reading a
/// million symbol keys copies nothing.
pub struct Segment {
    map: Mmap,
    header: Header,
    entries: Vec<SectionEntry>,
    /// Cached because nearly every accessor needs it and re-deriving it from
    /// the table on each call would dominate a tight loop.
    node_count: usize,
    edge_count: usize,
}

/// Written by hand rather than derived: a derive would try to format the whole
/// mapping, which for a multi-gigabyte segment is not a debug aid.
impl std::fmt::Debug for Segment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Segment")
            .field("segment_id", &self.header.segment_id)
            .field("tier", &self.tier().map(Tier::as_str))
            .field("nodes", &self.node_count)
            .field("edges", &self.edge_count)
            .field("sections", &self.entries.len())
            .field("bytes", &self.map.len())
            .finish()
    }
}

impl Segment {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let file = std::fs::File::open(path)
            .map_err(|e| StoreError::io(format!("opening segment {}", path.display()), e))?;
        // SAFETY: the store is the sole writer, segments are immutable once
        // written, and compaction never truncates a segment a reader has
        // mapped — it writes a new one and drops the old from the manifest.
        let map = unsafe { Mmap::map(&file) }
            .map_err(|e| StoreError::io(format!("mapping segment {}", path.display()), e))?;
        Self::from_map(map)
    }

    fn from_map(map: Mmap) -> Result<Self> {
        if map.len() < HEADER_LEN + FOOTER_LEN {
            return Err(StoreError::Corrupt(format!(
                "segment is {} bytes, shorter than an empty one ({})",
                map.len(),
                HEADER_LEN + FOOTER_LEN
            )));
        }

        let header = Header::read_from_bytes(&map[..HEADER_LEN])
            .map_err(|_| StoreError::Corrupt("header is not readable".into()))?;

        if header.magic != MAGIC {
            return Err(StoreError::Corrupt("not a codegraph segment (bad magic)".into()));
        }
        if header.byte_order != BYTE_ORDER_MARK {
            // Deliberately refuse rather than byte-swap: swapping would make a
            // genuinely corrupt file look readable.
            return Err(StoreError::Corrupt(format!(
                "segment byte order {:#010x} is not this platform's {BYTE_ORDER_MARK:#010x}",
                header.byte_order
            )));
        }
        if header.format_version != FORMAT_VERSION {
            return Err(StoreError::UnsupportedVersion {
                found: header.format_version,
                supported: FORMAT_VERSION,
            });
        }

        let footer_at = map.len() - FOOTER_LEN;
        let footer = Footer::read_from_bytes(&map[footer_at..])
            .map_err(|_| StoreError::Corrupt("footer is not readable".into()))?;
        if footer.magic_tail != MAGIC_TAIL {
            // The expected shape of a crash during a build. The manifest will
            // not reference such a segment anyway.
            return Err(StoreError::Corrupt(
                "segment is truncated (missing tail magic)".into(),
            ));
        }

        let (start, len) = (footer.table_offset as usize, footer.table_len as usize);
        let end = start.checked_add(len).ok_or_else(|| {
            StoreError::Corrupt("section table offset + length overflows".into())
        })?;
        if end > footer_at {
            return Err(StoreError::Corrupt(
                "section table runs past the footer".into(),
            ));
        }
        let table_bytes = &map[start..end];
        if hash64(table_bytes) != footer.table_hash {
            return Err(StoreError::Corrupt("section table failed its checksum".into()));
        }

        let entries = <[SectionEntry]>::ref_from_bytes(table_bytes)
            .map_err(|_| StoreError::Corrupt("section table is misaligned or ragged".into()))?
            .to_vec();

        // Every section must lie inside the file and before the table. Checked
        // once here so no accessor has to re-check, and so a malformed segment
        // fails at open rather than at some later read.
        for e in &entries {
            let s = e.offset as usize;
            let n = e.len as usize;
            let end = s.checked_add(n).ok_or_else(|| {
                StoreError::Corrupt(format!("section {:#06x} extent overflows", e.kind))
            })?;
            if end > start {
                return Err(StoreError::Corrupt(format!(
                    "section {:#06x} runs past the section table",
                    e.kind
                )));
            }
        }

        let node_count = header.node_count as usize;
        let edge_count = header.edge_count as usize;
        Ok(Self { map, header, entries, node_count, edge_count })
    }

    pub fn segment_id(&self) -> u64 {
        self.header.segment_id
    }
    pub fn tier(&self) -> Option<Tier> {
        Tier::from_u8(self.header.tier)
    }
    pub fn node_count(&self) -> usize {
        self.node_count
    }
    pub fn edge_count(&self) -> usize {
        self.edge_count
    }
    pub fn keys_are_sorted(&self) -> bool {
        self.header.flags & header_flags::KEYS_SORTED != 0
    }

    fn find(&self, kind: SectionKind) -> Option<&SectionEntry> {
        let k = kind.as_u16();
        self.entries
            .binary_search_by_key(&k, |e| e.kind)
            .ok()
            .map(|i| &self.entries[i])
    }

    fn raw(&self, kind: SectionKind) -> &[u8] {
        // Extents were validated at open, so an absent section is simply empty
        // — which is the correct answer for, say, `EdgeExt` in a segment with
        // no external edges.
        match self.find(kind) {
            Some(e) => &self.map[e.offset as usize..(e.offset + e.len) as usize],
            None => &[],
        }
    }

    /// Cast a section to a typed slice, checking the element count matches what
    /// the header claims. A column shorter than `node_count` would otherwise
    /// panic later at an index the caller believes is in range.
    fn column<T: FromBytes + zerocopy::Immutable + zerocopy::KnownLayout>(
        &self,
        kind: SectionKind,
        expected: usize,
    ) -> Result<&[T]> {
        let bytes = self.raw(kind);
        if bytes.is_empty() && expected == 0 {
            return Ok(&[]);
        }
        let slice = <[T]>::ref_from_bytes(bytes).map_err(|_| {
            StoreError::Corrupt(format!(
                "section {:#06x} is misaligned or not a whole number of elements",
                kind.as_u16()
            ))
        })?;
        if slice.len() != expected {
            return Err(StoreError::Corrupt(format!(
                "section {:#06x} holds {} elements, header says {expected}",
                kind.as_u16(),
                slice.len()
            )));
        }
        Ok(slice)
    }

    /// Verify every section against its recorded checksum.
    ///
    /// Not done at open: it reads the whole file, which defeats the point of
    /// mmap. Call it from a fsck path or a test.
    pub fn verify_checksums(&self) -> Result<()> {
        for e in &self.entries {
            let bytes = &self.map[e.offset as usize..(e.offset + e.len) as usize];
            if hash64(bytes) != e.hash {
                return Err(StoreError::Corrupt(format!(
                    "section {:#06x} failed its checksum",
                    e.kind
                )));
            }
        }
        Ok(())
    }

    // --- string arena ---

    pub fn string(&self, id: StrId) -> &str {
        if id.is_none() {
            return "";
        }
        let offsets = self.raw(SectionKind::StringOffsets);
        let Ok(offsets) = <[u32]>::ref_from_bytes(offsets) else { return "" };
        let i = id.index();
        if i + 1 >= offsets.len() {
            return "";
        }
        let bytes = self.raw(SectionKind::Strings);
        let (a, b) = (offsets[i] as usize, offsets[i + 1] as usize);
        if b > bytes.len() || a > b {
            return "";
        }
        // Written from `&str`, so this is valid UTF-8 unless the file is
        // corrupt — in which case an empty string beats a panic in a reader.
        std::str::from_utf8(&bytes[a..b]).unwrap_or("")
    }

    // --- files ---

    pub fn files(&self) -> Result<&[FileRow]> {
        let bytes = self.raw(SectionKind::Files);
        if bytes.is_empty() {
            return Ok(&[]);
        }
        <[FileRow]>::ref_from_bytes(bytes)
            .map_err(|_| StoreError::Corrupt("file table is misaligned or ragged".into()))
    }

    pub fn file_path(&self, id: FileId) -> &str {
        match self.files() {
            Ok(f) if !id.is_none() && id.index() < f.len() => self.string(f[id.index()].path),
            _ => "",
        }
    }

    // --- node columns ---

    pub fn keys(&self) -> Result<&[SymbolKey]> {
        self.column(SectionKind::NodeKey, self.node_count)
    }
    pub fn node_files(&self) -> Result<&[FileId]> {
        self.column(SectionKind::NodeFile, self.node_count)
    }
    pub fn node_names(&self) -> Result<&[StrId]> {
        self.column(SectionKind::NodeName, self.node_count)
    }
    pub fn node_norm_names(&self) -> Result<&[StrId]> {
        self.column(SectionKind::NodeNormName, self.node_count)
    }
    pub fn node_kinds(&self) -> Result<&[u8]> {
        self.column(SectionKind::NodeKind, self.node_count)
    }
    pub fn node_file_types(&self) -> Result<&[u8]> {
        self.column(SectionKind::NodeFileType, self.node_count)
    }
    pub fn node_lines(&self) -> Result<&[u32]> {
        self.column(SectionKind::NodeLine, self.node_count)
    }
    /// Definition hashes, or an empty slice for a segment written before the
    /// column existed — the caller treats a missing hash as `0`.
    pub fn node_hashes(&self) -> Result<&[u64]> {
        if self.raw(SectionKind::NodeHash).is_empty() {
            return Ok(&[]);
        }
        self.column(SectionKind::NodeHash, self.node_count)
    }

    pub fn node_flags(&self) -> Result<&[u8]> {
        self.column(SectionKind::NodeFlags, self.node_count)
    }

    /// Find a symbol by key.
    ///
    /// Binary search when the keys column is sorted, linear otherwise. A
    /// freshly flushed segment is usually unsorted; compaction sorts it.
    pub fn find_symbol(&self, key: SymbolKey) -> Result<Option<LocalId>> {
        let keys = self.keys()?;
        let idx = if self.keys_are_sorted() {
            keys.binary_search(&key).ok()
        } else {
            keys.iter().position(|k| *k == key)
        };
        Ok(idx.map(|i| LocalId::new(i as u32)))
    }

    // --- forward CSR ---

    pub fn fwd_offsets(&self) -> Result<&[u64]> {
        self.column(SectionKind::EdgeFwdOffsets, self.node_count + 1)
    }
    pub fn fwd_targets(&self) -> Result<&[u32]> {
        self.column(SectionKind::EdgeFwdTarget, self.edge_count)
    }
    pub fn fwd_rels(&self) -> Result<&[u8]> {
        self.column(SectionKind::EdgeFwdRel, self.edge_count)
    }
    pub fn fwd_confs(&self) -> Result<&[u8]> {
        self.column(SectionKind::EdgeFwdConf, self.edge_count)
    }
    pub fn fwd_flags(&self) -> Result<&[u8]> {
        self.column(SectionKind::EdgeFwdFlags, self.edge_count)
    }
    pub fn fwd_lines(&self) -> Result<&[u32]> {
        self.column(SectionKind::EdgeFwdLine, self.edge_count)
    }
    pub fn fwd_contexts(&self) -> Result<&[u32]> {
        self.column(SectionKind::EdgeFwdContext, self.edge_count)
    }

    /// The half-open CSR range of `node`'s outgoing edges.
    pub fn out_range(&self, node: LocalId) -> Result<std::ops::Range<usize>> {
        let o = self.fwd_offsets()?;
        let i = node.index();
        if i + 1 >= o.len() {
            return Ok(0..0);
        }
        Ok(o[i] as usize..o[i + 1] as usize)
    }

    /// Iterate `node`'s outgoing edges, keeping only relations in `mask`.
    ///
    /// The mask is tested against the raw discriminant byte, so filtering costs
    /// a shift and an AND per edge rather than an enum conversion.
    pub fn out_edges(
        &self,
        node: LocalId,
        mask: codegraph_core::RelationMask,
    ) -> Result<impl Iterator<Item = OutEdge<'_>> + '_> {
        let range = self.out_range(node)?;
        let (t, r, c, f, l, cx) = (
            self.fwd_targets()?,
            self.fwd_rels()?,
            self.fwd_confs()?,
            self.fwd_flags()?,
            self.fwd_lines()?,
            self.fwd_contexts()?,
        );
        Ok(range.filter(move |&i| mask.contains_raw(r[i])).map(move |i| OutEdge {
            target: LocalId::new(t[i]),
            relation: Relation::from_u8(r[i]),
            confidence: codegraph_core::Confidence::from_u8(c[i]),
            flags: f[i],
            line: l[i],
            context: (cx[i] != u32::MAX).then(|| self.string(StrId::new(cx[i]))),
        }))
    }

    // --- reverse CSR ---

    pub fn has_reverse_csr(&self) -> bool {
        self.header.flags & header_flags::HAS_REVERSE_CSR != 0
    }

    pub fn rev_offsets(&self) -> Result<&[u64]> {
        self.column(SectionKind::EdgeRevOffsets, self.node_count + 1)
    }
    /// For each reverse slot, the node the edge came *from*.
    pub fn rev_sources(&self) -> Result<&[u32]> {
        self.column(SectionKind::EdgeRevSource, self.edge_count)
    }
    /// For each reverse slot, the index of the corresponding forward edge —
    /// attributes are read from the forward columns through it.
    pub fn rev_edge_idx(&self) -> Result<&[u32]> {
        self.column(SectionKind::EdgeRevEdgeIdx, self.edge_count)
    }

    /// Iterate the edges pointing *at* `node`, keeping only relations in `mask`.
    ///
    /// This is the blast-radius direction. Returns an error rather than an
    /// empty iterator when the segment has no reverse CSR, so a caller cannot
    /// mistake "not built" for "no incoming edges".
    pub fn in_edges(
        &self,
        node: LocalId,
        mask: codegraph_core::RelationMask,
    ) -> Result<impl Iterator<Item = InEdge<'_>> + '_> {
        if !self.has_reverse_csr() {
            return Err(StoreError::Corrupt(
                "segment has no reverse CSR; compact the store first".into(),
            ));
        }
        let o = self.rev_offsets()?;
        let i = node.index();
        let range = if i + 1 < o.len() { o[i] as usize..o[i + 1] as usize } else { 0..0 };
        let (src, idx) = (self.rev_sources()?, self.rev_edge_idx()?);
        let (r, c, f, l, cx) =
            (self.fwd_rels()?, self.fwd_confs()?, self.fwd_flags()?, self.fwd_lines()?, self.fwd_contexts()?);
        Ok(range
            .filter(move |&s| mask.contains_raw(r[idx[s] as usize]))
            .map(move |s| {
                let e = idx[s] as usize;
                InEdge {
                    source: LocalId::new(src[s]),
                    relation: Relation::from_u8(r[e]),
                    confidence: codegraph_core::Confidence::from_u8(c[e]),
                    flags: f[e],
                    line: l[e],
                    context: (cx[e] != u32::MAX).then(|| self.string(StrId::new(cx[e]))),
                }
            }))
    }

    // --- external edges ---

    pub fn ext_edges(&self) -> Result<&[ExtEdge]> {
        let bytes = self.raw(SectionKind::EdgeExt);
        if bytes.is_empty() {
            return Ok(&[]);
        }
        <[ExtEdge]>::ref_from_bytes(bytes)
            .map_err(|_| StoreError::Corrupt("external edge table is misaligned".into()))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InEdge<'a> {
    pub source: LocalId,
    pub relation: Relation,
    pub confidence: codegraph_core::Confidence,
    pub flags: u8,
    pub line: u32,
    /// See [`OutEdge::context`].
    pub context: Option<&'a str>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OutEdge<'a> {
    pub target: LocalId,
    pub relation: Relation,
    pub confidence: codegraph_core::Confidence,
    pub flags: u8,
    pub line: u32,
    /// The edge's context string: a call's receiver, an import's specifier,
    /// a parameter's position on its `contains` edge.
    pub context: Option<&'a str>,
}
