//! Building a segment.
//!
//! A caller adds files, symbols, and edges in any order; [`SegmentBuilder::write`]
//! sorts what needs sorting, builds the CSR, and emits the sections. Nothing is
//! written until then, because CSR construction needs the whole edge list.

use std::collections::HashMap;
use std::io::{self, Seek, Write};

use codegraph_core::{Confidence, FileId, LocalId, Relation, StrId, SymbolKey, SymbolKind};
use zerocopy::IntoBytes;

use crate::format::*;

/// Interns strings, returning a stable [`StrId`] per distinct value.
#[derive(Default)]
struct StringArena {
    bytes: Vec<u8>,
    offsets: Vec<u32>,
    seen: HashMap<Box<str>, StrId>,
}

impl StringArena {
    fn new() -> Self {
        // The offsets array is `n+1` long: entry `i` spans `[o[i], o[i+1])`,
        // so it always carries a trailing end offset.
        Self { offsets: vec![0], ..Default::default() }
    }

    fn intern(&mut self, s: &str) -> StrId {
        if let Some(&id) = self.seen.get(s) {
            return id;
        }
        let id = StrId::new(u32::try_from(self.offsets.len() - 1).expect("string count < 2^32"));
        self.bytes.extend_from_slice(s.as_bytes());
        self.offsets.push(u32::try_from(self.bytes.len()).expect("string arena < 4 GiB"));
        self.seen.insert(s.into(), id);
        id
    }

    fn get(&self, id: StrId) -> &str {
        let (a, b) = (self.offsets[id.index()] as usize, self.offsets[id.index() + 1] as usize);
        std::str::from_utf8(&self.bytes[a..b]).expect("interned from a str")
    }

    fn len(&self) -> usize {
        self.offsets.len() - 1
    }
}

/// An edge before CSR construction, while its target may still be unresolved.
#[derive(Clone, Copy)]
struct PendingEdge {
    source: LocalId,
    /// Resolved within this segment, or [`None`] when only the key is known.
    target_local: Option<LocalId>,
    target_key: SymbolKey,
    rel: u8,
    conf: u8,
    flags: u8,
    line: u32,
    context: StrId,
}

/// A symbol to add to the segment.
#[derive(Debug, Clone)]
pub struct Symbol<'a> {
    pub key: SymbolKey,
    pub file: FileId,
    /// The name as written in the source.
    pub name: &'a str,
    /// Case- and diacritic-folded name. Precomputed here because every lookup
    /// path needs it and folding per query is pure waste.
    pub norm_name: &'a str,
    pub kind: SymbolKind,
    pub file_type: codegraph_core::FileType,
    /// 1-based; `0` means "no location recorded".
    pub line: u32,
    pub flags: u8,
    /// See `NodeHash`. `0` = not recorded.
    pub hash: u64,
}

/// An edge to add. The target is given as a [`SymbolKey`] whether or not it
/// lives in this segment — the builder resolves it if it can.
#[derive(Debug, Clone)]
pub struct Edge<'a> {
    pub source: LocalId,
    pub target: SymbolKey,
    pub rel: Relation,
    pub conf: Confidence,
    /// The call/import **site**, in the source's own file — not the target's
    /// definition line.
    pub line: u32,
    pub context: Option<&'a str>,
    pub flags: u8,
}

#[derive(Default)]
pub struct SegmentBuilder {
    tier: u8,
    segment_id: u64,
    strings: StringArena,
    files: Vec<FileRow>,

    keys: Vec<SymbolKey>,
    node_file: Vec<FileId>,
    node_name: Vec<StrId>,
    node_norm: Vec<StrId>,
    node_kind: Vec<u8>,
    node_ftype: Vec<u8>,
    node_line: Vec<u32>,
    node_flags: Vec<u8>,
    node_hash: Vec<u64>,

    edges: Vec<PendingEdge>,
    by_key: HashMap<SymbolKey, LocalId>,
    /// Emit the reverse CSR. Off by default: building it needs the whole edge
    /// list sorted a second way, which is wasted work for a freshly extracted
    /// segment that compaction is about to rewrite anyway.
    build_reverse: bool,
}

impl SegmentBuilder {
    pub fn new(segment_id: u64, tier: Tier) -> Self {
        Self {
            tier: tier as u8,
            segment_id,
            strings: StringArena::new(),
            ..Default::default()
        }
    }

    pub fn add_file(
        &mut self,
        path: &str,
        lang: u8,
        content_hash: u64,
        mtime_nanos: i64,
        size: u64,
    ) -> FileId {
        let path = self.strings.intern(path);
        let id = FileId::new(u32::try_from(self.files.len()).expect("file count < 2^32"));
        self.files.push(FileRow {
            path,
            lang,
            flags: 0,
            _pad: 0,
            content_hash,
            mtime_nanos,
            size,
        });
        id
    }

    /// Add a symbol, or return the existing [`LocalId`] if this key is already
    /// present. Idempotent on purpose: an extractor that emits the same symbol
    /// twice must not create two rows the CSR would then disagree about.
    pub fn add_symbol(&mut self, s: Symbol<'_>) -> LocalId {
        if let Some(&existing) = self.by_key.get(&s.key) {
            return existing;
        }
        let id = LocalId::new(u32::try_from(self.keys.len()).expect("symbol count < 2^32"));
        let name = self.strings.intern(s.name);
        let norm = self.strings.intern(s.norm_name);
        self.keys.push(s.key);
        self.node_file.push(s.file);
        self.node_name.push(name);
        self.node_norm.push(norm);
        self.node_kind.push(s.kind.as_u8());
        self.node_ftype.push(s.file_type.as_u8());
        self.node_line.push(s.line);
        self.node_flags.push(s.flags);
        self.node_hash.push(s.hash);
        self.by_key.insert(s.key, id);
        id
    }

    pub fn add_edge(&mut self, e: Edge<'_>) {
        let context = e.context.map_or(StrId::NONE, |c| self.strings.intern(c));
        self.edges.push(PendingEdge {
            source: e.source,
            target_local: self.by_key.get(&e.target).copied(),
            target_key: e.target,
            rel: e.rel.as_u8(),
            conf: e.conf.as_u8(),
            flags: e.flags,
            line: e.line,
            context,
        });
    }

    /// Emit the reverse CSR alongside the forward one. Compaction sets this;
    /// an extraction flush does not.
    pub fn with_reverse_csr(mut self, yes: bool) -> Self {
        self.build_reverse = yes;
        self
    }

    pub fn segment_id(&self) -> u64 {
        self.segment_id
    }
    pub fn symbol_count(&self) -> usize {
        self.keys.len()
    }
    pub fn edge_count(&self) -> usize {
        self.edges.len()
    }
    pub fn lookup(&self, key: SymbolKey) -> Option<LocalId> {
        self.by_key.get(&key).copied()
    }

    /// The name of an already-added symbol.
    pub fn name_of(&self, local: LocalId) -> Option<&str> {
        self.node_name.get(local.index()).map(|&s| self.strings.get(s))
    }

    /// The kind of an already-added symbol.
    pub fn kind_of(&self, local: LocalId) -> Option<SymbolKind> {
        self.node_kind.get(local.index()).map(|&k| SymbolKind::from_u8(k))
    }

    /// The key of an already-added symbol. Edges are addressed by key so the
    /// builder can resolve them itself, and a caller that holds a `LocalId`
    /// needs this to go back the other way.
    pub fn key_of(&self, local: LocalId) -> Option<SymbolKey> {
        self.keys.get(local.index()).copied()
    }

    /// Resolve edges whose target was added *after* the edge itself.
    ///
    /// `add_edge` resolves eagerly, but an extractor legitimately emits a call
    /// before it walks the callee's definition. Without this pass those edges
    /// would be written as external even though the target is right here, and
    /// every traversal would miss them until compaction.
    fn resolve_late_targets(&mut self) {
        for e in &mut self.edges {
            if e.target_local.is_none() {
                e.target_local = self.by_key.get(&e.target_key).copied();
            }
        }
    }

    /// Sort, build CSR, emit. Consumes the builder.
    pub fn write<W: Write + Seek>(mut self, out: &mut W) -> io::Result<()> {
        self.resolve_late_targets();

        let n = self.keys.len();

        // Split resolved from external. The CSR holds only resolved edges;
        // externals keep their own source column in `EdgeExt`.
        let (mut internal, external): (Vec<PendingEdge>, Vec<PendingEdge>) =
            self.edges.iter().copied().partition(|e| e.target_local.is_some());

        // Within a row, sort by (rel, target). That makes a relation-masked
        // scan a contiguous sub-slice found by binary search rather than a
        // filter over the whole row — which matters on a hub node with tens of
        // thousands of edges.
        internal.sort_unstable_by_key(|e| {
            (e.source.get(), e.rel, e.target_local.expect("partitioned").get())
        });

        let m = internal.len();
        let mut offsets = vec![0u64; n + 1];
        for e in &internal {
            offsets[e.source.index() + 1] += 1;
        }
        for i in 0..n {
            offsets[i + 1] += offsets[i];
        }

        let mut tgt = Vec::with_capacity(m);
        let mut rel = Vec::with_capacity(m);
        let mut conf = Vec::with_capacity(m);
        let mut eflags = Vec::with_capacity(m);
        let mut eline = Vec::with_capacity(m);
        let mut ectx = Vec::with_capacity(m);
        for e in &internal {
            tgt.push(e.target_local.expect("partitioned").get());
            rel.push(e.rel);
            conf.push(e.conf);
            eflags.push(e.flags);
            eline.push(e.line);
            ectx.push(e.context.get());
        }

        let ext: Vec<ExtEdge> = external
            .iter()
            .map(|e| ExtEdge {
                source: e.source.get(),
                rel: e.rel,
                conf: e.conf,
                flags: e.flags | edge_flags::EXTERNAL,
                _pad: 0,
                line: e.line,
                context: e.context.get(),
                target: e.target_key,
            })
            .collect();

        // Reverse CSR as a permutation into the forward arrays: for each node,
        // the indices of the forward edges that point *at* it. Attributes are
        // then read from the forward columns, so the two directions cannot
        // disagree about an edge.
        let (rev_offsets, rev_source, rev_idx) = if self.build_reverse {
            let mut counts = vec![0u64; n + 1];
            for e in &internal {
                counts[e.target_local.expect("partitioned").index() + 1] += 1;
            }
            for i in 0..n {
                counts[i + 1] += counts[i];
            }
            let mut cursor = counts.clone();
            let mut src = vec![0u32; m];
            let mut idx = vec![0u32; m];
            for (i, e) in internal.iter().enumerate() {
                let t = e.target_local.expect("partitioned").index();
                let slot = cursor[t] as usize;
                cursor[t] += 1;
                src[slot] = e.source.get();
                idx[slot] = i as u32;
            }
            (counts, src, idx)
        } else {
            (Vec::new(), Vec::new(), Vec::new())
        };

        let sorted_keys = self.keys.windows(2).all(|w| w[0] < w[1]);
        let header = Header {
            magic: MAGIC,
            format_version: FORMAT_VERSION,
            byte_order: BYTE_ORDER_MARK,
            segment_id: self.segment_id,
            tier: self.tier,
            flags: (if sorted_keys { header_flags::KEYS_SORTED } else { 0 })
                | (if self.build_reverse { header_flags::HAS_REVERSE_CSR } else { 0 }),
            _pad: [0; 2],
            node_count: u32::try_from(n).expect("symbol count < 2^32"),
            edge_count: m as u64,
            // Informational only; never used for correctness, so a clock that
            // jumps cannot corrupt a read.
            created_unix_nanos: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos() as u64),
            _reserved: [0; 16],
        };

        let mut w = SectionWriter::new(out, &header)?;
        w.section(SectionKind::Strings, self.strings.len(), &self.strings.bytes)?;
        w.section(
            SectionKind::StringOffsets,
            self.strings.offsets.len(),
            self.strings.offsets.as_bytes(),
        )?;
        w.section(SectionKind::Files, self.files.len(), self.files.as_bytes())?;

        w.section(SectionKind::NodeKey, n, self.keys.as_bytes())?;
        w.section(SectionKind::NodeFile, n, self.node_file.as_bytes())?;
        w.section(SectionKind::NodeName, n, self.node_name.as_bytes())?;
        w.section(SectionKind::NodeNormName, n, self.node_norm.as_bytes())?;
        w.section(SectionKind::NodeKind, n, &self.node_kind)?;
        w.section(SectionKind::NodeFileType, n, &self.node_ftype)?;
        w.section(SectionKind::NodeLine, n, self.node_line.as_bytes())?;
        w.section(SectionKind::NodeFlags, n, &self.node_flags)?;
        w.section(SectionKind::NodeHash, n, self.node_hash.as_bytes())?;

        w.section(SectionKind::EdgeFwdOffsets, offsets.len(), offsets.as_bytes())?;
        w.section(SectionKind::EdgeFwdTarget, m, tgt.as_bytes())?;
        w.section(SectionKind::EdgeFwdRel, m, &rel)?;
        w.section(SectionKind::EdgeFwdConf, m, &conf)?;
        w.section(SectionKind::EdgeFwdFlags, m, &eflags)?;
        w.section(SectionKind::EdgeFwdLine, m, eline.as_bytes())?;
        w.section(SectionKind::EdgeFwdContext, m, ectx.as_bytes())?;

        if self.build_reverse {
            w.section(SectionKind::EdgeRevOffsets, rev_offsets.len(), rev_offsets.as_bytes())?;
            w.section(SectionKind::EdgeRevSource, m, rev_source.as_bytes())?;
            w.section(SectionKind::EdgeRevEdgeIdx, m, rev_idx.as_bytes())?;
        }

        w.section(SectionKind::EdgeExt, ext.len(), ext.as_bytes())?;
        w.finish()
    }
}

/// Streams sections, tracking offsets so the table can be emitted last.
struct SectionWriter<'a, W: Write + Seek> {
    out: &'a mut W,
    pos: u64,
    entries: Vec<SectionEntry>,
}

impl<'a, W: Write + Seek> SectionWriter<'a, W> {
    fn new(out: &'a mut W, header: &Header) -> io::Result<Self> {
        out.write_all(header.as_bytes())?;
        Ok(Self { out, pos: HEADER_LEN as u64, entries: Vec::new() })
    }

    fn pad_to_alignment(&mut self) -> io::Result<()> {
        let target = align_up(self.pos as usize) as u64;
        let pad = target - self.pos;
        if pad > 0 {
            // Zero-filled, so a hex dump of a segment has no uninitialised
            // bytes and two builds of identical input are byte-identical.
            self.out.write_all(&vec![0u8; pad as usize])?;
            self.pos = target;
        }
        Ok(())
    }

    fn section(&mut self, kind: SectionKind, item_count: usize, payload: &[u8]) -> io::Result<()> {
        self.pad_to_alignment()?;
        self.entries.push(SectionEntry {
            kind: kind.as_u16(),
            flags: 0,
            item_count: u32::try_from(item_count).expect("item count < 2^32"),
            offset: self.pos,
            len: payload.len() as u64,
            hash: hash64(payload),
            _reserved: 0,
        });
        self.out.write_all(payload)?;
        self.pos += payload.len() as u64;
        Ok(())
    }

    fn finish(mut self) -> io::Result<()> {
        self.pad_to_alignment()?;
        // Sorted by kind so a reader can binary-search the table.
        self.entries.sort_unstable_by_key(|e| e.kind);
        let table = self.entries.as_bytes();
        let footer = Footer {
            table_offset: self.pos,
            table_len: table.len() as u64,
            table_hash: hash64(table),
            magic_tail: MAGIC_TAIL,
        };
        self.out.write_all(table)?;
        self.out.write_all(footer.as_bytes())?;
        self.out.flush()
    }
}
