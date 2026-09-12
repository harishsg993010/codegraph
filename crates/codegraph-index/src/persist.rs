//! Persisting the index.
//!
//! The index is rebuilt at compaction and read back on every open. Rebuilding
//! it instead costs an SCC pass, `k` DFS traversals, and two posting-list
//! builds over the whole graph — 23 ms at 1,886 symbols, and nowhere near
//! milliseconds at the scale this is aimed at. So it is written once and mmap'd
//! thereafter, exactly like a segment.
//!
//! The container mirrors the segment format: magic, a fixed header, 64-byte
//! aligned sections, a checksummed table, and a tail magic that a truncated
//! write cannot fake. It is written out separately rather than shared with the
//! segment writer because the two have different headers and only ~100 lines in
//! common; if a third format appears, that is the moment to extract a shared
//! container rather than now.

use std::io::{self, Write};
use std::path::Path;

use codegraph_store::format::{SectionEntry, align_up, hash64};
use zerocopy::{FromBytes, IntoBytes};

use crate::build::IndexData;
use crate::grail::Grail;

pub const MAGIC: [u8; 8] = *b"CGIDX\0\0\0";
pub const MAGIC_TAIL: [u8; 8] = *b"CGIDXEND";
/// Version 2 gave the reserved header bytes a meaning (`segment_id`,
/// `base_generation`) and added the overlay sections. A version-1 file is
/// refused and rebuilt; an index is derived data, so that costs a rebuild,
/// never a store.
pub const FORMAT_VERSION: u32 = 2;

/// `segment_id` of an index that was not built over exactly one segment. Such
/// an index answers for its generation but cannot serve as the base of an
/// overlay, because its row numbering is not one segment's.
pub const NO_SEGMENT: u64 = u64::MAX;
pub(crate) const HEADER_LEN: usize = 64;
pub(crate) const FOOTER_LEN: usize = 32;

/// Index file name for a manifest generation. Keyed by generation because the
/// index is a function of the data that generation names; a stale one is
/// therefore identifiable rather than silently wrong.
pub fn index_name(generation: u64) -> String {
    format!("index-{generation:012}.cgidx")
}

#[derive(Debug, Clone, Copy, FromBytes, IntoBytes, zerocopy::Immutable, zerocopy::KnownLayout)]
#[repr(C)]
pub(crate) struct Header {
    pub(crate) magic: [u8; 8],
    pub(crate) format_version: u32,
    pub(crate) byte_order: u32,
    pub(crate) node_count: u64,
    pub(crate) scc_count: u64,
    pub(crate) hub_threshold: u32,
    pub(crate) grail_k: u32,
    /// The manifest generation this index describes. An index whose generation
    /// does not match the store's is stale and must be refused, not used.
    pub(crate) generation: u64,
    /// The one segment this index numbers its rows by, or [`NO_SEGMENT`]. An
    /// overlay records the segment its base was built over, so the pairing
    /// is checked rather than assumed.
    pub(crate) segment_id: u64,
    /// For an overlay: the generation of the base index it extends. `0` for
    /// a base index.
    pub(crate) base_generation: u64,
}

#[derive(Debug, Clone, Copy, FromBytes, IntoBytes, zerocopy::Immutable, zerocopy::KnownLayout)]
#[repr(C)]
pub(crate) struct Footer {
    pub(crate) table_offset: u64,
    pub(crate) table_len: u64,
    pub(crate) table_hash: u64,
    pub(crate) magic_tail: [u8; 8],
}

/// Section ids. Permanent, like the segment's.
pub(crate) mod kind {
    pub const DEGREE_OUT: u16 = 0x0100;
    pub const DEGREE_IN: u16 = 0x0101;
    pub const DEGREE_TOTAL: u16 = 0x0102;
    pub const SCC_OF: u16 = 0x0110;
    pub const GRAIL_LABELS: u16 = 0x0111;
    pub const NAME_BYTES: u16 = 0x0120;
    pub const NAME_KEY_OFFSETS: u16 = 0x0121;
    pub const NAME_OFFSETS: u16 = 0x0122;
    pub const NAME_POSTINGS: u16 = 0x0123;
    pub const TRIGRAM_KEYS: u16 = 0x0130;
    pub const TRIGRAM_OFFSETS: u16 = 0x0131;
    pub const TRIGRAM_POSTINGS: u16 = 0x0132;
    // Overlay-only sections. Base rows whose degree a delta changed, as
    // parallel arrays keyed by row id.
    pub const PATCH_IDS: u16 = 0x0140;
    pub const PATCH_OUT: u16 = 0x0141;
    pub const PATCH_IN: u16 = 0x0142;
    pub const PATCH_TOTAL: u16 = 0x0143;
    // Reachability bitsets over the whole id space: rows that can reach an
    // added edge, rows an added edge can reach.
    pub const REACH_A: u16 = 0x0150;
    pub const REACH_B: u16 = 0x0151;
}

pub(crate) const BYTE_ORDER_MARK: u32 = 0x0102_0304;

#[derive(Debug, thiserror::Error)]
pub enum IndexFileError {
    #[error("{context}: {source}")]
    Io {
        context: String,
        #[source]
        source: io::Error,
    },
    #[error("corrupt index: {0}")]
    Corrupt(String),
    #[error("index format version {found} is not supported (this build reads {supported})")]
    UnsupportedVersion { found: u32, supported: u32 },
    /// The index describes a different generation of the store. Loud, because
    /// serving a stale index would answer questions about data that no longer
    /// exists.
    #[error("index is for generation {found}, store is at {expected}")]
    Stale { found: u64, expected: u64 },
}

pub(crate) type Result<T> = std::result::Result<T, IndexFileError>;

pub(crate) fn io_err(context: impl Into<String>, source: io::Error) -> IndexFileError {
    IndexFileError::Io { context: context.into(), source }
}

/// Write a container: header, aligned sections, checksummed table, footer.
///
/// Written whole, then synced: an index is derived data, so a partial one
/// must be unreadable rather than plausible.
pub(crate) fn write_container(path: &Path, header: &Header, sections: &[(u16, usize, &[u8])]) -> Result<()> {
    let mut buf: Vec<u8> = Vec::new();
    buf.extend_from_slice(header.as_bytes());
    let mut entries: Vec<SectionEntry> = Vec::with_capacity(sections.len());
    for &(k, items, payload) in sections {
        let target = align_up(buf.len());
        buf.resize(target, 0);
        entries.push(SectionEntry {
            kind: k,
            flags: 0,
            item_count: items as u32,
            offset: buf.len() as u64,
            len: payload.len() as u64,
            hash: hash64(payload),
            _reserved: 0,
        });
        buf.extend_from_slice(payload);
    }
    let target = align_up(buf.len());
    buf.resize(target, 0);
    entries.sort_unstable_by_key(|e| e.kind);
    let table_offset = buf.len() as u64;
    let table = entries.as_bytes();
    let footer = Footer {
        table_offset,
        table_len: table.len() as u64,
        table_hash: hash64(table),
        magic_tail: MAGIC_TAIL,
    };
    buf.extend_from_slice(table);
    buf.extend_from_slice(footer.as_bytes());

    let mut f = std::fs::File::create(path)
        .map_err(|e| io_err(format!("creating {}", path.display()), e))?;
    f.write_all(&buf)
        .map_err(|e| io_err(format!("writing {}", path.display()), e))?;
    f.sync_all()
        .map_err(|e| io_err(format!("syncing {}", path.display()), e))?;
    Ok(())
}

/// A name index as two sections: a string blob plus an offsets array, the
/// same shape as the segment's arena, so it mmaps without a per-string
/// allocation on read.
pub(crate) fn name_arena(keys: &[String]) -> (Vec<u8>, Vec<u32>) {
    let mut name_bytes = Vec::new();
    let mut name_key_offsets = Vec::with_capacity(keys.len() + 1);
    name_key_offsets.push(0u32);
    for k in keys {
        name_bytes.extend_from_slice(k.as_bytes());
        name_key_offsets.push(name_bytes.len() as u32);
    }
    (name_bytes, name_key_offsets)
}

impl IndexData {
    /// Write to `path`, tagged with the manifest generation it describes.
    ///
    /// Not layerable: see [`Self::write_base`].
    pub fn write(&self, path: &Path, generation: u64) -> Result<()> {
        self.write_base(path, generation, NO_SEGMENT)
    }

    /// Write to `path` as an index built over exactly `segment_id`, which is
    /// what lets a later generation extend it with an overlay instead of
    /// rebuilding it.
    pub fn write_base(&self, path: &Path, generation: u64, segment_id: u64) -> Result<()> {
        let header = Header {
            magic: MAGIC,
            format_version: FORMAT_VERSION,
            byte_order: BYTE_ORDER_MARK,
            node_count: self.node_count as u64,
            scc_count: self.scc_count as u64,
            hub_threshold: self.hub_threshold,
            grail_k: self.grail.k() as u32,
            generation,
            segment_id,
            base_generation: 0,
        };
        let (name_bytes, name_key_offsets) = name_arena(&self.name_keys);
        write_container(
            path,
            &header,
            &[
                (kind::DEGREE_OUT, self.degree_out.len(), self.degree_out.as_bytes()),
                (kind::DEGREE_IN, self.degree_in.len(), self.degree_in.as_bytes()),
                (kind::DEGREE_TOTAL, self.degree_total.len(), self.degree_total.as_bytes()),
                (kind::SCC_OF, self.scc_of.len(), self.scc_of.as_bytes()),
                (kind::GRAIL_LABELS, self.grail.labels().len(), self.grail.labels().as_bytes()),
                (kind::NAME_BYTES, name_bytes.len(), &name_bytes),
                (kind::NAME_KEY_OFFSETS, name_key_offsets.len(), name_key_offsets.as_bytes()),
                (kind::NAME_OFFSETS, self.name_offsets.len(), self.name_offsets.as_bytes()),
                (kind::NAME_POSTINGS, self.name_postings.len(), self.name_postings.as_bytes()),
                (kind::TRIGRAM_KEYS, self.trigram_keys.len(), self.trigram_keys.as_bytes()),
                (kind::TRIGRAM_OFFSETS, self.trigram_offsets.len(), self.trigram_offsets.as_bytes()),
                (kind::TRIGRAM_POSTINGS, self.trigram_postings.len(), self.trigram_postings.as_bytes()),
            ],
        )
    }


    /// Read back into owned memory, refusing an index built for a different
    /// generation.
    ///
    /// Copies every column onto the heap. Prefer [`crate::MappedIndex::open`],
    /// which costs address space instead — at 5M symbols this path measured
    /// 1.07 s and roughly half a gigabyte of heap. Kept because tests want an
    /// owned, comparable `IndexData`, and because a caller that wants to
    /// *mutate* an index needs one.
    pub fn read(path: &Path, expected_generation: u64) -> Result<Self> {
        use crate::view::IndexColumns;
        let m = crate::mapped::MappedIndex::open(path, expected_generation)?;
        // Payload checksums are verified here but not on the mapped path: an
        // owned read has already paid to touch every byte, so the check is
        // free, whereas doing it on open would defeat the mapping.
        m.verify_checksums()?;
        let grail = Grail::from_labels(m.grail_k(), m.scc_count(), m.grail_labels().to_vec())
            .ok_or_else(|| {
                IndexFileError::Corrupt("grail labels do not match k * components".into())
            })?;
        Ok(Self {
            node_count: m.node_count(),
            degree_out: m.degree_out().to_vec(),
            degree_in: m.degree_in().to_vec(),
            degree_total: m.degree_total().to_vec(),
            hub_threshold: m.hub_threshold(),
            scc_of: m.scc_of().to_vec(),
            scc_count: m.scc_count(),
            grail,
            name_keys: (0..m.name_count()).map(|i| m.name_key(i).to_string()).collect(),
            name_offsets: m.name_offsets().to_vec(),
            name_postings: m.name_postings().to_vec(),
            trigram_keys: m.trigram_keys().to_vec(),
            trigram_offsets: m.trigram_offsets().to_vec(),
            trigram_postings: m.trigram_postings().to_vec(),
        })
    }

}
