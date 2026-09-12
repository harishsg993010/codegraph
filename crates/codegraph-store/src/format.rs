//! On-disk segment layout. See `docs/segment-format.md` for the rationale.
//!
//! Everything in this module is an on-disk contract. A change to a constant, a
//! struct field, or a `SectionKind` discriminant reinterprets every stored
//! segment, so changes require a [`FORMAT_VERSION`] bump.

use codegraph_core::{FileId, StrId, SymbolKey};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

pub const MAGIC: [u8; 8] = *b"CGSEG\0\0\0";
pub const MAGIC_TAIL: [u8; 8] = *b"CGSEGEND";
pub const FORMAT_VERSION: u32 = 1;

/// Written little-endian. A reader that reads back `0x04030201` is big-endian
/// and must refuse the file rather than byte-swap it: silently swapping would
/// make a genuinely corrupt file look readable.
pub const BYTE_ORDER_MARK: u32 = 0x0102_0304;

/// Every section starts on this boundary. It is a cache line on every target we
/// support and exceeds the alignment of every POD below, so casting mmap'd
/// bytes to `&[T]` is always legal.
pub const SECTION_ALIGN: usize = 64;

pub const HEADER_LEN: usize = 64;
pub const FOOTER_LEN: usize = 32;

/// Which tier produced a segment. Deterministic parsing and LLM-derived
/// enrichment have different costs and lifetimes, so they are replaced
/// independently.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Tier {
    Ast = 0,
    Semantic = 1,
}

impl Tier {
    pub const fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Tier::Ast),
            1 => Some(Tier::Semantic),
            _ => None,
        }
    }
    pub const fn as_str(self) -> &'static str {
        match self {
            Tier::Ast => "ast",
            Tier::Semantic => "semantic",
        }
    }
}

pub mod header_flags {
    /// Reverse CSR sections are present (written at compaction only).
    pub const HAS_REVERSE_CSR: u8 = 1 << 0;
    /// `NodeKey` is sorted ascending, so lookup can binary-search the column
    /// without consulting the store-wide key table.
    pub const KEYS_SORTED: u8 = 1 << 1;
}

pub mod edge_flags {
    /// A dynamic `import()` — real at runtime, but it does not form a hard
    /// cycle, so cycle detection excludes it.
    pub const DEFERRED: u8 = 1 << 0;
    /// A type-only import, erased before runtime.
    pub const TYPE_ONLY: u8 = 1 << 1;
    /// Points outside the indexed corpus (a third-party package).
    pub const EXTERNAL: u8 = 1 << 2;
}

pub mod node_flags {
    /// This symbol stands for the file itself.
    pub const FILE_NODE: u8 = 1 << 0;
    /// Callable — guards indirect-call resolution against binding to a data
    /// symbol that merely shares a name.
    pub const CALLABLE: u8 = 1 << 1;
    /// A stub for something outside the corpus; carries no source location.
    pub const EXTERNAL: u8 = 1 << 2;
    /// An entrypoint, for reachability queries.
    pub const ENTRYPOINT: u8 = 1 << 3;
    /// A stand-in, owned by the file that wrote it, for a symbol defined
    /// elsewhere — so that file can record edges *leaving* the symbol. Its
    /// `stands_for` edge names the symbol; the view forwards the proxy to it
    /// and attributes the proxy's edges to it. Lives and dies with its file,
    /// unlike an `EXTERNAL` row; never canonical.
    pub const PROXY: u8 = 1 << 4;
}

/// Section identifiers. **Permanent**: a retired kind leaves a hole rather than
/// being reused. A reader skips a kind it does not recognise, which is what
/// lets a v1 reader open a file a later writer produced.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u16)]
pub enum SectionKind {
    Strings = 0x0001,
    StringOffsets = 0x0002,
    Files = 0x0010,

    NodeKey = 0x0020,
    NodeFile = 0x0021,
    NodeName = 0x0022,
    NodeNormName = 0x0023,
    NodeKind = 0x0024,
    NodeFileType = 0x0025,
    NodeLine = 0x0026,
    /// `[u64]`: a hash of each definition's text (see
    /// `codegraph_extract::definition_hash`), `0` when not recorded. Absent
    /// in segments written before it existed; readers treat absence as all
    /// zeros.
    NodeHash = 0x0027,
    NodeFlags = 0x0029,

    EdgeFwdOffsets = 0x0030,
    EdgeFwdTarget = 0x0031,
    EdgeFwdRel = 0x0032,
    EdgeFwdConf = 0x0033,
    EdgeFwdFlags = 0x0034,
    EdgeFwdLine = 0x0035,
    EdgeFwdContext = 0x0036,

    // Reverse CSR stores a *permutation* into the forward columns rather than
    // copying rel/conf/flags/line: one `u32` per edge instead of ten bytes,
    // and no way for the two directions to disagree about an edge's
    // attributes.
    EdgeRevOffsets = 0x0040,
    EdgeRevSource = 0x0041,
    EdgeRevEdgeIdx = 0x0042,

    EdgeExt = 0x0050,
}

impl SectionKind {
    pub const fn as_u16(self) -> u16 {
        self as u16
    }
}

/// Fixed 64-byte header at offset 0.
#[derive(Debug, Clone, Copy, FromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(C)]
pub struct Header {
    pub magic: [u8; 8],
    pub format_version: u32,
    pub byte_order: u32,
    pub segment_id: u64,
    pub tier: u8,
    pub flags: u8,
    pub _pad: [u8; 2],
    pub node_count: u32,
    pub edge_count: u64,
    pub created_unix_nanos: u64,
    pub _reserved: [u8; 16],
}

/// Fixed 32-byte footer at `len - 32`.
#[derive(Debug, Clone, Copy, FromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(C)]
pub struct Footer {
    pub table_offset: u64,
    pub table_len: u64,
    pub table_hash: u64,
    pub magic_tail: [u8; 8],
}

/// One row of the section table.
#[derive(Debug, Clone, Copy, FromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(C)]
pub struct SectionEntry {
    pub kind: u16,
    pub flags: u16,
    /// Elements, not bytes.
    pub item_count: u32,
    pub offset: u64,
    /// Payload bytes, excluding trailing alignment padding.
    pub len: u64,
    pub hash: u64,
    pub _reserved: u64,
}

/// A file the segment drew symbols from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, FromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(C)]
pub struct FileRow {
    /// Repo-relative, forward slashes, NFC. Never absolute — an absolute path
    /// would make the segment non-portable between checkouts.
    pub path: StrId,
    pub lang: u8,
    pub flags: u8,
    pub _pad: u16,
    pub content_hash: u64,
    pub mtime_nanos: i64,
    pub size: u64,
}

/// An edge whose target is not in this segment.
///
/// Held unresolved rather than dropped: this is what lets one file be
/// re-indexed without touching the segments its symbols point at. Compaction
/// resolves these through the store-wide key table and promotes them into the
/// CSR.
#[derive(Debug, Clone, Copy, PartialEq, Eq, FromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(C)]
pub struct ExtEdge {
    /// `LocalId` in this segment.
    pub source: u32,
    pub rel: u8,
    pub conf: u8,
    pub flags: u8,
    pub _pad: u8,
    pub line: u32,
    pub context: u32,
    /// Unresolved [`SymbolKey`].
    pub target: SymbolKey,
}

/// Round `n` up to the next [`SECTION_ALIGN`] boundary.
#[inline]
pub const fn align_up(n: usize) -> usize {
    n.next_multiple_of(SECTION_ALIGN)
}

/// blake3 truncated to 64 bits. Detects corruption and truncation; it is not an
/// integrity guarantee against an adversary who can rewrite the whole file.
pub fn hash64(bytes: &[u8]) -> u64 {
    let h = blake3::hash(bytes);
    u64::from_le_bytes(h.as_bytes()[..8].try_into().expect("blake3 output is 32 bytes"))
}

/// Compile-time guards. These sizes are on-disk contracts; a field reordered or
/// a padding assumption changed would silently shift every following column.
const _: () = {
    assert!(size_of::<Header>() == HEADER_LEN);
    assert!(size_of::<Footer>() == FOOTER_LEN);
    assert!(size_of::<SectionEntry>() == 40);
    assert!(size_of::<FileRow>() == 32);
    assert!(size_of::<ExtEdge>() == 32);
    assert!(size_of::<SymbolKey>() == 16);
    assert!(size_of::<FileId>() == 4);
    // Every POD must divide the section alignment, or a 64-byte-aligned section
    // start would not guarantee an aligned cast.
    assert!(SECTION_ALIGN.is_multiple_of(align_of::<Header>()));
    assert!(SECTION_ALIGN.is_multiple_of(align_of::<SectionEntry>()));
    assert!(SECTION_ALIGN.is_multiple_of(align_of::<FileRow>()));
    assert!(SECTION_ALIGN.is_multiple_of(align_of::<ExtEdge>()));
    assert!(SECTION_ALIGN.is_multiple_of(align_of::<SymbolKey>()));
    assert!(SECTION_ALIGN.is_multiple_of(align_of::<u64>()));
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alignment_rounds_up() {
        assert_eq!(align_up(0), 0);
        assert_eq!(align_up(1), 64);
        assert_eq!(align_up(64), 64);
        assert_eq!(align_up(65), 128);
    }

    #[test]
    fn hash_is_stable_and_sensitive() {
        assert_eq!(hash64(b"abc"), hash64(b"abc"));
        assert_ne!(hash64(b"abc"), hash64(b"abd"));
        assert_ne!(hash64(b""), hash64(b"\0"));
    }

    /// Section discriminants are on-disk values.
    #[test]
    fn section_kinds_are_pinned() {
        assert_eq!(SectionKind::Strings.as_u16(), 0x0001);
        assert_eq!(SectionKind::Files.as_u16(), 0x0010);
        assert_eq!(SectionKind::NodeKey.as_u16(), 0x0020);
        assert_eq!(SectionKind::EdgeFwdOffsets.as_u16(), 0x0030);
        assert_eq!(SectionKind::EdgeExt.as_u16(), 0x0050);
    }

    #[test]
    fn tier_round_trips() {
        assert_eq!(Tier::from_u8(0), Some(Tier::Ast));
        assert_eq!(Tier::from_u8(1), Some(Tier::Semantic));
        assert_eq!(Tier::from_u8(2), None);
    }

    /// The byte-order mark must be asymmetric, or a big-endian reader could not
    /// tell it was reading a foreign file.
    #[test]
    fn byte_order_mark_is_asymmetric() {
        assert_ne!(BYTE_ORDER_MARK, BYTE_ORDER_MARK.swap_bytes());
    }
}
