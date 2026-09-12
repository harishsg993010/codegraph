//! The memory-mapped index reader.
//!
//! Every accessor returns a slice borrowed from the mapping, so opening an
//! index is a syscall rather than a read. That is what keeps residency
//! page-cache-bound at scale: the owned path copies roughly half a gigabyte of
//! columns onto the heap for a 5M-symbol store, which is the one place the
//! project was not following its own zero-copy rule.

use std::path::Path;

use codegraph_store::format::{SectionEntry, hash64};
use memmap2::Mmap;
use zerocopy::FromBytes;

use crate::persist::{
    BYTE_ORDER_MARK, FOOTER_LEN, FORMAT_VERSION, Footer, HEADER_LEN, Header, IndexFileError, MAGIC,
    MAGIC_TAIL, Result, io_err, kind,
};
use crate::view::IndexColumns;

/// A mapped container: the header and the section extents, validated once.
pub(crate) struct Container {
    pub(crate) map: Mmap,
    pub(crate) header: Header,
    /// `(kind, start, end)` byte extents, resolved once at open so an accessor
    /// is a binary search plus a slice rather than a re-parse.
    pub(crate) sections: Vec<(u16, usize, usize)>,
}

impl Container {
    pub(crate) fn raw(&self, k: u16) -> &[u8] {
        match self.sections.binary_search_by_key(&k, |(kind, _, _)| *kind) {
            Ok(i) => {
                let (_, s, e) = self.sections[i];
                &self.map[s..e]
            }
            Err(_) => &[],
        }
    }

    /// Cast a section to `&[u32]`. An empty slice on failure rather than a
    /// panic: the shape check at open already rejected a malformed file, so
    /// reaching here means the section is genuinely absent.
    pub(crate) fn u32s(&self, k: u16) -> &[u32] {
        <[u32]>::ref_from_bytes(self.raw(k)).unwrap_or(&[])
    }

    pub(crate) fn u64s(&self, k: u16) -> &[u64] {
        <[u64]>::ref_from_bytes(self.raw(k)).unwrap_or(&[])
    }

    /// Verify every section against its recorded checksum.
    ///
    /// Reads the whole file, so this is an fsck operation rather than
    /// something `open` does.
    pub(crate) fn verify_checksums(&self) -> Result<()> {
        let footer_at = self.map.len() - FOOTER_LEN;
        let footer = Footer::read_from_bytes(&self.map[footer_at..])
            .map_err(|_| IndexFileError::Corrupt("footer is not readable".into()))?;
        let (start, len) = (footer.table_offset as usize, footer.table_len as usize);
        let entries = <[SectionEntry]>::ref_from_bytes(&self.map[start..start + len])
            .map_err(|_| IndexFileError::Corrupt("section table is misaligned".into()))?;
        for e in entries {
            let bytes = &self.map[e.offset as usize..(e.offset + e.len) as usize];
            if hash64(bytes) != e.hash {
                return Err(IndexFileError::Corrupt(format!(
                    "section {:#06x} failed its checksum",
                    e.kind
                )));
            }
        }
        Ok(())
    }
}

/// Map and validate a container. Checks everything but the generation, which
/// is the caller's policy: a base index is useful across generations.
pub(crate) fn open_container(path: &Path) -> Result<Container> {
    let file = std::fs::File::open(path)
        .map_err(|e| io_err(format!("opening {}", path.display()), e))?;
    // SAFETY: an index file is written whole and never mutated in place; a
    // new generation writes a new file.
    let map = unsafe { Mmap::map(&file) }
        .map_err(|e| io_err(format!("mapping {}", path.display()), e))?;

    if map.len() < HEADER_LEN + FOOTER_LEN {
        return Err(IndexFileError::Corrupt("file is too short to be an index".into()));
    }
    let header = Header::read_from_bytes(&map[..HEADER_LEN])
        .map_err(|_| IndexFileError::Corrupt("header is not readable".into()))?;
    if header.magic != MAGIC {
        return Err(IndexFileError::Corrupt("not a codegraph index (bad magic)".into()));
    }
    if header.byte_order != BYTE_ORDER_MARK {
        return Err(IndexFileError::Corrupt("index byte order is not this platform's".into()));
    }
    if header.format_version != FORMAT_VERSION {
        return Err(IndexFileError::UnsupportedVersion {
            found: header.format_version,
            supported: FORMAT_VERSION,
        });
    }

    let footer_at = map.len() - FOOTER_LEN;
    let footer = Footer::read_from_bytes(&map[footer_at..])
        .map_err(|_| IndexFileError::Corrupt("footer is not readable".into()))?;
    if footer.magic_tail != MAGIC_TAIL {
        return Err(IndexFileError::Corrupt("index is truncated".into()));
    }
    let (start, len) = (footer.table_offset as usize, footer.table_len as usize);
    let end = start
        .checked_add(len)
        .filter(|e| *e <= footer_at)
        .ok_or_else(|| IndexFileError::Corrupt("section table runs past the footer".into()))?;
    let table_bytes = &map[start..end];
    if hash64(table_bytes) != footer.table_hash {
        return Err(IndexFileError::Corrupt("section table failed its checksum".into()));
    }
    let entries = <[SectionEntry]>::ref_from_bytes(table_bytes)
        .map_err(|_| IndexFileError::Corrupt("section table is misaligned".into()))?;

    // Extents are validated here, once, so no accessor has to re-check and
    // a malformed index fails at open rather than deep inside a query.
    //
    // Section *payloads* are deliberately not checksummed here: that would
    // read the whole file and defeat the mapping. `verify_checksums` does
    // it on demand.
    let mut sections = Vec::with_capacity(entries.len());
    for e in entries {
        let (s, n) = (e.offset as usize, e.len as usize);
        let stop = s.checked_add(n).filter(|x| *x <= start).ok_or_else(|| {
            IndexFileError::Corrupt(format!("section {:#06x} is out of range", e.kind))
        })?;
        sections.push((e.kind, s, stop));
    }
    sections.sort_unstable_by_key(|(k, _, _)| *k);
    Ok(Container { map, header, sections })
}

pub struct MappedIndex {
    c: Container,
}

impl std::fmt::Debug for MappedIndex {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MappedIndex")
            .field("symbols", &self.c.header.node_count)
            .field("components", &self.c.header.scc_count)
            .field("generation", &self.c.header.generation)
            .field("bytes", &self.c.map.len())
            .finish()
    }
}

impl MappedIndex {
    /// Open, refusing an index built for a different generation.
    pub fn open(path: &Path, expected_generation: u64) -> Result<Self> {
        let m = Self::open_any(path)?;
        if m.generation() != expected_generation {
            return Err(IndexFileError::Stale {
                found: m.generation(),
                expected: expected_generation,
            });
        }
        Ok(m)
    }

    /// Open whatever generation the file holds. The caller decides whether
    /// it is usable — as the base of an overlay, an older generation is.
    pub fn open_any(path: &Path) -> Result<Self> {
        let c = open_container(path)?;
        if c.header.base_generation != 0 {
            return Err(IndexFileError::Corrupt("this is an overlay, not a base index".into()));
        }
        let m = Self { c };
        m.check_shape()?;
        Ok(m)
    }

    /// Cross-check the columns against the header, so a mismatch surfaces at
    /// open rather than as an out-of-bounds index inside a query.
    fn check_shape(&self) -> Result<()> {
        let n = self.node_count();
        for (label, len) in [
            ("degree_out", self.degree_out().len()),
            ("degree_in", self.degree_in().len()),
            ("degree_total", self.degree_total().len()),
            ("scc_of", self.scc_of().len()),
        ] {
            if len != n {
                return Err(IndexFileError::Corrupt(format!(
                    "{label} holds {len} entries, header says {n}"
                )));
            }
        }
        if self.grail_labels().len() != self.grail_k() * self.scc_count() * 2 {
            return Err(IndexFileError::Corrupt(
                "grail labels do not match k * components".into(),
            ));
        }
        if self.name_offsets().len() != self.name_count() + 1 {
            return Err(IndexFileError::Corrupt(
                "name offsets do not match the key count".into(),
            ));
        }
        if self.trigram_offsets().len() != self.trigram_keys().len() + 1 {
            return Err(IndexFileError::Corrupt(
                "trigram offsets do not match the key count".into(),
            ));
        }
        Ok(())
    }

    fn u32s(&self, k: u16) -> &[u32] {
        self.c.u32s(k)
    }

    /// Verify every section against its recorded checksum. An fsck, not
    /// something `open` does.
    pub fn verify_checksums(&self) -> Result<()> {
        self.c.verify_checksums()
    }

    pub fn generation(&self) -> u64 {
        self.c.header.generation
    }

    /// The segment this index numbers its rows by, if it was built over one.
    pub fn segment_id(&self) -> Option<u64> {
        (self.c.header.segment_id != crate::persist::NO_SEGMENT).then_some(self.c.header.segment_id)
    }

    /// Bytes mapped. Address space, not resident memory.
    pub fn mapped_bytes(&self) -> usize {
        self.c.map.len()
    }
}

impl IndexColumns for MappedIndex {
    fn node_count(&self) -> usize {
        self.c.header.node_count as usize
    }
    fn scc_count(&self) -> usize {
        self.c.header.scc_count as usize
    }
    fn hub_threshold(&self) -> u32 {
        self.c.header.hub_threshold
    }
    fn degree_out(&self) -> &[u32] {
        self.u32s(kind::DEGREE_OUT)
    }
    fn degree_in(&self) -> &[u32] {
        self.u32s(kind::DEGREE_IN)
    }
    fn degree_total(&self) -> &[u32] {
        self.u32s(kind::DEGREE_TOTAL)
    }
    fn scc_of(&self) -> &[u32] {
        self.u32s(kind::SCC_OF)
    }
    fn grail_k(&self) -> usize {
        self.c.header.grail_k as usize
    }
    fn grail_labels(&self) -> &[u32] {
        self.u32s(kind::GRAIL_LABELS)
    }
    fn name_count(&self) -> usize {
        self.u32s(kind::NAME_KEY_OFFSETS).len().saturating_sub(1)
    }
    fn name_key(&self, i: usize) -> &str {
        let offsets = self.u32s(kind::NAME_KEY_OFFSETS);
        if i + 1 >= offsets.len() {
            return "";
        }
        let bytes = self.c.raw(kind::NAME_BYTES);
        let (a, b) = (offsets[i] as usize, offsets[i + 1] as usize);
        if b > bytes.len() || a > b {
            return "";
        }
        // Written from `&str`, so this is valid UTF-8 unless the file is
        // corrupt — in which case an empty key beats a panic in a reader.
        std::str::from_utf8(&bytes[a..b]).unwrap_or("")
    }
    fn name_offsets(&self) -> &[u32] {
        self.u32s(kind::NAME_OFFSETS)
    }
    fn name_postings(&self) -> &[u32] {
        self.u32s(kind::NAME_POSTINGS)
    }
    fn trigram_keys(&self) -> &[u32] {
        self.u32s(kind::TRIGRAM_KEYS)
    }
    fn trigram_offsets(&self) -> &[u32] {
        self.u32s(kind::TRIGRAM_OFFSETS)
    }
    fn trigram_postings(&self) -> &[u32] {
        self.u32s(kind::TRIGRAM_POSTINGS)
    }
}
