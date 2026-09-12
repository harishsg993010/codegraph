//! Segment write → mmap → read round-trips, and the corruption paths.

use codegraph_core::{
    Confidence, FileType, LocalId, Relation, RelationMask, SymbolKey, SymbolKeyParts, SymbolKind,
};
use codegraph_store::format::{Tier, edge_flags, node_flags};
use codegraph_store::{Edge, Segment, SegmentBuilder, Symbol};

fn key(path: &str, scope: &[&str], name: &str) -> SymbolKey {
    SymbolKey::new(SymbolKeyParts {
        repo: "",
        path,
        kind: SymbolKind::Function,
        scope,
        name,
        disambiguator: 0,
    })
}

fn sym<'a>(k: SymbolKey, name: &'a str, line: u32) -> Symbol<'a> {
    Symbol {
        key: k,
        file: codegraph_core::FileId::new(0),
        name,
        norm_name: name,
        kind: SymbolKind::Function,
        file_type: FileType::Code,
        line,
        flags: 0,
        hash: 0,
    }
}

/// Write a builder to a temp file and map it back.
fn round_trip(b: SegmentBuilder) -> (tempfile::TempDir, Segment) {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("seg-0.cgseg");
    let mut f = std::fs::File::create(&path).expect("create");
    b.write(&mut f).expect("write");
    drop(f);
    let seg = Segment::open(&path).expect("open");
    (dir, seg)
}

fn bytes_of(b: SegmentBuilder) -> Vec<u8> {
    let mut buf = std::io::Cursor::new(Vec::new());
    b.write(&mut buf).expect("write");
    buf.into_inner()
}

#[test]
fn an_empty_segment_round_trips() {
    let b = SegmentBuilder::new(0, Tier::Ast);
    let (_d, seg) = round_trip(b);
    assert_eq!(seg.node_count(), 0);
    assert_eq!(seg.edge_count(), 0);
    assert_eq!(seg.tier(), Some(Tier::Ast));
    assert!(seg.keys().unwrap().is_empty());
    seg.verify_checksums().unwrap();
}

#[test]
fn symbols_round_trip() {
    let mut b = SegmentBuilder::new(7, Tier::Ast);
    b.add_file("src/a.py", 0, 0xdead_beef, 123, 456);
    let ka = key("src/a.py", &[], "alpha");
    let kb = key("src/a.py", &[], "beta");
    b.add_symbol(sym(ka, "alpha", 10));
    b.add_symbol(sym(kb, "beta", 20));

    let (_d, seg) = round_trip(b);
    assert_eq!(seg.segment_id(), 7);
    assert_eq!(seg.node_count(), 2);

    let keys = seg.keys().unwrap();
    assert_eq!(keys, &[ka, kb]);
    assert_eq!(seg.node_lines().unwrap(), &[10, 20]);

    let names = seg.node_names().unwrap();
    assert_eq!(seg.string(names[0]), "alpha");
    assert_eq!(seg.string(names[1]), "beta");

    assert_eq!(seg.files().unwrap().len(), 1);
    assert_eq!(seg.file_path(codegraph_core::FileId::new(0)), "src/a.py");
    assert_eq!(seg.files().unwrap()[0].content_hash, 0xdead_beef);

    assert_eq!(seg.find_symbol(ka).unwrap(), Some(LocalId::new(0)));
    assert_eq!(seg.find_symbol(kb).unwrap(), Some(LocalId::new(1)));
    assert_eq!(seg.find_symbol(key("nope", &[], "x")).unwrap(), None);
    seg.verify_checksums().unwrap();
}

#[test]
fn edges_round_trip_through_the_csr() {
    let mut b = SegmentBuilder::new(0, Tier::Ast);
    let (ka, kb, kc) = (
        key("a.py", &[], "a"),
        key("a.py", &[], "b"),
        key("a.py", &[], "c"),
    );
    let a = b.add_symbol(sym(ka, "a", 1));
    let _ = b.add_symbol(sym(kb, "b", 2));
    let _ = b.add_symbol(sym(kc, "c", 3));
    for (t, r) in [(kb, Relation::Calls), (kc, Relation::Uses)] {
        b.add_edge(Edge {
            source: a,
            target: t,
            rel: r,
            conf: Confidence::Extracted,
            line: 5,
            context: None,
            flags: 0,
        });
    }

    let (_d, seg) = round_trip(b);
    assert_eq!(seg.edge_count(), 2);
    // a has two out-edges; b and c have none.
    assert_eq!(seg.out_range(LocalId::new(0)).unwrap(), 0..2);
    assert_eq!(seg.out_range(LocalId::new(1)).unwrap(), 2..2);
    assert_eq!(seg.out_range(LocalId::new(2)).unwrap(), 2..2);

    let all: Vec<_> = seg.out_edges(LocalId::new(0), RelationMask::ALL).unwrap().collect();
    assert_eq!(all.len(), 2);
    assert!(all.iter().any(|e| e.relation == Relation::Calls && e.target == LocalId::new(1)));
    assert!(all.iter().any(|e| e.relation == Relation::Uses && e.target == LocalId::new(2)));
    assert!(all.iter().all(|e| e.line == 5));
    seg.verify_checksums().unwrap();
}

#[test]
fn the_relation_mask_filters_the_scan() {
    let mut b = SegmentBuilder::new(0, Tier::Ast);
    let (ka, kb, kc) = (key("a", &[], "a"), key("a", &[], "b"), key("a", &[], "c"));
    let a = b.add_symbol(sym(ka, "a", 1));
    b.add_symbol(sym(kb, "b", 2));
    b.add_symbol(sym(kc, "c", 3));
    b.add_edge(Edge { source: a, target: kb, rel: Relation::Calls, conf: Confidence::Extracted, line: 1, context: None, flags: 0 });
    b.add_edge(Edge { source: a, target: kc, rel: Relation::Contains, conf: Confidence::Extracted, line: 2, context: None, flags: 0 });

    let (_d, seg) = round_trip(b);
    // `contains` is nesting, not flow, so the taint mask must exclude it.
    let taint: Vec<_> = seg.out_edges(LocalId::new(0), Relation::TAINT).unwrap().collect();
    assert_eq!(taint.len(), 1);
    assert_eq!(taint[0].relation, Relation::Calls);

    let none: Vec<_> = seg.out_edges(LocalId::new(0), RelationMask::EMPTY).unwrap().collect();
    assert!(none.is_empty());
}

#[test]
fn an_unresolved_target_becomes_an_external_edge() {
    let mut b = SegmentBuilder::new(0, Tier::Ast);
    let ka = key("a", &[], "a");
    let elsewhere = key("other/pkg.py", &[], "helper");
    let a = b.add_symbol(sym(ka, "a", 1));
    b.add_edge(Edge { source: a, target: elsewhere, rel: Relation::Calls, conf: Confidence::Inferred, line: 3, context: None, flags: 0 });

    let (_d, seg) = round_trip(b);
    // Not in the CSR...
    assert_eq!(seg.edge_count(), 0);
    // ...but preserved, with its key intact for compaction to resolve.
    let ext = seg.ext_edges().unwrap();
    assert_eq!(ext.len(), 1);
    assert_eq!(ext[0].target, elsewhere);
    assert_eq!(ext[0].source, 0);
    assert!(ext[0].flags & edge_flags::EXTERNAL != 0);
}

/// An extractor legitimately emits a call before it walks the callee's
/// definition. That edge must still land in the CSR, not be exiled as external.
#[test]
fn a_target_added_after_its_edge_still_resolves_locally() {
    let mut b = SegmentBuilder::new(0, Tier::Ast);
    let (ka, kb) = (key("a", &[], "a"), key("a", &[], "b"));
    let a = b.add_symbol(sym(ka, "a", 1));
    b.add_edge(Edge { source: a, target: kb, rel: Relation::Calls, conf: Confidence::Extracted, line: 1, context: None, flags: 0 });
    b.add_symbol(sym(kb, "b", 2)); // target arrives late

    let (_d, seg) = round_trip(b);
    assert_eq!(seg.edge_count(), 1, "late-resolved edge was exiled to EdgeExt");
    assert!(seg.ext_edges().unwrap().is_empty());
    let e: Vec<_> = seg.out_edges(LocalId::new(0), RelationMask::ALL).unwrap().collect();
    assert_eq!(e[0].target, LocalId::new(1));
}

#[test]
fn adding_a_symbol_twice_is_idempotent() {
    let mut b = SegmentBuilder::new(0, Tier::Ast);
    let k = key("a", &[], "a");
    let first = b.add_symbol(sym(k, "a", 1));
    let second = b.add_symbol(sym(k, "a", 1));
    assert_eq!(first, second);
    assert_eq!(b.symbol_count(), 1);
}

#[test]
fn strings_are_interned() {
    let mut b = SegmentBuilder::new(0, Tier::Ast);
    for i in 0..50 {
        b.add_symbol(sym(key("a", &[], &format!("s{i}")), "same_name", i));
    }
    let (_d, seg) = round_trip(b);
    let names = seg.node_names().unwrap();
    // 50 symbols, one distinct name: every row points at the same StrId.
    assert!(names.iter().all(|n| *n == names[0]));
    assert_eq!(seg.string(names[0]), "same_name");
}

#[test]
fn context_strings_and_flags_survive() {
    let mut b = SegmentBuilder::new(0, Tier::Ast);
    let (ka, kb) = (key("a", &[], "a"), key("a", &[], "b"));
    let a = b.add_symbol(sym(ka, "a", 1));
    b.add_symbol(sym(kb, "b", 2));
    b.add_edge(Edge {
        source: a,
        target: kb,
        rel: Relation::DynamicImport,
        conf: Confidence::Ambiguous,
        line: 42,
        context: Some("await import('./b')"),
        flags: edge_flags::DEFERRED,
    });

    let (_d, seg) = round_trip(b);
    let ctx = seg.fwd_contexts().unwrap();
    assert_eq!(seg.string(codegraph_core::StrId::new(ctx[0])), "await import('./b')");
    assert_eq!(seg.fwd_flags().unwrap()[0], edge_flags::DEFERRED);
    assert_eq!(seg.fwd_confs().unwrap()[0], Confidence::Ambiguous.as_u8());
    assert_eq!(seg.fwd_lines().unwrap()[0], 42);
}

#[test]
fn node_flags_survive() {
    let mut b = SegmentBuilder::new(0, Tier::Ast);
    let mut s = sym(key("a", &[], "main"), "main", 1);
    s.flags = node_flags::CALLABLE | node_flags::ENTRYPOINT;
    b.add_symbol(s);
    let (_d, seg) = round_trip(b);
    let f = seg.node_flags().unwrap()[0];
    assert!(f & node_flags::CALLABLE != 0);
    assert!(f & node_flags::ENTRYPOINT != 0);
    assert!(f & node_flags::FILE_NODE == 0);
}

/// Two builds of identical input must produce identical bytes. Without this a
/// content-addressed store cannot tell "rebuilt" from "changed".
#[test]
fn writing_is_deterministic() {
    let build = || {
        let mut b = SegmentBuilder::new(3, Tier::Ast);
        b.add_file("src/a.py", 0, 1, 2, 3);
        for i in 0..20u32 {
            let k = key("src/a.py", &[], &format!("f{i}"));
            b.add_symbol(sym(k, "n", i));
        }
        let src = LocalId::new(0);
        for i in 1..20u32 {
            b.add_edge(Edge {
                source: src,
                target: key("src/a.py", &[], &format!("f{i}")),
                rel: Relation::Calls,
                conf: Confidence::Extracted,
                line: i,
                context: None,
                flags: 0,
            });
        }
        b
    };
    let a = bytes_of(build());
    let c = bytes_of(build());
    // The timestamp is the one field allowed to differ; blank it before
    // comparing rather than weakening the check to a length comparison.
    let blank = |mut v: Vec<u8>| {
        v[40..48].fill(0);
        v
    };
    assert_eq!(blank(a), blank(c), "identical input produced different bytes");
}

#[test]
fn sections_are_64_byte_aligned() {
    let mut b = SegmentBuilder::new(0, Tier::Ast);
    b.add_symbol(sym(key("a", &[], "a"), "a", 1));
    let (_d, seg) = round_trip(b);
    // If any section were misaligned the typed casts below would fail.
    seg.keys().unwrap();
    seg.node_lines().unwrap();
    seg.fwd_offsets().unwrap();
    seg.verify_checksums().unwrap();
}

// --- corruption paths ---

fn write_bytes(dir: &tempfile::TempDir, name: &str, bytes: &[u8]) -> std::path::PathBuf {
    let p = dir.path().join(name);
    std::fs::write(&p, bytes).expect("write");
    p
}

#[test]
fn a_flipped_byte_fails_the_checksum() {
    let mut b = SegmentBuilder::new(0, Tier::Ast);
    b.add_symbol(sym(key("a", &[], "alpha"), "alpha", 1));
    let mut bytes = bytes_of(b);
    // Corrupt inside the string arena, which starts right after the header.
    bytes[HEADER + 1] ^= 0xff;

    let dir = tempfile::tempdir().unwrap();
    let p = write_bytes(&dir, "seg.cgseg", &bytes);
    // Opening still succeeds — open validates structure, not payload, because
    // hashing every section would defeat the point of mmap.
    let seg = Segment::open(&p).expect("structurally valid");
    assert!(seg.verify_checksums().is_err(), "corruption went undetected");
}

const HEADER: usize = 64;

#[test]
fn a_truncated_segment_is_rejected() {
    let mut b = SegmentBuilder::new(0, Tier::Ast);
    b.add_symbol(sym(key("a", &[], "a"), "a", 1));
    let bytes = bytes_of(b);
    let dir = tempfile::tempdir().unwrap();

    // Chop the footer: the shape a crash mid-build leaves behind.
    let p = write_bytes(&dir, "cut.cgseg", &bytes[..bytes.len() - 8]);
    let err = Segment::open(&p).unwrap_err().to_string();
    assert!(err.contains("truncated") || err.contains("checksum"), "got: {err}");
}

#[test]
fn a_foreign_file_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let p = write_bytes(&dir, "junk.cgseg", &vec![0u8; 256]);
    let err = Segment::open(&p).unwrap_err().to_string();
    assert!(err.contains("magic"), "got: {err}");
}

#[test]
fn a_too_short_file_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let p = write_bytes(&dir, "tiny.cgseg", b"CGSEG");
    assert!(Segment::open(&p).is_err());
}

#[test]
fn a_future_format_version_is_refused_not_guessed_at() {
    let mut b = SegmentBuilder::new(0, Tier::Ast);
    b.add_symbol(sym(key("a", &[], "a"), "a", 1));
    let mut bytes = bytes_of(b);
    bytes[8..12].copy_from_slice(&99u32.to_le_bytes());
    let dir = tempfile::tempdir().unwrap();
    let p = write_bytes(&dir, "future.cgseg", &bytes);
    let err = Segment::open(&p).unwrap_err().to_string();
    assert!(err.contains("99"), "got: {err}");
}

#[test]
fn a_foreign_byte_order_is_refused() {
    let mut b = SegmentBuilder::new(0, Tier::Ast);
    b.add_symbol(sym(key("a", &[], "a"), "a", 1));
    let mut bytes = bytes_of(b);
    // Byte-swap the BOM, as a big-endian writer would have left it.
    let bom = u32::from_le_bytes(bytes[12..16].try_into().unwrap());
    bytes[12..16].copy_from_slice(&bom.swap_bytes().to_le_bytes());
    let dir = tempfile::tempdir().unwrap();
    let p = write_bytes(&dir, "be.cgseg", &bytes);
    let err = Segment::open(&p).unwrap_err().to_string();
    assert!(err.contains("byte order"), "got: {err}");
}

#[test]
fn a_corrupt_section_table_is_caught_at_open() {
    let mut b = SegmentBuilder::new(0, Tier::Ast);
    b.add_symbol(sym(key("a", &[], "a"), "a", 1));
    let mut bytes = bytes_of(b);
    // The table sits immediately before the 32-byte footer.
    let n = bytes.len();
    bytes[n - 40] ^= 0xff;
    let dir = tempfile::tempdir().unwrap();
    let p = write_bytes(&dir, "badtable.cgseg", &bytes);
    let err = Segment::open(&p).unwrap_err().to_string();
    assert!(err.contains("checksum") || err.contains("table"), "got: {err}");
}

/// The definition hash column round-trips.
#[test]
fn definition_hashes_round_trip() {
    use codegraph_core::{FileType, SymbolKey, SymbolKeyParts, SymbolKind};
    use codegraph_store::{SegmentBuilder, Symbol, Tier};
    let mut b = SegmentBuilder::new(1, Tier::Ast);
    let f = b.add_file("a.py", 1, 1, 0, 1);
    let key = SymbolKey::new(SymbolKeyParts { repo: "", path: "a.py", kind: SymbolKind::Function, scope: &[], name: "f", disambiguator: 0 });
    b.add_symbol(Symbol { key, file: f, name: "f", norm_name: "f", kind: SymbolKind::Function, file_type: FileType::Code, line: 1, flags: 0, hash: 0xdead_beef });
    let (_dir, seg) = round_trip(b);
    assert_eq!(seg.node_hashes().unwrap(), &[0xdead_beef]);
}
