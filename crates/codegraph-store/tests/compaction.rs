//! Compaction: sorting, external promotion, reverse CSR, and dead-row drop.

use codegraph_core::{
    Confidence, FileType, LocalId, Relation, RelationMask, SymbolKey, SymbolKeyParts, SymbolKind,
};
use codegraph_store::format::Tier;
use codegraph_store::{Edge, SegmentBuilder, Store, Symbol, compact};

fn key(path: &str, name: &str) -> SymbolKey {
    SymbolKey::new(SymbolKeyParts {
        repo: "",
        path,
        kind: SymbolKind::Function,
        scope: &[],
        name,
        disambiguator: 0,
    })
}

/// Commit one segment holding `syms` (path, name) and `edges` (from, to, rel).
fn commit(
    store: &mut Store,
    syms: &[(&str, &str)],
    edges: &[(&str, &str, &str, &str, Relation)],
) {
    let id = store.next_segment_id();
    let mut b = SegmentBuilder::new(id, Tier::Ast);
    let mut paths: Vec<String> = syms.iter().map(|(p, _)| p.to_string()).collect();
    paths.sort();
    paths.dedup();
    let mut fids = std::collections::HashMap::new();
    for p in &paths {
        fids.insert(p.clone(), b.add_file(p, 0, 0, 0, 0));
    }
    for (p, n) in syms {
        b.add_symbol(Symbol {
            key: key(p, n),
            file: fids[*p],
            name: n,
            norm_name: n,
            kind: SymbolKind::Function,
            file_type: FileType::Code,
            line: 1,
            flags: 0,
            hash: 0,
        });
    }
    for (sp, sn, tp, tn, rel) in edges {
        let src = b.lookup(key(sp, sn)).expect("edge source must exist");
        b.add_edge(Edge {
            source: src,
            target: key(tp, tn),
            rel: *rel,
            conf: Confidence::Extracted,
            line: 1,
            context: None,
            flags: 0,
        });
    }
    store.commit_segment(id, b, Tier::Ast, &paths).expect("commit");
}

#[test]
fn compaction_merges_segments_and_sorts_keys() {
    let dir = tempfile::tempdir().unwrap();
    let mut store = Store::create(dir.path()).unwrap();
    commit(&mut store, &[("a.py", "one"), ("a.py", "two")], &[]);
    commit(&mut store, &[("b.py", "three")], &[]);
    assert_eq!(store.manifest().segments.len(), 2);

    let stats = compact(&mut store).unwrap().expect("should compact");
    assert_eq!(stats.segments_before, 2);
    assert_eq!(stats.segments_after, 1);
    assert_eq!(stats.symbols, 3);

    let (_, seg) = store.segments().next().unwrap();
    assert!(seg.keys_are_sorted(), "compaction must sort the key column");
    assert!(seg.has_reverse_csr(), "compaction must build the reverse CSR");
    let keys = seg.keys().unwrap();
    assert!(keys.windows(2).all(|w| w[0] < w[1]), "keys are not ascending");
}

/// The point of holding externals unresolved: once the target's segment is in
/// hand, the edge becomes a real traversable edge.
#[test]
fn compaction_promotes_a_resolvable_external_edge() {
    let dir = tempfile::tempdir().unwrap();
    let mut store = Store::create(dir.path()).unwrap();
    // a.py calls b.py::helper, which does not exist yet.
    commit(
        &mut store,
        &[("a.py", "caller")],
        &[("a.py", "caller", "b.py", "helper", Relation::Calls)],
    );
    {
        let (_, seg) = store.segments().next().unwrap();
        assert_eq!(seg.edge_count(), 0);
        assert_eq!(seg.ext_edges().unwrap().len(), 1);
    }

    // Now b.py arrives.
    commit(&mut store, &[("b.py", "helper")], &[]);
    let stats = compact(&mut store).unwrap().expect("should compact");
    assert_eq!(stats.promoted, 1, "the external edge should have resolved");
    assert_eq!(stats.still_external, 0);

    let (_, seg) = store.segments().next().unwrap();
    assert_eq!(seg.edge_count(), 1, "promoted edge is not in the CSR");
    assert!(seg.ext_edges().unwrap().is_empty());

    let caller = seg.find_symbol(key("a.py", "caller")).unwrap().unwrap();
    let helper = seg.find_symbol(key("b.py", "helper")).unwrap().unwrap();
    let out: Vec<_> = seg.out_edges(caller, RelationMask::ALL).unwrap().collect();
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].target, helper);
    // The external marker must be cleared, or a promoted edge reads as
    // third-party forever.
    assert_eq!(out[0].flags & codegraph_store::edge_flags::EXTERNAL, 0);
}

#[test]
fn a_genuinely_external_target_stays_external() {
    let dir = tempfile::tempdir().unwrap();
    let mut store = Store::create(dir.path()).unwrap();
    commit(
        &mut store,
        &[("a.py", "caller")],
        &[("a.py", "caller", "site-packages/requests.py", "get", Relation::Calls)],
    );
    let stats = compact(&mut store).unwrap().expect("should compact");
    assert_eq!(stats.promoted, 0);
    assert_eq!(stats.still_external, 1);
    let (_, seg) = store.segments().next().unwrap();
    assert_eq!(seg.ext_edges().unwrap().len(), 1);
}

#[test]
fn the_reverse_csr_finds_incoming_edges() {
    let dir = tempfile::tempdir().unwrap();
    let mut store = Store::create(dir.path()).unwrap();
    commit(
        &mut store,
        &[("a.py", "x"), ("a.py", "y"), ("a.py", "z")],
        &[
            ("a.py", "x", "a.py", "z", Relation::Calls),
            ("a.py", "y", "a.py", "z", Relation::Calls),
            ("a.py", "x", "a.py", "y", Relation::Uses),
        ],
    );
    compact(&mut store).unwrap().expect("should compact");
    let (_, seg) = store.segments().next().unwrap();

    let z = seg.find_symbol(key("a.py", "z")).unwrap().unwrap();
    let x = seg.find_symbol(key("a.py", "x")).unwrap().unwrap();
    let y = seg.find_symbol(key("a.py", "y")).unwrap().unwrap();

    let mut into_z: Vec<_> = seg.in_edges(z, RelationMask::ALL).unwrap().map(|e| e.source).collect();
    into_z.sort_by_key(|l| l.get());
    let mut expect = vec![x, y];
    expect.sort_by_key(|l| l.get());
    assert_eq!(into_z, expect, "z should be called by both x and y");

    // x has nothing pointing at it.
    assert_eq!(seg.in_edges(x, RelationMask::ALL).unwrap().count(), 0);

    // The mask applies in reverse too.
    let calls_only: Vec<_> = seg
        .in_edges(y, RelationMask::of(&[Relation::Calls]))
        .unwrap()
        .collect();
    assert!(calls_only.is_empty(), "the x->y edge is `uses`, not `calls`");
}

/// Forward and reverse must describe exactly the same edge set — the reverse
/// CSR is a permutation, so any disagreement is a construction bug.
#[test]
fn forward_and_reverse_agree() {
    let dir = tempfile::tempdir().unwrap();
    let mut store = Store::create(dir.path()).unwrap();
    let syms: Vec<(String, String)> = (0..30)
        .map(|i| ("m.py".to_string(), format!("s{i}")))
        .collect();
    let sym_refs: Vec<(&str, &str)> =
        syms.iter().map(|(p, n)| (p.as_str(), n.as_str())).collect();
    let mut edge_spec = Vec::new();
    for i in 0..30usize {
        for j in [(i + 1) % 30, (i * 7 + 3) % 30] {
            edge_spec.push((
                sym_refs[i].0,
                sym_refs[i].1,
                sym_refs[j].0,
                sym_refs[j].1,
                if j % 2 == 0 { Relation::Calls } else { Relation::Uses },
            ));
        }
    }
    commit(&mut store, &sym_refs, &edge_spec);
    compact(&mut store).unwrap().expect("compact");
    let (_, seg) = store.segments().next().unwrap();

    let mut fwd = Vec::new();
    let mut rev = Vec::new();
    for i in 0..seg.node_count() {
        let n = LocalId::new(i as u32);
        for e in seg.out_edges(n, RelationMask::ALL).unwrap() {
            fwd.push((i as u32, e.target.get(), e.relation.as_u8()));
        }
        for e in seg.in_edges(n, RelationMask::ALL).unwrap() {
            rev.push((e.source.get(), i as u32, e.relation.as_u8()));
        }
    }
    fwd.sort_unstable();
    rev.sort_unstable();
    assert_eq!(fwd, rev, "forward and reverse describe different edge sets");
    assert_eq!(fwd.len(), seg.edge_count());
}

/// Rows whose file was superseded must not survive compaction.
#[test]
fn compaction_drops_superseded_rows() {
    let dir = tempfile::tempdir().unwrap();
    let mut store = Store::create(dir.path()).unwrap();
    commit(&mut store, &[("a.py", "old_name")], &[]);
    // Re-index a.py with different contents; ownership moves.
    commit(&mut store, &[("a.py", "new_name")], &[]);

    let stats = compact(&mut store).unwrap().expect("compact");
    assert_eq!(stats.symbols, 1, "the superseded row survived compaction");
    let (_, seg) = store.segments().next().unwrap();
    assert!(seg.find_symbol(key("a.py", "new_name")).unwrap().is_some());
    assert!(
        seg.find_symbol(key("a.py", "old_name")).unwrap().is_none(),
        "the old row is still reachable"
    );
}

#[test]
fn compaction_is_idempotent() {
    let dir = tempfile::tempdir().unwrap();
    let mut store = Store::create(dir.path()).unwrap();
    commit(
        &mut store,
        &[("a.py", "x"), ("b.py", "y")],
        &[("a.py", "x", "b.py", "y", Relation::Calls)],
    );
    let first = compact(&mut store).unwrap().expect("first compact");
    assert_eq!(first.segments_after, 1);
    // A second pass has nothing to gain and must say so rather than churn.
    assert!(compact(&mut store).unwrap().is_none(), "compaction churned");
}

#[test]
fn in_edges_without_a_reverse_csr_is_an_error_not_an_empty_answer() {
    let dir = tempfile::tempdir().unwrap();
    let mut store = Store::create(dir.path()).unwrap();
    commit(&mut store, &[("a.py", "x")], &[]);
    let (_, seg) = store.segments().next().unwrap();
    assert!(!seg.has_reverse_csr());
    assert!(
        seg.in_edges(LocalId::new(0), RelationMask::ALL).is_err(),
        "a missing reverse CSR must not read as 'no incoming edges'"
    );
}

#[test]
fn compacted_stores_still_verify() {
    let dir = tempfile::tempdir().unwrap();
    let mut store = Store::create(dir.path()).unwrap();
    commit(
        &mut store,
        &[("a.py", "x"), ("b.py", "y")],
        &[("a.py", "x", "b.py", "y", Relation::Calls)],
    );
    compact(&mut store).unwrap();
    store.verify().expect("compacted store failed its checksums");
}
