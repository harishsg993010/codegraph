//! The store-wide view and tiered compaction: what a query sees once a store
//! holds a base plus deltas, and when the base is rewritten.

use codegraph_core::{
    Confidence, FileType, LocalId, Relation, RelationMask, SymbolKey, SymbolKeyParts, SymbolKind,
};
use codegraph_store::format::Tier;
use codegraph_store::{
    CompactPolicy, Edge, SegmentBuilder, Store, Symbol, compact, compact_tiered, node_flags,
};

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

fn pkg_key(name: &str) -> SymbolKey {
    SymbolKey::new(SymbolKeyParts {
        repo: "",
        path: "",
        kind: SymbolKind::Package,
        scope: &[],
        name,
        disambiguator: 0,
    })
}

/// A symbol to commit: `(path, name, flags)`.
type Sym<'a> = (&'a str, &'a str, u8);
/// An edge to commit: `(from path, from name, to path, to name, rel)`.
type Ed<'a> = (&'a str, &'a str, &'a str, &'a str, Relation);

/// Commit one segment. Package rows (`EXTERNAL` flag) are keyed by name alone
/// and attached to the first path in `syms`, as the resolver does.
fn commit(store: &mut Store, syms: &[Sym], edges: &[Ed]) -> u64 {
    let id = store.next_segment_id();
    let mut b = SegmentBuilder::new(id, Tier::Ast).with_reverse_csr(true);
    let mut paths: Vec<String> = syms
        .iter()
        .filter(|(_, _, f)| f & node_flags::EXTERNAL == 0)
        .map(|(p, _, _)| p.to_string())
        .collect();
    paths.sort();
    paths.dedup();
    let mut fids = std::collections::HashMap::new();
    for p in &paths {
        fids.insert(p.clone(), b.add_file(p, 1, 0xABCD, 7, 99));
    }
    let k = |p: &str, n: &str, f: u8| if f & node_flags::EXTERNAL != 0 { pkg_key(n) } else { key(p, n) };
    for (p, n, f) in syms {
        b.add_symbol(Symbol {
            key: k(p, n, *f),
            file: fids[*p],
            name: n,
            norm_name: n,
            kind: if f & node_flags::EXTERNAL != 0 { SymbolKind::Package } else { SymbolKind::Function },
            file_type: FileType::Code,
            line: 1,
            flags: *f,
            hash: 0,
        });
    }
    let flag_of = |p: &str, n: &str| syms.iter().find(|s| s.0 == p && s.1 == n).map_or(0, |s| s.2);
    for (sp, sn, tp, tn, rel) in edges {
        let src = b.lookup(k(sp, sn, flag_of(sp, sn))).expect("edge source must exist");
        b.add_edge(Edge {
            source: src,
            target: k(tp, tn, flag_of(tp, tn)),
            rel: *rel,
            conf: Confidence::Extracted,
            line: 1,
            context: None,
            flags: 0,
        });
    }
    store.commit_segment(id, b, Tier::Ast, &paths).expect("commit");
    id
}

fn names(store: &Store, ids: &[LocalId]) -> Vec<String> {
    let v = store.view();
    let mut out: Vec<String> = ids.iter().map(|&i| v.name(i).unwrap().to_string()).collect();
    out.sort();
    out
}

/// Every edge the view exposes, as `(source name, target name, rel)`.
fn edge_set(store: &Store) -> Vec<(String, String, Relation)> {
    let v = store.view();
    let mut out = Vec::new();
    for id in v.ids() {
        for e in v.out_edges(id, RelationMask::ALL).unwrap() {
            out.push((v.name(id).unwrap().to_string(), v.name(e.node).unwrap().to_string(), e.relation));
        }
    }
    out.sort();
    out
}

fn base_then_delta(dir: &std::path::Path) -> Store {
    let mut store = Store::create(dir).unwrap();
    commit(
        &mut store,
        &[("a.py", "caller", 0), ("b.py", "helper", 0)],
        &[("a.py", "caller", "b.py", "helper", Relation::Calls)],
    );
    compact(&mut store).unwrap();
    // b.py is re-indexed: same helper, plus a new function.
    commit(
        &mut store,
        &[("b.py", "helper", 0), ("b.py", "extra", 0)],
        &[("b.py", "helper", "b.py", "extra", Relation::Calls)],
    );
    store
}

#[test]
fn a_reindexed_file_is_read_from_its_delta() {
    let dir = tempfile::tempdir().unwrap();
    let store = base_then_delta(dir.path());
    assert_eq!(store.segments().count(), 2, "precondition: base plus delta");

    let v = store.view();
    assert!(!v.is_simple());
    // The live rows are caller (base), helper and extra (delta). The base's
    // dead helper row is numbered but skipped.
    assert_eq!(v.node_count(), 4);
    let live: Vec<LocalId> = v.ids().collect();
    assert_eq!(names(&store, &live), ["caller", "extra", "helper"]);

    let helper = v.find(key("b.py", "helper")).expect("helper");
    let (seg_idx, _) = v.locate(helper).unwrap();
    assert_eq!(seg_idx, 1, "lookup returned the dead base row, not the delta's");
}

#[test]
fn edges_into_a_reindexed_file_follow_it() {
    let dir = tempfile::tempdir().unwrap();
    let store = base_then_delta(dir.path());
    let v = store.view();
    let caller = v.find(key("a.py", "caller")).unwrap();
    let helper = v.find(key("b.py", "helper")).unwrap();

    // Forward: the base CSR edge points at the dead row; the view forwards it.
    let out = v.out_edges(caller, RelationMask::ALL).unwrap();
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].node, helper, "edge still points at the dead row");

    // Reverse: the caller was never touched, but it must still show up.
    let inc = v.in_edges(helper, Relation::BLAST_RADIUS).unwrap();
    assert_eq!(inc.len(), 1);
    assert_eq!(inc[0].node, caller);
    assert_eq!(inc[0].relation, Relation::Calls);
}

#[test]
fn a_symbol_removed_by_a_reindex_is_gone_and_its_edges_with_it() {
    let dir = tempfile::tempdir().unwrap();
    let mut store = Store::create(dir.path()).unwrap();
    commit(
        &mut store,
        &[("a.py", "caller", 0), ("b.py", "helper", 0)],
        &[("a.py", "caller", "b.py", "helper", Relation::Calls)],
    );
    compact(&mut store).unwrap();
    // b.py no longer defines helper.
    commit(&mut store, &[("b.py", "other", 0)], &[]);

    let v = store.view();
    assert!(v.find(key("b.py", "helper")).is_none(), "a deleted symbol is still findable");
    let caller = v.find(key("a.py", "caller")).unwrap();
    assert!(v.out_edges(caller, RelationMask::ALL).unwrap().is_empty(), "a dangling edge survived");
}

#[test]
fn a_delta_edge_into_the_base_resolves_both_ways() {
    let dir = tempfile::tempdir().unwrap();
    let mut store = Store::create(dir.path()).unwrap();
    commit(&mut store, &[("lib.py", "helper", 0)], &[]);
    compact(&mut store).unwrap();
    // A new file calls into the base. Its segment cannot hold the target, so
    // the edge is written external, keyed.
    commit(
        &mut store,
        &[("new.py", "run", 0)],
        &[("new.py", "run", "lib.py", "helper", Relation::Calls)],
    );
    let (_, delta) = store.segments().nth(1).unwrap();
    assert_eq!(delta.ext_edges().unwrap().len(), 1, "precondition: the edge is external");

    let v = store.view();
    let run = v.find(key("new.py", "run")).unwrap();
    let helper = v.find(key("lib.py", "helper")).unwrap();
    assert_eq!(v.out_edges(run, RelationMask::ALL).unwrap()[0].node, helper);
    let inc = v.in_edges(helper, RelationMask::ALL).unwrap();
    assert_eq!(inc.len(), 1, "the base's reverse CSR cannot know about the delta; the view must");
    assert_eq!(inc[0].node, run);
}

#[test]
fn a_package_imported_from_two_segments_is_one_symbol() {
    let dir = tempfile::tempdir().unwrap();
    let mut store = Store::create(dir.path()).unwrap();
    commit(
        &mut store,
        &[("a.py", "a", 0), ("a.py", "requests", node_flags::EXTERNAL)],
        &[("a.py", "a", "a.py", "requests", Relation::DependsOn)],
    );
    compact(&mut store).unwrap();
    commit(
        &mut store,
        &[("b.py", "b", 0), ("b.py", "requests", node_flags::EXTERNAL)],
        &[("b.py", "b", "b.py", "requests", Relation::DependsOn)],
    );

    let v = store.view();
    let live: Vec<LocalId> = v.ids().collect();
    assert_eq!(names(&store, &live), ["a", "b", "requests"], "the package stub was duplicated");
    let pkg = v.find(pkg_key("requests")).unwrap();
    let mut importers = names(&store, &v.in_edges(pkg, RelationMask::ALL).unwrap().iter().map(|e| e.node).collect::<Vec<_>>());
    importers.dedup();
    assert_eq!(importers, ["a", "b"], "both importers must reach the one canonical stub");
}

#[test]
fn removing_a_file_drops_its_rows_from_the_view() {
    let dir = tempfile::tempdir().unwrap();
    let mut store = Store::create(dir.path()).unwrap();
    commit(
        &mut store,
        &[("a.py", "caller", 0), ("b.py", "helper", 0)],
        &[("a.py", "caller", "b.py", "helper", Relation::Calls)],
    );
    compact(&mut store).unwrap();
    store.remove_files(&["b.py".to_string()]).unwrap();

    let v = store.view();
    assert!(v.find(key("b.py", "helper")).is_none());
    assert_eq!(names(&store, &v.ids().collect::<Vec<_>>()), ["caller"]);
    assert!(edge_set(&store).is_empty());

    // And a full compaction physically drops them.
    let stats = compact(&mut store).unwrap().expect("dead rows are worth compacting");
    assert_eq!(stats.dropped_dead, 1);
    assert_eq!(stats.symbols, 1);
}

#[test]
fn compaction_carries_file_metadata() {
    let dir = tempfile::tempdir().unwrap();
    let mut store = Store::create(dir.path()).unwrap();
    commit(&mut store, &[("a.py", "x", 0)], &[]);
    commit(&mut store, &[("b.py", "y", 0)], &[]);
    compact(&mut store).unwrap();
    let files = store.view().live_files().unwrap();
    assert_eq!(files.len(), 2);
    for (_, row) in files {
        assert_eq!((row.lang, row.content_hash, row.mtime_nanos, row.size), (1, 0xABCD, 7, 99));
    }
}

#[test]
fn tiered_policy_leaves_a_short_delta_run_alone() {
    let dir = tempfile::tempdir().unwrap();
    let mut store = base_then_delta(dir.path());
    // The delta is as big as the base here, so the ratio has to allow that.
    let policy = CompactPolicy { max_deltas: 4, max_delta_ratio: 1.5 };
    assert!(compact_tiered(&mut store, &policy).unwrap().is_none());
    assert_eq!(store.segments().count(), 2);
}

#[test]
fn tiered_policy_merges_deltas_without_touching_the_base() {
    let dir = tempfile::tempdir().unwrap();
    let mut store = Store::create(dir.path()).unwrap();
    // A base of ten files.
    let syms: Vec<(String, String)> = (0..10).map(|i| (format!("f{i}.py"), format!("fn{i}"))).collect();
    let refs: Vec<Sym> = syms.iter().map(|(p, n)| (p.as_str(), n.as_str(), 0)).collect();
    commit(&mut store, &refs, &[]);
    compact(&mut store).unwrap();
    let base_id = store.segments().next().unwrap().0;

    // Three one-file deltas, each calling into the base.
    for i in 0..3 {
        let p = format!("new{i}.py");
        commit(&mut store, &[(p.as_str(), "run", 0)], &[(p.as_str(), "run", "f0.py", "fn0", Relation::Calls)]);
    }
    let policy = CompactPolicy { max_deltas: 2, max_delta_ratio: 0.9 };
    let stats = compact_tiered(&mut store, &policy).unwrap().expect("three deltas exceed two");
    assert!(!stats.full, "the base was rewritten");
    assert_eq!(stats.segments_after, 2, "deltas were not merged into one");
    assert_eq!(store.segments().next().unwrap().0, base_id, "the base segment changed identity");
    // Edges into the base stay external, keyed — and still resolve.
    assert_eq!(stats.still_external, 3);
    let v = store.view();
    let fn0 = v.find(key("f0.py", "fn0")).unwrap();
    assert_eq!(v.in_edges(fn0, RelationMask::ALL).unwrap().len(), 3);

    // Pushing the deltas past the ratio triggers the full rewrite.
    let policy = CompactPolicy { max_deltas: 100, max_delta_ratio: 0.1 };
    let stats = compact_tiered(&mut store, &policy).unwrap().expect("ratio exceeded");
    assert!(stats.full);
    assert_eq!(stats.segments_after, 1);
    assert_eq!(stats.promoted, 3, "the keyed edges should join the CSR");
    assert!(store.view().is_simple());
}

#[test]
fn a_full_compaction_after_deltas_matches_the_view() {
    let dir = tempfile::tempdir().unwrap();
    let mut store = base_then_delta(dir.path());
    commit(
        &mut store,
        &[("c.py", "user", 0)],
        &[("c.py", "user", "b.py", "extra", Relation::Calls)],
    );
    let before = edge_set(&store);
    let live_before = names(&store, &store.view().ids().collect::<Vec<_>>());
    assert_eq!(before.len(), 3, "precondition: three live edges across three segments");

    compact(&mut store).unwrap().expect("compact");
    assert_eq!(store.segments().count(), 1);
    assert_eq!(edge_set(&store), before, "compaction changed what the view answered");
    assert_eq!(names(&store, &store.view().ids().collect::<Vec<_>>()), live_before);
    store.verify().unwrap();
}

#[test]
fn a_store_reopened_with_deltas_sees_the_same_graph() {
    let dir = tempfile::tempdir().unwrap();
    let before = {
        let store = base_then_delta(dir.path());
        edge_set(&store)
    };
    let store = Store::open(dir.path()).unwrap();
    assert_eq!(edge_set(&store), before);
}

/// A re-indexed file's own internal edges exist twice on disk: once in the
/// dead base rows, once in the delta. The reverse direction must count them
/// once — the dead source's edge is superseded by its replacement's.
#[test]
fn a_reindexed_files_internal_callers_are_not_reported_twice() {
    let dir = tempfile::tempdir().unwrap();
    let mut store = Store::create(dir.path()).unwrap();
    commit(
        &mut store,
        &[("a.py", "outside", 0), ("b.py", "helper", 0), ("b.py", "inner", 0)],
        &[
            ("a.py", "outside", "b.py", "inner", Relation::Calls),
            ("b.py", "helper", "b.py", "inner", Relation::Calls),
        ],
    );
    compact(&mut store).unwrap();
    // b.py re-indexed unchanged.
    commit(
        &mut store,
        &[("b.py", "helper", 0), ("b.py", "inner", 0)],
        &[("b.py", "helper", "b.py", "inner", Relation::Calls)],
    );
    let v = store.view();
    let inner = v.find(key("b.py", "inner")).unwrap();
    let mut callers = names(&store, &v.in_edges(inner, RelationMask::ALL).unwrap().iter().map(|e| e.node).collect::<Vec<_>>());
    assert_eq!(callers, ["helper", "outside"], "callers doubled or lost: {callers:?}");
    callers.dedup();
    assert_eq!(callers.len(), 2);
}
