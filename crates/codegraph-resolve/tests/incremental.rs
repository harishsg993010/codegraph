//! Incremental updates: a one-file change writes a delta, never rewrites the
//! base, and the graph it leaves behind is the graph a full index would have
//! built.
//!
//! The comparison is in key space — `(source key, target key, relation)` over
//! every live edge, plus the set of live keys — because ids differ between a
//! store that grew by deltas and one built in a single pass.

use std::path::Path;

use codegraph_core::{Relation, RelationMask, SymbolKey};
use codegraph_index::IndexData;
use codegraph_query::{Direction, Engine};
use codegraph_resolve::{UpdateReport, index_tree, update_tree};
use codegraph_store::{CompactPolicy, Store, compact};

fn write(dir: &Path, rel: &str, body: &str) {
    let p = dir.join(rel);
    if let Some(parent) = p.parent() {
        std::fs::create_dir_all(parent).expect("mkdir");
    }
    std::fs::write(p, body).expect("write");
}

/// A policy that never compacts on its own, so the tests see the delta.
const NEVER: CompactPolicy = CompactPolicy { max_deltas: 1000, max_delta_ratio: 1000.0 };

fn full(src: &Path) -> (tempfile::TempDir, Store) {
    let sd = tempfile::tempdir().expect("tempdir");
    let mut store = Store::create(sd.path()).expect("create");
    index_tree(src, &mut store, "").expect("index");
    (sd, store)
}

fn update(src: &Path, store: &mut Store) -> UpdateReport {
    update_tree(src, store, "", &NEVER).expect("update")
}

type Snapshot = (Vec<SymbolKey>, Vec<(SymbolKey, SymbolKey, Relation)>);

/// Live keys and live edges, in key space.
fn snapshot(store: &Store) -> Snapshot {
    let v = store.view();
    let mut keys: Vec<SymbolKey> = v.ids().map(|id| v.key(id).unwrap()).collect();
    keys.sort();
    let mut edges = Vec::new();
    v.for_each_edge(
        |_| true,
        |e| {
            edges.push((v.key(e.source)?, v.key(e.target)?, Relation::from_u8(e.rel)));
            Ok(())
        },
    )
    .unwrap();
    edges.sort();
    edges.dedup();
    (keys, edges)
}

/// The snapshot a fresh full index of `src` produces.
fn fresh_snapshot(src: &Path) -> Snapshot {
    let (_sd, store) = full(src);
    snapshot(&store)
}

fn assert_matches_full(src: &Path, store: &Store, what: &str) {
    let got = snapshot(store);
    let want = fresh_snapshot(src);
    let name = |k: &SymbolKey| {
        let v = store.view();
        v.find(*k).map(|id| format!("{}:{}", v.path(id).unwrap(), v.name(id).unwrap())).unwrap_or(k.to_string())
    };
    let missing: Vec<String> = want.1.iter().filter(|e| !got.1.contains(e)).map(|e| format!("{} -{}-> {}", name(&e.0), e.2, name(&e.1))).collect();
    let extra: Vec<String> = got.1.iter().filter(|e| !want.1.contains(e)).map(|e| format!("{} -{}-> {}", name(&e.0), e.2, name(&e.1))).collect();
    assert_eq!(got.0, want.0, "{what}: live symbols differ from a full index");
    assert!(missing.is_empty() && extra.is_empty(), "{what}: edges differ from a full index\n  missing: {missing:?}\n  extra: {extra:?}");
}

fn project(dir: &Path) {
    write(dir, "lib.py", "def helper():\n    return 1\n\ndef unused():\n    pass\n");
    write(dir, "main.py", "import lib\n\ndef run():\n    helper()\n");
    write(dir, "other.py", "import os\n\ndef alone():\n    pass\n");
}

fn engine(store: Store) -> Engine {
    let index = IndexData::build(&store).expect("index");
    Engine::from_parts(store, index)
}

#[test]
fn an_unchanged_tree_is_a_no_op() {
    let src = tempfile::tempdir().unwrap();
    project(src.path());
    let (_sd, mut store) = full(src.path());
    let generation = store.manifest().generation;

    let r = update(src.path(), &mut store);
    assert!(r.incremental);
    assert_eq!((r.changed, r.deleted, r.reextracted), (0, 0, 0));
    assert_eq!(store.manifest().generation, generation, "a no-op committed a generation");
    assert_eq!(store.segments().count(), 1);
}

#[test]
fn a_touched_but_identical_file_is_not_reextracted() {
    let src = tempfile::tempdir().unwrap();
    project(src.path());
    let (_sd, mut store) = full(src.path());
    // Rewrite with the same bytes: mtime moves, content does not.
    std::thread::sleep(std::time::Duration::from_millis(20));
    write(src.path(), "lib.py", "def helper():\n    return 1\n\ndef unused():\n    pass\n");
    let r = update(src.path(), &mut store);
    assert_eq!(r.changed, 0, "a byte-identical rewrite was treated as a change");
}

#[test]
fn a_body_change_writes_a_delta_and_leaves_the_base_alone() {
    let src = tempfile::tempdir().unwrap();
    project(src.path());
    let (_sd, mut store) = full(src.path());
    let base_id = store.segments().next().unwrap().0;

    write(src.path(), "lib.py", "def helper():\n    return 2\n\ndef unused():\n    pass\n");
    let r = update(src.path(), &mut store);
    assert!(r.incremental);
    assert_eq!(r.changed, 1);
    // A body edit leaves lib.py's symbol set as it was, so main.py — which
    // imports it — binds exactly as before and is not re-extracted.
    assert_eq!(r.reextracted, 1, "{r:?}");
    assert_eq!(store.segments().count(), 2, "expected base plus one delta");
    assert_eq!(store.segments().next().unwrap().0, base_id, "the base was rewritten");
    assert_matches_full(src.path(), &store, "after a body change");
}

#[test]
fn an_api_change_pulls_importers_in_and_a_body_change_does_not() {
    let src = tempfile::tempdir().unwrap();
    project(src.path());
    let (_sd, mut store) = full(src.path());
    // Body only: same symbols.
    write(src.path(), "lib.py", "def helper():\n    return 42\n\ndef unused():\n    pass\n");
    let r = update(src.path(), &mut store);
    assert_eq!(r.reextracted, 1, "{r:?}");
    assert_matches_full(src.path(), &store, "after a body edit");
    // A symbol removed: importers must be revisited.
    write(src.path(), "lib.py", "def helper():\n    return 42\n");
    let r = update(src.path(), &mut store);
    assert_eq!(r.reextracted, 2, "lib.py and its importer main.py: {r:?}");
    assert_matches_full(src.path(), &store, "after removing a symbol");
}

#[test]
fn a_new_callee_is_picked_up_by_an_untouched_caller() {
    let src = tempfile::tempdir().unwrap();
    project(src.path());
    write(src.path(), "main.py", "import lib\n\ndef run():\n    helper()\n    later()\n");
    let (_sd, mut store) = full(src.path());
    {
        let e = engine_ref(&store);
        assert!(e.by_name("later").is_empty(), "precondition: later does not exist yet");
    }
    // lib gains the function main was already calling. main.py is untouched,
    // but as an importer of lib.py it is in the neighbourhood.
    write(src.path(), "lib.py", "def helper():\n    return 1\n\ndef unused():\n    pass\n\ndef later():\n    pass\n");
    update(src.path(), &mut store);
    assert_matches_full(src.path(), &store, "after adding a callee");

    let e = engine(store);
    let later = e.by_name("later");
    assert_eq!(later.len(), 1);
    let callers = e.neighbors(later[0], Direction::In, RelationMask::of(&[Relation::Calls])).unwrap();
    assert_eq!(callers.len(), 1, "the untouched caller did not bind to the new callee");
    assert_eq!(e.info(callers[0].id).unwrap().unwrap().name, "run");
}

fn engine_ref(store: &Store) -> Engine<IndexData> {
    let index = IndexData::build(store).expect("index");
    // A throwaway engine over a re-opened store, so the caller keeps its own.
    Engine::from_parts(Store::open(store.root()).unwrap(), index)
}

#[test]
fn a_renamed_function_vanishes_and_its_callers_lose_the_edge() {
    let src = tempfile::tempdir().unwrap();
    project(src.path());
    let (_sd, mut store) = full(src.path());
    write(src.path(), "lib.py", "def helper2():\n    return 1\n\ndef unused():\n    pass\n");
    update(src.path(), &mut store);
    assert_matches_full(src.path(), &store, "after a rename");

    let e = engine(store);
    assert!(e.by_name("helper").is_empty(), "the old name is still findable");
    let run = e.by_name("run")[0];
    let calls = e.neighbors(run, Direction::Out, RelationMask::of(&[Relation::Calls])).unwrap();
    assert!(calls.is_empty(), "run still calls something: {calls:?}");
}

#[test]
fn a_deleted_file_is_removed_and_its_importers_re_resolve() {
    let src = tempfile::tempdir().unwrap();
    project(src.path());
    let (_sd, mut store) = full(src.path());
    std::fs::remove_file(src.path().join("lib.py")).unwrap();
    let r = update(src.path(), &mut store);
    assert_eq!(r.deleted, 1);
    assert_matches_full(src.path(), &store, "after a deletion");
    let e = engine(store);
    assert!(e.by_name("helper").is_empty());
    assert!(e.search("lib.py").unwrap().is_empty(), "a deleted file is still searchable");
}

#[test]
fn a_new_file_is_added() {
    let src = tempfile::tempdir().unwrap();
    project(src.path());
    let (_sd, mut store) = full(src.path());
    write(src.path(), "extra.py", "import lib\n\ndef more():\n    helper()\n");
    let r = update(src.path(), &mut store);
    assert_eq!(r.changed, 1);
    assert_matches_full(src.path(), &store, "after adding a file");

    let e = engine(store);
    let helper = e.by_name("helper")[0];
    let mut callers: Vec<String> = e
        .neighbors(helper, Direction::In, RelationMask::of(&[Relation::Calls]))
        .unwrap()
        .iter()
        .map(|h| e.info(h.id).unwrap().unwrap().name)
        .collect();
    callers.sort();
    assert_eq!(callers, ["more", "run"], "the delta's caller and the base's must both be found");
}

#[test]
fn queries_span_base_and_delta() {
    let src = tempfile::tempdir().unwrap();
    project(src.path());
    let (_sd, mut store) = full(src.path());
    write(src.path(), "lib.py", "def helper():\n    return 3\n\ndef unused():\n    pass\n");
    update(src.path(), &mut store);
    assert_eq!(store.segments().count(), 2);

    let e = engine(store);
    let run = e.by_name("run");
    let helper = e.by_name("helper");
    assert_eq!((run.len(), helper.len()), (1, 1), "a symbol was found twice or not at all");
    // Forward, across the segment boundary and through the forwarded row.
    let path = e.shortest_path(run[0], helper[0], RelationMask::ALL, 4).unwrap();
    assert_eq!(path.as_deref().map(<[_]>::len), Some(2), "no path from run to helper: {path:?}");
    // Reverse: the blast radius of the re-indexed symbol still reaches its caller.
    let affected: Vec<String> = e
        .blast_radius(helper[0], 2)
        .unwrap()
        .iter()
        .map(|h| e.info(h.id).unwrap().unwrap().name)
        .collect();
    assert!(affected.contains(&"run".to_string()), "blast radius lost the caller: {affected:?}");
    // Search sees the delta's row and not the dead base row.
    let hits = e.search("helper").unwrap();
    assert_eq!(hits.len(), 1);
}

#[test]
fn repeated_updates_stay_consistent_and_the_policy_bounds_the_deltas() {
    let src = tempfile::tempdir().unwrap();
    project(src.path());
    // Files the updates never touch, so the base keeps owning something. (A
    // base that loses every file is retired, which is correct, but then there
    // is no base for the policy to protect.)
    for i in 0..10 {
        write(src.path(), &format!("stable{i}.py"), &format!("def stable{i}():\n    pass\n"));
    }
    let (_sd, mut store) = full(src.path());
    let base_id = store.segments().next().unwrap().0;
    let policy = CompactPolicy { max_deltas: 2, max_delta_ratio: 100.0 };
    for i in 0..6 {
        let file = ["lib.py", "main.py", "other.py"][i % 3];
        let body = match file {
            "lib.py" => format!("def helper():\n    return {i}\n\ndef unused():\n    pass\n"),
            "main.py" => format!("import lib\n\ndef run():\n    helper()\n    x = {i}\n"),
            _ => format!("import os\n\ndef alone():\n    return {i}\n"),
        };
        write(src.path(), file, &body);
        let r = update_tree(src.path(), &mut store, "", &policy).unwrap();
        assert!(r.incremental);
        assert!(
            store.segments().count() <= 1 + policy.max_deltas + 1,
            "delta run grew unbounded: {} segments after update {i}",
            store.segments().count()
        );
        if let Some(c) = &r.compaction {
            assert!(!c.full, "the base was rewritten by a small update: {c:?}");
        }
        assert_eq!(store.segments().next().unwrap().0, base_id, "the base changed identity");
        assert_matches_full(src.path(), &store, &format!("after update {i}"));
    }
    // And a full compaction of the accumulated deltas changes nothing.
    let before = snapshot(&store);
    compact(&mut store).unwrap().expect("there were deltas to merge");
    assert_eq!(store.segments().count(), 1);
    assert_eq!(snapshot(&store), before);
}

#[test]
fn a_persisted_store_updates_after_reopen() {
    let src = tempfile::tempdir().unwrap();
    project(src.path());
    let (sd, store) = full(src.path());
    drop(store);
    write(src.path(), "other.py", "import os\n\ndef alone():\n    return 9\n");
    let mut store = Store::open(sd.path()).unwrap();
    let r = update(src.path(), &mut store);
    assert_eq!((r.changed, r.reextracted), (1, 1), "{r:?}");
    assert_matches_full(src.path(), &store, "after reopen");
}

#[test]
fn a_different_repo_tag_is_refused() {
    let src = tempfile::tempdir().unwrap();
    project(src.path());
    let (_sd, mut store) = full(src.path());
    write(src.path(), "other.py", "import os\n\ndef alone():\n    return 9\n");
    let err = update_tree(src.path(), &mut store, "elsewhere", &NEVER).unwrap_err();
    assert!(err.to_string().contains("repo tag"), "{err}");
}

/// Go interface satisfaction needs arity, which the store does not hold, so a
/// re-extracted type's `implements` edges into *unchanged* interfaces are
/// carried forward rather than recomputed. Here `n.go` is re-extracted only
/// because it calls into the changed file; its interface lives in a file
/// nothing else touches.
#[test]
fn a_neighbours_implements_edge_into_an_unchanged_interface_survives() {
    let src = tempfile::tempdir().unwrap();
    // Go binds cross-file calls through imports, so the neighbour relation
    // needs a package boundary and a module path to resolve it through.
    write(src.path(), "go.mod", "module mod\n");
    write(src.path(), "c/changed.go", "package c\n\nfunc Changed() int { return 1 }\n");
    write(
        src.path(),
        "n.go",
        "package p\n\nimport \"mod/c\"\n\ntype N struct{}\n\nfunc (n *N) Name() string { return \"n\" }\nfunc (n *N) Verify(r int, w int) error { return nil }\n\nfunc Use() { c.Changed() }\n",
    );
    write(src.path(), "j.go", "package p\n\ntype J interface {\n\tName() string\n\tVerify(r int, w int) error\n}\n");
    let (_sd, mut store) = full(src.path());
    {
        let e = engine_ref(&store);
        let j = e.by_name("J");
        assert_eq!(j.len(), 1);
        let impls = e.neighbors(j[0], Direction::In, RelationMask::of(&[Relation::Implements])).unwrap();
        assert_eq!(impls.len(), 1, "precondition: N implements J in the full index");
    }

    // A new symbol, so the importer's bindings may have changed and n.go is
    // re-extracted — with its interface's file untouched.
    write(src.path(), "c/changed.go", "package c\n\nfunc Changed() int { return 2 }\n\nfunc Extra() {}\n");
    let r = update(src.path(), &mut store);
    assert_eq!(r.reextracted, 2, "changed.go and its importer n.go: {r:?}");
    assert_matches_full(src.path(), &store, "after changing a Go file");
}

/// A change that makes a type *newly* satisfy an unchanged interface is the
/// documented gap: it is found at the next full rebuild, not by the delta.
#[test]
fn a_newly_satisfied_unchanged_interface_is_found_by_the_rebuild_not_the_delta() {
    let src = tempfile::tempdir().unwrap();
    write(src.path(), "t.go", "package p\n\ntype T struct{}\n\nfunc (t *T) Name() string { return \"t\" }\n");
    write(src.path(), "j.go", "package p\n\ntype J interface {\n\tName() string\n\tVerify(r int, w int) error\n}\n");
    let (_sd, mut store) = full(src.path());
    // T gains Verify and now satisfies J; j.go has no edge to t.go, so it is
    // not re-extracted, and its arity is not known to the delta.
    write(src.path(), "t.go", "package p\n\ntype T struct{}\n\nfunc (t *T) Name() string { return \"t\" }\nfunc (t *T) Verify(r int, w int) error { return nil }\n");
    update(src.path(), &mut store);
    let has_edge = |store: &Store| {
        let e = engine_ref(store);
        let j = e.by_name("J")[0];
        !e.neighbors(j, Direction::In, RelationMask::of(&[Relation::Implements])).unwrap().is_empty()
    };
    assert!(!has_edge(&store), "the delta cannot know this; if it does, update the docs");
    // The policy's rewrite is a full re-index, which restores exactness. A
    // merge alone could not: it moves rows, it does not re-resolve.
    write(src.path(), "j.go", "package p\n\n// touched\ntype J interface {\n\tName() string\n\tVerify(r int, w int) error\n}\n");
    let rebuild = CompactPolicy { max_deltas: 1000, max_delta_ratio: 0.0 };
    let r = update_tree(src.path(), &mut store, "", &rebuild).unwrap();
    assert!(!r.incremental, "the policy should have forced a rebuild: {r:?}");
    assert_eq!(store.segments().count(), 1);
    assert!(has_edge(&store));
}

// --- the layered index ---

use codegraph_index::{IndexQuery, Opened, REACHABILITY_RELATIONS, open_or_build};

/// Every (live a, live b): the layered filter against a full rebuild and
/// against a BFS. The BFS is the ground truth; the full index is the
/// precision to beat.
fn check_layered(store: &Store, dir: &Path, what: &str) -> (usize, usize) {
    let (layered, how) = open_or_build(store, dir).expect("layered");
    assert_ne!(how, Opened::Rebuilt, "{what}: the base should still be extendable");
    let full = IndexData::build(store).expect("full");
    let e = Engine::from_parts(Store::open(store.root()).unwrap(), full);
    let ids: Vec<codegraph_core::LocalId> = store.view().ids().collect();
    let mut imprecise = 0usize;
    let mut checked = 0usize;
    for &a in &ids {
        // Ground truth, independent of any index.
        let reach: std::collections::HashSet<u32> =
            e.reachable_set(&[a], REACHABILITY_RELATIONS).unwrap().iter().map(|i| i.get()).collect();
        assert_eq!(layered.degree(a), e.index().degree(a), "{what}: degree of {a:?}");
        assert_eq!(layered.degrees(a), e.index().degrees(a), "{what}: in/out degree of {a:?}");
        let name = store.view().norm_name(a).unwrap().to_string();
        let mut l: Vec<u32> = layered.by_exact_name(&name).into_iter().filter(|&i| store.view().is_canonical(codegraph_core::LocalId::new(i))).collect();
        let mut f: Vec<u32> = e.index().by_exact_name(&name);
        l.sort();
        f.sort();
        assert_eq!(l, f, "{what}: name postings for {name:?}");
        for &b in &ids {
            checked += 1;
            let truth = reach.contains(&b.get());
            let lay = layered.maybe_reaches(a, b);
            let ful = e.index().maybe_reaches(a, b);
            assert!(!truth || lay, "{what}: layered filter rejected a real path {a:?} -> {b:?}");
            assert!(!truth || ful, "{what}: full filter rejected a real path {a:?} -> {b:?}");
            if lay && !ful {
                imprecise += 1;
            }
        }
    }
    (checked, imprecise)
}

#[test]
fn the_layered_index_is_sound_after_every_kind_of_change() {
    let src = tempfile::tempdir().unwrap();
    project(src.path());
    write(src.path(), "chain.py", "import lib\n\ndef a():\n    b()\n\ndef b():\n    c()\n\ndef c():\n    helper()\n");
    // Untouched files, so the base keeps owning something and stays the base.
    for i in 0..6 {
        write(src.path(), &format!("stable{i}.py"), &format!("import os\n\ndef s{i}():\n    pass\n"));
    }
    let (sd, mut store) = full(src.path());
    let (_, how) = open_or_build(&store, sd.path()).unwrap();
    assert_eq!(how, Opened::Rebuilt);
    assert_eq!(open_or_build(&store, sd.path()).unwrap().1, Opened::Base);

    // Body edit: same edges, so the base labels are exact and nothing is lost.
    write(src.path(), "lib.py", "def helper():\n    return 7\n\ndef unused():\n    pass\n");
    update(src.path(), &mut store);
    assert_eq!(open_or_build(&store, sd.path()).unwrap().1, Opened::OverlayBuilt);
    assert_eq!(open_or_build(&store, sd.path()).unwrap().1, Opened::Overlaid);
    let (checked, _) = check_layered(&store, sd.path(), "body edit");
    assert!(checked > 0);
    // A body edit re-keys the same edges, so the base labels stay exact and
    // no bitset fallback is needed. (Pair-by-pair precision against a rebuild
    // is not comparable: GRAIL intervals depend on traversal order, so two
    // sound label sets reject different unreachable pairs.)
    {
        // Scoped: on Windows a mapped index file cannot be rewritten, and the
        // rebuild at the end of this test has to be able to.
        let (layered, _) = open_or_build(&store, sd.path()).unwrap();
        let overlay = layered.overlay().expect("an overlay after a delta");
        assert!(!overlay.has_added_edges(), "a body edit was recorded as adding edges");
        // lib.py: its file row, two functions, and their CFG blocks.
        assert!(overlay.delta_rows() >= 3, "delta rows: {}", overlay.delta_rows());
    }

    // A new call from an untouched chain into a new function: added edges.
    write(src.path(), "lib.py", "def helper():\n    return 7\n\ndef unused():\n    pass\n\ndef sink():\n    pass\n");
    write(src.path(), "chain.py", "import lib\n\ndef a():\n    b()\n\ndef b():\n    c()\n\ndef c():\n    helper()\n    sink()\n");
    update(src.path(), &mut store);
    check_layered(&store, sd.path(), "added call");

    // A rename that breaks the chain: removed edges.
    write(src.path(), "lib.py", "def helper2():\n    return 7\n\ndef sink():\n    pass\n");
    update(src.path(), &mut store);
    check_layered(&store, sd.path(), "rename");

    // A deleted file and a new one.
    std::fs::remove_file(src.path().join("other.py")).unwrap();
    write(src.path(), "extra.py", "import chain\n\ndef top():\n    a()\n");
    let r = update(src.path(), &mut store);
    assert_eq!(r.reextracted, 1, "extra.py only; a deleted file's package stub is not a neighbour: {r:?}");
    check_layered(&store, sd.path(), "delete + add");

    // Reopen from disk: the overlay on disk is what a fresh process sees.
    drop(store);
    let store = Store::open(sd.path()).unwrap();
    assert_eq!(open_or_build(&store, sd.path()).unwrap().1, Opened::Overlaid);
    check_layered(&store, sd.path(), "reopened");

    // After a full compaction the base is a new segment: a rebuild is due.
    let mut store = store;
    compact(&mut store).unwrap();
    assert_eq!(open_or_build(&store, sd.path()).unwrap().1, Opened::Rebuilt);
    assert!(!sd.path().join(codegraph_index::OVERLAY_FILE).exists(), "a stale overlay was left behind");
}

/// The `flows_to` edges leaving `name`, as `(target path, target name)`.
fn flows_from(store: &Store, name: &str) -> Vec<(String, String)> {
    let v = store.view();
    let id = v.ids().find(|&i| v.name(i).unwrap() == name && v.is_canonical(i) && v.kind_raw(i).unwrap() != 19).expect("symbol");
    let mut out: Vec<(String, String)> = v
        .out_edges(id, Relation::DATA_FLOW)
        .unwrap()
        .iter()
        .map(|e| (v.path(e.node).unwrap().to_string(), v.name(e.node).unwrap().to_string()))
        .collect();
    out.sort();
    out.dedup();
    out
}

/// A value that leaves a symbol one file defines and is observed by another
/// file — `y = lib.make(); sink(y)` — is an edge *from* the callee. It must
/// belong to the file that observed it: it survives a re-index of the callee
/// (the callee's rows are replaced, the caller's are not) and disappears with
/// a re-index of the caller that removes it — and neither case may leave the
/// store different from a fresh full index, nor the layered index unsound.
#[test]
fn a_flow_out_of_a_foreign_symbol_belongs_to_the_file_that_observed_it() {
    let src = tempfile::tempdir().unwrap();
    write(src.path(), "lib.py", "def make():\n    return 1\n\ndef sink(v):\n    pass\n");
    write(src.path(), "use.py", "import lib\n\ndef go():\n    y = lib.make()\n    lib.sink(y)\n");
    for i in 0..6 {
        write(src.path(), &format!("stable{i}.py"), &format!("import os\n\ndef s{i}():\n    pass\n"));
    }
    let (sd, mut store) = full(src.path());
    assert_eq!(open_or_build(&store, sd.path()).unwrap().1, Opened::Rebuilt);
    let want = vec![("lib.py".to_string(), "v".to_string())];
    assert_eq!(flows_from(&store, "make"), want, "full index: make's return flows into sink's parameter");

    // Re-index the callee: its row is replaced; the caller's edge out of it
    // must still be there.
    write(src.path(), "lib.py", "def make():\n    return 2\n\ndef sink(v):\n    pass\n");
    let r = update(src.path(), &mut store);
    assert_eq!(r.reextracted, 1, "a body edit of the callee re-extracts only it");
    assert_eq!(flows_from(&store, "make"), want, "after re-indexing the callee");
    assert_matches_full(src.path(), &store, "callee re-indexed");
    check_layered(&store, sd.path(), "callee re-indexed");

    // Re-index the caller so the flow no longer exists: the edge must go.
    write(src.path(), "use.py", "import lib\n\ndef go():\n    y = lib.make()\n    lib.sink(1)\n");
    update(src.path(), &mut store);
    assert!(flows_from(&store, "make").is_empty(), "after the caller stopped passing the value on");
    assert_matches_full(src.path(), &store, "caller re-indexed");
    check_layered(&store, sd.path(), "caller re-indexed");

    // And back again, through a second delta over the first.
    write(src.path(), "use.py", "import lib\n\ndef go():\n    y = lib.make()\n    lib.sink(y)\n");
    update(src.path(), &mut store);
    assert_eq!(flows_from(&store, "make"), want, "after the caller passes it on again");
    assert_matches_full(src.path(), &store, "caller re-indexed twice");
    check_layered(&store, sd.path(), "caller re-indexed twice");

    // Compaction keeps the ownership: the merged base still answers the
    // same, and a later re-index of the callee still keeps the edge.
    compact(&mut store).expect("compact");
    assert_eq!(flows_from(&store, "make"), want, "after compaction");
    write(src.path(), "lib.py", "def make():\n    return 3\n\ndef sink(v):\n    pass\n");
    update(src.path(), &mut store);
    assert_eq!(flows_from(&store, "make"), want, "callee re-indexed over the compacted base");
    assert_matches_full(src.path(), &store, "callee re-indexed over the compacted base");
}

/// Locals are rows of their callable — searchable, explained through
/// `local_flow` and the CFG — and part of no file's API: a body edit that
/// adds one is still a one-file update.
#[test]
fn locals_are_stored_but_are_not_api() {
    use codegraph_core::SymbolKind;
    let src = tempfile::tempdir().unwrap();
    write(src.path(), "lib.py", "def helper(v):\n    return v\n");
    write(src.path(), "use.py", "import lib\n\ndef go(req):\n    y = lib.helper(req)\n    lib.sink(y)\n");
    let (_sd, mut store) = full(src.path());
    let v = store.view();
    let y = v.ids().find(|&i| v.name(i).unwrap() == "y" && v.kind_raw(i).unwrap() == SymbolKind::Local.as_u8()).expect("local y");
    let owner: Vec<String> = v.in_edges(y, RelationMask::of(&[Relation::Contains])).unwrap().iter().map(|e| v.name(e.node).unwrap().to_string()).collect();
    assert_eq!(owner, ["go"]);
    let assigned_from: Vec<String> = v.in_edges(y, Relation::LOCALS).unwrap().iter().map(|e| v.name(e.node).unwrap().to_string()).collect();
    assert!(assigned_from.contains(&"helper".to_string()), "{assigned_from:?}");
    let read_into: Vec<String> = v.out_edges(y, Relation::LOCALS).unwrap().iter().map(|e| v.name(e.node).unwrap().to_string()).collect();
    assert!(read_into.contains(&"sink".to_string()), "{read_into:?}");
    let blocks = v.in_edges(y, RelationMask::of(&[Relation::Defines, Relation::Uses])).unwrap().len();
    assert!(blocks >= 2, "a block defines y and a block uses it: {blocks}");

    // A new local in the body: one file re-extracted, importers untouched.
    write(src.path(), "use.py", "import lib\n\ndef go(req):\n    z = req\n    y = lib.helper(z)\n    lib.sink(y)\n");
    let r = update(src.path(), &mut store);
    assert_eq!(r.reextracted, 1);
    assert_matches_full(src.path(), &store, "a new local");
}

/// The stored local view is flow-sensitive through its edge contexts:
/// `origin -> local` names the definition line, `local -> sink` the lines
/// of the definitions that reach the read.
#[test]
fn local_flow_edges_carry_definition_lines() {
    use codegraph_core::SymbolKind;
    let src = tempfile::tempdir().unwrap();
    write(src.path(), "f.py", "def f(a, b):\n    x = a\n    sink1(x)\n    x = b\n    sink2(x)\n    if a:\n        x = a\n    sink3(x)\n");
    let (_sd, store) = full(src.path());
    let v = store.view();
    let x = v.ids().find(|&i| v.name(i).unwrap() == "x" && v.kind_raw(i).unwrap() == SymbolKind::Local.as_u8()).expect("local x");
    let mut into: Vec<(String, String)> = v
        .in_edges(x, Relation::LOCALS)
        .unwrap()
        .iter()
        .map(|e| (v.name(e.node).unwrap().to_string(), e.context.unwrap_or("").to_string()))
        .collect();
    into.sort();
    assert_eq!(into, [("a".to_string(), "2".to_string()), ("a".to_string(), "7".to_string()), ("b".to_string(), "4".to_string())]);
    let mut out: Vec<(String, String)> = v
        .out_edges(x, Relation::LOCALS)
        .unwrap()
        .iter()
        .map(|e| (v.name(e.node).unwrap().to_string(), e.context.unwrap_or("").to_string()))
        .collect();
    out.sort();
    assert_eq!(out, [("sink1".to_string(), "2".to_string()), ("sink2".to_string(), "4".to_string()), ("sink3".to_string(), "4,7".to_string())]);
}
