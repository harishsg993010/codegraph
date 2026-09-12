//! The Phase 1 exit criterion.
//!
//! For every golden corpus: import it into a store, read the store back, and
//! assert the two snapshots are identical. This exercises the whole write →
//! mmap → read path — string interning, CSR construction, key minting, scope
//! recovery — against real data rather than a fixture.

use codegraph_store::{Store, import_node_link};
use codegraph_verify::{Snapshot, diff};

/// The corpora live at the workspace root, which is one level up from a crate.
fn corpora_dir() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("corpora")
}

fn corpora() -> Vec<(String, String)> {
    let dir = corpora_dir();
    let mut out = Vec::new();
    let Ok(rd) = std::fs::read_dir(&dir) else {
        panic!("no corpora directory at {}", dir.display());
    };
    let mut paths: Vec<_> = rd
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|e| e == "json"))
        .collect();
    paths.sort();
    for p in paths {
        let name = p.file_stem().unwrap_or_default().to_string_lossy().to_string();
        out.push((name, std::fs::read_to_string(&p).expect("read corpus")));
    }
    assert!(!out.is_empty(), "no corpora found in {}", dir.display());
    out
}

/// Import `json` into a fresh store and snapshot both sides.
fn import_and_snapshot(json: &str) -> (Snapshot, Snapshot, codegraph_store::ImportStats) {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut store = Store::create(dir.path()).expect("create store");
    let stats = import_node_link(json, &mut store).expect("import");

    let from_json = Snapshot::from_node_link(json).expect("snapshot json");
    let from_store = Snapshot::from_store(&store).expect("snapshot store");
    (from_json, from_store, stats)
}

#[test]
fn every_corpus_round_trips_through_the_store() {
    for (name, json) in corpora() {
        let (from_json, from_store, stats) = import_and_snapshot(&json);
        let r = diff(&from_json, &from_store);

        assert!(
            r.is_clean(),
            "{name}: store does not match source\n  \
             symbols +{} -{} ~{}\n  edges +{} -{}\n  \
             first added: {:?}\n  first dropped: {:?}\n  stats: {stats:?}",
            r.symbols_added.len(),
            r.symbols_dropped.len(),
            r.symbols_changed.len(),
            r.edges_added.len(),
            r.edges_dropped.len(),
            r.symbols_added.first(),
            r.symbols_dropped.first(),
        );

        println!(
            "{name:<22} {:>6} symbols  {:>6} edges  ({} files)",
            from_store.symbols.len(),
            from_store.edges.len(),
            stats.files
        );
    }
}

/// Every live segment must pass its own checksums after a real import.
#[test]
fn imported_stores_verify() {
    for (name, json) in corpora() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut store = Store::create(dir.path()).expect("create");
        import_node_link(&json, &mut store).expect("import");
        store.verify().unwrap_or_else(|e| panic!("{name}: {e}"));
    }
}

/// A store must survive being closed and reopened — that is the whole point of
/// persisting a manifest.
#[test]
fn a_store_reopens_with_the_same_contents() {
    let (_name, json) = corpora().into_iter().next().expect("at least one corpus");
    let dir = tempfile::tempdir().expect("tempdir");

    let before = {
        let mut store = Store::create(dir.path()).expect("create");
        import_node_link(&json, &mut store).expect("import");
        Snapshot::from_store(&store).expect("snapshot")
    };

    let reopened = Store::open(dir.path()).expect("reopen");
    let after = Snapshot::from_store(&reopened).expect("snapshot");
    assert!(diff(&before, &after).is_clean(), "contents changed across a reopen");
}

/// Importing the same corpus twice must supersede the first segment, not
/// accumulate a duplicate — this is the ownership rule the manifest enforces.
#[test]
fn re_importing_supersedes_rather_than_accumulates() {
    let (_name, json) = corpora().into_iter().next().expect("at least one corpus");
    let dir = tempfile::tempdir().expect("tempdir");
    let mut store = Store::create(dir.path()).expect("create");

    import_node_link(&json, &mut store).expect("first import");
    let first = Snapshot::from_store(&store).expect("snapshot");
    let segments_after_first = store.manifest().segments.len();

    import_and_assert_superseded(&mut store, &json, segments_after_first, &first);
}

fn import_and_assert_superseded(
    store: &mut Store,
    json: &str,
    segments_after_first: usize,
    first: &Snapshot,
) {
    import_node_link(json, store).expect("second import");
    assert_eq!(
        store.manifest().segments.len(),
        segments_after_first,
        "the superseded segment was not retired"
    );
    let second = Snapshot::from_store(store).expect("snapshot");
    assert!(
        diff(first, &second).is_clean(),
        "re-importing identical input changed the contents"
    );
    // And the dead segment file should be reclaimable.
    let swept = store.sweep_dead_segments();
    assert!(swept > 0, "no dead segment file was swept");
}

/// Key minting must be deterministic: two independent imports of the same
/// bytes must produce the same keys, or nothing incremental can ever work.
#[test]
fn keys_are_stable_across_independent_imports() {
    let (_name, json) = corpora().into_iter().next().expect("at least one corpus");

    let keys_of = |json: &str| -> Vec<codegraph_core::SymbolKey> {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut store = Store::create(dir.path()).expect("create");
        import_node_link(json, &mut store).expect("import");
        let mut all: Vec<_> = store
            .segments()
            .flat_map(|(_, s)| s.keys().expect("keys").to_vec())
            .collect();
        all.sort_unstable();
        all
    };

    assert_eq!(keys_of(&json), keys_of(&json), "key minting is not deterministic");
}
