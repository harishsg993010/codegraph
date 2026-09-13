//! Change detection through git, when git is there: the update asks git
//! which files can have changed and checks only those, and the graph it
//! leaves behind is the graph a walk would have found. Each test skips
//! itself when no `git` binary is on the path.

use std::path::Path;
use std::process::Command;

use codegraph_core::{Relation, SymbolKey};
use codegraph_resolve::{TreeState, index_tree, update_tree};
use codegraph_store::{CompactPolicy, Store};

fn write(dir: &Path, rel: &str, body: &str) {
    let p = dir.join(rel);
    if let Some(parent) = p.parent() {
        std::fs::create_dir_all(parent).expect("mkdir");
    }
    std::fs::write(p, body).expect("write");
}

fn git(dir: &Path, args: &[&str]) -> bool {
    Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(args)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

/// A repository with one commit, or `None` when git is not installed.
fn repo() -> Option<tempfile::TempDir> {
    if !codegraph_resolve::tree::git_available() {
        eprintln!("git not installed; skipping");
        return None;
    }
    let d = tempfile::tempdir().expect("tempdir");
    assert!(git(d.path(), &["init", "-q"]));
    assert!(git(d.path(), &["config", "user.email", "t@example.com"]));
    assert!(git(d.path(), &["config", "user.name", "t"]));
    write(d.path(), "lib.py", "def helper(x):\n    return x\n\ndef old_api():\n    return helper(1)\n");
    write(d.path(), "app.py", "from lib import old_api, helper\n\ndef process():\n    return old_api() + helper(2)\n");
    write(d.path(), "gen/out.py", "def generated():\n    pass\n");
    write(d.path(), ".codegraphignore", "gen/\n");
    assert!(git(d.path(), &["add", "-A"]));
    assert!(git(d.path(), &["commit", "-q", "-m", "one"]));
    Some(d)
}

const NEVER: CompactPolicy = CompactPolicy { max_deltas: 1000, max_delta_ratio: 1000.0 };

type Snapshot = (Vec<SymbolKey>, Vec<(SymbolKey, SymbolKey, Relation)>);

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

fn fresh(src: &Path) -> Snapshot {
    let sd = tempfile::tempdir().expect("tempdir");
    let mut store = Store::create(sd.path()).expect("create");
    index_tree(src, &mut store, "").expect("index");
    snapshot(&store)
}

fn paths(store: &Store) -> Vec<String> {
    let mut v: Vec<String> = store.manifest().live_files().filter(|p| !p.is_empty()).map(str::to_string).collect();
    v.sort();
    v
}

#[test]
fn the_store_records_the_commit_and_the_dirty_set() {
    let Some(d) = repo() else { return };
    write(d.path(), "scratch.py", "x = 1\n"); // untracked, dirty
    let sd = tempfile::tempdir().unwrap();
    let mut store = Store::create(sd.path()).unwrap();
    index_tree(d.path(), &mut store, "").unwrap();
    let st = TreeState::load(sd.path()).expect("TREE written");
    let g = st.git.expect("git state recorded");
    assert_eq!(g.head.len(), 40);
    assert_eq!(g.dirty, ["scratch.py"]);
    assert_eq!(paths(&store), ["app.py", "lib.py", "scratch.py"], ".codegraphignore hides gen/");
}

#[test]
fn a_commit_a_delete_and_an_untracked_file_are_found_through_git_and_match_a_walk() {
    let Some(d) = repo() else { return };
    let sd = tempfile::tempdir().unwrap();
    let mut store = Store::create(sd.path()).unwrap();
    index_tree(d.path(), &mut store, "").unwrap();

    // Committed edit, a deletion, and a new untracked file.
    write(d.path(), "lib.py", "def helper(x):\n    return x + 1\n\ndef new_api():\n    return helper(1)\n");
    assert!(git(d.path(), &["commit", "-q", "-am", "two"]));
    std::fs::remove_file(d.path().join("app.py")).unwrap();
    write(d.path(), "extra.py", "from lib import new_api\n\ndef run():\n    return new_api()\n");

    let r = update_tree(d.path(), &mut store, "", &NEVER).unwrap();
    assert_eq!(r.detection, "git", "{r:?}");
    assert!(r.incremental);
    assert_eq!(r.changed_paths, ["extra.py", "lib.py"]);
    assert_eq!(r.deleted_paths, ["app.py"]);
    assert_eq!(snapshot(&store), fresh(d.path()), "base + delta must equal a fresh index");

    // Nothing changed since: git says so without a walk, and nothing is
    // re-extracted.
    let r = update_tree(d.path(), &mut store, "", &NEVER).unwrap();
    assert_eq!(r.detection, "git");
    assert_eq!((r.changed, r.deleted, r.reextracted), (0, 0, 0));
}

#[test]
fn an_ignore_file_change_falls_back_to_the_walk() {
    let Some(d) = repo() else { return };
    let sd = tempfile::tempdir().unwrap();
    let mut store = Store::create(sd.path()).unwrap();
    index_tree(d.path(), &mut store, "").unwrap();
    assert!(!paths(&store).iter().any(|p| p.starts_with("gen/")));

    // Un-ignoring gen/ adds files git never reported as changed.
    write(d.path(), ".codegraphignore", "");
    let r = update_tree(d.path(), &mut store, "", &NEVER).unwrap();
    assert_eq!(r.detection, "scan", "{r:?}");
    assert_eq!(r.changed_paths, ["gen/out.py"]);
    assert_eq!(snapshot(&store), fresh(d.path()));

    // Ignoring it again removes them.
    write(d.path(), ".codegraphignore", "gen/\n");
    let r = update_tree(d.path(), &mut store, "", &NEVER).unwrap();
    assert_eq!(r.detection, "scan");
    assert_eq!(r.deleted_paths, ["gen/out.py"]);
    assert_eq!(snapshot(&store), fresh(d.path()));
}

#[test]
fn a_store_moved_to_another_tree_does_not_trust_the_old_git_record() {
    let Some(d) = repo() else { return };
    let sd = tempfile::tempdir().unwrap();
    let mut store = Store::create(sd.path()).unwrap();
    index_tree(d.path(), &mut store, "").unwrap();
    // Same content, different root: the recorded root differs, so the
    // candidates are found by a walk.
    let d2 = tempfile::tempdir().unwrap();
    for f in ["lib.py", "app.py", ".codegraphignore"] {
        std::fs::copy(d.path().join(f), d2.path().join(f)).unwrap();
    }
    let r = update_tree(d2.path(), &mut store, "", &NEVER).unwrap();
    assert_eq!(r.detection, "scan");
    assert_eq!((r.changed, r.deleted), (0, 0));
}

#[test]
fn the_store_is_kept_out_of_the_repository() {
    let Some(d) = repo() else { return };
    let repo = codegraph_resolve::detect_git(d.path()).expect("in a repo");
    let store_dir = d.path().join(".codegraph");
    std::fs::create_dir_all(&store_dir).unwrap();
    assert!(codegraph_resolve::exclude_store_from_git(&repo, &store_dir));
    let exclude = std::fs::read_to_string(d.path().join(".git/info/exclude")).unwrap();
    assert!(exclude.lines().any(|l| l == "/.codegraph/"), "{exclude}");
    // Idempotent: already ignored, nothing added.
    assert!(!codegraph_resolve::exclude_store_from_git(&repo, &store_dir));
    // A store elsewhere is not the repository's business.
    let elsewhere = tempfile::tempdir().unwrap();
    assert!(!codegraph_resolve::exclude_store_from_git(&repo, elsewhere.path()));
}
