//! Nothing to run by hand: a source tree given to any command is indexed
//! on first use, and every later command answers from a store brought up
//! to date first.

use std::path::Path;
use std::process::Command;

fn write(dir: &Path, rel: &str, body: &str) {
    let p = dir.join(rel);
    if let Some(parent) = p.parent() {
        std::fs::create_dir_all(parent).expect("mkdir");
    }
    std::fs::write(p, body).expect("write");
}

/// Run the CLI; `(stdout, stderr)`, panicking on a non-zero exit.
fn run(args: &[&str]) -> (String, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_codegraph")).args(args).output().expect("run codegraph");
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    assert!(out.status.success(), "codegraph {args:?} failed:\n{stdout}\n{stderr}");
    (stdout, stderr)
}

#[test]
fn a_source_tree_is_indexed_on_first_use_and_kept_current_after() {
    let d = tempfile::tempdir().unwrap();
    write(d.path(), "app.py", "def first():\n    return 1\n");
    let tree = d.path().to_str().unwrap();

    // First use: no store exists; `search` indexes and answers.
    let (out, err) = run(&["search", tree, "first"]);
    assert!(out.contains("first (app.py:1)"), "{out}");
    assert!(err.contains("indexed"), "the first use should say it indexed: {err}");
    assert!(d.path().join(".codegraph/CURRENT").is_file(), "the store lives in the tree");

    // A change, then a query: the store is brought up to date before the
    // answer, without an `index` run.
    write(d.path(), "app.py", "def first():\n    return 1\n\ndef second():\n    return first()\n");
    let (out, err) = run(&["explain", tree, "second"]);
    assert!(out.contains("second (app.py:4)"), "{out}");
    assert!(err.contains("updated"), "the change should be reported: {err}");
    assert!(out.contains("first (app.py:1)"), "second() calls first(): {out}");

    // Nothing changed: quiet.
    let (_, err) = run(&["search", tree, "second"]);
    assert!(!err.contains("updated") && !err.contains("indexed"), "{err}");

    // The store directory works as a name too, and knows its tree.
    let store = d.path().join(".codegraph");
    write(d.path(), "extra.py", "def third():\n    return 3\n");
    let (out, err) = run(&["search", store.to_str().unwrap(), "third"]);
    assert!(out.contains("third (extra.py:1)"), "{out}");
    assert!(err.contains("updated"), "{err}");

    // `--no-sync` answers from the store as it is.
    write(d.path(), "late.py", "def fourth():\n    return 4\n");
    let (out, _) = run(&["--no-sync", "search", tree, "fourth"]);
    assert!(out.starts_with("0 matches"), "{out}");
    let (out, _) = run(&["search", tree, "fourth"]);
    assert!(out.contains("fourth (late.py:1)"), "{out}");
}

#[test]
fn a_locked_store_is_read_as_it_is() {
    let d = tempfile::tempdir().unwrap();
    write(d.path(), "app.py", "def first():\n    return 1\n");
    let tree = d.path().to_str().unwrap();
    run(&["search", tree, "first"]);

    // Another process holds the write lock: the query does not wait for
    // it and does not fail; it answers from the store and says why it did
    // not update.
    let store = d.path().join(".codegraph");
    let _lock = codegraph_store::WriteLock::try_acquire(&store).unwrap().expect("free");
    write(d.path(), "app.py", "def first():\n    return 1\n\ndef second():\n    return 2\n");
    let (out, err) = run(&["search", tree, "second"]);
    assert!(out.starts_with("0 matches"), "{out}");
    assert!(err.contains("another process is updating"), "{err}");
}
