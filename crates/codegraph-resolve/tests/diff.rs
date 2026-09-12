//! `diff`: the graph's view of an uncommitted change — what changed, who
//! breaks, what is reached — computed on a scratch copy, leaving the store
//! as it was.

use std::path::Path;

use codegraph_core::{Relation, SymbolKind};
use codegraph_resolve::{Change, ChangeKind, DiffOptions, DiffReport, diff_tree, index_tree};
use codegraph_store::Store;

fn write(dir: &Path, rel: &str, body: &str) {
    let p = dir.join(rel);
    if let Some(parent) = p.parent() {
        std::fs::create_dir_all(parent).expect("mkdir");
    }
    std::fs::write(p, body).expect("write");
}

const LIB: &str = "MAX_ITEMS = 10\n\ndef helper(v):\n    return v * 2\n\ndef old_api(x):\n    return helper(x)\n\ndef run(a, b):\n    return a + b\n";
const APP: &str = "import lib\n\ndef process(req):\n    n = lib.MAX_ITEMS\n    y = lib.helper(req)\n    z = lib.old_api(y)\n    return lib.run(z, n)\n\ndef main():\n    process(input())\n";
const CLI: &str = "import app\n\ndef entry():\n    app.main()\n";

fn project() -> (tempfile::TempDir, tempfile::TempDir) {
    let src = tempfile::tempdir().unwrap();
    write(src.path(), "lib.py", LIB);
    write(src.path(), "app.py", APP);
    write(src.path(), "cli.py", CLI);
    let sd = tempfile::tempdir().unwrap();
    let mut store = Store::create(sd.path()).unwrap();
    index_tree(src.path(), &mut store, "").unwrap();
    (src, sd)
}

fn diff(src: &Path, sd: &Path) -> DiffReport {
    diff_tree(src, sd, &DiffOptions::default()).expect("diff")
}

fn change<'a>(r: &'a DiffReport, name: &str) -> &'a Change {
    r.changes.iter().find(|c| c.symbol.name == name).unwrap_or_else(|| {
        panic!("no change named {name}; got {:?}", r.changes.iter().map(|c| (&c.symbol.name, &c.what)).collect::<Vec<_>>())
    })
}

fn names(hits: impl Iterator<Item = String>) -> Vec<String> {
    let mut v: Vec<String> = hits.collect();
    v.sort();
    v.dedup();
    v
}

#[test]
fn an_unchanged_tree_has_no_changes_and_the_store_is_untouched() {
    let (src, sd) = project();
    let before = std::fs::read_dir(sd.path()).unwrap().count();
    let r = diff(src.path(), sd.path());
    assert!(r.changed_files.is_empty() && r.changes.is_empty());
    assert_eq!(std::fs::read_dir(sd.path()).unwrap().count(), before, "diff wrote into the store");
}

#[test]
fn a_removed_function_breaks_its_callers_and_the_trace_reaches_the_entrypoint() {
    let (src, sd) = project();
    write(src.path(), "lib.py", &LIB.replace("def old_api(x):\n    return helper(x)\n\n", ""));
    let r = diff(src.path(), sd.path());
    let c = change(&r, "old_api");
    assert_eq!(c.what, ChangeKind::Removed);
    assert!(c.is_breaking());
    assert_eq!(names(c.breaks.iter().map(|(rel, d)| format!("{} {}", rel.as_str(), d.name))), ["calls process"]);
    // process -> main -> entry, by call; and the removed function's value
    // reached `run`'s parameter.
    let reached = names(c.impact.iter().map(|h| h.symbol.name.clone()));
    for want in ["process", "main", "entry", "a"] {
        assert!(reached.contains(&want.to_string()), "{want} not in {reached:?}");
    }
    let entry = c.impact.iter().find(|h| h.symbol.name == "entry").unwrap();
    assert_eq!(entry.depth, 3);
    assert_eq!(entry.via, Relation::Calls);
    // The importer that lost its binding is reported as such.
    let p = change(&r, "process");
    assert_eq!(p.what, ChangeKind::Bindings);
    assert!(p.edge_delta.iter().any(|(rel, d)| *rel == Relation::Calls && *d < 0), "{:?}", p.edge_delta);
    // The store itself still has old_api.
    let store = Store::open(sd.path()).unwrap();
    let v = store.view();
    assert!(v.ids().any(|i| v.name(i).unwrap() == "old_api"));
}

#[test]
fn a_signature_change_breaks_callers_and_a_body_change_does_not() {
    let (src, sd) = project();
    write(src.path(), "lib.py", &LIB.replace("def run(a, b):\n    return a + b", "def run(a, b, c):\n    return a + b + c").replace("return v * 2", "return v * 3"));
    let r = diff(src.path(), sd.path());
    let run = change(&r, "run");
    assert_eq!(run.what, ChangeKind::Signature(vec!["a".into(), "b".into()], vec!["a".into(), "b".into(), "c".into()]));
    assert_eq!(names(run.breaks.iter().map(|(_, d)| d.name.clone())), ["process"]);
    let helper = change(&r, "helper");
    assert_eq!(helper.what, ChangeKind::Definition);
    assert!(!helper.is_breaking());
    let reached = names(helper.impact.iter().map(|h| h.symbol.name.clone()));
    assert!(reached.contains(&"process".to_string()) && reached.contains(&"old_api".to_string()), "{reached:?}");
    assert_eq!(r.breaking(), 1);
}

#[test]
fn a_constant_change_is_traced_through_references_and_value_flow() {
    let (src, sd) = project();
    write(src.path(), "lib.py", &LIB.replace("MAX_ITEMS = 10", "MAX_ITEMS = 20"));
    let r = diff(src.path(), sd.path());
    assert_eq!(r.changes.len(), 1, "{:?}", r.changes.iter().map(|c| (&c.symbol.name, &c.what)).collect::<Vec<_>>());
    let c = change(&r, "MAX_ITEMS");
    assert_eq!(c.symbol.kind, SymbolKind::Constant);
    assert_eq!(c.what, ChangeKind::Definition);
    let by_ref = c.impact.iter().find(|h| h.via == Relation::References).expect("a referencing function");
    assert_eq!(by_ref.symbol.name, "process");
    let flow = c.impact.iter().find(|h| h.via == Relation::FlowsTo).expect("a value consumer");
    assert_eq!((flow.symbol.name.as_str(), flow.symbol.owner.as_deref()), ("b", Some("run")));
    assert!(c.impact.iter().any(|h| h.symbol.name == "entry"), "the trace stops short of the entrypoint");
}

#[test]
fn reformatting_and_moving_a_definition_is_not_a_change() {
    let (src, sd) = project();
    write(src.path(), "lib.py", &format!("# a comment\n\n{}", LIB.replace("return v * 2", "return  v *  2")));
    let r = diff(src.path(), sd.path());
    assert_eq!(r.changed_files, ["lib.py"]);
    assert!(r.changes.is_empty(), "{:?}", r.changes.iter().map(|c| (&c.symbol.name, &c.what)).collect::<Vec<_>>());
}

#[test]
fn added_symbols_and_deleted_files_are_reported() {
    let (src, sd) = project();
    write(src.path(), "lib.py", &format!("{LIB}\ndef new_api(x):\n    return x\n"));
    std::fs::remove_file(src.path().join("cli.py")).unwrap();
    let r = diff(src.path(), sd.path());
    assert_eq!(change(&r, "new_api").what, ChangeKind::Added);
    assert_eq!(r.deleted_files, ["cli.py"]);
    assert_eq!(change(&r, "entry").what, ChangeKind::Removed);
}
