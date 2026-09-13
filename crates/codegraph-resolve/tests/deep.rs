//! Deep search: code found by what it is connected to, on a small tree
//! where the answers are known.

use std::path::Path;

use codegraph_core::SymbolKind;
use codegraph_index::IndexData;
use codegraph_query::{DeepHit, DeepQuery, Engine};
use codegraph_resolve::index_tree;
use codegraph_store::Store;

fn write(dir: &Path, rel: &str, body: &str) {
    let p = dir.join(rel);
    if let Some(parent) = p.parent() {
        std::fs::create_dir_all(parent).expect("mkdir");
    }
    std::fs::write(p, body).expect("write");
}

fn engine(src: &Path) -> (tempfile::TempDir, Engine) {
    let sd = tempfile::tempdir().expect("tempdir");
    let mut store = Store::create(sd.path()).expect("create");
    index_tree(src, &mut store, "").expect("index");
    let index = IndexData::build(&store).expect("index");
    (sd, Engine::from_parts(store, index))
}

/// A tree where the interesting function has neither search term in its
/// name: `enforce_quota` reads `MAX_UPLOAD_BYTES`, branches on `size`, and
/// hands the path to `subprocess.run`.
fn tree() -> tempfile::TempDir {
    let d = tempfile::tempdir().expect("tempdir");
    write(
        d.path(),
        "storage/limits.py",
        "MAX_UPLOAD_BYTES = 1024\n\ndef upload_limit():\n    return MAX_UPLOAD_BYTES\n",
    );
    write(
        d.path(),
        "storage/enforce.py",
        "import subprocess\nfrom storage.limits import MAX_UPLOAD_BYTES\n\ndef enforce_quota(path, size):\n    if size > MAX_UPLOAD_BYTES:\n        raise ValueError('too big')\n    subprocess.run(['scan', path])\n    return size\n\ndef unrelated(a):\n    return a + 1\n",
    );
    write(
        d.path(),
        "web/handler.py",
        "from storage.enforce import enforce_quota\n\ndef handle_upload(request):\n    upload_size = len(request.body)\n    return enforce_quota(request.path, upload_size)\n",
    );
    d
}

fn run(e: &Engine, q: &str) -> Vec<DeepHit> {
    e.deep_search(&DeepQuery::parse(q), 20).expect("deep search")
}

fn names(hits: &[DeepHit]) -> Vec<String> {
    hits.iter().map(|h| h.info.name.clone()).collect()
}

fn hit<'a>(hits: &'a [DeepHit], name: &str) -> &'a DeepHit {
    hits.iter().find(|h| h.info.name == name).unwrap_or_else(|| panic!("{name} not among {:?}", names(hits)))
}

#[test]
fn the_function_that_connects_two_terms_scores_for_both() {
    let src = tree();
    let (_s, e) = engine(src.path());
    let hits = run(&e, "upload quota");
    // `enforce_quota` has `quota` in its name and `upload` only through the
    // constant it reads and the caller that reaches it.
    let h = hit(&hits, "enforce_quota");
    assert!(h.reasons.iter().any(|r| r.contains("quota")), "{:?}", h.reasons);
    assert!(h.reasons.iter().any(|r| r.contains("upload") || r.contains("MAX_UPLOAD_BYTES") || r.contains("handle_upload")), "{:?}", h.reasons);
    assert!(!h.reasons.iter().any(|r| r.contains("nothing for")), "both terms should be met: {:?}", h.reasons);
    // The unrelated function has no business here.
    assert!(!names(&hits).iter().any(|n| n == "unrelated"), "{:?}", names(&hits));
    // Two terms met beat one.
    let one = hit(&hits, "upload_limit");
    assert!(h.score > one.score, "{} vs {}", h.score, one.score);
}

#[test]
fn locals_and_conditions_inside_a_body_are_matched() {
    let src = tree();
    let (_s, e) = engine(src.path());
    // `size` is a parameter of enforce_quota and a local of handle_upload;
    // neither function is called `size`.
    let hits = run(&e, "size");
    let h = hit(&hits, "handle_upload");
    assert!(h.reasons.iter().any(|r| r.contains("local `upload_size`")), "{:?}", h.reasons);
    let h = hit(&hits, "enforce_quota");
    assert!(h.reasons.iter().any(|r| r.contains("parameter `size`") || r.contains("condition")), "{:?}", h.reasons);
    // The condition text is searchable on its own.
    let hits = run(&e, "MAX_UPLOAD_BYTES kind:function");
    let h = hit(&hits, "enforce_quota");
    assert!(h.reasons.iter().any(|r| r.contains("condition") || r.contains("references")), "{:?}", h.reasons);
}

#[test]
fn filters_narrow_by_structure_including_calls_to_library_stubs() {
    let src = tree();
    let (_s, e) = engine(src.path());
    // Who calls the library function `subprocess.run`? Nothing in the corpus
    // defines it; the call edge to its stub answers.
    let hits = run(&e, "kind:function calls:run");
    assert_eq!(names(&hits), ["enforce_quota"]);
    assert!(hit(&hits, "enforce_quota").reasons.iter().any(|r| r == "calls run"));
    // The same, by qualified name.
    let hits = run(&e, "calls:subprocess.run");
    assert_eq!(names(&hits), ["enforce_quota"]);
    // Path and kind filters compose with terms.
    let hits = run(&e, "upload in:web/ kind:function");
    assert_eq!(names(&hits), ["handle_upload"]);
    // A request parameter whose value reaches the library call.
    let hits = run(&e, "flows-to:run kind:parameter");
    let n = names(&hits);
    assert!(n.iter().any(|x| x == "path"), "{n:?}");
    assert!(hits.iter().all(|h| h.info.kind == SymbolKind::Parameter));
    // `called-by` and `references`.
    let hits = run(&e, "called-by:handle_upload");
    assert_eq!(names(&hits), ["enforce_quota"]);
    let hits = run(&e, "references:MAX_UPLOAD_BYTES");
    let n = names(&hits);
    assert!(n.contains(&"enforce_quota".to_string()) && n.contains(&"upload_limit".to_string()), "{n:?}");
    // A filter nothing satisfies is empty, not an error.
    assert!(run(&e, "calls:nonexistent_thing").is_empty());
}

#[test]
fn a_phrase_matches_a_run_of_subwords() {
    let src = tree();
    let (_s, e) = engine(src.path());
    let hits = run(&e, "\"upload bytes\"");
    // MAX_UPLOAD_BYTES carries the phrase as adjacent subwords.
    assert!(names(&hits).iter().any(|n| n == "MAX_UPLOAD_BYTES"), "{:?}", names(&hits));
    assert!(run(&e, "\"bytes upload\"").iter().all(|h| h.info.name != "MAX_UPLOAD_BYTES"));
}

#[test]
fn a_parameter_is_found_by_name_and_credits_its_function() {
    let src = tree();
    let (_s, e) = engine(src.path());
    // `request` is only a parameter of handle_upload: the function scores
    // for it, and the parameter itself is a result when asked for.
    let hits = run(&e, "request");
    let h = hit(&hits, "handle_upload");
    assert!(h.reasons.iter().any(|r| r.contains("parameter `request`")), "{:?}", h.reasons);
    let hits = run(&e, "request kind:parameter");
    assert_eq!(names(&hits), ["request"]);
    assert_eq!(hits[0].info.kind, SymbolKind::Parameter);
    // Plain search still leaves parameters out; the qualified form finds one.
    assert!(e.search("request").unwrap().iter().all(|id| !e.is_parameter(*id)));
    let q = e.by_qualified_name("handle_upload.request");
    assert_eq!(q.len(), 1);
    assert!(e.is_parameter(q[0]));
}
