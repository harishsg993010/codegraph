//! Rule files, end to end: written in YAML, run over a small tree, with the
//! answers a hand-built spec gives.

use std::path::Path;

use codegraph_index::IndexData;
use codegraph_query::Engine;
use codegraph_resolve::index_tree;
use codegraph_security::{RuleSpec, Security, parse_rules, render_json, render_text, run_rules, worst};
use codegraph_store::Store;

fn write(dir: &Path, rel: &str, body: &str) {
    let p = dir.join(rel);
    if let Some(parent) = p.parent() {
        std::fs::create_dir_all(parent).expect("mkdir");
    }
    std::fs::write(p, body).expect("write");
}

fn build(dir: &Path) -> (tempfile::TempDir, Engine) {
    let sd = tempfile::tempdir().expect("tempdir");
    let mut store = Store::create(sd.path()).expect("create");
    index_tree(dir, &mut store, "").expect("index");
    let index = IndexData::build(&store).expect("index build");
    (sd, Engine::from_parts(store, index))
}

/// A request handler passes user input to a shell in Python, and a Go
/// handler does the same through `exec.Command`; a test file does too.
fn project(dir: &Path) {
    write(
        dir,
        "web/handler.py",
        "import subprocess\n\ndef handle(request):\n    cmd = request.args['c']\n    return subprocess.Popen(cmd)\n\n\
         def safe(request):\n    cmd = request.args['c']\n    return subprocess.Popen(shlex_quote(cmd))\n",
    );
    write(
        dir,
        "srv/run.go",
        "package srv\n\nimport (\n\t\"net/http\"\n\t\"os/exec\"\n)\n\nfunc Handle(w http.ResponseWriter, r *http.Request) {\n\tc := r.FormValue(\"c\")\n\texec.Command(c).Run()\n}\n",
    );
    write(
        dir,
        "srv/run_test.go",
        "package srv\n\nimport (\n\t\"net/http\"\n\t\"os/exec\"\n)\n\nfunc HandleTest(w http.ResponseWriter, r *http.Request) {\n\tc := r.FormValue(\"c\")\n\texec.Command(c).Run()\n}\n",
    );
}

fn results(e: &Engine, yaml: &str) -> Vec<codegraph_security::RuleResult> {
    let rules = parse_rules(yaml, Path::new("rules.yaml")).expect("parse");
    let specs: Vec<RuleSpec> = rules.iter().map(|r| RuleSpec::from_rule(r).expect("spec")).collect();
    run_rules(&Security::new(e), &specs, 50)
}

fn sources_of(r: &codegraph_security::RuleResult) -> Vec<String> {
    let mut v: Vec<String> = r.analysis.as_ref().unwrap().findings.iter().map(|f| format!("{}:{}", f.source.path, f.source.name)).collect();
    v.sort();
    v.dedup();
    v
}

#[test]
fn a_rule_file_finds_the_flow_a_spec_finds() {
    let src = tempfile::tempdir().unwrap();
    project(src.path());
    let (_sd, e) = build(src.path());
    let yaml = r#"
rules:
  - id: py-shell
    message: request data reaches a shell
    severity: ERROR
    languages: [python]
    pattern-sources:
      - name: request
    pattern-sinks:
      - pattern: subprocess.Popen
    pattern-sanitizers:
      - pattern: shlex_quote
  - id: go-shell
    severity: WARNING
    languages: [go]
    paths:
      exclude: [_test.go]
    pattern-sources:
      - pattern: r            # the request parameter: FormValue's summary says its result comes from r
    pattern-sinks:
      - pattern: exec.Command
"#;
    let rs = results(&e, yaml);
    assert_eq!(rs.len(), 2);
    let py = &rs[0];
    assert!(py.error.is_none(), "{:?}", py.error);
    let srcs = sources_of(py);
    // `handle`'s request reaches Popen; `safe`'s goes through the sanitiser.
    assert!(srcs.iter().any(|s| s == "web/handler.py:request"), "{srcs:?}");
    let via: Vec<String> = py.analysis.as_ref().unwrap().findings.iter().map(|f| f.path.iter().map(|s| s.name.clone()).collect::<Vec<_>>().join(">")).collect();
    assert!(via.iter().all(|v| !v.contains("shlex_quote")), "{via:?}");
    assert!(!py.analysis.as_ref().unwrap().findings.iter().any(|f| f.path.iter().any(|s| s.name == "safe")), "{via:?}");
    // The Go rule sees run.go and not run_test.go.
    let go = &rs[1];
    let srcs = sources_of(go);
    assert!(srcs.iter().any(|s| s.starts_with("srv/run.go:")), "{srcs:?}");
    assert!(!srcs.iter().any(|s| s.contains("_test.go")), "{srcs:?}");
    assert_eq!(worst(&rs), Some(codegraph_security::Severity::Error));

    // Both reports carry the ids and severities.
    let text = render_text(&rs, &|s| format!("{} ({}:{})", s.name, s.path, s.line));
    assert!(text.contains("py-shell [ERROR] — request data reaches a shell"), "{text}");
    assert!(text.contains("go-shell [WARNING]"), "{text}");
    let json: serde_json::Value = serde_json::from_str(&render_json(&rs)).unwrap();
    assert_eq!(json["worst"], "ERROR");
    assert_eq!(json["rules"][0]["id"], "py-shell");
    assert!(!json["rules"][0]["findings"].as_array().unwrap().is_empty());
    assert_eq!(json["rules"][0]["findings"][0]["sink"]["name"], "Popen");
}

#[test]
fn languages_and_include_paths_narrow_a_rule() {
    let src = tempfile::tempdir().unwrap();
    project(src.path());
    let (_sd, e) = build(src.path());
    // The same patterns restricted to Python find nothing in Go.
    let yaml = r#"
rules:
  - id: only-python
    languages: [python]
    pattern-sources: [r]
    pattern-sinks: [exec.Command]
  - id: only-web
    paths: { include: [web/] }
    pattern-sources: [request]
    pattern-sinks: [subprocess.Popen, exec.Command]
"#;
    let rs = results(&e, yaml);
    assert_eq!(rs[0].analysis.as_ref().unwrap().findings.len(), 0, "{}", render_text(&rs, &|s| s.name.clone()));
    let srcs = sources_of(&rs[1]);
    assert!(srcs.iter().all(|s| s.starts_with("web/")), "{srcs:?}");
    assert!(!srcs.is_empty());
}

#[test]
fn a_callgraph_rule_asks_the_other_question() {
    let src = tempfile::tempdir().unwrap();
    project(src.path());
    let (_sd, e) = build(src.path());
    let yaml = r#"
rules:
  - id: reach
    mode: callgraph
    pattern-sources: [handle]
    pattern-sinks: [subprocess.Popen]
"#;
    let rs = results(&e, yaml);
    let a = rs[0].analysis.as_ref().unwrap();
    assert!(a.findings.iter().any(|f| f.source.name == "handle" && f.sink.name == "Popen"), "{}", render_text(&rs, &|s| s.name.clone()));
}

#[test]
fn the_shipped_starter_rules_parse() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../rules/starter.yaml");
    let rules = codegraph_security::load_rules(&path).expect("starter rules parse");
    assert!(rules.len() >= 5);
    for r in &rules {
        RuleSpec::from_rule(r).unwrap_or_else(|e| panic!("{}: {e}", r.id));
        assert!(!r.message.is_empty(), "{}: a starter rule says what it finds", r.id);
    }
}
