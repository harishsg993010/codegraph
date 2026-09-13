//! The security layer against a project with a known-shape vulnerability.

use codegraph_index::{IndexData, IndexQuery};
use codegraph_query::Engine;
use codegraph_resolve::index_tree;
use codegraph_security::{Matcher, Security, TaintSpec};
use codegraph_store::Store;
use std::path::Path;

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

/// `read_request` -> `build_command` -> `run_shell`, plus an unrelated
/// `safe_path` that must never be reported.
fn vulnerable_project(dir: &Path) {
    write(
        dir,
        "app/shell.py",
        "import subprocess\n\ndef run_shell(cmd):\n    return subprocess.Popen(cmd)\n",
    );
    write(
        dir,
        "app/cmd.py",
        "import app.shell\n\ndef build_command(raw):\n    return run_shell(raw)\n",
    );
    write(
        dir,
        "app/web.py",
        "import app.cmd\n\ndef read_request(req):\n    return build_command(req)\n\n\
         def main():\n    read_request(None)\n",
    );
    write(
        dir,
        "app/safe.py",
        "def safe_path():\n    return 1\n\ndef unused_helper():\n    safe_path()\n",
    );
}

fn spec() -> TaintSpec {
    TaintSpec::new("test")
        .source(Matcher::name("read_request"))
        .sink(Matcher::name("run_shell"))
}

#[test]
fn a_reachable_source_to_sink_path_is_found() {
    let src = tempfile::tempdir().unwrap();
    vulnerable_project(src.path());
    let (_sd, e) = build(src.path());
    let sec = Security::new(&e);

    let a = sec.analyse(&spec(), 100).unwrap();
    assert_eq!(a.sources, 1, "the source matcher resolved {} symbols", a.sources);
    assert_eq!(a.sinks, 1);
    assert_eq!(a.findings.len(), 1, "expected one finding");

    let f = &a.findings[0];
    assert_eq!(f.source.name, "read_request");
    assert_eq!(f.sink.name, "run_shell");
    // read_request -> build_command -> run_shell
    assert_eq!(f.depth(), 2, "path was {:?}", f.path.iter().map(|s| &s.name).collect::<Vec<_>>());
    assert_eq!(f.path.first().map(|s| s.name.as_str()), Some("read_request"));
    assert_eq!(f.path.last().map(|s| s.name.as_str()), Some("run_shell"));
}

/// A sink matched by name catches unrelated symbols sharing that name. On a
/// real Go corpus, `Exec` matched the database layer's `Exec` rather than
/// `os/exec`, and every finding was that one collision repeated. An exclusion
/// has to remove the wrong symbol without removing the name.
#[test]
fn an_exclusion_removes_a_collided_sink_and_keeps_the_real_one() {
    let src = tempfile::tempdir().unwrap();
    vulnerable_project(src.path());
    // A second, unrelated `run_shell` that the name matcher will also catch.
    write(
        src.path(),
        "db/orm.py",
        "def run_shell(sql):
    return 1

def read_request(q):
    return run_shell(q)
",
    );
    let (_sd, e) = build(src.path());
    let sec = Security::new(&e);

    let both = sec.analyse(&spec(), 100).unwrap();
    assert_eq!(both.sinks, 2, "the collision is the premise of this test");
    assert_eq!(both.findings.len(), 2);

    let narrowed = spec().exclude(Matcher::in_path("db/"));
    let a = sec.analyse(&narrowed, 100).unwrap();
    assert_eq!(a.sinks, 1, "the exclusion should leave the real sink");
    assert_eq!(a.findings.len(), 1);
    assert!(
        a.findings[0].sink.path.starts_with("app/"),
        "kept the excluded sink: {}",
        a.findings[0].sink.path
    );
}

/// The direction matters: a sink does not reach its source.
#[test]
fn the_reverse_direction_reports_nothing() {
    let src = tempfile::tempdir().unwrap();
    vulnerable_project(src.path());
    let (_sd, e) = build(src.path());
    let sec = Security::new(&e);

    let reversed = TaintSpec::new("reversed")
        .source(Matcher::name("run_shell"))
        .sink(Matcher::name("read_request"));
    assert!(sec.analyse(&reversed, 100).unwrap().findings.is_empty());
}

/// **The sanitiser property.** A sanitiser on the only path must suppress the
/// finding entirely, not merely annotate it.
#[test]
fn a_sanitizer_on_the_path_suppresses_the_finding() {
    let src = tempfile::tempdir().unwrap();
    vulnerable_project(src.path());
    let (_sd, e) = build(src.path());
    let sec = Security::new(&e);

    let sanitized = spec().sanitizer(Matcher::name("build_command"));
    let a = sec.analyse(&sanitized, 100).unwrap();
    assert_eq!(a.sanitizers, 1, "the sanitizer matcher resolved nothing");
    assert!(
        a.findings.is_empty(),
        "a path through a sanitizer was still reported: {:?}",
        a.findings.iter().map(|f| f.path.len()).collect::<Vec<_>>()
    );
}

/// A sanitiser that is not on the path must not suppress anything.
#[test]
fn an_unrelated_sanitizer_does_not_suppress() {
    let src = tempfile::tempdir().unwrap();
    vulnerable_project(src.path());
    let (_sd, e) = build(src.path());
    let sec = Security::new(&e);

    let a = sec.analyse(&spec().sanitizer(Matcher::name("safe_path")), 100).unwrap();
    assert_eq!(a.findings.len(), 1, "an unrelated sanitizer suppressed a real finding");
}

#[test]
fn entrypoints_are_detected() {
    let src = tempfile::tempdir().unwrap();
    vulnerable_project(src.path());
    let (_sd, e) = build(src.path());
    let sec = Security::new(&e);

    let eps = sec.entrypoints().unwrap();
    let names: Vec<String> = eps
        .iter()
        .filter_map(|id| e.info(*id).unwrap())
        .map(|i| i.name)
        .collect();
    assert!(names.contains(&"main".to_string()), "got {names:?}");
}

/// Reachability from an entrypoint is what separates a live finding from dead
/// code, so it has to actually discriminate.
#[test]
fn entrypoint_reachability_discriminates() {
    let src = tempfile::tempdir().unwrap();
    vulnerable_project(src.path());
    let (_sd, e) = build(src.path());
    let sec = Security::new(&e);

    let live = sec.reachable_from_entrypoints().unwrap();
    let live_names: std::collections::HashSet<String> = live
        .iter()
        .filter_map(|id| e.info(*id).unwrap())
        .map(|i| i.name)
        .collect();

    assert!(live_names.contains("read_request"), "got {live_names:?}");
    assert!(live_names.contains("run_shell"), "got {live_names:?}");
    // `unused_helper` is called by nothing and is not itself an entrypoint.
    assert!(
        !live_names.contains("unused_helper"),
        "dead code was reported as reachable: {live_names:?}"
    );

    // And the finding carries that fact.
    let a = sec.analyse(&spec(), 100).unwrap();
    assert!(a.findings[0].reachable_from_entrypoint);
}

#[test]
fn a_spec_matching_nothing_is_visible_rather_than_a_silent_pass() {
    let src = tempfile::tempdir().unwrap();
    vulnerable_project(src.path());
    let (_sd, e) = build(src.path());
    let sec = Security::new(&e);

    let s = TaintSpec::new("empty")
        .source(Matcher::name("no_such_source"))
        .sink(Matcher::name("no_such_sink"));
    let a = sec.analyse(&s, 100).unwrap();
    assert_eq!(a.sources, 0, "an unmatched source must report zero, not pass silently");
    assert_eq!(a.sinks, 0);
    assert!(a.findings.is_empty());
}

#[test]
fn findings_are_capped() {
    let src = tempfile::tempdir().unwrap();
    vulnerable_project(src.path());
    let (_sd, e) = build(src.path());
    let sec = Security::new(&e);
    assert!(sec.analyse(&spec(), 0).unwrap().findings.is_empty());
}

// --- dependency reachability ---

#[test]
fn external_packages_become_nodes_with_dependents() {
    let src = tempfile::tempdir().unwrap();
    vulnerable_project(src.path());
    let (_sd, e) = build(src.path());
    let sec = Security::new(&e);

    let pkgs = sec.packages().unwrap();
    assert!(
        pkgs.iter().any(|(n, _)| n == "subprocess"),
        "subprocess was not modelled as a package: {pkgs:?}"
    );
}

#[test]
fn package_reach_names_the_importing_files() {
    let src = tempfile::tempdir().unwrap();
    vulnerable_project(src.path());
    let (_sd, e) = build(src.path());
    let sec = Security::new(&e);

    let reach = sec.package_reach("subprocess").unwrap().expect("package present");
    assert_eq!(reach.package, "subprocess");
    assert!(
        reach.importers.iter().any(|i| i.path == "app/shell.py"),
        "importers were {:?}",
        reach.importers.iter().map(|i| &i.path).collect::<Vec<_>>()
    );
}

#[test]
fn an_absent_package_reports_none_rather_than_an_empty_result() {
    let src = tempfile::tempdir().unwrap();
    vulnerable_project(src.path());
    let (_sd, e) = build(src.path());
    let sec = Security::new(&e);
    assert!(
        sec.package_reach("definitely-not-imported").unwrap().is_none(),
        "an absent package must be distinguishable from one with no importers"
    );
}

/// The index filter is the reason this is affordable; the analysis reports how
/// much work it saved, and that number must be real.
#[test]
fn the_analysis_reports_how_many_pairs_the_index_rejected() {
    let src = tempfile::tempdir().unwrap();
    vulnerable_project(src.path());
    let (_sd, e) = build(src.path());
    let sec = Security::new(&e);

    // Every function against every function: mostly unreachable pairs.
    let broad = TaintSpec::new("broad")
        .source(Matcher::prefix(""))
        .sink(Matcher::prefix(""));
    let a = sec.analyse(&broad, 1000).unwrap();
    assert!(a.total_pairs() > 0);
    assert_eq!(a.total_pairs(), a.pairs_rejected_by_index + a.pairs_searched);
    assert!(
        a.rejection_rate() > 0.5,
        "the index rejected only {:.1}% of pairs",
        a.rejection_rate() * 100.0
    );
}

/// Regression: a taint path must be a chain of *calls*, not a chain of file
/// imports. Following import relations produced findings like
/// `request.py -> subprocess` — structurally real, analytically meaningless.
#[test]
fn a_taint_path_does_not_run_through_file_imports() {
    let src = tempfile::tempdir().unwrap();
    // Two files linked only by an import: no call connects them.
    write(src.path(), "a.py", "import b\n\ndef reader():\n    return 1\n");
    write(src.path(), "b.py", "def danger():\n    return 2\n");
    let (_sd, e) = build(src.path());
    let sec = Security::new(&e);

    let s = TaintSpec::new("import-only")
        .source(Matcher::name("reader"))
        .sink(Matcher::name("danger"));
    assert!(
        sec.analyse(&s, 100).unwrap().findings.is_empty(),
        "an import with no call between the two functions was reported as a taint path"
    );
}

/// File and package symbols cannot be taint sources or sinks — they do not
/// execute.
#[test]
fn files_and_packages_are_not_taint_endpoints() {
    let src = tempfile::tempdir().unwrap();
    vulnerable_project(src.path());
    let (_sd, e) = build(src.path());
    let sec = Security::new(&e);

    // `shell` matches both the file `shell.py` and nothing else executable.
    let s = TaintSpec::new("filey")
        .source(Matcher::contains("shell"))
        .sink(Matcher::contains("subprocess"));
    let a = sec.analyse(&s, 100).unwrap();
    for f in &a.findings {
        assert!(
            !f.source.path.is_empty() && f.source.line > 0,
            "a file symbol was reported as a taint source: {:?}",
            f.source
        );
        assert_ne!(
            f.sink.kind,
            codegraph_core::SymbolKind::Package,
            "a package was reported as a taint sink"
        );
    }
}

/// The narrowed flow mask must still be covered by the reachability index, or
/// the fast rejection silently stops applying.
#[test]
fn the_flow_mask_is_still_covered_by_the_index() {
    let src = tempfile::tempdir().unwrap();
    vulnerable_project(src.path());
    let (_sd, e) = build(src.path());
    assert!(
        e.index().covers(codegraph_security::FLOW),
        "the taint flow mask escaped what the reachability index covers"
    );
}

/// The analysis on a store that has grown by deltas, through the layered
/// index, must match the analysis on the same store compacted and rebuilt.
/// The sanitiser path sizes a per-id array; on a delta store the id space is
/// larger than the live symbol count, which is exactly what this caught.
#[test]
fn a_delta_store_analyses_like_its_compacted_form() {
    use codegraph_index::open_or_build;
    use codegraph_store::CompactPolicy;

    let src = tempfile::tempdir().unwrap();
    vulnerable_project(src.path());
    let sd = tempfile::tempdir().unwrap();
    let mut store = Store::create(sd.path()).expect("create");
    index_tree(src.path(), &mut store, "").expect("index");
    open_or_build(&store, sd.path()).unwrap();

    // A new sink and a new route to it: added edges, which is what the
    // overlay's bitsets exist for.
    write(
        src.path(),
        "app/shell.py",
        "import subprocess\n\ndef run_shell(cmd):\n    return subprocess.Popen(cmd)\n\ndef run_shell2(cmd):\n    return subprocess.Popen(cmd)\n",
    );
    write(
        src.path(),
        "app/web.py",
        "import app.cmd\nimport app.shell\n\ndef read_request(req):\n    return build_command(req)\n\n\
         def read_other(req):\n    run_shell2(req)\n\ndef main():\n    read_request(None)\n",
    );
    let never = CompactPolicy { max_deltas: 1000, max_delta_ratio: 1000.0 };
    codegraph_resolve::update_tree(src.path(), &mut store, "", &never).unwrap();
    assert!(store.segments().count() > 1, "precondition: a delta store");

    let two_sinks = || {
        TaintSpec::new("test")
            .source(Matcher::prefix("read_"))
            .sink(Matcher::prefix("run_shell"))
            .sanitizer(Matcher::name("build_command"))
    };
    let describe = |engine: &Engine<codegraph_index::Layered<codegraph_index::MappedIndex>>| {
        let a = Security::new(engine).analyse(&two_sinks(), 10).unwrap();
        let mut out: Vec<String> = a
            .findings
            .iter()
            .map(|f| format!("{} -> {} ({} hops)", f.source.name, f.sink.name, f.depth()))
            .collect();
        out.sort();
        (a.sources, a.sinks, out)
    };

    let (index, _) = open_or_build(&store, sd.path()).unwrap();
    let layered = describe(&Engine::from_parts(Store::open(sd.path()).unwrap(), index));
    assert_eq!(layered.2, ["read_other -> run_shell2 (1 hops)"], "{layered:?}");

    codegraph_store::compact(&mut store).unwrap().expect("deltas to merge");
    let (index, how) = open_or_build(&store, sd.path()).unwrap();
    assert_eq!(how, codegraph_index::Opened::Rebuilt);
    let rebuilt = describe(&Engine::from_parts(Store::open(sd.path()).unwrap(), index));
    assert_eq!(layered, rebuilt);
}

// --- dataflow mode ---

use codegraph_security::Mode;

fn build_engine(src: &Path) -> (tempfile::TempDir, Engine<codegraph_index::Layered<codegraph_index::MappedIndex>>) {
    let sd = tempfile::tempdir().expect("tempdir");
    let mut store = Store::create(sd.path()).expect("create");
    index_tree(src, &mut store, "").expect("index");
    let (index, _) = codegraph_index::open_or_build(&store, sd.path()).expect("index");
    (sd, Engine::from_parts(store, index))
}

fn finding_names<I: codegraph_index::IndexQuery>(e: &Engine<I>, spec: &TaintSpec) -> Vec<String> {
    let a = Security::new(e).analyse(spec, 100).unwrap();
    let mut out: Vec<String> = a
        .findings
        .iter()
        .map(|f| f.path.iter().map(|s| s.name.clone()).collect::<Vec<_>>().join(" -> "))
        .collect();
    out.sort();
    out
}

/// Three languages, one shape: `read_request(req)` hands `req` down two
/// calls into a process-spawning library call, and `safe()` calls the same
/// chain with a constant. Call-graph mode cannot tell the two apart;
/// dataflow mode can.
#[test]
fn dataflow_mode_follows_the_value_and_ignores_the_constant_caller() {
    // (language, files, source, wrapper around the sink, the library sink)
    type Case = (&'static str, Vec<(&'static str, &'static str)>, &'static str, &'static str, &'static str);
    let cases: Vec<Case> = vec![
        (
            "python",
            vec![
                ("app/shell.py", "import subprocess\n\ndef run_shell(cmd):\n    return subprocess.Popen(cmd)\n"),
                ("app/cmd.py", "import app.shell\n\ndef build_command(raw):\n    return run_shell(raw)\n"),
                ("app/web.py", "import app.cmd\n\ndef read_request(req):\n    return build_command(req)\n\ndef safe():\n    return build_command(\"ls\")\n"),
            ],
            "read_request",
            "run_shell",
            "Popen",
        ),
        (
            "go",
            vec![
                ("go.mod", "module mod\n"),
                ("shell/shell.go", "package shell\n\nimport \"os/exec\"\n\nfunc RunShell(cmd string) {\n\texec.Command(cmd)\n}\n"),
                ("cmd/cmd.go", "package cmd\n\nimport \"mod/shell\"\n\nfunc BuildCommand(raw string) {\n\tshell.RunShell(raw)\n}\n"),
                ("web/web.go", "package web\n\nimport \"mod/cmd\"\n\nfunc ReadRequest(req string) {\n\tcmd.BuildCommand(req)\n}\n\nfunc Safe() {\n\tcmd.BuildCommand(\"ls\")\n}\n"),
            ],
            "ReadRequest",
            "RunShell",
            "Command",
        ),
        (
            "javascript",
            vec![
                ("app/shell.js", "import { exec } from \"child_process\";\n\nexport function runShell(cmd) {\n  exec(cmd);\n}\n"),
                ("app/cmd.js", "import { runShell } from \"./shell.js\";\n\nexport function buildCommand(raw) {\n  runShell(raw);\n}\n"),
                ("app/web.js", "import { buildCommand } from \"./cmd.js\";\n\nexport function readRequest(req) {\n  buildCommand(req);\n}\n\nexport function safe() {\n  buildCommand(\"ls\");\n}\n"),
            ],
            "readRequest",
            "runShell",
            "exec",
        ),
    ];
    for (lang, files, source, wrapper, sink) in cases {
        let src = tempfile::tempdir().unwrap();
        for (p, body) in &files {
            write(src.path(), p, body);
        }
        let (_sd, e) = build_engine(src.path());
        let safe = if lang == "go" { "Safe" } else { "safe" };

        // Call-graph mode: both callers reach the wrapper around the sink,
        // constant or not. (A call-graph edge never targets a library stub;
        // the wrapper is the closest a call path gets.)
        let cg = TaintSpec::new("cg").source(Matcher::name(source)).source(Matcher::name(safe)).sink(Matcher::name(wrapper));
        let cg_findings = finding_names(&e, &cg);
        assert!(cg_findings.iter().any(|f| f.to_lowercase().contains("safe")), "{lang}: call-graph mode did not report the constant caller: {cg_findings:?}");

        // Dataflow mode: the request parameter reaches the sink's argument;
        // the constant does not.
        let df = TaintSpec::new("df").mode(Mode::DataFlow).source(Matcher::name(source)).source(Matcher::name(safe)).sink(Matcher::name(sink));
        let df_findings = finding_names(&e, &df);
        assert!(
            df_findings.iter().any(|f| f.starts_with("req") && f.ends_with(sink)),
            "{lang}: no value path from req to {sink}: {df_findings:?}"
        );
        assert!(
            !df_findings.iter().any(|f| f.to_lowercase().contains("safe")),
            "{lang}: the constant caller was reported in dataflow mode: {df_findings:?}"
        );
        // The path names the parameters it went through.
        let path = df_findings.iter().find(|f| f.starts_with("req")).unwrap();
        assert!(path.contains("raw") && path.contains("cmd"), "{lang}: path does not go through the parameters: {path}");
    }
}

/// A killed definition, a by-reference write, and a sanitiser, in dataflow
/// mode.
#[test]
fn dataflow_mode_respects_kills_and_sanitisers() {
    let src = tempfile::tempdir().unwrap();
    write(
        src.path(),
        "app/a.py",
        "import subprocess\n\n\
         def killed(req):\n    cmd = req\n    cmd = 'ls'\n    subprocess.Popen(cmd)\n\n\
         def live(req):\n    cmd = req\n    subprocess.Popen(cmd)\n\n\
         def cleaned(req):\n    cmd = escape(req)\n    subprocess.Popen(cmd)\n",
    );
    let (_sd, e) = build_engine(src.path());
    let spec = |sanitised: bool| {
        let s = TaintSpec::new("df")
            .mode(Mode::DataFlow)
            .source(Matcher::name("killed"))
            .source(Matcher::name("live"))
            .source(Matcher::name("cleaned"))
            .sink(Matcher::name("Popen"));
        if sanitised { s.sanitizer(Matcher::name("escape")) } else { s }
    };
    let found = finding_names(&e, &spec(false));
    let starts: Vec<&str> = found.iter().map(|f| f.split(" -> ").next().unwrap()).collect();
    assert!(found.iter().any(|f| f.contains("live")) || starts.contains(&"req"), "live flow missing: {found:?}");
    // `killed` never reaches Popen with req: its cmd was overwritten.
    let killed_param = e.by_name("killed").into_iter().flat_map(|k| e.neighbors(k, codegraph_query::Direction::Out, codegraph_core::RelationMask::of(&[codegraph_core::Relation::Contains])).unwrap()).map(|h| h.id).collect::<Vec<_>>();
    assert!(!killed_param.is_empty());
    let a = Security::new(&e).analyse(&spec(false), 100).unwrap();
    for f in &a.findings {
        assert!(!killed_param.contains(&f.source.id), "killed's parameter reached Popen through an overwritten variable: {}", f.path.iter().map(|s| s.name.clone()).collect::<Vec<_>>().join(" -> "));
    }
    // With `escape` as a sanitiser, `cleaned` no longer reports (its value
    // passes through the stub `escape`), while `live` still does.
    let sanitised = finding_names(&e, &spec(true));
    let a2 = Security::new(&e).analyse(&spec(true), 100).unwrap();
    let cleaned_param: Vec<_> = e.by_name("cleaned").into_iter().flat_map(|k| e.neighbors(k, codegraph_query::Direction::Out, codegraph_core::RelationMask::of(&[codegraph_core::Relation::Contains])).unwrap()).map(|h| h.id).collect();
    assert!(!a2.findings.iter().any(|f| cleaned_param.contains(&f.source.id)), "sanitiser ignored: {sanitised:?}");
    assert!(!sanitised.is_empty(), "the live flow disappeared with the sanitiser: {sanitised:?}");
}

/// `strcpy(buf, x); system(buf)`: the value reaches `system`. `strcpy` has
/// a library summary — argument 0 is written from the rest — so the flow
/// is recorded at extraction, `x -> buf -> system`, without a hop through
/// the stub; a library call without one would go through its stub,
/// entering and leaving on the same call site.
#[test]
fn dataflow_mode_follows_a_by_reference_write_through_a_library_call() {
    let src = tempfile::tempdir().unwrap();
    write(
        src.path(),
        "a.c",
        "#include <string.h>
#include <stdlib.h>

void run(char *x) {
  char buf[64];
  strcpy(buf, x);
  system(buf);
}

void other(char *y) {
  char b2[64];
  strcpy(b2, \"ls\");
  system(b2);
}
",
    );
    let (_sd, e) = build_engine(src.path());
    let spec = TaintSpec::new("df").mode(Mode::DataFlow).source(Matcher::name("run")).source(Matcher::name("other")).sink(Matcher::name("system"));
    let found = finding_names(&e, &spec);
    assert!(found.iter().any(|f| f.starts_with("x") && f.ends_with("system")), "x did not reach system through strcpy: {found:?}");
    // `other` copies a constant: its parameter never reaches system, and
    // `run`'s x must not leak into `other`'s call through the shared stub.
    assert!(!found.iter().any(|f| f.starts_with("y")), "the shared strcpy stub leaked across call sites: {found:?}");
}

/// Library summaries replace the default "every input may reach the
/// result, every argument may be written" at known calls. Without them,
/// each of the negative cases here is a finding.
#[test]
fn library_summaries_stop_the_default_over_approximation() {
    let src = tempfile::tempdir().unwrap();
    write(
        src.path(),
        "a.go",
        r#"package p

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strconv"

	"github.com/stretchr/testify/assert"
)

func viaSprintf(input string, other string) {
	msg := fmt.Sprintf("hello %s", other)
	exec.Command(msg)
}

func viaLen(input string) {
	n := len(input)
	s := strconv.Itoa(n)
	exec.Command(s)
}

func viaUnmarshal(input string) {
	var v Config
	json.Unmarshal([]byte(input), &v)
	exec.Command(v.Name)
}

func viaEqual(t *T, a string, b string) {
	assert.Equal(t, a, b)
	exec.Command(b)
}

func viaGetenv(input string) {
	p := os.Getenv(input)
	exec.Command(p)
}
"#,
    );
    let (_sd, e) = build_engine(src.path());
    let spec = |sources: &[&str]| {
        let mut s = TaintSpec::new("df").mode(Mode::DataFlow).sink(Matcher::name("Command"));
        for src in sources {
            s = s.source(Matcher::name(src));
        }
        s
    };
    let found = finding_names(&e, &spec(&["viaSprintf", "viaLen", "viaUnmarshal", "viaEqual", "viaGetenv"]));
    let has = |from: &str| found.iter().any(|f| f.starts_with(from) && f.ends_with("Command"));
    // `other` is formatted into the command; `input` never meets it.
    assert!(has("other"), "{found:?}");
    assert!(!found.iter().any(|f| f.starts_with("input -> ") && f.contains("Sprintf")), "input reached Command through Sprintf: {found:?}");
    // `len` produces a number, `Itoa` a string of it: nothing of `input`.
    assert!(!found.iter().any(|f| f.contains("Itoa")), "input reached Command through len/Itoa: {found:?}");
    // `Unmarshal` writes its second argument from its first.
    assert!(found.iter().any(|f| f.starts_with("input") && f.ends_with("Command")), "input did not reach Command through Unmarshal: {found:?}");
    // `assert.Equal` writes nothing: `a` does not become `b`.
    assert!(!has("a"), "a reached Command through assert.Equal: {found:?}");
    // `os.Getenv` returns external data, whatever its argument was.
    assert!(!found.iter().any(|f| f.starts_with("input") && f.contains("Getenv")), "input reached Command through Getenv: {found:?}");
    // …and that external data is a source in its own right.
    let env = finding_names(&e, &spec(&["Getenv"]));
    assert!(env.iter().any(|f| f.starts_with("Getenv") && f.ends_with("Command")), "{env:?}");
}

/// Context sensitivity: a value that enters a shared callee from one call
/// site leaves it into that call site only. `id` is called by `tainted`
/// with a source and by `clean` with a constant; without matching the
/// sites, the source would reach `clean`'s sink through `id`'s one
/// `param -> return` edge.
#[test]
fn a_value_leaves_a_callee_only_at_the_call_site_it_entered() {
    let src = tempfile::tempdir().unwrap();
    write(
        src.path(),
        "a.py",
        "def ident(x):\n    return x\n\ndef tainted(req):\n    v = ident(req)\n    return v\n\ndef clean():\n    c = ident(\"constant\")\n    run_shell(c)\n\ndef also_tainted(req):\n    d = ident(req)\n    run_shell(d)\n",
    );
    let (_sd, e) = build_engine(src.path());
    let spec = TaintSpec::new("cs").mode(Mode::DataFlow).source(Matcher::name("tainted")).source(Matcher::name("also_tainted")).sink(Matcher::name("run_shell"));
    let a = Security::new(&e).analyse(&spec, 100).unwrap();
    // The sources that reach run_shell, by line: `also_tainted`'s req (line
    // 12) does, through ident at its own call site; `tainted`'s req (line 4)
    // enters ident at a site that leaves only into `v`, and `v` is returned,
    // not run. Context-insensitively both would be reported.
    let mut lines: Vec<u32> = a.findings.iter().map(|f| f.source.line).collect();
    lines.sort();
    lines.dedup();
    assert_eq!(lines, [12], "{:?}", a.findings.iter().map(|f| f.path.iter().map(|s| format!("{}:{}", s.name, s.line)).collect::<Vec<_>>()).collect::<Vec<_>>());
    // Two levels: `wrap` calls `ident`; the site stack matches both.
    write(
        src.path(),
        "b.py",
        "def ident2(x):\n    return x\n\ndef wrap(y):\n    return ident2(y)\n\ndef hot(req):\n    run_shell(wrap(req))\n\ndef cold():\n    run_shell(wrap(\"k\"))\n",
    );
    let (_sd, e) = build_engine(src.path());
    let spec = TaintSpec::new("cs2").mode(Mode::DataFlow).source(Matcher::name("hot")).sink(Matcher::name("run_shell"));
    let a = Security::new(&e).analyse(&spec, 100).unwrap();
    // Exactly the hot path: hot's req -> wrap -> ident2 -> wrap -> run_shell.
    let paths: Vec<Vec<String>> = a.findings.iter().map(|f| f.path.iter().map(|s| s.name.clone()).collect()).collect();
    assert!(paths.iter().all(|p| p.first().map(String::as_str) == Some("req") || p.first().map(String::as_str) == Some("hot")), "{paths:?}");
    assert!(!paths.is_empty(), "the two-level flow is missing");
}
