//! Declarations, parameters, references and flow facts, checked with the same
//! assertions across every Tier-1 language.
//!
//! Each snippet has the same shapes: a module-level constant `LIMIT`, a type
//! `A` with a field `count` and a method `m(x, y)` whose body is
//!
//! ```text
//! z = x + LIMIT
//! self.count = z
//! w = helper(z, y)
//! return w
//! ```
//!
//! plus a function `killed(x)` where a definition is overwritten before use, a
//! function `branchy(c, x, y)` where both branches define the value, and a
//! function `loopy(c, x)` that redefines through a loop (its condition
//! compares two variables on purpose: `while c` with `c` a parameter nothing
//! writes is a loop that never exits, and the predicate pruning knows it). A language whose
//! tables are subtly wrong fails a shared assertion rather than quietly
//! under-extracting.

use codegraph_core::SymbolKind;
use codegraph_extract::{ArgPos, FileExtract, FlowNode, RawFlow, Walker, lang};

fn extract(lang_name: &str, path: &str, src: &str) -> FileExtract {
    let config = lang::ALL
        .iter()
        .copied()
        .find(|c| c.name == lang_name)
        .unwrap_or_else(|| panic!("no config named {lang_name}"));
    let mut w = Walker::new(config).expect("walker");
    w.extract(path, src.as_bytes()).expect("parse")
}

fn snippets() -> Vec<(&'static str, &'static str, &'static str)> {
    vec![
        (
            "python",
            "a.py",
            r#"
LIMIT = 10

class A:
    count = 0

    def m(self, x, y):
        z = x + LIMIT
        self.count = z
        w = helper(z, y)
        return w

def killed(x):
    z = x
    z = 1
    helper(z)

def branchy(c, x, y):
    if c:
        z = x
    else:
        z = y
    helper(z)

def loopy(c, x):
    z = x
    while z < x:
        z = helper(z)
    return z
"#,
        ),
        (
            "javascript",
            "a.js",
            r#"
const LIMIT = 10;

class A {
  count = 0;
  m(x, y) {
    let z = x + LIMIT;
    this.count = z;
    const w = helper(z, y);
    return w;
  }
}

function killed(x) {
  let z = x;
  z = 1;
  helper(z);
}

function branchy(c, x, y) {
  let z;
  if (c) { z = x; } else { z = y; }
  helper(z);
}

function loopy(c, x) {
  let z = x;
  while (z < x) { z = helper(z); }
  return z;
}
"#,
        ),
        (
            "typescript",
            "a.ts",
            r#"
const LIMIT: number = 10;

class A {
  count: number = 0;
  m(x: number, y: number): number {
    let z = x + LIMIT;
    this.count = z;
    const w = helper(z, y);
    return w;
  }
}

function killed(x: number) {
  let z = x;
  z = 1;
  helper(z);
}

function branchy(c: boolean, x: number, y: number) {
  let z;
  if (c) { z = x; } else { z = y; }
  helper(z);
}

function loopy(c: boolean, x: number) {
  let z = x;
  while (z < x) { z = helper(z); }
  return z;
}
"#,
        ),
        (
            "java",
            "A.java",
            r#"
class A {
  static final int LIMIT = 10;
  int count = 0;

  int m(int x, int y) {
    int z = x + LIMIT;
    this.count = z;
    int w = helper(z, y);
    return w;
  }

  void killed(int x) {
    int z = x;
    z = 1;
    helper(z);
  }

  void branchy(boolean c, int x, int y) {
    int z;
    if (c) { z = x; } else { z = y; }
    helper(z);
  }

  int loopy(boolean c, int x) {
    int z = x;
    while (z < x) { z = helper(z); }
    return z;
  }
}
"#,
        ),
        (
            "c",
            "a.c",
            r#"
const int LIMIT = 10;

int count = 0;

int m(int x, int y) {
  int z = x + LIMIT;
  count = z;
  int w = helper(z, y);
  return w;
}

void killed(int x) {
  int z = x;
  z = 1;
  helper(z);
}

void branchy(int c, int x, int y) {
  int z;
  if (c) { z = x; } else { z = y; }
  helper(z);
}

int loopy(int c, int x) {
  int z = x;
  while (z < x) { z = helper(z); }
  return z;
}
"#,
        ),
        (
            "cpp",
            "a.cpp",
            r#"
const int LIMIT = 10;

class A {
 public:
  int count = 0;
  int m(int x, int y) {
    int z = x + LIMIT;
    this->count = z;
    int w = helper(z, y);
    return w;
  }
};

void killed(int x) {
  int z = x;
  z = 1;
  helper(z);
}

void branchy(bool c, int x, int y) {
  int z;
  if (c) { z = x; } else { z = y; }
  helper(z);
}

int loopy(bool c, int x) {
  int z = x;
  while (z < x) { z = helper(z); }
  return z;
}
"#,
        ),
        (
            "go",
            "a.go",
            r#"
package p

const LIMIT = 10

type A struct {
	count int
}

func (a *A) m(x int, y int) int {
	z := x + LIMIT
	a.count = z
	w := helper(z, y)
	return w
}

func killed(x int) {
	z := x
	z = 1
	helper(z)
}

func branchy(c bool, x int, y int) {
	var z int
	if c {
		z = x
	} else {
		z = y
	}
	helper(z)
}

func loopy(c bool, x int) int {
	z := x
	for z < x {
		z = helper(z)
	}
	return z
}
"#,
        ),
        (
            "rust",
            "a.rs",
            r#"
const LIMIT: u32 = 10;

struct A { count: u32 }

impl A {
    fn m(&mut self, x: u32, y: u32) -> u32 {
        let z = x + LIMIT;
        self.count = z;
        let w = helper(z, y);
        w
    }
}

fn killed(x: u32) {
    let mut z = x;
    z = 1;
    helper(z);
}

fn branchy(c: bool, x: u32, y: u32) {
    let z;
    if c { z = x; } else { z = y; }
    helper(z);
}

fn loopy(c: bool, x: u32) -> u32 {
    let mut z = x;
    while z < x { z = helper(z); }
    z
}
"#,
        ),
        (
            "csharp",
            "A.cs",
            r#"
class A {
  const int LIMIT = 10;
  int count = 0;

  int m(int x, int y) {
    int z = x + LIMIT;
    this.count = z;
    var w = helper(z, y);
    return w;
  }

  void killed(int x) {
    int z = x;
    z = 1;
    helper(z);
  }

  void branchy(bool c, int x, int y) {
    int z;
    if (c) { z = x; } else { z = y; }
    helper(z);
  }

  int loopy(bool c, int x) {
    int z = x;
    while (z < x) { z = helper(z); }
    return z;
  }
}
"#,
        ),
        (
            "ruby",
            "a.rb",
            r#"
LIMIT = 10

class A
  def m(x, y)
    z = x + LIMIT
    @count = z
    w = helper(z, y)
    return w
  end
end

def killed(x)
  z = x
  z = 1
  helper(z)
end

def branchy(c, x, y)
  if c
    z = x
  else
    z = y
  end
  helper(z)
end

def loopy(c, x)
  z = x
  while z < x
    z = helper(z)
  end
  return z
end
"#,
        ),
    ]
}

fn sym(f: &FileExtract, name: &str, kind: SymbolKind) -> Option<u32> {
    f.symbols.iter().position(|s| s.name == name && s.kind == kind).map(|i| i as u32)
}

/// Parameters of the callable, in declared order.
fn params_of(f: &FileExtract, func: u32) -> Vec<(String, u32)> {
    let mut ps: Vec<(u32, String, u32)> = f
        .symbols
        .iter()
        .enumerate()
        .filter(|(_, s)| s.kind == SymbolKind::Parameter)
        .filter(|(i, _)| f.edges.iter().any(|e| e.from == func && e.to == *i as u32))
        .map(|(i, s)| (s.param_index.unwrap(), s.name.clone(), i as u32))
        .collect();
    ps.sort();
    ps.into_iter().map(|(_, n, i)| (n, i)).collect()
}

fn calls_named(f: &FileExtract, func: u32, callee: &str) -> Vec<u32> {
    f.calls
        .iter()
        .enumerate()
        .filter(|(_, c)| c.caller == Some(func) && c.callee == callee)
        .map(|(i, _)| i as u32)
        .collect()
}

fn flows_of(f: &FileExtract, func: u32) -> Vec<&RawFlow> {
    f.flows.iter().filter(|fl| fl.function == Some(func)).collect()
}

fn has_flow(f: &FileExtract, func: u32, source: &FlowNode, sink: &FlowNode) -> bool {
    flows_of(f, func).iter().any(|fl| fl.source == *source && fl.sink == *sink)
}

fn describe(f: &FileExtract, func: u32) -> String {
    let name = |n: &FlowNode| match n {
        FlowNode::Param(i) => format!("Param({})", f.symbols[*i as usize].name),
        FlowNode::CallResult(k) => format!("CallResult({})", f.calls[*k as usize].callee),
        FlowNode::Arg(k, p) => format!("Arg({}, {:?})", f.calls[*k as usize].callee, p),
        other => format!("{other:?}"),
    };
    flows_of(f, func).iter().map(|fl| format!("  {} -> {}", name(&fl.source), name(&fl.sink))).collect::<Vec<_>>().join("\n")
}

#[test]
fn every_language_declares_constants_fields_and_parameters() {
    for (lang, path, src) in snippets() {
        let f = extract(lang, path, src);
        assert!(sym(&f, "LIMIT", SymbolKind::Constant).is_some(), "{lang}: LIMIT is not a Constant: {:?}", f.symbols.iter().map(|s| (s.name.clone(), s.kind)).collect::<Vec<_>>());
        if lang == "c" {
            assert!(sym(&f, "count", SymbolKind::Variable).is_some(), "{lang}: no Variable `count`");
        } else {
            let count = sym(&f, "count", SymbolKind::Field).unwrap_or_else(|| panic!("{lang}: no Field `count`: {:?}", f.symbols.iter().map(|s| (s.name.clone(), s.kind)).collect::<Vec<_>>()));
            assert_eq!(f.symbols[count as usize].scope, vec!["A".to_string()], "{lang}: count is not scoped to A");
        }
        let m = sym(&f, "m", SymbolKind::Method).or_else(|| sym(&f, "m", SymbolKind::Function)).unwrap_or_else(|| panic!("{lang}: no m"));
        let ps = params_of(&f, m);
        let names: Vec<&str> = ps.iter().map(|(n, _)| n.as_str()).collect();
        // A receiver, where the language declares one, comes first.
        let tail: Vec<&str> = names.iter().rev().take(2).rev().copied().collect();
        assert_eq!(tail, ["x", "y"], "{lang}: parameters of m are {names:?}");
        assert!(f.symbols[ps[0].1 as usize].scope.ends_with(&["A".to_string(), "m".to_string()]) || f.symbols[ps[0].1 as usize].scope.ends_with(&["m".to_string()]), "{lang}: parameter scope {:?}", f.symbols[ps[0].1 as usize].scope);
    }
}

#[test]
fn every_language_records_references_to_non_locals() {
    for (lang, path, src) in snippets() {
        let f = extract(lang, path, src);
        let m = sym(&f, "m", SymbolKind::Method).or_else(|| sym(&f, "m", SymbolKind::Function)).unwrap();
        let refs: Vec<(String, bool)> = f.refs.iter().filter(|r| r.function == Some(m)).map(|r| (r.name.clone(), r.self_field)).collect();
        assert!(refs.contains(&("LIMIT".to_string(), false)), "{lang}: m does not reference LIMIT: {refs:?}");
        let self_field = lang != "c";
        assert!(refs.contains(&("count".to_string(), self_field)), "{lang}: m does not reference count: {refs:?}");
    }
}

#[test]
fn every_language_produces_the_same_flow_facts() {
    for (lang, path, src) in snippets() {
        let f = extract(lang, path, src);
        let m = sym(&f, "m", SymbolKind::Method).or_else(|| sym(&f, "m", SymbolKind::Function)).unwrap();
        let ps = params_of(&f, m);
        let x = ps.iter().find(|(n, _)| n == "x").unwrap().1;
        let y = ps.iter().find(|(n, _)| n == "y").unwrap().1;
        let helper = calls_named(&f, m, "helper");
        assert_eq!(helper.len(), 1, "{lang}: expected one call to helper in m, got {:?}", f.calls);
        let h = helper[0];
        let limit = FlowNode::NonLocal("LIMIT".into(), false);
        let count = FlowNode::NonLocal("count".into(), lang != "c");
        let d = describe(&f, m);
        assert!(has_flow(&f, m, &FlowNode::Param(x), &FlowNode::Arg(h, ArgPos::Index(0))), "{lang}: x -> helper arg 0 missing:\n{d}");
        assert!(has_flow(&f, m, &limit, &FlowNode::Arg(h, ArgPos::Index(0))), "{lang}: LIMIT -> helper arg 0 missing:\n{d}");
        assert!(has_flow(&f, m, &FlowNode::Param(y), &FlowNode::Arg(h, ArgPos::Index(1))), "{lang}: y -> helper arg 1 missing:\n{d}");
        assert!(has_flow(&f, m, &FlowNode::CallResult(h), &FlowNode::Return), "{lang}: helper() -> return missing:\n{d}");
        assert!(has_flow(&f, m, &FlowNode::Param(x), &count), "{lang}: x -> self.count missing:\n{d}");
        assert!(has_flow(&f, m, &limit, &count), "{lang}: LIMIT -> self.count missing:\n{d}");
        // And no flow that is not there: y never reaches count or arg 0.
        assert!(!has_flow(&f, m, &FlowNode::Param(y), &count), "{lang}: y -> self.count is a phantom flow:\n{d}");
        assert!(!has_flow(&f, m, &FlowNode::Param(y), &FlowNode::Arg(h, ArgPos::Index(0))), "{lang}: y -> helper arg 0 is a phantom flow:\n{d}");
    }
}

#[test]
fn a_killed_definition_does_not_flow() {
    for (lang, path, src) in snippets() {
        let f = extract(lang, path, src);
        let k = sym(&f, "killed", SymbolKind::Function).or_else(|| sym(&f, "killed", SymbolKind::Method)).unwrap();
        let x = params_of(&f, k).iter().find(|(n, _)| n == "x").unwrap().1;
        let h = calls_named(&f, k, "helper")[0];
        let d = describe(&f, k);
        assert!(!has_flow(&f, k, &FlowNode::Param(x), &FlowNode::Arg(h, ArgPos::Index(0))), "{lang}: x reached helper through a killed definition:\n{d}");
    }
}

#[test]
fn both_branches_flow() {
    for (lang, path, src) in snippets() {
        let f = extract(lang, path, src);
        let b = sym(&f, "branchy", SymbolKind::Function).or_else(|| sym(&f, "branchy", SymbolKind::Method)).unwrap();
        let ps = params_of(&f, b);
        let x = ps.iter().find(|(n, _)| n == "x").unwrap().1;
        let y = ps.iter().find(|(n, _)| n == "y").unwrap().1;
        let c = ps.iter().find(|(n, _)| n == "c").unwrap().1;
        let h = calls_named(&f, b, "helper")[0];
        let d = describe(&f, b);
        assert!(has_flow(&f, b, &FlowNode::Param(x), &FlowNode::Arg(h, ArgPos::Index(0))), "{lang}: then-branch flow missing:\n{d}");
        assert!(has_flow(&f, b, &FlowNode::Param(y), &FlowNode::Arg(h, ArgPos::Index(0))), "{lang}: else-branch flow missing:\n{d}");
        assert!(!has_flow(&f, b, &FlowNode::Param(c), &FlowNode::Arg(h, ArgPos::Index(0))), "{lang}: the condition flowed into the argument:\n{d}");
    }
}

#[test]
fn a_loop_reaches_a_fixpoint_with_the_redefinition() {
    for (lang, path, src) in snippets() {
        let f = extract(lang, path, src);
        let l = sym(&f, "loopy", SymbolKind::Function).or_else(|| sym(&f, "loopy", SymbolKind::Method)).unwrap();
        let x = params_of(&f, l).iter().find(|(n, _)| n == "x").unwrap().1;
        let h = calls_named(&f, l, "helper")[0];
        let d = describe(&f, l);
        assert!(has_flow(&f, l, &FlowNode::Param(x), &FlowNode::Arg(h, ArgPos::Index(0))), "{lang}: first iteration flow missing:\n{d}");
        assert!(has_flow(&f, l, &FlowNode::CallResult(h), &FlowNode::Arg(h, ArgPos::Index(0))), "{lang}: back-edge flow missing:\n{d}");
        assert!(has_flow(&f, l, &FlowNode::Param(x), &FlowNode::Return), "{lang}: zero-iteration return missing:\n{d}");
        assert!(has_flow(&f, l, &FlowNode::CallResult(h), &FlowNode::Return), "{lang}: loop result return missing:\n{d}");
    }
}

#[test]
fn every_callable_gets_blocks_with_labelled_successors() {
    for (lang, path, src) in snippets() {
        let f = extract(lang, path, src);
        let b = sym(&f, "branchy", SymbolKind::Function).or_else(|| sym(&f, "branchy", SymbolKind::Method)).unwrap();
        let blocks: Vec<_> = f.blocks.iter().filter(|bl| bl.function == b).collect();
        assert!(blocks.len() >= 4, "{lang}: branchy has {} blocks", blocks.len());
        let labels: Vec<&str> = blocks.iter().flat_map(|bl| bl.succ.iter().map(|(_, l)| l.as_str())).collect();
        assert!(labels.iter().any(|l| l.starts_with("then")), "{lang}: no then edge: {labels:?}");
        assert!(labels.iter().any(|l| l.starts_with("else")), "{lang}: no else edge: {labels:?}");
        let l = sym(&f, "loopy", SymbolKind::Function).or_else(|| sym(&f, "loopy", SymbolKind::Method)).unwrap();
        let labels: Vec<String> = f.blocks.iter().filter(|bl| bl.function == l).flat_map(|bl| bl.succ.iter().map(|(_, l)| l.clone())).collect();
        assert!(labels.iter().any(|l| l == "loop"), "{lang}: no back edge: {labels:?}");
    }
}

// --- the cases that would drop a real flow if handled carelessly ---

fn one(lang: &str, path: &str, src: &str, func: &str) -> (FileExtract, u32) {
    let f = extract(lang, path, src);
    let idx = sym(&f, func, SymbolKind::Function).or_else(|| sym(&f, func, SymbolKind::Method)).unwrap_or_else(|| panic!("{lang}: no {func}"));
    (f, idx)
}

fn param(f: &FileExtract, func: u32, name: &str) -> u32 {
    params_of(f, func).iter().find(|(n, _)| n == name).unwrap_or_else(|| panic!("no parameter {name}")).1
}

/// `strcpy(buf, x); system(buf)`: the callee wrote through `buf`.
#[test]
fn a_local_passed_to_an_unknown_callee_is_weakly_redefined() {
    for (lang, path, src) in [
        ("c", "a.c", "void f(char *x) {\n  char buf[64];\n  strcpy(buf, x);\n  system(buf);\n}\n"),
        ("cpp", "a.cpp", "void f(char *x) {\n  char buf[64];\n  strcpy(buf, x);\n  system(buf);\n}\n"),
        ("go", "a.go", "package p\n\nfunc f(x []byte) {\n\tvar buf []byte\n\tcopy(buf, x)\n\tsystem(buf)\n}\n"),
    ] {
        let (f, func) = one(lang, path, src, "f");
        let x = param(&f, func, "x");
        let system = calls_named(&f, func, "system")[0];
        let copy = calls_named(&f, func, if lang == "go" { "copy" } else { "strcpy" })[0];
        // Two facts that the resolver joins through the callee's stub with a
        // shared call-site tag: x into the copy, and the copy's result (the
        // weakly redefined `buf`) into system.
        let d = describe(&f, func);
        assert!(has_flow(&f, func, &FlowNode::Param(x), &FlowNode::Arg(copy, ArgPos::Index(1))), "{lang}: x -> copy arg 1 missing:
{d}");
        assert!(has_flow(&f, func, &FlowNode::CallResult(copy), &FlowNode::Arg(system, ArgPos::Index(0))), "{lang}: copy result -> system(buf) missing:
{d}");
    }
}

/// A callback's parameter receives the receiver and the other arguments,
/// and captured locals are read inside it.
#[test]
fn callbacks_receive_the_receiver_and_read_captured_locals() {
    for (lang, path, src) in [
        ("javascript", "a.js", "function f(arr, x) {\n  arr.forEach(v => sink(v, x));\n}\n"),
        ("typescript", "a.ts", "function f(arr: number[], x: number) {\n  arr.forEach(v => sink(v, x));\n}\n"),
        ("ruby", "a.rb", "def f(arr, x)\n  arr.each { |v| sink(v, x) }\nend\n"),
        ("python", "a.py", "def f(arr, x):\n    cb = lambda v: sink(v, x)\n    cb(arr)\n"),
        ("java", "A.java", "class A {\n  void f(java.util.List<Integer> arr, int x) {\n    arr.forEach(v -> sink(v, x));\n  }\n}\n"),
        ("csharp", "A.cs", "class A {\n  void f(int[] arr, int x) {\n    arr.ForEach(v => sink(v, x));\n  }\n}\n"),
        ("rust", "a.rs", "fn f(arr: Vec<u32>, x: u32) {\n    each(arr, |v| sink(v, x));\n}\n"),
        ("go", "a.go", "package p\n\nfunc f(arr []int, x int) {\n\teach(arr, func(v int) { sink(v, x) })\n}\n"),
    ] {
        let (f, func) = one(lang, path, src, "f");
        let x = param(&f, func, "x");
        let arr = param(&f, func, "arr");
        let sink = calls_named(&f, func, "sink");
        assert_eq!(sink.len(), 1, "{lang}: sink call not attributed to f: {:?}", f.calls);
        let d = describe(&f, func);
        assert!(has_flow(&f, func, &FlowNode::Param(x), &FlowNode::Arg(sink[0], ArgPos::Index(1))), "{lang}: captured x -> sink arg 1 missing:\n{d}");
        assert!(has_flow(&f, func, &FlowNode::Param(arr), &FlowNode::Arg(sink[0], ArgPos::Index(0))), "{lang}: arr -> callback param -> sink arg 0 missing:\n{d}");
    }
}

#[test]
fn go_named_results_flow_through_a_bare_return() {
    let (f, func) = one("go", "a.go", "package p\n\nfunc f(x int) (res int, err error) {\n\tres = x\n\treturn\n}\n", "f");
    let x = param(&f, func, "x");
    assert!(has_flow(&f, func, &FlowNode::Param(x), &FlowNode::Return), "named result did not flow:\n{}", describe(&f, func));
}

#[test]
fn rust_tail_expressions_return_through_branches() {
    let (f, func) = one("rust", "a.rs", "fn f(c: bool, x: u32, y: u32) -> u32 {\n    if c { x } else { y }\n}\n", "f");
    let x = param(&f, func, "x");
    let y = param(&f, func, "y");
    let d = describe(&f, func);
    assert!(has_flow(&f, func, &FlowNode::Param(x), &FlowNode::Return), "then tail missing:\n{d}");
    assert!(has_flow(&f, func, &FlowNode::Param(y), &FlowNode::Return), "else tail missing:\n{d}");
}

#[test]
fn ruby_implicit_return_is_the_last_statement() {
    let (f, func) = one("ruby", "a.rb", "def f(x)\n  y = helper(x)\n  y\nend\n", "f");
    let x = param(&f, func, "x");
    let h = calls_named(&f, func, "helper")[0];
    let d = describe(&f, func);
    assert!(has_flow(&f, func, &FlowNode::CallResult(h), &FlowNode::Return), "implicit return missing:\n{d}");
    assert!(has_flow(&f, func, &FlowNode::Param(x), &FlowNode::Arg(h, ArgPos::Index(0))), "{d}");
}

/// A handler sees the state at the point the exception was raised, not the
/// state after the whole body.
#[test]
fn an_exception_handler_sees_every_intermediate_state() {
    let (f, func) = one("python", "a.py", "def f(x):\n    z = x\n    try:\n        risky()\n        z = clean(z)\n        risky()\n    except Exception:\n        sink(z)\n", "f");
    let x = param(&f, func, "x");
    let sink = calls_named(&f, func, "sink")[0];
    assert!(has_flow(&f, func, &FlowNode::Param(x), &FlowNode::Arg(sink, ArgPos::Index(0))), "the pre-clean state was lost:\n{}", describe(&f, func));
}

#[test]
fn keyword_arguments_bind_by_name() {
    let (f, func) = one("python", "a.py", "def f(x):\n    run(cmd=x)\n", "f");
    let x = param(&f, func, "x");
    let run = calls_named(&f, func, "run")[0];
    assert!(has_flow(&f, func, &FlowNode::Param(x), &FlowNode::Arg(run, ArgPos::Name("cmd".into()))), "{}", describe(&f, func));
}

#[test]
fn tsx_shares_the_typescript_tables() {
    let f = extract("tsx", "a.tsx", "const LIMIT = 1;\nfunction f(x: number) {\n  const z = x + LIMIT;\n  return helper(z);\n}\n");
    let func = sym(&f, "f", SymbolKind::Function).unwrap();
    let x = param(&f, func, "x");
    let h = calls_named(&f, func, "helper")[0];
    assert!(has_flow(&f, func, &FlowNode::Param(x), &FlowNode::Arg(h, ArgPos::Index(0))));
    assert!(sym(&f, "LIMIT", SymbolKind::Constant).is_some());
}

#[test]
fn a_python_annotation_is_not_a_parameter() {
    let (f, m) = one("python", "t.py", "def parse(path: str, n: int = 3) -> dict:\n    return path\n", "parse");
    let names: Vec<String> = params_of(&f, m).into_iter().map(|(n, _)| n).collect();
    assert_eq!(names, ["path", "n"]);
}

/// A `match` arm's pattern binds locals: `Some(x)` makes `x` carry the
/// scrutinee. A case *value* (Go `case A:`) binds nothing.
#[test]
fn match_patterns_bind_locals_and_case_values_do_not() {
    let (f, m) = one("rust", "m.rs", "fn f(v: Option<u32>) {\n    match v {\n        Some(x) => sink(x),\n        None => {}\n    }\n}\n", "f");
    let v = param(&f, m, "v");
    let h = calls_named(&f, m, "sink")[0];
    assert!(has_flow(&f, m, &FlowNode::Param(v), &FlowNode::Arg(h, ArgPos::Index(0))), "{}", describe(&f, m));
    assert!(f.locals.iter().any(|l| l.name == "x"));
    assert!(!f.locals.iter().any(|l| l.name == "Some" || l.name == "None"));

    let (f, m) = one("go", "s.go", "package p\n\nfunc f(s int) {\n\tswitch s {\n\tcase A:\n\t\tsink(s)\n\t}\n}\n", "f");
    assert!(f.locals.is_empty(), "{:?}", f.locals);
    assert!(f.blocks.iter().all(|b| b.local_defines.is_empty()), "a case value was defined as a local");
    let _ = m;
}

/// Go's `if x := f(); cond {` runs its initialiser: `x` is defined before
/// the test and its value reaches the body.
#[test]
fn go_if_initialisers_define_before_the_test() {
    let (f, m) = one("go", "i.go", "package p\n\nfunc f(s S) error {\n\tif err := s.Begin(); err != nil {\n\t\treturn err\n\t}\n\treturn nil\n}\n", "f");
    let begin = calls_named(&f, m, "Begin")[0];
    assert!(has_flow(&f, m, &FlowNode::CallResult(begin), &FlowNode::Return), "{}", describe(&f, m));
}
