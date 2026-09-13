//! Field sensitivity on locals, and may-alias classes.
//!
//! `a.x = t; sink(a.y)` must not carry `t`: `a.y` is its own path. `a.x =
//! t; sink(a)` must: the whole object carries every field. `b = a; b.x =
//! t; sink(a.x)` must: `a` and `b` share the object (or `p = &x; *p = t;
//! sink(x)` in a language with addresses).

use codegraph_core::SymbolKind;
use codegraph_extract::{ArgPos, FileExtract, FlowNode, Walker, lang};

fn extract(lang_name: &str, path: &str, src: &str) -> FileExtract {
    let config = lang::ALL.iter().copied().find(|c| c.name == lang_name).expect("config");
    let mut w = Walker::new(config).expect("walker");
    w.extract(path, src.as_bytes()).expect("parse")
}

fn func(f: &FileExtract, name: &str) -> u32 {
    f.symbols.iter().position(|s| s.name == name && matches!(s.kind, SymbolKind::Function | SymbolKind::Method)).unwrap_or_else(|| panic!("no {name}")) as u32
}

fn param(f: &FileExtract, fi: u32, name: &str) -> FlowNode {
    let i = f
        .symbols
        .iter()
        .enumerate()
        .find(|(i, s)| s.kind == SymbolKind::Parameter && s.name == name && f.edges.iter().any(|e| e.from == fi && e.to == *i as u32))
        .map(|(i, _)| i as u32)
        .unwrap_or_else(|| panic!("no parameter {name}"));
    FlowNode::Param(i)
}

fn arg0(f: &FileExtract, fi: u32, callee: &str) -> FlowNode {
    let k = f.calls.iter().position(|c| c.caller == Some(fi) && c.callee == callee).unwrap_or_else(|| panic!("no call {callee}")) as u32;
    FlowNode::Arg(k, ArgPos::Index(0))
}

fn flows(f: &FileExtract, fi: u32, from: &FlowNode, to: &FlowNode) -> bool {
    f.flows.iter().any(|fl| fl.function == Some(fi) && fl.source == *from && fl.sink == *to)
}

fn describe(f: &FileExtract, fi: u32) -> String {
    f.flows.iter().filter(|fl| fl.function == Some(fi)).map(|fl| format!("  {:?} -> {:?}", fl.source, fl.sink)).collect::<Vec<_>>().join("\n")
}

fn check(f: &FileExtract, lang: &str, fname: &str, p: &str, sink: &str, want: bool) {
    let fi = func(f, fname);
    let got = flows(f, fi, &param(f, fi, p), &arg0(f, fi, sink));
    assert_eq!(got, want, "{lang}: {fname}: {p} -> {sink} should be {}:\n{}", if want { "there" } else { "absent" }, describe(f, fi));
}

/// `f(t, u)`: `a.x = t`, `a.y = u`; `sink1(a.y)` sees `u` only, `sink2(a)`
/// sees both, and after `a = fresh()` `sink3(a.x)` sees neither.
fn snippets() -> Vec<(&'static str, &'static str, &'static str)> {
    vec![
        ("python", "f.py", "def f(t, u):\n    a = Obj()\n    a.x = t\n    a.y = u\n    sink1(a.y)\n    sink2(a)\n    a = fresh()\n    sink3(a.x)\n"),
        ("javascript", "f.js", "function f(t, u) {\n  let a = {};\n  a.x = t;\n  a.y = u;\n  sink1(a.y);\n  sink2(a);\n  a = fresh();\n  sink3(a.x);\n}\n"),
        ("typescript", "f.ts", "function f(t: string, u: string) {\n  let a: any = {};\n  a.x = t;\n  a.y = u;\n  sink1(a.y);\n  sink2(a);\n  a = fresh();\n  sink3(a.x);\n}\n"),
        ("java", "F.java", "class F {\n  void f(String t, String u) {\n    Obj a = new Obj();\n    a.x = t;\n    a.y = u;\n    sink1(a.y);\n    sink2(a);\n    a = fresh();\n    sink3(a.x);\n  }\n}\n"),
        ("go", "f.go", "package p\n\nfunc f(t string, u string) {\n\ta := Obj{}\n\ta.x = t\n\ta.y = u\n\tsink1(a.y)\n\tsink2(a)\n\ta = fresh()\n\tsink3(a.x)\n}\n"),
        ("c", "f.c", "void f(char *t, char *u) {\n  struct Obj a;\n  a.x = t;\n  a.y = u;\n  sink1(a.y);\n  sink2(a);\n  a = fresh();\n  sink3(a.x);\n}\n"),
        ("cpp", "f.cpp", "void f(char *t, char *u) {\n  Obj a;\n  a.x = t;\n  a.y = u;\n  sink1(a.y);\n  sink2(a);\n  a = fresh();\n  sink3(a.x);\n}\n"),
        ("rust", "f.rs", "fn f(t: &str, u: &str) {\n    let mut a = Obj::new();\n    a.x = t;\n    a.y = u;\n    sink1(a.y);\n    sink2(a);\n    a = fresh();\n    sink3(a.x);\n}\n"),
        ("csharp", "F.cs", "class F {\n  void f(string t, string u) {\n    var a = new Obj();\n    a.x = t;\n    a.y = u;\n    sink1(a.y);\n    sink2(a);\n    a = fresh();\n    sink3(a.x);\n  }\n}\n"),
        ("ruby", "f.rb", "def f(t, u)\n  a = Obj.new\n  a.x = t\n  a.y = u\n  sink1(a.y)\n  sink2(a)\n  a = fresh()\n  sink3(a.x)\nend\n"),
    ]
}

#[test]
fn a_field_is_its_own_value_and_the_whole_object_carries_every_field() {
    for (lang, path, src) in snippets() {
        let f = extract(lang, path, src);
        check(&f, lang, "f", "u", "sink1", true);
        check(&f, lang, "f", "t", "sink1", false);
        check(&f, lang, "f", "t", "sink2", true);
        check(&f, lang, "f", "u", "sink2", true);
        // A whole-object assignment kills every field.
        check(&f, lang, "f", "t", "sink3", false);
        check(&f, lang, "f", "u", "sink3", false);
    }
}

#[test]
fn a_copy_shares_the_object_where_the_language_says_so() {
    for (lang, path, src) in [
        ("python", "g.py", "def g(t):\n    a = Obj()\n    b = a\n    b.x = t\n    sink(a.x)\n"),
        ("javascript", "g.js", "function g(t) {\n  let a = {};\n  let b = a;\n  b.x = t;\n  sink(a.x);\n}\n"),
        ("java", "G.java", "class G {\n  void g(String t) {\n    Obj a = new Obj();\n    Obj b = a;\n    b.x = t;\n    sink(a.x);\n  }\n}\n"),
        ("ruby", "g.rb", "def g(t)\n  a = Obj.new\n  b = a\n  b.x = t\n  sink(a.x)\nend\n"),
    ] {
        let f = extract(lang, path, src);
        check(&f, lang, "g", "t", "sink", true);
    }
    // In C a plain copy is a copy; the address is what aliases.
    let f = extract("c", "g.c", "void g(char *t) {\n  struct Obj a;\n  struct Obj b = a;\n  b.x = t;\n  sink(a.x);\n}\n");
    check(&f, "c", "g", "t", "sink", false);
}

#[test]
fn a_write_through_a_pointer_writes_the_pointee() {
    for (lang, path, src) in [
        ("c", "h.c", "void h(char *t) {\n  char *x;\n  char **p = &x;\n  *p = t;\n  sink(x);\n}\n"),
        ("cpp", "h.cpp", "void h(char *t) {\n  char *x;\n  char **p = &x;\n  *p = t;\n  sink(x);\n}\n"),
        ("go", "h.go", "package p\n\nfunc h(t string) {\n\tvar x string\n\tp := &x\n\t*p = t\n\tsink(x)\n}\n"),
        ("rust", "h.rs", "fn h(t: &str) {\n    let mut x = \"\";\n    let p = &mut x;\n    *p = t;\n    sink(x);\n}\n"),
    ] {
        let f = extract(lang, path, src);
        check(&f, lang, "h", "t", "sink", true);
    }
    // …and a read through the pointer reads the pointee's current value.
    let f = extract("c", "r.c", "void r(char *t) {\n  char *x;\n  char **p = &x;\n  x = t;\n  sink(*p);\n}\n");
    check(&f, "c", "r", "t", "sink", true);
}

#[test]
fn mutation_through_a_method_reaches_every_alias() {
    let f = extract("python", "m.py", "def m(t):\n    items = []\n    same = items\n    same.append(t)\n    sink(items)\n");
    check(&f, "python", "m", "t", "sink", true);
}
