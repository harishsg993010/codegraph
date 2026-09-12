//! Library summaries at extraction: what a known call writes, and what it
//! marks as external, is recorded as facts of the calling function.

use codegraph_core::SymbolKind;
use codegraph_extract::{ArgPos, FileExtract, FlowNode, Walker, lang};

fn extract(lang_name: &str, path: &str, src: &str) -> FileExtract {
    let config = lang::ALL.iter().copied().find(|c| c.name == lang_name).expect("config");
    let mut w = Walker::new(config).expect("walker");
    w.extract(path, src.as_bytes()).expect("parse")
}

fn func(f: &FileExtract, name: &str) -> u32 {
    f.symbols
        .iter()
        .position(|s| s.name == name && matches!(s.kind, SymbolKind::Function | SymbolKind::Method))
        .unwrap_or_else(|| panic!("no callable {name}")) as u32
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

fn call(f: &FileExtract, fi: u32, callee: &str) -> u32 {
    f.calls.iter().position(|c| c.caller == Some(fi) && c.callee == callee).unwrap_or_else(|| panic!("no call {callee}")) as u32
}

fn arg0(f: &FileExtract, fi: u32, callee: &str) -> FlowNode {
    FlowNode::Arg(call(f, fi, callee), ArgPos::Index(0))
}

fn flows(f: &FileExtract, fi: u32, from: &FlowNode, to: &FlowNode) -> bool {
    f.flows.iter().any(|fl| fl.function == Some(fi) && fl.source == *from && fl.sink == *to)
}

fn describe(f: &FileExtract, fi: u32) -> String {
    f.flows.iter().filter(|fl| fl.function == Some(fi)).map(|fl| format!("  {:?} -> {:?}", fl.source, fl.sink)).collect::<Vec<_>>().join("\n")
}

#[test]
fn c_string_functions_write_their_first_argument() {
    let f = extract(
        "c",
        "a.c",
        "void run(char *x, char *y) {\n  char buf[64];\n  strcpy(buf, x);\n  strcat(buf, y);\n  system(buf);\n}\n",
    );
    let r = func(&f, "run");
    assert!(flows(&f, r, &param(&f, r, "x"), &arg0(&f, r, "system")), "{}", describe(&f, r));
    assert!(flows(&f, r, &param(&f, r, "y"), &arg0(&f, r, "system")), "{}", describe(&f, r));
    let strcpy = &f.calls[call(&f, r, "strcpy") as usize];
    assert!(strcpy.summarised && !strcpy.external);
}

#[test]
fn a_filling_read_is_external_data() {
    let f = extract("c", "b.c", "void run(int fd) {\n  char buf[64];\n  read(fd, buf, 64);\n  system(buf);\n}\n");
    let r = func(&f, "run");
    let read = &f.calls[call(&f, r, "read") as usize];
    assert!(read.summarised && read.external);
    // The buffer's contents are the call's own: the fact names the call.
    assert!(flows(&f, r, &FlowNode::CallResult(call(&f, r, "read")), &arg0(&f, r, "system")), "{}", describe(&f, r));
}

#[test]
fn go_unmarshal_writes_its_second_argument_from_its_first() {
    let f = extract(
        "go",
        "a.go",
        "package p\n\nfunc run(data []byte) {\n\tvar v Config\n\tjson.Unmarshal(data, &v)\n\tsink(v)\n}\n",
    );
    let r = func(&f, "run");
    assert!(flows(&f, r, &param(&f, r, "data"), &arg0(&f, r, "sink")), "{}", describe(&f, r));
}

#[test]
fn a_mutating_method_writes_its_receiver() {
    for (lang, path, src) in [
        ("python", "a.py", "def run(x):\n    items = []\n    items.append(x)\n    sink(items)\n"),
        ("javascript", "a.js", "function run(x) {\n  const items = [];\n  items.push(x);\n  sink(items);\n}\n"),
        ("java", "A.java", "class A {\n  void run(String x) {\n    StringBuilder sb = new StringBuilder();\n    sb.append(x);\n    sink(sb);\n  }\n}\n"),
        ("go", "a.go", "package p\n\nfunc run(x string) {\n\tvar sb strings.Builder\n\tsb.WriteString(x)\n\tsink(sb)\n}\n"),
        ("rust", "a.rs", "fn run(x: &str) {\n    let mut s = String::new();\n    s.push_str(x);\n    sink(s);\n}\n"),
        ("ruby", "a.rb", "def run(x)\n  items = []\n  items.push(x)\n  sink(items)\nend\n"),
        ("csharp", "A.cs", "class A {\n  void run(string x) {\n    var sb = new StringBuilder();\n    sb.Append(x);\n    sink(sb);\n  }\n}\n"),
    ] {
        let f = extract(lang, path, src);
        let r = func(&f, "run");
        assert!(flows(&f, r, &param(&f, r, "x"), &arg0(&f, r, "sink")), "{lang}:\n{}", describe(&f, r));
    }
}

#[test]
fn a_summarised_result_carries_only_what_the_summary_says() {
    // `len` produces nothing; `strip` produces its receiver. Both facts are
    // recorded at extraction as the inputs the summary names; the call's
    // own result is left for the resolver to decide on.
    let f = extract("python", "s.py", "def run(x, y):\n    n = len(x)\n    s = y.strip()\n    sink(n)\n    sink2(s)\n");
    let r = func(&f, "run");
    assert!(!flows(&f, r, &param(&f, r, "x"), &arg0(&f, r, "sink")), "{}", describe(&f, r));
    assert!(flows(&f, r, &param(&f, r, "y"), &arg0(&f, r, "sink2")), "{}", describe(&f, r));
    assert!(f.calls[call(&f, r, "len") as usize].summarised);
    assert!(f.calls[call(&f, r, "strip") as usize].summarised);
}
