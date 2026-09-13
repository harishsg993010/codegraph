//! A non-local read only in a branch condition is still a reference: `if
//! size > MAX_UPLOAD_BYTES` reads the constant, though its value flows
//! nowhere. An import naming the same symbol is not a read.

use codegraph_core::SymbolKind;
use codegraph_extract::{FileExtract, Walker, lang};

fn extract(lang_name: &str, path: &str, src: &str) -> FileExtract {
    let config = lang::ALL.iter().copied().find(|c| c.name == lang_name).expect("config");
    let mut w = Walker::new(config).expect("walker");
    w.extract(path, src.as_bytes()).expect("parse")
}

fn refs_of(f: &FileExtract, fname: &str) -> Vec<String> {
    let fi = f.symbols.iter().position(|s| s.name == fname && matches!(s.kind, SymbolKind::Function | SymbolKind::Method)).unwrap_or_else(|| panic!("no {fname}")) as u32;
    let mut v: Vec<String> = f.refs.iter().filter(|r| r.function == Some(fi)).map(|r| r.name.clone()).collect();
    v.sort();
    v.dedup();
    v
}

#[test]
fn a_read_only_in_a_condition_is_a_reference_in_every_language() {
    let cases: &[(&str, &str, &str)] = &[
        ("python", "m.py", "LIMIT = 1\ndef check(size):\n    if size > LIMIT:\n        raise ValueError('x')\n    return size\n"),
        ("javascript", "m.js", "const LIMIT = 1;\nfunction check(size) {\n  if (size > LIMIT) { throw new Error('x'); }\n  return size;\n}\n"),
        ("typescript", "m.ts", "const LIMIT = 1;\nfunction check(size: number) {\n  while (size > LIMIT) { size--; }\n  return size;\n}\n"),
        ("go", "m.go", "package m\n\nconst LIMIT = 1\n\nfunc check(size int) int {\n\tif size > LIMIT {\n\t\tpanic(\"x\")\n\t}\n\treturn size\n}\n"),
        ("rust", "m.rs", "const LIMIT: i32 = 1;\nfn check(size: i32) -> i32 {\n    if size > LIMIT { panic!(\"x\"); }\n    size\n}\n"),
        ("java", "M.java", "class M {\n  static final int LIMIT = 1;\n  int check(int size) {\n    if (size > LIMIT) { throw new RuntimeException(); }\n    return size;\n  }\n}\n"),
        ("c", "m.c", "static const int LIMIT = 1;\nint check(int size) {\n  if (size > LIMIT) { return -1; }\n  return size;\n}\n"),
        ("cpp", "m.cpp", "static const int LIMIT = 1;\nint check(int size) {\n  if (size > LIMIT) { return -1; }\n  return size;\n}\n"),
        ("csharp", "M.cs", "class M {\n  const int LIMIT = 1;\n  int Check(int size) {\n    if (size > LIMIT) { throw new System.Exception(); }\n    return size;\n  }\n}\n"),
        ("ruby", "m.rb", "LIMIT = 1\ndef check(size)\n  raise 'x' if size > LIMIT\n  size\nend\n"),
    ];
    for (lang, path, src) in cases {
        let f = extract(lang, path, src);
        let fname = if *lang == "csharp" { "Check" } else { "check" };
        let refs = refs_of(&f, fname);
        assert!(refs.iter().any(|r| r == "LIMIT"), "{lang}: check should reference LIMIT, has {refs:?}");
    }
}

#[test]
fn an_import_is_not_a_read() {
    let f = extract("python", "m.py", "from lib import LIMIT\n\ndef check(size):\n    return size\n");
    assert!(f.refs.iter().all(|r| r.name != "LIMIT"), "{:?}", f.refs);
    let f = extract("javascript", "m.js", "import { LIMIT } from './lib';\n\nfunction check(size) { return size; }\n");
    assert!(f.refs.iter().all(|r| r.name != "LIMIT"), "{:?}", f.refs);
}
