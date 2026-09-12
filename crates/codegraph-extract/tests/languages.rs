//! Per-language extraction, checked against hand-written snippets.
//!
//! One snippet per Tier-1 language, each containing the same shapes: a type
//! with two same-named methods, a free function, a call from inside a method,
//! and an import. Asserting the same properties across all eleven is what keeps
//! the config-driven walk honest — a language whose config is subtly wrong
//! fails the shared assertions rather than quietly under-extracting.

use codegraph_core::{Relation, SymbolKind};
use codegraph_extract::{FileExtract, Walker, lang};

fn extract(lang_name: &str, path: &str, src: &str) -> FileExtract {
    let config = lang::ALL
        .iter()
        .copied()
        .find(|c| c.name == lang_name)
        .unwrap_or_else(|| panic!("no config named {lang_name}"));
    let mut w = Walker::new(config).expect("walker");
    w.extract(path, src.as_bytes()).expect("parse")
}

fn names(f: &FileExtract) -> Vec<String> {
    f.symbols.iter().map(|s| s.name.clone()).collect()
}

fn qualified(f: &FileExtract) -> Vec<String> {
    f.symbols.iter().map(codegraph_extract::RawSymbol::qualified).collect()
}

fn has_qualified(f: &FileExtract, want: &str) -> bool {
    qualified(f).iter().any(|q| q == want)
}

/// Every language's snippet, keyed by config name.
fn snippets() -> Vec<(&'static str, &'static str, &'static str)> {
    vec![
        (
            "python",
            "a.py",
            r#"
import os
from collections import OrderedDict

class Alpha:
    def __init__(self):
        helper()

class Beta:
    def __init__(self):
        pass

def helper():
    pass
"#,
        ),
        (
            "javascript",
            "a.js",
            r#"
import fs from "fs";

class Alpha {
  constructor() { helper(); }
}
class Beta {
  constructor() {}
}
function helper() {}
"#,
        ),
        (
            "typescript",
            "a.ts",
            r#"
import { readFile } from "fs";

class Alpha {
  constructor() { helper(); }
}
class Beta {
  constructor() {}
}
function helper(): void {}
"#,
        ),
        (
            "java",
            "A.java",
            r#"
import java.util.List;

class Alpha {
  Alpha() { helper(); }
}
class Beta {
  Beta() {}
  void helper() {}
}
"#,
        ),
        (
            "c",
            "a.c",
            r#"
#include <stdio.h>

struct Alpha { int x; };

void helper(void) {}

int main(void) {
  helper();
  return 0;
}
"#,
        ),
        (
            "cpp",
            "a.cpp",
            r#"
#include <vector>

class Alpha {
public:
  void run() { helper(); }
};
class Beta {
public:
  void run() {}
};
void helper() {}
"#,
        ),
        (
            "go",
            "a.go",
            r#"
package main

import "fmt"

type Alpha struct{}

func (a Alpha) Run() { helper() }

func helper() {}
"#,
        ),
        (
            "rust",
            "a.rs",
            r#"
use std::collections::HashMap;

struct Alpha;

impl Alpha {
    fn run(&self) { helper(); }
}

fn helper() {}
"#,
        ),
        (
            "csharp",
            "A.cs",
            r#"
using System;

class Alpha {
  public void Run() { Helper(); }
}
class Beta {
  public void Run() {}
}
"#,
        ),
        (
            "ruby",
            "a.rb",
            r#"
class Alpha
  def run
    helper()
  end
end

class Beta
  def run
  end
end
"#,
        ),
    ]
}

#[test]
fn every_language_extracts_symbols() {
    for (lang, path, src) in snippets() {
        let f = extract(lang, path, src);
        assert!(
            !f.symbols.is_empty(),
            "{lang}: extracted no symbols from a snippet with definitions"
        );
        assert!(!f.had_parse_error, "{lang}: snippet did not parse cleanly");
        assert!(
            names(&f).iter().any(|n| n.eq_ignore_ascii_case("alpha")),
            "{lang}: did not find the type Alpha; got {:?}",
            names(&f)
        );
    }
}

/// **The property the whole scope machinery exists for.** Two same-named
/// methods on different types must be distinguishable.
#[test]
fn same_named_members_are_separated_by_their_owner() {
    // Languages whose snippet has two types each with a same-named member.
    for (lang, path, src) in snippets() {
        let f = extract(lang, path, src);
        let member = match lang {
            "python" => "__init__",
            "javascript" | "typescript" => "constructor",
            "cpp" | "ruby" => "run",
            "csharp" => "Run",
            _ => continue,
        };
        let quals = qualified(&f);
        let hits: Vec<&String> = quals.iter().filter(|q| q.ends_with(member)).collect();
        assert!(
            hits.len() >= 2,
            "{lang}: expected two {member} members, got {quals:?}"
        );
        let distinct: std::collections::HashSet<&&String> = hits.iter().collect();
        assert_eq!(
            distinct.len(),
            hits.len(),
            "{lang}: same-named members collapsed to one key: {hits:?}"
        );
        // And they must be qualified by their owner, not bare.
        for h in hits {
            assert!(h.contains('.'), "{lang}: {h:?} is not qualified by its owner");
        }
    }
}

#[test]
fn javascript_constructors_are_qualified() {
    let (_, path, src) = snippets().into_iter().find(|(l, ..)| *l == "javascript").unwrap();
    let f = extract("javascript", path, src);
    assert!(has_qualified(&f, "Alpha.constructor"), "got {:?}", qualified(&f));
    assert!(has_qualified(&f, "Beta.constructor"), "got {:?}", qualified(&f));
}

#[test]
fn python_methods_are_qualified_and_free_functions_are_not() {
    let (_, path, src) = snippets().into_iter().find(|(l, ..)| *l == "python").unwrap();
    let f = extract("python", path, src);
    assert!(has_qualified(&f, "Alpha.__init__"), "got {:?}", qualified(&f));
    assert!(has_qualified(&f, "Beta.__init__"), "got {:?}", qualified(&f));
    assert!(has_qualified(&f, "helper"), "a free function must not be qualified");
}

/// A call inside a method belongs to the method, not to its class.
#[test]
fn calls_are_attributed_to_the_innermost_definition() {
    for lang in ["python", "javascript", "typescript", "cpp", "csharp", "ruby", "rust"] {
        let (_, path, src) = snippets().into_iter().find(|(l, ..)| *l == lang).unwrap();
        let f = extract(lang, path, src);
        let call = f
            .calls
            .iter()
            .find(|c| c.callee.eq_ignore_ascii_case("helper"))
            .unwrap_or_else(|| panic!("{lang}: no call to helper; got {:?}", f.calls));
        let caller = call
            .caller
            .unwrap_or_else(|| panic!("{lang}: call to helper has no caller"));
        let caller_sym = &f.symbols[caller as usize];
        assert!(
            !matches!(
                caller_sym.kind,
                SymbolKind::Class | SymbolKind::Struct | SymbolKind::Module | SymbolKind::Namespace
            ),
            "{lang}: call attributed to the enclosing type {:?} instead of the method",
            caller_sym.qualified()
        );
    }
}

#[test]
fn structural_edges_link_owners_to_members() {
    for (lang, path, src) in snippets() {
        let f = extract(lang, path, src);
        for e in &f.edges {
            assert!(
                (e.from as usize) < f.symbols.len() && (e.to as usize) < f.symbols.len(),
                "{lang}: edge endpoint out of range"
            );
            assert_ne!(e.from, e.to, "{lang}: self-edge");
            assert!(
                matches!(e.relation, Relation::Contains | Relation::Method),
                "{lang}: unexpected structural relation {:?}",
                e.relation
            );
        }
        // A member edge from a type must be `method`, not `contains`.
        for e in f.edges.iter().filter(|e| e.relation == Relation::Method) {
            let owner = &f.symbols[e.from as usize];
            assert!(
                matches!(
                    owner.kind,
                    SymbolKind::Class
                        | SymbolKind::Struct
                        | SymbolKind::Interface
                        | SymbolKind::Trait
                        | SymbolKind::Enum
                        | SymbolKind::Module
                        | SymbolKind::Namespace
                ),
                "{lang}: `method` edge from a non-type {:?}",
                owner.kind
            );
        }
    }
}

#[test]
fn imports_are_captured_where_the_language_has_them() {
    for lang in ["python", "javascript", "typescript", "java", "c", "cpp", "go", "rust", "csharp"] {
        let (_, path, src) = snippets().into_iter().find(|(l, ..)| *l == lang).unwrap();
        let f = extract(lang, path, src);
        assert!(!f.imports.is_empty(), "{lang}: snippet has an import but none was captured");
        assert!(
            f.imports.iter().all(|i| !i.module.is_empty()),
            "{lang}: an import has an empty specifier"
        );
        // Quotes and angle brackets are stripped at capture.
        assert!(
            f.imports.iter().all(|i| !i.module.starts_with('"') && !i.module.starts_with('<')),
            "{lang}: import specifier keeps its delimiters: {:?}",
            f.imports
        );
    }
}

#[test]
fn line_numbers_are_one_based_and_plausible() {
    for (lang, path, src) in snippets() {
        let lines = src.lines().count() as u32;
        let f = extract(lang, path, src);
        for s in &f.symbols {
            assert!(s.line >= 1, "{lang}: {:?} has line 0", s.name);
            assert!(s.line <= lines + 1, "{lang}: {:?} is past the end of file", s.name);
        }
        for c in &f.calls {
            assert!(c.line >= 1 && c.line <= lines + 1, "{lang}: call line out of range");
        }
    }
}

#[test]
fn extraction_is_deterministic() {
    for (lang, path, src) in snippets() {
        assert_eq!(extract(lang, path, src), extract(lang, path, src), "{lang}");
    }
}

/// A file with a syntax error must still yield what it can. Dropping it loses
/// more than it protects: half a file's symbols beat none.
#[test]
fn a_broken_file_still_yields_symbols() {
    let f = extract(
        "python",
        "broken.py",
        "def good():\n    pass\n\ndef bad(:\n    pass\n",
    );
    assert!(f.had_parse_error, "the error was not recorded");
    assert!(
        names(&f).contains(&"good".to_string()),
        "a parse error discarded the whole file; got {:?}",
        names(&f)
    );
}

#[test]
fn an_empty_file_is_not_an_error() {
    for (lang, path, _) in snippets() {
        let f = extract(lang, path, "");
        assert!(f.symbols.is_empty(), "{lang}");
        assert_eq!(f.size, 0);
    }
}

#[test]
fn the_content_hash_tracks_content() {
    let a = extract("python", "a.py", "def f(): pass\n");
    let b = extract("python", "a.py", "def f(): pass\n");
    let c = extract("python", "a.py", "def g(): pass\n");
    assert_eq!(a.content_hash, b.content_hash);
    assert_ne!(a.content_hash, c.content_hash);
}

/// Regression: `from typing import Literal` must record `typing`, not
/// `Literal`. Getting this wrong made a package list full of type names.
#[test]
fn a_from_import_records_the_module_not_the_imported_name() {
    let f = extract("python", "a.py", "from typing import Literal, Any\n");
    let mods: Vec<&str> = f.imports.iter().map(|i| i.module.as_str()).collect();
    assert!(mods.contains(&"typing"), "got {mods:?}");
    assert!(!mods.contains(&"Literal"), "recorded the imported symbol as a module: {mods:?}");
    assert!(!mods.contains(&"Any"), "recorded the imported symbol as a module: {mods:?}");
}

/// And `import numpy as np` must record `numpy`, not `numpy as np`.
#[test]
fn an_aliased_import_records_the_module_without_its_alias() {
    let f = extract("python", "a.py", "import numpy as np\nimport os\n");
    let mods: Vec<&str> = f.imports.iter().map(|i| i.module.as_str()).collect();
    assert!(mods.contains(&"numpy"), "got {mods:?}");
    assert!(mods.contains(&"os"), "got {mods:?}");
    assert!(
        !mods.iter().any(|m| m.contains(" as ")),
        "an alias leaked into the module name: {mods:?}"
    );
}

/// Go declares methods *outside* the type they belong to, so the walk's
/// enclosing-scope chain never names the owner. Without reading the receiver,
/// `Permission.IsAdmin` and `Other.IsAdmin` are the same symbol — the identity
/// split this project exists to avoid.
#[test]
fn a_go_method_is_owned_and_qualified_by_its_receiver_type() {
    let f = extract(
        "go",
        "perm.go",
        "package perm

type Permission struct{ M int }

         func (p *Permission) IsAdmin() bool { return true }

         type Other struct{}

         func (o *Other) IsAdmin() bool { return false }
",
    );
    let qualified: Vec<String> = f.symbols.iter().map(|s| s.qualified()).collect();
    assert!(qualified.contains(&"Permission.IsAdmin".to_string()), "got {qualified:?}");
    assert!(qualified.contains(&"Other.IsAdmin".to_string()), "got {qualified:?}");

    // And the ownership edge exists, so a type knows its own methods.
    let method_edges: Vec<(String, String)> = f
        .edges
        .iter()
        .filter(|e| e.relation == codegraph_core::Relation::Method)
        .map(|e| (f.symbols[e.from as usize].name.clone(), f.symbols[e.to as usize].name.clone()))
        .collect();
    assert!(
        method_edges.contains(&("Permission".to_string(), "IsAdmin".to_string())),
        "no Permission -> IsAdmin method edge: {method_edges:?}"
    );
}

/// A Go struct is not a type alias, and reporting it as one hides that it can
/// own methods.
#[test]
fn a_go_struct_and_interface_are_distinguished_from_an_alias() {
    let f = extract(
        "go",
        "t.go",
        "package t

type S struct{}
type I interface{ M() }
type A = int
",
    );
    let kinds: Vec<(&str, codegraph_core::SymbolKind)> =
        f.symbols.iter().map(|s| (s.name.as_str(), s.kind)).collect();
    assert!(kinds.contains(&("S", codegraph_core::SymbolKind::Struct)), "got {kinds:?}");
    assert!(kinds.contains(&("I", codegraph_core::SymbolKind::Interface)), "got {kinds:?}");
    assert!(kinds.contains(&("A", codegraph_core::SymbolKind::TypeAlias)), "got {kinds:?}");
}

/// A call on the method's own receiver is a self-call, whatever the author
/// named the receiver.
#[test]
fn a_call_on_the_receiver_variable_is_normalised_to_self() {
    let f = extract(
        "go",
        "perm.go",
        "package perm

type P struct{}

         func (p *P) CanRead() bool { return p.CanAccess() }

         func (p *P) CanAccess() bool { return true }
",
    );
    let call = f.calls.iter().find(|c| c.callee == "CanAccess").expect("the call");
    assert_eq!(call.receiver.as_deref(), Some("self"), "receiver was {:?}", call.receiver);
}

/// A Go import alias is the name the package is called by, and losing it makes
/// every `alias.Func()` look like a method call on an unknown value.
#[test]
fn a_go_import_alias_is_recorded_alongside_the_module() {
    let f = extract(
        "go",
        "a.go",
        "package a

import (
	access_model \"gitea.dev/models/perm/access\"
	\"fmt\"
)
",
    );
    let aliased = f.imports.iter().find(|i| i.module.ends_with("perm/access")).expect("import");
    assert_eq!(aliased.alias.as_deref(), Some("access_model"));
    let plain = f.imports.iter().find(|i| i.module == "fmt").expect("fmt");
    assert_eq!(plain.alias, None, "a plain import has no alias");
}

/// Regression: Go's grouped `import (...)` must yield one import per spec.
/// Matching `import_declaration` as well captured the whole parenthesised block
/// as a single module whose "name" was the block's source text.
#[test]
fn a_grouped_go_import_yields_one_module_per_spec() {
    let f = extract(
        "go",
        "a.go",
        "package main

import (
	\"context\"
	\"fmt\"

	\"code.gitea.io/gitea/models/db\"
)
",
    );
    let mods: Vec<&str> = f.imports.iter().map(|i| i.module.as_str()).collect();
    assert_eq!(mods, ["context", "fmt", "code.gitea.io/gitea/models/db"], "got {mods:?}");
}

/// And a Go alias lives in `name` while the module lives in `path`, so the
/// field order must prefer `path`. This is the same defect shape as
/// `from typing import Literal` recording `Literal`.
#[test]
fn an_aliased_go_import_records_the_path_not_the_alias() {
    let f = extract(
        "go",
        "a.go",
        "package main

import user_model \"code.gitea.io/gitea/models/user\"
",
    );
    let mods: Vec<&str> = f.imports.iter().map(|i| i.module.as_str()).collect();
    assert_eq!(mods, ["code.gitea.io/gitea/models/user"], "recorded the alias: {mods:?}");
}

#[test]
fn a_dotted_module_keeps_its_full_path() {
    let f = extract("python", "a.py", "from a.b.c import thing\nimport x.y\n");
    let mods: Vec<&str> = f.imports.iter().map(|i| i.module.as_str()).collect();
    assert!(mods.contains(&"a.b.c"), "got {mods:?}");
    assert!(mods.contains(&"x.y"), "got {mods:?}");
}

/// JavaScript keeps its specifier in `source`, and must not regress.
#[test]
fn javascript_imports_still_record_the_specifier() {
    let f = extract("javascript", "a.js", "import fs from \"fs\";\nimport { x } from \"./local\";\n");
    let mods: Vec<&str> = f.imports.iter().map(|i| i.module.as_str()).collect();
    assert!(mods.contains(&"fs"), "got {mods:?}");
    assert!(mods.contains(&"./local"), "got {mods:?}");
}
