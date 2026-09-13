//! Predicate-aware pruning, the same six functions in every language.
//!
//! The rule under test: a definition carries the decidable atoms it was
//! made under and picks up those of every branch it crosses; it is dropped
//! only when they contradict. So `if c: x = b` … `if not c: sink(x)` does not
//! carry `b` to the sink, while anything a disjunction, a call, an
//! undecidable condition or a redefinition touches still flows. Every
//! "pruned" assertion has a "there" assertion beside it, on the same sink:
//! a table that quietly stopped producing atoms would pass the pruned half
//! by accident and fail nothing, so the positive half is what proves the
//! atoms were made — and the pruned half that they were used.

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
            "p.py",
            r#"
def pruned(c, a, b):
    x = a
    if c:
        x = b
    if not c:
        sink(x)

def disj(c, d, a, b):
    x = a
    if c or d:
        x = b
    if not c:
        sink(x)

def conj(c, d, a, b):
    x = a
    if not (c and d):
        x = b
    if c:
        sink(x)

def joined(c, a, b, b2):
    if c:
        x = b
    else:
        x = b2
    sink(x)
    if c:
        sink2(x)

def looped(a, b):
    found = False
    x = a
    while cond():
        if found:
            x = b
    if not found:
        sink(x)

def ranged(n, a, b):
    x = a
    if n > 10:
        x = b
    if n < 5:
        sink(x)
    if n < 20:
        sink2(x)
"#,
        ),
        (
            "javascript",
            "p.js",
            r#"
function pruned(c, a, b) {
  let x = a;
  if (c) { x = b; }
  if (!c) { sink(x); }
}
function disj(c, d, a, b) {
  let x = a;
  if (c || d) { x = b; }
  if (!c) { sink(x); }
}
function conj(c, d, a, b) {
  let x = a;
  if (!(c && d)) { x = b; }
  if (c) { sink(x); }
}
function joined(c, a, b, b2) {
  let x;
  if (c) { x = b; } else { x = b2; }
  sink(x);
  if (c) { sink2(x); }
}
function looped(a, b) {
  let found = false;
  let x = a;
  while (cond()) {
    if (found) { x = b; }
  }
  if (!found) { sink(x); }
}
function ranged(n, a, b) {
  let x = a;
  if (n > 10) { x = b; }
  if (n < 5) { sink(x); }
  if (n < 20) { sink2(x); }
}
"#,
        ),
        (
            "typescript",
            "p.ts",
            r#"
function pruned(c: boolean, a: number, b: number) {
  let x = a;
  if (c) { x = b; }
  if (!c) { sink(x); }
}
function disj(c: boolean, d: boolean, a: number, b: number) {
  let x = a;
  if (c || d) { x = b; }
  if (!c) { sink(x); }
}
function conj(c: boolean, d: boolean, a: number, b: number) {
  let x = a;
  if (!(c && d)) { x = b; }
  if (c) { sink(x); }
}
function joined(c: boolean, a: number, b: number, b2: number) {
  let x: number;
  if (c) { x = b; } else { x = b2; }
  sink(x);
  if (c) { sink2(x); }
}
function looped(a: number, b: number) {
  let found = false;
  let x = a;
  while (cond()) {
    if (found) { x = b; }
  }
  if (!found) { sink(x); }
}
function ranged(n: number, a: number, b: number) {
  let x = a;
  if (n > 10) { x = b; }
  if (n < 5) { sink(x); }
  if (n < 20) { sink2(x); }
}
"#,
        ),
        (
            "java",
            "P.java",
            r#"
class P {
  void pruned(boolean c, int a, int b) {
    int x = a;
    if (c) { x = b; }
    if (!c) { sink(x); }
  }
  void disj(boolean c, boolean d, int a, int b) {
    int x = a;
    if (c || d) { x = b; }
    if (!c) { sink(x); }
  }
  void conj(boolean c, boolean d, int a, int b) {
    int x = a;
    if (!(c && d)) { x = b; }
    if (c) { sink(x); }
  }
  void joined(boolean c, int a, int b, int b2) {
    int x;
    if (c) { x = b; } else { x = b2; }
    sink(x);
    if (c) { sink2(x); }
  }
  void looped(int a, int b) {
    boolean found = false;
    int x = a;
    while (cond()) {
      if (found) { x = b; }
    }
    if (!found) { sink(x); }
  }
  void ranged(int n, int a, int b) {
    int x = a;
    if (n > 10) { x = b; }
    if (n < 5) { sink(x); }
    if (n < 20) { sink2(x); }
  }
}
"#,
        ),
        (
            "c",
            "p.c",
            r#"
void pruned(int c, int a, int b) {
  int x = a;
  if (c) { x = b; }
  if (!c) { sink(x); }
}
void disj(int c, int d, int a, int b) {
  int x = a;
  if (c || d) { x = b; }
  if (!c) { sink(x); }
}
void conj(int c, int d, int a, int b) {
  int x = a;
  if (!(c && d)) { x = b; }
  if (c) { sink(x); }
}
void joined(int c, int a, int b, int b2) {
  int x;
  if (c) { x = b; } else { x = b2; }
  sink(x);
  if (c) { sink2(x); }
}
void looped(int a, int b) {
  int found = 0;
  int x = a;
  while (cond()) {
    if (found) { x = b; }
  }
  if (!found) { sink(x); }
}
void ranged(int n, int a, int b) {
  int x = a;
  if (n > 10) { x = b; }
  if (n < 5) { sink(x); }
  if (n < 20) { sink2(x); }
}
"#,
        ),
        (
            "cpp",
            "p.cpp",
            r#"
void pruned(bool c, int a, int b) {
  int x = a;
  if (c) { x = b; }
  if (!c) { sink(x); }
}
void disj(bool c, bool d, int a, int b) {
  int x = a;
  if (c || d) { x = b; }
  if (!c) { sink(x); }
}
void conj(bool c, bool d, int a, int b) {
  int x = a;
  if (!(c && d)) { x = b; }
  if (c) { sink(x); }
}
void joined(bool c, int a, int b, int b2) {
  int x;
  if (c) { x = b; } else { x = b2; }
  sink(x);
  if (c) { sink2(x); }
}
void looped(int a, int b) {
  bool found = false;
  int x = a;
  while (cond()) {
    if (found) { x = b; }
  }
  if (!found) { sink(x); }
}
void ranged(int n, int a, int b) {
  int x = a;
  if (n > 10) { x = b; }
  if (n < 5) { sink(x); }
  if (n < 20) { sink2(x); }
}
"#,
        ),
        (
            "go",
            "p.go",
            r#"
package p

func pruned(c bool, a int, b int) {
	x := a
	if c {
		x = b
	}
	if !c {
		sink(x)
	}
}

func disj(c bool, d bool, a int, b int) {
	x := a
	if c || d {
		x = b
	}
	if !c {
		sink(x)
	}
}

func conj(c bool, d bool, a int, b int) {
	x := a
	if !(c && d) {
		x = b
	}
	if c {
		sink(x)
	}
}

func joined(c bool, a int, b int, b2 int) {
	var x int
	if c {
		x = b
	} else {
		x = b2
	}
	sink(x)
	if c {
		sink2(x)
	}
}

func looped(a int, b int) {
	found := false
	x := a
	for cond() {
		if found {
			x = b
		}
	}
	if !found {
		sink(x)
	}
}

func ranged(n int, a int, b int) {
	x := a
	if n > 10 {
		x = b
	}
	if n < 5 {
		sink(x)
	}
	if n < 20 {
		sink2(x)
	}
}
"#,
        ),
        (
            "rust",
            "p.rs",
            r#"
fn pruned(c: bool, a: u32, b: u32) {
    let mut x = a;
    if c { x = b; }
    if !c { sink(x); }
}
fn disj(c: bool, d: bool, a: u32, b: u32) {
    let mut x = a;
    if c || d { x = b; }
    if !c { sink(x); }
}
fn conj(c: bool, d: bool, a: u32, b: u32) {
    let mut x = a;
    if !(c && d) { x = b; }
    if c { sink(x); }
}
fn joined(c: bool, a: u32, b: u32, b2: u32) {
    let x;
    if c { x = b; } else { x = b2; }
    sink(x);
    if c { sink2(x); }
}
fn looped(a: u32, b: u32) {
    let mut found = false;
    let mut x = a;
    while cond() {
        if found { x = b; }
    }
    if !found { sink(x); }
}
fn ranged(n: i32, a: u32, b: u32) {
    let mut x = a;
    if n > 10 { x = b; }
    if n < 5 { sink(x); }
    if n < 20 { sink2(x); }
}
"#,
        ),
        (
            "csharp",
            "P.cs",
            r#"
class P {
  void pruned(bool c, int a, int b) {
    int x = a;
    if (c) { x = b; }
    if (!c) { sink(x); }
  }
  void disj(bool c, bool d, int a, int b) {
    int x = a;
    if (c || d) { x = b; }
    if (!c) { sink(x); }
  }
  void conj(bool c, bool d, int a, int b) {
    int x = a;
    if (!(c && d)) { x = b; }
    if (c) { sink(x); }
  }
  void joined(bool c, int a, int b, int b2) {
    int x;
    if (c) { x = b; } else { x = b2; }
    sink(x);
    if (c) { sink2(x); }
  }
  void looped(int a, int b) {
    bool found = false;
    int x = a;
    while (cond()) {
      if (found) { x = b; }
    }
    if (!found) { sink(x); }
  }
  void ranged(int n, int a, int b) {
    int x = a;
    if (n > 10) { x = b; }
    if (n < 5) { sink(x); }
    if (n < 20) { sink2(x); }
  }
}
"#,
        ),
        (
            "ruby",
            "p.rb",
            r#"
def pruned(c, a, b)
  x = a
  if c
    x = b
  end
  if !c
    sink(x)
  end
end

def disj(c, d, a, b)
  x = a
  if c || d
    x = b
  end
  if !c
    sink(x)
  end
end

def conj(c, d, a, b)
  x = a
  if !(c && d)
    x = b
  end
  if c
    sink(x)
  end
end

def joined(c, a, b, b2)
  if c
    x = b
  else
    x = b2
  end
  sink(x)
  if c
    sink2(x)
  end
end

def looped(a, b)
  found = false
  x = a
  while cond()
    if found
      x = b
    end
  end
  if !found
    sink(x)
  end
end

def ranged(n, a, b)
  x = a
  if n > 10
    x = b
  end
  if n < 5
    sink(x)
  end
  if n < 20
    sink2(x)
  end
end
"#,
        ),
    ]
}

fn sym(f: &FileExtract, name: &str) -> u32 {
    f.symbols
        .iter()
        .position(|s| s.name == name && matches!(s.kind, SymbolKind::Function | SymbolKind::Method))
        .unwrap_or_else(|| panic!("no callable {name}")) as u32
}

fn param(f: &FileExtract, func: u32, name: &str) -> u32 {
    f.symbols
        .iter()
        .enumerate()
        .find(|(i, s)| {
            s.kind == SymbolKind::Parameter
                && s.name == name
                && f.edges.iter().any(|e| e.from == func && e.to == *i as u32)
        })
        .map(|(i, _)| i as u32)
        .unwrap_or_else(|| panic!("no parameter {name}"))
}

fn call(f: &FileExtract, func: u32, callee: &str) -> u32 {
    f.calls
        .iter()
        .position(|c| c.caller == Some(func) && c.callee == callee)
        .unwrap_or_else(|| panic!("no call to {callee}")) as u32
}

fn flows_of(f: &FileExtract, func: u32) -> Vec<&RawFlow> {
    f.flows.iter().filter(|fl| fl.function == Some(func)).collect()
}

fn reaches(f: &FileExtract, func: u32, source: &FlowNode, sink: &FlowNode) -> bool {
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

/// `(function, parameter) -> sink's first argument`: present or not.
fn check(f: &FileExtract, lang: &str, func: &str, p: &str, sink: &str, want: bool) {
    let fi = sym(f, func);
    let src = FlowNode::Param(param(f, fi, p));
    let dst = FlowNode::Arg(call(f, fi, sink), ArgPos::Index(0));
    let got = reaches(f, fi, &src, &dst);
    assert_eq!(
        got,
        want,
        "{lang}: {func}: {p} -> {sink} should be {}:\n{}",
        if want { "there" } else { "pruned" },
        describe(f, fi)
    );
}

#[test]
fn a_contradiction_prunes_the_definition() {
    for (lang, path, src) in snippets() {
        let f = extract(lang, path, src);
        check(&f, lang, "pruned", "a", "sink", true);
        check(&f, lang, "pruned", "b", "sink", false);
    }
}

#[test]
fn a_disjunction_establishes_nothing_and_a_negated_conjunction_neither() {
    for (lang, path, src) in snippets() {
        let f = extract(lang, path, src);
        check(&f, lang, "disj", "a", "sink", true);
        check(&f, lang, "disj", "b", "sink", true);
        check(&f, lang, "conj", "a", "sink", true);
        check(&f, lang, "conj", "b", "sink", true);
    }
}

#[test]
fn a_join_keeps_what_both_paths_establish() {
    for (lang, path, src) in snippets() {
        let f = extract(lang, path, src);
        // The unconditional sink sees both arms.
        check(&f, lang, "joined", "b", "sink", true);
        check(&f, lang, "joined", "b2", "sink", true);
        // The one under `c` sees only the arm made under `c` — except where
        // the `sink(x)` call in between may have changed `c`, a parameter
        // of unknown type: there the atoms about `c` are gone by then.
        let call_may_change_c = matches!(lang, "python" | "javascript" | "typescript" | "ruby");
        check(&f, lang, "joined", "b", "sink2", true);
        check(&f, lang, "joined", "b2", "sink2", call_may_change_c);
    }
}

#[test]
fn a_loop_carries_atoms_around_its_back_edge_to_a_fixpoint() {
    for (lang, path, src) in snippets() {
        let f = extract(lang, path, src);
        // `x = b` only ever happens under `found`, which nothing sets: the
        // definition carries `found` around the loop and dies at `!found`.
        // (`found` is a scalar — a local built from literals — so a call in
        // the loop header does not invalidate what is known about it.)
        check(&f, lang, "looped", "a", "sink", true);
        check(&f, lang, "looped", "b", "sink", false);
    }
}

#[test]
fn integer_ranges_prune_only_when_empty() {
    for (lang, path, src) in snippets() {
        let f = extract(lang, path, src);
        check(&f, lang, "ranged", "b", "sink", false);
        check(&f, lang, "ranged", "a", "sink", true);
        check(&f, lang, "ranged", "b", "sink2", true);
    }
}

/// A local whose value can change under a call — a Python parameter, which
/// may be a list the callee empties — is not something a call may be
/// trusted not to have touched. The pruning holds across a call only in
/// languages where a call cannot change a local's truth, and for scalars.
#[test]
fn a_call_invalidates_atoms_about_non_scalars_where_it_can() {
    let py = r#"
def across(c, a, b):
    x = a
    if c:
        x = b
    other()
    if not c:
        sink(x)

def scalar(a, b):
    c = True
    x = a
    if c:
        x = b
    other()
    if not c:
        sink(x)
"#;
    let f = extract("python", "q.py", py);
    // `other()` may have emptied `c`: `b` reaches.
    check(&f, "python", "across", "b", "sink", true);
    // `c` is a literal: nothing a call does changes it.
    check(&f, "python", "scalar", "b", "sink", false);

    let go = r#"
package p

func across(c bool, a int, b int) {
	x := a
	if c {
		x = b
	}
	other()
	if !c {
		sink(x)
	}
}
"#;
    let f = extract("go", "q.go", go);
    // A Go bool parameter cannot be changed by a callee.
    check(&f, "go", "across", "b", "sink", false);
}

/// A local whose address is taken, or that a closure writes, may change
/// without a definition in sight: no atom speaks about it.
#[test]
fn address_taken_and_closure_written_locals_get_no_atoms() {
    let c = r#"
void f(int c, int a, int b) {
  int x = a;
  int *p = &c;
  if (c) { x = b; }
  poke(p);
  if (!c) { sink(x); }
}
"#;
    let f = extract("c", "r.c", c);
    check(&f, "c", "f", "b", "sink", true);

    let js = r#"
function f(c, a, b) {
  let x = a;
  const flip = () => { c = !c; };
  if (c) { x = b; }
  flip();
  if (!c) { sink(x); }
}
"#;
    let f = extract("javascript", "r.js", js);
    check(&f, "javascript", "f", "b", "sink", true);
}

/// A switch on a literal establishes equality on its arm and the negations
/// on the default; `case 1: x = b` cannot reach a sink under `c != 1`.
#[test]
fn switch_arms_establish_equality() {
    let go = r#"
package p

func f(c int, a int, b int) {
	x := a
	switch c {
	case 1:
		x = b
	}
	if c != 1 {
		sink(x)
	}
	if c == 1 {
		sink2(x)
	}
}
"#;
    let f = extract("go", "s.go", go);
    check(&f, "go", "f", "b", "sink", false);
    check(&f, "go", "f", "b", "sink2", true);
    check(&f, "go", "f", "a", "sink", true);

    let js = r#"
function f(c, a, b) {
  let x = a;
  switch (c) {
    case 1: x = b; break;
    default: break;
  }
  if (c !== 1) { sink(x); }
}
"#;
    let f = extract("javascript", "s.js", js);
    check(&f, "javascript", "f", "b", "sink", false);
    check(&f, "javascript", "f", "a", "sink", true);
}

/// Nothing is pruned on what the tables do not decide: an arbitrary call
/// in the condition, arithmetic, a field of a non-local.
#[test]
fn undecidable_conditions_prune_nothing() {
    let py = r#"
def f(c, d, a, b):
    x = a
    if check(c):
        x = b
    if not check(c):
        sink(x)
    y = a
    if c == d + 1:
        y = b
    if c != d + 1:
        sink2(y)
"#;
    let f = extract("python", "u.py", py);
    check(&f, "python", "f", "b", "sink", true);
    check(&f, "python", "f", "b", "sink2", true);
}

/// A literal `false` condition: its consequence is never entered.
#[test]
fn a_literal_false_condition_is_never_taken() {
    let js = r#"
function f(a, b) {
  let x = a;
  if (false) { x = b; }
  sink(x);
}
"#;
    let f = extract("javascript", "l.js", js);
    check(&f, "javascript", "f", "a", "sink", true);
    check(&f, "javascript", "f", "b", "sink", false);
}

/// Two subjects against each other: `a == b` then `a != b` with no
/// definition between cannot both hold; `a < b` … `a >= b` likewise. A
/// comparison of two variables used to establish nothing.
#[test]
fn two_subjects_compared_are_an_atom() {
    let py = r#"
def rel(a, b, t, u):
    x = u
    if a == b:
        x = t
    if a != b:
        sink(x)
    y = u
    if a < b:
        y = t
    if a >= b:
        sink2(y)
    z = u
    if a < b:
        z = t
    if a <= b:
        sink3(z)
"#;
    let f = extract("python", "rel.py", py);
    check(&f, "python", "rel", "t", "sink", false);
    check(&f, "python", "rel", "u", "sink", true);
    check(&f, "python", "rel", "t", "sink2", false);
    check(&f, "python", "rel", "u", "sink2", true);
    // `a < b` and `a <= b` agree: nothing pruned.
    check(&f, "python", "rel", "t", "sink3", true);
    let go = r#"
package p

func rel(a int, b int, t int, u int) {
	x := u
	if a == b {
		x = t
	}
	if a != b {
		sink(x)
	}
}
"#;
    let f = extract("go", "rel.go", go);
    check(&f, "go", "rel", "t", "sink", false);
    check(&f, "go", "rel", "u", "sink", true);
}

/// A pure predicate on a local is a subject: `s.isEmpty()` then
/// `!s.isEmpty()`; `len(x) > 0` then `len(x) == 0`. An arbitrary call is
/// not.
#[test]
fn pure_predicates_are_subjects_and_other_calls_are_not() {
    let java = r#"
class P {
  void f(String s, String t, String u) {
    String x = u;
    if (s.isEmpty()) { x = t; }
    if (!s.isEmpty()) { sink(x); }
    String y = u;
    if (s.startsWith("a")) { y = t; }
    if (!s.startsWith("a")) { sink2(y); }
    String z = u;
    if (compute(s)) { z = t; }
    if (!compute(s)) { sink3(z); }
  }
}
"#;
    let f = extract("java", "P.java", java);
    check(&f, "java", "f", "t", "sink", false);
    check(&f, "java", "f", "u", "sink", true);
    check(&f, "java", "f", "t", "sink2", false);
    // `compute` may return anything each time: no atom, nothing pruned.
    check(&f, "java", "f", "t", "sink3", true);

    // Go: `len(x) > 0` and `len(x) == 0` are intervals over one term.
    let go = r#"
package p

func g(items []int, t int, u int) {
	x := u
	if len(items) > 0 {
		x = t
	}
	if len(items) == 0 {
		sink(x)
	}
}
"#;
    let f = extract("go", "g.go", go);
    check(&f, "go", "g", "t", "sink", false);
    check(&f, "go", "g", "u", "sink", true);
}

/// Three atoms that contradict where no pair does.
#[test]
fn three_atom_intervals_are_decided_exactly() {
    let go = r#"
package p

func h(n int, t int, u int) {
	x := u
	if n >= 7 {
		if n <= 7 {
			x = t
		}
	}
	if n != 7 {
		sink(x)
	}
	y := u
	if n >= 7 {
		if n <= 8 {
			y = t
		}
	}
	if n != 7 {
		sink2(y)
	}
}
"#;
    let f = extract("go", "h.go", go);
    check(&f, "go", "h", "t", "sink", false);
    check(&f, "go", "h", "u", "sink", true);
    // n could be 8: not pruned.
    check(&f, "go", "h", "t", "sink2", true);
}
