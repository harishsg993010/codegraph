//! Source tree in, answered query out — the whole stack in one test.

use codegraph_core::{Relation, RelationMask};
use codegraph_index::IndexData;
use codegraph_query::{Engine, Walk};
use codegraph_resolve::index_tree;
use codegraph_store::Store;
use std::path::Path;

fn write(dir: &Path, rel: &str, body: &str) {
    let p = dir.join(rel);
    if let Some(parent) = p.parent() {
        std::fs::create_dir_all(parent).expect("mkdir");
    }
    std::fs::write(p, body).expect("write");
}

/// A small multi-language project with a real call chain through it.
fn project(dir: &Path) {
    write(
        dir,
        "app/db.py",
        "def connect():\n    return 1\n\ndef query(sql):\n    connect()\n    return []\n",
    );
    write(
        dir,
        "app/service.py",
        "import app.db\n\nclass Service:\n    def fetch(self):\n        query('select 1')\n\nclass Other:\n    def fetch(self):\n        pass\n",
    );
    write(
        dir,
        "app/main.py",
        "import app.service\n\ndef main():\n    fetch()\n",
    );
}

fn build(dir: &Path) -> (tempfile::TempDir, Engine) {
    let sd = tempfile::tempdir().expect("tempdir");
    let mut store = Store::create(sd.path()).expect("create");
    index_tree(dir, &mut store, "").expect("index");
    let index = IndexData::build(&store).expect("index build");
    (sd, Engine::from_parts(store, index))
}

/// Python states its heritage in one list and has no `implements` keyword, so
/// the distinction has to come from *what the base is*: PEP 544 makes a class a
/// protocol exactly when it lists `Protocol`, and `abc.ABC` marks an abstract
/// base. Anything else is ordinary inheritance.
#[test]
fn a_python_protocol_or_abc_base_is_implemented_and_a_plain_base_is_extended() {
    let src = tempfile::tempdir().unwrap();
    write(
        src.path(),
        "app/proto.py",
        "from typing import Protocol
import abc

         class Runner(Protocol):
    def run(self, x): ...

         class Store(abc.ABC):
    def get(self, k): ...

         class Plain:
    def helper(self): pass
",
    );
    write(
        src.path(),
        "app/impl.py",
        "from app.proto import Runner, Store, Plain

         class Job(Runner):
    def run(self, x): return x

         class Redis(Store, Plain):
    def get(self, k): return None
",
    );
    let (_sd, e) = build(src.path());

    let named = |n: &str, dir, mask| -> Vec<String> {
        let id = e.by_name(n);
        assert_eq!(id.len(), 1, "expected one {n}");
        e.neighbors(id[0], dir, mask)
            .unwrap()
            .iter()
            .filter_map(|h| e.info(h.id).ok().flatten())
            .map(|i| i.name)
            .collect()
    };
    let impls = RelationMask::of(&[Relation::Implements]);
    let inherits = RelationMask::of(&[Relation::Inherits]);

    assert_eq!(named("Runner", codegraph_query::Direction::In, impls), ["Job"]);
    assert_eq!(named("Store", codegraph_query::Direction::In, impls), ["Redis"]);
    // The ordinary base in the very same list must stay an inheritance.
    assert_eq!(named("Plain", codegraph_query::Direction::In, inherits), ["Redis"]);
    assert!(
        named("Plain", codegraph_query::Direction::In, impls).is_empty(),
        "a plain base class was reported as implemented"
    );
}

/// TypeScript states both, separately, so nothing needs inferring — and the
/// structural pass must not also fire and duplicate the declared edge.
#[test]
fn typescript_extends_and_implements_are_distinct_and_not_duplicated() {
    let src = tempfile::tempdir().unwrap();
    write(
        src.path(),
        "ui.ts",
        "export interface Greeter { greet(n: string): void }
         export interface Sub extends Greeter {}
         export class Base {}
         export class Impl extends Base implements Greeter {
  greet(n: string): void {}
}
",
    );
    let (_sd, e) = build(src.path());

    let greeter = e.by_name("Greeter");
    assert_eq!(greeter.len(), 1);
    let implementers: Vec<String> = e
        .neighbors(greeter[0], codegraph_query::Direction::In, RelationMask::of(&[Relation::Implements]))
        .unwrap()
        .iter()
        .filter_map(|h| e.info(h.id).ok().flatten())
        .map(|i| i.name)
        .collect();
    assert_eq!(implementers, ["Impl"], "expected exactly one, undoubled: {implementers:?}");

    let extenders: Vec<String> = e
        .neighbors(greeter[0], codegraph_query::Direction::In, RelationMask::of(&[Relation::Inherits]))
        .unwrap()
        .iter()
        .filter_map(|h| e.info(h.id).ok().flatten())
        .map(|i| i.name)
        .collect();
    assert_eq!(extenders, ["Sub"], "an interface extending an interface is inheritance");
}

/// A base class from outside the corpus has no symbol to point at, and must
/// produce no edge rather than one to a same-named class elsewhere.
#[test]
fn an_unresolvable_base_class_produces_no_edge() {
    let src = tempfile::tempdir().unwrap();
    write(src.path(), "a/models.py", "class Base:
    pass
");
    // Does not import a/models.py; `Base` here is a third-party class.
    write(src.path(), "b/view.py", "from django.db import Base

class View(Base):
    pass
");
    let (_sd, e) = build(src.path());

    let base = e.by_name("Base");
    assert_eq!(base.len(), 1);
    let hits = e
        .neighbors(base[0], codegraph_query::Direction::In, RelationMask::of(&[Relation::Inherits, Relation::Implements]))
        .unwrap();
    assert!(hits.is_empty(), "bound a foreign base class to an unrelated local one");
}

/// **Go has no `implements` keyword.** A type satisfies an interface by having
/// its methods, so the edge has to be computed by comparing method sets.
#[test]
fn a_go_type_implements_an_interface_it_structurally_satisfies() {
    let src = tempfile::tempdir().unwrap();
    write(
        src.path(),
        "auth/iface.go",
        "package auth

type Method interface {
	Name() string
	Verify(r int, w int) error
}
",
    );
    write(
        src.path(),
        "auth/basic.go",
        "package auth

type Basic struct{}

         func (b *Basic) Name() string { return \"basic\" }
         func (b *Basic) Verify(r int, w int) error { return nil }
",
    );
    // Same method names, wrong arity: must not match.
    write(
        src.path(),
        "auth/wrong.go",
        "package auth

type Wrong struct{}

         func (w *Wrong) Name() string { return \"wrong\" }
         func (w *Wrong) Verify(r int) error { return nil }
",
    );
    // Missing a method entirely: must not match.
    write(
        src.path(),
        "auth/partial.go",
        "package auth

type Partial struct{}

func (p *Partial) Name() string { return \"p\" }
",
    );
    let (_sd, e) = build(src.path());

    let iface = e.by_name("Method");
    assert_eq!(iface.len(), 1, "expected one Method interface");
    let implementers: Vec<String> = e
        .neighbors(iface[0], codegraph_query::Direction::In, RelationMask::of(&[Relation::Implements]))
        .unwrap()
        .iter()
        .filter_map(|h| e.info(h.id).ok().flatten())
        .map(|i| i.name)
        .collect();

    assert!(implementers.contains(&"Basic".to_string()), "got {implementers:?}");
    assert!(
        !implementers.contains(&"Wrong".to_string()),
        "matched on name alone, ignoring arity: {implementers:?}"
    );
    assert!(
        !implementers.contains(&"Partial".to_string()),
        "matched a type missing one of the methods: {implementers:?}"
    );
}

/// An embedded interface states requirements by reference. Ignoring them makes
/// the interface look emptier than it is, and an under-specified interface
/// matches *more* types — so this fails toward false edges, not missing ones.
#[test]
fn an_embedded_interface_contributes_its_methods() {
    let src = tempfile::tempdir().unwrap();
    write(src.path(), "io/r.go", "package io

type Reader interface {
	Read(p int) int
}
");
    write(
        src.path(),
        "io/rw.go",
        "package io

type ReadWriter interface {
	Reader
	Write(p int) int
}
",
    );
    // Has Write but not Read: satisfies Reader's embedder only if Read is
    // wrongly dropped from the requirement set.
    write(
        src.path(),
        "io/w.go",
        "package io

type OnlyWriter struct{}

func (o *OnlyWriter) Write(p int) int { return 0 }
",
    );
    write(
        src.path(),
        "io/both.go",
        "package io

type File struct{}

         func (f *File) Read(p int) int { return 0 }
         func (f *File) Write(p int) int { return 0 }
",
    );
    let (_sd, e) = build(src.path());

    let rw = e.by_name("ReadWriter");
    assert_eq!(rw.len(), 1);
    let names: Vec<String> = e
        .neighbors(rw[0], codegraph_query::Direction::In, RelationMask::of(&[Relation::Implements]))
        .unwrap()
        .iter()
        .filter_map(|h| e.info(h.id).ok().flatten())
        .map(|i| i.name)
        .collect();
    assert!(names.contains(&"File".to_string()), "got {names:?}");
    assert!(
        !names.contains(&"OnlyWriter".to_string()),
        "the embedded Reader's method was dropped from the requirement: {names:?}"
    );
}

/// An interface with no methods is satisfied by everything, so it must produce
/// no edges at all rather than an edge to every type in the corpus.
#[test]
fn an_empty_interface_implicates_nothing() {
    let src = tempfile::tempdir().unwrap();
    write(
        src.path(),
        "a/x.go",
        "package a

type Any interface{}

type T struct{}

func (t *T) F() int { return 1 }
",
    );
    let (_sd, e) = build(src.path());
    let any = e.by_name("Any");
    assert_eq!(any.len(), 1);
    let hits = e
        .neighbors(any[0], codegraph_query::Direction::In, RelationMask::of(&[Relation::Implements]))
        .unwrap();
    assert!(hits.is_empty(), "an empty interface claimed {} implementers", hits.len());
}

/// **`x.F()` inside `F` is not recursion.**
///
/// Found on Gitea: `Group.Verify` dispatches `method.Verify(...)` over its
/// configured auth methods. The bare name bound to the only `Verify` in that
/// file — itself — so the auth chain read as a function calling nothing but
/// itself.
#[test]
fn a_member_call_does_not_bind_to_its_own_caller() {
    let src = tempfile::tempdir().unwrap();
    write(
        src.path(),
        "group.go",
        "package auth

type Group struct{ methods []int }

         func (b *Group) Verify(x int) int {
	for _, m := range b.methods {
		_ = m.Verify(x)
	}
	return 0
}
",
    );
    let (_sd, e) = build(src.path());

    let verify = e.by_name("Verify");
    assert_eq!(verify.len(), 1, "expected one Verify");
    let outs: Vec<_> = e
        .neighbors(verify[0], codegraph_query::Direction::Out, RelationMask::of(&[Relation::Calls]))
        .unwrap();
    assert!(
        !outs.iter().any(|h| h.id == verify[0]),
        "m.Verify() bound to the enclosing Verify, inventing a self-loop"
    );
}

/// **A package-qualified call is not a local call.**
///
/// Found on Gitea: `uri.OpenWithClient` contains `os.Open(u.Path)`, and the
/// bare name `Open` bound to the `Open` defined three lines above it. That made
/// a call cycle out of two functions where only one edge exists, and a taint
/// query then reported three findings whose final hop was that phantom edge.
#[test]
fn a_call_through_an_imported_package_does_not_bind_to_a_local_name() {
    let src = tempfile::tempdir().unwrap();
    write(
        src.path(),
        "uri.go",
        "package uri

import \"os\"

         func Open(s string) error { return OpenWithClient(s) }

         func OpenWithClient(s string) error {
	f, err := os.Open(s)
	_ = f
	return err
}
",
    );
    let (_sd, e) = build(src.path());

    let open = e.by_name("Open");
    assert_eq!(open.len(), 1, "expected one `Open`");
    let with_client = e.by_name("OpenWithClient");
    assert_eq!(with_client.len(), 1);

    // The real edge survives.
    let from_open: Vec<_> = e
        .neighbors(open[0], codegraph_query::Direction::Out, RelationMask::of(&[Relation::Calls]))
        .unwrap();
    assert!(
        from_open.iter().any(|h| h.id == with_client[0]),
        "Open() calls OpenWithClient()"
    );

    // `os.Open` must not become an edge back to the local `Open`.
    let from_with_client: Vec<_> = e
        .neighbors(
            with_client[0],
            codegraph_query::Direction::Out,
            RelationMask::of(&[Relation::Calls]),
        )
        .unwrap();
    assert!(
        !from_with_client.iter().any(|h| h.id == open[0]),
        "os.Open bound to the local Open, fabricating a cycle"
    );
}

#[test]
fn a_source_tree_becomes_a_queryable_graph() {
    let src = tempfile::tempdir().unwrap();
    project(src.path());
    let (_sd, e) = build(src.path());

    // Lookup by name finds the definition.
    let connect = e.by_name("connect");
    assert_eq!(connect.len(), 1, "expected exactly one `connect`");
    let info = e.info(connect[0]).unwrap().expect("info");
    assert_eq!(info.path, "app/db.py");
    assert_eq!(info.name, "connect");

    // The local call query -> connect exists.
    let query = e.by_name("query");
    assert_eq!(query.len(), 1);
    let outs: Vec<_> = e
        .neighbors(query[0], codegraph_query::Direction::Out, RelationMask::of(&[Relation::Calls]))
        .unwrap();
    assert!(
        outs.iter().any(|h| h.id == connect[0]),
        "query() should call connect()"
    );
}

/// Same-named methods on different classes must stay distinct all the way
/// through to a query answer.
#[test]
fn same_named_methods_remain_addressable_separately() {
    let src = tempfile::tempdir().unwrap();
    project(src.path());
    let (_sd, e) = build(src.path());

    let fetches = e.by_name("fetch");
    assert_eq!(fetches.len(), 2, "the two fetch methods collapsed");
    // Both live in the same file, so only the owning class separates them.
    let mut keys: Vec<_> = fetches
        .iter()
        .map(|id| e.info(*id).unwrap().unwrap().key)
        .collect();
    keys.sort();
    keys.dedup();
    assert_eq!(keys.len(), 2, "two fetch methods share one SymbolKey");
}

#[test]
fn blast_radius_finds_dependents() {
    let src = tempfile::tempdir().unwrap();
    project(src.path());
    let (_sd, e) = build(src.path());

    let connect = e.by_name("connect")[0];
    let hits = e.blast_radius(connect, 3).unwrap();
    let names: Vec<String> = hits
        .iter()
        .filter_map(|h| e.info(h.id).unwrap())
        .map(|i| i.name)
        .collect();
    assert!(
        names.iter().any(|n| n == "query"),
        "changing connect() should affect query(); got {names:?}"
    );
}

#[test]
fn reachability_answers_a_source_to_sink_question() {
    let src = tempfile::tempdir().unwrap();
    project(src.path());
    let (_sd, e) = build(src.path());

    let query = e.by_name("query")[0];
    let connect = e.by_name("connect")[0];

    let path = e.taint_path(&[query], &[connect], Relation::TAINT, 8).unwrap();
    assert!(path.is_some(), "query -> connect should be reachable");
    let p = path.unwrap();
    assert_eq!(p.first(), Some(&query));
    assert_eq!(p.last(), Some(&connect));

    // And the reverse direction must not be.
    assert!(
        e.taint_path(&[connect], &[query], Relation::TAINT, 8).unwrap().is_none(),
        "connect -> query is backwards and must not resolve"
    );
}

#[test]
fn search_finds_symbols_by_substring_and_path() {
    let src = tempfile::tempdir().unwrap();
    project(src.path());
    let (_sd, e) = build(src.path());

    assert!(!e.search("conn").unwrap().is_empty(), "substring search missed `connect`");
    assert!(!e.search("service.py").unwrap().is_empty(), "path search missed a file");
    assert!(e.search("\u{1}nope").unwrap().is_empty());
}

#[test]
fn walking_from_a_file_reaches_its_symbols() {
    let src = tempfile::tempdir().unwrap();
    project(src.path());
    let (_sd, e) = build(src.path());

    let file = e
        .search("db.py")
        .unwrap()
        .into_iter()
        .find(|id| e.info(*id).unwrap().is_some_and(|i| i.name == "db.py"))
        .expect("the db.py file symbol");

    let hits = e.walk(&[file], Walk { depth: 2, ..Walk::default() }).unwrap();
    let names: Vec<String> = hits
        .iter()
        .filter_map(|h| e.info(h.id).unwrap())
        .map(|i| i.name)
        .collect();
    assert!(names.contains(&"connect".to_string()), "got {names:?}");
    assert!(names.contains(&"query".to_string()), "got {names:?}");
}

/// A store built from source must survive a close and reopen unchanged — the
/// whole point of persisting it.
#[test]
fn the_indexed_store_reopens() {
    let src = tempfile::tempdir().unwrap();
    project(src.path());
    let sd = tempfile::tempdir().unwrap();
    let (symbols, edges) = {
        let mut store = Store::create(sd.path()).unwrap();
        index_tree(src.path(), &mut store, "").unwrap();
        (store.symbol_count(), store.edge_count())
    };
    let reopened = Store::open(sd.path()).unwrap();
    assert_eq!(reopened.symbol_count(), symbols);
    assert_eq!(reopened.edge_count(), edges);
    reopened.verify().expect("checksums");
}
