//! Specifying what counts as a source, a sink, and a sanitiser.

use codegraph_core::LocalId;
use codegraph_index::IndexQuery;
use codegraph_query::Engine;
use codegraph_store::Result;

/// How to select a set of symbols.
///
/// Deliberately not regular expressions. A taint spec is read and audited by
/// people, and "any name containing `exec`" is both clearer and harder to get
/// subtly wrong than a pattern that might or might not be anchored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Matcher {
    /// Exact folded name.
    Name(String),
    /// Name starts with this.
    NamePrefix(String),
    /// Name contains this.
    NameContains(String),
    /// Name ends with this.
    NameSuffix(String),
    /// Any symbol in a file whose path contains this.
    InPath(String),
    /// A member of a named type: `Type.method`.
    Member { type_name: String, method: String },
}

impl Matcher {
    pub fn name(s: &str) -> Self {
        Self::Name(s.to_lowercase())
    }
    pub fn prefix(s: &str) -> Self {
        Self::NamePrefix(s.to_lowercase())
    }
    pub fn contains(s: &str) -> Self {
        Self::NameContains(s.to_lowercase())
    }
    pub fn suffix(s: &str) -> Self {
        Self::NameSuffix(s.to_lowercase())
    }
    pub fn in_path(s: &str) -> Self {
        Self::InPath(s.to_lowercase())
    }
    pub fn member(type_name: &str, method: &str) -> Self {
        Self::Member { type_name: type_name.to_lowercase(), method: method.to_lowercase() }
    }

    pub fn resolve<I: IndexQuery>(&self, engine: &Engine<I>) -> Result<Vec<LocalId>> {
        self.resolve_with(engine, false)
    }

    /// As [`Self::resolve`]; `stubs` admits external callee stubs, which a
    /// dataflow sink usually is.
    pub fn resolve_with<I: IndexQuery>(&self, engine: &Engine<I>, stubs: bool) -> Result<Vec<LocalId>> {
        let out = match self {
            Matcher::Name(n) if stubs => engine.by_name_with_stubs(n),
            Matcher::Name(n) => engine.by_name(n),
            Matcher::NamePrefix(p) => engine.by_prefix(p),
            Matcher::NameContains(c) => {
                // `search` also matches on path; narrow to name matches so a
                // sink called `exec` does not pull in every file under `exec/`.
                let mut hits = Vec::new();
                for id in engine.search(c)? {
                    if let Some(info) = engine.info(id)?
                        && info.name.to_lowercase().contains(c)
                    {
                        hits.push(id);
                    }
                }
                hits
            }
            Matcher::NameSuffix(c) => {
                let mut hits = Vec::new();
                for id in engine.search(c)? {
                    if let Some(info) = engine.info(id)?
                        && info.name.to_lowercase().ends_with(c.as_str())
                        && (stubs || !info.external)
                    {
                        hits.push(id);
                    }
                }
                hits
            }
            Matcher::InPath(p) => {
                let mut hits = Vec::new();
                for id in engine.search(p)? {
                    if let Some(info) = engine.info(id)?
                        && info.path.to_lowercase().contains(p)
                    {
                        hits.push(id);
                    }
                }
                hits
            }
            Matcher::Member { type_name, method } => {
                // A member is found by name, then confirmed by walking back to
                // its owner — the same ownership the walk recorded.
                let mask = codegraph_core::RelationMask::of(&[
                    codegraph_core::Relation::Method,
                    codegraph_core::Relation::Contains,
                ]);
                let mut hits = Vec::new();
                let named = if stubs { engine.by_name_with_stubs(method) } else { engine.by_name(method) };
                for id in named {
                    for e in engine.neighbors(id, codegraph_query::Direction::In, mask)? {
                        // A package answers to its last segment too:
                        // `exec.Command` for the package `os/exec`.
                        if let Some(owner) = engine.info(e.id)?
                            && let lower = owner.name.to_lowercase()
                            && (lower == *type_name || lower.rsplit(['/', ':']).next() == Some(type_name.as_str()))
                        {
                            hits.push(id);
                            break;
                        }
                    }
                }
                hits
            }
        };
        Ok(out)
    }
}

/// A taint question: what is untrusted, what is dangerous, what makes it safe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaintSpec {
    pub name: String,
    pub sources: Vec<Matcher>,
    pub sinks: Vec<Matcher>,
    /// Symbols that make a path safe. A path through one of these is not
    /// reported.
    pub sanitizers: Vec<Matcher>,
    /// Symbols a matcher picked up that are not what it meant.
    ///
    /// Sinks are matched by name, and a name is shared across ecosystems: Go's
    /// `Exec` is `os/exec` in one file and xorm's database `Exec` in another.
    /// Removing the name entirely loses the real sink; narrowing it by hand for
    /// every codebase is what a spec is for. Applied to sources and sinks
    /// alike, because `request` collides just as freely.
    pub excludes: Vec<Matcher>,
    /// When non-empty, only symbols one of these matches are sources,
    /// sinks or sanitisers (a rule's `paths.include`).
    pub includes: Vec<Matcher>,
    /// When non-empty, only symbols in files of these languages (canonical
    /// names: `python`, `go`, …); library stubs, which have no file, pass.
    pub languages: Vec<String>,
    /// Longest path reported, in edges.
    pub max_hops: u32,
    /// Call sites a value-flow path may be inside at once (see
    /// [`crate::DEFAULT_CONTEXT_DEPTH`]).
    pub context_depth: usize,
    pub mode: Mode,
}

/// What a taint question is asked over.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Mode {
    /// Call-graph reachability: is there a call path from a source function
    /// to a sink function. Necessary for a taint bug, not sufficient — it
    /// cannot see whether any value travels along the path.
    #[default]
    CallGraph,
    /// Value flow: does a value from a source (its return, or its
    /// parameters) reach a sink (its parameters, or an external callee)
    /// through `flows_to` edges — flow-, field- and predicate-sensitive
    /// within a function, call-site-matched across calls (a value leaves a
    /// callee only where it entered), may-alias by copy and address.
    DataFlow,
}

impl TaintSpec {
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            sources: Vec::new(),
            sinks: Vec::new(),
            sanitizers: Vec::new(),
            excludes: Vec::new(),
            includes: Vec::new(),
            languages: Vec::new(),
            // Long enough for a realistic call chain, short enough that a
            // pathological graph cannot make one query run forever.
            max_hops: 12,
            context_depth: crate::DEFAULT_CONTEXT_DEPTH,
            mode: Mode::CallGraph,
        }
    }
    pub fn context_depth(mut self, n: usize) -> Self {
        self.context_depth = n;
        self
    }
    pub fn mode(mut self, mode: Mode) -> Self {
        self.mode = mode;
        self
    }
    pub fn source(mut self, m: Matcher) -> Self {
        self.sources.push(m);
        self
    }
    pub fn sink(mut self, m: Matcher) -> Self {
        self.sinks.push(m);
        self
    }
    pub fn sanitizer(mut self, m: Matcher) -> Self {
        self.sanitizers.push(m);
        self
    }
    pub fn exclude(mut self, m: Matcher) -> Self {
        self.excludes.push(m);
        self
    }
    pub fn max_hops(mut self, n: u32) -> Self {
        self.max_hops = n;
        self
    }
}

/// Starter specs for common shapes.
///
/// These are a **starting point, not a policy**. Every real codebase names its
/// own sources and sinks, and shipping these as if they were complete would
/// give a false sense of coverage — which is worse than no analysis, because it
/// looks like one.
pub mod presets {
    use super::{Matcher, TaintSpec};

    /// Request data reaching a shell or eval.
    pub fn command_injection() -> TaintSpec {
        TaintSpec::new("command-injection")
            .source(Matcher::contains("request"))
            .source(Matcher::contains("argv"))
            .source(Matcher::name("input"))
            .sink(Matcher::contains("popen"))
            .sink(Matcher::name("system"))
            .sink(Matcher::name("exec"))
            .sink(Matcher::name("eval"))
            .sink(Matcher::contains("subprocess"))
            .sanitizer(Matcher::contains("shlex"))
            .sanitizer(Matcher::contains("quote"))
    }

    /// Request data reaching a SQL execution call.
    pub fn sql_injection() -> TaintSpec {
        TaintSpec::new("sql-injection")
            .source(Matcher::contains("request"))
            .source(Matcher::contains("param"))
            .sink(Matcher::name("execute"))
            .sink(Matcher::name("executemany"))
            .sink(Matcher::contains("raw_query"))
            .sanitizer(Matcher::contains("escape"))
            .sanitizer(Matcher::contains("parameterize"))
    }

    /// User-controlled paths reaching filesystem access.
    pub fn path_traversal() -> TaintSpec {
        TaintSpec::new("path-traversal")
            .source(Matcher::contains("request"))
            .source(Matcher::contains("upload"))
            .sink(Matcher::name("open"))
            .sink(Matcher::contains("readfile"))
            .sink(Matcher::contains("sendfile"))
            .sanitizer(Matcher::contains("realpath"))
            .sanitizer(Matcher::contains("normpath"))
            .sanitizer(Matcher::contains("secure_filename"))
    }

    pub fn all() -> Vec<TaintSpec> {
        vec![command_injection(), sql_injection(), path_traversal()]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matchers_fold_case_at_construction() {
        assert_eq!(Matcher::name("Exec"), Matcher::Name("exec".into()));
        assert_eq!(Matcher::prefix("Get"), Matcher::NamePrefix("get".into()));
        assert_eq!(
            Matcher::member("Cursor", "Execute"),
            Matcher::Member { type_name: "cursor".into(), method: "execute".into() }
        );
    }

    #[test]
    fn a_spec_builds_up() {
        let s = TaintSpec::new("t")
            .source(Matcher::name("a"))
            .sink(Matcher::name("b"))
            .sanitizer(Matcher::name("c"))
            .max_hops(3);
        assert_eq!(s.sources.len(), 1);
        assert_eq!(s.sinks.len(), 1);
        assert_eq!(s.sanitizers.len(), 1);
        assert_eq!(s.max_hops, 3);
    }

    #[test]
    fn presets_are_non_empty_and_named() {
        for s in presets::all() {
            assert!(!s.name.is_empty());
            assert!(!s.sources.is_empty(), "{}: no sources", s.name);
            assert!(!s.sinks.is_empty(), "{}: no sinks", s.name);
        }
    }

    /// A preset whose sink list overlaps its source list would report every
    /// source as a finding against itself.
    #[test]
    fn presets_do_not_overlap_sources_and_sinks() {
        for s in presets::all() {
            for src in &s.sources {
                assert!(
                    !s.sinks.contains(src),
                    "{}: {src:?} is both a source and a sink",
                    s.name
                );
            }
        }
    }
}
