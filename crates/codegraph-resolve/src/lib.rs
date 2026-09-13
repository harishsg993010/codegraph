//! Cross-file resolution, and assembling a store from extracted files.
//!
//! Extraction is per file and knows nothing outside it: a call records the name
//! it saw, an import records the specifier as written. Resolution is where those
//! become edges, and it is where this class of tool most often goes wrong.
//!
//! # The rule that matters
//!
//! When a call names something with no local definition, it is tempting to bind
//! it to the one symbol elsewhere in the corpus with that name. That is right
//! often enough to be seductive and wrong often enough to be dangerous: on a
//! monorepo, generically-named exports (`Config`, `Client`, `parse`) make it
//! fabricate dependencies between packages that have nothing to do with each
//! other, and those phantom edges then dominate every architectural query.
//!
//! So the rule here is: **bind only when the answer is unambiguous.** One
//! candidate corpus-wide, same language, and either same file or backed by an
//! import. Anything else is left unresolved. An edge that is not there is a
//! visible gap; an edge that is wrong is invisible and poisons everything
//! downstream.

pub mod diff;
pub mod pipeline;

use std::collections::{HashMap, HashSet};

use codegraph_core::{
    Confidence, FileType, LocalId, Relation, RelationMask, SymbolKey, SymbolKeyParts, SymbolKind,
};
use codegraph_extract::{ArgPos, FileExtract, FlowNode};
use codegraph_store::{
    Edge, Result, SegmentBuilder, Store, StoreError, Symbol, Tier, node_flags,
};

pub use diff::{Change, ChangeKind, DiffOptions, DiffReport, Hit, Named, diff_tree};
pub use pipeline::{IndexReport, UpdateReport, index_tree, scan, update_tree};

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct BuildStats {
    pub files: usize,
    pub symbols: usize,
    pub structural_edges: usize,
    /// Calls bound to a definition in the same file.
    pub calls_local: usize,
    /// Calls bound across files by the single-candidate rule.
    pub calls_cross_file: usize,
    /// Calls bound through their receiver's type — `self.foo()` and
    /// `Type.foo()`. The most precise rule, so it runs first.
    pub calls_receiver: usize,
    /// Calls deliberately left unbound because the name was ambiguous.
    pub calls_ambiguous: usize,
    /// Calls whose name matched nothing in the corpus (a stdlib or third-party
    /// callee, most often).
    pub calls_unresolved: usize,
    pub imports_resolved: usize,
    pub imports_external: usize,
    /// Distinct external packages the corpus depends on.
    pub packages: usize,
    /// `implements` edges inferred from structural interface satisfaction.
    pub implements: usize,
    /// Declared supertype references bound to a definition in the corpus.
    pub supertypes_resolved: usize,
    /// Declared supertype references naming something outside the corpus — a
    /// base class from a third-party package, most often.
    pub supertypes_external: usize,
    /// Interfaces skipped because their method set could not be compared —
    /// empty, or made only of embedded interfaces.
    pub interfaces_skipped: usize,
    pub parse_errors: usize,
    /// Module-level variables and constants, and fields.
    pub variables: usize,
    pub parameters: usize,
    /// CFG blocks stored.
    pub blocks: usize,
    /// `references` edges from callables to the variables they touch.
    pub references: usize,
    /// `flows_to` edges.
    pub flows: usize,
    /// Flow facts whose non-local endpoint named nothing the corpus holds.
    pub flows_unresolved: usize,
    /// Facts from a summarised external call's result, dropped: the
    /// summary already recorded what reaches it.
    pub flows_summarised: usize,
    /// External callee stubs minted for values flowing into unresolved calls.
    pub external_stubs: usize,
    /// Proxy rows: one per (file, foreign symbol a value flows out of).
    pub proxies: usize,
    /// Local-variable rows, and the `local_flow` edges through them.
    pub locals: usize,
    pub local_flows: usize,
}

/// Edge flag marking a dependency on something outside the corpus.
pub const EXTERNAL_EDGE: u8 = codegraph_store::edge_flags::EXTERNAL;

/// The top-level package a module specifier belongs to.
///
/// `requests.adapters` -> `requests`, `@scope/pkg/sub` -> `@scope/pkg`,
/// `github.com/stretchr/testify/assert` -> `github.com/stretchr/testify`,
/// `./local` -> nothing (relative paths are not packages).
///
/// The dot means two different things depending on the specifier's shape, and
/// treating it uniformly is wrong in both directions:
///
/// - In a *dotted* specifier (`requests.adapters`, `java.util.List`) the dot is
///   a namespace separator, so the package is the first segment.
/// - In a *path* specifier the leading segment can be a **host**
///   (`code.gitea.io/gitea/models/db`). Splitting on the dot there yields
///   `code`; keeping only the first path segment yields `code.gitea.io`, which
///   collapses every dependency hosted on one forge into a single package.
///   Neither is a package. The module is `host/org/repo` — three segments, the
///   convention every Go forge follows. It is a convention and not a law: a
///   two-segment module path yields one segment too many. That costs
///   granularity in a dependency list, whereas the alternatives cost
///   correctness, and a module's *own* path is stripped before it reaches here.
///
/// So: a specifier containing `/` is a path, and its dots are only namespace
/// separators when there is no `/`.
///
/// One thing shape alone cannot settle is where a non-host path ends.
/// `lodash/fp` is the `lodash` package's subpath, but `net/http` *is* the
/// package — Go has no such thing as a subpath import. `lang` decides that one
/// case; everything else is shape.
pub fn package_name_in(spec: &str, lang: &str) -> String {
    let spec = spec.trim();
    if spec.is_empty() || spec.starts_with('.') || spec.starts_with('/') {
        return String::new();
    }
    // A scoped npm package keeps two segments.
    if let Some(rest) = spec.strip_prefix('@') {
        let mut it = rest.split('/');
        return match (it.next(), it.next()) {
            (Some(scope), Some(name)) if !scope.is_empty() && !name.is_empty() => {
                format!("@{scope}/{name}")
            }
            _ => String::new(),
        };
    }
    if spec.contains('/') {
        let segments: Vec<&str> = spec.split('/').collect();
        // A dot in the first segment marks it as a host, so the package needs
        // the org and repo after it. Without one it is a plain namespaced path
        // (`net/http`, `lodash/fp`) whose package is the first segment.
        let keep = if segments[0].contains('.') {
            3
        } else if lang == "go" {
            // Go stdlib: the import path is the package. Truncating
            // `net/http` to `net` attributes it to a package nobody imported.
            segments.len()
        } else {
            1
        };
        return segments[..keep.min(segments.len())].join("/");
    }
    spec.split('.').next().unwrap_or("").to_string()
}

/// [`package_name_in`] without a language, for callers that do not have one.
pub fn package_name(spec: &str) -> String {
    package_name_in(spec, "")
}

/// The name a specifier is referred to by in code.
///
/// `os` -> `os`, `net/http` -> `http`, `gitea.dev/models/user` -> `user`,
/// `requests.adapters` -> `adapters`. This is the qualifier in `os.Open(...)`,
/// and knowing it is what separates a package-qualified call from a method
/// call — which look identical in Go.
///
/// Not exact: a Go import may be aliased (`user_model "…/models/user"`), and
/// the alias is the qualifier. Extraction records the module path rather than
/// the alias, so an aliased package is not recognised here.
fn import_qualifier(spec: &str) -> String {
    let spec = spec.trim().trim_matches(['"', '\'', '<', '>']);
    let last = spec.rsplit('/').next().unwrap_or(spec);
    let last = last.rsplit('.').next().unwrap_or(last);
    last.to_lowercase()
}

/// Packages live in their own keyspace: one node per package for the whole
/// corpus, regardless of which file imported it or under what path.
fn package_key(name: &str) -> SymbolKey {
    SymbolKey::new(SymbolKeyParts {
        repo: "",
        path: "",
        kind: SymbolKind::Package,
        scope: &[],
        name,
        disambiguator: 0,
    })
}

/// The key of the symbol standing for a file itself.
fn file_key(repo: &str, path: &str) -> SymbolKey {
    SymbolKey::new(SymbolKeyParts {
        repo,
        path,
        kind: SymbolKind::File,
        scope: &[],
        name: path.rsplit('/').next().unwrap_or(path),
        disambiguator: 0,
    })
}

fn symbol_key(repo: &str, path: &str, s: &codegraph_extract::RawSymbol, dis: u32) -> SymbolKey {
    let scope: Vec<&str> = s.scope.iter().map(String::as_str).collect();
    SymbolKey::new(SymbolKeyParts {
        repo,
        path,
        kind: s.kind,
        scope: &scope,
        name: &s.name,
        disambiguator: dis,
    })
}

fn fold(s: &str) -> String {
    s.trim().trim_end_matches("()").to_lowercase()
}

/// Whether a symbol kind can be the target of a call. Binding a call to a
/// struct or a type alias is how an indirect-call heuristic starts inventing
/// edges, so callability is checked rather than assumed.
fn is_callable(kind: SymbolKind) -> bool {
    matches!(kind, SymbolKind::Function | SymbolKind::Method | SymbolKind::Macro)
}

/// Whether a symbol kind can own methods.
fn is_type_like(kind: SymbolKind) -> bool {
    matches!(
        kind,
        SymbolKind::Class
            | SymbolKind::Interface
            | SymbolKind::Trait
            | SymbolKind::Struct
            | SymbolKind::Enum
            | SymbolKind::Module
            | SymbolKind::Namespace
    )
}

/// Receiver words that mean "the enclosing instance".
///
/// Language-specific spellings, kept in one list rather than in each config:
/// they are a closed set, and a receiver named `self` in a language without
/// that convention is a variable that will simply fail the member lookup.
fn is_self_receiver(receiver: &str) -> bool {
    matches!(
        receiver.trim(),
        "self" | "this" | "Self" | "me" | "cls" | "$this" | "base" | "super"
    )
}

/// Walk up the ownership chain from `symbol` to the nearest type-like owner.
///
/// Bounded: a malformed ownership chain must not hang resolution.
fn enclosing_type(
    f: &CorpusFile<'_>,
    owners: &HashMap<u32, u32>,
    symbol: u32,
) -> Option<u32> {
    let mut cur = symbol;
    for _ in 0..16 {
        if is_type_like(f.symbols[cur as usize].kind) {
            return Some(cur);
        }
        cur = *owners.get(&cur)?;
    }
    None
}

/// Resolve a module specifier to a path in the corpus.
///
/// Deliberately conservative and language-agnostic: try the specifier as a
/// path with each known extension, as a package `__init__`/`index`, and
/// finally as a unique path suffix. A specifier that matches several files
/// resolves to none — the same unambiguity rule as calls.
/// The corpus, as import resolution needs to see it. Built once per build and
/// borrowed by every specifier, so the lookups stay O(1).
struct Corpus<'a> {
    /// Exact path -> file index.
    paths: &'a HashMap<String, usize>,
    /// Filename stem -> file indices, narrowing the suffix rule.
    by_basename: &'a HashMap<String, Vec<usize>>,
    /// Directory -> the files in it, for languages that import directories.
    by_dir: &'a HashMap<String, Vec<usize>>,
    all_paths: &'a [String],
    /// Prefixes that name the corpus itself in an absolute specifier.
    roots: &'a [String],
}

fn resolve_import(
    spec: &str,
    from: &str,
    c: &Corpus<'_>,
    // Whether this language imports a *directory* of files rather than one
    // file. True for Go, where `import "x/y"` names every source file in `y/`.
    // Deliberately not the default: Python's `import pkg` does **not** import
    // `pkg`'s submodules, so expanding a directory there would invent edges.
    dir_packages: bool,
) -> Vec<usize> {
    let spec = spec.trim();
    if spec.is_empty() {
        return Vec::new();
    }

    // Relative specifiers resolve against the importing file's directory.
    let base = from.rsplit_once('/').map_or("", |(d, _)| d);
    let mut candidates: Vec<String> = Vec::new();
    if spec.starts_with('.') && !spec.starts_with("..") || spec.starts_with("./") {
        let rest = spec.trim_start_matches("./");
        candidates.push(if base.is_empty() { rest.into() } else { format!("{base}/{rest}") });
    } else if spec.starts_with("../") {
        // One level up is enough to cover the common case without a full
        // normaliser; deeper relatives fall through to the suffix rule.
        let up = base.rsplit_once('/').map_or("", |(d, _)| d);
        let rest = spec.trim_start_matches("../");
        candidates.push(if up.is_empty() { rest.into() } else { format!("{up}/{rest}") });
    }
    // Dotted module paths (Python, Java) and slash paths alike.
    candidates.push(spec.replace('.', "/"));
    candidates.push(spec.to_string());

    // Indexing *inside* a package makes its own absolute imports unresolvable:
    // rooted at `graphify/graphify`, the specifier `graphify.extractors.base`
    // names `extractors/base.py`, but the leading segment is the root itself
    // and matches nothing. Strip it — but only when it really is the root's
    // name, so `os.path` cannot be reduced to a local `path.py`.
    //
    // Measured on a real tree: without this, indexing the package directory
    // resolved 5 imports and bound 16.6% of calls; the repository root
    // resolved 1,500 and bound 29.3%. Same code, different starting directory.
    //
    // There can be more than one such prefix. A Go module declares its import
    // root in `go.mod` (`module gitea.dev`), which has nothing to do with the
    // checkout's directory name — measured on one real repository, 11,979 of
    // its imports start with that module path, and without it every one of
    // them is a dependency on a package that does not exist.
    for root in c.roots {
        if root.is_empty() {
            continue;
        }
        if let Some(rest) = spec
            .strip_prefix(root.as_str())
            .and_then(|r| r.strip_prefix('.').or_else(|| r.strip_prefix('/')))
            && !rest.is_empty()
        {
            // A module path is already slash-separated; only a dotted
            // specifier needs translating.
            candidates.push(if root.contains('/') || root.contains('.') {
                rest.to_string()
            } else {
                rest.replace('.', "/")
            });
        }
    }

    const EXTS: &[&str] = &[
        "", ".py", ".js", ".ts", ".tsx", ".jsx", ".mjs", ".cjs", ".go", ".rs", ".java", ".cs",
        ".rb", ".c", ".h", ".cpp", ".hpp",
    ];
    for cand in &candidates {
        for ext in EXTS {
            if let Some(&i) = c.paths.get(&format!("{cand}{ext}")) {
                return vec![i];
            }
        }
        for index in ["__init__.py", "index.ts", "index.js", "mod.rs"] {
            if let Some(&i) = c.paths.get(&format!("{cand}/{index}")) {
                return vec![i];
            }
        }
        // A directory package. Checked after the file probes so an explicit
        // file still wins.
        if dir_packages && let Some(members) = c.by_dir.get(cand.as_str()) {
            return members.clone();
        }
    }

    // Last resort: a unique file whose path ends with the specifier. Unique or
    // nothing — a specifier matching several files is exactly the ambiguity
    // that fabricates cross-package edges.
    //
    // Narrowed by basename first. Scanning every path here instead cost
    // O(corpus) per import: on a 17k-file tree with 111k imports that was ~1.9
    // billion string comparisons, and it dominated the whole pipeline.
    let Some(tail) = candidates.last().map(|t| t.trim_start_matches("./")) else {
        return Vec::new();
    };
    let last_segment = tail.rsplit('/').next().unwrap_or(tail);
    let stem = last_segment.split('.').next().unwrap_or(last_segment);
    let Some(bucket) = c.by_basename.get(stem) else {
        return Vec::new();
    };
    let mut hit = None;
    for &i in bucket {
        // Every file in the bucket already has this stem, so a stem test here
        // would always pass and the *directory* part of the specifier would go
        // unchecked — `pkg/mod` would match any `mod.py` anywhere. The full
        // tail has to match, on a path boundary.
        if tail_matches(&c.all_paths[i], tail) {
            if hit.is_some() {
                return Vec::new();
            }
            hit = Some(i);
        }
    }
    hit.into_iter().collect()
}

/// Does `path` end with `tail`, ignoring `path`'s extension, on a path
/// boundary?
///
/// `pkg/mod` matches `a/pkg/mod.py` but not `a/other/mod.py` (wrong directory)
/// and not `a/xpkg/mod.py` (not a boundary).
fn tail_matches(path: &str, tail: &str) -> bool {
    let stripped = match path.rsplit_once('.') {
        // Only treat the last dot as an extension when it is in the final
        // segment; `a.b/c` has no extension.
        Some((head, ext)) if !ext.contains('/') => head,
        _ => path,
    };
    for candidate in [path, stripped] {
        if candidate == tail {
            return true;
        }
        if let Some(prefix) = candidate.strip_suffix(tail)
            && prefix.ends_with('/')
        {
            return true;
        }
    }
    false
}

/// `file stem -> indices of files with that stem`. Built once per corpus so the
/// suffix rule above is a hash lookup rather than a scan.
fn basename_index(paths: &[String]) -> HashMap<String, Vec<usize>> {
    let mut out: HashMap<String, Vec<usize>> = HashMap::new();
    for (i, p) in paths.iter().enumerate() {
        let base = p.rsplit('/').next().unwrap_or(p);
        let stem = base.split('.').next().unwrap_or(base);
        out.entry(stem.to_string()).or_default().push(i);
    }
    out
}

/// One method, as `(folded name, arity)` — what interface satisfaction is
/// compared on.
type MethodSig = (String, Option<u32>);
/// A type's method set.
type Signature = std::collections::BTreeSet<MethodSig>;
/// A type, as `(file index, symbol index)`.
type TypeRef = (usize, u32);

/// Files grouped by their containing directory.
///
/// Needed because in some languages the unit of import is the *directory*, not
/// the file: `import "gitea.dev/modules/setting"` names every `.go` file in
/// `modules/setting/`, and there is no single file to bind it to.
fn directory_index(paths: &[String]) -> HashMap<String, Vec<usize>> {
    let mut out: HashMap<String, Vec<usize>> = HashMap::new();
    for (i, p) in paths.iter().enumerate() {
        if let Some((dir, _)) = p.rsplit_once('/') {
            out.entry(dir.to_string()).or_default().push(i);
        }
    }
    out
}

/// One symbol as resolution sees it, whether freshly extracted or read back
/// from the store.
#[derive(Debug, Clone)]
struct CorpusSym<'a> {
    name: &'a str,
    kind: SymbolKind,
    line: u32,
    /// Declared parameter count. `None` for context symbols: arity is not
    /// stored, so structural interface satisfaction cannot be recomputed
    /// against them — see [`build_delta`].
    arity: Option<u32>,
    key: SymbolKey,
    /// For a `Parameter`: its position.
    param_index: Option<u32>,
    /// The definition hash; `0` for context symbols (not needed there).
    hash: u64,
}

/// A within-file ownership edge: `contains` or `method`.
#[derive(Debug, Clone, Copy)]
struct OwnEdge {
    from: u32,
    to: u32,
    relation: Relation,
    line: u32,
}

/// One file as resolution sees it.
///
/// Either **fresh** — extracted this run, and about to be written — or
/// **context**: unchanged, read back from the store so the fresh files can
/// resolve against it, and written nowhere. Both look the same to the rules,
/// which is the point: a rule that behaves differently for a symbol depending
/// on where it came from would make an incremental build disagree with a
/// full one.
struct CorpusFile<'a> {
    path: &'a str,
    lang: &'a str,
    structural_interfaces: bool,
    symbols: Vec<CorpusSym<'a>>,
    edges: Vec<OwnEdge>,
    /// The key of the symbol standing for the file itself.
    file_key: SymbolKey,
    /// The extract, for a fresh file. Context files have none, and no calls,
    /// imports, or supertype references to resolve — their edges are already
    /// in the store.
    fresh: Option<&'a FileExtract>,
    /// The repo tag keys are minted under.
    repo: &'a str,
}

impl<'a> CorpusFile<'a> {
    /// A fresh file. Keys are minted here: a name colliding within one file
    /// gets a disambiguator rather than being dropped — two conditionally
    /// defined functions are two symbols.
    fn fresh(f: &'a FileExtract, repo: &'a str) -> Self {
        let mut used: HashMap<SymbolKey, u32> = HashMap::new();
        let symbols = f
            .symbols
            .iter()
            .map(|s| {
                let base_key = symbol_key(repo, &f.path, s, 0);
                let next = used.entry(base_key).or_insert(0);
                let dis = *next;
                *next += 1;
                CorpusSym {
                    name: &s.name,
                    kind: s.kind,
                    line: s.line,
                    arity: s.arity,
                    key: if dis == 0 { base_key } else { symbol_key(repo, &f.path, s, dis) },
                    param_index: s.param_index,
                    hash: s.hash,
                }
            })
            .collect();
        Self {
            path: &f.path,
            lang: f.lang,
            structural_interfaces: f.structural_interfaces,
            symbols,
            edges: f
                .edges
                .iter()
                .map(|e| OwnEdge { from: e.from, to: e.to, relation: e.relation, line: e.line })
                .collect(),
            file_key: file_key(repo, &f.path),
            fresh: Some(f),
            repo,
        }
    }
}

/// The symbols a fresh extract would be written as: `(key, kind)`.
///
/// What an incremental update compares against the store to decide whether a
/// change altered a file's symbol set or only bodies.
pub fn symbol_keys(f: &FileExtract, repo: &str) -> Vec<(SymbolKey, u8)> {
    CorpusFile::fresh(f, repo).symbols.iter().map(|s| (s.key, s.kind.as_u8())).collect()
}

/// Build a segment from freshly extracted files and commit it.
pub fn build(files: &[FileExtract], store: &mut Store, repo: &str) -> Result<BuildStats> {
    build_rooted(files, store, repo, &[])
}

/// As [`build`], but told the indexed root's directory name so intra-package
/// absolute imports resolve when the root *is* the package.
pub fn build_rooted(
    files: &[FileExtract],
    store: &mut Store,
    repo: &str,
    roots: &[String],
) -> Result<BuildStats> {
    let corpus: Vec<CorpusFile> = files.iter().map(|f| CorpusFile::fresh(f, repo)).collect();
    let id = store.next_segment_id();
    let b = SegmentBuilder::new(id, Tier::Ast);
    let (b, stats, paths) = resolve_into(b, &corpus, roots, &[])?;
    store.commit_segment(id, b, Tier::Ast, &paths)?;
    Ok(stats)
}

/// Build a **delta** segment: only `files` are written, resolved against the
/// rest of the corpus as the store already holds it.
///
/// The store is not rewritten. Edges from a fresh file into an unchanged one
/// are written keyed (`EdgeExt`), and the view resolves them; edges from
/// unchanged files into a re-indexed one follow its symbols by key. The caller
/// is expected to have re-extracted every file with an edge into a changed
/// file — see [`pipeline::update_tree`] — so that those edges are recomputed
/// rather than inherited.
///
/// # What a delta cannot recompute
///
/// Structural (`implements`) edges between a fresh type and an unchanged
/// interface: comparing method sets needs arity, which the store does not
/// hold. Those edges are **carried forward** from the file's previous version
/// where both endpoints still exist, and a type that *newly* satisfies an
/// unchanged interface is not found. Likewise a definition added or removed
/// in a fresh file can change whether a name is unique corpus-wide, and
/// bindings in files that neither changed nor share an edge with a changed
/// file are not revisited. Both are exact again at the next full re-index,
/// which [`pipeline::update_tree`]'s policy schedules once the deltas have
/// grown to a share of the base.
pub fn build_delta(
    files: &[FileExtract],
    store: &mut Store,
    repo: &str,
    roots: &[String],
) -> Result<BuildStats> {
    let id = store.next_segment_id();
    let fresh_paths: HashSet<&str> = files.iter().map(|f| f.path.as_str()).collect();
    let mut corpus: Vec<CorpusFile> = files.iter().map(|f| CorpusFile::fresh(f, repo)).collect();

    // --- context, read back from the store ---
    let view = store.view();
    let mut file_of_path: HashMap<&str, usize> = HashMap::new();
    // Store-wide id -> (corpus file, symbol index), dense: the ownership
    // edges below need to turn an edge target back into a corpus position.
    let mut at: Vec<(u32, u32)> = vec![(u32::MAX, u32::MAX); view.node_count()];
    let mut checked_repo = false;
    // `implements` edges from a re-indexed type to an unchanged interface,
    // to carry forward: `(type key, interface key, line, conf, context)`.
    let mut carried: Vec<(SymbolKey, SymbolKey, u32, Confidence, String)> = Vec::new();
    for si in 0..view.segment_count() {
        let (seg, base) = view.segment(si);
        let (files_col, names, kinds, lines, flags, keys) = (
            seg.node_files()?,
            seg.node_names()?,
            seg.node_kinds()?,
            seg.node_lines()?,
            seg.node_flags()?,
            seg.keys()?,
        );
        for l in 0..seg.node_count() {
            let gid = LocalId::new(base + l as u32);
            if !view.is_canonical(gid) || flags[l] & node_flags::EXTERNAL != 0 {
                continue;
            }
            let path = seg.file_path(files_col[l]);
            let kind = SymbolKind::from_u8(kinds[l]);
            // A block or a local is a callable's private structure: nothing
            // resolves against it, and it would inflate the name tables.
            if matches!(kind, SymbolKind::Block | SymbolKind::Local) {
                continue;
            }
            if fresh_paths.contains(path) {
                // The previous version of a file being re-indexed. Its rows
                // die at commit; only its structural edges are worth keeping.
                if is_type_like(kind) || kind == SymbolKind::Interface {
                    for e in view.out_edges(gid, RelationMask::of(&[Relation::Implements]))? {
                        let target_path = view.path(e.node)?;
                        if !fresh_paths.contains(target_path) {
                            carried.push((
                                keys[l],
                                view.key(e.node)?,
                                lines[l],
                                e.confidence,
                                view.name(e.node)?.to_string(),
                            ));
                        }
                    }
                }
                continue;
            }
            let fi = match file_of_path.get(path) {
                Some(&fi) => fi,
                None => {
                    let config = codegraph_extract::lang::for_path(std::path::Path::new(path));
                    corpus.push(CorpusFile {
                        path,
                        lang: config.map_or("", |c| c.name),
                        structural_interfaces: config.is_some_and(|c| c.structural_interfaces),
                        symbols: Vec::new(),
                        edges: Vec::new(),
                        file_key: SymbolKey::NONE,
                        fresh: None,
                        repo,
                    });
                    file_of_path.insert(path, corpus.len() - 1);
                    corpus.len() - 1
                }
            };
            if flags[l] & node_flags::FILE_NODE != 0 {
                // The store's keys were minted under some repo tag. If ours
                // differs, every keyed edge into the store would dangle —
                // silently. Check once, loudly.
                if !checked_repo {
                    if file_key(repo, path) != keys[l] {
                        return Err(StoreError::Manifest(format!(
                            "repo tag {repo:?} does not match the one this store was indexed with"
                        )));
                    }
                    checked_repo = true;
                }
                corpus[fi].file_key = keys[l];
                continue;
            }
            at[gid.index()] = (fi as u32, corpus[fi].symbols.len() as u32);
            corpus[fi].symbols.push(CorpusSym {
                name: seg.string(names[l]),
                kind,
                line: lines[l],
                arity: None,
                key: keys[l],
                param_index: None,
                hash: 0,
            });
        }
    }
    // Ownership edges of context types, so `Type.method()` in a fresh file
    // can bind to a method the store already holds; and of context
    // callables, whose parameters (with the position each `contains` edge
    // carries) are what a fresh caller's arguments bind to.
    let own = RelationMask::of(&[Relation::Contains, Relation::Method]);
    for gid in view.ids() {
        let (fi, si) = at[gid.index()];
        if fi == u32::MAX {
            continue;
        }
        let kind = corpus[fi as usize].symbols[si as usize].kind;
        if !is_type_like(kind) && !is_callable(kind) {
            continue;
        }
        for e in view.out_edges(gid, own)? {
            let (tf, ts) = at[e.node.index()];
            if tf != fi {
                continue;
            }
            if corpus[fi as usize].symbols[ts as usize].kind == SymbolKind::Parameter {
                let pos = e.context.and_then(|c| c.parse::<u32>().ok());
                corpus[fi as usize].symbols[ts as usize].param_index = pos;
            }
            corpus[fi as usize].edges.push(OwnEdge { from: si, to: ts, relation: e.relation, line: e.line });
        }
    }

    let b = SegmentBuilder::new(id, Tier::Ast).with_reverse_csr(true);
    let (b, stats, paths) = resolve_into(b, &corpus, roots, &carried)?;
    store.commit_segment(id, b, Tier::Ast, &paths)?;
    Ok(stats)
}

/// Resolve `corpus` and write its fresh files into `b`.
///
/// Every rule reads the whole corpus; only fresh files are written. Returns
/// the builder, the stats, and the paths the segment will own.
fn resolve_into<'a>(
    mut b: SegmentBuilder,
    corpus: &[CorpusFile<'a>],
    roots: &[String],
    carried: &[(SymbolKey, SymbolKey, u32, Confidence, String)],
) -> Result<(SegmentBuilder, BuildStats, Vec<String>)> {
    let fresh: Vec<usize> = (0..corpus.len()).filter(|&i| corpus[i].fresh.is_some()).collect();
    let mut stats = BuildStats { files: fresh.len(), ..Default::default() };

    let paths: Vec<String> = corpus.iter().map(|f| f.path.to_string()).collect();
    let path_index: HashMap<String, usize> =
        paths.iter().cloned().enumerate().map(|(i, p)| (p, i)).collect();
    let by_basename = basename_index(&paths);
    let by_dir = directory_index(&paths);
    let corpus_index = Corpus {
        paths: &path_index,
        by_basename: &by_basename,
        by_dir: &by_dir,
        all_paths: &paths,
        roots,
    };

    // --- files and their symbols ---
    // Indexed by corpus position; only fresh files have entries.
    let mut file_locals: Vec<LocalId> = vec![LocalId::NONE; corpus.len()];
    let mut file_ids: Vec<codegraph_core::FileId> = vec![codegraph_core::FileId::NONE; corpus.len()];
    let mut packages: HashSet<SymbolKey> = HashSet::new();
    let mut sym_locals: Vec<Vec<LocalId>> = vec![Vec::new(); corpus.len()];
    // folded name -> every symbol carrying it, for the single-candidate rule.
    let mut by_name: HashMap<String, Vec<(usize, u32)>> = HashMap::new();

    for (fi, f) in corpus.iter().enumerate() {
        for (si, s) in f.symbols.iter().enumerate() {
            by_name.entry(fold(s.name)).or_default().push((fi, si as u32));
        }
        let Some(x) = f.fresh else { continue };
        if x.had_parse_error {
            stats.parse_errors += 1;
        }
        let file_id = b.add_file(f.path, x.lang_id, x.content_hash, x.mtime_nanos, x.size);
        file_ids[fi] = file_id;
        let base = f.path.rsplit('/').next().unwrap_or(f.path);
        file_locals[fi] = b.add_symbol(Symbol {
            key: f.file_key,
            file: file_id,
            name: base,
            norm_name: &fold(base),
            kind: SymbolKind::File,
            file_type: FileType::Code,
            line: 1,
            flags: node_flags::FILE_NODE,
            hash: 0,
        });
        let mut locals = Vec::with_capacity(f.symbols.len());
        for s in &f.symbols {
            locals.push(b.add_symbol(Symbol {
                key: s.key,
                file: file_id,
                name: s.name,
                norm_name: &fold(s.name),
                kind: s.kind,
                hash: s.hash,
                file_type: FileType::Code,
                line: s.line,
                flags: if is_callable(s.kind) { node_flags::CALLABLE } else { 0 },
            }));
        }
        sym_locals[fi] = locals;
        stats.symbols += f.symbols.len() + 1;
    }

    // --- structural edges ---
    for &fi in &fresh {
        let f = &corpus[fi];
        let file_local = file_locals[fi];
        // The file contains every symbol that has no owner of its own.
        let owned: HashSet<u32> = f.edges.iter().map(|e| e.to).collect();
        for (si, s) in f.symbols.iter().enumerate() {
            if owned.contains(&(si as u32)) {
                continue;
            }
            b.add_edge(Edge {
                source: file_local,
                target: s.key,
                rel: Relation::Contains,
                conf: Confidence::Extracted,
                line: s.line,
                context: None,
                flags: 0,
            });
            stats.structural_edges += 1;
        }
        for e in &f.edges {
            // A parameter's position rides on its `contains` edge, so a
            // callee read back from the store still binds arguments by
            // position.
            let position = f.symbols[e.to as usize].param_index.map(|p| p.to_string());
            b.add_edge(Edge {
                source: sym_locals[fi][e.from as usize],
                target: f.symbols[e.to as usize].key,
                rel: e.relation,
                conf: Confidence::Extracted,
                line: e.line,
                context: position.as_deref(),
                flags: 0,
            });
            stats.structural_edges += 1;
        }
        stats.parameters += f.symbols.iter().filter(|s| s.kind == SymbolKind::Parameter).count();
        stats.variables += f
            .symbols
            .iter()
            .filter(|s| matches!(s.kind, SymbolKind::Variable | SymbolKind::Constant | SymbolKind::Field))
            .count();
    }

    // --- imports ---
    // Recorded before calls, because an import is the evidence a cross-file
    // call needs.
    let mut imported: Vec<HashSet<usize>> = vec![Default::default(); corpus.len()];
    // Package qualifier -> the files that import resolved to, per file. Empty
    // targets mean the package is outside the corpus, which is just as useful:
    // it proves a call through that qualifier is not local.
    let mut qualifiers: Vec<HashMap<String, Vec<usize>>> = vec![Default::default(); corpus.len()];
    // Qualifier -> external package key, so `os.environ` can be read as a
    // value coming from the package `os`.
    let mut qual_packages: Vec<HashMap<String, SymbolKey>> = vec![Default::default(); corpus.len()];
    for &fi in &fresh {
        let f = &corpus[fi];
        let x = f.fresh.expect("fresh");
        for imp in &x.imports {
            let targets = resolve_import(&imp.module, f.path, &corpus_index, f.lang == "go");
            let mut any = false;
            // An explicit alias *is* the qualifier; otherwise it is derived
            // from the specifier.
            let qual = match imp.alias.as_deref() {
                Some(a) => a.to_lowercase(),
                None => import_qualifier(&imp.module),
            };
            for target in &targets {
                let target = *target;
                if target == fi {
                    continue;
                }
                any = true;
                imported[fi].insert(target);
                if !qual.is_empty() {
                    qualifiers[fi].entry(qual.clone()).or_default().push(target);
                }
                b.add_edge(Edge {
                    source: file_locals[fi],
                    target: corpus[target].file_key,
                    rel: Relation::ImportsFrom,
                    conf: Confidence::Extracted,
                    line: imp.line,
                    context: Some(&imp.module),
                    flags: 0,
                });
                stats.imports_resolved += 1;
            }
            if !any {
                // An unresolved import names something outside the corpus:
                // a standard-library module or a third-party package.
                // Materialise it as a `Package` symbol with a `depends_on`
                // edge rather than dropping it — that edge is the entire
                // basis for asking "does our code reach this vulnerable
                // dependency", and a count alone cannot answer it.
                if !qual.is_empty() {
                    qualifiers[fi].entry(qual.clone()).or_default();
                }
                let pkg = package_name_in(&imp.module, f.lang);
                if !pkg.is_empty() {
                    let key = package_key(&pkg);
                    if !qual.is_empty() {
                        qual_packages[fi].insert(qual.clone(), key);
                    }
                    let local = b.add_symbol(Symbol {
                        key,
                        file: file_ids[fi],
                        name: &pkg,
                        norm_name: &fold(&pkg),
                        kind: SymbolKind::Package,
                        file_type: FileType::Code,
                        line: 0,
                        flags: node_flags::EXTERNAL,
                        hash: 0,
                    });
                    if packages.insert(key) {
                        stats.packages += 1;
                    }
                    b.add_edge(Edge {
                        source: file_locals[fi],
                        target: b_key(&b, local),
                        rel: Relation::DependsOn,
                        conf: Confidence::Extracted,
                        line: imp.line,
                        context: Some(&imp.module),
                        flags: crate::EXTERNAL_EDGE,
                    });
                }
                stats.imports_external += 1;
            }
        }
    }

    // --- ownership, for receiver-based binding ---
    // member symbol -> its owning symbol, per file, from the `method`/`contains`
    // edges the walk emitted (or the store holds).
    let mut owner_of: Vec<HashMap<u32, u32>> = Vec::with_capacity(corpus.len());
    // (file, owning type) -> folded member name -> member index.
    let mut members_of: Vec<HashMap<u32, HashMap<String, Vec<u32>>>> =
        Vec::with_capacity(corpus.len());
    for f in corpus {
        let mut owners = HashMap::new();
        let mut members: HashMap<u32, HashMap<String, Vec<u32>>> = HashMap::new();
        for e in &f.edges {
            owners.insert(e.to, e.from);
            members
                .entry(e.from)
                .or_default()
                .entry(fold(f.symbols[e.to as usize].name))
                .or_default()
                .push(e.to);
        }
        owner_of.push(owners);
        members_of.push(members);
    }

    // Type-like symbols by folded name, for `Type.method()` receivers.
    let mut types_by_name: HashMap<String, Vec<(usize, u32)>> = HashMap::new();
    for (fi, f) in corpus.iter().enumerate() {
        for (si, s) in f.symbols.iter().enumerate() {
            if is_type_like(s.kind) {
                types_by_name.entry(fold(s.name)).or_default().push((fi, si as u32));
            }
        }
    }

    // --- calls ---
    // Every binding is recorded so the flow facts can name a callee's
    // parameters and result.
    let mut bound: Vec<Vec<Option<(usize, u32)>>> = vec![Vec::new(); corpus.len()];
    for &fi in &fresh {
        let f = &corpus[fi];
        let x = f.fresh.expect("fresh");
        bound[fi] = vec![None; x.calls.len()];
        for (ci, call) in x.calls.iter().enumerate() {
            let folded = fold(&call.callee);
            let source = call
                .caller
                .map_or(file_locals[fi], |c| sym_locals[fi][c as usize]);

            // Receiver-based binding runs first: it is the most precise rule we
            // have, and without it every `self.foo()` falls through to the
            // name-uniqueness rules, which under-bind badly in object-oriented
            // code.
            if let Some(receiver) = call.receiver.as_deref() {
                let owning_type = if is_self_receiver(receiver) {
                    // `self.foo()` inside a method: the receiver is the type
                    // that owns the enclosing method.
                    call.caller.and_then(|c| enclosing_type(f, &owner_of[fi], c)).map(|t| (fi, t))
                } else {
                    // `Type.foo()`: bind only when exactly one type in the
                    // corpus carries that name, same unambiguity rule as
                    // everywhere else.
                    match types_by_name.get(&fold(receiver)).map(Vec::as_slice) {
                        Some([one]) => Some(*one),
                        _ => None,
                    }
                };

                if let Some((tf, ts)) = owning_type
                    && let Some(by_member) = members_of[tf].get(&ts)
                    && let Some([member]) = by_member.get(&folded).map(Vec::as_slice)
                    && is_callable(corpus[tf].symbols[*member as usize].kind)
                {
                    b.add_edge(Edge {
                        source,
                        target: corpus[tf].symbols[*member as usize].key,
                        rel: Relation::Calls,
                        // `self.foo()` inside the class that defines `foo` is
                        // as certain as a local call; a named-type receiver is
                        // an inference, since nothing here proves the name was
                        // not shadowed.
                        conf: if is_self_receiver(receiver) && tf == fi {
                            Confidence::Extracted
                        } else {
                            Confidence::Inferred
                        },
                        line: call.line,
                        context: Some(receiver),
                        flags: 0,
                    });
                    stats.calls_receiver += 1;
                    bound[fi][ci] = Some((tf, *member));
                    continue;
                }
            }

            // A receiver that names an imported package is a *qualifier*, not
            // a value: `os.Open(x)` calls `os`'s `Open`, and binding it to a
            // local function of that name is simply wrong.
            //
            // Found on a real corpus: `uri.OpenWithClient` contains
            // `os.Open(u.Path)`, which bound to the `Open` defined three lines
            // above it. That fabricated a call cycle, and a taint query then
            // reported a path through the edge that does not exist.
            //
            // When the package is inside the corpus the qualifier is *better*
            // evidence than the name alone, so binding is restricted to that
            // package's files rather than abandoned.
            let qualified_to: Option<&[usize]> = call
                .receiver
                .as_deref()
                .filter(|r| !is_self_receiver(r))
                .and_then(|r| qualifiers[fi].get(&fold(r)))
                .map(Vec::as_slice);
            if let Some([]) = qualified_to {
                stats.calls_unresolved += 1;
                continue;
            }

            let Some(candidates) = by_name.get(&folded) else {
                stats.calls_unresolved += 1;
                continue;
            };

            // Counted in one pass rather than collected: at 1.5M call sites a
            // `Vec` per site is 1.5M allocations for a count and a first
            // element.
            // A member call whose receiver named neither a type nor an imported
            // package is a call on a *value* whose type we cannot infer. The
            // bare name is then weak evidence, but it is evidence: dropping it
            // outright cost 46% of all bound calls on a real Go corpus, because
            // most Go calls are method calls on locals.
            //
            // So it still binds, at reduced confidence — with one case
            // forbidden outright because it is provably wrong.
            //
            // Found on Gitea: `Group.Verify` iterates its configured auth
            // methods and calls `method.Verify(...)`. The bare name bound to
            // the one `Verify` in the same file — *itself* — so the auth chain
            // appeared as a function that calls only itself, and the eight
            // implementations it dispatches to were invisible. `x.F()` inside
            // `F` is not recursion; recursion is a bare `F()`.
            let weak_receiver = call
                .receiver
                .as_deref()
                .is_some_and(|r| !is_self_receiver(r) && qualified_to.is_none());
            let forbidden_self = if weak_receiver { call.caller } else { None };
            // The name table folds case for search; every language here
            // binds by exact case. Go's `Foo` and `foo` in one package are
            // two functions, and the exported one is what `pkg.Foo` means.
            // When an exact-case candidate exists, the others are not
            // candidates.
            let exact_case = candidates.iter().any(|(cf, cs)| corpus[*cf].symbols[*cs as usize].name == call.callee);
            let off_case = |cf: usize, cs: u32| exact_case && corpus[cf].symbols[cs as usize].name != call.callee;

            let mut local_hit = None;
            let mut local_n = 0usize;
            for (cf, cs) in candidates {
                if qualified_to.is_some() {
                    break;
                }
                if (forbidden_self == Some(*cs) && *cf == fi) || off_case(*cf, *cs) {
                    continue;
                }
                if *cf == fi && is_callable(corpus[*cf].symbols[*cs as usize].kind) {
                    local_n += 1;
                    if local_n == 1 {
                        local_hit = Some((*cf, *cs));
                    } else {
                        break;
                    }
                }
            }
            if local_n == 1 {
                let (cf, cs) = local_hit.expect("counted one");
                b.add_edge(Edge {
                    source,
                    target: corpus[cf].symbols[cs as usize].key,
                    rel: Relation::Calls,
                    // A bare name in the same file is certain; the same name
                    // reached through a receiver we could not type is a guess.
                    conf: if weak_receiver { Confidence::Inferred } else { Confidence::Extracted },
                    line: call.line,
                    context: call.receiver.as_deref(),
                    flags: 0,
                });
                stats.calls_local += 1;
                bound[fi][ci] = Some((cf, cs));
                continue;
            }

            // Cross-file: exactly one callable candidate, same language, and
            // the importing file actually imports its file. All three, or the
            // edge is not made.
            let mut cross_hit = None;
            let mut cross_n = 0usize;
            for (cf, cs) in candidates {
                if *cf != fi
                    && !off_case(*cf, *cs)
                    && is_callable(corpus[*cf].symbols[*cs as usize].kind)
                    && corpus[*cf].lang == f.lang
                    && match qualified_to {
                        Some(targets) => targets.contains(cf),
                        None => imported[fi].contains(cf),
                    }
                {
                    cross_n += 1;
                    if cross_n == 1 {
                        cross_hit = Some((*cf, *cs));
                    } else {
                        break;
                    }
                }
            }
            match cross_n {
                1 => {
                    let (cf, cs) = cross_hit.expect("counted one");
                    b.add_edge(Edge {
                        source,
                        target: corpus[cf].symbols[cs as usize].key,
                        rel: Relation::Calls,
                        // Inferred: the import makes it plausible, but nothing
                        // here proves this is the callee rather than a
                        // same-named symbol the file also has in scope.
                        conf: Confidence::Inferred,
                        line: call.line,
                        context: call.receiver.as_deref(),
                        flags: 0,
                    });
                    stats.calls_cross_file += 1;
                    bound[fi][ci] = Some((cf, cs));
                }
                0 => stats.calls_unresolved += 1,
                _ => stats.calls_ambiguous += 1,
            }
        }
    }

    // --- variables, references, flows, blocks ---
    //
    // A flow fact names its ends as parameters, non-local names, calls and
    // the function itself; each becomes a symbol key here. Sources must be
    // rows in this segment (an edge is stored with its source), so a source
    // that lives in a context file is written through an `EXTERNAL` proxy
    // row carrying the same key: the view forwards it to the real row and
    // merges its edges, and a full merge folds it away.
    {
        let mut resolver = FlowResolver {
            corpus,
            fresh: &fresh,
            b: &mut b,
            sym_locals: &sym_locals,
            file_locals: &file_locals,
            file_ids: &file_ids,
            owner_of: &owner_of,
            members_of: &members_of,
            imported: &imported,
            qual_packages: &qual_packages,
            qualifiers: &qualifiers,
            bound: &bound,
            stats: &mut stats,
            stubs: HashMap::new(),
            proxies: HashMap::new(),
            module_vars: Vec::new(),
            params_by_callable: Vec::new(),
            refs_seen: HashSet::new(),
            local_flows_seen: HashSet::new(),
            flows_seen: HashSet::new(),
        };
        resolver.prepare();
        resolver.run();
    }

    // --- declared supertypes ---
    //
    // Python and TypeScript state their heritage, so unlike Go there is
    // nothing to infer about *whether* the relation holds — only which symbol
    // the written name refers to.
    //
    // Python has no `implements` keyword: `class C(Base, P)` uses one list for
    // both. PEP 544 supplies the distinction — a class is a protocol exactly
    // when it lists `Protocol` itself, and inheriting *from* a protocol does
    // not make the subclass one — so a base that is protocol-like or abstract
    // yields `implements` and anything else yields `inherits`.
    let mut type_by_name: HashMap<&str, Vec<TypeRef>> = HashMap::new();
    let mut protocol_like: HashSet<TypeRef> = Default::default();
    for (fi, f) in corpus.iter().enumerate() {
        for (si, sym) in f.symbols.iter().enumerate() {
            if is_type_like(sym.kind) || sym.kind == SymbolKind::Interface {
                type_by_name.entry(sym.name).or_default().push((fi, si as u32));
            }
        }
        if let Some(x) = f.fresh {
            for (si, name, _) in &x.supertypes {
                if matches!(name.as_str(), "Protocol" | "ABC" | "ABCMeta") {
                    protocol_like.insert((fi, *si));
                }
            }
        }
    }
    // Whether a *context* class is protocol-like is not knowable here: its
    // `Protocol` base is outside the corpus, so no edge records it. A fresh
    // class newly inheriting an unchanged protocol therefore gets `inherits`
    // until the next full re-index. An existing such edge keeps the file in
    // the re-extracted neighbourhood, where the distinction is exact.

    for &fi in &fresh {
        let f = &corpus[fi];
        let x = f.fresh.expect("fresh");
        for (si, name, declared) in &x.supertypes {
            // Same file first, then a unique candidate the file actually
            // imports. The same unambiguity rule calls use, for the same
            // reason: a wrong `inherits` edge reshapes every architectural
            // query that runs afterwards.
            let candidates = type_by_name.get(name.as_str()).map(Vec::as_slice).unwrap_or(&[]);
            let mut hit = None;
            for c in candidates {
                if c.0 == fi && c.1 != *si {
                    hit = Some(*c);
                    break;
                }
            }
            if hit.is_none() {
                let mut n = 0usize;
                for c in candidates {
                    if c.0 != fi && corpus[c.0].lang == f.lang && imported[fi].contains(&c.0) {
                        n += 1;
                        if n > 1 {
                            hit = None;
                            break;
                        }
                        hit = Some(*c);
                    }
                }
            }
            let Some(target) = hit else {
                stats.supertypes_external += 1;
                continue;
            };
            let relation = if *declared == Relation::Inherits && protocol_like.contains(&target) {
                Relation::Implements
            } else {
                *declared
            };
            b.add_edge(Edge {
                source: sym_locals[fi][*si as usize],
                target: corpus[target.0].symbols[target.1 as usize].key,
                rel: relation,
                // Declared, not inferred — the source says so.
                conf: Confidence::Extracted,
                line: f.symbols[*si as usize].line,
                context: Some(name),
                flags: 0,
            });
            stats.supertypes_resolved += 1;
        }
    }

    // --- implements ---
    //
    // Go has no `implements` keyword: a type satisfies an interface by having
    // its methods. So the edge cannot be read off a declaration and has to be
    // computed by comparing method sets across the whole corpus.
    //
    // Compared on **name and arity**, not on parameter and result types. That
    // is deliberately stated rather than hidden: it is the difference between
    // this and a Go type checker, and it means the edge is evidence rather than
    // proof. Hence `Confidence::Inferred`.
    //
    // Only fresh files take part: arity is not stored, so a context type's
    // method set cannot be compared. Edges to context interfaces are carried
    // forward instead (see `carried`); a newly satisfied one waits for the
    // next full re-index.
    let mut method_sets: HashMap<TypeRef, Signature> = HashMap::new();
    for &fi in &fresh {
        let f = &corpus[fi];
        if !f.structural_interfaces {
            continue;
        }
        for e in &f.edges {
            if e.relation != Relation::Method {
                continue;
            }
            let m = &f.symbols[e.to as usize];
            method_sets
                .entry((fi, e.from))
                .or_default()
                .insert((fold(m.name), m.arity));
        }
    }

    // Expand embedded interfaces: `type ReadWriter interface { Reader; Writer }`
    // requires everything Reader and Writer do. Resolved by name and only when
    // the name is unambiguous corpus-wide, the same rule as everywhere else.
    // An interface whose embedding cannot be resolved is dropped rather than
    // compared against an incomplete requirement set — an under-specified
    // interface matches *more* types, so guessing here invents edges.
    let mut interfaces_by_name: HashMap<&str, Vec<TypeRef>> = HashMap::new();
    for (fi, f) in corpus.iter().enumerate() {
        for (si, sym) in f.symbols.iter().enumerate() {
            if sym.kind == SymbolKind::Interface {
                interfaces_by_name.entry(sym.name).or_default().push((fi, si as u32));
            }
        }
    }
    let mut incomparable: HashSet<TypeRef> = Default::default();
    for &fi in &fresh {
        let x = corpus[fi].fresh.expect("fresh");
        for (si, name) in &x.embeds {
            // A qualified name (`io.Reader`) is matched on its last segment;
            // the package part cannot be checked without type information.
            let bare = name.rsplit('.').next().unwrap_or(name);
            match interfaces_by_name.get(bare).map(Vec::as_slice) {
                Some([one]) if *one != (fi, *si) => {
                    let inherited = method_sets.get(one).cloned().unwrap_or_default();
                    if inherited.is_empty() {
                        incomparable.insert((fi, *si));
                    } else {
                        method_sets.entry((fi, *si)).or_default().extend(inherited);
                    }
                }
                _ => {
                    incomparable.insert((fi, *si));
                }
            }
        }
    }

    // Concrete types indexed by each signature they carry, so an interface is
    // matched against the candidates that could possibly satisfy it rather
    // than against every type in the corpus.
    let mut by_signature: HashMap<&MethodSig, Vec<TypeRef>> = HashMap::new();
    let mut interfaces: Vec<TypeRef> = Vec::new();
    for (&(fi, ti), sigs) in &method_sets {
        if corpus[fi].symbols[ti as usize].kind == SymbolKind::Interface {
            if incomparable.contains(&(fi, ti)) {
                continue;
            }
            interfaces.push((fi, ti));
            continue;
        }
        for sig in sigs {
            by_signature.entry(sig).or_default().push((fi, ti));
        }
    }
    // An interface with no methods at all never reaches `method_sets`, so it
    // has to be counted separately — and it must never produce edges, since
    // `any` is satisfied by everything.
    stats.interfaces_skipped = incomparable.len();
    for &fi in &fresh {
        let f = &corpus[fi];
        // An interface in a language that declares its implementations is not
        // "not comparable" — it is not a candidate for this pass at all.
        if !f.structural_interfaces {
            continue;
        }
        stats.interfaces_skipped += f
            .symbols
            .iter()
            .enumerate()
            .filter(|(i, sym)| {
                sym.kind == SymbolKind::Interface
                    && !incomparable.contains(&(fi, *i as u32))
                    && !method_sets.contains_key(&(fi, *i as u32))
            })
            .count();
    }
    // Deterministic output: the map iteration order above is not stable.
    interfaces.sort_unstable();

    for (ifi, iti) in interfaces {
        let want = &method_sets[&(ifi, iti)];
        // An interface with no comparable methods matches everything. `any` is
        // the obvious case; an interface built only from embedded interfaces
        // is the subtler one, since its methods live in the embedded names and
        // are not resolved here.
        if want.is_empty() {
            stats.interfaces_skipped += 1;
            continue;
        }
        // Start from the rarest requirement: `Verify(2 args)` narrows to a
        // handful, `Name(0 args)` narrows to almost nothing.
        let Some(rarest) = want
            .iter()
            .filter_map(|sig| by_signature.get(sig))
            .min_by_key(|v| v.len())
        else {
            continue;
        };
        let mut hits: Vec<TypeRef> = rarest
            .iter()
            .copied()
            .filter(|c| method_sets.get(c).is_some_and(|have| want.is_subset(have)))
            .collect();
        hits.sort_unstable();
        for (cfi, cti) in hits {
            b.add_edge(Edge {
                source: sym_locals[cfi][cti as usize],
                target: corpus[ifi].symbols[iti as usize].key,
                rel: Relation::Implements,
                conf: Confidence::Inferred,
                line: corpus[cfi].symbols[cti as usize].line,
                context: Some(corpus[ifi].symbols[iti as usize].name),
                flags: 0,
            });
            stats.implements += 1;
        }
    }

    // Carried-forward `implements` edges: the previous version of a fresh file
    // implemented an unchanged interface, and the type still exists.
    for (src, tgt, line, conf, ctx) in carried {
        let Some(source) = b.lookup(*src) else { continue };
        b.add_edge(Edge {
            source,
            target: *tgt,
            rel: Relation::Implements,
            conf: *conf,
            line: *line,
            context: Some(ctx),
            flags: 0,
        });
        stats.implements += 1;
    }

    let owned: Vec<String> = fresh.iter().map(|&fi| corpus[fi].path.to_string()).collect();
    Ok((b, stats, owned))
}

/// An external callee: `(qualifier, name)` in the shared, path-less keyspace
/// the packages use. `subprocess.Popen` and `os.popen` are distinct.
/// `pkg`, `pkg.Sub`, `obj` — an identifier chain, not an expression.
fn is_dotted_name(s: &str) -> bool {
    !s.is_empty()
        && s.split(['.', ':'])
            .all(|part| !part.is_empty() && part.chars().all(|c| c.is_alphanumeric() || c == '_' || c == '$' || c == '@'))
}

fn stub_key(qualifier: &str, name: &str) -> SymbolKey {
    let scope: Vec<&str> = if qualifier.is_empty() { vec![] } else { vec![qualifier] };
    SymbolKey::new(SymbolKeyParts {
        repo: "",
        path: "",
        kind: SymbolKind::Function,
        scope: &scope,
        name,
        disambiguator: 0,
    })
}

/// A file's proxy for a symbol it does not define: keyed by the file and
/// the symbol, so each file has one and no two files share it.
fn proxy_key(repo: &str, path: &str, of: SymbolKey, kind: SymbolKind) -> SymbolKey {
    let of = format!("{:032x}", of.0);
    SymbolKey::new(SymbolKeyParts {
        repo,
        path,
        kind,
        scope: &["\0proxy"],
        name: &of,
        disambiguator: 0,
    })
}

/// A local variable: owned by its callable, one row per name.
fn local_key(repo: &str, path: &str, callable: &codegraph_extract::RawSymbol, name: &str) -> SymbolKey {
    let mut scope: Vec<&str> = callable.scope.iter().map(String::as_str).collect();
    scope.push(&callable.name);
    SymbolKey::new(SymbolKeyParts { repo, path, kind: SymbolKind::Local, scope: &scope, name, disambiguator: 0 })
}

/// A CFG block: owned by its callable, numbered.
fn block_key(repo: &str, path: &str, callable: &codegraph_extract::RawSymbol, index: u32) -> SymbolKey {
    let mut scope: Vec<&str> = callable.scope.iter().map(String::as_str).collect();
    scope.push(&callable.name);
    SymbolKey::new(SymbolKeyParts {
        repo,
        path,
        kind: SymbolKind::Block,
        scope: &scope,
        name: &format!("b{index}"),
        disambiguator: 0,
    })
}

/// Turns flow facts, references and blocks into edges.
struct FlowResolver<'r, 'a> {
    corpus: &'r [CorpusFile<'a>],
    fresh: &'r [usize],
    b: &'r mut SegmentBuilder,
    sym_locals: &'r [Vec<LocalId>],
    file_locals: &'r [LocalId],
    file_ids: &'r [codegraph_core::FileId],
    owner_of: &'r [HashMap<u32, u32>],
    members_of: &'r [HashMap<u32, HashMap<String, Vec<u32>>>],
    imported: &'r [HashSet<usize>],
    qual_packages: &'r [HashMap<String, SymbolKey>],
    /// Import qualifier -> the corpus files it names (`lib` in `lib.X`).
    qualifiers: &'r [HashMap<String, Vec<usize>>],
    bound: &'r [Vec<Option<(usize, u32)>>],
    stats: &'r mut BuildStats,
    stubs: HashMap<SymbolKey, LocalId>,
    /// `(file, symbol key)` -> that file's proxy row for the symbol.
    proxies: HashMap<(usize, SymbolKey), LocalId>,
    /// Per file: folded name -> module-level variable/constant.
    module_vars: Vec<HashMap<String, u32>>,
    /// Per file: callable -> its parameters as `(position, symbol)`.
    params_by_callable: Vec<HashMap<u32, Vec<(u32, u32)>>>,
    refs_seen: HashSet<(LocalId, SymbolKey)>,
    local_flows_seen: HashSet<(LocalId, SymbolKey, Option<String>)>,
    flows_seen: HashSet<(LocalId, SymbolKey, Option<String>)>,
}

/// One resolved end of a flow.
#[derive(Clone, Copy)]
enum End {
    /// A symbol of the corpus: `(file, symbol)`.
    Sym(usize, u32),
    /// A key with no corpus row: a package, a stub.
    Key(SymbolKey),
}

impl<'r, 'a> FlowResolver<'r, 'a> {
    /// The per-file lookup tables. Built once: a lookup per reference over a
    /// linear scan of the file's symbols made resolution quadratic.
    fn prepare(&mut self) {
        let is_var = |k: SymbolKind| matches!(k, SymbolKind::Variable | SymbolKind::Constant);
        for file in self.corpus {
            let mut vars: HashMap<String, u32> = HashMap::new();
            for (si, s) in file.symbols.iter().enumerate() {
                if is_var(s.kind) {
                    vars.entry(fold(s.name)).or_insert(si as u32);
                }
            }
            let mut params: HashMap<u32, Vec<(u32, u32)>> = HashMap::new();
            for e in &file.edges {
                if e.relation != Relation::Contains {
                    continue;
                }
                let s = &file.symbols[e.to as usize];
                if s.kind == SymbolKind::Parameter {
                    params.entry(e.from).or_default().push((s.param_index.unwrap_or(u32::MAX), e.to));
                }
            }
            for v in params.values_mut() {
                v.sort_unstable();
            }
            self.module_vars.push(vars);
            self.params_by_callable.push(params);
        }
    }

    fn run(&mut self) {
        for &fi in self.fresh {
            let x = self.corpus[fi].fresh.expect("fresh");
            // Facts.
            for fl in &x.flows {
                // A summarised call's stub does not stand for "every input
                // reaches the result": the summary already said what does,
                // as facts from those inputs. Its result is a value only when
                // the summary brings in external data — and then an untagged
                // one, so no argument's path can pass through it.
                let summarised_source = match &fl.source {
                    FlowNode::CallResult(k) if matches!(self.bound[fi].get(*k as usize), Some(None)) => {
                        let call = &x.calls[*k as usize];
                        if call.summarised && !call.external {
                            self.stats.flows_summarised += 1;
                            continue;
                        }
                        call.summarised
                    }
                    _ => false,
                };
                let Some(src) = self.end(fi, fl.function, &fl.source, true) else {
                    self.stats.flows_unresolved += 1;
                    continue;
                };
                let Some(sink) = self.end(fi, fl.function, &fl.sink, false) else {
                    self.stats.flows_unresolved += 1;
                    continue;
                };
                let Some(source) = self.source_row(fi, src) else { continue };
                let target = self.key_of(sink);
                // An edge into or out of an external stub is tagged with its
                // call site, so a search can enter a stub on one call and
                // leave it on the same one — `y = decode(x)` connects, and
                // `decode` does not become a conduit between unrelated
                // callers. Both ends of one call carry the same tag.
                let site = self.call_site(fi, &fl.source, &fl.sink, summarised_source);
                if self.flows_seen.insert((source, target, site.clone())) {
                    let conf = self.confidence(fi, &fl.source, &fl.sink);
                    self.b.add_edge(Edge {
                        source,
                        target,
                        rel: Relation::FlowsTo,
                        conf,
                        line: fl.line,
                        context: site.as_deref(),
                        flags: 0,
                    });
                    self.stats.flows += 1;
                }
            }
            // References: callable -> variable it reads or writes.
            for r in &x.refs {
                let source = r.function.map_or(self.file_locals[fi], |c| self.sym_locals[fi][c as usize]);
                let Some(end) = self.non_local(fi, r.function, &r.name, r.self_field) else { continue };
                let target = self.key_of(end);
                if self.refs_seen.insert((source, target)) {
                    let line = r.function.map_or(1, |c| self.corpus[fi].symbols[c as usize].line);
                    self.b.add_edge(Edge {
                        source,
                        target,
                        rel: Relation::References,
                        conf: Confidence::Extracted,
                        line,
                        context: None,
                        flags: 0,
                    });
                    self.stats.references += 1;
                }
            }
            // Blocks: the stored CFG.
            let path = self.corpus[fi].path;
            let repo_hint = ""; // keys of blocks reuse the file's repo through `block_key`'s caller
            let _ = repo_hint;
            let mut block_locals: HashMap<(u32, u32), LocalId> = HashMap::new();
            for bl in &x.blocks {
                let callable = &x.symbols[bl.function as usize];
                let key = block_key(self.repo_of(fi), path, callable, bl.index);
                let name = format!("b{}", bl.index);
                let local = self.b.add_symbol(Symbol {
                    key,
                    file: self.file_ids[fi],
                    name: &name,
                    norm_name: &name,
                    kind: SymbolKind::Block,
                    file_type: FileType::Code,
                    line: bl.line,
                    flags: 0,
                    hash: 0,
                });
                block_locals.insert((bl.function, bl.index), local);
                self.b.add_edge(Edge {
                    source: self.sym_locals[fi][bl.function as usize],
                    target: key,
                    rel: Relation::Contains,
                    conf: Confidence::Extracted,
                    line: bl.line,
                    context: Some(&bl.index.to_string()),
                    flags: 0,
                });
                self.stats.blocks += 1;
            }
            for bl in &x.blocks {
                let source = block_locals[&(bl.function, bl.index)];
                let callable = &x.symbols[bl.function as usize];
                for (succ, label) in &bl.succ {
                    self.b.add_edge(Edge {
                        source,
                        target: block_key(self.repo_of(fi), path, callable, *succ),
                        rel: Relation::Succeeds,
                        conf: Confidence::Extracted,
                        line: bl.line,
                        context: (!label.is_empty()).then_some(label.as_str()),
                        flags: 0,
                    });
                }
                for (rel, names) in [(Relation::Defines, &bl.defines), (Relation::Uses, &bl.uses)] {
                    for (name, self_field) in names {
                        let Some(end) = self.non_local(fi, Some(bl.function), name, *self_field) else { continue };
                        self.b.add_edge(Edge {
                            source,
                            target: self.key_of(end),
                            rel,
                            conf: Confidence::Extracted,
                            line: bl.line,
                            context: None,
                            flags: 0,
                        });
                    }
                }
                for (rel, names) in [(Relation::Defines, &bl.local_defines), (Relation::Uses, &bl.local_uses)] {
                    for name in names {
                        self.b.add_edge(Edge {
                            source,
                            target: local_key(self.repo_of(fi), path, callable, name),
                            rel,
                            conf: Confidence::Extracted,
                            line: bl.line,
                            context: None,
                            flags: 0,
                        });
                    }
                }
            }
            // Locals: one row per (callable, name), owned by the callable.
            for l in &x.locals {
                let callable = &x.symbols[l.function as usize];
                let key = local_key(self.repo_of(fi), path, callable, &l.name);
                let norm = fold(&l.name);
                self.b.add_symbol(Symbol {
                    key,
                    file: self.file_ids[fi],
                    name: &l.name,
                    norm_name: &norm,
                    kind: SymbolKind::Local,
                    file_type: FileType::Code,
                    line: l.line,
                    flags: 0,
                    hash: 0,
                });
                self.b.add_edge(Edge {
                    source: self.sym_locals[fi][l.function as usize],
                    target: key,
                    rel: Relation::Contains,
                    conf: Confidence::Extracted,
                    line: l.line,
                    context: Some("local"),
                    flags: 0,
                });
                self.stats.locals += 1;
            }
            // Value flow through locals, for presentation: what each local
            // is assigned, where each is read. The same ends as the facts,
            // with the same rule for a summarised call's result.
            for fl in &x.local_flows {
                if let FlowNode::CallResult(k) = &fl.source
                    && matches!(self.bound[fi].get(*k as usize), Some(None))
                {
                    let call = &x.calls[*k as usize];
                    if call.summarised && !call.external {
                        continue;
                    }
                }
                let Some(src) = self.end(fi, fl.function, &fl.source, true) else { continue };
                let Some(sink) = self.end(fi, fl.function, &fl.sink, false) else { continue };
                let Some(source) = self.source_row(fi, src) else { continue };
                let target = self.key_of(sink);
                if self.local_flows_seen.insert((source, target, fl.context.clone())) {
                    self.b.add_edge(Edge {
                        source,
                        target,
                        rel: Relation::LocalFlow,
                        conf: self.confidence(fi, &fl.source, &fl.sink),
                        line: fl.line,
                        context: fl.context.as_deref(),
                        flags: 0,
                    });
                    self.stats.local_flows += 1;
                }
            }
        }
    }

    fn repo_of(&self, fi: usize) -> &'a str {
        self.corpus[fi].repo
    }

    /// The call-site tag of a fact with an unresolved call at either end:
    /// `"<leave>><enter>"`, where `leave` is the call whose stub the value
    /// comes out of and `enter` the call whose stub it goes into. Either half
    /// may be empty. A search leaving a stub matches `leave` against the site
    /// it entered on, and takes `enter` as the site for the next stub.
    fn call_site(&self, fi: usize, source: &FlowNode, sink: &FlowNode, external_source: bool) -> Option<String> {
        // Every call, bound or not: the tag is what makes a value that
        // enters a callee at one call site leave it at the same one — the
        // search matches `enter` and `leave` like parentheses, so a
        // callee's one `param -> return` edge serves every caller without
        // joining them.
        let site = |n: &FlowNode| match n {
            FlowNode::CallResult(k) | FlowNode::Arg(k, _) => Some(*k),
            _ => None,
        };
        let path = self.corpus[fi].path;
        // External data leaves a stub on a site nothing enters on: the
        // value did not come in through any argument.
        let leave = if external_source { Some("!".to_string()) } else { site(source).map(|k| format!("{path}#{k}")) };
        let enter = site(sink).map(|k| format!("{path}#{k}"));
        if leave.is_none() && enter.is_none() {
            return None;
        }
        Some(format!("{}>{}", leave.unwrap_or_default(), enter.unwrap_or_default()))
    }

    /// A flow's confidence: certain when both ends are this file's own
    /// symbols, inferred when it goes through a bound call or a stub.
    fn confidence(&self, fi: usize, source: &FlowNode, sink: &FlowNode) -> Confidence {
        let via_call = |n: &FlowNode| match n {
            FlowNode::CallResult(k) | FlowNode::Arg(k, _) => {
                !matches!(self.bound[fi].get(*k as usize), Some(Some((cf, _))) if *cf == fi)
            }
            _ => false,
        };
        if via_call(source) || via_call(sink) { Confidence::Inferred } else { Confidence::Extracted }
    }

    /// The row file `fi` writes a flow *from* `end` on.
    ///
    /// A symbol of `fi`'s own is its row. Anything else — a symbol another
    /// file defines, a stub, a package — gets a proxy row owned by `fi`,
    /// even when the real row is in this very segment: rows and their
    /// edges belong to a file, and a flow leaving a foreign symbol must
    /// live and die with the file that observed it, not with the file that
    /// defines the symbol. The proxy's `stands_for` edge names the symbol;
    /// the view reads the proxy's edges as the symbol's.
    fn source_row(&mut self, fi: usize, end: End) -> Option<LocalId> {
        let (key, name, kind) = match end {
            End::Sym(cf, cs) if cf == fi => {
                return self.sym_locals[cf].get(cs as usize).copied().filter(|l| !l.is_none());
            }
            End::Sym(cf, cs) => {
                let sym = &self.corpus[cf].symbols[cs as usize];
                (sym.key, sym.name.to_string(), sym.kind)
            }
            End::Key(k) => {
                let l = self.stubs.get(&k).copied().or_else(|| self.b.lookup(k))?;
                let name = self.b.name_of(l)?.to_string();
                (k, name, self.b.kind_of(l)?)
            }
        };
        if let Some(&l) = self.proxies.get(&(fi, key)) {
            return Some(l);
        }
        let file = &self.corpus[fi];
        let pkey = proxy_key(file.repo, file.path, key, kind);
        let norm = fold(&name);
        let l = self.b.add_symbol(Symbol {
            key: pkey,
            file: self.file_ids[fi],
            name: &name,
            norm_name: &norm,
            kind,
            file_type: FileType::Code,
            line: 0,
            flags: node_flags::PROXY,
            hash: 0,
        });
        self.b.add_edge(Edge {
            source: l,
            target: key,
            rel: Relation::StandsFor,
            conf: Confidence::Extracted,
            line: 0,
            context: None,
            flags: 0,
        });
        self.proxies.insert((fi, key), l);
        self.stats.proxies += 1;
        Some(l)
    }

    fn key_of(&self, end: End) -> SymbolKey {
        match end {
            End::Sym(cf, cs) => self.corpus[cf].symbols[cs as usize].key,
            End::Key(k) => k,
        }
    }

    /// Resolve one end of a fact. `as_source` decides how an unresolved call
    /// is treated: a call's *result* is always something (a stub), while an
    /// argument of an unresolved call flows into the stub too.
    fn end(&mut self, fi: usize, function: Option<u32>, node: &FlowNode, _as_source: bool) -> Option<End> {
        match node {
            FlowNode::Param(i) => Some(End::Sym(fi, *i)),
            FlowNode::Return => Some(match function {
                Some(c) => End::Sym(fi, c),
                None => End::Key(self.corpus[fi].file_key),
            }),
            // A package is not a value: `os.Stdout.Write(x)` writes into
            // nothing this graph carries, and `p := os.ErrNotExist` reads
            // nothing it carries either. A package node in the flow graph
            // would join every writer of any `os.*` to every reader.
            FlowNode::NonLocal(name, self_field) => self
                .non_local(fi, function, name, *self_field)
                .filter(|e| !matches!(e, End::Key(k) if self.qual_packages[fi].values().any(|p| p == k))),
            FlowNode::CallResult(k) => match self.bound[fi].get(*k as usize).copied().flatten() {
                Some((cf, cs)) => Some(End::Sym(cf, cs)),
                None => Some(End::Key(self.stub_for(fi, *k))),
            },
            FlowNode::Arg(k, pos) => match self.bound[fi].get(*k as usize).copied().flatten() {
                Some((cf, cs)) => self.param_of(cf, cs, pos).map(|ps| End::Sym(cf, ps)),
                None => Some(End::Key(self.stub_for(fi, *k))),
            },
            // A local is its function's row; see `local_flows` in `run`.
            FlowNode::Local(name) => function.map(|c| End::Key(local_key(self.corpus[fi].repo, self.corpus[fi].path, &self.corpus[fi].fresh.expect("fresh").symbols[c as usize], name))),
        }
    }

    /// The parameter of callable `(cf, cs)` at `pos`. The receiver position
    /// maps to a leading `self`-like parameter, or nothing.
    fn param_of(&self, cf: usize, cs: u32, pos: &ArgPos) -> Option<u32> {
        let file = &self.corpus[cf];
        let empty = Vec::new();
        let params: &Vec<(u32, u32)> = self.params_by_callable[cf].get(&cs).unwrap_or(&empty);
        let first_is_receiver = params
            .iter()
            .find(|(p, _)| *p == 0)
            .is_some_and(|(_, si)| is_self_receiver(file.symbols[*si as usize].name) || (file.lang == "go" && file.symbols[cs as usize].kind == SymbolKind::Method));
        match pos {
            ArgPos::Index(i) if *i == u32::MAX => {
                first_is_receiver.then(|| params.iter().find(|(p, _)| *p == 0).map(|(_, si)| *si)).flatten()
            }
            ArgPos::Index(i) => {
                let want = if first_is_receiver { *i + 1 } else { *i };
                params.iter().find(|(p, _)| *p == want).map(|(_, si)| *si)
            }
            ArgPos::Name(n) => {
                let folded = fold(n);
                params.iter().find(|(_, si)| fold(file.symbols[*si as usize].name) == folded).map(|(_, si)| *si)
            }
        }
    }

    /// An external stub for unresolved call `k`, owned by its package when
    /// the qualifier names one.
    fn stub_for(&mut self, fi: usize, k: u32) -> SymbolKey {
        let call = &self.corpus[fi].fresh.expect("fresh").calls[k as usize];
        // The qualifier names a package, type or variable — a dotted name.
        // Any other receiver (`expect(x).toEqual(y)`, `a[i].f()`) is an
        // expression, and keying stubs by expression text would mint one
        // stub per call site.
        let qualifier = call
            .receiver
            .as_deref()
            .filter(|r| !is_self_receiver(r) && is_dotted_name(r))
            .unwrap_or("");
        let key = stub_key(qualifier, &call.callee);
        if self.stubs.contains_key(&key) {
            return key;
        }
        let norm = fold(&call.callee);
        let local = self.b.add_symbol(Symbol {
            key,
            file: self.file_ids[fi],
            name: &call.callee,
            norm_name: &norm,
            kind: SymbolKind::Function,
            file_type: FileType::Code,
            line: 0,
            flags: node_flags::EXTERNAL,
            hash: 0,
        });
        self.stubs.insert(key, local);
        self.stats.external_stubs += 1;
        // `subprocess.Popen` belongs to the package `subprocess`.
        if let Some(pkg) = self.qual_packages[fi].get(&fold(qualifier)).copied()
            && let Some(pkg_local) = self.b.lookup(pkg)
        {
            self.b.add_edge(Edge {
                source: pkg_local,
                target: key,
                rel: Relation::Contains,
                conf: Confidence::Extracted,
                line: 0,
                context: None,
                flags: 0,
            });
        }
        key
    }

    /// A non-local name read or written in `function`: a field of the
    /// enclosing type, a module-level symbol of this file, a package, or a
    /// unique imported module-level symbol.
    fn non_local(&self, fi: usize, function: Option<u32>, name: &str, self_field: bool) -> Option<End> {
        let file = &self.corpus[fi];
        // `lib.MAX`: a member of an import qualifier is that module's
        // variable; of anything else, nothing this resolves.
        if !self_field
            && let Some((qual, member)) = name.rsplit_once('.')
        {
            let files = self.qualifiers[fi].get(&fold(qual))?;
            let folded = fold(member);
            let mut hit = None;
            for &cf in files {
                if let Some(&si) = self.module_vars[cf].get(&folded) {
                    if hit.is_some() {
                        return None;
                    }
                    hit = Some(End::Sym(cf, si));
                }
            }
            return hit;
        }
        let folded = fold(name);
        if self_field {
            let owner = function.and_then(|c| enclosing_type(file, &self.owner_of[fi], c))?;
            let members = self.members_of[fi].get(&owner)?;
            let hits = members.get(&folded)?;
            let field = hits
                .iter()
                .find(|si| file.symbols[**si as usize].kind == SymbolKind::Field)
                .or_else(|| hits.first())?;
            return Some(End::Sym(fi, *field));
        }
        // Same file, module level.
        if let Some(&si) = self.module_vars[fi].get(&folded) {
            return Some(End::Sym(fi, si));
        }
        // An imported package used as a value.
        if let Some(k) = self.qual_packages[fi].get(&folded) {
            return Some(End::Key(*k));
        }
        // A unique module-level candidate in a file this one imports.
        let mut hit = None;
        for &cf in &self.imported[fi] {
            if self.corpus[cf].lang != file.lang {
                continue;
            }
            if let Some(&si) = self.module_vars[cf].get(&folded) {
                if hit.is_some() {
                    return None;
                }
                hit = Some(End::Sym(cf, si));
            }
        }
        hit
    }
}

/// The key of an already-added symbol.
///
/// Edges are addressed by key rather than by `LocalId` so the builder can
/// resolve them itself; this looks the key back up from the id the builder
/// returned.
fn b_key(b: &SegmentBuilder, local: LocalId) -> SymbolKey {
    b.key_of(local).unwrap_or(SymbolKey::NONE)
}

#[cfg(test)]
mod tests {

    /// Regression: a Go module path is `host/org/repo`. Splitting on `.` made
    /// every `code.gitea.io/...` import a package called `code`, and keeping
    /// only the first path segment would make them all `code.gitea.io`.
    #[test]
    fn a_host_qualified_specifier_keeps_its_module_path() {
        assert_eq!(package_name("github.com/go-chi/chi/v5/middleware"), "github.com/go-chi/chi");
        assert_eq!(package_name("github.com/stretchr/testify/assert"), "github.com/stretchr/testify");
        assert_eq!(package_name("golang.org/x/net/context"), "golang.org/x/net");
        // Shorter than three segments: keep what is there.
        assert_eq!(package_name("gopkg.in/yaml.v3"), "gopkg.in/yaml.v3");
    }

    #[test]
    fn a_dotted_specifier_still_splits_on_the_dot() {
        assert_eq!(package_name("requests.adapters"), "requests");
        assert_eq!(package_name("os"), "os");
    }

    #[test]
    fn a_plain_path_specifier_keeps_its_first_segment() {
        assert_eq!(package_name("net/http"), "net");
        assert_eq!(package_name_in("net/http", "go"), "net/http", "a Go stdlib path is the package");
        assert_eq!(package_name_in("encoding/json", "go"), "encoding/json");
        assert_eq!(package_name_in("lodash/fp", "js"), "lodash");
        assert_eq!(package_name("lodash/fp"), "lodash");
        assert_eq!(package_name("@scope/pkg/sub"), "@scope/pkg");
    }

    #[test]
    fn a_relative_specifier_is_not_a_package() {
        assert_eq!(package_name("./local"), "");
        assert_eq!(package_name("/abs/path"), "");
    }

    use super::*;

    /// Resolve `spec` against a synthetic corpus.
    fn resolve(spec: &str, from: &str, items: &[&str]) -> Option<usize> {
        let all: Vec<String> = items.iter().map(|s| (*s).to_string()).collect();
        let idx: HashMap<String, usize> =
            all.iter().cloned().enumerate().map(|(i, p)| (p, i)).collect();
        let base = basename_index(&all);
        let dirs = directory_index(&all);
        let c = Corpus { paths: &idx, by_basename: &base, by_dir: &dirs, all_paths: &all, roots: &[] };
        resolve_import(spec, from, &c, false).first().copied()
    }

    /// Resolve with an indexed-root name in play.
    fn resolve_in_root(spec: &str, from: &str, items: &[&str], root: &str) -> Option<usize> {
        let roots = [root.to_string()];
        let all: Vec<String> = items.iter().map(|s| (*s).to_string()).collect();
        let idx: HashMap<String, usize> =
            all.iter().cloned().enumerate().map(|(i, p)| (p, i)).collect();
        let base = basename_index(&all);
        let dirs = directory_index(&all);
        let c = Corpus { paths: &idx, by_basename: &base, by_dir: &dirs, all_paths: &all, roots: &roots };
        resolve_import(spec, from, &c, false).first().copied()
    }

    fn resolve_dir(spec: &str, items: &[&str], root: &str, dir_packages: bool) -> Vec<usize> {
        let all: Vec<String> = items.iter().map(|s| (*s).to_string()).collect();
        let idx: HashMap<String, usize> =
            all.iter().cloned().enumerate().map(|(i, p)| (p, i)).collect();
        let base = basename_index(&all);
        let dirs = directory_index(&all);
        let roots = [root.to_string()];
        let c = Corpus { paths: &idx, by_basename: &base, by_dir: &dirs, all_paths: &all, roots: &roots };
        resolve_import(spec, "main.go", &c, dir_packages)
    }

    /// A Go import names a package *directory*, so it resolves to every file in
    /// it. Binding it to one file — or to none, which is what happened before —
    /// loses the dependency entirely.
    #[test]
    fn a_go_import_resolves_to_every_file_in_the_package() {
        let files = ["main.go", "modules/setting/setting.go", "modules/setting/git.go"];
        let mut hit = resolve_dir("gitea.dev/modules/setting", &files, "gitea.dev", true);
        hit.sort_unstable();
        assert_eq!(hit, vec![1, 2], "a package directory must resolve to its members");
    }

    /// And the same shape must *not* expand where the language does not work
    /// that way: `import pkg` in Python does not import `pkg.sub`.
    #[test]
    fn a_directory_does_not_expand_when_the_language_does_not_package_by_directory() {
        let files = ["main.py", "pkg/a.py", "pkg/b.py"];
        assert!(
            resolve_dir("pkg", &files, "", false).is_empty(),
            "expanded a directory for a language whose imports are per-module"
        );
    }

    /// An explicit file still wins over the directory of the same name.
    #[test]
    fn a_file_beats_a_directory_of_the_same_name() {
        let files = ["main.go", "util.go", "util/helper.go"];
        assert_eq!(resolve_dir("util", &files, "", true), vec![1]);
    }

    #[test]
    fn resolves_a_relative_specifier() {
        assert_eq!(resolve("./b", "src/a.ts", &["src/a.ts", "src/b.ts"]), Some(1));
    }

    #[test]
    fn resolves_a_dotted_python_module() {
        assert_eq!(resolve("pkg.mod", "main.py", &["pkg/mod.py", "main.py"]), Some(0));
    }

    #[test]
    fn resolves_a_package_index() {
        assert_eq!(resolve("pkg", "main.py", &["pkg/__init__.py", "main.py"]), Some(0));
    }

    #[test]
    fn resolves_one_level_up() {
        assert_eq!(resolve("../b", "src/a/x.ts", &["src/a/x.ts", "src/b.ts"]), Some(1));
    }

    /// The unambiguity rule, applied to imports. Two files could match, so
    /// neither is chosen.
    #[test]
    fn an_ambiguous_specifier_resolves_to_nothing() {
        assert_eq!(
            resolve("util", "main.py", &["one/util.py", "two/util.py", "main.py"]),
            None
        );
    }

    #[test]
    fn an_unknown_specifier_resolves_to_nothing() {
        assert_eq!(resolve("numpy", "a.py", &["a.py"]), None);
        assert_eq!(resolve("", "a.py", &["a.py"]), None);
    }

    /// The basename index is a speed optimisation and must not widen what
    /// matches. Bucketing by stem means the directory part of a specifier is
    /// only checked by `tail_matches` — so this is where that check is proved.
    #[test]
    fn the_basename_index_does_not_widen_matching() {
        // Right stem, wrong directory: must not resolve.
        assert_eq!(resolve("nowhere/util", "main.py", &["one/util.py", "main.py"]), None);
        // Right stem, right directory: resolves.
        assert_eq!(resolve("one/util", "main.py", &["one/util.py", "main.py"]), Some(0));
        // A stem that is absent entirely still misses.
        assert_eq!(resolve("absent", "main.py", &["one/util.py", "main.py"]), None);
    }

    #[test]
    fn tail_matching_respects_path_boundaries() {
        assert!(tail_matches("a/pkg/mod.py", "pkg/mod"));
        assert!(tail_matches("pkg/mod.py", "pkg/mod"));
        assert!(tail_matches("mod.py", "mod"));
        assert!(tail_matches("a/mod", "mod"));
        // Wrong directory.
        assert!(!tail_matches("a/other/mod.py", "pkg/mod"));
        // Not a path boundary: `xpkg` is not `pkg`.
        assert!(!tail_matches("a/xpkg/mod.py", "pkg/mod"));
        // A dot in a directory name is not an extension.
        assert!(tail_matches("a.b/c", "a.b/c"));
    }

    /// Indexing a package at its own directory: `pkg.mod` must find `mod.py`,
    /// because the leading `pkg` is the root itself.
    #[test]
    fn an_intra_package_absolute_import_resolves_at_the_package_root() {
        assert_eq!(
            resolve_in_root("pkg.sub.mod", "other.py", &["sub/mod.py", "other.py"], "pkg"),
            Some(0)
        );
        // Without the root name it cannot, which is the bug this fixes.
        assert_eq!(resolve("pkg.sub.mod", "other.py", &["sub/mod.py", "other.py"]), None);
    }

    /// The strip must be anchored to the root's name, or `os.path` would be
    /// reduced to a local `path.py` and fabricate a dependency on it.
    #[test]
    fn stripping_only_applies_to_the_actual_root_name() {
        assert_eq!(
            resolve_in_root("os.path", "main.py", &["path.py", "main.py"], "pkg"),
            None,
            "a stdlib module was reduced to a local file"
        );
        // And a spec that merely starts with the same letters is not stripped.
        assert_eq!(
            resolve_in_root("pkgtools.mod", "main.py", &["mod.py", "main.py"], "pkg"),
            None
        );
    }

    #[test]
    fn basename_index_groups_by_stem() {
        let paths = vec!["a/util.py".to_string(), "b/util.py".to_string(), "c/other.rs".to_string()];
        let idx = basename_index(&paths);
        assert_eq!(idx.get("util").map(Vec::len), Some(2));
        assert_eq!(idx.get("other").map(Vec::len), Some(1));
        assert!(!idx.contains_key("missing"));
    }

    #[test]
    fn only_functions_and_methods_are_callable() {
        assert!(is_callable(SymbolKind::Function));
        assert!(is_callable(SymbolKind::Method));
        assert!(!is_callable(SymbolKind::Class));
        assert!(!is_callable(SymbolKind::TypeAlias));
        assert!(!is_callable(SymbolKind::Field));
    }

    #[test]
    fn folding_strips_call_parens_and_case() {
        assert_eq!(fold("Foo()"), "foo");
        assert_eq!(fold("  Bar  "), "bar");
    }
}
