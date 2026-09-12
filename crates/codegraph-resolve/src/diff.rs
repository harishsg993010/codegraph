//! `diff`: what a change to the source tree does to the graph, before it is
//! indexed.
//!
//! The store holds the tree as it was last indexed. `diff_tree` brings a
//! *scratch copy* of the store up to date with the tree — the same
//! incremental update `index` would run, into a temporary directory the
//! real store never sees — and compares the two: every symbol in a file
//! that changed, was deleted, or was re-extracted as a neighbour, keyed by
//! its [`SymbolKey`], with its definition hash, its parameter list and its
//! outgoing edges. A symbol that is gone, whose signature moved, whose
//! kind changed, whose definition text changed, or whose bindings changed
//! is a [`Change`].
//!
//! For each change the *old* graph then says who depended on it — the
//! callers, referencers, importers, subtypes that will break outright when
//! a symbol is removed or its signature moves — and, transitively, what is
//! affected: reverse dependencies plus the sinks the symbol's value flows
//! to, as a trace tree with the relation on every step. The old graph is
//! the right one to ask: the dependents that exist *now* are the ones the
//! change lands on.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::Path;

use codegraph_core::{LocalId, Relation, RelationMask, SymbolKey, SymbolKind};
use codegraph_store::{CompactPolicy, Result, Store, StoreError, View, node_flags};

use crate::pipeline::update_tree;

fn io_err(context: &str, e: std::io::Error) -> StoreError {
    StoreError::Io { context: context.to_string(), source: e }
}

/// The relations along which a change reaches its dependents, walked
/// against the edge: from a symbol to what calls, references, imports,
/// extends or implements it.
pub const DEPENDS: RelationMask = RelationMask::of(&[
    Relation::Calls,
    Relation::IndirectCall,
    Relation::References,
    Relation::Imports,
    Relation::ImportsFrom,
    Relation::DynamicImport,
    Relation::ReExports,
    Relation::Requires,
    Relation::Inherits,
    Relation::Extends,
    Relation::Implements,
    Relation::MixesIn,
    Relation::Embeds,
]);

/// The relations a signature change breaks along: a call site.
const CALLS: RelationMask = RelationMask::of(&[Relation::Calls, Relation::IndirectCall]);

#[derive(Debug, Clone)]
pub struct DiffOptions {
    pub repo: String,
    /// How many hops of impact to trace.
    pub depth: u32,
    /// Most impact hits recorded per change.
    pub max_hits: usize,
    /// A node with more dependents than this is reported, not expanded.
    pub fanout: usize,
}

impl Default for DiffOptions {
    fn default() -> Self {
        Self { repo: String::new(), depth: 3, max_hits: 500, fanout: 100 }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChangeKind {
    Added,
    Removed,
    /// The parameter list changed: `(old, new)`.
    Signature(Vec<String>, Vec<String>),
    /// The symbol kind changed: `(old, new)`.
    Kind(SymbolKind, SymbolKind),
    /// The definition's text changed.
    Definition,
    /// Same text, different edges: something it binds to moved.
    Bindings,
}

/// A symbol as `diff` names it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Named {
    pub name: String,
    pub path: String,
    pub line: u32,
    pub kind: SymbolKind,
    /// The callable or type this belongs to, for parameters and members.
    pub owner: Option<String>,
    pub external: bool,
}

#[derive(Debug, Clone)]
pub struct Change {
    /// The symbol's key: the same before and after, which is what makes
    /// "the same symbol, changed" a meaningful thing to say.
    pub key: SymbolKey,
    pub symbol: Named,
    pub what: ChangeKind,
    /// Net change in outgoing edges by relation (`+2 calls`, `-1 references`).
    pub edge_delta: Vec<(Relation, i64)>,
    /// Direct dependents this change breaks: callers of a removed or
    /// re-signed callable, referencers of a removed variable, subtypes of a
    /// removed type. Empty for a change that breaks nothing outright.
    pub breaks: Vec<(Relation, Named)>,
    /// What the change reaches, as a tree: each hit names its parent.
    pub impact: Vec<Hit>,
    pub impact_truncated: bool,
}

impl Change {
    pub fn is_breaking(&self) -> bool {
        !self.breaks.is_empty()
    }
}

/// One symbol the change reaches.
#[derive(Debug, Clone)]
pub struct Hit {
    pub symbol: Named,
    pub depth: u32,
    /// The edge walked to get here.
    pub via: Relation,
    /// `true`: this symbol depends on its parent (an edge walked against
    /// its direction); `false`: the parent's value flows into it.
    pub inbound: bool,
    pub parent: Option<usize>,
    /// Dependents this node has beyond what was expanded (a hub).
    pub unexpanded: usize,
}

#[derive(Debug, Clone)]
pub struct DiffReport {
    pub changed_files: Vec<String>,
    pub deleted_files: Vec<String>,
    /// Files re-extracted because they share an edge with a changed one.
    pub neighbour_files: Vec<String>,
    pub changes: Vec<Change>,
}

impl DiffReport {
    pub fn breaking(&self) -> usize {
        self.changes.iter().filter(|c| c.is_breaking()).count()
    }

    /// Distinct symbols any change reaches.
    pub fn affected(&self) -> usize {
        let mut seen: HashSet<(String, String, u32)> = HashSet::new();
        for c in &self.changes {
            for h in &c.impact {
                seen.insert((h.symbol.path.clone(), h.symbol.name.clone(), h.symbol.line));
            }
        }
        seen.len()
    }

    /// The report as text: the files, then each change with the dependents
    /// it breaks and its impact tree, `limit` lines of each.
    pub fn render(&self, limit: usize) -> String {
        use std::fmt::Write;
        let mut out = String::new();
        let place = |n: &Named| -> String {
            let what = match (&n.owner, n.kind) {
                (Some(o), SymbolKind::Parameter) => format!("{o}({})", n.name),
                (Some(o), _) => format!("{o}.{}", n.name),
                (None, _) => n.name.clone(),
            };
            if n.external { format!("{what} (external)") } else { format!("{what} ({}:{})", n.path, n.line) }
        };
        let kind = |n: &Named| format!("[{}]", n.kind);

        if self.changed_files.is_empty() && self.deleted_files.is_empty() {
            out.push_str("no changes since the store was indexed\n");
            return out;
        }
        let _ = writeln!(
            out,
            "{} file(s) changed, {} deleted, {} neighbour(s) re-extracted",
            self.changed_files.len(),
            self.deleted_files.len(),
            self.neighbour_files.len()
        );
        for f in &self.changed_files {
            let _ = writeln!(out, "  ~ {f}");
        }
        for f in &self.deleted_files {
            let _ = writeln!(out, "  - {f}");
        }
        if self.changes.is_empty() {
            out.push_str("\nno symbol changed: the edit touched no definition the graph records\n");
            return out;
        }
        let _ = writeln!(out, "\n{} change(s), {} breaking:", self.changes.len(), self.breaking());
        for c in &self.changes {
            let mark = match &c.what {
                ChangeKind::Added => "+",
                ChangeKind::Removed => "-",
                _ => "~",
            };
            let what = match &c.what {
                ChangeKind::Added => "added".to_string(),
                ChangeKind::Removed => "removed".to_string(),
                ChangeKind::Signature(old, new) => format!("signature ({}) -> ({})", old.join(", "), new.join(", ")),
                ChangeKind::Kind(old, new) => format!("kind {old} -> {new}"),
                ChangeKind::Definition => "definition changed".to_string(),
                ChangeKind::Bindings => "bindings changed".to_string(),
            };
            let delta: Vec<String> = c
                .edge_delta
                .iter()
                .map(|(rel, d)| format!("{}{} {}", if *d > 0 { "+" } else { "" }, d, rel.as_str()))
                .collect();
            let delta = if delta.is_empty() { String::new() } else { format!(" ({})", delta.join(", ")) };
            let breaks = if c.breaks.is_empty() { String::new() } else { format!(" — BREAKS {} dependent(s)", c.breaks.len()) };
            let _ = writeln!(out, "\n  {mark} {} {} {what}{delta}{breaks}", place(&c.symbol), kind(&c.symbol));
            for (rel, dep) in c.breaks.iter().take(limit) {
                let _ = writeln!(out, "      {:<14} {} {}", format!("{} from", rel.as_str()), place(dep), kind(dep));
            }
            if c.breaks.len() > limit {
                let _ = writeln!(out, "      ... and {} more", c.breaks.len() - limit);
            }
            if c.impact.is_empty() {
                continue;
            }
            let _ = writeln!(
                out,
                "    impact ({} symbol(s){}):",
                c.impact.len(),
                if c.impact_truncated { ", truncated" } else { "" }
            );
            // A tree: children directly under their parent, depth-first.
            let mut children: Vec<Vec<usize>> = vec![Vec::new(); c.impact.len()];
            let mut roots: Vec<usize> = Vec::new();
            for (i, h) in c.impact.iter().enumerate() {
                match h.parent {
                    Some(p) => children[p].push(i),
                    None => roots.push(i),
                }
            }
            let mut shown = 0usize;
            let mut stack: Vec<usize> = roots.into_iter().rev().collect();
            while let Some(i) = stack.pop() {
                if shown >= limit {
                    let _ = writeln!(out, "      ... {} more not shown", c.impact.len() - shown);
                    break;
                }
                shown += 1;
                let h = &c.impact[i];
                let indent = "  ".repeat(h.depth as usize);
                let via = if h.inbound { format!("{} by", dependent_verb(h.via)) } else { "flows to".to_string() };
                let more = if h.unexpanded > 0 { format!("  (+{} more dependents, not expanded)", h.unexpanded) } else { String::new() };
                let _ = writeln!(out, "    {indent}{:<16} {} {}{more}", via, place(&h.symbol), kind(&h.symbol));
                for &ch in children[i].iter().rev() {
                    stack.push(ch);
                }
            }
        }
        let _ = writeln!(
            out,
            "\nsummary: {} change(s), {} breaking, {} symbol(s) affected",
            self.changes.len(),
            self.breaking(),
            self.affected()
        );
        out
    }
}

/// The past participle a dependent is reported with.
fn dependent_verb(rel: Relation) -> &'static str {
    match rel {
        Relation::Calls | Relation::IndirectCall => "called",
        Relation::References => "referenced",
        Relation::Imports | Relation::ImportsFrom | Relation::DynamicImport => "imported",
        Relation::ReExports => "re-exported",
        Relation::Requires => "required",
        Relation::Inherits | Relation::Extends => "extended",
        Relation::Implements => "implemented",
        Relation::MixesIn => "mixed in",
        Relation::Embeds => "embedded",
        _ => rel.as_str(),
    }
}

/// A row as compared.
struct Row {
    kind: SymbolKind,
    hash: u64,
    params: Vec<String>,
    /// Outgoing edges that say what the symbol does: `(relation, target key)`.
    edges: BTreeMap<(u8, SymbolKey), i64>,
}

/// The rows of `view` in `paths`, keyed. Blocks, locals and parameters are
/// their owner's business (a parameter change shows as a signature change);
/// stubs, packages and proxies are nobody's.
fn rows_in(view: View<'_>, paths: &HashSet<String>) -> Result<HashMap<SymbolKey, Row>> {
    let structural = |k: SymbolKind| matches!(k, SymbolKind::Block | SymbolKind::Local | SymbolKind::Parameter);
    let counted = RelationMask::ALL
        .minus(Relation::CFG)
        .minus(Relation::LOCALS)
        .minus(RelationMask::of(&[Relation::Contains, Relation::Method, Relation::StandsFor]));
    let mut out = HashMap::new();
    for id in view.ids() {
        let flags = view.flags(id)?;
        if flags & (node_flags::EXTERNAL | node_flags::PROXY | node_flags::FILE_NODE) != 0 {
            continue;
        }
        let path = view.path(id)?;
        if !paths.contains(path) {
            continue;
        }
        let kind = SymbolKind::from_u8(view.kind_raw(id)?);
        if structural(kind) {
            continue;
        }
        let mut params: Vec<(u32, String)> = Vec::new();
        for e in view.out_edges(id, RelationMask::of(&[Relation::Contains]))? {
            if view.kind_raw(e.node)? == SymbolKind::Parameter.as_u8() {
                let pos = e.context.and_then(|c| c.parse::<u32>().ok()).unwrap_or(u32::MAX);
                params.push((pos, view.name(e.node)?.to_string()));
            }
        }
        params.sort();
        let mut edges: BTreeMap<(u8, SymbolKey), i64> = BTreeMap::new();
        for e in view.out_edges(id, counted)? {
            let tk = SymbolKind::from_u8(view.kind_raw(e.node)?);
            if structural(tk) {
                continue;
            }
            *edges.entry((e.relation.as_u8(), view.key(e.node)?)).or_default() += 1;
        }
        out.insert(
            view.key(id)?,
            Row { kind, hash: view.hash(id)?, params: params.into_iter().map(|(_, n)| n).collect(), edges },
        );
    }
    Ok(out)
}

fn named(view: View<'_>, id: LocalId) -> Result<Named> {
    let kind = SymbolKind::from_u8(view.kind_raw(id)?);
    let flags = view.flags(id)?;
    let own = RelationMask::of(&[Relation::Contains, Relation::Method]);
    let owner = if matches!(kind, SymbolKind::Parameter | SymbolKind::Method | SymbolKind::Local | SymbolKind::Field) {
        view.in_edges(id, own)?
            .iter()
            .find_map(|e| (view.flags(e.node).ok()? & node_flags::FILE_NODE == 0).then(|| view.name(e.node).ok().map(str::to_string)).flatten())
    } else {
        None
    };
    Ok(Named {
        name: view.name(id)?.to_string(),
        path: view.path(id)?.to_string(),
        line: view.line(id)?,
        kind,
        owner,
        external: flags & node_flags::EXTERNAL != 0,
    })
}

/// Compare the tree at `source` with the store at `store_dir`.
pub fn diff_tree(source: &Path, store_dir: &Path, opts: &DiffOptions) -> Result<DiffReport> {
    let old = Store::open(store_dir)?;

    // A scratch copy of the store: the base segments and the manifest,
    // nothing derived. The update runs there; the real store is not touched.
    let scratch = tempfile::tempdir().map_err(|e| io_err("creating a scratch store", e))?;
    for entry in std::fs::read_dir(store_dir).map_err(|e| io_err("reading the store", e))? {
        let entry = entry.map_err(|e| io_err("reading the store", e))?;
        let name = entry.file_name().to_string_lossy().to_string();
        if name == "CURRENT" || name.starts_with("MANIFEST-") || name.ends_with(".cgseg") {
            std::fs::copy(entry.path(), scratch.path().join(&name)).map_err(|e| io_err("copying the store", e))?;
        }
    }
    let mut new = Store::open(scratch.path())?;
    let never = CompactPolicy { max_deltas: usize::MAX, max_delta_ratio: f64::INFINITY };
    let report = update_tree(source, &mut new, &opts.repo, &never)?;
    if !report.incremental {
        return Err(StoreError::Corrupt("the store has no usable base to diff against; run `index` first".into()));
    }

    let changed_set: HashSet<String> = report.changed_paths.iter().cloned().collect();
    let deleted_set: HashSet<String> = report.deleted_paths.iter().cloned().collect();
    let mut touched: HashSet<String> = changed_set.clone();
    touched.extend(deleted_set.iter().cloned());
    touched.extend(report.reextracted_paths.iter().cloned());
    let mut neighbour_files: Vec<String> =
        report.reextracted_paths.iter().filter(|p| !changed_set.contains(*p)).cloned().collect();
    neighbour_files.sort();

    let old_view = old.view();
    let new_view = new.view();
    let before = rows_in(old_view, &touched)?;
    let after = rows_in(new_view, &touched)?;

    let mut keys: Vec<SymbolKey> = before.keys().chain(after.keys()).copied().collect();
    keys.sort_unstable();
    keys.dedup();

    let mut changes: Vec<Change> = Vec::new();
    for key in keys {
        let (what, symbol, edge_delta) = match (before.get(&key), after.get(&key)) {
            (Some(_), None) => (ChangeKind::Removed, old_view.find(key).map(|id| named(old_view, id)).transpose()?, Vec::new()),
            (None, Some(_)) => (ChangeKind::Added, new_view.find(key).map(|id| named(new_view, id)).transpose()?, Vec::new()),
            (Some(o), Some(n)) => {
                let what = if o.kind != n.kind {
                    ChangeKind::Kind(o.kind, n.kind)
                } else if o.params != n.params {
                    ChangeKind::Signature(o.params.clone(), n.params.clone())
                } else if o.hash != n.hash || (o.hash == 0 && o.edges != n.edges) {
                    ChangeKind::Definition
                } else if o.edges != n.edges {
                    ChangeKind::Bindings
                } else {
                    continue;
                };
                (what, new_view.find(key).map(|id| named(new_view, id)).transpose()?, edge_delta_of(o, n))
            }
            (None, None) => continue,
        };
        let Some(symbol) = symbol else { continue };
        changes.push(Change { key, symbol, what, edge_delta, breaks: Vec::new(), impact: Vec::new(), impact_truncated: false });
    }

    // Who breaks, and what is affected — from the old graph.
    for c in &mut changes {
        let Some(id) = old_view.find(c.key) else { continue };
        let break_mask = match &c.what {
            ChangeKind::Removed | ChangeKind::Kind(..) => Some(DEPENDS),
            ChangeKind::Signature(..) => Some(CALLS),
            _ => None,
        };
        if let Some(mask) = break_mask {
            let mut seen: HashSet<u32> = HashSet::new();
            for e in old_view.in_edges(id, mask)? {
                let k = SymbolKind::from_u8(old_view.kind_raw(e.node)?);
                if matches!(k, SymbolKind::Block | SymbolKind::Local) || !seen.insert(e.node.get()) {
                    continue;
                }
                c.breaks.push((e.relation, named(old_view, e.node)?));
            }
            c.breaks.sort_by(|a, b| (a.1.path.as_str(), a.1.line).cmp(&(b.1.path.as_str(), b.1.line)));
        }
        if c.what != ChangeKind::Added {
            let (impact, truncated) = trace(old_view, id, opts)?;
            c.impact = impact;
            c.impact_truncated = truncated;
        }
    }

    // Breaking first, then by place.
    changes.sort_by(|a, b| {
        b.is_breaking()
            .cmp(&a.is_breaking())
            .then_with(|| a.symbol.path.cmp(&b.symbol.path))
            .then_with(|| a.symbol.line.cmp(&b.symbol.line))
    });

    let mut changed_files = report.changed_paths.clone();
    changed_files.sort();
    let mut deleted_files = report.deleted_paths.clone();
    deleted_files.sort();
    Ok(DiffReport { changed_files, deleted_files, neighbour_files, changes })
}

fn edge_delta_of(o: &Row, n: &Row) -> Vec<(Relation, i64)> {
    let mut by_rel: BTreeMap<u8, i64> = BTreeMap::new();
    for ((rel, key), c) in &n.edges {
        let before = o.edges.get(&(*rel, *key)).copied().unwrap_or(0);
        *by_rel.entry(*rel).or_default() += c - before;
    }
    for ((rel, key), c) in &o.edges {
        if !n.edges.contains_key(&(*rel, *key)) {
            *by_rel.entry(*rel).or_default() -= c;
        }
    }
    by_rel.into_iter().filter(|(_, d)| *d != 0).map(|(r, d)| (Relation::from_u8(r), d)).collect()
}

/// The impact tree of `root` in `view`: reverse dependencies along
/// [`DEPENDS`], and the sinks its value flows to along `flows_to`, to
/// `opts.depth` hops. A stub is a leaf: it stands for a library, and what
/// a library does with a value is not this graph's to say.
fn trace(view: View<'_>, root: LocalId, opts: &DiffOptions) -> Result<(Vec<Hit>, bool)> {
    let mut hits: Vec<Hit> = Vec::new();
    let mut seen: HashSet<u32> = HashSet::from([root.get()]);
    // (id, depth, hit index)
    let mut frontier: Vec<(LocalId, u32, Option<usize>)> = vec![(root, 0, None)];
    let mut truncated = false;
    while !frontier.is_empty() {
        let mut next = Vec::new();
        for (id, depth, parent) in frontier {
            if depth >= opts.depth {
                continue;
            }
            let flags = view.flags(id)?;
            if flags & node_flags::EXTERNAL != 0 && parent.is_some() {
                continue;
            }
            let mut steps: Vec<(LocalId, Relation, bool)> = Vec::new();
            for e in view.in_edges(id, DEPENDS)? {
                steps.push((e.node, e.relation, true));
            }
            for e in view.out_edges(id, Relation::DATA_FLOW)? {
                steps.push((e.node, e.relation, false));
            }
            steps.retain(|(n, _, _)| {
                let k = SymbolKind::from_u8(view.kind_raw(*n).unwrap_or(255));
                !matches!(k, SymbolKind::Block | SymbolKind::Local)
            });
            let mut fresh: Vec<(LocalId, Relation, bool)> = Vec::new();
            for s in steps {
                if seen.insert(s.0.get()) {
                    fresh.push(s);
                }
            }
            if fresh.len() > opts.fanout {
                if let Some(p) = parent {
                    hits[p].unexpanded = fresh.len();
                }
                truncated = true;
                continue;
            }
            // Dependents first, then value consumers; each by place, so the
            // report reads in file order and is the same run to run.
            let mut named_fresh: Vec<(LocalId, Relation, bool, Named)> = Vec::with_capacity(fresh.len());
            for (n, via, inbound) in fresh {
                named_fresh.push((n, via, inbound, named(view, n)?));
            }
            named_fresh.sort_by(|a, b| {
                b.2.cmp(&a.2).then_with(|| (a.3.path.as_str(), a.3.line).cmp(&(b.3.path.as_str(), b.3.line)))
            });
            for (n, via, inbound, symbol) in named_fresh {
                if hits.len() >= opts.max_hits {
                    truncated = true;
                    break;
                }
                let idx = hits.len();
                hits.push(Hit { symbol, depth: depth + 1, via, inbound, parent, unexpanded: 0 });
                next.push((n, depth + 1, Some(idx)));
            }
        }
        frontier = next;
    }
    Ok((hits, truncated))
}
