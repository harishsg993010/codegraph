//! MCP server, built on the official `rmcp` SDK.
//!
//! The tool surface is declared with `#[tool_router]` / `#[tool]`, so the
//! JSON-Schema for each tool is derived from its argument struct rather than
//! written by hand — a schema and an implementation that can drift apart is a
//! class of bug worth not having.
//!
//! # Writing tool descriptions
//!
//! These are read by a model deciding what to call, so each says what the tool
//! answers and, where it matters, what it does *not*. The security tools in
//! particular state their limits inline: an agent that reads "0 findings" as
//! "no vulnerabilities" has been misled by the tool, not by the codebase.

use std::sync::{Arc, RwLock};

use codegraph_core::{LocalId, Relation, RelationMask};
use codegraph_index::{IndexQuery, Layered, MappedIndex};

/// The index the server runs on: a mapped base plus, once the store has
/// moved past it, an overlay.
pub type Index = Layered<MappedIndex>;
use codegraph_query::{Direction, Engine, SymbolInfo, Walk};
use codegraph_security::{Security, spec::presets};
use rmcp::{
    ErrorData, ServerHandler,
    handler::server::{router::tool::ToolRouter, wrapper::Parameters},
    model::{Implementation, ServerCapabilities, ServerInfo},
    tool, tool_handler, tool_router,
};
use schemars::JsonSchema;
use serde::Deserialize;

/// Open a store and whatever index it needs for serving.
///
/// A missing or stale index is recoverable, so build what is missing
/// rather than refuse — but say so, because a full rebuild is slow and the
/// operator should know why startup took a while.
pub fn open_store(dir: &std::path::Path) -> anyhow::Result<Engine<Index>> {
    use anyhow::Context;
    let store = codegraph_store::Store::open(dir).with_context(|| format!("opening store at {}", dir.display()))?;
    let (index, how) = codegraph_index::open_or_build(&store, dir)?;
    match how {
        codegraph_index::Opened::Base | codegraph_index::Opened::Overlaid => {}
        codegraph_index::Opened::OverlayBuilt => eprintln!("index overlay was missing; built it"),
        codegraph_index::Opened::Rebuilt => eprintln!("index unusable; rebuilt"),
    }
    Ok(Engine::from_parts(store, index))
}

/// A store served over MCP.
#[derive(Clone)]
pub struct CodeGraph {
    // `Arc` because the router hands `&self` to every tool call and the SDK
    // wants the handler `Clone`. The engine is read-only once open; when
    // the watcher brings the store forward it opens a new one and swaps it
    // in, and a call in flight finishes on the engine it started with.
    engine: Arc<RwLock<Arc<Engine<Index>>>>,
    tool_router: ToolRouter<Self>,
}

impl std::fmt::Debug for CodeGraph {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CodeGraph")
            .field("symbols", &self.engine().symbol_count())
            .finish()
    }
}

// --- tool arguments ---
//
// Doc comments become the JSON-Schema descriptions the client sees.

#[derive(Debug, Deserialize, JsonSchema)]
pub struct SearchArgs {
    /// Substring to look for in symbol names and file paths.
    pub query: String,
    /// Maximum results to return.
    #[serde(default = "d20")]
    pub limit: usize,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct DeepArgs {
    /// Free terms and `key:value` filters, space separated; quote a phrase
    /// (`"rate limit"`). Filters: `kind:function|method|class|variable|
    /// constant|field|parameter`, `in:<path substring>`, `calls:<name>`,
    /// `called-by:<name>`, `references:<name>`, `referenced-by:<name>`,
    /// `reaches:<name>` (call graph), `flows-to:<name>` and
    /// `flows-from:<name>` (data flow).
    pub query: String,
    /// Maximum hits to return.
    #[serde(default = "d20")]
    pub limit: usize,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct DiffArgs {
    /// The source directory the store was indexed from.
    pub source: String,
    /// How many hops of impact to trace (default 3).
    #[serde(default = "default_depth")]
    pub depth: u32,
    /// Most lines shown per change (default 40).
    #[serde(default = "d40")]
    pub limit: usize,
}

fn default_depth() -> u32 {
    3
}
fn d40() -> usize {
    40
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct SymbolArgs {
    /// Exact symbol name. If several symbols share it, the tool lists the
    /// candidates rather than guessing.
    pub symbol: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct WalkArgs {
    /// Exact symbol name.
    pub symbol: String,
    /// How many hops to expand.
    #[serde(default = "d2")]
    pub depth: u32,
    /// Maximum results to return.
    #[serde(default = "d30")]
    pub limit: usize,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct PathArgs {
    /// Exact name of the starting symbol.
    pub from: String,
    /// Exact name of the target symbol.
    pub to: String,
    /// Give up beyond this many hops.
    #[serde(default = "d12")]
    pub max_hops: u32,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct NeighborArgs {
    /// Exact symbol name.
    pub symbol: String,
    /// "out" for what this symbol uses, "in" for what uses it.
    #[serde(default = "out")]
    pub direction: String,
    /// Maximum results to return.
    #[serde(default = "d30")]
    pub limit: usize,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct AuditArgs {
    /// Maximum findings per analysis.
    #[serde(default = "d20")]
    pub limit: usize,
    /// "callgraph" (default): a finding is a call path from a source function
    /// to a sink function. "dataflow": a finding is a value from a source
    /// reaching a sink's argument — flow-, field- and predicate-sensitive
    /// inside a function, call-site-matched across calls, may-alias by copy
    /// and address.
    #[serde(default = "callgraph")]
    pub mode: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct DepsArgs {
    /// Package to report on. Omit to list every external package.
    #[serde(default)]
    pub package: String,
    /// Maximum results to return.
    #[serde(default = "d25")]
    pub limit: usize,
}

fn d2() -> u32 {
    2
}
fn d12() -> u32 {
    12
}
fn d20() -> usize {
    20
}
fn d25() -> usize {
    25
}
fn d30() -> usize {
    30
}
fn out() -> String {
    "out".into()
}
fn callgraph() -> String {
    "callgraph".into()
}

#[tool_router(router = tool_router)]
impl CodeGraph {
    pub fn new(engine: Engine<Index>) -> Self {
        Self { engine: Arc::new(RwLock::new(Arc::new(engine))), tool_router: Self::tool_router() }
    }

    /// The engine as of now. Held for the length of one call.
    pub fn engine(&self) -> Arc<Engine<Index>> {
        self.engine.read().unwrap_or_else(|p| p.into_inner()).clone()
    }

    /// Serve a newer engine from here on: the store moved (the watcher, or
    /// an index run elsewhere) and this one was opened on the new
    /// generation.
    pub fn replace(&self, engine: Engine<Index>) {
        *self.engine.write().unwrap_or_else(|p| p.into_inner()) = Arc::new(engine);
    }

    /// Keep the served graph current with the tree at `src`: watch it,
    /// and after each quiet period of `debounce` run one incremental
    /// update of the store at `store_dir`, rebuild the index overlay, and
    /// swap in an engine on the new generation. A failed round is
    /// reported on stderr and the last good engine stays. Returns once
    /// the watch is armed; the work happens on its own thread.
    pub fn follow(&self, src: std::path::PathBuf, store_dir: std::path::PathBuf, repo: String, debounce: std::time::Duration) -> Result<(), String> {
        let watcher = codegraph_resolve::TreeWatcher::new(&src, &store_dir, debounce).map_err(|e| e.to_string())?;
        let g = self.clone();
        std::thread::Builder::new()
            .name("codegraph-sync".into())
            .spawn(move || {
                while let Some(batch) = watcher.next() {
                    let t = std::time::Instant::now();
                    match codegraph_resolve::sync(&src, &store_dir, &repo, &codegraph_store::CompactPolicy::default()) {
                        Ok((r, _)) if r.changed == 0 && r.deleted == 0 && r.incremental => {}
                        Ok((r, _)) => match open_store(&store_dir) {
                            Ok(e) => {
                                g.replace(e);
                                eprintln!(
                                    "updated: {} changed, {} deleted, {} re-extracted ({}) in {:.1}s after {} event path(s)",
                                    r.changed,
                                    r.deleted,
                                    r.reextracted,
                                    if r.incremental { r.detection } else { "full rebuild" },
                                    t.elapsed().as_secs_f64(),
                                    batch.len()
                                );
                            }
                            Err(e) => eprintln!("update applied but the store could not be reopened: {e:#}"),
                        },
                        Err(e) => eprintln!("update failed: {e:#}"),
                    }
                }
            })
            .map_err(|e| e.to_string())?;
        Ok(())
    }

    /// Find symbols whose name or file path contains a substring. Use this
    /// first when you know roughly what something is called but not exactly.
    #[tool(name = "search")]
    async fn search(&self, Parameters(a): Parameters<SearchArgs>) -> String {
        let e = self.engine();
        let e = &*e;
        match e.search(&a.query) {
            Ok(hits) => {
                let mut out = format!("{} matches for {:?}\n", hits.len(), a.query);
                for id in hits.iter().take(a.limit) {
                    if let Ok(Some(i)) = e.info(*id) {
                        out.push_str(&format!("  [{}] {}\n", i.kind, describe(&i)));
                    }
                }
                if hits.len() > a.limit {
                    out.push_str(&format!("  ... and {} more\n", hits.len() - a.limit));
                }
                out
            }
            Err(err) => format!("search failed: {err}"),
        }
    }

    /// Find code by what it is connected to, not only by what it is called.
    #[tool(
        name = "deep_search",
        description = "Deep search over the graph. Free terms match symbol names and paths by subword (`upload` finds `MaxUploadSize`), and the insides of functions: their locals and parameters, the callees they call, the variables they read, and the conditions they branch on. Matches spread along calls, references and value flow, so the function that connects two terms scores for both even when neither word is in its name. Filters narrow by structure: `kind:function`, `in:routers/`, `calls:Popen`, `called-by:main`, `references:MaxSize`, `reaches:Exec` (call graph), `flows-to:Exec`, `flows-from:FormValue` (data flow); a library function is named by its bare or qualified name (`exec.Command`). Every hit says why it matched. Use `search` when you know the name; use this when you know what the code does."
    )]
    async fn deep_search(&self, Parameters(a): Parameters<DeepArgs>) -> String {
        let e = self.engine();
        let e = &*e;
        let q = codegraph_query::DeepQuery::parse(&a.query);
        if q.terms.is_empty() && q.filters.is_empty() {
            return "give some terms, filters, or both — e.g. `upload limit kind:function calls:Open`".into();
        }
        match e.deep_search(&q, a.limit) {
            Ok(hits) => {
                let filters: Vec<String> = q.filters.iter().map(|f| format!("{f:?}")).collect();
                let mut out = format!(
                    "{} hit(s) for terms {:?}{}\n",
                    hits.len(),
                    q.terms,
                    if filters.is_empty() { String::new() } else { format!(" with filters {}", filters.join(", ")) }
                );
                for h in &hits {
                    out.push_str(&format!("\n{:.2}  {} [{}]\n", h.score, describe(&h.info), h.info.kind));
                    for r in &h.reasons {
                        out.push_str(&format!("    {r}\n"));
                    }
                }
                out
            }
            Err(err) => format!("deep search failed: {err}"),
        }
    }

    /// Show one symbol: where it is defined, what it calls, and what calls it.
    #[tool(name = "explain")]
    async fn explain(&self, Parameters(a): Parameters<SymbolArgs>) -> String {
        let e = self.engine();
        let e = &*e;
        let id = match self.one(&a.symbol) {
            Ok(id) => id,
            Err(msg) => return msg,
        };
        let Ok(Some(info)) = e.info(id) else { return "symbol vanished".into() };
        let mut out = format!("{} [{}], degree {}\n", describe(&info), info.kind, info.degree);
        if let Ok(params) = e.parameters(id)
            && !params.is_empty()
        {
            let names: Vec<String> =
                params.iter().filter_map(|(_, p)| e.info(*p).ok().flatten().map(|i| i.name)).collect();
            out.push_str(&format!("parameters: {}\n", names.join(", ")));
        }
        let calls = RelationMask::of(&[Relation::Calls, Relation::IndirectCall]);
        let refs = RelationMask::of(&[Relation::References]);
        for (label, dir, mask) in [
            ("calls", Direction::Out, calls),
            ("called by", Direction::In, calls),
            ("references", Direction::Out, refs),
            ("referenced by", Direction::In, refs),
            ("flows to", Direction::Out, Relation::DATA_FLOW),
            ("flows from", Direction::In, Relation::DATA_FLOW),
        ] {
            let Ok(hits) = e.neighbors(id, dir, mask) else { continue };
            if hits.is_empty() {
                continue;
            }
            out.push_str(&format!("\n{label} ({}):\n", hits.len()));
            for h in hits.iter().take(15) {
                if let Ok(Some(i)) = e.info(h.id) {
                    out.push_str(&format!("  {}\n", describe(&i)));
                }
            }
        }
        out
    }

    /// What the uncommitted edits in the source tree do to the graph.
    #[tool(
        name = "diff",
        description = "Compare the source tree's current files with the index: every symbol (function, method, type, variable, constant, field) that was added, removed, re-signed, redefined or re-bound since the store was indexed. For each: the dependents it breaks outright (callers of a removed or re-signed callable, referencers of a removed variable, subtypes of a removed type) and a trace of what it affects through callers, references, imports, subtypes and value flow, with the relation on every step. Runs the incremental update on a scratch copy; the store is not modified. Use before committing to know what a change reaches."
    )]
    async fn diff(&self, Parameters(a): Parameters<DiffArgs>) -> String {
        let store_dir = self.engine().store().root().to_path_buf();
        let opts = codegraph_resolve::DiffOptions { depth: a.depth, ..Default::default() };
        match codegraph_resolve::diff_tree(std::path::Path::new(&a.source), &store_dir, &opts) {
            Ok(r) => r.render(a.limit),
            Err(e) => format!("diff failed: {e:#}"),
        }
    }

    /// A callable's stored control-flow graph.
    #[tool(
        name = "cfg",
        description = "The control-flow graph of a function or method as stored in the index: its basic blocks in order, each block's successors with the branch label and predicate the edge assumes (e.g. `then: x == 1`, `else`, `loop`, `exception`), and the non-local variables and fields each block reads and writes. Locals are not shown: they never leave the function. Empty for anything that is not a callable."
    )]
    async fn cfg(&self, Parameters(a): Parameters<SymbolArgs>) -> String {
        let e = self.engine();
        let e = &*e;
        let id = match self.one(&a.symbol) {
            Ok(id) => id,
            Err(msg) => return msg,
        };
        let Ok(Some(info)) = e.info(id) else { return "symbol vanished".into() };
        let Ok(blocks) = e.cfg(id) else { return "cfg unavailable".into() };
        if blocks.is_empty() {
            return format!("{} has no stored control-flow graph", describe(&info));
        }
        let names = |ids: &[LocalId]| -> String {
            ids.iter().filter_map(|i| e.info(*i).ok().flatten().map(|i| i.name)).collect::<Vec<_>>().join(", ")
        };
        let mut out = format!("{}: {} blocks\n", describe(&info), blocks.len());
        for b in &blocks {
            let succ: Vec<String> = b
                .successors
                .iter()
                .map(|(n, l)| if l.is_empty() { format!("b{n}") } else { format!("b{n} [{l}]") })
                .collect();
            out.push_str(&format!("b{} (line {}) -> {}\n", b.index, b.line, if succ.is_empty() { "exit".into() } else { succ.join(", ") }));
            if !b.defines.is_empty() {
                out.push_str(&format!("    writes {}\n", names(&b.defines)));
            }
            if !b.uses.is_empty() {
                out.push_str(&format!("    reads  {}\n", names(&b.uses)));
            }
        }
        out
    }

    /// What would be affected if this symbol changed — the reverse dependency
    /// walk. Use this before editing something to see its blast radius.
    #[tool(name = "affected")]
    async fn affected(&self, Parameters(a): Parameters<WalkArgs>) -> String {
        let e = self.engine();
        let e = &*e;
        let id = match self.one(&a.symbol) {
            Ok(id) => id,
            Err(msg) => return msg,
        };
        match e.blast_radius(id, a.depth) {
            Ok(hits) => {
                let mut out = format!("{} symbols affected within {} hops\n", hits.len(), a.depth);
                for h in hits.iter().take(a.limit) {
                    if let Ok(Some(i)) = e.info(h.id) {
                        out.push_str(&format!(
                            "  depth {} via {} — {}\n",
                            h.depth,
                            h.via.as_str(),
                            describe(&i)
                        ));
                    }
                }
                out
            }
            Err(err) => format!("blast radius failed: {err}"),
        }
    }

    /// Shortest call path between two symbols. "No path" is a real answer and
    /// usually the informative one: it means the two are not connected in the
    /// indexed call graph.
    #[tool(name = "path")]
    async fn path(&self, Parameters(a): Parameters<PathArgs>) -> String {
        let e = self.engine();
        let e = &*e;
        let from = match self.one(&a.from) {
            Ok(id) => id,
            Err(msg) => return msg,
        };
        let to = match self.one(&a.to) {
            Ok(id) => id,
            Err(msg) => return msg,
        };
        match e.shortest_path(from, to, RelationMask::ALL, a.max_hops) {
            Ok(Some(p)) => {
                let mut out = format!("{} hops\n", p.len().saturating_sub(1));
                for (n, id) in p.iter().enumerate() {
                    if let Ok(Some(i)) = e.info(*id) {
                        out.push_str(&format!("  {n}. {}\n", describe(&i)));
                    }
                }
                out
            }
            Ok(None) => format!("no path within {} hops", a.max_hops),
            Err(err) => format!("path search failed: {err}"),
        }
    }

    /// One hop from a symbol, in either direction, across all relation types.
    #[tool(name = "neighbors")]
    async fn neighbors(&self, Parameters(a): Parameters<NeighborArgs>) -> String {
        let e = self.engine();
        let e = &*e;
        let id = match self.one(&a.symbol) {
            Ok(id) => id,
            Err(msg) => return msg,
        };
        let dir = if a.direction == "in" { Direction::In } else { Direction::Out };
        match e.neighbors(id, dir, RelationMask::ALL) {
            Ok(hits) => {
                let mut out = format!("{} neighbours\n", hits.len());
                for h in hits.iter().take(a.limit) {
                    if let Ok(Some(i)) = e.info(h.id) {
                        out.push_str(&format!("  {} — {}\n", h.via.as_str(), describe(&i)));
                    }
                }
                out
            }
            Err(err) => format!("neighbours failed: {err}"),
        }
    }

    /// The neighbourhood around a symbol out to N hops — the shape of the code
    /// near it. Prefer this over several `neighbors` calls when orienting
    /// yourself in unfamiliar code.
    #[tool(name = "context")]
    async fn context(&self, Parameters(a): Parameters<WalkArgs>) -> String {
        let e = self.engine();
        let e = &*e;
        let id = match self.one(&a.symbol) {
            Ok(id) => id,
            Err(msg) => return msg,
        };
        let w = Walk { depth: a.depth, ..Walk::default() };
        match e.walk(&[id], w) {
            Ok(hits) => {
                let mut out = format!("{} symbols within {} hops\n", hits.len(), a.depth);
                for h in hits.iter().take(a.limit) {
                    if let Ok(Some(i)) = e.info(h.id) {
                        out.push_str(&format!(
                            "  {} {} — {}\n",
                            h.depth,
                            h.via.as_str(),
                            describe(&i)
                        ));
                    }
                }
                out
            }
            Err(err) => format!("walk failed: {err}"),
        }
    }

    /// Size and shape of the indexed corpus: symbol and edge counts, the mix of
    /// relation types, and the highest-degree symbols.
    #[tool(name = "stats")]
    async fn stats(&self) -> String {
        let e = self.engine();
        let e = &*e;
        let Ok((rels, confs)) = e.edge_histogram() else { return "stats unavailable".into() };
        let mut out = format!(
            "{} symbols, {} edges, {} components\n\nby relation:\n",
            e.symbol_count(),
            e.store().edge_count(),
            e.index().components()
        );
        for (r, c) in rels {
            out.push_str(&format!("  {:<24} {c}\n", r.as_str()));
        }
        out.push_str("\nby confidence:\n");
        for (c, k) in confs {
            out.push_str(&format!("  {:<24} {k}\n", c.as_str()));
        }
        if let Ok(hubs) = e.hubs(10) {
            out.push_str("\ntop by degree:\n");
            for i in hubs {
                out.push_str(&format!("  {:>6}  {}\n", i.degree, describe(&i)));
            }
        }
        out
    }

    /// Run the built-in security analyses: entrypoint reachability and
    /// source-to-sink taint reachability.
    ///
    /// This is call-graph reachability, not dataflow. A finding is a lead to
    /// investigate, not a proven vulnerability, and zero findings means zero
    /// matches for the built-in patterns rather than an absence of
    /// vulnerabilities.
    #[tool(name = "audit")]
    async fn audit(&self, Parameters(a): Parameters<AuditArgs>) -> String {
        let e = self.engine();
        let sec = Security::new(&e);
        let mut out = String::new();
        match (sec.entrypoints(), sec.reachable_from_entrypoints()) {
            (Ok(eps), Ok(live)) => out.push_str(&format!(
                "{} entrypoints, {} of {} symbols reachable from them\n",
                eps.len(),
                live.len(),
                e.symbol_count()
            )),
            _ => out.push_str("entrypoint analysis unavailable\n"),
        }
        let dataflow = a.mode.eq_ignore_ascii_case("dataflow");
        if dataflow {
            out.push_str(
                "mode: dataflow. A finding is a value from a source reaching a sink's argument: \
                 flow-, field- and predicate-sensitive within a function, call-site-matched \
                 across calls, may-alias by copy and address, library calls by summary. \
                 Missing edges (unresolved calls, reflection) mean missing findings.\n",
            );
        }
        for spec in presets::all() {
            let spec = if dataflow { spec.mode(codegraph_security::Mode::DataFlow) } else { spec };
            match sec.analyse(&spec, a.limit) {
                Ok(an) => {
                    out.push_str(&format!(
                        "\n{}: {} sources x {} sinks, {:.1}% ruled out by the reachability \
                         index, {} findings\n",
                        spec.name,
                        an.sources,
                        an.sinks,
                        an.rejection_rate() * 100.0,
                        an.findings.len()
                    ));
                    for f in &an.findings {
                        out.push_str(&format!(
                            "  {} -> {} [{} hops, {:?}{}]\n",
                            describe(&f.source),
                            describe(&f.sink),
                            f.depth(),
                            f.confidence,
                            if f.reachable_from_entrypoint { ", live" } else { ", unreachable" }
                        ));
                        if dataflow {
                            let via: Vec<String> = f.path.iter().map(|s| s.name.clone()).collect();
                            out.push_str(&format!("    via {}\n", via.join(" -> ")));
                        }
                    }
                }
                Err(err) => out.push_str(&format!("\n{}: failed: {err}\n", spec.name)),
            }
        }
        out.push_str(
            "\nnote: these are starter specs, not a policy. Zero findings means zero matches \
             for these patterns.\n",
        );
        out
    }

    /// External packages the corpus depends on. Given a package name, reports
    /// which files import it and whether any of them is reachable from an
    /// entrypoint — the difference between being in the lockfile and being
    /// actually called.
    #[tool(name = "deps")]
    async fn deps(&self, Parameters(a): Parameters<DepsArgs>) -> String {
        let e = self.engine();
        let sec = Security::new(e.as_ref());
        if a.package.is_empty() {
            return match sec.packages() {
                Ok(pkgs) => {
                    let mut out = format!("{} external packages\n", pkgs.len());
                    for (name, c) in pkgs.iter().take(a.limit) {
                        out.push_str(&format!("  {name:<30} {c} importing files\n"));
                    }
                    out
                }
                Err(err) => format!("packages failed: {err}"),
            };
        }
        match sec.package_reach(&a.package) {
            Ok(Some(r)) => {
                let mut out = format!(
                    "{}: {} importing files, {}\n",
                    r.package,
                    r.importers.len(),
                    if r.reachable_from_entrypoint {
                        "reachable from an entrypoint"
                    } else {
                        "not reachable from any entrypoint"
                    }
                );
                for i in r.importers.iter().take(a.limit) {
                    out.push_str(&format!("  {}\n", i.path));
                }
                out
            }
            Ok(None) => format!("{} is not a dependency of this corpus", a.package),
            Err(err) => format!("package reach failed: {err}"),
        }
    }

    /// Resolve a name to exactly one symbol.
    ///
    /// Ambiguity is reported rather than guessed at: silently picking one of
    /// several same-named symbols would make the answer depend on internal
    /// ordering, which a caller cannot reason about.
    fn one(&self, name: &str) -> Result<LocalId, String> {
        if name.trim().is_empty() {
            return Err("a symbol name is required".into());
        }
        let e = self.engine();
        let hits = e.by_name(name);
        match hits.len() {
            1 => Ok(hits[0]),
            0 => Err(format!("no symbol named {name:?}")),
            n => {
                let mut msg = format!("{name:?} is ambiguous — {n} symbols share it:\n");
                for id in hits.iter().take(10) {
                    if let Ok(Some(i)) = e.info(*id) {
                        msg.push_str(&format!("  {}\n", describe(&i)));
                    }
                }
                msg.push_str("qualify it, or use `search` to pick one.\n");
                Err(msg)
            }
        }
    }
}

#[tool_handler(router = self.tool_router)]
impl ServerHandler for CodeGraph {
    fn get_info(&self) -> ServerInfo {
        // `ServerInfo` is non-exhaustive, so build it and set the fields
        // rather than using a struct literal.
        let mut info = ServerInfo::new(ServerCapabilities::builder().enable_tools().build());
        // `Implementation::from_build_env` would report the SDK's crate name;
        // clients show this to users, so name the server, not the library.
        info.server_info = Implementation::new("codegraph", env!("CARGO_PKG_VERSION"));
        info.instructions = Some(
            "A code-index database over a source tree. Use `search` to find symbols by \
             name or path, `explain` for one symbol's callers and callees, `affected` for \
             blast radius before an edit, `path` to see how two symbols connect, \
             `context` to orient in unfamiliar code, and `audit` / `deps` for security \
             questions. Symbol arguments must name exactly one symbol; ambiguous names \
             return the candidates rather than a guess."
                .into(),
        );
        info
    }
}

fn describe(i: &SymbolInfo) -> String {
    format!("{} ({}:{})", i.name, i.path, i.line)
}

/// Re-exported so the binary does not need `rmcp` as a direct dependency.
pub use rmcp::{ServiceExt, transport::stdio};
pub type McpError = ErrorData;
