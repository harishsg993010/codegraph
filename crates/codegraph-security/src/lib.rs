//! The security layer: entrypoints, taint reachability, and dependency reach.
//!
//! All three are the same primitive — reachability over a relation-masked call
//! graph — asked in different directions:
//!
//! | question | direction | from | to |
//! |---|---|---|---|
//! | is this function reachable at all? | forward | entrypoints | the function |
//! | does untrusted input reach a dangerous call? | forward | sources | sinks |
//! | does our code reach a vulnerable dependency? | forward | our symbols | the package |
//!
//! What makes them answerable rather than merely expressible is the GRAIL
//! filter: on a real corpus it rejects 98–99.7% of unreachable pairs without
//! searching, so a query over millions of pairs only pays for the few that
//! might connect.
//!
//! # What this is and is not
//!
//! This is **reachability over a call graph**, not dataflow. It answers "is
//! there a call path from a source to a sink", which is a necessary condition
//! for a taint vulnerability and not a sufficient one: it cannot see whether
//! the tainted value is actually passed along that path, nor whether a
//! sanitiser on the way neutralises it. Treat a finding as a lead to
//! investigate, not a proven vulnerability. Findings carry a
//! [`Finding::confidence`] that says which.
//!
//! The reverse direction is the stronger guarantee: when reachability says
//! *unreachable*, and the call graph is complete for that language, the sink
//! genuinely cannot be called from that source. That is what makes it useful
//! for triage — ruling vulnerabilities *out* is where the leverage is.

pub mod report;
pub mod rules;
pub mod spec;

use codegraph_core::{LocalId, Relation, RelationMask};
use codegraph_index::IndexQuery;
use codegraph_query::{Engine, SymbolInfo};
use codegraph_store::Result;

pub use report::{RuleResult, RuleSpec, render_json, render_text, run_rules, worst};
pub use rules::{Rule, RuleError, Severity, load_rules, parse_rules, tree_rule_paths};
pub use spec::{Matcher, Mode, TaintSpec};

/// How much a finding is worth acting on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Confidence {
    /// Every edge on the path is `EXTRACTED` — a direct call the extractor saw.
    Direct,
    /// At least one edge is `INFERRED`. The path is plausible but rests on a
    /// resolution guess.
    Inferred,
}

/// A source that reaches a sink.
#[derive(Debug, Clone)]
pub struct Finding {
    pub source: SymbolInfo,
    pub sink: SymbolInfo,
    /// The call path, source first, sink last.
    pub path: Vec<SymbolInfo>,
    pub confidence: Confidence,
    /// Whether the source is itself reachable from an entrypoint. An
    /// unreachable source is usually dead code or a test fixture, and ranking
    /// it alongside live findings is how a report becomes noise.
    pub reachable_from_entrypoint: bool,
}

impl Finding {
    /// Hops from source to sink.
    pub fn depth(&self) -> usize {
        self.path.len().saturating_sub(1)
    }
}

/// Names that conventionally mark a program entrypoint.
///
/// Deliberately a short, conservative list. An over-broad entrypoint set makes
/// everything look reachable, which destroys the one thing reachability is good
/// for — ruling things out.
pub const ENTRYPOINT_NAMES: &[&str] = &[
    "main", "handler", "handle", "run", "serve", "start", "lambda_handler",
    "application", "app", "wsgi", "asgi", "execute", "dispatch", "process_request",
];

/// The relations a taint path may follow: **calls only**.
///
/// This is narrower than [`Relation::TAINT`], deliberately. That mask includes
/// `imports` and `depends_on`, which are *file-level* relations — and following
/// them produces "findings" like `request.py -> subprocess` where the path is a
/// chain of file imports, not a flow of data. Structurally real, analytically
/// meaningless, and exactly the kind of result that makes a security tool
/// untrustworthy.
///
/// Still a subset of [`crate::REACHABILITY`], so the reachability index covers
/// it and the fast rejection still applies.
pub const FLOW: RelationMask = RelationMask::of(&[
    Relation::Calls,
    Relation::IndirectCall,
    // A re-export forwards a call to its real definition, so a path through one
    // is a genuine call path.
    Relation::ReExports,
]);

/// The relations a *dependency* path may follow. Used for SCA, where file-level
/// imports are exactly what the question is about.
pub const DEPENDENCY_FLOW: RelationMask = RelationMask::of(&[
    Relation::Imports,
    Relation::ImportsFrom,
    Relation::DependsOn,
    Relation::Requires,
]);

/// The relations a *value* may travel along: `flows_to` only. Not covered
/// by the reachability labels ([`REACHABILITY`] is the call graph), so a
/// dataflow question is answered by search alone — one backward search per
/// sink, which is cheap because sinks are few.
pub const DATA_FLOW: RelationMask = Relation::DATA_FLOW;

/// The mask the reachability index is built over.
pub const REACHABILITY: RelationMask = codegraph_index::REACHABILITY_RELATIONS;

/// Can a symbol of this kind be a taint source or sink?
///
/// Files and packages cannot: they do not execute, so a "path" that begins or
/// ends at one is an import chain rather than a call chain.
/// The `<leave>` half of a stub edge's call-site tag.
fn leave_site(context: Option<&str>) -> Option<String> {
    let (l, _) = context?.split_once('>')?;
    (!l.is_empty()).then(|| l.to_string())
}

/// The `<enter>` half of a stub edge's call-site tag.
fn enter_site(context: Option<&str>) -> Option<String> {
    let (_, r) = context?.split_once('>')?;
    (!r.is_empty()).then(|| r.to_string())
}

/// Incoming flow edges, grouped by the call site they enter on, computed
/// once per node. A stub like `Sprintf`, or a corpus function every file
/// calls, has one edge per call in the corpus; grouping makes a visit cost
/// the edges of one call, not of every call. Sites are interned.
#[derive(Default)]
struct Arrivals {
    by_node: std::collections::HashMap<u32, Grouped>,
    sites: std::collections::HashMap<String, u32>,
}

/// Enter site (interned; `None` = an edge that crosses no call) ->
/// `(source, leave site of the edge)`.
type Grouped = std::collections::HashMap<Option<u32>, Vec<(u32, Option<u32>)>>;

/// The leave site of external data: nothing enters on it.
const EXTERNAL_SITE: u32 = u32::MAX;

/// `(source, leave site, enter site)` of one edge into a node.
type Arrival = (u32, Option<u32>, Option<u32>);

impl Arrivals {
    fn intern(&mut self, site: &str) -> u32 {
        if site == "!" {
            return EXTERNAL_SITE;
        }
        let n = self.sites.len() as u32;
        *self.sites.entry(site.to_string()).or_insert(n)
    }

    fn group(&mut self, view: codegraph_store::View<'_>, node: LocalId) -> Result<&Grouped> {
        if !self.by_node.contains_key(&node.get()) {
            let mut groups = Grouped::new();
            for e in view.in_edges(node, DATA_FLOW)? {
                let enter = enter_site(e.context).map(|s| self.intern(&s));
                let leave = leave_site(e.context).map(|s| self.intern(&s));
                groups.entry(enter).or_default().push((e.node.get(), leave));
            }
            self.by_node.insert(node.get(), groups);
        }
        Ok(&self.by_node[&node.get()])
    }

    /// The edges into `node` a backward walk may take with `stack` as the
    /// call sites it is inside (innermost last): every edge that crosses
    /// no call, plus — when inside a call — the one that entered on that
    /// site, or — when inside none — every entering edge, since a path may
    /// begin inside a callee and leave it towards any caller.
    fn arrivals(
        &mut self,
        view: codegraph_store::View<'_>,
        node: LocalId,
        top: Option<Option<u32>>,
    ) -> Result<Vec<Arrival>> {
        let g = self.group(view, node)?;
        let mut out = Vec::new();
        match top {
            // Inside a call: the internal edges, and the arguments of that call.
            Some(Some(site)) => {
                if let Some(v) = g.get(&None) {
                    out.extend(v.iter().map(|(u, l)| (*u, *l, None)));
                }
                if let Some(v) = g.get(&Some(site)) {
                    out.extend(v.iter().map(|(u, l)| (*u, *l, Some(site))));
                }
            }
            // Inside external data: nothing came in.
            Some(None) => {}
            // Inside nothing: everything.
            None => {
                for (enter, v) in g {
                    out.extend(v.iter().map(|(u, l)| (*u, *l, *enter)));
                }
            }
        }
        Ok(out)
    }
}

/// How many call sites a path may be inside at once before the oldest is
/// forgotten, unless the spec says otherwise. Forgetting is the sound
/// direction: an unmatched return may then leave towards any caller, as a
/// path that began inside a callee always could.
pub const DEFAULT_CONTEXT_DEPTH: usize = 6;

fn can_carry_taint(kind: codegraph_core::SymbolKind) -> bool {
    !matches!(
        kind,
        codegraph_core::SymbolKind::File
            | codegraph_core::SymbolKind::Package
            | codegraph_core::SymbolKind::Block
            // A local is on no `flows_to` edge: the facts run from its
            // function's inputs to its sinks and were resolved through it.
            | codegraph_core::SymbolKind::Local
    )
}

pub struct Security<'a, I: IndexQuery = codegraph_index::IndexData> {
    engine: &'a Engine<I>,
}

impl<'a, I: IndexQuery> Security<'a, I> {
    pub fn new(engine: &'a Engine<I>) -> Self {
        Self { engine }
    }

    /// Symbols that look like entrypoints.
    ///
    /// Matches callable symbols whose name is in [`ENTRYPOINT_NAMES`], plus
    /// anything already flagged by the extractor. Returns them sorted, so a
    /// report is stable between runs.
    pub fn entrypoints(&self) -> Result<Vec<LocalId>> {
        let view = self.engine.store().view();
        let mut out = Vec::new();
        // Per segment so the columns are fetched once, not once per row.
        for si in 0..view.segment_count() {
            let (seg, base) = view.segment(si);
            let flags = seg.node_flags()?;
            let kinds = seg.node_kinds()?;
            let norms = seg.node_norm_names()?;
            for l in 0..seg.node_count() {
                let id = LocalId::new(base + l as u32);
                if !view.is_canonical(id) {
                    continue;
                }
                if flags[l] & codegraph_store::node_flags::ENTRYPOINT != 0 {
                    out.push(id);
                    continue;
                }
                let kind = codegraph_core::SymbolKind::from_u8(kinds[l]);
                let callable = matches!(
                    kind,
                    codegraph_core::SymbolKind::Function | codegraph_core::SymbolKind::Method
                );
                if callable && ENTRYPOINT_NAMES.contains(&seg.string(norms[l])) {
                    out.push(id);
                }
            }
        }
        Ok(out)
    }

    /// Everything reachable from the entrypoints along [`FLOW`].
    ///
    /// The complement is the interesting half: a symbol *not* in this set
    /// cannot be invoked through any call path the index knows about.
    pub fn reachable_from_entrypoints(&self) -> Result<Vec<LocalId>> {
        let eps = self.entrypoints()?;
        if eps.is_empty() {
            return Ok(Vec::new());
        }
        self.engine.reachable_set(&eps, FLOW)
    }

    /// Resolve a matcher against the corpus.
    pub fn resolve(&self, m: &Matcher) -> Result<Vec<LocalId>> {
        m.resolve(self.engine)
    }

    /// Run a taint spec.
    ///
    /// One finding per (source, sink) pair that connects, capped by
    /// `max_findings`. Sources and sinks are resolved first so a spec that
    /// matches nothing is visible as an empty result rather than a silent pass.
    pub fn analyse(&self, spec: &TaintSpec, max_findings: usize) -> Result<Analysis> {
        // Sources and sinks are narrowed to symbols that can actually execute.
        // A matcher like `contains("request")` otherwise picks up every file
        // named `request.py`, and every finding rooted at one is an import
        // chain dressed up as a call path.
        let dataflow = spec.mode == Mode::DataFlow;
        let mask = if dataflow { DATA_FLOW } else { FLOW };
        // Path excludes are tests on the symbol's file (so a parameter,
        // which no name index holds, is judged like its owner); the other
        // excludes are resolved to symbols.
        let exclude_paths: Vec<&str> = spec
            .excludes
            .iter()
            .filter_map(|m| if let Matcher::InPath(p) = m { Some(p.as_str()) } else { None })
            .collect();
        let excluded: std::collections::HashSet<u32> = {
            let rest: Vec<Matcher> = spec.excludes.iter().filter(|m| !matches!(m, Matcher::InPath(_))).cloned().collect();
            self.resolve_all(&rest, dataflow)?.iter().map(|l| l.get()).collect()
        };
        // Path includes and languages are tests on the symbol's file, so a
        // parameter (which no name index holds) is judged like its owner.
        // A library stub is judged by the file that first mentioned it —
        // `subprocess.Popen` is Python's because a Python file called it —
        // and a stub with no file at all passes.
        let include_paths: Vec<&str> = spec
            .includes
            .iter()
            .filter_map(|m| if let Matcher::InPath(p) = m { Some(p.as_str()) } else { None })
            .collect();
        let included: std::collections::HashSet<u32> = {
            let rest: Vec<Matcher> = spec.includes.iter().filter(|m| !matches!(m, Matcher::InPath(_))).cloned().collect();
            self.resolve_all(&rest, dataflow)?.iter().map(|l| l.get()).collect()
        };
        let keep = |ids: Vec<LocalId>| -> Result<Vec<LocalId>> {
            let mut out = Vec::with_capacity(ids.len());
            for id in ids {
                if excluded.contains(&id.get()) {
                    continue;
                }
                if !exclude_paths.is_empty() || !spec.includes.is_empty() || !spec.languages.is_empty() {
                    let Some(info) = self.engine.info(id)? else { continue };
                    let path = info.path.to_lowercase();
                    let in_files = path.is_empty();
                    if !in_files && exclude_paths.iter().any(|p| path.contains(p)) {
                        continue;
                    }
                    if !spec.includes.is_empty()
                        && !in_files
                        && !include_paths.iter().any(|p| path.contains(p))
                        && !included.contains(&id.get())
                    {
                        continue;
                    }
                    if !in_files && !crate::rules::path_in_languages(&path, &spec.languages) {
                        continue;
                    }
                }
                out.push(id);
            }
            Ok(out)
        };
        let mut sources = keep(self.executable(self.resolve_all(&spec.sources, dataflow)?)?)?;
        // A sink is usually a library call, and a call to one is an edge
        // now, so a stub answers the call-graph question too.
        let mut sinks = keep(self.executable(self.resolve_all(&spec.sinks, true)?)?)?;
        if dataflow {
            // A value question may name a *parameter* as its source —
            // `request`, `handle.request` — which the name index does not
            // hold: parameters are found by a scan, once per spec.
            sources.extend(keep(self.parameters_matching(&spec.sources)?)?);
            // A value question starts at what a source *produces* — its
            // return value (the function symbol) and its inputs — and ends
            // at what a sink *consumes*: its parameters, or the external
            // stub itself.
            sources = self.with_parameters(sources)?;
            sinks = self.with_parameters(sinks)?;
        }
        let sanitizers = keep(self.resolve_all(&spec.sanitizers, dataflow)?)?;

        let live = self.reachable_from_entrypoints()?;
        let live_set: std::collections::HashSet<u32> = live.iter().map(|l| l.get()).collect();

        let mut findings = Vec::new();
        let mut rejected_by_index = 0usize;
        let mut searched = 0usize;

        if dataflow {
            // A value question is answered from the sinks: there are few of
            // them, and one backward search from a sink finds every source
            // whose value reaches it. Searching forward from each source
            // would walk the same flow graph once per source.
            let source_set: std::collections::HashSet<u32> = sources.iter().map(|l| l.get()).collect();
            let mut arrivals = Arrivals::default();
            'sinks: for &sink in &sinks {
                // The labels do not cover value flow; every sink is searched.
                searched += 1;
                let paths = self.value_paths_into(sink, &source_set, &sanitizers, spec.max_hops, spec.context_depth, &mut arrivals)?;
                for (src, path) in paths {
                    if findings.len() >= max_findings {
                        break 'sinks;
                    }
                    let mut infos = Vec::with_capacity(path.len());
                    for id in &path {
                        if let Some(info) = self.engine.info(*id)? {
                            infos.push(info);
                        }
                    }
                    let (Some(source), Some(sink_info)) = (infos.first().cloned(), infos.last().cloned())
                    else {
                        continue;
                    };
                    findings.push(Finding {
                        source,
                        sink: sink_info,
                        confidence: self.path_confidence(&path, mask)?,
                        reachable_from_entrypoint: live_set.contains(&src.get()),
                        path: infos,
                    });
                }
            }
        }

        'outer: for &src in &sources {
            if dataflow {
                break;
            }
            for &sink in &sinks {
                // Checked before doing the work, not after pushing: the
                // after-push form still produces one finding when the cap is
                // zero, and a caller asking for zero means zero.
                if findings.len() >= max_findings {
                    break 'outer;
                }
                if src == sink {
                    continue;
                }
                // The cheap half: the index rejects most pairs without any
                // search at all.
                if !self.engine.index().maybe_reaches(src, sink) {
                    rejected_by_index += 1;
                    continue;
                }
                searched += 1;
                let Some(path) =
                    self.path_avoiding(src, sink, &sanitizers, spec.max_hops, mask)?
                else {
                    continue;
                };

                let mut infos = Vec::with_capacity(path.len());
                for id in &path {
                    if let Some(info) = self.engine.info(*id)? {
                        infos.push(info);
                    }
                }
                let (Some(source), Some(sink_info)) = (infos.first().cloned(), infos.last().cloned())
                else {
                    continue;
                };
                findings.push(Finding {
                    source,
                    sink: sink_info,
                    confidence: self.path_confidence(&path, mask)?,
                    reachable_from_entrypoint: live_set.contains(&src.get()),
                    path: infos,
                });
            }
        }

        // Reachable-from-entrypoint first, then shorter paths, then higher
        // confidence: the order a human should read them in.
        findings.sort_by(|a, b| {
            b.reachable_from_entrypoint
                .cmp(&a.reachable_from_entrypoint)
                .then(a.depth().cmp(&b.depth()))
                .then(a.confidence.cmp(&b.confidence))
        });

        Ok(Analysis {
            findings,
            sources: sources.len(),
            sinks: sinks.len(),
            sanitizers: sanitizers.len(),
            pairs_rejected_by_index: rejected_by_index,
            pairs_searched: searched,
        })
    }

    /// Keep only symbols that can carry taint.
    fn executable(&self, ids: Vec<LocalId>) -> Result<Vec<LocalId>> {
        let mut out = Vec::with_capacity(ids.len());
        for id in ids {
            if let Some(info) = self.engine.info(id)?
                && can_carry_taint(info.kind)
            {
                out.push(id);
            }
        }
        Ok(out)
    }

    /// Parameters a name-style matcher names: exact, prefix, suffix,
    /// contains, or `function.param` as a member.
    fn parameters_matching(&self, matchers: &[Matcher]) -> Result<Vec<LocalId>> {
        let wanted: Vec<&Matcher> = matchers.iter().filter(|m| !matches!(m, Matcher::InPath(_))).collect();
        if wanted.is_empty() {
            return Ok(Vec::new());
        }
        let view = self.engine.store().view();
        let own = RelationMask::of(&[Relation::Contains]);
        let mut out = Vec::new();
        for id in view.ids() {
            if view.kind_raw(id)? != codegraph_core::SymbolKind::Parameter.as_u8() {
                continue;
            }
            let name = view.name(id)?.to_lowercase();
            let hit = wanted.iter().any(|m| match m {
                Matcher::Name(n) => name == *n,
                Matcher::NamePrefix(p) => name.starts_with(p.as_str()),
                Matcher::NameSuffix(p) => name.ends_with(p.as_str()),
                Matcher::NameContains(c) => name.contains(c.as_str()),
                Matcher::Member { type_name, method } => {
                    name == *method
                        && view.in_edges(id, own).ok().into_iter().flatten().any(|e| view.name(e.node).is_ok_and(|o| o.to_lowercase() == *type_name))
                }
                Matcher::InPath(_) => false,
            });
            if hit {
                out.push(id);
            }
        }
        Ok(out)
    }

    fn resolve_all(&self, matchers: &[Matcher], stubs: bool) -> Result<Vec<LocalId>> {
        let mut out = Vec::new();
        for m in matchers {
            out.extend(m.resolve_with(self.engine, stubs)?);
        }
        out.sort_unstable_by_key(|l| l.get());
        out.dedup();
        Ok(out)
    }

    /// Each symbol plus its parameters.
    fn with_parameters(&self, ids: Vec<LocalId>) -> Result<Vec<LocalId>> {
        let own = RelationMask::of(&[Relation::Contains]);
        let mut out = Vec::new();
        for id in ids {
            out.push(id);
            for e in self.engine.neighbors(id, codegraph_query::Direction::Out, own)? {
                if self.engine.kind(e.id)? == codegraph_core::SymbolKind::Parameter {
                    out.push(e.id);
                }
            }
        }
        out.sort_unstable_by_key(|l| l.get());
        out.dedup();
        Ok(out)
    }

    /// A path from `from` to `to` that passes through no sanitiser.
    ///
    /// Implemented as a BFS that refuses to expand a sanitiser rather than by
    /// finding a path and then checking it: a sanitised shortest path does not
    /// mean every path is sanitised, and rejecting on that basis would miss
    /// real findings.
    fn path_avoiding(
        &self,
        from: LocalId,
        to: LocalId,
        sanitizers: &[LocalId],
        max_hops: u32,
        mask: RelationMask,
    ) -> Result<Option<Vec<LocalId>>> {
        if sanitizers.is_empty() {
            return self.engine.shortest_path(from, to, mask, max_hops);
        }
        let blocked: std::collections::HashSet<u32> =
            sanitizers.iter().map(|l| l.get()).collect();
        if blocked.contains(&from.get()) || blocked.contains(&to.get()) {
            return Ok(None);
        }

        let n = self.engine.id_space();
        let mut parent: Vec<u32> = vec![u32::MAX; n];
        parent[from.index()] = from.get();
        let mut queue = std::collections::VecDeque::from([(from, 0u32)]);

        while let Some((node, depth)) = queue.pop_front() {
            if depth >= max_hops {
                continue;
            }
            for e in self.engine.neighbors(node, codegraph_query::Direction::Out, mask)? {
                let t = e.id;
                if t.index() >= n || parent[t.index()] != u32::MAX {
                    continue;
                }
                parent[t.index()] = node.get();
                if t == to {
                    let mut path = vec![to];
                    let mut cur = to;
                    while cur != from {
                        cur = LocalId::new(parent[cur.index()]);
                        path.push(cur);
                    }
                    path.reverse();
                    return Ok(Some(path));
                }
                // A sanitiser is visited but never expanded through, so a path
                // cannot route around it by going deeper.
                if !blocked.contains(&t.get()) {
                    queue.push_back((t, depth + 1));
                }
            }
        }
        Ok(None)
    }

    /// Every source in `sources` whose value reaches `sink` along
    /// `flows_to`, with one path each, avoiding sanitisers. One backward
    /// search from the sink.
    ///
    /// **Context-sensitive.** Every edge into a callee's parameter carries
    /// the call site it enters on, and every edge out of a callee's return
    /// the site it leaves on; the same for a library stub, whose "body" is
    /// nothing. The walk keeps the sites it is inside as a stack: leaving a
    /// callee backwards (through its return) pushes the site, and entering
    /// it backwards (through an argument) must pop the same one — matched
    /// like parentheses, so a value that entered `id` from `a` leaves `id`
    /// into `a` and never into `b`. A path that begins inside a callee has
    /// an empty stack and may leave towards any caller, which is the sound
    /// reading of "the sink is reachable from this parameter". External
    /// data leaves a stub on a site nothing enters on, so a library read
    /// is a source and never a conduit.
    fn value_paths_into(
        &self,
        sink: LocalId,
        sources: &std::collections::HashSet<u32>,
        sanitizers: &[LocalId],
        max_hops: u32,
        context_depth: usize,
        arrivals: &mut Arrivals,
    ) -> Result<Vec<(LocalId, Vec<LocalId>)>> {
        use std::collections::{HashMap, VecDeque};
        let blocked: std::collections::HashSet<u32> = sanitizers.iter().map(|l| l.get()).collect();
        if blocked.contains(&sink.get()) {
            return Ok(Vec::new());
        }
        let view = self.engine.store().view();
        // State: (node, the call sites the forward path is inside, innermost
        // last; `EXTERNAL_SITE` on top means "inside external data").
        type State = (u32, Vec<u32>);
        let start: State = (sink.get(), Vec::new());
        // Child pointers, towards the sink: state -> the state after it on
        // the forward path.
        let mut next: HashMap<State, State> = HashMap::new();
        next.insert(start.clone(), start.clone());
        let mut queue: VecDeque<(State, u32)> = VecDeque::from([(start, 0u32)]);
        let mut found: Vec<(LocalId, Vec<LocalId>)> = Vec::new();
        let mut found_set: std::collections::HashSet<u32> = std::collections::HashSet::new();
        while let Some((state, depth)) = queue.pop_front() {
            if depth >= max_hops {
                continue;
            }
            let node = LocalId::new(state.0);
            let top = state.1.last().map(|&s| (s != EXTERNAL_SITE).then_some(s));
            for (u, leave, enter) in arrivals.arrivals(view, node, top)? {
                // Backwards over `u -> v`: `enter` says the forward step went
                // into a callee — we are leaving it, so pop its site; `leave`
                // says it came out of one — we are entering it, so push.
                let mut stack = state.1.clone();
                if enter.is_some() && !stack.is_empty() {
                    stack.pop();
                }
                if let Some(l) = leave {
                    if stack.len() >= context_depth.max(1) {
                        stack.remove(0);
                    }
                    stack.push(l);
                }
                let prev: State = (u, stack);
                if next.contains_key(&prev) {
                    continue;
                }
                next.insert(prev.clone(), state.clone());
                if sources.contains(&u) && u != sink.get() && !blocked.contains(&u) && found_set.insert(u) {
                    let mut path = vec![LocalId::new(u)];
                    let mut cur = prev.clone();
                    while cur.0 != sink.get() {
                        cur = next[&cur].clone();
                        path.push(LocalId::new(cur.0));
                    }
                    found.push((LocalId::new(u), path));
                }
                // A sanitiser is visited but never expanded through.
                if !blocked.contains(&u) {
                    queue.push_back((prev, depth + 1));
                }
            }
        }
        found.sort_by_key(|(_, p)| p.len());
        Ok(found)
    }

    /// `Direct` only when every edge on the path was `EXTRACTED`.
    fn path_confidence(&self, path: &[LocalId], mask: RelationMask) -> Result<Confidence> {
        let view = self.engine.store().view();
        for pair in path.windows(2) {
            let mut best = None;
            for e in view.out_edges(pair[0], mask)? {
                if e.node == pair[1] {
                    best = Some(e.confidence);
                    break;
                }
            }
            if best != Some(codegraph_core::Confidence::Extracted) {
                return Ok(Confidence::Inferred);
            }
        }
        Ok(Confidence::Direct)
    }

    // --- dependency reachability (SCA) ---

    /// Which of our symbols reach the package named `package`.
    ///
    /// This is the question that separates "we have a vulnerable dependency in
    /// the lockfile" from "we actually call into it": the former is true of
    /// almost every repository, the latter is actionable.
    ///
    /// Returns the files that depend on the package, and whether any of them is
    /// reachable from an entrypoint.
    pub fn package_reach(&self, package: &str) -> Result<Option<PackageReach>> {
        let pkg: Vec<LocalId> = self
            .engine
            .by_name(package)
            .into_iter()
            .filter(|id| {
                self.engine
                    .info(*id)
                    .ok()
                    .flatten()
                    .is_some_and(|i| i.kind == codegraph_core::SymbolKind::Package)
            })
            .collect();
        let Some(&pkg_id) = pkg.first() else { return Ok(None) };

        // Dependents are found by walking *backwards* from the package node
        // along `depends_on`.
        let mask = RelationMask::of(&[Relation::DependsOn]);
        let mut importers = Vec::new();
        for e in self.engine.neighbors(pkg_id, codegraph_query::Direction::In, mask)? {
            if let Some(info) = self.engine.info(e.id)? {
                importers.push(info);
            }
        }
        importers.sort_by(|a, b| a.path.cmp(&b.path));
        importers.dedup_by(|a, b| a.id == b.id);

        let live = self.reachable_from_entrypoints()?;
        let live_set: std::collections::HashSet<u32> = live.iter().map(|l| l.get()).collect();
        let reachable = importers.iter().any(|i| live_set.contains(&i.id.get()));

        Ok(Some(PackageReach { package: package.to_string(), importers, reachable_from_entrypoint: reachable }))
    }

    /// Every external package the corpus depends on, with its importer count.
    pub fn packages(&self) -> Result<Vec<(String, usize)>> {
        let view = self.engine.store().view();
        let mask = RelationMask::of(&[Relation::DependsOn]);
        let mut out = Vec::new();
        for si in 0..view.segment_count() {
            let (seg, base) = view.segment(si);
            let kinds = seg.node_kinds()?;
            let names = seg.node_names()?;
            for l in 0..seg.node_count() {
                let id = LocalId::new(base + l as u32);
                if codegraph_core::SymbolKind::from_u8(kinds[l]) != codegraph_core::SymbolKind::Package
                    || !view.is_canonical(id)
                {
                    continue;
                }
                let n = view.in_edges(id, mask)?.len();
                out.push((seg.string(names[l]).to_string(), n));
            }
        }
        out.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
        Ok(out)
    }
}

#[derive(Debug, Clone)]
pub struct PackageReach {
    pub package: String,
    /// Files that import it.
    pub importers: Vec<SymbolInfo>,
    pub reachable_from_entrypoint: bool,
}

#[derive(Debug, Clone)]
pub struct Analysis {
    pub findings: Vec<Finding>,
    pub sources: usize,
    pub sinks: usize,
    pub sanitizers: usize,
    /// Pairs the reachability index ruled out without searching. Reported
    /// because it is the measure of whether the index is earning its space.
    pub pairs_rejected_by_index: usize,
    pub pairs_searched: usize,
}

impl Analysis {
    pub fn total_pairs(&self) -> usize {
        self.pairs_rejected_by_index + self.pairs_searched
    }
    /// Share of candidate pairs answered without a graph search.
    pub fn rejection_rate(&self) -> f64 {
        if self.total_pairs() == 0 {
            return 0.0;
        }
        self.pairs_rejected_by_index as f64 / self.total_pairs() as f64
    }
}
