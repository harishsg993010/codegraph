//! Deep search: find code by what it is connected to, not only by what it
//! is called.
//!
//! A query is free text plus filters. Each free term is matched against
//! symbol names and paths — whole, by subword (`MaxUploadSize` matches
//! `upload`), by prefix, by substring — and against what a callable's body
//! holds in the graph: its locals and parameters, the callees it names,
//! the variables it references, and the conditions on its control-flow
//! edges. Then the matches **spread** along the graph: a symbol adjacent
//! to a match (its caller, its callee, what references it, what its value
//! flows to) inherits a share of the score, and one adjacent to matches
//! for *different* terms is what the query is usually about — the function
//! that calls `parseUpload` and references `MaxSize` scores for both
//! `upload` and `size` though its own name has neither. Results carry the
//! reasons, so a hit can be trusted or dismissed at a glance.
//!
//! Filters narrow by structure: `kind:function`, `in:routers/`,
//! `calls:Popen`, `called-by:main`, `references:MaxSize`, `reaches:Exec`
//! (a call path exists), `flows-to:Exec` (a value reaches it),
//! `flows-from:FormValue`. A query of filters alone is a structural
//! search; a query of terms alone is a lexical one that follows edges.

use std::collections::{HashMap, HashSet, VecDeque};

use codegraph_core::{LocalId, Relation, RelationMask, SymbolKind};
use codegraph_index::IndexQuery;
use codegraph_store::{node_flags, Result};

use crate::{Direction, Engine, SymbolInfo};

/// A structural filter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Filter {
    Kind(SymbolKind),
    In(String),
    Calls(String),
    CalledBy(String),
    References(String),
    ReferencedBy(String),
    /// A call path from the symbol to a symbol of this name.
    Reaches(String),
    /// A value of the symbol reaches a symbol of this name.
    FlowsTo(String),
    /// A value of a symbol of this name reaches the symbol.
    FlowsFrom(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeepQuery {
    pub terms: Vec<String>,
    pub filters: Vec<Filter>,
    /// How far a match spreads: 1 credits neighbours, 2 (the default)
    /// their neighbours too. `hops:N` in the query, or the CLI flag.
    pub hops: u32,
    /// How many of a term's strongest matches spread (default 400).
    pub seeds: usize,
    /// Most nodes a `reaches:`/`flows-to:`/`flows-from:` filter expands
    /// (default 500,000); a larger target set is cut off, and the report
    /// says so.
    pub reach_limit: usize,
}

pub const DEFAULT_HOPS: u32 = 2;
pub const DEFAULT_SEEDS: usize = 400;
pub const DEFAULT_REACH_LIMIT: usize = 500_000;

impl Default for DeepQuery {
    fn default() -> Self {
        DeepQuery { terms: Vec::new(), filters: Vec::new(), hops: DEFAULT_HOPS, seeds: DEFAULT_SEEDS, reach_limit: DEFAULT_REACH_LIMIT }
    }
}

impl DeepQuery {
    /// `upload limit kind:function in:routers/ calls:Open` — terms and
    /// `key:value` filters in any order; a quoted phrase is one term.
    pub fn parse(text: &str) -> DeepQuery {
        let mut q = DeepQuery::default();
        let mut tokens: Vec<String> = Vec::new();
        let mut cur = String::new();
        let mut quoted = false;
        for ch in text.chars() {
            match ch {
                '"' => quoted = !quoted,
                c if c.is_whitespace() && !quoted => {
                    if !cur.is_empty() {
                        tokens.push(std::mem::take(&mut cur));
                    }
                }
                c => cur.push(c),
            }
        }
        if !cur.is_empty() {
            tokens.push(cur);
        }
        for t in tokens {
            // Tuning, not filters: `hops:3`, `seeds:1000`, `reach-limit:N`.
            if let Some((k, v)) = t.split_once(':')
                && let Ok(n) = v.parse::<usize>()
            {
                match k.to_ascii_lowercase().as_str() {
                    "hops" => {
                        q.hops = n as u32;
                        continue;
                    }
                    "seeds" => {
                        q.seeds = n;
                        continue;
                    }
                    "reach-limit" | "reachlimit" => {
                        q.reach_limit = n;
                        continue;
                    }
                    _ => {}
                }
            }
            let filter = t.split_once(':').and_then(|(k, v)| {
                if v.is_empty() {
                    return None;
                }
                let v = v.to_string();
                Some(match k.to_ascii_lowercase().as_str() {
                    "kind" => Filter::Kind(parse_kind(&v)?),
                    "in" | "path" => Filter::In(v.to_lowercase()),
                    "calls" => Filter::Calls(v),
                    "called-by" | "calledby" | "caller" => Filter::CalledBy(v),
                    "references" | "refs" | "reads" | "uses" => Filter::References(v),
                    "referenced-by" | "referencedby" => Filter::ReferencedBy(v),
                    "reaches" => Filter::Reaches(v),
                    "flows-to" | "flowsto" | "sink" => Filter::FlowsTo(v),
                    "flows-from" | "flowsfrom" | "source" => Filter::FlowsFrom(v),
                    _ => return None,
                })
            });
            match filter {
                Some(f) => q.filters.push(f),
                None => q.terms.push(t.to_lowercase()),
            }
        }
        q
    }
}

fn parse_kind(s: &str) -> Option<SymbolKind> {
    let s = s.to_ascii_lowercase();
    SymbolKind::ALL.iter().copied().find(|k| k.as_str() == s || format!("{k}").to_ascii_lowercase() == s).or(match s.as_str() {
        "func" | "fn" => Some(SymbolKind::Function),
        "var" => Some(SymbolKind::Variable),
        "const" => Some(SymbolKind::Constant),
        "type" | "struct" => Some(SymbolKind::Class),
        _ => None,
    })
}

/// One result.
#[derive(Debug, Clone)]
pub struct DeepHit {
    pub info: SymbolInfo,
    pub score: f32,
    /// Why, one line per term matched or filter satisfied.
    pub reasons: Vec<String>,
}

/// Subwords of an identifier: `MaxUploadSize` → `max`, `upload`, `size`;
/// `read_file` → `read`, `file`. Lowercase.
pub fn subwords(name: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let chars: Vec<char> = name.chars().collect();
    for (i, &c) in chars.iter().enumerate() {
        if !c.is_alphanumeric() {
            if !cur.is_empty() {
                out.push(std::mem::take(&mut cur));
            }
            continue;
        }
        // A boundary at a lower->upper step, and before the last upper of a
        // run followed by lower (`HTTPServer` → `http`, `server`).
        if i > 0 && c.is_uppercase() {
            let prev = chars[i - 1];
            let next_lower = chars.get(i + 1).is_some_and(|n| n.is_lowercase());
            if (prev.is_lowercase() || prev.is_numeric() || (prev.is_uppercase() && next_lower)) && !cur.is_empty() {
                out.push(std::mem::take(&mut cur));
            }
        }
        cur.extend(c.to_lowercase());
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

/// How well `term` matches `name`: exact, a subword, a prefix, a subword's
/// prefix, a substring — or not at all.
/// Does `text` (lower-case) contain `term` in any of the spellings a phrase
/// takes in code: `rate limit`, `ratelimit`, `rate_limit`, `rate-limit`?
fn contains_term(text: &str, term: &str) -> bool {
    if !term.contains(' ') {
        return text.contains(term);
    }
    text.contains(term) || text.contains(&term.replace(' ', "")) || text.contains(&term.replace(' ', "_")) || text.contains(&term.replace(' ', "-"))
}

fn name_quality(term: &str, name: &str) -> Option<f32> {
    let lower = name.to_lowercase();
    if lower == term {
        return Some(1.0);
    }
    let subs = subwords(name);
    if term.contains(' ') {
        // A phrase is a run of subwords: `rate limit` is in `RateLimitError`.
        let joined = subs.join(" ");
        if joined == term {
            return Some(1.0);
        }
        if joined.contains(term) {
            return Some(0.9);
        }
        return if contains_term(&lower, term) { Some(0.55) } else { None };
    }
    if subs.iter().any(|s| s == term) {
        return Some(0.9);
    }
    if lower.starts_with(term) {
        return Some(0.8);
    }
    if subs.iter().any(|s| s.starts_with(term)) {
        return Some(0.7);
    }
    if lower.contains(term) {
        return Some(0.55);
    }
    None
}

/// The last path segment without extension, and every segment: a term
/// matching the file name counts more than one matching a directory.
fn path_quality(term: &str, path: &str) -> Option<f32> {
    let lower = path.to_lowercase();
    let file = lower.rsplit('/').next().unwrap_or(&lower);
    let stem = file.rsplit_once('.').map(|(s, _)| s).unwrap_or(file);
    if let Some(q) = name_quality(term, stem) {
        return Some(q * 0.6);
    }
    if contains_term(&lower, term) {
        return Some(0.3);
    }
    None
}

/// Kinds a result can be. Structure (blocks, parameters, locals) and files
/// are matched but credited to what owns them — unless the query asks for
/// that kind (`kind:parameter flows-to:Exec`).
fn is_result_kind(kind: SymbolKind, asked: Option<SymbolKind>) -> bool {
    asked == Some(kind) || !matches!(kind, SymbolKind::Block | SymbolKind::Parameter | SymbolKind::Local | SymbolKind::File | SymbolKind::Package)
}

/// The relations a match spreads along, and the words for them.
const SPREAD: RelationMask = RelationMask::of(&[
    Relation::Calls,
    Relation::IndirectCall,
    Relation::References,
    Relation::FlowsTo,
    Relation::Method,
    Relation::Contains,
    Relation::Inherits,
    Relation::Extends,
    Relation::Implements,
]);

/// A match a symbol collects for one term, with the best reason.
#[derive(Clone)]
struct Credit {
    score: f32,
    reason: String,
}

fn credit(map: &mut HashMap<u32, Credit>, id: u32, score: f32, reason: impl FnOnce() -> String) {
    match map.get_mut(&id) {
        Some(c) if c.score >= score => {}
        Some(c) => {
            c.score = score;
            c.reason = reason();
        }
        None => {
            map.insert(id, Credit { score, reason: reason() });
        }
    }
}

impl<I: IndexQuery> Engine<I> {
    /// Deep search: see the module documentation.
    pub fn deep_search(&self, q: &DeepQuery, limit: usize) -> Result<Vec<DeepHit>> {
        let view = self.view();
        let owner_of = |id: LocalId| -> Result<Option<LocalId>> {
            let own = RelationMask::of(&[Relation::Contains, Relation::Method]);
            for e in view.in_edges(id, own)? {
                if view.flags(e.node)? & codegraph_store::node_flags::FILE_NODE == 0 {
                    return Ok(Some(e.node));
                }
            }
            Ok(None)
        };
        let name_of = |id: LocalId| -> Result<String> { Ok(view.name(id)?.to_string()) };

        // --- per term: direct and body matches, then spreading ---
        let mut per_term: Vec<HashMap<u32, Credit>> = Vec::with_capacity(q.terms.len());
        for term in &q.terms {
            let mut m: HashMap<u32, Credit> = HashMap::new();
            let candidates: Vec<LocalId> = if let Some((first, _)) = term.split_once(' ') {
                // A phrase: every word in the name or path, in some spelling.
                let words: Vec<&str> = term.split(' ').collect();
                let mut v = Vec::new();
                for id in self.search_with(first, true)? {
                    let text = format!("{} {}", view.norm_name(id)?, view.path(id)?.to_lowercase());
                    if words.iter().all(|w| text.contains(w)) {
                        v.push(id);
                    }
                }
                v
            } else if term.chars().count() >= 3 {
                self.search_with(term, true)?
            } else {
                let mut v = self.by_exact_name_any(term);
                v.extend(self.by_prefix(term));
                v
            };
            for id in candidates {
                let kind = SymbolKind::from_u8(view.kind_raw(id)?);
                let name = view.name(id)?;
                let path = view.path(id)?;
                let nq = name_quality(term, name);
                let pq = path_quality(term, path);
                match kind {
                    // Structure credits its owner as a body match.
                    SymbolKind::Local | SymbolKind::Parameter => {
                        if let (Some(qn), Some(owner)) = (nq, owner_of(id)?) {
                            let what = if kind == SymbolKind::Local { "local" } else { "parameter" };
                            let n = name.to_string();
                            credit(&mut m, owner.get(), qn * 0.75, || format!("{what} `{n}` matches '{term}'"));
                            if kind == SymbolKind::Parameter {
                                credit(&mut m, id.get(), qn, || format!("name matches '{term}'"));
                            }
                        }
                    }
                    SymbolKind::Block => {}
                    _ => {
                        if let Some(qn) = nq {
                            credit(&mut m, id.get(), qn, || format!("name matches '{term}'"));
                        }
                        if let Some(qp) = pq {
                            credit(&mut m, id.get(), qp, || format!("path matches '{term}'"));
                        }
                    }
                }
            }
            per_term.push(m);
        }

        // Conditions on control-flow edges: one pass over the blocks'
        // successors, every term at once. A callable whose branch tests
        // `size > limit` is about `limit`.
        if !q.terms.is_empty() {
            let succ = RelationMask::of(&[Relation::Succeeds]);
            let own = RelationMask::of(&[Relation::Contains]);
            // Blocks are reached from their callables, which is one pass
            // over `contains` rather than an in-edge lookup per block.
            let mut block_owner: HashMap<u32, u32> = HashMap::new();
            for id in view.ids() {
                let k = SymbolKind::from_u8(view.kind_raw(id)?);
                if !matches!(k, SymbolKind::Function | SymbolKind::Method) {
                    continue;
                }
                for e in view.out_edges(id, own)? {
                    if view.kind_raw(e.node)? == SymbolKind::Block.as_u8() {
                        block_owner.insert(e.node.get(), id.get());
                    }
                }
            }
            for (block, owner) in block_owner {
                let id = LocalId::new(block);
                for e in view.out_edges(id, succ)? {
                    let Some(ctx) = e.context else { continue };
                    let lower = ctx.to_lowercase();
                    for (ti, term) in q.terms.iter().enumerate() {
                        if contains_term(&lower, term) {
                            let c = ctx.trim_start_matches("then: ").trim_start_matches("else: ").to_string();
                            credit(&mut per_term[ti], owner, 0.7, || format!("condition `{c}` matches '{term}'"));
                        }
                    }
                }
            }
        }

        // Spreading: a neighbour of a match inherits half its score, twice
        // removed a quarter; hubs are not expanded (everything is next to
        // `Sprintf`). The neighbour's reason names the match.
        for m in &mut per_term {
            // The strongest matches spread; a term that matches thousands
            // of names (`size`) spreads from its best few hundred.
            let mut seeds: Vec<(u32, f32, String)> = m.iter().map(|(id, c)| (*id, c.score, c.reason.clone())).collect();
            seeds.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal).then(a.0.cmp(&b.0)));
            seeds.truncate(q.seeds.max(1));
            let hub = self.index.hub_cutoff();
            let mut frontier: Vec<(u32, f32, String, u32)> = seeds.into_iter().map(|(id, s, r)| (id, s, r, 0)).collect();
            let mut hops = 0;
            while hops < q.hops && !frontier.is_empty() && frontier.len() <= 5_000 {
                hops += 1;
                let mut next = Vec::new();
                for (id, score, _reason, _) in &frontier {
                    let node = LocalId::new(*id);
                    // A library stub is not a connection between its callers
                    // (`Sprintf` is next to everything); nor is a hub.
                    if self.index.degree(node) >= hub || view.flags(node)? & node_flags::EXTERNAL != 0 {
                        continue;
                    }
                    let src_name = name_of(node)?;
                    let src_kind = SymbolKind::from_u8(view.kind_raw(node)?);
                    let share = score * if hops == 1 { 0.5 } else { 0.25 };
                    for (dir, edges) in [(Direction::Out, view.out_edges(node, SPREAD)?), (Direction::In, view.in_edges(node, SPREAD)?)] {
                        for e in edges {
                            let target = e.node;
                            let tk = SymbolKind::from_u8(view.kind_raw(target)?);
                            if matches!(tk, SymbolKind::Block | SymbolKind::Local | SymbolKind::Parameter | SymbolKind::File) {
                                continue;
                            }
                            // A parameter matched by name credits its callee's
                            // callers weakly; structure between a matched
                            // owner and its members is not a "connection".
                            if src_kind == SymbolKind::File {
                                continue;
                            }
                            // The reason is the neighbour's: an edge *out* of
                            // the match into it reads, from its side, as
                            // "called by the match".
                            let verb = match (e.relation, dir) {
                                (Relation::Calls | Relation::IndirectCall, Direction::Out) => "called by",
                                (Relation::Calls | Relation::IndirectCall, Direction::In) => "calls",
                                (Relation::References, Direction::Out) => "referenced by",
                                (Relation::References, Direction::In) => "references",
                                (Relation::FlowsTo, Direction::Out) => "receives the value of",
                                (Relation::FlowsTo, Direction::In) => "its value reaches",
                                (Relation::Method | Relation::Contains, Direction::Out) => "member of",
                                (Relation::Method | Relation::Contains, Direction::In) => "owns",
                                (_, Direction::Out) => "extended by",
                                (_, Direction::In) => "extends",
                            };
                            // A neighbour everything is next to (a logger, a
                            // context type) is not made relevant by one match.
                            let deg = self.index.degree(target) as f32;
                            let share = if deg > 50.0 { share * 50.0 / deg } else { share };
                            let n = src_name.clone();
                            let before = m.get(&target.get()).map(|c| c.score).unwrap_or(0.0);
                            if share > before && share >= 0.05 {
                                credit(m, target.get(), share, || format!("{verb} {n}"));
                                next.push((target.get(), share, String::new(), hops));
                            }
                        }
                    }
                }
                frontier = next;
            }
        }

        // --- filters ---
        let named = |name: &str| -> Vec<LocalId> {
            let mut v = self.by_qualified_name(name);
            if v.is_empty() {
                v = self.search(name).unwrap_or_default();
            }
            v
        };
        let calls = RelationMask::of(&[Relation::Calls, Relation::IndirectCall]);
        let refs = RelationMask::of(&[Relation::References]);
        // Precomputed sets for the reachability filters.
        let mut reach_sets: Vec<(usize, HashSet<u32>)> = Vec::new();
        for (fi, f) in q.filters.iter().enumerate() {
            let (targets, mask, backwards) = match f {
                Filter::Reaches(n) => (named(n), Relation::TAINT, true),
                Filter::FlowsTo(n) => (named(n), Relation::DATA_FLOW, true),
                Filter::FlowsFrom(n) => (named(n), Relation::DATA_FLOW, false),
                _ => continue,
            };
            let mut seen: HashSet<u32> = HashSet::new();
            let mut queue: VecDeque<LocalId> = VecDeque::new();
            for t in targets {
                if seen.insert(t.get()) {
                    queue.push_back(t);
                }
            }
            while let Some(v) = queue.pop_front() {
                let edges = if backwards { view.in_edges(v, mask)? } else { view.out_edges(v, mask)? };
                for e in edges {
                    if seen.insert(e.node.get()) {
                        queue.push_back(e.node);
                    }
                }
                if seen.len() > q.reach_limit {
                    break;
                }
            }
            reach_sets.push((fi, seen));
        }
        let has_edge = |id: LocalId, dir: Direction, mask: RelationMask, name: &str| -> Result<Option<String>> {
            let want: HashSet<u32> = named(name).into_iter().map(|l| l.get()).collect();
            let edges = match dir {
                Direction::Out => view.out_edges(id, mask)?,
                Direction::In => view.in_edges(id, mask)?,
            };
            for e in edges {
                if want.contains(&e.node.get()) {
                    return Ok(Some(view.name(e.node)?.to_string()));
                }
            }
            Ok(None)
        };
        let passes = |id: LocalId, info: &SymbolInfo, reasons: &mut Vec<String>| -> Result<bool> {
            for (fi, f) in q.filters.iter().enumerate() {
                let ok = match f {
                    Filter::Kind(k) => info.kind == *k,
                    Filter::In(p) => info.path.to_lowercase().contains(p),
                    Filter::Calls(n) => match has_edge(id, Direction::Out, calls, n)? {
                        Some(t) => {
                            reasons.push(format!("calls {t}"));
                            true
                        }
                        None => false,
                    },
                    Filter::CalledBy(n) => match has_edge(id, Direction::In, calls, n)? {
                        Some(t) => {
                            reasons.push(format!("called by {t}"));
                            true
                        }
                        None => false,
                    },
                    Filter::References(n) => match has_edge(id, Direction::Out, refs, n)? {
                        Some(t) => {
                            reasons.push(format!("references {t}"));
                            true
                        }
                        None => false,
                    },
                    Filter::ReferencedBy(n) => match has_edge(id, Direction::In, refs, n)? {
                        Some(t) => {
                            reasons.push(format!("referenced by {t}"));
                            true
                        }
                        None => false,
                    },
                    Filter::Reaches(n) | Filter::FlowsTo(n) | Filter::FlowsFrom(n) => {
                        let set = reach_sets.iter().find(|(i, _)| *i == fi).map(|(_, s)| s);
                        let hit = set.is_some_and(|s| s.contains(&id.get()));
                        if hit {
                            reasons.push(match f {
                                Filter::Reaches(_) => format!("a call path reaches {n}"),
                                Filter::FlowsTo(_) => format!("its value reaches {n}"),
                                _ => format!("receives a value of {n}"),
                            });
                        }
                        hit
                    }
                };
                if !ok {
                    return Ok(false);
                }
            }
            Ok(true)
        };

        // --- combine ---
        let asked = q.filters.iter().find_map(|f| if let Filter::Kind(k) = f { Some(*k) } else { None });
        let mut candidates: HashSet<u32> = HashSet::new();
        if q.terms.is_empty() {
            for id in view.ids() {
                if is_result_kind(SymbolKind::from_u8(view.kind_raw(id)?), asked) {
                    candidates.insert(id.get());
                }
            }
        } else {
            for m in &per_term {
                candidates.extend(m.keys().copied());
            }
        }
        let mut hits: Vec<DeepHit> = Vec::new();
        for c in candidates {
            let id = LocalId::new(c);
            if !view.is_canonical(id) {
                continue;
            }
            let Some(info) = self.info(id)? else { continue };
            if !is_result_kind(info.kind, asked) || info.external {
                continue;
            }
            let mut reasons = Vec::new();
            let mut score = 0.0f32;
            let mut matched = 0usize;
            for (ti, m) in per_term.iter().enumerate() {
                if let Some(cr) = m.get(&c) {
                    score += cr.score;
                    matched += 1;
                    reasons.push(cr.reason.clone());
                } else {
                    reasons.push(format!("(nothing for '{}')", q.terms[ti]));
                }
            }
            if !q.terms.is_empty() && matched == 0 {
                continue;
            }
            if !passes(id, &info, &mut reasons)? {
                continue;
            }
            // Every term matched is worth more than one matched twice; a
            // well-connected symbol breaks ties.
            score += 0.5 * matched.saturating_sub(1) as f32;
            score += (1.0 + info.degree as f32).ln() / 40.0;
            // Two terms met through the same neighbour say so once.
            let mut seen_reason: HashSet<String> = HashSet::new();
            reasons.retain(|r| seen_reason.insert(r.clone()));
            hits.push(DeepHit { info, score, reasons });
        }
        hits.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap_or(std::cmp::Ordering::Equal).then_with(|| a.info.path.cmp(&b.info.path)).then_with(|| a.info.line.cmp(&b.info.line)));
        hits.truncate(limit);
        Ok(hits)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subwords_split_camel_and_snake() {
        assert_eq!(subwords("MaxUploadSize"), ["max", "upload", "size"]);
        assert_eq!(subwords("read_file_v2"), ["read", "file", "v2"]);
        assert_eq!(subwords("HTTPServer"), ["http", "server"]);
        assert_eq!(subwords("getURL"), ["get", "url"]);
    }

    #[test]
    fn queries_parse_terms_and_filters() {
        let q = DeepQuery::parse(r#"upload "size limit" kind:function in:routers/ calls:Open flows-to:Exec"#);
        assert_eq!(q.terms, ["upload", "size limit"]);
        assert_eq!(
            q.filters,
            [Filter::Kind(SymbolKind::Function), Filter::In("routers/".into()), Filter::Calls("Open".into()), Filter::FlowsTo("Exec".into())]
        );
        // An unknown key is a term.
        assert_eq!(DeepQuery::parse("http:server").terms, ["http:server"]);
        // Tuning keys are consumed.
        let q = DeepQuery::parse("upload hops:3 seeds:50 reach-limit:1000");
        assert_eq!(q.terms, ["upload"]);
        assert!(q.filters.is_empty());
        assert_eq!((q.hops, q.seeds, q.reach_limit), (3, 50, 1000));
        assert_eq!(DeepQuery::parse("x").hops, DEFAULT_HOPS);
    }

    #[test]
    fn name_quality_prefers_whole_and_subword_matches() {
        assert_eq!(name_quality("upload", "upload"), Some(1.0));
        assert_eq!(name_quality("upload", "MaxUploadSize"), Some(0.9));
        assert_eq!(name_quality("upl", "upload_file"), Some(0.8));
        assert_eq!(name_quality("upl", "file_upload"), Some(0.7));
        assert_eq!(name_quality("load", "upload"), Some(0.55));
        assert_eq!(name_quality("zzz", "upload"), None);
        assert_eq!(name_quality("rate limit", "RateLimitError"), Some(0.9));
        assert_eq!(name_quality("rate limit", "rate_limit"), Some(1.0));
        assert_eq!(name_quality("rate limit", "ratelimiter"), Some(0.55));
        assert_eq!(name_quality("rate limit", "limit_rate"), None);
    }
}
