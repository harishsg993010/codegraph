//! The read surface: lookup, traversal, paths, reachability.
//!
//! Every operation here is served from the store's mmap'd columns and the
//! derived index. Nothing scans the whole graph at query time — that was the
//! design constraint, and the places where it would have been easy to do so
//! (the hub cutoff, document frequency, degree ranking) read a precomputed
//! column instead.

use std::collections::VecDeque;

use codegraph_core::{Confidence, LocalId, Relation, RelationMask, SymbolKey};
use codegraph_index::{IndexData, IndexQuery};
use codegraph_store::{Result, Store, View};

pub mod deep;
pub mod rank;

pub use deep::{DeepHit, DeepQuery, Filter};

/// Edge counts grouped by relation and by confidence.
pub type EdgeHistogram = (Vec<(Relation, usize)>, Vec<(Confidence, usize)>);

/// A symbol, resolved for presentation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SymbolInfo {
    pub id: LocalId,
    pub key: SymbolKey,
    pub name: String,
    pub path: String,
    pub line: u32,
    pub kind: codegraph_core::SymbolKind,
    pub file_type: codegraph_core::FileType,
    pub degree: u32,
    /// A package or library stub the corpus does not define; `path` is then
    /// the file that first mentioned it, not a definition site.
    pub external: bool,
}

/// One step of a traversal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Hit {
    pub id: LocalId,
    pub depth: u32,
    pub via: Relation,
    /// The call/import **site** in the traversed edge's own file — not the
    /// target's definition line.
    pub via_line: u32,
}

/// One basic block of a callable's stored control-flow graph.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockInfo {
    pub id: LocalId,
    pub index: u32,
    pub line: u32,
    /// `(successor index, label)`: the label names the branch and the
    /// predicate the edge assumes, e.g. `then: x == 1`.
    pub successors: Vec<(u32, String)>,
    /// Non-local symbols written / read in this block.
    pub defines: Vec<LocalId>,
    pub uses: Vec<LocalId>,
}

/// Which way to walk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// Follow outgoing edges: "what does this use".
    Out,
    /// Follow incoming edges: "what would break if this changed".
    In,
}

/// Traversal knobs.
#[derive(Debug, Clone, Copy)]
pub struct Walk {
    pub depth: u32,
    pub relations: RelationMask,
    pub direction: Direction,
    /// Stop expanding *through* a node whose degree is at or above the index's
    /// hub threshold. It is still reported — a hub is usually the answer — but
    /// walking through it would pull in most of the graph.
    pub suppress_hubs: bool,
    /// Hard cap on nodes visited, so a pathological graph cannot hang a caller.
    pub max_nodes: usize,
}

impl Default for Walk {
    fn default() -> Self {
        Self {
            depth: 2,
            // Everything but the CFG and the locals: a walk from a function
            // should not wander into its own blocks or variables unless asked.
            relations: RelationMask::ALL.minus(Relation::CFG).minus(Relation::LOCALS),
            direction: Direction::Out,
            suppress_hubs: true,
            max_nodes: 10_000,
        }
    }
}

/// A store plus its derived index, ready to answer queries.
///
/// Generic over the index backing so the same engine serves an owned
/// [`IndexData`] (what a build produces) and a `MappedIndex` (what a reader
/// opens). Defaulted to the owned form so existing callers are unchanged, and
/// generic rather than `dyn` so the reachability filter — which runs per
/// candidate pair — stays a direct call.
pub struct Engine<I: IndexQuery = IndexData> {
    store: Store,
    index: I,
}

impl<I: IndexQuery> std::fmt::Debug for Engine<I> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Engine")
            .field("symbols", &self.index.symbols())
            .field("hub_threshold", &self.index.hub_cutoff())
            .field("components", &self.index.components())
            .finish()
    }
}

impl Engine<IndexData> {
    /// Open a compacted store and build its index.
    pub fn open(root: impl AsRef<std::path::Path>) -> Result<Self> {
        let store = Store::open(root)?;
        let index = IndexData::build(&store)?;
        Ok(Self { store, index })
    }
}

impl<I: IndexQuery> Engine<I> {
    pub fn from_parts(store: Store, index: I) -> Self {
        Self { store, index }
    }

    pub fn store(&self) -> &Store {
        &self.store
    }
    pub fn index(&self) -> &I {
        &self.index
    }
    /// Size of the id space: every row, live or not. What a per-id array
    /// has to be sized to. Not a symbol count — see [`Self::symbol_count`].
    pub fn id_space(&self) -> usize {
        self.store.view().node_count()
    }

    /// Live symbols. Not the id-space size: a store with deltas numbers its
    /// dead rows too, and those are nobody's symbols.
    pub fn symbol_count(&self) -> usize {
        let view = self.store.view();
        if view.is_simple() { self.index.symbols() } else { view.ids().count() }
    }

    /// The store-wide view. Everything below reads through this, so a store
    /// holding a base plus deltas answers exactly as a compacted one would.
    fn view(&self) -> View<'_> {
        self.store.view()
    }

    /// Every live symbol, ascending by id.
    pub fn ids(&self) -> impl Iterator<Item = LocalId> + '_ {
        self.store.view().ids()
    }

    /// Node flags of a symbol (`node_flags::*`).
    pub fn flags(&self, id: LocalId) -> Result<u8> {
        self.view().flags(id)
    }

    pub fn kind(&self, id: LocalId) -> Result<codegraph_core::SymbolKind> {
        Ok(codegraph_core::SymbolKind::from_u8(self.view().kind_raw(id)?))
    }

    // --- lookup ---

    pub fn by_key(&self, key: SymbolKey) -> Result<Option<LocalId>> {
        Ok(self.view().find(key))
    }

    /// Symbols whose folded name is exactly `name`.
    ///
    /// Postings are filtered by liveness: an index's base layer still lists
    /// the rows a later delta superseded. External callee stubs are left
    /// out — `explain Verify` means the corpus's `Verify`, not the unresolved
    /// call that shares its name — see [`Self::by_name_with_stubs`].
    pub fn by_name(&self, name: &str) -> Vec<LocalId> {
        self.by_name_with_stubs(name)
            .into_iter()
            .filter(|id| !self.is_stub(*id))
            .collect()
    }

    /// As [`Self::by_name`], including external callee stubs — what a sink
    /// matcher wants, since most sinks are library calls.
    pub fn by_name_with_stubs(&self, name: &str) -> Vec<LocalId> {
        self.by_exact_name_any(name).into_iter().filter(|id| !self.is_parameter(*id)).collect()
    }

    /// Every canonical row with exactly this name: stubs, locals and
    /// parameters included. Parameters are one callable's business and
    /// are left out of the other lookups; `deep` and the qualified form
    /// `handle.request` want them.
    pub fn by_exact_name_any(&self, name: &str) -> Vec<LocalId> {
        let view = self.view();
        self.index
            .by_exact_name(&name.trim().trim_end_matches("()").to_lowercase())
            .into_iter()
            .map(LocalId::new)
            .filter(|id| view.is_canonical(*id))
            .collect()
    }

    /// Is this row a parameter?
    pub fn is_parameter(&self, id: LocalId) -> bool {
        self.view().kind_raw(id).is_ok_and(|k| k == codegraph_core::SymbolKind::Parameter.as_u8())
    }

    /// Symbols by bare or qualified name, stubs included: `Command`, or
    /// `exec.Command` — the member of an owner called `exec`, where a
    /// package answers to its last segment too (`os/exec`). When the name
    /// is exactly the spelling of one candidate among several that fold
    /// together, that one.
    pub fn by_qualified_name(&self, name: &str) -> Vec<LocalId> {
        let view = self.view();
        let exact = |hits: Vec<LocalId>, name: &str| -> Vec<LocalId> {
            if hits.len() <= 1 {
                return hits;
            }
            let same: Vec<LocalId> = hits.iter().copied().filter(|id| view.name(*id).is_ok_and(|n| n == name)).collect();
            if same.is_empty() { hits } else { same }
        };
        let Some((owner, member)) = name.rsplit_once('.') else {
            return exact(self.by_name_with_stubs(name), name);
        };
        let own = RelationMask::of(&[Relation::Contains, Relation::Method]);
        let mut out = Vec::new();
        for id in self.by_exact_name_any(member) {
            let Ok(edges) = view.in_edges(id, own) else { continue };
            for e in edges {
                let Ok(n) = view.name(e.node) else { continue };
                if n == owner || n.rsplit(['/', ':']).next() == Some(owner) {
                    out.push(id);
                    break;
                }
            }
        }
        exact(out, member)
    }

    /// Symbols whose folded name starts with `prefix`.
    pub fn by_prefix(&self, prefix: &str) -> Vec<LocalId> {
        let view = self.view();
        self.index
            .by_name_prefix(&prefix.trim().to_lowercase())
            .into_iter()
            .map(LocalId::new)
            .filter(|id| view.is_canonical(*id) && !self.is_stub(*id) && !self.is_parameter(*id))
            .collect()
    }

    /// A callable's parameters in declared order, with their positions.
    pub fn parameters(&self, id: LocalId) -> Result<Vec<(u32, LocalId)>> {
        let view = self.view();
        let own = RelationMask::of(&[Relation::Contains]);
        let mut out = Vec::new();
        for e in view.out_edges(id, own)? {
            if codegraph_core::SymbolKind::from_u8(view.kind_raw(e.node)?) == codegraph_core::SymbolKind::Parameter {
                let pos = e.context.and_then(|c| c.parse::<u32>().ok()).unwrap_or(u32::MAX);
                out.push((pos, e.node));
            }
        }
        out.sort();
        Ok(out)
    }

    /// A callable's stored CFG, in block order. Empty for anything that is
    /// not a callable, or was indexed without one.
    pub fn cfg(&self, id: LocalId) -> Result<Vec<BlockInfo>> {
        let view = self.view();
        let own = RelationMask::of(&[Relation::Contains]);
        let mut blocks = Vec::new();
        for e in view.out_edges(id, own)? {
            if codegraph_core::SymbolKind::from_u8(view.kind_raw(e.node)?) != codegraph_core::SymbolKind::Block {
                continue;
            }
            let index = e.context.and_then(|c| c.parse::<u32>().ok()).unwrap_or(u32::MAX);
            let succ = RelationMask::of(&[Relation::Succeeds]);
            let mut successors = Vec::new();
            for s in view.out_edges(e.node, succ)? {
                // The successor's index is on the function's `contains` edge
                // to it; cheaper to read the block's name, `b<n>`.
                let n = view.name(s.node)?.trim_start_matches('b').parse::<u32>().unwrap_or(u32::MAX);
                successors.push((n, s.context.unwrap_or("").to_string()));
            }
            successors.sort();
            let defines = view.out_edges(e.node, RelationMask::of(&[Relation::Defines]))?.iter().map(|d| d.node).collect();
            let uses = view.out_edges(e.node, RelationMask::of(&[Relation::Uses]))?.iter().map(|d| d.node).collect();
            blocks.push(BlockInfo { id: e.node, index, line: view.line(e.node)?, successors, defines, uses });
        }
        blocks.sort_by_key(|b| b.index);
        Ok(blocks)
    }

    /// An external callee stub: a callable the corpus does not define, minted
    /// because a value flows into it.
    pub fn is_stub(&self, id: LocalId) -> bool {
        let view = self.view();
        view.flags(id).is_ok_and(|f| f & codegraph_store::node_flags::EXTERNAL != 0)
            && view.kind_raw(id).is_ok_and(|k| codegraph_core::SymbolKind::from_u8(k) != codegraph_core::SymbolKind::Package)
    }

    /// Substring search over name and path.
    ///
    /// The trigram index is a *prefilter*, so every candidate is verified
    /// against the real text before being returned. A needle too short to
    /// produce a trigram falls back to a full scan rather than returning
    /// nothing.
    pub fn search(&self, needle: &str) -> Result<Vec<LocalId>> {
        self.search_with(needle, false)
    }

    /// [`Self::search`], with parameters among the results when asked.
    pub fn search_with(&self, needle: &str, parameters: bool) -> Result<Vec<LocalId>> {
        let view = self.view();
        let needle = needle.to_lowercase();
        if needle.is_empty() {
            return Ok(Vec::new());
        }
        let matches = |id: LocalId| -> Result<bool> {
            if !parameters && view.kind_raw(id)? == codegraph_core::SymbolKind::Parameter.as_u8() {
                return Ok(false);
            }
            Ok(view.norm_name(id)?.contains(&needle)
                || view.path(id)?.to_lowercase().contains(&needle))
        };
        let mut out = Vec::new();
        match self.index.trigram_candidates(&needle) {
            Some(cands) => {
                for c in cands {
                    let id = LocalId::new(c);
                    if view.is_canonical(id) && matches(id)? {
                        out.push(id);
                    }
                }
            }
            None => {
                for id in view.ids() {
                    if matches(id)? {
                        out.push(id);
                    }
                }
            }
        }
        Ok(out)
    }

    /// `None` for an id that is out of range or no longer live.
    pub fn info(&self, id: LocalId) -> Result<Option<SymbolInfo>> {
        let view = self.view();
        if !view.is_canonical(id) {
            return Ok(None);
        }
        Ok(Some(SymbolInfo {
            id,
            key: view.key(id)?,
            name: view.name(id)?.to_string(),
            path: view.path(id)?.to_string(),
            line: view.line(id)?,
            kind: codegraph_core::SymbolKind::from_u8(view.kind_raw(id)?),
            file_type: codegraph_core::FileType::from_u8(view.file_type_raw(id)?),
            degree: self.index.degree(id),
            external: view.flags(id)? & codegraph_store::node_flags::EXTERNAL != 0,
        }))
    }

    // --- neighbourhood ---

    /// One hop, in either direction, filtered by relation.
    pub fn neighbors(&self, id: LocalId, dir: Direction, mask: RelationMask) -> Result<Vec<Hit>> {
        self.step(id, dir, mask, 1)
    }

    /// One hop from `id`, reported at `depth`.
    fn step(&self, id: LocalId, dir: Direction, mask: RelationMask, depth: u32) -> Result<Vec<Hit>> {
        let view = self.view();
        let edges = match dir {
            Direction::Out => view.out_edges(id, mask)?,
            Direction::In => view.in_edges(id, mask)?,
        };
        Ok(edges
            .into_iter()
            .map(|e| Hit { id: e.node, depth, via: e.relation, via_line: e.line })
            .collect())
    }

    // --- traversal ---

    /// Bounded breadth-first walk from `seeds`.
    ///
    /// Level-synchronous, so a node is reported at its true shortest depth
    /// rather than whichever depth reached it first.
    pub fn walk(&self, seeds: &[LocalId], w: Walk) -> Result<Vec<Hit>> {
        let view = self.view();
        let n = view.node_count();
        // A dense bitvec rather than a hash set: the visited test is the
        // innermost operation in the walk, and at this size a bit is cheaper
        // than a hash even when the visited set stays small.
        let mut seen = vec![false; n];
        let mut out = Vec::new();
        let mut queue: VecDeque<(LocalId, u32)> = VecDeque::new();

        for &s in seeds {
            if view.is_canonical(s) && !seen[s.index()] {
                seen[s.index()] = true;
                queue.push_back((s, 0));
            }
        }

        while let Some((node, depth)) = queue.pop_front() {
            if depth >= w.depth || out.len() >= w.max_nodes {
                continue;
            }
            // A hub is reported by whoever reached it, but not expanded
            // through. Seeds are exempt: the caller asked about that node.
            if w.suppress_hubs && depth > 0 && self.index.is_hub(node) {
                continue;
            }
            for hit in self.step(node, w.direction, w.relations, depth + 1)? {
                if hit.id.index() >= n || seen[hit.id.index()] {
                    continue;
                }
                seen[hit.id.index()] = true;
                out.push(hit);
                if out.len() >= w.max_nodes {
                    break;
                }
                queue.push_back((hit.id, depth + 1));
            }
        }
        Ok(out)
    }

    /// "What breaks if this changes" — the reverse walk.
    pub fn blast_radius(&self, id: LocalId, depth: u32) -> Result<Vec<Hit>> {
        self.walk(
            &[id],
            Walk {
                depth,
                relations: Relation::BLAST_RADIUS,
                direction: Direction::In,
                ..Walk::default()
            },
        )
    }

    // --- paths ---

    /// Shortest path from `a` to `b`, as a node sequence including both ends.
    ///
    /// Bidirectional BFS: two frontiers of radius d/2 instead of one of radius
    /// d, which on a branching graph is the difference between thousands of
    /// nodes and millions. Determinism comes from `LocalId` order — the
    /// frontier is expanded in id order, so the same store always yields the
    /// same path.
    pub fn shortest_path(
        &self,
        a: LocalId,
        b: LocalId,
        mask: RelationMask,
        max_hops: u32,
    ) -> Result<Option<Vec<LocalId>>> {
        let view = self.view();
        let n = view.node_count();
        if !view.is_canonical(a) || !view.is_canonical(b) {
            return Ok(None);
        }
        if a == b {
            return Ok(Some(vec![a]));
        }

        // Reject before searching when the labels already prove there is no
        // path — the whole point of the reachability index.
        //
        // Only when the index actually covers this mask. The labels are built
        // over flow relations, so consulting them for a wider query would
        // reject paths that run along relations the index never saw. That is a
        // silent wrong answer, not a slow one.
        if self.index.covers(mask) && !self.index.maybe_reaches(a, b) {
            return Ok(None);
        }

        const NONE: u32 = u32::MAX;
        let mut from_a = vec![NONE; n];
        let mut from_b = vec![NONE; n];
        from_a[a.index()] = a.get();
        from_b[b.index()] = b.get();
        let mut qa = VecDeque::from([a]);
        let mut qb = VecDeque::from([b]);
        let mut da = 0u32;
        let mut db = 0u32;

        while !qa.is_empty() && !qb.is_empty() {
            if da + db >= max_hops {
                return Ok(None);
            }
            // Expand the smaller frontier — that is what keeps the search
            // balanced when one side branches much harder than the other.
            let expand_a = qa.len() <= qb.len();
            let (queue, parents, other) = if expand_a {
                (&mut qa, &mut from_a, &from_b)
            } else {
                (&mut qb, &mut from_b, &from_a)
            };
            if expand_a {
                da += 1;
            } else {
                db += 1;
            }

            let level: Vec<LocalId> = queue.drain(..).collect();
            for node in level {
                let neighbours = if expand_a {
                    view.out_edges(node, mask)?
                } else {
                    view.in_edges(node, mask)?
                };
                for next in neighbours.into_iter().map(|e| e.node) {
                    if next.index() >= n || parents[next.index()] != NONE {
                        continue;
                    }
                    parents[next.index()] = node.get();
                    if other[next.index()] != NONE {
                        return Ok(Some(self.join(next, &from_a, &from_b, a, b)));
                    }
                    queue.push_back(next);
                }
            }
        }
        Ok(None)
    }

    /// Stitch the two half-paths at their meeting point.
    fn join(
        &self,
        meet: LocalId,
        from_a: &[u32],
        from_b: &[u32],
        a: LocalId,
        b: LocalId,
    ) -> Vec<LocalId> {
        let mut left = Vec::new();
        let mut cur = meet;
        loop {
            left.push(cur);
            if cur == a {
                break;
            }
            let p = from_a[cur.index()];
            if p == u32::MAX || LocalId::new(p) == cur {
                break;
            }
            cur = LocalId::new(p);
        }
        left.reverse();

        let mut cur = meet;
        loop {
            if cur == b {
                break;
            }
            let p = from_b[cur.index()];
            if p == u32::MAX || LocalId::new(p) == cur {
                break;
            }
            cur = LocalId::new(p);
            left.push(cur);
        }
        left
    }

    // --- reachability / taint ---

    /// Can any of `sources` reach any of `sinks` along `mask`?
    ///
    /// Returns a witness path for the first pair that connects. The index
    /// rejects most pairs outright, so the search only runs for pairs that
    /// might genuinely connect.
    pub fn taint_path(
        &self,
        sources: &[LocalId],
        sinks: &[LocalId],
        mask: RelationMask,
        max_hops: u32,
    ) -> Result<Option<Vec<LocalId>>> {
        let filter = self.index.covers(mask);
        for &s in sources {
            for &t in sinks {
                if filter && !self.index.maybe_reaches(s, t) {
                    continue;
                }
                if let Some(p) = self.shortest_path(s, t, mask, max_hops)? {
                    return Ok(Some(p));
                }
            }
        }
        Ok(None)
    }

    /// Everything reachable from `sources` along `mask`, unbounded in depth.
    ///
    /// This is the entrypoint-reachability primitive: run it from the
    /// entrypoints and intersect with a symbol set to answer "is this actually
    /// reachable".
    pub fn reachable_set(&self, sources: &[LocalId], mask: RelationMask) -> Result<Vec<LocalId>> {
        let view = self.view();
        let n = view.node_count();
        let mut seen = vec![false; n];
        let mut q = VecDeque::new();
        for &s in sources {
            if view.is_canonical(s) && !seen[s.index()] {
                seen[s.index()] = true;
                q.push_back(s);
            }
        }
        let mut out = Vec::new();
        while let Some(v) = q.pop_front() {
            out.push(v);
            view.for_each_out(v, mask, |t| {
                if !seen[t as usize] {
                    seen[t as usize] = true;
                    q.push_back(LocalId::new(t));
                }
            })?;
        }
        Ok(out)
    }

    // --- ranking helpers ---

    /// The highest-degree symbols, excluding file nodes.
    ///
    /// A bounded heap rather than a sort of the whole degree vector: `top_n` is
    /// small and the vector is the size of the graph.
    pub fn hubs(&self, top_n: usize) -> Result<Vec<SymbolInfo>> {
        let view = self.view();
        let mut ids: Vec<(u32, u32)> = Vec::new();
        for si in 0..view.segment_count() {
            let (seg, base) = view.segment(si);
            let flags = seg.node_flags()?;
            let kinds = seg.node_kinds()?;
            for (l, f) in flags.iter().enumerate() {
                let g = base + l as u32;
                if f & codegraph_store::node_flags::FILE_NODE == 0
                    && codegraph_index::build::is_hub_eligible(kinds[l])
                    && view.is_canonical(LocalId::new(g))
                {
                    ids.push((self.index.degree(LocalId::new(g)), g));
                }
            }
        }
        // Partial selection: only the top slice needs ordering.
        let k = top_n.min(ids.len());
        if k > 0 {
            ids.select_nth_unstable_by(k - 1, |a, b| b.0.cmp(&a.0).then(a.1.cmp(&b.1)));
            ids.truncate(k);
            ids.sort_unstable_by(|a, b| b.0.cmp(&a.0).then(a.1.cmp(&b.1)));
        }
        let mut out = Vec::with_capacity(k);
        for (_, i) in ids {
            if let Some(info) = self.info(LocalId::new(i))? {
                out.push(info);
            }
        }
        Ok(out)
    }

    /// Counts by relation and confidence, for stats surfaces.
    pub fn edge_histogram(&self) -> Result<EdgeHistogram> {
        let mut rels = [0usize; 256];
        let mut confs = [0usize; 256];
        self.view().for_each_edge(
            |_| true,
            |e| {
                // A proxy's link to its symbol is storage, not a fact.
                if e.rel == Relation::StandsFor.as_u8() {
                    return Ok(());
                }
                rels[e.rel as usize] += 1;
                confs[e.conf as usize] += 1;
                Ok(())
            },
        )?;
        let r = (0..256)
            .filter(|&i| rels[i] > 0)
            .map(|i| (Relation::from_u8(i as u8), rels[i]))
            .collect();
        let c = (0..256)
            .filter(|&i| confs[i] > 0)
            .map(|i| (Confidence::from_u8(i as u8), confs[i]))
            .collect();
        Ok((r, c))
    }
}
