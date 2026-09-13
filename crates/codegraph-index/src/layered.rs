//! An index that grows with the store: a base plus an overlay.
//!
//! The base index is built once, over a compacted single-segment store, and
//! mmap'd. When a delta is committed, the base is not rebuilt. An [`Overlay`]
//! is built instead — proportional to the delta, not the store — and a
//! [`Layered`] index answers from the two together.
//!
//! # What the overlay holds
//!
//! - **Degrees and postings for the delta rows**, computed fresh: they are
//!   few.
//! - **Degree patches for base rows** a delta touched: a base symbol that
//!   gained or lost a caller.
//! - **Reachability.** This is the part that cannot be patched exactly —
//!   maintaining transitive closure under edge insertion is a hard problem —
//!   so the overlay keeps the base's labels *sound* instead of recomputing
//!   them. Two facts make that possible:
//!
//!   1. A re-indexed symbol **inherits the component of its predecessor**, the
//!      dead base row with the same key. Every path that does not use an edge
//!      the delta *added* is a path the base graph had, so the base labels
//!      still answer for it. Removed edges only shrink reachability, and a
//!      "maybe" that turns out to be "no" is a slow answer, not a wrong one.
//!   2. Every path that *does* use an added edge `u -> v` passes through some
//!      added edge. So the overlay stores two bitsets: **A**, the rows that
//!      can reach the source of any added edge, and **B**, the rows any
//!      added edge's target can reach. Then
//!      `maybe(a, b) = base_labels(a, b) || (A[a] && B[b])`.
//!
//!   For a body edit the added set is empty — the file's edges are the same
//!   edges, re-keyed — and the filter is exactly the base's. For an edit that
//!   adds calls, precision degrades by exactly the pairs that the new edges
//!   could plausibly connect, and the next rebuild restores it.
//!
//! Base rows that died are still numbered and still in the base's postings;
//! the engine drops them by liveness. The base's hub cutoff is kept as is.

use std::collections::HashMap;
use std::path::Path;

use codegraph_core::{LocalId, Relation, RelationMask, SymbolKey};
use codegraph_store::{Result as StoreResult, Store, StoreError};
use zerocopy::IntoBytes;

use crate::build::{REACHABILITY_RELATIONS, is_structural, trigrams};
use crate::persist::{
    self, BYTE_ORDER_MARK, FORMAT_VERSION, Header, IndexFileError, MAGIC, kind,
};
use crate::view::{IndexColumns, IndexQuery, exact_postings, intersect_union, prefix_postings, trigram_candidate_ids};

/// Component id of a row that is not live: never reachable, never expanded.
const NO_COMPONENT: u32 = u32::MAX;

/// A block edge never counted towards a degree; see `build::is_structural`.
fn is_structural_kind(kind: u8) -> bool {
    kind == codegraph_core::SymbolKind::Block.as_u8()
}

/// The per-generation extension of a base index. Owned: it is small.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Overlay {
    generation: u64,
    base_generation: u64,
    segment_id: u64,
    /// Rows the base numbers: `[0, base_nodes)`.
    base_nodes: usize,
    /// Rows in the store now: `[0, node_count)`.
    node_count: usize,
    hub_threshold: u32,
    /// Components the overlay minted for rows with no predecessor.
    fresh_components: usize,

    // Columns for rows `[base_nodes, node_count)`.
    degree_out: Vec<u32>,
    degree_in: Vec<u32>,
    degree_total: Vec<u32>,
    scc_of: Vec<u32>,

    // Base rows whose degree changed: `(out, in, total)`.
    patch: HashMap<u32, (u32, u32, u32)>,

    // Reachability bitsets over `[0, node_count)`; empty when no edge was
    // added, in which case the base's labels are exact.
    reach_a: Vec<u64>,
    reach_b: Vec<u64>,

    name_keys: Vec<String>,
    name_offsets: Vec<u32>,
    name_postings: Vec<u32>,
    trigram_keys: Vec<u32>,
    trigram_offsets: Vec<u32>,
    trigram_postings: Vec<u32>,
}

fn bit(set: &[u64], i: u32) -> bool {
    set.get((i / 64) as usize).is_some_and(|w| w & (1u64 << (i % 64)) != 0)
}

fn set_bit(set: &mut [u64], i: u32) {
    set[(i / 64) as usize] |= 1u64 << (i % 64);
}

impl Overlay {
    /// Build the overlay for the store's current generation over `base`,
    /// which must have been built over the store's first segment at
    /// `base_generation`.
    pub fn build<B: IndexColumns>(
        store: &Store,
        base: &B,
        base_generation: u64,
        base_segment_id: u64,
    ) -> StoreResult<Self> {
        let view = store.view();
        let n = view.node_count();
        let n0 = base.node_count();
        let first = store.segments().next().map(|(id, s)| (id, s.node_count()));
        if first != Some((base_segment_id, n0)) || n < n0 {
            return Err(StoreError::Manifest(
                "the base index does not describe this store's first segment".into(),
            ));
        }
        let s0 = base.scc_count();
        let (seg0, _) = view.segment(0);

        // --- the base graph's edges at every dead base row, in key space ---
        // A dead row is a re-indexed (or deleted) symbol's previous version.
        // Its edges are what the base labels and degrees were computed over.
        let keys0 = seg0.keys()?;
        let (t0, r0) = (seg0.fwd_targets()?, seg0.fwd_rels()?);
        let stands_for = Relation::StandsFor.as_u8();
        let mut dead_by_key: HashMap<SymbolKey, u32> = HashMap::new();
        let mut dead_edges: HashMap<u32, HashMap<(SymbolKey, u8), u32>> = HashMap::new();
        // A dead proxy's edges left the symbol it stood for.
        let mut dead_proxy_of: HashMap<u32, SymbolKey> = HashMap::new();
        for l in 0..n0 {
            let id = LocalId::new(l as u32);
            // A live proxy is not canonical either, but nothing about it
            // changed: its edges are in the base degrees and labels, as its
            // symbol's, and still are.
            if view.is_canonical(id) || view.is_live_proxy(id) {
                continue;
            }
            dead_by_key.insert(keys0[l], l as u32);
            let mut m: HashMap<(SymbolKey, u8), u32> = HashMap::new();
            for e in seg0.out_range(id)? {
                if r0[e] == stands_for {
                    dead_proxy_of.insert(l as u32, keys0[t0[e] as usize]);
                    continue;
                }
                *m.entry((keys0[t0[e] as usize], r0[e])).or_default() += 1;
            }
            dead_edges.insert(l as u32, m);
        }

        // --- delta rows ---
        let (mut degree_out, mut degree_in, mut scc_of) =
            (vec![0u32; n - n0], vec![0u32; n - n0], vec![NO_COMPONENT; n - n0]);
        // Base rows: `(out delta, in delta)`.
        let mut patch: HashMap<u32, (i64, i64)> = HashMap::new();
        let mut added_sources: Vec<u32> = Vec::new();
        let mut added_targets: Vec<u32> = Vec::new();
        let mut fresh = 0usize;
        let base_scc = base.scc_of();

        for g in n0..n {
            let id = LocalId::new(g as u32);
            // A delta proxy is a row of edges that count as another
            // symbol's: diffed against its own predecessor like any row,
            // but its degree and its added edges are the symbol's.
            let live_proxy = view.is_live_proxy(id);
            if !view.is_canonical(id) && !live_proxy {
                continue;
            }
            let is_block = view.kind_raw(id)? == codegraph_core::SymbolKind::Block.as_u8();
            let key = view.key(id)?;
            let pred = dead_by_key.get(&key).copied();
            let owner = if live_proxy { view.edge_owner(id).expect("live proxy forwards") } else { id };
            if !live_proxy {
                scc_of[g - n0] = match pred {
                    Some(p) => base_scc[p as usize],
                    None => {
                        fresh += 1;
                        (s0 + fresh - 1) as u32
                    }
                };
                // Degrees, over everything the row's edges are: its own and
                // its live proxies' in every file.
                for e in view.out_edges(id, RelationMask::ALL)? {
                    let to_block = view.kind_raw(e.node)? == codegraph_core::SymbolKind::Block.as_u8();
                    if !is_block && !to_block {
                        degree_out[g - n0] += 1;
                    }
                }
                if !is_block {
                    for e in view.in_edges(id, RelationMask::ALL)? {
                        if view.kind_raw(e.node)? != codegraph_core::SymbolKind::Block.as_u8() {
                            degree_in[g - n0] += 1;
                        }
                    }
                }
            }
            // The diff is over what this row itself wrote — a proxy's edges
            // are diffed at the proxy — against its predecessor's.
            let mut now: HashMap<(SymbolKey, u8), u32> = HashMap::new();
            for e in view.own_edges(id, RelationMask::ALL)? {
                *now.entry((view.key(e.node)?, e.relation.as_u8())).or_default() += 1;
            }
            // A proxy's out-degree change lands on its symbol when that is a
            // base row; a delta row's degree was read off the view above.
            let owner_patch = live_proxy && owner.index() < n0;

            let before = pred.and_then(|p| dead_edges.remove(&p)).unwrap_or_default();
            // Added: in the row now, not on its predecessor.
            for (&(tkey, rel), &c_now) in &now {
                let c_before = before.get(&(tkey, rel)).copied().unwrap_or(0);
                if c_now <= c_before {
                    continue;
                }
                let Some(target) = view.find(tkey) else { continue };
                if target.index() < n0 && !is_block && !is_structural_kind(view.kind_raw(target)?) {
                    patch.entry(target.get()).or_default().1 += i64::from(c_now - c_before);
                }
                if owner_patch {
                    patch.entry(owner.get()).or_default().0 += i64::from(c_now - c_before);
                }
                if REACHABILITY_RELATIONS.contains_raw(rel) {
                    added_sources.push(owner.get());
                    added_targets.push(target.get());
                }
            }
            // Removed: on the predecessor, not in the row now.
            for (&(tkey, rel), &c_before) in &before {
                let c_now = now.get(&(tkey, rel)).copied().unwrap_or(0);
                if c_before <= c_now {
                    continue;
                }
                if let Some(target) = view.find(tkey)
                    && target.index() < n0
                    && !is_block
                    && !is_structural_kind(view.kind_raw(target)?)
                {
                    patch.entry(target.get()).or_default().1 -= i64::from(c_before - c_now);
                }
                if owner_patch {
                    patch.entry(owner.get()).or_default().0 -= i64::from(c_before - c_now);
                }
            }
        }

        // Dead base rows with no successor: a deleted symbol. Everything it
        // pointed at lost an in-edge, and every live base row that pointed at
        // it lost an out-edge — the view drops the dangling edge.
        for (p, before) in dead_edges {
            if view.kind_raw(LocalId::new(p))? == codegraph_core::SymbolKind::Block.as_u8() {
                continue;
            }
            for (&(tkey, _), &c) in &before {
                if let Some(target) = view.find(tkey)
                    && target.index() < n0
                    && !is_structural_kind(view.kind_raw(target)?)
                {
                    patch.entry(target.get()).or_default().1 -= i64::from(c);
                }
            }
            let pid = LocalId::new(p);
            if let Some(of) = dead_proxy_of.get(&p) {
                // A proxy that went away with its file, or with its symbol:
                // the symbol, if it still exists in the base, lost the edges
                // the proxy carried for it.
                if let Some(owner) = view.find(*of)
                    && owner.index() < n0
                {
                    let lost: u32 = before.values().sum();
                    patch.entry(owner.get()).or_default().0 -= i64::from(lost);
                }
            } else if view.canonical(pid).is_none() {
                for e in seg0.in_edges(pid, RelationMask::ALL)? {
                    let s = e.source;
                    if e.relation == Relation::StandsFor {
                        continue;
                    }
                    if s.index() < n0 && view.is_canonical(s) {
                        patch.entry(s.get()).or_default().0 -= 1;
                    }
                }
            }
        }

        let (bo, bi) = (base.degree_out(), base.degree_in());
        let patch: HashMap<u32, (u32, u32, u32)> = patch
            .into_iter()
            .filter(|(_, d)| *d != (0, 0))
            .map(|(id, (dout, din))| {
                let out = (i64::from(bo[id as usize]) + dout).max(0) as u32;
                let inn = (i64::from(bi[id as usize]) + din).max(0) as u32;
                (id, (out, inn, out + inn))
            })
            .collect();
        let degree_total: Vec<u32> =
            degree_out.iter().zip(&degree_in).map(|(a, b)| a + b).collect();

        // --- reachability bitsets ---
        let (mut reach_a, mut reach_b) = (Vec::new(), Vec::new());
        if !added_sources.is_empty() {
            let words = n.div_ceil(64);
            reach_a = vec![0u64; words];
            reach_b = vec![0u64; words];
            // A: everything that can reach an added edge's source.
            let mut stack: Vec<u32> = Vec::new();
            for &s in &added_sources {
                if !bit(&reach_a, s) {
                    set_bit(&mut reach_a, s);
                    stack.push(s);
                }
            }
            while let Some(v) = stack.pop() {
                for e in view.in_edges(LocalId::new(v), REACHABILITY_RELATIONS)? {
                    let u = e.node.get();
                    if !bit(&reach_a, u) {
                        set_bit(&mut reach_a, u);
                        stack.push(u);
                    }
                }
            }
            // B: everything an added edge's target can reach.
            for &t in &added_targets {
                if !bit(&reach_b, t) {
                    set_bit(&mut reach_b, t);
                    stack.push(t);
                }
            }
            while let Some(v) = stack.pop() {
                let mut next = Vec::new();
                view.for_each_out(LocalId::new(v), REACHABILITY_RELATIONS, |t| {
                    if !bit(&reach_b, t) {
                        set_bit(&mut reach_b, t);
                        next.push(t);
                    }
                })?;
                stack.extend(next);
            }
        }

        // --- names and trigrams for the delta rows ---
        let mut by_name: std::collections::BTreeMap<&str, Vec<u32>> = Default::default();
        let mut by_trigram: std::collections::BTreeMap<u32, Vec<u32>> = Default::default();
        let mut text = String::new();
        for si in 1..view.segment_count() {
            let (seg, base_id) = view.segment(si);
            let norms = seg.node_norm_names()?;
            let files = seg.node_files()?;
            let seg_kinds = seg.node_kinds()?;
            for l in 0..seg.node_count() {
                let g = base_id + l as u32;
                if !view.is_canonical(LocalId::new(g)) || is_structural(seg_kinds[l]) {
                    continue;
                }
                let s = seg.string(norms[l]);
                if !s.is_empty() {
                    by_name.entry(s).or_default().push(g);
                }
                text.clear();
                text.push_str(s);
                text.push('\0');
                text.push_str(&seg.file_path(files[l]).to_lowercase());
                for tri in trigrams(&text) {
                    by_trigram.entry(tri).or_default().push(g);
                }
            }
        }
        let mut name_keys = Vec::with_capacity(by_name.len());
        let mut name_offsets = vec![0u32];
        let mut name_postings = Vec::new();
        for (k, mut v) in by_name {
            v.sort_unstable();
            name_keys.push(k.to_string());
            name_postings.extend_from_slice(&v);
            name_offsets.push(name_postings.len() as u32);
        }
        let mut trigram_keys = Vec::with_capacity(by_trigram.len());
        let mut trigram_offsets = vec![0u32];
        let mut trigram_postings = Vec::new();
        for (k, mut v) in by_trigram {
            v.sort_unstable();
            v.dedup();
            trigram_keys.push(k);
            trigram_postings.extend_from_slice(&v);
            trigram_offsets.push(trigram_postings.len() as u32);
        }

        Ok(Self {
            generation: store.manifest().generation,
            base_generation,
            segment_id: base_segment_id,
            base_nodes: n0,
            node_count: n,
            hub_threshold: base.hub_threshold(),
            fresh_components: fresh,
            degree_out,
            degree_in,
            degree_total,
            scc_of,
            patch,
            reach_a,
            reach_b,
            name_keys,
            name_offsets,
            name_postings,
            trigram_keys,
            trigram_offsets,
            trigram_postings,
        })
    }

    pub fn generation(&self) -> u64 {
        self.generation
    }
    pub fn base_generation(&self) -> u64 {
        self.base_generation
    }
    /// Rows the delta added, live or not.
    pub fn delta_rows(&self) -> usize {
        self.node_count - self.base_nodes
    }
    /// Base rows whose degree the delta changed.
    pub fn patched_rows(&self) -> usize {
        self.patch.len()
    }
    /// Whether any edge was added since the base index, and the reachability
    /// filter therefore falls back to the bitsets for some pairs.
    pub fn has_added_edges(&self) -> bool {
        !self.reach_a.is_empty()
    }

    /// Write to `path`.
    pub fn write(&self, path: &Path) -> persist::Result<()> {
        let header = Header {
            magic: MAGIC,
            format_version: FORMAT_VERSION,
            byte_order: BYTE_ORDER_MARK,
            node_count: self.node_count as u64,
            scc_count: self.fresh_components as u64,
            hub_threshold: self.hub_threshold,
            grail_k: 0,
            generation: self.generation,
            segment_id: self.segment_id,
            base_generation: self.base_generation,
        };
        let (name_bytes, name_key_offsets) = persist::name_arena(&self.name_keys);
        let mut ids: Vec<u32> = self.patch.keys().copied().collect();
        ids.sort_unstable();
        let (mut po, mut pi, mut pt) = (Vec::new(), Vec::new(), Vec::new());
        for id in &ids {
            let (o, i, t) = self.patch[id];
            po.push(o);
            pi.push(i);
            pt.push(t);
        }
        persist::write_container(
            path,
            &header,
            &[
                (kind::DEGREE_OUT, self.degree_out.len(), self.degree_out.as_bytes()),
                (kind::DEGREE_IN, self.degree_in.len(), self.degree_in.as_bytes()),
                (kind::DEGREE_TOTAL, self.degree_total.len(), self.degree_total.as_bytes()),
                (kind::SCC_OF, self.scc_of.len(), self.scc_of.as_bytes()),
                (kind::NAME_BYTES, name_bytes.len(), &name_bytes),
                (kind::NAME_KEY_OFFSETS, name_key_offsets.len(), name_key_offsets.as_bytes()),
                (kind::NAME_OFFSETS, self.name_offsets.len(), self.name_offsets.as_bytes()),
                (kind::NAME_POSTINGS, self.name_postings.len(), self.name_postings.as_bytes()),
                (kind::TRIGRAM_KEYS, self.trigram_keys.len(), self.trigram_keys.as_bytes()),
                (kind::TRIGRAM_OFFSETS, self.trigram_offsets.len(), self.trigram_offsets.as_bytes()),
                (kind::TRIGRAM_POSTINGS, self.trigram_postings.len(), self.trigram_postings.as_bytes()),
                (kind::PATCH_IDS, ids.len(), ids.as_bytes()),
                (kind::PATCH_OUT, po.len(), po.as_bytes()),
                (kind::PATCH_IN, pi.len(), pi.as_bytes()),
                (kind::PATCH_TOTAL, pt.len(), pt.as_bytes()),
                (kind::REACH_A, self.reach_a.len(), self.reach_a.as_bytes()),
                (kind::REACH_B, self.reach_b.len(), self.reach_b.as_bytes()),
            ],
        )
    }

    /// Read back, refusing an overlay for another generation or another base.
    pub fn read(path: &Path, generation: u64, base_generation: u64) -> persist::Result<Self> {
        let c = crate::mapped::open_container(path)?;
        let h = c.header;
        if h.base_generation == 0 {
            return Err(IndexFileError::Corrupt("this is a base index, not an overlay".into()));
        }
        if h.generation != generation {
            return Err(IndexFileError::Stale { found: h.generation, expected: generation });
        }
        if h.base_generation != base_generation {
            return Err(IndexFileError::Stale { found: h.base_generation, expected: base_generation });
        }
        // Small enough to own: the payload is checked on the way in, which
        // the mapped base deliberately does not do.
        c.verify_checksums()?;
        let degree_out = c.u32s(kind::DEGREE_OUT).to_vec();
        let n = h.node_count as usize;
        if degree_out.len() > n {
            return Err(IndexFileError::Corrupt("overlay holds more rows than the store".into()));
        }
        let name_bytes = c.raw(kind::NAME_BYTES);
        let name_key_offsets = c.u32s(kind::NAME_KEY_OFFSETS);
        let mut name_keys = Vec::with_capacity(name_key_offsets.len().saturating_sub(1));
        for w in name_key_offsets.windows(2) {
            let s = std::str::from_utf8(&name_bytes[w[0] as usize..w[1] as usize])
                .map_err(|_| IndexFileError::Corrupt("name key is not UTF-8".into()))?;
            name_keys.push(s.to_string());
        }
        let ids = c.u32s(kind::PATCH_IDS);
        let (po, pi, pt) = (c.u32s(kind::PATCH_OUT), c.u32s(kind::PATCH_IN), c.u32s(kind::PATCH_TOTAL));
        if po.len() != ids.len() || pi.len() != ids.len() || pt.len() != ids.len() {
            return Err(IndexFileError::Corrupt("degree patches are ragged".into()));
        }
        let patch = ids.iter().enumerate().map(|(i, &id)| (id, (po[i], pi[i], pt[i]))).collect();
        let base_nodes = n - degree_out.len();
        Ok(Self {
            generation: h.generation,
            base_generation: h.base_generation,
            segment_id: h.segment_id,
            base_nodes,
            node_count: n,
            hub_threshold: h.hub_threshold,
            fresh_components: h.scc_count as usize,
            degree_in: c.u32s(kind::DEGREE_IN).to_vec(),
            degree_total: c.u32s(kind::DEGREE_TOTAL).to_vec(),
            scc_of: c.u32s(kind::SCC_OF).to_vec(),
            degree_out,
            patch,
            reach_a: c.u64s(kind::REACH_A).to_vec(),
            reach_b: c.u64s(kind::REACH_B).to_vec(),
            name_keys,
            name_offsets: c.u32s(kind::NAME_OFFSETS).to_vec(),
            name_postings: c.u32s(kind::NAME_POSTINGS).to_vec(),
            trigram_keys: c.u32s(kind::TRIGRAM_KEYS).to_vec(),
            trigram_offsets: c.u32s(kind::TRIGRAM_OFFSETS).to_vec(),
            trigram_postings: c.u32s(kind::TRIGRAM_POSTINGS).to_vec(),
        })
    }
}

/// A base index plus, when the store has moved past it, an overlay.
pub struct Layered<B: IndexColumns> {
    base: B,
    overlay: Option<Overlay>,
}

impl<B: IndexColumns> std::fmt::Debug for Layered<B> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Layered")
            .field("base_symbols", &self.base.node_count())
            .field("delta_rows", &self.overlay.as_ref().map_or(0, Overlay::delta_rows))
            .finish()
    }
}

impl<B: IndexColumns> Layered<B> {
    /// A base that describes the store's current generation on its own.
    pub fn plain(base: B) -> Self {
        Self { base, overlay: None }
    }

    /// A base extended by an overlay built over it.
    pub fn with_overlay(base: B, overlay: Overlay) -> persist::Result<Self> {
        if overlay.base_nodes != base.node_count() {
            return Err(IndexFileError::Corrupt(format!(
                "overlay expects a base of {} rows, base has {}",
                overlay.base_nodes,
                base.node_count()
            )));
        }
        Ok(Self { base, overlay: Some(overlay) })
    }

    pub fn base(&self) -> &B {
        &self.base
    }
    pub fn overlay(&self) -> Option<&Overlay> {
        self.overlay.as_ref()
    }

    fn component(&self, id: LocalId) -> u32 {
        let i = id.index();
        match &self.overlay {
            Some(o) if i >= o.base_nodes => o.scc_of.get(i - o.base_nodes).copied().unwrap_or(NO_COMPONENT),
            _ => self.base.scc_of().get(i).copied().unwrap_or(NO_COMPONENT),
        }
    }
}

impl<B: IndexColumns> IndexQuery for Layered<B> {
    fn symbols(&self) -> usize {
        self.overlay.as_ref().map_or(self.base.node_count(), |o| o.node_count)
    }
    fn components(&self) -> usize {
        self.base.scc_count() + self.overlay.as_ref().map_or(0, |o| o.fresh_components)
    }
    fn hub_cutoff(&self) -> u32 {
        self.base.hub_threshold()
    }
    fn degree(&self, id: LocalId) -> u32 {
        self.degrees(id).0 + self.degrees(id).1
    }
    fn degrees(&self, id: LocalId) -> (u32, u32) {
        let i = id.index();
        if let Some(o) = &self.overlay {
            if i >= o.base_nodes {
                let j = i - o.base_nodes;
                return (
                    o.degree_out.get(j).copied().unwrap_or(0),
                    o.degree_in.get(j).copied().unwrap_or(0),
                );
            }
            if let Some(&(out, inn, _)) = o.patch.get(&id.get()) {
                return (out, inn);
            }
        }
        (
            self.base.degree_out().get(i).copied().unwrap_or(0),
            self.base.degree_in().get(i).copied().unwrap_or(0),
        )
    }
    fn by_exact_name(&self, name: &str) -> Vec<u32> {
        let mut out = self.base.exact_name_postings(name).to_vec();
        if let Some(o) = &self.overlay {
            out.extend_from_slice(exact_postings(
                o.name_keys.len(),
                |i| &o.name_keys[i],
                &o.name_offsets,
                &o.name_postings,
                name,
            ));
        }
        out
    }
    fn by_name_prefix(&self, prefix: &str) -> Vec<u32> {
        let mut out = self.base.prefix_postings(prefix);
        if let Some(o) = &self.overlay {
            out.extend(prefix_postings(
                o.name_keys.len(),
                |i| &o.name_keys[i],
                &o.name_offsets,
                &o.name_postings,
                prefix,
            ));
        }
        out
    }
    fn trigram_candidates(&self, needle: &str) -> Option<Vec<u32>> {
        let needle = needle.to_lowercase();
        let tris: Vec<u32> = trigrams(&needle).collect();
        let mut out = self.base.trigram_candidate_ids(&tris)?;
        if let Some(o) = &self.overlay {
            let more = trigram_candidate_ids(&o.trigram_keys, &o.trigram_offsets, &o.trigram_postings, &tris)?;
            out = intersect_union(out, more);
        }
        Some(out)
    }
    fn maybe_reaches(&self, from: LocalId, to: LocalId) -> bool {
        let n = self.symbols();
        if from.index() >= n || to.index() >= n {
            return false;
        }
        let (sa, sb) = (self.component(from), self.component(to));
        if sa == NO_COMPONENT || sb == NO_COMPONENT {
            return false;
        }
        if sa == sb {
            return true;
        }
        let s0 = self.base.scc_count() as u32;
        let base_may = sa < s0 && sb < s0 && self.base.labels_may_reach(sa as usize, sb as usize);
        base_may
            || self
                .overlay
                .as_ref()
                .is_some_and(|o| bit(&o.reach_a, from.get()) && bit(&o.reach_b, to.get()))
    }
}

/// The names an index lives under, inside a store directory.
///
/// Every file is named by the generation it describes — `index-7.cgidx`,
/// `overlay-9.cgidx` — and is written once. A server has the current base
/// mapped while an update writes the next; on Windows a mapped file can
/// be neither overwritten nor renamed over, so a new generation is a new
/// file, and files no longer needed are removed when nothing maps them
/// any more (best effort, retried at every open). The unnumbered names
/// are what earlier versions wrote; they are still read.
pub const BASE_FILE: &str = "index.cgidx";
pub const OVERLAY_FILE: &str = "overlay.cgidx";

fn base_file(generation: u64) -> String {
    format!("index-{generation}.cgidx")
}
fn overlay_file(generation: u64) -> String {
    format!("overlay-{generation}.cgidx")
}

/// The index files in a store directory: `(path, is_overlay, generation)`,
/// legacy unnumbered names with generation `None`.
fn index_files(dir: &Path) -> Vec<(std::path::PathBuf, bool, Option<u64>)> {
    let Ok(rd) = std::fs::read_dir(dir) else { return Vec::new() };
    let mut v = Vec::new();
    for e in rd.flatten() {
        let name = e.file_name();
        let Some(name) = name.to_str() else { continue };
        let Some(stem) = name.strip_suffix(".cgidx") else { continue };
        if let Some(g) = stem.strip_prefix("index-") {
            if let Ok(g) = g.parse() {
                v.push((e.path(), false, Some(g)));
            }
        } else if let Some(g) = stem.strip_prefix("overlay-") {
            if let Ok(g) = g.parse() {
                v.push((e.path(), true, Some(g)));
            }
        } else if stem == "index" {
            v.push((e.path(), false, None));
        } else if stem == "overlay" {
            v.push((e.path(), true, None));
        }
    }
    v.sort();
    v
}

/// The base index a store's current generation can be served from: one
/// that describes it exactly, or the newest that was built over the
/// store's first segment and so can carry an overlay. `(path, index)`.
fn select_base(dir: &Path, generation: u64, first: Option<u64>) -> Option<(std::path::PathBuf, crate::MappedIndex)> {
    let mut candidates: Vec<(std::path::PathBuf, crate::MappedIndex)> = index_files(dir)
        .into_iter()
        .filter(|(_, overlay, _)| !overlay)
        .filter_map(|(p, _, _)| crate::MappedIndex::open_any(&p).ok().map(|m| (p, m)))
        .collect();
    if let Some(i) = candidates.iter().position(|(_, m)| m.generation() == generation) {
        return Some(candidates.swap_remove(i));
    }
    candidates.retain(|(_, m)| m.segment_id().is_some() && m.segment_id() == first);
    candidates.sort_by_key(|(_, m)| m.generation());
    candidates.pop()
}

/// The index files serving `generation` now: the base, and the overlay if
/// one is in use. What `verify` and `stats` should look at.
pub fn current_files(store: &Store, dir: &Path) -> Option<(std::path::PathBuf, Option<std::path::PathBuf>)> {
    let generation = store.manifest().generation;
    let first = store.segments().next().map(|(id, _)| id);
    let (base_path, base) = select_base(dir, generation, first)?;
    if base.generation() == generation {
        return Some((base_path, None));
    }
    let overlay = [dir.join(overlay_file(generation)), dir.join(OVERLAY_FILE)]
        .into_iter()
        .find(|p| Overlay::read(p, generation, base.generation()).is_ok());
    Some((base_path, overlay))
}

/// Remove every index file but the ones in use. A file another process
/// still maps cannot be removed on every platform; it is left for the
/// next sweep.
fn sweep_index_files(dir: &Path, keep: &[&Path]) {
    for (p, _, _) in index_files(dir) {
        if !keep.iter().any(|k| *k == p) {
            let _ = std::fs::remove_file(&p);
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum OpenError {
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error(transparent)]
    File(#[from] IndexFileError),
}

/// What [`open_or_build`] did to get an index for the store's generation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Opened {
    /// The base index describes this generation on its own.
    Base,
    /// The base plus an overlay already on disk.
    Overlaid,
    /// The base plus an overlay built now.
    OverlayBuilt,
    /// No usable base: a full index was built.
    Rebuilt,
}

/// Open the index for a store's current generation, building only what is
/// missing: nothing, an overlay, or — when there is no base to extend — the
/// whole index.
///
/// A base is extendable while the store's first segment is the one it was
/// built over. A full rebuild over a single-segment store produces a new
/// base; over a multi-segment store it produces an index that serves this
/// generation but cannot be extended, and the next update rebuilds again.
pub fn open_or_build(
    store: &Store,
    dir: &Path,
) -> std::result::Result<(Layered<crate::MappedIndex>, Opened), OpenError> {
    let generation = store.manifest().generation;
    let first = store.segments().next().map(|(id, _)| id);
    let single = store.segments().count() == 1;

    if let Some((base_path, base)) = select_base(dir, generation, first) {
        if base.generation() == generation {
            sweep_index_files(dir, &[&base_path]);
            return Ok((Layered::plain(base), Opened::Base));
        }
        if let Some(seg) = base.segment_id()
            && Some(seg) == first
        {
            let overlay_path = dir.join(overlay_file(generation));
            for p in [overlay_path.clone(), dir.join(OVERLAY_FILE)] {
                if let Ok(o) = Overlay::read(&p, generation, base.generation()) {
                    sweep_index_files(dir, &[&base_path, &p]);
                    return Ok((Layered::with_overlay(base, o)?, Opened::Overlaid));
                }
            }
            let o = Overlay::build(store, &base, base.generation(), seg)?;
            o.write(&overlay_path)?;
            sweep_index_files(dir, &[&base_path, &overlay_path]);
            return Ok((Layered::with_overlay(base, o)?, Opened::OverlayBuilt));
        }
    }

    let data = crate::IndexData::build(store)?;
    let base_path = dir.join(base_file(generation));
    match (single, first) {
        (true, Some(seg)) => data.write_base(&base_path, generation, seg)?,
        _ => data.write(&base_path, generation)?,
    }
    sweep_index_files(dir, &[&base_path]);
    Ok((Layered::plain(crate::MappedIndex::open(&base_path, generation)?), Opened::Rebuilt))
}
