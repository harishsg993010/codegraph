//! Building the derived index over a compacted store.
//!
//! Everything here is a function of the *whole* graph, which is why it lives in
//! an index rather than in a segment: a segment is written per batch of files,
//! but a degree, an SCC id, or a document frequency only means anything once
//! every file is in hand.
//!
//! Each of these replaces a cost the query engine would otherwise pay per call.
//! The degree percentile is the clearest case: traversal needs a hub cutoff,
//! deriving it means sorting the whole degree vector, and doing that on every
//! interactive query makes the engine `O(V log V)` no matter how good the
//! storage layer is.

use std::collections::BTreeMap;

use codegraph_core::{Relation, RelationMask};
use codegraph_store::{Result, Store};

use crate::grail::{DEFAULT_K, Grail};
use crate::scc;

/// The derived index, in memory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexData {
    pub node_count: usize,

    /// Out-, in-, and total degree per node. Nine separate query concerns read
    /// one of these; none of them should be counting edges at call time.
    pub degree_out: Vec<u32>,
    pub degree_in: Vec<u32>,
    pub degree_total: Vec<u32>,
    /// 99th percentile of total degree, floored at [`MIN_HUB_THRESHOLD`].
    /// Traversal refuses to expand through a node above this.
    pub hub_threshold: u32,

    /// Component id per node, and the count. Nodes in one component reach each
    /// other unconditionally, which is what makes recursion cheap to answer.
    pub scc_of: Vec<u32>,
    pub scc_count: usize,
    /// Interval labels over the condensation, indexed by **component id**.
    pub grail: Grail,

    /// Sorted distinct folded names, and the symbols under each. A plain sorted
    /// array rather than an FST: it mmaps as `&[u32]` with no decode step,
    /// which is worth more here than the FST's smaller footprint.
    pub name_keys: Vec<String>,
    pub name_offsets: Vec<u32>,
    pub name_postings: Vec<u32>,

    /// Trigram postings for substring and regex prefiltering. Sorted `u32`
    /// arrays for the same reason: a roaring bitmap is smaller but has to be
    /// deserialised, and "no decode on read" is the whole premise of the store.
    pub trigram_keys: Vec<u32>,
    pub trigram_offsets: Vec<u32>,
    pub trigram_postings: Vec<u32>,
}

/// A hub cutoff below this is noise — on a small graph the 99th percentile can
/// be 2, which would refuse to expand almost everything.
pub const MIN_HUB_THRESHOLD: u32 = 50;

/// Relations reachability is computed over: the call graph, and only that.
///
/// Value flow is deliberately *not* in the set. Labels over the union were
/// measured on Gitea: a function's return value flowing into another's
/// parameter makes the two "reach" each other label-wise, and the
/// call-graph filter's rejection rate fell from 94% to 48% — a call-graph
/// audit that took 42 ms took 7 s. The dataflow question does not need the
/// labels: it is answered by one backward search per sink, and there are
/// few sinks. Nesting relations are excluded too: `contains` would make
/// every symbol in a file reach every other, and the CFG relations would
/// make a function "reach" its own blocks.
pub const REACHABILITY_RELATIONS: RelationMask = Relation::TAINT;

/// Rows that are structure rather than symbols: a callable's parameters and
/// CFG blocks. They are never in the name tables, never hubs, and edges
/// touching a block do not count towards anyone's degree.
pub fn is_structural(kind: u8) -> bool {
    kind == codegraph_core::SymbolKind::Parameter.as_u8() || kind == codegraph_core::SymbolKind::Block.as_u8()
}

/// Rows that are never hubs: the structural ones, and locals — which are
/// in the name tables (so `search x` finds them) but are many, low-degree,
/// and one callable's business.
pub fn is_hub_eligible(kind: u8) -> bool {
    !is_structural(kind) && kind != codegraph_core::SymbolKind::Local.as_u8()
}

fn is_block(kind: u8) -> bool {
    kind == codegraph_core::SymbolKind::Block.as_u8()
}

impl IndexData {
    /// Build over every live segment of a store, through its view.
    ///
    /// Node numbering is the view's store-wide id space, so the degree, SCC
    /// and label columns line up with what the query engine addresses. A dead
    /// row keeps its number and gets zero degree, its own singleton component,
    /// and no postings — it is never returned by a lookup and never expanded
    /// through, so its labels are never consulted.
    pub fn build(store: &Store) -> Result<Self> {
        let view = store.view();
        let n = view.node_count();
        if n == 0 {
            return Ok(Self::empty());
        }

        // Row kinds, store-wide, so structural rows can be told apart.
        let mut kinds: Vec<u8> = Vec::with_capacity(n);
        for si in 0..view.segment_count() {
            let (seg, _) = view.segment(si);
            kinds.extend_from_slice(seg.node_kinds()?);
        }

        // --- degrees ---
        // An edge touching a CFG block is structure, not connectivity: a
        // function's degree must not grow with its block count.
        let mut degree_out = vec![0u32; n];
        let mut degree_in = vec![0u32; n];
        if view.is_single_live() {
            // One segment, nothing dead, no external edges: the CSR is the
            // graph, and reading it directly is the measured fast path. A
            // proxy row's edges count as its symbol's; its link to it is
            // storage, not an edge.
            let (seg, _) = view.segment(0);
            let offsets = seg.fwd_offsets()?;
            let targets = seg.fwd_targets()?;
            let rels = seg.fwd_rels()?;
            let stands_for = codegraph_core::Relation::StandsFor.as_u8();
            for i in 0..n {
                if is_block(kinds[i]) {
                    continue;
                }
                let Some(owner) = view.edge_owner(codegraph_core::LocalId::new(i as u32)) else { continue };
                let owner = owner.index();
                let (a, b) = (offsets[i] as usize, offsets[i + 1] as usize);
                for e in a..b {
                    let t = targets[e] as usize;
                    if t < n && !is_block(kinds[t]) && rels[e] != stands_for {
                        degree_out[owner] += 1;
                        degree_in[t] += 1;
                    }
                }
            }
        } else {
            for id in view.ids() {
                let i = id.index();
                if is_block(kinds[i]) {
                    continue;
                }
                view.for_each_out(id, RelationMask::ALL, |t| {
                    if !is_block(kinds[t as usize]) {
                        degree_out[i] += 1;
                        degree_in[t as usize] += 1;
                    }
                })?;
            }
        }
        let degree_total: Vec<u32> =
            degree_out.iter().zip(&degree_in).map(|(a, b)| a + b).collect();

        // Over live, non-structural rows only: a dead row has degree zero and
        // would drag the percentile down, making a store with deltas answer
        // differently from its compacted form; parameters and blocks are
        // many and low-degree and would do the same.
        let live_degrees: Vec<u32> = view
            .ids()
            .filter(|id| is_hub_eligible(kinds[id.index()]))
            .map(|id| degree_total[id.index()])
            .collect();
        let hub_threshold = percentile(&live_degrees, 0.99).max(MIN_HUB_THRESHOLD);

        // --- SCC over the reachability subgraph ---
        // Only flow-carrying relations participate, so recursion collapses but
        // a file "containing" its symbols does not.
        let flow = FlowGraph { view, mask: REACHABILITY_RELATIONS };
        let sccs = scc::compute(&flow);
        let grail = Grail::build(&sccs.dag_offsets, &sccs.dag_targets, DEFAULT_K);

        // --- name and trigram indexes ---
        // Per segment so the columns are fetched once, not once per row.
        let mut by_name: BTreeMap<&str, Vec<u32>> = BTreeMap::new();
        let mut by_trigram: BTreeMap<u32, Vec<u32>> = BTreeMap::new();
        let mut text = String::new();
        for si in 0..view.segment_count() {
            let (seg, base) = view.segment(si);
            let norms = seg.node_norm_names()?;
            let files = seg.node_files()?;
            let seg_kinds = seg.node_kinds()?;
            for l in 0..seg.node_count() {
                let g = base + l as u32;
                if !view.is_canonical(codegraph_core::LocalId::new(g)) || is_structural(seg_kinds[l]) {
                    continue;
                }
                let s = seg.string(norms[l]);
                if !s.is_empty() {
                    by_name.entry(s).or_default().push(g);
                }
                text.clear();
                text.push_str(s);
                // NUL-separated so a trigram cannot straddle the name/path
                // boundary and match something that appears in neither.
                text.push(' ');
                text.push_str(&seg.file_path(files[l]).to_lowercase());
                for tri in trigrams(&text) {
                    by_trigram.entry(tri).or_default().push(g);
                }
            }
        }
        let mut name_keys = Vec::with_capacity(by_name.len());
        let mut name_offsets = Vec::with_capacity(by_name.len() + 1);
        let mut name_postings = Vec::new();
        name_offsets.push(0u32);
        for (k, mut v) in by_name {
            v.sort_unstable();
            name_keys.push(k.to_string());
            name_postings.extend_from_slice(&v);
            name_offsets.push(name_postings.len() as u32);
        }
        let mut trigram_keys = Vec::with_capacity(by_trigram.len());
        let mut trigram_offsets = Vec::with_capacity(by_trigram.len() + 1);
        let mut trigram_postings = Vec::new();
        trigram_offsets.push(0u32);
        for (k, mut v) in by_trigram {
            v.sort_unstable();
            v.dedup();
            trigram_keys.push(k);
            trigram_postings.extend_from_slice(&v);
            trigram_offsets.push(trigram_postings.len() as u32);
        }

        Ok(Self {
            node_count: n,
            degree_out,
            degree_in,
            degree_total,
            hub_threshold,
            scc_of: sccs.of_node,
            scc_count: sccs.count,
            grail,
            name_keys,
            name_offsets,
            name_postings,
            trigram_keys,
            trigram_offsets,
            trigram_postings,
        })
    }

    pub fn empty() -> Self {
        Self {
            node_count: 0,
            degree_out: Vec::new(),
            degree_in: Vec::new(),
            degree_total: Vec::new(),
            hub_threshold: MIN_HUB_THRESHOLD,
            scc_of: Vec::new(),
            scc_count: 0,
            grail: Grail::build(&[0], &[], DEFAULT_K),
            name_keys: Vec::new(),
            name_offsets: vec![0],
            name_postings: Vec::new(),
            trigram_keys: Vec::new(),
            trigram_offsets: vec![0],
            trigram_postings: Vec::new(),
        }
    }

}

/// The flow-relation view of the graph, for SCC computation.
struct FlowGraph<'a> {
    view: codegraph_store::View<'a>,
    mask: RelationMask,
}

impl scc::Graph for FlowGraph<'_> {
    fn node_count(&self) -> usize {
        self.view.node_count()
    }
    fn for_each_successor(&self, node: u32, f: &mut dyn FnMut(u32)) {
        if self.view.is_single_live() {
            let (seg, _) = self.view.segment(0);
            let (Ok(offsets), Ok(targets), Ok(rels)) =
                (seg.fwd_offsets(), seg.fwd_targets(), seg.fwd_rels())
            else {
                return;
            };
            let id = codegraph_core::LocalId::new(node);
            if !self.view.is_canonical(id) {
                return;
            }
            let stands_for = codegraph_core::Relation::StandsFor.as_u8();
            // The row's own edges, then those of the proxies standing for it
            // (in a single live segment every shadow is a live proxy).
            for &row in std::iter::once(&node).chain(self.view.shadow_rows(id)) {
                let (a, b) = (offsets[row as usize] as usize, offsets[row as usize + 1] as usize);
                for i in a..b {
                    if self.mask.contains_raw(rels[i]) && rels[i] != stands_for {
                        f(targets[i]);
                    }
                }
            }
        } else {
            // A corrupt column would already have failed the degree pass.
            let _ = self.view.for_each_out(codegraph_core::LocalId::new(node), self.mask, f);
        }
    }
}

/// Byte trigrams of `s`, each packed into a `u32`.
///
/// Bytes, not chars: a multi-byte character simply contributes several
/// overlapping trigrams, which is correct for a *prefilter* — it can only make
/// the candidate set larger, never miss a match.
pub fn trigrams(s: &str) -> impl Iterator<Item = u32> + '_ {
    let b = s.as_bytes();
    (0..b.len().saturating_sub(2))
        .map(move |i| (b[i] as u32) << 16 | (b[i + 1] as u32) << 8 | b[i + 2] as u32)
}

/// The `p`-th percentile of `values`, by nearest rank. Copies in order to sort,
/// which is fine: this runs once per index build, not once per query.
fn percentile(values: &[u32], p: f64) -> u32 {
    if values.is_empty() {
        return 0;
    }
    let mut v = values.to_vec();
    v.sort_unstable();
    let idx = ((v.len() as f64 * p) as usize).min(v.len() - 1);
    v[idx]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trigrams_are_overlapping_byte_windows() {
        let t: Vec<u32> = trigrams("abcd").collect();
        assert_eq!(t.len(), 2);
        assert_eq!(t[0], (b'a' as u32) << 16 | (b'b' as u32) << 8 | b'c' as u32);
        assert_eq!(t[1], (b'b' as u32) << 16 | (b'c' as u32) << 8 | b'd' as u32);
    }

    #[test]
    fn short_strings_yield_no_trigrams() {
        assert_eq!(trigrams("ab").count(), 0);
        assert_eq!(trigrams("").count(), 0);
        assert_eq!(trigrams("abc").count(), 1);
    }

    #[test]
    fn percentile_picks_by_nearest_rank() {
        let v: Vec<u32> = (1..=100).collect();
        assert_eq!(percentile(&v, 0.99), 100);
        assert_eq!(percentile(&v, 0.50), 51);
        assert_eq!(percentile(&[], 0.99), 0);
        assert_eq!(percentile(&[7], 0.99), 7);
    }
}
