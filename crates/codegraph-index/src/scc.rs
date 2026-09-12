//! Strongly connected components, and the DAG they condense to.
//!
//! Reachability over a general digraph is expensive; over a DAG it admits cheap
//! interval labelling. Call graphs are nearly acyclic — recursion and mutual
//! recursion make small cycles — so condensing the SCCs first is what makes the
//! labelling in [`crate::grail`] worth building.
//!
//! Tarjan's algorithm, written **iteratively**. The recursive form is shorter
//! and is what every textbook shows, but its stack depth is the length of the
//! longest path: on a 5M-node call graph that overflows long before it finishes.

/// The SCC decomposition of a graph, plus its condensation.
#[derive(Debug, Clone)]
pub struct Sccs {
    /// Component id per node.
    pub of_node: Vec<u32>,
    pub count: usize,
    /// Condensation adjacency, CSR: component -> component, deduplicated and
    /// self-loop-free.
    pub dag_offsets: Vec<u32>,
    pub dag_targets: Vec<u32>,
}

impl Sccs {
    #[inline]
    pub fn component(&self, node: u32) -> u32 {
        self.of_node[node as usize]
    }

    /// Components reachable in one hop from `c`.
    #[inline]
    pub fn successors(&self, c: u32) -> &[u32] {
        let (a, b) = (self.dag_offsets[c as usize] as usize, self.dag_offsets[c as usize + 1] as usize);
        &self.dag_targets[a..b]
    }

    /// Two nodes in the same component reach each other by definition.
    #[inline]
    pub fn same_component(&self, a: u32, b: u32) -> bool {
        self.of_node[a as usize] == self.of_node[b as usize]
    }
}

/// Adjacency the algorithms here need: `successors(node)` over `0..n`.
pub trait Graph {
    fn node_count(&self) -> usize;
    /// Call `f` with each successor of `node`.
    fn for_each_successor(&self, node: u32, f: &mut dyn FnMut(u32));
}

/// A plain CSR graph, used by tests and by callers that already have one.
pub struct CsrGraph<'a> {
    pub offsets: &'a [u64],
    pub targets: &'a [u32],
}

impl Graph for CsrGraph<'_> {
    fn node_count(&self) -> usize {
        self.offsets.len().saturating_sub(1)
    }
    fn for_each_successor(&self, node: u32, f: &mut dyn FnMut(u32)) {
        let (a, b) = (self.offsets[node as usize] as usize, self.offsets[node as usize + 1] as usize);
        for &t in &self.targets[a..b] {
            f(t);
        }
    }
}

const UNVISITED: u32 = u32::MAX;

/// Tarjan's SCC, iterative.
pub fn compute(g: &dyn Graph) -> Sccs {
    let n = g.node_count();
    let mut index = vec![UNVISITED; n];
    let mut lowlink = vec![0u32; n];
    let mut on_stack = vec![false; n];
    let mut comp = vec![UNVISITED; n];
    let mut stack: Vec<u32> = Vec::new();
    let mut next_index: u32 = 0;
    let mut count: usize = 0;

    // Successors are materialised per frame rather than re-walked, so the
    // iterative form resumes exactly where the recursive one would.
    struct Frame {
        node: u32,
        succ: Vec<u32>,
        next: usize,
    }
    let mut frames: Vec<Frame> = Vec::new();

    for root in 0..n as u32 {
        if index[root as usize] != UNVISITED {
            continue;
        }
        let mut succ = Vec::new();
        g.for_each_successor(root, &mut |t| succ.push(t));
        frames.push(Frame { node: root, succ, next: 0 });
        index[root as usize] = next_index;
        lowlink[root as usize] = next_index;
        next_index += 1;
        stack.push(root);
        on_stack[root as usize] = true;

        while let Some(frame) = frames.last_mut() {
            let v = frame.node;
            if frame.next < frame.succ.len() {
                let w = frame.succ[frame.next];
                frame.next += 1;
                if w as usize >= n {
                    continue; // defensive: a malformed edge cannot panic here
                }
                if index[w as usize] == UNVISITED {
                    let mut s = Vec::new();
                    g.for_each_successor(w, &mut |t| s.push(t));
                    index[w as usize] = next_index;
                    lowlink[w as usize] = next_index;
                    next_index += 1;
                    stack.push(w);
                    on_stack[w as usize] = true;
                    frames.push(Frame { node: w, succ: s, next: 0 });
                } else if on_stack[w as usize] {
                    lowlink[v as usize] = lowlink[v as usize].min(index[w as usize]);
                }
            } else {
                // Frame exhausted: close the component if v is a root.
                if lowlink[v as usize] == index[v as usize] {
                    let id = count as u32;
                    count += 1;
                    while let Some(w) = stack.pop() {
                        on_stack[w as usize] = false;
                        comp[w as usize] = id;
                        if w == v {
                            break;
                        }
                    }
                }
                frames.pop();
                if let Some(parent) = frames.last() {
                    let p = parent.node as usize;
                    lowlink[p] = lowlink[p].min(lowlink[v as usize]);
                }
            }
        }
    }

    // Tarjan emits components in reverse topological order. Reverse the
    // numbering so an edge always runs from a lower id to a higher one, which
    // lets the labelling below assume a topological order for free.
    let last = count.saturating_sub(1) as u32;
    for c in &mut comp {
        *c = last - *c;
    }

    let (dag_offsets, dag_targets) = condense(g, &comp, count);
    Sccs { of_node: comp, count, dag_offsets, dag_targets }
}

/// Build the condensation's CSR: one edge per distinct component pair, no
/// self-loops (an intra-component edge carries no reachability information the
/// component id does not already carry).
fn condense(g: &dyn Graph, comp: &[u32], count: usize) -> (Vec<u32>, Vec<u32>) {
    let mut per_comp: Vec<Vec<u32>> = vec![Vec::new(); count];
    for v in 0..comp.len() as u32 {
        let cv = comp[v as usize];
        g.for_each_successor(v, &mut |w| {
            if (w as usize) < comp.len() {
                let cw = comp[w as usize];
                if cw != cv {
                    per_comp[cv as usize].push(cw);
                }
            }
        });
    }
    let mut offsets = Vec::with_capacity(count + 1);
    let mut targets = Vec::new();
    offsets.push(0u32);
    for list in &mut per_comp {
        list.sort_unstable();
        list.dedup();
        targets.extend_from_slice(list);
        offsets.push(targets.len() as u32);
    }
    (offsets, targets)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a CSR from an edge list.
    fn csr(n: usize, edges: &[(u32, u32)]) -> (Vec<u64>, Vec<u32>) {
        let mut per: Vec<Vec<u32>> = vec![Vec::new(); n];
        for &(a, b) in edges {
            per[a as usize].push(b);
        }
        let mut offsets = vec![0u64];
        let mut targets = Vec::new();
        for list in &per {
            targets.extend_from_slice(list);
            offsets.push(targets.len() as u64);
        }
        (offsets, targets)
    }

    fn sccs(n: usize, edges: &[(u32, u32)]) -> Sccs {
        let (o, t) = csr(n, edges);
        compute(&CsrGraph { offsets: &o, targets: &t })
    }

    #[test]
    fn isolated_nodes_are_their_own_components() {
        let s = sccs(3, &[]);
        assert_eq!(s.count, 3);
        assert_ne!(s.component(0), s.component(1));
    }

    #[test]
    fn a_chain_has_no_cycles() {
        let s = sccs(4, &[(0, 1), (1, 2), (2, 3)]);
        assert_eq!(s.count, 4);
        // Numbering is topological: an edge runs low -> high.
        for &(a, b) in &[(0u32, 1u32), (1, 2), (2, 3)] {
            assert!(s.component(a) < s.component(b), "not topologically ordered");
        }
    }

    #[test]
    fn a_cycle_collapses_to_one_component() {
        let s = sccs(3, &[(0, 1), (1, 2), (2, 0)]);
        assert_eq!(s.count, 1);
        assert!(s.same_component(0, 2));
    }

    /// Mutual recursion is the shape that actually occurs in call graphs.
    #[test]
    fn mutual_recursion_collapses() {
        // 0 -> 1 -> 0, plus a tail 1 -> 2.
        let s = sccs(3, &[(0, 1), (1, 0), (1, 2)]);
        assert_eq!(s.count, 2);
        assert!(s.same_component(0, 1));
        assert!(!s.same_component(0, 2));
        assert!(s.component(0) < s.component(2));
    }

    #[test]
    fn self_loops_do_not_create_extra_components() {
        let s = sccs(2, &[(0, 0), (0, 1)]);
        assert_eq!(s.count, 2);
        // A self-loop contributes no condensation edge.
        assert_eq!(s.successors(s.component(0)), &[s.component(1)]);
    }

    #[test]
    fn the_condensation_is_deduplicated() {
        // Two parallel paths from 0's component into 3's.
        let s = sccs(4, &[(0, 1), (0, 2), (1, 3), (2, 3)]);
        let c0 = s.component(0);
        // 0 -> {1,2}: two distinct components, listed once each.
        let succ = s.successors(c0);
        assert_eq!(succ.len(), 2);
        assert!(succ.windows(2).all(|w| w[0] < w[1]), "successors must be sorted");
    }

    #[test]
    fn two_disjoint_cycles_stay_separate() {
        let s = sccs(6, &[(0, 1), (1, 0), (2, 3), (3, 2), (4, 5)]);
        assert_eq!(s.count, 4);
        assert!(s.same_component(0, 1));
        assert!(s.same_component(2, 3));
        assert!(!s.same_component(0, 2));
    }

    /// The reason this is iterative. A recursive Tarjan overflows here.
    #[test]
    fn a_very_deep_chain_does_not_overflow() {
        let n = 200_000usize;
        let edges: Vec<(u32, u32)> = (0..n as u32 - 1).map(|i| (i, i + 1)).collect();
        let s = sccs(n, &edges);
        assert_eq!(s.count, n);
        assert!(s.component(0) < s.component(n as u32 - 1));
    }

    #[test]
    fn a_large_cycle_does_not_overflow() {
        let n = 200_000usize;
        let mut edges: Vec<(u32, u32)> = (0..n as u32 - 1).map(|i| (i, i + 1)).collect();
        edges.push((n as u32 - 1, 0));
        let s = sccs(n, &edges);
        assert_eq!(s.count, 1, "the whole chain is one cycle");
    }

    /// Every edge in the condensation must run strictly forward, or the
    /// interval labelling built on top of it is unsound.
    #[test]
    fn condensation_edges_run_strictly_forward() {
        let edges: Vec<(u32, u32)> = (0..500u32)
            .flat_map(|i| [(i, (i * 7 + 1) % 500), (i, (i * 13 + 5) % 500)])
            .collect();
        let s = sccs(500, &edges);
        for c in 0..s.count as u32 {
            for &t in s.successors(c) {
                assert!(c < t, "condensation edge {c} -> {t} is not forward");
            }
        }
    }
}
