//! GRAIL-style interval labels: a cheap, exact *negative* answer to
//! "can u reach v?".
//!
//! # What it does and does not promise
//!
//! Each node gets `k` intervals, one per randomised DFS over the condensation
//! DAG. If u reaches v then v's subtree sits inside u's in **every** traversal,
//! so `label_i(v) ⊆ label_i(u)` for all i. Contrapositive: find a single `i`
//! where containment fails and u provably does **not** reach v.
//!
//! The converse does not hold. Containment in all `k` traversals is necessary
//! but not sufficient, so a positive answer is only "maybe" and has to be
//! settled by an actual search. That asymmetry is the whole design: on a real
//! call graph the overwhelming majority of source→sink pairs are unreachable,
//! and this rejects them in `k` comparisons instead of a traversal.
//!
//! # Choosing `k`
//!
//! Raising `k` costs `8 * k` bytes per node and rejects more pairs. Measured
//! rejection rate over the unreachable pairs (see the `calibration` module,
//! which is how these numbers were produced and can reproduce them):
//!
//! | k | call-graph-shaped | dense random |
//! |---|---|---|
//! | 1 | 91.1% | 55.9% |
//! | 2 | 92.3% | 70.3% |
//! | 4 | **93.7%** | 81.3% |
//! | 8 | 94.4% | 88.4% |
//! | 12 | 94.7% | 91.4% |
//!
//! On the shape this index actually sees — mostly short-range edges within a
//! module, a few long-range ones — the curve flattens after `k = 3`: going from
//! 4 to 12 buys 1.0 percentage point for three times the space. `k = 4` sits at
//! the knee.
//!
//! A uniformly random DAG behaves quite differently and is still climbing at
//! `k = 12`. Interval labelling is defeated by cross edges with no locality,
//! and that column is here as a caution: if the graph shape ever changes —
//! a corpus dominated by generated code, say — this table needs re-measuring
//! rather than assuming.

/// Default number of independent labelings.
pub const DEFAULT_K: usize = 4;

/// One open frame of the iterative post-order walk:
/// `(node, slice start in the scratch buffer, child count, next child index)`.
type Frame = (u32, usize, usize, usize);

/// Interval labels over a DAG.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Grail {
    k: usize,
    n: usize,
    /// `k` blocks of `n` pairs: `labels[i * n * 2 + v * 2]` is v's min in
    /// labeling i, `+ 1` its max. One flat allocation so a lookup is two
    /// indexed reads and the whole thing mmaps as a `[u32]`.
    labels: Vec<u32>,
}

/// Deterministic PRNG. Seeded from the labeling index, so an index built twice
/// from the same graph is byte-identical — a store that cannot be rebuilt
/// reproducibly cannot be diffed.
struct SplitMix64(u64);

impl SplitMix64 {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    fn shuffle<T>(&mut self, v: &mut [T]) {
        for i in (1..v.len()).rev() {
            let j = (self.next() % (i as u64 + 1)) as usize;
            v.swap(i, j);
        }
    }
}

impl Grail {
    pub fn k(&self) -> usize {
        self.k
    }
    pub fn node_count(&self) -> usize {
        self.n
    }
    pub fn labels(&self) -> &[u32] {
        &self.labels
    }

    /// Rebuild from persisted label bytes.
    pub fn from_labels(k: usize, n: usize, labels: Vec<u32>) -> Option<Self> {
        (labels.len() == k * n * 2).then_some(Self { k, n, labels })
    }

    /// Build `k` labelings over a DAG given in CSR form.
    ///
    /// `offsets`/`targets` must describe an acyclic graph — condense the SCCs
    /// first. A cycle would not corrupt memory, but the intervals would stop
    /// meaning anything.
    pub fn build(offsets: &[u32], targets: &[u32], k: usize) -> Self {
        let n = offsets.len().saturating_sub(1);
        let mut labels = vec![0u32; k * n * 2];
        if n == 0 {
            return Self { k, n, labels };
        }

        let mut order: Vec<u32> = (0..n as u32).collect();
        // One scratch buffer for the whole build. Every open frame owns a
        // contiguous slice of it, and because frames are LIFO, finishing one
        // just truncates. That is one allocation per build instead of one per
        // node, which on a multi-million-node DAG is the difference between
        // fast and allocator-bound.
        let mut pending: Vec<u32> = Vec::new();
        let mut frames: Vec<Frame> = Vec::new();

        for i in 0..k {
            // Seeded per labeling, so the traversals differ from each other but
            // the set of them is reproducible.
            let mut rng = SplitMix64(0x5EED_0000_0000_0000 ^ (i as u64).wrapping_mul(0x9E37_79B9));
            rng.shuffle(&mut order);

            let base = i * n * 2;
            let mut visited = vec![false; n];
            let mut rank: u32 = 0;
            pending.clear();
            frames.clear();

            // Iterative post-order: a recursive walk would have stack depth
            // equal to the longest path in the DAG.
            let open = |v: u32, pending: &mut Vec<u32>, frames: &mut Vec<Frame>, rng: &mut SplitMix64| {
                let (a, b) = (offsets[v as usize] as usize, offsets[v as usize + 1] as usize);
                let start = pending.len();
                pending.extend_from_slice(&targets[a..b]);
                rng.shuffle(&mut pending[start..]);
                frames.push((v, start, b - a, 0));
            };

            for &root in &order {
                if visited[root as usize] {
                    continue;
                }
                visited[root as usize] = true;
                open(root, &mut pending, &mut frames, &mut rng);

                while let Some(&(v, start, len, next)) = frames.last() {
                    if next < len {
                        let child = pending[start + next];
                        frames.last_mut().expect("frame exists").3 += 1;
                        if !visited[child as usize] {
                            visited[child as usize] = true;
                            open(child, &mut pending, &mut frames, &mut rng);
                        }
                    } else {
                        // Finish v: its rank is its post-order number, and its
                        // interval minimum is the smallest minimum among its
                        // children — or its own rank when it has none.
                        rank += 1;
                        let mut lo = rank;
                        for j in 0..len {
                            let c = pending[start + j] as usize;
                            let cl = labels[base + c * 2];
                            // A zero label means "not yet assigned", which
                            // cannot happen for a finished child in a DAG; the
                            // guard keeps a cyclic input from poisoning `lo`.
                            if cl != 0 && cl < lo {
                                lo = cl;
                            }
                        }
                        labels[base + v as usize * 2] = lo;
                        labels[base + v as usize * 2 + 1] = rank;
                        pending.truncate(start);
                        frames.pop();
                    }
                }
            }
        }

        Self { k, n, labels }
    }

    /// `false` means u provably does **not** reach v. `true` means "maybe" and
    /// must be settled by a search.
    ///
    /// Reflexive by definition: a node reaches itself.
    #[inline]
    pub fn maybe_reaches(&self, u: u32, v: u32) -> bool {
        if u == v {
            return true;
        }
        let (u, v) = (u as usize, v as usize);
        if u >= self.n || v >= self.n {
            return false;
        }
        for i in 0..self.k {
            let base = i * self.n * 2;
            let (ulo, uhi) = (self.labels[base + u * 2], self.labels[base + u * 2 + 1]);
            let (vlo, vhi) = (self.labels[base + v * 2], self.labels[base + v * 2 + 1]);
            // Containment: v's whole interval must sit inside u's.
            if vlo < ulo || vhi > uhi {
                return false;
            }
        }
        true
    }
}


#[cfg(test)]
pub(crate) mod tests_support {
    use super::SplitMix64;
    use std::collections::VecDeque;

    pub fn build_csr(n: usize, edges: &[(u32, u32)]) -> (Vec<u32>, Vec<u32>) {
        let mut per: Vec<Vec<u32>> = vec![Vec::new(); n];
        for &(a, b) in edges {
            per[a as usize].push(b);
        }
        let mut offsets = vec![0u32];
        let mut targets = Vec::new();
        for list in &per {
            targets.extend_from_slice(list);
            offsets.push(targets.len() as u32);
        }
        (offsets, targets)
    }

    pub fn bfs_reaches(n: usize, offsets: &[u32], targets: &[u32], src: u32) -> Vec<bool> {
        let mut seen = vec![false; n];
        let mut q = VecDeque::new();
        seen[src as usize] = true;
        q.push_back(src);
        while let Some(v) = q.pop_front() {
            let (a, b) = (offsets[v as usize] as usize, offsets[v as usize + 1] as usize);
            for &t in &targets[a..b] {
                if !seen[t as usize] {
                    seen[t as usize] = true;
                    q.push_back(t);
                }
            }
        }
        seen
    }

    /// Uniformly random forward edges. The *pessimal* shape for interval
    /// labelling: cross edges everywhere, no locality to exploit.
    pub fn dense_random(n: usize) -> (usize, Vec<u32>, Vec<u32>) {
        let mut rng = SplitMix64(12345);
        let mut edges = Vec::new();
        for a in 0..n as u32 {
            for _ in 0..2 {
                let span = n as u32 - a;
                if span <= 1 { continue; }
                edges.push((a, a + 1 + (rng.next() % (span - 1) as u64) as u32));
            }
        }
        edges.sort_unstable();
        edges.dedup();
        let (o, t) = build_csr(n, &edges);
        (n, o, t)
    }

    /// Closer to a real call graph: mostly short-range edges within a module,
    /// with a few long-range ones. This is the shape the index actually sees.
    pub fn call_graph_ish(n: usize) -> (usize, Vec<u32>, Vec<u32>) {
        let mut rng = SplitMix64(777);
        let mut edges = Vec::new();
        for a in 0..n as u32 {
            for _ in 0..3 {
                let local = 1 + (rng.next() % 12) as u32;
                let b = a + local;
                if (b as usize) < n {
                    edges.push((a, b));
                }
            }
            if rng.next().is_multiple_of(10) {
                let span = n as u32 - a;
                if span > 1 {
                    edges.push((a, a + 1 + (rng.next() % (span - 1) as u64) as u32));
                }
            }
        }
        edges.sort_unstable();
        edges.dedup();
        let (o, t) = build_csr(n, &edges);
        (n, o, t)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    fn dag(n: usize, edges: &[(u32, u32)]) -> (Vec<u32>, Vec<u32>) {
        let mut per: Vec<Vec<u32>> = vec![Vec::new(); n];
        for &(a, b) in edges {
            assert!(a < b, "test DAGs must be topologically ordered");
            per[a as usize].push(b);
        }
        let mut offsets = vec![0u32];
        let mut targets = Vec::new();
        for list in &per {
            targets.extend_from_slice(list);
            offsets.push(targets.len() as u32);
        }
        (offsets, targets)
    }

    /// Ground truth, for comparison.
    fn bfs_reaches(n: usize, offsets: &[u32], targets: &[u32], src: u32) -> Vec<bool> {
        let mut seen = vec![false; n];
        let mut q = VecDeque::new();
        seen[src as usize] = true;
        q.push_back(src);
        while let Some(v) = q.pop_front() {
            let (a, b) = (offsets[v as usize] as usize, offsets[v as usize + 1] as usize);
            for &t in &targets[a..b] {
                if !seen[t as usize] {
                    seen[t as usize] = true;
                    q.push_back(t);
                }
            }
        }
        seen
    }

    #[test]
    fn empty_graph_is_fine() {
        let g = Grail::build(&[0], &[], DEFAULT_K);
        assert_eq!(g.node_count(), 0);
    }

    #[test]
    fn a_node_reaches_itself() {
        let (o, t) = dag(3, &[(0, 1)]);
        let g = Grail::build(&o, &t, DEFAULT_K);
        for v in 0..3 {
            assert!(g.maybe_reaches(v, v));
        }
    }

    #[test]
    fn a_chain_is_reachable_forward_and_rejected_backward() {
        let (o, t) = dag(5, &[(0, 1), (1, 2), (2, 3), (3, 4)]);
        let g = Grail::build(&o, &t, DEFAULT_K);
        assert!(g.maybe_reaches(0, 4));
        assert!(!g.maybe_reaches(4, 0), "backward reachability must be rejected");
        assert!(!g.maybe_reaches(3, 1));
    }

    #[test]
    fn disconnected_components_are_rejected() {
        let (o, t) = dag(4, &[(0, 1), (2, 3)]);
        let g = Grail::build(&o, &t, DEFAULT_K);
        assert!(!g.maybe_reaches(0, 2));
        assert!(!g.maybe_reaches(0, 3));
        assert!(g.maybe_reaches(2, 3));
    }

    /// **The soundness property.** A false negative would make a taint query
    /// silently miss a real path, which is the worst failure this crate could
    /// have. Checked exhaustively against BFS on random DAGs.
    #[test]
    fn never_reports_a_false_negative() {
        for seed in 0..40u64 {
            let n = 60usize;
            let mut rng = SplitMix64(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1);
            let mut edges = Vec::new();
            for a in 0..n as u32 {
                for _ in 0..3 {
                    let span = n as u32 - a;
                    if span <= 1 {
                        continue;
                    }
                    let b = a + 1 + (rng.next() % (span - 1) as u64) as u32;
                    edges.push((a, b));
                }
            }
            edges.sort_unstable();
            edges.dedup();
            let (o, t) = dag(n, &edges);
            let g = Grail::build(&o, &t, DEFAULT_K);

            for src in 0..n as u32 {
                let truth = bfs_reaches(n, &o, &t, src);
                for dst in 0..n as u32 {
                    if truth[dst as usize] {
                        assert!(
                            g.maybe_reaches(src, dst),
                            "seed {seed}: {src} reaches {dst} but the label rejected it"
                        );
                    }
                }
            }
        }
    }

    fn rejection_rate(n: usize, o: &[u32], t: &[u32], k: usize) -> f64 {
        let g = Grail::build(o, t, k);
        let (mut unreachable, mut rejected) = (0usize, 0usize);
        for src in 0..n as u32 {
            let truth = bfs_reaches(n, o, t, src);
            for dst in 0..n as u32 {
                if !truth[dst as usize] {
                    unreachable += 1;
                    if !g.maybe_reaches(src, dst) {
                        rejected += 1;
                    }
                }
            }
        }
        rejected as f64 / unreachable as f64
    }

    /// A filter that always says "maybe" is sound and worthless. On the shape
    /// this index actually sees, `DEFAULT_K` must reject the large majority of
    /// unreachable pairs. Threshold set from the calibration table with margin,
    /// not guessed.
    #[test]
    fn rejects_the_large_majority_on_call_graph_shaped_input() {
        let (n, o, t) = super::tests_support::call_graph_ish(400);
        let rate = rejection_rate(n, &o, &t, DEFAULT_K);
        assert!(
            rate > 0.90,
            "rejected only {:.1}% of unreachable pairs on realistic input",
            rate * 100.0
        );
    }

    /// A uniformly random DAG is the pessimal shape. Assert only that the
    /// filter still does real work there — not the realistic rate, which it
    /// does not reach and is not expected to.
    #[test]
    fn still_rejects_usefully_on_the_pessimal_shape() {
        let (n, o, t) = super::tests_support::dense_random(200);
        let rate = rejection_rate(n, &o, &t, DEFAULT_K);
        assert!(rate > 0.70, "only {:.1}% on dense random input", rate * 100.0);
    }

    /// More labels must never reject *fewer* pairs — that would mean the
    /// labelling is not monotone and the calibration table is meaningless.
    #[test]
    fn more_labels_never_reject_less() {
        let (n, o, t) = super::tests_support::call_graph_ish(200);
        let mut prev = 0.0;
        for k in [1usize, 2, 4, 8] {
            let rate = rejection_rate(n, &o, &t, k);
            assert!(rate >= prev - 1e-9, "k={k} rejected {rate:.3} < {prev:.3} at a lower k");
            prev = rate;
        }
    }

    /// An index that cannot be rebuilt reproducibly cannot be diffed.
    #[test]
    fn building_is_deterministic() {
        let (o, t) = dag(50, &(0..49u32).map(|i| (i, i + 1)).collect::<Vec<_>>());
        assert_eq!(Grail::build(&o, &t, DEFAULT_K), Grail::build(&o, &t, DEFAULT_K));
    }

    #[test]
    fn labels_round_trip() {
        let (o, t) = dag(10, &[(0, 1), (1, 2), (0, 3)]);
        let g = Grail::build(&o, &t, DEFAULT_K);
        let back = Grail::from_labels(g.k(), g.node_count(), g.labels().to_vec()).unwrap();
        assert_eq!(g, back);
        assert!(Grail::from_labels(g.k(), g.node_count(), vec![0; 3]).is_none());
    }

    #[test]
    fn a_deep_chain_does_not_overflow() {
        let n = 100_000usize;
        let edges: Vec<(u32, u32)> = (0..n as u32 - 1).map(|i| (i, i + 1)).collect();
        let (o, t) = dag(n, &edges);
        let g = Grail::build(&o, &t, 2);
        assert!(g.maybe_reaches(0, n as u32 - 1));
        assert!(!g.maybe_reaches(n as u32 - 1, 0));
    }
}

#[cfg(test)]
mod calibration {
    use super::*;
    use super::tests_support::*;

    /// Prints the rejection rate against `k` on two graph shapes. Ignored by
    /// default — this is how `DEFAULT_K` was chosen, kept so the choice can be
    /// re-checked rather than trusted.
    #[test]
    #[ignore = "calibration; run with --ignored to see the curve"]
    fn rejection_rate_by_k() {
        for (name, (n, o, t)) in [("dense-random", dense_random(200)), ("call-graph-ish", call_graph_ish(400))] {
            println!("\n{name}: {n} nodes, {} edges", t.len());
            for k in [1usize, 2, 3, 4, 6, 8, 12] {
                let g = Grail::build(&o, &t, k);
                let (mut un, mut rej) = (0usize, 0usize);
                for src in 0..n as u32 {
                    let truth = bfs_reaches(n, &o, &t, src);
                    for dst in 0..n as u32 {
                        if !truth[dst as usize] {
                            un += 1;
                            if !g.maybe_reaches(src, dst) {
                                rej += 1;
                            }
                        }
                    }
                }
                println!(
                    "  k={k:<3} rejects {:>5.1}%   {:>6} bytes/node",
                    rej as f64 / un as f64 * 100.0,
                    k * 8
                );
            }
        }
    }
}
