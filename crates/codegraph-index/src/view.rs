//! The read surface of an index.
//!
//! Two traits, deliberately:
//!
//! - [`IndexColumns`] is the **layout**: the raw columns an index is made of,
//!   as slices. [`IndexData`] (owned, what a build produces) and
//!   [`crate::MappedIndex`] (mmap'd, what a reader opens) both implement it,
//!   and a test can assert they agree column by column.
//! - [`IndexQuery`] is the **questions**: name lookup, prefix, trigram
//!   candidates, reachability, hub test. Anything with columns answers them
//!   through one blanket implementation, written once so the two backings
//!   cannot answer differently. A [`crate::Layered`] index — a base plus an
//!   overlay for the rows a delta added — has no single set of columns to hand
//!   out, so it implements the questions directly, from two sets.
//!
//! The engine is generic over `IndexQuery` only. It never sees a column.

use codegraph_core::{LocalId, RelationMask};

use crate::build::{IndexData, REACHABILITY_RELATIONS, trigrams};

/// The columns an index is made of.
pub trait IndexColumns {
    fn node_count(&self) -> usize;
    fn scc_count(&self) -> usize;
    fn hub_threshold(&self) -> u32;

    fn degree_out(&self) -> &[u32];
    fn degree_in(&self) -> &[u32];
    fn degree_total(&self) -> &[u32];
    fn scc_of(&self) -> &[u32];

    fn grail_k(&self) -> usize;
    fn grail_labels(&self) -> &[u32];

    fn name_count(&self) -> usize;
    fn name_key(&self, i: usize) -> &str;
    fn name_offsets(&self) -> &[u32];
    fn name_postings(&self) -> &[u32];

    fn trigram_keys(&self) -> &[u32];
    fn trigram_offsets(&self) -> &[u32];
    fn trigram_postings(&self) -> &[u32];

    // --- lookups over the columns, written once ---

    /// Postings of the folded name exactly `name`.
    fn exact_name_postings(&self, name: &str) -> &[u32] {
        exact_postings(self.name_count(), |i| self.name_key(i), self.name_offsets(), self.name_postings(), name)
    }

    /// Postings of every folded name starting with `prefix`, sorted, deduped.
    fn prefix_postings(&self, prefix: &str) -> Vec<u32> {
        prefix_postings(self.name_count(), |i| self.name_key(i), self.name_offsets(), self.name_postings(), prefix)
    }

    /// Rows whose search text may contain the (already folded) `needle`,
    /// given its trigrams. `None` means the needle is too short to filter.
    fn trigram_candidate_ids(&self, tris: &[u32]) -> Option<Vec<u32>> {
        trigram_candidate_ids(self.trigram_keys(), self.trigram_offsets(), self.trigram_postings(), tris)
    }

    /// Can component `ca` reach component `cb`, according to the labels? An
    /// exact "no", a "maybe" otherwise. Both must be component ids this
    /// index labelled.
    fn labels_may_reach(&self, ca: usize, cb: usize) -> bool {
        if ca == cb {
            return true;
        }
        let n = self.scc_count();
        let labels = self.grail_labels();
        for i in 0..self.grail_k() {
            let base = i * n * 2;
            let (ulo, uhi) = (labels[base + ca * 2], labels[base + ca * 2 + 1]);
            let (vlo, vhi) = (labels[base + cb * 2], labels[base + cb * 2 + 1]);
            if vlo < ulo || vhi > uhi {
                return false;
            }
        }
        true
    }
}

/// Everything a query needs from an index.
pub trait IndexQuery {
    /// Size of the id space — every row, live or not.
    fn symbols(&self) -> usize;
    /// Strongly connected components in the reachability graph.
    fn components(&self) -> usize;
    /// Traversal refuses to expand through a node whose degree is at or above
    /// this.
    fn hub_cutoff(&self) -> u32;

    /// Total degree of a row; `0` when out of range.
    fn degree(&self, id: LocalId) -> u32;
    /// `(out, in)` degree of a row.
    fn degrees(&self, id: LocalId) -> (u32, u32);

    /// Rows whose folded name is exactly `name`.
    fn by_exact_name(&self, name: &str) -> Vec<u32>;
    /// Rows whose folded name starts with `prefix`.
    fn by_name_prefix(&self, prefix: &str) -> Vec<u32>;

    /// Candidate rows whose search text may contain `needle`.
    ///
    /// A prefilter: never misses a real match, may return extras, so the caller
    /// must verify. `None` means "no filter possible, scan everything" —
    /// distinct from `Some(vec![])`, which means "provably nothing matches".
    fn trigram_candidates(&self, needle: &str) -> Option<Vec<u32>>;

    /// Can this index answer a reachability question posed with `mask`?
    fn covers(&self, mask: RelationMask) -> bool {
        mask.is_subset_of(REACHABILITY_RELATIONS)
    }

    /// `false` when `from` provably cannot reach `to` along flow relations.
    fn maybe_reaches(&self, from: LocalId, to: LocalId) -> bool;

    fn is_hub(&self, node: LocalId) -> bool {
        self.degree(node) >= self.hub_cutoff()
    }
}

impl<C: IndexColumns> IndexQuery for C {
    fn symbols(&self) -> usize {
        self.node_count()
    }
    fn components(&self) -> usize {
        self.scc_count()
    }
    fn hub_cutoff(&self) -> u32 {
        self.hub_threshold()
    }
    fn degree(&self, id: LocalId) -> u32 {
        self.degree_total().get(id.index()).copied().unwrap_or(0)
    }
    fn degrees(&self, id: LocalId) -> (u32, u32) {
        let i = id.index();
        (
            self.degree_out().get(i).copied().unwrap_or(0),
            self.degree_in().get(i).copied().unwrap_or(0),
        )
    }
    fn by_exact_name(&self, name: &str) -> Vec<u32> {
        self.exact_name_postings(name).to_vec()
    }
    fn by_name_prefix(&self, prefix: &str) -> Vec<u32> {
        self.prefix_postings(prefix)
    }
    fn trigram_candidates(&self, needle: &str) -> Option<Vec<u32>> {
        let needle = needle.to_lowercase();
        let tris: Vec<u32> = trigrams(&needle).collect();
        self.trigram_candidate_ids(&tris)
    }
    fn maybe_reaches(&self, from: LocalId, to: LocalId) -> bool {
        let (a, b) = (from.index(), to.index());
        if a >= self.node_count() || b >= self.node_count() {
            return false;
        }
        let scc = self.scc_of();
        self.labels_may_reach(scc[a] as usize, scc[b] as usize)
    }
}

/// Postings of the folded name exactly `name`, over a sorted key list behind
/// an accessor — binary search by index, since the keys are not one slice.
pub(crate) fn exact_postings<'a>(
    count: usize,
    key: impl Fn(usize) -> &'a str,
    offsets: &'a [u32],
    postings: &'a [u32],
    name: &str,
) -> &'a [u32] {
    let (mut lo, mut hi) = (0usize, count);
    while lo < hi {
        let mid = (lo + hi) / 2;
        match key(mid).cmp(name) {
            std::cmp::Ordering::Less => lo = mid + 1,
            std::cmp::Ordering::Greater => hi = mid,
            std::cmp::Ordering::Equal => {
                return &postings[offsets[mid] as usize..offsets[mid + 1] as usize];
            }
        }
    }
    &[]
}

/// Postings of every folded name starting with `prefix`, sorted, deduped.
pub(crate) fn prefix_postings<'a>(
    count: usize,
    key: impl Fn(usize) -> &'a str,
    offsets: &[u32],
    postings: &[u32],
    prefix: &str,
) -> Vec<u32> {
    let (mut lo, mut hi) = (0usize, count);
    while lo < hi {
        let mid = (lo + hi) / 2;
        if key(mid) < prefix {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    let mut out = Vec::new();
    for i in lo..count {
        if !key(i).starts_with(prefix) {
            break;
        }
        out.extend_from_slice(&postings[offsets[i] as usize..offsets[i + 1] as usize]);
    }
    out.sort_unstable();
    out.dedup();
    out
}

/// Rows whose search text may contain a needle with these trigrams. `None`
/// means the needle is too short to filter.
pub(crate) fn trigram_candidate_ids(
    keys: &[u32],
    offsets: &[u32],
    postings: &[u32],
    tris: &[u32],
) -> Option<Vec<u32>> {
    if tris.is_empty() {
        return None;
    }
    let posting = |tri: u32| -> &[u32] {
        match keys.binary_search(&tri) {
            Ok(i) => &postings[offsets[i] as usize..offsets[i + 1] as usize],
            Err(_) => &[],
        }
    };
    let mut lists: Vec<&[u32]> = tris.iter().map(|&t| posting(t)).collect();
    // Smallest first: the cost is bounded by the rarest trigram.
    lists.sort_by_key(|l| l.len());
    if lists[0].is_empty() {
        return Some(Vec::new());
    }
    let mut acc: Vec<u32> = lists[0].to_vec();
    for list in &lists[1..] {
        acc = intersect_sorted(&acc, list);
        if acc.is_empty() {
            break;
        }
    }
    Some(acc)
}

/// Union of two sorted, deduped lists.
pub(crate) fn intersect_union(a: Vec<u32>, b: Vec<u32>) -> Vec<u32> {
    if b.is_empty() {
        return a;
    }
    let mut out = a;
    out.extend(b);
    out.sort_unstable();
    out.dedup();
    out
}

pub(crate) fn intersect_sorted(a: &[u32], b: &[u32]) -> Vec<u32> {
    let mut out = Vec::with_capacity(a.len().min(b.len()));
    let (mut i, mut j) = (0usize, 0usize);
    while i < a.len() && j < b.len() {
        match a[i].cmp(&b[j]) {
            std::cmp::Ordering::Less => i += 1,
            std::cmp::Ordering::Greater => j += 1,
            std::cmp::Ordering::Equal => {
                out.push(a[i]);
                i += 1;
                j += 1;
            }
        }
    }
    out
}

impl IndexColumns for IndexData {
    fn node_count(&self) -> usize {
        self.node_count
    }
    fn scc_count(&self) -> usize {
        self.scc_count
    }
    fn hub_threshold(&self) -> u32 {
        self.hub_threshold
    }
    fn degree_out(&self) -> &[u32] {
        &self.degree_out
    }
    fn degree_in(&self) -> &[u32] {
        &self.degree_in
    }
    fn degree_total(&self) -> &[u32] {
        &self.degree_total
    }
    fn scc_of(&self) -> &[u32] {
        &self.scc_of
    }
    fn grail_k(&self) -> usize {
        self.grail.k()
    }
    fn grail_labels(&self) -> &[u32] {
        self.grail.labels()
    }
    fn name_count(&self) -> usize {
        self.name_keys.len()
    }
    fn name_key(&self, i: usize) -> &str {
        &self.name_keys[i]
    }
    fn name_offsets(&self) -> &[u32] {
        &self.name_offsets
    }
    fn name_postings(&self) -> &[u32] {
        &self.name_postings
    }
    fn trigram_keys(&self) -> &[u32] {
        &self.trigram_keys
    }
    fn trigram_offsets(&self) -> &[u32] {
        &self.trigram_offsets
    }
    fn trigram_postings(&self) -> &[u32] {
        &self.trigram_postings
    }
}

#[cfg(test)]
mod tests {
    use super::intersect_sorted;

    #[test]
    fn intersection_keeps_only_common_elements() {
        assert_eq!(intersect_sorted(&[1, 2, 3, 5], &[2, 3, 4]), vec![2, 3]);
        assert_eq!(intersect_sorted(&[1, 2], &[3, 4]), Vec::<u32>::new());
        assert_eq!(intersect_sorted(&[], &[1]), Vec::<u32>::new());
        assert_eq!(intersect_sorted(&[1, 2, 3], &[1, 2, 3]), vec![1, 2, 3]);
    }
}
