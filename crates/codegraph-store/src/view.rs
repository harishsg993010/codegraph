//! A store-wide view over every live segment.
//!
//! A segment knows only its own rows. Once a store holds more than one — a
//! compacted base plus the delta segments an incremental update writes — three
//! questions have no per-segment answer, and this is where they are answered
//! once so no query has to:
//!
//! 1. **Which rows count.** A row is live when the manifest still names its
//!    segment as the owner of its file's tier. Rows flagged `EXTERNAL` (package
//!    stubs) have no file of their own and are live in every segment. Rows
//!    flagged `PROXY` are live with their file like any other, but are never
//!    canonical: each stands in for a symbol another file defines, so that its
//!    file can own edges *leaving* that symbol, and its edges are read as the
//!    symbol's.
//! 2. **Which row is *the* row for a key.** A file re-indexed into a delta has
//!    a dead row in the base and a live one in the delta, both under the same
//!    [`SymbolKey`]; a package imported by two files in two segments has two
//!    live rows. The view picks one *canonical* row per key — the live one in
//!    the latest segment — and forwards everything else to it.
//! 3. **Where an edge lands.** A CSR target is a `LocalId` inside one segment;
//!    forwarding turns it into the canonical row. An `EdgeExt` names its target
//!    by key; the view resolves it at build time so traversal never touches a
//!    key table.
//!
//! # The id space
//!
//! Rows are numbered densely across segments in segment-id order, so segment
//! `i`'s row `l` is `bases[i] + l`. Dead rows keep their number — renumbering
//! would make ids differ between two views of the same segment set — and are
//! skipped by [`View::ids`]. The query layer reuses [`LocalId`] for these
//! store-wide ids: on a single compacted segment the two are the same number,
//! which is what every existing caller was already relying on.
//!
//! # Cost
//!
//! A single-segment store with every file live builds a view in O(files) and
//! answers every edge question straight from the CSR. The forwarding tables
//! are only materialised once a store has dead rows or several segments, and
//! they are proportional to the dead and duplicated rows — the changed files —
//! not to the store.

use std::collections::HashMap;

use codegraph_core::{Confidence, LocalId, Relation, RelationMask, SymbolKey};

use crate::error::{Result, StoreError};
use crate::format::{FileRow, Tier, node_flags};
use crate::manifest::Manifest;
use crate::reader::Segment;

const STANDS_FOR: u8 = Relation::StandsFor.as_u8();

/// The precomputed part of a view. Owned by the store, rebuilt on commit.
#[derive(Debug, Default)]
pub struct ViewData {
    /// Store-wide id base per segment, plus a trailing total.
    bases: Vec<u32>,
    /// Per segment, per `FileId`: does this segment still own the file's rows?
    file_live: Vec<Vec<bool>>,
    /// Per segment: every file live, so no row needs a liveness test.
    all_live: Vec<bool>,
    /// One bit per store-wide id: set when the row is *not* canonical — dead,
    /// or shadowed by a same-key row in a later segment. A bit rather than a
    /// hash lookup because this test runs once per edge on every traversal.
    noncanon: Vec<u64>,
    /// Non-canonical id -> the canonical row for its key. Absent when the key
    /// has no live row anywhere: the symbol was deleted.
    redirect: HashMap<u32, u32>,
    /// Canonical id -> the rows forwarded to it. The reverse direction needs
    /// it: an edge written against a now-dead row still points *at* it.
    shadows: HashMap<u32, Vec<u32>>,
    /// Key -> rows, for segments whose key column is not sorted. Built only
    /// when something needs to look a key up across segments.
    unsorted: HashMap<SymbolKey, Vec<u32>>,
    /// Per segment: `(source local, ext index)` sorted by source, so a row's
    /// external edges are a contiguous run found by binary search.
    ext_by_source: Vec<Vec<(u32, u32)>>,
    /// Per segment, per ext edge: the canonical target, or `u32::MAX` when the
    /// key resolves to nothing in this store.
    ext_target: Vec<Vec<u32>>,
    /// Canonical target -> `(segment index, ext index)` of edges pointing at it.
    ext_in: HashMap<u32, Vec<(u32, u32)>>,
    /// One segment, every row live, no external edges: the CSR *is* the graph.
    simple: bool,
    /// As `simple`, but proxy rows allowed: the CSR is the graph once each
    /// proxy's edges are read as its symbol's.
    single_live: bool,
}

/// One edge as seen through the view. `node` is the far end — the target for
/// an outgoing edge, the source for an incoming one — as a store-wide id.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ViewEdge<'a> {
    pub node: LocalId,
    pub relation: Relation,
    pub confidence: Confidence,
    pub flags: u8,
    pub line: u32,
    /// See [`crate::OutEdge::context`].
    pub context: Option<&'a str>,
}

impl ViewData {
    pub fn build(segments: &[(u64, Segment)], manifest: &Manifest) -> Result<Self> {
        let mut v = ViewData::default();
        let n_segs = segments.len();

        // --- id bases and file liveness ---
        v.bases.push(0);
        for (id, seg) in segments {
            let tier = seg.tier().unwrap_or(Tier::Ast);
            let live: Vec<bool> = seg
                .files()?
                .iter()
                .map(|f| manifest.is_live(seg.string(f.path), tier, *id))
                .collect();
            v.all_live.push(live.iter().all(|l| *l));
            v.file_live.push(live);
            let next = v.bases.last().expect("base") + seg.node_count() as u32;
            v.bases.push(next);
        }
        let total = *v.bases.last().expect("base") as usize;
        v.noncanon = vec![0u64; total.div_ceil(64)];

        let any_dead = v.all_live.iter().any(|a| !*a);
        let any_ext = segments.iter().any(|(_, s)| s.ext_edges().is_ok_and(|e| !e.is_empty()));
        let any_proxy = segments
            .iter()
            .any(|(_, s)| s.node_flags().is_ok_and(|f| f.iter().any(|x| x & node_flags::PROXY != 0)));
        v.single_live = n_segs <= 1 && !any_dead && !any_ext;
        v.simple = v.single_live && !any_proxy;
        if v.simple {
            v.ext_by_source = vec![Vec::new(); n_segs];
            v.ext_target = vec![Vec::new(); n_segs];
            return Ok(v);
        }

        // --- key table for unsorted segments ---
        // Needed to find a dead row's replacement and an ext edge's target.
        for (i, (_, seg)) in segments.iter().enumerate() {
            if seg.keys_are_sorted() {
                continue;
            }
            for (l, &k) in seg.keys()?.iter().enumerate() {
                v.unsorted.entry(k).or_default().push(v.bases[i] + l as u32);
            }
        }

        // --- dead rows, and duplicated external rows ---
        let mut dead: Vec<u32> = Vec::new();
        let mut externals: HashMap<SymbolKey, Vec<u32>> = HashMap::new();
        let mut proxies: Vec<u32> = Vec::new();
        for (i, (_, seg)) in segments.iter().enumerate() {
            let flags = seg.node_flags()?;
            let files = seg.node_files()?;
            let keys = seg.keys()?;
            let live = &v.file_live[i];
            for l in 0..seg.node_count() {
                let g = v.bases[i] + l as u32;
                if flags[l] & node_flags::EXTERNAL != 0 {
                    if n_segs > 1 {
                        externals.entry(keys[l]).or_default().push(g);
                    }
                } else if !v.all_live[i] && !live.get(files[l].index()).copied().unwrap_or(false) {
                    dead.push(g);
                } else if flags[l] & node_flags::PROXY != 0 {
                    proxies.push(g);
                }
            }
        }
        for g in &dead {
            v.mark_noncanon(*g);
        }
        // A proxy is never canonical. Its forward is set once the real rows
        // are settled, below.
        for g in &proxies {
            v.mark_noncanon(*g);
        }
        // Among external rows for one key the later segment wins, matching
        // compaction's rule. But an external row is only ever a *stand-in* —
        // a package stub, or a delta's proxy for a symbol whose row lives in
        // the base so that edges can leave it — so a live real row for the
        // same key outranks every stand-in.
        for (key, mut rows) in externals {
            rows.sort_unstable();
            let real = v.find_real(segments, key, &rows);
            let canon = real.unwrap_or(*rows.last().expect("one or more"));
            for g in &rows {
                if *g == canon {
                    continue;
                }
                v.mark_noncanon(*g);
                v.redirect.insert(*g, canon);
                v.shadows.entry(canon).or_default().push(*g);
            }
        }
        // A dead row forwards to the live row with its key, if there is one.
        for g in dead {
            let (i, l) = v.locate(g).expect("dead row is in range");
            let key = segments[i].1.keys()?[l.index()];
            if let Some(canon) = v.find_in(segments, key) {
                v.redirect.insert(g, canon);
                v.shadows.entry(canon).or_default().push(g);
            }
        }
        // A live proxy forwards to the symbol its `stands_for` edge names —
        // through that row's own forward when it has died and been replaced.
        // A proxy whose symbol is gone forwards nowhere: its edges left a
        // symbol that no longer exists, and are dropped with it.
        for g in proxies {
            let (i, l) = v.locate(g).expect("proxy row is in range");
            let seg = &segments[i].1;
            let (t, r) = (seg.fwd_targets()?, seg.fwd_rels()?);
            let mut canon = None;
            for e in seg.out_range(l)? {
                if r[e] == STANDS_FOR {
                    let tg = v.bases[i] + t[e];
                    canon = if v.is_canonical(tg) { Some(tg) } else { v.redirect.get(&tg).copied() };
                    break;
                }
            }
            if canon.is_none() {
                for e in seg.ext_edges()? {
                    if e.source == l.get() && e.rel == STANDS_FOR {
                        canon = v.find_in(segments, e.target);
                        break;
                    }
                }
            }
            if let Some(canon) = canon {
                v.redirect.insert(g, canon);
                v.shadows.entry(canon).or_default().push(g);
            }
        }

        // --- external edges ---
        for (i, (_, seg)) in segments.iter().enumerate() {
            let ext = seg.ext_edges()?;
            let mut by_source: Vec<(u32, u32)> = Vec::with_capacity(ext.len());
            let mut targets = Vec::with_capacity(ext.len());
            let flags = seg.node_flags()?;
            for (x, e) in ext.iter().enumerate() {
                let sg = v.bases[i] + e.source;
                // A live proxy's edges are read as its symbol's; a dead
                // source's edges died with it.
                let alive = v.is_canonical(sg)
                    || (flags[e.source as usize] & node_flags::PROXY != 0 && v.redirect.contains_key(&sg));
                let target = if alive { v.find_in(segments, e.target).unwrap_or(u32::MAX) } else { u32::MAX };
                targets.push(target);
                if target != u32::MAX {
                    by_source.push((e.source, x as u32));
                    if e.rel != STANDS_FOR {
                        v.ext_in.entry(target).or_default().push((i as u32, x as u32));
                    }
                }
            }
            by_source.sort_unstable();
            v.ext_by_source.push(by_source);
            v.ext_target.push(targets);
        }
        Ok(v)
    }

    /// A live, non-external row for `key` in any segment, if one exists.
    /// `externals` are the rows already known to be stand-ins.
    fn find_real(&self, segments: &[(u64, Segment)], key: SymbolKey, externals: &[u32]) -> Option<u32> {
        for (i, (_, seg)) in segments.iter().enumerate().rev() {
            let hits: Vec<u32> = if seg.keys_are_sorted() {
                match seg.keys().ok()?.binary_search(&key) {
                    Ok(l) => vec![self.bases[i] + l as u32],
                    Err(_) => Vec::new(),
                }
            } else {
                self.unsorted
                    .get(&key)
                    .cloned()
                    .unwrap_or_default()
                    .into_iter()
                    .filter(|g| self.locate(*g).is_some_and(|(s, _)| s == i))
                    .collect()
            };
            for g in hits {
                // Dead bits are already set by now; a live non-stand-in wins.
                if !externals.contains(&g) && self.is_canonical(g) {
                    return Some(g);
                }
            }
        }
        None
    }

    fn mark_noncanon(&mut self, g: u32) {
        self.noncanon[(g / 64) as usize] |= 1u64 << (g % 64);
    }

    #[inline]
    fn is_canonical(&self, g: u32) -> bool {
        self.noncanon
            .get((g / 64) as usize)
            .is_none_or(|w| w & (1u64 << (g % 64)) == 0)
    }

    /// `(segment index, local id)` of a store-wide id.
    fn locate(&self, g: u32) -> Option<(usize, LocalId)> {
        let n = self.bases.len().saturating_sub(1);
        if n == 0 || g >= self.bases[n] {
            return None;
        }
        // Segments are few; a linear scan beats a binary search's branches.
        let i = if n == 1 { 0 } else { self.bases[1..].iter().position(|&b| g < b)? };
        Some((i, LocalId::new(g - self.bases[i])))
    }

    /// The canonical row for `key`, searching later segments first so a
    /// re-indexed symbol is found in its delta rather than at its dead base
    /// row. A dead hit forwards; a dead hit with no forward is a deletion.
    fn find_in(&self, segments: &[(u64, Segment)], key: SymbolKey) -> Option<u32> {
        let consider = |g: u32| -> Option<u32> {
            if self.is_canonical(g) {
                Some(g)
            } else {
                self.redirect.get(&g).copied()
            }
        };
        for (i, (_, seg)) in segments.iter().enumerate().rev() {
            if seg.keys_are_sorted() {
                if let Ok(l) = seg.keys().ok()?.binary_search(&key)
                    && let Some(g) = consider(self.bases[i] + l as u32)
                {
                    return Some(g);
                }
            } else if let Some(rows) = self.unsorted.get(&key) {
                for &g in rows.iter().rev() {
                    if let Some(c) = consider(g) {
                        return Some(c);
                    }
                }
            } else if self.unsorted.is_empty() {
                // The table is only built once something needs it; a simple
                // view never does, so fall back to the segment's own scan.
                if let Some(l) = seg.find_symbol(key).ok()?
                    && let Some(g) = consider(self.bases[i] + l.get())
                {
                    return Some(g);
                }
            }
        }
        None
    }
}

/// A [`ViewData`] bound to the segments it describes.
#[derive(Clone, Copy)]
pub struct View<'a> {
    segments: &'a [(u64, Segment)],
    data: &'a ViewData,
}

impl<'a> View<'a> {
    pub(crate) fn new(segments: &'a [(u64, Segment)], data: &'a ViewData) -> Self {
        Self { segments, data }
    }

    /// Rows across every segment, dead ones included. The upper bound of the
    /// id space, which is what a visited-set has to be sized to.
    pub fn node_count(&self) -> usize {
        self.data.bases.last().map_or(0, |b| *b as usize)
    }

    pub fn segment_count(&self) -> usize {
        self.segments.len()
    }

    /// True when the CSR is the whole graph: one segment, nothing dead, no
    /// external edges. Callers with a hot loop can read columns directly.
    pub fn is_simple(&self) -> bool {
        self.data.simple
    }

    /// One segment, nothing dead, no external edges — but possibly proxy
    /// rows, whose edges count as another row's ([`Self::edge_owner`]) and
    /// whose rows a canonical row's edges include ([`Self::out_rows`]). What
    /// a compacted base looks like; a hot loop can read the CSR directly
    /// with those two accessors.
    pub fn is_single_live(&self) -> bool {
        self.data.single_live
    }

    /// The segment at `index`, and its store-wide id base.
    pub fn segment(&self, index: usize) -> (&'a Segment, u32) {
        (&self.segments[index].1, self.data.bases[index])
    }

    pub fn locate(&self, id: LocalId) -> Option<(usize, LocalId)> {
        self.data.locate(id.get())
    }

    /// Is `id` the row queries should see for its key?
    #[inline]
    pub fn is_canonical(&self, id: LocalId) -> bool {
        id.index() < self.node_count() && self.data.is_canonical(id.get())
    }

    /// `id` itself when canonical, its replacement when forwarded, `None` when
    /// the symbol no longer exists.
    #[inline]
    pub fn canonical(&self, id: LocalId) -> Option<LocalId> {
        let g = id.get();
        if self.data.is_canonical(g) {
            (id.index() < self.node_count()).then_some(id)
        } else {
            self.data.redirect.get(&g).map(|&c| LocalId::new(c))
        }
    }

    /// Every canonical row, ascending.
    pub fn ids(self) -> impl Iterator<Item = LocalId> + 'a {
        let data = self.data;
        let n = self.node_count() as u32;
        (0..n).filter(move |&g| data.is_canonical(g)).map(LocalId::new)
    }

    /// The canonical row for a key.
    pub fn find(&self, key: SymbolKey) -> Option<LocalId> {
        self.data.find_in(self.segments, key).map(LocalId::new)
    }

    // --- row columns ---

    fn row(&self, id: LocalId) -> Result<(&'a Segment, usize)> {
        let (i, l) = self
            .locate(id)
            .ok_or_else(|| StoreError::Manifest(format!("symbol id {} is out of range", id.get())))?;
        Ok((&self.segments[i].1, l.index()))
    }

    pub fn key(&self, id: LocalId) -> Result<SymbolKey> {
        let (s, l) = self.row(id)?;
        Ok(s.keys()?[l])
    }
    pub fn name(&self, id: LocalId) -> Result<&'a str> {
        let (s, l) = self.row(id)?;
        Ok(s.string(s.node_names()?[l]))
    }
    pub fn norm_name(&self, id: LocalId) -> Result<&'a str> {
        let (s, l) = self.row(id)?;
        Ok(s.string(s.node_norm_names()?[l]))
    }
    pub fn path(&self, id: LocalId) -> Result<&'a str> {
        let (s, l) = self.row(id)?;
        Ok(s.file_path(s.node_files()?[l]))
    }
    pub fn kind_raw(&self, id: LocalId) -> Result<u8> {
        let (s, l) = self.row(id)?;
        Ok(s.node_kinds()?[l])
    }
    pub fn file_type_raw(&self, id: LocalId) -> Result<u8> {
        let (s, l) = self.row(id)?;
        Ok(s.node_file_types()?[l])
    }
    pub fn line(&self, id: LocalId) -> Result<u32> {
        let (s, l) = self.row(id)?;
        Ok(s.node_lines()?[l])
    }
    /// The definition hash, `0` when the segment predates the column.
    pub fn hash(&self, id: LocalId) -> Result<u64> {
        let (s, l) = self.row(id)?;
        Ok(s.node_hashes()?.get(l).copied().unwrap_or(0))
    }
    pub fn flags(&self, id: LocalId) -> Result<u8> {
        let (s, l) = self.row(id)?;
        Ok(s.node_flags()?[l])
    }

    /// Every live file with its metadata: what an incremental update compares
    /// the source tree against.
    pub fn live_files(&self) -> Result<Vec<(&'a str, &'a FileRow)>> {
        let mut out = Vec::new();
        for (i, (_, seg)) in self.segments.iter().enumerate() {
            let live = &self.data.file_live[i];
            for (f, row) in seg.files()?.iter().enumerate() {
                if live.get(f).copied().unwrap_or(false) {
                    out.push((seg.string(row.path), row));
                }
            }
        }
        Ok(out)
    }

    // --- edges ---

    /// The canonical target of segment `i`'s CSR target `t`, or `None` when
    /// the target is dead with no replacement.
    #[inline]
    fn resolve(&self, i: usize, t: u32) -> Option<u32> {
        let g = self.data.bases[i] + t;
        if self.data.is_canonical(g) { Some(g) } else { self.data.redirect.get(&g).copied() }
    }

    /// The canonical *source* of an edge that segment `i`'s row `s` wrote.
    ///
    /// Not the same question as [`Self::resolve`]. A dead target is followed
    /// to its replacement, because the edge was written *at* a symbol and the
    /// symbol still exists. A dead source is dropped, because its replacement
    /// wrote its own edges — counting the dead row's too would report every
    /// caller in a re-indexed file twice. A live shadow (a duplicated package
    /// stub) is attributed to its canonical row, as its outgoing edges are.
    #[inline]
    fn resolve_source(&self, i: usize, s: u32) -> Option<u32> {
        let g = self.data.bases[i] + s;
        if self.data.is_canonical(g) {
            Some(g)
        } else if self.shadow_is_live(g) {
            self.data.redirect.get(&g).copied()
        } else {
            None
        }
    }

    /// The rows whose outgoing edges belong to `id`: itself, plus any live row
    /// forwarded to it. A live shadow is a duplicated package stub, which has
    /// no edges of its own, but the rule is stated generally so it cannot
    /// silently stop holding.
    /// The rows forwarded to `id`, live or not, without allocating. In a
    /// [`Self::is_single_live`] store every one of them is a live proxy.
    pub fn shadow_rows(&self, id: LocalId) -> &'a [u32] {
        self.data.shadows.get(&id.get()).map_or(&[], Vec::as_slice)
    }

    pub fn out_rows(&self, id: LocalId) -> Vec<u32> {
        let mut rows = vec![id.get()];
        if let Some(sh) = self.data.shadows.get(&id.get()) {
            rows.extend(sh.iter().copied().filter(|&g| self.shadow_is_live(g)));
        }
        rows
    }

    /// A shadowed row is live when its file is. An external row is live
    /// everywhere; a proxy is live with its file, and only while it forwards
    /// somewhere; any other shadowed row is dead.
    fn shadow_is_live(&self, g: u32) -> bool {
        let Some((i, l)) = self.data.locate(g) else { return false };
        let seg = &self.segments[i].1;
        let Ok(flags) = seg.node_flags() else { return false };
        let f = flags[l.index()];
        if f & node_flags::EXTERNAL != 0 {
            return true;
        }
        f & node_flags::PROXY != 0 && self.data.redirect.contains_key(&g) && self.row_file_live(i, l)
    }

    /// Is the file of segment `i`'s row `l` still owned by that segment?
    fn row_file_live(&self, i: usize, l: LocalId) -> bool {
        if self.data.all_live[i] {
            return true;
        }
        let seg = &self.segments[i].1;
        seg.node_files()
            .is_ok_and(|files| self.data.file_live[i].get(files[l.index()].index()).copied().unwrap_or(false))
    }

    /// A live proxy row: not canonical, forwarded to the symbol it stands
    /// for, and its file still owned. Its edges count as that symbol's.
    pub fn is_live_proxy(&self, id: LocalId) -> bool {
        let g = id.get();
        if self.data.is_canonical(g) {
            return false;
        }
        let Some((i, l)) = self.data.locate(g) else { return false };
        let seg = &self.segments[i].1;
        seg.node_flags().is_ok_and(|f| f[l.index()] & node_flags::PROXY != 0) && self.shadow_is_live(g)
    }

    /// The row whose edges `id`'s storage edges count as: itself when
    /// canonical, the symbol it stands for when a live proxy, the canonical
    /// duplicate when a live external shadow; none when dead.
    pub fn edge_owner(&self, id: LocalId) -> Option<LocalId> {
        let g = id.get();
        if self.data.is_canonical(g) {
            Some(id)
        } else if self.shadow_is_live(g) {
            self.data.redirect.get(&g).map(|&c| LocalId::new(c))
        } else {
            None
        }
    }

    /// The canonical target of segment `i`'s external edge `x`, if its key
    /// resolves anywhere in the store.
    pub fn ext_target(&self, i: usize, x: usize) -> Option<LocalId> {
        let t = *self.data.ext_target.get(i)?.get(x)?;
        (t != u32::MAX).then_some(LocalId::new(t))
    }

    /// The row a storage edge of `g` is reported under by
    /// [`Self::for_each_edge`]: `g` itself when canonical or a live proxy,
    /// the canonical duplicate for a live external shadow, none when dead.
    fn storage_source(&self, g: u32) -> Option<u32> {
        if self.data.is_canonical(g) {
            return Some(g);
        }
        if !self.shadow_is_live(g) {
            return None;
        }
        let (i, l) = self.data.locate(g)?;
        let flags = self.segments[i].1.node_flags().ok()?;
        if flags[l.index()] & node_flags::PROXY != 0 {
            Some(g)
        } else {
            self.data.redirect.get(&g).copied()
        }
    }

    /// External edges of segment `i` whose source is `l`.
    fn ext_run(&self, i: usize, l: LocalId) -> &'a [(u32, u32)] {
        let ext = &self.data.ext_by_source[i];
        let start = ext.partition_point(|&(s, _)| s < l.get());
        let end = start + ext[start..].partition_point(|&(s, _)| s == l.get());
        &ext[start..end]
    }

    /// Call `f` with the canonical target of every outgoing edge of `id` in
    /// `mask`. The hot path for index construction: no allocation per edge,
    /// no enum conversion, one bit test per edge.
    pub fn for_each_out(
        &self,
        id: LocalId,
        mask: RelationMask,
        mut f: impl FnMut(u32),
    ) -> Result<()> {
        if !self.is_canonical(id) {
            return Ok(());
        }
        for g in self.out_rows(id) {
            let (i, l) = self.data.locate(g).expect("in range");
            let seg = &self.segments[i].1;
            let (t, r) = (seg.fwd_targets()?, seg.fwd_rels()?);
            for e in seg.out_range(l)? {
                if mask.contains_raw(r[e])
                    && r[e] != STANDS_FOR
                    && let Some(target) = self.resolve(i, t[e])
                {
                    f(target);
                }
            }
            for &(_, x) in self.ext_run(i, l) {
                let rel = seg.ext_edges()?[x as usize].rel;
                let target = self.data.ext_target[i][x as usize];
                if mask.contains_raw(rel) && rel != STANDS_FOR && target != u32::MAX {
                    f(target);
                }
            }
        }
        Ok(())
    }

    /// The storage edges of one row, whatever its standing: what the row
    /// itself wrote, targets forwarded, `stands_for` left out. A canonical
    /// row's edges are these plus its live shadows' — see [`Self::out_edges`].
    pub fn own_edges(&self, id: LocalId, mask: RelationMask) -> Result<Vec<ViewEdge<'a>>> {
        let mut out = Vec::new();
        let Some((i, l)) = self.data.locate(id.get()) else { return Ok(out) };
        let seg = &self.segments[i].1;
        for e in seg.out_edges(l, mask)? {
            if e.relation == Relation::StandsFor {
                continue;
            }
            if let Some(target) = self.resolve(i, e.target.get()) {
                out.push(ViewEdge {
                    node: LocalId::new(target),
                    relation: e.relation,
                    confidence: e.confidence,
                    flags: e.flags,
                    line: e.line,
                    context: e.context,
                });
            }
        }
        for &(_, x) in self.ext_run(i, l) {
            let e = &seg.ext_edges()?[x as usize];
            let target = self.data.ext_target[i][x as usize];
            if mask.contains_raw(e.rel) && e.rel != STANDS_FOR && target != u32::MAX {
                out.push(ViewEdge {
                    node: LocalId::new(target),
                    relation: Relation::from_u8(e.rel),
                    confidence: Confidence::from_u8(e.conf),
                    flags: e.flags,
                    line: e.line,
                    context: (e.context != u32::MAX)
                        .then(|| seg.string(codegraph_core::StrId::new(e.context))),
                });
            }
        }
        Ok(out)
    }

    /// Outgoing edges of `id` in `mask`, with attributes.
    pub fn out_edges(&self, id: LocalId, mask: RelationMask) -> Result<Vec<ViewEdge<'a>>> {
        let mut out = Vec::new();
        if !self.is_canonical(id) {
            return Ok(out);
        }
        for g in self.out_rows(id) {
            out.extend(self.own_edges(LocalId::new(g), mask)?);
        }
        // The CSR's own within-row order, so a store with deltas answers in
        // the same order its compacted form would.
        out.sort_by_key(|e| (e.relation.as_u8(), e.node));
        Ok(out)
    }

    /// Incoming edges of `id` in `mask`.
    ///
    /// Edges written against a row that has since been forwarded to `id` — the
    /// base segment's edges into a file that was later re-indexed — are found
    /// through the forwarded rows' own reverse CSR, so a re-index of a callee
    /// does not lose the callers that were never touched.
    ///
    /// Errors, rather than answering empty, when a segment involved has no
    /// reverse CSR: "not built" and "no callers" are different answers.
    pub fn in_edges(&self, id: LocalId, mask: RelationMask) -> Result<Vec<ViewEdge<'a>>> {
        let mut out = Vec::new();
        if !self.is_canonical(id) {
            return Ok(out);
        }
        let mut rows = vec![id.get()];
        if let Some(sh) = self.data.shadows.get(&id.get()) {
            rows.extend_from_slice(sh);
        }
        for g in rows {
            let (i, l) = self.data.locate(g).expect("in range");
            let seg = &self.segments[i].1;
            for e in seg.in_edges(l, mask)? {
                if e.relation == Relation::StandsFor {
                    continue;
                }
                if let Some(source) = self.resolve_source(i, e.source.get()) {
                    out.push(ViewEdge {
                        node: LocalId::new(source),
                        relation: e.relation,
                        confidence: e.confidence,
                        flags: e.flags,
                        line: e.line,
                        context: e.context,
                    });
                }
            }
            if let Some(list) = self.data.ext_in.get(&g) {
                for &(si, x) in list {
                    let seg = &self.segments[si as usize].1;
                    let e = &seg.ext_edges()?[x as usize];
                    if !mask.contains_raw(e.rel) {
                        continue;
                    }
                    if let Some(source) = self.resolve_source(si as usize, e.source) {
                        out.push(ViewEdge {
                            node: LocalId::new(source),
                            relation: Relation::from_u8(e.rel),
                            confidence: Confidence::from_u8(e.conf),
                            flags: e.flags,
                            line: e.line,
                            context: (e.context != u32::MAX)
                                .then(|| seg.string(codegraph_core::StrId::new(e.context))),
                        });
                    }
                }
            }
        }
        out.sort_by_key(|e| (e.relation.as_u8(), e.node));
        Ok(out)
    }

    /// Every edge between canonical rows.
    ///
    /// What compaction and the verification harness read; not a query-time
    /// surface. Both endpoints are already forwarded, so an edge written
    /// against a dead row comes out pointing at its replacement.
    pub fn for_each_edge(
        &self,
        include_segment: impl Fn(usize) -> bool,
        mut f: impl FnMut(RawEdge<'a>) -> Result<()>,
    ) -> Result<()> {
        for (i, (_, seg)) in self.segments.iter().enumerate() {
            if !include_segment(i) {
                continue;
            }
            let base = self.data.bases[i];
            let (t, r, c, fl, ln, cx) = (
                seg.fwd_targets()?,
                seg.fwd_rels()?,
                seg.fwd_confs()?,
                seg.fwd_flags()?,
                seg.fwd_lines()?,
                seg.fwd_contexts()?,
            );
            let ctx = |s: u32| (s != u32::MAX).then(|| seg.string(codegraph_core::StrId::new(s)));
            for l in 0..seg.node_count() {
                let g = base + l as u32;
                // A live proxy is reported as itself, `stands_for` edge and
                // all: compaction copies it as a row, so the file that wrote
                // it keeps owning its edges. A live external duplicate folds
                // into its canonical row.
                let Some(src) = self.storage_source(g) else { continue };
                for e in seg.out_range(LocalId::new(l as u32))? {
                    if let Some(target) = self.resolve(i, t[e]) {
                        f(RawEdge {
                            source: LocalId::new(src),
                            target: LocalId::new(target),
                            rel: r[e],
                            conf: c[e],
                            flags: fl[e],
                            line: ln[e],
                            context: ctx(cx[e]),
                            via_ext: false,
                        })?;
                    }
                }
            }
            for (x, e) in seg.ext_edges()?.iter().enumerate() {
                let target = self.data.ext_target[i][x];
                if target == u32::MAX {
                    continue;
                }
                // `ext_target` is only set for canonical and live-proxy
                // sources; both report as themselves.
                f(RawEdge {
                    source: LocalId::new(base + e.source),
                    target: LocalId::new(target),
                    rel: e.rel,
                    conf: e.conf,
                    flags: e.flags,
                    line: e.line,
                    context: ctx(e.context),
                    via_ext: true,
                })?;
            }
        }
        Ok(())
    }
}

/// An edge as [`View::for_each_edge`] reports it: raw column values, both
/// endpoints canonical.
#[derive(Debug, Clone, Copy)]
pub struct RawEdge<'a> {
    pub source: LocalId,
    pub target: LocalId,
    pub rel: u8,
    pub conf: u8,
    pub flags: u8,
    pub line: u32,
    pub context: Option<&'a str>,
    /// Came from the segment's `EdgeExt` table rather than its CSR — it was
    /// resolved by key, not by position.
    pub via_ext: bool,
}
