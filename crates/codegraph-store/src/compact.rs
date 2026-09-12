//! Compaction: merge segments into one, sorted and fully linked.
//!
//! Three things only a merge can do, because each needs a whole segment set at
//! once:
//!
//! 1. **Sort by `SymbolKey`**, so lookup becomes a binary search over one
//!    column instead of a linear scan across segments.
//! 2. **Promote external edges.** An edge written before its target existed
//!    carries an unresolved key; once every segment is in hand, most of those
//!    resolve and move into the CSR where traversal can see them.
//! 3. **Build the reverse CSR**, which needs a stable `LocalId` ordering over
//!    the merged set — precisely what steps 1 and 2 establish.
//!
//! Dead rows are dropped on the way through: a row survives only if the view
//! names it canonical — live under the manifest's ownership and not shadowed
//! by a later row for the same key.
//!
//! # Tiers
//!
//! A full compaction rewrites everything, which at millions of symbols costs
//! tens of seconds for a one-file change. So a store is kept as one **base**
//! segment plus a short run of **delta** segments, and [`compact_tiered`]
//! chooses the cheapest merge that keeps the run short: nothing while the
//! deltas are few, the deltas among themselves once there are several, and
//! the base only when the deltas have grown to a fraction of it. The base is
//! then rewritten at a cadence proportional to how much has changed, not to
//! how often.

use std::collections::{HashMap, HashSet};

use codegraph_core::{Confidence, FileType, LocalId, Relation, SymbolKey, SymbolKind};

use crate::error::Result;
use crate::format::{FileRow, Tier, node_flags};
use crate::store::Store;
use crate::writer::{Edge, SegmentBuilder, Symbol};

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct CompactStats {
    pub segments_before: usize,
    pub segments_after: usize,
    pub symbols: usize,
    /// Rows dropped because their segment no longer owned the file, or a
    /// later segment carried the same key.
    pub dropped_dead: usize,
    /// External edges that found their target and moved into the CSR.
    pub promoted: usize,
    /// External edges whose target is outside the merged segment — genuinely
    /// outside the corpus, or in the base when only deltas were merged.
    pub still_external: usize,
    pub edges: usize,
    /// Whether the base was rewritten. `false` means only deltas were merged.
    pub full: bool,
}

/// When [`compact_tiered`] merges what.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct CompactPolicy {
    /// Merge the deltas among themselves once more than this many exist. Each
    /// delta is a segment to map at open and a place for a lookup to look, so
    /// the run is kept short — but merging deltas costs time proportional to
    /// the deltas, not the base, so it is cheap to do often.
    pub max_deltas: usize,
    /// Rewrite the base once the deltas hold more than this fraction of its
    /// rows. Below it, the dead rows the deltas superseded in the base are a
    /// bounded waste; above it, a full rewrite is amortised over enough change
    /// to have been worth doing anyway.
    pub max_delta_ratio: f64,
}

impl Default for CompactPolicy {
    fn default() -> Self {
        Self { max_deltas: 4, max_delta_ratio: 0.2 }
    }
}

/// One symbol, lifted out of its segment so it can be re-sorted.
struct Row {
    key: SymbolKey,
    path: String,
    name: String,
    norm: String,
    kind: SymbolKind,
    file_type: FileType,
    line: u32,
    flags: u8,
    hash: u64,
}

/// An edge in key space, so it survives the re-numbering.
type KeyEdge = (SymbolKey, SymbolKey, u8, u8, u8, u32, String);

/// Is this segment a compacted base: sorted, reverse-linked, ready to serve?
fn is_base(store: &Store, id: u64) -> bool {
    store.segment(id).is_some_and(|s| s.keys_are_sorted() && s.has_reverse_csr())
}

/// Merge every live segment into a single sorted segment.
///
/// A no-op returning `Ok(None)` when there is nothing to gain — one segment
/// that is already sorted, reverse-linked, and free of dead rows.
pub fn compact(store: &mut Store) -> Result<Option<CompactStats>> {
    let ids: Vec<u64> = store.segments().map(|(id, _)| id).collect();
    if ids.is_empty() {
        return Ok(None);
    }
    if ids.len() == 1 && is_base(store, ids[0]) && store.view().is_single_live() {
        return Ok(None);
    }
    merge(store, &ids, true).map(Some)
}

/// Merge as much as `policy` says is worth merging: nothing, the deltas, or
/// everything. See the module docs for the tiers.
pub fn compact_tiered(store: &mut Store, policy: &CompactPolicy) -> Result<Option<CompactStats>> {
    let ids: Vec<u64> = store.segments().map(|(id, _)| id).collect();
    let Some((&base, deltas)) = ids.split_first() else {
        return Ok(None);
    };
    // No base to build on — a store that has only ever been flushed, never
    // compacted — is a full merge whatever the policy says.
    if !is_base(store, base) {
        return merge(store, &ids, true).map(Some);
    }
    if deltas.is_empty() {
        return Ok(None);
    }
    let rows = |id: u64| store.segment(id).map_or(0, |s| s.node_count());
    let base_rows = rows(base).max(1);
    let delta_rows: usize = deltas.iter().map(|&d| rows(d)).sum();
    if delta_rows as f64 > policy.max_delta_ratio * base_rows as f64 {
        return merge(store, &ids, true).map(Some);
    }
    if deltas.len() > policy.max_deltas {
        return merge(store, deltas, false).map(Some);
    }
    Ok(None)
}

/// Merge the segments in `subset` into one new segment.
///
/// `full` means the subset is the whole store: external edges can be judged
/// genuinely external, and package stubs nothing points at any more can go.
/// Otherwise an edge whose target lives outside the subset stays external,
/// keyed, for the view to resolve.
fn merge(store: &mut Store, subset: &[u64], full: bool) -> Result<CompactStats> {
    let segments_before = store.manifest().segments.len();
    let view = store.view();
    let in_subset: Vec<bool> = store.segments().map(|(id, _)| subset.contains(&id)).collect();

    // Live file metadata, so a merged segment carries the content hashes an
    // incremental update needs to tell a changed file from an unchanged one.
    let mut file_rows: HashMap<String, FileRow> = HashMap::new();
    for (path, row) in view.live_files()? {
        file_rows.insert(path.to_string(), *row);
    }

    // --- rows ---
    let mut rows: Vec<Row> = Vec::new();
    let mut dropped_dead = 0usize;
    for (i, included) in in_subset.iter().enumerate() {
        if !included {
            continue;
        }
        let (seg, base) = view.segment(i);
        let files = seg.node_files()?;
        let names = seg.node_names()?;
        let norms = seg.node_norm_names()?;
        let kinds = seg.node_kinds()?;
        let types = seg.node_file_types()?;
        let lines = seg.node_lines()?;
        let flags = seg.node_flags()?;
        let hashes = seg.node_hashes()?;
        let keys = seg.keys()?;
        for l in 0..seg.node_count() {
            let id = LocalId::new(base + l as u32);
            // A live proxy is copied as a row: its file still owns the
            // edges it carries for a symbol defined elsewhere.
            if !view.is_canonical(id) && !view.is_live_proxy(id) {
                dropped_dead += 1;
                continue;
            }
            rows.push(Row {
                key: keys[l],
                path: seg.file_path(files[l]).to_string(),
                name: seg.string(names[l]).to_string(),
                norm: seg.string(norms[l]).to_string(),
                kind: SymbolKind::from_u8(kinds[l]),
                file_type: FileType::from_u8(types[l]),
                line: lines[l],
                flags: flags[l],
                hash: hashes.get(l).copied().unwrap_or(0),
            });
        }
    }

    // --- edges, in key space, both endpoints already forwarded ---
    let mut edges: Vec<KeyEdge> = Vec::new();
    let mut ext_pending: Vec<KeyEdge> = Vec::new();
    let mut promoted = 0usize;
    view.for_each_edge(
        |i| in_subset[i],
        |e| {
            let (ti, _) = view.locate(e.target).expect("canonical target is in range");
            let ke = (
                view.key(e.source)?,
                view.key(e.target)?,
                e.rel,
                e.conf,
                e.flags,
                e.line,
                e.context.unwrap_or("").to_string(),
            );
            if in_subset[ti] {
                // An external edge whose target is now in hand joins the CSR.
                promoted += usize::from(e.via_ext);
                edges.push(ke)
            } else {
                ext_pending.push(ke)
            }
            Ok(())
        },
    )?;
    // External edges whose key resolves to nothing in the store. Kept as they
    // are: the target may be indexed later, and until then they are the
    // record of a dependency the corpus does not contain.
    for (i, included) in in_subset.iter().enumerate() {
        if !included {
            continue;
        }
        let (seg, base) = view.segment(i);
        let keys = seg.keys()?;
        for (x, e) in seg.ext_edges()?.iter().enumerate() {
            let source = LocalId::new(base + e.source);
            if view.ext_target(i, x).is_some() || !(view.is_canonical(source) || view.is_live_proxy(source)) {
                continue;
            }
            ext_pending.push((
                keys[e.source as usize],
                e.target,
                e.rel,
                e.conf,
                e.flags,
                e.line,
                seg.string(codegraph_core::StrId::new(e.context)).to_string(),
            ));
        }
    }

    // A package stub nothing points at any more is the residue of an import
    // that was removed. Only a full merge can be sure nothing points at it.
    if full {
        let referenced: HashSet<SymbolKey> =
            edges.iter().chain(&ext_pending).map(|e| e.1).collect();
        rows.retain(|r| r.flags & node_flags::EXTERNAL == 0 || referenced.contains(&r.key));
    }

    // Sort by key. This is what earns `KEYS_SORTED` and turns lookup into a
    // binary search.
    rows.sort_unstable_by_key(|r| r.key);

    let known: HashSet<SymbolKey> = rows.iter().map(|r| r.key).collect();
    let (promoted_edges, still_ext): (Vec<_>, Vec<_>) =
        ext_pending.into_iter().partition(|e| known.contains(&e.1));
    promoted += promoted_edges.len();
    let still_external = still_ext.len();
    edges.extend(promoted_edges);

    // The files this segment will own: every file the subset owned. A package
    // stub whose file is not among them — its importer was deleted — is
    // attached to an unnamed pseudo-file rather than resurrecting the path.
    let mut paths: Vec<String> = store
        .manifest()
        .owners
        .iter()
        .filter(|(_, o)| o.ast.is_some_and(|s| subset.contains(&s)))
        .map(|(p, _)| p.clone())
        .collect();
    paths.sort_unstable();

    // --- write ---
    let id = store.next_segment_id();
    let mut b = SegmentBuilder::new(id, Tier::Ast).with_reverse_csr(true);
    let mut file_ids = HashMap::with_capacity(paths.len() + 1);
    for p in &paths {
        let meta = file_rows.get(p).copied();
        let fid = match meta {
            Some(m) => b.add_file(p, m.lang, m.content_hash, m.mtime_nanos, m.size),
            None => b.add_file(p, 0, 0, 0, 0),
        };
        file_ids.insert(p.as_str(), fid);
    }
    let mut orphan_file = None;
    for r in &rows {
        let file = match file_ids.get(r.path.as_str()) {
            Some(f) => *f,
            None => *orphan_file.get_or_insert_with(|| b.add_file("", 0, 0, 0, 0)),
        };
        b.add_symbol(Symbol {
            key: r.key,
            file,
            name: &r.name,
            norm_name: &r.norm,
            kind: r.kind,
            file_type: r.file_type,
            line: r.line,
            flags: r.flags,
            hash: r.hash,
        });
    }

    for (src, tgt, rel, conf, flags, line, ctx) in &edges {
        let Some(source) = b.lookup(*src) else { continue };
        b.add_edge(Edge {
            source,
            target: *tgt,
            rel: Relation::from_u8(*rel),
            conf: Confidence::from_u8(*conf),
            line: *line,
            context: (!ctx.is_empty()).then_some(ctx.as_str()),
            // Clear the external marker: these are internal now. Leaving it set
            // would make a promoted edge look third-party forever.
            flags: flags & !crate::format::edge_flags::EXTERNAL,
        });
    }
    for (src, tgt, rel, conf, flags, line, ctx) in &still_ext {
        let Some(source) = b.lookup(*src) else { continue };
        b.add_edge(Edge {
            source,
            target: *tgt,
            rel: Relation::from_u8(*rel),
            conf: Confidence::from_u8(*conf),
            line: *line,
            context: (!ctx.is_empty()).then_some(ctx.as_str()),
            flags: *flags,
        });
    }

    let symbols = b.symbol_count();
    let edge_total = edges.len();
    store.commit_segment(id, b, Tier::Ast, &paths)?;
    store.sweep_dead_segments();

    Ok(CompactStats {
        segments_before,
        segments_after: store.manifest().segments.len(),
        symbols,
        dropped_dead,
        promoted,
        still_external,
        edges: edge_total,
        full,
    })
}

/// True when a symbol row stands for a file rather than a symbol inside one.
pub fn is_file_node(flags: u8) -> bool {
    flags & node_flags::FILE_NODE != 0
}
