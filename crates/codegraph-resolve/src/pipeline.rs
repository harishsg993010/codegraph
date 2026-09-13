//! Source tree in, indexed store out — from scratch with [`index_tree`], or
//! incrementally with [`update_tree`].

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use codegraph_core::{LocalId, Relation, RelationMask, SymbolKey, SymbolKind};
use codegraph_extract::{FileExtract, Walker, content_hash, lang};
use codegraph_store::{
    CompactPolicy, CompactStats, Result, Store, StoreError, compact, compact_tiered, node_flags,
};
use rayon::prelude::*;

pub use crate::tree::{SKIP_DIRS, Scan, scan};

/// Extract every file, in parallel.
///
/// A `Walker` owns a tree-sitter parser, which is expensive to construct and
/// cheap to reuse. Building one per file measured at 88 files/s; keeping one
/// per (thread, language) in a thread-local cache is the single biggest lever
/// on extraction throughput, because parser construction otherwise dominates
/// everything the walk does.
pub fn extract_all(root: &Path, files: &[PathBuf]) -> Vec<FileExtract> {
    extract_all_with(root, files, None)
}

/// Files whose content is taken from here rather than from disk: `Some`
/// bytes stand in for the file, `None` says the file is absent. What
/// `diff` uses to see the tree as it was at the last commit.
pub type Overlay = HashMap<String, Option<Vec<u8>>>;

/// [`extract_all`] with an overlay.
pub fn extract_all_with(root: &Path, files: &[PathBuf], overlay: Option<&Overlay>) -> Vec<FileExtract> {
    use std::cell::RefCell;

    // The user's library summaries, from `<root>/.codegraph-summaries.json`
    // when there is one. A malformed file is said so, once, and ignored:
    // extraction must not fail on a side file.
    if let Err(e) = codegraph_extract::summaries::load_user_summaries(root) {
        eprintln!("warning: {e}");
    }

    thread_local! {
        static WALKERS: RefCell<HashMap<&'static str, Walker>> =
            RefCell::new(HashMap::new());
    }

    files
        .par_iter()
        .filter_map(|path| {
            let config = lang::for_path(path)?;
            // Repo-relative, forward slashes: an absolute path in a key would
            // make the store non-portable between checkouts.
            let rel = path
                .strip_prefix(root)
                .unwrap_or(path)
                .to_string_lossy()
                .replace('\\', "/");
            let source = match overlay.and_then(|o| o.get(&rel)) {
                Some(Some(bytes)) => bytes.clone(),
                Some(None) => return None,
                None => std::fs::read(path).ok()?,
            };
            WALKERS.with(|cache| {
                let mut cache = cache.borrow_mut();
                let walker = match cache.entry(config.name) {
                    std::collections::hash_map::Entry::Occupied(e) => e.into_mut(),
                    std::collections::hash_map::Entry::Vacant(e) => {
                        e.insert(Walker::new(config).ok()?)
                    }
                };
                let mut out = walker.extract(&rel, &source)?;
                out.mtime_nanos = mtime_nanos(path);
                Some(out)
            })
        })
        .collect()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexReport {
    pub scanned: usize,
    pub extracted: usize,
    pub build: crate::BuildStats,
    pub symbols: usize,
    pub edges: usize,
}

/// The prefixes an absolute specifier can use to name this corpus.
///
/// Two sources, because they disagree and both are real:
///
/// - The root's own directory name, so a package indexed at its own directory
///   can still resolve `pkg.sub` self-imports.
/// - A Go module path from `go.mod`, which is declared rather than derived and
///   need not resemble the directory at all — a checkout in `gitea/` can
///   declare `module gitea.dev`, and its 11,979 self-imports are then
///   unresolvable from the directory name alone.
fn import_roots(root: &Path) -> Vec<String> {
    let mut roots = Vec::new();
    if let Some(name) = root
        .canonicalize()
        .ok()
        .as_deref()
        .and_then(Path::file_name)
        .map(|n| n.to_string_lossy().to_string())
        && !name.is_empty()
    {
        roots.push(name);
    }
    // `module <path>` on its own line, before any `require` block.
    if let Ok(text) = std::fs::read_to_string(root.join("go.mod"))
        && let Some(path) = text
            .lines()
            .map(str::trim)
            .find_map(|l| l.strip_prefix("module ").map(str::trim))
        && !path.is_empty()
    {
        roots.push(path.to_string());
    }
    roots
}

/// Index a source tree into a store: scan, extract, resolve, commit, compact.
pub fn index_tree(root: &Path, store: &mut Store, repo: &str) -> Result<IndexReport> {
    let scan = scan(root);
    if scan.files.is_empty() {
        return Err(StoreError::Manifest(format!(
            "no indexable files under {}",
            root.display()
        )));
    }
    let files = extract_all(root, &scan.files);
    // Re-indexing an existing store: a file it holds that the tree no longer
    // has would otherwise stay live, since nothing supersedes it.
    let extracted: HashSet<&str> = files.iter().map(|f| f.path.as_str()).collect();
    let gone: Vec<String> = store
        .manifest()
        .live_files()
        .filter(|p| !p.is_empty() && !extracted.contains(p))
        .map(str::to_string)
        .collect();
    store.remove_files(&gone)?;
    let build = crate::build_rooted(&files, store, repo, &import_roots(root))?;
    compact(store)?;
    // What the tree looked like, for the next update: captured before the
    // extraction would be exact; captured after, a file edited during the
    // index is dirty now and will be re-checked next time. Either is safe.
    let state = TreeState::capture(root, repo);
    let _ = state.save(store.root());
    // A full index is the bootstrap: keep the store out of the repository.
    if state.git.is_some()
        && let Some(r) = crate::tree::detect_git(root)
    {
        crate::tree::exclude_store_from_git(&r, store.root());
    }
    Ok(IndexReport {
        scanned: scan.files.len(),
        extracted: files.len(),
        build,
        symbols: store.symbol_count(),
        edges: store.edge_count(),
    })
}

/// What an incremental update did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpdateReport {
    pub scanned: usize,
    /// Files whose content differs from the store's copy, or are new to it.
    pub changed: usize,
    /// Files the store held that are no longer in the tree.
    pub deleted: usize,
    /// Files actually re-extracted: the changed files plus every file that
    /// shares an edge with one of them.
    pub reextracted: usize,
    /// `false` when the store had no usable base and a full index ran.
    pub incremental: bool,
    pub build: crate::BuildStats,
    pub compaction: Option<CompactStats>,
    pub symbols: usize,
    pub edges: usize,
    /// Repo-relative paths: what changed, what was deleted, and everything
    /// re-extracted (the changed files plus their neighbourhood). Empty on
    /// a full re-index.
    pub changed_paths: Vec<String>,
    pub deleted_paths: Vec<String>,
    pub reextracted_paths: Vec<String>,
    /// How the changed files were found: `"git"` (the candidates git
    /// named, checked by hash), `"scan"` (every file, by size, mtime and
    /// hash), or `"full"` (a rebuild; nothing was compared).
    pub detection: &'static str,
}

/// The edges along which a changed file's *targets* have to be re-extracted:
/// heritage, where the target's own declaration decides the relation.
const HERITAGE: RelationMask = RelationMask::of(&[
    Relation::Inherits,
    Relation::Implements,
    Relation::Extends,
    Relation::MixesIn,
]);

use crate::tree::{TreeState, mtime_of};

fn mtime_nanos(path: &Path) -> i64 {
    std::fs::metadata(path).map_or(0, |m| mtime_of(&m))
}

/// What an update found to do, and how it found it.
struct Changes {
    /// Files whose content differs from the store's copy, or are new to it.
    changed: Vec<PathBuf>,
    /// Stored paths no longer in the tree (or no longer indexable).
    deleted: Vec<String>,
    /// Every indexable path in the tree now.
    present: HashSet<String>,
    /// Files considered: the walk's count, or the store's when git
    /// answered.
    scanned: usize,
    /// `"git"` when git named the candidates, `"scan"` after a walk.
    how: &'static str,
    /// Git's view now, to record with the update.
    git: Option<crate::tree::GitState>,
}

/// Which files differ from what the store holds.
///
/// With git, the candidates are the paths git names — dirty then, dirty
/// now, changed between the two commits — each checked against the
/// store by content hash; every other stored file is unchanged by git's
/// word. Without git, or when git cannot be sure, every file is checked:
/// unchanged when its size and mtime match the store's record, or failing
/// that when its content hash does — so an unchanged tree costs one `stat`
/// per file, and a touched-but-identical file costs one read.
fn find_changes(
    root: &Path,
    stored: &HashMap<String, (u64, i64, u64)>,
    previous: Option<&TreeState>,
    overlay: Option<&Overlay>,
) -> Changes {
    // An overlay describes a tree git does not know; every file is compared.
    let same_root = overlay.is_none() && previous.is_some_and(|p| {
        std::path::absolute(root).map(|a| a.to_string_lossy().replace('\\', "/")).ok().as_deref() == Some(p.root.as_str())
    });
    if same_root && let Some((now, candidates)) = previous.and_then(|p| crate::tree::git_candidates(root, p)) {
        let mut present: HashSet<String> = stored.keys().cloned().collect();
        let mut changed = Vec::new();
        let mut deleted = Vec::new();
        for rel in candidates {
            let path = root.join(&rel);
            if crate::tree::is_indexable(root, &rel) {
                present.insert(rel.clone());
                let unchanged = stored
                    .get(&rel)
                    .is_some_and(|&(hash, _, _)| std::fs::read(&path).is_ok_and(|b| content_hash(&b) == hash));
                if !unchanged {
                    changed.push(path);
                }
            } else if stored.contains_key(&rel) {
                present.remove(&rel);
                deleted.push(rel);
            }
        }
        changed.sort();
        deleted.sort();
        return Changes { changed, deleted, scanned: present.len(), present, how: "git", git: Some(now) };
    }

    let scan = scan(root);
    let mut present: HashSet<String> = HashSet::with_capacity(scan.files.len());
    let mut changed: Vec<PathBuf> = Vec::new();
    for (path, &(now_size, now_mtime)) in scan.files.iter().zip(&scan.metadata) {
        let rel = rel_path(root, path);
        let unchanged = match overlay.and_then(|o| o.get(&rel)) {
            // The overlay says what this file holds — or that it is not there.
            Some(Some(bytes)) => stored.get(&rel).is_some_and(|&(hash, _, _)| content_hash(bytes) == hash),
            Some(None) => continue,
            None => match stored.get(&rel) {
                Some(&(hash, mtime, size)) if now_size == size => {
                    (mtime != 0 && now_mtime == mtime)
                        || std::fs::read(path).is_ok_and(|bytes| content_hash(&bytes) == hash)
                }
                _ => false,
            },
        };
        present.insert(rel);
        if !unchanged {
            changed.push(path.clone());
        }
    }
    // Overlay files the tree does not have (deleted since the commit).
    if let Some(o) = overlay {
        for (rel, bytes) in o {
            if let Some(bytes) = bytes
                && !present.contains(rel)
                && lang::for_path(Path::new(rel)).is_some()
            {
                present.insert(rel.clone());
                if stored.get(rel).is_none_or(|&(hash, _, _)| content_hash(bytes) != hash) {
                    changed.push(root.join(rel));
                }
            }
        }
        changed.sort();
    }
    let mut deleted: Vec<String> = stored.keys().filter(|p| !present.contains(*p)).cloned().collect();
    deleted.sort();
    let git = crate::tree::detect_git(root).and_then(|r| crate::tree::git_state(root, &r));
    Changes { changed, deleted, scanned: scan.files.len(), present, how: "scan", git }
}

/// Repo-relative, forward slashes: the path as the store spells it.
fn rel_path(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

/// Bring a store up to date with its source tree, re-indexing only what
/// changed.
///
/// A file is unchanged when its size and mtime match the store's record, or
/// failing that when its content hash does — so an unchanged tree costs one
/// `stat` per file, and a touched-but-identical file costs one read. Changed
/// files are re-extracted along with their **neighbourhood**: every file that
/// has an edge to or from them. Those are the files whose bindings the change
/// can have altered — a caller that now finds or loses its callee, an
/// importer, a type implementing an interface — and re-extracting them means
/// their edges are recomputed rather than inherited. A file further away can
/// only be affected through corpus-wide name uniqueness, and that is left to
/// the next full compaction, which the [`CompactPolicy`] schedules.
///
/// The result is a delta segment beside the base. The base is rewritten only
/// when the policy says the deltas have grown to a fraction of it — and then
/// by a **full re-index**, not a merge, because a merge cannot revisit the
/// bindings a delta left to corpus-wide rules. That is what bounds the
/// staleness a delta can accumulate: it lasts until the next rebuild, and the
/// rebuild comes after a bounded amount of change.
pub fn update_tree(
    root: &Path,
    store: &mut Store,
    repo: &str,
    policy: &CompactPolicy,
) -> Result<UpdateReport> {
    update_tree_with(root, store, repo, policy, None)
}

/// [`update_tree`] against the tree as an overlay describes it: the files
/// named there have the overlay's content (or are absent), the rest are as
/// on disk. The store's tree record is not written — the overlay is not
/// the tree.
pub fn update_tree_with(
    root: &Path,
    store: &mut Store,
    repo: &str,
    policy: &CompactPolicy,
    overlay: Option<&Overlay>,
) -> Result<UpdateReport> {
    // A store with no compacted base cannot answer the neighbourhood
    // question (it needs the reverse CSR), so it gets the full treatment.
    let has_base = store
        .segments()
        .next()
        .is_some_and(|(_, s)| s.keys_are_sorted() && s.has_reverse_csr());
    // A store whose file table carries no content hashes — compacted before
    // compaction preserved them — cannot tell changed from unchanged either.
    let has_hashes = store
        .view()
        .live_files()?
        .iter()
        .any(|(_, r)| r.content_hash != 0);
    if !has_base || !has_hashes {
        let r = index_tree(root, store, repo)?;
        return Ok(UpdateReport {
            scanned: r.scanned,
            changed: r.extracted,
            deleted: 0,
            reextracted: r.extracted,
            incremental: false,
            build: r.build,
            compaction: None,
            symbols: r.symbols,
            edges: r.edges,
            changed_paths: Vec::new(),
            deleted_paths: Vec::new(),
            reextracted_paths: Vec::new(),
            detection: "full",
        });
    }

    // --- what changed ---
    let stored: HashMap<String, (u64, i64, u64)> = store
        .view()
        .live_files()?
        .into_iter()
        .filter(|(p, _)| !p.is_empty())
        .map(|(p, r)| (p.to_string(), (r.content_hash, r.mtime_nanos, r.size)))
        .collect();
    let previous = TreeState::load(store.root());
    let Changes { changed, deleted, present, scanned, how, git } = find_changes(root, &stored, previous.as_ref(), overlay);
    let state = TreeState {
        root: std::path::absolute(root).unwrap_or_else(|_| root.to_path_buf()).to_string_lossy().replace('\\', "/"),
        repo: repo.to_string(),
        git,
    };

    if changed.is_empty() && deleted.is_empty() {
        if overlay.is_none() {
            let _ = state.save(store.root());
        }
        return Ok(UpdateReport {
            scanned,
            changed: 0,
            deleted: 0,
            reextracted: 0,
            incremental: true,
            build: Default::default(),
            compaction: None,
            symbols: store.symbol_count(),
            edges: store.edge_count(),
            changed_paths: Vec::new(),
            deleted_paths: Vec::new(),
            reextracted_paths: Vec::new(),
            detection: how,
        });
    }

    // --- the neighbourhood ---
    // Changed files are extracted first: whether a neighbour needs
    // re-extracting depends on what changed *in* them.
    let changed_extracts = extract_all_with(root, &changed, overlay);
    let touched: HashSet<String> = changed
        .iter()
        .map(|p| rel_path(root, p))
        .chain(deleted.iter().cloned())
        .collect();
    // Per touched file: its symbols as the store has them, the files with an
    // edge *into* it (and whether that edge is `implements`), and the files
    // it has an edge *to*.
    let mut old_symbols: HashMap<String, HashSet<(SymbolKey, u8)>> = HashMap::new();
    let mut in_neighbours: HashMap<String, Vec<(String, bool)>> = HashMap::new();
    let mut out_neighbours: HashSet<String> = HashSet::new();
    {
        let view = store.view();
        for si in 0..view.segment_count() {
            let (seg, base) = view.segment(si);
            // Which of this segment's files are touched, by id: a per-row path
            // compare would be a string compare per row of the store.
            let file_touched: Vec<bool> =
                seg.files()?.iter().map(|f| touched.contains(seg.string(f.path))).collect();
            if !file_touched.iter().any(|t| *t) {
                continue;
            }
            let files = seg.node_files()?;
            let keys = seg.keys()?;
            let kinds = seg.node_kinds()?;
            let flags = seg.node_flags()?;
            for l in 0..seg.node_count() {
                let id = LocalId::new(base + l as u32);
                // A package stub is attached to whichever file first imported
                // it; it is not that file's symbol, and its importers are not
                // the file's neighbours.
                if !file_touched[files[l].index()]
                    || !view.is_canonical(id)
                    || flags[l] & node_flags::EXTERNAL != 0
                {
                    continue;
                }
                let path = seg.file_path(files[l]);
                // A callable's CFG blocks are renumbered by any edit to its
                // body; they are not part of the file's API and must not
                // make a body edit look like one.
                if flags[l] & node_flags::FILE_NODE == 0
                    && kinds[l] != SymbolKind::Block.as_u8()
                    && kinds[l] != SymbolKind::Local.as_u8()
                {
                    old_symbols.entry(path.to_string()).or_default().insert((keys[l], kinds[l]));
                }
                let usable = |p: &str| !p.is_empty() && !touched.contains(p) && present.contains(p);
                for e in view.in_edges(id, RelationMask::ALL)? {
                    let p = view.path(e.node)?;
                    if usable(p) {
                        in_neighbours
                            .entry(path.to_string())
                            .or_default()
                            .push((p.to_string(), e.relation == Relation::Implements));
                    }
                }
                for e in view.out_edges(id, HERITAGE)? {
                    let p = view.path(e.node)?;
                    if usable(p) {
                        out_neighbours.insert(p.to_string());
                    }
                }
            }
        }
    }
    // A file whose symbol set is unchanged — same keys, same kinds: a body
    // edit — cannot change what any other file binds to, since bindings are
    // by name, kind, and existence. Its importers stay put. The exception is
    // a type implementing one of its interfaces: satisfaction is judged on
    // arity, which the store does not hold, so the implementer is
    // re-extracted to be sure. In the other direction only the files holding
    // a changed file's *supertypes* are re-extracted: whether a base is a
    // protocol is read off its own declaration, which a context symbol does
    // not carry. Call and import targets need nothing — a callee is bound by
    // name and kind, and both are in the store.
    let mut reextract: HashSet<String> = out_neighbours;
    let new_symbols: HashMap<&str, HashSet<(SymbolKey, u8)>> = changed_extracts
        .iter()
        .map(|f| (f.path.as_str(), crate::symbol_keys(f, repo).into_iter().collect()))
        .collect();
    for (path, importers) in &in_neighbours {
        let stable = new_symbols
            .get(path.as_str())
            .is_some_and(|new| old_symbols.get(path).is_some_and(|old| old == new));
        for (p, via_implements) in importers {
            if !stable || *via_implements {
                reextract.insert(p.clone());
            }
        }
    }
    let neighbours: Vec<PathBuf> = {
        let mut v: Vec<PathBuf> = reextract.iter().map(|p| root.join(p)).collect();
        v.sort();
        v
    };

    // --- delta, or rebuild? ---
    // The rows this delta will add are about the rows its files hold now.
    // If that pushes the deltas past the policy's share of the base, a
    // rebuild is due anyway, and doing it now instead of writing a delta
    // first saves the delta. This is the only place the base is rewritten
    // on an update: a rebuild re-resolves everything, where the store's own
    // full merge would only move rows.
    let (base_rows, delta_rows, will_add) = {
        let view = store.view();
        let will: HashSet<&str> = touched
            .iter()
            .map(String::as_str)
            .chain(reextract.iter().map(String::as_str))
            .collect();
        let mut base_rows = 0usize;
        let mut delta_rows = 0usize;
        let mut will_add = 0usize;
        for si in 0..view.segment_count() {
            let (seg, _) = view.segment(si);
            if si == 0 { base_rows += seg.node_count() } else { delta_rows += seg.node_count() }
            let wanted: Vec<bool> =
                seg.files()?.iter().map(|f| will.contains(seg.string(f.path))).collect();
            if wanted.iter().any(|w| *w) {
                will_add += seg.node_files()?.iter().filter(|f| wanted[f.index()]).count();
            }
        }
        (base_rows.max(1), delta_rows, will_add)
    };
    if (delta_rows + will_add) as f64 > policy.max_delta_ratio * base_rows as f64 {
        let r = index_tree(root, store, repo)?;
        return Ok(UpdateReport {
            scanned: r.scanned,
            changed: changed.len(),
            deleted: deleted.len(),
            reextracted: r.extracted,
            incremental: false,
            build: r.build,
            compaction: None,
            symbols: r.symbols,
            edges: r.edges,
            changed_paths: changed.iter().map(|p| rel_path(root, p)).collect(),
            deleted_paths: deleted,
            reextracted_paths: Vec::new(),
            detection: "full",
        });
    }

    // --- write ---
    // Deletions first, so a changed file that imported a deleted one resolves
    // against a corpus that no longer contains it.
    store.remove_files(&deleted)?;
    let mut files = changed_extracts;
    files.extend(extract_all_with(root, &neighbours, overlay));
    // A file that would not extract must not keep its stale rows.
    let extracted: HashSet<&str> = files.iter().map(|f| f.path.as_str()).collect();
    let failed: Vec<String> = changed
        .iter()
        .chain(&neighbours)
        .map(|p| rel_path(root, p))
        .filter(|p| !extracted.contains(p.as_str()) && stored.contains_key(p))
        .collect();
    store.remove_files(&failed)?;
    let build = crate::build_delta(&files, store, repo, &import_roots(root))?;
    // Only the delta tier: the ratio was applied above, as a rebuild.
    let deltas_only = CompactPolicy { max_delta_ratio: f64::INFINITY, ..*policy };
    let compaction = compact_tiered(store, &deltas_only)?;
    if overlay.is_none() {
        let _ = state.save(store.root());
    }

    Ok(UpdateReport {
        scanned,
        changed: changed.len(),
        deleted: deleted.len() + failed.len(),
        reextracted: files.len(),
        incremental: true,
        build,
        compaction,
        symbols: store.symbol_count(),
        edges: store.edge_count(),
        changed_paths: changed.iter().map(|p| rel_path(root, p)).collect(),
        deleted_paths: deleted.into_iter().chain(failed).collect(),
        reextracted_paths: files.iter().map(|f| f.path.clone()).collect(),
        detection: how,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Shared with the receiver tests below.
    pub(super) fn write_for_tests(dir: &Path, rel: &str, body: &str) {
        write(dir, rel, body);
    }

    fn write(dir: &Path, rel: &str, body: &str) {
        let p = dir.join(rel);
        if let Some(parent) = p.parent() {
            std::fs::create_dir_all(parent).expect("mkdir");
        }
        std::fs::write(p, body).expect("write");
    }

    #[test]
    fn scan_finds_source_and_skips_noise() {
        let d = tempfile::tempdir().unwrap();
        write(d.path(), "a.py", "def f(): pass\n");
        write(d.path(), "sub/b.rs", "fn g() {}\n");
        write(d.path(), "node_modules/c.js", "function h() {}\n");
        write(d.path(), "notes.txt", "hello\n");

        let s = scan(d.path());
        let names: Vec<String> = s
            .files
            .iter()
            .map(|p| p.file_name().unwrap().to_string_lossy().to_string())
            .collect();
        assert!(names.contains(&"a.py".to_string()));
        assert!(names.contains(&"b.rs".to_string()));
        assert!(!names.contains(&"c.js".to_string()), "node_modules was scanned");
        assert!(!names.contains(&"notes.txt".to_string()), "a non-source file was scanned");
        assert_eq!(s.skipped_dirs, 1);
    }

    #[test]
    fn scan_is_deterministic() {
        let d = tempfile::tempdir().unwrap();
        for i in 0..20 {
            write(d.path(), &format!("f{i}.py"), "def f(): pass\n");
        }
        assert_eq!(scan(d.path()).files, scan(d.path()).files);
    }

    #[test]
    fn paths_are_repo_relative_and_posix() {
        let d = tempfile::tempdir().unwrap();
        write(d.path(), "pkg/mod.py", "def f(): pass\n");
        let s = scan(d.path());
        let files = extract_all(d.path(), &s.files);
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].path, "pkg/mod.py", "path is not repo-relative POSIX");
    }

    #[test]
    fn a_cross_file_call_resolves_through_an_import() {
        let d = tempfile::tempdir().unwrap();
        write(d.path(), "lib.py", "def helper():\n    pass\n");
        write(d.path(), "main.py", "import lib\n\ndef run():\n    helper()\n");

        let store_dir = tempfile::tempdir().unwrap();
        let mut store = Store::create(store_dir.path()).unwrap();
        let report = index_tree(d.path(), &mut store, "").unwrap();

        assert_eq!(report.extracted, 2);
        assert_eq!(report.build.imports_resolved, 1, "the import did not resolve");
        assert_eq!(
            report.build.calls_cross_file, 1,
            "the cross-file call did not bind: {:?}",
            report.build
        );
    }

    /// The rule this module exists for: an ambiguous name must not bind.
    #[test]
    fn an_ambiguous_cross_file_name_is_left_unbound() {
        let d = tempfile::tempdir().unwrap();
        write(d.path(), "one.py", "def helper():\n    pass\n");
        write(d.path(), "two.py", "def helper():\n    pass\n");
        write(d.path(), "main.py", "import one\nimport two\n\ndef run():\n    helper()\n");

        let store_dir = tempfile::tempdir().unwrap();
        let mut store = Store::create(store_dir.path()).unwrap();
        let report = index_tree(d.path(), &mut store, "").unwrap();
        assert_eq!(
            report.build.calls_cross_file, 0,
            "an ambiguous call was bound anyway: {:?}",
            report.build
        );
        assert_eq!(report.build.calls_ambiguous, 1);
    }

    /// And a call with no import backing it must not bind either, even when the
    /// name is unique — that is how phantom cross-package edges appear.
    #[test]
    fn a_cross_file_call_without_an_import_is_left_unbound() {
        let d = tempfile::tempdir().unwrap();
        write(d.path(), "lib.py", "def helper():\n    pass\n");
        write(d.path(), "main.py", "def run():\n    helper()\n");

        let store_dir = tempfile::tempdir().unwrap();
        let mut store = Store::create(store_dir.path()).unwrap();
        let report = index_tree(d.path(), &mut store, "").unwrap();
        assert_eq!(
            report.build.calls_cross_file, 0,
            "a call with no import evidence was bound: {:?}",
            report.build
        );
    }

    #[test]
    fn a_local_call_binds_as_extracted() {
        let d = tempfile::tempdir().unwrap();
        write(d.path(), "a.py", "def helper():\n    pass\n\ndef run():\n    helper()\n");
        let store_dir = tempfile::tempdir().unwrap();
        let mut store = Store::create(store_dir.path()).unwrap();
        let report = index_tree(d.path(), &mut store, "").unwrap();
        assert_eq!(report.build.calls_local, 1, "{:?}", report.build);
    }

    #[test]
    fn indexing_the_same_tree_twice_is_stable() {
        let d = tempfile::tempdir().unwrap();
        write(d.path(), "a.py", "class A:\n    def m(self): pass\n");
        write(d.path(), "b.py", "class B:\n    def m(self): pass\n");

        let run = || {
            let sd = tempfile::tempdir().unwrap();
            let mut store = Store::create(sd.path()).unwrap();
            let r = index_tree(d.path(), &mut store, "").unwrap();
            let keys: Vec<_> = store
                .segments()
                .flat_map(|(_, s)| s.keys().unwrap().to_vec())
                .collect();
            (r, keys)
        };
        let (r1, k1) = run();
        let (r2, k2) = run();
        assert_eq!(r1, r2);
        assert_eq!(k1, k2, "keys are not stable across independent runs");
    }

    /// Same-named methods on different classes must be distinct symbols end to
    /// end, not only inside the walk.
    #[test]
    fn same_named_methods_survive_as_distinct_symbols() {
        let d = tempfile::tempdir().unwrap();
        write(
            d.path(),
            "a.py",
            "class Alpha:\n    def __init__(self): pass\n\nclass Beta:\n    def __init__(self): pass\n",
        );
        let sd = tempfile::tempdir().unwrap();
        let mut store = Store::create(sd.path()).unwrap();
        index_tree(d.path(), &mut store, "").unwrap();

        let (_, seg) = store.segments().next().unwrap();
        let norms = seg.node_norm_names().unwrap();
        let inits = (0..seg.node_count())
            .filter(|&i| seg.string(norms[i]) == "__init__")
            .count();
        assert_eq!(inits, 2, "the two __init__ methods collapsed into one");
    }
}

#[cfg(test)]
mod receiver_tests {
    use super::*;
    use super::tests::write_for_tests as write;

    fn report(src: &Path) -> crate::IndexReport {
        let sd = tempfile::tempdir().unwrap();
        let mut store = Store::create(sd.path()).unwrap();
        index_tree(src, &mut store, "").unwrap()
    }

    /// `self.foo()` inside a class must bind to *that* class's `foo`, even when
    /// another class defines a method with the same name. This is the case the
    /// name-uniqueness rules cannot reach.
    #[test]
    fn a_self_call_binds_to_the_enclosing_types_method() {
        let d = tempfile::tempdir().unwrap();
        write(
            d.path(),
            "a.py",
            "class Alpha:\n    def helper(self): pass\n    def run(self):\n        self.helper()\n\n\
             class Beta:\n    def helper(self): pass\n",
        );
        let r = report(d.path());
        assert_eq!(
            r.build.calls_receiver, 1,
            "self.helper() did not bind through its receiver: {:?}",
            r.build
        );
        // And it must not have fallen through to the ambiguous bucket.
        assert_eq!(r.build.calls_ambiguous, 0, "{:?}", r.build);
    }

    /// The self rule must pick the right class when two classes in the same
    /// file both define the method.
    #[test]
    fn a_self_call_picks_the_right_owner() {
        let d = tempfile::tempdir().unwrap();
        write(
            d.path(),
            "a.py",
            "class Alpha:\n    def helper(self): pass\n\n\
             class Beta:\n    def helper(self): pass\n    def run(self):\n        self.helper()\n",
        );
        let sd = tempfile::tempdir().unwrap();
        let mut store = Store::create(sd.path()).unwrap();
        index_tree(d.path(), &mut store, "").unwrap();

        let index = codegraph_index::IndexData::build(&store).unwrap();
        let e = codegraph_query::Engine::from_parts(store, index);

        let run = e.by_name("run");
        assert_eq!(run.len(), 1);
        let called: Vec<_> = e
            .neighbors(
                run[0],
                codegraph_query::Direction::Out,
                codegraph_core::RelationMask::of(&[codegraph_core::Relation::Calls]),
            )
            .unwrap();
        assert_eq!(called.len(), 1, "run() should call exactly one helper");
        let target = e.info(called[0].id).unwrap().unwrap();
        // Beta's helper is the second one defined, so it has the higher line.
        assert_eq!(target.name, "helper");
        assert_eq!(
            target.line, 5,
            "self.helper() bound to the wrong class's helper (line {})",
            target.line
        );
    }

    #[test]
    fn a_named_type_receiver_binds_when_unambiguous() {
        let d = tempfile::tempdir().unwrap();
        write(
            d.path(),
            "a.py",
            "class Alpha:\n    def helper(self): pass\n\ndef run():\n    Alpha.helper()\n",
        );
        let r = report(d.path());
        assert_eq!(r.build.calls_receiver, 1, "{:?}", r.build);
    }

    /// Two classes with the same name means the receiver names nothing
    /// definite, so no edge — the same unambiguity rule as everywhere else.
    #[test]
    fn an_ambiguous_type_receiver_does_not_bind() {
        let d = tempfile::tempdir().unwrap();
        write(d.path(), "one.py", "class Shared:\n    def helper(self): pass\n");
        write(d.path(), "two.py", "class Shared:\n    def helper(self): pass\n");
        write(d.path(), "main.py", "def run():\n    Shared.helper()\n");
        let r = report(d.path());
        assert_eq!(
            r.build.calls_receiver, 0,
            "an ambiguous type receiver bound anyway: {:?}",
            r.build
        );
    }

    /// A receiver that is a plain variable names no type, so nothing binds
    /// through the receiver rule.
    #[test]
    fn an_unknown_receiver_falls_through() {
        let d = tempfile::tempdir().unwrap();
        write(
            d.path(),
            "a.py",
            "class Alpha:\n    def helper(self): pass\n\ndef run(thing):\n    thing.helper()\n",
        );
        let r = report(d.path());
        assert_eq!(r.build.calls_receiver, 0, "{:?}", r.build);
    }

    /// JavaScript spells it `this`, and the same rule must apply.
    #[test]
    fn this_works_the_same_way_in_javascript() {
        let d = tempfile::tempdir().unwrap();
        write(
            d.path(),
            "a.js",
            "class Alpha {\n  helper() {}\n  run() { this.helper(); }\n}\n\
             class Beta {\n  helper() {}\n}\n",
        );
        let r = report(d.path());
        assert_eq!(r.build.calls_receiver, 1, "{:?}", r.build);
    }
}
