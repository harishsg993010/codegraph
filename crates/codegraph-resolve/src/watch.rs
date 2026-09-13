//! Keeping a store current as the tree changes.
//!
//! [`TreeWatcher`] turns file-system events under a root into batches:
//! events arrive, the watcher waits for a quiet period (an editor writes
//! several files, a `git checkout` writes hundreds), then hands over the
//! paths that could matter — source files, ignore files, directories —
//! and nothing under the store itself, whose own writes would otherwise
//! trigger the next round. [`sync`] is one round: bring the store up to
//! date with the tree and the index up to date with the store. `codegraph
//! watch` and the MCP server run the two in a loop.

use std::path::{Path, PathBuf};
use std::sync::mpsc::{Receiver, RecvTimeoutError, Sender, channel};
use std::time::{Duration, Instant};

use codegraph_extract::lang;
use codegraph_index::{OpenError, Opened, open_or_build};
use codegraph_store::{CompactPolicy, Store, StoreError, WriteLock};

use crate::tree::TreeState;
use notify::{RecursiveMode, Watcher};

use crate::tree::{SKIP_DIRS, is_ignore_file};
use crate::{UpdateReport, update_tree};

/// A watch on a source tree, delivering batches of changed paths.
pub struct TreeWatcher {
    batches: Receiver<Vec<PathBuf>>,
    _watcher: notify::RecommendedWatcher,
}

/// Could a change at this path alter the graph? Source files, anything
/// that may be a directory (renamed, removed), and ignore files; never
/// the store, never a skipped directory's contents.
fn relevant(path: &Path, root: &Path, store_dir: &Path) -> bool {
    if path.starts_with(store_dir) {
        return false;
    }
    let rel = path.strip_prefix(root).unwrap_or(path);
    if rel.components().any(|c| SKIP_DIRS.contains(&c.as_os_str().to_string_lossy().as_ref())) {
        return false;
    }
    let name = path.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
    is_ignore_file(&name) || lang::for_path(path).is_some() || path.extension().is_none()
}

impl TreeWatcher {
    /// Watch `root` recursively. Events are grouped until `debounce` has
    /// passed with none; a batch is delivered only when it holds a path
    /// that could matter.
    pub fn new(root: &Path, store_dir: &Path, debounce: Duration) -> std::result::Result<Self, notify::Error> {
        let (raw_tx, raw_rx) = channel::<notify::Result<notify::Event>>();
        let (batch_tx, batch_rx) = channel::<Vec<PathBuf>>();
        let mut watcher = notify::recommended_watcher(move |ev| {
            let _ = raw_tx.send(ev);
        })?;
        watcher.watch(root, RecursiveMode::Recursive)?;
        let root = std::path::absolute(root).unwrap_or_else(|_| root.to_path_buf());
        let store_dir = std::path::absolute(store_dir).unwrap_or_else(|_| store_dir.to_path_buf());
        std::thread::Builder::new()
            .name("codegraph-watch".into())
            .spawn(move || collect(raw_rx, batch_tx, &root, &store_dir, debounce))
            .map_err(|e| notify::Error::generic(&e.to_string()))?;
        Ok(TreeWatcher { batches: batch_rx, _watcher: watcher })
    }

    /// The next batch, blocking. `None` once the watch has ended.
    pub fn next(&self) -> Option<Vec<PathBuf>> {
        self.batches.recv().ok()
    }

    /// The next batch within `timeout`, or `None`.
    pub fn next_within(&self, timeout: Duration) -> Option<Vec<PathBuf>> {
        self.batches.recv_timeout(timeout).ok()
    }
}

/// The debounce loop: gather paths until the tree has been quiet for
/// `debounce`, then deliver what is relevant.
fn collect(
    raw: Receiver<notify::Result<notify::Event>>,
    out: Sender<Vec<PathBuf>>,
    root: &Path,
    store_dir: &Path,
    debounce: Duration,
) {
    let mut pending: Vec<PathBuf> = Vec::new();
    let mut quiet_since: Option<Instant> = None;
    loop {
        let wait = match quiet_since {
            Some(t) => debounce.saturating_sub(t.elapsed()),
            None => Duration::from_secs(3600),
        };
        match raw.recv_timeout(wait) {
            Ok(Ok(ev)) => {
                for p in ev.paths {
                    if relevant(&p, root, store_dir) {
                        pending.push(p);
                    }
                }
                // Even an irrelevant event resets the clock: the tree is
                // not quiet yet.
                quiet_since = Some(Instant::now());
            }
            Ok(Err(_)) => {
                // A watch error (an overflow of the OS queue, a path gone):
                // the safe answer is "something changed", which the update
                // will confirm or deny by hashing.
                pending.push(root.to_path_buf());
                quiet_since = Some(Instant::now());
            }
            Err(RecvTimeoutError::Timeout) => {
                quiet_since = None;
                if !pending.is_empty() {
                    pending.sort();
                    pending.dedup();
                    if out.send(std::mem::take(&mut pending)).is_err() {
                        return;
                    }
                }
            }
            Err(RecvTimeoutError::Disconnected) => return,
        }
    }
}

/// One round: the store brought up to date with `root`, the index with
/// the store. `Ok(None)` when another process holds the store's write
/// lock — it is doing this same work, and the caller reads what is there.
pub fn sync(root: &Path, store_dir: &Path, repo: &str, policy: &CompactPolicy) -> std::result::Result<Option<(UpdateReport, Opened)>, OpenError> {
    let Some(_lock) = WriteLock::try_acquire(store_dir).map_err(|e| StoreError::io("locking the store", e))? else {
        return Ok(None);
    };
    let mut store = Store::open_or_create(store_dir)?;
    let report = update_tree(root, &mut store, repo, policy)?;
    let (_, how) = open_or_build(&store, store_dir)?;
    Ok(Some((report, how)))
}

/// What a path given to a command names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Located {
    /// The store directory: the path itself, its `.codegraph`, or the
    /// `.codegraph` a source tree will get.
    pub store_dir: PathBuf,
    /// The tree the store follows, when known: recorded in the store, or
    /// the directory given.
    pub source: Option<PathBuf>,
    /// No store yet: the path is a source tree to index on first use.
    pub fresh: bool,
}

/// Resolve what a command was given: a store directory, a source tree
/// with a store inside it, or a source tree with none yet.
pub fn locate(path: &Path) -> std::io::Result<Located> {
    let is_store = |d: &Path| d.join("CURRENT").is_file();
    if is_store(path) {
        let source = TreeState::load(path).map(|t| t.root_path()).filter(|r| r.is_dir());
        return Ok(Located { store_dir: path.to_path_buf(), source, fresh: false });
    }
    if !path.is_dir() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("{} is neither a store nor a source tree", path.display()),
        ));
    }
    let inner = path.join(".codegraph");
    if is_store(&inner) {
        let source = TreeState::load(&inner).map(|t| t.root_path()).filter(|r| r.is_dir()).unwrap_or_else(|| path.to_path_buf());
        return Ok(Located { store_dir: inner, source: Some(source), fresh: false });
    }
    Ok(Located { store_dir: inner, source: Some(path.to_path_buf()), fresh: true })
}

/// What [`ensure_current`] did.
#[derive(Debug)]
pub struct Ensured {
    pub located: Located,
    /// The update that ran, if one did.
    pub report: Option<UpdateReport>,
    /// Why no update ran, when none did and the store has a tree.
    pub skipped: Option<&'static str>,
}

/// The store a command should read, brought up to date first: a source
/// tree with no store is indexed (waiting for another process already
/// doing so), a store that knows its tree is synced unless another
/// process is syncing it now, a store that knows no tree is read as is.
pub fn ensure_current(path: &Path, repo: &str, policy: &CompactPolicy) -> std::result::Result<Ensured, OpenError> {
    let located = locate(path).map_err(|e| StoreError::io("locating the store", e))?;
    let Some(source) = located.source.clone() else {
        return Ok(Ensured { located, report: None, skipped: Some("the store does not record its source tree") });
    };
    if located.fresh {
        // First use: index, and if someone else is indexing this same
        // tree right now, wait for them rather than race.
        let lock = WriteLock::acquire(&located.store_dir, Duration::from_secs(600)).map_err(|e| StoreError::io("locking the store", e))?;
        if lock.is_none() {
            return Ok(Ensured { located, report: None, skipped: Some("another process has held the store's lock for ten minutes") });
        }
        let mut store = Store::open_or_create(&located.store_dir)?;
        let report = update_tree(&source, &mut store, repo, policy)?;
        open_or_build(&store, &located.store_dir)?;
        return Ok(Ensured { located, report: Some(report), skipped: None });
    }
    match sync(&source, &located.store_dir, repo, policy)? {
        Some((report, _)) => Ok(Ensured { located, report: Some(report), skipped: None }),
        None => Ok(Ensured { located, report: None, skipped: Some("another process is updating it") }),
    }
}
