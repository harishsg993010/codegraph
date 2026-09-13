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
use codegraph_store::{CompactPolicy, Store};
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
/// the store. Returns the update and what the index needed.
pub fn sync(root: &Path, store_dir: &Path, repo: &str, policy: &CompactPolicy) -> std::result::Result<(UpdateReport, Opened), OpenError> {
    let mut store = Store::open_or_create(store_dir)?;
    let report = update_tree(root, &mut store, repo, policy)?;
    let (_, how) = open_or_build(&store, store_dir)?;
    Ok((report, how))
}
