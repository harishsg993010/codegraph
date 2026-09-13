//! The source tree as a thing with a state: which files are in it, which
//! of them changed since the store last saw it, and what git knows about
//! either.
//!
//! Three concerns live here.
//!
//! **Which files.** [`scan`] walks the tree honouring `.gitignore`,
//! `.git/info/exclude` and `.codegraphignore` — gitignore syntax, any
//! directory, `!` re-includes — whether or not git is installed or the
//! tree is a repository. The built-in [`SKIP_DIRS`] list still applies as
//! a floor: `node_modules` is not indexed even in a tree with no ignore
//! file at all.
//!
//! **What git knows.** When the tree is inside a git repository and a
//! `git` binary is on the path, the store records the commit it indexed
//! and the paths that were dirty at the time. The next update then asks
//! git two questions — the current commit and the dirty paths — and the
//! files that can have changed are the union of the two dirty sets and
//! `git diff --name-only` between the commits. That is O(changes), not
//! O(files), and it is git's own stat cache doing the work. Any doubt —
//! git missing, a command failing, an ignore file among the changes, no
//! record from last time — falls back to the walk, which is always
//! correct and merely slower. Without git the store's file table *is* the
//! equivalent of git's index: path, size, mtime and content hash per
//! file, compared the way git compares its index to the working tree.
//!
//! **Remembering.** [`TreeState`] is the small JSON record beside the
//! manifest that makes the above possible across runs: the source root
//! the store was built from (so a server can watch it), and the git
//! commit and dirty set at the last index.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicUsize, Ordering};

use codegraph_extract::lang;
use serde::{Deserialize, Serialize};

/// Directories that never hold source we index. A conservative list — anything
/// missing here costs time, not correctness.
pub const SKIP_DIRS: &[&str] = &[
    ".git", ".hg", ".svn", "node_modules", "__pycache__", "target", "dist", "build",
    ".mypy_cache", ".pytest_cache", ".ruff_cache", ".venv", "venv", ".tox", "vendor",
    ".next", ".nuxt", ".cargo", ".rustup", ".codegraph",
];

/// The ignore file codegraph reads in addition to `.gitignore`: same
/// syntax, any directory, for what should stay out of the graph but not
/// out of the repository (generated code, fixtures, a vendored tree).
pub const IGNORE_FILE: &str = ".codegraphignore";

/// The name of the state record inside a store directory.
pub const STATE_FILE: &str = "TREE";

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Scan {
    pub files: Vec<PathBuf>,
    /// `(size, mtime nanos)` per file, aligned with `files`. Read off the
    /// directory entry, which on every platform we support already carries
    /// it — a `stat` per file afterwards would cost more than the walk.
    pub metadata: Vec<(u64, i64)>,
    /// Directories skipped by name, so a wrongly-skipped source tree is at
    /// least traceable rather than silently absent.
    pub skipped_dirs: usize,
}

/// Modification time as nanoseconds since the epoch; `0` when unavailable.
pub(crate) fn mtime_of(meta: &std::fs::Metadata) -> i64 {
    meta.modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map_or(0, |d| d.as_nanos() as i64)
}

/// The walk every scan and every ignore test share.
fn walker(root: &Path) -> ignore::WalkBuilder {
    let mut wb = ignore::WalkBuilder::new(root);
    wb.hidden(false)
        .follow_links(false)
        .git_ignore(true)
        .git_exclude(true)
        .git_global(false)
        .ignore(true)
        .parents(true)
        // `.gitignore` means what it says even where git is not installed
        // or the tree is not a repository.
        .require_git(false)
        .sort_by_file_path(|a, b| a.cmp(b));
    wb.add_custom_ignore_filename(IGNORE_FILE);
    wb
}

/// Collect indexable files under `root`: every file with a language we
/// parse that no ignore rule excludes, in a deterministic order.
pub fn scan(root: &Path) -> Scan {
    let skipped = std::sync::Arc::new(AtomicUsize::new(0));
    let mut out = Scan::default();
    let mut found: Vec<(PathBuf, (u64, i64))> = Vec::new();
    let mut wb = walker(root);
    let skipped_ref = skipped.clone();
    wb.filter_entry(move |e| {
        let dir = e.file_type().is_some_and(|t| t.is_dir());
        let name = e.file_name().to_string_lossy();
        if dir && SKIP_DIRS.contains(&name.as_ref()) {
            skipped_ref.fetch_add(1, Ordering::Relaxed);
            return false;
        }
        true
    });
    for entry in wb.build().flatten() {
        // Symlinks are not followed: a link into a sibling checkout would
        // index the same file twice under two paths, and two paths mean
        // two identities.
        let Some(ft) = entry.file_type() else { continue };
        if ft.is_symlink() || !ft.is_file() {
            continue;
        }
        let path = entry.path().to_path_buf();
        if lang::for_path(&path).is_none() {
            continue;
        }
        let meta = entry.metadata().map(|m| (m.len(), mtime_of(&m))).unwrap_or((0, 0));
        found.push((path, meta));
    }
    found.sort();
    for (path, meta) in found {
        out.files.push(path);
        out.metadata.push(meta);
    }
    out.skipped_dirs = skipped.load(Ordering::Relaxed);
    out
}

/// Would `scan` include this path? For a path git reports as changed: the
/// same ignore rules, the same language filter, the same skip list.
pub fn is_indexable(root: &Path, rel: &str) -> bool {
    let path = root.join(rel);
    if lang::for_path(&path).is_none() || !path.is_file() {
        return false;
    }
    if Path::new(rel).components().any(|c| SKIP_DIRS.contains(&c.as_os_str().to_string_lossy().as_ref())) {
        return false;
    }
    // The walk itself, restricted to the directories on the way down to
    // the one path: what the ignore rules say at each level is exactly
    // what the scan would have said.
    let mut wb = walker(root);
    wb.max_depth(Some(Path::new(rel).components().count()));
    let target = path.clone();
    wb.filter_entry(move |e| target.starts_with(e.path()) || e.path() == target);
    wb.build().flatten().any(|e| e.path() == path)
}

/// Would the ignore rules exclude this path, whether or not it exists?
/// The rules in every directory from the root down to the path's, deeper
/// ones taking precedence, plus `.git/info/exclude` at the root. For a
/// path that exists, [`is_indexable`] is the exact answer; this is for
/// one that does not (deleted since the commit `diff` compares with).
pub fn is_ignored(root: &Path, rel: &str) -> bool {
    if Path::new(rel).components().any(|c| SKIP_DIRS.contains(&c.as_os_str().to_string_lossy().as_ref())) {
        return true;
    }
    let mut b = ignore::gitignore::GitignoreBuilder::new(root);
    let exclude = root.join(".git").join("info").join("exclude");
    if exclude.is_file() {
        b.add(exclude);
    }
    let mut dir = root.to_path_buf();
    let parts: Vec<&str> = rel.split('/').collect();
    for (i, part) in parts.iter().enumerate() {
        for name in [".gitignore", ".ignore", IGNORE_FILE] {
            let f = dir.join(name);
            if f.is_file() {
                b.add(f);
            }
        }
        if i + 1 < parts.len() {
            dir.push(part);
        }
    }
    let Ok(g) = b.build() else { return false };
    g.matched_path_or_any_parents(rel, false).is_ignore()
}

/// The content of `rel` at `HEAD`, or `None` when the commit has no such
/// file (untracked, or added since).
pub fn git_show_head(root: &Path, repo: &GitRepo, rel: &str) -> Option<Vec<u8>> {
    let spec = format!("HEAD:{}{}", repo.prefix, rel);
    git_output(root, &["show", &spec])
}

/// Is this the name of a file whose change alters what the scan returns?
pub fn is_ignore_file(rel: &str) -> bool {
    let name = rel.rsplit('/').next().unwrap_or(rel);
    name == ".gitignore" || name == IGNORE_FILE || name == ".ignore" || rel.ends_with(".git/info/exclude")
}

// ---------------------------------------------------------------- git ---

/// The git repository a tree is inside, if git is installed and says so.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitRepo {
    /// The repository's top-level directory.
    pub toplevel: PathBuf,
    /// The indexed root relative to the top level, with a trailing `/`,
    /// or empty when the root is the top level.
    pub prefix: String,
    /// The commit checked out, when there is one.
    pub head: Option<String>,
}

/// What git knew at one moment: the commit checked out and the paths
/// (relative to the indexed root, forward slashes) that differed from it —
/// modified, staged, untracked. Ignored files are not dirty: they are not
/// indexed either.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GitState {
    pub head: String,
    pub dirty: Vec<String>,
    /// The repository's top-level directory, for reporting.
    #[serde(default)]
    pub toplevel: String,
}

/// Is a usable `git` on the path? Asked once per process.
pub fn git_available() -> bool {
    static AVAILABLE: OnceLock<bool> = OnceLock::new();
    *AVAILABLE.get_or_init(|| {
        Command::new("git")
            .arg("--version")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .is_ok_and(|s| s.success())
    })
}

fn git_output(root: &Path, args: &[&str]) -> Option<Vec<u8>> {
    let out = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(args)
        .stderr(std::process::Stdio::null())
        .output()
        .ok()?;
    out.status.success().then_some(out.stdout)
}

/// The repository `root` is inside, if git is installed and `root` is in
/// a work tree. One process: top level, prefix and commit together, or
/// — in a repository with no commit yet — the first two alone.
pub fn detect_git(root: &Path) -> Option<GitRepo> {
    if !git_available() {
        return None;
    }
    let (out, with_head) = match git_output(root, &["rev-parse", "--show-toplevel", "--show-prefix", "HEAD"]) {
        Some(o) => (o, true),
        None => (git_output(root, &["rev-parse", "--show-toplevel", "--show-prefix"])?, false),
    };
    let text = String::from_utf8(out).ok()?;
    let mut lines = text.lines();
    let toplevel = PathBuf::from(lines.next()?.trim());
    let prefix = lines.next().unwrap_or("").trim().to_string();
    let head = with_head.then(|| lines.next().unwrap_or("").trim().to_string()).filter(|h| !h.is_empty());
    Some(GitRepo { toplevel, prefix, head })
}

/// The commit and dirty set now. `None` when git cannot say (no commit
/// yet, a command failing) — the caller falls back to the walk.
pub fn git_state(root: &Path, repo: &GitRepo) -> Option<GitState> {
    let head = repo.head.clone()?;
    // Porcelain v1, NUL-terminated: `XY path\0`, renames off so every
    // entry is one path. `--untracked-files=all` lists files, not the
    // directories that hold them.
    let out = git_output(root, &["status", "--porcelain=v1", "-z", "--untracked-files=all", "--no-renames", "--", "."])?;
    let mut dirty = Vec::new();
    for entry in out.split(|b| *b == 0) {
        if entry.len() < 4 {
            continue;
        }
        let path = String::from_utf8_lossy(&entry[3..]).to_string();
        if let Some(rel) = path.strip_prefix(repo.prefix.as_str()) {
            dirty.push(rel.to_string());
        }
    }
    dirty.sort();
    dirty.dedup();
    Some(GitState { head, dirty, toplevel: repo.toplevel.to_string_lossy().replace('\\', "/") })
}

/// Paths (relative to the indexed root) that differ between two commits,
/// or `None` when git cannot compare them (a rewritten history, a
/// commit gone after a rebase).
pub fn git_changed_between(root: &Path, repo: &GitRepo, old: &str, new: &str) -> Option<Vec<String>> {
    if old == new {
        return Some(Vec::new());
    }
    let range = format!("{old}..{new}");
    let out = git_output(root, &["diff", "--name-only", "--no-renames", "-z", &range, "--", "."])?;
    let mut v = Vec::new();
    for entry in out.split(|b| *b == 0) {
        if entry.is_empty() {
            continue;
        }
        let path = String::from_utf8_lossy(entry).to_string();
        if let Some(rel) = path.strip_prefix(repo.prefix.as_str()) {
            v.push(rel.to_string());
        }
    }
    Some(v)
}

/// Keep the store out of the repository: add its directory to
/// `.git/info/exclude` when it lives inside the work tree and is not
/// already ignored. Local to this clone, never committed, exactly what
/// git's own tooling does with its scratch directories.
pub fn exclude_store_from_git(repo: &GitRepo, store_dir: &Path) -> bool {
    let store_dir = std::path::absolute(store_dir).unwrap_or_else(|_| store_dir.to_path_buf());
    let toplevel = std::path::absolute(&repo.toplevel).unwrap_or_else(|_| repo.toplevel.clone());
    let Ok(rel) = store_dir.strip_prefix(&toplevel) else { return false };
    let rel = rel.to_string_lossy().replace('\\', "/");
    if rel.is_empty() {
        return false;
    }
    // Already ignored by some rule? Then nothing to add.
    if git_output(&repo.toplevel, &["check-ignore", "-q", &rel]).is_some() {
        return false;
    }
    let exclude = repo.toplevel.join(".git").join("info").join("exclude");
    let Some(parent) = exclude.parent() else { return false };
    if std::fs::create_dir_all(parent).is_err() {
        return false;
    }
    let existing = std::fs::read_to_string(&exclude).unwrap_or_default();
    let line = format!("/{rel}/");
    if existing.lines().any(|l| l.trim() == line) {
        return false;
    }
    let mut body = existing;
    if !body.is_empty() && !body.ends_with('\n') {
        body.push('\n');
    }
    body.push_str("# codegraph store\n");
    body.push_str(&line);
    body.push('\n');
    std::fs::write(&exclude, body).is_ok()
}

// -------------------------------------------------------------- state ---

/// What the store remembers about the tree it was built from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct TreeState {
    /// The absolute source root, so `watch` and the server can find the
    /// tree from the store alone.
    pub root: String,
    /// The repository label the store was indexed with.
    #[serde(default)]
    pub repo: String,
    /// Git's view at the last index, when git was available.
    #[serde(default)]
    pub git: Option<GitState>,
}

impl TreeState {
    pub fn load(store_dir: &Path) -> Option<Self> {
        let text = std::fs::read_to_string(store_dir.join(STATE_FILE)).ok()?;
        serde_json::from_str(&text).ok()
    }

    /// Written whole, then renamed into place, so a reader never sees a
    /// partial record.
    pub fn save(&self, store_dir: &Path) -> std::io::Result<()> {
        let text = serde_json::to_string_pretty(self).map_err(std::io::Error::other)?;
        let tmp = store_dir.join(format!("{STATE_FILE}.tmp"));
        std::fs::write(&tmp, text)?;
        std::fs::rename(&tmp, store_dir.join(STATE_FILE))
    }

    /// The record for `root` as it is now.
    pub fn capture(root: &Path, repo_label: &str) -> Self {
        let abs = std::path::absolute(root).unwrap_or_else(|_| root.to_path_buf());
        let git = detect_git(root).and_then(|r| git_state(root, &r));
        TreeState { root: abs.to_string_lossy().replace('\\', "/"), repo: repo_label.to_string(), git }
    }

    pub fn root_path(&self) -> PathBuf {
        PathBuf::from(&self.root)
    }
}

/// The files git says may differ from what the store holds, or `None`
/// when git cannot answer with certainty and a walk is needed.
///
/// Certainty needs: git available and the tree in a repository; a state
/// from last time with a git record; the current state readable; the two
/// commits comparable; and no ignore file among the changes, since an
/// ignore rule can add or remove files git would not mention.
pub fn git_candidates(root: &Path, previous: &TreeState) -> Option<(GitState, Vec<String>)> {
    let prev = previous.git.as_ref()?;
    let repo = detect_git(root)?;
    let now = git_state(root, &repo)?;
    let between = git_changed_between(root, &repo, &prev.head, &now.head)?;
    let mut set: HashSet<String> = prev.dirty.iter().cloned().collect();
    set.extend(now.dirty.iter().cloned());
    set.extend(between);
    if set.iter().any(|p| is_ignore_file(p)) {
        return None;
    }
    let mut v: Vec<String> = set.into_iter().collect();
    v.sort();
    Some((now, v))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write(dir: &Path, rel: &str, body: &str) {
        let p = dir.join(rel);
        if let Some(parent) = p.parent() {
            std::fs::create_dir_all(parent).expect("mkdir");
        }
        std::fs::write(p, body).expect("write");
    }

    fn rels(root: &Path, s: &Scan) -> Vec<String> {
        s.files.iter().map(|p| p.strip_prefix(root).unwrap().to_string_lossy().replace('\\', "/")).collect()
    }

    #[test]
    fn codegraphignore_and_gitignore_are_honoured_without_git() {
        let d = tempfile::tempdir().unwrap();
        write(d.path(), "a.py", "x = 1\n");
        write(d.path(), "gen/b.py", "y = 2\n");
        write(d.path(), "gen/keep.py", "z = 3\n");
        write(d.path(), "fixtures/c.py", "w = 4\n");
        write(d.path(), "sub/d.py", "v = 5\n");
        write(d.path(), "sub/skip_me.py", "u = 6\n");
        write(d.path(), ".codegraphignore", "gen/\n!gen/keep.py\n");
        write(d.path(), ".gitignore", "fixtures/\n");
        write(d.path(), "sub/.codegraphignore", "skip_*.py\n");
        let s = scan(d.path());
        // `!gen/keep.py` cannot re-include a file under an excluded
        // directory — gitignore semantics, and git agrees.
        assert_eq!(rels(d.path(), &s), ["a.py", "sub/d.py"]);
        assert!(is_indexable(d.path(), "a.py"));
        assert!(is_indexable(d.path(), "sub/d.py"));
        assert!(!is_indexable(d.path(), "gen/b.py"));
        assert!(!is_indexable(d.path(), "fixtures/c.py"));
        assert!(!is_indexable(d.path(), "sub/skip_me.py"));
        assert!(!is_indexable(d.path(), "missing.py"));
    }

    #[test]
    fn is_ignored_answers_for_paths_that_do_not_exist() {
        let d = tempfile::tempdir().unwrap();
        write(d.path(), ".codegraphignore", "gen/\n");
        write(d.path(), "sub/.gitignore", "*.skip.py\n");
        assert!(is_ignored(d.path(), "gen/anything.py"));
        assert!(is_ignored(d.path(), "sub/a.skip.py"));
        assert!(!is_ignored(d.path(), "sub/a.py"));
        assert!(!is_ignored(d.path(), "a.py"));
        assert!(is_ignored(d.path(), "node_modules/x.js"));
    }

    #[test]
    fn built_in_skip_list_still_applies() {
        let d = tempfile::tempdir().unwrap();
        write(d.path(), "a.py", "x = 1\n");
        write(d.path(), "node_modules/m/index.js", "module.exports = 1;\n");
        write(d.path(), ".codegraph/junk.py", "no\n");
        let s = scan(d.path());
        assert_eq!(rels(d.path(), &s), ["a.py"]);
        assert_eq!(s.skipped_dirs, 2);
        assert!(!is_indexable(d.path(), "node_modules/m/index.js"));
    }

    #[test]
    fn tree_state_round_trips() {
        let d = tempfile::tempdir().unwrap();
        let st = TreeState {
            root: "C:/src/x".into(),
            repo: "".into(),
            git: Some(GitState { head: "abc".into(), dirty: vec!["a.py".into()], toplevel: "C:/src".into() }),
        };
        st.save(d.path()).unwrap();
        assert_eq!(TreeState::load(d.path()), Some(st));
        assert!(TreeState::load(&d.path().join("nope")).is_none());
    }

    #[test]
    fn ignore_files_are_recognised() {
        assert!(is_ignore_file(".gitignore"));
        assert!(is_ignore_file("sub/.codegraphignore"));
        assert!(is_ignore_file(".git/info/exclude"));
        assert!(!is_ignore_file("sub/main.py"));
    }
}
