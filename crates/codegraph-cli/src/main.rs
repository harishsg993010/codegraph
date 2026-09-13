//! `codegraph` — index a source tree and ask questions about it.
//!
//! Every read command opens the **mapped** index, so a cold invocation costs a
//! couple of syscalls rather than a rebuild. That is the property that makes a
//! CLI usable at all: a tool that spends a second reconstructing derived data
//! before answering is a tool people stop reaching for.

use std::path::{Path, PathBuf};
use std::time::Instant;

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand, ValueEnum};
use codegraph_core::{LocalId, Relation, RelationMask};
use codegraph_index::{IndexQuery, Layered, MappedIndex, Opened, open_or_build};
use codegraph_query::{Direction, Engine, SymbolInfo};
use codegraph_security::{Security, spec::presets};
use codegraph_store::{CompactPolicy, Store};

/// The index a read command runs on: a mapped base, plus an overlay once
/// the store has moved past it.
type Index = Layered<MappedIndex>;

#[derive(Parser)]
#[command(name = "codegraph", version, about = "A code-index database")]
#[command(long_about = "A code-index database.\n\nEvery command takes a store directory or a source tree. A source tree with no store is indexed on first use (into <tree>/.codegraph); a store that knows its tree is brought up to date before every answer, through git when git is there. Nothing has to be run by hand to keep a graph current.")]
struct Cli {
    /// Answer from the store as it is; do not bring it up to date first.
    #[arg(long, global = true, env = "CODEGRAPH_NO_SYNC")]
    no_sync: bool,
    #[command(subcommand)]
    command: Command,
}

/// Set once from the flag; read by every open.
static NO_SYNC: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

#[derive(Subcommand)]
enum Command {
    /// Index a source tree into a store.
    ///
    /// On an existing store this is incremental: only files whose content
    /// changed (and the files sharing an edge with them) are re-indexed, into
    /// a delta segment beside the base. The base is rebuilt once the deltas
    /// grow to a share of it.
    Index {
        /// Source directory to index. The store is `<source>/.codegraph`.
        source: PathBuf,
        /// Repository tag, for multi-repo stores.
        #[arg(long, default_value = "")]
        repo: String,
        /// Re-index every file, even on an existing store.
        #[arg(long)]
        full: bool,
    },
    /// Keep a store current: index the tree, then watch it and re-index
    /// what changes after each quiet period. Honours `.gitignore` and
    /// `.codegraphignore`; with git installed, change detection asks git.
    /// Runs until interrupted.
    Watch {
        /// Source directory. The store is `<source>/.codegraph`.
        source: PathBuf,
        /// Quiet period after the last file-system event before an update, in milliseconds.
        #[arg(long, default_value_t = 400)]
        debounce_ms: u64,
    },
    /// What the uncommitted changes in a source tree do to the graph: every
    /// symbol added, removed, re-signed or redefined since the store was
    /// last indexed, who breaks, and what is affected — traced through
    /// callers, references, imports, subtypes and value flow.
    ///
    /// The store is not modified; the update runs on a scratch copy.
    Diff {
        /// Source directory. The store is `<source>/.codegraph`.
        source: PathBuf,
        /// Repository tag, as given to `index`.
        #[arg(long, default_value = "")]
        repo: String,
        /// How many hops of impact to trace.
        #[arg(long, default_value_t = 3)]
        depth: u32,
        /// A node with more dependents than this is reported and not
        /// expanded (default 100).
        #[arg(long, default_value_t = 100)]
        max_fanout: usize,
        /// Most symbols traced per change (default 500).
        #[arg(long, default_value_t = 500)]
        max_impact: usize,
        /// Most impact lines shown per change.
        #[arg(short = 'n', long, default_value_t = 40)]
        limit: usize,
        /// Exit with status 2 when any change breaks a dependent.
        #[arg(long)]
        fail_on_break: bool,
    },
    /// Merge every segment into one. Not normally needed — `index` compacts
    /// on its own schedule — but it makes a store with deltas single-segment
    /// again, which is the fastest shape to query.
    Compact { store: PathBuf },
    /// Deep search: find code by what it is connected to, not only by what
    /// it is called. Free terms match names, paths, locals, parameters,
    /// callees, referenced variables and branch conditions, by subword;
    /// matches spread along calls, references and value flow, so the
    /// function that connects two terms scores for both. Filters narrow by
    /// structure: `kind:function`, `in:routers/`, `calls:Popen`,
    /// `called-by:main`, `references:MaxSize`, `reaches:Exec`,
    /// `flows-to:Exec`, `flows-from:FormValue`. Every hit says why.
    Deep {
        store: PathBuf,
        /// Terms and `key:value` filters; quote a phrase. `hops:N`,
        /// `seeds:N` and `reach-limit:N` in the query tune the search too.
        query: Vec<String>,
        #[arg(short = 'n', long, default_value_t = 20)]
        limit: usize,
        /// How far a match spreads along the graph (default 2).
        #[arg(long)]
        hops: Option<u32>,
        /// How many of a term's strongest matches spread (default 400).
        #[arg(long)]
        seeds: Option<usize>,
        /// Most nodes a reachability filter expands (default 500000).
        #[arg(long)]
        reach_limit: Option<usize>,
    },
    /// Search symbols by name or path.
    Search {
        store: PathBuf,
        query: String,
        #[arg(short = 'n', long, default_value_t = 20)]
        limit: usize,
    },
    /// Show a symbol and what it connects to.
    Explain {
        store: PathBuf,
        symbol: String,
        #[arg(short, long, default_value_t = 15)]
        limit: usize,
    },
    /// Shortest path between two symbols.
    Path {
        store: PathBuf,
        from: String,
        to: String,
        #[arg(long, default_value_t = 12)]
        max_hops: u32,
    },
    /// What breaks if a symbol changes.
    Affected {
        store: PathBuf,
        symbol: String,
        #[arg(short, long, default_value_t = 2)]
        depth: u32,
        #[arg(short = 'n', long, default_value_t = 30)]
        limit: usize,
    },
    /// Run the security analyses.
    Audit {
        store: PathBuf,
        /// Which analysis to run.
        #[arg(long, value_enum, default_value_t = AuditKind::All)]
        kind: AuditKind,
        /// What a taint question is asked over: call paths, or value flow.
        #[arg(long, value_enum, default_value_t = AuditMode::Callgraph)]
        mode: AuditMode,
        #[arg(short = 'n', long, default_value_t = 20)]
        limit: usize,
        /// Drop sources and sinks in files whose path contains this. Repeatable.
        ///
        /// Sinks are matched by name, and names collide across ecosystems: on a
        /// Go corpus `Exec` matches the database layer as readily as `os/exec`.
        #[arg(long = "exclude", value_name = "PATH")]
        excludes: Vec<String>,
        /// A rule file (`.yaml`) or a directory of them, in the Semgrep-like
        /// shape (`pattern-sources`, `pattern-sinks`, `pattern-sanitizers`,
        /// `pattern-not`, `paths`, `languages`, `severity`, `metadata`).
        /// Repeatable. `<tree>/.codegraph-rules.yaml` and
        /// `<tree>/.codegraph-rules/` are read without asking. When any rule
        /// is loaded the starter specs are not run unless `--presets`.
        #[arg(long = "rules", value_name = "FILE-OR-DIR")]
        rules: Vec<PathBuf>,
        /// Run the built-in starter specs as well as the rules.
        #[arg(long)]
        presets: bool,
        /// Output form.
        #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
        format: OutputFormat,
        /// Exit 1 when any finding has this severity or worse (ERROR,
        /// WARNING, INFO), for CI.
        #[arg(long, value_name = "SEVERITY")]
        fail_on: Option<String>,
        /// Longest path reported, in edges, for every rule and starter spec
        /// (default 12, or the rule's own `max-hops`).
        #[arg(long)]
        max_hops: Option<u32>,
        /// Call sites a value-flow path may be inside at once before the
        /// oldest is forgotten (default 6, or the rule's own
        /// `context-depth`). Higher is more precise through deep call
        /// chains and slower.
        #[arg(long)]
        context_depth: Option<usize>,
    },
    /// Which of our code reaches a package.
    Deps {
        store: PathBuf,
        /// Report reach for this package instead of listing all.
        package: Option<String>,
        #[arg(short = 'n', long, default_value_t = 20)]
        limit: usize,
    },
    /// A callable's control-flow graph: blocks, branches, and the variables
    /// each block reads and writes.
    Cfg { store: PathBuf, symbol: String },
    /// Store statistics.
    Stats { store: PathBuf },
    /// Check every segment and the index against their checksums.
    Verify { store: PathBuf },
}

#[derive(Copy, Clone, PartialEq, Eq, ValueEnum)]
enum AuditKind {
    All,
    Taint,
    Entrypoints,
}

#[derive(Copy, Clone, PartialEq, Eq, ValueEnum)]
enum OutputFormat {
    Text,
    Json,
}

#[derive(Copy, Clone, PartialEq, Eq, ValueEnum)]
enum AuditMode {
    /// A finding is a call path from a source function to a sink function.
    Callgraph,
    /// A finding is a value from a source reaching a sink's argument:
    /// flow-, field- and predicate-sensitive within a function, call-site
    /// matched across calls, may-alias by copy and address.
    Dataflow,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    NO_SYNC.store(cli.no_sync, std::sync::atomic::Ordering::Relaxed);
    match cli.command {
        Command::Index { source, repo, full } => cmd_index(&source, &repo, full),
        Command::Watch { source, debounce_ms } => cmd_watch(&source, debounce_ms),
        Command::Compact { store } => cmd_compact(&store),
        Command::Search { store, query, limit } => cmd_search(&store, &query, limit),
        Command::Deep { store, query, limit, hops, seeds, reach_limit } => {
            // A shell-quoted phrase arrives as one argument; keep it one term.
            let joined: Vec<String> = query.iter().map(|a| if a.contains(char::is_whitespace) { format!("\"{a}\"") } else { a.clone() }).collect();
            cmd_deep(&store, &joined.join(" "), limit, hops, seeds, reach_limit)
        }
        Command::Explain { store, symbol, limit } => cmd_explain(&store, &symbol, limit),
        Command::Path { store, from, to, max_hops } => cmd_path(&store, &from, &to, max_hops),
        Command::Affected { store, symbol, depth, limit } => {
            cmd_affected(&store, &symbol, depth, limit)
        }
        Command::Audit { store, kind, mode, limit, excludes, rules, presets, format, fail_on, max_hops, context_depth } => {
            cmd_audit(&store, kind, mode, limit, &excludes, &rules, presets, format, fail_on.as_deref(), max_hops, context_depth)
        }
        Command::Cfg { store, symbol } => cmd_cfg(&store, &symbol),
        Command::Diff { source, repo, depth, max_fanout, max_impact, limit, fail_on_break } => {
            cmd_diff(&source, &repo, depth, max_fanout, max_impact, limit, fail_on_break)
        }
        Command::Deps { store, package, limit } => cmd_deps(&store, package.as_deref(), limit),
        Command::Stats { store } => cmd_stats(&store),
        Command::Verify { store } => cmd_verify(&store),
    }
}

/// Open what a command was given — a store, or a source tree — current.
///
/// A source tree with no store is indexed first (once; the store lives in
/// `<tree>/.codegraph`). A store that records its tree is synced before it
/// is read: through git when git is there, by a walk otherwise, and only
/// what changed is re-indexed. Both are reported on stderr, so the answer
/// on stdout stays the answer. `--no-sync` reads the store as it is.
/// Rebuilding a missing index is announced too, because it is slow and
/// the user should know why.
fn open(path: &Path) -> Result<Engine<Index>> {
    let store_dir = if NO_SYNC.load(std::sync::atomic::Ordering::Relaxed) {
        codegraph_resolve::locate(path)?.store_dir
    } else {
        let t = Instant::now();
        let ensured = codegraph_resolve::ensure_current(path, "", &CompactPolicy::default())
            .with_context(|| format!("bringing {} up to date", path.display()))?;
        match (&ensured.report, ensured.skipped) {
            (Some(r), _) if !r.incremental => eprintln!(
                "{} {} in {:.1}s: {} files, {} symbols, {} edges (store: {})",
                if ensured.located.fresh { "indexed" } else { "updated: rebuilt" },
                ensured.located.source.as_deref().unwrap_or(path).display(),
                t.elapsed().as_secs_f64(),
                r.reextracted,
                r.symbols,
                r.edges,
                ensured.located.store_dir.display()
            ),
            (Some(r), _) if r.changed > 0 || r.deleted > 0 => eprintln!(
                "updated in {:.1}s: {} changed, {} deleted, {} re-extracted ({})",
                t.elapsed().as_secs_f64(),
                r.changed,
                r.deleted,
                r.reextracted,
                r.detection
            ),
            (Some(_), _) => {}
            (None, Some(why)) if why != "the store does not record its source tree" => eprintln!("not updated: {why}"),
            (None, _) => {}
        }
        ensured.located.store_dir
    };
    let store = Store::open(&store_dir)
        .with_context(|| format!("opening store at {}", store_dir.display()))?;
    let (index, how) = open_or_build(&store, &store_dir)?;
    match how {
        Opened::Base | Opened::Overlaid => {}
        Opened::OverlayBuilt => eprintln!("index overlay was missing; built it"),
        Opened::Rebuilt => eprintln!("index unusable; rebuilt"),
    }
    Ok(Engine::from_parts(store, index))
}

/// Bring the index up to the store's generation after a write, and say what
/// that took.
fn refresh_index(store: &Store, store_dir: &Path) -> Result<&'static str> {
    Ok(match open_or_build(store, store_dir)?.1 {
        Opened::Base => "index current",
        Opened::Overlaid => "index overlay current",
        Opened::OverlayBuilt => "index overlay built",
        Opened::Rebuilt => "index rebuilt",
    })
}

/// Resolve a user-supplied symbol name to exactly one symbol.
///
/// Ambiguity is reported rather than guessed at: picking one of several
/// same-named symbols silently would make the answer depend on internal
/// ordering, which is not something a user can reason about.
///
/// Accepts `path:Name` to disambiguate, where `path` is any suffix of the
/// file's path. That form is what the ambiguity error tells the user to type,
/// so it has to be a form the tool takes.
/// The symbols named by `bare`, which may be `owner.name` — a method of a
/// type, a parameter or local of a callable, a block (`f.b3`).
fn by_owned_name(e: &Engine<Index>, bare: &str) -> Result<Vec<LocalId>> {
    // Corpus symbols first; a library stub answers to its bare name only
    // when nothing in the corpus has it, and always to its qualified name.
    if !bare.contains('.') {
        let hits = e.by_name(bare);
        if !hits.is_empty() {
            let same: Vec<LocalId> = hits.iter().copied().filter(|id| e.info(*id).ok().flatten().is_some_and(|i| i.name == bare)).collect();
            return Ok(if same.is_empty() { hits } else { same });
        }
    }
    Ok(e.by_qualified_name(bare))
}

fn resolve_one(e: &Engine<Index>, spec: &str) -> Result<LocalId> {
    // Split on the *last* colon: a Windows path can carry a drive letter, and
    // a symbol name cannot contain a colon.
    if let Some((path, bare)) = spec.rsplit_once(':')
        && !path.is_empty()
        && !bare.is_empty()
    {
        let mut narrowed = Vec::new();
        for id in by_owned_name(e, bare)? {
            if let Some(i) = e.info(id)?
                && (i.path == path || i.path.ends_with(&format!("/{path}")))
            {
                narrowed.push(id);
            }
        }
        match narrowed.len() {
            1 => return Ok(narrowed[0]),
            0 => bail!("no symbol named {bare:?} in a file matching {path:?}"),
            n => {
                eprintln!("{spec:?} still matches {n} symbols:");
                for id in narrowed.iter().take(10) {
                    if let Some(i) = e.info(*id)? {
                        eprintln!("  {} ({}:{})", i.name, i.path, i.line);
                    }
                }
                bail!("{spec:?} is ambiguous")
            }
        }
    }
    let name = spec;
    let hits = by_owned_name(e, name)?;
    match hits.len() {
        1 => Ok(hits[0]),
        0 => {
            // Fall back to a substring search so a near-miss is helpful.
            let near = e.search(name)?;
            if near.is_empty() {
                bail!("no symbol named {name:?}");
            }
            eprintln!("no exact match for {name:?}; did you mean:");
            for id in near.iter().take(5) {
                if let Some(i) = e.info(*id)? {
                    eprintln!("  {} ({}:{})", i.name, i.path, i.line);
                }
            }
            bail!("no exact match for {name:?}");
        }
        n => {
            eprintln!("{name:?} is ambiguous — {n} symbols share it:");
            for id in hits.iter().take(10) {
                if let Some(i) = e.info(*id)? {
                    eprintln!("  {} ({}:{})", i.name, i.path, i.line);
                }
            }
            eprintln!("qualify it as <path>:{name}");
            bail!("{name:?} is ambiguous")
        }
    }
}

fn show(i: &SymbolInfo) -> String {
    if i.external {
        format!("{} (external)", i.name)
    } else {
        format!("{} ({}:{})", i.name, i.path, i.line)
    }
}

/// As [`show`], but a parameter is named with the callable it belongs to:
/// `ctx` on its own says nothing, `MergePullRequest(ctx)` does.
fn show_in_context(e: &Engine<Index>, i: &SymbolInfo) -> String {
    if i.kind != codegraph_core::SymbolKind::Parameter {
        return show(i);
    }
    let own = RelationMask::of(&[Relation::Contains]);
    let owner = e
        .neighbors(i.id, Direction::In, own)
        .ok()
        .and_then(|hits| hits.into_iter().find_map(|h| e.info(h.id).ok().flatten()));
    match owner {
        Some(o) if o.external => format!("{}({}) (external)", o.name, i.name),
        Some(o) => format!("{}({}) ({}:{})", o.name, i.name, o.path, o.line),
        None => show(i),
    }
}

/// The kind, plus `external` for a library stub the corpus does not define.
fn tag(e: &Engine<Index>, i: &SymbolInfo) -> String {
    if e.is_stub(i.id) { format!("[{} external]", i.kind) } else { format!("[{}]", i.kind) }
}

// --- commands ---

/// Where a tree's store lives. Always `<tree>/.codegraph`: one place, so
/// every command, the watcher and the server find the same store, and a
/// `.gitignore` or `.git/info/exclude` rule covers it everywhere.
fn store_of(source: &Path) -> PathBuf {
    source.join(".codegraph")
}

fn cmd_index(source: &Path, repo: &str, full: bool) -> Result<()> {
    let store_dir = store_of(source);
    let t = Instant::now();
    let existing = store_dir.join("CURRENT").exists();
    // One writer at a time: a watcher or a query syncing this store waits
    // for us, and we for it.
    let _lock = codegraph_store::WriteLock::acquire(&store_dir, std::time::Duration::from_secs(600))
        .with_context(|| format!("locking {}", store_dir.display()))?
        .ok_or_else(|| anyhow::anyhow!("another process has held the store's lock for ten minutes"))?;
    let mut s = Store::open_or_create(&store_dir)?;

    // An existing store is brought up to date; a new one, or `--full`, is
    // indexed from scratch.
    let (extracted, build, symbols, edges, note) = if existing && !full {
        let r = codegraph_resolve::update_tree(source, &mut s, repo, &CompactPolicy::default())?;
        let note = if !r.incremental {
            "rebuilt in full (no usable base, or the deltas had grown past the policy)".to_string()
        } else if r.changed == 0 && r.deleted == 0 {
            format!("up to date ({} files unchanged, by {})", r.scanned, r.detection)
        } else {
            let mut n = format!(
                "incremental ({}): {} changed, {} deleted, {} re-extracted of {} scanned",
                r.detection, r.changed, r.deleted, r.reextracted, r.scanned
            );
            if let Some(c) = &r.compaction {
                n.push_str(&format!("; merged {} segments into {}", c.segments_before, c.segments_after));
            }
            n
        };
        (r.reextracted, r.build, r.symbols, r.edges, note)
    } else {
        let r = codegraph_resolve::index_tree(source, &mut s, repo)?;
        (r.extracted, r.build, r.symbols, r.edges, String::new())
    };

    // The index follows the generation: nothing to do after a no-op, an
    // overlay after a delta, a rebuild after a full index.
    let index_note = refresh_index(&s, &store_dir)?;
    let secs = t.elapsed().as_secs_f64();

    println!(
        "indexed {extracted} files in {secs:.1}s ({:.0} files/s)",
        extracted as f64 / secs.max(1e-9)
    );
    if !note.is_empty() {
        println!("  {note}; {index_note}");
    }
    println!("  {symbols} symbols, {edges} edges, {} segment(s)", s.manifest().segments.len());
    let b = &build;
    let bound = b.calls_local + b.calls_cross_file + b.calls_receiver;
    let seen = bound + b.calls_ambiguous + b.calls_unresolved;
    println!(
        "  calls: {bound} bound ({:.1}%), {} ambiguous, {} unresolved",
        if seen > 0 { bound as f64 / seen as f64 * 100.0 } else { 0.0 },
        b.calls_ambiguous,
        b.calls_unresolved
    );
    println!(
        "  {} external packages, {} external callee stubs, {} proxies, {} files failed to parse",
        b.packages, b.external_stubs, b.proxies, b.parse_errors
    );
    println!(
        "  {} variables, {} parameters, {} blocks, {} locals; {} references, {} flows ({} unresolved, {} summarised), {} local flows",
        b.variables, b.parameters, b.blocks, b.locals, b.references, b.flows, b.flows_unresolved, b.flows_summarised, b.local_flows
    );
    println!(
        "  supertypes: {} resolved, {} external; {} structural implements ({} interfaces not comparable)",
        b.supertypes_resolved, b.supertypes_external, b.implements, b.interfaces_skipped
    );
    println!("{}", git_note(source, &store_dir, !existing || full));
    println!("\nstore: {}", store_dir.display());
    Ok(())
}

/// What git has to do with this store: the commit the tree is at, and —
/// on a fresh index — whether the store was just kept out of the
/// repository. Read off the store's own record, so a no-op update spawns
/// no extra git process. Nothing when git is not installed or the tree
/// is not a repository: the walk and the store's file table do the same
/// job, slower.
fn git_note(source: &Path, store_dir: &Path, bootstrap: bool) -> String {
    let Some(g) = codegraph_resolve::TreeState::load(store_dir).and_then(|t| t.git) else {
        return "  git: not used (no git binary, not a repository, or no commit yet); changes are found by walking the tree".into();
    };
    let mut note = format!(
        "  git: {} at {} ({} dirty); changes are found through git",
        g.toplevel,
        &g.head[..g.head.len().min(10)],
        g.dirty.len()
    );
    if bootstrap && let Some(repo) = codegraph_resolve::detect_git(source) {
        // Done by the index itself; said here so the user knows.
        let excluded = std::path::absolute(store_dir).is_ok_and(|s| s.strip_prefix(std::path::absolute(&repo.toplevel).unwrap_or_default()).is_ok())
            && std::fs::read_to_string(repo.toplevel.join(".git/info/exclude")).is_ok_and(|t| t.contains("# codegraph store"));
        if excluded {
            note.push_str("; store is in .git/info/exclude");
        }
    }
    note
}

fn cmd_watch(source: &Path, debounce_ms: u64) -> Result<()> {
    use codegraph_resolve::{TreeWatcher, sync};
    use std::time::Duration;
    let store_dir = store_of(source);
    let policy = CompactPolicy::default();
    let stamp = || {
        let t = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs());
        format!("{:02}:{:02}:{:02}", t / 3600 % 24, t / 60 % 60, t % 60)
    };
    // The watch is armed before the first sync so nothing written during
    // it is missed; an event for a file the sync already read costs one
    // hash next round.
    let watcher = TreeWatcher::new(source, &store_dir, Duration::from_millis(debounce_ms))
        .with_context(|| format!("watching {}", source.display()))?;
    let t = Instant::now();
    let (r, _) = loop {
        match sync(source, &store_dir, "", &policy).with_context(|| format!("indexing {}", source.display()))? {
            Some(x) => break x,
            None => {
                println!("waiting for another process to release {}", store_dir.display());
                std::thread::sleep(Duration::from_secs(1));
            }
        }
    };
    println!(
        "[{}] {} — {} symbols, {} edges ({:.1}s)",
        stamp(),
        if r.incremental { format!("up to date: {} changed, {} deleted, {} re-extracted ({})", r.changed, r.deleted, r.reextracted, r.detection) } else { format!("indexed {} files", r.reextracted) },
        r.symbols,
        r.edges,
        t.elapsed().as_secs_f64()
    );
    println!("{}", git_note(source, &store_dir, !r.incremental));
    println!("watching {} (store {}); Ctrl-C to stop", source.display(), store_dir.display());
    while let Some(batch) = watcher.next() {
        let t = Instant::now();
        match sync(source, &store_dir, "", &policy) {
            Ok(None) => println!("[{}] another process is updating the store; skipped", stamp()),
            Ok(Some((r, _))) if r.incremental && r.changed == 0 && r.deleted == 0 => {
                let shown: Vec<String> = batch.iter().take(3).map(|p| p.strip_prefix(source).unwrap_or(p).to_string_lossy().replace('\\', "/")).collect();
                println!(
                    "[{}] {} event path(s) ({}{}), nothing changed ({}, {:.2}s)",
                    stamp(),
                    batch.len(),
                    shown.join(", "),
                    if batch.len() > 3 { ", ..." } else { "" },
                    r.detection,
                    t.elapsed().as_secs_f64()
                );
            }
            Ok(Some((r, _))) => {
                let mut what: Vec<&str> = r.changed_paths.iter().chain(&r.deleted_paths).map(String::as_str).collect();
                what.truncate(5);
                println!(
                    "[{}] {} changed, {} deleted, {} re-extracted ({}) in {:.1}s — {} symbols, {} edges{}{}",
                    stamp(),
                    r.changed,
                    r.deleted,
                    r.reextracted,
                    if r.incremental { r.detection } else { "full rebuild" },
                    t.elapsed().as_secs_f64(),
                    r.symbols,
                    r.edges,
                    if what.is_empty() { String::new() } else { format!(": {}", what.join(", ")) },
                    if r.changed_paths.len() + r.deleted_paths.len() > 5 { ", ..." } else { "" }
                );
            }
            Err(e) => println!("[{}] update failed: {e:#}", stamp()),
        }
    }
    Ok(())
}

fn cmd_compact(store_dir: &Path) -> Result<()> {
    let t = Instant::now();
    let store_dir = &codegraph_resolve::locate(store_dir)?.store_dir;
    let _lock = codegraph_store::WriteLock::acquire(store_dir, std::time::Duration::from_secs(600))?
        .ok_or_else(|| anyhow::anyhow!("another process has held the store's lock for ten minutes"))?;
    let mut s = Store::open(store_dir)
        .with_context(|| format!("opening store at {}", store_dir.display()))?;
    match codegraph_store::compact(&mut s)? {
        Some(c) => {
            refresh_index(&s, store_dir)?;
            println!(
                "compacted {} segments into 1 in {:.1}s: {} symbols, {} edges, {} dead rows dropped",
                c.segments_before,
                t.elapsed().as_secs_f64(),
                c.symbols,
                c.edges,
                c.dropped_dead
            );
        }
        None => println!("already compact"),
    }
    Ok(())
}

fn cmd_search(store: &Path, query: &str, limit: usize) -> Result<()> {
    let e = open(store)?;
    let hits = e.search(query)?;
    println!("{} matches", hits.len());
    for id in hits.iter().take(limit) {
        if let Some(i) = e.info(*id)? {
            println!("  {:<8} {}", format!("[{}]", i.kind), show(&i));
        }
    }
    if hits.len() > limit {
        println!("  ... and {} more", hits.len() - limit);
    }
    Ok(())
}

fn cmd_deep(store: &Path, query: &str, limit: usize, hops: Option<u32>, seeds: Option<usize>, reach_limit: Option<usize>) -> Result<()> {
    use codegraph_query::DeepQuery;
    let e = open(store)?;
    let mut q = DeepQuery::parse(query);
    if let Some(h) = hops {
        q.hops = h;
    }
    if let Some(n) = seeds {
        q.seeds = n;
    }
    if let Some(n) = reach_limit {
        q.reach_limit = n;
    }
    if q.terms.is_empty() && q.filters.is_empty() {
        bail!("give some terms, filters, or both — e.g. `upload limit kind:function calls:Open`");
    }
    let t = Instant::now();
    let hits = e.deep_search(&q, limit)?;
    let filters: Vec<String> = q.filters.iter().map(|f| format!("{f:?}")).collect();
    println!(
        "{} hit(s) for terms {:?}{} ({:.0} ms)",
        hits.len(),
        q.terms,
        if filters.is_empty() { String::new() } else { format!(" with filters {}", filters.join(", ")) },
        t.elapsed().as_secs_f64() * 1e3
    );
    for h in &hits {
        println!("\n  {:.2}  {} {}", h.score, show_in_context(&e, &h.info), tag(&e, &h.info));
        for r in &h.reasons {
            println!("          {r}");
        }
    }
    Ok(())
}

fn cmd_explain(store: &Path, symbol: &str, limit: usize) -> Result<()> {
    let e = open(store)?;
    let id = resolve_one(&e, symbol)?;
    let info = e.info(id)?.context("symbol vanished")?;
    println!("{} {}", show(&info), tag(&e, &info));
    println!("  degree {}", info.degree);

    // A callable's signature, in order.
    let params = e.parameters(id)?;
    if !params.is_empty() {
        let names: Vec<String> = params
            .iter()
            .filter_map(|(_, p)| e.info(*p).ok().flatten().map(|i| i.name))
            .collect();
        println!("  parameters ({})", names.join(", "));
    }
    let blocks = e.cfg(id)?.len();
    if blocks > 0 {
        println!("  cfg: {blocks} blocks (see `cfg`)");
    }
    // A callable's locals, by name; `explain <local>` says more about one.
    let own = RelationMask::of(&[Relation::Contains]);
    let mut locals: Vec<String> = Vec::new();
    for h in e.neighbors(id, Direction::Out, own)? {
        if let Some(i) = e.info(h.id)?
            && i.kind == codegraph_core::SymbolKind::Local
        {
            locals.push(i.name);
        }
    }
    if !locals.is_empty() {
        locals.sort();
        println!("  locals ({})", locals.join(", "));
    }
    if info.kind == codegraph_core::SymbolKind::Local {
        // Whose it is, then what it holds and where it goes: the value view
        // is flow-insensitive (one row per name), which is why it is shown
        // here and not walked by `path` or `audit`.
        for h in e.neighbors(id, Direction::In, own)? {
            if let Some(o) = e.info(h.id)? {
                println!("  local of {} {}", show(&o), tag(&e, &o));
            }
        }
    }

    // Structure before behaviour. Asking about a type and being shown only its
    // call edges hides the thing you asked about: what it *is*.
    let structural = RelationMask::of(&[Relation::Method, Relation::Contains]);
    let calls = RelationMask::of(&[Relation::Calls, Relation::IndirectCall]);
    // Kept apart: "implements" and "extends" answer different questions, and a
    // combined list cannot say which edge is which.
    let implements = RelationMask::of(&[Relation::Implements]);
    let inherits = RelationMask::of(&[Relation::Inherits, Relation::Extends]);
    let references = RelationMask::of(&[Relation::References]);
    let flows = Relation::DATA_FLOW;
    let local_flow = Relation::LOCALS;
    let cfg_use = RelationMask::of(&[Relation::Defines, Relation::Uses]);
    let is_structure = |i: &SymbolInfo| {
        matches!(
            i.kind,
            codegraph_core::SymbolKind::Parameter | codegraph_core::SymbolKind::Block | codegraph_core::SymbolKind::Local
        )
    };
    for (label, dir, mask) in [
        ("members", Direction::Out, structural),
        ("member of", Direction::In, structural),
        ("implements", Direction::Out, implements),
        ("implemented by", Direction::In, implements),
        ("extends", Direction::Out, inherits),
        ("extended by", Direction::In, inherits),
        ("calls", Direction::Out, calls),
        ("called by", Direction::In, calls),
        ("references", Direction::Out, references),
        ("referenced by", Direction::In, references),
        ("flows to", Direction::Out, flows),
        ("flows from", Direction::In, flows),
        ("assigned from", Direction::In, local_flow),
        ("read into", Direction::Out, local_flow),
        ("defined / used in blocks", Direction::In, cfg_use),
    ] {
        // The local views only mean something for a local.
        if (mask == local_flow || mask == cfg_use) && info.kind != codegraph_core::SymbolKind::Local {
            continue;
        }
        // The local views are flow-sensitive through their edge context:
        // which definition a value came in by, and which definitions of
        // the local reach each read.
        if mask == local_flow {
            let view = e.store().view();
            let edges = match dir {
                Direction::In => view.in_edges(id, mask)?,
                Direction::Out => view.out_edges(id, mask)?,
            };
            let mut lines: Vec<(SymbolInfo, String)> = Vec::new();
            for edge in edges {
                if let Some(i) = e.info(edge.node)? {
                    let note = match (dir, edge.context) {
                        (Direction::In, Some(c)) => format!("  at line {c}"),
                        (Direction::Out, Some(c)) if c.contains(',') => format!("  (definitions at lines {c})"),
                        (Direction::Out, Some(c)) => format!("  (definition at line {c})"),
                        _ => String::new(),
                    };
                    lines.push((i, note));
                }
            }
            lines.sort_by(|a, b| (a.0.path.as_str(), a.0.line, a.1.as_str()).cmp(&(b.0.path.as_str(), b.0.line, b.1.as_str())));
            lines.dedup_by(|a, b| a.0.id == b.0.id && a.1 == b.1);
            if lines.is_empty() {
                continue;
            }
            println!("\n  {label} ({}):", lines.len());
            for (i, note) in lines.iter().take(limit) {
                println!("    {:<10} {}{note}", tag(&e, i), show(i));
            }
            if lines.len() > limit {
                println!("    ... and {} more", lines.len() - limit);
            }
            continue;
        }
        let mut infos: Vec<SymbolInfo> = Vec::new();
        for h in e.neighbors(id, dir, mask)? {
            if let Some(i) = e.info(h.id)? {
                // Parameters and blocks are shown on their own lines above,
                // not as members.
                if mask == structural && is_structure(&i) {
                    continue;
                }
                infos.push(i);
            }
        }
        // One line per symbol, however many edges reach it.
        infos.sort_by(|a, b| (a.path.as_str(), a.line, a.id.get()).cmp(&(b.path.as_str(), b.line, b.id.get())));
        infos.dedup_by_key(|i| i.id);
        if infos.is_empty() {
            continue;
        }
        println!("\n  {label} ({}):", infos.len());
        for i in infos.iter().take(limit) {
            println!("    {:<10} {}", tag(&e, i), show(i));
        }
        if infos.len() > limit {
            println!("    ... and {} more", infos.len() - limit);
        }
    }
    Ok(())
}

fn cmd_path(store: &Path, from: &str, to: &str, max_hops: u32) -> Result<()> {
    let e = open(store)?;
    let (a, b) = (resolve_one(&e, from)?, resolve_one(&e, to)?);
    match e.shortest_path(a, b, RelationMask::ALL, max_hops)? {
        Some(path) => {
            println!("{} hops:", path.len().saturating_sub(1));
            for (n, id) in path.iter().enumerate() {
                if let Some(i) = e.info(*id)? {
                    println!("  {n}. {}", show(&i));
                }
            }
        }
        // "No path" is a real answer, not a failure — and with a complete call
        // graph it is the more useful one.
        None => println!("no path within {max_hops} hops"),
    }
    Ok(())
}

fn cmd_affected(store: &Path, symbol: &str, depth: u32, limit: usize) -> Result<()> {
    let e = open(store)?;
    let id = resolve_one(&e, symbol)?;
    let hits = e.blast_radius(id, depth)?;
    println!("{} symbols affected within {depth} hops", hits.len());
    for h in hits.iter().take(limit) {
        if let Some(i) = e.info(h.id)? {
            println!("  depth {} via {:<14} {}", h.depth, h.via.as_str(), show(&i));
        }
    }
    if hits.len() > limit {
        println!("  ... and {} more", hits.len() - limit);
    }
    Ok(())
}

fn cmd_diff(source: &Path, repo: &str, depth: u32, max_fanout: usize, max_impact: usize, limit: usize, fail_on_break: bool) -> Result<()> {
    use codegraph_resolve::DiffOptions;
    // The diff is against the last commit when git knows the tree, so the
    // store's own state does not matter and is not synced here; without
    // git it is against the store, which is then left exactly as it is.
    // A tree with no store is indexed first: with git that is enough to
    // diff right away; without, the next diff has a baseline.
    let located = codegraph_resolve::locate(source)?;
    if located.fresh {
        let t = Instant::now();
        let ensured = codegraph_resolve::ensure_current(source, repo, &CompactPolicy::default())?;
        if let Some(r) = &ensured.report {
            eprintln!("indexed {} in {:.1}s: {} files, {} symbols, {} edges (store: {})", source.display(), t.elapsed().as_secs_f64(), r.reextracted, r.symbols, r.edges, located.store_dir.display());
        }
        if codegraph_resolve::detect_git(source).is_none() {
            eprintln!("no git here: nothing to compare against until the next edit");
            return Ok(());
        }
    }
    let store_dir = located.store_dir;
    let t = Instant::now();
    let opts = DiffOptions { repo: repo.to_string(), depth, fanout: max_fanout, max_hits: max_impact };
    let r = codegraph_resolve::diff_tree(source, &store_dir, &opts)?;
    print!("{}", r.render(limit));
    println!("({:.1} s)", t.elapsed().as_secs_f64());
    if fail_on_break && r.breaking() > 0 {
        std::process::exit(2);
    }
    Ok(())
}

fn cmd_cfg(store: &Path, symbol: &str) -> Result<()> {
    let e = open(store)?;
    let id = resolve_one(&e, symbol)?;
    let info = e.info(id)?.context("symbol vanished")?;
    let blocks = e.cfg(id)?;
    if blocks.is_empty() {
        bail!("{} has no stored control-flow graph (not a callable, or indexed without one)", show(&info));
    }
    println!("{} {}: {} blocks", show(&info), tag(&e, &info), blocks.len());
    let names = |ids: &[LocalId]| -> String {
        ids.iter().filter_map(|i| e.info(*i).ok().flatten().map(|i| i.name)).collect::<Vec<_>>().join(", ")
    };
    for b in &blocks {
        let succ: Vec<String> = b
            .successors
            .iter()
            .map(|(n, l)| if l.is_empty() { format!("b{n}") } else { format!("b{n} [{l}]") })
            .collect();
        println!("  b{} (line {}) -> {}", b.index, b.line, if succ.is_empty() { "exit".to_string() } else { succ.join(", ") });
        if !b.defines.is_empty() {
            println!("      writes {}", names(&b.defines));
        }
        if !b.uses.is_empty() {
            println!("      reads  {}", names(&b.uses));
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn cmd_audit(
    store: &Path,
    kind: AuditKind,
    mode: AuditMode,
    limit: usize,
    excludes: &[String],
    rule_paths: &[PathBuf],
    presets_too: bool,
    format: OutputFormat,
    fail_on: Option<&str>,
    max_hops: Option<u32>,
    context_depth: Option<usize>,
) -> Result<()> {
    use codegraph_security::{RuleSpec, Severity, load_rules, render_json, render_text, run_rules, tree_rule_paths, worst};
    let fail_on = match fail_on {
        Some(s) => Some(Severity::parse(s).ok_or_else(|| anyhow::anyhow!("--fail-on {s:?}: use ERROR, WARNING or INFO"))?),
        None => None,
    };
    let e = open(store)?;
    let sec = Security::new(&e);
    let text = format == OutputFormat::Text;

    if text && matches!(kind, AuditKind::All | AuditKind::Entrypoints) {
        let eps = sec.entrypoints()?;
        let live = sec.reachable_from_entrypoints()?;
        println!(
            "entrypoints: {} | reachable from them: {} of {} ({:.1}%)",
            eps.len(),
            live.len(),
            e.symbol_count(),
            live.len() as f64 / e.symbol_count().max(1) as f64 * 100.0
        );
    }
    if !matches!(kind, AuditKind::All | AuditKind::Taint) {
        return Ok(());
    }

    // The rules: those named, plus the tree's own, plus the starter specs
    // when nothing else was given (or asked for).
    let mut paths: Vec<PathBuf> = rule_paths.to_vec();
    if let Some(root) = codegraph_resolve::TreeState::load(&codegraph_resolve::locate(store)?.store_dir).map(|t| t.root_path()) {
        paths.extend(tree_rule_paths(&root));
    }
    let mut rules: Vec<RuleSpec> = Vec::new();
    let mut loaded_files = 0usize;
    for p in &paths {
        let loaded = load_rules(p).map_err(|e| anyhow::anyhow!("{e}"))?;
        loaded_files += 1;
        for r in &loaded {
            rules.push(RuleSpec::from_rule(r).map_err(|m| anyhow::anyhow!("{}: rule {:?}: {m}", p.display(), r.id))?);
        }
    }
    let spec_mode = match mode {
        AuditMode::Callgraph => codegraph_security::Mode::CallGraph,
        AuditMode::Dataflow => codegraph_security::Mode::DataFlow,
    };
    let using_presets = rules.is_empty() || presets_too;
    if using_presets {
        rules.extend(presets::all().into_iter().map(|s| RuleSpec::from_preset(s, spec_mode)));
    }
    for r in &mut rules {
        for p in excludes {
            r.spec.excludes.push(codegraph_security::Matcher::in_path(p));
        }
        if let Some(h) = max_hops {
            r.spec.max_hops = h;
        }
        if let Some(d) = context_depth {
            r.spec.context_depth = d;
        }
    }

    if text {
        if loaded_files > 0 {
            println!("rules: {} from {} file(s){}", rules.iter().filter(|r| r.from_file).count(), loaded_files, if using_presets { " + starter specs" } else { "" });
        }
        if rules.iter().any(|r| r.spec.mode == codegraph_security::Mode::DataFlow) {
            println!(
                "taint: a finding is a value from a source reaching a sink's argument. Flow-, field- and \
                 predicate-sensitive within a function, call-site-matched across calls (a value leaves a \
                 callee where it entered), may-alias by copy and address; library calls by summary."
            );
        }
    }
    let results = run_rules(&sec, &rules, limit);
    match format {
        OutputFormat::Text => {
            print!("{}", render_text(&results, &|s| show_in_context(&e, s)));
            if using_presets {
                println!("\nnote: the starter specs are a starting point, not a policy. Zero findings means zero matches for *these* patterns; write your own in a rule file (--rules).");
            }
        }
        OutputFormat::Json => println!("{}", render_json(&results)),
    }
    if let (Some(threshold), Some(w)) = (fail_on, worst(&results))
        && w >= threshold
    {
        std::process::exit(1);
    }
    Ok(())
}

fn cmd_deps(store: &Path, package: Option<&str>, limit: usize) -> Result<()> {
    let e = open(store)?;
    let sec = Security::new(&e);
    match package {
        Some(name) => match sec.package_reach(name)? {
            Some(reach) => {
                println!(
                    "{}: {} importing files, {}",
                    reach.package,
                    reach.importers.len(),
                    if reach.reachable_from_entrypoint {
                        "reachable from an entrypoint"
                    } else {
                        "not reachable from any entrypoint"
                    }
                );
                for i in reach.importers.iter().take(limit) {
                    println!("  {}", i.path);
                }
            }
            None => println!("{name} is not a dependency of this corpus"),
        },
        None => {
            let pkgs = sec.packages()?;
            println!("{} external packages", pkgs.len());
            for (name, n) in pkgs.iter().take(limit) {
                println!("  {name:<32} {n:>6} importing files");
            }
        }
    }
    Ok(())
}

fn cmd_stats(store: &Path) -> Result<()> {
    let e = open(store)?;
    let (rels, confs) = e.edge_histogram()?;
    println!("symbols     {}", e.symbol_count());
    println!("edges       {}", rels.iter().map(|(_, n)| n).sum::<usize>());
    println!("segments    {}", e.store().manifest().segments.len());
    println!("components  {}", e.index().components());
    println!("hub cutoff  degree >= {}", e.index().hub_cutoff());

    println!("\nby relation:");
    for (r, n) in rels {
        println!("  {:<24} {n:>9}", r.as_str());
    }
    println!("\nby confidence:");
    for (c, n) in confs {
        println!("  {:<24} {n:>9}", c.as_str());
    }

    println!("\ntop symbols by degree:");
    for i in e.hubs(10)? {
        println!("  {:>7}  {}", i.degree, show(&i));
    }
    Ok(())
}

fn cmd_verify(store: &Path) -> Result<()> {
    let store = &codegraph_resolve::locate(store)?.store_dir;
    let s = Store::open(store)?;
    s.verify()?;
    println!("segments: ok ({} live)", s.manifest().segments.len());

    if let Some((path, overlay_path)) = codegraph_index::current_files(&s, store) {
        let index = MappedIndex::open_any(&path)?;
        index.verify_checksums()?;
        let generation = s.manifest().generation;
        match overlay_path {
            None if index.generation() == generation => println!("index:    ok ({} bytes mapped)", index.mapped_bytes()),
            None => println!("index:    stale (generation {} of {generation}); the next open rebuilds it", index.generation()),
            Some(op) => {
                let overlay = codegraph_index::Overlay::read(&op, generation, index.generation())?;
                println!(
                    "index:    ok ({} bytes mapped, overlay of {} rows, {} patched)",
                    index.mapped_bytes(),
                    overlay.delta_rows(),
                    overlay.patched_rows()
                );
            }
        }
    } else {
        println!("index:    absent");
    }
    Ok(())
}
