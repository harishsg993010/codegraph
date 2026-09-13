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
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Index a source tree into a store.
    ///
    /// On an existing store this is incremental: only files whose content
    /// changed (and the files sharing an edge with them) are re-indexed, into
    /// a delta segment beside the base. The base is rebuilt once the deltas
    /// grow to a share of it.
    Index {
        /// Source directory to index.
        source: PathBuf,
        /// Where to write the store. Defaults to `<source>/.codegraph`.
        #[arg(short, long)]
        store: Option<PathBuf>,
        /// Repository tag, for multi-repo stores.
        #[arg(long, default_value = "")]
        repo: String,
        /// Re-index every file, even on an existing store.
        #[arg(long)]
        full: bool,
    },
    /// What the uncommitted changes in a source tree do to the graph: every
    /// symbol added, removed, re-signed or redefined since the store was
    /// last indexed, who breaks, and what is affected — traced through
    /// callers, references, imports, subtypes and value flow.
    ///
    /// The store is not modified; the update runs on a scratch copy.
    Diff {
        /// Source directory, as given to `index`.
        source: PathBuf,
        /// The store. Defaults to `<source>/.codegraph`.
        #[arg(short, long)]
        store: Option<PathBuf>,
        /// Repository tag, as given to `index`.
        #[arg(long, default_value = "")]
        repo: String,
        /// How many hops of impact to trace.
        #[arg(long, default_value_t = 3)]
        depth: u32,
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
    match cli.command {
        Command::Index { source, store, repo, full } => cmd_index(&source, store, &repo, full),
        Command::Compact { store } => cmd_compact(&store),
        Command::Search { store, query, limit } => cmd_search(&store, &query, limit),
        Command::Explain { store, symbol, limit } => cmd_explain(&store, &symbol, limit),
        Command::Path { store, from, to, max_hops } => cmd_path(&store, &from, &to, max_hops),
        Command::Affected { store, symbol, depth, limit } => {
            cmd_affected(&store, &symbol, depth, limit)
        }
        Command::Audit { store, kind, mode, limit, excludes } => cmd_audit(&store, kind, mode, limit, &excludes),
        Command::Cfg { store, symbol } => cmd_cfg(&store, &symbol),
        Command::Diff { source, store, repo, depth, limit, fail_on_break } => {
            cmd_diff(&source, store, &repo, depth, limit, fail_on_break)
        }
        Command::Deps { store, package, limit } => cmd_deps(&store, package.as_deref(), limit),
        Command::Stats { store } => cmd_stats(&store),
        Command::Verify { store } => cmd_verify(&store),
    }
}

/// Open a store and its index for reading.
///
/// Rebuilds the index when it is missing or stale rather than failing: a stale
/// index is a recoverable state, and making the user run a separate command to
/// fix it is friction for no safety gain. Rebuilding is announced, because it
/// is slow and the user should know why.
fn open(store_dir: &Path) -> Result<Engine<Index>> {
    let store = Store::open(store_dir)
        .with_context(|| format!("opening store at {}", store_dir.display()))?;
    let (index, how) = open_or_build(&store, store_dir)?;
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
    // The name table folds case; when several symbols fold together and
    // one is spelled exactly as asked, that one is meant.
    let exact = |hits: Vec<LocalId>, name: &str| -> Vec<LocalId> {
        if hits.len() <= 1 {
            return hits;
        }
        let same: Vec<LocalId> = hits.iter().copied().filter(|id| e.info(*id).ok().flatten().is_some_and(|i| i.name == name)).collect();
        if same.is_empty() { hits } else { same }
    };
    let Some((owner, name)) = bare.rsplit_once('.') else { return Ok(exact(e.by_name(bare), bare)) };
    let own = RelationMask::of(&[Relation::Contains, Relation::Method]);
    let mut out = Vec::new();
    for id in e.by_name(name) {
        for h in e.neighbors(id, Direction::In, own)? {
            if e.info(h.id)?.is_some_and(|o| o.name == owner) {
                out.push(id);
                break;
            }
        }
    }
    Ok(exact(out, name))
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

fn cmd_index(source: &Path, store: Option<PathBuf>, repo: &str, full: bool) -> Result<()> {
    let store_dir = store.unwrap_or_else(|| source.join(".codegraph"));
    let t = Instant::now();
    let existing = store_dir.join("CURRENT").exists();
    let mut s = Store::open_or_create(&store_dir)?;

    // An existing store is brought up to date; a new one, or `--full`, is
    // indexed from scratch.
    let (extracted, build, symbols, edges, note) = if existing && !full {
        let r = codegraph_resolve::update_tree(source, &mut s, repo, &CompactPolicy::default())?;
        let note = if !r.incremental {
            "rebuilt in full (no usable base, or the deltas had grown past the policy)".to_string()
        } else if r.changed == 0 && r.deleted == 0 {
            format!("up to date ({} files unchanged)", r.scanned)
        } else {
            let mut n = format!(
                "incremental: {} changed, {} deleted, {} re-extracted of {} scanned",
                r.changed, r.deleted, r.reextracted, r.scanned
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
    println!("\nstore: {}", store_dir.display());
    Ok(())
}

fn cmd_compact(store_dir: &Path) -> Result<()> {
    let t = Instant::now();
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

fn cmd_diff(source: &Path, store: Option<PathBuf>, repo: &str, depth: u32, limit: usize, fail_on_break: bool) -> Result<()> {
    use codegraph_resolve::DiffOptions;
    let store_dir = store.unwrap_or_else(|| source.join(".codegraph"));
    let t = Instant::now();
    let opts = DiffOptions { repo: repo.to_string(), depth, ..DiffOptions::default() };
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

fn cmd_audit(store: &Path, kind: AuditKind, mode: AuditMode, limit: usize, excludes: &[String]) -> Result<()> {
    let e = open(store)?;
    let sec = Security::new(&e);

    if matches!(kind, AuditKind::All | AuditKind::Entrypoints) {
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

    if matches!(kind, AuditKind::All | AuditKind::Taint) {
        if mode == AuditMode::Dataflow {
            println!(
                "\nmode: dataflow — a finding is a value from a source reaching a sink's \
                 argument. Flow-, field- and predicate-sensitive within a function, \
                 call-site-matched across calls (a value leaves a callee where it \
                 entered), may-alias by copy and address; library calls by summary."
            );
        }
        for spec in presets::all() {
            let spec = excludes
                .iter()
                .fold(spec, |s, p| s.exclude(codegraph_security::Matcher::in_path(p)));
            let spec = match mode {
                AuditMode::Callgraph => spec,
                AuditMode::Dataflow => spec.mode(codegraph_security::Mode::DataFlow),
            };
            let t = Instant::now();
            let a = sec.analyse(&spec, limit)?;
            match mode {
                AuditMode::Callgraph => println!(
                    "\n{}: {} sources x {} sinks, {:.1}% rejected by index, {} findings ({:.0} ms)",
                    spec.name,
                    a.sources,
                    a.sinks,
                    a.rejection_rate() * 100.0,
                    a.findings.len(),
                    t.elapsed().as_secs_f64() * 1e3
                ),
                // Value flow is searched backwards from each sink; the
                // reachability labels do not cover it.
                AuditMode::Dataflow => println!(
                    "\n{}: {} sources x {} sinks, {} sinks searched, {} findings ({:.0} ms)",
                    spec.name,
                    a.sources,
                    a.sinks,
                    a.pairs_searched,
                    a.findings.len(),
                    t.elapsed().as_secs_f64() * 1e3
                ),
            }
            for f in &a.findings {
                println!(
                    "  {} -> {}  [{} hops, {:?}{}]",
                    show_in_context(&e, &f.source),
                    show_in_context(&e, &f.sink),
                    f.depth(),
                    f.confidence,
                    if f.reachable_from_entrypoint { ", live" } else { ", unreachable" }
                );
                let via: Vec<String> = f.path.iter().map(|s| s.name.clone()).collect();
                println!("      via {}", via.join(" -> "));
            }
        }
        // These presets are a starting point, and saying so beats letting an
        // empty result read as "no vulnerabilities".
        println!(
            "\nnote: these are starter specs, not a policy. Zero findings means \
             zero matches for *these* patterns."
        );
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
    let s = Store::open(store)?;
    s.verify()?;
    println!("segments: ok ({} live)", s.manifest().segments.len());

    let path = store.join(codegraph_index::BASE_FILE);
    if path.exists() {
        let index = MappedIndex::open_any(&path)?;
        index.verify_checksums()?;
        let generation = s.manifest().generation;
        if index.generation() == generation {
            println!("index:    ok ({} bytes mapped)", index.mapped_bytes());
        } else {
            let overlay = codegraph_index::Overlay::read(
                &store.join(codegraph_index::OVERLAY_FILE),
                generation,
                index.generation(),
            )?;
            println!(
                "index:    ok ({} bytes mapped, overlay of {} rows, {} patched)",
                index.mapped_bytes(),
                overlay.delta_rows(),
                overlay.patched_rows()
            );
        }
    } else {
        println!("index:    absent");
    }
    Ok(())
}
