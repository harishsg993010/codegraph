//! `codegraph-verify` — snapshot an index, or diff two of them.
//!
//!   codegraph-verify snapshot <index.json>            print a summary
//!   codegraph-verify diff     <before.json> <after.json>
//!   codegraph-verify baseline <dir>                   summarise every *.json in dir

use std::path::Path;

use anyhow::{Context, Result, bail};
use codegraph_verify::{Snapshot, diff};

/// Load either a node-link JSON file or a store directory, so `diff` can
/// compare one against the other directly.
fn load(path: &Path) -> Result<Snapshot> {
    if path.is_dir() {
        let store = codegraph_store::Store::open(path)
            .with_context(|| format!("opening store {}", path.display()))?;
        return Snapshot::from_store(&store);
    }
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("reading {}", path.display()))?;
    Snapshot::from_node_link(&text).with_context(|| format!("parsing {}", path.display()))
}

/// Import a node-link index into a store, then report the size change.
fn import_cmd(src: &Path, dst: &Path) -> Result<()> {
    let text = std::fs::read_to_string(src)
        .with_context(|| format!("reading {}", src.display()))?;
    let mut store = codegraph_store::Store::open_or_create(dst)
        .with_context(|| format!("opening store {}", dst.display()))?;
    let stats = codegraph_store::import_node_link(&text, &mut store)?;

    let json_bytes = text.len() as u64;
    let store_bytes: u64 = std::fs::read_dir(dst)?
        .flatten()
        .filter_map(|e| e.metadata().ok())
        .filter(|m| m.is_file())
        .map(|m| m.len())
        .sum();
    let items = (stats.symbols + stats.edges).max(1) as f64;
    println!(
        "{:<22} {:>6} symbols {:>6} edges | json {:>8} B ({:.0} B/item) -> store {:>8} B ({:.0} B/item)  {:.2}x smaller",
        src.file_stem().unwrap_or_default().to_string_lossy(),
        stats.symbols,
        stats.edges,
        json_bytes,
        json_bytes as f64 / items,
        store_bytes,
        store_bytes as f64 / items,
        json_bytes as f64 / store_bytes.max(1) as f64,
    );
    if stats.dangling > 0 || stats.collisions > 0 {
        println!("  (dangling {}, collisions {})", stats.dangling, stats.collisions);
    }
    Ok(())
}

fn summarise(name: &str, s: &Snapshot) {
    let files: std::collections::BTreeSet<&str> = s
        .symbols
        .keys()
        .filter_map(|k| k.split('\u{0}').next())
        .filter(|f| !f.is_empty())
        .collect();
    println!(
        "{name:<24} {:>7} symbols  {:>7} edges  {:>6} files  {:>5} dangling  {:>5} collided",
        s.symbols.len(),
        s.edges.len(),
        files.len(),
        s.dangling,
        s.collisions
    );
}

/// Cap on how many individual differences we print. A diff with thousands of
/// entries is a signal in itself; dumping all of them buries it.
const SHOW: usize = 20;

fn show<T: std::fmt::Debug>(label: &str, items: &[T]) {
    if items.is_empty() {
        return;
    }
    println!("\n{label} ({}):", items.len());
    for it in items.iter().take(SHOW) {
        println!("  {it:?}");
    }
    if items.len() > SHOW {
        println!("  ... and {} more", items.len() - SHOW);
    }
}

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("snapshot") => {
            let p = args.get(1).context("usage: snapshot <index.json>")?;
            let s = load(Path::new(p))?;
            summarise(p, &s);
        }
        Some("diff") => {
            let (Some(a), Some(b)) = (args.get(1), args.get(2)) else {
                bail!("usage: diff <before.json> <after.json>");
            };
            let (before, after) = (load(Path::new(a))?, load(Path::new(b))?);
            summarise("before", &before);
            summarise("after", &after);
            let r = diff(&before, &after);
            if r.is_clean() {
                println!("\nCLEAN — no difference in symbols or edges.");
                return Ok(());
            }
            show("symbols added", &r.symbols_added);
            show("symbols dropped", &r.symbols_dropped);
            show("symbols changed", &r.symbols_changed);
            show("edges added", &r.edges_added);
            show("edges dropped", &r.edges_dropped);
            if r.dangling_before != r.dangling_after {
                println!("\ndangling endpoints: {} -> {}", r.dangling_before, r.dangling_after);
            }
            // A difference is a report, not a failure: the caller judges whether
            // it is a regression or an intended improvement.
        }
        Some("import") => {
            let (Some(src), Some(dst)) = (args.get(1), args.get(2)) else {
                bail!("usage: import <index.json> <store-dir>");
            };
            import_cmd(Path::new(src), Path::new(dst))?;
        }
        Some("baseline") => {
            let dir = args.get(1).map(String::as_str).unwrap_or("corpora");
            let mut entries: Vec<_> = std::fs::read_dir(dir)
                .with_context(|| format!("reading {dir}"))?
                .flatten()
                .map(|e| e.path())
                .filter(|p| p.extension().is_some_and(|e| e == "json"))
                .collect();
            entries.sort();
            if entries.is_empty() {
                bail!("no *.json corpora found in {dir}");
            }
            for p in entries {
                let name = p.file_stem().unwrap_or_default().to_string_lossy().to_string();
                match load(&p) {
                    Ok(s) => summarise(&name, &s),
                    Err(e) => println!("{name:<24} FAILED: {e:#}"),
                }
            }
        }
        _ => {
            println!("usage:");
            println!("  codegraph-verify snapshot <index.json>");
            println!("  codegraph-verify diff     <before.json> <after.json>");
            println!("  codegraph-verify baseline [dir]        (default: corpora)");
            println!("  codegraph-verify import   <index.json> <store-dir>");
            println!();
            println!("`diff` accepts a store directory on either side.");
        }
    }
    Ok(())
}
