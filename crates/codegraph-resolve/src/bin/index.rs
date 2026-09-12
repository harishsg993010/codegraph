//! Index a source tree and report what came out.
//!
//!   index <source-dir> [store-dir]

use std::path::{Path, PathBuf};
use std::time::Instant;

use codegraph_index::IndexData;
use codegraph_resolve::pipeline;
use codegraph_store::{Store, compact};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let Some(src) = args.next() else {
        eprintln!("usage: index <source-dir> [store-dir]");
        std::process::exit(2);
    };
    let src = PathBuf::from(src);
    let store_dir = args.next().map(PathBuf::from);
    let tmp;
    let store_path: &Path = match &store_dir {
        Some(p) => p,
        None => {
            tmp = tempfile::tempdir()?;
            tmp.path()
        }
    };

    println!("indexing {}", src.display());

    let t = Instant::now();
    let scan = pipeline::scan(&src);
    let scan_s = t.elapsed().as_secs_f64();
    println!(
        "  scan     {:>8} files in {scan_s:>6.2}s  ({} noise dirs skipped)",
        scan.files.len(),
        scan.skipped_dirs
    );
    if scan.files.is_empty() {
        return Ok(());
    }

    let t = Instant::now();
    let files = pipeline::extract_all(&src, &scan.files);
    let extract_s = t.elapsed().as_secs_f64();
    let bytes: u64 = files.iter().map(|f| f.size).sum();
    let raw_symbols: usize = files.iter().map(|f| f.symbols.len()).sum();
    let raw_calls: usize = files.iter().map(|f| f.calls.len()).sum();
    println!(
        "  extract  {:>8} files in {extract_s:>6.2}s  = {:>7.0} files/s, {:.1} MB/s",
        files.len(),
        files.len() as f64 / extract_s,
        bytes as f64 / extract_s / 1e6,
    );
    println!("           {raw_symbols} raw symbols, {raw_calls} call sites");

    let mut store = Store::open_or_create(store_path)?;
    let t = Instant::now();
    let build = codegraph_resolve::build(&files, &mut store, "")?;
    let build_s = t.elapsed().as_secs_f64();

    let t = Instant::now();
    compact(&mut store)?;
    let compact_s = t.elapsed().as_secs_f64();

    let t = Instant::now();
    let index = IndexData::build(&store)?;
    let index_s = t.elapsed().as_secs_f64();

    let total = scan_s + extract_s + build_s + compact_s + index_s;
    println!(
        "  resolve  {build_s:>6.2}s | compact {compact_s:>6.2}s | index {index_s:>6.2}s"
    );
    println!(
        "  TOTAL    {total:>6.2}s  = {:>7.0} files/s end to end",
        files.len() as f64 / total
    );

    // Store size against the source it describes.
    let store_bytes: u64 = std::fs::read_dir(store_path)?
        .flatten()
        .filter_map(|e| e.metadata().ok())
        .filter(|m| m.is_file())
        .map(|m| m.len())
        .sum();
    let items = (store.symbol_count() + store.edge_count()).max(1);
    println!(
        "\n  {} symbols, {} edges, {} components",
        store.symbol_count(),
        store.edge_count(),
        index.scc_count
    );
    println!(
        "  store {:.1} MB for {:.1} MB of source ({:.0} B/item, {:.1}% of source size)",
        store_bytes as f64 / 1e6,
        bytes as f64 / 1e6,
        store_bytes as f64 / items as f64,
        store_bytes as f64 / bytes.max(1) as f64 * 100.0,
    );

    // The resolution report. Printed in full, including what was *not* bound:
    // a silent gap is the failure mode this layer is most prone to.
    println!("\n  resolution:");
    println!("    structural edges     {:>8}", build.structural_edges);
    println!("    calls bound (local)  {:>8}", build.calls_local);
    println!("    calls bound (cross)  {:>8}", build.calls_cross_file);
    println!("    calls bound (receiver){:>7}", build.calls_receiver);
    println!("    calls ambiguous      {:>8}  (left unbound on purpose)", build.calls_ambiguous);
    println!("    calls unresolved     {:>8}  (stdlib / third-party / missed)", build.calls_unresolved);
    println!("    imports resolved     {:>8}", build.imports_resolved);
    println!("    imports external     {:>8}", build.imports_external);
    println!("    files w/ parse error {:>8}  of {}", build.parse_errors, files.len());

    let bound = build.calls_local + build.calls_cross_file + build.calls_receiver;
    let seen = bound + build.calls_ambiguous + build.calls_unresolved;
    if seen > 0 {
        println!(
            "    -> {:.1}% of call sites bound to a definition",
            bound as f64 / seen as f64 * 100.0
        );
    }

    // Per-language breakdown, so a language whose config is wrong shows up as
    // an outlier rather than averaging away.
    let mut by_lang: std::collections::BTreeMap<&str, (usize, usize, usize)> = Default::default();
    for f in &files {
        let e = by_lang.entry(f.lang).or_default();
        e.0 += 1;
        e.1 += f.symbols.len();
        e.2 += f.calls.len();
    }
    if by_lang.len() > 1 {
        println!("\n  by language:");
        for (lang, (n, syms, calls)) in by_lang {
            println!(
                "    {lang:<12} {n:>6} files  {syms:>8} symbols ({:>5.1}/file)  {calls:>8} calls",
                syms as f64 / n as f64
            );
        }
    }
    Ok(())
}
