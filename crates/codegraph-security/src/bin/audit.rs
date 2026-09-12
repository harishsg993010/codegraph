//! Run the security layer over an indexed store.
//!
//!   audit <store-dir>

use std::time::Instant;

use codegraph_index::IndexData;
use codegraph_query::Engine;
use codegraph_security::{Security, spec::presets};
use codegraph_store::Store;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let Some(dir) = std::env::args().nth(1) else {
        eprintln!("usage: audit <store-dir>");
        std::process::exit(2);
    };
    let root = std::path::PathBuf::from(dir);

    let t = Instant::now();
    let store = Store::open(&root)?;
    let open_ms = t.elapsed().as_secs_f64() * 1e3;

    let index_path = root.join("index.cgidx");
    let t = Instant::now();
    let index = if index_path.exists() {
        IndexData::read(&index_path, store.manifest().generation)?
    } else {
        let ix = IndexData::build(&store)?;
        ix.write(&index_path, store.manifest().generation)?;
        ix
    };
    let index_ms = t.elapsed().as_secs_f64() * 1e3;

    println!(
        "{} symbols, {} edges, {} components  (store open {open_ms:.0} ms, index {index_ms:.0} ms)",
        store.symbol_count(),
        store.edge_count(),
        index.scc_count
    );

    let e = Engine::from_parts(store, index);
    let sec = Security::new(&e);

    let t = Instant::now();
    let eps = sec.entrypoints()?;
    let live = sec.reachable_from_entrypoints()?;
    let reach_ms = t.elapsed().as_secs_f64() * 1e3;
    println!(
        "\nentrypoints: {} | reachable from them: {} of {} symbols ({:.1}%)  [{reach_ms:.0} ms]",
        eps.len(),
        live.len(),
        e.symbol_count(),
        live.len() as f64 / e.symbol_count().max(1) as f64 * 100.0
    );

    // Dependencies, most-imported first.
    let pkgs = sec.packages()?;
    println!("\ntop external dependencies ({} total):", pkgs.len());
    for (name, importers) in pkgs.iter().take(10) {
        println!("  {name:<28} {importers:>5} importing files");
    }

    println!("\ntaint specs:");
    for spec in presets::all() {
        let t = Instant::now();
        let a = sec.analyse(&spec, 25)?;
        let ms = t.elapsed().as_secs_f64() * 1e3;
        println!(
            "  {:<20} {:>5} sources x {:>5} sinks = {:>9} pairs | \
             {:>5.1}% rejected by index | {:>3} findings | {ms:>7.0} ms",
            spec.name,
            a.sources,
            a.sinks,
            a.total_pairs(),
            a.rejection_rate() * 100.0,
            a.findings.len(),
        );
        for f in a.findings.iter().take(3) {
            println!(
                "      {} ({}:{}) -> {} ({}:{})  {} hops, {:?}{}",
                f.source.name,
                f.source.path,
                f.source.line,
                f.sink.name,
                f.sink.path,
                f.sink.line,
                f.depth(),
                f.confidence,
                if f.reachable_from_entrypoint { ", live" } else { ", not reachable from an entrypoint" }
            );
        }
    }
    Ok(())
}
