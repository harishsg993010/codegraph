//! Latency baseline for the read surface.
//!
//! Reports p50/p99 per operation so a later phase can tell a regression from
//! noise. Percentiles rather than a mean: a mean hides the tail, and the tail
//! is what an interactive caller actually feels.
//!
//!   bench <index.json>...

use std::time::Instant;

use codegraph_core::{LocalId, Relation, RelationMask};
use codegraph_index::IndexData;
use codegraph_query::{Direction, Engine, Walk};
use codegraph_store::{Store, compact, import_node_link};

struct Timings(Vec<f64>);

impl Timings {
    fn new() -> Self {
        Self(Vec::new())
    }
    fn record<T>(&mut self, f: impl FnOnce() -> T) -> T {
        let t = Instant::now();
        let out = f();
        self.0.push(t.elapsed().as_secs_f64() * 1e6);
        out
    }
    fn pct(&mut self, p: f64) -> f64 {
        if self.0.is_empty() {
            return 0.0;
        }
        self.0.sort_by(|a, b| a.partial_cmp(b).expect("no NaN timings"));
        let i = ((self.0.len() as f64 * p) as usize).min(self.0.len() - 1);
        self.0[i]
    }
    fn report(&mut self, label: &str) {
        let n = self.0.len();
        println!(
            "  {label:<26} p50 {:>9.1} us   p99 {:>9.1} us   ({n} calls)",
            self.pct(0.50),
            self.pct(0.99)
        );
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() {
        eprintln!("usage: bench <index.json>...");
        std::process::exit(2);
    }

    for path in &args {
        let json = std::fs::read_to_string(path)?;
        let name = std::path::Path::new(path)
            .file_stem()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();

        let dir = tempfile::tempdir()?;
        let mut store = Store::create(dir.path())?;

        let t = Instant::now();
        import_node_link(&json, &mut store)?;
        let import_ms = t.elapsed().as_secs_f64() * 1e3;

        let t = Instant::now();
        compact(&mut store)?;
        let compact_ms = t.elapsed().as_secs_f64() * 1e3;

        let t = Instant::now();
        let index = IndexData::build(&store)?;
        let index_ms = t.elapsed().as_secs_f64() * 1e3;

        // Cold open: reopen from disk and rebuild the index, which is what a
        // fresh process pays today.
        let t = Instant::now();
        let reopened = Store::open(dir.path())?;
        let open_ms = t.elapsed().as_secs_f64() * 1e3;
        drop(reopened);

        let e = Engine::from_parts(store, index);
        let n = e.symbol_count();
        println!(
            "\n{name}  —  {n} symbols, {} edges, {} components",
            e.store().edge_count(),
            e.index().scc_count
        );
        println!(
            "  build:  import {import_ms:.1} ms | compact {compact_ms:.1} ms | \
             index {index_ms:.1} ms | store open {open_ms:.2} ms"
        );

        if n == 0 {
            continue;
        }

        // Probe set drawn from the corpus itself, so the queries are ones that
        // actually hit rather than uniformly missing.
        let seg = e.store().segments().next().expect("segment").1;
        let norms = seg.node_norm_names()?;
        let names: Vec<String> = (0..n)
            .step_by((n / 200).max(1))
            .map(|i| seg.string(norms[i]).to_string())
            .filter(|s| !s.is_empty())
            .collect();
        let ids: Vec<LocalId> = (0..n)
            .step_by((n / 200).max(1))
            .map(|i| LocalId::new(i as u32))
            .collect();

        let mut t_key = Timings::new();
        let keys = seg.keys()?;
        for id in &ids {
            let k = keys[id.index()];
            t_key.record(|| e.by_key(k).expect("lookup"));
        }
        t_key.report("lookup by key");

        let mut t_name = Timings::new();
        for nm in &names {
            t_name.record(|| e.by_name(nm));
        }
        t_name.report("lookup by exact name");

        let mut t_prefix = Timings::new();
        for nm in &names {
            let p: String = nm.chars().take(3).collect();
            t_prefix.record(|| e.by_prefix(&p));
        }
        t_prefix.report("lookup by prefix");

        let mut t_search = Timings::new();
        for nm in &names {
            let p: String = nm.chars().take(5).collect();
            t_search.record(|| e.search(&p).expect("search"));
        }
        t_search.report("substring search");

        let mut t_nbr = Timings::new();
        for id in &ids {
            t_nbr.record(|| e.neighbors(*id, Direction::Out, RelationMask::ALL).expect("nbr"));
        }
        t_nbr.report("neighbours (1 hop)");

        let mut t_walk = Timings::new();
        let w = Walk { depth: 3, ..Walk::default() };
        for id in &ids {
            t_walk.record(|| e.walk(&[*id], w).expect("walk"));
        }
        t_walk.report("k-hop walk (depth 3)");

        let mut t_blast = Timings::new();
        for id in &ids {
            t_blast.record(|| e.blast_radius(*id, 2).expect("blast"));
        }
        t_blast.report("blast radius (depth 2)");

        let mut t_path = Timings::new();
        for (i, a) in ids.iter().enumerate() {
            let b = ids[(i * 7 + 3) % ids.len()];
            t_path.record(|| e.shortest_path(*a, b, RelationMask::ALL, 12).expect("path"));
        }
        t_path.report("shortest path");

        // Reachability is the new capability. Measure both halves: the
        // rejection path (which the label filter answers without searching)
        // and the connecting path (which actually runs a bidirectional BFS).
        // Reporting only the first would flatter the design — most random
        // pairs are unreachable, so an average would be all filter and no
        // search.
        let mut t_reject = Timings::new();
        let mut t_connect = Timings::new();
        let mut rejected = 0usize;

        // Pairs known to connect, found by walking the reachable set.
        let mut connecting: Vec<(LocalId, LocalId)> = Vec::new();
        for a in ids.iter().take(60) {
            let reach = e.reachable_set(&[*a], Relation::TAINT)?;
            if let Some(&b) = reach.iter().rev().find(|&&b| b != *a) {
                connecting.push((*a, b));
            }
        }

        for (i, a) in ids.iter().enumerate() {
            let b = ids[(i * 13 + 5) % ids.len()];
            let hit = t_reject.record(|| {
                e.taint_path(&[*a], &[b], Relation::TAINT, 24).expect("taint")
            });
            if hit.is_none() {
                rejected += 1;
            }
        }
        t_reject.report("taint (mixed pairs)");
        println!("    ({rejected} of {} pairs had no path)", ids.len());

        if connecting.is_empty() {
            println!("  {:<26} no connecting pairs in this corpus", "taint (connecting)");
        } else {
            for (a, b) in &connecting {
                t_connect.record(|| {
                    e.taint_path(&[*a], &[*b], Relation::TAINT, 24).expect("taint")
                });
            }
            t_connect.report("taint (connecting pairs)");
        }

        let mut t_hubs = Timings::new();
        for _ in 0..50 {
            t_hubs.record(|| e.hubs(10).expect("hubs"));
        }
        t_hubs.report("top-10 hubs");

        let mut t_stats = Timings::new();
        for _ in 0..50 {
            t_stats.record(|| e.edge_histogram().expect("hist"));
        }
        t_stats.report("edge histogram");
    }
    Ok(())
}
