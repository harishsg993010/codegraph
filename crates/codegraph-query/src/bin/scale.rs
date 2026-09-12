//! Scale test: synthesise a large store and check that residency and latency
//! hold.
//!
//! Every latency number recorded so far comes from a corpus that fits in cache.
//! This builds one that does not, and asks the two questions the design rests
//! on: does memory stay page-cache-bound, and do queries stay fast when the
//! data no longer fits in L2?
//!
//!   scale <symbols> <edges-per-symbol> [store-dir]

use std::time::Instant;

use codegraph_core::{
    Confidence, FileType, LocalId, Relation, RelationMask, SymbolKey, SymbolKeyParts, SymbolKind,
};
use codegraph_index::{IndexColumns, IndexData, IndexQuery};
use codegraph_query::{Engine, Walk};
use codegraph_store::{Edge, SegmentBuilder, Store, Symbol, Tier, compact};

/// Deterministic PRNG, so a scale run is reproducible.
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
}

fn key(path: &str, name: &str) -> SymbolKey {
    SymbolKey::new(SymbolKeyParts {
        repo: "",
        path,
        kind: SymbolKind::Function,
        scope: &[],
        name,
        disambiguator: 0,
    })
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let n: usize = args.next().and_then(|s| s.parse().ok()).unwrap_or(1_000_000);
    let fanout: usize = args.next().and_then(|s| s.parse().ok()).unwrap_or(6);
    // `dag` (default) mirrors a real call graph: overwhelmingly forward edges
    // with a few small recursive cycles. `cyclic` deliberately wraps edges
    // around, producing one giant strongly-connected core — a shape real code
    // does not have, but worth measuring because it is where interval
    // labelling degrades.
    let shape = args.next().unwrap_or_else(|| "dag".into());
    let dir = args.next();

    let tmp;
    let root: std::path::PathBuf = match dir {
        Some(d) => std::path::PathBuf::from(d),
        None => {
            tmp = tempfile::tempdir()?;
            tmp.path().to_path_buf()
        }
    };
    let _ = std::fs::remove_dir_all(&root);

    println!("building {n} symbols, ~{} edges, shape={shape}", n * fanout);

    // Shaped like a real corpus rather than uniformly random: symbols grouped
    // into files, most edges local to a neighbourhood, a few long-range. A
    // uniformly random graph is the pessimal case for interval labelling and
    // would understate the filter, which would be flattering in the wrong
    // direction — it would make the scale test easier to pass than reality.
    const PER_FILE: usize = 20;
    let t = Instant::now();
    let mut store = Store::create(&root)?;
    let id = store.next_segment_id();
    let mut b = SegmentBuilder::new(id, Tier::Ast).with_reverse_csr(true);

    let files = n.div_ceil(PER_FILE);
    let mut paths = Vec::with_capacity(files);
    let mut file_ids = Vec::with_capacity(files);
    for f in 0..files {
        let p = format!("src/mod{:04}/file{:05}.py", f / 100, f);
        file_ids.push(b.add_file(&p, 0, f as u64, 0, 1024));
        paths.push(p);
    }

    let mut names = Vec::with_capacity(n);
    for i in 0..n {
        let f = i / PER_FILE;
        let name = format!("sym{i}");
        b.add_symbol(Symbol {
            key: key(&paths[f], &name),
            file: file_ids[f],
            name: &name,
            norm_name: &name,
            kind: SymbolKind::Function,
            file_type: FileType::Code,
            line: (i % PER_FILE) as u32 + 1,
            flags: codegraph_store::node_flags::CALLABLE,
            hash: 0,
        });
        names.push(name);
    }
    let symbols_s = t.elapsed().as_secs_f64();

    let t = Instant::now();
    let mut rng = Rng(0xC0DE_CAFE);
    for i in 0..n {
        let f = i / PER_FILE;
        for k in 0..fanout {
            let span = (PER_FILE * 4).min(n).max(2);
            let target = if shape == "cyclic" {
                (i + 1 + (rng.next() as usize) % span) % n
            } else if k == 0 && rng.next().is_multiple_of(20) {
                let ahead = n.saturating_sub(i + 1);
                if ahead == 0 { continue } else { i + 1 + (rng.next() as usize) % ahead }
            } else if rng.next().is_multiple_of(50) && i > 1 {
                // Occasional back-edge: recursion and mutual recursion do
                // exist, and a DAG with none would flatter the filter.
                i - 1 - (rng.next() as usize) % span.min(i)
            } else {
                let hi = (i + 1 + span).min(n);
                if i + 1 >= hi { continue } else { i + 1 + (rng.next() as usize) % (hi - i - 1) }
            };
            if target == i || target >= n {
                continue;
            }
            b.add_edge(Edge {
                source: LocalId::new(i as u32),
                target: key(&paths[target / PER_FILE], &names[target]),
                rel: if k % 3 == 0 { Relation::Calls } else { Relation::Contains },
                conf: Confidence::Extracted,
                line: 1,
                context: None,
                flags: 0,
            });
        }
        let _ = f;
    }
    let edges_s = t.elapsed().as_secs_f64();
    let edge_count = b.edge_count();

    let t = Instant::now();
    store.commit_segment(id, b, Tier::Ast, &paths)?;
    let write_s = t.elapsed().as_secs_f64();

    let t = Instant::now();
    compact(&mut store)?;
    let compact_s = t.elapsed().as_secs_f64();

    let t = Instant::now();
    let index = IndexData::build(&store)?;
    let index_s = t.elapsed().as_secs_f64();

    let t = Instant::now();
    index.write(&root.join("index.cgidx"), store.manifest().generation)?;
    let index_write_s = t.elapsed().as_secs_f64();

    println!(
        "  build: symbols {symbols_s:.1}s | edges {edges_s:.1}s | write {write_s:.1}s | \
         compact {compact_s:.1}s | index {index_s:.1}s | index write {index_write_s:.1}s"
    );

    // Cold open: drop everything and reopen from disk, which is what a fresh
    // process pays.
    drop(store);
    drop(index);
    let t = Instant::now();
    let store = Store::open(&root)?;
    let open_s = t.elapsed().as_secs_f64();
    // Both index paths, so the difference the mapping buys is visible rather
    // than asserted.
    let t = Instant::now();
    let owned = IndexData::read(&root.join("index.cgidx"), store.manifest().generation)?;
    let owned_ms = t.elapsed().as_secs_f64() * 1e3;
    drop(owned);
    let t = Instant::now();
    let index = codegraph_index::MappedIndex::open(
        &root.join("index.cgidx"),
        store.manifest().generation,
    )?;
    let mapped_ms = t.elapsed().as_secs_f64() * 1e3;
    println!(
        "  cold open: store {:.0} ms | index owned {owned_ms:.0} ms | index mapped {mapped_ms:.0} ms",
        open_s * 1e3
    );

    let store_bytes: u64 = std::fs::read_dir(&root)?
        .flatten()
        .filter_map(|e| e.metadata().ok())
        .filter(|m| m.is_file())
        .map(|m| m.len())
        .sum();
    let items = store.symbol_count() + store.edge_count();
    println!(
        "  {} symbols, {} edges ({} requested), {} components",
        store.symbol_count(),
        store.edge_count(),
        edge_count,
        index.scc_count()
    );
    println!(
        "  store {:.2} GB on disk = {:.0} B/item",
        store_bytes as f64 / 1e9,
        store_bytes as f64 / items as f64
    );

    let e = Engine::from_parts(store, index);
    let total = e.symbol_count();

    // Probes spread across the whole id space, so the reads actually touch
    // pages rather than staying in whatever the build left hot.
    let mut rng = Rng(99);
    let probes: Vec<LocalId> = (0..2000)
        .map(|_| LocalId::new((rng.next() as usize % total) as u32))
        .collect();

    macro_rules! timed {
        ($label:literal, $body:expr) => {{
            let mut us: Vec<f64> = Vec::with_capacity(probes.len());
            for &id in &probes {
                let _ = id;
                let t = Instant::now();
                let _ = $body(id);
                us.push(t.elapsed().as_secs_f64() * 1e6);
            }
            us.sort_by(|a, b| a.partial_cmp(b).expect("no NaN"));
            println!(
                "  {:<24} p50 {:>8.1} us   p99 {:>9.1} us",
                $label,
                us[us.len() / 2],
                us[us.len() * 99 / 100]
            );
        }};
    }

    println!("\n  latency at {total} symbols:");
    timed!("lookup by key", |id: LocalId| {
        let seg = e.store().segments().next().expect("seg").1;
        e.by_key(seg.keys().expect("keys")[id.index()])
    });
    timed!("neighbours (1 hop)", |id| e.neighbors(
        id,
        codegraph_query::Direction::Out,
        RelationMask::ALL
    ));
    timed!("k-hop walk (depth 3)", |id| e.walk(&[id], Walk { depth: 3, ..Walk::default() }));
    timed!("blast radius (depth 2)", |id| e.blast_radius(id, 2));

    // Reachability: the claim the whole security layer rests on.
    let mut rng = Rng(1234);
    let pairs: Vec<(LocalId, LocalId)> = (0..2000)
        .map(|_| {
            (
                LocalId::new((rng.next() as usize % total) as u32),
                LocalId::new((rng.next() as usize % total) as u32),
            )
        })
        .collect();
    // Measured twice. With a mapped index the first pass pays a page fault per
    // cold label page; the second shows the steady-state cost. Reporting only
    // one of them would misrepresent the mmap tradeoff in whichever direction
    // happened to flatter it.
    for pass in 0..2 {
        let mut us = Vec::with_capacity(pairs.len());
        let mut rejected = 0usize;
        for &(a, b) in &pairs {
            let t = Instant::now();
            let maybe = e.index().maybe_reaches(a, b);
            us.push(t.elapsed().as_secs_f64() * 1e6);
            if !maybe {
                rejected += 1;
            }
        }
        us.sort_by(|a, b| a.partial_cmp(b).expect("no NaN"));
        println!(
            "  {:<24} p50 {:>8.3} us   p99 {:>9.3} us   ({:.1}% rejected){}",
            if pass == 0 { "reachability (cold)" } else { "reachability (warm)" },
            us[us.len() / 2],
            us[us.len() * 99 / 100],
            rejected as f64 / pairs.len() as f64 * 100.0,
            if pass == 0 { "" } else { "  <- steady state" },
        );
    }

    // The rejection rate above is a share of *all* pairs, which is not
    // comparable with the real-corpus figure unless the reachable fraction is
    // known too. In a synthetic forward-biased DAG roughly half of all random
    // pairs are genuinely reachable, so a 50% rejection rate can still mean the
    // filter is rejecting nearly every unreachable pair. Measure that directly.
    let mut us = Vec::new();
    let mut connected = 0usize;
    let mut searched_sample = 0usize;
    for &(a, b) in pairs.iter().take(500) {
        let t = Instant::now();
        let found = e.shortest_path(a, b, Relation::TAINT, 12)?;
        us.push(t.elapsed().as_secs_f64() * 1e6);
        if e.index().maybe_reaches(a, b) {
            searched_sample += 1;
            if found.is_some() {
                connected += 1;
            }
        }
    }
    us.sort_by(|a, b| a.partial_cmp(b).expect("no NaN"));
    println!(
        "  {:<24} p50 {:>8.1} us   p99 {:>9.1} us",
        "taint source -> sink",
        us[us.len() / 2],
        us[us.len() * 99 / 100]
    );

    // Of the pairs the filter let through, how many really connect within the
    // hop bound? A high number means the filter is precise; a low one means it
    // is waving through work that a search then has to reject.
    if searched_sample > 0 {
        println!(
            "
  of {searched_sample} pairs the filter passed, {connected} connect              ({:.0}% precision within {} hops)",
            connected as f64 / searched_sample as f64 * 100.0,
            12
        );
    }

    Ok(())
}
