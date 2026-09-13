//! `codegraph-mcp` — serve a store over MCP on stdio.
//!
//!   codegraph-mcp <store-dir> [--no-watch] [--debounce-ms N]
//!
//! stdout carries the protocol and nothing else; every diagnostic goes to
//! stderr. A stray line on stdout corrupts the stream, and the client's error
//! will point anywhere but here.
//!
//! When the store remembers the tree it was built from (every store
//! `codegraph index` writes does), the server watches that tree and brings
//! the store, the index and its own engine forward after each quiet period,
//! so a model editing the tree asks questions of the tree as it is.

use std::time::Duration;

use anyhow::Result;
use codegraph_resolve::TreeState;
use codegraph_server::{CodeGraph, ServiceExt, open_store, stdio};

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut dir = None;
    let mut watch = true;
    let mut debounce = Duration::from_millis(400);
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--no-watch" => watch = false,
            "--debounce-ms" => {
                i += 1;
                debounce = Duration::from_millis(args.get(i).and_then(|v| v.parse().ok()).unwrap_or(400));
            }
            other => dir = Some(other.to_string()),
        }
        i += 1;
    }
    let Some(dir) = dir else {
        eprintln!("usage: codegraph-mcp <store-or-source-dir> [--no-watch] [--debounce-ms N]");
        std::process::exit(2);
    };
    let given = std::path::PathBuf::from(dir);

    // A source tree is indexed on first use; a store that knows its tree
    // is brought up to date before the first answer.
    let ensured = codegraph_resolve::ensure_current(&given, "", &codegraph_store::CompactPolicy::default())
        .map_err(|e| anyhow::anyhow!("bringing {} up to date: {e}", given.display()))?;
    if let Some(r) = &ensured.report {
        if ensured.located.fresh || !r.incremental {
            eprintln!("indexed {}: {} files, {} symbols, {} edges", given.display(), r.reextracted, r.symbols, r.edges);
        } else if r.changed > 0 || r.deleted > 0 {
            eprintln!("updated: {} changed, {} deleted, {} re-extracted ({})", r.changed, r.deleted, r.reextracted, r.detection);
        }
    }
    let root = ensured.located.store_dir;

    let engine = open_store(&root)?;
    eprintln!("codegraph-mcp ready: {} symbols from {}", engine.symbol_count(), root.display());
    let graph = CodeGraph::new(engine);

    if watch {
        match TreeState::load(&root).map(|t| (t.root_path(), t.repo)) {
            Some((src, repo)) if src.is_dir() => match graph.follow(src.clone(), root.clone(), repo, debounce) {
                Ok(()) => eprintln!("watching {} for changes", src.display()),
                Err(e) => eprintln!("not watching {}: {e}", src.display()),
            },
            Some((src, _)) => eprintln!("not watching: the tree {} is not there", src.display()),
            None => eprintln!("not watching: the store does not record its source tree (index it once with this version)"),
        }
    }

    let service = graph.serve(stdio()).await?;
    service.waiting().await?;
    Ok(())
}
