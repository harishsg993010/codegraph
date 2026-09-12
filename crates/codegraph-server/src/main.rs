//! `codegraph-mcp` — serve a store over MCP on stdio.
//!
//!   codegraph-mcp <store-dir>
//!
//! stdout carries the protocol and nothing else; every diagnostic goes to
//! stderr. A stray line on stdout corrupts the stream, and the client's error
//! will point anywhere but here.

use anyhow::{Context, Result};
use codegraph_index::{Opened, open_or_build};
use codegraph_query::Engine;
use codegraph_server::{CodeGraph, ServiceExt, stdio};
use codegraph_store::Store;

#[tokio::main]
async fn main() -> Result<()> {
    let Some(dir) = std::env::args().nth(1) else {
        eprintln!("usage: codegraph-mcp <store-dir>");
        std::process::exit(2);
    };
    let root = std::path::PathBuf::from(dir);

    let store =
        Store::open(&root).with_context(|| format!("opening store at {}", root.display()))?;
    // A missing or stale index is recoverable, so build what is missing
    // rather than refuse — but say so, because a full rebuild is slow and the
    // operator should know why startup took a while.
    let (index, how) = open_or_build(&store, &root)?;
    match how {
        Opened::Base | Opened::Overlaid => {}
        Opened::OverlayBuilt => eprintln!("index overlay was missing; built it"),
        Opened::Rebuilt => eprintln!("index unusable; rebuilt"),
    }

    let engine = Engine::from_parts(store, index);
    eprintln!(
        "codegraph-mcp ready: {} symbols from {}",
        engine.symbol_count(),
        root.display()
    );

    let service = CodeGraph::new(engine).serve(stdio()).await?;
    service.waiting().await?;
    Ok(())
}
