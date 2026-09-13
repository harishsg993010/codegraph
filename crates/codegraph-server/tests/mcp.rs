//! The MCP surface, driven through the SDK's own client.
//!
//! Testing through a real client rather than by calling the tool functions
//! directly is the point: it exercises the generated schemas, the router
//! dispatch, and argument deserialisation — which is where a hand-written
//! schema and its implementation would drift apart.

use codegraph_index::open_or_build;
use codegraph_query::Engine;
use codegraph_resolve::index_tree;
use codegraph_server::CodeGraph;
use codegraph_store::Store;
use rmcp::{ServiceExt, model::CallToolRequestParams, object};
use std::path::Path;

fn write(dir: &Path, rel: &str, body: &str) {
    let p = dir.join(rel);
    if let Some(parent) = p.parent() {
        std::fs::create_dir_all(parent).expect("mkdir");
    }
    std::fs::write(p, body).expect("write");
}

/// A small project with a real call chain and one ambiguous name.
fn project(dir: &Path) {
    write(
        dir,
        "app/db.py",
        "def connect():\n    return 1\n\ndef query(sql):\n    connect()\n    return []\n",
    );
    write(
        dir,
        "app/service.py",
        "import app.db\n\ndef fetch():\n    query('select 1')\n\n\
         class A:\n    def shared(self): pass\n\nclass B:\n    def shared(self): pass\n",
    );
    write(dir, "app/main.py", "import app.service\n\ndef main():\n    fetch()\n");
}

/// Build a store, then a connected (client, server) pair over an in-memory
/// duplex so no process or pipe is involved.
async fn connect() -> (tempfile::TempDir, tempfile::TempDir, rmcp::service::RunningService<rmcp::RoleClient, ()>) {
    let src = tempfile::tempdir().expect("tempdir");
    project(src.path());
    let sd = tempfile::tempdir().expect("tempdir");

    let mut store = Store::create(sd.path()).expect("create");
    index_tree(src.path(), &mut store, "").expect("index");
    let (index, _) = open_or_build(&store, sd.path()).expect("index");
    let engine = Engine::from_parts(store, index);

    let (client_io, server_io) = tokio::io::duplex(8 * 1024 * 1024);
    tokio::spawn(async move {
        let service = CodeGraph::new(engine)
            .serve(server_io)
            .await
            .expect("server start");
        let _ = service.waiting().await;
    });
    let client = ().serve(client_io).await.expect("client connect");
    (src, sd, client)
}

/// The served graph follows the tree: a file written after the server is
/// up is searchable without a restart, and one removed is gone.
#[tokio::test]
async fn the_server_follows_the_tree() {
    let src = tempfile::tempdir().expect("tempdir");
    project(src.path());
    let sd = tempfile::tempdir().expect("tempdir");
    let mut store = Store::create(sd.path()).expect("create");
    index_tree(src.path(), &mut store, "").expect("index");
    drop(store);
    let engine = codegraph_server::open_store(sd.path()).expect("open");
    let graph = CodeGraph::new(engine);
    graph
        .follow(src.path().to_path_buf(), sd.path().to_path_buf(), String::new(), std::time::Duration::from_millis(150))
        .expect("watch starts");

    let (client_io, server_io) = tokio::io::duplex(8 * 1024 * 1024);
    tokio::spawn(async move {
        let service = graph.serve(server_io).await.expect("server start");
        let _ = service.waiting().await;
    });
    let client = ().serve(client_io).await.expect("client connect");

    let text = call(&client, "search", object!({"query": "late_arrival"})).await;
    assert!(text.starts_with("0 matches"), "got: {text}");

    write(src.path(), "app/late.py", "def late_arrival():\n    return 1\n");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
    loop {
        let text = call(&client, "search", object!({"query": "late_arrival"})).await;
        if text.contains("app/late.py") {
            break;
        }
        assert!(std::time::Instant::now() < deadline, "the new file never appeared: {text}");
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    }

    std::fs::remove_file(src.path().join("app/late.py")).unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
    loop {
        let text = call(&client, "search", object!({"query": "late_arrival"})).await;
        if text.starts_with("0 matches") {
            break;
        }
        assert!(std::time::Instant::now() < deadline, "the removed file never went: {text}");
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    }
    client.cancel().await.ok();
}

/// Call a tool and return its text content.
async fn call(
    client: &rmcp::service::RunningService<rmcp::RoleClient, ()>,
    name: &'static str,
    args: serde_json::Map<String, serde_json::Value>,
) -> String {
    let result = client
        .call_tool(CallToolRequestParams::new(name).with_arguments(args))
        .await
        .unwrap_or_else(|e| panic!("{name} failed: {e}"));
    result
        .content
        .iter()
        .filter_map(|c| c.as_text().map(|t| t.text.clone()))
        .collect::<Vec<_>>()
        .join("\n")
}

#[tokio::test]
async fn the_server_advertises_its_tools() {
    let (_s, _d, client) = connect().await;
    let tools = client.list_all_tools().await.expect("list tools");
    let names: Vec<String> = tools.iter().map(|t| t.name.to_string()).collect();

    for expected in ["search", "explain", "affected", "path", "neighbors", "context", "stats", "audit", "deps", "cfg", "diff", "deep_search"] {
        assert!(names.contains(&expected.to_string()), "missing tool {expected}; got {names:?}");
    }
    // Every tool must carry a description a model can act on, and a schema.
    for t in &tools {
        let d = t.description.as_deref().unwrap_or("");
        assert!(d.len() > 40, "{}: description too thin: {d:?}", t.name);
        assert_eq!(
            t.input_schema.get("type").and_then(|v| v.as_str()),
            Some("object"),
            "{}: schema is not an object",
            t.name
        );
    }
    client.cancel().await.ok();
}

#[tokio::test]
async fn search_finds_a_symbol() {
    let (_s, _d, client) = connect().await;
    let text = call(&client, "search", object!({"query": "connect"})).await;
    assert!(text.contains("connect"), "got: {text}");
    assert!(text.contains("app/db.py"), "result lacks a location: {text}");
    client.cancel().await.ok();
}

#[tokio::test]
async fn explain_reports_callers_and_callees() {
    let (_s, _d, client) = connect().await;
    let text = call(&client, "explain", object!({"symbol": "query"})).await;
    assert!(text.contains("query"), "got: {text}");
    assert!(text.contains("connect"), "query() should be shown calling connect(): {text}");
    client.cancel().await.ok();
}

#[tokio::test]
async fn path_finds_a_chain_and_reports_absence_honestly() {
    let (_s, _d, client) = connect().await;
    let found = call(&client, "path", object!({"from": "fetch", "to": "connect"})).await;
    assert!(found.contains("hops"), "got: {found}");

    let absent = call(&client, "path", object!({"from": "connect", "to": "fetch"})).await;
    assert!(absent.contains("no path"), "backwards path should be absent: {absent}");
    client.cancel().await.ok();
}

/// An ambiguous symbol must come back as a list of candidates, not a guess.
#[tokio::test]
async fn an_ambiguous_symbol_returns_candidates() {
    let (_s, _d, client) = connect().await;
    let text = call(&client, "explain", object!({"symbol": "shared"})).await;
    assert!(text.contains("ambiguous"), "got: {text}");
    // Both owners should be listed so the caller can pick.
    assert!(text.matches("app/service.py").count() >= 2, "candidates not listed: {text}");
    client.cancel().await.ok();
}

#[tokio::test]
async fn a_missing_symbol_is_reported_not_guessed() {
    let (_s, _d, client) = connect().await;
    let text = call(&client, "explain", object!({"symbol": "no_such_symbol"})).await;
    assert!(text.contains("no symbol named"), "got: {text}");
    client.cancel().await.ok();
}

#[tokio::test]
async fn optional_arguments_have_working_defaults() {
    let (_s, _d, client) = connect().await;
    // `limit` and `depth` omitted entirely: serde defaults must apply rather
    // than the call failing to deserialise.
    let text = call(&client, "affected", object!({"symbol": "connect"})).await;
    assert!(text.contains("affected within 2 hops"), "default depth not applied: {text}");
    client.cancel().await.ok();
}

#[tokio::test]
async fn stats_describes_the_corpus() {
    let (_s, _d, client) = connect().await;
    let text = call(&client, "stats", object!({})).await;
    assert!(text.contains("symbols"), "got: {text}");
    assert!(text.contains("by relation"), "got: {text}");
    client.cancel().await.ok();
}

/// The audit tool must state its own limits in the output, so an agent cannot
/// read "0 findings" as "no vulnerabilities".
#[tokio::test]
async fn audit_states_its_limits() {
    let (_s, _d, client) = connect().await;
    let text = call(&client, "audit", object!({})).await;
    assert!(text.contains("entrypoints"), "got: {text}");
    assert!(
        text.contains("starter specs"),
        "audit output does not caveat its coverage: {text}"
    );
    client.cancel().await.ok();
}

#[tokio::test]
async fn deps_lists_external_packages() {
    let (_s, _d, client) = connect().await;
    let text = call(&client, "deps", object!({})).await;
    assert!(text.contains("external packages"), "got: {text}");
    client.cancel().await.ok();
}

#[tokio::test]
async fn an_unknown_tool_is_an_error_not_a_panic() {
    let (_s, _d, client) = connect().await;
    let result = client
        .call_tool(CallToolRequestParams::new("no_such_tool"))
        .await;
    assert!(result.is_err(), "an unknown tool should be rejected");
    client.cancel().await.ok();
}
