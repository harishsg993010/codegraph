# Phase 5 — index mmap, CLI, MCP server

229 tests, clippy-clean. Two of the three Phase 5 deliverables plus the Phase 4
carry-forward; PyO3 bindings are not built (see the end).

---

## Index mmap — the carry-forward, closed

Phase 4 measured index open at **1,076 ms and ~500 MB of heap** at 5M symbols,
because `IndexData::read` copied every column into a `Vec`. That was the one
component not following the store's own zero-copy rule.

The read surface is now a trait, [`IndexQuery`], with two backings: `IndexData`
(owned, what a build produces) and `MappedIndex` (mmap'd, what a reader opens).
Every actual query — name lookup, prefix, trigram candidates, reachability, hub
test — is a **default method on the trait**, so the two backings cannot answer
differently. A test asserts they agree on every column and every derived query
across all four corpora.

At 5M symbols / 30M edges:

| | before | after |
|---|---|---|
| index cold open | 1,385 ms | **0 ms** |
| reachability filter, first touch | 0.4 µs | 6.1 µs |
| reachability filter, steady state | 0.4 µs | **0.3 µs** |

The middle row is the honest cost and worth stating plainly: mmap does not make
the work vanish, it moves it. The eager 1.4 s copy becomes page faults spread
across the first queries that touch each label page, and only pages actually
touched are ever read. Steady state matches the owned path exactly. Other
latencies improved too (key lookup 14.4 → 3.8 µs), because half a gigabyte of
heap is no longer competing with the store for page cache.

`Engine` is now generic over the backing, defaulted to the owned form so
existing callers are unchanged, and generic rather than `dyn` so the
reachability filter — which runs per candidate pair — stays a direct call.

## `codegraph` — the CLI

One binary replacing the scattered dev bins: `index`, `search`, `explain`,
`path`, `affected`, `audit`, `deps`, `stats`, `verify`. Every read command opens
the *mapped* index, so a cold invocation costs a couple of syscalls rather than a
rebuild — which is the property that makes a CLI worth reaching for.

Two decisions worth recording:

- **Ambiguity is reported, not resolved.** `explain foo` where three symbols are
  called `foo` lists the candidates and exits non-zero. Silently picking one
  would make the answer depend on internal ordering, which a user cannot reason
  about.
- **A stale index is rebuilt, not refused.** It is a recoverable state, and
  making the user run a separate command for it is friction with no safety gain.
  The rebuild is announced on stderr, because it is slow.

## MCP server, on the official SDK

Built on **`rmcp` 3.1** — the official Rust MCP SDK — rather than the hand-rolled
JSON-RPC loop I started with. The tool surface is declared with `#[tool_router]`
/ `#[tool]`, so each tool's JSON Schema is derived from its argument struct.
A schema and an implementation that can drift apart is a class of bug worth not
having, and hand-writing the schemas had exactly that shape.

Nine tools: `search`, `explain`, `affected`, `path`, `neighbors`, `context`,
`stats`, `audit`, `deps`.

Descriptions are written for a model choosing what to call, and the security
tools state their limits *inline* — `audit` says in its own description and in
its output that this is call-graph reachability rather than dataflow, and that
zero findings means zero matches for the built-in patterns. An agent that reads
"0 findings" as "no vulnerabilities" has been misled by the tool, not by the
codebase, and that is the tool's problem to fix.

Tested through the SDK's **own client** over an in-memory duplex, not by calling
the tool functions directly — that exercises the generated schemas, router
dispatch, and argument deserialisation, which is precisely where a hand-written
surface would rot. 11 tests, including that optional arguments deserialise from
their `serde` defaults and that an ambiguous symbol returns candidates.

Verified against the real binary over stdio:

```
initialize -> codegraph 0.1.0, protocol 2025-06-18
tools/list -> 9 tools
tools/call search "extract_rust" -> extract_rust (extractors/rust.py:61)
```

One thing the smoke test caught: `serverInfo.name` was reporting `rmcp`, the
SDK's crate name, because `Implementation::from_build_env` reads the *library's*
build environment. Clients show that string to users, so it is set explicitly.

## A resolution bug the CLI surfaced

Running `index` on a package directory reported 5 resolved imports; running it on
the repository root reported 1,500, with call binding nearly doubling from 16.6%
to 29.3%. Same code, same files, different starting directory.

The cause: indexing *inside* a package makes its own absolute imports
unresolvable. Rooted at `graphify/graphify`, the specifier
`graphify.extractors.base` names `extractors/base.py`, but its leading segment is
the root itself and matches nothing. The resolver now strips that segment — but
only when it genuinely equals the root's directory name, so `os.path` cannot be
reduced to a local `path.py`. Indexing the package directory now resolves 354
imports and binds 22.4%.

This is the kind of defect that only shows up when you use the thing. It was
invisible in the library tests because they construct their corpora at the root.

## Not built: PyO3 bindings

The third Phase 5 deliverable. Not started, and I would rather say so than ship
a stub: the value of bindings is that existing Python tooling can call the store,
and that needs a `maturin`/wheel build and a Python-side test to mean anything.
The mapped index makes it cheaper to do well now than it would have been before —
the binding can open a store per call without a rebuild — but it is a real piece
of work, not a wrapper.

## Carried forward

1. **PyO3 bindings**, as above.
2. **Distance-bounded reachability.** The filter answers "is there any path";
   taint asks "within N hops". Unchanged from Phase 4.
3. **`compact` rewrites the whole store** — 29 s at 5M symbols for a one-file
   change. The segment design exists to avoid this, and it is now the largest
   gap between what the architecture promises and what it does.
4. **Framework-aware entrypoint detection.** Still name-based, so the live/dead
   split that makes findings triageable is coarser than it should be.
