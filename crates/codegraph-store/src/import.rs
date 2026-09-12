//! Importing an existing node-link index into the store.
//!
//! This exists so Phase 1 can be exercised on real corpora before any
//! extractor is written. It is also the migration path for an existing index.
//!
//! # The interesting part: minting keys
//!
//! A node-link index identifies symbols by an opaque id that is a derived
//! value — it encodes a path and a name, and it gets rewritten whenever
//! resolution learns something. We cannot carry those ids in, because the whole
//! point of [`SymbolKey`] is that identity stops moving.
//!
//! So the importer *re-derives* identity: it recovers each symbol's owning
//! scope from the `contains` / `method` edges, then mints a key from
//! `(path, kind, scope, name)`. The incoming id survives only as a lookup table
//! used to translate edge endpoints, and is discarded afterwards.

use std::collections::{BTreeMap, HashMap};

use codegraph_core::{
    Confidence, FileType, LocalId, Relation, SymbolKey, SymbolKeyParts, SymbolKind,
};
use serde_json::Value;

use crate::error::{Result, StoreError};
use crate::format::{Tier, node_flags};
use crate::store::Store;
use crate::writer::{Edge, SegmentBuilder, Symbol};

#[derive(Debug, Default, PartialEq, Eq)]
pub struct ImportStats {
    pub files: usize,
    pub symbols: usize,
    pub edges: usize,
    /// Edges whose endpoints did not both resolve to a symbol. Reported rather
    /// than swallowed: a jump here is a real signal.
    pub dangling: usize,
    /// Distinct incoming nodes that minted the same key. Non-zero means the
    /// source index held two symbols this scheme cannot tell apart.
    pub collisions: usize,
}

/// Normalise a path for storage: forward slashes, no `./` prefix.
fn norm_path(s: &str) -> String {
    let s = s.replace('\\', "/");
    s.strip_prefix("./").unwrap_or(&s).to_string()
}

/// Fold a name for lookup: strip a trailing `()`, lowercase.
fn norm_name(s: &str) -> String {
    s.trim().trim_end_matches("()").trim().to_lowercase()
}

/// Guess a [`SymbolKind`] from the shape of the incoming record.
///
/// The source index does not carry a kind, so this is inference, and it is
/// deliberately coarse: kind is part of the key, so being *consistent* matters
/// far more than being precise. A symbol classified the same way on every
/// import keeps a stable key even if the classification is arguably wrong.
fn infer_kind(label: &str, file_type: FileType, is_file_node: bool) -> SymbolKind {
    if is_file_node {
        return SymbolKind::File;
    }
    match file_type {
        FileType::Rationale => SymbolKind::Rationale,
        FileType::Concept => SymbolKind::Concept,
        _ => {
            if label.ends_with("()") {
                // A dotted prefix means it hangs off a type.
                if label.starts_with('.') || label.contains('.') {
                    SymbolKind::Method
                } else {
                    SymbolKind::Function
                }
            } else if label.chars().next().is_some_and(char::is_uppercase) {
                SymbolKind::Class
            } else {
                SymbolKind::Variable
            }
        }
    }
}

struct Raw {
    path: String,
    label: String,
    file_type: FileType,
    line: u32,
}

/// Import a node-link JSON document as one `ast`-tier segment.
pub fn import_node_link(json: &str, store: &mut Store) -> Result<ImportStats> {
    let v: Value = serde_json::from_str(json)
        .map_err(|e| StoreError::Manifest(format!("index is not valid JSON: {e}")))?;

    let nodes = v
        .get("nodes")
        .and_then(Value::as_array)
        .ok_or_else(|| StoreError::Manifest("index has no `nodes` array".into()))?;
    // `links` is the node-link convention; `edges` is what a raw writer emits.
    let links = v
        .get("links")
        .or_else(|| v.get("edges"))
        .and_then(Value::as_array)
        .ok_or_else(|| StoreError::Manifest("index has neither `links` nor `edges`".into()))?;

    // --- pass 1: raw facts, keyed by the incoming id ---
    let mut raw: Vec<Raw> = Vec::with_capacity(nodes.len());
    let mut index_of: HashMap<&str, usize> = HashMap::with_capacity(nodes.len());
    for n in nodes {
        let Some(id) = n.get("id").and_then(Value::as_str) else { continue };
        index_of.insert(id, raw.len());
        raw.push(Raw {
            path: norm_path(n.get("source_file").and_then(Value::as_str).unwrap_or("")),
            label: n.get("label").and_then(Value::as_str).unwrap_or("").to_string(),
            file_type: FileType::from_str_or_unknown(
                n.get("file_type").and_then(Value::as_str).unwrap_or("concept"),
            ),
            line: n
                .get("source_location")
                .and_then(Value::as_str)
                .and_then(|s| s.trim_start_matches('L').parse().ok())
                .unwrap_or(0),
        });
    }

    // --- pass 2: recover ownership from containment edges ---
    // `contains`/`method` run owner -> member, so inverting gives each symbol
    // its parent. First owner wins: two parents is a defect in the source, and
    // choosing deterministically beats choosing arbitrarily.
    let mut owner_of: HashMap<usize, usize> = HashMap::new();
    for e in links {
        let rel = e.get("relation").and_then(Value::as_str).unwrap_or("");
        if rel != "contains" && rel != "method" {
            continue;
        }
        let (Some(s), Some(t)) = (
            e.get("source").and_then(Value::as_str),
            e.get("target").and_then(Value::as_str),
        ) else {
            continue;
        };
        if let (Some(&si), Some(&ti)) = (index_of.get(s), index_of.get(t))
            && si != ti
        {
            owner_of.entry(ti).or_insert(si);
        }
    }

    // A symbol whose label is its file's own name stands for the file itself.
    let is_file_node = |i: usize| -> bool {
        let r = &raw[i];
        if r.path.is_empty() || r.label.is_empty() {
            return false;
        }
        let base = r.path.rsplit('/').next().unwrap_or(&r.path);
        r.label.eq_ignore_ascii_case(base) || r.label.eq_ignore_ascii_case(&r.path)
    };

    // Scope chain, outermost first, stopping at the file node — the path is
    // already half the key, so repeating the file name in it would be noise.
    // Bounded, because a malformed index can contain an ownership cycle.
    let scope_of = |i: usize| -> Vec<String> {
        let mut parts = Vec::new();
        let mut cur = i;
        for _ in 0..16 {
            let Some(&owner) = owner_of.get(&cur) else { break };
            if is_file_node(owner) {
                break;
            }
            let name = norm_name(&raw[owner].label);
            if name.is_empty() {
                break;
            }
            parts.push(name);
            cur = owner;
        }
        parts.reverse();
        parts
    };

    // --- pass 3: files ---
    let mut builder = SegmentBuilder::new(store.next_segment_id(), Tier::Ast);
    let mut file_ids: BTreeMap<String, codegraph_core::FileId> = BTreeMap::new();
    let mut paths: Vec<String> = raw.iter().map(|r| r.path.clone()).collect();
    paths.sort_unstable();
    paths.dedup();
    for p in &paths {
        // The source index carries no content hash or mtime; leaving them zero
        // is honest. An extractor fills them in for real.
        let id = builder.add_file(p, 0, 0, 0, 0);
        file_ids.insert(p.clone(), id);
    }

    // --- pass 4: symbols ---
    let mut local_of: HashMap<usize, LocalId> = HashMap::with_capacity(raw.len());
    let mut key_of: HashMap<usize, SymbolKey> = HashMap::with_capacity(raw.len());
    let mut seen: HashMap<SymbolKey, usize> = HashMap::with_capacity(raw.len());
    // base key -> next free disambiguator, so placing a collision group is linear
    let mut next_disambiguator: HashMap<SymbolKey, u32> = HashMap::new();
    let mut collisions = 0usize;

    // Indexed rather than iterated on purpose: `scope_of` and `is_file_node`
    // take an index because they walk to *other* rows of `raw`, so a borrowing
    // iterator over the same vector would conflict with them.
    #[allow(clippy::needless_range_loop)]
    for i in 0..raw.len() {
        let scope = scope_of(i);
        let scope_refs: Vec<&str> = scope.iter().map(String::as_str).collect();
        let file_node = is_file_node(i);
        let kind = infer_kind(&raw[i].label, raw[i].file_type, file_node);
        let name = norm_name(&raw[i].label);

        // A genuine duplicate gets a disambiguator rather than being dropped.
        // Deterministic, because `raw` is in document order and the source
        // canonicalises that order.
        //
        // The next free disambiguator is remembered per base key. Probing from
        // zero each time would be quadratic in the size of a collision group —
        // a real corpus with 33 identically-named nodes cost 528 hash
        // computations to place them.
        let base = SymbolKey::new(SymbolKeyParts {
            repo: "",
            path: &raw[i].path,
            kind,
            scope: &scope_refs,
            name: &name,
            disambiguator: 0,
        });
        let next = next_disambiguator.entry(base).or_insert(0u32);
        let disambiguator = *next;
        *next += 1;
        if disambiguator > 0 {
            // Counts *symbols that had to be disambiguated*, not probe
            // attempts — one per extra member of a collision group.
            collisions += 1;
        }
        let key = if disambiguator == 0 {
            base
        } else {
            SymbolKey::new(SymbolKeyParts {
                repo: "",
                path: &raw[i].path,
                kind,
                scope: &scope_refs,
                name: &name,
                disambiguator,
            })
        };
        debug_assert!(!seen.contains_key(&key), "disambiguator failed to separate keys");
        seen.insert(key, i);

        let flags = if file_node { node_flags::FILE_NODE } else { 0 };
        let local = builder.add_symbol(Symbol {
            key,
            file: *file_ids.get(&raw[i].path).expect("path was interned above"),
            name: &raw[i].label,
            norm_name: &name,
            kind,
            file_type: raw[i].file_type,
            line: raw[i].line,
            flags,
            hash: 0,
        });
        local_of.insert(i, local);
        key_of.insert(i, key);
    }

    // --- pass 5: edges ---
    let mut dangling = 0usize;
    let mut edges = 0usize;
    for e in links {
        let (Some(s), Some(t)) = (
            e.get("source").and_then(Value::as_str),
            e.get("target").and_then(Value::as_str),
        ) else {
            continue;
        };
        let (Some(&si), Some(&ti)) = (index_of.get(s), index_of.get(t)) else {
            dangling += 1;
            continue;
        };
        builder.add_edge(Edge {
            source: local_of[&si],
            target: key_of[&ti],
            rel: Relation::from_str_or_unknown(
                e.get("relation").and_then(Value::as_str).unwrap_or(""),
            ),
            conf: Confidence::from_str_or_unknown(
                e.get("confidence").and_then(Value::as_str).unwrap_or(""),
            ),
            line: e
                .get("source_location")
                .and_then(Value::as_str)
                .and_then(|s| s.trim_start_matches('L').parse().ok())
                .unwrap_or(0),
            context: e.get("context").and_then(Value::as_str),
            flags: 0,
        });
        edges += 1;
    }

    let stats = ImportStats {
        files: paths.len(),
        symbols: builder.symbol_count(),
        edges,
        dangling,
        collisions,
    };

    // Use the id already baked into the builder's header so the two cannot drift.
    let id = builder.segment_id();
    store.commit_segment(id, builder, Tier::Ast, &paths)?;
    Ok(stats)
}
