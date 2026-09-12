//! Differential verification for code indexes.
//!
//! The point of this crate is to give every later phase something to be measured
//! against. It normalises an index — ours, or an existing one we can import —
//! into a comparison form, and diffs two of them.
//!
//! # Why the comparison key is not the index's own node id
//!
//! Node ids in this problem space are derived values: they are minted from a
//! path plus a symbol name before cross-file resolution has run, and every
//! resolution pass that learns something has to rewrite them. Two indexes of the
//! same tree can therefore be semantically identical and share not one id.
//!
//! So a diff keyed on ids measures the id scheme, not the extraction. We key on
//! the **natural** identity instead — `(source_file, qualified name)` for a
//! symbol, and `(source, relation, target)` in those terms for an edge — which
//! is stable across id schemes and is what a human means by "the same symbol".
//!
//! # Why the name has to be qualified
//!
//! `(file, bare name)` is not injective. A file with five classes has five
//! `__init__` methods, and extractors label them `.__init__` with no class
//! prefix — on a real corpus that silently collapsed 26% of symbols, which
//! would make the harness hide exactly the regressions it exists to catch. So
//! the owning scope is recovered from the `contains`/`method` edges and folded
//! into the key, giving `ClassA.__init__` and `ClassB.__init__`. Any collision
//! that survives is counted and reported rather than merged in silence.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

/// A symbol's natural identity: the file it lives in, and its name.
pub type SymbolKey = (String, String);

/// The attributes a diff actually compares. Deliberately a small set: these are
/// the fields a downstream consumer can observe. Anything derived (degree,
/// community, centrality) is excluded — it is a function of the graph, so
/// comparing it would report one upstream difference many times over.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SymbolRow {
    pub file_type: String,
    /// `None` when the index records no location for this symbol.
    pub line: Option<u32>,
}

/// An edge in natural terms. `source`/`target` are `SymbolKey`s flattened to
/// strings so the whole row is `Ord` and lands in a `BTreeSet`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct EdgeRow {
    pub source: String,
    pub relation: String,
    pub target: String,
    pub confidence: String,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Snapshot {
    pub symbols: BTreeMap<String, SymbolRow>,
    pub edges: BTreeSet<EdgeRow>,
    /// Symbols an edge referenced that no symbol row defines. Tracked rather
    /// than dropped silently: a jump in dangling references is a real
    /// regression signal even when symbol and edge counts look unchanged.
    pub dangling: usize,
    /// Distinct symbols that still shared a natural key after qualification and
    /// were therefore merged. Never silently zero: a harness that folds symbols
    /// together hides differences, so this is surfaced on every summary.
    pub collisions: usize,
}

fn flat(file: &str, name: &str) -> String {
    format!("{file}\u{0}{name}")
}

/// Normalise a symbol name for comparison: strip a trailing `()` and fold case.
///
/// Extractors disagree about whether a function's name carries its parens, and
/// that disagreement is cosmetic. Folding case as well means a diff does not
/// light up over a casing change in one extractor's output.
fn norm_name(s: &str) -> String {
    s.trim().trim_end_matches("()").trim().to_lowercase()
}

/// Normalise a path: forward slashes, no leading `./`.
fn norm_path(s: &str) -> String {
    let s = s.replace('\\', "/");
    s.strip_prefix("./").unwrap_or(&s).to_string()
}

impl Snapshot {
    /// Import a node-link JSON index (the `{nodes, links|edges}` shape).
    pub fn from_node_link(json: &str) -> Result<Self> {
        let v: serde_json::Value =
            serde_json::from_str(json).context("index is not valid JSON")?;

        let nodes = v
            .get("nodes")
            .and_then(|n| n.as_array())
            .context("index has no `nodes` array")?;

        // Writers disagree on the edge key: `links` is the node-link
        // convention, `edges` is what a raw writer emits. Accept both.
        let edges = v
            .get("links")
            .or_else(|| v.get("edges"))
            .and_then(|e| e.as_array())
            .context("index has neither `links` nor `edges`")?;

        // Pass 1: raw per-id facts, before any qualification.
        let mut file_of: BTreeMap<&str, String> = BTreeMap::new();
        let mut name_of: BTreeMap<&str, String> = BTreeMap::new();
        for n in nodes {
            let Some(id) = n.get("id").and_then(|x| x.as_str()) else { continue };
            file_of.insert(
                id,
                norm_path(n.get("source_file").and_then(|x| x.as_str()).unwrap_or("")),
            );
            name_of.insert(
                id,
                norm_name(n.get("label").and_then(|x| x.as_str()).unwrap_or("")),
            );
        }

        // Pass 2: recover the owning scope. `contains`/`method` edges run
        // owner -> member, so inverting them gives each symbol its parent.
        // Only the *first* owner is kept: a symbol with two parents is a defect
        // in the index, and picking deterministically beats picking arbitrarily.
        let mut owner_of: BTreeMap<&str, &str> = BTreeMap::new();
        for e in edges {
            let rel = e.get("relation").and_then(|x| x.as_str()).unwrap_or("");
            if rel != "contains" && rel != "method" {
                continue;
            }
            let (Some(s), Some(t)) = (
                e.get("source").and_then(|x| x.as_str()),
                e.get("target").and_then(|x| x.as_str()),
            ) else {
                continue;
            };
            if s != t {
                owner_of.entry(t).or_insert(s);
            }
        }

        // A file node stands for the file itself, so it adds nothing to a key
        // that already carries the path — qualifying `.foo` as `a.py.foo`
        // would be noise. Recognise it by its label matching the file's own
        // name, which is how these indexes mark it.
        let is_file_node = |id: &str| -> bool {
            let (Some(f), Some(nm)) = (file_of.get(id), name_of.get(id)) else {
                return false;
            };
            if f.is_empty() || nm.is_empty() {
                return false;
            }
            let base = f.rsplit('/').next().unwrap_or(f).to_lowercase();
            *nm == base || *nm == f.to_lowercase()
        };

        // Walk owners up to the file node, collecting scope names. Bounded: a
        // malformed index can contain an ownership cycle, and this must not hang.
        let qualified = |id: &str| -> String {
            let mut parts = Vec::new();
            let mut cur = id;
            for _ in 0..16 {
                let Some(&owner) = owner_of.get(cur) else { break };
                if is_file_node(owner) {
                    break;
                }
                match name_of.get(owner) {
                    Some(n) if !n.is_empty() => parts.push(n.clone()),
                    _ => break,
                }
                cur = owner;
            }
            parts.reverse();
            let own = name_of.get(id).cloned().unwrap_or_default();
            if parts.is_empty() {
                own
            } else {
                // The member label is often already dot-prefixed (`.__init__`),
                // so join without doubling the separator.
                format!("{}{}{}", parts.join("."), if own.starts_with('.') { "" } else { "." }, own)
            }
        };

        let mut symbols: BTreeMap<String, SymbolRow> = BTreeMap::new();
        // id -> natural key, so edges (which reference ids) can be translated.
        let mut by_id: BTreeMap<&str, String> = BTreeMap::new();
        let mut collisions = 0usize;

        for n in nodes {
            let Some(id) = n.get("id").and_then(|x| x.as_str()) else { continue };
            let file = file_of.get(id).cloned().unwrap_or_default();
            let key = flat(&file, &qualified(id));
            by_id.insert(id, key.clone());

            // "L42" -> 42. A missing or unparseable location is None, not 0 —
            // 0 would compare equal to a real line and hide a difference.
            let line = n
                .get("source_location")
                .and_then(|x| x.as_str())
                .and_then(|s| s.trim_start_matches('L').parse::<u32>().ok());

            let row = SymbolRow {
                file_type: n
                    .get("file_type")
                    .and_then(|x| x.as_str())
                    .unwrap_or("concept")
                    .to_string(),
                line,
            };
            if symbols.insert(key, row).is_some() {
                collisions += 1;
            }
        }

        let mut out = BTreeSet::new();
        let mut dangling = 0usize;
        for e in edges {
            let (Some(s), Some(t)) = (
                e.get("source").and_then(|x| x.as_str()),
                e.get("target").and_then(|x| x.as_str()),
            ) else {
                continue;
            };
            let (Some(sk), Some(tk)) = (by_id.get(s), by_id.get(t)) else {
                dangling += 1;
                continue;
            };
            out.insert(EdgeRow {
                source: sk.clone(),
                relation: e
                    .get("relation")
                    .and_then(|x| x.as_str())
                    .unwrap_or("")
                    .to_string(),
                target: tk.clone(),
                confidence: e
                    .get("confidence")
                    .and_then(|x| x.as_str())
                    .unwrap_or("")
                    .to_string(),
            });
        }

        Ok(Snapshot { symbols, edges: out, dangling, collisions })
    }
}

#[derive(Debug, Default)]
pub struct Report {
    pub symbols_added: Vec<String>,
    pub symbols_dropped: Vec<String>,
    /// `(key, before, after)`
    pub symbols_changed: Vec<(String, SymbolRow, SymbolRow)>,
    pub edges_added: Vec<EdgeRow>,
    pub edges_dropped: Vec<EdgeRow>,
    pub dangling_before: usize,
    pub dangling_after: usize,
    pub collisions_before: usize,
    pub collisions_after: usize,
}

impl Report {
    /// True when nothing differs. The caller decides whether a difference is a
    /// regression — this crate reports, it does not judge.
    pub fn is_clean(&self) -> bool {
        self.symbols_added.is_empty()
            && self.symbols_dropped.is_empty()
            && self.symbols_changed.is_empty()
            && self.edges_added.is_empty()
            && self.edges_dropped.is_empty()
    }
}

/// Diff `before` against `after`. "Added" means present in `after` only.
pub fn diff(before: &Snapshot, after: &Snapshot) -> Report {
    let mut r = Report {
        dangling_before: before.dangling,
        dangling_after: after.dangling,
        collisions_before: before.collisions,
        collisions_after: after.collisions,
        ..Default::default()
    };

    for (k, a) in &before.symbols {
        match after.symbols.get(k) {
            None => r.symbols_dropped.push(k.clone()),
            Some(b) if b != a => r.symbols_changed.push((k.clone(), a.clone(), b.clone())),
            Some(_) => {}
        }
    }
    for k in after.symbols.keys() {
        if !before.symbols.contains_key(k) {
            r.symbols_added.push(k.clone());
        }
    }

    r.edges_dropped = before.edges.difference(&after.edges).cloned().collect();
    r.edges_added = after.edges.difference(&before.edges).cloned().collect();
    r
}

// ---------------------------------------------------------------------------
// Reading a store back into the same comparison form
// ---------------------------------------------------------------------------

impl Snapshot {
    /// Build a snapshot from a store, in the same natural-key form
    /// [`Snapshot::from_node_link`] produces.
    ///
    /// This is what makes the round-trip provable: import a source index, read
    /// the store back, and the two snapshots must be identical. Any difference
    /// is either an import bug or a storage bug, and the diff names the symbols
    /// and edges that moved.
    ///
    /// The scope is recovered here exactly as the JSON side recovers it — by
    /// walking `contains`/`method` edges — rather than read from a column. The
    /// store deliberately keeps `norm_name` as the *bare* folded name, because
    /// that is what a user searching for `__init__` needs to match; qualifying
    /// it in storage would break lookup to make this one comparison easier.
    pub fn from_store(store: &codegraph_store::Store) -> Result<Self> {
        use codegraph_core::{FileType, Relation, RelationMask};

        // Through the view, so a store holding a base plus deltas snapshots as
        // the graph it answers with: dead rows skipped, forwarded and keyed
        // edges resolved. An edge the view cannot resolve is what `dangling`
        // counts.
        let view = store.view();
        let scope_rels = RelationMask::of(&[Relation::Contains, Relation::Method]);
        let mut symbols = BTreeMap::new();
        let mut edges = BTreeSet::new();
        let mut collisions = 0usize;
        let mut dangling = 0usize;
        // store-wide id -> natural key
        let mut key_of: BTreeMap<u32, String> = BTreeMap::new();

        let is_file_node = |id: codegraph_core::LocalId| -> Result<bool> {
            Ok(view.flags(id)? & codegraph_store::node_flags::FILE_NODE != 0)
        };

        // Invert containment: owner -> member becomes member -> owner.
        let mut owner_of: BTreeMap<u32, u32> = BTreeMap::new();
        for id in view.ids() {
            for e in view.out_edges(id, scope_rels)? {
                if e.node != id {
                    owner_of.entry(e.node.get()).or_insert(id.get());
                }
            }
        }

        // Walk to the file node, collecting scope names outermost first.
        // Bounded, so a cyclic ownership chain cannot hang the reader.
        let qualified = |id: codegraph_core::LocalId| -> Result<String> {
            let mut parts: Vec<&str> = Vec::new();
            let mut cur = id.get();
            for _ in 0..16 {
                let Some(&owner) = owner_of.get(&cur) else { break };
                let o = codegraph_core::LocalId::new(owner);
                if is_file_node(o)? {
                    break;
                }
                let nm = view.norm_name(o)?;
                if nm.is_empty() {
                    break;
                }
                parts.push(nm);
                cur = owner;
            }
            parts.reverse();
            let own = view.norm_name(id)?;
            Ok(if parts.is_empty() {
                own.to_string()
            } else {
                let sep = if own.starts_with('.') { "" } else { "." };
                format!("{}{sep}{own}", parts.join("."))
            })
        };

        for id in view.ids() {
            // A package stub is attached to whichever file first imported it,
            // which depends on build order and on whether it arrived in a
            // delta. Its identity is its name alone — as its key is.
            let external = view.flags(id)? & codegraph_store::node_flags::EXTERNAL != 0;
            let k = flat(if external { "" } else { view.path(id)? }, &qualified(id)?);
            key_of.insert(id.get(), k.clone());
            let line = view.line(id)?;
            let row = SymbolRow {
                file_type: FileType::from_u8(view.file_type_raw(id)?).as_str().to_string(),
                line: (line != 0).then_some(line),
            };
            if symbols.insert(k, row).is_some() {
                collisions += 1;
            }
        }

        for id in view.ids() {
            let source = &key_of[&id.get()];
            for e in view.out_edges(id, RelationMask::ALL)? {
                let Some(target) = key_of.get(&e.node.get()) else {
                    dangling += 1;
                    continue;
                };
                edges.insert(EdgeRow {
                    source: source.clone(),
                    relation: e.relation.as_str().to_string(),
                    target: target.clone(),
                    confidence: e.confidence.as_str().to_string(),
                });
            }
        }
        // Keyed edges whose target is nowhere in the store stay unresolved;
        // count them rather than pretend they are absent.
        for si in 0..view.segment_count() {
            let (seg, _) = view.segment(si);
            dangling += (0..seg.ext_edges()?.len()).filter(|&x| view.ext_target(si, x).is_none()).count();
        }

        Ok(Snapshot { symbols, edges, dangling, collisions })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: &str = r#"{
        "nodes": [
            {"id": "a_1", "label": "foo()", "source_file": "src/a.py",
             "source_location": "L4", "file_type": "code"},
            {"id": "b_1", "label": "Bar",   "source_file": "src/b.py",
             "source_location": "L9", "file_type": "code"}
        ],
        "links": [
            {"source": "a_1", "target": "b_1", "relation": "calls",
             "confidence": "EXTRACTED"}
        ]
    }"#;

    #[test]
    fn imports_node_link() {
        let s = Snapshot::from_node_link(A).unwrap();
        assert_eq!(s.symbols.len(), 2);
        assert_eq!(s.edges.len(), 1);
        assert_eq!(s.dangling, 0);
    }

    #[test]
    fn a_snapshot_matches_itself() {
        let s = Snapshot::from_node_link(A).unwrap();
        let t = Snapshot::from_node_link(A).unwrap();
        assert!(diff(&s, &t).is_clean());
    }

    #[test]
    fn accepts_the_edges_key_as_well_as_links() {
        let s = Snapshot::from_node_link(&A.replace("\"links\"", "\"edges\"")).unwrap();
        assert_eq!(s.edges.len(), 1);
    }

    /// The property this whole crate exists for: renaming every id must not
    /// register as a difference, because an id is a derived value.
    #[test]
    fn is_blind_to_the_id_scheme() {
        let renamed = A.replace("a_1", "zzz_completely_different").replace("b_1", "qqq_other");
        let before = Snapshot::from_node_link(A).unwrap();
        let after = Snapshot::from_node_link(&renamed).unwrap();
        assert!(diff(&before, &after).is_clean(), "id rename leaked into the diff");
    }

    /// ...but a real change must register.
    #[test]
    fn sees_a_moved_symbol() {
        let moved = A.replace("\"L4\"", "\"L7\"");
        let before = Snapshot::from_node_link(A).unwrap();
        let after = Snapshot::from_node_link(&moved).unwrap();
        let r = diff(&before, &after);
        assert!(!r.is_clean());
        assert_eq!(r.symbols_changed.len(), 1);
        assert_eq!(r.symbols_changed[0].1.line, Some(4));
        assert_eq!(r.symbols_changed[0].2.line, Some(7));
    }

    #[test]
    fn sees_a_dropped_edge() {
        let no_edge = A.replace(
            r#"{"source": "a_1", "target": "b_1", "relation": "calls",
             "confidence": "EXTRACTED"}"#,
            "",
        );
        let before = Snapshot::from_node_link(A).unwrap();
        let after = Snapshot::from_node_link(&no_edge).unwrap();
        let r = diff(&before, &after);
        assert_eq!(r.edges_dropped.len(), 1);
        assert_eq!(r.edges_added.len(), 0);
    }

    #[test]
    fn trailing_parens_and_case_do_not_split_a_symbol() {
        let variant = A.replace("\"foo()\"", "\"Foo\"");
        let before = Snapshot::from_node_link(A).unwrap();
        let after = Snapshot::from_node_link(&variant).unwrap();
        assert!(diff(&before, &after).is_clean());
    }

    /// The regression this qualification exists for. Two classes in one file
    /// each with an `__init__`: an unqualified key folds them into one symbol
    /// and the harness goes blind to half the file.
    const TWO_CLASSES: &str = r#"{
        "nodes": [
            {"id": "f",  "label": "a.py",     "source_file": "src/a.py",
             "source_location": "L1", "file_type": "code"},
            {"id": "c1", "label": "Alpha",    "source_file": "src/a.py",
             "source_location": "L2", "file_type": "code"},
            {"id": "c2", "label": "Beta",     "source_file": "src/a.py",
             "source_location": "L9", "file_type": "code"},
            {"id": "m1", "label": ".__init__", "source_file": "src/a.py",
             "source_location": "L3", "file_type": "code"},
            {"id": "m2", "label": ".__init__", "source_file": "src/a.py",
             "source_location": "L10", "file_type": "code"}
        ],
        "links": [
            {"source": "f",  "target": "c1", "relation": "contains", "confidence": "EXTRACTED"},
            {"source": "f",  "target": "c2", "relation": "contains", "confidence": "EXTRACTED"},
            {"source": "c1", "target": "m1", "relation": "method",   "confidence": "EXTRACTED"},
            {"source": "c2", "target": "m2", "relation": "method",   "confidence": "EXTRACTED"}
        ]
    }"#;

    #[test]
    fn same_named_methods_of_different_classes_stay_distinct() {
        let s = Snapshot::from_node_link(TWO_CLASSES).unwrap();
        assert_eq!(s.collisions, 0, "qualification failed; symbols were merged");
        assert_eq!(s.symbols.len(), 5, "expected file + 2 classes + 2 methods");
        let names: Vec<&str> = s.symbols.keys().filter_map(|k| k.split('\u{0}').nth(1)).collect();
        assert!(names.contains(&"alpha.__init__"), "got {names:?}");
        assert!(names.contains(&"beta.__init__"), "got {names:?}");
    }

    /// The file node must not leak into the qualifier — `a.py.alpha` would be
    /// noise, since the path is already half the key.
    #[test]
    fn the_file_node_is_not_part_of_the_qualifier() {
        let s = Snapshot::from_node_link(TWO_CLASSES).unwrap();
        let names: Vec<&str> = s.symbols.keys().filter_map(|k| k.split('\u{0}').nth(1)).collect();
        assert!(names.contains(&"alpha"), "got {names:?}");
        assert!(!names.iter().any(|n| n.starts_with("a.py.")), "file node leaked: {names:?}");
    }

    /// A malformed index can contain an ownership cycle. The walk is bounded,
    /// so this must terminate rather than hang.
    #[test]
    fn an_ownership_cycle_terminates() {
        let cyclic = r#"{
            "nodes": [
                {"id": "x", "label": "X", "source_file": "s.py", "source_location": "L1", "file_type": "code"},
                {"id": "y", "label": "Y", "source_file": "s.py", "source_location": "L2", "file_type": "code"}
            ],
            "links": [
                {"source": "x", "target": "y", "relation": "contains", "confidence": "EXTRACTED"},
                {"source": "y", "target": "x", "relation": "contains", "confidence": "EXTRACTED"}
            ]
        }"#;
        let s = Snapshot::from_node_link(cyclic).unwrap();
        assert_eq!(s.symbols.len(), 2);
    }

    #[test]
    fn counts_dangling_edge_endpoints() {
        let broken = A.replace("\"target\": \"b_1\"", "\"target\": \"nonexistent\"");
        let s = Snapshot::from_node_link(&broken).unwrap();
        assert_eq!(s.dangling, 1);
        assert_eq!(s.edges.len(), 0);
    }
}
