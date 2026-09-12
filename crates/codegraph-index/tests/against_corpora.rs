//! The index, checked against brute force on real corpus data.
//!
//! Every derived structure here replaces a computation the query engine would
//! otherwise do directly. These tests assert the shortcut agrees with the long
//! way round — on real graphs, not fixtures.

use std::collections::VecDeque;

use codegraph_core::{LocalId, RelationMask};
use codegraph_index::{IndexColumns, IndexData, IndexQuery};
use codegraph_index::build::REACHABILITY_RELATIONS;
use codegraph_store::{Store, compact, import_node_link};

fn corpora() -> Vec<(String, String)> {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("corpora");
    let mut paths: Vec<_> = std::fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("reading {}: {e}", dir.display()))
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|e| e == "json"))
        .collect();
    paths.sort();
    assert!(!paths.is_empty(), "no corpora in {}", dir.display());
    paths
        .into_iter()
        .map(|p| {
            (
                p.file_stem().unwrap_or_default().to_string_lossy().to_string(),
                std::fs::read_to_string(&p).expect("read"),
            )
        })
        .collect()
}

/// Import, compact, and index one corpus.
fn prepare(json: &str) -> (tempfile::TempDir, Store, IndexData) {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut store = Store::create(dir.path()).expect("create");
    import_node_link(json, &mut store).expect("import");
    compact(&mut store).expect("compact");
    let index = IndexData::build(&store).expect("build index");
    (dir, store, index)
}

#[test]
fn degrees_match_a_direct_count() {
    for (name, json) in corpora() {
        let (_d, store, index) = prepare(&json);
        let (_, seg) = store.segments().next().unwrap();
        assert_eq!(index.node_count, seg.node_count(), "{name}: node count");

        for i in 0..seg.node_count() {
            let n = LocalId::new(i as u32);
            let out = seg.out_edges(n, RelationMask::ALL).unwrap().count() as u32;
            let inn = seg.in_edges(n, RelationMask::ALL).unwrap().count() as u32;
            assert_eq!(index.degree_out[i], out, "{name}: out-degree of node {i}");
            assert_eq!(index.degree_in[i], inn, "{name}: in-degree of node {i}");
            assert_eq!(index.degree_total[i], out + inn, "{name}: total degree of node {i}");
        }
    }
}

/// Ground truth: BFS over the same relation mask the index used.
fn bfs_reachable(seg: &codegraph_store::Segment, src: u32, n: usize) -> Vec<bool> {
    let mut seen = vec![false; n];
    let mut q = VecDeque::new();
    seen[src as usize] = true;
    q.push_back(src);
    while let Some(v) = q.pop_front() {
        for e in seg.out_edges(LocalId::new(v), REACHABILITY_RELATIONS).unwrap() {
            let t = e.target.get();
            if (t as usize) < n && !seen[t as usize] {
                seen[t as usize] = true;
                q.push_back(t);
            }
        }
    }
    seen
}

/// **The soundness property, on real data.** A false negative would make a
/// taint query silently miss a real path.
#[test]
fn reachability_never_reports_a_false_negative() {
    for (name, json) in corpora() {
        let (_d, store, index) = prepare(&json);
        let (_, seg) = store.segments().next().unwrap();
        let n = seg.node_count();

        // Every source on the smaller corpora; a sample on the large one, since
        // this is O(V * (V + E)).
        let step = if n > 400 { n / 200 } else { 1 };
        for src in (0..n).step_by(step.max(1)) {
            let truth = bfs_reachable(seg, src as u32, n);
            for (dst, &reachable) in truth.iter().enumerate() {
                if reachable {
                    assert!(
                        index.maybe_reaches(LocalId::new(src as u32), LocalId::new(dst as u32)),
                        "{name}: {src} reaches {dst} but the index rejected it"
                    );
                }
            }
        }
    }
}

/// And it must still reject a useful share of the unreachable pairs, or it is
/// sound but worthless.
#[test]
fn reachability_rejects_most_unreachable_pairs() {
    for (name, json) in corpora() {
        let (_d, store, index) = prepare(&json);
        let (_, seg) = store.segments().next().unwrap();
        let n = seg.node_count();
        if n < 20 {
            continue; // too small for the rate to mean anything
        }

        let step = if n > 400 { n / 100 } else { 1 };
        let (mut unreachable, mut rejected) = (0usize, 0usize);
        for src in (0..n).step_by(step.max(1)) {
            let truth = bfs_reachable(seg, src as u32, n);
            for (dst, &r) in truth.iter().enumerate() {
                if !r {
                    unreachable += 1;
                    if !index.maybe_reaches(LocalId::new(src as u32), LocalId::new(dst as u32)) {
                        rejected += 1;
                    }
                }
            }
        }
        let rate = rejected as f64 / unreachable.max(1) as f64;
        println!("{name:<22} rejects {:.1}% of {unreachable} unreachable pairs", rate * 100.0);
        assert!(rate > 0.80, "{name}: rejected only {:.1}%", rate * 100.0);
    }
}

#[test]
fn exact_name_lookup_finds_every_symbol() {
    for (name, json) in corpora() {
        let (_d, store, index) = prepare(&json);
        let (_, seg) = store.segments().next().unwrap();
        let norms = seg.node_norm_names().unwrap();

        for (i, &norm) in norms.iter().enumerate() {
            let n = seg.string(norm);
            if n.is_empty() {
                continue;
            }
            let hits = index.by_exact_name(n);
            assert!(
                hits.contains(&(i as u32)),
                "{name}: symbol {i} named {n:?} is not under its own name"
            );
        }
        assert!(index.by_exact_name("\u{1}definitely-not-a-symbol").is_empty());
    }
}

#[test]
fn prefix_lookup_is_consistent_with_exact_lookup() {
    for (_name, json) in corpora() {
        let (_d, _store, index) = prepare(&json);
        for key in index.name_keys.iter().take(50) {
            let exact = index.by_exact_name(key);
            let prefix = index.by_name_prefix(key);
            for id in exact {
                assert!(prefix.contains(&id), "prefix lookup lost an exact match for {key:?}");
            }
        }
    }
}

/// The prefilter contract: it may over-approximate, but it must never miss.
#[test]
fn the_trigram_prefilter_never_misses_a_match() {
    for (name, json) in corpora() {
        let (_d, store, index) = prepare(&json);
        let (_, seg) = store.segments().next().unwrap();
        let norms = seg.node_norm_names().unwrap();
        let files = seg.node_files().unwrap();

        // Reconstruct the same search text the builder indexed.
        let text_of = |i: usize| {
            format!("{}\0{}", seg.string(norms[i]), seg.file_path(files[i]).to_lowercase())
        };

        // Probe with substrings drawn from real symbols, so the needles are
        // ones that genuinely occur.
        let mut probes: Vec<String> = Vec::new();
        for i in (0..seg.node_count()).step_by(7).take(40) {
            let n = seg.string(norms[i]);
            if n.len() >= 4 {
                probes.push(n[..4].to_string());
            }
        }
        probes.push("init".into());
        probes.push(".py".into());

        for probe in probes {
            let Some(cands) = index.trigram_candidates(&probe) else { continue };
            let cand_set: std::collections::HashSet<u32> = cands.into_iter().collect();
            for i in 0..seg.node_count() {
                if text_of(i).contains(&probe.to_lowercase()) {
                    assert!(
                        cand_set.contains(&(i as u32)),
                        "{name}: {probe:?} occurs in symbol {i} but the prefilter missed it"
                    );
                }
            }
        }
    }
}

/// A needle shorter than a trigram must say "cannot filter" rather than
/// "nothing matches" — the two are very different answers.
#[test]
fn a_short_needle_disables_the_filter_rather_than_rejecting() {
    let (_name, json) = corpora().into_iter().next().unwrap();
    let (_d, _store, index) = prepare(&json);
    assert!(index.trigram_candidates("ab").is_none());
    assert!(index.trigram_candidates("").is_none());
    // A trigram that occurs nowhere is a real "nothing matches".
    assert_eq!(index.trigram_candidates("\u{1}\u{2}\u{3}"), Some(vec![]));
}

#[test]
fn the_hub_threshold_is_a_real_percentile() {
    for (name, json) in corpora() {
        let (_d, _store, index) = prepare(&json);
        if index.node_count == 0 {
            continue;
        }
        let above = index.degree_total.iter().filter(|d| **d >= index.hub_threshold).count();
        assert!(
            above < index.node_count.max(1),
            "{name}: every node counts as a hub"
        );
        assert!(index.hub_threshold >= codegraph_index::MIN_HUB_THRESHOLD);
    }
}

#[test]
fn building_the_index_is_deterministic() {
    let (_name, json) = corpora().into_iter().next().unwrap();
    let (_d1, s1, i1) = prepare(&json);
    let (_d2, s2, i2) = prepare(&json);
    assert_eq!(s1.symbol_count(), s2.symbol_count());
    assert_eq!(i1, i2, "two builds of the same corpus produced different indexes");
}

#[test]
fn a_multi_segment_store_indexes_like_its_compacted_form() {
    let (_name, json) = corpora().into_iter().next().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let mut store = Store::create(dir.path()).unwrap();
    // Two segments covering *different* files, so neither supersedes the other
    // and the store genuinely holds two.
    import_node_link(&json, &mut store).unwrap();
    let other = json.replace("\"source_file\": \"", "\"source_file\": \"other/");
    import_node_link(&other, &mut store).unwrap();
    assert!(
        store.manifest().segments.len() > 1,
        "test needs a multi-segment store to be meaningful"
    );

    // Degree and name postings per key, before and after compaction. The ids
    // differ — compaction renumbers — so the comparison is in key space.
    let snapshot = |store: &Store, index: &IndexData| {
        let view = store.view();
        let mut out: Vec<(codegraph_core::SymbolKey, u32, usize)> = view
            .ids()
            .map(|id| {
                let name = view.norm_name(id).unwrap();
                (view.key(id).unwrap(), index.degree_total[id.index()], index.by_exact_name(name).len())
            })
            .collect();
        out.sort();
        out
    };
    let before = IndexData::build(&store).expect("a multi-segment store must index");
    let snap_before = snapshot(&store, &before);
    compact(&mut store).unwrap();
    let after = IndexData::build(&store).unwrap();
    assert_eq!(snapshot(&store, &after), snap_before, "the view and the compacted segment disagree");
    assert_eq!(before.scc_count - (before.node_count - snap_before.len()), after.scc_count,
        "component count differs once dead singleton rows are discounted");
}

// --- persistence ---

#[test]
fn the_index_round_trips_through_a_file() {
    for (name, json) in corpora() {
        let (dir, _store, index) = prepare(&json);
        let path = dir.path().join("index.cgidx");
        index.write(&path, 1).unwrap_or_else(|e| panic!("{name}: write: {e}"));
        let back = IndexData::read(&path, 1).unwrap_or_else(|e| panic!("{name}: read: {e}"));
        assert_eq!(index, back, "{name}: index changed across a round trip");
    }
}

/// An index built for another generation describes data that may no longer
/// exist. Serving it would answer questions about a graph that is gone.
#[test]
fn a_stale_index_is_refused() {
    let (_n, json) = corpora().into_iter().next().unwrap();
    let (dir, _store, index) = prepare(&json);
    let path = dir.path().join("index.cgidx");
    index.write(&path, 7).unwrap();
    assert!(IndexData::read(&path, 7).is_ok());
    let err = IndexData::read(&path, 8).unwrap_err().to_string();
    assert!(err.contains("generation"), "got: {err}");
}

#[test]
fn a_corrupt_index_section_is_caught() {
    let (_n, json) = corpora().into_iter().next().unwrap();
    let (dir, _store, index) = prepare(&json);
    let path = dir.path().join("index.cgidx");
    index.write(&path, 1).unwrap();

    let mut bytes = std::fs::read(&path).unwrap();
    // Corrupt a payload byte, past the 64-byte header.
    bytes[100] ^= 0xff;
    std::fs::write(&path, &bytes).unwrap();
    assert!(
        IndexData::read(&path, 1).is_err(),
        "a flipped byte in a section went undetected"
    );
}

#[test]
fn a_truncated_index_is_refused() {
    let (_n, json) = corpora().into_iter().next().unwrap();
    let (dir, _store, index) = prepare(&json);
    let path = dir.path().join("index.cgidx");
    index.write(&path, 1).unwrap();
    let bytes = std::fs::read(&path).unwrap();
    std::fs::write(&path, &bytes[..bytes.len() - 8]).unwrap();
    let err = IndexData::read(&path, 1).unwrap_err().to_string();
    assert!(err.contains("truncated") || err.contains("checksum"), "got: {err}");
}

#[test]
fn a_foreign_file_is_not_read_as_an_index() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("junk.cgidx");
    std::fs::write(&path, vec![0u8; 512]).unwrap();
    assert!(IndexData::read(&path, 1).is_err());
}

/// Reading a persisted index must be far cheaper than rebuilding it — that is
/// the entire reason it exists.
#[test]
fn reading_is_cheaper_than_rebuilding() {
    let (_n, json) = corpora().into_iter().max_by_key(|(_, j)| j.len()).unwrap();
    let (dir, store, index) = prepare(&json);
    let path = dir.path().join("index.cgidx");
    index.write(&path, 1).unwrap();

    let t = std::time::Instant::now();
    let rebuilt = IndexData::build(&store).unwrap();
    let build = t.elapsed();

    let t = std::time::Instant::now();
    let read = IndexData::read(&path, 1).unwrap();
    let load = t.elapsed();

    assert_eq!(rebuilt, read);
    println!("rebuild {build:?} vs read {load:?}");
    assert!(
        load < build,
        "reading the index ({load:?}) was not faster than rebuilding it ({build:?})"
    );
}

// --- mapped vs owned ---

/// The refactor's core property: an mmap'd index and an owned one must answer
/// every query identically. Two backings behind one trait is only safe if this
/// holds.
#[test]
fn the_mapped_index_answers_exactly_like_the_owned_one() {
    use codegraph_index::MappedIndex;

    for (name, json) in corpora() {
        let (dir, _store, owned) = prepare(&json);
        let path = dir.path().join("index.cgidx");
        owned.write(&path, 1).unwrap();
        let mapped = MappedIndex::open(&path, 1).unwrap_or_else(|e| panic!("{name}: {e}"));

        assert_eq!(mapped.node_count(), owned.node_count(), "{name}: node count");
        assert_eq!(mapped.scc_count(), owned.scc_count(), "{name}: component count");
        assert_eq!(mapped.hub_threshold(), owned.hub_threshold(), "{name}: hub threshold");
        assert_eq!(mapped.degree_out(), owned.degree_out(), "{name}: out degree");
        assert_eq!(mapped.degree_in(), owned.degree_in(), "{name}: in degree");
        assert_eq!(mapped.degree_total(), owned.degree_total(), "{name}: total degree");
        assert_eq!(mapped.scc_of(), owned.scc_of(), "{name}: components");
        assert_eq!(mapped.grail_labels(), owned.grail_labels(), "{name}: labels");

        assert_eq!(mapped.name_count(), owned.name_count(), "{name}: name count");
        for i in 0..owned.name_count() {
            assert_eq!(mapped.name_key(i), owned.name_key(i), "{name}: name key {i}");
        }

        // And the derived queries, not just the columns.
        for i in (0..owned.name_count()).step_by(7).take(200) {
            let key = owned.name_key(i).to_string();
            assert_eq!(
                mapped.by_exact_name(&key),
                owned.by_exact_name(&key),
                "{name}: exact lookup of {key:?}"
            );
            let p: String = key.chars().take(3).collect();
            assert_eq!(
                mapped.by_name_prefix(&p),
                owned.by_name_prefix(&p),
                "{name}: prefix lookup of {p:?}"
            );
            let sub: String = key.chars().take(5).collect();
            assert_eq!(
                mapped.trigram_candidates(&sub),
                owned.trigram_candidates(&sub),
                "{name}: trigram candidates for {sub:?}"
            );
        }

        let n = owned.node_count();
        for a in (0..n).step_by((n / 40).max(1)) {
            for b in (0..n).step_by((n / 40).max(1)) {
                let (x, y) = (LocalId::new(a as u32), LocalId::new(b as u32));
                assert_eq!(
                    mapped.maybe_reaches(x, y),
                    owned.maybe_reaches(x, y),
                    "{name}: reachability {a} -> {b}"
                );
            }
        }
    }
}

/// A mapped index must reject the same malformed files the owned reader does.
#[test]
fn the_mapped_reader_rejects_a_stale_or_broken_index() {
    use codegraph_index::MappedIndex;

    let (_n, json) = corpora().into_iter().next().unwrap();
    let (dir, _store, owned) = prepare(&json);
    let path = dir.path().join("index.cgidx");
    owned.write(&path, 5).unwrap();

    assert!(MappedIndex::open(&path, 5).is_ok());
    assert!(MappedIndex::open(&path, 6).is_err(), "a stale generation was accepted");

    let bytes = std::fs::read(&path).unwrap();
    let cut = dir.path().join("cut.cgidx");
    std::fs::write(&cut, &bytes[..bytes.len() - 8]).unwrap();
    assert!(MappedIndex::open(&cut, 5).is_err(), "a truncated index was accepted");
}

/// Opening a mapped index must not read the payload — that is the whole point.
/// Verified by asserting that a corrupted *payload* still opens (the structure
/// is intact) while `verify_checksums` catches it on demand.
#[test]
fn mapping_does_not_read_the_payload_but_fsck_does() {
    use codegraph_index::MappedIndex;

    let (_n, json) = corpora().into_iter().next().unwrap();
    let (dir, _store, owned) = prepare(&json);
    let path = dir.path().join("index.cgidx");
    owned.write(&path, 1).unwrap();

    let mut bytes = std::fs::read(&path).unwrap();
    bytes[100] ^= 0xff; // inside a section payload, past the header
    std::fs::write(&path, &bytes).unwrap();

    let mapped = MappedIndex::open(&path, 1).expect("structure is still valid");
    assert!(
        mapped.verify_checksums().is_err(),
        "payload corruption went undetected by fsck"
    );
    // The owned reader verifies eagerly, so it must refuse outright.
    assert!(IndexData::read(&path, 1).is_err(), "the owned reader accepted corruption");
}
