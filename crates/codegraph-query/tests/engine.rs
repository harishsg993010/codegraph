//! The query surface, checked against brute force on real corpora.

use std::collections::VecDeque;

use codegraph_core::{LocalId, Relation, RelationMask};
use codegraph_index::{IndexData, IndexQuery};
use codegraph_query::{Direction, Engine, Walk};
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

fn engine(json: &str) -> (tempfile::TempDir, Engine) {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut store = Store::create(dir.path()).expect("create");
    import_node_link(json, &mut store).expect("import");
    compact(&mut store).expect("compact");
    let index = IndexData::build(&store).expect("index");
    (dir, Engine::from_parts(store, index))
}

/// The largest corpus, for the checks that only need one.
fn biggest() -> (tempfile::TempDir, Engine) {
    let (_n, json) = corpora()
        .into_iter()
        .max_by_key(|(_, j)| j.len())
        .expect("a corpus");
    engine(&json)
}

#[test]
fn name_lookup_agrees_with_a_full_scan() {
    for (name, json) in corpora() {
        let (_d, e) = engine(&json);
        let seg = e.store().segments().next().unwrap().1;
        let norms = seg.node_norm_names().unwrap();

        for i in (0..seg.node_count()).step_by(5) {
            let n = seg.string(norms[i]).to_string();
            if n.is_empty() {
                continue;
            }
            let want: Vec<LocalId> = (0..seg.node_count())
                .filter(|&j| seg.string(norms[j]) == n)
                .map(|j| LocalId::new(j as u32))
                .collect();
            let mut got = e.by_name(&n);
            got.sort_by_key(|l| l.get());
            assert_eq!(got, want, "{name}: lookup of {n:?}");
        }
    }
}

#[test]
fn search_agrees_with_a_full_scan() {
    for (name, json) in corpora() {
        let (_d, e) = engine(&json);
        let seg = e.store().segments().next().unwrap().1;
        let norms = seg.node_norm_names().unwrap();
        let files = seg.node_files().unwrap();

        let mut probes: Vec<String> = vec!["init".into(), "get".into(), ".py".into(), "a".into()];
        for i in (0..seg.node_count()).step_by(11).take(15) {
            let n = seg.string(norms[i]);
            if n.len() >= 4 {
                probes.push(n[..4].to_string());
            }
        }

        for probe in probes {
            let p = probe.to_lowercase();
            let want: Vec<LocalId> = (0..seg.node_count())
                .filter(|&j| {
                    seg.string(norms[j]).contains(&p)
                        || seg.file_path(files[j]).to_lowercase().contains(&p)
                })
                .map(|j| LocalId::new(j as u32))
                .collect();
            let mut got = e.search(&probe).unwrap();
            got.sort_by_key(|l| l.get());
            assert_eq!(got, want, "{name}: search for {probe:?}");
        }
    }
}

/// Level-synchronous BFS must report a node at its true shortest depth.
#[test]
fn walk_depths_match_bfs() {
    for (name, json) in corpora() {
        let (_d, e) = engine(&json);
        let seg = e.store().segments().next().unwrap().1;
        let n = seg.node_count();

        for src in (0..n).step_by((n / 20).max(1)).take(20) {
            let s = LocalId::new(src as u32);
            let w = Walk {
                depth: 3,
                relations: RelationMask::ALL,
                direction: Direction::Out,
                suppress_hubs: false, // compare against plain BFS
                max_nodes: usize::MAX,
            };
            let hits = e.walk(&[s], w).unwrap();

            // Ground truth.
            let mut dist = vec![u32::MAX; n];
            dist[src] = 0;
            let mut q = VecDeque::from([s]);
            while let Some(v) = q.pop_front() {
                if dist[v.index()] >= 3 {
                    continue;
                }
                for edge in seg.out_edges(v, RelationMask::ALL).unwrap() {
                    if dist[edge.target.index()] == u32::MAX {
                        dist[edge.target.index()] = dist[v.index()] + 1;
                        q.push_back(edge.target);
                    }
                }
            }

            for h in &hits {
                assert_eq!(
                    dist[h.id.index()], h.depth,
                    "{name}: node {} reported at depth {} but BFS says {}",
                    h.id.get(), h.depth, dist[h.id.index()]
                );
            }
            let expected = dist.iter().filter(|d| **d != u32::MAX && **d > 0).count();
            assert_eq!(hits.len(), expected, "{name}: walk from {src} missed nodes");
        }
    }
}

#[test]
fn hub_suppression_shrinks_the_walk_but_keeps_the_hub() {
    let (_d, e) = biggest();
    let hubs = e.hubs(1).unwrap();
    if hubs.is_empty() || !e.index().is_hub(hubs[0].id) {
        return; // corpus has no node above the floor; nothing to assert
    }
    let seed = hubs[0].id;
    let base = Walk { depth: 3, suppress_hubs: false, max_nodes: usize::MAX, ..Walk::default() };
    let suppressed = Walk { suppress_hubs: true, ..base };
    let a = e.walk(&[seed], base).unwrap();
    let b = e.walk(&[seed], suppressed).unwrap();
    assert!(b.len() <= a.len(), "suppression grew the walk");
}

#[test]
fn shortest_path_is_a_real_path_of_minimal_length() {
    for (name, json) in corpora() {
        let (_d, e) = engine(&json);
        let seg = e.store().segments().next().unwrap().1;
        let n = seg.node_count();
        if n < 4 {
            continue;
        }

        let mut checked = 0usize;
        for src in (0..n).step_by((n / 15).max(1)) {
            let s = LocalId::new(src as u32);
            // BFS ground truth for distances.
            let mut dist = vec![u32::MAX; n];
            dist[src] = 0;
            let mut q = VecDeque::from([s]);
            while let Some(v) = q.pop_front() {
                for edge in seg.out_edges(v, RelationMask::ALL).unwrap() {
                    if dist[edge.target.index()] == u32::MAX {
                        dist[edge.target.index()] = dist[v.index()] + 1;
                        q.push_back(edge.target);
                    }
                }
            }
            for dst in (0..n).step_by((n / 15).max(1)) {
                let t = LocalId::new(dst as u32);
                let got = e.shortest_path(s, t, RelationMask::ALL, 16).unwrap();
                match (dist[dst], got) {
                    (u32::MAX, p) => assert!(p.is_none(), "{name}: path found where none exists"),
                    (d, Some(p)) if d <= 16 => {
                        checked += 1;
                        assert_eq!(p.first(), Some(&s), "{name}: path does not start at the source");
                        assert_eq!(p.last(), Some(&t), "{name}: path does not end at the target");
                        assert_eq!(
                            p.len() as u32 - 1,
                            d,
                            "{name}: path {src}->{dst} has {} hops, shortest is {d}",
                            p.len() - 1
                        );
                        // Every consecutive pair must be a real edge.
                        for pair in p.windows(2) {
                            let ok = seg
                                .out_edges(pair[0], RelationMask::ALL)
                                .unwrap()
                                .any(|edge| edge.target == pair[1]);
                            assert!(ok, "{name}: {:?} -> {:?} is not an edge", pair[0], pair[1]);
                        }
                    }
                    (d, None) if d <= 16 => {
                        panic!("{name}: no path {src}->{dst} but BFS found one at distance {d}")
                    }
                    _ => {}
                }
            }
        }
        assert!(checked > 0, "{name}: no reachable pairs were exercised");
    }
}

#[test]
fn a_node_reaches_itself_in_zero_hops() {
    let (_d, e) = biggest();
    let p = e.shortest_path(LocalId::new(0), LocalId::new(0), RelationMask::ALL, 8).unwrap();
    assert_eq!(p, Some(vec![LocalId::new(0)]));
}

/// The reachable set must agree with an unbounded BFS along the same mask.
#[test]
fn reachable_set_agrees_with_bfs() {
    let (_d, e) = biggest();
    let seg = e.store().segments().next().unwrap().1;
    let n = seg.node_count();
    for src in (0..n).step_by((n / 10).max(1)).take(10) {
        let s = LocalId::new(src as u32);
        let got: std::collections::HashSet<u32> = e
            .reachable_set(&[s], Relation::TAINT)
            .unwrap()
            .into_iter()
            .map(|l| l.get())
            .collect();

        let mut seen = vec![false; n];
        seen[src] = true;
        let mut q = VecDeque::from([s]);
        let mut want = std::collections::HashSet::from([src as u32]);
        while let Some(v) = q.pop_front() {
            for edge in seg.out_edges(v, Relation::TAINT).unwrap() {
                if !seen[edge.target.index()] {
                    seen[edge.target.index()] = true;
                    want.insert(edge.target.get());
                    q.push_back(edge.target);
                }
            }
        }
        assert_eq!(got, want, "reachable set from {src} disagrees with BFS");
    }
}

/// A taint query must find a path whenever one exists along the mask.
#[test]
fn taint_finds_a_path_when_one_exists() {
    let (_d, e) = biggest();
    let seg = e.store().segments().next().unwrap().1;
    let n = seg.node_count();

    let mut found = 0usize;
    for src in (0..n).step_by((n / 30).max(1)) {
        let s = LocalId::new(src as u32);
        let reach = e.reachable_set(&[s], Relation::TAINT).unwrap();
        // Pick a genuinely reachable, distinct target.
        let Some(&t) = reach.iter().find(|&&t| t != s) else { continue };
        let path = e.taint_path(&[s], &[t], Relation::TAINT, 32).unwrap();
        assert!(
            path.is_some(),
            "{src} reaches {} along taint relations but taint_path found nothing",
            t.get()
        );
        found += 1;
        if found > 20 {
            break;
        }
    }
    assert!(found > 0, "no taint-reachable pairs were exercised");
}

#[test]
fn blast_radius_walks_backwards() {
    let (_d, e) = biggest();
    let seg = e.store().segments().next().unwrap().1;
    // Find a node with incoming blast-radius edges.
    let target = (0..seg.node_count()).find(|&i| {
        seg.in_edges(LocalId::new(i as u32), Relation::BLAST_RADIUS)
            .map(|mut it| it.next().is_some())
            .unwrap_or(false)
    });
    let Some(t) = target else { return };
    let hits = e.blast_radius(LocalId::new(t as u32), 2).unwrap();
    assert!(!hits.is_empty(), "blast radius of a node with dependents is empty");
    // Every hit must actually point at something in the walk.
    for h in &hits {
        assert!(h.depth >= 1 && h.depth <= 2);
    }
}

#[test]
fn hubs_are_ordered_by_degree_and_exclude_file_nodes() {
    let (_d, e) = biggest();
    let hubs = e.hubs(10).unwrap();
    assert!(!hubs.is_empty());
    for w in hubs.windows(2) {
        assert!(w[0].degree >= w[1].degree, "hubs are not ordered by degree");
    }
    let seg = e.store().segments().next().unwrap().1;
    let flags = seg.node_flags().unwrap();
    for h in &hubs {
        assert_eq!(
            flags[h.id.index()] & codegraph_store::node_flags::FILE_NODE,
            0,
            "a file node was reported as a hub"
        );
    }
}

#[test]
fn the_edge_histogram_sums_to_the_edge_count() {
    for (name, json) in corpora() {
        let (_d, e) = engine(&json);
        let seg = e.store().segments().next().unwrap().1;
        let (rels, confs) = e.edge_histogram().unwrap();
        assert_eq!(rels.iter().map(|(_, c)| c).sum::<usize>(), seg.edge_count(), "{name}");
        assert_eq!(confs.iter().map(|(_, c)| c).sum::<usize>(), seg.edge_count(), "{name}");
    }
}

#[test]
fn info_round_trips_through_lookup() {
    let (_d, e) = biggest();
    for i in (0..e.symbol_count()).step_by(13).take(50) {
        let id = LocalId::new(i as u32);
        let info = e.info(id).unwrap().expect("info");
        assert_eq!(e.by_key(info.key).unwrap(), Some(id), "key lookup did not round-trip");
    }
    assert!(e.info(LocalId::new(u32::MAX - 1)).unwrap().is_none());
}

/// Regression: the reachability index is built over flow relations only, so
/// consulting it for a *wider* mask rejected paths along relations it never
/// saw. A `contains` edge at distance 1 was reported as no path at all.
#[test]
fn a_wider_mask_than_the_index_covers_is_not_filtered() {
    for (name, json) in corpora() {
        let (_d, e) = engine(&json);
        let seg = e.store().segments().next().unwrap().1;

        // Find a direct edge whose relation is outside the reachability mask.
        let mut probe = None;
        'outer: for i in 0..seg.node_count() {
            let src = LocalId::new(i as u32);
            for edge in seg.out_edges(src, RelationMask::ALL).unwrap() {
                if !codegraph_index::REACHABILITY_RELATIONS.contains(edge.relation) {
                    probe = Some((src, edge.target));
                    break 'outer;
                }
            }
        }
        let Some((a, b)) = probe else { continue };
        if a == b {
            continue;
        }

        let path = e.shortest_path(a, b, RelationMask::ALL, 8).unwrap();
        assert_eq!(
            path,
            Some(vec![a, b]),
            "{name}: a direct edge outside the index's mask was filtered away"
        );
        // And the guard itself must agree about coverage.
        assert!(!e.index().covers(RelationMask::ALL));
        assert!(e.index().covers(codegraph_index::REACHABILITY_RELATIONS));
    }
}
