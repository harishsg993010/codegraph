//! The manifest: which segments are live, and who owns each file's rows.
//!
//! # Why ownership rather than tombstones
//!
//! A segment is immutable, so "this file changed" cannot be expressed by
//! editing it. Instead the manifest records, per `(file, tier)`, which segment
//! currently owns that file's rows. Writing a new segment for a file moves
//! ownership; the previous segment's rows for that file are then dead, and
//! compaction drops them.
//!
//! That gives the tier semantics for free. Re-parsing a file moves only its
//! `ast` ownership, so its LLM-derived `semantic` rows keep pointing at the
//! segment that produced them — no graph rewrite, no tier-scoped filter pass.
//!
//! # Why JSON
//!
//! The manifest is kilobytes next to gigabytes of segments, so its encoding
//! costs nothing, and being able to read it in an editor while debugging a
//! store is worth more than the bytes.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::{Result, StoreError};
use crate::format::{FORMAT_VERSION, Tier};

/// Names the generation that is currently authoritative.
pub const CURRENT: &str = "CURRENT";

pub fn manifest_name(generation: u64) -> String {
    format!("MANIFEST-{generation:012}")
}

pub fn segment_name(id: u64) -> String {
    format!("seg-{id:012}.cgseg")
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SegmentEntry {
    pub id: u64,
    pub tier: String,
    pub nodes: u32,
    pub edges: u64,
}

/// Which segment owns a file's rows, per tier. `None` means no segment holds
/// that tier for this file — which is the normal state for `semantic` in a
/// store that has only ever been parsed.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Owner {
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub ast: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub semantic: Option<u64>,
}

impl Owner {
    fn get(&self, tier: Tier) -> Option<u64> {
        match tier {
            Tier::Ast => self.ast,
            Tier::Semantic => self.semantic,
        }
    }
    fn set(&mut self, tier: Tier, id: Option<u64>) {
        match tier {
            Tier::Ast => self.ast = id,
            Tier::Semantic => self.semantic = id,
        }
    }
    fn is_empty(&self) -> bool {
        self.ast.is_none() && self.semantic.is_none()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Manifest {
    pub format_version: u32,
    pub generation: u64,
    /// Monotonic. Never reused, so a segment file name identifies its contents
    /// for the life of the store even after the segment is dropped.
    pub next_segment_id: u64,
    pub segments: Vec<SegmentEntry>,
    /// `file path -> owning segment per tier`. `BTreeMap` so the serialised
    /// form is deterministic and two equal manifests are byte-equal.
    pub owners: BTreeMap<String, Owner>,
}

impl Default for Manifest {
    fn default() -> Self {
        Self {
            format_version: FORMAT_VERSION,
            generation: 0,
            next_segment_id: 0,
            segments: Vec::new(),
            owners: BTreeMap::new(),
        }
    }
}

impl Manifest {
    /// Allocate the next segment id.
    pub fn allocate_segment_id(&mut self) -> u64 {
        let id = self.next_segment_id;
        self.next_segment_id += 1;
        id
    }

    /// Is this segment still the owner of `path`'s `tier` rows?
    pub fn is_live(&self, path: &str, tier: Tier, segment_id: u64) -> bool {
        self.owners.get(path).and_then(|o| o.get(tier)) == Some(segment_id)
    }

    /// Record a new segment and move ownership of every file it covers.
    ///
    /// Returns the segment ids that lost their last file and are now fully
    /// dead — compaction's work list.
    pub fn add_segment(&mut self, entry: SegmentEntry, tier: Tier, files: &[String]) -> Vec<u64> {
        let id = entry.id;
        self.segments.push(entry);
        for f in files {
            self.owners.entry(f.clone()).or_default().set(tier, Some(id));
        }
        self.collect_dead()
    }

    /// Drop a file entirely — both tiers.
    pub fn remove_file(&mut self, path: &str) -> Vec<u64> {
        self.owners.remove(path);
        self.collect_dead()
    }

    /// Segments no longer owning any file. Computed rather than tracked
    /// incrementally: a counter that drifts silently leaks disk forever, and
    /// this runs once per commit over a list that stays small after compaction.
    fn collect_dead(&self) -> Vec<u64> {
        let mut alive = std::collections::HashSet::new();
        for o in self.owners.values() {
            alive.extend(o.ast);
            alive.extend(o.semantic);
        }
        self.segments
            .iter()
            .map(|s| s.id)
            .filter(|id| !alive.contains(id))
            .collect()
    }

    /// Forget dead segments. The caller deletes the files — separately, because
    /// a reader may still have them mapped.
    pub fn retire(&mut self, dead: &[u64]) {
        self.segments.retain(|s| !dead.contains(&s.id));
    }

    pub fn live_files(&self) -> impl Iterator<Item = &str> {
        self.owners
            .iter()
            .filter(|(_, o)| !o.is_empty())
            .map(|(p, _)| p.as_str())
    }

    /// Read the generation named by `CURRENT`.
    pub fn load(root: &Path) -> Result<Self> {
        let cur = std::fs::read_to_string(root.join(CURRENT))
            .map_err(|e| StoreError::io(format!("reading {CURRENT}"), e))?;
        let want: u64 = cur
            .trim()
            .parse()
            .map_err(|_| StoreError::Manifest(format!("{CURRENT} holds {cur:?}, not a generation")))?;
        let path = root.join(manifest_name(want));
        let text = std::fs::read_to_string(&path)
            .map_err(|e| StoreError::io(format!("reading {}", path.display()), e))?;
        let m: Manifest = serde_json::from_str(&text)
            .map_err(|e| StoreError::Manifest(format!("parsing {}: {e}", path.display())))?;
        if m.format_version != FORMAT_VERSION {
            return Err(StoreError::UnsupportedVersion {
                found: m.format_version,
                supported: FORMAT_VERSION,
            });
        }
        if m.generation != want {
            return Err(StoreError::Manifest(format!(
                "{CURRENT} says generation {want} but the manifest says {}",
                m.generation
            )));
        }
        Ok(m)
    }

    /// Commit as a new generation.
    ///
    /// The ordering is the durability contract: the manifest is written and
    /// flushed *before* `CURRENT` names it, so a crash at any point leaves
    /// `CURRENT` pointing at a generation that is fully on disk. A manifest
    /// nothing points at is inert and swept on the next commit.
    pub fn commit(&mut self, root: &Path) -> Result<()> {
        self.generation += 1;
        let path = root.join(manifest_name(self.generation));
        let body = serde_json::to_vec_pretty(self)
            .map_err(|e| StoreError::Manifest(format!("serialising manifest: {e}")))?;
        write_synced(&path, &body)?;

        let tmp = root.join("CURRENT.tmp");
        write_synced(&tmp, self.generation.to_string().as_bytes())?;
        std::fs::rename(&tmp, root.join(CURRENT))
            .map_err(|e| StoreError::io(format!("installing {CURRENT}"), e))?;
        sync_dir(root);
        Ok(())
    }

    /// Delete manifests older than the current generation.
    ///
    /// Best-effort: a manifest that cannot be removed is inert, so failing here
    /// would abort a commit that already succeeded.
    pub fn sweep_old_manifests(&self, root: &Path) {
        let Ok(rd) = std::fs::read_dir(root) else { return };
        for e in rd.flatten() {
            let name = e.file_name();
            let Some(name) = name.to_str() else { continue };
            let Some(rest) = name.strip_prefix("MANIFEST-") else { continue };
            if rest.parse::<u64>().is_ok_and(|g| g < self.generation) {
                let _ = std::fs::remove_file(e.path());
            }
        }
    }
}

/// Write and fsync. The fsync is the difference between "crash-safe" and
/// "power-loss-durable", and a store that loses its manifest loses everything.
fn write_synced(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write;
    let mut f = std::fs::File::create(path)
        .map_err(|e| StoreError::io(format!("creating {}", path.display()), e))?;
    f.write_all(bytes)
        .map_err(|e| StoreError::io(format!("writing {}", path.display()), e))?;
    f.sync_all()
        .map_err(|e| StoreError::io(format!("syncing {}", path.display()), e))?;
    Ok(())
}

/// Fsync the directory so the rename itself is durable.
///
/// Best-effort by design: POSIX requires this, Windows has no equivalent and
/// returns an error for a directory handle opened this way. Failing the commit
/// over it would make the store unusable on Windows for no gain.
fn sync_dir(dir: &Path) {
    if let Ok(f) = std::fs::File::open(dir) {
        let _ = f.sync_all();
    }
}

/// Where a segment's file lives.
pub fn segment_path(root: &Path, id: u64) -> PathBuf {
    root.join(segment_name(id))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(id: u64) -> SegmentEntry {
        SegmentEntry { id, tier: "ast".into(), nodes: 1, edges: 0 }
    }

    #[test]
    fn ids_are_monotonic_and_never_reused() {
        let mut m = Manifest::default();
        assert_eq!(m.allocate_segment_id(), 0);
        assert_eq!(m.allocate_segment_id(), 1);
        m.retire(&[0, 1]);
        // Retiring must not roll the counter back.
        assert_eq!(m.allocate_segment_id(), 2);
    }

    #[test]
    fn ownership_moves_and_the_old_segment_dies() {
        let mut m = Manifest::default();
        let files = vec!["a.py".to_string()];
        let dead = m.add_segment(entry(0), Tier::Ast, &files);
        assert!(dead.is_empty());
        assert!(m.is_live("a.py", Tier::Ast, 0));

        // Re-parse a.py into a new segment.
        let dead = m.add_segment(entry(1), Tier::Ast, &files);
        assert_eq!(dead, vec![0], "the superseded segment should be dead");
        assert!(!m.is_live("a.py", Tier::Ast, 0));
        assert!(m.is_live("a.py", Tier::Ast, 1));
    }

    /// The tier property the whole design exists for: re-parsing must not
    /// disturb the expensive LLM-derived tier.
    #[test]
    fn re_parsing_leaves_the_semantic_tier_alone() {
        let mut m = Manifest::default();
        let files = vec!["a.py".to_string()];
        m.add_segment(entry(0), Tier::Ast, &files);
        m.add_segment(
            SegmentEntry { id: 1, tier: "semantic".into(), nodes: 1, edges: 0 },
            Tier::Semantic,
            &files,
        );

        let dead = m.add_segment(entry(2), Tier::Ast, &files);
        assert_eq!(dead, vec![0], "only the old ast segment should die");
        assert!(m.is_live("a.py", Tier::Semantic, 1), "semantic tier was disturbed");
        assert!(m.is_live("a.py", Tier::Ast, 2));
    }

    #[test]
    fn a_segment_covering_several_files_lives_until_all_are_superseded() {
        let mut m = Manifest::default();
        let both = vec!["a.py".to_string(), "b.py".to_string()];
        m.add_segment(entry(0), Tier::Ast, &both);

        let dead = m.add_segment(entry(1), Tier::Ast, &["a.py".to_string()]);
        assert!(dead.is_empty(), "segment 0 still owns b.py");

        let dead = m.add_segment(entry(2), Tier::Ast, &["b.py".to_string()]);
        assert_eq!(dead, vec![0]);
    }

    #[test]
    fn deleting_a_file_kills_its_segments() {
        let mut m = Manifest::default();
        let files = vec!["a.py".to_string()];
        m.add_segment(entry(0), Tier::Ast, &files);
        let dead = m.remove_file("a.py");
        assert_eq!(dead, vec![0]);
        assert!(m.live_files().next().is_none());
    }

    #[test]
    fn round_trips_through_disk() {
        let dir = tempfile::tempdir().unwrap();
        let mut m = Manifest::default();
        let id = m.allocate_segment_id();
        m.add_segment(entry(id), Tier::Ast, &["a.py".to_string()]);
        m.commit(dir.path()).unwrap();

        let back = Manifest::load(dir.path()).unwrap();
        assert_eq!(back, m);
        assert_eq!(back.generation, 1);
        assert!(back.is_live("a.py", Tier::Ast, 0));
    }

    #[test]
    fn each_commit_advances_the_generation() {
        let dir = tempfile::tempdir().unwrap();
        let mut m = Manifest::default();
        m.commit(dir.path()).unwrap();
        m.commit(dir.path()).unwrap();
        assert_eq!(m.generation, 2);
        assert_eq!(Manifest::load(dir.path()).unwrap().generation, 2);
    }

    /// A manifest written but never named by `CURRENT` is what a crash between
    /// the two writes leaves behind. It must be inert, not fatal.
    #[test]
    fn an_orphan_manifest_is_ignored() {
        let dir = tempfile::tempdir().unwrap();
        let mut m = Manifest::default();
        m.commit(dir.path()).unwrap();
        std::fs::write(dir.path().join(manifest_name(99)), b"{ not json").unwrap();
        assert_eq!(Manifest::load(dir.path()).unwrap().generation, 1);
    }

    #[test]
    fn a_current_disagreeing_with_its_manifest_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let mut m = Manifest::default();
        m.commit(dir.path()).unwrap();
        std::fs::write(dir.path().join(CURRENT), b"7").unwrap();
        assert!(Manifest::load(dir.path()).is_err());
    }

    #[test]
    fn old_manifests_are_swept() {
        let dir = tempfile::tempdir().unwrap();
        let mut m = Manifest::default();
        m.commit(dir.path()).unwrap();
        m.commit(dir.path()).unwrap();
        m.sweep_old_manifests(dir.path());
        assert!(!dir.path().join(manifest_name(1)).exists());
        assert!(dir.path().join(manifest_name(2)).exists());
    }

    #[test]
    fn serialised_form_is_deterministic() {
        let mut a = Manifest::default();
        let mut b = Manifest::default();
        for f in ["z.py", "a.py", "m.py"] {
            a.owners.entry(f.into()).or_default().set(Tier::Ast, Some(1));
        }
        for f in ["a.py", "m.py", "z.py"] {
            b.owners.entry(f.into()).or_default().set(Tier::Ast, Some(1));
        }
        assert_eq!(
            serde_json::to_string(&a).unwrap(),
            serde_json::to_string(&b).unwrap()
        );
    }
}
