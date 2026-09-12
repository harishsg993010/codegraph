//! The store: a directory of segments plus the manifest that says which of
//! them count.
//!
//! Opening maps every live segment. That is cheap — `mmap` reserves address
//! space and reads nothing — so a cold open costs one manifest parse and one
//! syscall per segment, not a pass over the data.

use std::path::{Path, PathBuf};

use codegraph_core::{LocalId, SymbolKey};

use crate::error::{Result, StoreError};
use crate::format::Tier;
use crate::manifest::{Manifest, SegmentEntry, segment_path};
use crate::reader::Segment;
use crate::view::{View, ViewData};
use crate::writer::SegmentBuilder;

pub struct Store {
    root: PathBuf,
    manifest: Manifest,
    /// Live segments in id order. A `Vec` rather than a map because the view
    /// indexes segments by position on every edge, and a store holds a
    /// handful of them.
    segments: Vec<(u64, Segment)>,
    /// Rebuilt on every commit: the segment set is what it describes.
    view: ViewData,
}

impl std::fmt::Debug for Store {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Store")
            .field("root", &self.root)
            .field("generation", &self.manifest.generation)
            .field("segments", &self.segments.len())
            .field("files", &self.manifest.owners.len())
            .finish()
    }
}

impl Store {
    /// Create an empty store. Fails if one already exists, so a create never
    /// silently adopts unrelated files.
    pub fn create(root: impl AsRef<Path>) -> Result<Self> {
        let root = root.as_ref().to_path_buf();
        if root.join(crate::manifest::CURRENT).exists() {
            return Err(StoreError::Manifest(format!(
                "a store already exists at {}",
                root.display()
            )));
        }
        std::fs::create_dir_all(&root)
            .map_err(|e| StoreError::io(format!("creating {}", root.display()), e))?;
        let mut manifest = Manifest::default();
        manifest.commit(&root)?;
        let mut s = Self { root, manifest, segments: Vec::new(), view: ViewData::default() };
        s.rebuild_view()?;
        Ok(s)
    }

    pub fn open(root: impl AsRef<Path>) -> Result<Self> {
        let root = root.as_ref().to_path_buf();
        let manifest = Manifest::load(&root)?;
        let mut segments = Vec::with_capacity(manifest.segments.len());
        for e in &manifest.segments {
            segments.push((e.id, Segment::open(segment_path(&root, e.id))?));
        }
        segments.sort_by_key(|(id, _)| *id);
        let mut s = Self { root, manifest, segments, view: ViewData::default() };
        s.rebuild_view()?;
        Ok(s)
    }

    pub fn open_or_create(root: impl AsRef<Path>) -> Result<Self> {
        let root = root.as_ref();
        if root.join(crate::manifest::CURRENT).exists() {
            Self::open(root)
        } else {
            Self::create(root)
        }
    }

    fn rebuild_view(&mut self) -> Result<()> {
        self.view = ViewData::build(&self.segments, &self.manifest)?;
        Ok(())
    }

    pub fn root(&self) -> &Path {
        &self.root
    }
    pub fn manifest(&self) -> &Manifest {
        &self.manifest
    }
    pub fn segment(&self, id: u64) -> Option<&Segment> {
        self.segments
            .binary_search_by_key(&id, |(i, _)| *i)
            .ok()
            .map(|i| &self.segments[i].1)
    }

    /// Live segments, in id order so iteration is deterministic.
    pub fn segments(&self) -> impl Iterator<Item = (u64, &Segment)> {
        self.segments.iter().map(|(id, s)| (*id, s))
    }

    /// The store-wide view: one id space over every segment, with dead and
    /// duplicated rows forwarded to the row that counts.
    pub fn view(&self) -> View<'_> {
        View::new(&self.segments, &self.view)
    }

    pub fn symbol_count(&self) -> usize {
        self.segments.iter().map(|(_, s)| s.node_count()).sum()
    }
    pub fn edge_count(&self) -> usize {
        self.segments.iter().map(|(_, s)| s.edge_count()).sum()
    }

    /// Allocate the id a segment about to be built should carry.
    pub fn next_segment_id(&mut self) -> u64 {
        self.manifest.allocate_segment_id()
    }

    /// Write a segment, move ownership of `files` to it, and commit.
    ///
    /// Ordering matters: the segment file is fully written and synced *before*
    /// the manifest names it, so a crash can leave an unreferenced segment but
    /// never a manifest pointing at a segment that is not there.
    pub fn commit_segment(
        &mut self,
        id: u64,
        builder: SegmentBuilder,
        tier: Tier,
        files: &[String],
    ) -> Result<()> {
        let (nodes, edges) = (builder.symbol_count(), builder.edge_count());
        let path = segment_path(&self.root, id);

        {
            let mut f = std::fs::File::create(&path)
                .map_err(|e| StoreError::io(format!("creating {}", path.display()), e))?;
            builder
                .write(&mut f)
                .map_err(|e| StoreError::io(format!("writing {}", path.display()), e))?;
            f.sync_all()
                .map_err(|e| StoreError::io(format!("syncing {}", path.display()), e))?;
        }

        // Map it before committing: a segment that will not open is a bug we
        // want to hear about now, not on the next process start.
        let segment = Segment::open(&path)?;

        let entry = SegmentEntry {
            id,
            tier: tier.as_str().to_string(),
            nodes: nodes as u32,
            edges: edges as u64,
        };
        let dead = self.manifest.add_segment(entry, tier, files);
        self.manifest.retire(&dead);
        self.manifest.commit(&self.root)?;
        self.manifest.sweep_old_manifests(&self.root);

        self.segments.push((id, segment));
        self.segments.sort_by_key(|(id, _)| *id);
        self.segments.retain(|(id, _)| !dead.contains(id));
        self.rebuild_view()
    }

    /// Forget `files` entirely — both tiers — and commit.
    ///
    /// The rows stay in their segments until compaction drops them; what
    /// changes is that no segment owns them, so the view stops seeing them.
    /// A segment left owning nothing is retired here, exactly as it would be
    /// by a segment commit.
    pub fn remove_files(&mut self, files: &[String]) -> Result<()> {
        if files.is_empty() {
            return Ok(());
        }
        let mut dead = Vec::new();
        for f in files {
            dead = self.manifest.remove_file(f);
        }
        self.manifest.retire(&dead);
        self.manifest.commit(&self.root)?;
        self.manifest.sweep_old_manifests(&self.root);
        self.segments.retain(|(id, _)| !dead.contains(id));
        self.rebuild_view()
    }

    /// Delete segment files the manifest no longer references.
    ///
    /// Separate from commit because a reader may still have one mapped, and on
    /// Windows an open file cannot be unlinked at all. A file that will not
    /// delete is left for the next sweep rather than failing the caller.
    pub fn sweep_dead_segments(&self) -> usize {
        let live: std::collections::HashSet<u64> =
            self.manifest.segments.iter().map(|s| s.id).collect();
        let Ok(rd) = std::fs::read_dir(&self.root) else { return 0 };
        let mut removed = 0;
        for e in rd.flatten() {
            let name = e.file_name();
            let Some(name) = name.to_str() else { continue };
            let Some(rest) = name.strip_prefix("seg-").and_then(|r| r.strip_suffix(".cgseg"))
            else {
                continue;
            };
            let Ok(id) = rest.parse::<u64>() else { continue };
            if !live.contains(&id) && std::fs::remove_file(e.path()).is_ok() {
                removed += 1;
            }
        }
        removed
    }

    /// Find a symbol's canonical row: the segment holding it and its id there.
    pub fn find_symbol(&self, key: SymbolKey) -> Result<Option<(u64, LocalId)>> {
        let view = self.view();
        Ok(view.find(key).and_then(|g| {
            let (i, local) = view.locate(g)?;
            Some((self.segments[i].0, local))
        }))
    }

    /// Is this segment still the authority for `path`'s `tier` rows?
    pub fn is_live(&self, path: &str, tier: Tier, segment_id: u64) -> bool {
        self.manifest.is_live(path, tier, segment_id)
    }

    /// Verify every live segment against its recorded checksums.
    pub fn verify(&self) -> Result<()> {
        for (id, seg) in self.segments() {
            seg.verify_checksums()
                .map_err(|e| StoreError::Corrupt(format!("segment {id}: {e}")))?;
        }
        Ok(())
    }
}
