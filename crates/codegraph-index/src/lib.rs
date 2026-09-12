//! Derived indexes: everything the query engine needs that is a function of
//! the whole graph rather than of one segment.
//!
//! These are rebuilt at compaction and live beside the segments, keyed by
//! manifest generation — a derived statistic changes on a different cadence
//! than the data it summarises, and putting it in the segment would force a
//! segment rewrite every time one moved.

pub mod build;
pub mod grail;
pub mod layered;
pub mod mapped;
pub mod persist;
pub mod view;
pub mod scc;

pub use build::{IndexData, MIN_HUB_THRESHOLD, REACHABILITY_RELATIONS, trigrams};
pub use grail::Grail;
pub use layered::{BASE_FILE, Layered, OVERLAY_FILE, OpenError, Opened, Overlay, open_or_build};
pub use mapped::MappedIndex;
pub use persist::{IndexFileError, index_name};
pub use view::{IndexColumns, IndexQuery};
pub use scc::{CsrGraph, Graph, Sccs};
