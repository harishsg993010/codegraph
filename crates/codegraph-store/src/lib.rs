//! The store: immutable segments, mmap'd and read with no parse step.
//!
//! See `docs/segment-format.md` for the on-disk contract.

pub mod compact;
pub mod error;
pub mod format;
pub mod import;
pub mod lock;
pub mod manifest;
pub mod reader;
pub mod store;
pub mod view;
pub mod writer;

pub use compact::{CompactPolicy, CompactStats, compact, compact_tiered};
pub use error::{Result, StoreError};
pub use import::{ImportStats, import_node_link};
pub use lock::{LOCK_FILE, WriteLock};
pub use format::{SectionKind, Tier, edge_flags, node_flags};
pub use manifest::{Manifest, SegmentEntry};
pub use reader::{InEdge, OutEdge, Segment};
pub use store::Store;
pub use view::{RawEdge, View, ViewEdge};
pub use writer::{Edge, SegmentBuilder, Symbol};
