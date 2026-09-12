//! Identity and vocabulary shared by every other crate.
//!
//! Nothing here touches the filesystem or allocates a graph. It is the set of
//! types the store, the extractors, and the query engine must agree on
//! byte-for-byte, so it is deliberately small and deliberately stable.

pub mod ids;
pub mod vocab;

pub use ids::{FileId, LocalId, StrId, SymbolKey, SymbolKeyParts};
pub use vocab::{Confidence, FileType, Relation, RelationMask, SymbolKind};
