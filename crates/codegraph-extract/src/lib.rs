//! Deterministic extraction: source tree in, symbols and facts out.
//!
//! The walk is generic and the languages are data (`lang`), so scope
//! qualification, name extraction, and edge emission are written once and
//! cannot drift between languages.

pub mod flow;
pub mod lang;
pub mod summaries;
pub mod syntax;
pub mod walk;

pub use lang::{ALL, LangConfig, for_extension, for_path, lang_id};
pub use walk::{
    ArgPos, FileExtract, FlowNode, RawBlock, RawCall, RawEdge, RawFlow, RawImport, RawRef, RawSymbol,
    Walker, content_hash,
};
