//! Store errors.

use thiserror::Error;

pub type Result<T> = std::result::Result<T, StoreError>;

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("{context}: {source}")]
    Io {
        context: String,
        #[source]
        source: std::io::Error,
    },

    /// The bytes on disk do not describe a valid segment. Always loud: a
    /// corrupt store must never be read as if it were merely empty.
    #[error("corrupt segment: {0}")]
    Corrupt(String),

    #[error("segment format version {found} is not supported (this build reads {supported})")]
    UnsupportedVersion { found: u32, supported: u32 },

    #[error("{0}")]
    Manifest(String),
}

impl StoreError {
    pub fn io(context: impl Into<String>, source: std::io::Error) -> Self {
        Self::Io { context: context.into(), source }
    }
}
