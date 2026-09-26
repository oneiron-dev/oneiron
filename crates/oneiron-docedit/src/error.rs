//! Errors from the storage-independent document editor.

/// A document edit or integrity failure.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// An anchor or locator is malformed.
    #[error("invalid anchor: {0}")]
    InvalidAnchor(&'static str),
    /// The OPC input or edit session is invalid.
    #[error("edit round-trip failed: {0}")]
    EditRoundtripFailed(&'static str),
    /// The edit plan or manifest is invalid.
    #[error("invalid edit manifest: {0}")]
    InvalidEditManifest(&'static str),
}

pub type Result<T> = std::result::Result<T, Error>;
