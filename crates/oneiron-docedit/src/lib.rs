//! Storage-independent document editing. The engine depends on this organ, never the reverse.
pub mod calc;
pub mod docx;
pub mod opc;
mod prepared;
pub mod roundtrip;
pub use prepared::{PreparationReport, PrepareInput, PreparedEdit, prepare};

/// A document operation refused before handing bytes back to storage.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    #[error("invalid OPC package: {0}")]
    InvalidPackage(&'static str),
    #[error("document edit refused: {0}")]
    EditFailed(&'static str),
    #[error("invalid edit manifest: {0}")]
    InvalidManifest(&'static str),
    #[error("prepared edit binding mismatch")]
    CommitMismatch,
}
impl Error {
    #[must_use]
    pub const fn reason(&self) -> &'static str {
        match self {
            Self::InvalidPackage(reason)
            | Self::EditFailed(reason)
            | Self::InvalidManifest(reason) => reason,
            Self::CommitMismatch => "prepared edit binding mismatch",
        }
    }
}
pub type Result<T> = std::result::Result<T, Error>;
