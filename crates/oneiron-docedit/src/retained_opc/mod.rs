//! Bounded, retained OPC archives. A no-op returns the original archive, and
//! narrow XML text edits preserve every other part's original ZIP records.
mod package;
mod xml;

pub use package::{Editability, Limits, Package};
pub use xml::XmlLimits;

/// An archive or edit that cannot be proven safe to retain.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum Error {
    /// Malformed, unsupported, or over-limit archive.
    #[error("invalid OPC package: {0}")]
    Invalid(&'static str),
    /// The edit does not identify exactly one leaf text node.
    #[error("XML edit refused: {0}")]
    Edit(&'static str),
}

/// Result of a bounded package operation.
pub type Result<T> = std::result::Result<T, Error>;
