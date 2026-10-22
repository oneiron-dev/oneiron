//! Bounded, retained OPC archives. A no-op returns the original archive;
//! narrow XML edits and added parts preserve every other part's original
//! ZIP records.
mod package;
mod xml;

pub use package::{Editability, Limits, Package, Relationship, rels_name};
pub use xml::XmlLimits;

/// An archive or edit that cannot be proven safe to retain, or work the
/// machine's memory or a deadline stopped.
#[derive(Debug, Clone, thiserror::Error, PartialEq, Eq)]
pub enum Error {
    /// Malformed, unsupported, or over-limit archive.
    #[error("invalid OPC package: {0}")]
    Invalid(&'static str),
    /// The edit does not identify exactly one leaf text node.
    #[error("XML edit refused: {0}")]
    Edit(&'static str),
    /// The work's memory was refused at the machine's floor, or its wait or
    /// deadline ran out (FIX 8574): a well-formed package, never invalid.
    #[error(transparent)]
    Resource(#[from] crate::resource::ResourceRefusal),
}

impl Error {
    /// The refusal, when memory or a deadline stopped the work.
    #[must_use]
    pub const fn resource(&self) -> Option<crate::resource::ResourceRefusal> {
        match self {
            Self::Resource(refusal) => Some(*refusal),
            Self::Invalid(_) | Self::Edit(_) => None,
        }
    }

    /// An XML reader's failure as `fallback`, keeping a resource refusal
    /// as itself.
    pub(crate) fn of_xml(error: crate::ooxml::XmlError, fallback: Self) -> Self {
        error.resource().map_or(fallback, Self::Resource)
    }
}

/// Result of a bounded package operation.
pub type Result<T> = std::result::Result<T, Error>;
