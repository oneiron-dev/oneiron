//! Bounded, retained OPC archives. A no-op returns the original archive;
//! narrow XML edits and added parts preserve every other part's original
//! ZIP records.
mod package;
mod xml;

pub use package::{Editability, Limits, Package, Relationship, rels_name};

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
    /// A well-formed package past a ceiling its caller set, or past classic
    /// ZIP's widths (FIX 5354): named with its dimension, never invalid.
    #[error("package ceiling: {0}")]
    Capacity(crate::resource::CapacityHit),
}

impl Error {
    /// The refusal, when memory or a deadline stopped the work.
    #[must_use]
    pub const fn resource(&self) -> Option<crate::resource::ResourceRefusal> {
        match self {
            Self::Resource(refusal) => Some(*refusal),
            Self::Invalid(_) | Self::Edit(_) | Self::Capacity(_) => None,
        }
    }

    /// The ceiling, when a well-formed package passed one.
    #[must_use]
    pub const fn capacity(&self) -> Option<crate::resource::CapacityHit> {
        match self {
            Self::Capacity(hit) => Some(*hit),
            Self::Invalid(_) | Self::Edit(_) | Self::Resource(_) => None,
        }
    }

    /// `observed` past `limit` on `dimension`.
    pub(crate) fn capacity_hit(
        dimension: crate::resource::Dimension,
        observed: usize,
        limit: usize,
    ) -> Self {
        Self::Capacity(crate::resource::CapacityHit::new(
            dimension,
            crate::resource::wide(observed),
            crate::resource::wide(limit),
        ))
    }

    /// An XML reader's failure as `fallback`, keeping a resource refusal
    /// as itself.
    pub(crate) fn of_xml(error: crate::ooxml::XmlError, fallback: Self) -> Self {
        error.resource().map_or(fallback, Self::Resource)
    }
}

/// Result of a bounded package operation.
pub type Result<T> = std::result::Result<T, Error>;
