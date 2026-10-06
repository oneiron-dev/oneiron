//! Typed failures for the formula crate. No stringly errors cross the seam.
use std::borrow::Cow;

/// Every way formula evaluation, routing, or corpus measurement can fail.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FormulaError {
    /// A corpus case names a cell or range outside the 1-based grid.
    #[error("invalid cell address: {0}")]
    InvalidAddress(&'static str),
    /// A setup value or expected value has a shape the runner cannot stage.
    #[error("unsupported corpus value: {0}")]
    UnsupportedValue(&'static str),
    /// The upstream engine refused a workbook, cell, or formula operation.
    /// The detail is the upstream display string; callers match on the case
    /// status, not on this text.
    #[error("engine error: {0}")]
    Engine(String),
    /// Malformed workbook content cannot enter either recalculation path.
    #[error("invalid workbook: {0}")]
    InvalidWorkbook(&'static str),
    /// Valid workbook features this optional adapter cannot safely serialize.
    /// The reason names the feature, such as the function the engine lacks.
    #[error("workbook requires the fallback session: {0}")]
    UnsupportedWorkbook(Cow<'static, str>),
    /// The retained OPC boundary refused the archive or an edit.
    #[error(transparent)]
    Package(#[from] oneiron_docedit::retained_opc::Error),
    /// The corpus file itself is unreadable or fails its pinned hashes.
    #[error("invalid corpus: {0}")]
    InvalidCorpus(&'static str),
}

impl FormulaError {
    /// Stable machine key for receipts. Never the display string.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::InvalidAddress(_) => "invalid-address",
            Self::UnsupportedValue(_) => "unsupported-value",
            Self::Engine(_) => "engine-error",
            Self::InvalidWorkbook(_) => "invalid-workbook",
            Self::UnsupportedWorkbook(_) => "unsupported-workbook",
            Self::Package(_) => "invalid-package",
            Self::InvalidCorpus(_) => "invalid-corpus",
        }
    }
}

/// A part the namespace-aware reader refuses is malformed workbook content.
impl From<oneiron_docedit::ooxml::XmlError> for FormulaError {
    fn from(error: oneiron_docedit::ooxml::XmlError) -> Self {
        Self::InvalidWorkbook(error.0)
    }
}

/// Crate-local result alias.
pub type Result<T> = std::result::Result<T, FormulaError>;
