//! Companion background task family strings.

/// Companion background task family.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum CompanionTaskKind {
    /// Rebuild or refresh context assembly state for a companion target.
    Context,
    /// Refresh derived profile state for a companion target.
    Profile,
    /// Consolidate companion memory material for a companion target.
    Memory,
    /// Generate a goodbye artifact after an amicable relationship ending.
    GoodbyeArtifact,
}

impl CompanionTaskKind {
    /// Returns the pinned payload string for this companion task kind.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Context => "context",
            Self::Profile => "profile",
            Self::Memory => "memory",
            Self::GoodbyeArtifact => "goodbye_artifact",
        }
    }

    /// Parses a pinned companion task kind string.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "context" => Some(Self::Context),
            "profile" => Some(Self::Profile),
            "memory" => Some(Self::Memory),
            "goodbye_artifact" => Some(Self::GoodbyeArtifact),
            _ => None,
        }
    }
}
