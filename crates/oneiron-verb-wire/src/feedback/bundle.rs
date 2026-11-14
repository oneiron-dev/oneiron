//! Moved from `crates/oneiron/src/feedback/bundle.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

/// Maximum accepted length of any single reference token in bytes.
pub const FEEDBACK_REF_MAX_BYTES: usize = 256;

/// What kind of feedback this bundle carries.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(rename_all = "kebab-case")]
pub enum FeedbackCategory {
    /// Something is broken.
    Bug,
    /// Something works but hurts.
    Papercut,
    /// Something is unclear.
    Confusion,
    /// Something is missing.
    FeatureWish,
}

impl FeedbackCategory {
    /// All categories in wire order.
    pub const ALL: [Self; 4] = [
        Self::Bug,
        Self::Papercut,
        Self::Confusion,
        Self::FeatureWish,
    ];

    /// Stable wire token for this category.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Bug => "bug",
            Self::Papercut => "papercut",
            Self::Confusion => "confusion",
            Self::FeatureWish => "feature-wish",
        }
    }
}
