//! A slide review request's own dial and pacing (FIX 9336): what a caller
//! narrows the host's dial and the vault's policy row by, never widening
//! either.

use serde::{Deserialize, Serialize};

use crate::llm::decision::SlideReviewLimits;

/// A slide review's own pacing, each field narrowing the vault's policy
/// row (FIX 9336): units per batch, units, text bytes and image bytes of
/// one unit. An absent field leaves the vault's.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(deny_unknown_fields)]
pub struct SlideReviewLimitsInput {
    #[serde(default)]
    pub batch_size: Option<u64>,
    #[serde(default)]
    pub max_units: Option<u64>,
    #[serde(default)]
    pub max_text_bytes: Option<u64>,
    #[serde(default)]
    pub max_image_bytes: Option<u64>,
}

impl SlideReviewLimitsInput {
    /// The limits a review request carries, which the vault narrows its own
    /// row by: an absent field narrows nothing.
    #[must_use]
    pub fn limits(self) -> SlideReviewLimits {
        let narrowed = |field: Option<u64>| {
            field.map_or(usize::MAX, |v| usize::try_from(v).unwrap_or(usize::MAX))
        };
        SlideReviewLimits {
            batch_size: narrowed(self.batch_size),
            max_units: narrowed(self.max_units),
            max_text_bytes: narrowed(self.max_text_bytes),
            max_image_bytes: narrowed(self.max_image_bytes),
        }
    }
}
