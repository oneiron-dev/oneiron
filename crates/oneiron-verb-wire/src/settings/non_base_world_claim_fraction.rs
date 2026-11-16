//! Moved from `crates/oneiron/src/settings/non_base_world_claim_fraction.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_base::error::Error;
use oneiron_base::error::Result;
use serde::Deserialize;
use serde::Serialize;

/// The share a pack gives worlds other than base while the owner has set
/// none: fiction takes at most half, so it never crowds base reality out
/// (ARCH-0004 / ARCH-0022).
pub const DEFAULT_NON_BASE_WORLD_CLAIM_FRACTION: f32 = 0.5;

/// The non-base world claim fraction: `vault.settings.non_base_world_claim_fraction`'s
/// answer, and `.set`'s input and answer.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NonBaseWorldClaimFraction {
    /// The most of a context pack's claims that worlds other than base may
    /// hold, from 0 (base reality alone) to 1 (no cap): a partitioned pack
    /// keeps at most `floor(fraction times its emitted claims)` of them.
    pub fraction: f32,
}

impl NonBaseWorldClaimFraction {
    /// The fraction while the owner has set none.
    pub const DEFAULT: Self = Self {
        fraction: DEFAULT_NON_BASE_WORLD_CLAIM_FRACTION,
    };

    /// Refuses a fraction below 0, above 1, or not a number.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidConfig`] naming the fraction.
    pub fn validate(self) -> Result<()> {
        if (0.0..=1.0).contains(&self.fraction) {
            Ok(())
        } else {
            Err(Error::InvalidConfig(format!(
                "the non-base world claim fraction must be from 0 to 1, not {}",
                self.fraction
            )))
        }
    }
}

impl Default for NonBaseWorldClaimFraction {
    fn default() -> Self {
        Self::DEFAULT
    }
}
