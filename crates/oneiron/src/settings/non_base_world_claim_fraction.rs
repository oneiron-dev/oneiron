//! The owner's non-base world claim fraction (ARCH-0004 #world-scope: "The
//! non-base fraction is a budget knob, and the vault owner sets it"; FIX
//! WORLD-SHARE-FRACTION-NO-OWNER-DOOR). It is the most of a context pack's
//! claims that worlds other than base may hold, from 0 (base reality alone)
//! to 1 (no cap). An unset key reads as
//! [`DEFAULT_NON_BASE_WORLD_CLAIM_FRACTION`]. Every pack that partitions its
//! claims by world reads it, unless its caller names a fraction of its own.
//!
//! It is the catalogue key `recall.non_base_world_claim_fraction`
//! (`settings::setting_keys`): the owner alone sets it, through
//! `vault.settings.set`, and every change is one `SETTING_CHANGE` row. Its
//! read (`vault.settings.get`) answers the owner, or a holder of any
//! `engine.controls` class, checked at the read, as every dial read is
//! (untangle 6.6f; S66F-READ = C).

use serde::{Deserialize, Serialize};

use super::setting_keys::NON_BASE_WORLD_CLAIM_FRACTION;
use crate::Vault;
use crate::error::{Error, Result};
use crate::setting::SettingValue;

/// The share a pack gives worlds other than base while the owner has set
/// none: fiction takes at most half, so it never crowds base reality out
/// (ARCH-0004 / ARCH-0022).
pub const DEFAULT_NON_BASE_WORLD_CLAIM_FRACTION: f32 = 0.5;

/// The non-base world claim fraction: the value of the key
/// `recall.non_base_world_claim_fraction`.
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

impl SettingValue for NonBaseWorldClaimFraction {
    fn check(self) -> Result<Self> {
        self.validate()?;
        Ok(self)
    }
}

impl Vault {
    /// The non-base world claim fraction in force: the owner's, or
    /// [`DEFAULT_NON_BASE_WORLD_CLAIM_FRACTION`] while the owner has set none.
    /// A context pack whose caller names no fraction reads it.
    ///
    /// # Errors
    ///
    /// Storage errors.
    pub fn non_base_world_claim_fraction(&self) -> Result<NonBaseWorldClaimFraction> {
        let rtxn = self.store.env.read_txn()?;
        Ok(NON_BASE_WORLD_CLAIM_FRACTION
            .read_in_txn(self, &rtxn, &[], None)?
            .value)
    }
}
