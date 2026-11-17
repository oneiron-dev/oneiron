//! The N dial over vault_meta, and the two text helpers every child in this module uses.

use serde::{Deserialize, Serialize};

use super::setting_keys::MIN_OUTCOMES;
use crate::Vault;
use crate::error::{ArtifactError, Error, Result};
use crate::setting::{SettingSource, SettingValue};

/// N, the attributed outcomes a skill must carry before it can be optimized: the catalogue key
/// `skills.optimize.min_outcomes` ([`super::setting_keys::MIN_OUTCOMES`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(transparent)]
pub struct SkillOptimizeMinOutcomes(pub u32);

impl SettingValue for SkillOptimizeMinOutcomes {
    /// N is above zero: a job that may rewrite a skill on no evidence at all is the thing N
    /// exists to prevent.
    fn check(self) -> Result<Self> {
        if self.0 == 0 {
            Err(Error::InvalidConfig(
                "skill optimize min_outcomes must be > 0: evidence is the point".into(),
            ))
        } else {
            Ok(self)
        }
    }
}

/// N when the dial has never been set.
///
/// Five, matching `SKILL_RELIABILITY_FLOOR_MIN_OUTCOMES`: the two gates ask
/// the same underlying question ("is there evidence, or only a prior?") of the
/// same posterior, and answering it with two different numbers would mean a
/// skill could be evidenced enough to retire but not enough to repair.
pub const DEFAULT_SKILL_OPTIMIZE_MIN_OUTCOMES: u32 = 5;

/// Page size of the SKILL type-index sweep.
pub(super) const SKILL_SCAN_PAGE: usize = 1024;

pub(super) const fn invalid(reason: &'static str) -> Error {
    Error::Artifact(ArtifactError::InvalidSkillBody(reason))
}

pub(super) fn validate_text(value: &str, max_bytes: usize, reason: &'static str) -> Result<()> {
    if value.trim().is_empty() || value.len() > max_bytes {
        return Err(invalid(reason));
    }
    Ok(())
}

/// Reads the N dial (default [`DEFAULT_SKILL_OPTIMIZE_MIN_OUTCOMES`]).
///
/// # Errors
///
/// Storage errors; [`Error::CorruptedIndex`] on a stored N that does not decode.
pub fn skill_optimize_min_outcomes(vault: &Vault) -> Result<u32> {
    skill_optimize_min_outcomes_sourced(vault).map(|(value, _)| value)
}

/// The native dial read, with no body source when the shipped default is
/// used. A stored setting row has no source-row identity on this carrier.
pub(super) fn skill_optimize_min_outcomes_sourced(
    vault: &Vault,
) -> Result<(u32, Option<Vec<crate::EntityId>>)> {
    let rtxn = vault.store.env.read_txn()?;
    let read = MIN_OUTCOMES.read_in_txn(vault, &rtxn, &[], None)?;
    Ok(match read.source {
        SettingSource::Default => (read.value.0, Some(Vec::new())),
        _ => (read.value.0, None),
    })
}
