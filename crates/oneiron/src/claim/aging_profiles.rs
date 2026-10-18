//! Class-level aging policy data; claim classification stays predicate-root metadata.
use serde::{Deserialize, Serialize};

use super::{AccessFactorPolicy, ClaimAgingClass};
use crate::error::{Error, Result};

/// Exponential availability profiles for the engine's existing aging classes.
/// These affect retrieval only, never confidence, retention or stored claim bodies.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ClaimAgingProfiles {
    pub durable: AccessFactorPolicy,
    pub standard: AccessFactorPolicy,
    pub ephemeral: AccessFactorPolicy,
}

impl Default for ClaimAgingProfiles {
    fn default() -> Self {
        Self {
            durable: ClaimAgingClass::Durable.policy(),
            standard: ClaimAgingClass::Standard.policy(),
            ephemeral: ClaimAgingClass::Ephemeral.policy(),
        }
    }
}

impl ClaimAgingProfiles {
    #[must_use]
    pub fn policy(self, class: ClaimAgingClass) -> AccessFactorPolicy {
        match class {
            ClaimAgingClass::Durable => self.durable,
            ClaimAgingClass::Standard => self.standard,
            ClaimAgingClass::Ephemeral => self.ephemeral,
        }
    }

    pub(crate) fn validate(self) -> Result<()> {
        for policy in [self.durable, self.standard, self.ephemeral] {
            validate_access_factor_policy(policy)?;
        }
        Ok(())
    }
}

pub(crate) fn validate_access_factor_policy(policy: AccessFactorPolicy) -> Result<()> {
    if !policy.half_life_secs.is_finite() || policy.half_life_secs <= 0.0 {
        return Err(Error::InvalidConfig(
            "aging half_life_secs must be finite and positive".to_owned(),
        ));
    }
    if !super::access_factor_override_valid(policy.floor) {
        return Err(Error::InvalidConfig(
            "aging floor must be finite and within [0, 1]".to_owned(),
        ));
    }
    Ok(())
}
