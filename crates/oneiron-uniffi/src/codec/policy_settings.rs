//! Owned policy action output conversion (FIX 12936).

use super::{Lift, OneironError, WireJson};

impl Lift<oneiron::policy_setting_doors::PolicyActionOutcome> for crate::PolicyActionOutcome {
    fn lift(
        value: oneiron::policy_setting_doors::PolicyActionOutcome,
    ) -> Result<Self, OneironError> {
        Ok(Self {
            outcome: WireJson::lift(value.outcome)?,
        })
    }
}
