//! The edit-distance learning thresholds as policy value rows (FIX 9802,
//! 9809): the agreeing rulings that earn a proposed standing escalation
//! policy, the distinct receipts the substitution miner waits for, and how
//! long a rejected mined proposal keeps its cluster quiet.
//!
//! Each is a vault-scope `policy_values` row the shipped manifest seeds as
//! data; an owner's or holder's authored row changes it through the manifest
//! authoring doors, and the shared scoped selection resolves it.

use super::policy_values::{PolicyEvaluationScope, PolicyValue, PolicyValueKey};
use super::resolution::PolicyManifestResolution;
use crate::error::{Error, Result};

/// The shipped vault-scope row for `key`, read from the seeded data rather
/// than an engine constant.
fn shipped_vault_value(key: PolicyValueKey) -> Result<u64> {
    let defaults: serde_json::Value =
        serde_json::from_str(include_str!("policy_value_defaults.json"))
            .map_err(|_| Error::InvariantViolation("shipped policy value rows"))?;
    defaults
        .as_array()
        .and_then(|rows| {
            rows.iter()
                .find(|row| row["key"] == key.as_str() && row["scope"]["level"] == "vault")
        })
        .and_then(|row| row["value"].as_u64())
        .ok_or(Error::InvariantViolation(
            "shipped edit-distance threshold row",
        ))
}

impl PolicyManifestResolution {
    /// The vault's row for `key`, else the shipped one. A fail-closed
    /// manifest reads the shipped row, since a threshold grants nothing.
    fn edit_distance_threshold(
        &self,
        key: PolicyValueKey,
        typed: fn(u64) -> PolicyValue,
    ) -> Result<u64> {
        let fallback = typed(shipped_vault_value(key)?);
        match self
            .resolved_policy_value(key, &PolicyEvaluationScope::default(), fallback)
            .value
        {
            PolicyValue::EscalationStandingRulings(value)
            | PolicyValue::MinerRecurrenceReceipts(value)
            | PolicyValue::MinerRejectionWaitSeconds(value) => Ok(value),
            _ => Err(Error::InvariantViolation("typed policy key")),
        }
    }

    /// Agreeing rulings a `(scope, trigger)` pair owes before a standing
    /// escalation policy is proposed (FIX 9802).
    ///
    /// # Errors
    ///
    /// [`Error::InvariantViolation`] when the shipped row is missing.
    pub(crate) fn escalation_standing_rulings(&self) -> Result<u64> {
        self.edit_distance_threshold(
            PolicyValueKey::EscalationStandingRulings,
            PolicyValue::EscalationStandingRulings,
        )
    }

    /// Distinct receipts a substitution cluster owes before the miner acts on
    /// it (FIX 9809).
    ///
    /// # Errors
    ///
    /// [`Error::InvariantViolation`] when the shipped row is missing.
    pub(crate) fn miner_recurrence_receipts(&self) -> Result<u64> {
        self.edit_distance_threshold(
            PolicyValueKey::MinerRecurrenceReceipts,
            PolicyValue::MinerRecurrenceReceipts,
        )
    }

    /// Seconds a rejected mined proposal keeps its cluster quiet (FIX 9809).
    ///
    /// # Errors
    ///
    /// [`Error::InvariantViolation`] when the shipped row is missing.
    pub(crate) fn miner_rejection_wait_seconds(&self) -> Result<u64> {
        self.edit_distance_threshold(
            PolicyValueKey::MinerRejectionWaitSeconds,
            PolicyValue::MinerRejectionWaitSeconds,
        )
    }
}
