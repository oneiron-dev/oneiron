//! The edit-distance learning thresholds as policy value rows (FIX 9802,
//! 9809): the agreeing rulings that earn a proposed standing escalation
//! policy, the distinct receipts the substitution miner waits for, and how
//! long a rejected mined proposal keeps its cluster quiet.
//!
//! Each is a vault-scope `policy_values` row the shipped manifest seeds as
//! data, at today's value. The seeded row is a fallback: a row an
//! authenticated owner or holder door authored for the same key and scope
//! replaces it (the Engine 10-22 C1 origin rule), and other trusted rows only
//! narrow; the shared scoped selection then resolves what remains. A manifest
//! that does not read or decode never refuses the caller and never picks a
//! stricter value: it warns, and the shipped row stands.

use std::collections::BTreeSet;

use super::manifest_authenticity::{PolicyRowOrigin, policy_row_origin};
use super::policy_values::{
    PolicyEvaluationScope, PolicyRowScope, PolicyValue, PolicyValueKey, PolicyValueRow,
};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};

/// One edit-distance learning threshold.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EditDistanceThreshold {
    /// Agreeing rulings a `(scope, trigger)` pair owes before a standing
    /// escalation policy is proposed (FIX 9802).
    StandingRulings,
    /// Distinct receipts a substitution cluster owes before the miner acts on
    /// it (FIX 9809).
    RecurrenceReceipts,
    /// Seconds a rejected mined proposal keeps its cluster quiet (FIX 9809).
    RejectionWaitSeconds,
}

impl EditDistanceThreshold {
    /// The threshold `key` names, if it names one.
    const fn of(key: PolicyValueKey) -> Option<Self> {
        match key {
            PolicyValueKey::EscalationStandingRulings => Some(Self::StandingRulings),
            PolicyValueKey::MinerRecurrenceReceipts => Some(Self::RecurrenceReceipts),
            PolicyValueKey::MinerRejectionWaitSeconds => Some(Self::RejectionWaitSeconds),
            _ => None,
        }
    }

    const fn key(self) -> PolicyValueKey {
        match self {
            Self::StandingRulings => PolicyValueKey::EscalationStandingRulings,
            Self::RecurrenceReceipts => PolicyValueKey::MinerRecurrenceReceipts,
            Self::RejectionWaitSeconds => PolicyValueKey::MinerRejectionWaitSeconds,
        }
    }

    const fn value(self, value: u64) -> PolicyValue {
        match self {
            Self::StandingRulings => PolicyValue::EscalationStandingRulings(value),
            Self::RecurrenceReceipts => PolicyValue::MinerRecurrenceReceipts(value),
            Self::RejectionWaitSeconds => PolicyValue::MinerRejectionWaitSeconds(value),
        }
    }
}

/// The manifest fold's hold on the thresholds' seeded rows: set aside while
/// the fold reads every trusted manifest, then kept only where no authored
/// row names the same key and scope.
#[derive(Debug, Default)]
pub(in crate::gate) struct SeededThresholdRows {
    seeded: Vec<PolicyValueRow>,
    authored: BTreeSet<(PolicyValueKey, PolicyRowScope)>,
}

impl SeededThresholdRows {
    /// Folds one trusted manifest's value rows into `folded`, setting a
    /// seeded manifest's threshold rows aside and noting an authored one's.
    pub(in crate::gate) fn fold(
        &mut self,
        store: &impl crate::store::ManifestDbs,
        txn: &heed::RoTxn<'_>,
        id: &EntityId,
        body: &[u8],
        rows: Vec<PolicyValueRow>,
        folded: &mut Vec<PolicyValueRow>,
    ) -> Result<()> {
        if !rows
            .iter()
            .any(|row| EditDistanceThreshold::of(row.key).is_some())
        {
            folded.extend(rows);
            return Ok(());
        }
        let origin = policy_row_origin(store, txn, id, body)?;
        for row in rows {
            if EditDistanceThreshold::of(row.key).is_some() {
                match origin {
                    PolicyRowOrigin::Seeded => {
                        self.seeded.push(row);
                        continue;
                    }
                    PolicyRowOrigin::Authored => {
                        self.authored.insert((row.key, row.scope));
                    }
                    PolicyRowOrigin::Narrowing => {}
                }
            }
            folded.push(row);
        }
        Ok(())
    }

    /// Appends the seeded rows no authored row replaced.
    pub(in crate::gate) fn finish(self, folded: &mut Vec<PolicyValueRow>) {
        let authored = self.authored;
        folded.extend(
            self.seeded
                .into_iter()
                .filter(|row| !authored.contains(&(row.key, row.scope))),
        );
    }
}

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

/// `threshold` as the policy manifest resolves it in `txn`: the vault's row,
/// else the shipped one. A manifest that does not read, or that fails closed
/// on a row it cannot decode, warns and reads the shipped row.
///
/// # Errors
///
/// [`Error::InvariantViolation`] only when the build's own shipped row is
/// missing; a vault's manifest never fails the read.
pub(crate) fn edit_distance_threshold_in_txn(
    store: &impl crate::store::ManifestDbs,
    txn: &heed::RoTxn<'_>,
    threshold: EditDistanceThreshold,
) -> Result<u64> {
    let key = threshold.key();
    let shipped = shipped_vault_value(key)?;
    let policy = match super::resolve_policy_manifest(store, txn) {
        Ok(policy) => policy,
        Err(error) => {
            tracing::warn!(
                key = key.as_str(),
                error = %error,
                "the policy manifest did not read: the shipped edit-distance threshold stands"
            );
            return Ok(shipped);
        }
    };
    if policy.is_fail_closed() {
        tracing::warn!(
            key = key.as_str(),
            "the policy manifest fails closed: the shipped edit-distance threshold stands"
        );
        return Ok(shipped);
    }
    match policy
        .resolved_policy_value(
            key,
            &PolicyEvaluationScope::default(),
            threshold.value(shipped),
        )
        .value
    {
        PolicyValue::EscalationStandingRulings(value)
        | PolicyValue::MinerRecurrenceReceipts(value)
        | PolicyValue::MinerRejectionWaitSeconds(value) => Ok(value),
        _ => {
            tracing::warn!(
                key = key.as_str(),
                "a policy value of another key resolved: the shipped edit-distance threshold stands"
            );
            Ok(shipped)
        }
    }
}
