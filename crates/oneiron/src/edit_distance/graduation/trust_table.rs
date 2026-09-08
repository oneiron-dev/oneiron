//! Trust-table join over ramp stats, policy, and offer state.

use super::answers::{SnoozeState, snooze_state_in_txn};
use super::posterior::guard_evidence;
use super::threshold_policy::{ThresholdRow, graduation_policy_in_txn};
use crate::consent_graduation::{RampScope, RampState, ScopeOutcomeStats};
use crate::error::Result;
use crate::vault::Vault;

// ---------------------------------------------------------------------------
// The trust table
// ---------------------------------------------------------------------------

/// One scope's row in the trust table: everything a settings or console screen
/// needs about it in one place.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct TrustTableRow {
    /// The scope this row is about.
    pub scope: RampScope,
    /// MS-06's consent posture — what authority is live.
    pub state: RampState,
    /// MS-06's folded counters.
    pub stats: ScopeOutcomeStats,
    /// The threshold in force — the row that actually decides, not the
    /// compiled default it may have shadowed.
    pub threshold: ThresholdRow,
    /// Whether the engine is currently asking about this scope.
    pub snooze: SnoozeState,
    /// The live standing grant, when [`RampState::Graduated`].
    pub grant_ref: Option<String>,
    /// Whether the history clears [`Self::threshold`] right now. Distinct from
    /// `state == Offered` only in that it survives the read: it is what
    /// [`OfferAnswer::GoAuto`] may act on.
    pub offer_is_earned: bool,
}

/// Every scope with ramp history, with the policy and offer state governing it.
///
/// Ordered by scope, so two reads of an unchanged vault produce the same table.
///
/// # Errors
///
/// [`Error::CorruptedIndex`] on an unreadable stats, threshold or answer row,
/// plus storage failures.
pub fn trust_table(vault: &Vault) -> Result<Vec<TrustTableRow>> {
    let rtxn = vault.store.env.read_txn()?;
    let mut rows = Vec::new();
    for stats in crate::consent_graduation::ramp_stats_in_txn(vault, &rtxn)? {
        let threshold = graduation_policy_in_txn(&vault.store, &rtxn, &stats.scope)?;
        let (wins, losses) = guard_evidence(&stats);
        let offer_is_earned = stats.scope.is_graduatable() && threshold.is_cleared_by(wins, losses);
        rows.push(TrustTableRow {
            state: stats.state,
            threshold,
            snooze: snooze_state_in_txn(&vault.store, &rtxn, &stats.scope)?,
            grant_ref: crate::consent_graduation::active_grant_ref_in_txn(
                vault,
                &rtxn,
                &stats.scope,
            )?,
            offer_is_earned,
            scope: stats.scope.clone(),
            stats,
        });
    }
    rows.sort_by(|left, right| left.scope.cmp(&right.scope));
    Ok(rows)
}
