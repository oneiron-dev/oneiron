//! Public Vault doors plus the shared accept-offer txn helper used by ED-05.

use super::fold::{
    OutcomeWitness, append_demotion_in_txn, derive_state_in_txn, offer_is_standing_in_txn,
    ramp_stats_in_txn, read_counters_in_txn, record_outcome_for_scope_in_txn, stats_view,
    write_counters_in_txn,
};
use super::scope::RampScope;
use super::state::{Counters, DemotionReason, RampState, ScopeOutcomeStats};
use super::storage::{
    RAMP_STATS_KEY_PREFIX, StoredScopeStats, decode_row, floor_key, stats_key, stats_row_parts,
};
use crate::consent::{AuthenticatedOwner, ConsentReceipt};
use crate::error::{Error, GateError, Result};
use crate::identity_topology::ProposalOutcome;
use crate::vault::Vault;

impl Vault {
    /// Resolves the ramp scope handle for one (op kind × target class × actor)
    /// tuple. Identical tuples resolve to the same scope; any difference on any
    /// axis is a different scope (oracle
    /// `ms06_ramp_scope_keys_on_op_class_agent_tuple`).
    ///
    /// # Errors
    ///
    /// [`GateError::InvalidConsentBound`](crate::error::GateError::InvalidConsentBound) when a tuple field is empty or oversized.
    pub fn ramp_scope(&self, op_kind: &str, target_class: &str, actor: &str) -> Result<RampScope> {
        RampScope::new(op_kind, target_class, actor)
    }

    /// Folds one ruling into a scope's statistics, demoting the scope if the
    /// ruling was not clean. The propose-lane door for surfaces outside
    /// identity topology.
    ///
    /// The ruling lands as a durable outcome row FIRST: a counter this door
    /// moved with nothing behind it would be autonomy the ledger cannot
    /// witness, and the next rebuild would take it away again.
    ///
    /// # Errors
    ///
    /// [`GateError::InvalidConsentBound`](crate::error::GateError::InvalidConsentBound) when the scope tuple is unbuildable
    /// (checked before the first write), plus storage failures.
    pub fn record_proposal_outcome_for_ramp(
        &self,
        scope: &RampScope,
        outcome: ProposalOutcome,
    ) -> Result<ScopeOutcomeStats> {
        scope.validate()?;
        let at = crate::unix_seconds_now();
        let counters = self.with_write_txn(|wtxn| {
            record_outcome_for_scope_in_txn(self, wtxn, scope, outcome, at, OutcomeWitness::Door)
        })?;
        let rtxn = self.store.env.read_txn()?;
        let state = derive_state_in_txn(self, &rtxn, scope, counters)?;
        Ok(stats_view(scope.clone(), counters, state))
    }

    /// One scope's statistics, or `None` when nothing has ever been ruled in
    /// it.
    ///
    /// # Errors
    ///
    /// Storage failures.
    pub fn scope_stats(&self, scope: &RampScope) -> Result<Option<ScopeOutcomeStats>> {
        let rtxn = self.store.env.read_txn()?;
        let Some(raw) = self.store.vault_meta.get(&rtxn, &stats_key(scope))? else {
            return Ok(None);
        };
        let row: StoredScopeStats = decode_row(&raw, "ramp stats row")?;
        let (stored_scope, counters) = stats_row_parts(row)?;
        let state = derive_state_in_txn(self, &rtxn, &stored_scope, counters)?;
        Ok(Some(stats_view(stored_scope, counters, state)))
    }

    /// The scope's current posture as a pinned wire string.
    ///
    /// # Errors
    ///
    /// Storage failures.
    pub fn ramp_scope_state(&self, scope: &RampScope) -> Result<RampState> {
        let rtxn = self.store.env.read_txn()?;
        let counters = read_counters_in_txn(&self.store, &rtxn, scope)?;
        derive_state_in_txn(self, &rtxn, scope, counters)
    }

    /// Every scope the engine should ASK about right now: eligible, history past
    /// its threshold row, no grant live yet, and not held by ED-05's snooze or
    /// pin.
    ///
    /// An offer is DERIVED, never a stored row — so it cannot outlive the
    /// evidence that produced it, and a demotion retracts it by construction.
    ///
    /// The suppression consult is the whole of what snooze and pin do: they
    /// remove a scope from this list and from nothing else. The offer stays
    /// standing ([`RampState::Offered`]) and stays acceptable, because "stop
    /// asking me" is not "take this away from me".
    ///
    /// # Errors
    ///
    /// Storage failures.
    pub fn graduation_offers(&self) -> Result<Vec<RampScope>> {
        let rtxn = self.store.env.read_txn()?;
        let now = crate::unix_seconds_now();
        let mut offers = Vec::new();
        for stats in ramp_stats_in_txn(self, &rtxn)? {
            if stats.state == RampState::Offered
                && !crate::edit_distance::graduation::asks_are_suppressed_in_txn(
                    &self.store,
                    &rtxn,
                    &stats.scope,
                    now,
                )?
            {
                offers.push(stats.scope);
            }
        }
        offers.sort_unstable();
        Ok(offers)
    }

    /// The owner taps a surfaced graduation offer, minting the standing grant.
    ///
    /// Requires an [`AuthenticatedOwner`] and routes through the one
    /// [`Vault::create_standing_grant`] door: no streak, however long, can
    /// produce authority on its own (DEC-0006 invariant 5, oracle
    /// `ms06_streak_offers_standing_grant_never_auto_grants`).
    ///
    /// The offer must still be STANDING at the instant the grant is written,
    /// and that is tested in the minting transaction itself. A tap answers an
    /// offer the owner saw; between seeing it and tapping it, a rejection or an
    /// amendment may have retracted that offer and receipted the demotion. A
    /// stale tap that could still mint would let a scope walk back from
    /// demoted to graduated with no ruling in between — the exact silence this
    /// module exists to prevent.
    ///
    /// Answering here and answering through
    /// [`crate::edit_distance::graduation::answer_graduation_offer`] are the
    /// same act and leave the same durable state: both record the go-auto
    /// answer, which clears whatever snooze or pin the scope was carrying.
    ///
    /// # Errors
    ///
    /// [`GateError::InvalidConsentBound`](crate::error::GateError::InvalidConsentBound) when the scope is not on the ramp at all,
    /// when its tuple is unbuildable, or when it is not currently offering
    /// graduation; plus whatever `create_standing_grant` rejects (the
    /// catastrophe floor).
    pub fn accept_graduation_offer(
        &self,
        owner: &AuthenticatedOwner,
        scope: &RampScope,
    ) -> Result<ConsentReceipt> {
        let at = crate::unix_seconds_now();
        self.with_write_txn(|wtxn| accept_graduation_offer_in_txn(self, wtxn, owner, scope, at))
    }

    /// Demotes a scope back to the propose lane: revokes its standing grant if
    /// one is live, appends the demotion receipt, and zeroes the clean streak.
    ///
    /// Reducing one's own authority needs no owner authentication — only
    /// GRANTING does. What it does need is to be said out loud, which is the
    /// unconditional receipt (oracle
    /// `ms06_self_demotion_is_receipted_never_silent`): a scope with no live
    /// grant still records the act, so "I stopped trusting myself here" is
    /// never inferred from an absence.
    ///
    /// # Errors
    ///
    /// [`GateError::InvalidConsentBound`](crate::error::GateError::InvalidConsentBound) when the scope tuple is unbuildable,
    /// plus storage failures.
    pub fn demote_scope_to_propose(&self, scope: &RampScope, reason: DemotionReason) -> Result<()> {
        scope.validate()?;
        let at = crate::unix_seconds_now();
        self.with_write_txn(|wtxn| append_demotion_in_txn(self, wtxn, scope, reason, at))
    }

    /// Overrides one scope's graduation streak floor (ED-05's seam; the
    /// compiled default is [`DEFAULT_GRADUATION_STREAK_FLOOR`]).
    ///
    /// # Errors
    ///
    /// [`GateError::InvalidConsentBound`](crate::error::GateError::InvalidConsentBound) when the scope tuple is unbuildable,
    /// plus storage failures.
    pub fn set_ramp_streak_floor(&self, scope: &RampScope, floor: u32) -> Result<()> {
        scope.validate()?;
        self.with_write_txn(|wtxn| {
            self.store
                .vault_meta
                .put(wtxn, &floor_key(scope), &floor.to_le_bytes())?;
            Ok(())
        })
    }

    /// The streak in force for one scope — this scope's own override when it
    /// has one, otherwise whatever ED-05 threshold row governs it.
    ///
    /// Reads the EFFECTIVE policy rather than only the override keyspace, so it
    /// cannot answer with the compiled default while a pattern row is the thing
    /// actually deciding. [`crate::edit_distance::graduation::
    /// graduation_policy_for`] returns the whole row, guard included.
    ///
    /// # Errors
    ///
    /// [`Error::CorruptedIndex`] on an unreadable threshold row, plus storage
    /// failures.
    pub fn ramp_streak_floor(&self, scope: &RampScope) -> Result<u32> {
        Ok(crate::edit_distance::graduation::graduation_policy_for(self, scope)?.required_streak)
    }

    /// CID-7 door: drops the whole statistics projection and refolds it from
    /// truth — every identity-topology resolution event, interleaved in ledger
    /// order with this module's own outcome and demotion rows.
    ///
    /// All three inputs are needed and none is optional: the resolution events
    /// are the rulings the propose lane produced (each stamped with its own
    /// scope tuple, so no join is required), the outcome rows are the rulings
    /// recorded through the ramp door, and the demotion rows carry the streak
    /// resets no ruling implies. Floors, outcomes and demotions are untouched —
    /// a rebuild repairs a cache, it never rewrites policy or history.
    ///
    /// The scan runs INSIDE the transaction that replaces the projection.
    /// Reading truth on one transaction and overwriting the projection on a
    /// later one leaves a window in which a resolution commits between them,
    /// and the rebuild would then erase an update it never saw.
    ///
    /// # Errors
    ///
    /// Storage failures, and [`Error::CorruptedIndex`] on an unreadable row.
    pub fn rebuild_ramp_stats_from_receipts(&self) -> Result<()> {
        self.with_write_txn(|wtxn| {
            let events = self.ramp_fold_events_in_txn(&*wtxn)?;
            let stale: Vec<Vec<u8>> = self
                .store
                .vault_meta
                .prefix_iter(&*wtxn, RAMP_STATS_KEY_PREFIX)?
                .map(|row| row.map(|(key, _)| key.to_vec()))
                .collect::<Result<_>>()?;
            for key in stale {
                self.store.vault_meta.delete(wtxn, &key)?;
            }

            let mut folded: std::collections::BTreeMap<RampScope, Counters> =
                std::collections::BTreeMap::new();
            for event in &events {
                let counters = folded.entry(event.scope.clone()).or_default();
                match event.outcome {
                    Some(outcome) => counters.apply_outcome(outcome, event.at),
                    None => counters.apply_demotion(event.at),
                }
            }
            for (scope, counters) in &folded {
                write_counters_in_txn(&self.store, wtxn, scope, *counters)?;
            }
            Ok(())
        })
    }
}

/// [`Vault::accept_graduation_offer`] inside the caller's write txn, at `at`.
///
/// The whole door, checks included, so ED-05 — which routes its own `go-auto`
/// answer through here — cannot end up enforcing a looser version of it. The
/// public method is this function plus a transaction.
///
/// The ANSWER is recorded here rather than by either caller, for the same
/// reason: this is the only code path both public acceptance doors share, so it
/// is the only place that can guarantee they leave identical state. See
/// [`crate::edit_distance::graduation::record_go_auto_answer_in_txn`].
pub(crate) fn accept_graduation_offer_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    owner: &AuthenticatedOwner,
    scope: &RampScope,
    at: u64,
) -> Result<ConsentReceipt> {
    scope.validate()?;
    if !scope.is_graduatable() {
        return Err(Error::Gate(GateError::InvalidConsentBound(
            "op kind does not ride the propose lane; there is nothing to graduate",
        )));
    }
    let bound = scope.to_grant_bound()?;
    if !offer_is_standing_in_txn(vault, &*wtxn, scope)? {
        return Err(Error::Gate(GateError::InvalidConsentBound(
            "this scope is not offering graduation; a retracted offer cannot be accepted",
        )));
    }
    crate::edit_distance::graduation::record_go_auto_answer_in_txn(vault, wtxn, scope, at)?;
    vault.create_standing_grant_in_txn(wtxn, owner, bound)
}
