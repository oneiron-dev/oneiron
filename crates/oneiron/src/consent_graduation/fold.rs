//! Txn-level counters projection, incremental maintenance, and CID-7 rebuild fold.

use super::scope::RampScope;
use super::state::{
    Counters, DemotionReason, FOLD_RANK_LEDGER, FOLD_RANK_RAMP_ROW, RampFoldEvent, RampState,
    ScopeOutcomeStats,
};
use super::storage::{
    RAMP_DEMOTION_KEY_PREFIX, RAMP_DEMOTION_ROW_LABEL, RAMP_OUTCOME_KEY_PREFIX,
    RAMP_OUTCOME_ROW_LABEL, RAMP_ROW_VERSION, RAMP_STATS_KEY_PREFIX, StoredDemotion,
    StoredRampOutcome, StoredScopeStats, decode_ramp_row, decode_row, encode_row, floor_key,
    ramp_row_key, ramp_row_key_id, stats_key, stats_row, stats_row_parts, stored_row_scope,
};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::identity_topology::{
    IdentityTopologyAction, IdentityTopologyRejection, ProposalOutcome, StoredIdentityOpAction,
    fold_identity_topology_log,
};
use crate::store::Store;
use crate::vault::Vault;

pub(super) fn read_counters_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    scope: &RampScope,
) -> Result<Counters> {
    let Some(raw) = store.vault_meta.get(txn, &stats_key(scope))? else {
        return Ok(Counters::default());
    };
    let row: StoredScopeStats = decode_row(&raw, "ramp stats row")?;
    Ok(stats_row_parts(row)?.1)
}

pub(super) fn write_counters_in_txn(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    scope: &RampScope,
    counters: Counters,
) -> Result<()> {
    let data = encode_row(&stats_row(scope, counters), "ramp stats row encode failed")?;
    store.vault_meta.put(wtxn, &stats_key(scope), &data)?;
    Ok(())
}

/// The per-scope streak override, when the owner set one.
///
/// `Option` rather than defaulted, because ED-05 composes it: an ABSENT
/// override falls through to the threshold row's own streak, whereas a present
/// one is the most specific policy statement there is and takes that axis
/// outright.
pub(crate) fn ramp_floor_override_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    scope: &RampScope,
) -> Result<Option<u32>> {
    let Some(raw) = store.vault_meta.get(txn, &floor_key(scope))? else {
        return Ok(None);
    };
    <[u8; 4]>::try_from(raw.as_ref())
        .map(|bytes| Some(u32::from_le_bytes(bytes)))
        .map_err(|_| Error::CorruptedIndex("ramp streak floor row"))
}

/// The scope's live standing grant reference, when one is active.
pub(crate) fn active_grant_ref_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    scope: &RampScope,
) -> Result<Option<String>> {
    let grant_ref = scope.grant_ref()?;
    Ok(
        crate::consent::standing_grant_is_active_in_txn(&vault.store, txn, &grant_ref)?
            .then_some(grant_ref),
    )
}

/// Derives the posture from the two things that actually decide it: whether a
/// grant is live, and whether the ruling history has earned an offer.
///
/// The second half is ED-05's (ONE-1761): the compiled streak floor this module
/// shipped is now the catch-all row of
/// [`crate::edit_distance::graduation`]'s threshold table, which adds the
/// posterior guard that tells a spotless streak apart from an equally long one
/// with corrections behind it.
///
/// Snooze and pin do NOT appear here. They govern whether the engine ASKS,
/// which is [`Vault::graduation_offers`]'s question; this one is what authority
/// is live, and an offer the owner has declined for now is still an offer they
/// may accept. Keeping them orthogonal is why a snooze can never quietly cost
/// the owner a graduation they wanted.
pub(super) fn derive_state_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    scope: &RampScope,
    counters: Counters,
) -> Result<RampState> {
    if !scope.is_graduatable() {
        return Ok(RampState::Propose);
    }
    if active_grant_ref_in_txn(vault, txn, scope)?.is_some() {
        return Ok(RampState::Graduated);
    }
    let policy =
        crate::edit_distance::graduation::graduation_policy_in_txn(&vault.store, txn, scope)?;
    let corrections = counters.amended.saturating_add(counters.rejected);
    if policy.is_cleared_by(counters.untouched_streak, corrections) {
        return Ok(RampState::Offered);
    }
    Ok(RampState::Propose)
}

/// Whether an offer is standing for this scope right now — ED-05's atomic
/// pre-check, so an answer cannot be recorded against an offer a ruling
/// retracted while the owner was reading it.
pub(crate) fn offer_is_standing_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    scope: &RampScope,
) -> Result<bool> {
    let counters = read_counters_in_txn(&vault.store, txn, scope)?;
    Ok(derive_state_in_txn(vault, txn, scope, counters)? == RampState::Offered)
}

/// Every scope with a statistics row, fully derived.
///
/// The enumeration behind both [`Vault::graduation_offers`] and ED-05's trust
/// table: one scan, one place the all-scopes read can be got wrong.
pub(crate) fn ramp_stats_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
) -> Result<Vec<ScopeOutcomeStats>> {
    let mut rows = Vec::new();
    for entry in vault
        .store
        .vault_meta
        .prefix_iter(txn, RAMP_STATS_KEY_PREFIX)?
    {
        let (_, raw) = entry?;
        let row: StoredScopeStats = decode_row(&raw, "ramp stats row")?;
        let (scope, counters) = stats_row_parts(row)?;
        let state = derive_state_in_txn(vault, txn, &scope, counters)?;
        rows.push(stats_view(scope, counters, state));
    }
    Ok(rows)
}

pub(super) fn stats_view(
    scope: RampScope,
    counters: Counters,
    state: RampState,
) -> ScopeOutcomeStats {
    ScopeOutcomeStats {
        scope,
        untouched_streak: counters.untouched_streak,
        amended: counters.amended,
        rejected: counters.rejected,
        last_outcome: counters.last_outcome,
        updated_at: counters.updated_at,
        state,
    }
}

/// Appends one demotion row and revokes the scope's standing grant, if any.
///
/// The receipt IS the row: a demotion writes exactly one durable record, which
/// [`demotion_receipts`] projects. Revoking and recording land in the caller's
/// transaction together, so no reader can observe a revoked grant with no
/// receipt explaining it — that is what "never silent" means mechanically.
pub(super) fn append_demotion_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    scope: &RampScope,
    reason: DemotionReason,
    at: u64,
) -> Result<()> {
    let grant_ref = scope.grant_ref()?;
    let grant_ref = crate::consent::revoke_standing_grant_in_txn(&vault.store, wtxn, &grant_ref)?
        .then_some(grant_ref);
    let row = StoredDemotion {
        v: RAMP_ROW_VERSION,
        op_kind: scope.op_kind.clone(),
        target_class: scope.target_class.clone(),
        actor: scope.actor.clone(),
        reason: reason.as_str().to_owned(),
        grant_ref,
        after_seq: vault.read_identity_topology_seq_in_txn(&*wtxn)?,
        at,
    };
    let data = encode_row(&row, "ramp demotion row encode failed")?;
    vault.store.vault_meta.put(
        wtxn,
        &ramp_row_key(RAMP_DEMOTION_KEY_PREFIX, at, &EntityId::now()),
        &data,
    )?;

    let mut counters = read_counters_in_txn(&vault.store, &*wtxn, scope)?;
    counters.apply_demotion(at);
    write_counters_in_txn(&vault.store, wtxn, scope, counters)
}

/// Appends the durable record of a ruling that has no ledger event of its own.
///
/// The row is what makes a door-recorded streak REAL: it is the receipt the
/// offer rests on, and it is what a rebuild refolds. Rulings resolved through
/// identity topology never reach here — their type-76 event is already both.
fn append_door_outcome_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    scope: &RampScope,
    outcome: ProposalOutcome,
    at: u64,
) -> Result<()> {
    let row = StoredRampOutcome {
        v: RAMP_ROW_VERSION,
        op_kind: scope.op_kind.clone(),
        target_class: scope.target_class.clone(),
        actor: scope.actor.clone(),
        outcome: outcome.as_str().to_owned(),
        after_seq: vault.read_identity_topology_seq_in_txn(&*wtxn)?,
        at,
    };
    let data = encode_row(&row, "ramp outcome row encode failed")?;
    vault.store.vault_meta.put(
        wtxn,
        &ramp_row_key(RAMP_OUTCOME_KEY_PREFIX, at, &EntityId::now()),
        &data,
    )?;
    Ok(())
}

/// What makes one folded ruling durable, and therefore refoldable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum OutcomeWitness {
    /// An identity-topology resolution event: the type-76 row IS the record,
    /// and the r7 proposal-outcome receipt projects it. Writing a ramp row too
    /// would double-count the same ruling on every refold.
    Ledger,
    /// No ledger event exists (the propose-lane door for surfaces outside
    /// identity topology), so the ramp appends its own outcome row.
    Door,
}

/// Folds one resolved proposal into its scope's counters, inside the caller's
/// write txn — the incremental maintenance half of the projection.
///
/// A ruling that is not clean DEMOTES a graduated scope in the same
/// transaction (ARCH-0055 r7): the owner correcting the engine is exactly the
/// evidence that the engine had not earned the right to stop asking.
///
/// Replicated resolutions do not pass through here — they arrive through sync
/// admission, which owns no ramp state, so a replica's counters stay behind
/// until [`Vault::rebuild_ramp_stats_from_receipts`] folds the ledger it did
/// receive. That is a deliberate boundary, not the division `identity_redirect`
/// draws: redirect rows ARE maintained at the sync reconciliation chokepoint.
/// The ramp can afford to differ because a graduated grant lives in
/// `vault_meta`, which no sync path writes — a replica holds no ramp authority
/// to be stale ABOUT, so lagging counters are fail-closed (it keeps proposing).
/// Surfacing offers on a replica from replicated rulings would be a design
/// amendment: fold at the sync reconcile chokepoint, as redirect does.
pub(super) fn record_outcome_for_scope_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    scope: &RampScope,
    outcome: ProposalOutcome,
    at: u64,
    witness: OutcomeWitness,
) -> Result<Counters> {
    if witness == OutcomeWitness::Door {
        append_door_outcome_in_txn(vault, wtxn, scope, outcome, at)?;
    }
    let mut counters = read_counters_in_txn(&vault.store, &*wtxn, scope)?;
    counters.apply_outcome(outcome, at);
    write_counters_in_txn(&vault.store, wtxn, scope, counters)?;

    if let Some(reason) = DemotionReason::for_outcome(outcome)
        && active_grant_ref_in_txn(vault, &*wtxn, scope)?.is_some()
    {
        append_demotion_in_txn(vault, wtxn, scope, reason, at)?;
        // The demotion folded exactly this into the store: our own counters,
        // demoted. No re-read needed.
        counters.apply_demotion(at);
    }
    Ok(counters)
}

/// [`record_outcome_for_scope_in_txn`] for callers that do not need the folded
/// counters back — the shape the identity-topology resolution door uses.
///
/// Measurement is universal and graduation is not: an identity-topology scope's
/// counters move here like any other scope's, and [`op_kind_is_ramp_eligible`]
/// is what keeps merge/split from ever reaching an offer, a grant, or an
/// apply-path check.
pub(crate) fn record_ramp_outcome_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    scope: &RampScope,
    outcome: ProposalOutcome,
    at: u64,
) -> Result<()> {
    record_outcome_for_scope_in_txn(vault, wtxn, scope, outcome, at, OutcomeWitness::Ledger)?;
    Ok(())
}

impl Vault {
    /// Every fold input, in [`FoldKey`] order.
    pub(super) fn ramp_fold_events_in_txn(
        &self,
        rtxn: &heed::RoTxn<'_>,
    ) -> Result<Vec<RampFoldEvent>> {
        let mut events = Vec::new();
        for (event_id, record) in self.resolution_events_in_txn(rtxn)? {
            let StoredIdentityOpAction::ProposalResolution { outcome, scope, .. } = &record.action
            else {
                continue;
            };
            events.push(RampFoldEvent {
                key: (record.seq, FOLD_RANK_LEDGER, event_id),
                scope: RampScope::from(scope),
                at: record.at,
                outcome: Some(*outcome),
            });
        }

        for entry in self
            .store
            .vault_meta
            .prefix_iter(rtxn, RAMP_OUTCOME_KEY_PREFIX)?
        {
            let (key, raw) = entry?;
            let row: StoredRampOutcome = decode_ramp_row(&raw, RAMP_OUTCOME_ROW_LABEL)?;
            let id = ramp_row_key_id(RAMP_OUTCOME_KEY_PREFIX, &key, RAMP_OUTCOME_ROW_LABEL)?;
            let outcome = ProposalOutcome::parse(&row.outcome)
                .ok_or(Error::CorruptedIndex(RAMP_OUTCOME_ROW_LABEL))?;
            events.push(RampFoldEvent {
                key: (row.after_seq, FOLD_RANK_RAMP_ROW, id),
                scope: stored_row_scope(
                    row.op_kind,
                    row.target_class,
                    row.actor,
                    RAMP_OUTCOME_ROW_LABEL,
                )?,
                at: row.at,
                outcome: Some(outcome),
            });
        }

        for entry in self
            .store
            .vault_meta
            .prefix_iter(rtxn, RAMP_DEMOTION_KEY_PREFIX)?
        {
            let (key, raw) = entry?;
            let row: StoredDemotion = decode_ramp_row(&raw, RAMP_DEMOTION_ROW_LABEL)?;
            let id = ramp_row_key_id(RAMP_DEMOTION_KEY_PREFIX, &key, RAMP_DEMOTION_ROW_LABEL)?;
            events.push(RampFoldEvent {
                key: (row.after_seq, FOLD_RANK_RAMP_ROW, id),
                scope: stored_row_scope(
                    row.op_kind,
                    row.target_class,
                    row.actor,
                    RAMP_DEMOTION_ROW_LABEL,
                )?,
                at: row.at,
                outcome: None,
            });
        }

        events.sort_unstable_by_key(|event| event.key);
        Ok(events)
    }

    /// Every identity-topology RESOLUTION event, with the duplicate suppression
    /// the receipt projection applies: a ruling the fold rejected because the
    /// proposal was already resolved never happened, so it is not an outcome
    /// here either.
    ///
    /// Enumeration runs over `identity_topology_events_in_txn` — the one
    /// surface the fold, the receipt projection and any rebuild share — and is
    /// therefore complete. The public receipt query is not a substitute: it
    /// visits only the newest `MAX_RECEIPT_QUERY_SCAN` rows of the family, so a
    /// rebuild driven from it would delete a whole projection and refold a
    /// suffix of its history.
    pub(super) fn resolution_events_in_txn(
        &self,
        rtxn: &heed::RoTxn<'_>,
    ) -> Result<Vec<(EntityId, crate::identity_topology::StoredIdentityOpEvent)>> {
        let fold =
            fold_identity_topology_log(&self.fold_effective_identity_topology_events_in_txn(rtxn)?);
        let superseded: std::collections::BTreeSet<EntityId> = fold
            .rejections
            .iter()
            .filter(|(_, reason)| {
                matches!(
                    reason,
                    IdentityTopologyRejection::ProposalAlreadyResolved { .. }
                )
            })
            .map(|(event_id, _)| *event_id)
            .collect();

        let mut resolutions = Vec::new();
        for event in self.identity_topology_events_in_txn(rtxn)? {
            if !matches!(event.action, IdentityTopologyAction::ResolveProposal { .. })
                || superseded.contains(&event.event_id)
            {
                continue;
            }
            let record = self
                .identity_topology_event_in_txn(rtxn, &event.event_id)?
                .ok_or(Error::CorruptedIndex("identity topology event index"))?;
            resolutions.push((event.event_id, record));
        }
        Ok(resolutions)
    }
}
