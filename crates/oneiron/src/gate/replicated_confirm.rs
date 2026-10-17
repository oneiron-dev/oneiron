//! Device-local confirmation for a newly materialized critical claim revision.

use crate::claim::{ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus};
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::store::{GateDecisionId, GateDecisionRecord, PendingGateConsentRecord, Store};

use super::ceiling::PolicyCriticality;
use super::confirm::{
    GATE_REASON_PENDING_REPLICATED_CRITICAL_CONFIRM, pending_row_holds_critical_confirm,
};
use super::constants::POLICY_SCHEMA_VERSION;
use super::decision::{GateOutcome, GateReasonCode};
use super::doors::GateConsentBinding;
use super::input::GateContentKind;
use super::resolution::{GateRetentionContext, resolve_policy_manifest};

/// Called only for a new or changed replicated body, after put validation.
/// Replication still lands the peer's bytes; its Auto stamp is not a local Clear.
/// The hold stays until this device's owner clears or declines it, and it never
/// rewrites the peer's bytes.
///
/// An ordinary pending row this device holds reviewed an earlier body, so it
/// cannot hold the arriving Auto revision: this device's own confirm replaces
/// it, and opens the claim's owner-answer obligation. A claim whose obligation
/// is open already stays held, and the put shows its owner an item for this
/// revision. A reserved predicate never takes the confirm road on this device:
/// only its owning door writes it, past the criticality ladder. A restrictive
/// `comm.*` claim only adds suppression, and a restriction always lands
/// usable: a Decline here would retract it outside the opt-out's own clear.
pub(crate) fn attach_replicated_critical_confirm_in_txn(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    claim_id: &EntityId,
    body: &ClaimBody,
) -> Result<()> {
    if body.lifecycle != ClaimLifecycleStatus::Active
        || body.approval != ClaimApprovalStatus::Auto
        || crate::comm::is_restrictive_comm_predicate(store, wtxn, &body.predicate)?
        || crate::claim::is_reserved_predicate(&body.predicate)
        || store
            .owner_answer_obligation_in_txn(wtxn, claim_id)?
            .is_some()
    {
        return Ok(());
    }
    if let Some(row) = store
        .pending_gate_consent_in_txn(wtxn, claim_id)?
        .filter(pending_row_holds_critical_confirm)
    {
        // A confirm parked before obligations were recorded is one.
        return store.open_owner_answer_obligation_in_txn(
            wtxn,
            claim_id,
            row.decision_id,
            &row.diff_handle,
        );
    }
    let policy = resolve_policy_manifest(store, &*wtxn)?;
    if policy.criticality_for_predicate(&body.predicate) != PolicyCriticality::Critical {
        return Ok(());
    }
    let binding = GateConsentBinding::for_claim(body, &policy)?;
    put_critical_confirm_item_in_txn(
        store,
        wtxn,
        claim_id,
        body,
        binding,
        GATE_REASON_PENDING_REPLICATED_CRITICAL_CONFIRM,
    )?;
    Ok(())
}

/// Parks a critical confirm on `body` under `reason`: a fresh pending
/// decision and its tray row, which opens the claim's obligation if none is
/// open. The confirm carries no actor and no Dreamer run.
pub(super) fn put_critical_confirm_item_in_txn(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    claim_id: &EntityId,
    body: &ClaimBody,
    binding: GateConsentBinding,
    reason: &str,
) -> Result<PendingGateConsentRecord> {
    let mut decision = GateDecisionRecord {
        version: 0,
        decision_id: GateDecisionId::from_bytes(store.clock.ulid()?),
        created_at: crate::ports::recorded_at_in_txn(store, wtxn)?,
        // This records B's outstanding verdict, not permission to act on Auto.
        outcome: GateOutcome::Pending.as_str().to_owned(),
        reason_codes: vec![GateReasonCode::PendingCriticalityFloor.as_str().to_owned()],
        receipt_reasons: Vec::new(),
        system_notices: Vec::new(),
        actor_class: "system".to_owned(),
        actor_ref: None,
        content_kind: GateContentKind::Claim.as_str().to_owned(),
        policy_manifest_version: POLICY_SCHEMA_VERSION.to_owned(),
        claim_id: Some(*claim_id.as_bytes()),
        grant_ref: None,
        diff_handle: binding.diff_handle,
        read_frontier_hash: binding.read_frontier_hash,
        redacted_at: None,
    };
    store.append_fresh_gate_decision_in_txn(wtxn, &mut decision)?;
    store.stamp_claim_gate_retention_context_in_txn(
        wtxn,
        decision.decision_id,
        claim_id,
        GateRetentionContext {
            world: Some(body.world.unwrap_or_else(crate::claim::base_world_id)),
            project: Some(body.scope_project),
            sub_project: None,
            thread: None,
        },
    )?;
    let pending = PendingGateConsentRecord {
        version: crate::store::PENDING_GATE_CONSENT_VERSION,
        claim_id: *claim_id.as_bytes(),
        decision_id: decision.decision_id,
        created_at: decision.created_at,
        diff_handle: decision.diff_handle,
        read_frontier_hash: decision.read_frontier_hash,
        reason_codes: vec![reason.to_owned()],
        // Neither a peer body nor an owner's item carries an authenticated
        // local Dreamer envelope.
        dreamer_run_id: None,
    };
    // This also writes the exact-confirm index and the ordinary tray indexes.
    store.put_pending_gate_consent_in_txn(wtxn, &pending)?;
    Ok(pending)
}
