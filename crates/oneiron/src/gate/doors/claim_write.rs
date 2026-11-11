//! Claim write entry seams plus the phase-ordered inner executor.

mod closer;
mod decision_context;
mod record_inner;
mod reference_hook;
mod reference_read;
mod stored_close;

use record_inner::check_claim_policy_for_write_with_record_inner;
pub(crate) use reference_hook::check_claim_policy_for_write_with_record_with_reader_reference_probe;
pub(crate) use reference_read::unresolved_claim_reference;
use stored_close::{closes_stored_row_only, closes_stored_value};

use super::burst_inputs::claim_burst_inputs;
use super::consent::{
    GateConsentBinding, claim_gate_input, enforce_claim_gate_decision_with_consent,
    gate_decision_matches_pending_candidate, reject_gate_decision,
};
use super::dreamer_run::{
    dreamer_attempt_id_from_write_envelope, dreamer_isolation_decision, dreamer_precommit_denial,
    dreamer_run_id_from_write_envelope, live_run_claim_put_from_write_envelope,
    pending_consent_dreamer_run_id,
};
use super::peripheral::{
    ClaimGateWrite, GateWriteMode, auto_check_value_preview, edge_actor_class_str,
    local_write_actor_entity_ref, validate_write_envelope, write_envelope_actor_ref,
};
use super::recorded::RecordedClaimGateDecision;
use crate::claim::{
    ClaimApprovalStatus, ClaimBody, DreamerIsolationClass, claim_sensitivity_band,
    dreamer_isolation_class,
};
use crate::claim_check::{AutoCheckCandidate, AutoCheckOutcome};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::gate::confirm::{
    GATE_REASON_ALLOW_CRITICAL_CONFIRM_ATTACHED, GATE_REASON_ALLOW_CRITICAL_OWNER_AUTHORED,
    GATE_REASON_ALLOW_FALLBACK_CRITICALITY, GATE_REASON_PENDING_CRITICAL_CONFIRM_ATTACHED,
    critical_claim_can_land_auto_with_confirm, pending_row_holds_critical_confirm,
};
use crate::gate::constants::LOCAL_WRITE_ACTOR_CLASS;
use crate::gate::decision::{GateDecision, GateOutcome, GateReasonCode};
use crate::gate::definition_ceiling::agent_definition_ceiling_for_actor;
use crate::gate::delegation_chain::evaluate_with_delegation_chain;
use crate::gate::input::{GateActor, GateContentKind, GateProvenanceHandles};
use crate::gate::resolution::{PolicyManifestResolution, check_claim_source_trust};
use crate::gate::weave_grant::{GATE_REASON_ALLOW_WEAVE_GRANT, landing_weave_grant_in_txn};
use crate::store::{
    GateDecisionId, GateDecisionRecord, PendingGateConsentRecord, Store, TrayRemoval,
    checker_hold_receipt_reason,
};
use crate::write_envelope::{SourceLineage, WriteEnvelope};

/// The receipt reason of a write held because its value does not fit the auto
/// checker's preview, so no checker could review all of it.
const CHECKER_PARTIAL_VIEW_RECEIPT_REASON: &str = "checker_partial_view";

/// The claim write door.
///
/// `operation_effect_body` is the HOST-CONSTRUCTED synthetic-operation mode
/// the GATE-12 block below describes: it is spelled at the call site, never
/// derived from the body, envelope, provenance, predicate, value, approval or
/// actor, and every persisted-candidate caller passes `false`. The seam is an
/// explicit parameter rather than a `GateWriteMode` field so that a caller
/// cannot inherit it by copying a mode value around: a door that means it has
/// to say so, here, in its own call.
// The synthetic-operation mode is spelled beside the axis tuple rather than
// folded into it, for the reason the doc comment gives.
pub(crate) fn check_claim_policy_for_write(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    id: &EntityId,
    write: ClaimGateWrite<'_>,
    policy: &PolicyManifestResolution,
    mode: GateWriteMode,
    operation_effect_body: bool,
) -> Result<()> {
    let mut recorded_decision = None;
    check_claim_policy_for_write_with_record_inner(
        store,
        wtxn,
        id,
        write,
        policy,
        mode,
        &mut recorded_decision,
        None,
        operation_effect_body,
        false,
        None,
        false,
    )
}

// The pending-bind seam threads the preflight receipt identity one parameter
// further than the record seam; bundling the axis tuple would hide the
// preflight decision binding this lane opened.
pub(crate) fn check_claim_policy_for_write_with_preflight_decision(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    id: &EntityId,
    write: ClaimGateWrite<'_>,
    policy: &PolicyManifestResolution,
    mode: GateWriteMode,
    preflight_decision_id: Option<GateDecisionId>,
) -> Result<()> {
    let mut recorded_decision = None;
    check_claim_policy_for_write_with_record_inner(
        store,
        wtxn,
        id,
        write,
        policy,
        mode,
        &mut recorded_decision,
        preflight_decision_id,
        // The batch/replay claim door only ever carries PERSISTED candidates,
        // so it never opens the synthetic-operation mode.
        false,
        false,
        None,
        false,
    )
}

pub(crate) fn check_claim_policy_for_write_with_record(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    id: &EntityId,
    write: ClaimGateWrite<'_>,
    policy: &PolicyManifestResolution,
    mode: GateWriteMode,
    recorded_decision: &mut Option<RecordedClaimGateDecision>,
) -> Result<()> {
    check_claim_policy_for_write_with_record_inner(
        store,
        wtxn,
        id,
        write,
        policy,
        mode,
        recorded_decision,
        None,
        // Every caller of the record seam writes a persisted candidate.
        false,
        false,
        None,
        false,
    )
}

/// [`check_claim_policy_for_write_with_record`] for a writer whose own scoped
/// read the caller holds (OF-063, FIX 1218): every typed record ref the body
/// names must resolve under `reader` in this final write's snapshot. One that
/// does not is the door's verdict, a hard Deny
/// (`gate.deny.unresolved_record_reference`) recorded on the ordinary path,
/// that no isolation, confirmation, checker, source trust or Proposed lane
/// overrides. Missing and unreadable are the same refusal. Everything else is
/// the record seam's, unchanged; a trusted caller with no reader keeps that
/// seam.
#[expect(
    clippy::too_many_arguments,
    reason = "the record seam's arguments plus the writer's own scoped read"
)]
pub(crate) fn check_claim_policy_for_write_with_record_with_reader(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    id: &EntityId,
    write: ClaimGateWrite<'_>,
    policy: &PolicyManifestResolution,
    mode: GateWriteMode,
    recorded_decision: &mut Option<RecordedClaimGateDecision>,
    reader: &crate::claim::ScopedRead<'_>,
) -> Result<()> {
    check_claim_policy_for_write_with_record_inner(
        store,
        wtxn,
        id,
        write,
        policy,
        mode,
        recorded_decision,
        None,
        false,
        false,
        Some(reader),
        false,
    )
}

/// [`check_claim_policy_for_write`] for a claim an off-record room stages
/// (FIX 9967): the same judgment under base policy, which keeps the decision
/// it judged for the room to stage beside the claim, in the claim's own
/// overlay segment. It appends nothing, records no metric and touches no key
/// custody, whatever `mode` says of recording. The decision, with the
/// retention scope its claim names, is the caller's only once the check
/// passes; `None` when no policy verdict was reached.
pub(crate) fn capture_claim_policy_for_write(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    id: &EntityId,
    write: ClaimGateWrite<'_>,
    policy: &PolicyManifestResolution,
    mode: GateWriteMode,
) -> Result<Option<crate::store::RoomGateDecision>> {
    // The scope a base write stamps beside its decision, as it does.
    let context = crate::gate::GateRetentionContext {
        world: Some(write.body.world.unwrap_or_else(crate::claim::base_world_id)),
        project: Some(write.body.scope_project),
        sub_project: None,
        thread: None,
    };
    let mut captured = None;
    check_claim_policy_for_write_with_record_inner(
        store,
        wtxn,
        id,
        write,
        policy,
        GateWriteMode {
            record_decision: false,
            ..mode
        },
        &mut captured,
        None,
        // A room stages a persisted candidate.
        false,
        false,
        None,
        true,
    )?;
    Ok(captured.map(
        |recorded: RecordedClaimGateDecision| crate::store::RoomGateDecision {
            record: recorded.into_record(),
            context,
        },
    ))
}

/// Whether the source-trust step this door ends on would let `body` land
/// `Auto` from `envelope` under `policy`. A writer asks before it requests
/// `Auto`, so a source the policy does not trust stays where it landed
/// instead of failing the write.
pub(crate) fn claim_source_trust_admits_auto(
    body: &ClaimBody,
    envelope: &WriteEnvelope,
    policy: &PolicyManifestResolution,
) -> bool {
    let mut auto = body.clone();
    auto.approval = ClaimApprovalStatus::Auto;
    let actor_ref = write_envelope_actor_ref(Some(envelope));
    check_claim_source_trust(
        &auto,
        actor_ref.as_deref(),
        policy,
        Some(envelope.lineage()),
    )
    .is_ok()
}
