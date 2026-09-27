//! Actor-attributed proposal observation with scoped advisory policy rows.
use crate::claim::{ClaimApprovalStatus, ClaimBody};
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::store::Store;
use crate::write_envelope::WriteEnvelope;
use heed::RwTxn;

pub(super) struct ProposedPut<'a> {
    pub(super) body: Option<&'a ClaimBody>,
    pub(super) envelope: Option<&'a WriteEnvelope>,
    pub(super) policy: Option<&'a crate::gate::PolicyManifestResolution>,
    pub(super) body_changed: bool,
    pub(super) replicated: bool,
}

pub(super) fn observe_proposed_put(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    id: EntityId,
    put: ProposedPut<'_>,
) -> Result<()> {
    // Replays and envelope-less system puts cannot be attributed to an actor.
    let Some(body) = put
        .body
        .filter(|body| body.approval == ClaimApprovalStatus::Proposed)
    else {
        return Ok(());
    };
    if put.replicated {
        return Ok(());
    }
    let Some(envelope) = put.envelope else {
        return Ok(());
    };
    // Use stored claim axes, never caller-supplied policy selectors.
    let scope = crate::gate::policy_values::PolicyEvaluationScope {
        world: Some(body.world.unwrap_or_else(crate::claim::base_world_id)),
        project: Some(body.scope_project),
        ..Default::default()
    };
    let threshold = match put.policy {
        Some(policy) => policy.proposal_check_threshold_in_scope(&scope),
        None => crate::gate::resolve_policy_manifest(store, &*wtxn)?
            .proposal_check_threshold_in_scope(&scope),
    };
    crate::gate::proposal_observation::observe_submission_in_txn(
        store,
        wtxn,
        envelope.actor().entity_ref(),
        &format!("claim:{}", id.to_hex()),
        threshold,
        put.body_changed,
    )
}
