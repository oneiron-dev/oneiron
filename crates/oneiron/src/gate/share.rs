//! Narrow adapter for the audience-crossing creation of a brief read grant.

use crate::entity_id::EntityId;
use crate::error::Result;
use crate::share::{Share, share_effect_target};
use crate::store::{GateDecisionId, Store};
use crate::write_envelope::WriteActor;

use super::{
    ExternalEffectGateInput, ExternalEffectPolicyRisk, GateActor, GateDecision,
    GateProvenanceHandles, check_external_effect_policy, resolve_policy_manifest,
};

pub(crate) fn check_share_create_policy(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    share_id: &EntityId,
    issuer: &WriteActor,
    share: &Share,
) -> Result<(GateDecisionId, GateDecision)> {
    let policy = resolve_policy_manifest(store, txn)?;
    let effect = share_create_effect(share_id, issuer, share)?;
    // Execution, not a preview: charge any governing connector budget and record
    // the real decision in the grant's transaction. Pending is never authority.
    let (id, decision, _) = check_external_effect_policy(store, txn, &effect, &policy, true)?;
    Ok((id, decision))
}

pub(crate) fn share_create_effect(
    share_id: &EntityId,
    issuer: &WriteActor,
    share: &Share,
) -> Result<ExternalEffectGateInput> {
    Ok(ExternalEffectGateInput {
        actor: GateActor {
            actor_class: issuer.actor_class().gate_actor_class().to_owned(),
            actor_ref: Some(issuer.entity_ref().to_hex()),
            delegation_grant_ref: None,
        },
        provenance: GateProvenanceHandles {
            actor_entity_ref: Some(issuer.entity_ref()),
            ..GateProvenanceHandles::default()
        },
        verb: "share_brief".to_owned(),
        channel: "shared_brief".to_owned(),
        channel_identity_ref: None,
        counterparty: Some(share.recipient_ref.to_hex()),
        // The consent composer target-pins brief_ref, but not counterparty or
        // provenance. Bind ALL immutable grant axes into that target, including
        // recipient, issuer, share id and canonical WORLD/FACET maximum. An
        // approval for one target cannot be redeemed for another share/scope.
        brief_ref: Some(share_effect_target(share_id, issuer, share)?),
        send_ref: None,
        standing_grant_ref: None,
        scoped_mcp_call: None,
        counterparty_first_touch: None,
        counterparty_opted_out: false,
        counterparty_opt_out_receipt_reason: None,
        // This read-grant operation is the issuer's explicit request. These
        // eligibility bits do not supply authority: the external-effect door
        // still requires an actual policy/standing grant or approve-once.
        has_opted_in: true,
        has_permission: true,
        policy_risk: ExternalEffectPolicyRisk::Normal,
    })
}
