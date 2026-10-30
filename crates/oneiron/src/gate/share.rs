//! Narrow adapter for the audience-crossing creation of a brief read grant.

use crate::entity_id::EntityId;
use crate::error::Result;
use crate::share::{Share, share_effect_target};
use crate::store::Store;
use crate::write_envelope::WriteActor;

use super::{
    ExternalEffectCheck, ExternalEffectGateInput, ExternalEffectPolicyRisk, GateActor,
    GateProvenanceHandles, check_external_effect_policy_paced, resolve_policy_manifest,
};

pub(crate) fn check_share_create_policy(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    share_id: &EntityId,
    issuer: &WriteActor,
    share: &Share,
    travel: &crate::share_travel::TravelChoice,
) -> Result<ExternalEffectCheck> {
    let policy = resolve_policy_manifest(store, txn)?;
    let effect = share_create_effect(share_id, issuer, share, travel)?;
    // Execution, not a preview: charge any governing connector budget and record
    // the real decision in the grant's transaction. Pending is never authority.
    // A full count-bound window paces the share instead (FIX 12155).
    check_external_effect_policy_paced(store, txn, &effect, &policy)
}

pub(crate) fn share_create_effect(
    share_id: &EntityId,
    issuer: &WriteActor,
    share: &Share,
    travel: &crate::share_travel::TravelChoice,
) -> Result<ExternalEffectGateInput> {
    Ok(ExternalEffectGateInput {
        actor: GateActor {
            actor_class: issuer.actor_class().gate_actor_class().to_owned(),
            actor_ref: Some(issuer.entity_ref().to_hex()),
            delegation_grant_ref: None,
        },
        provenance: GateProvenanceHandles {
            actor_entity_ref: Some(issuer.entity_ref()),
            // FIX 11921: the run the issuer writes for, if any.
            run_attempt: issuer.run_attempt(),
            ..GateProvenanceHandles::default()
        },
        verb: "share_brief".to_owned(),
        channel: "shared_brief".to_owned(),
        channel_identity_ref: None,
        counterparty: Some(share.recipient_ref.to_hex()),
        // The consent composer target-pins brief_ref, but not counterparty or
        // provenance. Bind ALL immutable grant axes into that target, including
        // recipient, issuer, share id, canonical WORLD/FACET maximum and the
        // born-with text chosen to travel. An approval for one target cannot
        // be redeemed for another share, scope or travel choice.
        brief_ref: Some(share_effect_target(share_id, issuer, share, travel)?),
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
        send_autonomy: None,
    })
}
