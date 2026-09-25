//! Owner presentation must ride the ordinary gate, frozen payload and recovery.
use super::*;
use crate::channel_identity::{
    ChannelIdentity, ChannelIdentityBinding, ChannelIdentityState, SelfHeldShape,
};
use crate::channel_identity_autonomy::{FrozenSpacePosting, GroupPostingPreset};
use crate::outbound_chokepoint::{
    OutboundEffectCommand, OutboundTransport, execute_outbound_effect,
};
use crate::outbound_intent_ledger::{
    FrozenOutboundCall, IntentState, OutboundSendOutcome, intent_ledger_records,
};
use std::rc::Rc;

#[derive(Default)]
struct PostingSink {
    presentations: Vec<Option<FrozenSpacePosting>>,
    fail: bool,
}
impl OutboundExecutionSink for PostingSink {
    fn execute(&mut self, request: &OutboundExecutionRequest<'_>) -> OutboundExecutionOutcome {
        self.presentations.push(request.space_posting.clone());
        if self.fail {
            OutboundExecutionOutcome::failed("definite non-delivery")
        } else {
            OutboundExecutionOutcome::delivered_to_channel("posting-fixture")
        }
    }
}
struct UncalledTransport;
impl OutboundTransport for UncalledTransport {
    fn send(&mut self, _: &FrozenOutboundCall) -> OutboundSendOutcome {
        panic!("revoked owner presentation reached recovery transport")
    }
}

#[test]
fn owner_presentation_is_frozen_gated_space_local_and_revocable_on_recovery()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let (_dir, vault) = temp_vault();
    let vault = Rc::new(vault);
    let actor = auto_agent_actor(&vault)?;
    let actor_ref = actor.actor_entity_ref.unwrap();
    put_policy_manifest_bytes(
        &vault,
        entity(0xD0),
        &policy_manifest(&actor_ref.to_hex(), "email", &["send"]),
    )?;
    let owner_id = entity(0x51);
    vault.put_entity(
        &owner_id,
        crate::registry::ENTITY_TYPE_PERSON,
        crate::temporal::TimeRange { start: 1, end: 1 },
        1,
        b"owner",
    )?;
    let owner = Rc::new(vault.authenticate_owner(
        owner_id,
        &owner_id.to_hex(),
        true,
        crate::store::GateDecisionId::now(),
    )?);
    let identity_id = entity(0x93);
    let mut identity = ChannelIdentity::requested(
        "email",
        "agent@example.com",
        SelfHeldShape::DedicatedAddress,
        ChannelIdentityBinding::actor(actor_ref),
        1,
    );
    identity.state = ChannelIdentityState::Active;
    vault.create_channel_identity(&identity_id, &identity)?;
    let make_request =
        |seq| email_send_dispatch_request(actor.clone(), seq).channel_identity_ref(identity_id);
    let target = make_request(0).intent.target;
    let mut sink = PostingSink::default();
    assert_eq!(
        vault
            .dispatch_outbound_intent(make_request(0), &mut sink)?
            .outcome,
        OutboundDispatchOutcome::DeliveredToChannel
    );
    assert_eq!(sink.presentations, vec![None]);
    vault.set_space_posting_preset(
        identity_id,
        &target,
        GroupPostingPreset::OwnerWithApproval,
        &owner,
        10,
    )?;
    let pending = make_request(1);
    assert_eq!(
        vault
            .dispatch_outbound_intent(pending.clone(), &mut sink)?
            .outcome,
        OutboundDispatchOutcome::Held
    );
    assert_eq!(sink.presentations.len(), 1);
    let bound = vault
        .space_posting_plan(identity_id, &target, Default::default())?
        .needs_owner_consent
        .unwrap();
    let grant_ref = bound.digest().to_hex();
    vault.create_standing_grant(&owner, bound)?;
    let sent = vault.dispatch_outbound_intent(pending, &mut sink)?;
    assert_eq!(sent.outcome, OutboundDispatchOutcome::DeliveredToChannel);
    let presentation = sink.presentations[1].as_ref().unwrap();
    assert_eq!(presentation.preset(), GroupPostingPreset::OwnerWithApproval);
    assert_eq!(presentation.space_ref(), target);
    assert_eq!(presentation.identity_ref(), identity_id.to_hex());
    assert_eq!(
        sent.receipt.fields.get("space_posting").map(String::as_str),
        Some("owner_with_approval")
    );
    assert_eq!(
        sent.receipt
            .fields
            .get("space_posting_policy_risk")
            .map(String::as_str),
        Some("true")
    );

    // An unrelated space cannot borrow the first space's grant.
    let mut other = make_request(2);
    other.intent.target = "another@example.com".to_owned();
    vault.set_space_posting_preset(
        identity_id,
        &other.intent.target,
        GroupPostingPreset::OwnerWithApproval,
        &owner,
        11,
    )?;
    assert_eq!(
        vault.dispatch_outbound_intent(other, &mut sink)?.outcome,
        OutboundDispatchOutcome::Held
    );
    assert_eq!(sink.presentations.len(), 2);

    // The old paid admission does not preserve a subsequently revoked right.
    sink.fail = true;
    let retry = make_request(3);
    assert_eq!(
        vault
            .dispatch_outbound_intent(retry.clone(), &mut sink)?
            .outcome,
        OutboundDispatchOutcome::Failed
    );
    let ledger = intent_ledger_records(&vault)?;
    let pending_id = ledger
        .records
        .iter()
        .find(|row| row.state == IntentState::Pending)
        .unwrap()
        .id;
    let v = vault.clone();
    let o = owner.clone();
    crate::outbound_chokepoint::BEFORE_NEW_ADMISSION.with(|hook| {
        *hook.borrow_mut() = Some(Box::new(move || {
            v.revoke_consent_grant(&o, &grant_ref).unwrap();
        }));
    });
    assert_eq!(
        vault.dispatch_outbound_intent(retry, &mut sink)?.outcome,
        OutboundDispatchOutcome::Held
    );
    assert_eq!(sink.presentations.len(), 3);
    let authority = crate::outbound_consent::OutboundBindingAuthority::for_vault(&vault)?;
    let recovered = execute_outbound_effect(
        &vault,
        &authority,
        OutboundEffectCommand::Resume(pending_id),
        2000,
        &mut UncalledTransport,
    )?;
    assert_eq!(recovered.gate_outcome.as_deref(), Some("pending"));
    assert_eq!(recovered.dispatch.state, Some(IntentState::Pending));

    // Draft-only is not a send permission, even if someone separately grants
    // the matching presentation envelope.
    vault.set_space_posting_preset(
        identity_id,
        &target,
        GroupPostingPreset::OwnerDrafts,
        &owner,
        12,
    )?;
    let draft_bound = vault
        .space_posting_plan(identity_id, &target, Default::default())?
        .needs_owner_consent
        .unwrap();
    vault.create_standing_grant(&owner, draft_bound)?;
    assert_eq!(
        vault
            .dispatch_outbound_intent(make_request(4), &mut sink)?
            .outcome,
        OutboundDispatchOutcome::Held
    );
    assert_eq!(sink.presentations.len(), 3);
    Ok(())
}
