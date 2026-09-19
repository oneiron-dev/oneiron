//! Gmail delegated sends require both live MailSend custody and one human approval.
use super::*;
use crate::channel_identity::{
    ChannelIdentityBinding, ChannelIdentityFulfillment, ChannelIdentityState, DelegatedGrant,
    DelegatedGrantScope, DelegatedProvisionRequest, delegated_custody_scopes,
};
use crate::channel_identity_provider::gmail_send::{
    GmailDelegatedSendSink, GmailSendMessage, GmailSendWire,
};
use crate::secret_custody::{
    CustodyClass, CustodyTier, SECRET_CUSTODY_SCHEMA_VERSION, SecretBinding, SecretCustodyFloor,
    SecretCustodyRecord, SecretCustodyStatus,
};

#[derive(Default)]
struct Wire {
    sent: Vec<(String, String, GmailSendMessage)>,
}
impl GmailSendWire for Wire {
    fn send_message(
        &mut self,
        secret: &str,
        mailbox: &str,
        message: &GmailSendMessage,
    ) -> crate::Result<String> {
        self.sent
            .push((secret.into(), mailbox.into(), message.clone()));
        Ok("gmail-message-42".into())
    }
}
fn fixture(
    vault: &Vault,
    send: bool,
) -> std::result::Result<(EntityId, OutboundDispatchActor), Box<dyn std::error::Error>> {
    let actor_id = entity(0x91);
    put_connector_task_actor(vault, actor_id, 1)?;
    let actor = OutboundDispatchActor::agent(actor_id);
    put_policy_manifest_bytes(
        vault,
        entity(0xE0),
        &policy_manifest(actor.actor_ref.as_deref().unwrap(), "email", &["send"]),
    )?;
    let mut scopes = delegated_custody_scopes("email", "member@example.com");
    let mut grant_scopes = vec![DelegatedGrantScope::MailRead];
    if send {
        scopes.push("mail.send".into());
        grant_scopes.push(DelegatedGrantScope::MailSend);
    }
    vault.register_secret(SecretCustodyRecord {
        schema_version: SECRET_CUSTODY_SCHEMA_VERSION,
        name: "oauth/gmail/member".into(),
        class: CustodyClass::CrossVault,
        device_only: true,
        value_bytes: b"token-not-a-receipt".to_vec(),
        status: SecretCustodyStatus::Active,
        registered_at: 1,
        rotated_at: None,
        rotation_generation: 0,
        bindings: vec![SecretBinding {
            effector: "connector:gmail".into(),
            tier_ceiling: CustodyTier::T0Doored,
            scopes,
        }],
        manifest_ref: String::new(),
        declared_paths: vec![],
        policy_floor_snapshot: SecretCustodyFloor::default(),
    })?;
    let identity = entity(0x92);
    vault.provision_delegated_identity(
        &identity,
        DelegatedProvisionRequest {
            channel: "email".into(),
            address_or_handle: "member@example.com".into(),
            binding: ChannelIdentityBinding::actor(actor_id),
            grant: DelegatedGrant::new("oauth/gmail/member", grant_scopes),
        },
        2,
    )?;
    vault.transition_channel_identity(
        &identity,
        ChannelIdentityState::PendingFulfillment,
        Some(ChannelIdentityFulfillment::Api),
        3,
        None,
    )?;
    vault.transition_channel_identity(&identity, ChannelIdentityState::Active, None, 4, None)?;
    Ok((identity, actor))
}
fn message() -> GmailSendMessage {
    GmailSendMessage {
        to: "recipient@example.com".into(),
        subject: "Subject".into(),
        body: "Message".into(),
    }
}
fn request(
    actor: OutboundDispatchActor,
    identity: EntityId,
    intent_ref: &str,
) -> OutboundDispatchRequest {
    OutboundDispatchRequest::new(
        format!("receipt:{intent_ref}"),
        intent_ref,
        OutboundIntent::from_trigger(
            OutboundIntentDraft::new("member", "send", "email", "recipient@example.com"),
            OutboundIntentTrigger::agent_immediate("session:gmail"),
        ),
        actor,
        OutboundDispatchGate::allow_when_policy_grants(),
        10,
        OutboundDeliveryWindowDecision::DeliverNow,
    )
    .channel_identity_ref(identity)
}
#[test]
fn gmail_send_approved_dispatch_emits_receipt_and_approval_cannot_be_rearmed()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let (_dir, vault) = temp_vault();
    let (identity, actor) = fixture(&vault, true)?;
    vault
        .memory(entity(0x91), EdgeActorClass::Human)
        .approve_gmail_message("intent:gmail", identity, &message())?;
    let mut sink = GmailDelegatedSendSink::new(&vault, Wire::default()).with_message(
        "intent:gmail".into(),
        identity,
        message(),
    )?;
    let result =
        vault.dispatch_outbound_intent(request(actor, identity, "intent:gmail"), &mut sink)?;
    assert_eq!(result.outcome, OutboundDispatchOutcome::DeliveredToChannel);
    assert_eq!(
        result
            .receipt
            .fields
            .get("provider_ref")
            .map(String::as_str),
        Some("gmail-message-42")
    );
    assert_eq!(
        sink.wire().sent,
        vec![(
            "oauth/gmail/member".into(),
            "member@example.com".into(),
            message()
        )]
    );
    assert!(
        vault
            .memory(entity(0x91), EdgeActorClass::Human)
            .approve_gmail_message("intent:gmail", identity, &message())
            .is_err()
    );
    Ok(())
}
#[test]
fn gmail_send_unapproved_readonly_and_changed_payload_fail_closed()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    for mode in ["unapproved", "readonly", "changed"] {
        let (_dir, vault) = temp_vault();
        let (identity, actor) = fixture(&vault, mode != "readonly")?;
        let mut outgoing = message();
        if mode == "readonly" {
            assert!(
                vault
                    .verify_delegated_custody(
                        "email",
                        "member@example.com",
                        &DelegatedGrant::new(
                            "oauth/gmail/member",
                            vec![DelegatedGrantScope::MailSend]
                        )
                    )
                    .is_err()
            );

            assert!(
                vault
                    .memory(entity(0x91), EdgeActorClass::Human)
                    .approve_gmail_message("intent:gmail", identity, &outgoing)
                    .is_err()
            );
        } else if mode == "changed" {
            vault
                .memory(entity(0x91), EdgeActorClass::Human)
                .approve_gmail_message("intent:gmail", identity, &outgoing)?;
            outgoing.body.push_str(" substituted");
        }
        assert!(
            vault
                .memory(entity(0x91), EdgeActorClass::Agent)
                .approve_gmail_message("intent:agent", identity, &outgoing)
                .is_err()
        );
        let mut sink = GmailDelegatedSendSink::new(&vault, Wire::default()).with_message(
            "intent:gmail".into(),
            identity,
            outgoing,
        )?;
        let result =
            vault.dispatch_outbound_intent(request(actor, identity, "intent:gmail"), &mut sink)?;
        assert_eq!(result.outcome, OutboundDispatchOutcome::Failed, "{mode}");
        assert!(sink.wire().sent.is_empty());
    }
    Ok(())
}
