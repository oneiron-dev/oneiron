//! Per-rail outbound SOW contract and local qualification probes. These exercise the
//! engine boundary with a fake transport, not a live provider credential.

use super::*;

const RAILS: &[(&str, &str, OutboundRetryClass, bool)] = &[
    ("line", "push", OutboundRetryClass::IdempotentNative, false),
    (
        "telegram",
        "send",
        OutboundRetryClass::IdempotentEmulated,
        false,
    ),
    (
        "slack",
        "send",
        OutboundRetryClass::IdempotentEmulated,
        false,
    ),
    (
        "discord",
        "send",
        OutboundRetryClass::IdempotentNative,
        false,
    ),
    (
        "discord",
        "cold_dm",
        OutboundRetryClass::IdempotentNative,
        true,
    ),
    ("apns", "push", OutboundRetryClass::IdempotentEmulated, true),
    (
        "imessage_mfb",
        "send",
        OutboundRetryClass::IdempotentNative,
        true,
    ),
    (
        "imessage_bridge",
        "send",
        OutboundRetryClass::IdempotentEmulated,
        true,
    ),
    (
        "email_resend",
        "send",
        OutboundRetryClass::IdempotentNative,
        true,
    ),
    (
        "email_ses",
        "send",
        OutboundRetryClass::IdempotentEmulated,
        true,
    ),
    (
        "email_postmark",
        "send",
        OutboundRetryClass::IdempotentEmulated,
        true,
    ),
    (
        "voice",
        "call",
        OutboundRetryClass::IdempotentEmulated,
        true,
    ),
];

#[test]
fn every_adapter_declares_a_real_retry_and_permission_contract() {
    for &(channel, verb, ref retry_class, policy_risk) in RAILS {
        let manifest = outbound_capability_manifest(channel).expect("adapter manifest");
        let contract = outbound_verb_contract(channel, verb).expect("adapter verb");
        assert_eq!(&contract.retry_class, retry_class, "{channel}.{verb}");
        assert_eq!(
            contract.capability_vs_permission.policy_risk, policy_risk,
            "{channel}.{verb}"
        );
        assert!(!contract.channel_call.is_empty());
        assert!(!contract.capability_vs_permission.note.is_empty());
        assert_eq!(
            manifest.verified_at,
            contract.capability_vs_permission.verified_at
        );
        assert!(outbound_verb_contract(channel, "not_a_verb").is_err());
    }
    for manifest in outbound_capability_manifests() {
        for kind in &manifest.message_verbs {
            assert!(
                manifest.verbs.iter().any(|verb| &verb.kind == kind),
                "{}.{} projects without a declared operation",
                manifest.connector,
                kind
            );
        }
    }
    let discord = outbound_capability_manifest("discord").expect("Discord manifest");
    assert!(discord.message_verbs.contains(&"cold_dm".to_owned()));
    assert_eq!(
        serde_json::to_value(discord).unwrap()["message_verbs"],
        serde_json::json!(["send", "cold_dm"])
    );
    let cold_dm = outbound_verb_contract("discord", "cold_dm").expect("declared cold DM");
    assert_eq!(
        cold_dm.interruption_class,
        OutboundInterruptionClass::Ambient
    );
    assert!(cold_dm.capability_vs_permission.policy_risk);
    // The generic window door reads the resolved interruption_class. This
    // connector-specific operation is not a raw-name ambient exception.
    assert!(!outbound_delivery_window_is_chat_like_ambient(
        &OutboundIntent::from_trigger(
            OutboundIntentDraft::new("agent", "cold_dm", "discord", "owner"),
            OutboundIntentTrigger::agent_immediate("manifest-row"),
        ),
        cold_dm,
        None
    ));

    for channel in ["slack", "discord"] {
        let manifest = outbound_capability_manifest(channel).unwrap();
        assert_eq!(manifest.connector_family, "workspace_bot");
        assert_eq!(manifest.family, Some("workspace_bot"));
        assert_eq!(
            serde_json::to_value(manifest).unwrap()["connector_family"],
            "workspace_bot"
        );
        assert_eq!(
            serde_json::to_value(manifest).unwrap()["family"],
            "workspace_bot"
        );
    }
    assert_eq!(
        outbound_verb_contract("line", "push").unwrap().params["X-Line-Retry-Key"],
        "frozen ledger idempotency key"
    );
    assert_eq!(
        outbound_verb_contract("discord", "send").unwrap().params["enforce_nonce"],
        true
    );
    assert_eq!(
        outbound_verb_contract("imessage_mfb", "send")
            .unwrap()
            .params["message_uuid"],
        "stable provider-valid UUID derived from frozen ledger idempotency key"
    );
    for channel in ["email_ses", "email_postmark", "apns", "telegram", "slack"] {
        assert_eq!(
            outbound_verb_contract(channel, if channel == "apns" { "push" } else { "send" })
                .unwrap()
                .retry_class,
            OutboundRetryClass::IdempotentEmulated,
            "{channel} must not claim provider-native dedupe"
        );
    }
    assert_eq!(
        outbound_verb_contract("email_resend", "send")
            .unwrap()
            .params["provider_idempotency_header"],
        "Idempotency-Key"
    );
    assert_eq!(
        outbound_verb_contract("imessage_mfb", "invite")
            .unwrap()
            .capability_vs_permission
            .permission,
        OutboundPermissionState::ProviderReview
    );
    assert!(outbound_verb_contract("imessage_bridge", "invite").is_err());
}

fn qualification_request(
    channel: &str,
    verb: &str,
    actor: EntityId,
    tag: &str,
) -> OutboundDispatchRequest {
    let intent = OutboundIntent::from_trigger(
        OutboundIntentDraft::new("agent", verb, channel, "counterparty:qualified")
            .content_ref("content:qualified")
            .idempotency_key(format!("idem:{tag}")),
        OutboundIntentTrigger::agent_immediate("session:qualified"),
    );
    OutboundDispatchRequest::new(
        format!("outbound:intent:{tag}"),
        format!("intent:{tag}"),
        intent,
        OutboundDispatchActor::agent(actor),
        OutboundDispatchGate::allow_when_policy_grants(),
        1_000,
        OutboundDeliveryWindowDecision::DeliverNow,
    )
}

#[test]
fn adapter_qualification_replay_timeout_scope_and_degrade() -> Result<(), Box<dyn std::error::Error>>
{
    for (index, &(channel, verb, ref retry_class, _)) in RAILS.iter().enumerate() {
        let (_tmp, vault) = temp_vault();
        let actor = entity(0x70);
        vault.put_entity(
            &actor,
            crate::registry::ENTITY_TYPE_PERSON,
            crate::temporal::TimeRange { start: 1, end: 1 },
            1,
            b"agent",
        )?;
        put_policy_manifest_bytes(
            &vault,
            entity(0x71),
            &policy_manifest(&actor.to_hex(), channel, &[verb]),
        )?;
        let tag = format!("qual:{index}");
        let request = qualification_request(channel, verb, actor, &tag);
        let mut sink = RecordingExecutor::default();
        let first = vault.dispatch_outbound_intent(request.clone(), &mut sink)?;
        assert_eq!(
            first.outcome,
            OutboundDispatchOutcome::DeliveredToChannel,
            "{channel}"
        );
        let replay = vault.dispatch_outbound_intent(request, &mut sink)?;
        assert_eq!(
            replay.outcome,
            OutboundDispatchOutcome::DeliveredToChannel,
            "{channel}"
        );
        assert_eq!(
            sink.calls.len(),
            1,
            "{channel}: same intent must have only one effect"
        );
        assert_eq!(
            sink.idempotency_keys[0].is_some(),
            *retry_class == OutboundRetryClass::IdempotentNative,
            "{channel}"
        );

        // Platform permission is distinct from the transport capability.
        let mut unpermitted =
            qualification_request(channel, verb, actor, &format!("unpermitted:{index}"));
        unpermitted.gate.has_permission = false;
        let blocked = vault.dispatch_outbound_intent(unpermitted, &mut sink)?;
        assert_eq!(
            blocked.outcome,
            OutboundDispatchOutcome::Held,
            "{channel}: missing permission"
        );
        assert_eq!(sink.calls.len(), 1);

        // A real but ungranted connector must not borrow this rail's grant.
        let escape = if channel == "email_ses" {
            "email_postmark"
        } else {
            "email_ses"
        };
        let denied = qualification_request(escape, "send", actor, &format!("denied:{index}"));
        let denied_result = vault.dispatch_outbound_intent(denied, &mut sink)?;
        assert_eq!(
            denied_result.outcome,
            OutboundDispatchOutcome::Held,
            "{channel}: scope escape must hold"
        );
        assert!(outbound_verb_contract("not_registered", verb).is_err());
        assert_eq!(
            sink.calls.len(),
            1,
            "{channel}: scope escape reached transport"
        );

        let mut ambiguous = RecordingExecutor {
            outcome: OutboundExecutionOutcome::failed("timeout").with_possible_delivery(),
            ..Default::default()
        };
        let timeout_request =
            qualification_request(channel, verb, actor, &format!("timeout:{index}"));
        let _ = vault.dispatch_outbound_intent(timeout_request.clone(), &mut ambiguous)?;
        ambiguous.outcome = OutboundExecutionOutcome::delivered_to_channel("provider:reconciled");
        let _ = vault.dispatch_outbound_intent(timeout_request, &mut ambiguous)?;
        assert_eq!(
            ambiguous.calls.len(),
            if *retry_class == OutboundRetryClass::IdempotentNative {
                2
            } else {
                1
            },
            "{channel}: timeout must not double-send without provider dedupe"
        );

        // The delivery-window decision is evaluated before any adapter call.
        let degraded = qualification_request(channel, verb, actor, &format!("degrade:{index}"));
        let degraded = OutboundDispatchRequest {
            window_decision: OutboundDeliveryWindowDecision::Degrade {
                reason: "quiet_window".to_owned(),
                from: channel.to_owned(),
                to: "ambient".to_owned(),
            },
            ..degraded
        };
        let mut quiet_sink = RecordingExecutor::default();
        let result = vault.dispatch_outbound_intent(degraded, &mut quiet_sink)?;
        assert!(
            matches!(
                result.outcome,
                OutboundDispatchOutcome::Degraded | OutboundDispatchOutcome::Held
            ),
            "{channel}"
        );
        assert!(
            quiet_sink.calls.is_empty(),
            "{channel}: interrupt reached transport during quiet window"
        );
    }
    Ok(())
}

fn risk_scoped_manifest(actor: &str, channel: &str, verb: &str, risk: &str) -> Vec<u8> {
    let mut value = rmpv::decode::read_value(&mut std::io::Cursor::new(policy_manifest(
        actor,
        channel,
        &[verb],
    )))
    .expect("decode policy fixture");
    let Value::Map(map) = &mut value else {
        panic!("policy fixture map")
    };
    let Value::Array(grants) = &mut map
        .iter_mut()
        .find(|(key, _)| key.as_str() == Some("scoped_grants"))
        .expect("scoped grants")
        .1
    else {
        panic!("grants array")
    };
    let Value::Map(grant) = &mut grants[0] else {
        panic!("grant map")
    };
    let Value::Map(selectors) = &mut grant
        .iter_mut()
        .find(|(key, _)| key.as_str() == Some("selectors"))
        .expect("selectors")
        .1
    else {
        panic!("selectors map")
    };
    selectors.push((Value::from("policy_risk"), Value::from(risk)));
    let mut data = Vec::new();
    rmpv::encode::write_value(&mut data, &value).expect("encode scoped grant");
    data
}

#[test]
fn adapter_capability_is_not_permission_and_an_owner_grant_can_enable_risk()
-> Result<(), Box<dyn std::error::Error>> {
    for (index, &(channel, verb, _, policy_risk)) in RAILS.iter().enumerate() {
        let (_tmp, vault) = temp_vault();
        let actor = entity(0x72);
        vault.put_entity(
            &actor,
            crate::registry::ENTITY_TYPE_PERSON,
            crate::temporal::TimeRange { start: 1, end: 1 },
            1,
            b"agent",
        )?;
        put_policy_manifest_bytes(
            &vault,
            entity(0x73),
            &risk_scoped_manifest(&actor.to_hex(), channel, verb, "normal"),
        )?;
        let mut sink = RecordingExecutor::default();
        let before = qualification_request(channel, verb, actor, &format!("permission:{index}"));
        let before_result = vault.dispatch_outbound_intent(before, &mut sink)?;
        if policy_risk {
            assert_eq!(
                before_result.outcome,
                OutboundDispatchOutcome::Held,
                "{channel}: risk without owner grant"
            );
            assert_eq!(before_result.gate_outcome, "pending", "{channel}");
            assert!(sink.calls.is_empty(), "{channel}: risk bypassed the gate");
            put_policy_manifest_bytes(
                &vault,
                entity(0x74),
                &risk_scoped_manifest(&actor.to_hex(), channel, verb, "hold_to_proposal"),
            )?;
            let granted = qualification_request(channel, verb, actor, &format!("granted:{index}"));
            let granted_result = vault.dispatch_outbound_intent(granted, &mut sink)?;
            assert_eq!(
                granted_result.outcome,
                OutboundDispatchOutcome::DeliveredToChannel,
                "{channel}: owner grant must execute"
            );
            assert_eq!(sink.calls.len(), 1);
        } else {
            assert_eq!(
                before_result.outcome,
                OutboundDispatchOutcome::DeliveredToChannel,
                "{channel}"
            );
        }
    }
    Ok(())
}

// Isolate this fixture's policy pack from the vault bootstrap pack. The gate
// test suite uses the same test-only deindex door for control-claim fixtures;
// the provider's exact-channel send grant remains in the pack below.
fn clear_bootstrap_policy(vault: &Vault) -> crate::Result<()> {
    let id = crate::gate::default_policy_manifest_id()?;
    vault.with_write_txn(|wtxn| crate::batch::deindex_entity_for_test(&vault.store, wtxn, &id))
}

// The test author writes comm control claims through the ordinary gate too.
// Grant those fixture writes without widening the outbound agent's exact
// provider/channel send grant.
fn provider_email_policy_manifest(actor: &str, channel: &str) -> Vec<u8> {
    let bytes = policy_manifest(actor, channel, &["send"]);
    let mut value =
        rmpv::decode::read_value(&mut std::io::Cursor::new(bytes)).expect("decode policy fixture");
    let Value::Map(entries) = &mut value else {
        panic!("policy map")
    };
    let Value::Array(rules) = &mut entries
        .iter_mut()
        .find(|(key, _)| key.as_str() == Some("rules"))
        .expect("rules")
        .1
    else {
        panic!("rules array")
    };
    rules.push(Value::Map(vec![
        (Value::from("prefix"), Value::from("comm.")),
        (
            Value::from("axes"),
            Value::Map(vec![
                (Value::from("criticality"), Value::from("normal")),
                (Value::from("sensitivity"), Value::from("normal")),
            ]),
        ),
    ]));
    let Value::Array(ceilings) = &mut entries
        .iter_mut()
        .find(|(key, _)| key.as_str() == Some("actor_ceilings"))
        .expect("ceilings")
        .1
    else {
        panic!("ceilings array")
    };
    ceilings.push(Value::Map(vec![
        (Value::from("actor_class"), Value::from("first_party")),
        (Value::from("ceiling"), Value::from("auto")),
    ]));
    let mut out = Vec::new();
    rmpv::encode::write_value(&mut out, &value).expect("encode policy fixture");
    out
}

/// A provider name remains an authorization key, but its recipient protections
/// and frozen email headers are shared with the email channel class.
#[test]
fn provider_email_opt_out_override_and_frozen_unsubscribe_headers()
-> Result<(), Box<dyn std::error::Error>> {
    use crate::campaign::send_hygiene::ListUnsubscribeTarget;
    use crate::comm::SendOverrideScope;
    use crate::edge::EdgeActorClass;
    use crate::receipt::ReceiptQuery;

    #[derive(Default)]
    struct EmailSink {
        headers: Vec<std::collections::BTreeMap<String, String>>,
    }
    impl OutboundExecutionSink for EmailSink {
        fn execute(&mut self, request: &OutboundExecutionRequest<'_>) -> OutboundExecutionOutcome {
            self.headers.push(request.hygiene_headers.clone());
            OutboundExecutionOutcome::delivered_to_channel("provider:accepted")
        }
    }

    for (index, channel) in ["email_resend", "email_ses", "email_postmark"]
        .iter()
        .enumerate()
    {
        let (_tmp, vault) = temp_vault();
        clear_bootstrap_policy(&vault)?;
        let actor = entity(0x76);
        vault.put_entity(
            &actor,
            crate::registry::ENTITY_TYPE_PERSON,
            crate::temporal::TimeRange { start: 1, end: 1 },
            1,
            b"agent",
        )?;
        put_policy_manifest_bytes(
            &vault,
            entity(0x77),
            &provider_email_policy_manifest(&actor.to_hex(), channel),
        )?;
        let contact_id = entity(0x78);
        let identity_ref = entity(0x79);
        let contact =
            CounterpartyContactRecord::user_introduction(identity_ref, "kenji@example.com", 10)?;
        vault
            .create_counterparty_contact(&contact_id, &contact)
            .expect("seed opted-out contact");
        vault
            .opt_out_counterparty_contact(&contact_id, CounterpartyOptOutReason::Unsubscribe, 20)
            .expect("record email opt-out");
        let tag = format!("provider-email:{index}");
        let mut request = qualification_request(channel, "send", actor, &tag)
            .channel_identity_ref(identity_ref)
            .counterparty_ref("kenji@example.com")
            .campaign_unsubscribe(ListUnsubscribeTarget {
                mailto_uri: Some("mailto:leave@example.com".to_owned()),
                https_one_click_uri: "https://example.com/unsubscribe".to_owned(),
            });
        request.intent.target = "kenji@example.com".to_owned();
        let mut sink = EmailSink::default();
        let held = vault.dispatch_outbound_intent(request.clone(), &mut sink)?;
        assert_eq!(held.outcome, OutboundDispatchOutcome::Held, "{channel}");
        assert_eq!(held.gate_outcome, "pending", "{channel}");
        assert_eq!(
            held.receipt.fields.get("hold_reason").map(String::as_str),
            Some("gate.pending.counterparty_opt_out"),
            "{channel}"
        );
        assert!(
            sink.headers.is_empty(),
            "{channel}: opted-out send crossed wire"
        );

        // Override validity uses the vault's trusted clock, not occurred_at.
        vault.clock.set(40);
        // Only a human may mint this receipted override. Both generic-email
        // and provider-spelled rulings share the recipient class, never the
        // connector's authorization key.
        let owner = entity(0x7a);
        vault.put_entity(
            &owner,
            crate::registry::ENTITY_TYPE_PERSON,
            crate::temporal::TimeRange { start: 1, end: 1 },
            1,
            b"owner",
        )?;
        crate::comm::mint_send_override(
            &vault,
            "kenji@example.com",
            Some(if index == 0 { "email" } else { channel }),
            SendOverrideScope::Standing,
            None,
            crate::WriteActor::new(owner, EdgeActorClass::Human),
            30,
            None,
        )
        .expect("owner mints receipted email send override");
        request.receipt_id = format!("outbound:intent:overridden:{index}");
        let sent = vault.dispatch_outbound_intent(request, &mut sink)?;
        assert_eq!(
            sent.outcome,
            OutboundDispatchOutcome::DeliveredToChannel,
            "{channel}: gate={:?}, receipt={:?}",
            sent.gate_reason_codes,
            sent.receipt.fields
        );
        assert_eq!(sink.headers.len(), 1, "{channel}");
        assert!(
            sink.headers[0].contains_key("List-Unsubscribe"),
            "{channel}"
        );
        assert_eq!(
            sink.headers[0]
                .get("List-Unsubscribe-Post")
                .map(String::as_str),
            Some("List-Unsubscribe=One-Click"),
            "{channel}"
        );
        assert!(
            sent.receipt
                .fields
                .get("gate_receipt_reasons")
                .is_some_and(|reasons| reasons.contains("comm_send_override_standing")),
            "{channel}"
        );
        assert!(
            vault
                .get_counterparty_contact(&contact_id)?
                .unwrap()
                .is_opted_out()
        );
        assert!(!vault.receipts(ReceiptQuery::new(10))?.is_empty());
    }
    Ok(())
}

#[test]
fn provider_email_honors_email_do_not_contact_head() -> Result<(), Box<dyn std::error::Error>> {
    for (index, channel) in ["email_resend", "email_ses", "email_postmark"]
        .iter()
        .enumerate()
    {
        for restriction in ["email", *channel] {
            check_email_dnc(channel, restriction, index)?;
        }
    }
    Ok(())
}

fn check_email_dnc(
    channel: &str,
    restriction: &str,
    index: usize,
) -> Result<(), Box<dyn std::error::Error>> {
    let (_tmp, vault) = temp_vault();
    clear_bootstrap_policy(&vault)?;
    let actor = entity(0x7b);
    vault.put_entity(
        &actor,
        crate::registry::ENTITY_TYPE_PERSON,
        crate::temporal::TimeRange { start: 1, end: 1 },
        1,
        b"agent",
    )?;
    put_policy_manifest_bytes(
        &vault,
        entity(0x7c),
        &provider_email_policy_manifest(&actor.to_hex(), channel),
    )?;
    let address = format!("restricted-{index}-{restriction}@example.com");
    let party = crate::comm::resolve_or_create_comm_party(&vault, &address)?;
    let mut dnc = ClaimBody::new(
        crate::campaign::claims::PREDICATE_COMM_DO_NOT_CONTACT,
        ClaimSubject::Entity(party),
        Value::Map(vec![
            (Value::from("channel"), Value::from(restriction)),
            (Value::from("scope"), Value::from("send")),
        ]),
        1.0,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
    );
    dnc.valid_from = Some(1);
    vault
        .put_claim(
            &entity(0x7d),
            &dnc,
            crate::temporal::TimeRange { start: 1, end: 1 },
            1,
        )
        .expect("seed do-not-contact head");
    assert_eq!(
        vault.get_claim(&entity(0x7d))?.expect("stored DNC").value,
        dnc.value,
        "{channel}: accepted restriction remains stored"
    );
    let mut request = qualification_request(
        channel,
        "send",
        actor,
        &format!("dnc:{index}:{restriction}"),
    )
    .counterparty_ref(&address);
    request.intent.target = address;
    let mut sink = RecordingExecutor::default();
    let held = vault.dispatch_outbound_intent(request, &mut sink)?;
    assert_eq!(held.outcome, OutboundDispatchOutcome::Held, "{channel}");
    assert!(
        held.receipt
            .fields
            .get("gate_receipt_reasons")
            .is_some_and(|reasons| reasons.contains("counterparty_opt_out_do_not_contact")),
        "{channel}"
    );
    assert!(sink.calls.is_empty(), "{channel}: DNC reached transport");
    Ok(())
}

#[test]
fn provider_key_stop_projects_email_contact_and_holds_each_provider_send()
-> Result<(), Box<dyn std::error::Error>> {
    use crate::channel_identity::{ChannelIdentityBinding, ChannelIdentityState, SelfHeldShape};
    for (index, channel) in ["email_resend", "email_ses", "email_postmark"]
        .iter()
        .enumerate()
    {
        let (_tmp, vault) = temp_vault();
        clear_bootstrap_policy(&vault)?;
        let actor = entity(0x81);
        vault.put_entity(
            &actor,
            crate::registry::ENTITY_TYPE_PERSON,
            crate::temporal::TimeRange { start: 1, end: 1 },
            1,
            b"agent",
        )?;
        put_policy_manifest_bytes(
            &vault,
            entity(0x82),
            &provider_email_policy_manifest(&actor.to_hex(), channel),
        )?;
        let identity_ref = entity(0x83);
        let identity = crate::test_util::self_held_identity_in_state(
            "email",
            "sender@example.com",
            SelfHeldShape::DedicatedAddress,
            ChannelIdentityBinding::actor(actor),
            ChannelIdentityState::Active,
            10,
        );
        vault.create_channel_identity(&identity_ref, &identity)?;
        let address = format!("stop-{index}@example.com");
        let contact_id = entity(0x84);
        vault.create_counterparty_contact(
            &contact_id,
            &CounterpartyContactRecord::user_introduction(identity_ref, &address, 10)?,
        )?;
        crate::comm::record_comm_inbound_stop(&vault, &address, channel, 30)?;
        crate::comm::run_comm_projector(&vault)?;
        let contact = vault
            .get_counterparty_contact(&contact_id)?
            .expect("projected contact");
        assert!(
            contact.is_opted_out(),
            "{channel}: STOP did not rematerialize email contact"
        );
        assert_eq!(
            contact.opt_out.expect("standing stop").reason,
            CounterpartyOptOutReason::Stop
        );
        let party = crate::comm::resolve_or_create_comm_party(&vault, &address)?;
        let rtxn = vault.store.env.read_txn()?;
        let heads = crate::comm::standing_opt_out_heads_in_txn(&vault, &rtxn, party)?;
        assert!(
            heads
                .iter()
                .any(|head| head.channel_class.as_deref() == Some("email")
                    && head.matches_channel(channel)),
            "{channel}: stored STOP class"
        );
        drop(rtxn);
        let mut request = qualification_request(channel, "send", actor, &format!("stop:{index}"))
            .channel_identity_ref(identity_ref)
            .counterparty_ref(&address);
        request.intent.target = address;
        let mut sink = RecordingExecutor::default();
        let held = vault.dispatch_outbound_intent(request, &mut sink)?;
        assert_eq!(held.outcome, OutboundDispatchOutcome::Held, "{channel}");
        assert_eq!(
            held.gate_reason_codes,
            vec!["gate.pending.counterparty_opt_out"],
            "{channel}"
        );
        assert!(
            sink.calls.is_empty(),
            "{channel}: STOP crossed provider wire"
        );
    }
    Ok(())
}

#[test]
fn discord_cold_dm_is_ambient_after_risk_grant_but_not_before()
-> Result<(), Box<dyn std::error::Error>> {
    for (index, minute) in [Some(23 * 60), None].into_iter().enumerate() {
        let (_tmp, vault) = temp_vault();
        let actor = entity(0x85);
        vault.put_entity(
            &actor,
            crate::registry::ENTITY_TYPE_PERSON,
            crate::temporal::TimeRange { start: 1, end: 1 },
            1,
            b"agent",
        )?;
        put_policy_manifest_bytes(
            &vault,
            entity(0x86),
            &risk_scoped_manifest(&actor.to_hex(), "discord", "cold_dm", "normal"),
        )?;
        put_claim_body(&vault, 0x87, &quiet_delivery_window_claim_body(0x85))?;
        let request = |suffix: &str| {
            let mut request = qualification_request(
                "discord",
                "cold_dm",
                actor,
                &format!("cold-dm:{index}:{suffix}"),
            );
            request.occurred_at = ONE_1768_EXECUTE_AT;
            if let Some(minute) = minute {
                request = request.delivery_window_local_minute_of_day(minute);
            }
            request
        };
        let mut sink = RecordingExecutor::default();
        let pending = vault.dispatch_outbound_intent(request("ungranted"), &mut sink)?;
        assert_eq!(pending.outcome, OutboundDispatchOutcome::Held, "{minute:?}");
        assert_eq!(pending.gate_outcome, "pending", "{minute:?}");
        assert!(sink.calls.is_empty());
        // The risk grant is deliberately exact-channel and exact-verb; it
        // cannot turn a cold DM into a push or grant another workspace bot.
        put_policy_manifest_bytes(
            &vault,
            entity(0x88),
            &risk_scoped_manifest(&actor.to_hex(), "discord", "cold_dm", "hold_to_proposal"),
        )?;
        let sent = vault.dispatch_outbound_intent(request("granted"), &mut sink)?;
        assert_eq!(
            sent.outcome,
            OutboundDispatchOutcome::DeliveredToChannel,
            "owner-authorized async DM in live quiet window {minute:?}: {:?}",
            sent.receipt.fields
        );
        assert_eq!(sink.calls.len(), 1);
        assert_eq!(
            sent.receipt
                .fields
                .get("window_ladder_rung")
                .map(String::as_str),
            Some("ambient")
        );
        assert_eq!(
            sent.receipt
                .fields
                .get("window_effective_action")
                .map(String::as_str),
            Some("deliver_now")
        );
        assert!(
            crate::attempt_queue::AttemptQueue::new(&vault)
                .list()?
                .is_empty(),
            "{minute:?}: no hold/retry row"
        );
    }
    Ok(())
}

#[test]
fn scheduled_cold_dm_projects_one_counterparty_touch_after_owner_grant()
-> Result<(), Box<dyn std::error::Error>> {
    use crate::attempt_queue::AttemptQueue;
    use crate::edge::EdgeActorClass;
    use crate::memory::OutboundDraftInput;

    let (_tmp, vault) = temp_vault();
    let actor = entity(0x8a);
    put_connector_task_actor(&vault, actor, 100)?;
    put_policy_manifest_bytes(
        &vault,
        entity(0x8b),
        &risk_scoped_manifest(&actor.to_hex(), "discord", "cold_dm", "normal"),
    )?;
    let party = "party:owner-cold-dm";
    let draft = OutboundDraftInput {
        verb: "cold_dm".to_owned(),
        channel: "discord".to_owned(),
        target: "transport:owner-dm".to_owned(),
        on_behalf_of: None,
        content_ref: Some("content:cold-dm".to_owned()),
        idempotency_key: Some("cold-dm:one-effect".to_owned()),
        dedupe_key: None,
        trigger: "agent_immediate".to_owned(),
        trigger_ref: "session:cold-dm".to_owned(),
        job_ref: None,
        occurred_at: Some(100),
    };
    vault
        .memory(actor, EdgeActorClass::Agent)
        .schedule_outbound_for_counterparty(&draft, party)?;
    let mut sink = RecordingExecutor::default();
    assert_eq!(vault.run_connector_task_executor(&mut sink, 101)?, 0);
    assert!(sink.calls.is_empty(), "normal grant cannot send a cold DM");
    assert_eq!(
        crate::comm::count_active_comm_claims(
            &vault,
            crate::comm::PREDICATE_COMM_LAST_TOUCH,
            party,
            "discord"
        )?,
        0
    );

    put_policy_manifest_bytes(
        &vault,
        entity(0x8c),
        &risk_scoped_manifest(&actor.to_hex(), "discord", "cold_dm", "hold_to_proposal"),
    )?;
    assert_eq!(vault.run_connector_task_executor(&mut sink, 200)?, 1);
    assert_eq!(sink.calls.len(), 1);
    let tasks = vault.connector_send_tasks()?;
    assert_eq!(tasks.len(), 1);
    assert_eq!(tasks[0].outcome, Some(ConnectorSendTaskOutcome::Delivered));
    let receipts = vault.receipts(
        crate::receipt::ReceiptQuery::new(10).with_kind(crate::receipt::ReceiptKind::Outbound),
    )?;
    assert!(
        receipts
            .iter()
            .any(|receipt| receipt.outcome == "delivered_to_channel"
                && receipt.fields.get("counterparty_ref").map(String::as_str) == Some(party))
    );
    assert_eq!(
        crate::comm::count_active_comm_claims(
            &vault,
            crate::comm::PREDICATE_COMM_LAST_TOUCH,
            party,
            "discord"
        )?,
        0
    );
    crate::comm::run_comm_projector(&vault)?;
    assert_eq!(
        crate::comm::count_active_comm_claims(
            &vault,
            crate::comm::PREDICATE_COMM_LAST_TOUCH,
            party,
            "discord"
        )?,
        1
    );
    assert_eq!(
        crate::comm::count_total_comm_claim_rows(
            &vault,
            crate::comm::PREDICATE_COMM_LAST_TOUCH,
            party,
            "discord"
        )?,
        1
    );
    crate::comm::run_comm_projector(&vault)?;
    assert_eq!(
        crate::comm::count_total_comm_claim_rows(
            &vault,
            crate::comm::PREDICATE_COMM_LAST_TOUCH,
            party,
            "discord"
        )?,
        1
    );
    assert_eq!(sink.calls.len(), 1);
    assert!(
        !AttemptQueue::new(&vault).list()?.is_empty(),
        "scheduled execution remains auditable"
    );
    Ok(())
}
