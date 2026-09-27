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
        "frozen ledger idempotency key"
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
        let denied = qualification_request("email_ses", "send", actor, &format!("denied:{index}"));
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
