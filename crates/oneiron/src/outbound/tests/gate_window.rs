//! Gate-pending holds, delivery-window door evaluation, pending re-arm and retry-after authority.

use super::*;

#[test]
fn dispatch_pipeline_holds_gate_pending_without_executing()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let (_tmp, vault) = temp_vault();
    let agent = entity(0x52);
    let actor = OutboundDispatchActor::agent(agent);
    vault
        .put_entity(
            &agent,
            crate::registry::ENTITY_TYPE_PERSON,
            crate::temporal::TimeRange { start: 1, end: 1 },
            1,
            b"dispatch actor",
        )
        .expect("seed dispatch actor");
    put_policy_manifest_bytes(
        &vault,
        entity(0xD1),
        &policy_manifest(
            actor.actor_ref.as_deref().expect("actor ref"),
            "email",
            &["send"],
        ),
    )?;

    let gate = OutboundDispatchGate {
        has_opted_in: true,
        has_permission: false,
        policy_risk: OutboundDispatchPolicyRisk::Normal,
    };
    let request = OutboundDispatchRequest::new(
        "outbound:intent:held",
        "intent:held",
        dispatch_intent(OutboundIntentTrigger::agent_immediate("session:held")),
        actor,
        gate,
        1_010,
        OutboundDeliveryWindowDecision::DeliverNow,
    );

    let mut executor = RecordingExecutor::default();
    let result = vault.dispatch_outbound_intent(request, &mut executor)?;

    assert_eq!(result.outcome, OutboundDispatchOutcome::Held);
    assert!(executor.calls.is_empty());
    assert_eq!(result.gate_outcome, "pending");
    assert!(
        result
            .receipt
            .policy_trace
            .contains(&"gate.pending.external_effect_authority".to_owned())
    );
    assert_eq!(
        result.receipt.fields.get("hold_reason").map(String::as_str),
        Some("gate.pending.external_effect_authority")
    );
    assert_eq!(
        result
            .receipt
            .fields
            .get("gate_reason_codes")
            .map(String::as_str),
        Some("gate.pending.external_effect_authority")
    );
    assert_eq!(result.receipt.outcome, "held");
    Ok(())
}

#[test]
fn dispatch_pipeline_preserves_gate_hold_reason_when_window_also_holds()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let (_tmp, vault) = temp_vault();
    let agent = entity(0xA7);
    let actor = OutboundDispatchActor::agent(agent);
    vault
        .put_entity(
            &agent,
            crate::registry::ENTITY_TYPE_PERSON,
            crate::temporal::TimeRange { start: 1, end: 1 },
            1,
            b"dispatch actor",
        )
        .expect("seed dispatch actor");
    put_policy_manifest_bytes(
        &vault,
        crate::gate::default_policy_manifest_id()?,
        &policy_manifest(
            actor.actor_ref.as_deref().expect("actor ref"),
            "email",
            &["send"],
        ),
    )?;

    let gate = OutboundDispatchGate {
        has_opted_in: true,
        has_permission: false,
        policy_risk: OutboundDispatchPolicyRisk::Normal,
    };
    let request = OutboundDispatchRequest::new(
        "outbound:intent:gate-and-window-held",
        "intent:gate-and-window-held",
        dispatch_intent(OutboundIntentTrigger::agent_immediate(
            "session:gate-window-held",
        )),
        actor,
        gate,
        1_015,
        OutboundDeliveryWindowDecision::Hold {
            reason: "quiet_window".to_owned(),
            retry_at: Some(2_100),
        },
    );

    let mut executor = RecordingExecutor::default();
    let result = vault.dispatch_outbound_intent(request, &mut executor)?;

    assert_eq!(result.outcome, OutboundDispatchOutcome::Held);
    assert!(executor.calls.is_empty());
    assert_eq!(result.gate_outcome, "pending");
    assert_eq!(
        result.receipt.fields.get("hold_reason").map(String::as_str),
        Some("gate.pending.external_effect_authority")
    );
    assert_eq!(
        result
            .receipt
            .fields
            .get("window_reason")
            .map(String::as_str),
        Some("quiet_window")
    );
    assert_eq!(
        result.receipt.fields.get("retry_at").map(String::as_str),
        Some("2100")
    );
    assert!(
        result
            .receipt
            .policy_trace
            .contains(&"delivery_window.hold:quiet_window".to_owned())
    );
    Ok(())
}

/// ONE-1752: an opted-out counterparty HOLDS the send for the owner instead of
/// suppressing it. Nothing else about this path moved — the transport is still
/// never reached, and the receipt still carries the opt-out reason trail.
#[test]
fn dispatch_pipeline_holds_gate_pending_opt_out_without_executing()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let (_tmp, vault) = temp_vault();
    let agent = entity(0xD6);
    let actor = OutboundDispatchActor::agent(agent);
    vault
        .put_entity(
            &agent,
            crate::registry::ENTITY_TYPE_PERSON,
            crate::temporal::TimeRange { start: 1, end: 1 },
            1,
            b"dispatch actor",
        )
        .expect("seed dispatch actor");
    put_policy_manifest_bytes(
        &vault,
        entity(0xD4),
        &policy_manifest(
            actor.actor_ref.as_deref().expect("actor ref"),
            "email",
            &["send"],
        ),
    )?;

    let identity_ref = entity(0xB6);
    let contact_id = entity(0xB7);
    let contact =
        CounterpartyContactRecord::user_introduction(identity_ref, "kenji@example.com", 10)?;
    vault.create_counterparty_contact(&contact_id, &contact)?;
    vault.opt_out_counterparty_contact(&contact_id, CounterpartyOptOutReason::Unsubscribe, 20)?;

    let request = OutboundDispatchRequest::new(
        "outbound:intent:suppressed",
        "intent:suppressed",
        dispatch_intent(OutboundIntentTrigger::agent_immediate("session:suppressed")),
        actor,
        OutboundDispatchGate::allow_when_policy_grants(),
        1_045,
        OutboundDeliveryWindowDecision::DeliverNow,
    )
    .channel_identity_ref(identity_ref)
    .counterparty_ref("kenji@example.com");

    let mut executor = RecordingExecutor::default();
    let result = vault.dispatch_outbound_intent(request, &mut executor)?;

    assert_eq!(result.outcome, OutboundDispatchOutcome::Held);
    assert!(executor.calls.is_empty());
    assert_eq!(result.gate_outcome, "pending");
    assert_eq!(result.receipt.outcome, "held");
    assert_eq!(
        result.receipt.fields.get("hold_reason").map(String::as_str),
        Some("gate.pending.counterparty_opt_out")
    );
    assert!(!result.receipt.fields.contains_key("suppression"));
    assert!(
        result
            .receipt
            .policy_trace
            .contains(&"gate.pending.counterparty_opt_out".to_owned())
    );
    assert!(
        result
            .receipt
            .policy_trace
            .contains(&"counterparty_opt_out_unsubscribe".to_owned())
    );
    assert_eq!(
        result
            .receipt
            .fields
            .get("gate_receipt_reasons")
            .map(String::as_str),
        Some("counterparty_opt_out_unsubscribe,counterparty_first_touch_user_introduction")
    );
    Ok(())
}

#[test]
fn dispatch_pipeline_rejects_unsupported_verbs_before_execution() {
    let (_tmp, vault) = temp_vault();
    let agent = entity(0x53);
    let actor = OutboundDispatchActor::agent(agent);
    vault
        .put_entity(
            &agent,
            crate::registry::ENTITY_TYPE_PERSON,
            crate::temporal::TimeRange { start: 1, end: 1 },
            1,
            b"dispatch actor",
        )
        .expect("seed dispatch actor");
    let intent = OutboundIntent::from_trigger(
        OutboundIntentDraft::new("agent-alpha", "edit", "line", "line:user:kenji"),
        OutboundIntentTrigger::agent_immediate("session:edit"),
    );
    let request = OutboundDispatchRequest::new(
        "outbound:intent:line-edit",
        "intent:line-edit",
        intent,
        actor,
        OutboundDispatchGate::allow_when_policy_grants(),
        1_020,
        OutboundDeliveryWindowDecision::DeliverNow,
    );

    let mut executor = RecordingExecutor::default();
    let error = vault
        .dispatch_outbound_intent(request, &mut executor)
        .expect_err("line edit should fail capability resolution");

    assert!(executor.calls.is_empty());
    match error {
        OutboundDispatchError::UnsupportedCapability(error) => {
            assert_eq!(error.connector(), "line");
            assert_eq!(error.verb(), Some("edit"));
        }
        OutboundDispatchError::InvalidBoundActor => {
            panic!("unexpected facade-bound actor validation")
        }
        OutboundDispatchError::Engine(error) => panic!("unexpected engine error: {error}"),
        OutboundDispatchError::Chokepoint(error) => {
            panic!("unexpected chokepoint error: {error}")
        }
    }
}

#[test]
fn dispatch_pipeline_window_hold_skips_execution_after_gate_allow()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let (_tmp, vault) = temp_vault();
    let agent = entity(0x54);
    let actor = OutboundDispatchActor::agent(agent);
    vault
        .put_entity(
            &agent,
            crate::registry::ENTITY_TYPE_PERSON,
            crate::temporal::TimeRange { start: 1, end: 1 },
            1,
            b"dispatch actor",
        )
        .expect("seed dispatch actor");
    put_policy_manifest_bytes(
        &vault,
        entity(0xD2),
        &policy_manifest(
            actor.actor_ref.as_deref().expect("actor ref"),
            "email",
            &["send"],
        ),
    )?;

    let request = OutboundDispatchRequest::new(
        "outbound:intent:window-held",
        "intent:window-held",
        dispatch_intent(OutboundIntentTrigger::commitment_timer_wake(
            "commitment:morning",
        )),
        actor,
        OutboundDispatchGate::allow_when_policy_grants(),
        1_030,
        OutboundDeliveryWindowDecision::Hold {
            reason: "quiet_window".to_owned(),
            retry_at: Some(2_000),
        },
    );

    let mut executor = RecordingExecutor::default();
    let result = vault.dispatch_outbound_intent(request, &mut executor)?;

    assert_eq!(result.outcome, OutboundDispatchOutcome::Held);
    assert!(executor.calls.is_empty());
    assert_eq!(result.gate_outcome, "allow");
    assert_eq!(
        result
            .receipt
            .fields
            .get("window_action")
            .map(String::as_str),
        Some("hold")
    );
    assert_eq!(
        result.receipt.fields.get("retry_at").map(String::as_str),
        Some("2000")
    );
    assert_eq!(
        result.receipt.fields.get("hold_reason").map(String::as_str),
        Some("quiet_window")
    );
    assert!(
        result
            .receipt
            .policy_trace
            .contains(&"delivery_window.hold:quiet_window".to_owned())
    );
    Ok(())
}

#[test]
fn dispatch_door_defers_call_inside_stored_quiet_hours()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let (_tmp, vault) = temp_vault();
    let agent = entity(0xB1);
    let actor = OutboundDispatchActor::agent(agent);
    vault
        .put_entity(
            &agent,
            crate::registry::ENTITY_TYPE_PERSON,
            crate::temporal::TimeRange { start: 1, end: 1 },
            1,
            b"dispatch actor",
        )
        .expect("seed dispatch actor");
    put_policy_manifest_bytes(
        &vault,
        entity(0xE2),
        &policy_manifest(
            actor.actor_ref.as_deref().expect("actor ref"),
            "voice",
            &["call"],
        ),
    )?;
    put_claim_body(&vault, 0xE3, &quiet_delivery_window_claim_body(0xB1))?;

    let intent = OutboundIntent::from_trigger(
        OutboundIntentDraft::new("agent-alpha", "call", "voice", "+15551234567"),
        OutboundIntentTrigger::commitment_timer_wake("commitment:quiet-call"),
    );
    let request = OutboundDispatchRequest::new(
        "outbound:intent:quiet-call",
        "intent:quiet-call",
        intent,
        actor,
        OutboundDispatchGate::allow_when_policy_grants(),
        23 * 60 * 60,
        OutboundDeliveryWindowDecision::DeliverNow,
    )
    .delivery_window_local_minute_of_day(23 * 60);

    let mut executor = RecordingExecutor::default();
    let result = vault.dispatch_outbound_intent(request, &mut executor)?;

    assert_eq!(result.outcome, OutboundDispatchOutcome::Held);
    assert!(executor.calls.is_empty());
    assert_eq!(result.gate_outcome, "allow");
    assert_eq!(
        result
            .receipt
            .fields
            .get("window_action")
            .map(String::as_str),
        Some("hold")
    );
    assert_eq!(
        result
            .receipt
            .fields
            .get("window_reason")
            .map(String::as_str),
        Some("quiet_window")
    );
    assert_eq!(
        result.receipt.fields.get("retry_at").map(String::as_str),
        Some("115200")
    );
    assert_ne!(result.receipt.outcome, "suppressed");
    Ok(())
}

#[test]
fn dispatch_door_allows_chat_send_inside_stored_quiet_hours()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let (_tmp, vault) = temp_vault();
    let agent = entity(0xB2);
    let actor = OutboundDispatchActor::agent(agent);
    vault
        .put_entity(
            &agent,
            crate::registry::ENTITY_TYPE_PERSON,
            crate::temporal::TimeRange { start: 1, end: 1 },
            1,
            b"dispatch actor",
        )
        .expect("seed dispatch actor");
    put_policy_manifest_bytes(
        &vault,
        entity(0xE5),
        &policy_manifest(
            actor.actor_ref.as_deref().expect("actor ref"),
            "slack",
            &["send"],
        ),
    )?;
    put_claim_body(&vault, 0xE6, &quiet_delivery_window_claim_body(0xB2))?;

    let intent = OutboundIntent::from_trigger(
        OutboundIntentDraft::new("agent-alpha", "send", "slack", "slack:channel:C123"),
        OutboundIntentTrigger::agent_immediate("session:chat-leave"),
    );
    let request = OutboundDispatchRequest::new(
        "outbound:intent:chat-leave",
        "intent:chat-leave",
        intent,
        actor,
        OutboundDispatchGate::allow_when_policy_grants(),
        23 * 60 * 60,
        OutboundDeliveryWindowDecision::DeliverNow,
    )
    .delivery_window_local_minute_of_day(23 * 60);

    let mut executor = RecordingExecutor::default();
    let result = vault.dispatch_outbound_intent(request, &mut executor)?;

    assert_eq!(result.outcome, OutboundDispatchOutcome::DeliveredToChannel);
    assert_eq!(
        executor.calls,
        vec![(
            "intent:chat-leave".to_owned(),
            "slack".to_owned(),
            "send".to_owned()
        )]
    );
    assert_eq!(
        result
            .receipt
            .fields
            .get("window_action")
            .map(String::as_str),
        Some("deliver_now")
    );
    assert!(
        result
            .receipt
            .policy_trace
            .contains(&"delivery_window.no_restriction".to_owned())
    );
    Ok(())
}

#[test]
fn dispatch_door_defers_interruption_when_calendar_busy_is_active()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let (_tmp, vault) = temp_vault();
    let agent = entity(0xB3);
    let actor = OutboundDispatchActor::agent(agent);
    vault
        .put_entity(
            &agent,
            crate::registry::ENTITY_TYPE_PERSON,
            crate::temporal::TimeRange { start: 1, end: 1 },
            1,
            b"dispatch actor",
        )
        .expect("seed dispatch actor");
    put_policy_manifest_bytes(
        &vault,
        entity(0xE8),
        &policy_manifest(
            actor.actor_ref.as_deref().expect("actor ref"),
            "voice",
            &["call"],
        ),
    )?;
    put_claim_body(
        &vault,
        0xE9,
        &calendar_busy_delivery_window_claim_body(0xB3),
    )?;

    let intent = OutboundIntent::from_trigger(
        OutboundIntentDraft::new("agent-alpha", "call", "voice", "+15557654321"),
        OutboundIntentTrigger::agent_immediate("session:calendar-busy-call"),
    );
    let request = OutboundDispatchRequest::new(
        "outbound:intent:calendar-busy-call",
        "intent:calendar-busy-call",
        intent,
        actor,
        OutboundDispatchGate::allow_when_policy_grants(),
        12 * 60 * 60,
        OutboundDeliveryWindowDecision::DeliverNow,
    )
    .active_delivery_context(DeliveryWindowContextCondition::CalendarBusy);

    let mut executor = RecordingExecutor::default();
    let result = vault.dispatch_outbound_intent(request, &mut executor)?;

    assert_eq!(result.outcome, OutboundDispatchOutcome::Held);
    assert!(executor.calls.is_empty());
    assert_eq!(
        result
            .receipt
            .fields
            .get("window_reason")
            .map(String::as_str),
        Some("context_window")
    );
    assert_eq!(result.receipt.fields.get("retry_at"), None);
    assert_ne!(result.receipt.outcome, "suppressed");
    Ok(())
}

#[test]
fn dispatch_door_ignores_delivery_window_claims_for_other_subjects()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let (_tmp, vault) = temp_vault();
    let agent = entity(0xB4);
    let actor = OutboundDispatchActor::agent(agent);
    vault
        .put_entity(
            &agent,
            crate::registry::ENTITY_TYPE_PERSON,
            crate::temporal::TimeRange { start: 1, end: 1 },
            1,
            b"dispatch actor",
        )
        .expect("seed dispatch actor");
    put_policy_manifest_bytes(
        &vault,
        entity(0xEC),
        &policy_manifest(
            actor.actor_ref.as_deref().expect("actor ref"),
            "voice",
            &["call"],
        ),
    )?;
    put_claim_body(&vault, 0xED, &quiet_delivery_window_claim_body(0xC4))?;

    let intent = OutboundIntent::from_trigger(
        OutboundIntentDraft::new("agent-alpha", "call", "voice", "+15550001111"),
        OutboundIntentTrigger::commitment_timer_wake("commitment:other-subject-call"),
    );
    let request = OutboundDispatchRequest::new(
        "outbound:intent:other-subject-call",
        "intent:other-subject-call",
        intent,
        actor,
        OutboundDispatchGate::allow_when_policy_grants(),
        23 * 60 * 60,
        OutboundDeliveryWindowDecision::DeliverNow,
    )
    .delivery_window_local_minute_of_day(23 * 60);

    let mut executor = RecordingExecutor::default();
    let result = vault.dispatch_outbound_intent(request, &mut executor)?;

    assert_eq!(result.outcome, OutboundDispatchOutcome::DeliveredToChannel);
    assert_eq!(executor.calls.len(), 1);
    assert_eq!(
        result
            .receipt
            .fields
            .get("window_action")
            .map(String::as_str),
        Some("deliver_now")
    );
    Ok(())
}

#[test]
fn dispatch_door_uses_supplied_local_minute_for_user_local_quiet_hours()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let (_tmp, vault) = temp_vault();
    let agent = entity(0xB5);
    let actor = OutboundDispatchActor::agent(agent);
    vault
        .put_entity(
            &agent,
            crate::registry::ENTITY_TYPE_PERSON,
            crate::temporal::TimeRange { start: 1, end: 1 },
            1,
            b"dispatch actor",
        )
        .expect("seed dispatch actor");
    put_policy_manifest_bytes(
        &vault,
        entity(0xEE),
        &policy_manifest(
            actor.actor_ref.as_deref().expect("actor ref"),
            "voice",
            &["call"],
        ),
    )?;
    put_claim_body(&vault, 0xEF, &quiet_delivery_window_claim_body(0xB5))?;

    let intent = OutboundIntent::from_trigger(
        OutboundIntentDraft::new("agent-alpha", "call", "voice", "+15550002222"),
        OutboundIntentTrigger::commitment_timer_wake("commitment:local-minute-call"),
    );
    let request = OutboundDispatchRequest::new(
        "outbound:intent:local-minute-call",
        "intent:local-minute-call",
        intent,
        actor,
        OutboundDispatchGate::allow_when_policy_grants(),
        12 * 60 * 60,
        OutboundDeliveryWindowDecision::DeliverNow,
    )
    .delivery_window_local_minute_of_day(23 * 60);

    let mut executor = RecordingExecutor::default();
    let result = vault.dispatch_outbound_intent(request, &mut executor)?;

    assert_eq!(result.outcome, OutboundDispatchOutcome::Held);
    assert!(executor.calls.is_empty());
    assert_eq!(
        result
            .receipt
            .fields
            .get("window_reason")
            .map(String::as_str),
        Some("quiet_window")
    );
    assert_eq!(
        result.receipt.fields.get("retry_at").map(String::as_str),
        Some("75600")
    );
    Ok(())
}

#[test]
fn dispatch_door_holds_interrupt_when_local_minute_missing_for_time_window()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let (_tmp, vault) = temp_vault();
    let agent = entity(0xB6);
    let actor = OutboundDispatchActor::agent(agent);
    vault
        .put_entity(
            &agent,
            crate::registry::ENTITY_TYPE_PERSON,
            crate::temporal::TimeRange { start: 1, end: 1 },
            1,
            b"dispatch actor",
        )
        .expect("seed dispatch actor");
    put_policy_manifest_bytes(
        &vault,
        entity(0xF0),
        &policy_manifest(
            actor.actor_ref.as_deref().expect("actor ref"),
            "voice",
            &["call"],
        ),
    )?;
    put_claim_body(&vault, 0xF1, &quiet_delivery_window_claim_body(0xB6))?;

    let intent = OutboundIntent::from_trigger(
        OutboundIntentDraft::new("agent-alpha", "call", "voice", "+15550003333"),
        OutboundIntentTrigger::commitment_timer_wake("commitment:missing-local-minute"),
    );
    let request = OutboundDispatchRequest::new(
        "outbound:intent:missing-local-minute",
        "intent:missing-local-minute",
        intent,
        actor,
        OutboundDispatchGate::allow_when_policy_grants(),
        23 * 60 * 60,
        OutboundDeliveryWindowDecision::DeliverNow,
    );

    let mut executor = RecordingExecutor::default();
    let result = vault.dispatch_outbound_intent(request, &mut executor)?;

    assert_eq!(result.outcome, OutboundDispatchOutcome::Held);
    assert!(executor.calls.is_empty());
    assert_eq!(
        result
            .receipt
            .fields
            .get("window_reason")
            .map(String::as_str),
        Some("local_minute_unavailable")
    );
    assert_eq!(result.receipt.fields.get("retry_at"), None);
    Ok(())
}

#[test]
fn dispatch_door_preserves_connector_channel_for_channel_window_claim()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let (_tmp, vault) = temp_vault();
    let agent = entity(0xB7);
    let actor = OutboundDispatchActor::agent(agent);
    vault
        .put_entity(
            &agent,
            crate::registry::ENTITY_TYPE_PERSON,
            crate::temporal::TimeRange { start: 1, end: 1 },
            1,
            b"dispatch actor",
        )
        .expect("seed dispatch actor");
    put_policy_manifest_bytes(
        &vault,
        entity(0xF2),
        &policy_manifest(
            actor.actor_ref.as_deref().expect("actor ref"),
            "voice",
            &["call"],
        ),
    )?;
    put_claim_body(
        &vault,
        0xF3,
        &channel_delivery_window_claim_body(0xB7, "voice", "voice_window"),
    )?;

    let intent = OutboundIntent::from_trigger(
        OutboundIntentDraft::new("agent-alpha", "call", "voice", "+15550004444"),
        OutboundIntentTrigger::commitment_timer_wake("commitment:voice-window"),
    );
    let request = OutboundDispatchRequest::new(
        "outbound:intent:voice-window",
        "intent:voice-window",
        intent,
        actor,
        OutboundDispatchGate::allow_when_policy_grants(),
        23 * 60 * 60,
        OutboundDeliveryWindowDecision::DeliverNow,
    )
    .delivery_window_local_minute_of_day(23 * 60);

    let mut executor = RecordingExecutor::default();
    let result = vault.dispatch_outbound_intent(request, &mut executor)?;

    assert_eq!(result.outcome, OutboundDispatchOutcome::Held);
    assert_eq!(
        result
            .receipt
            .fields
            .get("window_reason")
            .map(String::as_str),
        Some("voice_window")
    );
    assert!(executor.calls.is_empty());
    Ok(())
}

#[test]
fn dispatch_door_enforces_manifest_interrupt_for_email_send()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let (_tmp, vault) = temp_vault();
    let agent = entity(0xB8);
    let actor = OutboundDispatchActor::agent(agent);
    vault
        .put_entity(
            &agent,
            crate::registry::ENTITY_TYPE_PERSON,
            crate::temporal::TimeRange { start: 1, end: 1 },
            1,
            b"dispatch actor",
        )
        .expect("seed dispatch actor");
    put_policy_manifest_bytes(
        &vault,
        entity(0xF4),
        &policy_manifest(
            actor.actor_ref.as_deref().expect("actor ref"),
            "email",
            &["send"],
        ),
    )?;
    put_claim_body(&vault, 0xF5, &quiet_delivery_window_claim_body(0xB8))?;

    let request = OutboundDispatchRequest::new(
        "outbound:intent:quiet-email",
        "intent:quiet-email",
        dispatch_intent(OutboundIntentTrigger::commitment_timer_wake(
            "commitment:quiet-email",
        )),
        actor,
        OutboundDispatchGate::allow_when_policy_grants(),
        23 * 60 * 60,
        OutboundDeliveryWindowDecision::DeliverNow,
    )
    .delivery_window_local_minute_of_day(23 * 60);

    let mut executor = RecordingExecutor::default();
    let result = vault.dispatch_outbound_intent(request, &mut executor)?;

    assert_eq!(result.outcome, OutboundDispatchOutcome::DeliveredToChannel);
    assert_eq!(executor.calls.len(), 1);
    Ok(())
}

#[test]
fn dispatch_door_preserves_passive_apns_window_context()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let (_tmp, vault) = temp_vault();
    let agent = entity(0xB9);
    let actor = OutboundDispatchActor::agent(agent);
    vault
        .put_entity(
            &agent,
            crate::registry::ENTITY_TYPE_PERSON,
            crate::temporal::TimeRange { start: 1, end: 1 },
            1,
            b"dispatch actor",
        )
        .expect("seed dispatch actor");
    put_policy_manifest_bytes(
        &vault,
        entity(0xF6),
        &policy_manifest(
            actor.actor_ref.as_deref().expect("actor ref"),
            "apns",
            &["push"],
        ),
    )?;
    put_claim_body(&vault, 0xF7, &quiet_delivery_window_claim_body(0xB9))?;

    let intent = OutboundIntent::from_trigger(
        OutboundIntentDraft::new("agent-alpha", "push", "apns", "device:kenji"),
        OutboundIntentTrigger::agent_immediate("session:passive-push"),
    );
    let request = OutboundDispatchRequest::new(
        "outbound:intent:passive-push",
        "intent:passive-push",
        intent,
        actor,
        OutboundDispatchGate::allow_when_policy_grants(),
        23 * 60 * 60,
        OutboundDeliveryWindowDecision::DeliverNow,
    )
    .delivery_window_local_minute_of_day(23 * 60)
    .delivery_window_apns_interruption_level(DeliveryWindowApnsInterruptionLevel::Passive);

    let mut executor = RecordingExecutor::default();
    let result = vault.dispatch_outbound_intent(request, &mut executor)?;

    assert_eq!(result.outcome, OutboundDispatchOutcome::DeliveredToChannel);
    assert_eq!(executor.calls.len(), 1);
    assert_eq!(
        result
            .receipt
            .fields
            .get("window_action")
            .map(String::as_str),
        Some("deliver_now")
    );
    Ok(())
}

#[test]
fn dispatch_door_preserves_request_degrade_target_for_stored_quiet_policy()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let (_tmp, vault) = temp_vault();
    let agent = entity(0xBA);
    let actor = OutboundDispatchActor::agent(agent);
    vault
        .put_entity(
            &agent,
            crate::registry::ENTITY_TYPE_PERSON,
            crate::temporal::TimeRange { start: 1, end: 1 },
            1,
            b"dispatch actor",
        )
        .expect("seed dispatch actor");
    put_policy_manifest_bytes(
        &vault,
        entity(0xF8),
        &policy_manifest(
            actor.actor_ref.as_deref().expect("actor ref"),
            "email",
            &["send"],
        ),
    )?;
    put_claim_body(&vault, 0xF9, &quiet_delivery_window_claim_body(0xBA))?;

    let context = DeliveryWindowEvaluationContext::new(
        23 * 60 * 60,
        23 * 60,
        DeliveryWindowVerbClass::Interrupt,
    )?
    .channel("email")
    .interrupt_surface("email:send")
    .degrade_to("chat:passive");
    let policy = quiet_delivery_window_policy();
    let request = OutboundDispatchRequest::new(
        "outbound:intent:quiet-email-degrade",
        "intent:quiet-email-degrade",
        dispatch_intent(OutboundIntentTrigger::commitment_timer_wake(
            "commitment:quiet-email-degrade",
        )),
        actor,
        OutboundDispatchGate::allow_when_policy_grants(),
        23 * 60 * 60,
        OutboundDeliveryWindowDecision::DeliverNow,
    )
    .delivery_window_policy(&context, &[policy]);

    let mut executor = RecordingExecutor::default();
    let result = vault.dispatch_outbound_intent(request, &mut executor)?;

    assert_eq!(result.outcome, OutboundDispatchOutcome::Degraded);
    assert!(executor.calls.is_empty());
    assert_eq!(
        result.receipt.fields.get("degraded_to").map(String::as_str),
        Some("chat:passive")
    );
    assert_eq!(
        result
            .receipt
            .fields
            .get("window_action")
            .map(String::as_str),
        Some("degrade")
    );
    Ok(())
}

#[test]
fn most_restrictive_delivery_window_decision_merges_same_rank_holds() {
    let current = OutboundDeliveryWindowDecision::Hold {
        reason: "current".to_owned(),
        retry_at: Some(100),
    };
    let later = OutboundDeliveryWindowDecision::Hold {
        reason: "later".to_owned(),
        retry_at: Some(200),
    };
    assert_eq!(
        most_restrictive_delivery_window_decision(current.clone(), later.clone()),
        later
    );

    let indefinite = OutboundDeliveryWindowDecision::Hold {
        reason: "indefinite".to_owned(),
        retry_at: None,
    };
    assert_eq!(
        most_restrictive_delivery_window_decision(current, indefinite.clone()),
        indefinite
    );
}

#[test]
fn dispatch_request_evaluates_delivery_window_policy_before_execution()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let (_tmp, vault) = temp_vault();
    let agent = entity(0x55);
    let actor = OutboundDispatchActor::agent(agent);
    vault
        .put_entity(
            &agent,
            crate::registry::ENTITY_TYPE_PERSON,
            crate::temporal::TimeRange { start: 1, end: 1 },
            1,
            b"dispatch actor",
        )
        .expect("seed dispatch actor");
    put_policy_manifest_bytes(
        &vault,
        entity(0xD3),
        &policy_manifest(
            actor.actor_ref.as_deref().expect("actor ref"),
            "email",
            &["send"],
        ),
    )?;

    let context =
        DeliveryWindowEvaluationContext::new(1_030, 23 * 60, DeliveryWindowVerbClass::Interrupt)?
            .interrupt_surface("email:send")
            .degrade_to("chat:passive");
    let policy = quiet_delivery_window_policy();
    let request = OutboundDispatchRequest::new(
        "outbound:intent:window-degraded",
        "intent:window-degraded",
        dispatch_intent(OutboundIntentTrigger::commitment_timer_wake(
            "commitment:quiet",
        )),
        actor,
        OutboundDispatchGate::allow_when_policy_grants(),
        1_030,
        OutboundDeliveryWindowDecision::DeliverNow,
    )
    .delivery_window_policy(&context, &[policy]);

    let mut executor = RecordingExecutor::default();
    let result = vault.dispatch_outbound_intent(request, &mut executor)?;

    assert_eq!(result.outcome, OutboundDispatchOutcome::Degraded);
    assert!(executor.calls.is_empty());
    assert_eq!(
        result
            .receipt
            .fields
            .get("window_action")
            .map(String::as_str),
        Some("degrade")
    );
    assert_eq!(
        result
            .receipt
            .fields
            .get("degraded_from")
            .map(String::as_str),
        Some("email:send")
    );
    assert_eq!(
        result.receipt.fields.get("degraded_to").map(String::as_str),
        Some("chat:passive")
    );
    assert!(
        result
            .receipt
            .policy_trace
            .contains(&"delivery_window.degrade:quiet_window".to_owned())
    );
    Ok(())
}

#[test]
fn gate_pending_hold_re_arms_on_the_bounded_seconds_curve() -> crate::Result<()> {
    use crate::attempt_queue::AttemptState;

    let (_tmp, vault, actor) = gate_pending_fixture(0x14)?;
    let task_ref = schedule_gate_pending_send(&vault, actor, "gate-pending-curve")?;

    let mut executor = RecordingExecutor::default();
    let mut now = ONE_1768_EXECUTE_AT;
    let mut observed_delays = Vec::new();
    for round in 0..11 {
        run_parked_round(&vault, &mut executor, now, round);
        assert!(
            executor.calls.is_empty(),
            "round {round}: a send parked on human authority never reaches the sink"
        );

        let receipt = one_1768_receipts(&vault)?
            .pop()
            .expect("every hold is surfaced as a receipt");
        assert_eq!(
            receipt_field(&receipt, "gate_outcome"),
            Some("pending"),
            "round {round}: the hold is the GATE's, not the window's"
        );
        assert_eq!(
            receipt_field(&receipt, "window_action"),
            Some("deliver_now"),
            "round {round}: the window itself admits this send"
        );
        // The re-arm edge is SURFACED on the receipt, not merely queued.
        let surfaced: u64 = receipt_field(&receipt, "retry_at")
            .unwrap_or_else(|| panic!("round {round}: every executor hold stamps retry_at"))
            .parse()
            .expect("retry_at is an instant");
        observed_delays.push(surfaced - now);

        // The queue re-arms at exactly the instant the receipt surfaced.
        let attempts = one_1768_bridge_attempts(&vault)?;
        let armed = attempts
            .iter()
            .find(|attempt| attempt.state == AttemptState::Scheduled)
            .expect("a fresh retry row is armed");
        assert_eq!(
            armed.scheduled_at,
            Some(surfaced),
            "round {round}: backoff_until must equal the receipted retry_at"
        );
        // Fresh rows reset attempt_count, so it can never be the exponent.
        assert_eq!(armed.attempt_count, 0, "round {round}");
        assert!(
            armed.retry_of.is_some(),
            "round {round}: the retry lineage is explicit"
        );
        // A parked send is never silently failed.
        assert_eq!(
            vault
                .connector_send_task(&task_ref)?
                .expect("task stays alive")
                .outcome,
            None,
            "round {round}"
        );
        now = surfaced;
    }

    assert_eq!(
        observed_delays,
        vec![1, 2, 4, 8, 16, 32, 64, 128, 256, 300, 300],
        "the gate-pending delay doubles from 1s by chain depth and saturates at the 300s cap"
    );
    Ok(())
}

#[test]
fn same_node_pending_retries_leave_the_connector_task_byte_identical() -> crate::Result<()> {
    use crate::attempt_queue::AttemptState;

    let (_tmp, vault, actor) = gate_pending_fixture(0x18)?;
    let task_ref = schedule_gate_pending_send(&vault, actor, "gate-pending-bytes")?;

    let mut executor = RecordingExecutor::default();
    let mut now = ONE_1768_EXECUTE_AT;
    // The first claim legitimately writes: it stamps the node that took it.
    run_parked_round(&vault, &mut executor, now, 0);
    let after_first_claim = vault.get_raw(&task_ref)?.expect("task row exists");

    for round in 1..6 {
        let receipt = one_1768_receipts(&vault)?.pop().expect("hold receipt");
        now = receipt_field(&receipt, "retry_at")
            .expect("retry_at")
            .parse()
            .expect("retry_at is an instant");
        run_parked_round(&vault, &mut executor, now, round);
        // The row is compared WHOLE — the 25-byte metadata header carries the
        // learned time, so an identical body written again would still differ
        // here. Re-marking the same node on the same still-parked TASK is a
        // no-op, and a no-op writes nothing at all.
        assert_eq!(
            vault.get_raw(&task_ref)?.expect("task row exists"),
            after_first_claim,
            "round {round}: a same-node pending retry must not rewrite the TASK"
        );
        // The retry lane itself is still live: this is idempotence, not a stall.
        assert!(
            one_1768_bridge_attempts(&vault)?
                .iter()
                .any(|attempt| attempt.state == AttemptState::Scheduled),
            "round {round}: the send is still armed"
        );
    }

    // A terminal projection IS a state change: it writes exactly once, and
    // repeating the same projection writes nothing further.
    super::connector_task::project_connector_send_task_outcome(
        &vault,
        task_ref,
        ConnectorSendTaskOutcome::Delivered,
        now + 1,
    )?;
    let projected = vault.get_raw(&task_ref)?.expect("task row exists");
    assert_ne!(
        projected, after_first_claim,
        "the terminal outcome is a real write"
    );
    super::connector_task::project_connector_send_task_outcome(
        &vault,
        task_ref,
        ConnectorSendTaskOutcome::Delivered,
        now + 2,
    )?;
    assert_eq!(
        vault.get_raw(&task_ref)?.expect("task row exists"),
        projected,
        "the same terminal projection twice writes exactly once"
    );
    Ok(())
}

#[test]
fn provider_retry_after_is_the_exact_re_arm_authority() -> crate::Result<()> {
    use crate::attempt_queue::AttemptState;

    // A rate-limited provider that states its own cool-down. The adapter
    // reports what the provider said; it invents nothing.
    let rate_limited = || RecordingExecutor {
        outcome: OutboundExecutionOutcome::failed("provider_rate_limited")
            .with_receipt_field("retry_after", "900"),
        ..RecordingExecutor::default()
    };

    // The dispatch path CAPTURES it: normalized beside the gate stamps, with
    // the connector's own raw text still on the receipt next to it.
    let (_tmp, vault) = temp_vault();
    let actor = entity(0x1C);
    put_connector_task_actor(&vault, actor, ONE_1768_SCHEDULED_AT)?;
    put_policy_manifest_bytes(
        &vault,
        entity(0x1D),
        &policy_manifest(&actor.to_hex(), "slack", &["react"]),
    )?;
    let mut sink = rate_limited();
    let result = vault
        .dispatch_outbound_intent(
            OutboundDispatchRequest::new(
                "outbound:intent:one-1879-retry-after",
                "intent:one-1879-retry-after",
                OutboundIntent::from_trigger(
                    OutboundIntentDraft::new(actor.to_hex(), "react", "slack", "channel:ops"),
                    OutboundIntentTrigger::agent_immediate("session:one-1879"),
                ),
                OutboundDispatchActor::agent(actor),
                OutboundDispatchGate::allow_when_policy_grants(),
                ONE_1768_EXECUTE_AT,
                OutboundDeliveryWindowDecision::DeliverNow,
            ),
            &mut sink,
        )
        .expect("dispatch");
    assert_eq!(sink.calls.len(), 1, "the provider was actually called");
    assert_eq!(result.outcome, OutboundDispatchOutcome::Failed);
    assert_eq!(
        receipt_field(&result.receipt, "provider_retry_after"),
        Some("900"),
        "the cool-down is stamped as a machine-readable re-arm authority"
    );
    assert_eq!(
        receipt_field(&result.receipt, "retry_after"),
        Some("900"),
        "and the connector's own text survives verbatim beside it"
    );
    assert_eq!(
        receipt_field(&result.receipt, "gate_outcome"),
        Some("allow"),
        "capturing it disturbs no gate stamp"
    );
    assert!(result.receipt.fields.contains_key("gate_decision_ref"));

    // The executor OBEYS it: the re-arm is the provider's exact instant, not
    // the generic transport curve's first rung (which would be now + 60s).
    vault
        .memory(actor, EdgeActorClass::Agent)
        .schedule_outbound(&one_1768_draft("slack", "react", "one-1879-retry-after"))
        .expect("schedule");
    let mut executor = rate_limited();
    run_parked_round(&vault, &mut executor, ONE_1768_EXECUTE_AT, 0);
    assert_eq!(executor.calls.len(), 1);
    let attempts = one_1768_bridge_attempts(&vault)?;
    let armed = attempts
        .iter()
        .find(|attempt| attempt.state == AttemptState::Scheduled)
        .expect("a rate-limited send re-arms rather than failing terminally");
    assert_eq!(
        armed.scheduled_at,
        Some(ONE_1768_EXECUTE_AT + 900),
        "the provider's stated cool-down is the exact re-arm instant"
    );
    Ok(())
}

#[test]
fn missing_retry_after_rejects_injected_provider_retry_after() -> crate::Result<()> {
    exercise_provider_retry_after_collision(None, None)
}

#[test]
fn malformed_retry_after_rejects_injected_provider_retry_after() -> crate::Result<()> {
    for raw in [
        "",
        " \t ",
        "-1",
        "1.5",
        "not-a-number",
        "18446744073709551616",
    ] {
        exercise_provider_retry_after_collision(Some(raw), None)?;
    }
    Ok(())
}

#[test]
fn parsed_retry_after_overrides_injected_provider_retry_after() -> crate::Result<()> {
    exercise_provider_retry_after_collision(Some(" 900 "), Some(900))
}

/// A retried transport failure is an AUDITABLE outcome, exactly as a hold is:
/// re-arming the queue is not a substitute for the record. Without the durable
/// row, what the provider said, the evidence it failed on, and the instant the
/// send actually re-arms at exist only inside a queue row the next attempt
/// overwrites.
#[test]
fn transport_failed_pending_retry_persists_an_audit_receipt() -> crate::Result<()> {
    use crate::attempt_queue::AttemptState;

    let (_tmp, vault) = temp_vault();
    let actor = entity(0x1E);
    put_connector_task_actor(&vault, actor, ONE_1768_SCHEDULED_AT)?;
    put_policy_manifest_bytes(
        &vault,
        entity(0x1F),
        &policy_manifest(&actor.to_hex(), "slack", &["react"]),
    )?;
    vault
        .memory(actor, EdgeActorClass::Agent)
        .schedule_outbound(&one_1768_draft("slack", "react", "one-1879-retry-audit"))
        .expect("schedule");
    let task_ref = vault.connector_send_tasks()?[0].task_ref;

    let mut executor = RecordingExecutor {
        outcome: OutboundExecutionOutcome::failed("provider_rate_limited")
            .with_receipt_field("retry_after", "900"),
        ..RecordingExecutor::default()
    };
    run_parked_round(&vault, &mut executor, ONE_1768_EXECUTE_AT, 0);
    assert_eq!(executor.calls.len(), 1, "the provider was actually called");

    let receipt = one_1768_receipts(&vault)?
        .pop()
        .expect("a retried transport failure is still surfaced as a receipt");
    assert_eq!(receipt.outcome, "failed");
    assert_eq!(
        receipt_field(&receipt, "dispatch_outcome"),
        Some("failed"),
        "the row names the outcome it actually parked on"
    );
    assert_eq!(
        receipt_field(&receipt, "retry_state"),
        Some("provider_rate_limited"),
        "the failure evidence survives the retry, not just the delay"
    );
    assert_eq!(
        receipt_field(&receipt, "provider_retry_after"),
        Some("900"),
        "the normalized cool-down is durable"
    );
    assert_eq!(
        receipt_field(&receipt, "retry_after"),
        Some("900"),
        "and the connector's own text survives verbatim beside it"
    );
    let surfaced: u64 = receipt_field(&receipt, "retry_at")
        .expect("every executor re-arm stamps retry_at")
        .parse()
        .expect("retry_at is an instant");
    assert_eq!(
        surfaced,
        ONE_1768_EXECUTE_AT + 900,
        "the audited retry edge is the provider's own instant"
    );

    // The queue re-arms at exactly the instant the receipt surfaced.
    let attempts = one_1768_bridge_attempts(&vault)?;
    let armed = attempts
        .iter()
        .find(|attempt| attempt.state == AttemptState::Scheduled)
        .expect("a rate-limited send re-arms rather than failing terminally");
    assert_eq!(
        armed.scheduled_at,
        Some(surfaced),
        "backoff_until must equal the receipted retry_at"
    );

    // Audit-only: the row is no idempotency token and closes nothing, so the
    // send is still owed and the next attempt still dispatches.
    assert_eq!(
        usize::from(send_receipt_exists_for_task(&vault, task_ref)?),
        0
    );
    assert_eq!(
        vault
            .connector_send_task(&task_ref)?
            .expect("task stays alive")
            .outcome,
        None
    );
    Ok(())
}
