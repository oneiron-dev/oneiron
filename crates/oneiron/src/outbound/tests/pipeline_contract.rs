//! Intent shape, verb capability contract, manifests and pipeline execute-and-receipt core.

use super::*;

#[test]
fn every_outbound_verb_declares_the_closed_seven_field_contract() {
    assert_eq!(
        OUTBOUND_VERB_FIELD_CONTRACT,
        [
            "kind",
            "channel_call",
            "params",
            "interruption_class",
            "delivery_semantics",
            "retry_class",
            "capability_vs_permission",
        ]
    );

    for manifest in outbound_capability_manifests() {
        assert_eq!(
            manifest.manifest_version, OUTBOUND_CAPABILITY_MANIFEST_VERSION,
            "{} uses an unexpected manifest version",
            manifest.connector
        );
        assert!(
            !manifest.verbs.is_empty(),
            "{} must expose at least one outbound verb",
            manifest.connector
        );
        for verb in &manifest.verbs {
            let value = serde_json::to_value(verb).expect("serialize outbound verb");
            let object = value.as_object().expect("verb serializes as object");
            let fields = object.keys().map(String::as_str).collect::<Vec<_>>();
            assert_eq!(
                fields, OUTBOUND_VERB_FIELD_CONTRACT,
                "{}.{} drifted from the closed field contract",
                manifest.connector, verb.kind
            );
            assert!(
                verb.capability_vs_permission.capability,
                "{}.{} must describe a capability",
                manifest.connector, verb.kind
            );
        }
    }
}

#[test]
fn outbound_intent_job_ref_is_optional_for_legacy_intents() {
    let intent: OutboundIntent = serde_json::from_str(
        r#"{
                "actor": "agent-alpha",
                "verb": "send",
                "channel": "email",
                "target": "counterparty:kenji",
                "intent_source": "agent_immediate",
                "trigger_ref": "run:planning"
            }"#,
    )
    .expect("legacy intent without job_ref remains valid");

    assert_eq!(intent.job_ref, None);

    let brief_rooted = OutboundIntent {
        job_ref: Some("brief:party".to_owned()),
        ..intent
    };
    let value = serde_json::to_value(&brief_rooted).expect("serialize intent");
    assert_eq!(value["job_ref"], "brief:party");
}

#[test]
fn three_trigger_doors_converge_into_one_intent_shape() {
    let commitment = dispatch_intent(OutboundIntentTrigger::commitment_timer_wake(
        "commitment:party-reminder",
    ));
    assert_eq!(commitment.intent_source, "commitment");
    assert_eq!(commitment.trigger_ref, "commitment:party-reminder");

    let gap = dispatch_intent(OutboundIntentTrigger::gap_queue("gap:unresolved-thread"));
    assert_eq!(gap.intent_source, "gap_queue");
    assert_eq!(gap.trigger_ref, "gap:unresolved-thread");

    let immediate = dispatch_intent(
        OutboundIntentTrigger::agent_immediate("session:reply-now").job_ref("brief:party"),
    );
    assert_eq!(immediate.intent_source, "agent_immediate");
    assert_eq!(immediate.job_ref.as_deref(), Some("brief:party"));
    assert_eq!(
        immediate.idempotency_key.as_deref(),
        Some("idem:invite-kenji")
    );
    assert_eq!(immediate.dedupe_key.as_deref(), Some("dedupe:invite-kenji"));
}

#[test]
fn dispatch_pipeline_resolves_gates_executes_and_emits_receipt()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let (_tmp, vault) = temp_vault();
    let agent = entity(0x51);
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
        entity(0xD0),
        &policy_manifest(
            actor.actor_ref.as_deref().expect("actor ref"),
            "email",
            &["send"],
        ),
    )?;

    let intent = dispatch_intent(
        OutboundIntentTrigger::agent_immediate("session:send-now").job_ref("brief:party"),
    );
    let request = OutboundDispatchRequest::new(
        "outbound:intent:invite-kenji",
        "intent:invite-kenji",
        intent,
        actor,
        OutboundDispatchGate::allow_when_policy_grants(),
        1_000,
        OutboundDeliveryWindowDecision::DeliverNow,
    )
    .counterparty_ref("counterparty:kenji");

    let mut executor = RecordingExecutor::default();
    let result = vault.dispatch_outbound_intent(request, &mut executor)?;

    assert_eq!(result.outcome, OutboundDispatchOutcome::DeliveredToChannel);
    assert_eq!(
        executor.calls,
        vec![(
            "intent:invite-kenji".to_owned(),
            "email".to_owned(),
            "send".to_owned()
        )]
    );
    assert_eq!(result.gate_outcome, "allow");
    assert_eq!(result.gate_reason_codes, vec!["gate.allow"]);
    assert_eq!(
        result
            .receipt
            .fields
            .get("gate_decision_ref")
            .map(String::as_str),
        result.gate_decision_id.as_deref()
    );
    assert!(!result.receipt.fields.contains_key("gate_decision_id"));
    assert_eq!(result.receipt.outcome, "delivered_to_channel");
    assert_eq!(
        result
            .receipt
            .fields
            .get("channel_call")
            .map(String::as_str),
        Some("send_email")
    );
    assert_eq!(
        result
            .receipt
            .fields
            .get("provider_ref")
            .map(String::as_str),
        Some("provider:message:one")
    );
    assert_eq!(
        result
            .receipt
            .fields
            .get("idempotency_key")
            .map(String::as_str),
        Some("idem:invite-kenji")
    );
    assert_eq!(
        result.receipt.fields.get("dedupe_key").map(String::as_str),
        Some("dedupe:invite-kenji")
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
fn verified_dispatch_classifies_a_missing_bound_actor_as_authorization_failure() {
    let (_tmp, vault) = temp_vault();
    let missing_actor = entity(0x52);
    let request = OutboundDispatchRequest::new(
        "outbound:intent:missing-actor",
        "intent:missing-actor",
        dispatch_intent(OutboundIntentTrigger::agent_immediate(
            "session:missing-actor",
        )),
        OutboundDispatchActor::agent(missing_actor),
        OutboundDispatchGate::allow_when_policy_grants(),
        1_001,
        OutboundDeliveryWindowDecision::DeliverNow,
    );
    let mut executor = RecordingExecutor::default();

    let err = OutboundDispatchPipeline
        .dispatch_with_verified_actor(
            &vault,
            request,
            &mut executor,
            missing_actor,
            EdgeActorClass::Agent,
        )
        .expect_err("missing bound actor must fail closed");

    assert!(matches!(err, OutboundDispatchError::InvalidBoundActor));
    assert!(executor.calls.is_empty());
}

#[test]
fn dispatch_pipeline_records_context_receipt_field_set()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let (_tmp, vault) = temp_vault();
    let agent = entity(0x51);
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
        entity(0xD0),
        &policy_manifest(
            actor.actor_ref.as_deref().expect("actor ref"),
            "email",
            &["send"],
        ),
    )?;

    let context = ContextReceiptFields {
        persona_compile_stamp: "oneiron.prompt_recompile.v1:deadbeef".to_owned(),
        activated_memory_ids: vec![entity(0x21).to_hex(), entity(0x22).to_hex()],
        board_state_ref: "board:cafe1234".to_owned(),
        substrate_ref: Some(format!("model:{}", entity(0x77).to_hex())),
        model: Some("test-model-v1".to_owned()),
        reasoning_effort: Some("high".to_owned()),
        prompt_input_ref: None,
        disclosure_stamp: None,
    };
    let request = OutboundDispatchRequest::new(
        "outbound:intent:invite-kenji",
        "intent:invite-kenji",
        dispatch_intent(OutboundIntentTrigger::agent_immediate("session:send-now")),
        actor.clone(),
        OutboundDispatchGate::allow_when_policy_grants(),
        1_000,
        OutboundDeliveryWindowDecision::DeliverNow,
    )
    .context_receipt(context.clone());

    let mut executor = RecordingExecutor::default();
    let result = vault.dispatch_outbound_intent(request, &mut executor)?;
    assert_eq!(result.outcome, OutboundDispatchOutcome::DeliveredToChannel);
    assert_eq!(
        result.receipt.context_receipt_fields().as_ref(),
        Some(&context),
        "what she knew rides the emit receipt"
    );
    assert_eq!(
        result
            .receipt
            .fields
            .get("activated_memory_ids")
            .map(String::as_str),
        Some(format!("{},{}", entity(0x21).to_hex(), entity(0x22).to_hex()).as_str())
    );

    // Emits dispatched without an assembled-context stamp stay unstamped.
    let request = OutboundDispatchRequest::new(
        "outbound:intent:invite-yuki",
        "intent:invite-yuki",
        dispatch_intent(OutboundIntentTrigger::agent_immediate("session:send-now")),
        actor,
        OutboundDispatchGate::allow_when_policy_grants(),
        1_001,
        OutboundDeliveryWindowDecision::DeliverNow,
    );
    let result = vault.dispatch_outbound_intent(request, &mut executor)?;
    assert_eq!(result.receipt.context_receipt_fields(), None);
    Ok(())
}

#[test]
fn dispatch_pipeline_executes_deliverable_apns_cap()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let (_tmp, vault) = temp_vault();
    let agent = entity(0xA8);
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
        entity(0xD8),
        &policy_manifest(
            actor.actor_ref.as_deref().expect("actor ref"),
            "apns",
            &["push"],
        ),
    )?;

    let intent = OutboundIntent::from_trigger(
        OutboundIntentDraft::new("agent-alpha", "push", "apns", "device:kenji")
            .on_behalf_of("owner")
            .content_ref("content:push-kenji")
            .idempotency_key("idem:push-kenji")
            .dedupe_key("dedupe:push-kenji"),
        OutboundIntentTrigger::agent_immediate("session:push-now"),
    );
    let request = OutboundDispatchRequest::new(
        "outbound:intent:push-kenji",
        "intent:push-kenji",
        intent,
        actor,
        OutboundDispatchGate::allow_when_policy_grants(),
        1_005,
        OutboundDeliveryWindowDecision::DeliverNowWithApnsCap {
            reason: "apns_time_sensitive_ceiling".to_owned(),
            from: "push:critical".to_owned(),
            to: "push:time_sensitive".to_owned(),
        },
    );

    let mut executor = RecordingExecutor::default();
    let result = vault.dispatch_outbound_intent(request, &mut executor)?;

    assert_eq!(result.outcome, OutboundDispatchOutcome::DeliveredToChannel);
    assert_eq!(
        executor.calls,
        vec![(
            "intent:push-kenji".to_owned(),
            "apns".to_owned(),
            "push".to_owned()
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
    assert_eq!(
        result
            .receipt
            .fields
            .get("degraded_from")
            .map(String::as_str),
        Some("push:critical")
    );
    assert_eq!(
        result.receipt.fields.get("degraded_to").map(String::as_str),
        Some("push:time_sensitive")
    );
    assert!(
        result
            .receipt
            .policy_trace
            .contains(&"delivery_window.apns_cap:apns_time_sensitive_ceiling".to_owned())
    );
    Ok(())
}

#[test]
fn dispatch_pipeline_records_typed_failed_execution()
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

    let request = OutboundDispatchRequest::new(
        "outbound:intent:failed-send",
        "intent:failed-send",
        dispatch_intent(OutboundIntentTrigger::agent_immediate(
            "session:failed-send",
        )),
        actor,
        OutboundDispatchGate::allow_when_policy_grants(),
        1_040,
        OutboundDeliveryWindowDecision::DeliverNow,
    );

    let mut executor = RecordingExecutor {
        outcome: OutboundExecutionOutcome::failed("transport_timeout"),
        ..RecordingExecutor::default()
    };
    let result = vault.dispatch_outbound_intent(request, &mut executor)?;

    assert_eq!(result.outcome, OutboundDispatchOutcome::Failed);
    assert_eq!(result.receipt.outcome, "failed");
    assert_eq!(
        result.receipt.fields.get("retry_state").map(String::as_str),
        Some("transport_timeout")
    );
    Ok(())
}

#[test]
fn unsupported_connector_verb_is_typed_and_actionable() {
    let error = outbound_verb_contract("line", "edit").expect_err("line edit unsupported");

    assert_eq!(error.connector(), "line");
    assert_eq!(error.verb(), Some("edit"));
    assert!(error.connector_known());
    assert!(
        error.supported_verbs().contains(&"send".to_owned()),
        "known connector errors should include supported verbs"
    );
    assert!(
        error
            .recovery_suggestions()
            .iter()
            .any(|suggestion| suggestion.contains("/v1/core/outbound/capabilities/line")),
        "unsupported errors must tell clients how to recover"
    );

    let error = outbound_verb_contract("unknown-connector", "send")
        .expect_err("unknown connector unsupported");
    assert!(!error.connector_known());
    assert!(error.supported_verbs().is_empty());
    assert!(
        error.supported_connectors().contains(&"slack".to_owned()),
        "unknown connector errors should include registered connectors"
    );
}

#[test]
fn connector_only_discovery_errors_do_not_fabricate_a_verb() {
    let error = unsupported_outbound_connector("unknown-connector");

    assert_eq!(error.connector(), "unknown_connector");
    assert_eq!(error.verb(), None);
    assert!(!error.connector_known());
    assert!(error.supported_verbs().is_empty());
    assert!(
        error
            .recovery_suggestions()
            .iter()
            .any(|suggestion| suggestion.contains("/v1/core/outbound/capabilities")),
        "connector-only unsupported errors should advertise the manifest index"
    );
}

#[test]
fn connector_specific_verbs_live_as_manifest_data() {
    let line_narrowcast =
        outbound_verb_contract("line", "narrowcast").expect("line narrowcast manifest");
    assert_eq!(line_narrowcast.kind, "narrowcast");
    assert_eq!(
        line_narrowcast.capability_vs_permission.permission,
        OutboundPermissionState::ProviderReview
    );

    let mfb_invite = outbound_verb_contract("imessage-mfb", "invite").expect("mfb invite manifest");
    assert_eq!(mfb_invite.kind, "invite");
    assert!(
        !COMMON_OUTBOUND_VERB_KINDS.contains(&mfb_invite.kind.as_str()),
        "connector-specific verbs should not expand the common vocabulary"
    );

    let linkedin_dm =
        outbound_verb_contract("linkedin", "send-dm").expect("linkedin send_dm manifest");
    assert_eq!(linkedin_dm.kind, "send_dm");
    assert_eq!(linkedin_dm.channel_call, "send_message");
    assert!(
        !COMMON_OUTBOUND_VERB_KINDS.contains(&linkedin_dm.kind.as_str()),
        "LinkedIn-specific DM verbs should stay manifest data"
    );

    let linkedin_connect = outbound_verb_contract("linkedin", "connect_request")
        .expect("linkedin connect_request manifest");
    assert_eq!(linkedin_connect.kind, "connect_request");
    assert_eq!(linkedin_connect.channel_call, "connect_with_person");
}

#[test]
fn line_reply_and_push_manifests_separate_quota_semantics() {
    let line_reply = outbound_verb_contract("line", "reply").expect("line reply manifest");
    assert_eq!(line_reply.channel_call, "reply_message");
    assert_eq!(
        line_reply.capability_vs_permission.permission,
        OutboundPermissionState::Allowed
    );
    assert_eq!(line_reply.params["quota"]["quota_debit"], false);
    assert_eq!(line_reply.params["quota"]["metered"], false);
    assert_eq!(line_reply.params["quota"]["plan_tier"], "all");
    assert!(line_reply.params.get("replyToken").is_none());
    assert_eq!(
        line_reply.params["reply_token_ref"],
        "payload_ref host-local reply token handle"
    );

    let line_push = outbound_verb_contract("line", "push").expect("line push manifest");
    assert_eq!(line_push.channel_call, "push_message");
    assert_eq!(
        line_push.capability_vs_permission.permission,
        OutboundPermissionState::Conditional
    );
    assert_eq!(line_push.params["quota"]["quota_debit"], true);
    assert_eq!(line_push.params["quota"]["metered"], true);
    assert_eq!(
        line_push.params["quota"]["free_monthly_allowance"],
        crate::channel_identity_provider::DEFAULT_LINE_PUSH_MONTHLY_ALLOWANCE
    );
    assert_eq!(
        line_push.params["quota"]["overage_policy"],
        "requires_metered_plan"
    );

    let legacy_send = outbound_verb_contract("line", "send").expect("legacy line send");
    assert_eq!(legacy_send.channel_call, "reply_message | push_message");
    assert_eq!(
        legacy_send.capability_vs_permission.permission,
        OutboundPermissionState::Conditional
    );
    assert_eq!(legacy_send.params["mode"], "reply | push");
    assert_eq!(
        legacy_send.params["reply"]["reply_token_ref"],
        "payload_ref host-local reply token handle"
    );
    assert_eq!(
        legacy_send.params["reply"]["quota"],
        line_reply.params["quota"]
    );
    assert_eq!(
        legacy_send.params["push"]["quota"],
        line_push.params["quota"]
    );
    assert_eq!(legacy_send.params["reply"]["quota"]["quota_debit"], false);
    assert_eq!(legacy_send.params["push"]["quota"]["quota_debit"], true);
    assert_eq!(legacy_send.params["push"]["quota"]["metered"], true);
    assert_eq!(
        legacy_send.params["push"]["quota"]["free_monthly_allowance"],
        crate::channel_identity_provider::DEFAULT_LINE_PUSH_MONTHLY_ALLOWANCE
    );
    assert_eq!(
        legacy_send.params["push"]["quota"]["overage_policy"],
        "requires_metered_plan"
    );

    let legacy_send_media =
        outbound_verb_contract("line", "send_media").expect("legacy line send_media");
    assert_eq!(
        legacy_send_media.capability_vs_permission.permission,
        OutboundPermissionState::Conditional
    );
    assert_eq!(legacy_send_media.params["mode"], "reply | push");
    assert_eq!(
        legacy_send_media.params["reply"]["reply_token_ref"],
        "payload_ref host-local reply token handle"
    );
    assert_eq!(
        legacy_send_media.params["reply"]["quota"],
        line_reply.params["quota"]
    );
    assert_eq!(
        legacy_send_media.params["push"]["quota"],
        line_push.params["quota"]
    );
    assert_eq!(
        legacy_send_media.params["reply"]["quota"]["quota_debit"],
        false
    );
    assert_eq!(
        legacy_send_media.params["push"]["quota"]["quota_debit"],
        true
    );
    assert_eq!(legacy_send_media.params["push"]["quota"]["metered"], true);
    assert_eq!(
        legacy_send_media.params["push"]["quota"]["overage_policy"],
        "requires_metered_plan"
    );
}

#[test]
fn manifests_emit_concrete_schema_on_demand_links() {
    let slack = outbound_capability_manifest("slack").expect("slack manifest");

    assert_eq!(
        slack.schema_on_demand,
        "/v1/core/outbound/capabilities/slack"
    );
}

#[test]
fn semantic_cooldown_collapses_distinct_intents_but_not_replay_or_expiry()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let (_tmp, vault) = temp_vault();
    let agent = entity(0x69);
    vault.put_entity(
        &agent,
        crate::registry::ENTITY_TYPE_PERSON,
        crate::temporal::TimeRange { start: 1, end: 1 },
        1,
        b"actor",
    )?;
    put_policy_manifest_bytes(
        &vault,
        entity(0x6a),
        &policy_manifest(&agent.to_hex(), "email", &["send"]),
    )?;
    let mut sink = RecordingExecutor::default();
    let make = |name: &str, at: u64, dedupe: Option<&str>| {
        let mut intent = dispatch_intent(OutboundIntentTrigger::agent_immediate(format!(
            "session:{name}"
        )));
        intent.idempotency_key = Some(format!("idem:{name}"));
        intent.dedupe_key = dedupe.map(str::to_owned);
        OutboundDispatchRequest::new(
            format!("receipt:{name}"),
            format!("intent:{name}"),
            intent,
            OutboundDispatchActor::agent(agent),
            OutboundDispatchGate::allow_when_policy_grants(),
            at,
            OutboundDeliveryWindowDecision::DeliverNow,
        )
    };
    vault.clock.set(1_000);
    let first = vault.dispatch_outbound_intent(make("first", 1_000, Some("one-nag")), &mut sink)?;
    assert_eq!(first.outcome, OutboundDispatchOutcome::DeliveredToChannel);
    vault.clock.set(1_001);
    let duplicate =
        vault.dispatch_outbound_intent(make("second", 1_001, Some("one-nag")), &mut sink)?;
    assert_eq!(duplicate.outcome, OutboundDispatchOutcome::Suppressed);
    assert_eq!(
        duplicate
            .receipt
            .fields
            .get("suppression")
            .map(String::as_str),
        Some("dedupe")
    );
    assert_eq!(duplicate.gate_outcome, "allow");
    assert_eq!(duplicate.gate_reason_codes, vec!["gate.allow"]);
    assert_eq!(sink.calls.len(), 1);
    let future_dated =
        vault.dispatch_outbound_intent(make("future", 99_999_999, Some("one-nag")), &mut sink)?;
    assert_eq!(future_dated.outcome, OutboundDispatchOutcome::Suppressed);
    let mut changed_target = make("other-target", 1_002, Some("one-nag"));
    changed_target.intent.target = "another@example.com".to_owned();
    let changed_target = vault.dispatch_outbound_intent(changed_target, &mut sink)?;
    assert_eq!(changed_target.outcome, OutboundDispatchOutcome::Suppressed);
    assert_eq!(sink.calls.len(), 1);
    // Replaying the original attempt is not a new semantic intent.
    vault.clock.set(1_002);
    let replay =
        vault.dispatch_outbound_intent(make("first", 1_002, Some("one-nag")), &mut sink)?;
    assert_eq!(replay.outcome, OutboundDispatchOutcome::DeliveredToChannel);
    assert_eq!(sink.calls.len(), 1);
    vault.clock.set(1_003);
    let independent = vault.dispatch_outbound_intent(make("third", 1_003, None), &mut sink)?;
    assert_eq!(
        independent.outcome,
        OutboundDispatchOutcome::DeliveredToChannel
    );
    vault.clock.set(87_401);
    let expired =
        vault.dispatch_outbound_intent(make("fourth", 87_401, Some("one-nag")), &mut sink)?;
    assert_eq!(expired.outcome, OutboundDispatchOutcome::DeliveredToChannel);
    assert_eq!(sink.calls.len(), 3);
    Ok(())
}

#[test]
fn concurrent_distinct_attempts_with_one_semantic_key_only_send_once()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    use crate::outbound_chokepoint::BEFORE_NEW_ADMISSION;
    use std::sync::{Arc, Barrier};

    let (_tmp, vault) = temp_vault();
    let agent = entity(0x70);
    vault.put_entity(
        &agent,
        crate::registry::ENTITY_TYPE_PERSON,
        crate::temporal::TimeRange { start: 1, end: 1 },
        1,
        b"actor",
    )?;
    put_policy_manifest_bytes(
        &vault,
        entity(0x71),
        &policy_manifest(&agent.to_hex(), "email", &["send"]),
    )?;
    vault.clock.set(1_000);
    let barrier = Arc::new(Barrier::new(2));
    let (first, second) = std::thread::scope(|scope| {
        let vault = &vault;
        let spawn = |name: &'static str, barrier: Arc<Barrier>| {
            let mut intent = dispatch_intent(OutboundIntentTrigger::agent_immediate(format!(
                "session:{name}"
            )));
            intent.idempotency_key = Some(format!("idem:{name}"));
            let request = OutboundDispatchRequest::new(
                format!("receipt:{name}"),
                format!("intent:{name}"),
                intent,
                OutboundDispatchActor::agent(agent),
                OutboundDispatchGate::allow_when_policy_grants(),
                1_000,
                OutboundDeliveryWindowDecision::DeliverNow,
            );
            scope.spawn(move || {
                BEFORE_NEW_ADMISSION.with(|hook| {
                    *hook.borrow_mut() = Some(Box::new(move || {
                        barrier.wait();
                    }));
                });
                let mut sink = RecordingExecutor::default();
                let result = vault.dispatch_outbound_intent(request, &mut sink);
                (result, sink.calls.len())
            })
        };
        let a = spawn("one", Arc::clone(&barrier));
        let b = spawn("two", Arc::clone(&barrier));
        (
            a.join().expect("first thread"),
            b.join().expect("second thread"),
        )
    });
    let outcomes = [first.0?.outcome, second.0?.outcome];
    assert!(outcomes.contains(&OutboundDispatchOutcome::DeliveredToChannel));
    assert!(outcomes.contains(&OutboundDispatchOutcome::Suppressed));
    assert_eq!(first.1 + second.1, 1);
    Ok(())
}

#[test]
fn semantic_cooldown_survives_reopen() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let (tmp, vault) = temp_vault();
    let actor_id = entity(0x72);
    vault.put_entity(
        &actor_id,
        crate::registry::ENTITY_TYPE_PERSON,
        crate::temporal::TimeRange { start: 1, end: 1 },
        1,
        b"actor",
    )?;
    put_policy_manifest_bytes(
        &vault,
        entity(0x73),
        &policy_manifest(&actor_id.to_hex(), "email", &["send"]),
    )?;
    let request = |name: &str| {
        let mut intent = dispatch_intent(OutboundIntentTrigger::agent_immediate(format!(
            "session:{name}"
        )));
        intent.idempotency_key = Some(format!("idem:{name}"));
        OutboundDispatchRequest::new(
            format!("receipt:{name}"),
            format!("intent:{name}"),
            intent,
            OutboundDispatchActor::agent(actor_id),
            OutboundDispatchGate::allow_when_policy_grants(),
            1_000,
            OutboundDeliveryWindowDecision::DeliverNow,
        )
    };
    vault.clock.set(1_000);
    let mut first_sink = RecordingExecutor::default();
    assert_eq!(
        vault
            .dispatch_outbound_intent(request("first"), &mut first_sink)?
            .outcome,
        OutboundDispatchOutcome::DeliveredToChannel
    );
    drop(vault);
    let clock = crate::ports::ManualClock::new(1_001);
    let reopened = Vault::open(
        tmp.path(),
        VaultConfig {
            store_clock: clock.bundle(),
            ..VaultConfig::default()
        },
    )?;
    let mut second_sink = RecordingExecutor::default();
    let result = reopened.dispatch_outbound_intent(request("second"), &mut second_sink)?;
    assert_eq!(result.outcome, OutboundDispatchOutcome::Suppressed);
    assert_eq!(
        result.receipt.fields.get("suppression").map(String::as_str),
        Some("dedupe")
    );
    assert!(second_sink.calls.is_empty());
    let before = reopened.gate_decisions(100)?.len();
    drop(reopened);
    let reopened = Vault::open(
        tmp.path(),
        VaultConfig {
            store_clock: crate::ports::ManualClock::new(1_002).bundle(),
            ..VaultConfig::default()
        },
    )?;
    let queried = reopened.receipts(
        crate::receipt::ReceiptQuery::new(10).with_kind(crate::receipt::ReceiptKind::Outbound),
    )?;
    assert_eq!(
        queried
            .iter()
            .filter(|row| row.receipt_id == result.receipt.receipt_id)
            .count(),
        1
    );
    let replay = reopened.dispatch_outbound_intent(request("second"), &mut second_sink)?;
    assert_eq!(replay.outcome, OutboundDispatchOutcome::Suppressed);
    assert_eq!(replay.receipt, result.receipt);
    assert_eq!(reopened.gate_decisions(100)?.len(), before);
    assert!(second_sink.calls.is_empty());
    Ok(())
}

#[test]
fn delivered_cooldown_starts_at_late_retry_not_first_admission()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let (_tmp, vault) = temp_vault();
    let actor = entity(0x74);
    vault.put_entity(
        &actor,
        crate::registry::ENTITY_TYPE_PERSON,
        crate::temporal::TimeRange { start: 1, end: 1 },
        1,
        b"actor",
    )?;
    put_policy_manifest_bytes(
        &vault,
        entity(0x75),
        &policy_manifest(&actor.to_hex(), "email", &["send"]),
    )?;
    let request = |name: &str, at: u64| {
        let mut intent = dispatch_intent(OutboundIntentTrigger::agent_immediate(format!(
            "session:{name}"
        )));
        intent.idempotency_key = Some(format!("idem:{name}"));
        OutboundDispatchRequest::new(
            format!("receipt:{name}"),
            format!("intent:{name}"),
            intent,
            OutboundDispatchActor::agent(actor),
            OutboundDispatchGate::allow_when_policy_grants(),
            at,
            OutboundDeliveryWindowDecision::DeliverNow,
        )
    };
    vault.clock.set(1_000);
    let mut failed = RecordingExecutor {
        outcome: OutboundExecutionOutcome::failed("transport_not_started"),
        ..Default::default()
    };
    assert_eq!(
        vault
            .dispatch_outbound_intent(request("first", 1_000), &mut failed)?
            .outcome,
        OutboundDispatchOutcome::Failed
    );
    vault.clock.set(90_000);
    let mut delivered = RecordingExecutor::default();
    assert_eq!(
        vault
            .dispatch_outbound_intent(request("first", 90_000), &mut delivered)?
            .outcome,
        OutboundDispatchOutcome::DeliveredToChannel
    );
    vault.clock.set(90_001);
    let next = vault.dispatch_outbound_intent(request("second", 90_001), &mut delivered)?;
    assert_eq!(next.outcome, OutboundDispatchOutcome::Suppressed);
    assert_eq!(delivered.calls.len(), 1);
    vault.clock.set(176_400);
    assert_eq!(
        vault
            .dispatch_outbound_intent(request("third", 176_400), &mut delivered)?
            .outcome,
        OutboundDispatchOutcome::DeliveredToChannel
    );
    Ok(())
}

#[test]
fn definitive_no_wire_expires_and_fences_the_old_retry()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let (_tmp, vault) = temp_vault();
    let actor = entity(0x76);
    vault.put_entity(
        &actor,
        crate::registry::ENTITY_TYPE_PERSON,
        crate::temporal::TimeRange { start: 1, end: 1 },
        1,
        b"actor",
    )?;
    put_policy_manifest_bytes(
        &vault,
        entity(0x77),
        &policy_manifest(&actor.to_hex(), "email", &["send"]),
    )?;
    let request = |name: &str, at: u64| {
        let mut intent = dispatch_intent(OutboundIntentTrigger::agent_immediate(format!(
            "session:{name}"
        )));
        intent.idempotency_key = Some(format!("idem:{name}"));
        OutboundDispatchRequest::new(
            format!("receipt:{name}"),
            format!("intent:{name}"),
            intent,
            OutboundDispatchActor::agent(actor),
            OutboundDispatchGate::allow_when_policy_grants(),
            at,
            OutboundDeliveryWindowDecision::DeliverNow,
        )
    };
    vault.clock.set(1_000);
    let mut failed = RecordingExecutor {
        outcome: OutboundExecutionOutcome::failed("transport_not_started"),
        ..Default::default()
    };
    assert_eq!(
        vault
            .dispatch_outbound_intent(request("first", 1_000), &mut failed)?
            .outcome,
        OutboundDispatchOutcome::Failed
    );
    vault.clock.set(1_001);
    assert_eq!(
        vault
            .dispatch_outbound_intent(request("second", 1_001), &mut failed)?
            .outcome,
        OutboundDispatchOutcome::Suppressed
    );
    vault.clock.set(87_400);
    let mut sent = RecordingExecutor::default();
    assert_eq!(
        vault
            .dispatch_outbound_intent(request("third", 87_400), &mut sent)?
            .outcome,
        OutboundDispatchOutcome::DeliveredToChannel
    );
    let old = vault.dispatch_outbound_intent(request("first", 87_401), &mut sent)?;
    assert_eq!(old.outcome, OutboundDispatchOutcome::Failed);
    assert_eq!(sent.calls.len(), 1);
    Ok(())
}

#[test]
fn replicated_suppression_artifact_projects_on_another_vault()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    use crate::batch::ENTITY_METADATA_HEADER_LEN;
    use crate::receipt::{ReceiptKind, ReceiptQuery};
    use crate::registry::ENTITY_TYPE_ASSET;
    let (_tmp, source) = temp_vault();
    let actor = entity(0x78);
    source.put_entity(
        &actor,
        crate::registry::ENTITY_TYPE_PERSON,
        crate::temporal::TimeRange { start: 1, end: 1 },
        1,
        b"actor",
    )?;
    put_policy_manifest_bytes(
        &source,
        entity(0x79),
        &policy_manifest(&actor.to_hex(), "email", &["send"]),
    )?;
    source.clock.set(1_000);
    let request = |name: &str| {
        let mut intent = dispatch_intent(OutboundIntentTrigger::agent_immediate(format!(
            "session:{name}"
        )));
        intent.idempotency_key = Some(format!("idem:{name}"));
        OutboundDispatchRequest::new(
            format!("receipt:{name}"),
            format!("intent:{name}"),
            intent,
            OutboundDispatchActor::agent(actor),
            OutboundDispatchGate::allow_when_policy_grants(),
            1_000,
            OutboundDeliveryWindowDecision::DeliverNow,
        )
    };
    let mut sink = RecordingExecutor::default();
    source.dispatch_outbound_intent(request("first"), &mut sink)?;
    let suppressed = source.dispatch_outbound_intent(request("second"), &mut sink)?;
    assert_eq!(suppressed.outcome, OutboundDispatchOutcome::Suppressed);
    let (_peer_tmp, peer) = temp_vault();
    // A replicated ASSET lands through the ordinary batch/entity door. The
    // private intent ledger is deliberately NOT copied to the peer.
    for asset in source.entities_by_type(ENTITY_TYPE_ASSET)? {
        let raw = source.get_raw(&asset)?.expect("source asset");
        peer.put_entity(
            &asset,
            ENTITY_TYPE_ASSET,
            crate::temporal::TimeRange {
                start: 1_000,
                end: 1_000,
            },
            1_000,
            &raw[ENTITY_METADATA_HEADER_LEN..],
        )?;
    }
    let projected = peer.receipts(ReceiptQuery::new(10).with_kind(ReceiptKind::Outbound))?;
    assert_eq!(projected, vec![suppressed.receipt]);
    let scan = peer.scan_receipts(ReceiptQuery::new(10).with_kind(ReceiptKind::Outbound))?;
    assert_eq!(scan.records, projected);
    Ok(())
}

#[test]
fn suppressed_approve_once_replays_without_spending_the_unused_approval()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    use crate::consent::{
        ActionClass, ActionEnvelope, ActorBound, ComposedEffect, EffectFacts, GrantBound,
        UndoFidelity,
    };
    let (_tmp, vault) = temp_vault();
    let actor = entity(0x7c);
    vault.put_entity(
        &actor,
        crate::registry::ENTITY_TYPE_PERSON,
        crate::temporal::TimeRange { start: 1, end: 1 },
        1,
        b"actor",
    )?;
    put_policy_manifest_bytes(
        &vault,
        entity(0x7d),
        &policy_manifest(&actor.to_hex(), "email", &["send"]),
    )?;
    let request = |name: &str, at: u64| {
        let mut intent = dispatch_intent(OutboundIntentTrigger::agent_immediate(format!(
            "session:{name}"
        )));
        intent.idempotency_key = Some(format!("idem:{name}"));
        OutboundDispatchRequest::new(
            format!("receipt:{name}"),
            format!("intent:{name}"),
            intent,
            OutboundDispatchActor::agent(actor),
            OutboundDispatchGate::allow_when_policy_grants(),
            at,
            OutboundDeliveryWindowDecision::DeliverNow,
        )
    };
    vault.clock.set(1_000);
    let mut sink = RecordingExecutor::default();
    assert_eq!(
        vault
            .dispatch_outbound_intent(request("first", 1_000), &mut sink)?
            .outcome,
        OutboundDispatchOutcome::DeliveredToChannel
    );
    let owner_id = entity(0x7e);
    vault.put_entity(
        &owner_id,
        crate::registry::ENTITY_TYPE_PERSON,
        crate::temporal::TimeRange { start: 1, end: 1 },
        1,
        b"owner",
    )?;
    let owner = vault.authenticate_owner(
        owner_id,
        &owner_id.to_hex(),
        true,
        crate::store::GateDecisionId::now(),
    )?;
    let mut facts = EffectFacts::new("external:email:send")?;
    facts.fires_hooks = true;
    facts.triggers_publish = true;
    facts.external_observers = true;
    facts.undo_fidelity = UndoFidelity::None;
    let bound = GrantBound::action(
        ActorBound::new(actor.to_hex())?,
        ActionClass::new("send")?,
        ActionEnvelope::new(["verb:send".to_owned()])?.with_target("email")?,
    )?;
    let digest = ComposedEffect::new(facts)
        .with_action_requirement(bound)?
        .digest();
    vault.approve_once(&owner, digest)?;
    let second = request("second", 1_001);
    let suppression = vault.dispatch_outbound_intent(second.clone(), &mut sink)?;
    assert_eq!(suppression.outcome, OutboundDispatchOutcome::Suppressed);
    assert_eq!(
        vault.dispatch_outbound_intent(second, &mut sink)?.receipt,
        suppression.receipt
    );
    vault.clock.set(87_401);
    // If suppression spent the marker, Gate evaluation refuses this send
    // with ConsentApproveOnceSpent before it can reach the connector.
    assert_eq!(
        vault
            .dispatch_outbound_intent(request("third", 87_401), &mut sink)?
            .outcome,
        OutboundDispatchOutcome::DeliveredToChannel
    );
    assert_eq!(sink.calls.len(), 2);
    Ok(())
}

#[test]
fn an_earlier_ambiguous_send_is_not_erased_by_a_later_definite_failure()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let (_tmp, vault) = temp_vault();
    let actor = entity(0x81);
    vault.put_entity(
        &actor,
        crate::registry::ENTITY_TYPE_PERSON,
        crate::temporal::TimeRange { start: 1, end: 1 },
        1,
        b"actor",
    )?;
    put_policy_manifest_bytes(
        &vault,
        entity(0x82),
        &policy_manifest(&actor.to_hex(), "email", &["replace"]),
    )?;
    let request = |name: &str, at: u64| {
        let mut intent = dispatch_intent(OutboundIntentTrigger::agent_immediate(format!(
            "session:{name}"
        )));
        intent.verb = "replace".to_owned();
        intent.idempotency_key = Some(format!("idem:{name}"));
        OutboundDispatchRequest::new(
            format!("receipt:{name}"),
            format!("intent:{name}"),
            intent,
            OutboundDispatchActor::agent(actor),
            OutboundDispatchGate::allow_when_policy_grants(),
            at,
            OutboundDeliveryWindowDecision::DeliverNow,
        )
    };
    vault.clock.set(1_000);
    let mut sink = RecordingExecutor {
        outcome: OutboundExecutionOutcome::failed("ambiguous").with_possible_delivery(),
        ..Default::default()
    };
    assert_eq!(
        vault
            .dispatch_outbound_intent(request("first", 1_000), &mut sink)?
            .outcome,
        OutboundDispatchOutcome::Failed
    );
    vault.clock.set(90_000);
    sink.outcome = OutboundExecutionOutcome::failed("not_started");
    assert_eq!(
        vault
            .dispatch_outbound_intent(request("first", 90_000), &mut sink)?
            .outcome,
        OutboundDispatchOutcome::Failed
    );
    vault.clock.set(90_001);
    assert_eq!(
        vault
            .dispatch_outbound_intent(request("second", 90_001), &mut sink)?
            .outcome,
        OutboundDispatchOutcome::Suppressed
    );
    assert_eq!(sink.calls.len(), 2);
    Ok(())
}
