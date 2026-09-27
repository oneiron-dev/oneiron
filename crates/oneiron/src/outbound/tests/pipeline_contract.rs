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
fn four_trigger_doors_converge_into_one_intent_shape() {
    let commitment = dispatch_intent(OutboundIntentTrigger::commitment_timer_wake(
        "commitment:party-reminder",
    ));
    assert_eq!(commitment.intent_source, "commitment");
    assert_eq!(commitment.trigger_ref, "commitment:party-reminder");

    let gap = dispatch_intent(OutboundIntentTrigger::gap_queue("gap:unresolved-thread"));
    assert_eq!(gap.intent_source, "gap_queue");
    assert_eq!(gap.trigger_ref, "gap:unresolved-thread");

    let transition = dispatch_intent(OutboundIntentTrigger::record_transition(
        "esign:claim:terminal",
    ));
    assert_eq!(transition.intent_source, "record_transition");
    assert_eq!(transition.trigger_ref, "esign:claim:terminal");
    assert_eq!(
        OutboundIntentSource::parse(&transition.intent_source),
        Some(OutboundIntentSource::RecordTransition)
    );

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
fn provider_reaction_manifests_declare_only_real_tapback_rails_and_vocabularies() {
    // LINE's Messaging API has stickers (messages), not a reaction-to-message call.
    // Official Messages for Business likewise has no tapback API. Neither may
    // advertise a react verb just because a human client can show reactions.
    for channel in ["line", "imessage_mfb", "email"] {
        let manifest = outbound_capability_manifest(channel).expect("registered connector");
        assert!(!manifest.verbs.iter().any(|verb| verb.kind == "react"));
        let error = outbound_verb_contract(channel, "react").expect_err("no tapback API");
        assert_eq!(error.connector(), channel);
        assert_eq!(error.verb(), Some("react"));
        assert!(error.connector_known());
        assert!(!error.supported_verbs().contains(&"react".to_owned()));
    }

    let bridge = outbound_verb_contract("imessage_bridge", "react").expect("bridge tapback");
    assert_eq!(bridge.channel_call, "local_messages_tapback");
    assert_eq!(
        bridge.delivery_semantics.kind,
        OutboundDeliverySemanticsKind::ReactionTarget
    );
    assert_eq!(
        bridge.interruption_class,
        OutboundInterruptionClass::Ambient
    );
    assert_eq!(
        bridge.capability_vs_permission.permission,
        OutboundPermissionState::Conditional
    );
    assert_eq!(
        bridge.params["emoji_vocabulary"],
        serde_json::json!(["👍", "👎", "❤️", "😂", "‼️", "❓"])
    );

    let app = outbound_verb_contract("in_app", "react").expect("first-party reaction");
    assert_eq!(app.channel_call, "reaction.put");
    assert_eq!(
        app.delivery_semantics.kind,
        OutboundDeliverySemanticsKind::ReactionTarget
    );
    assert_eq!(app.interruption_class, OutboundInterruptionClass::Ambient);
    assert_eq!(app.params["emoji_vocabulary"], "unicode_emoji");

    for (channel, vocabulary) in [
        ("telegram", "chat_available_reactions"),
        ("slack", "workspace_unicode_and_custom_names"),
        ("discord", "unicode_and_permitted_custom"),
    ] {
        let contract = outbound_verb_contract(channel, "react").expect("existing react verb");
        assert_eq!(contract.params["emoji_vocabulary"], vocabulary);
    }
}

#[test]
fn dispatch_rejects_unsupported_tapback_before_transport() {
    let (_tmp, vault) = temp_vault();
    let agent = entity(0x53);
    vault
        .put_entity(
            &agent,
            crate::registry::ENTITY_TYPE_PERSON,
            crate::temporal::TimeRange { start: 1, end: 1 },
            1,
            b"dispatch actor",
        )
        .expect("seed dispatch actor");
    let mut executor = RecordingExecutor::default();
    for channel in ["line", "imessage_mfb", "email"] {
        let intent = OutboundIntent::from_trigger(
            OutboundIntentDraft::new("agent-alpha", "react", channel, "message:target"),
            OutboundIntentTrigger::agent_immediate("session:tapback"),
        );
        let request = OutboundDispatchRequest::new(
            format!("outbound:intent:{channel}-tapback"),
            format!("intent:{channel}-tapback"),
            intent,
            OutboundDispatchActor::agent(entity(0x53)),
            OutboundDispatchGate::allow_when_policy_grants(),
            1_020,
            OutboundDeliveryWindowDecision::DeliverNow,
        );
        let error = vault
            .dispatch_outbound_intent(request, &mut executor)
            .expect_err("unsupported tapback must fail before transport");
        match error {
            OutboundDispatchError::UnsupportedCapability(error) => {
                assert_eq!(error.connector(), channel);
                assert_eq!(error.verb(), Some("react"));
                assert!(error.connector_known());
            }
            other => panic!("expected typed unsupported capability, got {other}"),
        }
    }
    assert!(executor.calls.is_empty());
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
