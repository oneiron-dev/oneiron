//! LinkedIn DM verified-send suite: content observation, caps, cadence and retry guard.

use super::*;

#[test]
fn linkedin_send_dm_receipt_is_delivered_only_after_content_observation()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let (_tmp, vault) = temp_vault();
    let actor = OutboundDispatchActor::agent(entity(0xB1));
    vault
        .put_entity(
            &entity(0xB1),
            crate::registry::ENTITY_TYPE_PERSON,
            crate::temporal::TimeRange { start: 1, end: 1 },
            1,
            b"dispatch actor",
        )
        .expect("seed dispatch actor");
    allow_linkedin_send(&vault, &actor)?;

    let message = "Happy to share more details.";
    let transport = ScriptedLinkedInTransport::new(vec![
        linkedin_conversation(
            "2-jane-doe-abc",
            "Jane Doe\n10:01 AM\nThanks for reaching out.",
        ),
        linkedin_conversation(
            "2-jane-doe-abc",
            "Jane Doe\n10:01 AM\nThanks for reaching out.\nYura\n10:04 AM\nHappy to share more details.",
        ),
    ]);
    let plan =
        LinkedInVerifiedSendPlan::new("linkedin:member:jane-doe", "2-jane-doe-abc", message)?;
    let mut sink = LinkedInMcpVerifiedSendSink::new(linkedin_adapter()?, transport)
        .with_plan("intent:linkedin-send", plan)?;
    let result = vault.dispatch_outbound_intent(
        linkedin_send_request(
            actor,
            "outbound:intent:linkedin-send",
            "intent:linkedin-send",
        ),
        &mut sink,
    )?;

    assert_eq!(result.outcome, OutboundDispatchOutcome::DeliveredToChannel);
    assert_eq!(result.receipt.outcome, "delivered_to_channel");
    assert_eq!(
        sink.transport().send_calls.len(),
        1,
        "fresh send must call send_message once"
    );
    assert_eq!(
        sink.transport().get_calls,
        vec!["2-jane-doe-abc".to_owned(), "2-jane-doe-abc".to_owned()],
        "success is verified by baseline and post-send thread reads"
    );
    let provider_ref = result
        .receipt
        .fields
        .get("provider_ref")
        .expect("verified send writes provider/thread message ref");
    assert!(provider_ref.starts_with("linkedin:thread:2-jane-doe-abc@message:"));
    assert_eq!(
        result.receipt.fields.get("artifact_thread_message_ref"),
        Some(provider_ref),
        "receipt door must target the artifact thread@message"
    );
    assert_eq!(
        result
            .receipt
            .fields
            .get("send_message_return_trusted")
            .map(String::as_str),
        Some("false")
    );
    assert_eq!(
        result
            .receipt
            .fields
            .get("send_message_result")
            .map(String::as_str),
        Some("ignored"),
        "send_message success return is recorded but not trusted"
    );
    assert_eq!(
        result
            .receipt
            .fields
            .get("linkedin_send_verification")
            .map(String::as_str),
        Some("content_observed")
    );
    Ok(())
}

#[test]
fn linkedin_kill_switch_suppresses_before_mcp_transport()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let (_tmp, vault) = temp_vault();
    let actor = OutboundDispatchActor::agent(entity(0xC1));
    vault
        .put_entity(
            &entity(0xC1),
            crate::registry::ENTITY_TYPE_PERSON,
            crate::temporal::TimeRange { start: 1, end: 1 },
            1,
            b"dispatch actor",
        )
        .expect("seed dispatch actor");
    allow_linkedin_send(&vault, &actor)?;

    let policy = active_linkedin_policy()?;
    let mut harness = RecordingLinkedInSandboxHarness::default();
    let killed = run_linkedin_kill_switch(
        policy,
        &mut harness,
        1_090,
        "consent:owner-disabled-linkedin",
    )?;
    assert_eq!(harness.destroyed, vec!["sandbox:tokyo:yura"]);
    assert_eq!(harness.revoked, vec!["linkedin:seat:yura"]);
    assert!(killed.verb_catalog().is_empty());

    let mut sink = LinkedInMcpVerifiedSendSink::new(
        linkedin_adapter()?,
        ScriptedLinkedInTransport::new(vec![]),
    );
    let result = vault.dispatch_outbound_intent(
        linkedin_send_request(
            actor,
            "outbound:intent:linkedin-kill-switch",
            "intent:linkedin-kill-switch",
        )
        .linkedin_sandbox_policy(killed),
        &mut sink,
    )?;

    assert_eq!(result.outcome, OutboundDispatchOutcome::Suppressed);
    assert!(sink.transport().send_calls.is_empty());
    assert!(sink.transport().get_calls.is_empty());
    assert_eq!(
        result
            .receipt
            .fields
            .get("linkedin_policy_enforced_engine_side")
            .map(String::as_str),
        Some("true")
    );
    assert_eq!(
        result
            .receipt
            .fields
            .get("linkedin_engine_policy_reason")
            .map(String::as_str),
        Some("linkedin.kill_switch_engaged")
    );
    assert_eq!(
        result
            .receipt
            .fields
            .get("linkedin_sandbox_destroyed")
            .map(String::as_str),
        Some("true")
    );
    assert_eq!(
        result
            .receipt
            .fields
            .get("linkedin_verb_catalog_revoked")
            .map(String::as_str),
        Some("true")
    );
    Ok(())
}

#[test]
fn linkedin_daily_dm_cap_holds_before_mcp_transport()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let (_tmp, vault) = temp_vault();
    let actor = OutboundDispatchActor::agent(entity(0xC2));
    vault
        .put_entity(
            &entity(0xC2),
            crate::registry::ENTITY_TYPE_PERSON,
            crate::temporal::TimeRange { start: 1, end: 1 },
            1,
            b"dispatch actor",
        )
        .expect("seed dispatch actor");
    allow_linkedin_send(&vault, &actor)?;
    let policy = active_linkedin_policy()?
        .with_state(LinkedInSeatDispatchState::active().with_dm_sends_today(15));
    let mut sink = LinkedInMcpVerifiedSendSink::new(
        linkedin_adapter()?,
        ScriptedLinkedInTransport::new(vec![]),
    );
    let result = vault.dispatch_outbound_intent(
        linkedin_send_request(actor, "outbound:intent:linkedin-cap", "intent:linkedin-cap")
            .linkedin_sandbox_policy(policy),
        &mut sink,
    )?;

    assert_eq!(result.outcome, OutboundDispatchOutcome::Held);
    assert!(sink.transport().send_calls.is_empty());
    assert!(sink.transport().get_calls.is_empty());
    assert_eq!(
        result
            .receipt
            .fields
            .get("linkedin_engine_policy_reason")
            .map(String::as_str),
        Some("linkedin.daily_dm_cap")
    );
    assert_eq!(
        result
            .receipt
            .fields
            .get("linkedin_daily_dm_cap")
            .map(String::as_str),
        Some("15")
    );
    assert_eq!(
        result
            .receipt
            .fields
            .get("linkedin_dm_sends_today")
            .map(String::as_str),
        Some("15")
    );
    Ok(())
}

#[test]
fn linkedin_cadence_holds_before_mcp_transport()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let (_tmp, vault) = temp_vault();
    let actor = OutboundDispatchActor::agent(entity(0xC3));
    vault
        .put_entity(
            &entity(0xC3),
            crate::registry::ENTITY_TYPE_PERSON,
            crate::temporal::TimeRange { start: 1, end: 1 },
            1,
            b"dispatch actor",
        )
        .expect("seed dispatch actor");
    allow_linkedin_send(&vault, &actor)?;
    let policy = active_linkedin_policy()?
        .with_state(LinkedInSeatDispatchState::active().with_next_send_not_before(1_500));
    let mut sink = LinkedInMcpVerifiedSendSink::new(
        linkedin_adapter()?,
        ScriptedLinkedInTransport::new(vec![]),
    );
    let result = vault.dispatch_outbound_intent(
        linkedin_send_request(
            actor,
            "outbound:intent:linkedin-cadence",
            "intent:linkedin-cadence",
        )
        .linkedin_sandbox_policy(policy),
        &mut sink,
    )?;

    assert_eq!(result.outcome, OutboundDispatchOutcome::Held);
    assert!(sink.transport().send_calls.is_empty());
    assert!(sink.transport().get_calls.is_empty());
    assert_eq!(
        result
            .receipt
            .fields
            .get("linkedin_engine_policy_reason")
            .map(String::as_str),
        Some("linkedin.cadence_not_ready")
    );
    assert_eq!(
        result
            .receipt
            .fields
            .get("linkedin_next_send_not_before")
            .map(String::as_str),
        Some("1500")
    );
    Ok(())
}

#[test]
fn linkedin_sweeps_are_suppressed_before_mcp_transport()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let (_tmp, vault) = temp_vault();
    let actor = OutboundDispatchActor::agent(entity(0xC4));
    vault
        .put_entity(
            &entity(0xC4),
            crate::registry::ENTITY_TYPE_PERSON,
            crate::temporal::TimeRange { start: 1, end: 1 },
            1,
            b"dispatch actor",
        )
        .expect("seed dispatch actor");
    allow_linkedin_send(&vault, &actor)?;
    let policy =
        active_linkedin_policy()?.with_state(LinkedInSeatDispatchState::active().as_sweep());
    let mut sink = LinkedInMcpVerifiedSendSink::new(
        linkedin_adapter()?,
        ScriptedLinkedInTransport::new(vec![]),
    );
    let result = vault.dispatch_outbound_intent(
        linkedin_send_request(
            actor,
            "outbound:intent:linkedin-sweep",
            "intent:linkedin-sweep",
        )
        .linkedin_sandbox_policy(policy),
        &mut sink,
    )?;

    assert_eq!(result.outcome, OutboundDispatchOutcome::Suppressed);
    assert!(sink.transport().send_calls.is_empty());
    assert!(sink.transport().get_calls.is_empty());
    assert_eq!(
        result
            .receipt
            .fields
            .get("linkedin_engine_policy_reason")
            .map(String::as_str),
        Some("linkedin.no_sweeps")
    );
    assert_eq!(
        result
            .receipt
            .fields
            .get("linkedin_sweeps_allowed")
            .map(String::as_str),
        Some("false")
    );
    Ok(())
}

#[test]
fn linkedin_send_dm_plan_target_mismatch_fails_before_send()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let (_tmp, vault) = temp_vault();
    let actor = OutboundDispatchActor::agent(entity(0xB7));
    vault
        .put_entity(
            &entity(0xB7),
            crate::registry::ENTITY_TYPE_PERSON,
            crate::temporal::TimeRange { start: 1, end: 1 },
            1,
            b"dispatch actor",
        )
        .expect("seed dispatch actor");
    allow_linkedin_send(&vault, &actor)?;

    let plan = LinkedInVerifiedSendPlan::new(
        "linkedin:member:jane-doe",
        "2-jane-doe-abc",
        "Happy to share more details.",
    )?;
    let transport = ScriptedLinkedInTransport::new(vec![linkedin_conversation(
        "2-jane-doe-abc",
        "Yura\n10:04 AM\nHappy to share more details.",
    )]);
    let mut sink = LinkedInMcpVerifiedSendSink::new(linkedin_adapter()?, transport)
        .with_plan("intent:linkedin-target-mismatch", plan)?;
    let result = vault.dispatch_outbound_intent(
        OutboundDispatchRequest::new(
            "outbound:intent:linkedin-target-mismatch",
            "intent:linkedin-target-mismatch",
            linkedin_send_intent(OutboundIntentTrigger::agent_immediate(
                "session:linkedin-send",
            )),
            actor,
            OutboundDispatchGate::allow_when_policy_grants(),
            1_061,
            OutboundDeliveryWindowDecision::DeliverNow,
        )
        .counterparty_ref("linkedin:member:mallory"),
        &mut sink,
    )?;

    assert_eq!(result.outcome, OutboundDispatchOutcome::Failed);
    assert_eq!(result.receipt.outcome, "failed");
    assert!(sink.transport().send_calls.is_empty());
    assert!(sink.transport().get_calls.is_empty());
    assert_eq!(
        result.receipt.fields.get("retry_state").map(String::as_str),
        Some("linkedin_verified_send_target_mismatch")
    );
    assert_eq!(
        result
            .receipt
            .fields
            .get("send_message_called")
            .map(String::as_str),
        Some("false")
    );
    assert_eq!(
        result
            .receipt
            .fields
            .get("linkedin_send_verification")
            .map(String::as_str),
        Some("target_mismatch")
    );
    Ok(())
}

#[test]
fn linkedin_send_dm_verifies_metadata_light_conversation_with_requested_thread()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let (_tmp, vault) = temp_vault();
    let actor = OutboundDispatchActor::agent(entity(0xB8));
    vault
        .put_entity(
            &entity(0xB8),
            crate::registry::ENTITY_TYPE_PERSON,
            crate::temporal::TimeRange { start: 1, end: 1 },
            1,
            b"dispatch actor",
        )
        .expect("seed dispatch actor");
    allow_linkedin_send(&vault, &actor)?;

    let message = "Happy to share more details.";
    let plan =
        LinkedInVerifiedSendPlan::new("linkedin:member:jane-doe", "2-jane-doe-abc", message)?;
    let transport = ScriptedLinkedInTransport::new(vec![
        linkedin_conversation(
            "2-jane-doe-abc",
            "Jane Doe\n10:01 AM\nThanks for reaching out.",
        ),
        linkedin_conversation_without_thread_metadata(
            "Jane Doe\n10:01 AM\nThanks for reaching out.\nYura\n10:04 AM\nHappy to share more details.",
        ),
    ]);
    let mut sink = LinkedInMcpVerifiedSendSink::new(linkedin_adapter()?, transport)
        .with_plan("intent:linkedin-metadata-light", plan)?;
    let result = vault.dispatch_outbound_intent(
        linkedin_send_request(
            actor,
            "outbound:intent:linkedin-metadata-light",
            "intent:linkedin-metadata-light",
        ),
        &mut sink,
    )?;

    assert_eq!(result.outcome, OutboundDispatchOutcome::DeliveredToChannel);
    assert_eq!(sink.transport().send_calls.len(), 1);
    assert_eq!(
        sink.transport().get_calls,
        vec!["2-jane-doe-abc".to_owned(), "2-jane-doe-abc".to_owned()]
    );
    assert_eq!(
        result
            .receipt
            .fields
            .get("linkedin_send_verification")
            .map(String::as_str),
        Some("content_observed")
    );
    Ok(())
}

#[test]
fn linkedin_send_dm_send_failure_fails_without_verification()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let (_tmp, vault) = temp_vault();
    let actor = OutboundDispatchActor::agent(entity(0xB4));
    vault
        .put_entity(
            &entity(0xB4),
            crate::registry::ENTITY_TYPE_PERSON,
            crate::temporal::TimeRange { start: 1, end: 1 },
            1,
            b"dispatch actor",
        )
        .expect("seed dispatch actor");
    allow_linkedin_send(&vault, &actor)?;

    let message = "Happy to share more details.";
    let transport = ScriptedLinkedInTransport::new(vec![linkedin_conversation(
        "2-jane-doe-abc",
        "Jane Doe\n10:01 AM\nThanks for reaching out.",
    )])
    .failing_send("upstream_send_message_flaked");
    let plan =
        LinkedInVerifiedSendPlan::new("linkedin:member:jane-doe", "2-jane-doe-abc", message)?;
    let mut sink = LinkedInMcpVerifiedSendSink::new(linkedin_adapter()?, transport)
        .with_plan("intent:linkedin-send-failed", plan)?;
    let result = vault.dispatch_outbound_intent(
        linkedin_send_request(
            actor,
            "outbound:intent:linkedin-send-failed",
            "intent:linkedin-send-failed",
        ),
        &mut sink,
    )?;

    assert_eq!(result.outcome, OutboundDispatchOutcome::Failed);
    assert_eq!(result.receipt.outcome, "failed");
    assert!(!result.receipt.fields.contains_key("provider_ref"));
    assert_eq!(sink.transport().send_calls.len(), 1);
    assert_eq!(
        sink.transport().get_calls,
        vec!["2-jane-doe-abc".to_owned()]
    );
    assert_eq!(
        result.receipt.fields.get("retry_state").map(String::as_str),
        Some("verify_after_send_send_message_failed")
    );
    assert_eq!(
        result
            .receipt
            .fields
            .get("send_message_result")
            .map(String::as_str),
        Some("failed")
    );
    assert_eq!(
        result
            .receipt
            .fields
            .get("send_message_tool_error")
            .map(String::as_str),
        Some("upstream_send_message_flaked")
    );
    assert_eq!(
        result
            .receipt
            .fields
            .get("linkedin_send_verification")
            .map(String::as_str),
        Some("send_message_failed")
    );
    Ok(())
}

#[test]
fn linkedin_send_dm_observed_absent_produces_failed_receipt_without_phantom_success()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let (_tmp, vault) = temp_vault();
    let actor = OutboundDispatchActor::agent(entity(0xB2));
    vault
        .put_entity(
            &entity(0xB2),
            crate::registry::ENTITY_TYPE_PERSON,
            crate::temporal::TimeRange { start: 1, end: 1 },
            1,
            b"dispatch actor",
        )
        .expect("seed dispatch actor");
    allow_linkedin_send(&vault, &actor)?;

    let plan = LinkedInVerifiedSendPlan::new(
        "linkedin:member:jane-doe",
        "2-jane-doe-abc",
        "Happy to share more details.",
    )?
    .with_max_observation_attempts(2)?;
    let transport = ScriptedLinkedInTransport::new(vec![
        linkedin_conversation(
            "2-jane-doe-abc",
            "Jane Doe\n10:01 AM\nThanks for reaching out.",
        ),
        linkedin_conversation(
            "2-jane-doe-abc",
            "Jane Doe\n10:01 AM\nThanks for reaching out.",
        ),
        linkedin_conversation(
            "2-jane-doe-abc",
            "Jane Doe\n10:01 AM\nThanks for reaching out.",
        ),
    ]);
    let mut sink = LinkedInMcpVerifiedSendSink::new(linkedin_adapter()?, transport)
        .with_plan("intent:linkedin-absent", plan)?;
    let result = vault.dispatch_outbound_intent(
        linkedin_send_request(
            actor,
            "outbound:intent:linkedin-absent",
            "intent:linkedin-absent",
        ),
        &mut sink,
    )?;

    assert_eq!(result.outcome, OutboundDispatchOutcome::Failed);
    assert_eq!(result.receipt.outcome, "failed");
    assert!(!result.receipt.fields.contains_key("provider_ref"));
    assert_eq!(
        result.receipt.fields.get("retry_state").map(String::as_str),
        Some("verify_after_send_observed_absent")
    );
    assert_eq!(
        result
            .receipt
            .fields
            .get("linkedin_send_verification")
            .map(String::as_str),
        Some("observed_absent")
    );
    assert_eq!(
        result
            .receipt
            .fields
            .get("verification_attempts")
            .map(String::as_str),
        Some("2")
    );
    assert_eq!(sink.transport().send_calls.len(), 1);
    Ok(())
}

#[test]
fn linkedin_send_dm_does_not_verify_older_matching_transcript_line()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let (_tmp, vault) = temp_vault();
    let actor = OutboundDispatchActor::agent(entity(0xB5));
    vault
        .put_entity(
            &entity(0xB5),
            crate::registry::ENTITY_TYPE_PERSON,
            crate::temporal::TimeRange { start: 1, end: 1 },
            1,
            b"dispatch actor",
        )
        .expect("seed dispatch actor");
    allow_linkedin_send(&vault, &actor)?;

    let message = "Happy to share more details.";
    let plan =
        LinkedInVerifiedSendPlan::new("linkedin:member:jane-doe", "2-jane-doe-abc", message)?
            .with_max_observation_attempts(1)?;
    let transport = ScriptedLinkedInTransport::new(vec![
        linkedin_conversation(
            "2-jane-doe-abc",
            "Jane Doe\n10:01 AM\nThanks for reaching out.",
        ),
        linkedin_conversation(
            "2-jane-doe-abc",
            "Yura\n10:04 AM\nHappy to share more details.\nJane Doe\n10:05 AM\nSounds good.",
        ),
    ]);
    let mut sink = LinkedInMcpVerifiedSendSink::new(linkedin_adapter()?, transport)
        .with_plan("intent:linkedin-older-match", plan)?;
    let result = vault.dispatch_outbound_intent(
        linkedin_send_request(
            actor,
            "outbound:intent:linkedin-older-match",
            "intent:linkedin-older-match",
        ),
        &mut sink,
    )?;

    assert_eq!(result.outcome, OutboundDispatchOutcome::Failed);
    assert!(!result.receipt.fields.contains_key("provider_ref"));
    assert_eq!(sink.transport().send_calls.len(), 1);
    assert_eq!(sink.transport().get_calls.len(), 2);
    assert_eq!(
        result.receipt.fields.get("retry_state").map(String::as_str),
        Some("verify_after_send_observed_stale")
    );
    assert_eq!(
        result
            .receipt
            .fields
            .get("linkedin_send_verification")
            .map(String::as_str),
        Some("observed_stale")
    );
    Ok(())
}

#[test]
fn linkedin_send_dm_requires_new_post_send_occurrence()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let (_tmp, vault) = temp_vault();
    let actor = OutboundDispatchActor::agent(entity(0xB9));
    vault
        .put_entity(
            &entity(0xB9),
            crate::registry::ENTITY_TYPE_PERSON,
            crate::temporal::TimeRange { start: 1, end: 1 },
            1,
            b"dispatch actor",
        )
        .expect("seed dispatch actor");
    allow_linkedin_send(&vault, &actor)?;

    let message = "Happy to share more details.";
    let plan =
        LinkedInVerifiedSendPlan::new("linkedin:member:jane-doe", "2-jane-doe-abc", message)?
            .with_max_observation_attempts(1)?;
    let existing_thread = linkedin_conversation(
        "2-jane-doe-abc",
        "Jane Doe\n10:01 AM\nThanks for reaching out.\nYura\n10:04 AM\nHappy to share more details.",
    );
    let transport = ScriptedLinkedInTransport::new(vec![existing_thread.clone(), existing_thread]);
    let mut sink = LinkedInMcpVerifiedSendSink::new(linkedin_adapter()?, transport)
        .with_plan("intent:linkedin-noop-send", plan)?;
    let result = vault.dispatch_outbound_intent(
        linkedin_send_request(
            actor,
            "outbound:intent:linkedin-noop-send",
            "intent:linkedin-noop-send",
        ),
        &mut sink,
    )?;

    assert_eq!(result.outcome, OutboundDispatchOutcome::Failed);
    assert_eq!(sink.transport().send_calls.len(), 1);
    assert_eq!(
        result.receipt.fields.get("retry_state").map(String::as_str),
        Some("verify_after_send_observed_stale")
    );
    assert_eq!(
        result
            .receipt
            .fields
            .get("linkedin_send_verification")
            .map(String::as_str),
        Some("observed_stale")
    );
    assert_eq!(
        result
            .receipt
            .fields
            .get("pre_send_match_count")
            .map(String::as_str),
        Some("1")
    );
    assert_eq!(
        result
            .receipt
            .fields
            .get("post_send_match_count")
            .map(String::as_str),
        Some("1")
    );
    Ok(())
}

#[test]
fn linkedin_send_dm_successful_absent_read_clears_prior_get_error()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let (_tmp, vault) = temp_vault();
    let actor = OutboundDispatchActor::agent(entity(0xB6));
    vault
        .put_entity(
            &entity(0xB6),
            crate::registry::ENTITY_TYPE_PERSON,
            crate::temporal::TimeRange { start: 1, end: 1 },
            1,
            b"dispatch actor",
        )
        .expect("seed dispatch actor");
    allow_linkedin_send(&vault, &actor)?;

    let plan = LinkedInVerifiedSendPlan::new(
        "linkedin:member:jane-doe",
        "2-jane-doe-abc",
        "Happy to share more details.",
    )?
    .with_max_observation_attempts(2)?;
    let transport = ScriptedLinkedInTransport::new(vec![
        linkedin_conversation(
            "2-jane-doe-abc",
            "Jane Doe\n10:01 AM\nThanks for reaching out.",
        ),
        linkedin_conversation(
            "2-jane-doe-abc",
            "Jane Doe\n10:01 AM\nThanks for reaching out.",
        ),
    ])
    .with_get_error_after_precheck("temporary_get_failure");
    let mut sink = LinkedInMcpVerifiedSendSink::new(linkedin_adapter()?, transport)
        .with_plan("intent:linkedin-transient-error", plan)?;
    let result = vault.dispatch_outbound_intent(
        linkedin_send_request(
            actor,
            "outbound:intent:linkedin-transient-error",
            "intent:linkedin-transient-error",
        ),
        &mut sink,
    )?;

    assert_eq!(result.outcome, OutboundDispatchOutcome::Failed);
    assert_eq!(sink.transport().get_calls.len(), 3);
    assert_eq!(
        result.receipt.fields.get("retry_state").map(String::as_str),
        Some("verify_after_send_observed_absent")
    );
    assert_eq!(
        result
            .receipt
            .fields
            .get("linkedin_send_verification")
            .map(String::as_str),
        Some("observed_absent")
    );
    assert!(
        !result
            .receipt
            .fields
            .contains_key("verify_get_conversation_error"),
        "a later successful absent read should classify the final attempt"
    );
    Ok(())
}

#[test]
fn linkedin_retry_guard_observes_existing_message_without_duplicate_send()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let (_tmp, vault) = temp_vault();
    let actor = OutboundDispatchActor::agent(entity(0xB3));
    vault
        .put_entity(
            &entity(0xB3),
            crate::registry::ENTITY_TYPE_PERSON,
            crate::temporal::TimeRange { start: 1, end: 1 },
            1,
            b"dispatch actor",
        )
        .expect("seed dispatch actor");
    allow_linkedin_send(&vault, &actor)?;

    let message = "Happy to share more details.";
    let plan =
        LinkedInVerifiedSendPlan::new("linkedin:member:jane-doe", "2-jane-doe-abc", message)?
            .retry_guarded();
    let transport = ScriptedLinkedInTransport::new(vec![linkedin_conversation(
        "2-jane-doe-abc",
        "Jane Doe\n10:01 AM\nThanks for reaching out.\nYura\n10:04 AM\nHappy to share more details.",
    )]);
    let mut sink = LinkedInMcpVerifiedSendSink::new(linkedin_adapter()?, transport)
        .with_plan("intent:linkedin-retry", plan)?;
    let result = vault.dispatch_outbound_intent(
        linkedin_send_request(
            actor,
            "outbound:intent:linkedin-retry",
            "intent:linkedin-retry",
        ),
        &mut sink,
    )?;

    assert_eq!(result.outcome, OutboundDispatchOutcome::DeliveredToChannel);
    assert!(sink.transport().send_calls.is_empty());
    assert_eq!(
        result
            .receipt
            .fields
            .get("duplicate_send_guard")
            .map(String::as_str),
        Some("observed_existing")
    );
    assert_eq!(
        result
            .receipt
            .fields
            .get("send_message_called")
            .map(String::as_str),
        Some("false")
    );
    assert_eq!(
        result
            .receipt
            .fields
            .get("linkedin_send_verification")
            .map(String::as_str),
        Some("content_observed")
    );
    Ok(())
}
