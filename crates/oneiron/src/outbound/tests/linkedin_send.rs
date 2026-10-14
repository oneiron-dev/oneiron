//! LinkedIn DM verified-send suite: content observation, caps, cadence and retry guard.

use super::*;

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
fn linkedin_send_dm_send_failure_is_ambiguous_without_verification()
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

    assert_eq!(result.outcome, OutboundDispatchOutcome::Ambiguous);
    assert_eq!(result.receipt.outcome, "ambiguous");
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
fn linkedin_send_dm_observed_absent_produces_ambiguous_receipt_without_phantom_success()
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

    assert_eq!(result.outcome, OutboundDispatchOutcome::Ambiguous);
    assert_eq!(result.receipt.outcome, "ambiguous");
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

/// One dispatch actor with a policy that lets it send LinkedIn DMs.
fn linkedin_sender(
    vault: &crate::Vault,
    seed: u8,
) -> std::result::Result<OutboundDispatchActor, Box<dyn std::error::Error>> {
    let actor = OutboundDispatchActor::agent(entity(seed));
    vault.put_entity(
        &entity(seed),
        crate::registry::ENTITY_TYPE_PERSON,
        crate::temporal::TimeRange { start: 1, end: 1 },
        1,
        b"dispatch actor",
    )?;
    allow_linkedin_send(vault, &actor)?;
    Ok(actor)
}

/// A transcript that names who sent each message, as a host transport reads
/// it from the provider rather than from the page text.
fn attributed_conversation(thread_id: &str, messages: &[(&str, &str, &str)]) -> serde_json::Value {
    serde_json::json!({
        "url": format!("https://www.linkedin.com/messaging/thread/{thread_id}/"),
        "messages": messages
            .iter()
            .map(|(id, sender, text)| serde_json::json!({"id": id, "sender": sender, "text": text}))
            .collect::<Vec<_>>(),
    })
}

/// H130: the recipient writes half the transcript. If the message never
/// left (the send call returned but nothing arrived) and the recipient types
/// the same words, page text alone must not become a delivered receipt.
#[test]
fn a_recipient_echo_is_never_a_delivered_receipt()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let (_tmp, vault) = temp_vault();
    let actor = linkedin_sender(&vault, 0xB8)?;
    let message = "Happy to share more details.";
    let transport = ScriptedLinkedInTransport::new(vec![
        linkedin_conversation(
            "2-jane-doe-abc",
            "Jane Doe\n10:01 AM\nThanks for reaching out.",
        ),
        linkedin_conversation(
            "2-jane-doe-abc",
            "Jane Doe\n10:01 AM\nThanks for reaching out.\nJane Doe\n10:05 AM\nHappy to share more details.",
        ),
    ]);
    let plan =
        LinkedInVerifiedSendPlan::new("linkedin:member:jane-doe", "2-jane-doe-abc", message)?
            .with_max_observation_attempts(1)?;
    let mut sink = LinkedInMcpVerifiedSendSink::new(linkedin_adapter()?, transport)
        .with_plan("intent:linkedin-echo", plan)?;
    let result = vault.dispatch_outbound_intent(
        linkedin_send_request(
            actor,
            "outbound:intent:linkedin-echo",
            "intent:linkedin-echo",
        ),
        &mut sink,
    )?;

    assert_ne!(result.outcome, OutboundDispatchOutcome::DeliveredToChannel);
    assert_eq!(result.outcome, OutboundDispatchOutcome::Ambiguous);
    assert_eq!(
        result
            .receipt
            .fields
            .get("linkedin_send_verification")
            .map(String::as_str),
        Some("content_observed_unattributed")
    );
    Ok(())
}

/// H130, the retry guard: a matching tail the transcript does not attribute to
/// this seat skips the duplicate send without claiming a delivery.
#[test]
fn a_retry_guard_never_counts_a_recipient_echo_as_delivered()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let (_tmp, vault) = temp_vault();
    let actor = linkedin_sender(&vault, 0xB9)?;
    let transport = ScriptedLinkedInTransport::new(vec![linkedin_conversation(
        "2-jane-doe-abc",
        "Jane Doe\n10:05 AM\nHappy to share more details.",
    )]);
    let plan = LinkedInVerifiedSendPlan::new(
        "linkedin:member:jane-doe",
        "2-jane-doe-abc",
        "Happy to share more details.",
    )?
    .retry_guarded();
    let mut sink = LinkedInMcpVerifiedSendSink::new(linkedin_adapter()?, transport)
        .with_plan("intent:linkedin-echo-guard", plan)?;
    let result = vault.dispatch_outbound_intent(
        linkedin_send_request(
            actor,
            "outbound:intent:linkedin-echo-guard",
            "intent:linkedin-echo-guard",
        ),
        &mut sink,
    )?;

    assert_ne!(result.outcome, OutboundDispatchOutcome::DeliveredToChannel);
    assert_eq!(result.outcome, OutboundDispatchOutcome::Ambiguous);
    assert!(sink.transport().send_calls.is_empty());
    Ok(())
}

fn send_attributed(
    vault: &crate::Vault,
    actor: OutboundDispatchActor,
    conversations: Vec<serde_json::Value>,
    intent_ref: &str,
) -> std::result::Result<OutboundDispatchResult, Box<dyn std::error::Error>> {
    let plan = LinkedInVerifiedSendPlan::new(
        "linkedin:member:jane-doe",
        "2-jane-doe-abc",
        "Happy to share more details.",
    )?
    .with_max_observation_attempts(1)?;
    let mut sink = LinkedInMcpVerifiedSendSink::new(
        linkedin_adapter()?,
        ScriptedLinkedInTransport::new(conversations),
    )
    .with_plan(intent_ref, plan)?;
    Ok(vault.dispatch_outbound_intent(
        linkedin_send_request(actor, &format!("outbound:{intent_ref}"), intent_ref),
        &mut sink,
    )?)
}

/// The legitimate path: a transcript that names senders proves delivery with a
/// new message this seat sent. The same words from the recipient do not.
#[test]
fn an_attributed_new_message_from_this_seat_is_delivered()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let (_tmp, vault) = temp_vault();
    let message = "Happy to share more details.";
    let echo = attributed_conversation(
        "2-jane-doe-abc",
        &[
            ("m1", "linkedin:member:jane-doe", "Thanks for reaching out."),
            ("m2", "linkedin:member:jane-doe", message),
        ],
    );
    let sent = attributed_conversation(
        "2-jane-doe-abc",
        &[
            ("m1", "linkedin:member:jane-doe", "Thanks for reaching out."),
            ("m2", "linkedin:member:jane-doe", message),
            ("m3", "linkedin:member:yura", message),
        ],
    );
    let delivered = send_attributed(
        &vault,
        linkedin_sender(&vault, 0xBA)?,
        vec![echo.clone(), sent],
        "intent:linkedin-attributed",
    )?;
    assert_eq!(
        delivered.outcome,
        OutboundDispatchOutcome::DeliveredToChannel
    );

    let (_echo_tmp, echo_vault) = temp_vault();
    let echoed = send_attributed(
        &echo_vault,
        linkedin_sender(&echo_vault, 0xBA)?,
        vec![
            attributed_conversation(
                "2-jane-doe-abc",
                &[("m1", "linkedin:member:jane-doe", "Thanks for reaching out.")],
            ),
            echo,
        ],
        "intent:linkedin-attributed-echo",
    )?;
    assert_ne!(echoed.outcome, OutboundDispatchOutcome::DeliveredToChannel);
    Ok(())
}
