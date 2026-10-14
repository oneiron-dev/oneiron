//! LinkedIn connect-request execution through the outbound gate and verified sink.

use super::*;
use crate::linkedin_connector::{
    LinkedInConnectionObservation, LinkedInConnectionState, LinkedInMcpConnectRequest,
    LinkedInMcpConnectTransport, LinkedInMcpVerifiedConnectSink, LinkedInVerifiedConnectPlan,
};

struct ConnectTransport {
    calls: Vec<LinkedInMcpConnectRequest>,
    reads: Vec<String>,
    observations:
        std::collections::VecDeque<std::result::Result<LinkedInConnectionObservation, String>>,
    send_result: std::result::Result<serde_json::Value, String>,
}

impl ConnectTransport {
    fn new(states: &[LinkedInConnectionState]) -> Self {
        Self {
            calls: Vec::new(),
            reads: Vec::new(),
            observations: states
                .iter()
                .copied()
                .map(|state| {
                    Ok(LinkedInConnectionObservation {
                        recipient_key: "linkedin:member:jane-doe".to_owned(),
                        state,
                    })
                })
                .collect(),
            send_result: Ok(serde_json::json!({"success": true})),
        }
    }
}

impl LinkedInMcpConnectTransport for ConnectTransport {
    fn connect_with_person(
        &mut self,
        request: &LinkedInMcpConnectRequest,
    ) -> std::result::Result<serde_json::Value, String> {
        self.calls.push(request.clone());
        self.send_result.clone()
    }

    fn get_person_profile(
        &mut self,
        recipient_key: &str,
    ) -> std::result::Result<LinkedInConnectionObservation, String> {
        self.reads.push(recipient_key.to_owned());
        self.observations
            .pop_front()
            .unwrap_or_else(|| Err("no_more_profile_reads".to_owned()))
    }
}

fn connect_dispatch(
    vault: &Vault,
    actor: OutboundDispatchActor,
    receipt_id: &str,
    intent_ref: &str,
    sink: &mut LinkedInMcpVerifiedConnectSink<ConnectTransport>,
    policy: LinkedInSeatSandboxPolicy,
) -> std::result::Result<OutboundDispatchResult, Box<dyn std::error::Error>> {
    connect_dispatch_with_policy(vault, actor, receipt_id, intent_ref, sink, Some(policy))
}

fn connect_dispatch_with_policy(
    vault: &Vault,
    actor: OutboundDispatchActor,
    receipt_id: &str,
    intent_ref: &str,
    sink: &mut LinkedInMcpVerifiedConnectSink<ConnectTransport>,
    policy: Option<LinkedInSeatSandboxPolicy>,
) -> std::result::Result<OutboundDispatchResult, Box<dyn std::error::Error>> {
    connect_dispatch_to(
        vault,
        actor,
        receipt_id,
        intent_ref,
        "linkedin:member:jane-doe",
        sink,
        policy,
    )
}

fn connect_dispatch_to(
    vault: &Vault,
    actor: OutboundDispatchActor,
    receipt_id: &str,
    intent_ref: &str,
    recipient: &str,
    sink: &mut LinkedInMcpVerifiedConnectSink<ConnectTransport>,
    policy: Option<LinkedInSeatSandboxPolicy>,
) -> std::result::Result<OutboundDispatchResult, Box<dyn std::error::Error>> {
    connect_dispatch_at(
        vault, actor, receipt_id, intent_ref, recipient, sink, policy, 1_060,
    )
}

#[expect(clippy::too_many_arguments, reason = "one test dispatch, spelled out")]
fn connect_dispatch_at(
    vault: &Vault,
    actor: OutboundDispatchActor,
    receipt_id: &str,
    intent_ref: &str,
    recipient: &str,
    sink: &mut LinkedInMcpVerifiedConnectSink<ConnectTransport>,
    policy: Option<LinkedInSeatSandboxPolicy>,
    occurred_at: u64,
) -> std::result::Result<OutboundDispatchResult, Box<dyn std::error::Error>> {
    let intent = OutboundIntent::from_trigger(
        OutboundIntentDraft::new(
            "agent-alpha",
            "connect_request",
            LINKEDIN_CHANNEL,
            recipient,
        )
        .on_behalf_of("owner")
        .content_ref("content:optional-note"),
        OutboundIntentTrigger::agent_immediate("session:linkedin-connect"),
    );
    let mut request = OutboundDispatchRequest::new(
        receipt_id,
        intent_ref,
        intent,
        actor,
        OutboundDispatchGate::allow_when_policy_grants(),
        occurred_at,
        OutboundDeliveryWindowDecision::DeliverNow,
    )
    .counterparty_ref(recipient);
    if let Some(policy) = policy {
        request = request.linkedin_sandbox_policy(policy);
    }
    Ok(vault.dispatch_outbound_intent(request, sink)?)
}

fn connect_fixture() -> std::result::Result<
    (tempfile::TempDir, TimedVault, OutboundDispatchActor),
    Box<dyn std::error::Error>,
> {
    let (tmp, vault) = temp_vault();
    let actor = OutboundDispatchActor::agent(entity(0xD1));
    vault.put_entity(
        &entity(0xD1),
        crate::registry::ENTITY_TYPE_PERSON,
        crate::temporal::TimeRange { start: 1, end: 1 },
        1,
        b"dispatch actor",
    )?;
    put_policy_manifest_bytes(
        &vault,
        entity(0xD2),
        &policy_manifest(
            actor.actor_ref.as_deref().expect("actor ref"),
            LINKEDIN_CHANNEL,
            &["connect_request"],
        ),
    )?;
    Ok((tmp, vault, actor))
}

#[test]
fn connect_request_never_uses_tool_success_without_observation()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let (_tmp, vault, actor) = connect_fixture()?;
    let mut sink = LinkedInMcpVerifiedConnectSink::new(
        linkedin_adapter()?,
        ConnectTransport::new(&[
            LinkedInConnectionState::Connectable,
            LinkedInConnectionState::Connectable,
        ]),
    )
    .with_plan(
        "intent:unobserved",
        LinkedInVerifiedConnectPlan::new("linkedin:member:jane-doe", None)?
            .with_max_observation_attempts(1)?,
    )?;
    let result = connect_dispatch(
        &vault,
        actor,
        "receipt:unobserved",
        "intent:unobserved",
        &mut sink,
        active_linkedin_policy()?,
    )?;
    assert_eq!(result.outcome, OutboundDispatchOutcome::Ambiguous);
    assert_eq!(
        result
            .receipt
            .fields
            .get("delivery_may_have_occurred")
            .map(String::as_str),
        Some("true")
    );
    assert!(!result.receipt.fields.contains_key("provider_ref"));
    assert_eq!(sink.transport().calls.len(), 1);
    Ok(())
}

#[test]
fn connect_request_retry_observes_pending_without_second_send()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let (_tmp, vault, actor) = connect_fixture()?;
    let mut sink = LinkedInMcpVerifiedConnectSink::new(
        linkedin_adapter()?,
        ConnectTransport::new(&[
            LinkedInConnectionState::Connectable,
            LinkedInConnectionState::Connectable,
            LinkedInConnectionState::Pending,
        ]),
    )
    .with_plan(
        "intent:retry",
        LinkedInVerifiedConnectPlan::new("linkedin:member:jane-doe", None)?
            .with_max_observation_attempts(1)?,
    )?;
    let first = connect_dispatch(
        &vault,
        actor.clone(),
        "receipt:retry:first",
        "intent:retry",
        &mut sink,
        active_linkedin_policy()?,
    )?;
    assert_eq!(first.outcome, OutboundDispatchOutcome::Ambiguous);
    sink.add_plan(
        "intent:retry",
        LinkedInVerifiedConnectPlan::new("linkedin:member:jane-doe", None)?.retry_guarded(),
    )?;
    let second = connect_dispatch(
        &vault,
        actor,
        "receipt:retry:second",
        "intent:retry",
        &mut sink,
        active_linkedin_policy()?,
    )?;
    // The ledger owns the exact replay and abandons an ambiguous non-idempotent
    // send before it can reach the sink again.
    assert_eq!(second.outcome, OutboundDispatchOutcome::Ambiguous);
    assert_eq!(sink.transport().calls.len(), 1);
    assert_eq!(sink.transport().reads.len(), 2);

    // A resumed host execution that does reach the sink must still verify a
    // pending connection without issuing a second provider call.
    let (_tmp, vault, actor) = connect_fixture()?;
    let mut guarded = LinkedInMcpVerifiedConnectSink::new(
        linkedin_adapter()?,
        ConnectTransport::new(&[LinkedInConnectionState::Pending]),
    )
    .with_plan(
        "intent:recovery",
        LinkedInVerifiedConnectPlan::new("linkedin:member:jane-doe", None)?.retry_guarded(),
    )?;
    let recovered = connect_dispatch(
        &vault,
        actor,
        "receipt:recovery",
        "intent:recovery",
        &mut guarded,
        active_linkedin_policy()?,
    )?;
    assert_eq!(
        recovered.outcome,
        OutboundDispatchOutcome::DeliveredToChannel
    );
    assert_eq!(
        recovered
            .receipt
            .fields
            .get("duplicate_send_guard")
            .map(String::as_str),
        Some("observed_existing")
    );
    assert_eq!(
        recovered
            .receipt
            .fields
            .get("connect_with_person_called")
            .map(String::as_str),
        Some("false")
    );
    assert!(guarded.transport().calls.is_empty());
    assert_eq!(guarded.transport().reads.len(), 1);
    Ok(())
}

#[test]
fn connect_request_retry_without_observation_does_not_resend()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let (_tmp, vault, actor) = connect_fixture()?;
    let mut sink = LinkedInMcpVerifiedConnectSink::new(
        linkedin_adapter()?,
        ConnectTransport::new(&[LinkedInConnectionState::Connectable]),
    )
    .with_plan(
        "intent:retry-absent",
        LinkedInVerifiedConnectPlan::new("linkedin:member:jane-doe", None)?.retry_guarded(),
    )?;
    let result = connect_dispatch(
        &vault,
        actor,
        "receipt:retry-absent",
        "intent:retry-absent",
        &mut sink,
        active_linkedin_policy()?,
    )?;
    assert_eq!(result.outcome, OutboundDispatchOutcome::Failed);
    assert_eq!(
        result
            .receipt
            .fields
            .get("duplicate_send_guard")
            .map(String::as_str),
        Some("retry_unconfirmed")
    );
    assert!(sink.transport().calls.is_empty());
    Ok(())
}

#[test]
fn connect_request_rejects_preexisting_pending_without_claiming_new_delivery()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let (_tmp, vault, actor) = connect_fixture()?;
    let mut sink = LinkedInMcpVerifiedConnectSink::new(
        linkedin_adapter()?,
        ConnectTransport::new(&[LinkedInConnectionState::Pending]),
    )
    .with_plan(
        "intent:existing",
        LinkedInVerifiedConnectPlan::new("linkedin:member:jane-doe", None)?,
    )?;
    let result = connect_dispatch(
        &vault,
        actor,
        "receipt:existing",
        "intent:existing",
        &mut sink,
        active_linkedin_policy()?,
    )?;
    assert_eq!(result.outcome, OutboundDispatchOutcome::Failed);
    assert!(!result.receipt.fields.contains_key("provider_ref"));
    assert!(sink.transport().calls.is_empty());
    Ok(())
}

#[test]
fn connect_request_fails_closed_on_wrong_profile_and_observes_after_tool_error()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let (_tmp, vault, actor) = connect_fixture()?;
    let mut transport = ConnectTransport::new(&[LinkedInConnectionState::Connectable]);
    transport
        .observations
        .push_back(Ok(LinkedInConnectionObservation {
            recipient_key: "linkedin:member:someone-else".to_owned(),
            state: LinkedInConnectionState::Pending,
        }));
    let mut sink = LinkedInMcpVerifiedConnectSink::new(linkedin_adapter()?, transport).with_plan(
        "intent:mismatch",
        LinkedInVerifiedConnectPlan::new("linkedin:member:jane-doe", None)?
            .with_max_observation_attempts(1)?,
    )?;
    let result = connect_dispatch(
        &vault,
        actor,
        "receipt:mismatch",
        "intent:mismatch",
        &mut sink,
        active_linkedin_policy()?,
    )?;
    assert_eq!(result.outcome, OutboundDispatchOutcome::Ambiguous);
    assert!(!result.receipt.fields.contains_key("provider_ref"));
    assert_eq!(
        result
            .receipt
            .fields
            .get("verify_profile_error")
            .map(String::as_str),
        Some("profile_target_mismatch")
    );

    let (_tmp, vault, actor) = connect_fixture()?;
    let mut transport = ConnectTransport::new(&[
        LinkedInConnectionState::Connectable,
        LinkedInConnectionState::Pending,
    ]);
    transport.send_result = Err("provider_error_after_side_effect".to_owned());
    let mut sink = LinkedInMcpVerifiedConnectSink::new(linkedin_adapter()?, transport).with_plan(
        "intent:tool-error",
        LinkedInVerifiedConnectPlan::new("linkedin:member:jane-doe", None)?,
    )?;
    let result = connect_dispatch(
        &vault,
        actor,
        "receipt:tool-error",
        "intent:tool-error",
        &mut sink,
        active_linkedin_policy()?,
    )?;
    assert_eq!(result.outcome, OutboundDispatchOutcome::DeliveredToChannel);
    assert_eq!(
        result
            .receipt
            .fields
            .get("connect_with_person_result")
            .map(String::as_str),
        Some("failed")
    );
    assert_eq!(sink.transport().calls.len(), 1);
    Ok(())
}

#[test]
fn connect_request_without_seat_policy_refuses_before_provider_reads_or_send()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let (_tmp, vault, actor) = connect_fixture()?;
    let mut sink = LinkedInMcpVerifiedConnectSink::new(
        linkedin_adapter()?,
        ConnectTransport::new(&[
            LinkedInConnectionState::Connectable,
            LinkedInConnectionState::Pending,
        ]),
    )
    .with_plan(
        "intent:missing-policy",
        LinkedInVerifiedConnectPlan::new("linkedin:member:jane-doe", None)?,
    )?;
    let outcome = connect_dispatch_with_policy(
        &vault,
        actor,
        "receipt:missing-policy",
        "intent:missing-policy",
        &mut sink,
        None,
    );
    assert!(
        outcome.is_err(),
        "an omitted policy must not admit the effect"
    );
    assert!(sink.transport().reads.is_empty());
    assert!(sink.transport().calls.is_empty());
    Ok(())
}

#[test]
fn scheduled_connect_without_seat_policy_refuses_before_provider_transport()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    use crate::memory::OutboundDraftInput;

    let (_tmp, vault, _actor) = connect_fixture()?;
    let scheduled = vault
        .memory(entity(0xD1), crate::edge::EdgeActorClass::Agent)
        .schedule_outbound(&OutboundDraftInput {
            verb: "connect_request".to_owned(),
            channel: LINKEDIN_CHANNEL.to_owned(),
            target: "linkedin:member:jane-doe".to_owned(),
            on_behalf_of: Some("owner".to_owned()),
            content_ref: None,
            idempotency_key: Some("connect:scheduled:missing-policy".to_owned()),
            dedupe_key: None,
            trigger: "agent_immediate".to_owned(),
            trigger_ref: "session:linkedin-connect".to_owned(),
            job_ref: None,
            occurred_at: Some(1_060),
        });
    assert!(
        scheduled.is_err(),
        "schedule admission must reject missing seat policy"
    );
    assert!(vault.connector_send_tasks()?.is_empty());
    let mut sink = LinkedInMcpVerifiedConnectSink::new(
        linkedin_adapter()?,
        ConnectTransport::new(&[
            LinkedInConnectionState::Connectable,
            LinkedInConnectionState::Pending,
        ]),
    );
    assert_eq!(vault.run_connector_task_executor(&mut sink, 1_061)?, 0);
    assert!(sink.transport().reads.is_empty());
    assert!(sink.transport().calls.is_empty());
    Ok(())
}

/// One sink that can connect to `recipient` under `intent_ref`: the profile
/// read finds the person connectable, then the connection pending.
fn capped_connect_sink(
    intent_ref: &str,
    recipient: &str,
) -> std::result::Result<LinkedInMcpVerifiedConnectSink<ConnectTransport>, Box<dyn std::error::Error>>
{
    let observe = |state| {
        Ok(LinkedInConnectionObservation {
            recipient_key: recipient.to_owned(),
            state,
        })
    };
    Ok(LinkedInMcpVerifiedConnectSink::new(
        linkedin_adapter()?,
        ConnectTransport {
            calls: Vec::new(),
            reads: Vec::new(),
            observations: [
                observe(LinkedInConnectionState::Connectable),
                observe(LinkedInConnectionState::Pending),
            ]
            .into(),
            send_result: Ok(serde_json::json!({"success": true})),
        },
    )
    .with_plan(
        intent_ref,
        LinkedInVerifiedConnectPlan::new(recipient, None)?.with_max_observation_attempts(1)?,
    )?)
}

fn daily_connect_cap_of_one() -> crate::Result<LinkedInSeatSandboxPolicy> {
    active_linkedin_policy()?.with_limits(crate::linkedin_connector::LinkedInAccountRiskLimits {
        daily_connect_request_cap: 1,
        ..crate::linkedin_connector::LinkedInAccountRiskLimits::default()
    })
}

/// Security pack 2, F26 H359: the daily connect cap counts this vault's own
/// admitted connects, not only the host's snapshot. On one unchanged snapshot
/// with a cap of one, a connect to a second person is held before any profile
/// read or provider call: once in order, and once when the first connect is
/// admitted between the second's seat check and its admission.
#[test]
fn a_connect_past_the_daily_cap_is_held_on_an_unchanged_snapshot()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let (_tmp, vault, actor) = connect_fixture()?;
    let mut first_sink = capped_connect_sink("intent:cap:first", "linkedin:member:jane-doe")?;
    let first = connect_dispatch_to(
        &vault,
        actor.clone(),
        "receipt:cap:first",
        "intent:cap:first",
        "linkedin:member:jane-doe",
        &mut first_sink,
        Some(daily_connect_cap_of_one()?),
    )?;
    assert_ne!(first.outcome, OutboundDispatchOutcome::Held);
    assert_eq!(first_sink.transport().calls.len(), 1);
    let mut second_sink = capped_connect_sink("intent:cap:second", "linkedin:member:john-roe")?;
    let second = connect_dispatch_to(
        &vault,
        actor,
        "receipt:cap:second",
        "intent:cap:second",
        "linkedin:member:john-roe",
        &mut second_sink,
        Some(daily_connect_cap_of_one()?),
    )?;
    assert_eq!(
        second.outcome,
        OutboundDispatchOutcome::Held,
        "FAILBEFORE H359: a connect past the daily cap was not held"
    );
    assert!(second_sink.transport().calls.is_empty());
    assert!(second_sink.transport().reads.is_empty());

    // The first connect lands after the second passed its seat check: the
    // admission writer lock still counts it.
    let (_tmp, vault, actor) = connect_fixture()?;
    let vault = std::rc::Rc::new(vault);
    let hook_vault = std::rc::Rc::clone(&vault);
    let hook_actor = actor.clone();
    crate::outbound_chokepoint::BEFORE_NEW_ADMISSION.with(|slot| {
        *slot.borrow_mut() = Some(Box::new(move || {
            let mut sink = capped_connect_sink("intent:race:first", "linkedin:member:jane-doe")
                .expect("first sink");
            let first = connect_dispatch_to(
                &hook_vault,
                hook_actor,
                "receipt:race:first",
                "intent:race:first",
                "linkedin:member:jane-doe",
                &mut sink,
                Some(daily_connect_cap_of_one().expect("policy")),
            )
            .expect("the first connect dispatches");
            assert_eq!(sink.transport().calls.len(), 1);
            assert_ne!(first.outcome, OutboundDispatchOutcome::Held);
        }));
    });
    let mut racing_sink = capped_connect_sink("intent:race:second", "linkedin:member:john-roe")?;
    let racing = connect_dispatch_to(
        &vault,
        actor,
        "receipt:race:second",
        "intent:race:second",
        "linkedin:member:john-roe",
        &mut racing_sink,
        Some(daily_connect_cap_of_one()?),
    )?;
    assert_eq!(
        racing.outcome,
        OutboundDispatchOutcome::Held,
        "FAILBEFORE H359 race: the admission took the last allowance twice"
    );
    assert!(racing_sink.transport().calls.is_empty());

    // The window is a day of the dispatch clock's seconds: yesterday's
    // connect no longer spends today's allowance.
    let (_tmp, vault, actor) = connect_fixture()?;
    let mut sink = capped_connect_sink("intent:day:first", "linkedin:member:jane-doe")?;
    connect_dispatch_to(
        &vault,
        actor.clone(),
        "receipt:day:first",
        "intent:day:first",
        "linkedin:member:jane-doe",
        &mut sink,
        Some(daily_connect_cap_of_one()?),
    )?;
    let mut next_day = capped_connect_sink("intent:day:second", "linkedin:member:john-roe")?;
    let next = connect_dispatch_at(
        &vault,
        actor,
        "receipt:day:second",
        "intent:day:second",
        "linkedin:member:john-roe",
        &mut next_day,
        Some(daily_connect_cap_of_one()?),
        1_060 + 86_401,
    )?;
    assert_ne!(
        next.outcome,
        OutboundDispatchOutcome::Held,
        "H359: yesterday's connect spent today's allowance"
    );
    assert_eq!(next_day.transport().calls.len(), 1);
    Ok(())
}
