//! Verify-after-send and fail-closed retry tests for connection requests.
use super::*;
use crate::linkedin_connector::{
    LinkedInConnectionState as State, LinkedInMcpConnectRequest, LinkedInMcpConnectTransport,
    LinkedInMcpVerifiedConnectSink, LinkedInVerifiedConnectPlan,
};
use std::collections::{BTreeMap, VecDeque};

struct Wire {
    reads: VecDeque<State>,
    calls: Vec<LinkedInMcpConnectRequest>,
}
impl Wire {
    fn new(reads: Vec<State>) -> Self {
        Self {
            reads: reads.into(),
            calls: vec![],
        }
    }
}
impl LinkedInMcpConnectTransport for Wire {
    fn connect_with_person(
        &mut self,
        request: &LinkedInMcpConnectRequest,
    ) -> std::result::Result<serde_json::Value, String> {
        self.calls.push(request.clone());
        Ok(serde_json::json!({"success": true}))
    }
    fn connection_state(&mut self, _: &str) -> std::result::Result<State, String> {
        self.reads.pop_front().ok_or("no observation".into())
    }
}
fn plan() -> crate::Result<LinkedInVerifiedConnectPlan> {
    LinkedInVerifiedConnectPlan::new("linkedin:member:jane-doe", Some("A note".into()))
}
fn intent() -> OutboundIntent {
    OutboundIntent::from_trigger(
        OutboundIntentDraft::new(
            "agent-alpha",
            "connect_request",
            "linkedin",
            "linkedin:member:jane-doe",
        ),
        OutboundIntentTrigger::agent_immediate("session:connect"),
    )
}
fn prepare(
    vault: &Vault,
) -> std::result::Result<OutboundDispatchActor, Box<dyn std::error::Error>> {
    let actor = OutboundDispatchActor::agent(entity(0xB1));
    put_connector_task_actor(vault, entity(0xB1), 1)?;
    put_policy_manifest_bytes(
        vault,
        entity(0xE0),
        &policy_manifest(
            actor.actor_ref.as_deref().unwrap(),
            "linkedin",
            &["connect_request"],
        ),
    )?;
    Ok(actor)
}
fn request(
    actor: OutboundDispatchActor,
    policy: LinkedInSeatSandboxPolicy,
) -> OutboundDispatchRequest {
    OutboundDispatchRequest::new(
        "receipt:connect",
        "intent:connect",
        intent(),
        actor,
        OutboundDispatchGate::allow_when_policy_grants(),
        1060,
        OutboundDeliveryWindowDecision::DeliverNow,
    )
    .linkedin_sandbox_policy(policy)
}
#[test]
fn linkedin_connect_dispatch_observes_before_delivered_receipt()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let (_tmp, vault) = temp_vault();
    let actor = prepare(&vault)?;
    let mut sink = LinkedInMcpVerifiedConnectSink::new(
        &vault,
        Wire::new(vec![
            State::NotConnected,
            State::RequestPending {
                provider_ref: "invitation:42".into(),
            },
        ]),
    )
    .with_plan("intent:connect", plan()?)?;
    let result =
        vault.dispatch_outbound_intent(request(actor, active_linkedin_policy()?), &mut sink)?;
    assert_eq!(result.outcome, OutboundDispatchOutcome::DeliveredToChannel);
    assert_eq!(
        result
            .receipt
            .fields
            .get("provider_ref")
            .map(String::as_str),
        Some("invitation:42")
    );
    assert_eq!(
        result
            .receipt
            .fields
            .get("connect_with_person_return_trusted")
            .map(String::as_str),
        Some("false")
    );
    assert_eq!(sink.transport().calls.len(), 1);
    assert_eq!(sink.transport().calls[0].note.as_deref(), Some("A note"));
    assert!(sink.transport().reads.is_empty());
    Ok(())
}
#[test]
fn linkedin_connect_cap_and_kill_switch_stop_transport()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    for (policy, expected) in [
        (
            active_linkedin_policy()?
                .with_state(LinkedInSeatDispatchState::active().with_dm_sends_today(15)),
            OutboundDispatchOutcome::Held,
        ),
        (
            active_linkedin_policy()?.mark_killed(1059, "owner-disabled")?,
            OutboundDispatchOutcome::Suppressed,
        ),
    ] {
        let (_tmp, vault) = temp_vault();
        let actor = prepare(&vault)?;
        let mut sink = LinkedInMcpVerifiedConnectSink::new(&vault, Wire::new(vec![]))
            .with_plan("intent:connect", plan()?)?;
        assert_eq!(
            vault
                .dispatch_outbound_intent(request(actor, policy), &mut sink)?
                .outcome,
            expected
        );
        assert!(sink.transport().calls.is_empty());
    }
    Ok(())
}
#[test]
fn linkedin_connect_does_not_trust_tool_return_or_resend_after_sink_restart() -> crate::Result<()> {
    let (_tmp, vault) = temp_vault();
    let intent = intent();
    let request = OutboundExecutionRequest {
        intent_ref: "intent:connect",
        intent: &intent,
        idempotency_key: None,
        verb_contract: outbound_verb_contract("linkedin", "connect_request").unwrap(),
        channel_identity_ref: None,
        counterparty_ref: None,
        hygiene_headers: BTreeMap::new(),
        apns_interruption_level: None,
        calendar_invite: None,
    };
    let mut first = LinkedInMcpVerifiedConnectSink::new(
        &vault,
        Wire::new(vec![State::NotConnected, State::NotConnected]),
    )
    .with_plan("intent:connect", plan()?)?;
    let result = first.execute(&request);
    assert_eq!(result.kind, OutboundExecutionOutcomeKind::Failed);
    assert!(result.delivery_may_have_occurred);
    assert_eq!(first.transport().calls.len(), 1);
    drop(first);
    let mut second =
        LinkedInMcpVerifiedConnectSink::new(&vault, Wire::new(vec![State::NotConnected]))
            .with_plan("intent:connect", plan()?)?;
    assert_eq!(
        second.execute(&request).kind,
        OutboundExecutionOutcomeKind::Failed
    );
    assert!(second.transport().calls.is_empty());
    let mut third = LinkedInMcpVerifiedConnectSink::new(
        &vault,
        Wire::new(vec![State::Connected {
            provider_ref: "connection:42".into(),
        }]),
    )
    .with_plan("intent:connect", plan()?)?;
    assert_eq!(
        third.execute(&request).kind,
        OutboundExecutionOutcomeKind::DeliveredToChannel
    );
    assert!(third.transport().calls.is_empty());
    Ok(())
}
