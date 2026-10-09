//! Gate-pending holds, delivery-window door evaluation, pending re-arm and retry-after authority.

use super::*;

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
        OutboundDispatchError::ObsoleteAskConfirmation => {
            panic!("unexpected stale ask confirmation")
        }
        OutboundDispatchError::FailureResultIneligible => {
            panic!("unexpected failure policy denial")
        }
        OutboundDispatchError::Step(error) => panic!("unexpected step error: {error}"),
        OutboundDispatchError::Engine(error) => panic!("unexpected engine error: {error}"),
        OutboundDispatchError::Chokepoint(error) => {
            panic!("unexpected chokepoint error: {error}")
        }
    }
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
