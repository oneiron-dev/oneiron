//! A stored durable failure must be eligible before its outbound effect is prepared.
use super::*;
use crate::attempt_queue::AttemptId;
use crate::llm::{
    BudgetExhaustionPolicy, BudgetGuard, BudgetLease, CallClass, CallEnvelope, CallPurpose,
    ContentPart, DeterministicFallback, DurableStepContext, FatalLlmError, LlmBackend,
    LlmGenerateFuture, LlmMessage, LlmMessageRole, LlmRequest, LlmStreamResult, ModelId,
    ModelLocality, ModelTierRef, ResponseFormat, TierPrecedence, call_as_step,
};
use crate::outbound::dispatch_types::OutboundDispatchError;
use crate::write_envelope::WriteActor;
use std::future::Future;
use std::task::{Context, Poll, Waker};

struct FatalBackend;
impl LlmBackend for FatalBackend {
    fn generate<'a>(&'a self, _: LlmRequest, _: &'a BudgetLease) -> LlmGenerateFuture<'a> {
        Box::pin(async { Err(FatalLlmError::Auth.into()) })
    }
    fn stream<'a>(&'a self, _: LlmRequest, _: &'a BudgetLease) -> LlmStreamResult<'a> {
        Err(FatalLlmError::Auth.into())
    }
}

struct NeverTransport;
impl crate::outbound_chokepoint::OutboundTransport for NeverTransport {
    fn send(
        &mut self,
        _: &crate::outbound_intent_ledger::FrozenOutboundCall,
    ) -> crate::outbound_intent_ledger::OutboundSendOutcome {
        panic!("ineligible Pending step cannot reach transport")
    }
}

fn ready<F: Future>(future: F) -> F::Output {
    let mut future = std::pin::pin!(future);
    let mut cx = Context::from_waker(Waker::noop());
    match future.as_mut().poll(&mut cx) {
        Poll::Ready(result) => result,
        Poll::Pending => panic!("scripted fatal has no pending operation"),
    }
}

fn failure_manifest(actor: &str, eligible: bool, grant: bool) -> Vec<u8> {
    let bytes = policy_manifest(actor, "email", if grant { &["send"] } else { &[] });
    let Value::Map(mut fields) = rmpv::decode::read_value(&mut bytes.as_slice()).expect("manifest")
    else {
        panic!("manifest map")
    };
    fields.push((
        Value::from("dreamer_failure_rules"),
        Value::Array(vec![Value::Map(vec![
            (Value::from("failure"), Value::from("fatal")),
            (Value::from("route"), Value::from("fallback")),
            (Value::from("consolidation_eligible"), Value::Boolean(false)),
            (Value::from("effector_eligible"), Value::Boolean(eligible)),
        ])]),
    ));
    let mut encoded = Vec::new();
    rmpv::encode::write_value(&mut encoded, &Value::Map(fields)).expect("encode manifest");
    encoded
}

fn request() -> LlmRequest {
    LlmRequest {
        model: ModelId::new("test/model@r1").expect("model"),
        envelope: CallEnvelope {
            scope: Default::default(),
            purpose: CallPurpose::Consolidation,
            class: CallClass::Durable {
                fallback: DeterministicFallback {
                    name: "json_rules_v1".into(),
                    config: Some(
                        serde_json::json!({"version":1,"rows":[{"failure":"fatal","value":{"verdict":"hold"}}]}),
                    ),
                },
            },
            tier: TierPrecedence::for_purpose(
                &CallPurpose::Consolidation,
                ModelTierRef("consolidation".into()),
            ),
            response_format: ResponseFormat::Text,
            locality: ModelLocality::OwnServer,
        },
        messages: vec![LlmMessage {
            role: LlmMessageRole::User,
            content: vec![ContentPart::Text {
                text: "step effect test".into(),
            }],
        }],
        tools: Vec::new(),
        params: Default::default(),
        provider_options: Default::default(),
    }
}

#[test]
fn step_derived_effect_rechecks_resident_eligibility_and_still_uses_gate()
-> Result<(), Box<dyn std::error::Error>> {
    let (_tmp, vault) = temp_vault();
    let agent = entity(0x51);
    vault.put_entity(
        &agent,
        crate::registry::ENTITY_TYPE_PERSON,
        crate::temporal::TimeRange { start: 1, end: 1 },
        1,
        b"dispatch actor",
    )?;
    vault.clock.set(1_000);
    let actor = OutboundDispatchActor::agent(agent);
    let manifest_id = entity(0xD0);
    put_policy_manifest_bytes(
        &vault,
        manifest_id,
        &failure_manifest(&agent.to_hex(), false, true),
    )?;

    let attempt_id = AttemptId::now();
    let ctx = DurableStepContext {
        vault: &vault,
        attempt_id,
        run_id: Some("run:step-effect".into()),
        envelope_actor: WriteActor::new(agent, EdgeActorClass::Agent),
        subject: agent,
        deadline: None,
        now_ms: 1_000,
    };
    let step_request = request();
    let guard = BudgetGuard::with_reserve_units(
        "step-effect",
        10_000,
        500,
        BudgetExhaustionPolicy::Suspend,
    );
    ready(call_as_step(
        &ctx,
        &FatalBackend,
        &guard,
        step_request.clone(),
    ))
    .expect("fatal produces recorded fallback");

    let outbound = OutboundDispatchRequest::new(
        "receipt:step-effect",
        "intent:step-effect",
        dispatch_intent(OutboundIntentTrigger::agent_immediate(
            "session:step-effect",
        )),
        actor,
        OutboundDispatchGate::allow_when_policy_grants(),
        1_000,
        OutboundDeliveryWindowDecision::DeliverNow,
    )
    .counterparty_ref("counterparty:kenji");
    let mut sink = RecordingExecutor::default();
    assert!(matches!(
        vault.dispatch_outbound_intent_from_step(
            attempt_id,
            &step_request,
            outbound.clone(),
            &mut sink
        ),
        Err(OutboundDispatchError::FailureResultIneligible)
    ));
    assert!(sink.calls.is_empty());
    let mut other_actor = outbound.clone();
    other_actor.actor = OutboundDispatchActor::agent(entity(0x52));
    assert!(matches!(
        vault.dispatch_outbound_intent_from_step(attempt_id, &step_request, other_actor, &mut sink),
        Err(OutboundDispatchError::Step(_))
    ));
    assert!(sink.calls.is_empty());

    let mut mismatched_step = step_request.clone();
    mismatched_step.messages.push(LlmMessage {
        role: LlmMessageRole::User,
        content: vec![ContentPart::Text {
            text: "different step".into(),
        }],
    });
    assert!(matches!(
        vault.dispatch_outbound_intent_from_step(
            attempt_id,
            &mismatched_step,
            outbound.clone(),
            &mut sink
        ),
        Err(OutboundDispatchError::Step(_))
    ));
    assert!(sink.calls.is_empty());

    put_policy_manifest_bytes(
        &vault,
        manifest_id,
        &failure_manifest(&agent.to_hex(), true, true),
    )?;
    // The caller starts with an eligible row, but it is revoked after payload
    // preflight and BEFORE the outbound writer transaction starts. The hook
    // parks only this scoped worker; no process-global test state is shared.
    let raced = std::thread::scope(|scope| {
        let (arrived_tx, arrived_rx) = std::sync::mpsc::sync_channel(0);
        let (release_tx, release_rx) = std::sync::mpsc::sync_channel(0);
        let candidate = outbound.clone();
        let vault_ref = &vault;
        let step_request_ref = &step_request;
        let sink_ref = &mut sink;
        let worker = scope.spawn(move || {
            crate::outbound_chokepoint::BEFORE_NEW_ADMISSION.with(|hook| {
                *hook.borrow_mut() = Some(Box::new(move || {
                    arrived_tx.send(()).expect("at admission seam");
                    release_rx.recv().expect("resume admission");
                }));
            });
            vault_ref.dispatch_outbound_intent_from_step(
                attempt_id,
                step_request_ref,
                candidate,
                sink_ref,
            )
        });
        arrived_rx
            .recv_timeout(std::time::Duration::from_secs(10))
            .expect("pre-admission rendezvous");
        put_policy_manifest_bytes(
            &vault,
            manifest_id,
            &failure_manifest(&agent.to_hex(), false, true),
        )
        .expect("revoke before admission");
        release_tx.send(()).expect("release admission");
        worker.join().expect("dispatch worker")
    });
    assert!(matches!(
        raced,
        Err(OutboundDispatchError::FailureResultIneligible)
    ));
    assert!(sink.calls.is_empty());
    let effect_attempt =
        crate::outbound::dispatch_attempt_id::outbound_dispatch_attempt_id(&outbound.intent_ref)?;
    let txn = vault.store.env.read_txn()?;
    assert!(
        crate::outbound_intent_ledger::read_intent_for_attempt_in_txn(
            &vault,
            &txn,
            effect_attempt,
            0
        )?
        .is_none()
    );
    drop(txn);

    put_policy_manifest_bytes(
        &vault,
        manifest_id,
        &failure_manifest(&agent.to_hex(), true, true),
    )?;
    let result = vault.dispatch_outbound_intent_from_step(
        attempt_id,
        &step_request,
        outbound.clone(),
        &mut sink,
    )?;
    assert_eq!(result.outcome, OutboundDispatchOutcome::DeliveredToChannel);
    assert_eq!(sink.calls.len(), 1);
    let gate_count = vault.gate_decisions(100)?.len();
    let txn = vault.store.env.read_txn()?;
    let delivered_row = crate::outbound_intent_ledger::read_intent_for_attempt_in_txn(
        &vault,
        &txn,
        effect_attempt,
        0,
    )?
    .expect("delivered row");
    drop(txn);

    // A later restriction cannot hide the already-recorded Done/Acked result.
    put_policy_manifest_bytes(
        &vault,
        manifest_id,
        &failure_manifest(&agent.to_hex(), false, true),
    )?;
    let replay = vault.dispatch_outbound_intent_from_step(
        attempt_id,
        &step_request,
        outbound.clone(),
        &mut sink,
    )?;
    assert_eq!(replay.outcome, OutboundDispatchOutcome::DeliveredToChannel);
    assert_eq!(sink.calls.len(), 1, "terminal replay must never resend");
    assert_eq!(vault.gate_decisions(100)?.len(), gate_count);
    let txn = vault.store.env.read_txn()?;
    let replayed_row = crate::outbound_intent_ledger::read_intent_for_attempt_in_txn(
        &vault,
        &txn,
        effect_attempt,
        0,
    )?
    .expect("replayed row");
    assert_eq!(
        replayed_row.budget_accounting,
        delivered_row.budget_accounting
    );
    assert!(
        replayed_row == delivered_row,
        "terminal replay rewrote its ledger row"
    );
    drop(txn);
    assert!(matches!(
        vault.dispatch_outbound_intent_from_step(
            attempt_id,
            &mismatched_step,
            outbound.clone(),
            &mut sink
        ),
        Err(OutboundDispatchError::Chokepoint(
            crate::outbound_intent_ledger::IntentLedgerError::InvalidRecord(_)
        ))
    ));
    assert_eq!(sink.calls.len(), 1);

    // Permission from the failure row never replaces the ordinary effect gate.
    put_policy_manifest_bytes(
        &vault,
        manifest_id,
        &failure_manifest(&agent.to_hex(), true, false),
    )?;
    let mut other_intent = outbound;
    other_intent.receipt_id = "receipt:step-effect:no-grant".into();
    other_intent.intent_ref = "intent:step-effect:no-grant".into();
    let mut pending_request = other_intent.clone();
    pending_request.receipt_id = "receipt:step-effect:pending".into();
    pending_request.intent_ref = "intent:step-effect:pending".into();
    // ONE-1881 semantic dedupe: this is a different logical send, not a
    // duplicate of the delivered one whose terminal replay we proved above.
    pending_request.intent.target = "counterparty:second".into();
    pending_request.intent.idempotency_key = Some("idem:step-effect:second".into());
    pending_request.intent.dedupe_key = Some("dedupe:step-effect:second".into());
    let denied = vault.dispatch_outbound_intent_from_step(
        attempt_id,
        &step_request,
        other_intent,
        &mut sink,
    )?;
    assert_ne!(denied.outcome, OutboundDispatchOutcome::DeliveredToChannel);
    assert_eq!(sink.calls.len(), 1);

    // A Pending live retry is not terminal replay: it must read the current
    // failure rule again and may send only after that rule admits the result.
    put_policy_manifest_bytes(
        &vault,
        manifest_id,
        &failure_manifest(&agent.to_hex(), true, true),
    )?;
    sink.outcome = OutboundExecutionOutcome::failed("provider_timeout");
    let first = vault.dispatch_outbound_intent_from_step(
        attempt_id,
        &step_request,
        pending_request.clone(),
        &mut sink,
    )?;
    assert_eq!(first.outcome, OutboundDispatchOutcome::Failed);
    assert_eq!(sink.calls.len(), 2);
    let pending_attempt = crate::outbound::dispatch_attempt_id::outbound_dispatch_attempt_id(
        &pending_request.intent_ref,
    )?;
    let txn = vault.store.env.read_txn()?;
    let pending_row = crate::outbound_intent_ledger::read_intent_for_attempt_in_txn(
        &vault,
        &txn,
        pending_attempt,
        0,
    )?
    .expect("pending ledger row");
    assert_eq!(
        pending_row.state,
        crate::outbound_intent_ledger::IntentState::Pending
    );
    drop(txn);
    put_policy_manifest_bytes(
        &vault,
        manifest_id,
        &failure_manifest(&agent.to_hex(), false, true),
    )?;
    assert!(matches!(
        vault.dispatch_outbound_intent_from_step(
            attempt_id,
            &step_request,
            pending_request.clone(),
            &mut sink,
        ),
        Err(OutboundDispatchError::FailureResultIneligible)
    ));
    assert_eq!(sink.calls.len(), 2);
    // Engine-owned Resume has no prepared request but still carries the
    // authenticated step binding in the frozen ledger payload.
    let authority = crate::outbound_consent::OutboundBindingAuthority::for_vault(&vault)?;
    assert!(matches!(
        crate::outbound_chokepoint::execute_outbound_effect(
            &vault,
            &authority,
            crate::outbound_chokepoint::OutboundEffectCommand::Resume(pending_row.id),
            1_000,
            &mut NeverTransport,
        ),
        Err(crate::outbound_intent_ledger::IntentLedgerError::FailureResultIneligible)
    ));
    let txn = vault.store.env.read_txn()?;
    let blocked_row = crate::outbound_intent_ledger::read_intent_for_attempt_in_txn(
        &vault,
        &txn,
        pending_attempt,
        0,
    )?
    .expect("pending row remains");
    assert_eq!(
        blocked_row.state,
        crate::outbound_intent_ledger::IntentState::Pending
    );
    drop(txn);
    put_policy_manifest_bytes(
        &vault,
        manifest_id,
        &failure_manifest(&agent.to_hex(), true, true),
    )?;
    sink.outcome = OutboundExecutionOutcome::delivered_to_channel("provider:message:two");
    let resumed = vault.dispatch_outbound_intent_from_step(
        attempt_id,
        &step_request,
        pending_request,
        &mut sink,
    )?;
    assert_eq!(resumed.outcome, OutboundDispatchOutcome::DeliveredToChannel);
    assert_eq!(sink.calls.len(), 3);
    Ok(())
}
