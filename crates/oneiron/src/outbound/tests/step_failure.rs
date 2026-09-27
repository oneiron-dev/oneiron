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
    let result = vault.dispatch_outbound_intent_from_step(
        attempt_id,
        &step_request,
        outbound.clone(),
        &mut sink,
    )?;
    assert_eq!(result.outcome, OutboundDispatchOutcome::DeliveredToChannel);
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
    let denied = vault.dispatch_outbound_intent_from_step(
        attempt_id,
        &step_request,
        other_intent,
        &mut sink,
    )?;
    assert_ne!(denied.outcome, OutboundDispatchOutcome::DeliveredToChannel);
    assert_eq!(sink.calls.len(), 1);
    Ok(())
}
