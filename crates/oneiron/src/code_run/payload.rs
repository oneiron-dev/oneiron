use rmpv::Value;

use crate::{
    ClaimApprovalStatus, ClaimCandidate, ClaimSource, EdgeActorClass, EntityId, Error, Result,
    ScoredEntity, WriteActor, WriteEnvelope, WriteProvenance,
    context_projection::ContextSpec,
    error::{GateDenialOutcome, GateDenialReason},
};

use super::dispatcher::SELF_PROVENANCE_SURFACE_KEY;
use super::support::{
    bool_value, decode_array, edge_kind_value, entity_id_value, entity_value, expect_map,
    f32_value, invalid_code_run_replay, map_get, optional_entity_value, optional_f32_value,
    optional_u64_value, optional_value, request_map, str_array, str_value, u64_value,
};
use super::types::{
    SelfCall, SelfContextResult, SelfDeniedResult, SelfDispatchOutcome, SelfDurableWait,
    SelfDurableWaitReason, SelfEffect, SelfFailedResult, SelfMemoryEdgeWriteResult,
    SelfMemorySearchResult, SelfMemoryWriteResult, SelfSpeechResult,
};

const CODE_RUN_REPLAY_CANONICAL_REQUEST_ACTOR: [u8; 16] = [0x42; 16];

pub(super) fn self_call_request_value(call: &SelfCall) -> Result<Value> {
    Ok(match call {
        SelfCall::MemorySearch(call) => request_map(vec![
            ("query", Value::from(call.query.as_str())),
            ("limit", Value::from(call.limit as u64)),
        ]),
        SelfCall::MemoryWriteFixture(call) => request_map(vec![
            ("id", entity_id_value(call.id)),
            ("candidate", claim_candidate_request_value(&call.candidate)?),
            ("occurred_start", Value::from(call.occurred.start)),
            ("occurred_end", Value::from(call.occurred.end)),
            ("learned_at", Value::from(call.learned_at)),
        ]),
        SelfCall::MemoryPutClaim(call) => request_map(vec![
            ("id", entity_id_value(call.id)),
            ("candidate", claim_candidate_request_value(&call.candidate)?),
            ("occurred_start", Value::from(call.occurred.start)),
            ("occurred_end", Value::from(call.occurred.end)),
            ("learned_at", Value::from(call.learned_at)),
        ]),
        SelfCall::MemorySupersedeClaim(call) => request_map(vec![
            ("new_id", entity_id_value(call.new_id)),
            ("old_id", entity_id_value(call.old_id)),
            ("now", Value::from(call.now)),
        ]),
        SelfCall::MemoryPutEdge(call) => request_map(vec![
            ("src", entity_id_value(call.src)),
            ("kind", Value::from(call.kind as u8)),
            ("tgt", entity_id_value(call.tgt)),
            ("weight", Value::F32(call.weight)),
        ]),
        SelfCall::AskHuman(call) => {
            request_map(vec![("prompt", Value::from(call.prompt.as_str()))])
        }
        SelfCall::DestructiveFixture(call) | SelfCall::OutboundFixture(call) => {
            request_map(vec![("label", Value::from(call.label.as_str()))])
        }
        SelfCall::Context(call) => {
            request_map(vec![("spec", Value::from(context_spec_json(&call.spec)?))])
        }
        SelfCall::Speak(call) | SelfCall::Think(call) | SelfCall::Express(call) => {
            request_map(vec![
                ("text", Value::from(call.text.as_str())),
                ("order", Value::from(u64::from(call.order))),
                ("occurred_at", Value::from(call.occurred_at)),
            ])
        }
    })
}

fn context_spec_json(spec: &ContextSpec) -> Result<String> {
    serde_json::to_string(spec).map_err(|_| invalid_code_run_replay("context spec does not encode"))
}

fn claim_candidate_request_value(candidate: &ClaimCandidate) -> Result<Value> {
    let envelope = canonical_replay_request_envelope()?;
    let body = (*candidate).clone().into_claim_body(&envelope);
    Ok(Value::Map(vec![
        (
            Value::from("predicate"),
            Value::from(body.predicate.as_str()),
        ),
        (Value::from("subject"), Value::Binary(body.subject.encode())),
        (Value::from("value"), body.value.clone()),
        (Value::from("confidence"), Value::F32(body.confidence)),
        (Value::from("salience"), optional_f32_value(body.salience)),
        (
            Value::from("evidence"),
            optional_value(body.evidence.clone()),
        ),
        (
            Value::from("valid_from"),
            optional_u64_value(body.valid_from),
        ),
        (Value::from("valid_to"), optional_u64_value(body.valid_to)),
        (Value::from("world"), optional_entity_value(body.world)),
        (Value::from("scope"), optional_value(body.scope.clone())),
        (Value::from("stale"), Value::Boolean(body.stale)),
    ]))
}

fn canonical_replay_request_envelope() -> Result<WriteEnvelope> {
    let actor = EntityId::from_bytes(CODE_RUN_REPLAY_CANONICAL_REQUEST_ACTOR)
        .map_err(|_| invalid_code_run_replay("canonical replay actor id is invalid"))?;
    Ok(WriteEnvelope::new(
        WriteActor::new(actor, EdgeActorClass::Agent),
        ClaimSource::Generated,
        WriteProvenance::new(Value::Map(vec![(
            Value::from(SELF_PROVENANCE_SURFACE_KEY),
            Value::from("code_run_replay_request"),
        )]))?,
        ClaimApprovalStatus::Proposed,
    ))
}

pub(super) fn self_dispatch_outcome_value(outcome: &SelfDispatchOutcome) -> Value {
    match outcome {
        SelfDispatchOutcome::MemorySearch(result) => request_map(vec![
            ("kind", Value::from("memory_search")),
            ("query", Value::from(result.query.as_str())),
            (
                "results",
                Value::Array(
                    result
                        .results
                        .iter()
                        .map(|hit| {
                            request_map(vec![
                                ("id", entity_id_value(hit.id)),
                                ("score", Value::F32(hit.score)),
                            ])
                        })
                        .collect(),
                ),
            ),
        ]),
        SelfDispatchOutcome::MemoryWrite(result) => request_map(vec![
            ("kind", Value::from("memory_write")),
            ("id", entity_id_value(result.id)),
        ]),
        SelfDispatchOutcome::MemoryEdgeWrite(result) => request_map(vec![
            ("kind", Value::from("memory_edge_write")),
            ("src", entity_id_value(result.src)),
            ("edge_kind", Value::from(result.kind as u8)),
            ("tgt", entity_id_value(result.tgt)),
        ]),
        SelfDispatchOutcome::DurableWait(wait) => request_map(vec![
            ("kind", Value::from("durable_wait")),
            ("wait_id", entity_id_value(wait.wait_id)),
            ("effect", Value::from(wait.effect.as_str())),
            ("reason", Value::from(durable_wait_reason_str(wait.reason))),
            (
                "prompt",
                wait.prompt
                    .as_ref()
                    .map_or(Value::Nil, |prompt| Value::from(prompt.as_str())),
            ),
        ]),
        SelfDispatchOutcome::Denied(result) => request_map(vec![
            ("kind", Value::from("denied")),
            ("effect", Value::from(result.effect.as_str())),
            ("outcome", Value::from(result.outcome.as_str())),
            (
                "reason_codes",
                Value::Array(
                    result
                        .reason_codes
                        .iter()
                        .map(|reason| Value::from(reason.as_str()))
                        .collect(),
                ),
            ),
        ]),
        SelfDispatchOutcome::Failed(result) => request_map(vec![
            ("kind", Value::from("failed")),
            ("effect", Value::from(result.effect.as_str())),
            ("error", Value::from(result.error.as_str())),
        ]),
        SelfDispatchOutcome::Context(result) => request_map(vec![
            ("kind", Value::from("context")),
            (
                "spec",
                context_spec_json(&result.spec).map_or(Value::Nil, Value::from),
            ),
        ]),
        SelfDispatchOutcome::Speech(result) => request_map(vec![
            ("kind", Value::from("speech")),
            ("effect", Value::from(result.effect.as_str())),
            ("order", Value::from(u64::from(result.order))),
            ("is_visible", Value::Boolean(result.is_visible)),
            ("emitted", Value::Boolean(result.emitted)),
        ]),
    }
}

pub(super) fn decode_self_dispatch_outcome(value: &Value) -> Result<SelfDispatchOutcome> {
    let entries = expect_map(value, "dispatch outcome must be a map")?;
    let kind = str_value(map_get(entries, "kind")?)?;
    match kind {
        "memory_search" => {
            let results = decode_array(map_get(entries, "results")?, decode_scored_entity)?;
            Ok(SelfDispatchOutcome::MemorySearch(SelfMemorySearchResult {
                query: str_value(map_get(entries, "query")?)?.to_owned(),
                results,
            }))
        }
        "memory_write" => Ok(SelfDispatchOutcome::MemoryWrite(SelfMemoryWriteResult {
            id: entity_value(map_get(entries, "id")?)?,
        })),
        "memory_edge_write" => Ok(SelfDispatchOutcome::MemoryEdgeWrite(
            SelfMemoryEdgeWriteResult {
                src: entity_value(map_get(entries, "src")?)?,
                kind: edge_kind_value(map_get(entries, "edge_kind")?)?,
                tgt: entity_value(map_get(entries, "tgt")?)?,
            },
        )),
        "durable_wait" => {
            let prompt = match map_get(entries, "prompt")? {
                Value::Nil => None,
                value => Some(str_value(value)?.to_owned()),
            };
            Ok(SelfDispatchOutcome::DurableWait(SelfDurableWait {
                wait_id: entity_value(map_get(entries, "wait_id")?)?,
                effect: self_effect_from_str(str_value(map_get(entries, "effect")?)?)?,
                reason: durable_wait_reason_from_str(str_value(map_get(entries, "reason")?)?)?,
                prompt,
            }))
        }
        "denied" => Ok(SelfDispatchOutcome::Denied(SelfDeniedResult {
            effect: self_effect_from_str(str_value(map_get(entries, "effect")?)?)?,
            outcome: str_value(map_get(entries, "outcome")?)?.to_owned(),
            reason_codes: str_array(map_get(entries, "reason_codes")?)?,
        })),
        "failed" => Ok(SelfDispatchOutcome::Failed(SelfFailedResult {
            effect: self_effect_from_str(str_value(map_get(entries, "effect")?)?)?,
            error: str_value(map_get(entries, "error")?)?.to_owned(),
        })),
        "speech" => {
            let order = u32::try_from(u64_value(map_get(entries, "order")?)?)
                .map_err(|_| invalid_code_run_replay("speech order out of range"))?;
            let effect = self_effect_from_str(str_value(map_get(entries, "effect")?)?)?;
            if !effect.is_speech() {
                return Err(invalid_code_run_replay(
                    "speech outcome names a non-speech effect",
                ));
            }
            let is_visible = bool_value(map_get(entries, "is_visible")?)?;
            let emitted = bool_value(map_get(entries, "emitted")?)?;
            // ONE-1686 coherence, at the DECODE boundary: a `speech` outcome
            // means a MESSAGE bubble was materialized, so `emitted: false` is
            // not a weaker speech row — it is a row claiming two contradictory
            // things at once. A speech attempt that produced no bubble is a
            // `denied`, `failed` or `durable_wait` row, and replay must be able
            // to tell those apart without guessing: the trailing-plaintext
            // fallback reads exactly this distinction.
            if !emitted {
                return Err(invalid_code_run_replay(
                    "speech outcome claims no emission; a bubble-less attempt is denied/failed",
                ));
            }
            // Visibility is the UTTERANCE's, decided once by the family; a row
            // that disagrees with its own effect is a forged axis, not a
            // variant.
            if is_visible
                != effect
                    .speech_utterance()
                    .ok_or(invalid_code_run_replay(
                        "speech effect carries no utterance",
                    ))?
                    .is_visible()
            {
                return Err(invalid_code_run_replay(
                    "speech outcome visibility contradicts its effect",
                ));
            }
            Ok(SelfDispatchOutcome::Speech(SelfSpeechResult {
                effect,
                order,
                is_visible,
                emitted,
            }))
        }
        "context" => Ok(SelfDispatchOutcome::Context(SelfContextResult {
            spec: serde_json::from_str(str_value(map_get(entries, "spec")?)?)
                .map_err(|_| invalid_code_run_replay("context spec does not decode"))?,
        })),
        _ => Err(invalid_code_run_replay("unknown dispatch outcome kind")),
    }
}

pub(super) fn replay_denied_trap_error(result: &SelfDeniedResult) -> Error {
    let outcome =
        GateDenialOutcome::parse(&result.outcome).map_or("deny", GateDenialOutcome::as_str);
    let reason_codes = result
        .reason_codes
        .iter()
        .filter_map(|reason| GateDenialReason::from_code(reason))
        .map(GateDenialReason::as_str)
        .collect::<Vec<_>>();
    Error::GateWriteRejected {
        outcome,
        reason_codes,
    }
}

pub(super) fn replay_failed_trap_error(_result: &SelfFailedResult) -> Error {
    invalid_code_run_replay("replayed failed self trap")
}

fn decode_scored_entity(value: &Value) -> Result<ScoredEntity> {
    let entries = expect_map(value, "scored entity must be a map")?;
    Ok(ScoredEntity {
        id: entity_value(map_get(entries, "id")?)?,
        score: f32_value(map_get(entries, "score")?)?,
    })
}

pub(super) fn self_effect_from_str(value: &str) -> Result<SelfEffect> {
    match value {
        "self.memory.search" => Ok(SelfEffect::MemorySearch),
        "self.memory.write_fixture" => Ok(SelfEffect::MemoryWriteFixture),
        "self.memory.put_claim" => Ok(SelfEffect::MemoryPutClaim),
        "self.memory.supersede_claim" => Ok(SelfEffect::MemorySupersedeClaim),
        "self.memory.put_edge" => Ok(SelfEffect::MemoryPutEdge),
        "self.ask_human" => Ok(SelfEffect::AskHuman),
        "self.fixture.destructive" => Ok(SelfEffect::DestructiveFixture),
        "self.fixture.outbound" => Ok(SelfEffect::OutboundFixture),
        "self.tasks.delegate" => Ok(SelfEffect::TaskDelegate),
        "self.context" => Ok(SelfEffect::Context),
        "self.speak" => Ok(SelfEffect::Speak),
        "self.think" => Ok(SelfEffect::Think),
        "self.express" => Ok(SelfEffect::Express),
        _ => Err(invalid_code_run_replay("unknown self effect")),
    }
}

pub(super) fn durable_wait_reason_str(reason: SelfDurableWaitReason) -> &'static str {
    match reason {
        SelfDurableWaitReason::HumanInput => "human_input",
        SelfDurableWaitReason::DestructiveEffect => "destructive_effect",
        SelfDurableWaitReason::OutboundEffect => "outbound_effect",
        SelfDurableWaitReason::PeerResult => "peer_result",
    }
}

pub(super) fn durable_wait_reason_from_str(value: &str) -> Result<SelfDurableWaitReason> {
    match value {
        "human_input" => Ok(SelfDurableWaitReason::HumanInput),
        "destructive_effect" => Ok(SelfDurableWaitReason::DestructiveEffect),
        "outbound_effect" => Ok(SelfDurableWaitReason::OutboundEffect),
        "peer_result" => Ok(SelfDurableWaitReason::PeerResult),
        _ => Err(invalid_code_run_replay("unknown durable wait reason")),
    }
}
