//! Code-run request and outcome replay values.
//! Entry: `self_call_request_value`.
//! The request child owns request encoding; `code_run::types` owns call and outcome types.

mod observations;
mod request;
mod session_hooks;

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
    AgentVerbRefusalWords, SelfCall, SelfContextResult, SelfDeniedResult, SelfDispatchOutcome,
    SelfDurableWait, SelfDurableWaitReason, SelfEffect, SelfFailedResult,
    SelfMemoryEdgeWriteResult, SelfMemoryWriteResult, SelfSpeechResult,
};
use super::{SelfLeaderCall, SummarizeEffort, coordination_codec};
use crate::error::GateError;

pub(crate) use self::observations::agent_verb_observations_of;
pub(super) use self::request::self_call_request_value;

fn context_spec_json(spec: &ContextSpec) -> Result<String> {
    serde_json::to_string(spec).map_err(|_| invalid_code_run_replay("context spec does not encode"))
}

pub(super) fn self_dispatch_outcome_value(outcome: &SelfDispatchOutcome) -> Result<Value> {
    Ok(match outcome {
        SelfDispatchOutcome::AgentSpawn(result) => super::coordination_codec::spawn_value(result)?,
        SelfDispatchOutcome::AgentDefinitionPut(result) => request_map(vec![
            ("kind", Value::from("agent_definition_put")),
            ("id", entity_id_value(result.id)),
            ("disposition", Value::from(result.disposition.as_str())),
        ]),
        SelfDispatchOutcome::TaskAsk(result) => super::coordination_codec::ask_value(result)?,
        SelfDispatchOutcome::TaskAskStatus(result) => {
            super::coordination_codec::status_value(result)?
        }
        SelfDispatchOutcome::MemorySearch(result) => session_hooks::memory_search_value(result)?,
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
        SelfDispatchOutcome::AgentVerb(answer) => {
            let mut entries = vec![
                ("kind", Value::from("agent_verb")),
                ("output", Value::from(answer.output.to_string())),
            ];
            if let Some(rows) = &answer.rows {
                entries.push((
                    "rows",
                    Value::Array(rows.iter().copied().map(entity_id_value).collect()),
                ));
            }
            observations::keep_observations(&mut entries, &answer.observations)?;
            request_map(entries)
        }
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
        SelfDispatchOutcome::InferenceDefaults(json) => request_map(vec![
            ("kind", Value::from("inference_defaults")),
            ("json", Value::from(json.as_str())),
        ]),
        SelfDispatchOutcome::Fold(json) => request_map(vec![
            ("kind", Value::from("fold")),
            ("json", Value::from(json.as_str())),
        ]),
        SelfDispatchOutcome::TaskRefusal(result) => request_map(vec![
            ("kind", Value::from("task_refusal")),
            ("task_ref", entity_id_value(result.task_ref)),
            ("level", Value::from(result.level.as_str())),
            ("replay", Value::Boolean(result.replay)),
        ]),
        SelfDispatchOutcome::SkillCall(result) => request_map(vec![
            ("kind", Value::from("skill_call")),
            ("skill", entity_id_value(result.skill)),
            ("output", Value::from(result.output.to_string())),
        ]),
        SelfDispatchOutcome::WakePolicyWritten(policy) => {
            request_map(vec![
                ("kind", Value::from("wake_policy_written")),
                (
                    "policy",
                    Value::from(serde_json::to_string(policy).map_err(|_| {
                        invalid_code_run_replay("wake policy result does not encode")
                    })?),
                ),
            ])
        }
        SelfDispatchOutcome::ReportBlocked { receipt } => request_map(vec![
            ("kind", Value::from("report_blocked")),
            ("receipt", entity_id_value(*receipt)),
        ]),
        SelfDispatchOutcome::Speech(result) => request_map(vec![
            ("kind", Value::from("speech")),
            ("effect", Value::from(result.effect.as_str())),
            ("order", Value::from(u64::from(result.order))),
            ("is_visible", Value::Boolean(result.is_visible)),
            ("emitted", Value::Boolean(result.emitted)),
        ]),
        SelfDispatchOutcome::ReaderSpawn(receipt) => json_outcome("reader_spawn", receipt)?,
        SelfDispatchOutcome::ReaderReport(receipt) => json_outcome("reader_report", receipt)?,
        SelfDispatchOutcome::TaskWaitSet(result) => json_outcome("task_wait_set", result)?,
        SelfDispatchOutcome::Summarize(reply) => json_outcome("summarize", reply)?,
        SelfDispatchOutcome::Leader(json) => request_map(vec![
            ("kind", Value::from("leader")),
            ("json", Value::from(json.as_str())),
        ]),
        SelfDispatchOutcome::Team(answer) => json_outcome("team", answer)?,
        SelfDispatchOutcome::TeamSubmitted(answer) => json_outcome("team_submitted", answer)?,
    })
}

/// An outcome kept as its JSON, as a fold's answer is.
fn json_outcome(kind: &'static str, value: &impl serde::Serialize) -> Result<Value> {
    let json = serde_json::to_string(value)
        .map_err(|_| invalid_code_run_replay("dispatch outcome does not encode"))?;
    Ok(request_map(vec![
        ("kind", Value::from(kind)),
        ("json", Value::from(json)),
    ]))
}

/// An outcome [`json_outcome`] kept.
fn decode_json_outcome<T: serde::de::DeserializeOwned>(entries: &[(Value, Value)]) -> Result<T> {
    serde_json::from_str(str_value(map_get(entries, "json")?)?)
        .map_err(|_| invalid_code_run_replay("dispatch outcome does not decode"))
}

pub(super) fn decode_self_dispatch_outcome(value: &Value) -> Result<SelfDispatchOutcome> {
    let entries = expect_map(value, "dispatch outcome must be a map")?;
    let kind = str_value(map_get(entries, "kind")?)?;
    match kind {
        "inference_defaults" => Ok(SelfDispatchOutcome::InferenceDefaults(
            str_value(map_get(entries, "json")?)?.to_owned(),
        )),
        "fold" => Ok(SelfDispatchOutcome::Fold(
            str_value(map_get(entries, "json")?)?.to_owned(),
        )),
        "leader" => Ok(SelfDispatchOutcome::Leader(
            str_value(map_get(entries, "json")?)?.to_owned(),
        )),
        "reader_spawn" => Ok(SelfDispatchOutcome::ReaderSpawn(decode_json_outcome(
            entries,
        )?)),
        "reader_report" => Ok(SelfDispatchOutcome::ReaderReport(decode_json_outcome(
            entries,
        )?)),
        "team" => Ok(SelfDispatchOutcome::Team(decode_json_outcome(entries)?)),
        "team_submitted" => Ok(SelfDispatchOutcome::TeamSubmitted(decode_json_outcome(
            entries,
        )?)),
        "task_wait_set" => Ok(SelfDispatchOutcome::TaskWaitSet(decode_json_outcome(
            entries,
        )?)),
        "summarize" => Ok(SelfDispatchOutcome::Summarize(decode_json_outcome(
            entries,
        )?)),
        "task_refusal" => Ok(SelfDispatchOutcome::TaskRefusal(
            super::SelfTaskRefusalResult {
                task_ref: entity_value(map_get(entries, "task_ref")?)?,
                level: crate::agent_def::RefusalLevel::parse(str_value(map_get(
                    entries, "level",
                )?)?)
                .ok_or_else(|| invalid_code_run_replay("invalid refusal level"))?,
                replay: bool_value(map_get(entries, "replay")?)?,
            },
        )),
        "skill_call" => Ok(SelfDispatchOutcome::SkillCall(super::SelfSkillCallResult {
            skill: entity_value(map_get(entries, "skill")?)?,
            output: serde_json::from_str(str_value(map_get(entries, "output")?)?)
                .map_err(|_| invalid_code_run_replay("invalid skill call output"))?,
        })),
        "wake_policy_written" => {
            let policy: crate::dreamer_wake::DreamerWakePolicy =
                serde_json::from_str(str_value(map_get(entries, "policy")?)?)
                    .map_err(|_| invalid_code_run_replay("wake policy result does not decode"))?;
            Ok(SelfDispatchOutcome::WakePolicyWritten(policy.validate()?))
        }
        "report_blocked" => Ok(SelfDispatchOutcome::ReportBlocked {
            receipt: entity_value(map_get(entries, "receipt")?)?,
        }),

        "agent_definition_put" => {
            let disposition = match str_value(map_get(entries, "disposition")?)? {
                "active" => crate::agent_def::AgentDefinitionPutDisposition::Active,
                "proposed" => crate::agent_def::AgentDefinitionPutDisposition::Proposed,
                _ => {
                    return Err(invalid_code_run_replay(
                        "invalid definition put disposition",
                    ));
                }
            };
            Ok(SelfDispatchOutcome::AgentDefinitionPut(
                super::SelfAgentDefinitionPutResult {
                    id: entity_value(map_get(entries, "id")?)?,
                    disposition,
                },
            ))
        }
        "agent_spawn" => Ok(SelfDispatchOutcome::AgentSpawn(
            super::coordination_codec::decode_spawn(value)?,
        )),
        "task_ask" => Ok(SelfDispatchOutcome::TaskAsk(
            super::coordination_codec::decode_ask(value)?,
        )),
        "task_ask_status" => Ok(SelfDispatchOutcome::TaskAskStatus(
            super::coordination_codec::decode_status(value)?,
        )),
        "memory_search" => session_hooks::decode_memory_search(entries),
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
        "agent_verb" => Ok(SelfDispatchOutcome::AgentVerb(super::AgentVerbAnswer {
            output: serde_json::from_str(str_value(map_get(entries, "output")?)?)
                .map_err(|_| invalid_code_run_replay("invalid agent verb output"))?,
            // An answer recorded with no row set decodes as one, and no
            // caller off this device is released it.
            rows: map_get(entries, "rows")
                .ok()
                .map(|rows| decode_array(rows, entity_value))
                .transpose()?,
            observations: observations::decode_observations(entries)?,
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

/// Writes a refused row's own words onto its recorded `denied` outcome,
/// beside the code; the outcome's decoder reads past them.
pub(super) fn word_refusal(outcome: &mut Value, words: &AgentVerbRefusalWords) {
    if let Value::Map(entries) = outcome {
        entries.push((Value::from("message"), Value::from(words.message.as_str())));
        entries.push((
            Value::from("suggestions"),
            Value::Array(
                words
                    .suggestions
                    .iter()
                    .map(|suggestion| Value::from(suggestion.as_str()))
                    .collect(),
            ),
        ));
    }
}

/// The words [`word_refusal`] kept on a recorded `denied` outcome, with its
/// code; `None` for any other outcome, or a refusal kept without words.
pub(super) fn refusal_words(outcome: &Value) -> Option<AgentVerbRefusalWords> {
    let entries = expect_map(outcome, "dispatch outcome must be a map").ok()?;
    let text = |key: &str| {
        map_get(entries, key)
            .and_then(str_value)
            .map(str::to_owned)
            .ok()
    };
    if text("kind")? != "denied" {
        return None;
    }
    Some(AgentVerbRefusalWords {
        code: text("outcome")?,
        message: text("message")?,
        suggestions: map_get(entries, "suggestions").and_then(str_array).ok()?,
    })
}

/// The key [`keep_row_receipt`] writes a dispatched row's receipt under, on
/// its recorded outcome; the outcome's decoder reads past it.
const ROW_RECEIPT: &str = "row_receipt";

/// Writes the call receipt a dispatched row's reply stated onto its recorded
/// outcome (FIX 8159), so a replay under the same key states it again.
pub(super) fn keep_row_receipt(outcome: &mut Value, receipt: &str) {
    if let Value::Map(entries) = outcome {
        entries.push((Value::from(ROW_RECEIPT), Value::from(receipt)));
    }
}

/// The receipt [`keep_row_receipt`] kept on a recorded outcome; `None` when
/// its row stated none.
pub(super) fn row_receipt(outcome: &Value) -> Option<String> {
    let entries = expect_map(outcome, "dispatch outcome must be a map").ok()?;
    map_get(entries, ROW_RECEIPT)
        .and_then(str_value)
        .map(str::to_owned)
        .ok()
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
    Error::Gate(GateError::GateWriteRejected {
        outcome,
        reason_codes,
    })
}

/// The trap a replayed failed call raises. A call whose reply an erase of
/// its run's actor took (FIX 5718) traps as `ErrorKind::ResponseErased`,
/// never as a write that failed before it ran: its effect ran, and it is
/// never made again.
pub(super) fn replay_failed_trap_error(result: &SelfFailedResult) -> Error {
    if result.error == super::storage::RESPONSE_ERASED {
        return super::storage::response_erased_error("a replayed call's reply");
    }
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
        "agents.spawn" => Ok(SelfEffect::AgentsSpawn),
        "vault.agents.put" => Ok(SelfEffect::AgentsPut),
        "tasks.ask" => Ok(SelfEffect::TasksAsk),
        "tasks.wait" => Ok(SelfEffect::TasksWait),
        "tasks.refuse" => Ok(SelfEffect::TasksRefuse),
        "tasks.consult.result" => Ok(SelfEffect::ConsultResult),
        "self.skills.call" => Ok(SelfEffect::SkillsCall),
        "self.memory.search" => Ok(SelfEffect::MemorySearch),
        "self.memory.write_fixture" => Ok(SelfEffect::MemoryWriteFixture),
        "self.memory.put_claim" => Ok(SelfEffect::MemoryPutClaim),
        "self.memory.supersede_claim" => Ok(SelfEffect::MemorySupersedeClaim),
        "self.memory.put_edge" => Ok(SelfEffect::MemoryPutEdge),
        "ask" => Ok(SelfEffect::Ask),
        "self.fixture.destructive" => Ok(SelfEffect::DestructiveFixture),
        "self.fixture.outbound" => Ok(SelfEffect::OutboundFixture),
        "self.tasks.delegate" => Ok(SelfEffect::TaskDelegate),
        "self.context" => Ok(SelfEffect::Context),
        "self.speak" => Ok(SelfEffect::Speak),
        "self.think" => Ok(SelfEffect::Think),
        "self.express" => Ok(SelfEffect::Express),
        "self.report_blocked" => Ok(SelfEffect::ReportBlocked),
        "self.inference_defaults.read" => Ok(SelfEffect::InferenceDefaultsRead),
        "self.inference_defaults.replace" => Ok(SelfEffect::InferenceDefaultsReplace),
        "dreamer.wake_policy.set" => Ok(SelfEffect::WakePolicyWrite),
        "self.verbs.call" => Ok(SelfEffect::AgentVerb),
        "connector.answer" => Ok(SelfEffect::ConnectorAnswer),
        "vault.worlds.privacy.set" => Ok(SelfEffect::WorldPrivacySet),
        "self.fold" => Ok(SelfEffect::Fold),
        "self.spawn" => Ok(SelfEffect::ReaderSpawn),
        "tasks.update" => Ok(SelfEffect::ReaderReport),
        "tasks.wait_set" => Ok(SelfEffect::TasksWaitSet),
        "summarize" => Ok(SelfEffect::Summarize),
        "self.leader" => Ok(SelfEffect::Leader),
        "self.leader.split" => Ok(SelfEffect::LeaderSplit),
        "self.team" => Ok(SelfEffect::Team),
        "self.workflows.dispatch_bound" => Ok(SelfEffect::WorkflowDispatch),
        other => SelfEffect::repo_from_label(other)
            .ok_or_else(|| invalid_code_run_replay("unknown self effect")),
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
