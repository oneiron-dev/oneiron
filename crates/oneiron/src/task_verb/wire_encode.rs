//! Write side of the hand-rolled rmpv wire format for typed TASK bodies.
//!
//! LOCKSTEP PAIRING: every `*_value` builder here has an exact inverse
//! `decode_*` in [`super::wire_decode`]. Any wire-format change must touch
//! both files together, or stored rows stop round-tripping.

use rmpv::Value;

use crate::consult_ladder::{
    ConsultLineage, EntityDeltaArtifact, EntityDeltaShape, LadderTerminalState,
};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};

use super::consult_payload::{ConsultPayload, ConsultPayloadRef};
use super::consult_result::TaskVerbBody;
use super::terminal_state::{ConsultResultSummary, TaskExecutionState, TaskTerminalRecord};
use super::verb_kind::TaskAssignee;

/// Serializes one rmpv value. Writing msgpack into a `Vec` cannot fail, so
/// this is the infallible canonical-bytes primitive the terminal-register
/// tiebreak and the body encoder both build on.
pub(super) fn canonical_bytes(value: &Value) -> Vec<u8> {
    let mut encoded = Vec::new();
    rmpv::encode::write_value(&mut encoded, value)
        .expect("writing msgpack into a Vec is infallible");
    encoded
}

pub(super) fn entity_ref_value(entity_ref: EntityId) -> Value {
    Value::from(entity_ref.to_hex())
}

pub(super) fn task_assignee_value(assignee: TaskAssignee) -> Value {
    let mut entries = vec![(Value::from("kind"), Value::from(assignee.as_str()))];
    match assignee {
        TaskAssignee::Dreamer => {}
        TaskAssignee::AgentDef { agent_def_ref } => entries.push((
            Value::from("agent_def_ref"),
            entity_ref_value(agent_def_ref),
        )),
        TaskAssignee::Peer { actor_ref } | TaskAssignee::Human { actor_ref } => {
            entries.push((Value::from("actor_ref"), entity_ref_value(actor_ref)));
        }
    }
    Value::Map(entries)
}

fn consult_payload_ref_value(payload_ref: ConsultPayloadRef) -> Value {
    Value::Map(vec![
        (
            Value::from("kind"),
            Value::from(match payload_ref {
                ConsultPayloadRef::Claim(_) => "claim",
                ConsultPayloadRef::Turn(_) => "turn",
            }),
        ),
        (
            Value::from("entity_ref"),
            entity_ref_value(payload_ref.entity_ref()),
        ),
    ])
}

pub(super) fn consult_payload_value(payload: &ConsultPayload) -> Value {
    Value::Map(vec![
        (
            Value::from("question_ref"),
            consult_payload_ref_value(payload.question_ref),
        ),
        (
            Value::from("context_refs"),
            Value::Array(
                payload
                    .context_refs
                    .iter()
                    .copied()
                    .map(consult_payload_ref_value)
                    .collect(),
            ),
        ),
        (
            Value::from("correlation_ref"),
            entity_ref_value(payload.correlation_ref),
        ),
        // ONE-1888 additions. Absent (nil) is the ONE-1699 question shape.
        (
            Value::from("purpose"),
            payload
                .purpose
                .map_or(Value::Nil, |purpose| Value::from(purpose.as_str())),
        ),
        (
            Value::from("entity_delta"),
            payload
                .entity_delta
                .as_ref()
                .map_or(Value::Nil, entity_delta_artifact_value),
        ),
        (
            Value::from("lineage"),
            payload.lineage.map_or(Value::Nil, consult_lineage_value),
        ),
    ])
}

fn entity_delta_shape_value(shape: &EntityDeltaShape) -> Value {
    Value::Map(vec![
        (
            Value::from("operation_kind"),
            Value::from(shape.operation_kind.as_str()),
        ),
        (
            Value::from("target_entity_type"),
            Value::from(shape.target_entity_type),
        ),
        (
            Value::from("normalized_paths"),
            Value::Array(
                shape
                    .normalized_paths
                    .iter()
                    .map(|path| Value::from(path.as_str()))
                    .collect(),
            ),
        ),
    ])
}

fn entity_delta_artifact_value(delta: &EntityDeltaArtifact) -> Value {
    Value::Map(vec![
        (
            Value::from("target_ref"),
            entity_ref_value(delta.target_ref),
        ),
        (
            Value::from("base_state_ref"),
            delta.base_state_ref.map_or(Value::Nil, entity_ref_value),
        ),
        (Value::from("delta_ref"), entity_ref_value(delta.delta_ref)),
        (Value::from("shape"), entity_delta_shape_value(&delta.shape)),
        (
            Value::from("proposer_actor_ref"),
            entity_ref_value(delta.proposer_actor_ref),
        ),
        (
            Value::from("owning_actor_ref"),
            entity_ref_value(delta.owning_actor_ref),
        ),
        (
            Value::from("message_thread_ref"),
            delta
                .message_thread_ref
                .map_or(Value::Nil, entity_ref_value),
        ),
    ])
}

fn consult_lineage_value(lineage: ConsultLineage) -> Value {
    Value::Map(vec![
        (
            Value::from("relation"),
            Value::from(lineage.relation.as_str()),
        ),
        (
            Value::from("parent_task_ref"),
            entity_ref_value(lineage.parent_task_ref),
        ),
    ])
}

fn consult_result_summary_value(summary: &ConsultResultSummary) -> Value {
    match summary {
        ConsultResultSummary::Answer { evidence_refs } => Value::Map(vec![
            (Value::from("outcome"), Value::from("answer")),
            (
                Value::from("evidence_refs"),
                Value::Array(
                    evidence_refs
                        .iter()
                        .copied()
                        .map(consult_payload_ref_value)
                        .collect(),
                ),
            ),
        ]),
        ConsultResultSummary::Abstained { reason_ref } => Value::Map(vec![
            (Value::from("outcome"), Value::from("abstained")),
            (
                Value::from("reason_ref"),
                consult_payload_ref_value(*reason_ref),
            ),
        ]),
    }
}

pub(super) fn task_terminal_record_value(record: &TaskTerminalRecord) -> Value {
    Value::Map(vec![
        (
            Value::from("disposition"),
            Value::from(record.disposition.as_str()),
        ),
        (
            Value::from("result_ref"),
            record.result_ref.map_or(Value::Nil, entity_ref_value),
        ),
        (
            Value::from("summary"),
            record
                .summary
                .as_ref()
                .map_or(Value::Nil, consult_result_summary_value),
        ),
        (Value::from("finished_at"), Value::from(record.finished_at)),
        (
            Value::from("ladder"),
            record
                .ladder
                .map_or(Value::Nil, |ladder| Value::from(ladder.as_str())),
        ),
        (
            Value::from("counter_task_ref"),
            record.counter_task_ref.map_or(Value::Nil, entity_ref_value),
        ),
    ])
}

/// The settled LADDER state a deferring terminal leaves on a live TASK row.
/// `result_ref` is non-optional here by construction — a ladder terminal
/// without a durable result is unrepresentable.
fn ladder_terminal_state_value(state: &LadderTerminalState) -> Value {
    Value::Map(vec![
        (
            Value::from("disposition"),
            Value::from(state.disposition.as_str()),
        ),
        (
            Value::from("result_ref"),
            entity_ref_value(state.result_ref),
        ),
        (
            Value::from("counter_task_ref"),
            state.counter_task_ref.map_or(Value::Nil, entity_ref_value),
        ),
        (Value::from("finished_at"), Value::from(state.finished_at)),
    ])
}

fn task_execution_state_value(state: &TaskExecutionState) -> Value {
    match state {
        TaskExecutionState::Queued => {
            Value::Map(vec![(Value::from("state"), Value::from("queued"))])
        }
        TaskExecutionState::Working { started_at } => Value::Map(vec![
            (Value::from("state"), Value::from("working")),
            (Value::from("started_at"), Value::from(*started_at)),
        ]),
        TaskExecutionState::Interrupted { ladder } => Value::Map(vec![
            (Value::from("state"), Value::from("interrupted")),
            (
                Value::from("ladder"),
                ladder.map_or(Value::Nil, |state| ladder_terminal_state_value(&state)),
            ),
        ]),
        TaskExecutionState::Terminal(record) => Value::Map(vec![
            (Value::from("state"), Value::from("terminal")),
            (Value::from("terminal"), task_terminal_record_value(record)),
        ]),
    }
}

pub(super) fn encode_task_verb_body(body: TaskVerbBody) -> Vec<u8> {
    let value = Value::Map(vec![
        (Value::from("role"), Value::from(body.role)),
        (
            Value::from("schema_version"),
            Value::from(body.schema_version),
        ),
        (Value::from("subkind"), Value::from(body.subkind)),
        (
            Value::from("kind"),
            body.kind
                .map_or(Value::Nil, |kind| Value::from(kind.as_str())),
        ),
        (Value::from("owner_ref"), Value::from(body.owner_ref)),
        (
            Value::from("assignee"),
            body.assignee.map_or(Value::Nil, task_assignee_value),
        ),
        (
            Value::from("label"),
            body.label.map_or(Value::Nil, Value::from),
        ),
        (Value::from("spec"), body.spec),
        (
            Value::from("consult"),
            body.consult
                .as_ref()
                .map_or(Value::Nil, consult_payload_value),
        ),
        (
            Value::from("ttl"),
            body.ttl.map_or(Value::Nil, |ttl| {
                Value::Map(vec![(
                    Value::from("deadline_at"),
                    Value::from(ttl.deadline_at),
                )])
            }),
        ),
        (
            Value::from("state"),
            body.state
                .as_ref()
                .map_or(Value::Nil, task_execution_state_value),
        ),
        (Value::from("provenance"), body.provenance),
        (Value::from("created_at"), Value::from(body.created_at)),
    ]);
    canonical_bytes(&value)
}

pub(super) fn encode_task_realization_input(spec: &Value) -> Result<Vec<u8>> {
    let mut payload = Vec::new();
    rmpv::encode::write_value(&mut payload, spec)
        .map_err(|_| Error::InvalidTaskBody("tasks.create.spec"))?;
    Ok(payload)
}
