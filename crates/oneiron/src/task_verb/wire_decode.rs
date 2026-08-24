//! Read side of the hand-rolled rmpv wire format for typed TASK bodies.
//!
//! LOCKSTEP PAIRING: every `decode_*` here is the exact inverse of a
//! `*_value` builder in [`super::wire_encode`]. Any wire-format change must
//! touch both files together, or stored rows stop round-tripping.

use rmpv::Value;

use crate::Vault;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::consult_ladder::{
    ConsultLineage, ConsultLineageRelation, ConsultPurpose, EntityDeltaArtifact, EntityDeltaShape,
    LadderTerminalDisposition, LadderTerminalState,
};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::habit::TaskRole;
use crate::registry::ENTITY_TYPE_TASK;

use super::consts::{TASK_VERB_BODY_SCHEMA_VERSIONS, TASK_VERB_BODY_SUBKIND};
use super::consult_payload::{ConsultPayload, ConsultPayloadRef};
use super::consult_result::TaskVerbBody;
use super::terminal_state::{
    ConsultResultSummary, TaskExecutionState, TaskTerminalDisposition, TaskTerminalRecord,
};
use super::verb_kind::{TaskAssignee, TaskKind, TaskTtl};

pub(super) fn task_verb_body(vault: &Vault, task_ref: EntityId) -> Result<Option<TaskVerbBody>> {
    let rtxn = vault.store.env.read_txn()?;
    task_verb_body_in(vault, &rtxn, task_ref)
}

/// Transaction-scoped body read. The custody seal `get_raw` applies is not
/// needed here: a non-TASK type byte returns `None` two lines below, so a
/// SECRET_CUSTODY row can never be decoded through this door.
pub(super) fn task_verb_body_in(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    task_ref: EntityId,
) -> Result<Option<TaskVerbBody>> {
    let Some(raw) = vault.get_raw_in(rtxn, &task_ref)? else {
        return Ok(None);
    };
    let Some(header) = EntityMetadataHeader::parse(&raw) else {
        return Err(Error::CorruptedIndex("tasks.create.header"));
    };
    if header.entity_type != ENTITY_TYPE_TASK {
        return Ok(None);
    }
    let body = &raw[ENTITY_METADATA_HEADER_LEN..];
    if !task_body_has_typed_subkind(body)? {
        return Ok(None);
    }
    let body = decode_task_verb_body(body)?;
    if !TASK_VERB_BODY_SCHEMA_VERSIONS.contains(&body.schema_version)
        || body.role != TaskRole::Task.role_byte()
    {
        return Err(Error::InvalidTaskBody("tasks.create.version"));
    }
    Ok(Some(body))
}

pub(super) fn task_entity_role(vault: &Vault, task_ref: EntityId) -> Result<Option<TaskRole>> {
    let rtxn = vault.store.env.read_txn()?;
    task_entity_role_in(vault, &rtxn, task_ref)
}

/// Transaction-scoped role read, so a board page classifies its rows without
/// opening a second entity transaction per id.
pub(super) fn task_entity_role_in(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    task_ref: EntityId,
) -> Result<Option<TaskRole>> {
    let Some(raw) = vault.get_raw_in(rtxn, &task_ref)? else {
        return Ok(None);
    };
    let Some(header) = EntityMetadataHeader::parse(&raw) else {
        return Err(Error::CorruptedIndex("tasks.role.header"));
    };
    if header.entity_type != ENTITY_TYPE_TASK {
        return Ok(None);
    }
    crate::habit::task_role_from_body_bytes(&raw[ENTITY_METADATA_HEADER_LEN..]).map(Some)
}

pub(super) fn decode_task_verb_body(body: &[u8]) -> Result<TaskVerbBody> {
    let mut cursor = body;
    let value = rmpv::decode::read_value(&mut cursor)
        .map_err(|_| Error::InvalidTaskBody("tasks.create.body"))?;
    if !cursor.is_empty() {
        return Err(Error::InvalidTaskBody("tasks.create.body"));
    }
    let entries = value
        .as_map()
        .ok_or(Error::InvalidTaskBody("tasks.create.body"))?;
    let byte = |key| {
        task_body_field(entries, key)?
            .as_u64()
            .and_then(|value| u8::try_from(value).ok())
            .ok_or(Error::InvalidTaskBody("tasks.create.body"))
    };
    let string = |key| {
        task_body_field(entries, key)?
            .as_str()
            .map(str::to_owned)
            .ok_or(Error::InvalidTaskBody("tasks.create.body"))
    };
    let label = match task_body_field(entries, "label")? {
        Value::Nil => None,
        value => Some(
            value
                .as_str()
                .map(str::to_owned)
                .ok_or(Error::InvalidTaskBody("tasks.create.body"))?,
        ),
    };
    let created_at = task_body_field(entries, "created_at")?
        .as_u64()
        .ok_or(Error::InvalidTaskBody("tasks.create.body"))?;
    Ok(TaskVerbBody {
        role: byte("role")?,
        schema_version: byte("schema_version")?,
        subkind: string("subkind")?,
        // A schema-v1 row carries none of the additive keys; absent decodes to
        // `None`, and `None` is the legacy standard/Dreamer-routed behavior.
        kind: task_body_optional(entries, "kind")?
            .map(|value| {
                value
                    .as_str()
                    .ok_or(Error::InvalidTaskBody("tasks.body.kind"))
                    .and_then(TaskKind::from_token)
            })
            .transpose()?,
        owner_ref: string("owner_ref")?,
        assignee: task_body_optional(entries, "assignee")?
            .map(decode_task_assignee)
            .transpose()?,
        label,
        spec: task_body_field(entries, "spec")?.clone(),
        consult: task_body_optional(entries, "consult")?
            .map(decode_consult_payload)
            .transpose()?,
        ttl: task_body_optional(entries, "ttl")?
            .map(|value| {
                let entries = value
                    .as_map()
                    .ok_or(Error::InvalidTaskBody("tasks.body.ttl"))?;
                task_body_field(entries, "deadline_at")?
                    .as_u64()
                    .map(TaskTtl::at)
                    .ok_or(Error::InvalidTaskBody("tasks.body.ttl"))
            })
            .transpose()?,
        state: task_body_optional(entries, "state")?
            .map(decode_task_execution_state)
            .transpose()?,
        provenance: task_body_field(entries, "provenance")?.clone(),
        created_at,
    })
}

/// Reads one additive body key. Absent (schema-v1 row) and explicitly `Nil`
/// both mean "not set"; a duplicated key is still a corrupt body.
pub(super) fn task_body_optional<'a>(
    entries: &'a [(Value, Value)],
    name: &str,
) -> Result<Option<&'a Value>> {
    let mut values = entries
        .iter()
        .filter(|(key, _)| key.as_str() == Some(name))
        .map(|(_, value)| value);
    let Some(value) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        return Err(Error::InvalidTaskBody("tasks.create.body"));
    }
    Ok(match value {
        Value::Nil => None,
        value => Some(value),
    })
}

pub(super) fn decode_entity_ref(value: &Value, context: &'static str) -> Result<EntityId> {
    value
        .as_str()
        .ok_or(Error::InvalidTaskBody(context))
        .and_then(|hex| EntityId::from_hex(hex).map_err(|_| Error::InvalidTaskBody(context)))
}

pub(super) fn decode_task_assignee(value: &Value) -> Result<TaskAssignee> {
    let entries = value
        .as_map()
        .ok_or(Error::InvalidTaskBody("tasks.body.assignee"))?;
    let kind = task_body_field(entries, "kind")?
        .as_str()
        .ok_or(Error::InvalidTaskBody("tasks.body.assignee"))?;
    match kind {
        "dreamer" => Ok(TaskAssignee::Dreamer),
        "agent_def" => Ok(TaskAssignee::AgentDef {
            agent_def_ref: decode_entity_ref(
                task_body_field(entries, "agent_def_ref")?,
                "tasks.body.assignee",
            )?,
        }),
        "peer" => Ok(TaskAssignee::Peer {
            actor_ref: decode_entity_ref(
                task_body_field(entries, "actor_ref")?,
                "tasks.body.assignee",
            )?,
        }),
        "human" => Ok(TaskAssignee::Human {
            actor_ref: decode_entity_ref(
                task_body_field(entries, "actor_ref")?,
                "tasks.body.assignee",
            )?,
        }),
        _ => Err(Error::InvalidTaskBody("tasks.body.assignee")),
    }
}

fn decode_consult_payload_ref(value: &Value) -> Result<ConsultPayloadRef> {
    let entries = value
        .as_map()
        .ok_or(Error::InvalidTaskBody("tasks.consult.ref"))?;
    let entity_ref =
        decode_entity_ref(task_body_field(entries, "entity_ref")?, "tasks.consult.ref")?;
    match task_body_field(entries, "kind")?.as_str() {
        Some("claim") => Ok(ConsultPayloadRef::Claim(entity_ref)),
        Some("turn") => Ok(ConsultPayloadRef::Turn(entity_ref)),
        _ => Err(Error::InvalidTaskBody("tasks.consult.ref")),
    }
}

pub(super) fn decode_consult_payload(value: &Value) -> Result<ConsultPayload> {
    let entries = value
        .as_map()
        .ok_or(Error::InvalidTaskBody("tasks.body.consult"))?;
    let context_refs = task_body_field(entries, "context_refs")?
        .as_array()
        .ok_or(Error::InvalidTaskBody("tasks.body.consult"))?
        .iter()
        .map(decode_consult_payload_ref)
        .collect::<Result<Vec<_>>>()?;
    let payload = ConsultPayload {
        question_ref: decode_consult_payload_ref(task_body_field(entries, "question_ref")?)?,
        context_refs,
        correlation_ref: decode_entity_ref(
            task_body_field(entries, "correlation_ref")?,
            "tasks.body.consult",
        )?,
        // A ONE-1699 row carries none of these keys; absent decodes to `None`,
        // and `None` is the legacy question shape.
        purpose: task_body_optional(entries, "purpose")?
            .map(|value| {
                value
                    .as_str()
                    .and_then(ConsultPurpose::from_token)
                    .ok_or(Error::InvalidTaskBody("tasks.consult.purpose"))
            })
            .transpose()?,
        entity_delta: task_body_optional(entries, "entity_delta")?
            .map(decode_entity_delta_artifact)
            .transpose()?,
        lineage: task_body_optional(entries, "lineage")?
            .map(decode_consult_lineage)
            .transpose()?,
    };
    payload.validate()?;
    Ok(payload)
}

fn decode_entity_delta_shape(value: &Value) -> Result<EntityDeltaShape> {
    let entries = value
        .as_map()
        .ok_or(Error::InvalidTaskBody("tasks.consult.delta_shape"))?;
    let normalized_paths = task_body_field(entries, "normalized_paths")?
        .as_array()
        .ok_or(Error::InvalidTaskBody("tasks.consult.delta_shape"))?
        .iter()
        .map(|entry| {
            entry
                .as_str()
                .map(str::to_owned)
                .ok_or(Error::InvalidTaskBody("tasks.consult.delta_shape"))
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(EntityDeltaShape {
        operation_kind: task_body_field(entries, "operation_kind")?
            .as_str()
            .map(str::to_owned)
            .ok_or(Error::InvalidTaskBody("tasks.consult.delta_shape"))?,
        target_entity_type: task_body_field(entries, "target_entity_type")?
            .as_u64()
            .and_then(|raw| u8::try_from(raw).ok())
            .ok_or(Error::InvalidTaskBody("tasks.consult.delta_shape"))?,
        normalized_paths,
    })
}

fn decode_entity_delta_artifact(value: &Value) -> Result<EntityDeltaArtifact> {
    let entries = value
        .as_map()
        .ok_or(Error::InvalidTaskBody("tasks.consult.entity_delta"))?;
    let optional_ref = |name| -> Result<Option<EntityId>> {
        task_body_optional(entries, name)?
            .map(|value| decode_entity_ref(value, "tasks.consult.entity_delta"))
            .transpose()
    };
    Ok(EntityDeltaArtifact {
        target_ref: decode_entity_ref(
            task_body_field(entries, "target_ref")?,
            "tasks.consult.entity_delta",
        )?,
        base_state_ref: optional_ref("base_state_ref")?,
        delta_ref: decode_entity_ref(
            task_body_field(entries, "delta_ref")?,
            "tasks.consult.entity_delta",
        )?,
        shape: decode_entity_delta_shape(task_body_field(entries, "shape")?)?,
        proposer_actor_ref: decode_entity_ref(
            task_body_field(entries, "proposer_actor_ref")?,
            "tasks.consult.entity_delta",
        )?,
        owning_actor_ref: decode_entity_ref(
            task_body_field(entries, "owning_actor_ref")?,
            "tasks.consult.entity_delta",
        )?,
        message_thread_ref: optional_ref("message_thread_ref")?,
    })
}

fn decode_consult_lineage(value: &Value) -> Result<ConsultLineage> {
    let entries = value
        .as_map()
        .ok_or(Error::InvalidTaskBody("tasks.consult.lineage"))?;
    Ok(ConsultLineage {
        relation: task_body_field(entries, "relation")?
            .as_str()
            .and_then(ConsultLineageRelation::from_token)
            .ok_or(Error::InvalidTaskBody("tasks.consult.lineage"))?,
        parent_task_ref: decode_entity_ref(
            task_body_field(entries, "parent_task_ref")?,
            "tasks.consult.lineage",
        )?,
    })
}

fn decode_consult_result_summary(value: &Value) -> Result<ConsultResultSummary> {
    let entries = value
        .as_map()
        .ok_or(Error::InvalidTaskBody("tasks.terminal.summary"))?;
    match task_body_field(entries, "outcome")?.as_str() {
        Some("answer") => Ok(ConsultResultSummary::Answer {
            evidence_refs: task_body_field(entries, "evidence_refs")?
                .as_array()
                .ok_or(Error::InvalidTaskBody("tasks.terminal.summary"))?
                .iter()
                .map(decode_consult_payload_ref)
                .collect::<Result<Vec<_>>>()?,
        }),
        Some("abstained") => Ok(ConsultResultSummary::Abstained {
            reason_ref: decode_consult_payload_ref(task_body_field(entries, "reason_ref")?)?,
        }),
        _ => Err(Error::InvalidTaskBody("tasks.terminal.summary")),
    }
}

pub(super) fn decode_task_terminal_record(value: &Value) -> Result<TaskTerminalRecord> {
    let entries = value
        .as_map()
        .ok_or(Error::InvalidTaskBody("tasks.body.terminal"))?;
    Ok(TaskTerminalRecord {
        disposition: task_body_field(entries, "disposition")?
            .as_str()
            .ok_or(Error::InvalidTaskBody("tasks.terminal.disposition"))
            .and_then(TaskTerminalDisposition::from_token)?,
        result_ref: task_body_optional(entries, "result_ref")?
            .map(|value| decode_entity_ref(value, "tasks.body.terminal"))
            .transpose()?,
        summary: task_body_optional(entries, "summary")?
            .map(decode_consult_result_summary)
            .transpose()?,
        finished_at: task_body_field(entries, "finished_at")?
            .as_u64()
            .ok_or(Error::InvalidTaskBody("tasks.body.terminal"))?,
        ladder: task_body_optional(entries, "ladder")?
            .map(|value| {
                value
                    .as_str()
                    .and_then(LadderTerminalDisposition::from_token)
                    .ok_or(Error::InvalidTaskBody("tasks.terminal.ladder"))
            })
            .transpose()?,
        counter_task_ref: task_body_optional(entries, "counter_task_ref")?
            .map(|value| decode_entity_ref(value, "tasks.body.terminal"))
            .transpose()?,
    })
}

fn decode_ladder_terminal_state(value: &Value) -> Result<LadderTerminalState> {
    let entries = value
        .as_map()
        .ok_or(Error::InvalidTaskBody("tasks.body.state"))?;
    Ok(LadderTerminalState {
        disposition: task_body_field(entries, "disposition")?
            .as_str()
            .and_then(LadderTerminalDisposition::from_token)
            .ok_or(Error::InvalidTaskBody("tasks.terminal.ladder"))?,
        result_ref: decode_entity_ref(task_body_field(entries, "result_ref")?, "tasks.body.state")?,
        counter_task_ref: task_body_optional(entries, "counter_task_ref")?
            .map(|value| decode_entity_ref(value, "tasks.body.state"))
            .transpose()?,
        finished_at: task_body_field(entries, "finished_at")?
            .as_u64()
            .ok_or(Error::InvalidTaskBody("tasks.body.state"))?,
    })
}

/// The ladder half a LIVE `interrupted` register may carry.
///
/// Only a disposition that DEFERS to a follow-on settles the ladder without
/// settling the task, so only that one is representable here — the projection
/// writes every other settled ladder as a terminal record. A row pairing
/// `interrupted` with, say, an approved ladder is not a state this engine can
/// reach: it freezes every ladder write door while reading as settled to the
/// projections, so a peer that ships one is refused at the wire rather than
/// persisted and believed.
fn decode_interrupted_ladder_terminal(value: &Value) -> Result<LadderTerminalState> {
    let terminal = decode_ladder_terminal_state(value)?;
    // Well-formedness as well as deferral. The counter link belongs to exactly
    // one disposition, and the ladder transition door enforces that on every
    // terminal it mints — so a deferring terminal that also names a successor
    // is a state no internal door can produce. Admitting one would settle the
    // register with it and have the board project a counter for an escalation.
    if terminal.disposition.defers_to_follow_on() && terminal.is_well_formed() {
        Ok(terminal)
    } else {
        Err(Error::InvalidTaskBody("tasks.terminal.ladder"))
    }
}

fn decode_task_execution_state(value: &Value) -> Result<TaskExecutionState> {
    let entries = value
        .as_map()
        .ok_or(Error::InvalidTaskBody("tasks.body.state"))?;
    match task_body_field(entries, "state")?.as_str() {
        Some("queued") => Ok(TaskExecutionState::Queued),
        Some("working") => Ok(TaskExecutionState::Working {
            started_at: task_body_field(entries, "started_at")?
                .as_u64()
                .ok_or(Error::InvalidTaskBody("tasks.body.state"))?,
        }),
        Some("interrupted") => Ok(TaskExecutionState::Interrupted {
            ladder: task_body_optional(entries, "ladder")?
                .map(decode_interrupted_ladder_terminal)
                .transpose()?,
        }),
        Some("terminal") => Ok(TaskExecutionState::Terminal(decode_task_terminal_record(
            task_body_field(entries, "terminal")?,
        )?)),
        _ => Err(Error::InvalidTaskBody("tasks.body.state")),
    }
}

pub(super) fn task_body_field<'a>(entries: &'a [(Value, Value)], name: &str) -> Result<&'a Value> {
    let mut values = entries
        .iter()
        .filter(|(key, _)| key.as_str() == Some(name))
        .map(|(_, value)| value);
    let value = values
        .next()
        .ok_or(Error::InvalidTaskBody("tasks.create.body"))?;
    if values.next().is_some() {
        return Err(Error::InvalidTaskBody("tasks.create.body"));
    }
    Ok(value)
}

fn task_body_has_typed_subkind(body: &[u8]) -> Result<bool> {
    let mut cursor = body;
    let value = rmpv::decode::read_value(&mut cursor)
        .map_err(|_| Error::InvalidTaskBody("tasks.create.body"))?;
    if !cursor.is_empty() {
        return Err(Error::InvalidTaskBody("tasks.create.body"));
    }
    let Some(entries) = value.as_map() else {
        return Ok(false);
    };
    Ok(entries
        .iter()
        .filter(|(key, _)| key.as_str() == Some("subkind"))
        .count()
        == 1
        && entries
            .iter()
            .filter(|(key, value)| {
                key.as_str() == Some("subkind") && value.as_str() == Some(TASK_VERB_BODY_SUBKIND)
            })
            .count()
            == 1)
}
