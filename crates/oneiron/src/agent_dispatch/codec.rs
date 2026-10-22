//! Pinned-key MessagePack codec plus payload/status decode helpers.
//!
//! Entry: `encode_agent_dispatch_input`.
//! Strict input decoding lives in `decode`; wire keys belong to `types`.

use rmpv::Value;

use crate::agent_def::{decode_agent_definition, encode_agent_definition};
use crate::attempt_queue::AttemptRecord;
use crate::context_projection::{ContextSpec, validate_context_spec};
use crate::dreamer_runner::{
    DreamerAttemptPayload, DreamerAttemptStatus, decode_dreamer_attempt_payload,
};
use crate::edge::EdgeActorClass;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::write_envelope::WriteActor;

use super::types::{
    AGENT_DISPATCH_ATTEMPT_TYPE, AGENT_DISPATCH_INPUT_KEYS, AGENT_DISPATCH_INPUT_SCHEMA_VERSION,
    AgentDispatchInput, AgentDispatchStatus, AgentDispatchTarget, KEY_AGENT_DEF, KEY_BUDGET,
    KEY_COMM, KEY_CONTEXT_FROM, KEY_CONTEXT_SPEC, KEY_DEFINITION, KEY_DEPTH_REMAINING,
    KEY_DIRECT_SPAWN, KEY_LAUNCH, KEY_OBJECTIVES, KEY_ORIGIN_CONVERSATION, KEY_PLAN, KEY_PRESET,
    KEY_PROJECT_REF, KEY_SCHEMA_VERSION, KEY_SCOPE, KEY_SPAWN_INTENT, KEY_TARGET,
    KEY_TASK_TYPE_REF, KEY_TEAM, TARGET_CUSTOM, TARGET_SYSTEM,
};
use super::{
    CommReach, DirectSpawnReceipt, SpawnPlanReceipt, TeamRunStamp, healer_context, room_join, types,
};
use crate::error::ArtifactError;

mod decode;
pub use self::decode::decode_agent_dispatch_input;
use self::decode::decode_team_stamp;

fn objectives_invalid() -> Error {
    Error::Artifact(ArtifactError::InvalidAgentDispatchInput(
        "objectives must be one or more distinct non-empty lines",
    ))
}

/// The caller's objectives as the seal will take them: at least one entry,
/// each non-empty with no control characters, no duplicates. The order is
/// the caller's, kept verbatim.
fn validate_objectives(rows: &[String]) -> Result<()> {
    if rows.is_empty() {
        return Err(objectives_invalid());
    }
    let mut seen = std::collections::BTreeSet::new();
    for row in rows {
        if row.is_empty() || row.chars().any(char::is_control) || !seen.insert(row.as_str()) {
            return Err(objectives_invalid());
        }
    }
    Ok(())
}

fn decode_objectives(value: &Value) -> Result<Vec<String>> {
    let values = value.as_array().ok_or_else(objectives_invalid)?;
    if values.is_empty() {
        return Err(objectives_invalid());
    }
    let rows = values
        .iter()
        .map(|value| {
            value
                .as_str()
                .map(str::to_owned)
                .ok_or_else(objectives_invalid)
        })
        .collect::<Result<Vec<_>>>()?;
    validate_objectives(&rows)?;
    Ok(rows)
}

/// Encodes a dispatch input into its pinned-key MessagePack `Value` map.
pub fn encode_agent_dispatch_input(input: &AgentDispatchInput) -> Result<Value> {
    let mut entries = vec![(
        Value::from(KEY_SCHEMA_VERSION),
        Value::from(AGENT_DISPATCH_INPUT_SCHEMA_VERSION),
    )];
    match &input.target {
        AgentDispatchTarget::Workflow(_) => {
            return Err(super::widen_record::invalid(
                "workflow requires its own payload",
            ));
        }
        AgentDispatchTarget::Custom(id) => {
            entries.push((Value::from(KEY_TARGET), Value::from(TARGET_CUSTOM)));
            entries.push((Value::from(KEY_AGENT_DEF), Value::from(id.to_hex())));
        }
    }
    let definition = encode_agent_definition(&input.definition).map_err(|_| {
        Error::Artifact(ArtifactError::InvalidAgentDispatchInput(
            "definition must encode as a valid AGENT_DEF body",
        ))
    })?;
    entries.push((Value::from(KEY_DEFINITION), Value::Binary(definition)));
    // Additive keys are ELIDED when absent, so a dispatch carrying none encodes
    // byte-identically to a pre-ONE-1709 row.
    if let Some(spec) = &input.context_spec {
        let json = serde_json::to_string(spec).map_err(|_| {
            Error::Artifact(ArtifactError::InvalidAgentDispatchInput(
                "context_spec must encode as a descriptor",
            ))
        })?;
        entries.push((Value::from(KEY_CONTEXT_SPEC), Value::from(json.as_str())));
    }
    if !input.context_from.is_empty() {
        entries.push((
            Value::from(KEY_CONTEXT_FROM),
            Value::Array(
                input
                    .context_from
                    .iter()
                    .map(|id| Value::from(id.to_hex()))
                    .collect(),
            ),
        ));
    }
    if let Some(depth_remaining) = input.depth_remaining {
        entries.push((
            Value::from(KEY_DEPTH_REMAINING),
            Value::from(depth_remaining),
        ));
    }
    if let Some(project_ref) = input.project_ref {
        entries.push((
            Value::from(KEY_PROJECT_REF),
            Value::from(project_ref.to_hex()),
        ));
    }
    if let Some(intent) = &input.spawn_intent {
        entries.push((Value::from(KEY_SPAWN_INTENT), Value::from(intent.as_str())));
    }
    if let Some(scope) = &input.scope {
        let json = serde_json::to_string(scope).map_err(|_| {
            Error::Artifact(ArtifactError::InvalidAgentDispatchInput(
                "scope must encode",
            ))
        })?;
        entries.push((Value::from(KEY_SCOPE), Value::from(json)));
    }
    if let Some(case) = &input.healer_case {
        super::healer_context::validate(case)?;
        let bytes = rmp_serde::to_vec_named(case)
            .map_err(|_| Error::InvalidConfig("healer case encode".into()))?;
        entries.push((Value::from("healer_case"), Value::Binary(bytes)));
    }
    // OF-543: the type stamp always rides the payload, root included — a
    // spawn without one is invalid, never untyped.
    if input.type_ref.node_id.is_empty() {
        return Err(Error::Artifact(ArtifactError::InvalidAgentDispatchInput(
            "task_type_ref node_id must not be empty",
        )));
    }
    entries.push((
        Value::from(KEY_TASK_TYPE_REF),
        Value::from(input.type_ref.wire_form().as_str()),
    ));
    if let Some(budget) = input.budget {
        entries.push((Value::from(KEY_BUDGET), Value::from(budget)));
    }
    if let Some(launch) = &input.launch {
        let json = serde_json::to_string(launch).map_err(|_| {
            Error::Artifact(ArtifactError::InvalidAgentDispatchInput(
                "launch statement must encode",
            ))
        })?;
        entries.push((Value::from(KEY_LAUNCH), Value::from(json)));
    }
    super::room_join::encode_room_keys(input, &mut entries)?;
    if let Some(team) = &input.team {
        team.validate()?;
        let json = serde_json::to_string(team).map_err(|_| {
            Error::Artifact(ArtifactError::InvalidAgentDispatchInput(
                "team-run stamp must encode",
            ))
        })?;
        entries.push((Value::from(KEY_TEAM), Value::from(json)));
    }
    if let Some(plan) = &input.plan {
        plan.validate()?;
        let json = serde_json::to_string(plan).map_err(|_| {
            Error::Artifact(ArtifactError::InvalidAgentDispatchInput(
                "spawn plan receipt must encode",
            ))
        })?;
        entries.push((Value::from(KEY_PLAN), Value::from(json)));
    }
    if let Some(rows) = &input.objectives {
        validate_objectives(rows)?;
        entries.push((
            Value::from(KEY_OBJECTIVES),
            Value::Array(rows.iter().map(|row| Value::from(row.as_str())).collect()),
        ));
    }
    // FIX 1380: the comm reach is required, so every dispatch carries one.
    entries.push((Value::from(KEY_COMM), Value::from(input.comm.as_str())));
    // OF-541: a direct spawn's receipt, or Nil. Required, so every dispatch
    // carries the key.
    let direct_spawn = match &input.direct_spawn {
        Some(receipt) => Value::from(serde_json::to_string(receipt).map_err(|_| {
            Error::Artifact(ArtifactError::InvalidAgentDispatchInput(
                "direct spawn receipt must encode",
            ))
        })?),
        None => Value::Nil,
    };
    entries.push((Value::from(KEY_DIRECT_SPAWN), direct_spawn));
    Ok(Value::Map(entries))
}

/// Extracts the dispatched agent's label from a dreamer attempt payload when
/// (and only when) it carries an agent-dispatch input. `None` for non-agent
/// payloads AND for an agent-dispatch payload whose input fails the pinned
/// codec — callers treat the latter as unattributable and fail closed.
#[must_use]
pub fn agent_dispatch_payload_agent_id(payload: &DreamerAttemptPayload) -> Option<String> {
    if payload.attempt_type != AGENT_DISPATCH_ATTEMPT_TYPE {
        return None;
    }
    decode_agent_dispatch_input(&payload.input)
        .ok()
        .map(|input| input.definition.agent_id)
}

/// Derives the dispatched agent's write actor: the AGENT_DEF row id, class
/// `Agent`. This is the identity the gate's live ceiling resolver and
/// `actor_ceilings` rows key on.
pub fn agent_dispatch_actor(input: &AgentDispatchInput) -> Result<WriteActor> {
    Ok(WriteActor::new(
        input.target.agent_definition_ref()?,
        EdgeActorClass::Agent,
    ))
}

/// A queue row's decoded dispatch input, or `None` when the row is not an
/// agent dispatch at all.
///
/// Absent / wrong-kind / wrong-attempt-type / undecodable are all "no dispatch
/// lineage", never storage corruption: the queue and codec are `pub`, so any
/// attempt id can be named as a parent (the D13 non-boundary ruling).
/// The OF-543 type stamp of a queue row's dispatch payload, for the
/// terminal attempt receipt. `None` only for non-dispatch rows.
#[must_use]
pub(crate) fn attempt_task_type_ref(
    record: &AttemptRecord,
) -> Option<crate::task_type::TaskTypeRef> {
    record_dispatch_input(record).map(|input| input.type_ref)
}

/// The OF-540 team-run stamp a queue row's payload froze, for the terminal
/// attempt receipt and the TASK lifecycle bodies: an agent dispatch's, or
/// the one an external TASK try froze at its accept. `None` for any other
/// row and for work outside any team run.
///
/// Strict, unlike the lineage reads: a malformed stamp (or input map) on an
/// agent-dispatch or external-try payload is an error, never a quiet "no
/// team".
pub(crate) fn attempt_team_stamp(record: &AttemptRecord) -> Result<Option<super::TeamRunStamp>> {
    if record.kind == crate::task_verb::TASK_EXTERNAL_ATTEMPT_KIND {
        return Ok(crate::task_verb::decode_external_task_attempt(&record.payload)?.team);
    }
    if record.kind != crate::dreamer_runner::DREAMER_RUNNER_ATTEMPT_KIND {
        return Ok(None);
    }
    // An envelope that does not decode names no attempt type, so it is not
    // known to be an agent dispatch at all.
    let Ok(payload) = decode_dreamer_attempt_payload(&record.payload) else {
        return Ok(None);
    };
    if payload.attempt_type != AGENT_DISPATCH_ATTEMPT_TYPE {
        return Ok(None);
    }
    let Value::Map(entries) = &payload.input else {
        return Err(Error::Artifact(ArtifactError::InvalidAgentDispatchInput(
            "agent dispatch input must be a MessagePack map",
        )));
    };
    entries
        .iter()
        .find(|(key, _)| key.as_str() == Some(KEY_TEAM))
        .map(|(_, value)| decode_team_stamp(value))
        .transpose()
}

pub(crate) fn record_dispatch_input(record: &AttemptRecord) -> Option<AgentDispatchInput> {
    if record.kind != crate::dreamer_runner::DREAMER_RUNNER_ATTEMPT_KIND {
        return None;
    }
    let payload = decode_dreamer_attempt_payload(&record.payload).ok()?;
    if payload.attempt_type != AGENT_DISPATCH_ATTEMPT_TYPE {
        return None;
    }
    decode_agent_dispatch_input(&payload.input).ok()
}

pub(super) fn agent_dispatch_status(status: DreamerAttemptStatus) -> Result<AgentDispatchStatus> {
    if status.payload.attempt_type != AGENT_DISPATCH_ATTEMPT_TYPE {
        return Err(Error::Artifact(ArtifactError::InvalidAgentDispatchInput(
            "existing dedupe row does not carry an agent dispatch payload",
        )));
    }
    let input = decode_agent_dispatch_input(&status.payload.input)?;
    Ok(AgentDispatchStatus {
        attempt: status.attempt,
        input,
    })
}
