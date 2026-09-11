//! Pinned-key MessagePack codec plus payload/status decode helpers.

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
    AgentDispatchInput, AgentDispatchStatus, AgentDispatchTarget, KEY_AGENT_DEF, KEY_CONTEXT_FROM,
    KEY_CONTEXT_SPEC, KEY_DEFINITION, KEY_DEPTH_REMAINING, KEY_PRESET, KEY_SCHEMA_VERSION,
    KEY_TARGET, TARGET_CUSTOM, TARGET_SYSTEM,
};
use crate::error::ArtifactError;

/// Encodes a dispatch input into its pinned-key MessagePack `Value` map.
pub fn encode_agent_dispatch_input(input: &AgentDispatchInput) -> Result<Value> {
    let mut entries = vec![(
        Value::from(KEY_SCHEMA_VERSION),
        Value::from(AGENT_DISPATCH_INPUT_SCHEMA_VERSION),
    )];
    match &input.target {
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
            Value::from(u64::from(depth_remaining)),
        ));
    }
    Ok(Value::Map(entries))
}

/// Decodes a pinned-key dispatch input map (strict: map shape, string keys,
/// pinned key set, no duplicates, schema version 1, the target/agent_def/
/// preset cross-field invariant, and a definition snapshot that re-validates
/// structurally).
pub fn decode_agent_dispatch_input(value: &Value) -> Result<AgentDispatchInput> {
    let Value::Map(entries) = value else {
        return Err(Error::Artifact(ArtifactError::InvalidAgentDispatchInput(
            "agent dispatch input must be a MessagePack map",
        )));
    };

    let mut schema_version = None;
    let mut target = None;
    let mut agent_def = None;
    let mut preset = None;
    let mut definition = None;
    let mut context_spec = None;
    let mut context_from = Vec::new();
    let mut depth_remaining = None;
    let mut seen = [false; AGENT_DISPATCH_INPUT_KEYS.len()];

    for (key, value) in entries {
        let Some(key) = key.as_str() else {
            return Err(Error::Artifact(ArtifactError::InvalidAgentDispatchInput(
                "agent dispatch input keys must be strings",
            )));
        };
        let Some(index) = AGENT_DISPATCH_INPUT_KEYS
            .iter()
            .position(|known| *known == key)
        else {
            return Err(Error::Artifact(ArtifactError::InvalidAgentDispatchInput(
                "agent dispatch input key is not in the pinned AGENT_DISPATCH_INPUT_KEYS set",
            )));
        };
        if seen[index] {
            return Err(Error::Artifact(ArtifactError::InvalidAgentDispatchInput(
                "duplicate agent dispatch input key",
            )));
        }
        seen[index] = true;

        match AGENT_DISPATCH_INPUT_KEYS[index] {
            KEY_SCHEMA_VERSION => {
                schema_version = Some(value.as_u64().ok_or(Error::Artifact(
                    ArtifactError::InvalidAgentDispatchInput(
                        "agent dispatch input schema_version must be an integer",
                    ),
                ))?);
            }
            KEY_TARGET => {
                target = Some(match value.as_str() {
                    Some(TARGET_CUSTOM) => TARGET_CUSTOM,
                    Some(TARGET_SYSTEM) => TARGET_SYSTEM,
                    _ => {
                        return Err(Error::Artifact(ArtifactError::InvalidAgentDispatchInput(
                            "agent dispatch target must be one of custom|system",
                        )));
                    }
                });
            }
            KEY_AGENT_DEF => {
                let hex = value.as_str().ok_or(Error::Artifact(
                    ArtifactError::InvalidAgentDispatchInput(
                        "agent_def must be a hex-encoded EntityId string",
                    ),
                ))?;
                agent_def = Some(EntityId::from_hex(hex).map_err(|_| {
                    Error::Artifact(ArtifactError::InvalidAgentDispatchInput(
                        "agent_def must be a hex-encoded EntityId string",
                    ))
                })?);
            }
            KEY_PRESET => {
                let logical_id = value.as_str().ok_or(Error::Artifact(
                    ArtifactError::InvalidAgentDispatchInput(
                        "preset must name a known system agent preset",
                    ),
                ))?;
                preset = Some(
                    crate::agent_def::legacy_logical_id_row(logical_id)
                        .ok()
                        .flatten()
                        .ok_or(Error::Artifact(ArtifactError::InvalidAgentDispatchInput(
                            "preset must name a known system agent preset",
                        )))?,
                );
            }
            KEY_DEFINITION => {
                let Value::Binary(bytes) = value else {
                    return Err(Error::Artifact(ArtifactError::InvalidAgentDispatchInput(
                        "definition must be a binary AGENT_DEF body",
                    )));
                };
                definition = Some(decode_agent_definition(bytes).map_err(|_| {
                    Error::Artifact(ArtifactError::InvalidAgentDispatchInput(
                        "definition must decode as a valid AGENT_DEF body",
                    ))
                })?);
            }
            KEY_CONTEXT_SPEC => {
                let json = value.as_str().ok_or(Error::Artifact(
                    ArtifactError::InvalidAgentDispatchInput(
                        "context_spec must be a serialized descriptor",
                    ),
                ))?;
                let spec: ContextSpec = serde_json::from_str(json).map_err(|_| {
                    Error::Artifact(ArtifactError::InvalidAgentDispatchInput(
                        "context_spec must be a serialized descriptor",
                    ))
                })?;
                validate_context_spec(&spec)?;
                context_spec = Some(spec);
            }
            KEY_CONTEXT_FROM => {
                let Value::Array(refs) = value else {
                    return Err(Error::Artifact(ArtifactError::InvalidAgentDispatchInput(
                        "context_from must be an array of hex EntityId strings",
                    )));
                };
                for entry in refs {
                    let hex = entry.as_str().ok_or(Error::Artifact(
                        ArtifactError::InvalidAgentDispatchInput(
                            "context_from must be an array of hex EntityId strings",
                        ),
                    ))?;
                    context_from.push(EntityId::from_hex(hex).map_err(|_| {
                        Error::Artifact(ArtifactError::InvalidAgentDispatchInput(
                            "context_from must be an array of hex EntityId strings",
                        ))
                    })?);
                }
            }
            KEY_DEPTH_REMAINING => {
                let depth = value.as_u64().ok_or(Error::Artifact(
                    ArtifactError::InvalidAgentDispatchInput("depth_remaining must be an integer"),
                ))?;
                depth_remaining = Some(u8::try_from(depth).map_err(|_| {
                    Error::Artifact(ArtifactError::InvalidAgentDispatchInput(
                        "depth_remaining must fit in a u8",
                    ))
                })?);
            }
            _ => unreachable!("index resolved from AGENT_DISPATCH_INPUT_KEYS"),
        }
    }

    let schema_version =
        schema_version.ok_or(Error::Artifact(ArtifactError::InvalidAgentDispatchInput(
            "missing required agent dispatch input key schema_version",
        )))?;
    if schema_version != AGENT_DISPATCH_INPUT_SCHEMA_VERSION {
        return Err(Error::Artifact(ArtifactError::InvalidAgentDispatchInput(
            "agent dispatch input schema_version must be 1",
        )));
    }
    let target = target.ok_or(Error::Artifact(ArtifactError::InvalidAgentDispatchInput(
        "missing required agent dispatch input key target",
    )))?;
    let definition =
        definition.ok_or(Error::Artifact(ArtifactError::InvalidAgentDispatchInput(
            "missing required agent dispatch input key definition",
        )))?;

    // Cross-field target invariant (mirrors `resolve_scope` in agent_def.rs):
    // the id/preset key is present iff the target discriminant selects it.
    let target = match target {
        TARGET_CUSTOM => {
            if preset.is_some() {
                return Err(Error::Artifact(ArtifactError::InvalidAgentDispatchInput(
                    "preset key is only valid when target is system",
                )));
            }
            AgentDispatchTarget::Custom(agent_def.ok_or(Error::Artifact(
                ArtifactError::InvalidAgentDispatchInput("target custom requires an agent_def key"),
            ))?)
        }
        // Compat-only legacy arm: a persisted pre-1890 `target="system"` row
        // decodes to the pinned seeded row its preset string names. Encode
        // never produces this shape again.
        TARGET_SYSTEM => {
            if agent_def.is_some() {
                return Err(Error::Artifact(ArtifactError::InvalidAgentDispatchInput(
                    "agent_def key is only valid when target is custom",
                )));
            }
            AgentDispatchTarget::Custom(preset.ok_or(Error::Artifact(
                ArtifactError::InvalidAgentDispatchInput("target system requires a preset key"),
            ))?)
        }
        _ => unreachable!("target parsed from the pinned discriminants"),
    };

    Ok(AgentDispatchInput {
        target,
        definition,
        context_spec,
        context_from,
        depth_remaining,
    })
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
#[must_use]
pub fn agent_dispatch_actor(input: &AgentDispatchInput) -> WriteActor {
    match &input.target {
        AgentDispatchTarget::Custom(id) => WriteActor::new(*id, EdgeActorClass::Agent),
    }
}

/// A queue row's decoded dispatch input, or `None` when the row is not an
/// agent dispatch at all.
///
/// Absent / wrong-kind / wrong-attempt-type / undecodable are all "no dispatch
/// lineage", never storage corruption: the queue and codec are `pub`, so any
/// attempt id can be named as a parent (the D13 non-boundary ruling).
pub(super) fn record_dispatch_input(record: &AttemptRecord) -> Option<AgentDispatchInput> {
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
