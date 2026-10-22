//! Strict pinned-key dispatch input decoding.
//! Entry: `decode_agent_dispatch_input`.
//! Dispatch input and key definitions belong to `agent_dispatch::types`.

use super::*;

/// The strict OF-540 team-stamp decode the codec and [`attempt_team_stamp`]
/// share: a serialized stamp whose team reference passes the receipt rule.
pub(super) fn decode_team_stamp(value: &Value) -> Result<super::TeamRunStamp> {
    let json = value
        .as_str()
        .ok_or(Error::Artifact(ArtifactError::InvalidAgentDispatchInput(
            "team must be a serialized team-run stamp",
        )))?;
    let stamp: super::TeamRunStamp = serde_json::from_str(json).map_err(|_| {
        Error::Artifact(ArtifactError::InvalidAgentDispatchInput(
            "team must decode as a team-run stamp",
        ))
    })?;
    stamp.validate()?;
    Ok(stamp)
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
    let mut project_ref = None;
    let mut spawn_intent = None;
    let mut scope = None;
    let mut healer_case = None;
    let mut type_ref = None;
    let mut budget = None;
    let mut launch = None;
    let mut room = None;
    let mut join = None;
    let mut team = None;
    let mut plan = None;
    let mut objectives = None;
    let mut comm = None;
    let mut direct_spawn = None;
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
            KEY_PROJECT_REF => {
                project_ref = Some(
                    EntityId::from_hex(value.as_str().ok_or(Error::Artifact(
                        ArtifactError::InvalidAgentDispatchInput(
                            "project_ref must be a hex EntityId",
                        ),
                    ))?)
                    .map_err(|_| {
                        Error::Artifact(ArtifactError::InvalidAgentDispatchInput(
                            "project_ref must be a hex EntityId",
                        ))
                    })?,
                );
            }
            KEY_SPAWN_INTENT => {
                let digest = value.as_str().ok_or(Error::Artifact(
                    ArtifactError::InvalidAgentDispatchInput("spawn_intent must be a digest"),
                ))?;
                if digest.len() != 64
                    || !digest
                        .bytes()
                        .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
                {
                    return Err(Error::Artifact(ArtifactError::InvalidAgentDispatchInput(
                        "spawn_intent must be lowercase hex",
                    )));
                }
                spawn_intent = Some(digest.to_owned());
            }
            KEY_SCOPE => {
                let json = value.as_str().ok_or(Error::Artifact(
                    ArtifactError::InvalidAgentDispatchInput("scope must be serialized Scope"),
                ))?;
                scope = Some(serde_json::from_str(json).map_err(|_| {
                    Error::Artifact(ArtifactError::InvalidAgentDispatchInput(
                        "scope must decode as Scope",
                    ))
                })?);
            }
            "healer_case" => {
                let Value::Binary(bytes) = value else {
                    return Err(Error::InvalidConfig(
                        "healer case must be named msgpack".into(),
                    ));
                };
                let case = rmp_serde::from_slice(bytes)
                    .map_err(|_| Error::InvalidConfig("invalid healer case".into()))?;
                super::healer_context::validate(&case)?;
                healer_case = Some(case);
            }
            KEY_TASK_TYPE_REF => {
                let wire = value.as_str().ok_or(Error::Artifact(
                    ArtifactError::InvalidAgentDispatchInput(
                        "task_type_ref must be node_id@tree_version",
                    ),
                ))?;
                type_ref = Some(
                    crate::task_type::TaskTypeRef::parse_wire(wire).map_err(|_| {
                        Error::Artifact(ArtifactError::InvalidAgentDispatchInput(
                            "task_type_ref must be node_id@tree_version",
                        ))
                    })?,
                );
            }
            KEY_BUDGET => {
                budget = Some(value.as_u64().ok_or(Error::Artifact(
                    ArtifactError::InvalidAgentDispatchInput("budget must be an integer"),
                ))?);
            }
            KEY_LAUNCH => {
                let json = value.as_str().ok_or(Error::Artifact(
                    ArtifactError::InvalidAgentDispatchInput(
                        "launch must be a serialized launch statement",
                    ),
                ))?;
                launch = Some(serde_json::from_str(json).map_err(|_| {
                    Error::Artifact(ArtifactError::InvalidAgentDispatchInput(
                        "launch must decode as a launch statement",
                    ))
                })?);
            }
            super::types::KEY_ROOM => room = Some(super::room_join::decode_room(value)?),
            super::types::KEY_JOIN => join = Some(super::room_join::decode_join(value)?),
            KEY_DEPTH_REMAINING => {
                depth_remaining = Some(value.as_u64().ok_or(Error::Artifact(
                    ArtifactError::InvalidAgentDispatchInput("depth_remaining must be an integer"),
                ))?);
            }
            // Read by `dispatch_origin_conversation`; checked here so a
            // malformed stamp fails the codec like any other key.
            KEY_ORIGIN_CONVERSATION => {
                if value
                    .as_str()
                    .is_none_or(|hex| EntityId::from_hex(hex).is_err())
                {
                    return Err(Error::Artifact(ArtifactError::InvalidAgentDispatchInput(
                        "origin_conversation must be an entity id",
                    )));
                }
            }
            KEY_TEAM => {
                team = Some(decode_team_stamp(value)?);
            }
            KEY_PLAN => {
                let json = value.as_str().ok_or(Error::Artifact(
                    ArtifactError::InvalidAgentDispatchInput(
                        "plan must be a serialized spawn plan receipt",
                    ),
                ))?;
                let receipt: super::SpawnPlanReceipt =
                    serde_json::from_str(json).map_err(|_| {
                        Error::Artifact(ArtifactError::InvalidAgentDispatchInput(
                            "plan must decode as a spawn plan receipt",
                        ))
                    })?;
                receipt.validate()?;
                plan = Some(receipt);
            }
            KEY_OBJECTIVES => {
                objectives = Some(decode_objectives(value)?);
            }
            KEY_COMM => {
                comm = Some(value.as_str().and_then(super::CommReach::parse).ok_or(
                    Error::Artifact(ArtifactError::InvalidAgentDispatchInput(
                        "comm must be one of parent|subtree|project|vault",
                    )),
                )?);
            }
            KEY_DIRECT_SPAWN => {
                direct_spawn = Some(if value.is_nil() {
                    None
                } else {
                    let json = value.as_str().ok_or(Error::Artifact(
                        ArtifactError::InvalidAgentDispatchInput(
                            "direct_spawn must be a serialized direct spawn receipt",
                        ),
                    ))?;
                    let receipt: super::DirectSpawnReceipt =
                        serde_json::from_str(json).map_err(|_| {
                            Error::Artifact(ArtifactError::InvalidAgentDispatchInput(
                                "direct_spawn must decode as a direct spawn receipt",
                            ))
                        })?;
                    Some(receipt)
                });
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
    let comm = comm.ok_or(Error::Artifact(ArtifactError::InvalidAgentDispatchInput(
        "missing required agent dispatch input key comm",
    )))?;
    let direct_spawn =
        direct_spawn.ok_or(Error::Artifact(ArtifactError::InvalidAgentDispatchInput(
            "missing required agent dispatch input key direct_spawn",
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
        healer_case,
        target,
        definition,
        context_spec,
        context_from,
        depth_remaining,
        project_ref,
        spawn_intent,
        scope,
        // Rows written before OF-543 carry no stamp; they read as the
        // seeded root, the unsure placement, rather than failing decode.
        type_ref: type_ref.unwrap_or_default(),
        budget,
        launch,
        room,
        join,
        team,
        plan,
        objectives,
        comm,
        direct_spawn,
    })
}
