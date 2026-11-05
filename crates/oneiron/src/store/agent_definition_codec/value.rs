//! Agent definition value and field decoding.
//! Entry: `decode_agent_definition_value`.
//! Definition types belong to `agent_def::types`; byte entry points stay in `codec`.

use super::*;

pub(super) fn decode_agent_definition_value(value: &Value) -> Result<AgentDefinition> {
    let Value::Map(entries) = value else {
        return Err(Error::Artifact(ArtifactError::InvalidAgentDefBody(
            "body must be a MessagePack map",
        )));
    };

    let mut agent_id = None;
    let mut desc = None;
    let mut version = None;
    let mut instructions = None;
    let mut skills = None;
    let mut connectors = None;
    let mut code_mode_mcps = None;
    let mut model_tier = None;
    let mut scope_discriminant = None;
    let mut world = None;
    let mut ceiling = None;
    let mut forked_from = None;
    let mut approval_status = None;
    let mut lifecycle_status = None;
    let mut source = None;
    let mut confidence = None;
    let mut generated = None;
    let mut human_authored = None;
    let mut provenance = None;
    let mut logical_id = None;
    let mut enabled = None;
    let mut display_name = None;
    let mut memory_profile = None;
    let mut dreaming = None;
    let mut dreaming_model = None;
    let mut wake_cadence = None;
    let mut refusal = None;
    let mut models = None;
    let mut compaction_model = None;
    let mut seen = [false; AGENT_DEF_BODY_KEYS.len()];

    for (key, value) in entries {
        let Some(key) = key.as_str() else {
            return Err(Error::Artifact(ArtifactError::InvalidAgentDefBody(
                "body keys must be strings",
            )));
        };
        let Some(index) = AGENT_DEF_BODY_KEYS.iter().position(|known| *known == key) else {
            return Err(Error::Artifact(ArtifactError::InvalidAgentDefBody(
                "body key is not in the pinned AGENT_DEF_BODY_KEYS set",
            )));
        };
        if seen[index] {
            return Err(Error::Artifact(ArtifactError::InvalidAgentDefBody(
                "duplicate body key",
            )));
        }
        seen[index] = true;

        match AGENT_DEF_BODY_KEYS[index] {
            KEY_AGENT_ID => {
                agent_id = Some(text_value(
                    value,
                    AGENT_ID_MAX_BYTES,
                    "agentId must be a non-empty UTF-8 string",
                )?);
            }
            KEY_DESC => {
                desc = Some(text_value(
                    value,
                    AGENT_DESC_MAX_BYTES,
                    "desc must be a non-empty UTF-8 string",
                )?);
            }
            KEY_VERSION => {
                version = Some(text_value(
                    value,
                    AGENT_VERSION_MAX_BYTES,
                    "version must be a non-empty UTF-8 string",
                )?);
            }
            KEY_INSTRUCTIONS => {
                instructions = Some(text_value(
                    value,
                    AGENT_INSTRUCTIONS_MAX_BYTES,
                    "instructions must be a non-empty UTF-8 string",
                )?);
            }
            KEY_SKILLS => skills = Some(decode_skill_dependencies(value)?),
            KEY_CONNECTORS => connectors = Some(decode_connectors(value)?),
            KEY_CODE_MODE_MCPS => code_mode_mcps = Some(decode_mcp_refs(value)?),
            KEY_MODEL_TIER => {
                let tier = text_value(
                    value,
                    AGENT_MODEL_TIER_MAX_BYTES,
                    "modelTier must be a non-empty UTF-8 string",
                )?;
                model_tier = Some(ModelTierRef(tier));
            }
            KEY_SCOPE => {
                scope_discriminant = Some(value.as_str().map(str::to_owned).ok_or(
                    Error::Artifact(ArtifactError::InvalidAgentDefBody("scope must be a string")),
                )?);
            }
            KEY_WORLD => {
                let hex =
                    value
                        .as_str()
                        .ok_or(Error::Artifact(ArtifactError::InvalidAgentDefBody(
                            "world must be a hex-encoded EntityId string",
                        )))?;
                world = Some(EntityId::from_hex(hex).map_err(|_| {
                    Error::Artifact(ArtifactError::InvalidAgentDefBody(
                        "world must be a hex-encoded EntityId string",
                    ))
                })?);
            }
            KEY_CEILING => {
                ceiling = Some(value.as_str().and_then(AgentCeiling::parse).ok_or(
                    Error::Artifact(ArtifactError::InvalidAgentDefBody(
                        "ceiling must be one of auto|proposed",
                    )),
                )?);
            }
            KEY_FORKED_FROM => {
                let text =
                    value
                        .as_str()
                        .ok_or(Error::Artifact(ArtifactError::InvalidAgentDefBody(
                            "forkedFrom must be a hex-encoded EntityId string",
                        )))?;
                forked_from = Some(decode_forked_from(text)?);
            }
            KEY_APPROVAL_STATUS => {
                approval_status = Some(value.as_str().and_then(ClaimApprovalStatus::parse).ok_or(
                    Error::Artifact(ArtifactError::InvalidAgentDefBody(
                        "approvalStatus must be one of auto|proposed|approved|rejected",
                    )),
                )?);
            }
            KEY_LIFECYCLE_STATUS => {
                lifecycle_status =
                    Some(value.as_str().and_then(ClaimLifecycleStatus::parse).ok_or(
                        Error::Artifact(ArtifactError::InvalidAgentDefBody(
                            "lifecycleStatus must be one of active|superseded|retracted",
                        )),
                    )?);
            }
            KEY_SOURCE => {
                source =
                    Some(
                        value.as_str().and_then(ClaimSource::parse).ok_or(
                            Error::Artifact(ArtifactError::InvalidAgentDefBody(
                                "source must be one of user_stated|observed|inferred|imported|tool_output|generated",
                            )),
                        )?,
                    );
            }
            KEY_CONFIDENCE => {
                confidence = Some(crate::claim::unit_interval_f32(value).ok_or(
                    Error::Artifact(ArtifactError::InvalidAgentDefBody(
                        "confidence must be finite in the unit interval",
                    )),
                )?);
            }
            KEY_GENERATED => {
                let Value::Boolean(flag) = value else {
                    return Err(Error::Artifact(ArtifactError::InvalidAgentDefBody(
                        "generated must be a boolean",
                    )));
                };
                generated = Some(*flag);
            }
            KEY_HUMAN_AUTHORED => {
                let Value::Boolean(flag) = value else {
                    return Err(Error::Artifact(ArtifactError::InvalidAgentDefBody(
                        "humanAuthored must be a boolean",
                    )));
                };
                human_authored = Some(*flag);
            }
            KEY_PROVENANCE => provenance = Some(value.clone()),
            KEY_LOGICAL_ID => {
                logical_id = Some(text_value(
                    value,
                    AGENT_LOGICAL_ID_MAX_BYTES,
                    "logicalId must be a non-empty UTF-8 string",
                )?);
            }
            KEY_ENABLED => {
                let Value::Boolean(flag) = value else {
                    return Err(Error::Artifact(ArtifactError::InvalidAgentDefBody(
                        "enabled must be a boolean",
                    )));
                };
                enabled = Some(*flag);
            }
            KEY_DISPLAY_NAME => {
                display_name = Some(text_value(
                    value,
                    AGENT_DISPLAY_NAME_MAX_BYTES,
                    "displayName must be a non-empty UTF-8 string",
                )?);
            }
            KEY_MEMORY_PROFILE => memory_profile = Some(decode_memory_profile(value)?),
            KEY_DREAMING => {
                dreaming = Some(value.as_str().and_then(DreamingMode::parse).ok_or(
                    Error::Artifact(ArtifactError::InvalidAgentDefBody(
                        "dreaming must be one of own|inherit|off",
                    )),
                )?);
            }
            KEY_DREAMING_MODEL => {
                dreaming_model = Some(ModelTierRef(text_value(
                    value,
                    AGENT_MODEL_TIER_MAX_BYTES,
                    "dreamingModel must be a non-empty UTF-8 string",
                )?));
            }
            KEY_WAKE_CADENCE => wake_cadence = Some(decode_wake_cadence(value)?),
            KEY_REFUSAL => refusal = Some(decode_refusal_dial(value)?),
            KEY_MODELS => models = Some(decode_agent_models(value)?),
            KEY_COMPACTION_MODEL => compaction_model = Some(decode_compaction_model(value)?),
            _ => unreachable!("index resolved from AGENT_DEF_BODY_KEYS"),
        }
    }

    let scope = resolve_scope(scope_discriminant.as_deref(), world)?;

    let definition = AgentDefinition {
        agent_id: agent_id.ok_or(Error::Artifact(ArtifactError::InvalidAgentDefBody(
            "missing required key agentId",
        )))?,
        desc: desc.ok_or(Error::Artifact(ArtifactError::InvalidAgentDefBody(
            "missing required key desc",
        )))?,
        version: version.ok_or(Error::Artifact(ArtifactError::InvalidAgentDefBody(
            "missing required key version",
        )))?,
        instructions,
        skills: skills.ok_or(Error::Artifact(ArtifactError::InvalidAgentDefBody(
            "missing required key skills",
        )))?,
        connectors: connectors.ok_or(Error::Artifact(ArtifactError::InvalidAgentDefBody(
            "missing required key connectors",
        )))?,
        code_mode_mcps: code_mode_mcps.ok_or(Error::Artifact(
            ArtifactError::InvalidAgentDefBody("missing required key codeModeMcps"),
        ))?,
        model_tier,
        scope,
        ceiling: ceiling.unwrap_or(AgentCeiling::Proposed),
        forked_from,
        approval_status: approval_status.ok_or(Error::Artifact(
            ArtifactError::InvalidAgentDefBody("missing required key approvalStatus"),
        ))?,
        lifecycle_status: lifecycle_status.ok_or(Error::Artifact(
            ArtifactError::InvalidAgentDefBody("missing required key lifecycleStatus"),
        ))?,
        source: source.ok_or(Error::Artifact(ArtifactError::InvalidAgentDefBody(
            "missing required key source",
        )))?,
        confidence: confidence.ok_or(Error::Artifact(ArtifactError::InvalidAgentDefBody(
            "missing required key confidence",
        )))?,
        generated: generated.ok_or(Error::Artifact(ArtifactError::InvalidAgentDefBody(
            "missing required key generated",
        )))?,
        human_authored: human_authored.ok_or(Error::Artifact(
            ArtifactError::InvalidAgentDefBody("missing required key humanAuthored"),
        ))?,
        provenance: provenance.ok_or(Error::Artifact(ArtifactError::InvalidAgentDefBody(
            "missing required key provenance",
        )))?,
        logical_id,
        // Missing decodes as enabled: pre-1890 bodies carried no key and were
        // dispatchable.
        enabled: enabled.unwrap_or(true),
        display_name,
        memory_profile,
        dreaming,
        dreaming_model,
        wake_cadence,
        refusal,
        models: models.unwrap_or_default(),
        compaction_model,
    };
    validate_agent_definition(&definition)?;
    Ok(definition)
}

/// Decodes the `forkedFrom` wire string: always 32 lower-case hex on encode,
/// plus a compat-only arm for the six legacy `sys.*` preset strings persisted
/// before ONE-1890 (crash-recovery carve-out: one mapping, zero machinery).
/// Unknown strings stay typed decode errors.
pub(super) fn decode_forked_from(text: &str) -> Result<EntityId> {
    if let Ok(id) = EntityId::from_hex(text) {
        return Ok(id);
    }
    legacy_logical_id_row(text)?.ok_or(Error::Artifact(ArtifactError::InvalidAgentDefBody(
        "forkedFrom must be a hex-encoded EntityId string",
    )))
}

/// Resolves the `scope`/`world` two-key cross-field invariant: the `world` key
/// is present iff the discriminant is `world`. Unknown-key rejection cannot
/// catch this case because `world` is itself a pinned key, so it needs its own
/// arm.
pub(super) fn resolve_scope(
    discriminant: Option<&str>,
    world: Option<EntityId>,
) -> Result<AgentScope> {
    let discriminant = discriminant.ok_or(Error::Artifact(ArtifactError::InvalidAgentDefBody(
        "missing required key scope",
    )))?;
    match discriminant {
        SCOPE_ALL => {
            if world.is_some() {
                return Err(Error::Artifact(ArtifactError::InvalidAgentDefBody(
                    "world key is only valid when scope is world",
                )));
            }
            Ok(AgentScope::All)
        }
        SCOPE_BASE => {
            if world.is_some() {
                return Err(Error::Artifact(ArtifactError::InvalidAgentDefBody(
                    "world key is only valid when scope is world",
                )));
            }
            Ok(AgentScope::Base)
        }
        SCOPE_WORLD => {
            let world = world.ok_or(Error::Artifact(ArtifactError::InvalidAgentDefBody(
                "scope world requires a world key",
            )))?;
            Ok(AgentScope::World(world))
        }
        _ => Err(Error::Artifact(ArtifactError::InvalidAgentDefBody(
            "scope must be one of all|base|world",
        ))),
    }
}

pub(super) fn decode_wake_cadence(value: &Value) -> Result<AgentWakeCadence> {
    let Value::Map(entries) = value else {
        return Err(Error::Artifact(ArtifactError::InvalidAgentDefBody(
            "wakeCadence must be a map",
        )));
    };
    let (mut kind, mut every_turns) = (None, None);
    for (key, value) in entries {
        match key.as_str() {
            Some("kind") if kind.is_none() => {
                kind = Some(value.as_str().ok_or(Error::Artifact(
                    ArtifactError::InvalidAgentDefBody("wakeCadence kind must be a string"),
                ))?);
            }
            Some("everyTurns") if every_turns.is_none() => {
                every_turns = Some(value.as_u64().filter(|n| *n > 0).ok_or(Error::Artifact(
                    ArtifactError::InvalidAgentDefBody("wakeCadence everyTurns must be positive"),
                ))?);
            }
            _ => {
                return Err(Error::Artifact(ArtifactError::InvalidAgentDefBody(
                    "unknown or duplicate wakeCadence key",
                )));
            }
        }
    }
    match kind {
        Some("companion") => Ok(AgentWakeCadence::Companion { every_turns }),
        Some("leader") => Ok(AgentWakeCadence::Leader { every_turns }),
        Some("worker") if every_turns.is_none() => Ok(AgentWakeCadence::Worker),
        _ => Err(Error::Artifact(ArtifactError::InvalidAgentDefBody(
            "invalid wakeCadence kind or interval",
        ))),
    }
}
