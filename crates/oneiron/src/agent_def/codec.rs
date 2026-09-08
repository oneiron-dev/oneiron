//! Pinned-key MessagePack encode and top-level body decode.

use super::decode::{
    decode_connectors, decode_mcp_refs, decode_memory_profile, decode_skill_dependencies,
    encode_mcp_ref, text_value, validate_agent_definition,
};
use super::manifest::system_agent_manifest;
use super::types::{
    AGENT_DEF_BODY_KEYS, AGENT_DESC_MAX_BYTES, AGENT_DISPLAY_NAME_MAX_BYTES, AGENT_ID_MAX_BYTES,
    AGENT_INSTRUCTIONS_MAX_BYTES, AGENT_LOGICAL_ID_MAX_BYTES, AGENT_MODEL_TIER_MAX_BYTES,
    AGENT_VERSION_MAX_BYTES, AgentCeiling, AgentDefinition, AgentScope, ContextBudgetSplit,
    KEY_AGENT_ID, KEY_APPROVAL_STATUS, KEY_CEILING, KEY_CODE_MODE_MCPS, KEY_CONFIDENCE,
    KEY_CONNECTORS, KEY_DEP_MIN_VERSION, KEY_DEP_SKILL_ID, KEY_DESC, KEY_DISPLAY_NAME, KEY_ENABLED,
    KEY_FORKED_FROM, KEY_GENERATED, KEY_HUMAN_AUTHORED, KEY_INSTRUCTIONS, KEY_LIFECYCLE_STATUS,
    KEY_LOGICAL_ID, KEY_MEMORY_PROFILE, KEY_MODEL_TIER, KEY_PROFILE_BUDGET_SPLIT,
    KEY_PROFILE_COMPACTION, KEY_PROFILE_COMPACTION_BACKEND, KEY_PROFILE_WINDOW_TOKEN_BUDGET,
    KEY_PROVENANCE, KEY_SCOPE, KEY_SKILLS, KEY_SOURCE, KEY_SPLIT_CLAIMS, KEY_SPLIT_OTHER,
    KEY_SPLIT_SUMMARIES, KEY_SPLIT_TURNS, KEY_VERSION, KEY_WORLD, MemoryProfile, SCOPE_ALL,
    SCOPE_BASE, SCOPE_WORLD,
};
use crate::claim::{ClaimApprovalStatus, ClaimLifecycleStatus, ClaimSource};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::llm::ModelTierRef;
use crate::skill::SkillDependency;
use rmpv::Value;

/// Encodes a validated `AgentDefinition` into its pinned-key MessagePack body.
pub fn encode_agent_definition(def: &AgentDefinition) -> Result<Vec<u8>> {
    validate_agent_definition(def)?;
    let mut entries = vec![
        (
            Value::from(KEY_AGENT_ID),
            Value::from(def.agent_id.as_str()),
        ),
        (Value::from(KEY_DESC), Value::from(def.desc.as_str())),
        (Value::from(KEY_VERSION), Value::from(def.version.as_str())),
    ];
    if let Some(instructions) = &def.instructions {
        entries.push((
            Value::from(KEY_INSTRUCTIONS),
            Value::from(instructions.as_str()),
        ));
    }
    entries.push((
        Value::from(KEY_SKILLS),
        Value::Array(def.skills.iter().map(encode_skill_dependency).collect()),
    ));
    entries.push((
        Value::from(KEY_CONNECTORS),
        Value::Array(
            def.connectors
                .iter()
                .map(|connector| Value::from(connector.as_str()))
                .collect(),
        ),
    ));
    entries.push((
        Value::from(KEY_CODE_MODE_MCPS),
        Value::Array(def.code_mode_mcps.iter().map(encode_mcp_ref).collect()),
    ));
    if let Some(model_tier) = &def.model_tier {
        entries.push((
            Value::from(KEY_MODEL_TIER),
            Value::from(model_tier.as_str()),
        ));
    }
    entries.push((
        Value::from(KEY_SCOPE),
        Value::from(def.scope.discriminant()),
    ));
    if let AgentScope::World(world) = &def.scope {
        entries.push((Value::from(KEY_WORLD), Value::from(world.to_hex())));
    }
    if def.ceiling == AgentCeiling::Auto {
        entries.push((Value::from(KEY_CEILING), Value::from(def.ceiling.as_str())));
    }
    if let Some(parent) = &def.forked_from {
        entries.push((Value::from(KEY_FORKED_FROM), Value::from(parent.to_hex())));
    }
    entries.push((
        Value::from(KEY_APPROVAL_STATUS),
        Value::from(def.approval_status.as_str()),
    ));
    entries.push((
        Value::from(KEY_LIFECYCLE_STATUS),
        Value::from(def.lifecycle_status.as_str()),
    ));
    entries.push((Value::from(KEY_SOURCE), Value::from(def.source.as_str())));
    entries.push((Value::from(KEY_CONFIDENCE), Value::F32(def.confidence)));
    entries.push((Value::from(KEY_GENERATED), Value::Boolean(def.generated)));
    entries.push((
        Value::from(KEY_HUMAN_AUTHORED),
        Value::Boolean(def.human_authored),
    ));
    entries.push((Value::from(KEY_PROVENANCE), def.provenance.clone()));
    if let Some(logical_id) = &def.logical_id {
        entries.push((
            Value::from(KEY_LOGICAL_ID),
            Value::from(logical_id.as_str()),
        ));
    }
    // The one always-encode key: a decode-default-only `enabled` would make a
    // seeded `enabled: true` row encode differently across vaults.
    entries.push((Value::from(KEY_ENABLED), Value::Boolean(def.enabled)));
    if let Some(display_name) = &def.display_name {
        entries.push((
            Value::from(KEY_DISPLAY_NAME),
            Value::from(display_name.as_str()),
        ));
    }
    if let Some(profile) = &def.memory_profile {
        entries.push((
            Value::from(KEY_MEMORY_PROFILE),
            encode_memory_profile(profile),
        ));
    }

    let value = Value::Map(entries);
    let mut out = Vec::new();
    rmpv::encode::write_value(&mut out, &value)
        .map_err(|_| Error::InvariantViolation("AGENT_DEF body MessagePack encode failed"))?;
    Ok(out)
}

/// Decodes a pinned-key MessagePack body into an `AgentDefinition`.
pub fn decode_agent_definition(bytes: &[u8]) -> Result<AgentDefinition> {
    let mut cursor = bytes;
    let value = rmpv::decode::read_value(&mut cursor)
        .map_err(|_| Error::InvalidAgentDefBody("body is not valid MessagePack"))?;
    if !cursor.is_empty() {
        return Err(Error::InvalidAgentDefBody("trailing bytes after body map"));
    }
    decode_agent_definition_value(&value)
}

/// Body-only structural validation for the public raw-put seam.
///
/// The authoring-side no-widen arm that used to live here is GONE with the
/// preset table (ONE-1890): a body alone cannot answer "what is my parent's
/// ceiling?" now that lineage is a row id. It relocated to the `batch.rs`
/// AGENT_DEF create arm, which loads the parent ROW, and the gate's live clamp
/// resolves the same bound at evaluation time (GATE-HALF).
pub(crate) fn validate_agent_definition_bytes(bytes: &[u8]) -> Result<()> {
    decode_agent_definition(bytes).map(|_| ())
}

pub(crate) fn validate_agent_definition_update(
    prior: &AgentDefinition,
    updated: &AgentDefinition,
) -> Result<()> {
    validate_agent_definition(updated)?;
    if prior == updated {
        return Ok(());
    }
    if prior.agent_id != updated.agent_id {
        return Err(Error::InvalidAgentDefBody(
            "agentId cannot change on update",
        ));
    }
    if prior.forked_from != updated.forked_from {
        return Err(Error::InvalidAgentDefBody(
            "forkedFrom cannot change on update",
        ));
    }
    if prior.logical_id != updated.logical_id {
        return Err(Error::InvalidAgentDefBody(
            "logicalId cannot change on update",
        ));
    }
    if prior.generated != updated.generated || prior.human_authored != updated.human_authored {
        return Err(Error::InvalidAgentDefBody(
            "authorship flags cannot change on update",
        ));
    }
    if prior.source != updated.source {
        return Err(Error::InvalidAgentDefBody("source cannot change on update"));
    }
    if prior.version == updated.version {
        return Err(Error::InvalidAgentDefBody(
            "version must change when updating agent definition body",
        ));
    }
    Ok(())
}

fn decode_agent_definition_value(value: &Value) -> Result<AgentDefinition> {
    let Value::Map(entries) = value else {
        return Err(Error::InvalidAgentDefBody("body must be a MessagePack map"));
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
    let mut seen = [false; AGENT_DEF_BODY_KEYS.len()];

    for (key, value) in entries {
        let Some(key) = key.as_str() else {
            return Err(Error::InvalidAgentDefBody("body keys must be strings"));
        };
        let Some(index) = AGENT_DEF_BODY_KEYS.iter().position(|known| *known == key) else {
            return Err(Error::InvalidAgentDefBody(
                "body key is not in the pinned AGENT_DEF_BODY_KEYS set",
            ));
        };
        if seen[index] {
            return Err(Error::InvalidAgentDefBody("duplicate body key"));
        }
        seen[index] = true;

        match AGENT_DEF_BODY_KEYS[index] {
            KEY_AGENT_ID => {
                agent_id = Some(text_value(
                    value,
                    AGENT_ID_MAX_BYTES,
                    "agentId must be a non-empty UTF-8 string at most 256 bytes",
                )?);
            }
            KEY_DESC => {
                desc = Some(text_value(
                    value,
                    AGENT_DESC_MAX_BYTES,
                    "desc must be a non-empty UTF-8 string at most 4096 bytes",
                )?);
            }
            KEY_VERSION => {
                version = Some(text_value(
                    value,
                    AGENT_VERSION_MAX_BYTES,
                    "version must be a non-empty UTF-8 string at most 128 bytes",
                )?);
            }
            KEY_INSTRUCTIONS => {
                instructions = Some(text_value(
                    value,
                    AGENT_INSTRUCTIONS_MAX_BYTES,
                    "instructions must be a non-empty UTF-8 string at most 16384 bytes",
                )?);
            }
            KEY_SKILLS => skills = Some(decode_skill_dependencies(value)?),
            KEY_CONNECTORS => connectors = Some(decode_connectors(value)?),
            KEY_CODE_MODE_MCPS => code_mode_mcps = Some(decode_mcp_refs(value)?),
            KEY_MODEL_TIER => {
                let tier = text_value(
                    value,
                    AGENT_MODEL_TIER_MAX_BYTES,
                    "modelTier must be a non-empty UTF-8 string at most 256 bytes",
                )?;
                model_tier = Some(ModelTierRef(tier));
            }
            KEY_SCOPE => {
                scope_discriminant = Some(
                    value
                        .as_str()
                        .map(str::to_owned)
                        .ok_or(Error::InvalidAgentDefBody("scope must be a string"))?,
                );
            }
            KEY_WORLD => {
                let hex = value.as_str().ok_or(Error::InvalidAgentDefBody(
                    "world must be a hex-encoded EntityId string",
                ))?;
                world = Some(EntityId::from_hex(hex).map_err(|_| {
                    Error::InvalidAgentDefBody("world must be a hex-encoded EntityId string")
                })?);
            }
            KEY_CEILING => {
                ceiling = Some(value.as_str().and_then(AgentCeiling::parse).ok_or(
                    Error::InvalidAgentDefBody("ceiling must be one of auto|proposed"),
                )?);
            }
            KEY_FORKED_FROM => {
                let text = value.as_str().ok_or(Error::InvalidAgentDefBody(
                    "forkedFrom must be a hex-encoded EntityId string",
                ))?;
                forked_from = Some(decode_forked_from(text)?);
            }
            KEY_APPROVAL_STATUS => {
                approval_status = Some(value.as_str().and_then(ClaimApprovalStatus::parse).ok_or(
                    Error::InvalidAgentDefBody(
                        "approvalStatus must be one of auto|proposed|approved|rejected",
                    ),
                )?);
            }
            KEY_LIFECYCLE_STATUS => {
                lifecycle_status =
                    Some(value.as_str().and_then(ClaimLifecycleStatus::parse).ok_or(
                        Error::InvalidAgentDefBody(
                            "lifecycleStatus must be one of active|superseded|retracted",
                        ),
                    )?);
            }
            KEY_SOURCE => {
                source =
                    Some(
                        value.as_str().and_then(ClaimSource::parse).ok_or(
                            Error::InvalidAgentDefBody(
                                "source must be one of user_stated|observed|inferred|imported|tool_output|generated",
                            ),
                        )?,
                    );
            }
            KEY_CONFIDENCE => {
                confidence = Some(crate::claim::unit_interval_f32(value).ok_or(
                    Error::InvalidAgentDefBody("confidence must be finite in the unit interval"),
                )?);
            }
            KEY_GENERATED => {
                let Value::Boolean(flag) = value else {
                    return Err(Error::InvalidAgentDefBody("generated must be a boolean"));
                };
                generated = Some(*flag);
            }
            KEY_HUMAN_AUTHORED => {
                let Value::Boolean(flag) = value else {
                    return Err(Error::InvalidAgentDefBody(
                        "humanAuthored must be a boolean",
                    ));
                };
                human_authored = Some(*flag);
            }
            KEY_PROVENANCE => provenance = Some(value.clone()),
            KEY_LOGICAL_ID => {
                logical_id = Some(text_value(
                    value,
                    AGENT_LOGICAL_ID_MAX_BYTES,
                    "logicalId must be a non-empty UTF-8 string at most 256 bytes",
                )?);
            }
            KEY_ENABLED => {
                let Value::Boolean(flag) = value else {
                    return Err(Error::InvalidAgentDefBody("enabled must be a boolean"));
                };
                enabled = Some(*flag);
            }
            KEY_DISPLAY_NAME => {
                display_name = Some(text_value(
                    value,
                    AGENT_DISPLAY_NAME_MAX_BYTES,
                    "displayName must be a non-empty UTF-8 string at most 256 bytes",
                )?);
            }
            KEY_MEMORY_PROFILE => memory_profile = Some(decode_memory_profile(value)?),
            _ => unreachable!("index resolved from AGENT_DEF_BODY_KEYS"),
        }
    }

    let scope = resolve_scope(scope_discriminant.as_deref(), world)?;

    let definition = AgentDefinition {
        agent_id: agent_id.ok_or(Error::InvalidAgentDefBody("missing required key agentId"))?,
        desc: desc.ok_or(Error::InvalidAgentDefBody("missing required key desc"))?,
        version: version.ok_or(Error::InvalidAgentDefBody("missing required key version"))?,
        instructions,
        skills: skills.ok_or(Error::InvalidAgentDefBody("missing required key skills"))?,
        connectors: connectors.ok_or(Error::InvalidAgentDefBody(
            "missing required key connectors",
        ))?,
        code_mode_mcps: code_mode_mcps.ok_or(Error::InvalidAgentDefBody(
            "missing required key codeModeMcps",
        ))?,
        model_tier,
        scope,
        ceiling: ceiling.unwrap_or(AgentCeiling::Proposed),
        forked_from,
        approval_status: approval_status.ok_or(Error::InvalidAgentDefBody(
            "missing required key approvalStatus",
        ))?,
        lifecycle_status: lifecycle_status.ok_or(Error::InvalidAgentDefBody(
            "missing required key lifecycleStatus",
        ))?,
        source: source.ok_or(Error::InvalidAgentDefBody("missing required key source"))?,
        confidence: confidence.ok_or(Error::InvalidAgentDefBody(
            "missing required key confidence",
        ))?,
        generated: generated.ok_or(Error::InvalidAgentDefBody("missing required key generated"))?,
        human_authored: human_authored.ok_or(Error::InvalidAgentDefBody(
            "missing required key humanAuthored",
        ))?,
        provenance: provenance.ok_or(Error::InvalidAgentDefBody(
            "missing required key provenance",
        ))?,
        logical_id,
        // Missing decodes as enabled: pre-1890 bodies carried no key and were
        // dispatchable.
        enabled: enabled.unwrap_or(true),
        display_name,
        memory_profile,
    };
    validate_agent_definition(&definition)?;
    Ok(definition)
}

/// Decodes the `forkedFrom` wire string: always 32 lower-case hex on encode,
/// plus a compat-only arm for the six legacy `sys.*` preset strings persisted
/// before ONE-1890 (crash-recovery carve-out: one mapping, zero machinery).
/// Unknown strings stay typed decode errors.
fn decode_forked_from(text: &str) -> Result<EntityId> {
    if let Ok(id) = EntityId::from_hex(text) {
        return Ok(id);
    }
    legacy_logical_id_row(text)?.ok_or(Error::InvalidAgentDefBody(
        "forkedFrom must be a hex-encoded EntityId string",
    ))
}

/// The pinned row id a legacy `sys.*` wire string maps to, or `None` when the
/// string names no seeded row. The ONE map both legacy decoders share.
pub(crate) fn legacy_logical_id_row(logical_id: &str) -> Result<Option<EntityId>> {
    Ok(system_agent_manifest()?
        .definitions
        .iter()
        .find(|seed| seed.logical_id == logical_id)
        .map(|seed| seed.entity_id.0))
}

/// Resolves the `scope`/`world` two-key cross-field invariant: the `world` key
/// is present iff the discriminant is `world`. Unknown-key rejection cannot
/// catch this case because `world` is itself a pinned key, so it needs its own
/// arm.
fn resolve_scope(discriminant: Option<&str>, world: Option<EntityId>) -> Result<AgentScope> {
    let discriminant =
        discriminant.ok_or(Error::InvalidAgentDefBody("missing required key scope"))?;
    match discriminant {
        SCOPE_ALL => {
            if world.is_some() {
                return Err(Error::InvalidAgentDefBody(
                    "world key is only valid when scope is world",
                ));
            }
            Ok(AgentScope::All)
        }
        SCOPE_BASE => {
            if world.is_some() {
                return Err(Error::InvalidAgentDefBody(
                    "world key is only valid when scope is world",
                ));
            }
            Ok(AgentScope::Base)
        }
        SCOPE_WORLD => {
            let world = world.ok_or(Error::InvalidAgentDefBody(
                "scope world requires a world key",
            ))?;
            Ok(AgentScope::World(world))
        }
        _ => Err(Error::InvalidAgentDefBody(
            "scope must be one of all|base|world",
        )),
    }
}

fn encode_skill_dependency(dependency: &SkillDependency) -> Value {
    Value::Map(vec![
        (
            Value::from(KEY_DEP_SKILL_ID),
            Value::from(dependency.skill_id.as_str()),
        ),
        (
            Value::from(KEY_DEP_MIN_VERSION),
            dependency
                .min_version
                .as_deref()
                .map_or(Value::Nil, Value::from),
        ),
    ])
}

/// Encodes a [`MemoryProfile`] sub-map: the four [`MEMORY_PROFILE_KEYS`] in
/// pinned order, with `budget_split` elided when absent.
fn encode_memory_profile(profile: &MemoryProfile) -> Value {
    let mut entries = vec![(
        Value::from(KEY_PROFILE_WINDOW_TOKEN_BUDGET),
        Value::from(profile.window_token_budget),
    )];
    if let Some(split) = profile.budget_split {
        entries.push((
            Value::from(KEY_PROFILE_BUDGET_SPLIT),
            encode_context_budget_split(split),
        ));
    }
    entries.push((
        Value::from(KEY_PROFILE_COMPACTION_BACKEND),
        Value::from(profile.compaction_backend.as_str()),
    ));
    entries.push((
        Value::from(KEY_PROFILE_COMPACTION),
        Value::from(profile.compaction.as_str()),
    ));
    Value::Map(entries)
}

fn encode_context_budget_split(split: ContextBudgetSplit) -> Value {
    Value::Map(vec![
        (Value::from(KEY_SPLIT_CLAIMS), Value::F32(split.claims)),
        (Value::from(KEY_SPLIT_TURNS), Value::F32(split.turns)),
        (
            Value::from(KEY_SPLIT_SUMMARIES),
            Value::F32(split.summaries),
        ),
        (Value::from(KEY_SPLIT_OTHER), Value::F32(split.other)),
    ])
}
