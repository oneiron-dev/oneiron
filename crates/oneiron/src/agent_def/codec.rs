//! Pinned-key MessagePack encode and top-level body decode.
//!
//! Entry: `decode_agent_definition`.
//! Value and field decoding lives in `value`; definition types belong to `types`.

use super::decode::{
    decode_connectors, decode_mcp_refs, decode_memory_profile, decode_skill_dependencies,
    encode_mcp_ref, text_value, validate_agent_definition,
};
use super::manifest::system_agent_manifest;
use super::models::{decode_agent_models, decode_compaction_model, encode_agent_models};
use super::refusal::{decode_refusal_dial, encode_refusal_dial};
use super::types::{
    AGENT_DEF_BODY_KEYS, AGENT_DESC_MAX_BYTES, AGENT_DISPLAY_NAME_MAX_BYTES, AGENT_ID_MAX_BYTES,
    AGENT_INSTRUCTIONS_MAX_BYTES, AGENT_LOGICAL_ID_MAX_BYTES, AGENT_MODEL_TIER_MAX_BYTES,
    AGENT_VERSION_MAX_BYTES, AgentCeiling, AgentDefinition, AgentScope, AgentWakeCadence,
    ContextBudgetSplit, DreamingMode, KEY_AGENT_ID, KEY_APPROVAL_STATUS, KEY_CEILING,
    KEY_CODE_MODE_MCPS, KEY_COMPACTION_MODEL, KEY_CONFIDENCE, KEY_CONNECTORS, KEY_DEP_MIN_VERSION,
    KEY_DEP_SKILL_ID, KEY_DESC, KEY_DISPLAY_NAME, KEY_DREAMING, KEY_DREAMING_MODEL, KEY_ENABLED,
    KEY_FORKED_FROM, KEY_GENERATED, KEY_HUMAN_AUTHORED, KEY_INSTRUCTIONS, KEY_LIFECYCLE_STATUS,
    KEY_LOGICAL_ID, KEY_MEMORY_PROFILE, KEY_MODEL_TIER, KEY_MODELS, KEY_PROFILE_BUDGET_SPLIT,
    KEY_PROFILE_COMPACTION, KEY_PROFILE_COMPACTION_BACKEND, KEY_PROFILE_HOT_STEPS,
    KEY_PROFILE_OPTIONAL_MEMORY, KEY_PROFILE_OUTPUT_DECAY, KEY_PROFILE_VERBATIM_PINS,
    KEY_PROFILE_WINDOW_TOKEN_BUDGET, KEY_PROVENANCE, KEY_REFUSAL, KEY_SCOPE, KEY_SKILLS,
    KEY_SOURCE, KEY_SPLIT_CLAIMS, KEY_SPLIT_OTHER, KEY_SPLIT_SUMMARIES, KEY_SPLIT_TURNS,
    KEY_VERSION, KEY_WAKE_CADENCE, KEY_WORLD, MemoryProfile, OUTPUT_DECAY_KEYS, SCOPE_ALL,
    SCOPE_BASE, SCOPE_WORLD,
};
use crate::claim::{ClaimApprovalStatus, ClaimLifecycleStatus, ClaimSource};
use crate::entity_id::EntityId;
use crate::error::{ArtifactError, Error, Result};
use crate::llm::ModelTierRef;
use crate::skill::SkillDependency;
use rmpv::Value;

mod value;
use self::value::decode_agent_definition_value;

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

    if let Some(mode) = def.dreaming {
        entries.push((Value::from(KEY_DREAMING), Value::from(mode.as_str())));
    }
    if let Some(model) = &def.dreaming_model {
        entries.push((Value::from(KEY_DREAMING_MODEL), Value::from(model.as_str())));
    }

    if let Some(cadence) = def.wake_cadence {
        entries.push((Value::from(KEY_WAKE_CADENCE), encode_wake_cadence(cadence)));
    }
    if let Some(dial) = def.refusal {
        entries.push((Value::from(KEY_REFUSAL), encode_refusal_dial(dial)));
    }
    if !def.models.is_empty() {
        entries.push((Value::from(KEY_MODELS), encode_agent_models(&def.models)));
    }
    if let Some(model) = &def.compaction_model {
        entries.push((
            Value::from(KEY_COMPACTION_MODEL),
            Value::from(model.as_str()),
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
    let value = rmpv::decode::read_value(&mut cursor).map_err(|_| {
        Error::Artifact(ArtifactError::InvalidAgentDefBody(
            "body is not valid MessagePack",
        ))
    })?;
    if !cursor.is_empty() {
        return Err(Error::Artifact(ArtifactError::InvalidAgentDefBody(
            "trailing bytes after body map",
        )));
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
        return Err(Error::Artifact(ArtifactError::InvalidAgentDefBody(
            "agentId cannot change on update",
        )));
    }
    if prior.forked_from != updated.forked_from {
        return Err(Error::Artifact(ArtifactError::InvalidAgentDefBody(
            "forkedFrom cannot change on update",
        )));
    }
    if prior.logical_id != updated.logical_id {
        return Err(Error::Artifact(ArtifactError::InvalidAgentDefBody(
            "logicalId cannot change on update",
        )));
    }
    if prior.generated != updated.generated || prior.human_authored != updated.human_authored {
        return Err(Error::Artifact(ArtifactError::InvalidAgentDefBody(
            "authorship flags cannot change on update",
        )));
    }
    if prior.source != updated.source {
        return Err(Error::Artifact(ArtifactError::InvalidAgentDefBody(
            "source cannot change on update",
        )));
    }
    // How far the ceiling may go is the id pin's to say (`id_pin`), on every
    // put road: an update may narrow it, and only the owner's door widens it.
    if prior.version == updated.version {
        return Err(Error::Artifact(ArtifactError::InvalidAgentDefBody(
            "version must change when updating agent definition body",
        )));
    }
    Ok(())
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

/// Encodes a [`MemoryProfile`] sub-map: the [`MEMORY_PROFILE_KEYS`] in
/// pinned order, with `budget_split`, `hot_steps`, `output_decay`, an empty
/// `verbatim_pins` and `optional_memory` elided when absent.
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
    if let Some(hot_steps) = profile.hot_steps {
        entries.push((Value::from(KEY_PROFILE_HOT_STEPS), Value::from(hot_steps)));
    }
    if let Some(decay) = profile.output_decay {
        entries.push((
            Value::from(KEY_PROFILE_OUTPUT_DECAY),
            Value::Map(vec![
                (
                    Value::from(OUTPUT_DECAY_KEYS[0]),
                    Value::from(decay.overview_after_turns),
                ),
                (
                    Value::from(OUTPUT_DECAY_KEYS[1]),
                    Value::from(decay.stub_after_turns),
                ),
            ]),
        ));
    }
    if !profile.verbatim_pins.is_empty() {
        entries.push((
            Value::from(KEY_PROFILE_VERBATIM_PINS),
            Value::Array(
                profile
                    .verbatim_pins
                    .iter()
                    .map(|pin| Value::from(pin.as_str()))
                    .collect(),
            ),
        ));
    }
    if let Some(optional_memory) = &profile.optional_memory {
        entries.push((
            Value::from(KEY_PROFILE_OPTIONAL_MEMORY),
            super::optional_memory::encode_optional_memory_profile(optional_memory),
        ));
    }
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

fn encode_wake_cadence(cadence: AgentWakeCadence) -> Value {
    let (kind, every_turns) = match cadence {
        AgentWakeCadence::Companion { every_turns } => ("companion", every_turns),
        AgentWakeCadence::Leader { every_turns } => ("leader", every_turns),
        AgentWakeCadence::Worker => ("worker", None),
    };
    let mut entries = vec![(Value::from("kind"), Value::from(kind))];
    if let Some(turns) = every_turns {
        entries.push((Value::from("everyTurns"), Value::from(turns)));
    }
    Value::Map(entries)
}
