//! Core half of `store::agent_manifest`: its store-layer items live in `oneiron_store::agent_manifest` and are
//! re-exported here; the items below stay in the engine.

pub(crate) use oneiron_store::agent_manifest::*;

use crate::entity_id::EntityId;
use crate::error::{ArtifactError, Error, Result};
use crate::store::agent_definition::AgentDefinition;
use std::collections::HashSet;

/// The canonical seeded-roster manifest. Private: the parsed form never
/// escapes this module, and `AgentDefinition` stays the only public model.
#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SystemAgentDefinitionManifest {
    version: u8,
    pub(crate) definitions: Vec<SystemAgentDefinitionSeed>,
}

#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SystemAgentDefinitionSeed {
    pub(crate) entity_id: HexEntityId,
    pub(crate) logical_id: String,
    pub(crate) actor_entity_id: HexEntityId,
    pub(crate) display_name: String,
    pub(crate) enabled: bool,
    /// Field-for-field JSON adapter for the remaining `AgentDefinition` body
    /// keys. Nothing is derived from `logical_id` or `display_name`.
    pub(crate) definition: AgentDefinitionManifestFields,
}

#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AgentDefinitionManifestFields {
    pub(crate) agent_id: String,
    pub(crate) desc: String,
    pub(crate) version: String,
    pub(crate) instructions: Option<String>,
    pub(crate) skills: Vec<ManifestSkillDependency>,
    pub(crate) connectors: Vec<String>,
    pub(crate) code_mode_mcps: Vec<ManifestMcpRef>,
    pub(crate) model_tier: Option<String>,
    pub(crate) dreaming: Option<String>,
    pub(crate) dreaming_model: Option<String>,
    pub(crate) scope: ManifestScope,
    pub(crate) ceiling: String,
    pub(crate) forked_from: Option<HexEntityId>,
    pub(crate) approval_status: String,
    pub(crate) lifecycle_status: String,
    pub(crate) source: String,
    pub(crate) confidence: f32,
    pub(crate) generated: bool,
    pub(crate) human_authored: bool,
    pub(crate) provenance: serde_json::Map<String, serde_json::Value>,
}

/// Parses and fully validates a seeded-roster manifest. MALFORMED IS NOT
/// MISSING: every rejection here aborts open before any row is staged.
pub(crate) fn parse_system_agent_definition_manifest(
    json: &str,
) -> Result<SystemAgentDefinitionManifest> {
    let manifest: SystemAgentDefinitionManifest = serde_json::from_str(json).map_err(|_| {
        Error::Artifact(ArtifactError::InvalidAgentDefBody(
            "system agent manifest is not valid schema-v1 JSON",
        ))
    })?;
    if manifest.version != 1 {
        return Err(Error::Artifact(ArtifactError::InvalidAgentDefBody(
            "system agent manifest schema version must be 1",
        )));
    }
    let mut logical_ids = HashSet::new();
    let mut row_ids = HashSet::new();
    let mut actor_ids = HashSet::new();
    for seed in &manifest.definitions {
        validate_text_field(
            &seed.logical_id,
            AGENT_LOGICAL_ID_MAX_BYTES,
            "manifest logical id must be a non-empty string",
        )?;
        if !seed.logical_id.starts_with(SYSTEM_LOGICAL_ID_PREFIX) {
            return Err(Error::Artifact(ArtifactError::InvalidAgentDefBody(
                "manifest logical id must use the reserved sys. prefix",
            )));
        }
        validate_text_field(
            &seed.display_name,
            AGENT_DISPLAY_NAME_MAX_BYTES,
            "manifest display name must be a non-empty string",
        )?;
        // Schema v1: the gate classifier derives authority by reading the
        // entity stored AT the actor id, so a divergent actor id could never
        // resolve to the seeded definition.
        if seed.actor_entity_id.0 != seed.entity_id.0 {
            return Err(Error::Artifact(ArtifactError::InvalidAgentDefBody(
                "manifest schema v1 requires actor_entity_id to equal entity_id",
            )));
        }
        if !logical_ids.insert(seed.logical_id.as_str()) {
            return Err(Error::Artifact(ArtifactError::InvalidAgentDefBody(
                "manifest logical ids must be unique",
            )));
        }
        if !row_ids.insert(seed.entity_id.0) {
            return Err(Error::Artifact(ArtifactError::InvalidAgentDefBody(
                "manifest row ids must be unique",
            )));
        }
        if !actor_ids.insert(seed.actor_entity_id.0) {
            return Err(Error::Artifact(ArtifactError::InvalidAgentDefBody(
                "manifest actor ids must be unique",
            )));
        }
    }
    Ok(manifest)
}

/// The parsed embedded manifest. Parsed once: decode-path consumers (the
/// legacy `forkedFrom` and dispatch-target compat arms) must not re-parse JSON
/// per row.
pub(crate) fn system_agent_manifest() -> Result<&'static SystemAgentDefinitionManifest> {
    static MANIFEST: std::sync::OnceLock<Option<SystemAgentDefinitionManifest>> =
        std::sync::OnceLock::new();
    MANIFEST
        .get_or_init(|| {
            parse_system_agent_definition_manifest(SYSTEM_AGENT_DEFINITIONS_V1_JSON).ok()
        })
        .as_ref()
        .ok_or(Error::Artifact(ArtifactError::InvalidAgentDefBody(
            "embedded system agent manifest is malformed",
        )))
}

/// The `sys.*` logical-id reservation, enforced at the AGENT_DEF put-decode
/// chokepoint where both the body and its destination row id are in hand: a
/// `sys.`-prefixed logical id is admissible only at its own pinned row id.
pub(crate) fn validate_reserved_logical_id(id: &EntityId, def: &AgentDefinition) -> Result<()> {
    let Some(logical_id) = def.logical_id.as_deref() else {
        return Ok(());
    };
    if !logical_id.starts_with(SYSTEM_LOGICAL_ID_PREFIX) {
        return Ok(());
    }
    if legacy_logical_id_row(logical_id)? == Some(*id) {
        return Ok(());
    }
    Err(Error::Artifact(ArtifactError::InvalidAgentDefBody(
        "sys.* logical ids are reserved for seeded rows",
    )))
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
