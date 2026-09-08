//! Embedded sys.* roster manifest, legacy compat, and seeding/reconciliation.

use super::codec::{decode_agent_definition, encode_agent_definition, legacy_logical_id_row};
use super::decode::validate_text_field;
use super::types::{
    AGENT_DISPLAY_NAME_MAX_BYTES, AGENT_LOGICAL_ID_MAX_BYTES, AgentCeiling, AgentDefinition,
    AgentScope, McpRef, SYSTEM_AGENT_DEFINITIONS_V1_JSON, SYSTEM_LOGICAL_ID_PREFIX,
};
use crate::batch::{BatchOp, ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader, apply_ops};
use crate::claim::{ClaimApprovalStatus, ClaimLifecycleStatus, ClaimSource};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::llm::ModelTierRef;
use crate::registry::ENTITY_TYPE_AGENT_DEF;
use crate::skill::SkillDependency;
use crate::temporal::TimeRange;
use rmpv::Value;
use std::collections::HashSet;

/// Legacy per-vault system-agent toggle key prefix in `vault_meta` (full key =
/// prefix + logical-id bytes). Pre-ONE-1890 state, consumed ONCE into the
/// seeded row's `enabled` field and deleted in the same transaction; the
/// literal survives only here, in the seeder's legacy-consumption path.
const LEGACY_SYSTEM_AGENT_TOGGLE_KEY_PREFIX: &[u8] = b"agent_def:system_toggle:v1:";

/// The two pre-1890 reserved-actor census rows in `vault_meta`, deleted with
/// the census they served — both readers died with the compiled roster. Like
/// the toggle prefix above, these literals survive only here, in the seeder's
/// legacy-consumption path.
const PRE_1890_ACTOR_CENSUS_KEYS: [&[u8]; 2] = [
    b"agent_def:reserved_actor_census:v2",
    b"agent_def:default_reserved_actor_census:v1",
];

/// `occurred`/`learned_at` for every seeded row, pinned so the six baseline
/// rows are byte-identical across vaults (idiom: `DEFAULT_POLICY_MANIFEST_TIMESTAMP`).
const SEEDED_AGENT_DEFINITION_TIMESTAMP: u64 = 0;

/// A 32-character lower-case hex `EntityId`, the manifest's only id spelling.
#[derive(Debug)]
pub(super) struct HexEntityId(pub(super) EntityId);

impl<'de> serde::Deserialize<'de> for HexEntityId {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        let text = <&str as serde::Deserialize>::deserialize(deserializer)?;
        if text.len() != 32
            || !text
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(serde::de::Error::custom(
                "entity id must be 32 lower-case hex characters",
            ));
        }
        EntityId::from_hex(text)
            .map(HexEntityId)
            .map_err(|_| serde::de::Error::custom("entity id must be a valid EntityId"))
    }
}

/// The canonical seeded-roster manifest. Private: the parsed form never
/// escapes this module, and `AgentDefinition` stays the only public model.
#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SystemAgentDefinitionManifest {
    version: u8,
    pub(super) definitions: Vec<SystemAgentDefinitionSeed>,
}

#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SystemAgentDefinitionSeed {
    pub(super) entity_id: HexEntityId,
    pub(super) logical_id: String,
    pub(super) actor_entity_id: HexEntityId,
    pub(super) display_name: String,
    pub(super) enabled: bool,
    /// Field-for-field JSON adapter for the remaining `AgentDefinition` body
    /// keys. Nothing is derived from `logical_id` or `display_name`.
    definition: AgentDefinitionManifestFields,
}

#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct AgentDefinitionManifestFields {
    agent_id: String,
    desc: String,
    version: String,
    instructions: Option<String>,
    skills: Vec<ManifestSkillDependency>,
    connectors: Vec<String>,
    code_mode_mcps: Vec<ManifestMcpRef>,
    model_tier: Option<String>,
    scope: ManifestScope,
    ceiling: String,
    forked_from: Option<HexEntityId>,
    approval_status: String,
    lifecycle_status: String,
    source: String,
    confidence: f32,
    generated: bool,
    human_authored: bool,
    provenance: serde_json::Map<String, serde_json::Value>,
}

#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ManifestSkillDependency {
    skill_id: String,
    min_version: Option<String>,
}

#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ManifestMcpRef {
    key: String,
    min_version: Option<String>,
}

#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields, tag = "kind", rename_all = "snake_case")]
enum ManifestScope {
    All,
    Base,
    World { world: HexEntityId },
}

impl AgentDefinitionManifestFields {
    fn to_definition(
        &self,
        logical_id: String,
        enabled: bool,
        display_name: String,
    ) -> Result<AgentDefinition> {
        let ceiling = AgentCeiling::parse(&self.ceiling).ok_or(Error::InvalidAgentDefBody(
            "manifest ceiling must be one of auto|proposed",
        ))?;
        let approval_status =
            ClaimApprovalStatus::parse(&self.approval_status).ok_or(Error::InvalidAgentDefBody(
                "manifest approvalStatus must be a known claim approval status",
            ))?;
        let lifecycle_status = ClaimLifecycleStatus::parse(&self.lifecycle_status).ok_or(
            Error::InvalidAgentDefBody("manifest lifecycleStatus must be a known claim lifecycle"),
        )?;
        let source = ClaimSource::parse(&self.source).ok_or(Error::InvalidAgentDefBody(
            "manifest source must be a known claim source",
        ))?;
        Ok(AgentDefinition::new(
            self.agent_id.clone(),
            self.desc.clone(),
            self.version.clone(),
            self.instructions.clone(),
            self.skills
                .iter()
                .map(|dependency| SkillDependency {
                    skill_id: dependency.skill_id.clone(),
                    min_version: dependency.min_version.clone(),
                })
                .collect(),
            self.connectors.clone(),
            self.code_mode_mcps
                .iter()
                .map(|mcp| McpRef {
                    key: mcp.key.clone(),
                    min_version: mcp.min_version.clone(),
                })
                .collect(),
            self.model_tier.clone().map(ModelTierRef),
            match &self.scope {
                ManifestScope::All => AgentScope::All,
                ManifestScope::Base => AgentScope::Base,
                ManifestScope::World { world } => AgentScope::World(world.0),
            },
            ceiling,
            self.forked_from.as_ref().map(|parent| parent.0),
            approval_status,
            lifecycle_status,
            source,
            self.confidence,
            self.generated,
            self.human_authored,
            json_object_to_msgpack(&self.provenance),
            Some(logical_id),
            enabled,
            Some(display_name),
        ))
    }
}

fn json_object_to_msgpack(object: &serde_json::Map<String, serde_json::Value>) -> Value {
    Value::Map(
        object
            .iter()
            .map(|(key, value)| (Value::from(key.as_str()), json_to_msgpack(value)))
            .collect(),
    )
}

fn json_to_msgpack(value: &serde_json::Value) -> Value {
    match value {
        serde_json::Value::Null => Value::Nil,
        serde_json::Value::Bool(flag) => Value::Boolean(*flag),
        serde_json::Value::Number(number) => number
            .as_i64()
            .map(Value::from)
            .or_else(|| number.as_u64().map(Value::from))
            .or_else(|| number.as_f64().map(Value::from))
            .unwrap_or(Value::Nil),
        serde_json::Value::String(text) => Value::from(text.as_str()),
        serde_json::Value::Array(values) => {
            Value::Array(values.iter().map(json_to_msgpack).collect())
        }
        serde_json::Value::Object(object) => json_object_to_msgpack(object),
    }
}

/// Parses and fully validates a seeded-roster manifest. MALFORMED IS NOT
/// MISSING: every rejection here aborts open before any row is staged.
pub(crate) fn parse_system_agent_definition_manifest(
    json: &str,
) -> Result<SystemAgentDefinitionManifest> {
    let manifest: SystemAgentDefinitionManifest = serde_json::from_str(json).map_err(|_| {
        Error::InvalidAgentDefBody("system agent manifest is not valid schema-v1 JSON")
    })?;
    if manifest.version != 1 {
        return Err(Error::InvalidAgentDefBody(
            "system agent manifest schema version must be 1",
        ));
    }
    let mut logical_ids = HashSet::new();
    let mut row_ids = HashSet::new();
    let mut actor_ids = HashSet::new();
    for seed in &manifest.definitions {
        validate_text_field(
            &seed.logical_id,
            AGENT_LOGICAL_ID_MAX_BYTES,
            "manifest logical id must be a non-empty string at most 256 bytes",
        )?;
        if !seed.logical_id.starts_with(SYSTEM_LOGICAL_ID_PREFIX) {
            return Err(Error::InvalidAgentDefBody(
                "manifest logical id must use the reserved sys. prefix",
            ));
        }
        validate_text_field(
            &seed.display_name,
            AGENT_DISPLAY_NAME_MAX_BYTES,
            "manifest display name must be a non-empty string at most 256 bytes",
        )?;
        // Schema v1: the gate classifier derives authority by reading the
        // entity stored AT the actor id, so a divergent actor id could never
        // resolve to the seeded definition.
        if seed.actor_entity_id.0 != seed.entity_id.0 {
            return Err(Error::InvalidAgentDefBody(
                "manifest schema v1 requires actor_entity_id to equal entity_id",
            ));
        }
        if !logical_ids.insert(seed.logical_id.as_str()) {
            return Err(Error::InvalidAgentDefBody(
                "manifest logical ids must be unique",
            ));
        }
        if !row_ids.insert(seed.entity_id.0) {
            return Err(Error::InvalidAgentDefBody(
                "manifest row ids must be unique",
            ));
        }
        if !actor_ids.insert(seed.actor_entity_id.0) {
            return Err(Error::InvalidAgentDefBody(
                "manifest actor ids must be unique",
            ));
        }
    }
    Ok(manifest)
}

/// The parsed embedded manifest. Parsed once: decode-path consumers (the
/// legacy `forkedFrom` and dispatch-target compat arms) must not re-parse JSON
/// per row.
pub(super) fn system_agent_manifest() -> Result<&'static SystemAgentDefinitionManifest> {
    static MANIFEST: std::sync::OnceLock<Option<SystemAgentDefinitionManifest>> =
        std::sync::OnceLock::new();
    MANIFEST
        .get_or_init(|| {
            parse_system_agent_definition_manifest(SYSTEM_AGENT_DEFINITIONS_V1_JSON).ok()
        })
        .as_ref()
        .ok_or(Error::InvalidAgentDefBody(
            "embedded system agent manifest is malformed",
        ))
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
    Err(Error::InvalidAgentDefBody(
        "sys.* logical ids are reserved for seeded rows",
    ))
}

/// Seeds/reconciles the canonical roster inside the caller's write
/// transaction. Takes the open-path input quartet rather than a `&Vault`,
/// because it runs before any handle exists.
pub(crate) fn seed_system_agent_definitions(
    store: &crate::store::Store,
    config: &crate::config::VaultConfig,
    analyzer: &crate::analyzer::MultilingualAnalyzer,
    wtxn: &mut heed::RwTxn<'_>,
    text_index_trusted: bool,
) -> Result<()> {
    let manifest = parse_system_agent_definition_manifest(SYSTEM_AGENT_DEFINITIONS_V1_JSON)?;
    reconcile_system_agent_definitions_in(
        store,
        config,
        analyzer,
        wtxn,
        text_index_trusted,
        &manifest,
    )
}

/// Convergent reconciliation over the stored rows: create what is missing,
/// never overwrite what exists, fail closed on a foreign occupant. LMDB write
/// serialization plus deterministic ids makes concurrent opens converge — the
/// later writer observes the first writer's committed row and writes nothing.
pub(crate) fn reconcile_system_agent_definitions_in(
    store: &crate::store::Store,
    config: &crate::config::VaultConfig,
    analyzer: &crate::analyzer::MultilingualAnalyzer,
    wtxn: &mut heed::RwTxn<'_>,
    text_index_trusted: bool,
    manifest: &SystemAgentDefinitionManifest,
) -> Result<()> {
    for seed in &manifest.definitions {
        let id = seed.entity_id.0;
        let legacy_enabled = take_legacy_system_agent_toggle(store, wtxn, &seed.logical_id)?;
        match store.entities.get(wtxn, id.as_bytes())? {
            Some(raw) => {
                let header = EntityMetadataHeader::parse(&raw)
                    .ok_or(Error::SeededAgentDefinitionConflict { id })?;
                if header.entity_type != ENTITY_TYPE_AGENT_DEF {
                    return Err(Error::SeededAgentDefinitionConflict { id });
                }
                let stored = decode_agent_definition(&raw[ENTITY_METADATA_HEADER_LEN..])
                    .map_err(|_| Error::SeededAgentDefinitionConflict { id })?;
                // A valid occupant whose logical id is missing or different is
                // a legacy foreign row: conflict, never adoption, never
                // overwrite. A match leaves every stored byte alone —
                // including user edits, `display_name`, and `enabled = false`.
                if stored.logical_id.as_deref() != Some(seed.logical_id.as_str()) {
                    return Err(Error::SeededAgentDefinitionConflict { id });
                }
            }
            None => {
                let definition = seed.definition_row(legacy_enabled)?;
                let data = encode_agent_definition(&definition)?;
                apply_ops(
                    store,
                    config,
                    analyzer,
                    wtxn,
                    vec![BatchOp::Put {
                        id,
                        entity_type: ENTITY_TYPE_AGENT_DEF,
                        occurred: TimeRange {
                            start: SEEDED_AGENT_DEFINITION_TIMESTAMP,
                            end: SEEDED_AGENT_DEFINITION_TIMESTAMP,
                        },
                        learned_at: SEEDED_AGENT_DEFINITION_TIMESTAMP,
                        data,
                        allow_maintenance: false,
                        allow_reserved_predicate: false,
                        hub_sync_imported: false,
                    }],
                    text_index_trusted,
                    false,
                    true,
                )?;
            }
        }
    }
    for key in PRE_1890_ACTOR_CENSUS_KEYS {
        store.vault_meta.delete(wtxn, key)?;
    }
    Ok(())
}

/// Reads and DELETES the pre-1890 per-vault toggle for `logical_id`, in the
/// caller's transaction. `Some(false)`/`Some(true)` initialize a newly created
/// row's `enabled`; an absent or unreadable byte leaves the manifest default.
fn take_legacy_system_agent_toggle(
    store: &crate::store::Store,
    wtxn: &mut heed::RwTxn<'_>,
    logical_id: &str,
) -> Result<Option<bool>> {
    let mut key = LEGACY_SYSTEM_AGENT_TOGGLE_KEY_PREFIX.to_vec();
    key.extend_from_slice(logical_id.as_bytes());
    let stored = match store.vault_meta.get(wtxn, key.as_slice())? {
        Some(raw) if *raw == [0x01] => Some(true),
        Some(raw) if *raw == [0x00] => Some(false),
        Some(_) | None => None,
    };
    store.vault_meta.delete(wtxn, key.as_slice())?;
    Ok(stored)
}

impl SystemAgentDefinitionSeed {
    /// The row this seed materializes, with `enabled` initialized from the
    /// one-time legacy toggle when one was present.
    fn definition_row(&self, legacy_enabled: Option<bool>) -> Result<AgentDefinition> {
        self.definition.to_definition(
            self.logical_id.clone(),
            legacy_enabled.unwrap_or(self.enabled),
            self.display_name.clone(),
        )
    }
}
