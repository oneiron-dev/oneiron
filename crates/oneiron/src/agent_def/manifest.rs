//! Embedded sys.* roster manifest, legacy compat, and seeding/reconciliation.

use super::codec::{decode_agent_definition, encode_agent_definition};
use super::types::{
    AgentCeiling, AgentDefinition, AgentScope, DreamingMode, McpRef,
    SYSTEM_AGENT_DEFINITIONS_V1_JSON,
};
use crate::batch::{BatchOp, ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader, apply_ops};
use crate::claim::{ClaimApprovalStatus, ClaimLifecycleStatus, ClaimSource};
use crate::entity_id::EntityId;
use crate::error::{ArtifactError, Error, Result};
use crate::llm::ModelTierRef;
use crate::ports::EntityStoreRead;
use crate::registry::ENTITY_TYPE_AGENT_DEF;
use crate::side_table::{self, Raw, SideTable};
use crate::skill::SkillDependency;
use crate::temporal::TimeRange;
use rmpv::Value;

pub(crate) use crate::store::agent_manifest::validate_reserved_logical_id;
use crate::store::agent_manifest::{AgentDefinitionManifestFields, ManifestScope};
pub(super) use crate::store::agent_manifest::{
    SystemAgentDefinitionManifest, SystemAgentDefinitionSeed,
    parse_system_agent_definition_manifest, system_agent_manifest,
};

/// Legacy per-vault system-agent toggle in `vault_meta` (key = logical id).
/// Pre-ONE-1890 state, consumed ONCE into the seeded row's `enabled` field and
/// deleted in the same transaction; the table survives only here, in the
/// seeder's legacy-consumption path.
const SYSTEM_TOGGLE_LEGACY: SideTable<String, Vec<u8>, Raw> =
    SideTable::new(&side_table::AGENT_DEF_SYSTEM_TOGGLE_LEGACY);

/// The two pre-1890 reserved-actor census rows in `vault_meta`, deleted with
/// the census they served — both readers died with the compiled roster. Like
/// the toggle table above, these tables survive only here, in the seeder's
/// legacy-consumption path.
const RESERVED_ACTOR_CENSUS_V2: SideTable<(), (), Raw> =
    SideTable::new(&side_table::AGENT_DEF_RESERVED_ACTOR_CENSUS_V2);
const DEFAULT_RESERVED_ACTOR_CENSUS_V1: SideTable<(), (), Raw> =
    SideTable::new(&side_table::AGENT_DEF_DEFAULT_RESERVED_ACTOR_CENSUS_V1);

/// `occurred`/`learned_at` for every seeded row, pinned so the six baseline
/// rows are byte-identical across vaults (idiom: `DEFAULT_POLICY_MANIFEST_TIMESTAMP`).
pub(crate) const SEEDED_AGENT_DEFINITION_TIMESTAMP: u64 = 0;

impl AgentDefinitionManifestFields {
    fn to_definition(
        &self,
        logical_id: String,
        enabled: bool,
        display_name: String,
    ) -> Result<AgentDefinition> {
        let ceiling = AgentCeiling::parse(&self.ceiling).ok_or(Error::Artifact(
            ArtifactError::InvalidAgentDefBody("manifest ceiling must be one of auto|proposed"),
        ))?;
        let approval_status = ClaimApprovalStatus::parse(&self.approval_status).ok_or(
            Error::Artifact(ArtifactError::InvalidAgentDefBody(
                "manifest approvalStatus must be a known claim approval status",
            )),
        )?;
        let lifecycle_status = ClaimLifecycleStatus::parse(&self.lifecycle_status).ok_or(
            Error::Artifact(ArtifactError::InvalidAgentDefBody(
                "manifest lifecycleStatus must be a known claim lifecycle",
            )),
        )?;
        let source = ClaimSource::parse(&self.source).ok_or(Error::Artifact(
            ArtifactError::InvalidAgentDefBody("manifest source must be a known claim source"),
        ))?;
        let dreaming = self
            .dreaming
            .as_deref()
            .map(|mode| {
                DreamingMode::parse(mode).ok_or(Error::Artifact(
                    ArtifactError::InvalidAgentDefBody(
                        "manifest dreaming must be one of own|inherit|off",
                    ),
                ))
            })
            .transpose()?;
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
        )
        .with_dreaming(dreaming, self.dreaming_model.clone().map(ModelTierRef)))
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

/// Canonical export-safe identity from the compiled seeded roster, never from
/// user-editable AGENT_DEF display names or version text.
pub(crate) fn system_export_identity(
    id: &EntityId,
) -> Result<Option<(&'static str, &'static str)>> {
    Ok(system_agent_manifest()?
        .definitions
        .iter()
        .find(|seed| seed.entity_id.0 == *id)
        .map(|seed| (seed.logical_id.as_str(), seed.definition.version.as_str())))
}

/// The ceiling and lineage the seed manifest gives the row at `id`, when `id`
/// is a seeded row id: what that id answers to before it holds a pin of its
/// own (see `id_pin`).
pub(super) fn seeded_lineage(id: &EntityId) -> Result<Option<(AgentCeiling, Option<EntityId>)>> {
    system_agent_manifest()?
        .definitions
        .iter()
        .find(|seed| seed.entity_id.0 == *id)
        .map(|seed| {
            let ceiling = AgentCeiling::parse(&seed.definition.ceiling).ok_or(Error::Artifact(
                ArtifactError::InvalidAgentDefBody("manifest ceiling must be one of auto|proposed"),
            ))?;
            Ok((
                ceiling,
                seed.definition.forked_from.as_ref().map(|parent| parent.0),
            ))
        })
        .transpose()
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
    // Rows older than the pin are pinned before anything can delete one, and
    // before a deleted seeded row re-seeds within its pin (H215).
    super::id_pin::pin_stored_rows_in_txn(store, wtxn)?;
    reconcile_system_agent_definitions_in(
        store,
        config,
        analyzer,
        wtxn,
        text_index_trusted,
        &manifest,
    )
}

/// Convergent reconciliation over the stored rows: create what is missing
/// and was never deleted, never overwrite what exists, fail closed on a
/// foreign occupant. LMDB write
/// serialization plus deterministic ids makes concurrent opens converge — the
/// later writer observes the first writer's committed row and writes nothing.
pub(super) fn reconcile_system_agent_definitions_in(
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
        match store.port_entity_record(wtxn, &id)?.map(|row| row.encode()) {
            Some(raw) => {
                let header = EntityMetadataHeader::parse(&raw).ok_or(Error::Artifact(
                    ArtifactError::SeededAgentDefinitionConflict { id },
                ))?;
                if header.entity_type != ENTITY_TYPE_AGENT_DEF {
                    return Err(Error::Artifact(
                        ArtifactError::SeededAgentDefinitionConflict { id },
                    ));
                }
                let stored =
                    decode_agent_definition(&raw[ENTITY_METADATA_HEADER_LEN..]).map_err(|_| {
                        Error::Artifact(ArtifactError::SeededAgentDefinitionConflict { id })
                    })?;
                // A valid occupant whose logical id is missing or different is
                // a legacy foreign row: conflict, never adoption, never
                // overwrite. A match leaves every stored byte alone —
                // including user edits, `display_name`, and `enabled = false`.
                if stored.logical_id.as_deref() != Some(seed.logical_id.as_str()) {
                    return Err(Error::Artifact(
                        ArtifactError::SeededAgentDefinitionConflict { id },
                    ));
                }
            }
            // The owner's deletion of a seeded row is durable (FIX 10204):
            // no later open brings it back. Only an authorized restore, which
            // clears the deletion, does.
            None if crate::ports::TombstoneStoreRead::port_deletion_state(store, wtxn, &id)?
                .deleted => {}
            None => {
                let mut definition = seed.definition_row(legacy_enabled)?;
                // A deleted seeded row comes back no wider than the narrowest
                // ceiling its id has held (H215): an agent that deleted its
                // own narrowed row gains nothing from the next open.
                if let Some(pinned) = super::id_pin::pinned_ceiling_in_txn(store, wtxn, &id)?
                    && definition.ceiling.widens_beyond(pinned)
                {
                    definition.ceiling = pinned;
                }
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
    RESERVED_ACTOR_CENSUS_V2.delete(store, wtxn, &())?;
    DEFAULT_RESERVED_ACTOR_CENSUS_V1.delete(store, wtxn, &())?;
    Ok(())
}

/// Gives each seeded system agent its model PERSON in the caller's writer
/// (FIX 12098): every row derives from the manifest and the pinned seed
/// time, so each device writes the same bytes. A seed whose row is absent,
/// deleted, erased or not an AGENT_DEF gets none.
pub(crate) fn ensure_seeded_agent_persons_in_txn(
    vault: &crate::Vault,
    txn: &mut heed::RwTxn<'_>,
) -> Result<()> {
    for seed in &system_agent_manifest()?.definitions {
        let id = seed.entity_id.0;
        if vault.archive_tombstone_in_txn(txn, &id)?.is_some() {
            continue;
        }
        let crate::vault::LiveEntityRow::Live {
            entity_type: ENTITY_TYPE_AGENT_DEF,
            ..
        } = crate::vault::live_entity_row_in_txn(&vault.store, txn, &id)?
        else {
            continue;
        };
        crate::context_board::ensure_seeded_agent_person_in_txn(
            vault,
            txn,
            id,
            &seed.display_name,
        )?;
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
    let key = logical_id.to_owned();
    let stored = match SYSTEM_TOGGLE_LEGACY.get(store, wtxn, &key)? {
        Some(raw) if raw == [0x01] => Some(true),
        Some(raw) if raw == [0x00] => Some(false),
        Some(_) | None => None,
    };
    SYSTEM_TOGGLE_LEGACY.delete(store, wtxn, &key)?;
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
