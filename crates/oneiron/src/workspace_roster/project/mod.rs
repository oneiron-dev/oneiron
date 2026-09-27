//! Project responsibility records and their derived home-room membership.
//! PROJECT uses the compiled-pack registration door, not a new core kind.
mod deletion;
mod edges;
mod projection;
pub(crate) use deletion::deindex_project_room;
pub(crate) use edges::{
    validate_project_edge_delete, validate_project_edge_put, validate_project_graph,
};
#[cfg(test)]
mod tests;
pub(crate) use projection::{reconcile_project_rooms, validate_project_body, validate_room_body};

use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::error::{Error, Result};
use crate::registry::{ENTITY_TYPE_CONVERSATION, TypeByteZone};
use crate::{EntityId, TimeRange, Vault};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// Preferred slot in an otherwise empty compiled-pack registry. Existing
/// vaults can assign another slot; use Vault::project_type_byte for the binding.
pub const PROJECT_TYPE_BYTE: u8 = 103;
const PACK: &str = "oneiron.project";
const ROOT: &[u8] = b"project.root.v1";
/// A hub hop uses a smaller PPR budget than an ordinary `belongs_to` edge.
pub(crate) const HUB_BELONGS_TO_LAMBDA: f32 = 0.05;
const HUB_MEMBERSHIP_WEIGHT: f32 = 0.05;
pub(super) const ROOM_PROJECT: &[u8] = b"project.room_owner.v1/";
const CHANGES: &[u8] = b"project.room_changes.v1/";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProjectRole {
    Project,
    Corpus,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectRecord {
    /// Corpus is a role of the same PROJECT hub, not a new entity kind.
    pub role: ProjectRole,
    pub schema_version: u8,
    /// Parent projects. A project may belong to more than one venture.
    pub parents: Vec<String>,
    pub claims_scope_ref: String,
    pub leader: String,
    pub board: Vec<String>,
    pub roster: Vec<String>,
    pub sessions: Vec<String>,
    pub tasks: Vec<String>,
    pub branches: Vec<String>,
    pub skill_forks: Vec<String>,
    pub goal: Option<String>,
    pub budget: Option<String>,
    pub asks: Vec<String>,
    pub home_room: String,
}
impl ProjectRecord {
    pub fn new(
        id: EntityId,
        parent: Option<EntityId>,
        claims_scope_ref: EntityId,
        leader: EntityId,
    ) -> Self {
        Self {
            schema_version: 1,
            role: ProjectRole::Project,
            parents: parent.into_iter().map(|p| p.to_hex()).collect(),
            claims_scope_ref: claims_scope_ref.to_hex(),
            leader: leader.to_hex(),
            board: vec![],
            roster: vec![leader.to_hex()],
            sessions: vec![],
            tasks: vec![],
            branches: vec![],
            skill_forks: vec![],
            goal: None,
            budget: None,
            asks: vec![],
            home_room: home_room_id(id).to_hex(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectRoom {
    pub schema_version: u8,
    pub kind: String,
    pub project_id: String,
    #[serde(rename = "memberIds")]
    pub member_ids: Vec<String>,
    /// Membership never grants additional memory scope.
    pub claims_scope_ref: String,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectRoomChange {
    pub project_id: String,
    pub room_id: String,
    pub previous_members: Vec<String>,
    pub member_ids: Vec<String>,
    pub at: u64,
}

pub(super) fn invalid() -> Error {
    Error::InvalidConfig("invalid project or home room".into())
}
pub(super) fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    rmp_serde::to_vec_named(value).map_err(|_| invalid())
}
pub(super) fn decode<T: for<'a> Deserialize<'a>>(bytes: &[u8]) -> Result<T> {
    rmp_serde::from_slice(bytes).map_err(|_| invalid())
}
fn home_room_id(project: EntityId) -> EntityId {
    let hash = blake3::hash(&[b"project.home_room.v1/", project.as_bytes().as_slice()].concat());
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&hash.as_bytes()[..16]);
    bytes[0] = 0xB7;
    EntityId::from_bytes(bytes).expect("non-reserved deterministic room id")
}
pub(super) fn record<T: for<'a> Deserialize<'a>>(
    store: &crate::store::Store,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
    kind: u8,
) -> Result<Option<T>> {
    let Some(raw) = store.entities.get(txn, id.as_bytes())? else {
        return Ok(None);
    };
    let header = EntityMetadataHeader::parse(&raw).ok_or_else(invalid)?;
    if header.entity_type != kind {
        return Err(invalid());
    }
    if raw.len() == ENTITY_METADATA_HEADER_LEN {
        return Ok(None);
    }
    decode(&raw[ENTITY_METADATA_HEADER_LEN..]).map(Some)
}

pub(crate) fn is_project_type(store: &crate::store::Store, kind: u8) -> bool {
    store
        .structural_kind_registration(kind)
        .is_some_and(|row| row.pack == PACK && row.short_id_prefix == "pj")
}
/// Check the dynamic compiled-pack kind through the persisted root binding.
/// Unseeded test stores have no root and therefore no project hubs.
pub(crate) fn is_project_entity(
    store: &impl crate::store::ManifestDbs,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
) -> Result<bool> {
    let Some(root) = store.vault_meta().get(txn, ROOT)? else {
        return Ok(false);
    };
    let Some(root_raw) = store.entities().get(txn, &root)? else {
        return Err(Error::CorruptedIndex("project root missing"));
    };
    let root_header = EntityMetadataHeader::parse(&root_raw)
        .ok_or(Error::CorruptedIndex("project root header"))?;
    let Some(raw) = store.entities().get(txn, id.as_bytes())? else {
        return Ok(false);
    };
    let header =
        EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("project entity header"))?;
    Ok(header.entity_type == root_header.entity_type && raw.len() > ENTITY_METADATA_HEADER_LEN)
}

pub(super) fn project_type(store: &crate::store::Store) -> Option<u8> {
    store
        .structural_kind_registrations()
        .into_iter()
        .find(|row| row.pack == PACK && row.short_id_prefix == "pj")
        .map(|row| row.type_byte)
}
/// Read a verified project record in the caller's transaction. A future or
/// malformed project cannot confer inherited policy-writing power.
pub(crate) fn project_record_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
) -> Result<Option<ProjectRecord>> {
    let Some(kind) = project_type(&vault.store) else {
        return Ok(None);
    };
    if !is_project_entity(&vault.store, txn, id)? {
        return Ok(None);
    }
    record(&vault.store, txn, id, kind)
}

pub(crate) fn project_room_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
) -> Result<Option<ProjectRoom>> {
    record(&vault.store, txn, id, ENTITY_TYPE_CONVERSATION)
}

/// A project or its verified home room is a persisted effect location. An
/// arbitrary conversation ID or cross-project room is not a selector.
fn policy_project_path(
    store: &crate::store::Store,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
    kind: u8,
    project: &ProjectRecord,
) -> Result<(EntityId, Option<EntityId>)> {
    match project.parents.as_slice() {
        [] => Ok((id, None)),
        [parent_ref] => {
            let parent = EntityId::from_hex(parent_ref)?;
            if parent == id || !is_project_entity(store, txn, parent)? {
                return Err(invalid());
            }
            let parent_record: ProjectRecord =
                record(store, txn, parent, kind)?.ok_or_else(invalid)?;
            if parent_record.role != ProjectRole::Project || parent_record.parents.len() > 1 {
                return Err(invalid());
            }
            // The root is a vault hub, not an extra product policy level.
            if parent_record.parents.is_empty() {
                Ok((id, None))
            } else {
                Ok((parent, Some(id)))
            }
        }
        _ => Err(invalid()), // no arbitrary winner in a multi-parent project
    }
}

pub(crate) fn effect_project_origin_in_txn(
    store: &crate::store::Store,
    txn: &heed::RoTxn<'_>,
    origin: EntityId,
) -> Result<Option<(EntityId, Option<EntityId>, Option<EntityId>)>> {
    let Some(kind) = project_type(store) else {
        return Ok(None);
    };
    if is_project_entity(store, txn, origin)? {
        let project: ProjectRecord = record(store, txn, origin, kind)?.ok_or_else(invalid)?;
        if project.role != ProjectRole::Project {
            return Ok(None);
        }
        let (project, subproject) = policy_project_path(store, txn, origin, kind, &project)?;
        return Ok(Some((project, subproject, None)));
    }
    let Some(raw) = store.entities.get(txn, origin.as_bytes())? else {
        return Ok(None);
    };
    let header = EntityMetadataHeader::parse(&raw).ok_or_else(invalid)?;
    if header.entity_type != ENTITY_TYPE_CONVERSATION {
        return Ok(None);
    }
    let room: ProjectRoom = decode(&raw[ENTITY_METADATA_HEADER_LEN..])?;
    let project_id = EntityId::from_hex(&room.project_id)?;
    if !is_project_entity(store, txn, project_id)? {
        return Ok(None);
    }
    let project: ProjectRecord = record(store, txn, project_id, kind)?.ok_or_else(invalid)?;
    if project.role != ProjectRole::Project
        || project.home_room != origin.to_hex()
        || project.roster != room.member_ids
        || project.claims_scope_ref != room.claims_scope_ref
    {
        return Err(invalid());
    }
    let (project, subproject) = policy_project_path(store, txn, project_id, kind, &project)?;
    Ok(Some((project, subproject, Some(origin))))
}

impl Vault {
    /// Persisted project kind binding. Never assume a slot already occupied by another pack.
    pub fn project_type_byte(&self) -> Result<u8> {
        project_type(&self.store).ok_or_else(invalid)
    }
    /// Creates or edits the project. The common batch projector co-commits the
    /// home room and its ChangeLog row, including raw-put and replay writes.
    pub fn put_project(&self, id: EntityId, record: &ProjectRecord, now: u64) -> Result<()> {
        self.put_entity(
            &id,
            self.project_type_byte()?,
            TimeRange {
                start: now,
                end: now,
            },
            now,
            &encode(record)?,
        )
    }
    /// Attach an asset to a project collection with a low-weight `belongs_to`
    /// edge. CLAIMs never link to hubs: their sideways scope is the project id.
    pub fn put_project_member(&self, asset: EntityId, project: EntityId) -> Result<()> {
        self.with_write_txn(|txn| {
            if !is_project_entity(&self.store, txn, project)? {
                return Err(invalid());
            }
            let raw = self
                .store
                .entities
                .get(txn, asset.as_bytes())?
                .ok_or_else(invalid)?;
            let header = EntityMetadataHeader::parse(&raw).ok_or_else(invalid)?;
            if !matches!(
                header.entity_type,
                crate::registry::ENTITY_TYPE_ASSET
                    | crate::registry::ENTITY_TYPE_ASSET_TEXT
                    | crate::registry::ENTITY_TYPE_CODE_ARTIFACT
            ) || raw.len() == ENTITY_METADATA_HEADER_LEN
            {
                return Err(invalid());
            }
            crate::ports::EdgeStore::port_edge_upsert(
                self,
                txn,
                &asset,
                crate::edge::EdgeKind::BelongsTo,
                &project,
                HUB_MEMBERSHIP_WEIGHT,
            )
        })
    }
    pub fn project(&self, id: EntityId) -> Result<Option<ProjectRecord>> {
        record(
            &self.store,
            &self.store.env.read_txn()?,
            id,
            self.project_type_byte()?,
        )
    }
    pub fn project_room(&self, id: EntityId) -> Result<Option<ProjectRoom>> {
        record(
            &self.store,
            &self.store.env.read_txn()?,
            id,
            ENTITY_TYPE_CONVERSATION,
        )
    }
    pub fn root_project(&self) -> Result<EntityId> {
        let txn = self.store.env.read_txn()?;
        let raw = self.store.vault_meta.get(&txn, ROOT)?.ok_or_else(invalid)?;
        EntityId::from_bytes(raw.as_ref().try_into().map_err(|_| invalid())?)
    }
    pub fn project_room_changes(&self, project: EntityId) -> Result<Vec<ProjectRoomChange>> {
        let txn = self.store.env.read_txn()?;
        self.store
            .vault_meta
            .prefix_iter(&txn, &[CHANGES, project.as_bytes()].concat())?
            .map(|row| {
                let (_, bytes) = row?;
                decode(&bytes)
            })
            .collect()
    }
}

pub(crate) fn seed_root_project(vault: &Vault) -> Result<()> {
    let kind = if let Some(kind) = project_type(&vault.store) {
        kind
    } else {
        if vault
            .store
            .vault_meta
            .get(&vault.store.env.read_txn()?, ROOT)?
            .is_some()
        {
            return Err(invalid());
        }
        let kind = (crate::registry::TYPE_BYTE_ZONE_COMPILED_PRODUCT_START
            ..=crate::registry::TYPE_BYTE_ZONE_COMPILED_PRODUCT_END)
            .find(|byte| {
                crate::registry::entity_type_registry_entry(*byte).is_none()
                    && vault.structural_kind_registration(*byte).is_none()
            })
            .ok_or_else(invalid)?;
        vault.register_structural_kind(kind, "pj", TypeByteZone::CompiledProduct, PACK)?;
        kind
    };
    let (leader, _) = vault
        .get_seeded_agent_definition_by_logical_id("sys.team_lead")?
        .ok_or_else(invalid)?;
    vault.with_write_txn(|txn| {
        if vault.store.vault_meta.get(txn, ROOT)?.is_some() {
            return Ok(());
        }
        let id = EntityId::now();
        let body = ProjectRecord::new(id, None, id, leader);
        vault
            .batch_in()
            .put(
                &id,
                kind,
                TimeRange { start: 0, end: 0 },
                0,
                &encode(&body)?,
            )
            .apply(txn)?;
        vault.store.vault_meta.put(txn, ROOT, id.as_bytes())?;
        Ok(())
    })
}
