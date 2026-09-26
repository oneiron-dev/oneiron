//! Project responsibility records and their derived home-room membership.
//! PROJECT uses the compiled-pack registration door, not a new core kind.
mod deletion;
mod projection;
pub(crate) use deletion::deindex_project_room;
#[cfg(test)]
mod tests;
pub(crate) use projection::{reconcile_project_rooms, validate_project_body, validate_room_body};

use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::error::{Error, RecordError, Result};
use crate::llm::Scope;
use crate::registry::{ENTITY_TYPE_CONVERSATION, TypeByteZone};
use crate::{EntityId, TimeRange, Vault};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// Preferred slot in an otherwise empty compiled-pack registry. Existing
/// vaults can assign another slot; use Vault::project_type_byte for the binding.
pub const PROJECT_TYPE_BYTE: u8 = 103;
const PACK: &str = "oneiron.project";
const ROOT: &[u8] = b"project.root.v1";
pub(super) const ROOM_PROJECT: &[u8] = b"project.room_owner.v1/";
const CHANGES: &[u8] = b"project.room_changes.v1/";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectRecord {
    pub schema_version: u8,
    pub parent: Option<String>,
    pub claims_scope_ref: String,
    /// Four-axis and resource-set bounds for this project and its descendants.
    pub slice: Scope,
    /// Maximum allowed depth for this project (the board-controlled depth row).
    pub depth_limit: u8,
    /// Descendant-spawn levels left in this project's slice.
    pub depth_remaining: u8,
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
            parent: parent.map(|p| p.to_hex()),
            claims_scope_ref: claims_scope_ref.to_hex(),
            slice: Scope::default(),
            depth_limit: 10,
            depth_remaining: if parent.is_none() { 10 } else { 0 },
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
pub(super) fn project_type(store: &crate::store::Store) -> Option<u8> {
    store
        .structural_kind_registrations()
        .into_iter()
        .find(|row| row.pack == PACK && row.short_id_prefix == "pj")
        .map(|row| row.type_byte)
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
    /// A project's leader spawns one new child under a slice no wider than its own.
    /// The host supplies the actor id from its authenticated caller context;
    /// this door compares it to the live leader in the creation transaction.
    /// Project record edits outside this verb still pass the shared ancestry
    /// projector, which refuses scope and depth widening on raw/replay writes.
    pub fn spawn_subproject(
        &self,
        parent_id: EntityId,
        child_id: EntityId,
        actor: EntityId,
        leader: EntityId,
        slice: Scope,
        now: u64,
    ) -> Result<ProjectRecord> {
        let kind = self.project_type_byte()?;
        self.with_write_txn(|txn| {
            let parent: ProjectRecord = record(&self.store, txn, parent_id, kind)?
                .ok_or(RecordError::InvalidProjectBody("missing parent project"))?;
            if parent.leader != actor.to_hex() {
                return Err(RecordError::InvalidProjectBody("only the leader may spawn").into());
            }
            if self.store.entities.get(txn, child_id.as_bytes())?.is_some() {
                return Err(RecordError::InvalidProjectBody("subproject id already exists").into());
            }
            let remaining = parent
                .depth_remaining
                .min(parent.depth_limit)
                .checked_sub(1)
                .ok_or(RecordError::InvalidProjectBody("project depth exhausted"))?;
            parent.slice.attenuate(slice.clone()).map_err(|_| {
                RecordError::InvalidProjectBody("subproject slice widens its parent")
            })?;
            let mut child = ProjectRecord::new(
                child_id,
                Some(parent_id),
                EntityId::from_hex(&parent.claims_scope_ref)?,
                leader,
            );
            child.slice = slice;
            child.depth_limit = parent.depth_limit;
            child.depth_remaining = remaining;
            child.board.push(actor.to_hex());
            self.batch_in()
                .put(
                    &child_id,
                    kind,
                    TimeRange {
                        start: now,
                        end: now,
                    },
                    now,
                    &encode(&child)?,
                )
                .apply(txn)?;
            Ok(child)
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
