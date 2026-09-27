//! Project responsibility records and their derived home-room membership.
//! PROJECT uses the compiled-pack registration door, not a new core kind.
mod deletion;
mod projection;
pub(crate) use deletion::deindex_project_room;
#[cfg(test)]
mod tests;
pub(crate) use projection::{
    normalize_project_body, reconcile_project_rooms, validate_project_body, validate_room_body,
};
#[cfg(test)]
pub(crate) use tests::{create_project_signed_for_test, set_project_depth_signed_for_test};

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
pub(super) const ROOM_PROJECT: &[u8] = b"project.room_owner.v1/";
const CHANGES: &[u8] = b"project.room_changes.v1/";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectRecord {
    pub schema_version: u8,
    pub depth: u8,
    pub parent: Option<String>,
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
            // Fixture/host convenience only. The write door replaces this
            // value with the vault's resolved manifest creation default.
            depth: crate::gate::seeded_project_depth_default(),
            parent: parent.map(|p| p.to_hex()),
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
    /// Creates or edits membership. Birth policy is separately materialized
    /// under an immutable, content-addressed POLICY_MANIFEST identity.
    pub fn put_project(&self, id: EntityId, record: &ProjectRecord, now: u64) -> Result<()> {
        self.with_write_txn(|txn| {
            let mut body = record.clone();
            if self.store.entities.get(txn, id.as_bytes())?.is_none() {
                let (_, birth_depth) =
                    match crate::gate::project_depth::birth_for_project(&self.store, txn, id)? {
                        Some((birth_id, birth)) => {
                            if birth.owner.is_none()
                                && self.authority_fold_readonly_in_txn(txn)?.vault_id.is_some()
                                && !crate::gate::project_depth::locally_seeded_birth(
                                    &self.store,
                                    txn,
                                    birth_id,
                                    &birth,
                                )?
                            {
                                return Err(crate::error::RecordError::InvalidProjectBody(
                                    "unsigned remote project birth is not authorized",
                                )
                                .into());
                            }
                            (birth_id, birth.depth)
                        }
                        None => {
                            if self.authority_fold_readonly_in_txn(txn)?.vault_id.is_some() {
                                return Err(crate::error::RecordError::InvalidProjectBody(
                                    "a new project requires an owner-signed birth",
                                )
                                .into());
                            }
                            crate::gate::project_depth::put_birth_in_txn(self, txn, id, now)?
                        }
                    };
                body.depth = birth_depth;
            }
            self.batch_in()
                .put(
                    &id,
                    self.project_type_byte()?,
                    TimeRange {
                        start: now,
                        end: now,
                    },
                    now,
                    &encode(&body)?,
                )
                .apply(txn)?;
            Ok(())
        })
    }

    /// Person-authorized project creation. The signed birth fact commits with
    /// membership, and can be verified on another replica without assuming
    /// its default manifest or trusting a receiver-local project body.
    pub fn create_project_with_owner<S>(
        &self,
        id: EntityId,
        record: &ProjectRecord,
        authenticated_owner: &crate::write_envelope::WriteActor,
        now: u64,
        signer_key: crate::authority::AuthorityKey,
        signer: S,
    ) -> Result<()>
    where
        S: FnOnce(&[u8]) -> Result<Vec<u8>>,
    {
        self.with_write_txn(|txn| {
            if self.store.entities.get(txn, id.as_bytes())?.is_some()
                || crate::gate::project_depth::birth_for_project(&self.store, txn, id)?.is_some()
            {
                return Err(crate::error::RecordError::InvalidProjectBody(
                    "project birth identity is already occupied",
                )
                .into());
            }
            let (_, depth) = crate::gate::project_depth::put_signed_birth_in_txn(
                self,
                txn,
                id,
                authenticated_owner,
                now,
                signer_key,
                signer,
            )?;
            let mut body = record.clone();
            body.depth = depth;
            self.batch_in()
                .put(
                    &id,
                    self.project_type_byte()?,
                    TimeRange {
                        start: now,
                        end: now,
                    },
                    now,
                    &encode(&body)?,
                )
                .apply(txn)?;
            Ok(())
        })
    }

    /// Person-authored project-depth policy edit. The host supplies its
    /// authority signer; the engine persists an immutable causal contribution.
    pub fn set_project_depth<S>(
        &self,
        id: EntityId,
        depth: u8,
        authenticated_owner: &crate::write_envelope::WriteActor,
        now: u64,
        signer_key: crate::authority::AuthorityKey,
        signer: S,
    ) -> Result<()>
    where
        S: FnOnce(&[u8]) -> Result<Vec<u8>>,
    {
        self.with_write_txn(|txn| {
            if record::<ProjectRecord>(&self.store, txn, id, self.project_type_byte()?)?.is_none() {
                return Err(Error::EntityNotFound);
            }
            crate::gate::project_depth::put_edit_in_txn(
                self,
                txn,
                id,
                depth,
                authenticated_owner,
                now,
                signer_key,
                signer,
            )
        })
    }

    /// Complete project view: membership plus the live policy depth row.
    pub fn project(&self, id: EntityId) -> Result<Option<ProjectRecord>> {
        let txn = self.store.env.read_txn()?;
        let Some(mut body) =
            record::<ProjectRecord>(&self.store, &txn, id, self.project_type_byte()?)?
        else {
            return Ok(None);
        };
        body.depth = crate::gate::project_depth::resolve_project_depth(
            &self.store,
            &txn,
            self.privacy_posture(),
            id,
        )?
        .depth;
        Ok(Some(body))
    }
    pub fn project_room(&self, id: EntityId) -> Result<Option<ProjectRoom>> {
        record(
            &self.store,
            &self.store.env.read_txn()?,
            id,
            ENTITY_TYPE_CONVERSATION,
        )
    }
    /// Resolve the root or a named project in the dispatch admission snapshot.
    pub(crate) fn project_for_spawn_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        requested: Option<EntityId>,
    ) -> Result<(EntityId, ProjectRecord)> {
        let id = match requested {
            Some(id) => id,
            None => {
                let raw = self.store.vault_meta.get(txn, ROOT)?.ok_or_else(invalid)?;
                EntityId::from_bytes(raw.as_ref().try_into().map_err(|_| invalid())?)?
            }
        };
        let mut body: ProjectRecord = record(&self.store, txn, id, self.project_type_byte()?)?
            .ok_or(Error::EntityNotFound)?;
        body.depth = crate::gate::project_depth::resolve_project_depth(
            &self.store,
            txn,
            self.privacy_posture(),
            id,
        )?
        .depth;
        Ok((id, body))
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
        let mut body = ProjectRecord::new(id, None, id, leader);
        let (_, depth) = crate::gate::project_depth::put_birth_in_txn(vault, txn, id, 0)?;
        body.depth = depth;
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
