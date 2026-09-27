//! Project responsibility records and their derived home-room membership.
//! PROJECT uses the compiled-pack registration door, not a new core kind.
mod deletion;
mod projection;
pub(crate) use deletion::deindex_project_room;
#[cfg(test)]
mod tests;
pub(crate) use projection::{
    reconcile_project_rooms, validate_project_body, validate_project_depth_change,
    validate_room_body,
};
#[cfg(test)]
pub(crate) use tests::set_project_depth_signed_for_test;

use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::error::{Error, Result};
use crate::registry::{ENTITY_TYPE_CONVERSATION, TypeByteZone};
use crate::{EntityId, TimeRange, Vault};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// Preferred slot in an otherwise empty compiled-pack registry. Existing
/// vaults can assign another slot; use Vault::project_type_byte for the binding.
pub const PROJECT_TYPE_BYTE: u8 = 103;
const DEFAULT_PROJECT_DEPTH: u8 = 10;
const PACK: &str = "oneiron.project";
const ROOT: &[u8] = b"project.root.v1";
pub(super) const ROOM_PROJECT: &[u8] = b"project.room_owner.v1/";
const CHANGES: &[u8] = b"project.room_changes.v1/";
const DEPTH_EDIT: &[u8] = b"project.depth_edit.v1/";
const DEPTH_HISTORY: &[u8] = b"project.depth_history.v1/";

fn depth_history_key(id: EntityId) -> Vec<u8> {
    [DEPTH_HISTORY, id.as_bytes()].concat()
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct ProjectDepthHistory {
    depth: u8,
    revision: u64,
}

fn depth_history_decode(bytes: &[u8]) -> Result<ProjectDepthHistory> {
    let [depth, revision @ ..] = bytes else {
        return Err(invalid());
    };
    let revision: [u8; 8] = revision.try_into().map_err(|_| invalid())?;
    Ok(ProjectDepthHistory {
        depth: *depth,
        revision: u64::from_be_bytes(revision),
    })
}

fn depth_history_encode(history: ProjectDepthHistory) -> [u8; 9] {
    let mut bytes = [0; 9];
    bytes[0] = history.depth;
    bytes[1..].copy_from_slice(&history.revision.to_be_bytes());
    bytes
}

fn depth_history_of(body: &ProjectRecord) -> ProjectDepthHistory {
    ProjectDepthHistory {
        depth: body.depth,
        revision: body.depth_proof.as_ref().map_or(0, |proof| proof.revision),
    }
}

fn depth_edit_key(id: EntityId) -> Vec<u8> {
    [DEPTH_EDIT, id.as_bytes()].concat()
}

fn depth_edit_digest(old: &[u8], new: &[u8]) -> [u8; 32] {
    let mut hash = blake3::Hasher::new();
    hash.update(b"project.depth_edit.v1");
    hash.update(old);
    hash.update(new);
    *hash.finalize().as_bytes()
}

/// Signed owner act that travels with the project body. The signature binds
/// the project, vault, actor, revision and depth; mutable member refs stay
/// ordinary project data. A receiver verifies this against its authority log.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectDepthProof {
    pub schema_version: u8,
    pub project_id: String,
    pub actor_ref: String,
    pub vault_id: [u8; 32],
    pub revision: u64,
    pub depth: u8,
    pub suite: String,
    pub public_key: Vec<u8>,
    pub signature: Vec<u8>,
}

fn depth_transcript(proof: &ProjectDepthProof) -> Result<Vec<u8>> {
    let mut bytes = b"oneiron.project.depth.v1\0".to_vec();
    bytes.extend_from_slice(&encode(&(
        proof.schema_version,
        &proof.project_id,
        &proof.actor_ref,
        proof.vault_id,
        proof.revision,
        proof.depth,
    ))?);
    Ok(bytes)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectRecord {
    pub schema_version: u8,
    pub depth: u8,
    pub depth_proof: Option<ProjectDepthProof>,
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
            depth: DEFAULT_PROJECT_DEPTH,
            depth_proof: None,
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
    /// Changes a project's spawn ceiling through the existing owner write authority.
    /// The host signs the exact depth revision with an authority key actively
    /// bound to the human writer; replicas verify that same signed revision.
    /// A host translates a person's request into a typed depth, not prompt text.
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
        if usize::from(depth) > crate::context_projection::CONTEXT_PROJECTION_MAX_ANCESTORS {
            return Err(crate::error::RecordError::InvalidProjectBody(
                "depth exceeds projection bound",
            )
            .into());
        }
        self.with_write_txn(|txn| {
            self.verify_owner_write_actor_in_txn(txn, authenticated_owner)?;
            let mut body: ProjectRecord = record(&self.store, txn, id, self.project_type_byte()?)?
                .ok_or(Error::EntityNotFound)?;
            if body.depth == depth {
                return Ok(());
            }
            let fold = self.authority_fold_readonly_in_txn(txn)?;
            let (suite, public_key) = match &signer_key {
                crate::authority::AuthorityKey::Ed25519(bytes) => ("ed25519", bytes.to_vec()),
                crate::authority::AuthorityKey::P256(bytes) => ("p256", bytes.clone()),
            };
            let mut proof = ProjectDepthProof {
                schema_version: 1,
                project_id: id.to_hex(),
                actor_ref: authenticated_owner.entity_ref().to_hex(),
                vault_id: fold.vault_id.ok_or_else(invalid)?,
                revision: body.depth_proof.as_ref().map_or(Ok(1), |proof| {
                    proof.revision.checked_add(1).ok_or_else(invalid)
                })?,
                depth,
                suite: suite.into(),
                public_key,
                signature: Vec::new(),
            };
            proof.signature = signer(&depth_transcript(&proof)?)?;
            body.depth = depth;
            body.depth_proof = Some(proof);
            let bytes = encode(&body)?;
            let proof_key = depth_edit_key(id);
            if self.store.vault_meta.get(txn, &proof_key)?.is_some() {
                return Err(invalid());
            }
            let old = self
                .store
                .entities
                .get(txn, id.as_bytes())?
                .ok_or(Error::EntityNotFound)?;
            self.store
                .vault_meta
                .put(txn, &proof_key, &depth_edit_digest(&old, &bytes))?;
            self.batch_in()
                .put(
                    &id,
                    self.project_type_byte()?,
                    TimeRange {
                        start: now,
                        end: now,
                    },
                    now,
                    &bytes,
                )
                .apply(txn)?;
            if self.store.vault_meta.get(txn, &proof_key)?.is_some() {
                return Err(Error::InvariantViolation(
                    "project depth proof not consumed",
                ));
            }
            Ok(())
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
        let body = record(&self.store, txn, id, self.project_type_byte()?)?
            .ok_or(Error::EntityNotFound)?;
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
