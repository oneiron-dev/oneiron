//! Project responsibility records and their derived home-room membership.
//! PROJECT uses the compiled-pack registration door, not a new core kind.
mod conversion;
pub use conversion::MessageHangs;
mod deletion;
mod edges;
mod goal;
mod mint;
pub(crate) use mint::project_mint_gate_refs_in_txn;
mod origin;
pub use mint::{ProjectBudgetShare, ProjectGoalRecord, ProjectMintReceipt};
mod leader_chat;
mod projection;
mod widen;
pub(crate) use deletion::deindex_project_room;
pub(crate) use edges::{
    validate_project_edge_delete, validate_project_edge_put, validate_project_graph,
};
pub(crate) use goal::GoalLimits;
pub use goal::{GoalAxis, GoalExplorationBudget, GoalInterviewTurns, GoalPreference, GoalRecord};
pub(crate) use goal::{
    admitted_claim_of_project, guard_claim_put as guard_goal_claim_put, guard_goal_delete,
    guard_pointer_put as guard_goal_pointer_put, precheck_goal_delete, retire_goal_for_delete,
};
#[cfg(test)]
mod review_tests;
pub(crate) use leader_chat::CHAT_FIELD as LEADER_CHAT_FIELD;
pub use leader_chat::{LEADER_CHAT_RULE_PREDICATE, LeaderChat};
pub(crate) use leader_chat::{
    admit_turn as admit_leader_chat_turn, admit_witness as admit_leader_chat_witness,
    permit_record as permit_leader_chat_record, permitted_record as leader_chat_record_permitted,
    settle_record as settle_leader_chat_record,
    validate_local_turns as validate_local_leader_chat_turns,
    verify_existing_turn as verify_existing_leader_chat_turn,
};
pub use widen::{ProjectWidenAsk, ProjectWidenAxis};
#[cfg(test)]
mod tests;
pub(crate) use projection::{
    normalize_project_body, reconcile_project_rooms, validate_project_body, validate_room_body,
};
#[cfg(all(test, feature = "sync"))]
pub(crate) use tests::create_project_signed_for_test;
#[cfg(test)]
pub(crate) use tests::set_project_depth_signed_for_test;

use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::error::{Error, Result};
use crate::registry::{ENTITY_TYPE_CONVERSATION, TypeByteZone};
use crate::side_table::{self, Named, Raw, SideTable};
use crate::{EntityId, TimeRange, Vault};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// Preferred slot in an otherwise empty compiled-pack registry. Existing
/// vaults can assign another slot; use Vault::project_type_byte for the binding.
pub const PROJECT_TYPE_BYTE: u8 = 103;
const PACK: &str = "oneiron.project";

/// The root project's entity id, seeded once at first boot. Key: ().
const ROOT: SideTable<(), EntityId, Raw> = SideTable::new(&side_table::PROJECT_ROOT);

/// Index from a project's derived home room back to the project that owns it. Key: id16 (derived
/// home-room id).
pub(super) const ROOM_PROJECT: SideTable<EntityId, EntityId, Raw> =
    SideTable::new(&side_table::PROJECT_ROOM_OWNER);

/// Change-log event recording a project's home-room membership transition. Key: id16 (project) +
/// id16 (change event id).
const CHANGES: SideTable<(EntityId, EntityId), ProjectRoomChange, Named> =
    SideTable::new(&side_table::PROJECT_ROOM_CHANGES);
pub(crate) const HUB_BELONGS_TO_LAMBDA: f32 = 0.05;

const HUB_MEMBERSHIP_WEIGHT: f32 = 0.05;

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
    /// Cache of the live depth row; the policy contributions are authority.
    /// A body written before the row existed decodes with the seeded default.
    #[serde(default = "crate::gate::seeded_project_depth_default")]
    pub depth: u8,
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
    #[serde(default)]
    pub goal_record: Option<ProjectGoalRecord>,
    #[serde(default)]
    pub why: Option<String>,
    #[serde(default)]
    pub born_from: Option<String>,
    pub budget: Option<String>,
    #[serde(default)]
    pub budget_share: Option<ProjectBudgetShare>,
    pub asks: Vec<String>,
    pub home_room: String,
    #[serde(default)]
    pub origin_room: Option<String>,
    #[serde(default)]
    pub origin_thread: Option<String>,
    #[serde(default)]
    pub origin_at: Option<u64>,
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
            // Fixture/host convenience only. The write door replaces this
            // value with the vault's resolved manifest creation default.
            depth: crate::gate::seeded_project_depth_default(),
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
            goal_record: None,
            why: None,
            born_from: None,
            budget: None,
            budget_share: None,
            asks: vec![],
            home_room: home_room_id(id).to_hex(),
            origin_room: None,
            origin_thread: None,
            origin_at: None,
        }
    }

    /// The thread this project was converted from. A card mint on a plain
    /// message has `born_from` but no origin thread.
    pub(crate) fn origin_card(&self) -> Option<RoomOriginCard> {
        Some(RoomOriginCard {
            room: self.origin_room.clone()?,
            thread: self.origin_thread.clone()?,
            message: self.born_from.clone()?,
            at: self.origin_at?,
        })
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
    /// Absent on an ordinary room, so its body and API shape stay unchanged.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin: Option<RoomOriginCard>,
}
/// A reference to the original thread, not a second copy of its messages.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoomOriginCard {
    pub room: String,
    pub thread: String,
    pub message: String,
    pub at: u64,
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
    let Some(raw) = crate::ports::EntityStoreRead::port_entity_raw(store, txn, &id)? else {
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
    let Some(root) = ROOT.get(store, txn, &())? else {
        return Ok(false);
    };
    let Some(root_raw) = crate::ports::EntityStoreRead::port_entity_raw(store, txn, &root)? else {
        return Err(Error::CorruptedIndex("project root missing"));
    };
    let root_header = EntityMetadataHeader::parse(&root_raw)
        .ok_or(Error::CorruptedIndex("project root header"))?;
    let Some(raw) = crate::ports::EntityStoreRead::port_entity_raw(store, txn, &id)? else {
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
impl Vault {
    /// Persisted project kind binding. Never assume a slot already occupied by another pack.
    pub fn project_type_byte(&self) -> Result<u8> {
        project_type(&self.store).ok_or_else(invalid)
    }
    /// Creates or edits membership. Birth policy is separately materialized
    /// under an immutable, content-addressed POLICY_MANIFEST identity; the
    /// write door fills the body's depth cache from it.
    pub fn put_project(&self, id: EntityId, record: &ProjectRecord, now: u64) -> Result<()> {
        self.with_write_txn(|txn| {
            let body = record.clone();
            if self.store.entities.get(txn, id.as_bytes())?.is_none() {
                let posture = self.privacy_posture();
                match crate::gate::project_depth::birth_for_project(&self.store, txn, id)? {
                    Some((_, birth))
                        if birth.owner.is_none()
                            && !crate::gate::project_depth::unsigned_birth_trusted(
                                &self.store,
                                txn,
                                posture,
                                &birth,
                            )? =>
                    {
                        return Err(crate::error::RecordError::InvalidProjectBody(
                            "unsigned remote project birth is not authorized",
                        )
                        .into());
                    }
                    Some(_) => {}
                    None => {
                        if !crate::gate::project_depth::implicit_birth_applies(
                            &self.store,
                            txn,
                            posture,
                            id,
                        )? {
                            return Err(crate::error::RecordError::InvalidProjectBody(
                                "a new project requires an owner-signed birth",
                            )
                            .into());
                        }
                    }
                }
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
    /// Attach an asset to a project collection with a low-weight `belongs_to`
    /// edge. CLAIMs never link to hubs: their sideways scope is the project id.
    pub fn put_project_member(&self, asset: EntityId, project: EntityId) -> Result<()> {
        self.with_write_txn(|txn| {
            if !is_project_entity(&self.store, txn, project)? {
                return Err(invalid());
            }
            let raw = crate::ports::EntityStoreRead::port_entity_raw(&self.store, txn, &asset)?
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
            None => ROOT.get(&self.store, txn, &())?.ok_or_else(invalid)?,
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
        ROOT.get(&self.store, &txn, &())?.ok_or_else(invalid)
    }
    pub fn project_room_changes(&self, project: EntityId) -> Result<Vec<ProjectRoomChange>> {
        let txn = self.store.env.read_txn()?;
        CHANGES
            .iter_from(&self.store, &txn, project.as_bytes())?
            .map(|row| row.map(|(_, change)| change))
            .collect()
    }
}

pub(crate) fn seed_root_project(vault: &Vault) -> Result<()> {
    let kind = if let Some(kind) = project_type(&vault.store) {
        kind
    } else {
        if ROOT.contains(&vault.store, &vault.store.env.read_txn()?, &())? {
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
        if ROOT.contains(&vault.store, txn, &())? {
            return Ok(());
        }
        let id = EntityId::now();
        // The root is born from the seeded default on every replica, so it
        // needs no stored birth row. Name it the root first: the write door
        // derives that birth from the root marker, also in an owner-rooted
        // vault that predates root seeding.
        ROOT.put(&vault.store, txn, &(), &id)?;
        let mut body = ProjectRecord::new(id, None, id, leader);
        // The owner already exists at this point in vault open. A fresh root
        // board must be able to receive the first cross-project widen ask.
        body.board
            .push(crate::vault::embedded_owner_actor_id()?.to_hex());
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
        Ok(())
    })
}
