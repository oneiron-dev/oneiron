//! The project write hooks the store layer's batch put and import paths run,
//! supplied by the engine when a store opens.

use std::collections::{BTreeSet, HashSet};

use heed::{RoTxn, RwTxn};

use crate::analyzer::MultilingualAnalyzer;
use crate::config::{HostingPrivacyPosture, VaultConfig};
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::store::{GateDecisionId, Store};
use crate::write_envelope::claim_body::ClaimBody;

/// The engine's project write hooks. A store holds one implementation from
/// the moment it is assembled (see [`crate::store::StoreHooks`]). The store
/// layer calls each method at the point where it called the engine function
/// of the same name, with the same arguments, and keeps its result.
pub trait StoreProjectWrites: Send + Sync {
    /// The engine's `workspace_roster::refresh_project_frontiers`.
    fn refresh_project_frontiers(
        &self,
        store: &Store,
        txn: &mut RwTxn<'_>,
        posture: HostingPrivacyPosture,
        touched: &BTreeSet<EntityId>,
    ) -> Result<()>;

    /// The engine's `workspace_roster::reconcile_project_rooms`.
    fn reconcile_project_rooms(
        &self,
        store: &Store,
        config: &VaultConfig,
        analyzer: &MultilingualAnalyzer,
        trusted: bool,
        txn: &mut RwTxn<'_>,
        touched: &BTreeSet<EntityId>,
    ) -> Result<()>;

    /// The engine's `workspace_roster::validate_local_leader_chat_turns`.
    fn validate_local_leader_chat_turns(
        &self,
        store: &Store,
        txn: &RoTxn<'_>,
        turns: &BTreeSet<EntityId>,
    ) -> Result<()>;

    /// The engine's `workspace_roster::capture_project_put`.
    fn capture_project_put(
        &self,
        store: &Store,
        txn: &RoTxn<'_>,
        id: EntityId,
        kind: u8,
        data: &[u8],
    ) -> Result<Vec<(EntityId, Vec<u8>)>>;

    /// The engine's `workspace_roster::guard_goal_claim_put`.
    fn guard_goal_claim_put(
        &self,
        store: &Store,
        txn: &RoTxn<'_>,
        id: EntityId,
        incoming: Option<&ClaimBody>,
        bytes: &[u8],
        replicated: bool,
    ) -> Result<()>;

    /// The engine's `workspace_roster::guard_goal_pointer_put`.
    fn guard_goal_pointer_put(
        &self,
        store: &Store,
        txn: &RoTxn<'_>,
        id: EntityId,
        bytes: &[u8],
        replicated: bool,
    ) -> Result<()>;

    /// The engine's `workspace_roster::normalize_project_body`.
    fn normalize_project_body(
        &self,
        store: &Store,
        txn: &RoTxn<'_>,
        id: EntityId,
        bytes: &[u8],
        posture: HostingPrivacyPosture,
    ) -> Result<Vec<u8>>;

    /// The engine's `workspace_roster::validate_project_body`.
    fn validate_project_body(&self, id: EntityId, bytes: &[u8]) -> Result<Vec<EntityId>>;

    /// The engine's `workspace_roster::validate_project_transition`.
    fn validate_project_transition(
        &self,
        store: &Store,
        txn: &RoTxn<'_>,
        id: EntityId,
        kind: u8,
        bytes: &[u8],
        posture: HostingPrivacyPosture,
    ) -> Result<()>;

    /// The engine's `workspace_roster::note_project_proof`.
    fn note_project_proof(
        &self,
        store: &Store,
        txn: &mut RwTxn<'_>,
        id: EntityId,
        kind: u8,
        data: &[u8],
    ) -> Result<()>;

    /// The engine's `workspace_roster::validate_room_body`.
    fn validate_room_body(
        &self,
        store: &Store,
        txn: &RoTxn<'_>,
        id: EntityId,
        data: &[u8],
    ) -> Result<()>;

    /// The engine's `workspace_roster::root_project_in`.
    fn root_project_in(&self, store: &Store, txn: &RoTxn<'_>) -> Result<Option<EntityId>>;

    /// The engine's `workspace_roster::seed_root_project`, run by a vault's
    /// open seeding.
    fn seed_root_project(&self, vault: &crate::Vault) -> Result<()>;

    /// The engine's `workspace_roster::project_mint_gate_refs_in_txn`.
    fn project_mint_gate_refs_in_txn(
        &self,
        vault: &crate::Vault,
        txn: &RoTxn<'_>,
    ) -> Result<HashSet<GateDecisionId>>;
}
