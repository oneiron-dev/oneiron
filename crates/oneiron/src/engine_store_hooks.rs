//! The engine's implementation of the store layer's hooks: each method
//! forwards to the engine function of the same name.

use heed::{RoTxn, RwTxn};
use oneiron_authority::federation::Sensitivity;

use crate::entity_id::EntityId;
use crate::error::Result;
use std::collections::{BTreeSet, HashSet};

use crate::analyzer::MultilingualAnalyzer;
use crate::config::{HostingPrivacyPosture, VaultConfig};
use crate::store::{
    GateDecisionId, Store, StoreDeleteGuards, StoreHooks, StoreProjectWrites, StoreScopeStamps,
};
use crate::write_envelope::claim_body::ClaimBody;

/// The hooks every vault's store opens with.
pub(crate) const ENGINE_STORE_HOOKS: StoreHooks = StoreHooks {
    delete_guards: &EngineDeleteGuards,
    scope_stamps: &EngineScopeStamps,
    project_writes: &EngineProjectWrites,
};

/// The engine's delete guards.
pub(crate) struct EngineDeleteGuards;

/// The engine's record-scope stamp hooks.
pub(crate) struct EngineScopeStamps;

/// The engine's project write hooks.
pub(crate) struct EngineProjectWrites;

impl StoreDeleteGuards for EngineDeleteGuards {
    fn reject_audience_edit_delete(
        &self,
        store: &Store,
        txn: &RoTxn<'_>,
        id: &EntityId,
    ) -> Result<()> {
        crate::workspace_roster::reject_audience_edit_delete(store, txn, id)
    }

    fn reject_ruling_delete(&self, store: &Store, txn: &RoTxn<'_>, id: &EntityId) -> Result<()> {
        crate::federation::reject_ruling_delete(store, txn, id)
    }

    fn refuse_revision_delete(&self, store: &Store, txn: &RoTxn<'_>, id: &EntityId) -> Result<()> {
        crate::workspace_roster::refuse_revision_delete(store, txn, id)
    }

    fn precheck_goal_delete(
        &self,
        store: &Store,
        txn: &RoTxn<'_>,
        id: EntityId,
        gated: bool,
    ) -> Result<()> {
        crate::workspace_roster::precheck_goal_delete(store, txn, id, gated)
    }

    fn guard_goal_delete(&self, store: &Store, txn: &RoTxn<'_>, id: EntityId) -> Result<()> {
        crate::workspace_roster::guard_goal_delete(store, txn, id)
    }

    fn retire_goal_for_delete(
        &self,
        vault: &crate::Vault,
        txn: &mut RwTxn<'_>,
        id: EntityId,
    ) -> Result<()> {
        crate::workspace_roster::retire_goal_for_delete(vault, txn, id)
    }

    fn guard_batch_identity_delete_in_txn(
        &self,
        store: &Store,
        txn: &RoTxn<'_>,
        id: &EntityId,
    ) -> Result<()> {
        crate::identity_topology::guard_batch_identity_delete_in_txn(store, txn, id)
    }

    fn deindex_project_room(
        &self,
        store: &Store,
        txn: &mut RwTxn<'_>,
        id: &EntityId,
    ) -> Result<(bool, bool, Vec<EntityId>)> {
        crate::workspace_roster::deindex_project_room(store, txn, id)
    }
}

impl StoreScopeStamps for EngineScopeStamps {
    fn retire_stamp(&self, store: &Store, txn: &mut RwTxn<'_>, id: EntityId) -> Result<()> {
        crate::federation::record_scope::retire_stamp(store, txn, id)
    }

    fn restamp_document_pointer(
        &self,
        store: &Store,
        txn: &mut RwTxn<'_>,
        id: EntityId,
        kind: u8,
        original: &[u8],
        pointer: &[u8],
    ) -> Result<()> {
        crate::federation::record_scope::restamp_document_pointer(
            store, txn, id, kind, original, pointer,
        )
    }

    fn stamp_blob_project(
        &self,
        store: &Store,
        txn: &mut RwTxn<'_>,
        id: EntityId,
        project: EntityId,
    ) -> Result<()> {
        crate::federation::record_scope::stamp_blob_project(store, txn, id, project)
    }

    fn restrict_stamp_in_txn(
        &self,
        store: &Store,
        txn: &mut RwTxn<'_>,
        id: EntityId,
        band: Sensitivity,
    ) -> Result<()> {
        crate::federation::record_scope::restrict_stamp_in_txn(store, txn, id, band)
    }

    fn settle_epoch_birth(
        &self,
        store: &Store,
        txn: &mut RwTxn<'_>,
        id: EntityId,
        world: EntityId,
        facet: EntityId,
    ) -> Result<()> {
        crate::federation::record_scope::settle_epoch_birth(store, txn, id, world, facet)
    }

    fn backfill_task_base(
        &self,
        store: &Store,
        txn: &mut RwTxn<'_>,
        id: EntityId,
        data: &[u8],
    ) -> Result<()> {
        crate::federation::record_scope::backfill_task_base(store, txn, id, data)
    }

    fn has_stored_position(&self, store: &Store, txn: &RoTxn<'_>, id: EntityId) -> Result<bool> {
        crate::federation::record_scope::has_stored_position(store, txn, id)
    }
}

impl StoreProjectWrites for EngineProjectWrites {
    fn refresh_project_frontiers(
        &self,
        store: &Store,
        txn: &mut RwTxn<'_>,
        posture: HostingPrivacyPosture,
        touched: &BTreeSet<EntityId>,
    ) -> Result<()> {
        crate::workspace_roster::refresh_project_frontiers(store, txn, posture, touched)
    }

    fn reconcile_project_rooms(
        &self,
        store: &Store,
        config: &VaultConfig,
        analyzer: &MultilingualAnalyzer,
        trusted: bool,
        txn: &mut RwTxn<'_>,
        touched: &BTreeSet<EntityId>,
    ) -> Result<()> {
        crate::workspace_roster::reconcile_project_rooms(
            store, config, analyzer, trusted, txn, touched,
        )
    }

    fn validate_local_leader_chat_turns(
        &self,
        store: &Store,
        txn: &RoTxn<'_>,
        turns: &BTreeSet<EntityId>,
    ) -> Result<()> {
        crate::workspace_roster::validate_local_leader_chat_turns(store, txn, turns)
    }

    fn capture_project_put(
        &self,
        store: &Store,
        txn: &RoTxn<'_>,
        id: EntityId,
        kind: u8,
        data: &[u8],
    ) -> Result<Vec<(EntityId, Vec<u8>)>> {
        crate::workspace_roster::capture_project_put(store, txn, id, kind, data)
    }

    fn guard_goal_claim_put(
        &self,
        store: &Store,
        txn: &RoTxn<'_>,
        id: EntityId,
        incoming: Option<&ClaimBody>,
        bytes: &[u8],
        replicated: bool,
    ) -> Result<()> {
        crate::workspace_roster::guard_goal_claim_put(store, txn, id, incoming, bytes, replicated)
    }

    fn guard_goal_pointer_put(
        &self,
        store: &Store,
        txn: &RoTxn<'_>,
        id: EntityId,
        bytes: &[u8],
        replicated: bool,
    ) -> Result<()> {
        crate::workspace_roster::guard_goal_pointer_put(store, txn, id, bytes, replicated)
    }

    fn normalize_project_body(
        &self,
        store: &Store,
        txn: &RoTxn<'_>,
        id: EntityId,
        bytes: &[u8],
        posture: HostingPrivacyPosture,
    ) -> Result<Vec<u8>> {
        crate::workspace_roster::normalize_project_body(store, txn, id, bytes, posture)
    }

    fn validate_project_body(&self, id: EntityId, bytes: &[u8]) -> Result<Vec<EntityId>> {
        crate::workspace_roster::validate_project_body(id, bytes)
    }

    fn validate_project_transition(
        &self,
        store: &Store,
        txn: &RoTxn<'_>,
        id: EntityId,
        kind: u8,
        bytes: &[u8],
        posture: HostingPrivacyPosture,
    ) -> Result<()> {
        crate::workspace_roster::validate_project_transition(store, txn, id, kind, bytes, posture)
    }

    fn note_project_proof(
        &self,
        store: &Store,
        txn: &mut RwTxn<'_>,
        id: EntityId,
        kind: u8,
        data: &[u8],
    ) -> Result<()> {
        crate::workspace_roster::note_project_proof(store, txn, id, kind, data)
    }

    fn validate_room_body(
        &self,
        store: &Store,
        txn: &RoTxn<'_>,
        id: EntityId,
        data: &[u8],
    ) -> Result<()> {
        crate::workspace_roster::validate_room_body(store, txn, id, data)
    }

    fn root_project_in(&self, store: &Store, txn: &RoTxn<'_>) -> Result<Option<EntityId>> {
        crate::workspace_roster::root_project_in(store, txn)
    }

    fn project_mint_gate_refs_in_txn(
        &self,
        vault: &crate::Vault,
        txn: &RoTxn<'_>,
    ) -> Result<HashSet<GateDecisionId>> {
        crate::workspace_roster::project_mint_gate_refs_in_txn(vault, txn)
    }
}
