//! The engine's implementation of the store layer's hooks: each method
//! forwards to the engine function of the same name.

use heed::{RoTxn, RwTxn};
use oneiron_authority::federation::Sensitivity;

use crate::entity_id::EntityId;
use crate::error::Result;
use crate::store::{Store, StoreDeleteGuards, StoreHooks, StoreScopeStamps};

/// The hooks every vault's store opens with.
pub(crate) const ENGINE_STORE_HOOKS: StoreHooks = StoreHooks {
    delete_guards: &EngineDeleteGuards,
    scope_stamps: &EngineScopeStamps,
};

/// The engine's delete guards.
pub(crate) struct EngineDeleteGuards;

/// The engine's record-scope stamp hooks.
pub(crate) struct EngineScopeStamps;

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
