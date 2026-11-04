//! The engine's implementation of the store layer's delete guards: each
//! method forwards to the engine function of the same name.

use heed::{RoTxn, RwTxn};

use crate::entity_id::EntityId;
use crate::error::Result;
use crate::store::{Store, StoreDeleteGuards};

/// The delete guards every vault's store opens with.
pub(crate) struct EngineDeleteGuards;

/// The one instance the open doors pass.
pub(crate) static ENGINE_DELETE_GUARDS: EngineDeleteGuards = EngineDeleteGuards;

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
