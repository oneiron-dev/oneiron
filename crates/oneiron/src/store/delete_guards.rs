//! The delete guards the store layer's delete paths run, supplied by the
//! engine when a store opens.

use heed::{RoTxn, RwTxn};

use crate::entity_id::EntityId;
use crate::error::Result;
use crate::store::Store;

/// The engine's delete guards. A store holds one implementation from the
/// moment it is assembled: every open door takes it as a required input, so
/// no store exists without its guards. The store layer calls each method at
/// the point where it called the engine function of the same name, with the
/// same arguments, and keeps its result.
pub trait StoreDeleteGuards: Send + Sync {
    /// The engine's `workspace_roster::reject_audience_edit_delete`.
    fn reject_audience_edit_delete(
        &self,
        store: &Store,
        txn: &RoTxn<'_>,
        id: &EntityId,
    ) -> Result<()>;

    /// The engine's `federation::reject_ruling_delete`.
    fn reject_ruling_delete(&self, store: &Store, txn: &RoTxn<'_>, id: &EntityId) -> Result<()>;

    /// The engine's `workspace_roster::refuse_revision_delete`.
    fn refuse_revision_delete(&self, store: &Store, txn: &RoTxn<'_>, id: &EntityId) -> Result<()>;

    /// The engine's `workspace_roster::precheck_goal_delete`.
    fn precheck_goal_delete(
        &self,
        store: &Store,
        txn: &RoTxn<'_>,
        id: EntityId,
        gated: bool,
    ) -> Result<()>;

    /// The engine's `workspace_roster::guard_goal_delete`.
    fn guard_goal_delete(&self, store: &Store, txn: &RoTxn<'_>, id: EntityId) -> Result<()>;

    /// The engine's `workspace_roster::retire_goal_for_delete`.
    fn retire_goal_for_delete(
        &self,
        vault: &crate::Vault,
        txn: &mut RwTxn<'_>,
        id: EntityId,
    ) -> Result<()>;

    /// The engine's `identity_topology::guard_batch_identity_delete_in_txn`.
    fn guard_batch_identity_delete_in_txn(
        &self,
        store: &Store,
        txn: &RoTxn<'_>,
        id: &EntityId,
    ) -> Result<()>;

    /// The engine's `workspace_roster::deindex_project_room`.
    fn deindex_project_room(
        &self,
        store: &Store,
        txn: &mut RwTxn<'_>,
        id: &EntityId,
    ) -> Result<(bool, bool, Vec<EntityId>)>;
}
