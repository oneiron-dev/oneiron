//! The record-scope stamp hooks the store layer's write and erase paths run,
//! supplied by the engine when a store opens.

use heed::{RoTxn, RwTxn};
use oneiron_authority::federation::Sensitivity;

use crate::entity_id::EntityId;
use crate::error::Result;
use crate::store::Store;

/// The engine's record-scope stamp hooks. A store holds one implementation
/// from the moment it is assembled (see [`crate::store::StoreHooks`]). The
/// store layer calls each method at the point where it called the engine
/// function of the same name, with the same arguments, and keeps its result.
pub trait StoreScopeStamps: Send + Sync {
    /// The engine's `federation::record_scope::retire_stamp`.
    fn retire_stamp(&self, store: &Store, txn: &mut RwTxn<'_>, id: EntityId) -> Result<()>;

    /// The engine's `federation::record_scope::restamp_document_pointer`.
    fn restamp_document_pointer(
        &self,
        store: &Store,
        txn: &mut RwTxn<'_>,
        id: EntityId,
        kind: u8,
        original: &[u8],
        pointer: &[u8],
    ) -> Result<()>;

    /// The engine's `federation::record_scope::stamp_blob_project`.
    fn stamp_blob_project(
        &self,
        store: &Store,
        txn: &mut RwTxn<'_>,
        id: EntityId,
        project: EntityId,
    ) -> Result<()>;

    /// The engine's `federation::record_scope::restrict_stamp_in_txn`.
    fn restrict_stamp_in_txn(
        &self,
        store: &Store,
        txn: &mut RwTxn<'_>,
        id: EntityId,
        band: Sensitivity,
    ) -> Result<()>;

    /// The engine's `federation::record_scope::settle_epoch_birth`.
    fn settle_epoch_birth(
        &self,
        store: &Store,
        txn: &mut RwTxn<'_>,
        id: EntityId,
        world: EntityId,
        facet: EntityId,
    ) -> Result<()>;

    /// The engine's `federation::record_scope::backfill_task_base`.
    fn backfill_task_base(
        &self,
        store: &Store,
        txn: &mut RwTxn<'_>,
        id: EntityId,
        data: &[u8],
    ) -> Result<()>;

    /// The engine's `federation::record_scope::has_stored_position`.
    fn has_stored_position(&self, store: &Store, txn: &RoTxn<'_>, id: EntityId) -> Result<bool>;
}
