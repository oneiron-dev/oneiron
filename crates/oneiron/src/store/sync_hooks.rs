//! The sync hooks the store layer's write, erase and maintenance paths run in
//! a build with sync, supplied by the engine when a store opens.

use std::collections::BTreeSet;

use heed::{RoTxn, RwTxn};
use loro::LoroDoc;

use crate::deletion::delete_bearing_update::DeleteBearingUpdate;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::store::Store;
use crate::store::window_rows::CarrierRemoval;

/// The engine's sync hooks. A store holds one implementation from the moment
/// it is assembled (see [`crate::store::StoreHooks`]). The store layer calls
/// each method at the point where it called the engine function its
/// documentation names, with the same arguments, and keeps its result.
pub(crate) trait StoreSyncHooks: Send + Sync {
    /// The engine's `sync::federation_burst::check_active_in_txn`.
    fn check_federation_imports_in_txn(&self, vault: &crate::Vault, txn: &RoTxn<'_>) -> Result<()>;

    /// The engine's `sync::queue::push_embed_job_in_txn`.
    fn push_embed_job_in_txn(
        &self,
        store: &Store,
        wtxn: &mut RwTxn<'_>,
        entity_id: &EntityId,
        priority: u8,
    ) -> Result<()>;

    /// The engine's `sync::queue::delete_embed_job_in_txn`.
    fn delete_embed_job_in_txn(
        &self,
        store: &Store,
        wtxn: &mut RwTxn<'_>,
        entity_id: &EntityId,
    ) -> Result<bool>;

    /// The engine's `sync::queue::queued_window_labels_in_txn`.
    fn queued_window_labels_in_txn(
        &self,
        vault: &crate::Vault,
        txn: &RoTxn<'_>,
    ) -> Result<BTreeSet<String>>;

    /// The engine's `sync::queue::queued_window_update_count_in_txn`.
    fn queued_window_update_count_in_txn(
        &self,
        store: &Store,
        txn: &RoTxn<'_>,
        window_key: &str,
    ) -> Result<usize>;

    /// The engine's `sync::queue::scrub_window_updates_in_txn`.
    fn scrub_window_updates_in_txn(
        &self,
        vault: &crate::Vault,
        wtxn: &mut RwTxn<'_>,
        window_key: &str,
    ) -> Result<u32>;

    /// The engine's `sync::residence::indexed_windows_in_txn`.
    fn indexed_windows_in_txn(
        &self,
        store: &Store,
        txn: &RoTxn<'_>,
        prefix: &str,
    ) -> Result<BTreeSet<String>>;

    /// The engine's `sync::row_birth::actor_erase::birth_carriers_remain_in_txn`.
    fn birth_carriers_remain_in_txn(
        &self,
        vault: &crate::Vault,
        txn: &RoTxn<'_>,
        actors: &BTreeSet<EntityId>,
    ) -> Result<bool>;

    /// The engine's `sync::bridge::persist_window_update_in_txn`.
    fn persist_window_update_in_txn(
        &self,
        vault: &crate::Vault,
        wtxn: &mut RwTxn<'_>,
        window_key: &str,
        update_bytes: &[u8],
    ) -> Result<()>;

    /// The engine's `sync::window::merge_window_heads`.
    fn merge_window_heads(&self, doc: &LoroDoc) -> Result<()>;

    /// The engine's `sync::selector::erase_carried_born_with_in_txn`, an
    /// entity side-row eraser of `deletion::derived_rows`.
    fn erase_carried_born_with_in_txn(
        &self,
        store: &Store,
        wtxn: &mut RwTxn<'_>,
        id: &EntityId,
    ) -> Result<()>;

    /// The engine's `sync::federation_burst::erase_retained_copies_in_txn`, an
    /// entity side-row eraser of `deletion::derived_rows`.
    fn erase_retained_copies_in_txn(
        &self,
        store: &Store,
        txn: &mut RwTxn<'_>,
        id: &EntityId,
    ) -> Result<()>;

    /// The engine's `sync::window::apply_tombstone_to_window_doc`.
    fn apply_tombstone_to_window_doc(
        &self,
        doc: &LoroDoc,
        id: &EntityId,
        raw_value: &[u8],
    ) -> Result<()>;

    /// The engine's `sync::window::mark_removed_carriers_first`.
    fn mark_removed_carriers_first(
        &self,
        vault: &crate::Vault,
        path: CarrierRemoval,
        carriers: &[(EntityId, Vec<u8>)],
    ) -> Result<()>;

    /// The engine's `sync::queue::push_delete_bearing_in_txn`.
    fn push_delete_bearing_in_txn(
        &self,
        vault: &crate::Vault,
        wtxn: &mut RwTxn<'_>,
        window_key: &str,
        update: &DeleteBearingUpdate,
    ) -> Result<u64>;

    /// The engine's `sync::documents::compact`.
    fn compact_document(&self, vault: &crate::Vault, id: EntityId, erased: bool) -> Result<()>;
}
