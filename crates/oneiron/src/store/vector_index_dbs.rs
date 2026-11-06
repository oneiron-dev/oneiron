//! The engine's [`VectorIndexDbs`] for each of its store handles: the table
//! accessors and union flag of [`ManifestDbs`], and the engine checks the
//! vector index runs, each the engine function of the same purpose on that
//! handle.

use heed::{RoTxn, RwTxn};
use oneiron_store::overlay_db::OverlayDb;
use oneiron_store::vector_index::VectorIndexDbs;

use crate::entity_id::EntityId;
use crate::error::Result;
use crate::store::{CoreDbs, ManifestDbs, SessionStoreView, Store, StoreRead};

macro_rules! engine_vector_index_dbs {
    ($($handle:ty),+ $(,)?) => {
        $(
            impl VectorIndexDbs for $handle {
                fn index_vectors(&self) -> &OverlayDb {
                    ManifestDbs::vectors(self)
                }

                fn index_neighbors(&self) -> &OverlayDb {
                    ManifestDbs::hnsw_neighbors(self)
                }

                fn index_meta(&self) -> &OverlayDb {
                    ManifestDbs::hnsw_meta(self)
                }

                fn index_reads_union(&self) -> bool {
                    ManifestDbs::is_union(self)
                }

                fn index_entity_present(&self, txn: &RoTxn<'_>, id: &EntityId) -> Result<bool> {
                    crate::ports::EntityStoreRead::port_entity_present(self, txn, id)
                }

                fn index_any_pending_walk(&self, txn: &RoTxn<'_>) -> Result<bool> {
                    crate::ports::any_pending_walk(self, txn)
                }

                fn index_is_archived(&self, txn: &RoTxn<'_>, id: &EntityId) -> Result<bool> {
                    crate::vault_cleanup::is_archived_in_txn(self, txn, id)
                }

                fn index_is_stale(&self, txn: &RoTxn<'_>, id: &EntityId) -> Result<bool> {
                    crate::ports::stale_in_txn(self, txn, id)
                }

                fn index_clear_embedding_devices(&self, wtxn: &mut RwTxn<'_>) -> Result<()> {
                    crate::embed::clear_all_embedding_devices_in_txn(self, wtxn)
                }
            }
        )+
    };
}

engine_vector_index_dbs!(Store, StoreRead<'_>, SessionStoreView<'_>, CoreDbs<'_>);
