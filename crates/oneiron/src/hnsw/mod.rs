//! HNSW graph index over the persisted neighbor graph.

mod delete;
mod discipline;
mod entry_point;
mod insert;
mod keys;
mod one_way;
mod rebuild;
mod search;
mod slim_drop;
mod storage;
mod types;

pub(crate) use self::delete::hnsw_deindex;
pub(crate) use self::discipline::{LinkDiscipline, read_link_discipline};
pub(crate) use self::insert::{
    InsertPlan, hnsw_insert_batched, hnsw_insert_planned, run_pending_legacy_rebuild,
};
pub(crate) use self::keys::COUNT_KEY;
pub(crate) use self::rebuild::{
    build_hnsw_graph_from_snapshot, clear_hnsw_graph_in_txn, collect_vector_ids, write_rebuilt_hnsw,
};
pub(crate) use self::search::hnsw_search;
pub(crate) use self::slim_drop::{drop_rebuildable_hnsw, hnsw_is_dropped};
pub(crate) use self::storage::{
    has_population, hnsw_entity_count, increment_embedding_model_epoch, increment_vector_version,
    read_embedding_model_epoch, read_vector_version,
};
pub(crate) use self::types::RebuiltHnswGraph;

// Test-only paths (no production use outside `hnsw/`): the `#[cfg(test)]`
// re-export keeps `crate::hnsw::X` resolving for the test targets without
// leaving an unused import in the library build.
#[cfg(test)]
pub(crate) use self::insert::hnsw_insert;
#[cfg(test)]
pub(crate) use self::keys::DROPPED_REBUILDABLE_KEY;
#[cfg(test)]
use self::keys::SYMMETRIC_LINKS_KEY;

#[cfg(test)]
mod tests;

// The flat hnsw.rs module used to provide these names to the sibling test
// modules through `use super::*`: only the children that own a test-used
// `pub(super)` item are globbed here (every other test-used hnsw name
// arrives through the `pub(crate)` re-exports above), and the crate names
// the tests name bare are repeated here because a parent cannot import a
// child's private imports. Together the tests resolve exactly as before.
#[cfg(test)]
use self::{keys::*, one_way::*, storage::*};
#[cfg(test)]
use crate::entity_id::{ENTITY_ID_LEN, EntityId, parse_entity_id};
#[cfg(test)]
use crate::error::{Error, Result};
#[cfg(test)]
use crate::store::{EMBEDDING_MODEL_EPOCH_KEY, VECTOR_VERSION_KEY};
#[cfg(test)]
use heed::{RoTxn, RwTxn};

#[cfg(test)]
mod slim_graph_tests {
    use super::*;
    use crate::TimeRange;
    use crate::test_util::{embedding_test_config, entity, open_test_vault_with};

    #[test]
    fn dropped_marker_clear_is_atomic_with_full_graph() -> Result<()> {
        let (_dir, vault) = open_test_vault_with(embedding_test_config());
        let id = entity(50);
        vault.put_entity(&id, 1, TimeRange { start: 1, end: 1 }, 1, b"node")?;
        vault.put_vector(&id, &[1.0, 0.0, 0.0, 0.0])?;
        vault.with_write_txn(|txn| drop_rebuildable_hnsw(&vault.store, txn))?;
        let graph = {
            let txn = vault.store.env.read_txn()?;
            build_hnsw_graph_from_snapshot(
                &vault.store,
                &vault.config,
                &txn,
                &[id],
                LinkDiscipline::Symmetric,
            )?
        };
        let revision = vault.store.env.info().last_txn_id;
        {
            let mut txn = vault.store.env.write_txn()?;
            write_rebuilt_hnsw(&vault.store, &mut txn, &graph, LinkDiscipline::Symmetric)?;
            assert!(!hnsw_is_dropped(&vault.store, &txn)?);
            assert_eq!(read_count(&vault.store, &txn)?, 1);
            assert_eq!(read_entry_point(&vault.store, &txn)?, Some(id));
            assert_eq!(vault.store.hnsw_neighbors.len(&txn)?, 1);
            // Abort a fully staged graph write: neither shape nor clear lands.
        }
        assert_eq!(vault.store.env.info().last_txn_id, revision);
        {
            let txn = vault.store.env.read_txn()?;
            assert!(hnsw_is_dropped(&vault.store, &txn)?);
            assert_eq!(vault.store.hnsw_neighbors.len(&txn)?, 0);
            assert_eq!(read_count(&vault.store, &txn)?, 0);
            assert_eq!(read_entry_point(&vault.store, &txn)?, None);
        }
        vault.with_write_txn(|txn| {
            write_rebuilt_hnsw(&vault.store, txn, &graph, LinkDiscipline::Symmetric)
        })?;
        let txn = vault.store.env.read_txn()?;
        assert!(!hnsw_is_dropped(&vault.store, &txn)?);
        assert_eq!(read_count(&vault.store, &txn)?, 1);
        assert_eq!(vault.store.hnsw_neighbors.len(&txn)?, 1);
        assert_eq!(read_entry_point(&vault.store, &txn)?, Some(id));
        assert_eq!(
            read_link_discipline(&vault.store, &txn)?,
            LinkDiscipline::Symmetric
        );
        Ok(())
    }
}
