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
pub(crate) use self::insert::{hnsw_insert_batched, run_pending_legacy_rebuild};
pub(crate) use self::keys::COUNT_KEY;
pub(crate) use self::rebuild::{
    build_hnsw_graph_from_snapshot, clear_hnsw_graph_in_txn, write_rebuilt_hnsw,
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
pub(crate) use self::delete::hnsw_deindex_probed;
#[cfg(test)]
pub(crate) use self::discipline::{
    mark_symmetric_links, read_legacy_snapshot_rebuilds, read_refresh_fallback_rebuilds,
};
#[cfg(test)]
pub(crate) use self::insert::{hnsw_insert, hnsw_insert_probed};
#[cfg(test)]
pub(crate) use self::keys::{
    DROPPED_REBUILDABLE_KEY, LEGACY_REBUILDS_KEY, REFRESH_FALLBACK_REBUILDS_KEY,
    SYMMETRIC_LINKS_KEY,
};

#[cfg(test)]
mod archive_tests;
#[cfg(test)]
mod tests;

// The flat hnsw.rs module used to provide these names to the sibling test
// modules through `use super::*`: only the children that own a test-used
// `pub(super)` item are globbed here (every other test-used hnsw name
// arrives through the `pub(crate)` re-exports above), and the crate names
// the tests name bare are repeated here because a parent cannot import a
// child's private imports. Together the tests resolve exactly as before.
#[cfg(test)]
use self::{entry_point::*, insert::*, keys::*, one_way::*, search::*, storage::*, types::*};
#[cfg(test)]
use crate::config::VaultConfig;
#[cfg(test)]
use crate::distance::cosine_distance;
#[cfg(test)]
use crate::entity_id::{ENTITY_ID_LEN, EntityId, parse_entity_id};
#[cfg(test)]
use crate::error::{Error, Result};
#[cfg(test)]
use crate::pipeline::ScoredEntity;
#[cfg(test)]
use crate::store::{EMBEDDING_MODEL_EPOCH_KEY, VECTOR_VERSION_KEY};
#[cfg(test)]
use heed::{RoTxn, RwTxn};
#[cfg(test)]
use std::collections::{HashMap, HashSet};

#[cfg(test)]
mod slim_graph_tests {
    use super::*;
    use crate::TimeRange;
    use crate::test_util::{embedding_test_config, entity, open_test_vault_with};

    #[test]
    fn dropped_write_is_single_graph_application() -> Result<()> {
        for discipline in [LinkDiscipline::Legacy, LinkDiscipline::Symmetric] {
            let (_dir, vault) = open_test_vault_with(embedding_test_config());
            let id = entity(50);
            vault.put_entity(&id, 1, TimeRange { start: 1, end: 1 }, 1, b"node")?;
            vault.with_write_txn(|txn| {
                if discipline == LinkDiscipline::Legacy {
                    vault.store.hnsw_meta.delete(txn, SYMMETRIC_LINKS_KEY)?;
                } else {
                    mark_symmetric_links(&vault.store, txn)?;
                }
                drop_rebuildable_hnsw(&vault.store, txn)?;
                // The landed production order: source row first, then hook.
                let vector = [1.0_f32, 0.0, 0.0, 0.0];
                let raw: Vec<u8> = vector.iter().flat_map(|v| v.to_le_bytes()).collect();
                vault.store.vectors.put(txn, id.as_bytes(), &raw)?;
                let mut ops = 0;
                hnsw_insert_probed(&vault.store, &vault.config, txn, &id, &vector, &mut ops)?;
                assert_eq!(ops, 1, "rebuild returns before insertion/refresh");
                assert!(!hnsw_is_dropped(&vault.store, txn)?);
                assert_eq!(read_link_discipline(&vault.store, txn)?, discipline);
                assert_eq!(read_count(&vault.store, txn)?, 1);
                assert_eq!(
                    load_neighbors(&vault.store, txn, &id)?,
                    Vec::<EntityId>::new()
                );
                Ok(())
            })?;
        }
        Ok(())
    }

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
