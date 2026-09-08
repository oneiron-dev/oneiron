//! Vault maintenance, learned-at range scans, transaction helpers and sync state.

use super::Vault;
use super::entities::{MAX_LEARNED_RANGE_RESULTS, require_key_len};
use crate::batch::EntityMetadataHeader;
use crate::edge::EdgeKind;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::hnsw;
use crate::maintain::MaintenanceBuilder;
use crate::store::{MODEL_ID_KEY, Store, validate_embedding_model_id};

/// Cap for `sync_state_keys_with_prefix` to prevent unbounded allocation when
/// a pathological prefix scans a very large sync_state database.
#[cfg(feature = "sync")]
const MAX_SYNC_STATE_KEYS: usize = 10_000;

impl Vault {
    // NOTE (ONE-1133): the bare non-txn `purge_entity_active_store` wrapper
    // was removed — both sync replay surfaces now route through the
    // reason-aware `apply_replayed_tombstone`, and a bare purge entry point
    // would be an invitation to bypass the ARCH-0038 reason semantics.

    // -----------------------------------------------------------------
    // ARCH-0050 R6 L2 code-memory doors (ONE-1608).
    //
    // Every wrapper here opens ONE transaction, delegates to the internal
    // `crate::code_memory` implementation, and commits exactly once on
    // success. None exposes `Store`, `RoTxn`, or `RwTxn`; the public
    // contract suite reaches only these methods.
    // -----------------------------------------------------------------

    // Read/write/list helpers intentionally remain behind `feature = "sync"`
    // instead of `cfg(test)` because the sync bridge regression suite is an
    // integration test crate. Production bridge code still uses direct
    // transactional `sync_state` access when multiple keys must update
    // atomically.

    // ─── Tree Query API ───────────────────────────────────────

    /// Creates a maintenance builder for index and cache upkeep operations.
    pub fn maintain(&self) -> MaintenanceBuilder<'_> {
        MaintenanceBuilder::new(self)
    }

    /// Checks if an entity exists in the LMDB vault.
    pub fn entity_exists(&self, id: &EntityId) -> Result<bool> {
        let rtxn = self.store.env.read_txn()?;
        Ok(self.store.entities.get(&rtxn, id.as_bytes())?.is_some())
    }

    /// Checks if a directed edge exists in the LMDB vault.
    pub fn edge_exists(&self, src: &EntityId, kind: EdgeKind, tgt: &EntityId) -> Result<bool> {
        let key = Store::encode_edge_key(src, kind, tgt);
        let rtxn = self.store.env.read_txn()?;
        Ok(self.store.edges_out.get(&rtxn, &key)?.is_some())
    }

    /// Returns the `learned_at` timestamp from an entity's header (bytes 17-24).
    pub fn get_learned_at(&self, id: &EntityId) -> Result<u64> {
        let rtxn = self.store.env.read_txn()?;
        let raw = self
            .store
            .entities
            .get(&rtxn, id.as_bytes())?
            .ok_or(Error::EntityNotFound)?;
        let header =
            EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
        Ok(header.learned_at)
    }

    /// Returns the greatest `learned_at` timestamp present in the temporal index.
    pub fn latest_learned_at(&self) -> Result<Option<u64>> {
        let rtxn = self.store.env.read_txn()?;
        let Some((key, _)) = self.store.temporal_learned.last(&rtxn)? else {
            return Ok(None);
        };
        require_key_len(&key, 24, "temporal learned key")?;
        Ok(Some(u64::from_be_bytes(key[..8].try_into().map_err(
            |_| Error::CorruptedIndex("temporal learned key"),
        )?)))
    }

    /// Returns the greatest `learned_at` timestamp whose entity type is not excluded.
    pub fn latest_learned_at_excluding_entity_types(
        &self,
        excluded_types: &[u8],
    ) -> Result<Option<u64>> {
        let rtxn = self.store.env.read_txn()?;
        for entry in self.store.temporal_learned.rev_iter(&rtxn)? {
            let (key, _) = entry?;
            require_key_len(&key, 24, "temporal learned key")?;
            let learned_at = u64::from_be_bytes(
                key[..8]
                    .try_into()
                    .map_err(|_| Error::CorruptedIndex("temporal learned key"))?,
            );
            let id = EntityId::from_bytes(
                key[8..24]
                    .try_into()
                    .map_err(|_| Error::CorruptedIndex("temporal learned key"))?,
            )
            .map_err(|_| Error::CorruptedIndex("temporal learned key"))?;
            let raw = self
                .store
                .entities
                .get(&rtxn, id.as_bytes())?
                .ok_or(Error::CorruptedIndex("temporal learned dangling entity"))?;
            let header =
                EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
            if !excluded_types.contains(&header.entity_type) {
                return Ok(Some(learned_at));
            }
        }
        Ok(None)
    }

    /// Returns entity IDs whose `learned_at` falls within `[start, end)`.
    ///
    /// Range-seeks the `temporal_learned` index by timestamp prefix.
    /// Returns an empty result when `start >= end`.
    pub fn entities_in_learned_range(&self, start: u64, end: u64) -> Result<Vec<EntityId>> {
        if start >= end {
            return Ok(Vec::new());
        }

        let rtxn = self.store.env.read_txn()?;
        let mut ids = Vec::new();
        let start_key = start.to_be_bytes();
        let end_key = end.to_be_bytes();
        for entry in self.store.temporal_learned.range(
            &rtxn,
            &(
                std::ops::Bound::Included(&start_key[..]),
                std::ops::Bound::Excluded(&end_key[..]),
            ),
        )? {
            let (key, _) = entry?;
            require_key_len(&key, 24, "temporal learned key")?;
            // Cap check BEFORE push so an exact-MAX result set returns Ok,
            // matching scan_edges semantics. Only an MAX+1-th in-range row
            // triggers IndexOverflow.
            if ids.len() >= MAX_LEARNED_RANGE_RESULTS {
                return Err(Error::IndexOverflow("entities_in_learned_range"));
            }
            let id = EntityId::from_bytes(
                key[8..24]
                    .try_into()
                    .map_err(|_| Error::CorruptedIndex("temporal learned key"))?,
            )
            .map_err(|_| Error::CorruptedIndex("temporal learned key"))?;
            ids.push(id);
        }
        Ok(ids)
    }

    /// Atomically switches embedding spaces, invalidates in-flight async-fill tokens, and schedules every persisted claim for refill.
    pub fn begin_embedding_migration(&mut self, new_model: &str) -> Result<()> {
        validate_embedding_model_id(new_model)?;
        let new_model = new_model.to_owned();
        let changed = self.with_write_txn(|wtxn| {
            match self.store.hnsw_meta.get(&*wtxn, MODEL_ID_KEY)? {
                Some(raw)
                    if std::str::from_utf8(&raw)
                        .map_err(|_| Error::CorruptedIndex("model id"))?
                        == new_model =>
                {
                    return Ok(false);
                }
                Some(_) | None => {}
            }
            self.store
                .hnsw_meta
                .put(wtxn, MODEL_ID_KEY, new_model.as_bytes())?;
            hnsw::clear_hnsw_graph_in_txn(&self.store, wtxn)?;
            hnsw::increment_vector_version(&self.store, wtxn)?;
            hnsw::increment_embedding_model_epoch(&self.store, wtxn)?;
            crate::embed::remark_all_claims_pending_in_txn(
                self,
                wtxn,
                crate::embed::EMBED_PRIORITY_BACKFILL,
            )?;
            Ok(true)
        })?;
        if changed {
            self.config.embedding_model = Some(new_model);
        }
        Ok(())
    }

    /// Executes a closure within a single LMDB write transaction.
    ///
    /// The transaction commits on `Ok(())` return and rolls back on `Err`.
    /// Used by the sync layer to atomically write entity data + pending-mirror markers.
    /// As with [`Self::try_with_write_txn`], VAD postcommit errors are returned
    /// after the approval is durable, not as a rollback of the closure.
    pub fn with_write_txn<F, T>(&self, f: F) -> Result<T>
    where
        F: FnOnce(&mut heed::RwTxn<'_>) -> Result<T>,
    {
        self.try_with_write_txn(f)
    }

    /// Executes a closure within a single LMDB write transaction and allows
    /// callers to return their own error type.
    ///
    /// The transaction commits on `Ok` return and rolls back on `Err`.
    /// Explicit Dreamer approvals applied through [`Self::batch_in`] run VAD
    /// consolidation after commit. A postcommit error retains Approved; retry
    /// [`Self::consolidate_claim_vad_now`] to finish that work.
    pub fn try_with_write_txn<F, T, E>(&self, f: F) -> std::result::Result<T, E>
    where
        F: FnOnce(&mut heed::RwTxn<'_>) -> std::result::Result<T, E>,
        E: From<Error>,
    {
        let mut wtxn = self.store.env.write_txn().map_err(Error::from)?;
        let (result, pending_vad_ids) = {
            let _active_write_txn = crate::store::active_write_txn_guard();
            let vad_scope = crate::batch::VadPostcommitScope::new(self, &wtxn);
            let result = f(&mut wtxn)?;
            (result, vad_scope.finish())
        };
        let approved_vad_ids =
            self.resolved_dreamer_vad_approvals_in_txn(&wtxn, pending_vad_ids)?;
        wtxn.commit().map_err(Error::from)?;
        // Approval is durable now. The canonical consolidator opens its own
        // writer; its failure is returned without rolling back Approved.
        let now = crate::unix_seconds_now();
        for id in approved_vad_ids {
            self.consolidate_claim_vad_now(&id, now)?;
        }
        Ok(result)
    }

    /// Reads a value from the sync_state database for sync integration tests
    /// and diagnostics.
    ///
    /// Production bridge code uses direct transactional access so multi-key
    /// sync-state updates stay atomic.
    #[doc(hidden)]
    #[cfg(feature = "sync")]
    pub fn sync_state_get(&self, key: &str) -> Result<Option<Vec<u8>>> {
        let rtxn = self.store.env.read_txn()?;
        Ok(self
            .store
            .sync_state
            .get(&rtxn, key)?
            .map(|bytes| bytes.to_vec()))
    }

    /// Reads a value from `sync_state` using an existing write transaction.
    #[doc(hidden)]
    #[cfg(feature = "sync")]
    pub fn sync_state_get_in_write_txn(
        &self,
        wtxn: &heed::RwTxn<'_>,
        key: &str,
    ) -> Result<Option<Vec<u8>>> {
        Ok(self
            .store
            .sync_state
            .get(wtxn, key)?
            .map(|bytes| bytes.to_vec()))
    }

    /// Writes a value to the sync_state database for sync integration tests
    /// and diagnostics.
    ///
    /// Production bridge code uses direct transactional access so multi-key
    /// sync-state updates stay atomic.
    #[doc(hidden)]
    #[cfg(feature = "sync")]
    pub fn sync_state_put(&self, key: &str, value: &[u8]) -> Result<()> {
        self.with_write_txn(|wtxn| {
            self.store.sync_state.put(wtxn, key, value)?;
            Ok(())
        })
    }

    /// Writes a value to `sync_state` using an existing write transaction.
    #[doc(hidden)]
    #[cfg(feature = "sync")]
    pub fn sync_state_put_in_write_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        key: &str,
        value: &[u8],
    ) -> Result<()> {
        self.store.sync_state.put(wtxn, key, value)?;
        Ok(())
    }

    /// Deletes a key from the sync_state database for diagnostics and
    /// server-side sync metadata cleanup.
    #[doc(hidden)]
    #[cfg(feature = "sync")]
    pub fn sync_state_delete(&self, key: &str) -> Result<bool> {
        self.with_write_txn(|wtxn| self.store.sync_state.delete(wtxn, key))
    }

    /// Lists all keys with the given prefix in sync_state for sync integration
    /// tests and diagnostics.
    ///
    /// Production bridge code uses direct transactional access so multi-key
    /// sync-state updates stay atomic.
    #[doc(hidden)]
    #[cfg(feature = "sync")]
    pub fn sync_state_keys_with_prefix(&self, prefix: &str) -> Result<Vec<String>> {
        let rtxn = self.store.env.read_txn()?;
        let mut keys = Vec::new();
        let iter = self.store.sync_state.prefix_iter(&rtxn, prefix)?;
        for entry in iter {
            // Cap check BEFORE push — matches scan_edges semantics.
            if keys.len() >= MAX_SYNC_STATE_KEYS {
                return Err(Error::IndexOverflow("sync_state_keys_with_prefix"));
            }
            let (k, _) = entry?;
            keys.push(k.to_string());
        }
        Ok(keys)
    }

    /// Lists `sync_queue` rows with the given key prefix for sync
    /// integration tests and diagnostics (e.g. the `h:{seq:8BE}` hard-erase
    /// sweep family a replayed remote hard tombstone must enqueue).
    ///
    /// Production code uses direct transactional access so multi-key
    /// updates stay atomic.
    #[doc(hidden)]
    #[cfg(feature = "sync")]
    pub fn sync_queue_rows_with_prefix(&self, prefix: &[u8]) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
        let rtxn = self.store.env.read_txn()?;
        let mut rows = Vec::new();
        for entry in self.store.sync_queue.prefix_iter(&rtxn, prefix)? {
            // Cap check BEFORE push — matches scan_edges semantics.
            if rows.len() >= MAX_SYNC_STATE_KEYS {
                return Err(Error::IndexOverflow("sync_queue_rows_with_prefix"));
            }
            let (k, v) = entry?;
            rows.push((k.to_vec(), v.to_vec()));
        }
        Ok(rows)
    }
}
