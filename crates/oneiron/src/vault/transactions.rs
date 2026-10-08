//! Vault maintenance, learned-at range scans, transaction helpers and sync state.

use super::Vault;
use super::entities::MAX_LEARNED_RANGE_RESULTS;
use crate::batch::EntityMetadataHeader;
use crate::edge::EdgeKind;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::hnsw;
use crate::maintain::MaintenanceBuilder;
use crate::ports::EdgeStoreRead;
use crate::ports::EntityStoreRead;
use crate::store::{EMBEDDING_TRANSFORM_KEY, MODEL_ID_KEY, validate_embedding_model_id};

/// Cap for `sync_state_keys_with_prefix` to prevent unbounded allocation when
/// a pathological prefix scans a very large sync_state database.
#[cfg(feature = "sync")]
const MAX_SYNC_STATE_KEYS: usize = 10_000;

/// Generic sync diagnostics may not edit the inputs to an authority fold.
/// Authority-owned writers use their own validated doors and advance the
/// snapshot generation in the same transaction as their row changes.
#[cfg(feature = "sync")]
fn check_generic_sync_state_key(key: &str) -> Result<()> {
    if key.starts_with("authlog:") || key.starts_with("peerauth:") {
        return Err(Error::InvalidConfig(
            "authority-owned sync_state key requires its authority door".to_owned(),
        ));
    }
    Ok(())
}

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
        Ok(self.store.port_entity_record(&rtxn, id)?.is_some())
    }

    /// Checks if a directed edge exists in the LMDB vault.
    pub fn edge_exists(&self, src: &EntityId, kind: EdgeKind, tgt: &EntityId) -> Result<bool> {
        let rtxn = self.store.env.read_txn()?;
        Ok(self.store.port_edge_get(&rtxn, src, kind, tgt)?.is_some())
    }

    /// Returns the `learned_at` timestamp from an entity's header (bytes 17-24).
    pub fn get_learned_at(&self, id: &EntityId) -> Result<u64> {
        let rtxn = self.store.env.read_txn()?;
        let raw = self
            .store
            .port_entity_record(&rtxn, id)?
            .map(|row| row.encode())
            .ok_or(Error::EntityNotFound)?;
        let header =
            EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
        Ok(header.learned_at)
    }

    /// Returns the greatest `learned_at` timestamp present in the temporal index.
    pub fn latest_learned_at(&self) -> Result<Option<u64>> {
        let txn = self.store.env.read_txn()?;
        self.store
            .port_entity_timeline(
                &txn,
                crate::ports::TimelineQuery {
                    reverse: true,
                    ..Default::default()
                },
            )?
            .next()
            .transpose()
            .map(|row| row.map(|row| row.timestamp))
    }

    /// Returns the greatest `learned_at` timestamp whose entity type is not excluded.
    pub fn latest_learned_at_excluding_entity_types(
        &self,
        excluded_types: &[u8],
    ) -> Result<Option<u64>> {
        let txn = self.store.env.read_txn()?;
        for row in self.store.port_entity_timeline(
            &txn,
            crate::ports::TimelineQuery {
                reverse: true,
                ..Default::default()
            },
        )? {
            let row = row?;
            let entity = self
                .store
                .port_entity_record(&txn, &row.id)?
                .ok_or(Error::CorruptedIndex("temporal learned dangling entity"))?;
            if !excluded_types.contains(&entity.entity_type) {
                return Ok(Some(row.timestamp));
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
        let txn = self.store.env.read_txn()?;
        let query = crate::ports::TimelineQuery {
            start: std::ops::Bound::Included(start),
            end: std::ops::Bound::Excluded(end),
            ..Default::default()
        };
        let mut ids = Vec::new();
        for row in self.store.port_entity_timeline(&txn, query)? {
            if ids.len() >= MAX_LEARNED_RANGE_RESULTS {
                return Err(Error::IndexOverflow("entities_in_learned_range"));
            }
            ids.push(row?.id);
        }
        Ok(ids)
    }

    /// Atomically switches embedding spaces, invalidates in-flight async-fill tokens, and schedules every embeddable record for refill.
    ///
    /// Claims and epoch summaries are queued for the embedding worker. Every
    /// other record that held a vector is embedded again at idle from its
    /// published revision, which stays as it is
    /// ([`Self::refresh_indexed_at_idle`]).
    ///
    /// A vault already pinned to `new_model` is left as it is. A move to
    /// another model drops the stored embedding transform with the old
    /// model's vectors.
    pub fn begin_embedding_migration(&mut self, new_model: &str) -> Result<()> {
        self.swap_embedding_space(new_model, None, false)
    }

    /// [`Self::begin_embedding_migration`] to a model and the embedding
    /// transform the host now declares, both repinned in the same
    /// transaction. Swaps when either differs from what the vault holds.
    pub fn migrate_embedding_space(&mut self, new_model: &str, transform: &str) -> Result<()> {
        self.swap_embedding_space(new_model, Some(transform), false)
    }

    /// The same atomic swap under the pins the vault already holds: every
    /// vector dropped and every embeddable record scheduled again.
    ///
    /// For a host whose embedding output changed in a way neither pin names.
    /// Requires the vault's configured embedding model.
    pub fn refill_embedding_space(&mut self) -> Result<()> {
        let model = self.config.embedding_model.clone().ok_or_else(|| {
            Error::InvalidConfig("refilling the embedding space requires an embedding model".into())
        })?;
        let transform = self.config.embedding_transform.clone();
        self.swap_embedding_space(&model, transform.as_deref(), true)
    }

    /// Checks a transform the host only learns after open — a local model
    /// whose files arrive after the vault opened — against the pinned one:
    /// adopted where none is pinned, refused (`EmbeddingTransformChanged`)
    /// where another is.
    pub fn adopt_embedding_transform(&self, transform: &str) -> Result<()> {
        self.with_write_txn(|wtxn| {
            crate::store::admit_embedding_transform_in_txn(&self.store, wtxn, transform)
        })
    }

    /// `transform: None` keeps the stored transform under the same model and
    /// drops it under another. `refill` swaps even when nothing differs.
    ///
    /// Every success leaves this handle on the pins the vault holds, a vault
    /// already there included: a handle another process migrated past is
    /// current again, and no vector is dropped for it.
    fn swap_embedding_space(
        &mut self,
        new_model: &str,
        transform: Option<&str>,
        refill: bool,
    ) -> Result<()> {
        let held = self.with_write_txn(|wtxn| {
            self.swap_embedding_space_in_txn(wtxn, new_model, transform, refill)
        })?;
        self.config.embedding_model = Some(new_model.to_owned());
        self.config.embedding_transform = held;
        Ok(())
    }

    /// The swap itself, in the caller's transaction. Returns the transform the
    /// vault holds after it.
    pub(crate) fn swap_embedding_space_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        new_model: &str,
        transform: Option<&str>,
        refill: bool,
    ) -> Result<Option<String>> {
        validate_embedding_model_id(new_model)?;
        let stored_utf8 = |key: &[u8], what: &'static str| -> Result<Option<String>> {
            self.store
                .hnsw_meta
                .get(&*wtxn, key)?
                .map(|raw| {
                    std::str::from_utf8(&raw)
                        .map(str::to_owned)
                        .map_err(|_| Error::CorruptedIndex(what))
                })
                .transpose()
        };
        let same_model = stored_utf8(MODEL_ID_KEY, "model id")?.as_deref() == Some(new_model);
        let stored_transform = stored_utf8(EMBEDDING_TRANSFORM_KEY, "embedding transform")?;
        let same_transform = transform.is_none() || stored_transform.as_deref() == transform;
        if same_model && same_transform && !refill {
            return Ok(stored_transform);
        }
        self.store
            .hnsw_meta
            .put(wtxn, MODEL_ID_KEY, new_model.as_bytes())?;
        let pinned_transform = match transform {
            Some(transform) => {
                self.store
                    .hnsw_meta
                    .put(wtxn, EMBEDDING_TRANSFORM_KEY, transform.as_bytes())?;
                Some(transform.to_owned())
            }
            None if same_model => stored_transform,
            None => {
                self.store.hnsw_meta.delete(wtxn, EMBEDDING_TRANSFORM_KEY)?;
                None
            }
        };
        // What the worker does not refill is refilled at idle from its
        // published revision; marked while the vectors still say who had one.
        crate::vault::entity_revision::schedule_vector_refills(self, wtxn)?;
        hnsw::clear_hnsw_graph_in_txn(&self.store, wtxn)?;
        hnsw::increment_vector_version(&self.store, wtxn)?;
        hnsw::increment_embedding_model_epoch(&self.store, wtxn)?;
        // The sweep below queues the work where the build has a queue. A
        // build without one marks the records only, and leaves the queueing
        // to the next serving open, which runs it from this marker (cold
        // attach).
        if cfg!(feature = "sync") {
            self.store
                .hnsw_meta
                .delete(wtxn, crate::embed::COLD_ATTACH_PENDING_KEY)?;
        } else {
            self.store
                .hnsw_meta
                .put(wtxn, crate::embed::COLD_ATTACH_PENDING_KEY, b"1")?;
        }
        crate::vault::entity_revision::drop_staged_vectors(&self.store, wtxn)?;
        crate::embed::remark_all_embeddable_pending_in_txn(
            self,
            wtxn,
            crate::embed::EMBED_PRIORITY_BACKFILL,
        )?;
        Ok(pinned_transform)
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
        let (result, postcommit) = {
            let _active_write_txn = crate::store::active_write_txn_guard();
            let vad_scope = crate::batch::VadPostcommitScope::new(self, &wtxn);
            let result = f(&mut wtxn)?;
            (result, vad_scope.finish())
        };
        let approved_vad_ids =
            self.resolved_dreamer_vad_approvals_in_txn(&wtxn, postcommit.vad_ids)?;
        wtxn.commit().map_err(Error::from)?;
        self.store.notify_attempt_observers();
        if postcommit.proactivity_changed {
            self.store.notify_proactivity_changes();
        }
        // Approval is durable now. The canonical consolidator opens its own
        // writer; its failure is returned without rolling back Approved. The
        // clock is observed only when there is an approval to consolidate.
        if !approved_vad_ids.is_empty() {
            let now = self.store.clock.now_recorded_at();
            for id in approved_vad_ids {
                self.consolidate_claim_vad_now(&id, now)?;
            }
        }
        Ok(result)
    }

    /// Reads a value from the sync_state database for sync integration tests
    /// and diagnostics.
    ///
    /// Production bridge code uses direct transactional access so multi-key
    /// sync-state updates stay atomic. `key` must fall under a declared
    /// `side_table` `SyncState` table (see `side_table::host_declared_sync_state`):
    /// every generic host door checks the same declaration list a bound
    /// `SideTable` is checked against at compile time.
    #[doc(hidden)]
    #[cfg(feature = "sync")]
    pub fn sync_state_get(&self, key: &str) -> Result<Option<Vec<u8>>> {
        crate::side_table::host_declared_sync_state(key)?;
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
        crate::side_table::host_declared_sync_state(key)?;
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
    /// sync-state updates stay atomic. Refuses an undeclared key (see
    /// [`Self::sync_state_get`]) instead of writing it.
    #[doc(hidden)]
    #[cfg(feature = "sync")]
    pub fn sync_state_put(&self, key: &str, value: &[u8]) -> Result<()> {
        check_generic_sync_state_key(key)?;
        self.with_write_txn(|wtxn| {
            crate::side_table::host_sync_state_put(&self.store, wtxn, key, value)
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
        check_generic_sync_state_key(key)?;
        crate::side_table::host_sync_state_put(&self.store, wtxn, key, value)
    }

    /// Deletes a key from the sync_state database for diagnostics and
    /// server-side sync metadata cleanup.
    #[doc(hidden)]
    #[cfg(feature = "sync")]
    pub fn sync_state_delete(&self, key: &str) -> Result<bool> {
        check_generic_sync_state_key(key)?;
        self.with_write_txn(|wtxn| {
            crate::side_table::host_sync_state_delete(&self.store, wtxn, key)
        })
    }

    /// Lists all keys with the given prefix in sync_state for sync integration
    /// tests and diagnostics.
    ///
    /// Production bridge code uses direct transactional access so multi-key
    /// sync-state updates stay atomic. `prefix` must overlap a declared
    /// `SyncState` table — a family prefix shorter than the declared one
    /// (`"rm:"` over `rm:w:` and `rmp:w:`) or a single leading byte from a
    /// whole-table diagnostic sweep are both accepted; see
    /// [`side_table::host_declared_sync_state_scan`].
    #[doc(hidden)]
    #[cfg(feature = "sync")]
    pub fn sync_state_keys_with_prefix(&self, prefix: &str) -> Result<Vec<String>> {
        crate::side_table::host_declared_sync_state_scan(prefix)?;
        let rtxn = self.store.env.read_txn()?;
        let mut keys = Vec::new();
        let iter = self.store.sync_state.prefix_iter(&rtxn, prefix)?;
        for entry in iter {
            // Cap check BEFORE push — matches scan_edges semantics.
            if keys.len() >= MAX_SYNC_STATE_KEYS {
                return Err(Error::IndexOverflow("sync_state_keys_with_prefix"));
            }
            let (k, _) = entry?;
            crate::side_table::host_declared_sync_state(&k)?;
            keys.push(k.to_string());
        }
        Ok(keys)
    }

    /// Stream host-owned rows while retaining the caller's write snapshot.
    /// Used to rebuild derived host indexes without losing concurrent meter facts.
    /// `prefix` must overlap a declared `SyncState` table, the same as
    /// [`Self::sync_state_keys_with_prefix`].
    #[doc(hidden)]
    #[cfg(feature = "sync")]
    pub fn sync_state_visit_prefix_in_write_txn<E>(
        &self,
        txn: &heed::RwTxn<'_>,
        prefix: &str,
        mut visit: impl FnMut(&str, &[u8]) -> std::result::Result<(), E>,
    ) -> std::result::Result<(), E>
    where
        E: From<Error>,
    {
        crate::side_table::host_declared_sync_state_scan(prefix).map_err(E::from)?;
        for row in self.store.sync_state.prefix_iter(txn, prefix)? {
            let (key, value) = row?;
            crate::side_table::host_declared_sync_state(&key).map_err(E::from)?;
            visit(&key, &value)?;
        }
        Ok(())
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

    /// The entity-put audit row count for `id`
    /// (`ports::ChangeLogStore::port_changelog_list_by_entity`, `batch/put_apply/apply.rs`'s
    /// `audit_entity_put_in_txn` call). Only the batch entry writes this row,
    /// so an integration test pins that a fixture went through it by reading
    /// this count; `ports` is crate-private, so `tests/it` needs a door.
    #[doc(hidden)]
    #[cfg(feature = "test-support")]
    pub fn entity_put_audit_count_for_test(&self, id: &EntityId) -> Result<usize> {
        use crate::ports::ChangeLogStore;
        let rtxn = self.store.env.read_txn()?;
        Ok(self
            .store
            .port_changelog_list_by_entity(&rtxn, id, 100)?
            .len())
    }
}

#[cfg(all(test, feature = "sync"))]
mod sync_scan_tests;
