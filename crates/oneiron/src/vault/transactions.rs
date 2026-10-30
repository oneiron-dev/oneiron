//! Vault maintenance, learned-at range scans, transaction helpers and sync state.

use super::Vault;
use crate::TimeRange;
use crate::batch::EntityMetadataHeader;
use crate::edge::EdgeKind;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::hnsw;
use crate::maintain::MaintenanceBuilder;
use crate::ports::EdgeStoreRead;
use crate::ports::EntityStoreRead;
use crate::ports::{IndexMetaKey, RetrievalIndexInventory};
use crate::store::{
    BackupWriteClass, Callback, EMBEDDING_TRANSFORM_KEY, MODEL_ID_KEY, validate_embedding_model_id,
};

/// Advisory threshold row for the sync-state and sync-queue prefix scans and
/// deletion's window update-key read: past it the scan raises one check and
/// reads on (rule 5). It bounds no result.
#[cfg(feature = "sync")]
pub(crate) const MAX_SYNC_STATE_KEYS: usize = 10_000;

/// Generic sync diagnostics may not edit the inputs to an authority fold.
/// Authority-owned writers use their own validated doors and advance the
/// snapshot generation in the same transaction as their row changes. Nor may
/// they edit the record of which identity-topology seals this vault wrote and
/// whose it last counted: only the seal writes it (H161). Nor the record of
/// which author carriers it wrote: only the carrier write and its scrub touch
/// it (H161 sidecars). Nor a delete's fence, hard-delete marker or topology
/// reservation: only the delete doors write them. Nor a federation world's
/// registration or stale stamp: only the registration and the stale sweep
/// write them. Nor a peer-origin digest: only the peer import records what it
/// brought.
#[cfg(feature = "sync")]
fn check_generic_sync_state_key(key: &str) -> Result<()> {
    if key.starts_with("authlog:") || key.starts_with("peerauth:") {
        return Err(Error::InvalidConfig(
            "authority-owned sync_state key requires its authority door".to_owned(),
        ));
    }
    if key.starts_with("it:sealed:") || key.starts_with("it:mine_signers") {
        return Err(Error::InvalidConfig(
            "identity-topology seal trust is written only by the seal".to_owned(),
        ));
    }
    if key.starts_with("it:authored:") {
        return Err(Error::InvalidConfig(
            "identity-topology authorship is written only by its carrier".to_owned(),
        ));
    }
    if [
        crate::side_table::DELETION_ROW_FENCE.prefix,
        crate::side_table::DELETION_HARD_DELETE_MARKER.prefix,
        crate::side_table::DELETION_TOPOLOGY_DELETE_INTENT.prefix,
        crate::side_table::FEDERATION_TOMBSTONE_SCOPE.prefix,
    ]
    .iter()
    .any(|prefix| key.as_bytes().starts_with(prefix))
    {
        return Err(Error::InvalidConfig(
            "deletion fences, markers and topology reservations are written only by the delete doors"
                .to_owned(),
        ));
    }
    if key.starts_with(crate::federation::FEDERATION_WORLD_KEY_PREFIX)
        || key.starts_with(crate::federation::FEDERATION_STALE_KEY_PREFIX)
    {
        return Err(Error::InvalidConfig(
            "federation world registrations and stale stamps are written only by the engine"
                .to_owned(),
        ));
    }
    if key
        .as_bytes()
        .starts_with(crate::side_table::SYNC_PEER_ORIGIN.prefix)
    {
        return Err(Error::InvalidConfig(
            "peer-origin digests are written only by the peer import".to_owned(),
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

    /// Returns the occurred interval from an entity's header.
    pub fn get_occurred(&self, id: &EntityId) -> Result<TimeRange> {
        let rtxn = self.store.env.read_txn()?;
        let row = self
            .store
            .port_entity_record(&rtxn, id)?
            .ok_or(Error::EntityNotFound)?;
        Ok(row.occurred)
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
        self.latest_learned_at_excluding_entity_types_at(
            excluded_types,
            crate::claim::CallerLocality::OnDevice,
        )
    }

    /// [`Self::latest_learned_at_excluding_entity_types`] for a caller whose
    /// rows go to `destination`: no row a world withholds from one of its
    /// machines dates it for one off this device (DEC-0005, mesh PR2b).
    pub fn latest_learned_at_excluding_entity_types_at(
        &self,
        excluded_types: &[u8],
        destination: impl Into<crate::settings::ReadDestination>,
    ) -> Result<Option<u64>> {
        let destination: crate::settings::ReadDestination = destination.into();
        let txn = self.store.env.read_txn()?;
        let flagged = crate::settings::device_local_worlds_for(self, &txn, &destination)?;
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
            if !excluded_types.contains(&entity.entity_type)
                && !crate::settings::device_local_keeps_among(&self.store, &txn, &flagged, &row.id)?
            {
                return Ok(Some(row.timestamp));
            }
        }
        Ok(None)
    }

    /// Returns entity IDs whose `learned_at` falls within `[start, end)`.
    ///
    /// Range-seeks the `temporal_learned` index by timestamp prefix.
    /// Returns an empty result when `start >= end`. Every row is read: past
    /// the window's threshold row the scan raises one check and reads on.
    pub fn entities_in_learned_range(&self, start: u64, end: u64) -> Result<Vec<EntityId>> {
        if start >= end {
            return Ok(Vec::new());
        }
        let txn = self.store.env.read_txn()?;
        let window = [start.to_be_bytes(), end.to_be_bytes()].concat();
        let mut count = crate::scan_check::ScanCount::start(
            &self.store,
            &txn,
            crate::scan_check::EngineScan::LearnedRangeRows,
            &window,
        )?;
        let query = crate::ports::TimelineQuery {
            start: std::ops::Bound::Included(start),
            end: std::ops::Bound::Excluded(end),
            ..Default::default()
        };
        let mut ids = Vec::new();
        for row in self.store.port_entity_timeline(&txn, query)? {
            count.row();
            ids.push(row?.id);
        }
        drop(txn);
        count.finish(self);
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
        self.with_write_txn_grouped(|wtxn| {
            crate::store::admit_embedding_transform_in_txn(&self.store, wtxn, transform)
        })
    }

    /// The transform the vault pins for its vectors, `None` while none is.
    /// A host whose model files are named by a moving hub ref reads it to load
    /// the commit the stored vectors came from (FIX 9489).
    pub fn embedding_transform(&self) -> Result<Option<String>> {
        let rtxn = self.store.env.read_txn()?;
        self.store
            .port_index_meta_with_raw(&rtxn, IndexMetaKey::EmbeddingTransform, |raw| {
                std::str::from_utf8(raw)
                    .map(str::to_owned)
                    .map_err(|_| Error::CorruptedIndex("embedding transform"))
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
        let held = self.with_write_txn_grouped(|wtxn| {
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
        let stored_utf8 = |key: IndexMetaKey, what: &'static str| -> Result<Option<String>> {
            self.store.port_index_meta_with_raw(&*wtxn, key, |raw| {
                std::str::from_utf8(raw)
                    .map(str::to_owned)
                    .map_err(|_| Error::CorruptedIndex(what))
            })
        };
        let same_model =
            stored_utf8(IndexMetaKey::ModelId, "model id")?.as_deref() == Some(new_model);
        let stored_transform =
            stored_utf8(IndexMetaKey::EmbeddingTransform, "embedding transform")?;
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
    /// The transaction commits on `Ok` return and rolls back on `Err`, and
    /// `Ok` returns once the commit is durable. The closure runs on the
    /// calling thread. In the vault's group commit (OF-536) this write is a
    /// group of its own: it joins no group already open, so it never waits on
    /// what an earlier write's caller holds, and its group commits right after
    /// it, so no later write waits on a lock or permit its result carries.
    /// Explicit Dreamer approvals applied through [`Self::batch_in`] run VAD
    /// consolidation after commit. A postcommit error retains Approved; retry
    /// [`Self::consolidate_claim_vad_now`] to finish that work. While a host's
    /// payment worker is attached ([`Self::attach_claim_vad_payment_worker`]),
    /// that worker runs it after this returns, and its failure stays owed
    /// for the housekeeping pass (FIX 11702).
    pub fn try_with_write_txn<F, T, E>(&self, f: F) -> std::result::Result<T, E>
    where
        F: FnOnce(&mut heed::RwTxn<'_>) -> std::result::Result<T, E>,
        E: From<Error>,
    {
        self.write_txn_door(Callback::Opaque, f)
    }

    /// [`Self::with_write_txn`] for the engine's own write paths, audited to
    /// hold nothing across the group commit.
    #[doc(hidden)]
    pub fn with_write_txn_grouped<F, T>(&self, f: F) -> Result<T>
    where
        F: FnOnce(&mut heed::RwTxn<'_>) -> Result<T>,
    {
        self.try_with_write_txn_grouped(f)
    }

    /// [`Self::try_with_write_txn`] for the engine's own write paths, audited
    /// to hold nothing across the group commit: the group goes on after this
    /// write, so more writes share its fsync.
    ///
    /// The caller promises that neither the closure's result (`Ok` or `Err`)
    /// nor anything the calling thread holds while it waits keeps a lock,
    /// permit or guard that another write's closure takes. Those stay alive
    /// until the whole group commits, and the group cannot commit while a
    /// later member waits on them. A write that breaks the promise deadlocks
    /// the vault's writer. Hosts use [`Self::try_with_write_txn`].
    #[doc(hidden)]
    pub fn try_with_write_txn_grouped<F, T, E>(&self, f: F) -> std::result::Result<T, E>
    where
        F: FnOnce(&mut heed::RwTxn<'_>) -> std::result::Result<T, E>,
        E: From<Error>,
    {
        self.write_txn_door(Callback::Audited, f)
    }

    /// The write door for a closure of either kind (`try_with_write_txn` and
    /// `try_with_write_txn_grouped` name it).
    pub(crate) fn write_txn_door<F, T, E>(
        &self,
        callback: Callback,
        f: F,
    ) -> std::result::Result<T, E>
    where
        F: FnOnce(&mut heed::RwTxn<'_>) -> std::result::Result<T, E>,
        E: From<Error>,
    {
        self.write_txn_door_classed(callback, BackupWriteClass::Content, f)
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
        self.with_write_txn_grouped(|wtxn| {
            crate::side_table::host_sync_state_put(self, wtxn, key, value)
        })
    }

    /// Writes each of `rows` to `sync_state` in one write, as
    /// [`Self::sync_state_put`] writes one (FIX 6730): when every key is a
    /// host's telemetry (a wire window's counters, a wire or `[limits]`
    /// question, the managed ledger's revision) the commit moves no backup
    /// watermark, so an idle host reuses its backup; any other key makes the
    /// whole write content. Refuses an undeclared key, as `sync_state_put`
    /// does.
    #[doc(hidden)]
    #[cfg(feature = "sync")]
    pub fn sync_state_put_telemetry_batch(&self, rows: &[(&str, &[u8])]) -> Result<()> {
        for (key, _) in rows {
            check_generic_sync_state_key(key)?;
        }
        let class = crate::store::telemetry_batch_class(rows.iter().map(|(key, _)| *key));
        self.write_txn_door_classed(Callback::Audited, class, |wtxn| {
            for (key, value) in rows {
                crate::side_table::host_sync_state_put(self, wtxn, key, value)?;
            }
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
        check_generic_sync_state_key(key)?;
        crate::side_table::host_sync_state_put(self, wtxn, key, value)
    }

    /// Deletes a key from the sync_state database for diagnostics and
    /// server-side sync metadata cleanup.
    #[doc(hidden)]
    #[cfg(feature = "sync")]
    pub fn sync_state_delete(&self, key: &str) -> Result<bool> {
        check_generic_sync_state_key(key)?;
        self.with_write_txn_grouped(|wtxn| {
            crate::side_table::host_sync_state_delete(&self.store, wtxn, key)
        })
    }

    /// Lists all keys with the given prefix in sync_state for sync integration
    /// tests and diagnostics, however many: past the advisory threshold row
    /// the scan raises one check and reads on (rule 5).
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
        let mut count = crate::scan_check::ScanCount::start_at(
            crate::scan_check::EngineScan::PackQuarantineRows,
            prefix.as_bytes(),
            MAX_SYNC_STATE_KEYS as u64,
        );
        let mut keys = Vec::new();
        for entry in self.store.sync_state.prefix_iter(&rtxn, prefix)? {
            count.row();
            let (k, _) = entry?;
            crate::side_table::host_declared_sync_state(&k)?;
            keys.push(k.to_string());
        }
        drop(rtxn);
        count.finish(self);
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
    /// sweep family a replayed remote hard tombstone must enqueue), however
    /// many: past the advisory threshold row the scan raises one check and
    /// reads on (rule 5).
    ///
    /// Production code uses direct transactional access so multi-key
    /// updates stay atomic.
    #[doc(hidden)]
    #[cfg(feature = "sync")]
    pub fn sync_queue_rows_with_prefix(&self, prefix: &[u8]) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
        let rtxn = self.store.env.read_txn()?;
        let mut count = crate::scan_check::ScanCount::start_at(
            crate::scan_check::EngineScan::PackQuarantineRows,
            prefix,
            MAX_SYNC_STATE_KEYS as u64,
        );
        let mut rows = Vec::new();
        for entry in self.store.sync_queue.prefix_iter(&rtxn, prefix)? {
            count.row();
            let (k, v) = entry?;
            rows.push((k.to_vec(), v.to_vec()));
        }
        drop(rtxn);
        count.finish(self);
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

#[cfg(feature = "sync")]
mod sync_state_delete;
mod sync_state_page;
#[cfg(feature = "sync")]
mod sync_state_reclaim;
#[cfg(feature = "sync")]
mod telemetry_if_absent;
mod write_door;

#[cfg(all(test, feature = "sync"))]
mod sync_scan_tests;
