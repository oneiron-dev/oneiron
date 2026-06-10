//! Top-level `Vault` API: the crate's main entry point for all LMDB-backed
//! entity / vector / edge / text / temporal operations. Also hosts the private
//! edge-record helpers used exclusively by Vault methods.

use std::path::Path;

use heed::Database;
use heed::types::Bytes;
use serde::Serialize;
use uuid::Uuid;

use crate::analyzer::{AnalyzerChannel, AnalyzerManifest, AnalyzerMode, MultilingualAnalyzer};
use crate::batch::{
    ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader, deindex_entity, delete_from_phonetic_postings,
};
use crate::deletion::{
    DeleteEntityOutcome, DeleteReason, HARD_ERASE_SWEEP_PREFIX, LAST_HARD_ERASE_SWEEP_SEQ_KEY,
    RedactionReceiptInput, RedactionScope, decode_hard_erase_sweep_seq,
    encode_hard_erase_sweep_job, encode_hard_erase_sweep_key, encode_redaction_audit_receipt,
};
use crate::error::{Error, Result};
use crate::limits::{
    ERR_CHILD_OF_CYCLE_CHECK, MAX_ANCESTOR_DEPTH, MAX_CHILD_OF_CYCLE_TRAVERSAL_STEPS,
};
use crate::store::{
    DB_MANIFEST, HnswCompatibilityState, MODEL_ID_KEY, STORAGE_ABI_VERSION_KEY,
    STORAGE_SCHEMA_VERSION_KEY, Store, TEXT_ANALYZER_MANIFEST_HASH_KEY, TEXT_ANALYZER_MANIFEST_KEY,
    TEXT_BM25_FIELD_SCHEMA_HASH_KEY, TEXT_INDEX_SCHEMA_VERSION, TEXT_INDEX_SCHEMA_VERSION_KEY,
    lmdb_database_open_guard,
};
use crate::types::{
    EDGE_KEY_LEN, ENTITY_ID_LEN, ENTITY_TYPE_REDACTION_AUDIT, EdgeInfo, EdgeKind, EntityId,
    ScoredEntity, TimeRange, Vad, VaultConfig, bytes_to_hex_lower, decode_edge_value_for_kind,
};
use crate::{
    BatchBuilder, ContextPackBuilder, MaintenanceBuilder, PipelineBuilder, TxnBatchBuilder, bm25,
    hnsw, le_bytes_to_f32_vec, ppr, unix_seconds_now,
};

const MIN_MAP_SIZE_BYTES: usize = 1 << 20;

/// Length of the edge-kind prefix: `entity_id (16) | kind (1)`.
const EDGE_KIND_PREFIX_LEN: usize = ENTITY_ID_LEN + 1;

/// Cap for `entities_by_type` to prevent unbounded allocation on large indexes.
const MAX_TYPE_QUERY_RESULTS: usize = 100_000;

/// Cap for `entities_in_learned_range` to prevent unbounded allocation on
/// wide time-range queries. Distinct from `MAX_TYPE_QUERY_RESULTS` so the two
/// APIs can be tuned independently.
const MAX_LEARNED_RANGE_RESULTS: usize = 100_000;

/// Cap for `targets`/`sources` to prevent unbounded allocation.
const MAX_EDGE_QUERY_RESULTS: usize = 100_000;

/// Cap for `subtree` to prevent unbounded allocation on deep trees.
const MAX_SUBTREE_RESULTS: usize = 50_000;

/// Cap for `sync_state_keys_with_prefix` to prevent unbounded allocation when
/// a pathological prefix scans a very large sync_state database.
#[cfg(feature = "sync")]
const MAX_SYNC_STATE_KEYS: usize = 10_000;

/// Build an edge prefix `[entity_id | kind]` for targeted LMDB prefix scans.
/// Avoids scanning all edge kinds for a given entity.
fn edge_kind_prefix(id: &EntityId, kind: EdgeKind) -> [u8; EDGE_KIND_PREFIX_LEN] {
    let mut prefix = [0u8; EDGE_KIND_PREFIX_LEN];
    prefix[..ENTITY_ID_LEN].copy_from_slice(id.as_bytes());
    prefix[ENTITY_ID_LEN] = kind as u8;
    prefix
}

fn require_key_len(key: &[u8], expected: usize, context: &'static str) -> Result<()> {
    if key.len() != expected {
        return Err(Error::CorruptedIndex(context));
    }
    Ok(())
}

/// Returns the first outbound ChildOf parent for `node`, or `None` if it has
/// no ChildOf edge (i.e. it is a root).
///
/// Each node has at most one ChildOf parent. If multiple exist due to data
/// corruption, only the first by LMDB key order is returned.
fn first_child_of_parent(
    store: &Store,
    rtxn: &heed::RoTxn<'_>,
    node: &EntityId,
) -> Result<Option<EntityId>> {
    let prefix = edge_kind_prefix(node, EdgeKind::ChildOf);
    if let Some(entry) = store.edges_out.prefix_iter(rtxn, &prefix)?.next() {
        let (key, value) = entry?;
        return Ok(Some(parse_edge_record(key, value)?.target));
    }
    Ok(None)
}

/// Main vault API wrapping LMDB storage and configuration.
pub struct Vault {
    pub(crate) store: Store,
    pub(crate) config: VaultConfig,
    pub(crate) analyzer: MultilingualAnalyzer,
    /// `false` only when `Vault::open` ran with
    /// `skip_text_index_manifest_check = true` against a populated index.
    /// In that state the on-disk postings may have been written under a
    /// different analyzer manifest than the in-memory one, so scoring
    /// against them silently returns wrong results. `search_text` returns
    /// `Error::CorruptedIndex` until `MaintenanceBuilder::clear_text_index`
    /// rewrites the manifest. Reopening cleanly also restores trust via
    /// the regular handshake path.
    pub(crate) text_index_trusted: std::sync::atomic::AtomicBool,
}

impl Vault {
    /// Opens or creates a vault at `path`.
    ///
    /// Open-time compatibility gates run in the canonical order documented at
    /// the top of [`crate::store`]: `Store::open` runs the storage gates
    /// (`vault_meta` created first → ABI gate → schema gate → DB-manifest set
    /// → DB opens → HNSW/dimension preflight → embedding-model preflight),
    /// then this function runs the final analyzer / BM25F text-index
    /// handshake against `vault_meta`. The
    /// [`VaultConfig::skip_text_index_manifest_check`] escape hatch bypasses
    /// only that final handshake (and marks a populated text index untrusted
    /// so text reads/writes fail closed until
    /// [`crate::MaintenanceBuilder::clear_text_index`] commits).
    ///
    /// Every gate fails closed: the first failing gate returns its typed
    /// [`Error`] and no usable `Vault` handle is constructed.
    pub fn open(path: impl AsRef<Path>, config: VaultConfig) -> Result<Self> {
        if config.dimensions == 0 {
            return Err(Error::InvalidConfig(
                "dimensions must be greater than zero".to_owned(),
            ));
        }
        if config.hnsw.m_max_0 == 0 {
            return Err(Error::InvalidConfig(
                "hnsw m_max_0 must be greater than zero".to_owned(),
            ));
        }
        if config.map_size < MIN_MAP_SIZE_BYTES {
            return Err(Error::InvalidConfig(format!(
                "map_size must be at least {MIN_MAP_SIZE_BYTES} bytes"
            )));
        }

        let store = Store::open(path, &config)?;
        let analyzer = MultilingualAnalyzer::discover(&config.dict_search_paths)
            .map_err(|e| Error::AnalyzerError(e.to_string()))?;
        let text_index_trusted = if config.skip_text_index_manifest_check {
            // Bypass-on-empty-index is fine — there are no postings under any
            // analyzer manifest yet, so anything we write next will be the
            // first authoritative state. Bypass-on-populated-index leaves the
            // on-disk postings potentially analyzer-incompatible with the
            // in-memory analyzer; mark the index untrusted so search fails
            // closed until `clear_text_index` runs. The same residual-rows
            // check used by the handshake applies — `total_docs == 0` alone
            // can still hide stale postings/forward/length/stats rows.
            let rtxn = store.env.read_txn()?;
            let empty = text_index_is_empty(&store, &rtxn)?;
            drop(rtxn);
            if empty {
                let mut wtxn = store.env.write_txn()?;
                write_text_index_manifest_if_empty(&store, &mut wtxn, &analyzer)?;
                wtxn.commit()?;
            }
            empty
        } else {
            handshake_text_index_manifest(&store, &analyzer)?;
            true
        };

        Ok(Self {
            store,
            config,
            analyzer,
            text_index_trusted: std::sync::atomic::AtomicBool::new(text_index_trusted),
        })
    }

    /// Internal guard: read paths over the text index must refuse to score
    /// when the analyzer-manifest handshake was bypassed on a populated
    /// index. See the docstring on `Vault::text_index_trusted`.
    pub(crate) fn ensure_text_index_trusted(&self) -> Result<()> {
        if self
            .text_index_trusted
            .load(std::sync::atomic::Ordering::Acquire)
        {
            Ok(())
        } else {
            Err(Error::CorruptedIndex(
                "text index handshake bypassed on populated index",
            ))
        }
    }

    /// Current text-index status. `analyzer_manifest` reflects the analyzer
    /// this vault was opened with; `schema_version` and `total_docs` reflect
    /// what was persisted by prior writes.
    pub fn text_index_status(&self) -> Result<TextIndexStatus> {
        let rtxn = self.store.env.read_txn()?;
        let total_docs = bm25::read_total_docs(&self.store, &rtxn)?;
        let schema_version = read_text_schema_version(&self.store, &rtxn)?;
        Ok(TextIndexStatus {
            total_docs,
            schema_version,
            analyzer_manifest: self.analyzer.manifest(),
        })
    }

    /// Read-only diagnostic snapshot of the persisted compatibility metadata
    /// that the open-time gates consume.
    ///
    /// This method describes the stored state without repairing, rebuilding,
    /// seeding, or validating it. Missing or legacy compatibility rows are
    /// reported as `None` plus an explicit state marker instead of being
    /// treated as gate failures.
    pub fn doctor(&self) -> Result<VaultDoctorReport> {
        let rtxn = self.store.env.read_txn()?;
        let mut unreadable_fields = Vec::new();
        let storage_abi_version = doctor_optional_u16(
            crate::store::read_vault_meta_u16(
                &self.store.vault_meta,
                &rtxn,
                STORAGE_ABI_VERSION_KEY,
                "storage ABI version",
            ),
            "vault_meta.storage_abi_version",
            &mut unreadable_fields,
        )?;
        let storage_schema_version = doctor_optional_u16(
            crate::store::read_vault_meta_u16(
                &self.store.vault_meta,
                &rtxn,
                STORAGE_SCHEMA_VERSION_KEY,
                "storage schema version",
            ),
            "vault_meta.schema_version",
            &mut unreadable_fields,
        )?;
        let embedding_model_id =
            doctor_embedding_model_id(&self.store, &rtxn, &mut unreadable_fields)?;
        let hnsw = doctor_hnsw(&self.store, &rtxn, &mut unreadable_fields)?;
        let analyzer_manifest_hash = doctor_hash_hex(
            &self.store,
            &rtxn,
            TEXT_ANALYZER_MANIFEST_HASH_KEY,
            "vault_meta.text_analyzer_manifest_hash",
            &mut unreadable_fields,
        )?;
        let bm25_field_schema_hash = doctor_hash_hex(
            &self.store,
            &rtxn,
            TEXT_BM25_FIELD_SCHEMA_HASH_KEY,
            "vault_meta.text_bm25_field_schema_hash",
            &mut unreadable_fields,
        )?;
        let text_index_schema_version = doctor_optional_u16(
            read_text_schema_version(&self.store, &rtxn),
            "vault_meta.text_index_schema_version",
            &mut unreadable_fields,
        )?;
        drop(rtxn);
        let db_manifest = {
            // Held for consistency with `Store::open`'s DB-open serialization;
            // the txn that performs `mdb_dbi_open` must finish before release.
            let _db_open_guard = lmdb_database_open_guard()?;
            let manifest_rtxn = self.store.env.read_txn()?;
            let report = doctor_db_manifest(&self.store, &manifest_rtxn)?;
            drop(manifest_rtxn);
            report
        };

        Ok(VaultDoctorReport {
            storage_abi_version,
            storage_schema_version,
            embedding_model_id,
            hnsw,
            analyzer_manifest_hash,
            bm25_field_schema_hash,
            text_index_schema_version,
            db_manifest,
            unreadable_fields,
        })
    }

    /// Stores an entity blob.
    pub fn put_entity(
        &self,
        id: &EntityId,
        entity_type: u8,
        occurred: TimeRange,
        learned_at: u64,
        data: &[u8],
    ) -> Result<()> {
        self.batch()
            .put(id, entity_type, occurred, learned_at, data)
            .commit()
    }

    /// Retrieves an entity blob by ID.
    pub fn get(&self, id: &EntityId) -> Result<Option<Vec<u8>>> {
        let rtxn = self.store.env.read_txn()?;
        let value = self.store.entities.get(&rtxn, id.as_bytes())?;
        let Some(bytes) = value else {
            return Ok(None);
        };

        if EntityMetadataHeader::parse(bytes).is_none() {
            return Err(Error::CorruptedIndex("entity header"));
        }

        Ok(Some(bytes[ENTITY_METADATA_HEADER_LEN..].to_vec()))
    }

    /// Deletes an entity blob by ID using the destructive user-hard-delete
    /// contract.
    pub fn delete_entity(&self, id: &EntityId) -> Result<bool> {
        Ok(self
            .delete_entity_with_reason(id, DeleteReason::UserHardDelete)?
            .existed)
    }

    /// Deletes an entity according to the pinned ARCH-0038 reason behavior.
    pub fn delete_entity_with_reason(
        &self,
        id: &EntityId,
        reason: DeleteReason,
    ) -> Result<DeleteEntityOutcome> {
        let requested_at = unix_seconds_now();
        let Some(header) = self.read_entity_header(id)? else {
            return self.delete_entity_without_header(id, reason, requested_at);
        };

        if !reason.active_store_hard_purge_v1() {
            // ARCH-0038's CRDT tombstone drives destructive HardErase replay.
            // `user_delete` is a local SoftErase shell in M0-6; cross-device
            // soft-delete propagation is deferred to ONE-1090 (M4).
            let existed = self.soft_erase_active_store(id)?;
            return Ok(DeleteEntityOutcome {
                existed,
                receipt_id: None,
                sweep_key: None,
            });
        }

        self.write_crdt_tombstone(id, header.learned_at, requested_at)?;
        let tombstone_complete_at = unix_seconds_now();

        let soft_complete_at = if matches!(
            reason,
            DeleteReason::GdprDelete | DeleteReason::PolicyDelete
        ) {
            let _ = self.soft_erase_active_store(id)?;
            unix_seconds_now()
        } else {
            tombstone_complete_at
        };

        let request_id = Uuid::now_v7().to_string();
        let receipt_id = EntityId::now();
        let scope = RedactionScope::entity(id);
        let mut wtxn = self.store.env.write_txn()?;
        let existed = self.purge_entity_active_store_in_txn(&mut wtxn, id)?;
        if !existed {
            wtxn.commit()?;
            return Ok(DeleteEntityOutcome::missing());
        }

        let hard_purge_complete_at = unix_seconds_now();
        let sweep_key = self.write_redaction_receipt_and_sweep_in_txn(
            &mut wtxn,
            &receipt_id,
            RedactionReceiptInput {
                request_id,
                scope,
                reason,
                requested_at,
                soft_complete_at,
                hard_purge_complete_at,
                sweep_queued_at: reason
                    .queues_historical_sweep()
                    .then_some(hard_purge_complete_at),
            },
        )?;

        wtxn.commit()?;
        Ok(DeleteEntityOutcome {
            existed,
            receipt_id: Some(receipt_id),
            sweep_key: Some(sweep_key),
        })
    }

    fn delete_entity_without_header(
        &self,
        id: &EntityId,
        reason: DeleteReason,
        requested_at: u64,
    ) -> Result<DeleteEntityOutcome> {
        let mut wtxn = self.store.env.write_txn()?;
        let had_active_data = self.active_delete_scope_exists_in_txn(&wtxn, id)?;
        let existed = self.purge_entity_active_store_in_txn(&mut wtxn, id)?;
        if !had_active_data && !existed {
            wtxn.commit()?;
            return Ok(DeleteEntityOutcome::missing());
        }
        if !reason.writes_receipt() {
            wtxn.commit()?;
            return Ok(DeleteEntityOutcome {
                existed,
                receipt_id: None,
                sweep_key: None,
            });
        }

        let receipt_id = EntityId::now();
        let hard_purge_complete_at = unix_seconds_now();
        let sweep_key = self.write_redaction_receipt_and_sweep_in_txn(
            &mut wtxn,
            &receipt_id,
            RedactionReceiptInput {
                request_id: Uuid::now_v7().to_string(),
                scope: RedactionScope::entity(id),
                reason,
                requested_at,
                soft_complete_at: hard_purge_complete_at,
                hard_purge_complete_at,
                sweep_queued_at: reason
                    .queues_historical_sweep()
                    .then_some(hard_purge_complete_at),
            },
        )?;
        wtxn.commit()?;
        Ok(DeleteEntityOutcome {
            existed,
            receipt_id: Some(receipt_id),
            sweep_key: Some(sweep_key),
        })
    }

    pub(crate) fn purge_entity_active_store(&self, id: &EntityId) -> Result<bool> {
        let mut wtxn = self.store.env.write_txn()?;
        let existed = self.purge_entity_active_store_in_txn(&mut wtxn, id)?;
        wtxn.commit()?;
        Ok(existed)
    }

    fn purge_entity_active_store_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        id: &EntityId,
    ) -> Result<bool> {
        let (existed, had_vector, had_graph_mutation, neighbors) =
            deindex_entity(&self.store, wtxn, id)?;
        ppr::invalidate_ppr_for_delete(&self.store, wtxn, id, &neighbors)?;
        if had_graph_mutation {
            ppr::increment_graph_version(&self.store, wtxn)?;
        }
        if had_vector {
            crate::hnsw::increment_vector_version(&self.store, wtxn)?;
        }
        Ok(existed)
    }

    fn soft_erase_active_store(&self, id: &EntityId) -> Result<bool> {
        let mut wtxn = self.store.env.write_txn()?;
        let (existed, had_vector) = self.soft_erase_active_store_in_txn(&mut wtxn, id)?;
        if had_vector {
            crate::hnsw::increment_vector_version(&self.store, &mut wtxn)?;
        }
        wtxn.commit()?;
        Ok(existed)
    }

    fn soft_erase_active_store_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        id: &EntityId,
    ) -> Result<(bool, bool)> {
        bm25::deindex_text(&self.store, wtxn, id)?;
        delete_from_phonetic_postings(&self.store, wtxn, id)?;
        let had_vector = self.store.vectors.delete(wtxn, id.as_bytes())?;
        crate::hnsw::hnsw_deindex(&self.store, wtxn, id)?;

        let Some(entity_record) = self.store.entities.get(wtxn, id.as_bytes())? else {
            return Ok((false, had_vector));
        };
        if EntityMetadataHeader::parse(entity_record).is_none() {
            return Err(Error::CorruptedIndex("entity metadata"));
        }

        let payload = entity_record[..ENTITY_METADATA_HEADER_LEN].to_vec();
        self.store.entities.put(wtxn, id.as_bytes(), &payload)?;
        Ok((true, had_vector))
    }

    fn read_entity_header(&self, id: &EntityId) -> Result<Option<EntityMetadataHeader>> {
        let rtxn = self.store.env.read_txn()?;
        let Some(raw) = self.store.entities.get(&rtxn, id.as_bytes())? else {
            return Ok(None);
        };
        EntityMetadataHeader::parse(raw)
            .ok_or(Error::CorruptedIndex("entity metadata"))
            .map(Some)
    }

    fn active_delete_scope_exists_in_txn(
        &self,
        txn: &heed::RwTxn<'_>,
        id: &EntityId,
    ) -> Result<bool> {
        if self.store.entities.get(txn, id.as_bytes())?.is_some()
            || self.store.vectors.get(txn, id.as_bytes())?.is_some()
            || self.store.text_forward.get(txn, id.as_bytes())?.is_some()
            || self.store.text_meta.get(txn, id.as_bytes())?.is_some()
            || self
                .store
                .text_doc_field_lengths
                .get(txn, id.as_bytes())?
                .is_some()
            || self
                .store
                .phonetic_forward
                .get(txn, id.as_bytes())?
                .is_some()
            || self
                .store
                .short_ids_reverse
                .get(txn, id.as_bytes())?
                .is_some()
        {
            return Ok(true);
        }

        let mut edges_out = self.store.edges_out.prefix_iter(txn, id.as_bytes())?;
        if edges_out.next().transpose()?.is_some() {
            return Ok(true);
        }
        let mut edges_in = self.store.edges_in.prefix_iter(txn, id.as_bytes())?;
        Ok(edges_in.next().transpose()?.is_some())
    }

    #[cfg(feature = "sync")]
    fn write_crdt_tombstone(&self, id: &EntityId, learned_at: u64, deleted_at: u64) -> Result<()> {
        use crate::sync::loro_support::{doc_version_vector, export_snapshot, map_insert_bytes};
        use crate::sync::schema::create_window_doc;
        use crate::sync::types::WindowKey;
        use crate::sync::window::load_window_from_state;

        let window_key = WindowKey::from_timestamp(learned_at);
        let doc = match load_window_from_state(self, "local", &window_key) {
            Ok(doc) => doc,
            Err(Error::WindowNotFound { .. }) => create_window_doc("local", &window_key),
            Err(err) => return Err(err),
        };
        let tombstones = doc.get_map("tombstones");
        map_insert_bytes(&tombstones, id.to_hex().as_str(), &deleted_at.to_le_bytes())?;
        doc.commit();

        let snapshot = export_snapshot(&doc)?;
        let vv = doc_version_vector(&doc);
        self.with_write_txn(|wtxn| {
            let doc_key = format!("d:w:{window_key}");
            self.store.sync_state.put(wtxn, &doc_key, &snapshot)?;

            let sv_key = format!("sv:w:{window_key}");
            self.store.sync_state.put(wtxn, &sv_key, &vv)?;

            let svf_key = format!("svf:w:{window_key}");
            self.store.sync_state.put(wtxn, &svf_key, &[1_u8])?;
            Ok(())
        })
    }

    #[cfg(not(feature = "sync"))]
    fn write_crdt_tombstone(
        &self,
        _id: &EntityId,
        _learned_at: u64,
        _deleted_at: u64,
    ) -> Result<()> {
        Ok(())
    }

    fn put_redaction_audit_receipt_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        receipt_id: &EntityId,
        learned_at: u64,
        body: &[u8],
    ) -> Result<()> {
        let mut payload = Vec::with_capacity(ENTITY_METADATA_HEADER_LEN + body.len());
        payload.push(ENTITY_TYPE_REDACTION_AUDIT);
        payload.extend_from_slice(&learned_at.to_be_bytes());
        payload.extend_from_slice(&learned_at.to_be_bytes());
        payload.extend_from_slice(&learned_at.to_be_bytes());
        payload.extend_from_slice(body);
        self.store
            .entities
            .put(wtxn, receipt_id.as_bytes(), &payload)?;

        let type_key = Store::encode_type_key(ENTITY_TYPE_REDACTION_AUDIT, receipt_id);
        self.store.type_index.put(wtxn, &type_key, &[])?;

        let learned_key = Store::encode_temporal_key(learned_at, receipt_id);
        self.store.temporal_learned.put(wtxn, &learned_key, &[])?;
        Ok(())
    }

    fn write_redaction_receipt_and_sweep_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        receipt_id: &EntityId,
        input: RedactionReceiptInput,
    ) -> Result<Vec<u8>> {
        let sweep_key = if let Some(queued_at) = input.sweep_queued_at {
            self.enqueue_hard_erase_sweep_in_txn(wtxn, input.scope.clone(), queued_at)?
        } else {
            Vec::new()
        };

        let hard_purge_complete_at = input.hard_purge_complete_at;
        let body = encode_redaction_audit_receipt(input)?;
        self.put_redaction_audit_receipt_in_txn(wtxn, receipt_id, hard_purge_complete_at, &body)?;
        Ok(sweep_key)
    }

    fn enqueue_hard_erase_sweep_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        scope: RedactionScope,
        queued_at: u64,
    ) -> Result<Vec<u8>> {
        let seq = self.allocate_next_hard_erase_sweep_seq(wtxn)?;
        let key = encode_hard_erase_sweep_key(seq);
        let value = encode_hard_erase_sweep_job(scope, queued_at)?;
        self.store.sync_queue.put(wtxn, &key, &value)?;
        Ok(key.to_vec())
    }

    fn allocate_next_hard_erase_sweep_seq(&self, wtxn: &mut heed::RwTxn<'_>) -> Result<u64> {
        let metadata_seq = match self
            .store
            .sync_queue
            .get(&*wtxn, LAST_HARD_ERASE_SWEEP_SEQ_KEY)?
        {
            Some(raw) if raw.len() == 8 => {
                Some(u64::from_le_bytes(raw.try_into().map_err(|_| {
                    Error::CorruptedIndex("hard erase sweep metadata")
                })?))
            }
            Some(_) => return Err(Error::CorruptedIndex("hard erase sweep metadata")),
            None => None,
        };
        let current = match metadata_seq {
            Some(seq) => seq,
            None => self.max_hard_erase_sweep_seq(wtxn)?,
        };
        let next = current
            .checked_add(1)
            .ok_or(Error::ArithmeticOverflow("hard erase sweep sequence"))?;
        if self
            .store
            .sync_queue
            .get(&*wtxn, &encode_hard_erase_sweep_key(next))?
            .is_some()
        {
            let repaired_current = self.max_hard_erase_sweep_seq(wtxn)?;
            let repaired_next = repaired_current
                .checked_add(1)
                .ok_or(Error::ArithmeticOverflow("hard erase sweep sequence"))?;
            if self
                .store
                .sync_queue
                .get(&*wtxn, &encode_hard_erase_sweep_key(repaired_next))?
                .is_some()
            {
                return Err(Error::CorruptedIndex("hard erase sweep metadata"));
            }
            self.store.sync_queue.put(
                wtxn,
                LAST_HARD_ERASE_SWEEP_SEQ_KEY,
                &repaired_next.to_le_bytes(),
            )?;
            return Ok(repaired_next);
        }
        self.store
            .sync_queue
            .put(wtxn, LAST_HARD_ERASE_SWEEP_SEQ_KEY, &next.to_le_bytes())?;
        Ok(next)
    }

    fn max_hard_erase_sweep_seq(&self, wtxn: &heed::RwTxn<'_>) -> Result<u64> {
        let mut max_seq = 0_u64;
        for row in self
            .store
            .sync_queue
            .prefix_iter(wtxn, HARD_ERASE_SWEEP_PREFIX)?
        {
            let (key, _) = row?;
            if let Some(seq) = decode_hard_erase_sweep_seq(key) {
                max_seq = max_seq.max(seq);
            }
        }
        Ok(max_seq)
    }

    /// Stores a vector for an entity.
    pub fn put_vector(&self, id: &EntityId, vector: &[f32]) -> Result<()> {
        self.batch().vector(id, vector).commit()
    }

    /// Retrieves a vector for an entity.
    pub fn get_vector(&self, id: &EntityId) -> Result<Option<Vec<f32>>> {
        let rtxn = self.store.env.read_txn()?;
        let Some(bytes) = self.store.vectors.get(&rtxn, id.as_bytes())? else {
            return Ok(None);
        };

        let vector = le_bytes_to_f32_vec(bytes)?;
        if vector.len() != self.config.dimensions {
            // Persisted-data corruption — the LMDB row decoded to a vector
            // whose length does not match the configured dimensionality.
            // Distinct from `DimensionMismatch`, which is reserved for
            // caller input validation in `search_vector` / `index_vector`.
            return Err(Error::CorruptedIndex("vector value"));
        }

        Ok(Some(vector))
    }

    /// Searches nearest neighbors by cosine similarity using the HNSW index.
    pub fn search_vector(&self, query: &[f32], limit: usize) -> Result<Vec<ScoredEntity>> {
        if query.len() != self.config.dimensions {
            return Err(Error::DimensionMismatch {
                expected: self.config.dimensions,
                got: query.len(),
            });
        }
        if let Some(error) = Error::invalid_vector_component(query) {
            return Err(error);
        }

        let rtxn = self.store.env.read_txn()?;
        hnsw::hnsw_search(&self.store, &self.config, &rtxn, query, limit)
    }

    /// Stores a directed edge and its reverse index entry.
    pub fn put_edge(
        &self,
        src: &EntityId,
        kind: EdgeKind,
        tgt: &EntityId,
        weight: f32,
    ) -> Result<()> {
        self.batch().edge(src, kind, tgt, weight).commit()
    }

    /// Stores a directed edge with explicit VAD scores.
    pub fn put_edge_with_vad(
        &self,
        src: &EntityId,
        kind: EdgeKind,
        tgt: &EntityId,
        weight: f32,
        vad: Vad,
    ) -> Result<()> {
        self.batch()
            .edge_with_vad(src, kind, tgt, weight, vad)
            .commit()
    }

    /// Deletes a directed edge and its reverse index entry.
    pub fn delete_edge(&self, src: &EntityId, kind: EdgeKind, tgt: &EntityId) -> Result<bool> {
        let key_out = Store::encode_edge_key(src, kind, tgt);
        let key_in = Store::encode_edge_key(tgt, kind, src);

        self.with_write_txn(|wtxn| {
            let existed_out = self.store.edges_out.delete(wtxn, &key_out)?;
            let deleted_in = self.store.edges_in.delete(wtxn, &key_in)?;

            if !existed_out {
                // Inbound-only rows are opportunistic cleanup for an inconsistent
                // reverse index and do not affect the outbound graph PPR uses.
                let _ = deleted_in;
                return Ok(false);
            }

            ppr::invalidate_ppr_for_edge(&self.store, wtxn, src, tgt)?;
            ppr::increment_graph_version(&self.store, wtxn)?;
            Ok(true)
        })
    }

    /// Returns outbound edges for `src`.
    pub fn edges_out(&self, src: &EntityId) -> Result<Vec<EdgeInfo>> {
        let rtxn = self.store.env.read_txn()?;
        scan_edges(&self.store.edges_out, &rtxn, src.as_bytes())
    }

    /// Returns inbound edges for `tgt`.
    pub fn edges_in(&self, tgt: &EntityId) -> Result<Vec<EdgeInfo>> {
        let rtxn = self.store.env.read_txn()?;
        scan_edges(&self.store.edges_in, &rtxn, tgt.as_bytes())
    }

    /// Returns BM25 text matches for a query.
    pub fn search_text(&self, query: &str, limit: usize) -> Result<Vec<ScoredEntity>> {
        self.ensure_text_index_trusted()?;
        let rtxn = self.store.env.read_txn()?;
        bm25::search_text(
            &self.store,
            &rtxn,
            &self.analyzer,
            &bm25::Bm25Config::default(),
            query,
            limit,
        )
    }

    /// Creates a new write batch builder bound to this vault.
    pub fn batch(&self) -> BatchBuilder<'_> {
        BatchBuilder::new(self)
    }

    /// Creates a batch builder that writes into an externally-owned transaction.
    ///
    /// Call `.apply(wtxn)` to execute writes without committing.
    /// Use with `with_write_txn()` for atomic multi-operation writes (e.g. entity + pm marker).
    pub fn batch_in(&self) -> TxnBatchBuilder<'_> {
        TxnBatchBuilder::new(self)
    }

    /// Creates a query pipeline builder for multi-signal retrieval.
    pub fn query(&self) -> PipelineBuilder<'_> {
        PipelineBuilder::new(self)
    }

    /// Creates a context pack builder for retrieval + hydration + serialization.
    pub fn context_pack(&self) -> ContextPackBuilder<'_> {
        ContextPackBuilder::new(self)
    }

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
            EntityMetadataHeader::parse(raw).ok_or(Error::CorruptedIndex("entity header"))?;
        Ok(header.learned_at)
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
            require_key_len(key, 24, "temporal learned key")?;
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

    /// Executes a closure within a single LMDB write transaction.
    ///
    /// The transaction commits on `Ok(())` return and rolls back on `Err`.
    /// Used by the sync layer to atomically write entity data + pending-mirror markers.
    pub fn with_write_txn<F, T>(&self, f: F) -> Result<T>
    where
        F: FnOnce(&mut heed::RwTxn<'_>) -> Result<T>,
    {
        let mut wtxn = self.store.env.write_txn()?;
        let result = f(&mut wtxn)?;
        wtxn.commit()?;
        Ok(result)
    }

    // Read/write/list helpers intentionally remain behind `feature = "sync"`
    // instead of `cfg(test)` because the sync bridge regression suite is an
    // integration test crate. Production bridge code still uses direct
    // transactional `sync_state` access when multiple keys must update
    // atomically.

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

    /// Test utility for deleting a key from the sync_state database.
    #[cfg(all(feature = "sync", test))]
    pub fn sync_state_delete(&self, key: &str) -> Result<bool> {
        self.with_write_txn(|wtxn| Ok(self.store.sync_state.delete(wtxn, key)?))
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

    /// Returns the raw entity blob (header + data) for an entity.
    ///
    /// Unlike `get()` which strips the header, this returns the full LMDB value.
    pub fn get_raw(&self, id: &EntityId) -> Result<Option<Vec<u8>>> {
        let rtxn = self.store.env.read_txn()?;
        self.get_raw_in(&rtxn, id)
    }

    pub(crate) fn get_raw_in(
        &self,
        rtxn: &heed::RoTxn<'_>,
        id: &EntityId,
    ) -> Result<Option<Vec<u8>>> {
        Ok(self
            .store
            .entities
            .get(rtxn, id.as_bytes())?
            .map(|bytes| bytes.to_vec()))
    }

    // ─── Tree Query API ───────────────────────────────────────

    /// Returns all entity IDs of a given type via prefix scan on type_index.
    ///
    /// Returns all matching entity IDs, or `Err(IndexOverflow("entities_by_type"))`
    /// if the scan would exceed `MAX_TYPE_QUERY_RESULTS`.
    pub fn entities_by_type(&self, entity_type: u8) -> Result<Vec<EntityId>> {
        let rtxn = self.store.env.read_txn()?;
        let mut ids = Vec::new();
        for entry in self.store.type_index.prefix_iter(&rtxn, &[entity_type])? {
            if ids.len() >= MAX_TYPE_QUERY_RESULTS {
                return Err(Error::IndexOverflow("entities_by_type"));
            }
            let (key, _) = entry?;
            require_key_len(key, 17, "type index key")?;
            let id = EntityId::from_bytes(
                key[1..17]
                    .try_into()
                    .map_err(|_| Error::CorruptedIndex("type index key"))?,
            )
            .map_err(|_| Error::CorruptedIndex("type index key"))?;
            ids.push(id);
        }
        Ok(ids)
    }

    /// Returns the entity type byte for a stored entity, or None if not found.
    pub fn get_entity_type(&self, id: &EntityId) -> Result<Option<u8>> {
        let rtxn = self.store.env.read_txn()?;
        let Some(raw) = self.store.entities.get(&rtxn, id.as_bytes())? else {
            return Ok(None);
        };
        let header =
            EntityMetadataHeader::parse(raw).ok_or(Error::CorruptedIndex("entity header"))?;
        Ok(Some(header.entity_type))
    }

    /// Outbound edge targets filtered by kind and optional target entity type.
    ///
    /// For a ChildOf edge (child → parent), calling `targets(child, ChildOf, None)`
    /// returns the parent.
    pub fn targets(
        &self,
        src: &EntityId,
        kind: EdgeKind,
        target_type: Option<u8>,
    ) -> Result<Vec<EntityId>> {
        let rtxn = self.store.env.read_txn()?;
        self.filtered_edge_peers(
            &rtxn,
            &self.store.edges_out,
            src,
            kind,
            target_type,
            "targets",
        )
    }

    /// Inbound edge sources filtered by kind and optional source entity type.
    ///
    /// For a ChildOf edge (child → parent), calling `sources(parent, ChildOf, None)`
    /// returns the children.
    pub fn sources(
        &self,
        tgt: &EntityId,
        kind: EdgeKind,
        source_type: Option<u8>,
    ) -> Result<Vec<EntityId>> {
        let rtxn = self.store.env.read_txn()?;
        self.filtered_edge_peers(
            &rtxn,
            &self.store.edges_in,
            tgt,
            kind,
            source_type,
            "sources",
        )
    }

    /// Scans an edge database (edges_out or edges_in) for entries matching `kind`,
    /// returning the peer entity IDs. Optionally filters by the peer's entity type.
    ///
    /// Capped at `MAX_EDGE_QUERY_RESULTS` scanned peer rows to prevent
    /// unbounded allocation and worst-case filtered scans.
    fn filtered_edge_peers(
        &self,
        rtxn: &heed::RoTxn<'_>,
        db: &Database<Bytes, Bytes>,
        prefix_id: &EntityId,
        kind: EdgeKind,
        peer_type: Option<u8>,
        overflow_context: &'static str,
    ) -> Result<Vec<EntityId>> {
        let prefix = edge_kind_prefix(prefix_id, kind);
        let mut ids = Vec::new();
        for (scanned, entry) in db.prefix_iter(rtxn, &prefix)?.enumerate() {
            if scanned >= MAX_EDGE_QUERY_RESULTS {
                return Err(Error::IndexOverflow(overflow_context));
            }
            let (key, value) = entry?;
            let peer = parse_edge_record(key, value)?.target;

            if let Some(req_type) = peer_type
                && !self.entity_has_type(rtxn, &peer, req_type)?
            {
                continue;
            }

            ids.push(peer);
        }
        Ok(ids)
    }

    /// Returns true if the entity exists and has the given type byte.
    ///
    /// Returns `Ok(false)` for missing entities or unparsable headers (corruption).
    /// This is intentional for edge filtering: a corrupted peer should be skipped,
    /// not fail the entire query. Compare with `get_entity_type()` which returns
    /// `Err(CorruptedIndex("entity header"))` on corruption — appropriate for
    /// direct lookups where the caller should know about data issues.
    fn entity_has_type(
        &self,
        rtxn: &heed::RoTxn<'_>,
        id: &EntityId,
        expected_type: u8,
    ) -> Result<bool> {
        let Some(raw) = self.store.entities.get(rtxn, id.as_bytes())? else {
            return Ok(false);
        };
        let Some(header) = EntityMetadataHeader::parse(raw) else {
            return Ok(false);
        };
        Ok(header.entity_type == expected_type)
    }

    /// Subtree descendants via ChildOf traversal, limited to `max_depth`.
    /// Returns `(id, depth)` pairs sorted by depth.
    ///
    /// Uses BFS internally (queue-based) so that when the result cap is hit,
    /// shallower nodes are always included before deeper ones. This ensures
    /// fair capping across wide trees.
    /// Children are found via inbound ChildOf edges (since ChildOf direction is
    /// child → parent, children appear in the parent's edges_in).
    ///
    /// Returns all descendants, or `Err(IndexOverflow("subtree"))` if the
    /// result set or pending frontier would exceed `MAX_SUBTREE_RESULTS`.
    pub fn subtree(&self, root: &EntityId, max_depth: u32) -> Result<Vec<(EntityId, u32)>> {
        let rtxn = self.store.env.read_txn()?;
        let mut result = Vec::new();
        let mut frontier = std::collections::VecDeque::from([(*root, 0_u32)]);
        let mut visited = std::collections::HashSet::new();
        visited.insert(*root);

        while let Some((node, depth)) = frontier.pop_front() {
            if depth > 0 {
                if result.len() >= MAX_SUBTREE_RESULTS {
                    return Err(Error::IndexOverflow("subtree"));
                }
                result.push((node, depth));
            }
            if depth >= max_depth {
                continue;
            }

            // Find children: inbound ChildOf edges (child --ChildOf--> node)
            let child_prefix = edge_kind_prefix(&node, EdgeKind::ChildOf);
            for entry in self.store.edges_in.prefix_iter(&rtxn, &child_prefix)? {
                let (key, value) = entry?;
                let child = parse_edge_record(key, value)?.target;
                if visited.insert(child) {
                    if result.len() + frontier.len() >= MAX_SUBTREE_RESULTS {
                        return Err(Error::IndexOverflow("subtree"));
                    }
                    frontier.push_back((child, depth + 1));
                }
            }
        }

        // BFS already produces depth-ordered results, but sort to ensure
        // deterministic ordering within each depth level (by entity ID).
        result.sort_unstable_by(|a, b| {
            a.1.cmp(&b.1)
                .then_with(|| a.0.as_bytes().cmp(b.0.as_bytes()))
        });
        Ok(result)
    }

    /// Walk ancestors via outbound ChildOf edges.
    ///
    /// Returns ancestor IDs from immediate parent to root (nearest first).
    /// The `visited` set prevents infinite loops on corrupted cyclic data, and
    /// `MAX_ANCESTOR_DEPTH` bounds pathological acyclic chains.
    pub fn ancestors(&self, node: &EntityId) -> Result<Vec<EntityId>> {
        let rtxn = self.store.env.read_txn()?;
        let mut result = Vec::new();
        let mut current = *node;
        let mut visited = std::collections::HashSet::new();
        visited.insert(current);

        while let Some(parent) = first_child_of_parent(&self.store, &rtxn, &current)? {
            if !visited.insert(parent) {
                break; // Cycle detected — stop walking but don't error
            }
            if result.len() >= MAX_ANCESTOR_DEPTH {
                return Err(Error::IndexOverflow("ancestors"));
            }
            result.push(parent);
            current = parent;
        }

        Ok(result)
    }

    /// Checks whether making `target` a parent of `node` would create a cycle.
    ///
    /// Convenience wrapper that opens its own read transaction.
    /// For atomic check+insert, use `would_create_cycle_in_txn` within a
    /// write transaction (see `BatchBuilder::edge_checked`).
    pub fn would_create_cycle(&self, node: &EntityId, target: &EntityId) -> Result<bool> {
        let rtxn = self.store.env.read_txn()?;
        self.would_create_cycle_in_txn(&rtxn, node, target)
    }

    /// Checks whether making `target` a parent of `node` would create a cycle,
    /// using the provided read transaction for atomicity with subsequent writes.
    ///
    /// Walks ancestors of `target` — if `node` is found among them, it's a cycle.
    /// Short-circuits as soon as `node` is found instead of collecting all ancestors.
    /// The `visited` set prevents infinite loops on corrupted cyclic data, and
    /// `MAX_CHILD_OF_CYCLE_TRAVERSAL_STEPS` bounds pathological acyclic chains.
    pub(crate) fn would_create_cycle_in_txn(
        &self,
        rtxn: &heed::RoTxn<'_>,
        node: &EntityId,
        target: &EntityId,
    ) -> Result<bool> {
        if node == target {
            return Ok(true);
        }
        let mut current = *target;
        let mut visited = std::collections::HashSet::new();
        visited.insert(current);
        let mut traversed_steps = 0usize;

        while let Some(parent) = first_child_of_parent(&self.store, rtxn, &current)? {
            if traversed_steps >= MAX_CHILD_OF_CYCLE_TRAVERSAL_STEPS {
                return Err(Error::IndexOverflow(ERR_CHILD_OF_CYCLE_CHECK));
            }
            traversed_steps += 1;
            if parent == *node {
                return Ok(true);
            }
            if !visited.insert(parent) {
                break; // Existing cycle in data — stop walking
            }
            current = parent;
        }
        Ok(false)
    }
}

fn scan_edges(
    database: &Database<Bytes, Bytes>,
    rtxn: &heed::RoTxn<'_>,
    prefix: &[u8; 16],
) -> Result<Vec<EdgeInfo>> {
    let mut edges = Vec::new();
    for entry in database.prefix_iter(rtxn, prefix.as_slice())? {
        if edges.len() >= MAX_EDGE_QUERY_RESULTS {
            // Fail loud — sync mirror paths (replay_pending_mirrors,
            // reverse_rematerialize) must not silently truncate edges
            // for high-degree nodes.
            return Err(Error::IndexOverflow("scan_edges"));
        }
        let (key, value) = entry?;
        edges.push(parse_edge_record(key, value)?);
    }
    Ok(edges)
}

/// Snapshot of a vault's text-index state. Returned from
/// [`Vault::text_index_status`].
#[derive(Debug, Clone)]
pub struct TextIndexStatus {
    /// Number of logical documents currently indexed.
    pub total_docs: u32,
    /// Schema version recorded on disk. `None` for vaults with no text
    /// index writes yet.
    pub schema_version: Option<u16>,
    /// Analyzer manifest resolved at open time (reflects dict discovery
    /// against `VaultConfig.dict_search_paths`).
    pub analyzer_manifest: AnalyzerManifest,
}

/// Read-only report of vault open-integrity metadata returned by
/// [`Vault::doctor`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct VaultDoctorReport {
    /// Value read from `vault_meta["storage_abi_version"]`.
    pub storage_abi_version: Option<u16>,
    /// Value read from `vault_meta["schema_version"]`.
    pub storage_schema_version: Option<u16>,
    /// Value read from `hnsw_meta["model_id"]`.
    pub embedding_model_id: Option<String>,
    /// Vector/HNSW compatibility state read from `hnsw_meta["hnsw_config"]`.
    pub hnsw: VaultDoctorHnswReport,
    /// Lowercase hex of `vault_meta["text_analyzer_manifest_hash"]`.
    pub analyzer_manifest_hash: Option<String>,
    /// Lowercase hex of `vault_meta["text_bm25_field_schema_hash"]`.
    pub bm25_field_schema_hash: Option<String>,
    /// Value read from `vault_meta["text_index_schema_version"]`.
    pub text_index_schema_version: Option<u16>,
    /// ARCH-0019 named database manifest presence.
    pub db_manifest: VaultDoctorDbManifestReport,
    /// Metadata fields whose rows were present but could not be decoded.
    pub unreadable_fields: Vec<String>,
}

/// State of the persisted HNSW compatibility row.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[non_exhaustive]
#[serde(rename_all = "snake_case")]
pub enum VaultDoctorHnswRecordState {
    /// No `hnsw_config` row is present.
    Missing,
    /// Legacy row shape without metric/structure tags.
    Legacy,
    /// Current row shape with all compatibility fields.
    Current,
    /// Row exists but does not match any known compatibility encoding.
    Invalid,
}

/// Vector/HNSW compatibility values persisted in `hnsw_meta`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct VaultDoctorHnswReport {
    /// Encoding state of `hnsw_meta["hnsw_config"]`.
    pub record_state: VaultDoctorHnswRecordState,
    /// Persisted vector dimensions.
    pub vector_dimensions: Option<usize>,
    /// Persisted layer-0 HNSW neighbor cap.
    pub m_max_0: Option<usize>,
    /// Persisted HNSW construction beam width.
    pub ef_construction: Option<usize>,
    /// Persisted vector distance metric.
    pub distance_metric: Option<String>,
    /// Persisted vector index structure.
    pub index_structure: Option<String>,
}

/// Presence report for the ARCH-0019 named LMDB database manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct VaultDoctorDbManifestReport {
    /// Number of databases required by `DB_MANIFEST`.
    pub expected_count: usize,
    /// Number of required databases found in the LMDB unnamed database.
    pub present_count: usize,
    /// Required database names found in the LMDB unnamed database.
    pub present_names: Vec<String>,
    /// Required database names missing from the LMDB unnamed database.
    pub missing_names: Vec<String>,
    /// Extra named databases not listed in `DB_MANIFEST`.
    pub unexpected_names: Vec<String>,
}

/// Canonical hash over BM25F field-schema semantics that make existing
/// posting, forward, and field-length rows compatible with this build.
/// Scoring-only knobs such as weights and `b` are deliberately excluded.
fn bm25_field_schema_hash() -> [u8; 32] {
    bm25_field_schema_hash_for_records(&bm25_field_schema_records(
        &bm25::Bm25Config::default(),
        bm25::POSTINGS_VALUE_FORMAT_VERSION,
    ))
}

#[derive(Clone, Copy)]
struct Bm25FieldSchemaRecord {
    field_id: u16,
    channel_name: &'static str,
    length_policy: bm25::FieldLengthPolicy,
    permits_zero_doc_field_length: bool,
    postings_value_format_version: u16,
}

fn bm25_field_schema_records(
    config: &bm25::Bm25Config,
    postings_value_format_version: u16,
) -> Vec<Bm25FieldSchemaRecord> {
    AnalyzerChannel::ALL_V1
        .into_iter()
        .map(|channel| Bm25FieldSchemaRecord {
            field_id: channel.field_id(),
            channel_name: channel.as_str(),
            length_policy: config.field(channel).length_policy,
            permits_zero_doc_field_length: channel.permits_zero_doc_field_length(),
            postings_value_format_version,
        })
        .collect()
}

fn bm25_field_schema_hash_for_records(records: &[Bm25FieldSchemaRecord]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b"oneiron-bm25-field-schema-v2");
    h.update([0]);
    for record in records {
        h.update(record.field_id.to_le_bytes());
        h.update([0]);
        h.update(record.channel_name.as_bytes());
        h.update([0]);
        h.update(record.length_policy.manifest_tag().as_bytes());
        h.update([0]);
        h.update([u8::from(record.permits_zero_doc_field_length)]);
        h.update([0]);
        h.update(record.postings_value_format_version.to_le_bytes());
        h.update([0]);
    }
    h.finalize().into()
}

fn read_text_schema_version(store: &Store, rtxn: &heed::RoTxn<'_>) -> Result<Option<u16>> {
    let Some(raw) = store.vault_meta.get(rtxn, TEXT_INDEX_SCHEMA_VERSION_KEY)? else {
        return Ok(None);
    };
    let bytes: [u8; 2] = raw
        .try_into()
        .map_err(|_| Error::CorruptedIndex("text schema version"))?;
    Ok(Some(u16::from_le_bytes(bytes)))
}

fn read_hash_32(store: &Store, rtxn: &heed::RoTxn<'_>, key: &[u8]) -> Result<Option<[u8; 32]>> {
    let Some(raw) = store.vault_meta.get(rtxn, key)? else {
        return Ok(None);
    };
    let arr: [u8; 32] = raw
        .try_into()
        .map_err(|_| Error::CorruptedIndex("text index hash"))?;
    Ok(Some(arr))
}

fn doctor_optional_u16(
    value: Result<Option<u16>>,
    field: &'static str,
    unreadable_fields: &mut Vec<String>,
) -> Result<Option<u16>> {
    match value {
        Ok(value) => Ok(value),
        Err(Error::CorruptedIndex(_) | Error::InvalidKey) => {
            unreadable_fields.push(field.to_owned());
            Ok(None)
        }
        Err(err) => Err(err),
    }
}

fn doctor_hash_hex(
    store: &Store,
    rtxn: &heed::RoTxn<'_>,
    key: &[u8],
    field: &'static str,
    unreadable_fields: &mut Vec<String>,
) -> Result<Option<String>> {
    match read_hash_32(store, rtxn, key) {
        Ok(Some(hash)) => Ok(Some(bytes_to_hex_lower(&hash))),
        Ok(None) => Ok(None),
        Err(Error::CorruptedIndex(_) | Error::InvalidKey) => {
            unreadable_fields.push(field.to_owned());
            Ok(None)
        }
        Err(err) => Err(err),
    }
}

fn doctor_embedding_model_id(
    store: &Store,
    rtxn: &heed::RoTxn<'_>,
    unreadable_fields: &mut Vec<String>,
) -> Result<Option<String>> {
    let Some(raw) = store.hnsw_meta.get(rtxn, MODEL_ID_KEY)? else {
        return Ok(None);
    };
    match crate::store::parse_utf8_bytes(raw) {
        Ok(model_id) => Ok(Some(model_id)),
        Err(Error::InvalidKey | Error::CorruptedIndex(_)) => {
            unreadable_fields.push("hnsw_meta.model_id".to_owned());
            Ok(None)
        }
        Err(err) => Err(err),
    }
}

fn doctor_hnsw(
    store: &Store,
    rtxn: &heed::RoTxn<'_>,
    unreadable_fields: &mut Vec<String>,
) -> Result<VaultDoctorHnswReport> {
    match crate::store::read_hnsw_compatibility(&store.hnsw_meta, rtxn) {
        Ok(HnswCompatibilityState::Missing) => Ok(VaultDoctorHnswReport {
            record_state: VaultDoctorHnswRecordState::Missing,
            vector_dimensions: None,
            m_max_0: None,
            ef_construction: None,
            distance_metric: None,
            index_structure: None,
        }),
        Ok(HnswCompatibilityState::Legacy(config)) => Ok(VaultDoctorHnswReport {
            record_state: VaultDoctorHnswRecordState::Legacy,
            vector_dimensions: Some(config.dimensions),
            m_max_0: Some(config.m_max_0),
            ef_construction: Some(config.ef_construction),
            distance_metric: None,
            index_structure: None,
        }),
        Ok(HnswCompatibilityState::Current(config)) => Ok(VaultDoctorHnswReport {
            record_state: VaultDoctorHnswRecordState::Current,
            vector_dimensions: Some(config.dimensions),
            m_max_0: Some(config.m_max_0),
            ef_construction: Some(config.ef_construction),
            distance_metric: Some(crate::store::format_hnsw_distance_metric(
                config.distance_metric,
            )),
            index_structure: Some(crate::store::format_hnsw_index_structure(
                config.index_structure,
            )),
        }),
        Err(Error::InvalidKey | Error::CorruptedIndex(_)) => {
            unreadable_fields.push("hnsw_meta.hnsw_config".to_owned());
            Ok(VaultDoctorHnswReport {
                record_state: VaultDoctorHnswRecordState::Invalid,
                vector_dimensions: None,
                m_max_0: None,
                ef_construction: None,
                distance_metric: None,
                index_structure: None,
            })
        }
        Err(err) => Err(err),
    }
}

fn doctor_db_manifest(
    store: &Store,
    rtxn: &heed::RoTxn<'_>,
) -> Result<VaultDoctorDbManifestReport> {
    let env_names = crate::store::materialized_database_names(&store.env, rtxn)?;
    let mut present_names = Vec::new();
    let mut missing_names = Vec::new();

    for entry in DB_MANIFEST {
        if env_names.iter().any(|name| name == entry.name) {
            present_names.push(entry.name.to_owned());
        } else {
            missing_names.push(entry.name.to_owned());
        }
    }

    let mut unexpected_names: Vec<String> = env_names
        .into_iter()
        .filter(|name| !DB_MANIFEST.iter().any(|entry| entry.name == name))
        .collect();

    present_names.sort();
    missing_names.sort();
    unexpected_names.sort();

    Ok(VaultDoctorDbManifestReport {
        expected_count: DB_MANIFEST.len(),
        present_count: present_names.len(),
        present_names,
        missing_names,
        unexpected_names,
    })
}

/// Returns `true` when none of the text-index DBs hold residual rows.
///
/// The `total_docs` sentinel alone isn't authoritative — a zero or missing
/// sentinel coexisting with rows in any of the text DBs is corruption, not
/// emptiness.
fn text_index_residual_rows_empty(store: &Store, txn: &heed::RoTxn<'_>) -> Result<bool> {
    let residual = store.text_postings.len(txn)?
        + store.text_forward.len(txn)?
        + store.text_doc_field_lengths.len(txn)?
        + store.text_bm25_field_stats.len(txn)?;
    Ok(residual == 0)
}

/// Whether the on-disk text index is fully empty: zero `total_docs` AND
/// no residual rows in any text DB. Used by `Vault::open` to decide
/// whether bypassing the manifest handshake is safe.
fn text_index_is_empty(store: &Store, txn: &heed::RoTxn<'_>) -> Result<bool> {
    if bm25::read_total_docs(store, txn)? != 0 {
        return Ok(false);
    }
    text_index_residual_rows_empty(store, txn)
}

/// Validate the on-disk analyzer manifest against the in-memory one. Runs
/// once at `Vault::open`. States are handled per plan ONE-317 §4.2:
///
/// * empty index, any stored state → rewrite manifest, proceed
/// * non-empty, matching hashes → proceed
/// * non-empty, field schema mismatch → `Bm25FieldSchemaChanged`
/// * non-empty, manifest hash mismatch → `IncompatibleAnalyzer` naming the
///   first language whose mode flipped (or `*` when the stored manifest is
///   absent / unparsable, i.e. pre-ONE-317 vault)
fn handshake_text_index_manifest(store: &Store, analyzer: &MultilingualAnalyzer) -> Result<()> {
    let current_manifest = analyzer.manifest();
    let current_manifest_hash = current_manifest
        .canonical_hash()
        .map_err(|e| Error::AnalyzerError(format!("manifest hash: {e}")))?;
    let current_field_schema_hash = bm25_field_schema_hash();

    // Hash-match is the common path on Vault::open and is read-only; only
    // the empty-index rewrite branch mutates. Take a read txn first and
    // upgrade only when we actually need to write.
    let rtxn = store.env.read_txn()?;
    let total_docs = bm25::read_total_docs(store, &rtxn)?;

    if total_docs == 0 {
        // The `total_docs` sentinel alone isn't sufficient to declare the
        // index empty: a missing or zeroed sentinel coexisting with rows
        // in the inverted/forward/length/stats DBs would let us silently
        // rewrite the manifest over a populated incompatible index. Refuse
        // to rewrite unless every text DB is actually empty.
        if !text_index_residual_rows_empty(store, &rtxn)? {
            return Err(Error::CorruptedIndex(
                "text index sentinel missing with residual rows",
            ));
        }
        drop(rtxn);
        let mut wtxn = store.env.write_txn()?;
        write_text_index_manifest_if_empty(store, &mut wtxn, analyzer)?;
        wtxn.commit()?;
        return Ok(());
    }

    let stored_manifest_hash = read_hash_32(store, &rtxn, TEXT_ANALYZER_MANIFEST_HASH_KEY)?;
    let stored_field_schema_hash = read_hash_32(store, &rtxn, TEXT_BM25_FIELD_SCHEMA_HASH_KEY)?;
    let stored_manifest_bytes = store
        .vault_meta
        .get(&rtxn, TEXT_ANALYZER_MANIFEST_KEY)?
        .map(|b| b.to_vec());
    drop(rtxn);

    validate_stored_manifest_hashes(
        stored_manifest_hash,
        stored_field_schema_hash,
        current_manifest_hash,
        current_field_schema_hash,
        &current_manifest,
        stored_manifest_bytes,
    )
}

/// Compare a stored text-index manifest+field-schema hash pair against the
/// current analyzer state. Returns `Ok(())` on compatibility, or the
/// appropriate `IncompatibleAnalyzer` / `Bm25FieldSchemaChanged` /
/// `manifest_mismatch_error` outcome otherwise.
fn validate_stored_manifest_hashes(
    stored_manifest_hash: Option<[u8; 32]>,
    stored_field_schema_hash: Option<[u8; 32]>,
    current_manifest_hash: [u8; 32],
    current_field_schema_hash: [u8; 32],
    current_manifest: &AnalyzerManifest,
    stored_manifest_bytes: Option<Vec<u8>>,
) -> Result<()> {
    let Some(stored_hash) = stored_manifest_hash else {
        // Pre-ONE-317 vault with docs in it: fail closed.
        return Err(Error::IncompatibleAnalyzer {
            lang: "*".to_owned(),
            stored_mode: "unknown",
            current_mode: AnalyzerMode::Portable.as_str(),
        });
    };

    // A present manifest with a missing field-schema hash signals partial
    // corruption, not schema evolution — route it to IncompatibleAnalyzer.
    match stored_field_schema_hash {
        Some(hash) if hash == current_field_schema_hash => {}
        Some(_) => return Err(Error::Bm25FieldSchemaChanged),
        None => {
            return Err(Error::IncompatibleAnalyzer {
                lang: "*".to_owned(),
                stored_mode: "corrupt",
                current_mode: "any",
            });
        }
    }

    if stored_hash == current_manifest_hash {
        return Ok(());
    }

    Err(manifest_mismatch_error(
        current_manifest,
        stored_manifest_bytes,
    ))
}

fn manifest_mismatch_error(
    current_manifest: &AnalyzerManifest,
    stored_manifest_bytes: Option<Vec<u8>>,
) -> Error {
    // Manifest hash changed. Try to name the specific language whose mode
    // flipped; fall back to `*` if the stored manifest doesn't parse.
    if let Some(bytes) = stored_manifest_bytes
        && let Ok(stored) = serde_json::from_slice::<AnalyzerManifest>(&bytes)
    {
        for (lang, current_policy) in &current_manifest.langs {
            if let Some(stored_policy) = stored.langs.get(lang)
                && stored_policy.mode != current_policy.mode
            {
                return Error::IncompatibleAnalyzer {
                    lang: lang.clone(),
                    stored_mode: stored_policy.mode.as_str(),
                    current_mode: current_policy.mode.as_str(),
                };
            }
        }
    }

    Error::IncompatibleAnalyzer {
        lang: "*".to_owned(),
        stored_mode: "mismatched",
        current_mode: "mismatched",
    }
}

/// Validate that a text-index write can append rows compatible with the
/// current on-disk manifest in the same LMDB write transaction that will
/// receive the postings. If the index is still empty, stamp the current
/// manifest as the first authoritative text-index state.
pub(crate) fn ensure_text_index_manifest_matches_wtxn(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    analyzer: &MultilingualAnalyzer,
) -> Result<()> {
    if text_index_is_empty(store, &*wtxn)? {
        write_text_index_manifest(store, wtxn, analyzer)?;
        return Ok(());
    }

    match read_text_schema_version(store, &*wtxn)? {
        Some(TEXT_INDEX_SCHEMA_VERSION) => {}
        Some(_) => return Err(Error::Bm25FieldSchemaChanged),
        None => {
            return Err(Error::IncompatibleAnalyzer {
                lang: "*".to_owned(),
                stored_mode: "corrupt",
                current_mode: "any",
            });
        }
    }

    let current_manifest = analyzer.manifest();
    let current_manifest_hash = current_manifest
        .canonical_hash()
        .map_err(|e| Error::AnalyzerError(format!("manifest hash: {e}")))?;
    let current_field_schema_hash = bm25_field_schema_hash();
    let stored_manifest_hash = read_hash_32(store, &*wtxn, TEXT_ANALYZER_MANIFEST_HASH_KEY)?;
    let stored_field_schema_hash = read_hash_32(store, &*wtxn, TEXT_BM25_FIELD_SCHEMA_HASH_KEY)?;
    let stored_manifest_bytes = store
        .vault_meta
        .get(&*wtxn, TEXT_ANALYZER_MANIFEST_KEY)?
        .map(|b| b.to_vec());

    validate_stored_manifest_hashes(
        stored_manifest_hash,
        stored_field_schema_hash,
        current_manifest_hash,
        current_field_schema_hash,
        &current_manifest,
        stored_manifest_bytes,
    )
}

fn write_text_index_manifest_if_empty(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    analyzer: &MultilingualAnalyzer,
) -> Result<()> {
    if !text_index_is_empty(store, &*wtxn)? {
        return Err(Error::CorruptedIndex(
            "text index populated before manifest write",
        ));
    }
    write_text_index_manifest(store, wtxn, analyzer)
}

/// Write the current analyzer manifest + field-schema hash + schema
/// version into `vault_meta`. Used by open-on-empty-index and by
/// `MaintenanceBuilder::clear_text_index`.
pub(crate) fn write_text_index_manifest(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    analyzer: &MultilingualAnalyzer,
) -> Result<()> {
    let manifest = analyzer.manifest();
    let manifest_json = manifest
        .canonical_json()
        .map_err(|e| Error::AnalyzerError(format!("manifest json: {e}")))?;
    let manifest_hash = manifest
        .canonical_hash()
        .map_err(|e| Error::AnalyzerError(format!("manifest hash: {e}")))?;
    let field_schema_hash = bm25_field_schema_hash();

    store.vault_meta.put(
        wtxn,
        TEXT_INDEX_SCHEMA_VERSION_KEY,
        &TEXT_INDEX_SCHEMA_VERSION.to_le_bytes(),
    )?;
    store
        .vault_meta
        .put(wtxn, TEXT_ANALYZER_MANIFEST_KEY, manifest_json.as_bytes())?;
    store
        .vault_meta
        .put(wtxn, TEXT_ANALYZER_MANIFEST_HASH_KEY, &manifest_hash)?;
    store
        .vault_meta
        .put(wtxn, TEXT_BM25_FIELD_SCHEMA_HASH_KEY, &field_schema_hash)?;
    Ok(())
}

fn parse_edge_record(key: &[u8], value: &[u8]) -> Result<EdgeInfo> {
    if key.len() != EDGE_KEY_LEN {
        return Err(Error::CorruptedIndex("edge record"));
    }

    let kind =
        EdgeKind::try_from_u8(key[ENTITY_ID_LEN]).ok_or(Error::CorruptedIndex("edge record"))?;
    let target = EntityId::from_bytes(
        key[EDGE_KIND_PREFIX_LEN..EDGE_KEY_LEN]
            .try_into()
            .map_err(|_| Error::CorruptedIndex("edge record"))?,
    )
    .map_err(|_| Error::CorruptedIndex("edge record"))?;
    let decoded = decode_edge_value_for_kind(kind, value)
        .map_err(|_| Error::CorruptedIndex("edge record"))?;

    Ok(EdgeInfo {
        kind,
        target,
        target_short_id: None,
        weight: decoded.weight,
        created_at: decoded.created_at,
        vad: decoded.vad,
        provenance: decoded.provenance,
    })
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;
    use crate::store::{
        TEXT_ANALYZER_MANIFEST_HASH_KEY, TEXT_ANALYZER_MANIFEST_KEY,
        TEXT_BM25_FIELD_SCHEMA_HASH_KEY, TEXT_INDEX_SCHEMA_VERSION_KEY,
    };
    use crate::types::{HnswConfig, TextAnalyzerConfig, TimeRange, VaultConfig};

    fn test_config() -> VaultConfig {
        VaultConfig {
            map_size: 32 * 1024 * 1024,
            dimensions: 4,
            embedding_model: Some("test-model-v1".to_owned()),
            max_readers: 16,
            hnsw: HnswConfig {
                m_max_0: 64,
                ef_construction: 200,
                ef_search: 128,
            },
            text_analyzer: TextAnalyzerConfig::default(),
            dict_search_paths: Vec::<PathBuf>::new(),
            skip_text_index_manifest_check: false,
        }
    }

    fn entity(byte: u8) -> EntityId {
        EntityId::from_bytes_unchecked([byte; ENTITY_ID_LEN])
    }

    fn range(start: u64, end: u64) -> TimeRange {
        TimeRange { start, end }
    }

    #[test]
    fn new_empty_vault_writes_manifest_keys() -> Result<()> {
        let tmp = tempfile::tempdir()?;
        let vault = Vault::open(tmp.path(), test_config())?;

        let status = vault.text_index_status()?;
        assert_eq!(status.total_docs, 0);
        assert_eq!(status.schema_version, Some(2));
        assert!(!status.analyzer_manifest.channels.is_empty());

        let rtxn = vault.store.env.read_txn()?;
        for key in [
            TEXT_INDEX_SCHEMA_VERSION_KEY,
            TEXT_ANALYZER_MANIFEST_KEY,
            TEXT_ANALYZER_MANIFEST_HASH_KEY,
            TEXT_BM25_FIELD_SCHEMA_HASH_KEY,
        ] {
            assert!(
                vault.store.vault_meta.get(&rtxn, key)?.is_some(),
                "missing handshake key {:?}",
                std::str::from_utf8(key).unwrap(),
            );
        }
        Ok(())
    }

    #[test]
    fn bypass_on_empty_persists_manifest_for_normal_reopen() -> Result<()> {
        let tmp = tempfile::tempdir()?;
        let a = entity(10);

        {
            let mut cfg = test_config();
            cfg.skip_text_index_manifest_check = true;
            let vault = Vault::open(tmp.path(), cfg)?;
            vault
                .batch()
                .put(&a, 0, range(1, 1), 1, b"a")
                .text(&a, &[("body", "hello world")])
                .commit()?;
        }

        let vault = Vault::open(tmp.path(), test_config())?;
        assert_eq!(vault.search_text("hello", 10)?.len(), 1);
        Ok(())
    }

    #[test]
    fn reopen_same_manifest_preserves_text_index() -> Result<()> {
        let tmp = tempfile::tempdir()?;
        let a = entity(11);

        {
            let vault = Vault::open(tmp.path(), test_config())?;
            vault
                .batch()
                .put(&a, 0, range(1, 1), 1, b"a")
                .text(&a, &[("body", "hello world")])
                .commit()?;
            assert_eq!(vault.search_text("hello", 10)?.len(), 1);
        }

        let vault = Vault::open(tmp.path(), test_config())?;
        assert_eq!(vault.search_text("hello", 10)?.len(), 1);
        Ok(())
    }

    /// `Vault::open` runs the handshake. Each variant corrupts a different
    /// `vault_meta` row on a populated vault and asserts the expected
    /// handshake error.
    ///
    /// Variants:
    /// - `reopen_missing_manifest_on_populated_vault`:
    ///   `delete(TEXT_ANALYZER_MANIFEST_HASH_KEY)` simulates pre-ONE-317
    ///   populated vault. Expects `IncompatibleAnalyzer`.
    /// - `field_schema_hash_mismatch`:
    ///   `put(TEXT_BM25_FIELD_SCHEMA_HASH_KEY, &[0xEE; 32])` simulates
    ///   `Bm25Config` field schema flip. Expects `Bm25FieldSchemaChanged`.
    /// - `analyzer_manifest_hash_mismatch`:
    ///   `put(TEXT_ANALYZER_MANIFEST_HASH_KEY, &[0xCC; 32])` simulates a
    ///   dict mode flip. Expects `IncompatibleAnalyzer`.
    /// - `truncated_stored_hash`:
    ///   `put(TEXT_ANALYZER_MANIFEST_HASH_KEY, &[0xCC; 16])` — half-length
    ///   payload should fail closed, not be silently rehashed. Expects
    ///   `CorruptedIndex`.
    #[test]
    fn handshake_rejects_corrupted_manifest() -> Result<()> {
        enum Corrupt {
            Delete(&'static [u8]),
            Put(&'static [u8], Vec<u8>),
        }
        enum Expect {
            IncompatibleAnalyzer,
            Bm25FieldSchemaChanged,
            CorruptedIndex,
        }

        let cases: Vec<(&str, u8, Corrupt, Expect)> = vec![
            (
                "reopen_missing_manifest_on_populated_vault",
                21,
                Corrupt::Delete(TEXT_ANALYZER_MANIFEST_HASH_KEY),
                Expect::IncompatibleAnalyzer,
            ),
            (
                "field_schema_hash_mismatch",
                31,
                Corrupt::Put(TEXT_BM25_FIELD_SCHEMA_HASH_KEY, vec![0xEE; 32]),
                Expect::Bm25FieldSchemaChanged,
            ),
            (
                "analyzer_manifest_hash_mismatch",
                41,
                Corrupt::Put(TEXT_ANALYZER_MANIFEST_HASH_KEY, vec![0xCC; 32]),
                Expect::IncompatibleAnalyzer,
            ),
            (
                "truncated_stored_hash",
                51,
                Corrupt::Put(TEXT_ANALYZER_MANIFEST_HASH_KEY, vec![0xCC; 16]),
                Expect::CorruptedIndex,
            ),
        ];

        for (case_name, byte, corrupt, expect) in cases {
            let tmp = tempfile::tempdir()?;
            let a = entity(byte);

            {
                let vault = Vault::open(tmp.path(), test_config())?;
                vault
                    .batch()
                    .put(&a, 0, range(1, 1), 1, b"a")
                    .text(&a, &[("body", "hello world")])
                    .commit()?;
            }

            {
                let vault = Vault::open(tmp.path(), test_config())?;
                let mut wtxn = vault.store.env.write_txn()?;
                match &corrupt {
                    Corrupt::Delete(key) => {
                        vault.store.vault_meta.delete(&mut wtxn, key)?;
                    }
                    Corrupt::Put(key, value) => {
                        vault.store.vault_meta.put(&mut wtxn, key, value)?;
                    }
                }
                wtxn.commit()?;
            }

            let err = match Vault::open(tmp.path(), test_config()) {
                Ok(_) => panic!("case {case_name}: expected Vault::open to fail"),
                Err(e) => e,
            };
            let ok = match expect {
                Expect::IncompatibleAnalyzer => {
                    matches!(err, Error::IncompatibleAnalyzer { .. })
                }
                Expect::Bm25FieldSchemaChanged => matches!(err, Error::Bm25FieldSchemaChanged),
                Expect::CorruptedIndex => matches!(err, Error::CorruptedIndex(_)),
            };
            assert!(ok, "case {case_name}: unexpected error {err:?}");
        }
        Ok(())
    }

    #[test]
    fn bm25_field_schema_hash_binds_on_disk_semantics() {
        let records = bm25_field_schema_records(
            &bm25::Bm25Config::default(),
            bm25::POSTINGS_VALUE_FORMAT_VERSION,
        );
        let baseline = bm25_field_schema_hash_for_records(&records);

        let mut changed = records.clone();
        changed[0].field_id = changed[0].field_id.saturating_add(1);
        assert_ne!(baseline, bm25_field_schema_hash_for_records(&changed));

        let mut changed = records.clone();
        changed[0].channel_name = "renamed_surface";
        assert_ne!(baseline, bm25_field_schema_hash_for_records(&changed));

        let mut changed = records.clone();
        changed[0].length_policy = bm25::FieldLengthPolicy::NoNorm;
        assert_ne!(baseline, bm25_field_schema_hash_for_records(&changed));

        let mut changed = records.clone();
        changed[0].permits_zero_doc_field_length = !changed[0].permits_zero_doc_field_length;
        assert_ne!(baseline, bm25_field_schema_hash_for_records(&changed));

        let mut changed = records;
        changed[0].postings_value_format_version += 1;
        assert_ne!(baseline, bm25_field_schema_hash_for_records(&changed));
    }

    #[test]
    fn bm25_field_schema_hash_ignores_scoring_knobs() {
        let default = bm25::Bm25Config::default();
        let mut fields = default.fields;
        fields[AnalyzerChannel::Surface.field_id() as usize].weight = 9.0;
        fields[AnalyzerChannel::Surface.field_id() as usize].b = 0.1;
        let scoring = bm25::Bm25Config {
            k1: 2.0,
            formula: bm25::Bm25Formula::Plus { delta: 0.5 },
            fields,
        };

        assert_eq!(
            bm25_field_schema_hash_for_records(&bm25_field_schema_records(
                &default,
                bm25::POSTINGS_VALUE_FORMAT_VERSION,
            )),
            bm25_field_schema_hash_for_records(&bm25_field_schema_records(
                &scoring,
                bm25::POSTINGS_VALUE_FORMAT_VERSION,
            )),
        );
    }

    // `analyzer_manifest_hash_mismatch` and `handshake_rejects_truncated_stored_hash`
    // are folded into `handshake_rejects_corrupted_manifest` above.

    #[test]
    fn skip_manifest_check_unblocks_clear_text_index_recovery() -> Result<()> {
        let tmp = tempfile::tempdir()?;
        let a = entity(61);

        {
            let vault = Vault::open(tmp.path(), test_config())?;
            vault
                .batch()
                .put(&a, 0, range(1, 1), 1, b"a")
                .text(&a, &[("body", "hello world")])
                .commit()?;
        }

        // Corrupt the analyzer manifest hash so a normal open fails closed.
        {
            let vault = Vault::open(tmp.path(), test_config())?;
            let mut wtxn = vault.store.env.write_txn()?;
            vault
                .store
                .vault_meta
                .put(&mut wtxn, TEXT_ANALYZER_MANIFEST_HASH_KEY, &[0xAB; 32])?;
            wtxn.commit()?;
        }

        assert!(matches!(
            Vault::open(tmp.path(), test_config()),
            Err(Error::IncompatibleAnalyzer { .. })
        ));

        // Bypass the handshake just long enough to rebuild.
        {
            let mut cfg = test_config();
            cfg.skip_text_index_manifest_check = true;
            let vault = Vault::open(tmp.path(), cfg)?;
            vault.maintain().clear_text_index().run()?;
        }

        // Normal open now succeeds — clear_text_index rewrote the manifest.
        let vault = Vault::open(tmp.path(), test_config())?;
        assert_eq!(vault.text_index_status()?.total_docs, 0);
        Ok(())
    }

    #[test]
    fn search_text_fails_closed_when_handshake_bypassed_on_populated_index() -> Result<()> {
        let tmp = tempfile::tempdir()?;
        let a = entity(71);

        {
            let vault = Vault::open(tmp.path(), test_config())?;
            vault
                .batch()
                .put(&a, 0, range(1, 1), 1, b"a")
                .text(&a, &[("body", "hello world")])
                .commit()?;
        }

        // Open with the bypass set — the index has rows but the handshake
        // didn't run. `search_text` would otherwise score against postings
        // that may have been written under a different analyzer manifest.
        let mut cfg = test_config();
        cfg.skip_text_index_manifest_check = true;
        let vault = Vault::open(tmp.path(), cfg)?;
        let err = vault
            .search_text("hello", 10)
            .expect_err("search_text must refuse on bypassed-and-populated state");
        assert!(
            matches!(err, Error::CorruptedIndex(_)),
            "expected CorruptedIndex, got {err:?}",
        );

        // After clear_text_index, trust is restored within the same vault.
        vault.maintain().clear_text_index().run()?;
        assert!(vault.search_text("hello", 10).is_ok());
        Ok(())
    }

    #[test]
    fn text_write_fails_closed_when_trust_bypassed() -> Result<()> {
        let tmp = tempfile::tempdir()?;
        let a = entity(73);
        let b = entity(74);

        {
            let vault = Vault::open(tmp.path(), test_config())?;
            vault
                .batch()
                .put(&a, 0, range(1, 1), 1, b"a")
                .text(&a, &[("body", "hello world")])
                .commit()?;
        }

        let mut cfg = test_config();
        cfg.skip_text_index_manifest_check = true;
        let vault = Vault::open(tmp.path(), cfg)?;
        let err = vault
            .batch()
            .put(&b, 0, range(1, 1), 1, b"b")
            .text(&b, &[("body", "new text")])
            .commit()
            .expect_err("text write must refuse bypassed populated index");
        assert!(
            matches!(err, Error::CorruptedIndex(_)),
            "expected CorruptedIndex, got {err:?}",
        );
        Ok(())
    }

    #[test]
    fn text_write_fails_closed_when_stored_manifest_diverged() -> Result<()> {
        let tmp = tempfile::tempdir()?;
        let a = entity(75);
        let b = entity(76);
        let vault = Vault::open(tmp.path(), test_config())?;
        vault
            .batch()
            .put(&a, 0, range(1, 1), 1, b"a")
            .text(&a, &[("body", "hello world")])
            .commit()?;

        {
            let mut wtxn = vault.store.env.write_txn()?;
            vault
                .store
                .vault_meta
                .put(&mut wtxn, TEXT_ANALYZER_MANIFEST_HASH_KEY, &[0xCC; 32])?;
            wtxn.commit()?;
        }

        let err = vault
            .batch()
            .put(&b, 0, range(1, 1), 1, b"b")
            .text(&b, &[("body", "new text")])
            .commit()
            .expect_err("text write must refuse manifest divergence");
        assert!(
            matches!(err, Error::IncompatibleAnalyzer { .. }),
            "expected IncompatibleAnalyzer, got {err:?}",
        );
        Ok(())
    }

    #[test]
    fn manifest_write_fails_closed_if_index_populated_during_writer() -> Result<()> {
        let tmp = tempfile::tempdir()?;
        let vault = Vault::open(tmp.path(), test_config())?;
        let mut wtxn = vault.store.env.write_txn()?;
        vault
            .store
            .text_postings
            .put(&mut wtxn, b"residual", b"x")?;

        let err = write_text_index_manifest_if_empty(&vault.store, &mut wtxn, &vault.analyzer)
            .expect_err("manifest write must re-check emptiness in writer");
        assert!(
            matches!(err, Error::CorruptedIndex(_)),
            "expected CorruptedIndex, got {err:?}",
        );
        Ok(())
    }

    #[test]
    fn handshake_rejects_residual_rows_with_missing_total_docs_sentinel() -> Result<()> {
        let tmp = tempfile::tempdir()?;
        let a = entity(72);

        {
            let vault = Vault::open(tmp.path(), test_config())?;
            vault
                .batch()
                .put(&a, 0, range(1, 1), 1, b"a")
                .text(&a, &[("body", "alpha")])
                .commit()?;

            // Wipe the `total_docs` sentinel out of `text_meta` while
            // leaving `text_postings` / `text_forward` /
            // `text_doc_field_lengths` / `text_bm25_field_stats` populated.
            let mut wtxn = vault.store.env.write_txn()?;
            vault.store.text_meta.clear(&mut wtxn)?;
            wtxn.commit()?;
        }

        let err = match Vault::open(tmp.path(), test_config()) {
            Ok(_) => panic!("expected Vault::open to fail closed"),
            Err(e) => e,
        };
        assert!(
            matches!(err, Error::CorruptedIndex(_)),
            "expected CorruptedIndex, got {err:?}",
        );
        Ok(())
    }

    #[test]
    fn text_index_status_reflects_indexed_docs() -> Result<()> {
        let tmp = tempfile::tempdir()?;
        let vault = Vault::open(tmp.path(), test_config())?;
        let a = entity(51);
        let b = entity(52);

        vault
            .batch()
            .put(&a, 0, range(1, 1), 1, b"a")
            .put(&b, 0, range(1, 1), 1, b"b")
            .text(&a, &[("body", "first")])
            .text(&b, &[("body", "second")])
            .commit()?;

        assert_eq!(vault.text_index_status()?.total_docs, 2);
        Ok(())
    }
}
