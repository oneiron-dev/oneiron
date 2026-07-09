//! Top-level `Vault` API: the crate's main entry point for all LMDB-backed
//! entity / vector / edge / text / temporal operations. Also hosts
//! edge-record helpers kept for Vault-facing compatibility.

use std::path::Path;
use std::time::Instant;

use heed::Database;
use heed::types::Bytes;
use rmpv::Value;
use serde::Serialize;
use uuid::Uuid;

use crate::affect::Vad;
use crate::affect::VadAnnotationCleanup;
use crate::affect::delete_vad_annotation_metadata_for_type_in_txn;
use crate::affect::delete_vad_annotation_metadata_in_txn;
use crate::affect::vad_annotation_delete_scope_exists_in_txn;
use crate::analyzer::{AnalyzerChannel, AnalyzerManifest, AnalyzerMode, MultilingualAnalyzer};
use crate::batch::{
    ApplyOpsGateMode, BatchOp, ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader, apply_ops,
    apply_ops_with_gate_mode, deindex_entity, deindex_lexical_query_hints_for_target,
    delete_from_phonetic_postings, encode_short_id_forward_key,
};
use crate::channel_identity::{
    ChannelIdentity, ChannelIdentityFulfillment, ChannelIdentityState,
    decode_channel_identity_body, encode_channel_identity_body,
};
use crate::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject,
    claim_generated_origin, encode_claim_body, is_reserved_predicate, validate_claim_body_bytes,
};
use crate::companion::CompanionLifecycleEvent;
use crate::companion::{
    COMPANION_REGISTER_PACK_ID, COMPANION_REGISTER_SHORT_ID_PREFIX, COMPANION_TASK_JOB_KIND,
    CompanionExportClassification, CompanionRecord, CompanionRecordKey, CompanionRegister,
    CompanionSubject, CompanionTask, CompanionTaskKind, CompanionTaskStatus,
    ENTITY_TYPE_COMPANION_REGISTER, EndCompanionRelationship, EndCompanionRelationshipOutcome,
    EnqueueCompanionTaskOutcome, decode_companion_record_body, encode_companion_record_body,
    encode_companion_task_payload,
};
use crate::config::VaultConfig;
use crate::counterparty_contact::{
    CounterpartyContactRecord, CounterpartyOptOutReason, counterparty_contact_index_key,
    counterparty_contact_index_key_for_record, decode_counterparty_contact_body,
    decode_counterparty_contact_index_value, encode_counterparty_contact_body,
    encode_counterparty_contact_index_value,
};
use crate::deletion::HydratedShortIdDeletion;
use crate::deletion::HydratedShortIdDeletionReason;
use crate::deletion::HydratedShortIdDeletionSource;
use crate::deletion::MemoryTimeline;
use crate::deletion::MemoryTimelineRecord;
use crate::deletion::MemoryTimelineRecordState;
use crate::deletion::{
    DeleteEntityOutcome, DeleteReason, HARD_ERASE_SWEEP_PREFIX, HardEraseSweepExtras,
    LAST_HARD_ERASE_SWEEP_SEQ_KEY, RedactionReceiptInput, RedactionScope, ReplayedTombstoneOutcome,
    TombstoneValueV2, decode_hard_erase_sweep_seq, decode_tombstone_value,
    encode_hard_erase_sweep_job, encode_hard_erase_sweep_key, encode_redaction_audit_receipt,
    local_hard_delete_key, pending_tombstone_key, window_label_from_timestamp,
};
use crate::edge::{
    EdgeActorClass, EdgeConfirmationStatus, EdgeInfo, EdgeKind, EdgeProvenanceFlags,
    EdgeValueLayout, edge_value_layout_for_kind, parse_strict_edge_record,
};
use crate::entity_id::{ENTITY_ID_LEN, EntityId, bytes_to_hex_lower};
use crate::error::{Error, Result};
use crate::job_queue::{EnqueueJob, EnqueueOutcome, JobQueue};
use crate::limits::{
    ERR_CHILD_OF_CYCLE_CHECK, MAX_ANCESTOR_DEPTH, MAX_CHILD_OF_CYCLE_TRAVERSAL_STEPS,
};
use crate::outbound_grant::{
    StandingOutboundGrant, decode_standing_outbound_grant_body,
    encode_standing_outbound_grant_body, standing_outbound_grant_principal_index_key,
};
use crate::pipeline::ScoredEntity;
use crate::provenance::{
    EdgeProvenanceClaimBody, EdgeRef, PREDICATE_EDGE_PROVENANCE, ProvenancePrecedence,
    SupersessionStatus, close_record_for_supersession, decode_edge_provenance_body,
    decode_model_entity_body, derive_confirmation_status, downgrade_edge_to_bare,
    encode_edge_provenance_value, encode_model_entity_body, resolve_persisted_actor_class,
    restamp_edge_flags, retract_record, validate_actor_class, validate_edge_provenance_value,
    validate_model_substrate_field, winner_index,
};
use crate::registry::{
    ENTITY_TYPE_AUTHORITY_LOG, ENTITY_TYPE_CHANNEL_IDENTITY, ENTITY_TYPE_CLAIM,
    ENTITY_TYPE_COUNTERPARTY_CONTACT, ENTITY_TYPE_MODEL, ENTITY_TYPE_OUTBOUND_GRANT,
    ENTITY_TYPE_POLICY_MANIFEST, ENTITY_TYPE_REDACTION_AUDIT, EntityClassification,
    StructuralKindRegistration, TypeByteBand, entity_type_registry_entry,
};
use crate::store::{
    DB_MANIFEST, GateDecisionRecord, HnswCompatibilityState, MODEL_ID_KEY, PendingGateConsentGroup,
    PendingGateConsentRecord, RetrievalAction, RetrievalBlendTuningConfig,
    RetrievalBlendWeightTableEntry, RetrievalOutcome, RetrievalOutcomeRecord, RetrievalRunId,
    RetrievalRunRecord, RetrievalScoreBreakdown, RetrievalScoreComponent, RetrievalSignal,
    RetrievalTrace, RetrievalTraceForkHash, STORAGE_ABI_VERSION_KEY, STORAGE_SCHEMA_VERSION_KEY,
    Store, TEXT_ANALYZER_MANIFEST_HASH_KEY, TEXT_ANALYZER_MANIFEST_KEY,
    TEXT_BM25_FIELD_SCHEMA_HASH_KEY, TEXT_INDEX_SCHEMA_VERSION, TEXT_INDEX_SCHEMA_VERSION_KEY,
    lmdb_database_open_guard,
};
use crate::temporal::TimeRange;
use crate::write_envelope::ClaimCandidate;
use crate::write_envelope::WriteEnvelope;
use crate::{
    BatchBuilder, ContextPackBuilder, MaintenanceBuilder, PipelineBuilder, RetrievalWithTelemetry,
    TxnBatchBuilder, bm25, hnsw, le_bytes_to_f32_vec, ppr, unix_seconds_now,
};

const MIN_MAP_SIZE_BYTES: usize = 1 << 20;

/// Contract stored-weight prior for `claim_of` edges (contracts.ts
/// `edgeKinds.pprWeight` = 1.0), unwrapped at COMPILE time: the writers below
/// hardwire kinds whose prior is pinned non-null, so a contract change to
/// `null` fails the build instead of the write.
pub(crate) const CLAIM_OF_DEFAULT_WEIGHT: f32 = match EdgeKind::ClaimOf.default_weight() {
    Some(weight) => weight,
    None => panic!("contract pins a non-null pprWeight for claim_of"),
};

/// Contract stored-weight prior for `supersedes` edges (contracts.ts
/// `edgeKinds.pprWeight` = 0.3); compile-time unwrapped like
/// [`CLAIM_OF_DEFAULT_WEIGHT`].
pub(crate) const SUPERSEDES_DEFAULT_WEIGHT: f32 = match EdgeKind::Supersedes.default_weight() {
    Some(weight) => weight,
    None => panic!("contract pins a non-null pprWeight for supersedes"),
};

/// Length of the edge-kind prefix: `entity_id (16) | kind (1)`.
const EDGE_KIND_PREFIX_LEN: usize = ENTITY_ID_LEN + 1;

/// Cap for `entities_by_type` to prevent unbounded allocation on large indexes.
const MAX_TYPE_QUERY_RESULTS: usize = 100_000;

/// Cap for `entities_in_learned_range` to prevent unbounded allocation on
/// wide time-range queries. Distinct from `MAX_TYPE_QUERY_RESULTS` so the two
/// APIs can be tuned independently.
const MAX_LEARNED_RANGE_RESULTS: usize = 100_000;

/// Cap for `targets`/`sources` to prevent unbounded allocation.
pub(crate) const MAX_EDGE_QUERY_RESULTS: usize = 100_000;

/// Cap for `subtree` to prevent unbounded allocation on deep trees.
const MAX_SUBTREE_RESULTS: usize = 50_000;

/// Cap for renderer timeline expansion across supersession edges.
const MAX_MEMORY_TIMELINE_RECORDS: usize = 10_000;

/// Cap for `sync_state_keys_with_prefix` to prevent unbounded allocation when
/// a pathological prefix scans a very large sync_state database.
#[cfg(feature = "sync")]
const MAX_SYNC_STATE_KEYS: usize = 10_000;

fn seed_default_policy_manifest(
    store: &Store,
    config: &VaultConfig,
    analyzer: &MultilingualAnalyzer,
    text_index_trusted: bool,
) -> Result<()> {
    let id = crate::gate::default_policy_manifest_id()?;
    let timestamp = crate::gate::DEFAULT_POLICY_MANIFEST_TIMESTAMP;
    let ops = vec![BatchOp::Put {
        id,
        entity_type: ENTITY_TYPE_POLICY_MANIFEST,
        occurred: TimeRange {
            start: timestamp,
            end: timestamp,
        },
        learned_at: timestamp,
        data: crate::gate::default_policy_manifest(),
        allow_maintenance: true,
        allow_reserved_predicate: false,
    }];
    let mut wtxn = store.env.write_txn()?;
    apply_ops(
        store,
        config,
        analyzer,
        &mut wtxn,
        ops,
        text_index_trusted,
        false,
        true,
    )?;
    wtxn.commit()?;
    Ok(())
}

/// Build an edge prefix `[entity_id | kind]` for targeted LMDB prefix scans.
/// Avoids scanning all edge kinds for a given entity.
pub(crate) fn edge_kind_prefix(id: &EntityId, kind: EdgeKind) -> [u8; EDGE_KIND_PREFIX_LEN] {
    let mut prefix = [0u8; EDGE_KIND_PREFIX_LEN];
    prefix[..ENTITY_ID_LEN].copy_from_slice(id.as_bytes());
    prefix[ENTITY_ID_LEN] = kind as u8;
    prefix
}

pub(crate) fn require_key_len(key: &[u8], expected: usize, context: &'static str) -> Result<()> {
    if key.len() != expected {
        return Err(Error::CorruptedIndex(context));
    }
    Ok(())
}

pub(crate) fn entity_id_from_type_index_key(key: &[u8]) -> Result<EntityId> {
    require_key_len(key, 17, "type index key")?;
    EntityId::from_bytes(
        key[1..17]
            .try_into()
            .map_err(|_| Error::CorruptedIndex("type index key"))?,
    )
    .map_err(|_| Error::CorruptedIndex("type index key"))
}

pub(crate) fn companion_record_id_for_key_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    key: &CompanionRecordKey,
) -> Result<Option<EntityId>> {
    key.validate()?;
    for index_entry in store
        .type_index
        .prefix_iter(txn, &[ENTITY_TYPE_COMPANION_REGISTER])?
    {
        let (type_key, _) = index_entry?;
        let id = entity_id_from_type_index_key(type_key)?;
        let Some(raw) = store.entities.get(txn, id.as_bytes())? else {
            return Err(Error::CorruptedIndex("companion register type index"));
        };
        let header =
            EntityMetadataHeader::parse(raw).ok_or(Error::CorruptedIndex("entity header"))?;
        if header.entity_type != ENTITY_TYPE_COMPANION_REGISTER {
            return Err(Error::CorruptedIndex("companion register type index"));
        }
        let record = decode_companion_record_body(&raw[ENTITY_METADATA_HEADER_LEN..])?;
        if record.lifecycle == ClaimLifecycleStatus::Active && record.key() == *key {
            return Ok(Some(id));
        }
    }
    Ok(None)
}

pub(crate) fn companion_record_any_id_for_key_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    key: &CompanionRecordKey,
) -> Result<Option<EntityId>> {
    key.validate()?;
    for index_entry in store
        .type_index
        .prefix_iter(txn, &[ENTITY_TYPE_COMPANION_REGISTER])?
    {
        let (type_key, _) = index_entry?;
        let id = entity_id_from_type_index_key(type_key)?;
        let Some(raw) = store.entities.get(txn, id.as_bytes())? else {
            return Err(Error::CorruptedIndex("companion register type index"));
        };
        let header =
            EntityMetadataHeader::parse(raw).ok_or(Error::CorruptedIndex("entity header"))?;
        if header.entity_type != ENTITY_TYPE_COMPANION_REGISTER {
            return Err(Error::CorruptedIndex("companion register type index"));
        }
        let record = decode_companion_record_body(&raw[ENTITY_METADATA_HEADER_LEN..])?;
        if record.key() == *key {
            return Ok(Some(id));
        }
    }
    Ok(None)
}

#[derive(Debug, Default)]
pub(crate) struct CompanionRecordKeyLookup {
    pub(crate) active_id: Option<EntityId>,
    pub(crate) any_id: Option<EntityId>,
    pub(crate) retired_history_id: Option<EntityId>,
}

pub(crate) fn companion_record_key_lookup_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    key: &CompanionRecordKey,
    retired_lifecycle_events: Option<&[CompanionLifecycleEvent]>,
) -> Result<CompanionRecordKeyLookup> {
    key.validate()?;
    let mut lookup = CompanionRecordKeyLookup::default();
    for index_entry in store
        .type_index
        .prefix_iter(txn, &[ENTITY_TYPE_COMPANION_REGISTER])?
    {
        let (type_key, _) = index_entry?;
        let id = entity_id_from_type_index_key(type_key)?;
        let Some(raw) = store.entities.get(txn, id.as_bytes())? else {
            return Err(Error::CorruptedIndex("companion register type index"));
        };
        let header =
            EntityMetadataHeader::parse(raw).ok_or(Error::CorruptedIndex("entity header"))?;
        if header.entity_type != ENTITY_TYPE_COMPANION_REGISTER {
            return Err(Error::CorruptedIndex("companion register type index"));
        }
        let record = decode_companion_record_body(&raw[ENTITY_METADATA_HEADER_LEN..])?;
        if record.key() != *key {
            continue;
        }
        lookup.any_id.get_or_insert(id);
        if record.lifecycle == ClaimLifecycleStatus::Active {
            lookup.active_id.get_or_insert(id);
        }
        if let Some(lifecycle_events) = retired_lifecycle_events
            && record.lifecycle == ClaimLifecycleStatus::Retracted
            && record.lifecycle_events.as_slice() == lifecycle_events
        {
            lookup.retired_history_id.get_or_insert(id);
        }
        if lookup.active_id.is_some()
            && lookup.any_id.is_some()
            && (retired_lifecycle_events.is_none() || lookup.retired_history_id.is_some())
        {
            break;
        }
    }
    Ok(lookup)
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

/// ONE-1149 race-test rendezvous seam. The deterministic raced-delete harness
/// must order the deleter's lock-free `read_entity_header` read_txn (which does
/// NOT take the single LMDB write lock) BEFORE the eraser's commit, so the
/// headerful gate is forced to win the header read and the partial-residue leg
/// is exercised every run instead of nondeterministically diverting to the
/// headerless path. The only way to inject that ordering across the spawned
/// production call is a `#[cfg(test)]` signal emitted from inside
/// `delete_entity_with_reason` once the header is proven `Some`. It compiles
/// out of production entirely (the `#[cfg(not(test))]` shim is a no-op),
/// mirroring the established sweep-side fault-injection seam idiom.
#[cfg(test)]
static AFTER_HEADER_READ: std::sync::Mutex<Option<std::sync::mpsc::SyncSender<()>>> =
    std::sync::Mutex::new(None);

/// Installs the one-shot rendezvous sender consumed by
/// [`signal_after_header_read`]. Called by the raced-delete harness before it
/// releases the deleter; the matching receiver `recv()`s on the eraser side
/// just before its commit.
#[cfg(test)]
pub(crate) fn install_after_header_read_signal(tx: std::sync::mpsc::SyncSender<()>) {
    *AFTER_HEADER_READ
        .lock()
        .expect("AFTER_HEADER_READ poisoned") = Some(tx);
}

/// Fires the rendezvous signal exactly once if a sender is installed, then
/// clears it so unrelated headerful deletes in the same serial run never block
/// on a stale rendezvous. A no-op when no harness installed a sender.
#[cfg(test)]
fn signal_after_header_read() {
    let sender = AFTER_HEADER_READ
        .lock()
        .expect("AFTER_HEADER_READ poisoned")
        .take();
    if let Some(sender) = sender {
        // The rendezvous (`sync_channel(0)`) blocks here until the eraser
        // `recv()`s; that recv is positioned immediately before its commit, so
        // the deleter's header read is provably ordered before the erase.
        let _ = sender.send(());
    }
}

/// Production no-op shim for the race-test rendezvous seam: compiles out the
/// signal entirely in non-test builds.
#[cfg(not(test))]
#[inline(always)]
fn signal_after_header_read() {}

/// Result of resolving a context-pack short reference.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HydratedShortId {
    /// Entity id referenced by the short-id row.
    pub id: EntityId,
    /// Numeric entity type from the entity header, or zero for a dangling row.
    pub entity_type: u8,
    /// Entity learned-at timestamp from the header, or zero for a dangling row.
    pub learned_at: u64,
    /// Deletion metadata when the short-id row resolves to deleted state.
    pub deletion: Option<HydratedShortIdDeletion>,
    /// Entity body bytes. `None` means a deleted shell or dangling row.
    pub body: Option<Vec<u8>>,
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
    /// Live-window delete-routing seam (M4-10 / ONE-1135): a `Weak` to the
    /// production [`crate::sync::manager::WindowManager`], set by
    /// [`crate::sync::manager::WindowManager::attach_to_vault`]. When a
    /// deleted entity's window is OPEN, `write_crdt_tombstone` commits
    /// through the registry-owned live doc instead of a transient snapshot
    /// copy. `Weak` so the vault never keeps a dropped manager (and its
    /// observer subscriptions) alive.
    #[cfg(feature = "sync")]
    pub(crate) live_window_manager: std::sync::Mutex<std::sync::Weak<crate::sync::WindowManager>>,
    /// Distinguishes "no sync manager has ever been attached" from "a manager
    /// was attached but can no longer be queried". The latter is ambiguous for
    /// sweep safety and must defer.
    #[cfg(feature = "sync")]
    pub(crate) live_window_manager_attached: std::sync::atomic::AtomicBool,
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
        if store.created_new_vault() {
            seed_default_policy_manifest(&store, &config, &analyzer, text_index_trusted)?;
        }

        Ok(Self {
            store,
            config,
            analyzer,
            text_index_trusted: std::sync::atomic::AtomicBool::new(text_index_trusted),
            #[cfg(feature = "sync")]
            live_window_manager: std::sync::Mutex::new(std::sync::Weak::new()),
            #[cfg(feature = "sync")]
            live_window_manager_attached: std::sync::atomic::AtomicBool::new(false),
        })
    }

    /// Registers the production window manager as the live-window delete
    /// router (M4-10 / ONE-1135). Called by
    /// [`crate::sync::manager::WindowManager::attach_to_vault`].
    #[cfg(feature = "sync")]
    pub(crate) fn attach_live_window_manager(
        &self,
        manager: std::sync::Weak<crate::sync::WindowManager>,
    ) {
        self.live_window_manager_attached
            .store(true, std::sync::atomic::Ordering::Release);
        *self
            .live_window_manager
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = manager;
    }

    /// Returns the registry-owned live window for `key` — paired with the
    /// manager's [`crate::sync::bridge::Materializer`], so the delete path
    /// can serialize its live-doc tombstone commit against Observer B
    /// callbacks — if a manager is attached AND currently has the window
    /// open. Lookup only — never opens a window (a delete must not fault a
    /// month into memory).
    #[cfg(feature = "sync")]
    pub(crate) fn live_window(
        &self,
        key: &crate::sync::WindowKey,
    ) -> Option<(
        std::sync::Arc<crate::sync::window::LoadedWindow>,
        std::sync::Arc<crate::sync::bridge::Materializer>,
    )> {
        let manager = self
            .live_window_manager
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .upgrade()?;
        let window = manager.window(key)?;
        Some((window, std::sync::Arc::clone(manager.materializer())))
    }

    /// Whether `key` is currently unsafe for sweep compaction: registered in
    /// an attached manager OR still retained by an outstanding orphaned
    /// `Arc<LoadedWindow>` after deregistration. A live doc holds the full op
    /// history in memory, and its next full-snapshot persist would rewrite
    /// that history over a shallow-compacted `d:w:` row, so the sweep must
    /// never compact while such a handle may persist.
    #[cfg(feature = "sync")]
    pub(crate) fn live_window_for_sweep(&self, key: &crate::sync::WindowKey) -> bool {
        let attached = self
            .live_window_manager_attached
            .load(std::sync::atomic::Ordering::Acquire);
        let manager = match self.live_window_manager.lock() {
            Ok(manager) => manager,
            Err(_) => return true,
        };
        match manager.upgrade() {
            Some(manager) => manager.window_live_for_sweep(key),
            None => attached,
        }
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

    /// Registers a vault-scoped pack StructuralKind slot.
    ///
    /// The claim is persisted in `vault_meta` under the dynamic kind-registry
    /// key family and becomes visible to subsequent write validation and
    /// short-id allocation for this vault. The operation rejects reserved
    /// Semantic/CORE bytes, bytes outside `band`, maintenance-band bytes, and
    /// collisions with either static or already-registered runtime entries.
    pub fn register_structural_kind(
        &self,
        type_byte: u8,
        short_id_prefix: impl Into<String>,
        band: TypeByteBand,
        pack: impl Into<String>,
    ) -> Result<StructuralKindRegistration> {
        self.store
            .register_structural_kind(type_byte, short_id_prefix, band, pack)
    }

    /// Returns the dynamic StructuralKind registration for `type_byte`, if
    /// this vault has one. Static registry entries are not mirrored here.
    #[must_use]
    pub fn structural_kind_registration(
        &self,
        type_byte: u8,
    ) -> Option<StructuralKindRegistration> {
        self.store.structural_kind_registration(type_byte)
    }

    /// Returns all vault-scoped dynamic StructuralKind registrations sorted
    /// by type byte. Static registry entries are intentionally excluded.
    #[must_use]
    pub fn structural_kind_registrations(&self) -> Vec<StructuralKindRegistration> {
        self.store.structural_kind_registrations()
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

    /// Appends an immutable TASK/HabitCheckin child under a Habit-role TASK.
    pub fn put_habit_checkin(
        &self,
        habit_id: &EntityId,
        checkin_id: &EntityId,
        occurred: TimeRange,
        learned_at: u64,
        data: &[u8],
    ) -> Result<()> {
        self.batch()
            .put_habit_checkin(habit_id, checkin_id, occurred, learned_at, data)
            .commit()
    }

    /// Mints a standing outbound grant from an authenticated OF-336 grant intent.
    pub fn mint_standing_outbound_grant(
        &self,
        id: &EntityId,
        intent: &crate::genui::GrantMintIntent,
        created_at: u64,
    ) -> Result<StandingOutboundGrant> {
        let policy = {
            let rtxn = self.store.env.read_txn()?;
            crate::gate::resolve_policy_manifest(&self.store, &rtxn)?
        };
        let (binding_diff_handle, read_frontier_hash) =
            crate::gate::standing_outbound_grant_binding_parts(intent, &policy)?;
        let grant = StandingOutboundGrant::from_grant_mint_intent(
            intent,
            created_at,
            binding_diff_handle,
            read_frontier_hash,
        )?;
        let data = encode_standing_outbound_grant_body(&grant)?;
        let mut wtxn = self.store.env.write_txn()?;
        if self.store.entities.get(&wtxn, id.as_bytes())?.is_some() {
            return Err(Error::OutboundGrantAlreadyExists);
        }
        self.apply_standing_outbound_grant_body(&mut wtxn, id, created_at, data)?;
        wtxn.commit()?;
        Ok(grant)
    }

    /// Revokes a standing outbound grant by rewriting the same record as revoked.
    pub fn revoke_standing_outbound_grant(
        &self,
        id: &EntityId,
        revoked_at: u64,
    ) -> Result<StandingOutboundGrant> {
        let mut wtxn = self.store.env.write_txn()?;
        let raw = self
            .store
            .entities
            .get(&wtxn, id.as_bytes())?
            .ok_or(Error::EntityNotFound)?;
        let header =
            EntityMetadataHeader::parse(raw).ok_or(Error::CorruptedIndex("entity header"))?;
        if header.entity_type != ENTITY_TYPE_OUTBOUND_GRANT {
            return Err(Error::InvalidEntityType(header.entity_type));
        }
        let grant = decode_standing_outbound_grant_body(&raw[ENTITY_METADATA_HEADER_LEN..])?;
        let revoked = grant.revoked(revoked_at)?;
        let data = encode_standing_outbound_grant_body(&revoked)?;
        self.apply_standing_outbound_grant_body(&mut wtxn, id, revoked_at, data)?;
        wtxn.commit()?;
        Ok(revoked)
    }

    /// Reads and decodes a standing outbound grant record.
    pub fn get_standing_outbound_grant(
        &self,
        id: &EntityId,
    ) -> Result<Option<StandingOutboundGrant>> {
        let rtxn = self.store.env.read_txn()?;
        let Some(raw) = self.store.entities.get(&rtxn, id.as_bytes())? else {
            return Ok(None);
        };
        let header =
            EntityMetadataHeader::parse(raw).ok_or(Error::CorruptedIndex("entity header"))?;
        if header.entity_type != ENTITY_TYPE_OUTBOUND_GRANT {
            return Err(Error::InvalidEntityType(header.entity_type));
        }
        decode_standing_outbound_grant_body(&raw[ENTITY_METADATA_HEADER_LEN..]).map(Some)
    }

    /// Creates a ChannelIdentity record through the engine maintenance door.
    ///
    /// Generic public entity puts for `ENTITY_TYPE_CHANNEL_IDENTITY` remain
    /// rejected with `MaintenanceKindNotWritable`; this method validates the
    /// CID-1 body and enforces the assignment-key uniqueness invariant before
    /// writing.
    pub fn create_channel_identity(&self, id: &EntityId, identity: &ChannelIdentity) -> Result<()> {
        let data = encode_channel_identity_body(identity)?;
        let mut wtxn = self.store.env.write_txn()?;
        if self.store.entities.get(&wtxn, id.as_bytes())?.is_some()
            || self.channel_identity_assignment_conflict_in_txn(&wtxn, id, identity)?
        {
            return Err(Error::ChannelIdentityAlreadyExists);
        }
        self.apply_channel_identity_body(&mut wtxn, id, identity.state_changed_at, data)?;
        wtxn.commit()?;
        Ok(())
    }

    /// Creates the pre-provisioned own-app home-channel identity for an agent.
    pub fn create_own_app_channel_identity(
        &self,
        id: &EntityId,
        agent_ref: EntityId,
        created_at: u64,
    ) -> Result<ChannelIdentity> {
        let identity = ChannelIdentity::own_app_home(agent_ref, created_at);
        self.create_channel_identity(id, &identity)?;
        Ok(identity)
    }

    /// Applies a checked ChannelIdentity lifecycle transition in place.
    pub fn transition_channel_identity(
        &self,
        id: &EntityId,
        next_state: ChannelIdentityState,
        pending_fulfillment: Option<ChannelIdentityFulfillment>,
        state_changed_at: u64,
        quarantine_until: Option<u64>,
    ) -> Result<ChannelIdentity> {
        let mut wtxn = self.store.env.write_txn()?;
        let raw = self
            .store
            .entities
            .get(&wtxn, id.as_bytes())?
            .ok_or(Error::EntityNotFound)?;
        let header =
            EntityMetadataHeader::parse(raw).ok_or(Error::CorruptedIndex("entity header"))?;
        if header.entity_type != ENTITY_TYPE_CHANNEL_IDENTITY {
            return Err(Error::InvalidEntityType(header.entity_type));
        }
        let current = decode_channel_identity_body(&raw[ENTITY_METADATA_HEADER_LEN..])?;
        let next = current.transition(
            next_state,
            pending_fulfillment,
            state_changed_at,
            quarantine_until,
        )?;
        if self.channel_identity_assignment_conflict_in_txn(&wtxn, id, &next)? {
            return Err(Error::ChannelIdentityAlreadyExists);
        }
        let data = encode_channel_identity_body(&next)?;
        self.apply_channel_identity_body(&mut wtxn, id, state_changed_at, data)?;
        wtxn.commit()?;
        Ok(next)
    }

    /// Reads and decodes a ChannelIdentity record.
    pub fn get_channel_identity(&self, id: &EntityId) -> Result<Option<ChannelIdentity>> {
        let rtxn = self.store.env.read_txn()?;
        let Some(raw) = self.store.entities.get(&rtxn, id.as_bytes())? else {
            return Ok(None);
        };
        let header =
            EntityMetadataHeader::parse(raw).ok_or(Error::CorruptedIndex("entity header"))?;
        if header.entity_type != ENTITY_TYPE_CHANNEL_IDENTITY {
            return Err(Error::InvalidEntityType(header.entity_type));
        }
        decode_channel_identity_body(&raw[ENTITY_METADATA_HEADER_LEN..]).map(Some)
    }

    /// Reads the ChannelIdentity bound to an exact `(channel, address)` key.
    pub fn channel_identity_by_assignment(
        &self,
        channel: &str,
        address_or_handle: &str,
    ) -> Result<Option<(EntityId, ChannelIdentity)>> {
        let rtxn = self.store.env.read_txn()?;
        for entry in self
            .store
            .type_index
            .prefix_iter(&rtxn, &[ENTITY_TYPE_CHANNEL_IDENTITY])?
        {
            let (key, _) = entry?;
            let id = entity_id_from_type_index_key(key)?;
            let raw = self
                .store
                .entities
                .get(&rtxn, id.as_bytes())?
                .ok_or(Error::CorruptedIndex("type index row without entity"))?;
            let header =
                EntityMetadataHeader::parse(raw).ok_or(Error::CorruptedIndex("entity header"))?;
            if header.entity_type != ENTITY_TYPE_CHANNEL_IDENTITY {
                return Err(Error::CorruptedIndex("type index row kind mismatch"));
            }
            let identity = decode_channel_identity_body(&raw[ENTITY_METADATA_HEADER_LEN..])?;
            if identity.assignment_key() == (channel, address_or_handle) {
                return Ok(Some((id, identity)));
            }
        }
        Ok(None)
    }

    /// Creates a per-(identity, counterparty) contact record.
    ///
    /// Generic public entity puts for `ENTITY_TYPE_COUNTERPARTY_CONTACT` remain
    /// rejected with `MaintenanceKindNotWritable`; this method validates the
    /// CID-7 body and enforces a single consent row per target.
    pub fn create_counterparty_contact(
        &self,
        id: &EntityId,
        record: &CounterpartyContactRecord,
    ) -> Result<()> {
        let data = encode_counterparty_contact_body(record)?;
        let mut wtxn = self.store.env.write_txn()?;
        if self.store.entities.get(&wtxn, id.as_bytes())?.is_some()
            || self.counterparty_contact_assignment_conflict_in_txn(&wtxn, id, record)?
        {
            return Err(Error::CounterpartyContactAlreadyExists);
        }
        self.apply_counterparty_contact_body(&mut wtxn, id, record.updated_at, data)?;
        wtxn.commit()?;
        Ok(())
    }

    /// Records a legal/platform opt-out event on a counterparty contact.
    pub fn opt_out_counterparty_contact(
        &self,
        id: &EntityId,
        reason: CounterpartyOptOutReason,
        recorded_at: u64,
    ) -> Result<CounterpartyContactRecord> {
        let mut wtxn = self.store.env.write_txn()?;
        let raw = self
            .store
            .entities
            .get(&wtxn, id.as_bytes())?
            .ok_or(Error::EntityNotFound)?;
        let header =
            EntityMetadataHeader::parse(raw).ok_or(Error::CorruptedIndex("entity header"))?;
        if header.entity_type != ENTITY_TYPE_COUNTERPARTY_CONTACT {
            return Err(Error::InvalidEntityType(header.entity_type));
        }
        let current = decode_counterparty_contact_body(&raw[ENTITY_METADATA_HEADER_LEN..])?;
        let opted_out = current.opted_out(reason, recorded_at)?;
        let data = encode_counterparty_contact_body(&opted_out)?;
        self.apply_counterparty_contact_body(&mut wtxn, id, recorded_at, data)?;
        wtxn.commit()?;
        Ok(opted_out)
    }

    /// Revokes owner visibility/reachability for a counterparty contact.
    pub fn revoke_counterparty_contact(
        &self,
        id: &EntityId,
        revoked_at: u64,
    ) -> Result<CounterpartyContactRecord> {
        let mut wtxn = self.store.env.write_txn()?;
        let raw = self
            .store
            .entities
            .get(&wtxn, id.as_bytes())?
            .ok_or(Error::EntityNotFound)?;
        let header =
            EntityMetadataHeader::parse(raw).ok_or(Error::CorruptedIndex("entity header"))?;
        if header.entity_type != ENTITY_TYPE_COUNTERPARTY_CONTACT {
            return Err(Error::InvalidEntityType(header.entity_type));
        }
        let current = decode_counterparty_contact_body(&raw[ENTITY_METADATA_HEADER_LEN..])?;
        let revoked = current.revoked(revoked_at)?;
        let data = encode_counterparty_contact_body(&revoked)?;
        self.apply_counterparty_contact_body(&mut wtxn, id, revoked_at, data)?;
        wtxn.commit()?;
        Ok(revoked)
    }

    /// Reads and decodes a CounterpartyContact record.
    pub fn get_counterparty_contact(
        &self,
        id: &EntityId,
    ) -> Result<Option<CounterpartyContactRecord>> {
        let rtxn = self.store.env.read_txn()?;
        let Some(raw) = self.store.entities.get(&rtxn, id.as_bytes())? else {
            return Ok(None);
        };
        let header =
            EntityMetadataHeader::parse(raw).ok_or(Error::CorruptedIndex("entity header"))?;
        if header.entity_type != ENTITY_TYPE_COUNTERPARTY_CONTACT {
            return Err(Error::InvalidEntityType(header.entity_type));
        }
        decode_counterparty_contact_body(&raw[ENTITY_METADATA_HEADER_LEN..]).map(Some)
    }

    /// Finds one contact record by `(identity_ref, counterparty)`.
    pub fn find_counterparty_contact(
        &self,
        identity_ref: &EntityId,
        counterparty: &str,
    ) -> Result<Option<(EntityId, CounterpartyContactRecord)>> {
        let rtxn = self.store.env.read_txn()?;
        let index_key = counterparty_contact_index_key(identity_ref, counterparty)?;
        if let Some(raw_id) = self.store.vault_meta.get(&rtxn, &index_key)? {
            let id = decode_counterparty_contact_index_value(raw_id)?;
            let Some(raw) = self.store.entities.get(&rtxn, id.as_bytes())? else {
                return Err(Error::CorruptedIndex(
                    "counterparty contact lookup index entity row",
                ));
            };
            let header = EntityMetadataHeader::parse(raw).ok_or(Error::CorruptedIndex(
                "counterparty contact lookup index entity header",
            ))?;
            if header.entity_type != ENTITY_TYPE_COUNTERPARTY_CONTACT {
                return Err(Error::CorruptedIndex(
                    "counterparty contact lookup index entity type",
                ));
            }
            let record = decode_counterparty_contact_body(&raw[ENTITY_METADATA_HEADER_LEN..])?;
            if !record.matches_counterparty(identity_ref, counterparty) {
                return Err(Error::CorruptedIndex(
                    "counterparty contact lookup index assignment",
                ));
            }
            return Ok(Some((id, record)));
        }

        for entry in self
            .store
            .type_index
            .prefix_iter(&rtxn, &[ENTITY_TYPE_COUNTERPARTY_CONTACT])?
        {
            let (key, _) = entry?;
            let id = entity_id_from_type_index_key(key)?;
            let Some(raw) = self.store.entities.get(&rtxn, id.as_bytes())? else {
                return Err(Error::CorruptedIndex("counterparty contact entity row"));
            };
            let header = EntityMetadataHeader::parse(raw)
                .ok_or(Error::CorruptedIndex("counterparty contact entity header"))?;
            if header.entity_type != ENTITY_TYPE_COUNTERPARTY_CONTACT {
                return Err(Error::CorruptedIndex("counterparty contact entity type"));
            }
            let record = decode_counterparty_contact_body(&raw[ENTITY_METADATA_HEADER_LEN..])?;
            if record.matches_counterparty(identity_ref, counterparty) {
                return Ok(Some((id, record)));
            }
        }
        Ok(None)
    }

    /// Lists contact records visible for a channel identity.
    pub fn counterparty_contacts_for_identity(
        &self,
        identity_ref: &EntityId,
    ) -> Result<Vec<(EntityId, CounterpartyContactRecord)>> {
        let rtxn = self.store.env.read_txn()?;
        let mut records = Vec::new();
        for entry in self
            .store
            .type_index
            .prefix_iter(&rtxn, &[ENTITY_TYPE_COUNTERPARTY_CONTACT])?
        {
            let (key, _) = entry?;
            let id = entity_id_from_type_index_key(key)?;
            let Some(raw) = self.store.entities.get(&rtxn, id.as_bytes())? else {
                return Err(Error::CorruptedIndex("counterparty contact entity row"));
            };
            let header = EntityMetadataHeader::parse(raw)
                .ok_or(Error::CorruptedIndex("counterparty contact entity header"))?;
            if header.entity_type != ENTITY_TYPE_COUNTERPARTY_CONTACT {
                return Err(Error::CorruptedIndex("counterparty contact entity type"));
            }
            let record = decode_counterparty_contact_body(&raw[ENTITY_METADATA_HEADER_LEN..])?;
            if record.identity_ref.as_bytes() == identity_ref.as_bytes() {
                records.push((id, record));
            }
        }
        Ok(records)
    }

    pub(crate) fn channel_identity_assignment_conflict_in_txn(
        &self,
        txn: &heed::RwTxn<'_>,
        id: &EntityId,
        identity: &ChannelIdentity,
    ) -> Result<bool> {
        for entry in self
            .store
            .type_index
            .prefix_iter(txn, &[ENTITY_TYPE_CHANNEL_IDENTITY])?
        {
            let (key, _) = entry?;
            let existing_id = entity_id_from_type_index_key(key)?;
            if existing_id == *id {
                continue;
            }
            let raw = self
                .store
                .entities
                .get(txn, existing_id.as_bytes())?
                .ok_or(Error::CorruptedIndex("type index row without entity"))?;
            let header =
                EntityMetadataHeader::parse(raw).ok_or(Error::CorruptedIndex("entity header"))?;
            if header.entity_type != ENTITY_TYPE_CHANNEL_IDENTITY {
                return Err(Error::CorruptedIndex("type index row kind mismatch"));
            }
            let stored = decode_channel_identity_body(&raw[ENTITY_METADATA_HEADER_LEN..])?;
            if stored.assignment_key() == identity.assignment_key() {
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn counterparty_contact_assignment_conflict_in_txn(
        &self,
        txn: &heed::RwTxn<'_>,
        id: &EntityId,
        record: &CounterpartyContactRecord,
    ) -> Result<bool> {
        let index_key = counterparty_contact_index_key_for_record(record)?;
        if let Some(raw_id) = self.store.vault_meta.get(txn, &index_key)? {
            let existing_id = decode_counterparty_contact_index_value(raw_id)?;
            if existing_id != *id {
                return Ok(true);
            }
        }

        for entry in self
            .store
            .type_index
            .prefix_iter(txn, &[ENTITY_TYPE_COUNTERPARTY_CONTACT])?
        {
            let (key, _) = entry?;
            let existing_id = entity_id_from_type_index_key(key)?;
            if existing_id == *id {
                continue;
            }
            let Some(raw) = self.store.entities.get(txn, existing_id.as_bytes())? else {
                return Err(Error::CorruptedIndex("counterparty contact entity row"));
            };
            let header = EntityMetadataHeader::parse(raw)
                .ok_or(Error::CorruptedIndex("counterparty contact entity header"))?;
            if header.entity_type != ENTITY_TYPE_COUNTERPARTY_CONTACT {
                return Err(Error::CorruptedIndex("counterparty contact entity type"));
            }
            let stored = decode_counterparty_contact_body(&raw[ENTITY_METADATA_HEADER_LEN..])?;
            if stored.matches_counterparty(&record.identity_ref, &record.counterparty) {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Returns the active grant id authorizing a companion profile, if any.
    pub fn companion_profile_access_grant(
        &self,
        principal_ref: &EntityId,
        person_ref: &EntityId,
        persona_ref: &EntityId,
    ) -> Result<Option<EntityId>> {
        let rtxn = self.store.env.read_txn()?;
        crate::gate::companion_profile_access_grant(
            &self.store,
            &rtxn,
            principal_ref,
            person_ref,
            persona_ref,
        )
    }

    /// Creates a companion register record when neither the entity id nor the
    /// `(scope, subject)` register key is already present.
    pub fn create_companion_record(
        &self,
        id: &EntityId,
        record: &CompanionRecord,
        learned_at: u64,
    ) -> Result<()> {
        self.ensure_companion_register_kind()?;
        if record.lifecycle != ClaimLifecycleStatus::Active {
            return Err(Error::InvalidClaimBody(
                "companion record create must be active",
            ));
        }
        let record = record.created_at(learned_at)?;
        let data = encode_companion_record_body(&record)?;
        let key = record.key();
        let mut wtxn = self.store.env.write_txn()?;
        if self.store.entities.get(&wtxn, id.as_bytes())?.is_some()
            || companion_record_any_id_for_key_in_txn(&self.store, &wtxn, &key)?.is_some()
        {
            return Err(Error::CompanionRecordAlreadyExists);
        }
        self.apply_companion_record_body(&mut wtxn, id, learned_at, data)?;
        wtxn.commit()?;
        Ok(())
    }

    /// Writes or replaces a companion register record for an existing id.
    ///
    /// The register key is immutable for an existing record; callers that need
    /// a different `(scope, subject)` should create a new record and retire the
    /// old one.
    pub fn update_companion_record(
        &self,
        id: &EntityId,
        record: &CompanionRecord,
        learned_at: u64,
    ) -> Result<CompanionRecord> {
        self.ensure_companion_register_kind()?;
        if record.lifecycle != ClaimLifecycleStatus::Active {
            return Err(Error::InvalidClaimBody(
                "companion record update must be active",
            ));
        }
        let mut wtxn = self.store.env.write_txn()?;
        let existing = self.read_companion_record_in_txn(&wtxn, id)?;
        if existing.lifecycle != ClaimLifecycleStatus::Active {
            return Err(Error::InvalidClaimBody("companion record is retired"));
        }
        if existing.key() != record.key() {
            return Err(Error::InvalidClaimBody(
                "companion record key cannot change",
            ));
        }
        if existing.export_classification != CompanionExportClassification::LocalOnly
            && record.export_classification == CompanionExportClassification::LocalOnly
        {
            return Err(Error::InvalidClaimBody(
                "companion record export cannot be downgraded to local_only",
            ));
        }
        let mut updated = record.clone();
        updated.lifecycle_events = existing.lifecycle_events;
        if updated.lifecycle_events.is_empty() {
            let ev = crate::companion::CompanionLifecycleEvent::created(learned_at);
            updated.lifecycle_events.push(ev);
        }
        let data = encode_companion_record_body(&updated)?;
        self.apply_companion_record_body(&mut wtxn, id, learned_at, data)?;
        wtxn.commit()?;
        Ok(updated)
    }

    /// Reads and decodes one companion register record by entity id.
    pub fn get_companion_record(&self, id: &EntityId) -> Result<Option<CompanionRecord>> {
        let rtxn = self.store.env.read_txn()?;
        let Some(raw) = self.store.entities.get(&rtxn, id.as_bytes())? else {
            return Ok(None);
        };
        let header =
            EntityMetadataHeader::parse(raw).ok_or(Error::CorruptedIndex("entity header"))?;
        if header.entity_type != ENTITY_TYPE_COMPANION_REGISTER {
            return Err(Error::InvalidEntityType(header.entity_type));
        }
        decode_companion_record_body(&raw[ENTITY_METADATA_HEADER_LEN..]).map(Some)
    }

    /// Retires a companion register record by rewriting it as retracted and
    /// stamping an auditable lifecycle event. Repeating retire on an already
    /// retracted record is an idempotent no-op that returns the stored record
    /// without adding another lifecycle event.
    pub fn retire_companion_record(
        &self,
        id: &EntityId,
        retired_at: u64,
    ) -> Result<CompanionRecord> {
        self.ensure_companion_register_kind()?;
        let mut wtxn = self.store.env.write_txn()?;
        let existing = self.read_companion_record_in_txn(&wtxn, id)?;
        if existing.lifecycle == ClaimLifecycleStatus::Retracted {
            return Ok(existing);
        }
        let retired = existing.retired_at(retired_at)?;
        let data = encode_companion_record_body(&retired)?;
        self.apply_companion_record_body(&mut wtxn, id, retired_at, data)?;
        wtxn.commit()?;
        Ok(retired)
    }

    /// Ends an active companion relationship by breaking the active binding,
    /// scrubbing the private relationship payload, and optionally enqueueing a
    /// goodbye-artifact generation task. General vault entities are not
    /// deleted by this teardown path.
    pub fn end_companion_relationship(
        &self,
        id: &EntityId,
        input: EndCompanionRelationship,
    ) -> Result<EndCompanionRelationshipOutcome> {
        self.ensure_companion_register_kind()?;
        let mut wtxn = self.store.env.write_txn()?;
        let existing = self.read_companion_record_in_txn(&wtxn, id)?;
        if !matches!(&existing.subject, CompanionSubject::Relationship { .. }) {
            return Err(Error::InvalidClaimBody(
                "companion relationship end requires relationship record",
            ));
        }
        let already_ended = existing.lifecycle == ClaimLifecycleStatus::Retracted;

        let mut scrubbed = existing;
        scrubbed.value = Value::Map(vec![
            (Value::from("kind"), Value::from("relationship_ended")),
            (Value::from("private_memory"), Value::from("removed")),
            (Value::from("ended_at"), Value::from(input.ended_at)),
        ]);
        let ended = if already_ended {
            scrubbed.validate_current_schema_lifecycle_events()?;
            scrubbed
        } else {
            scrubbed.retired_at(input.ended_at)?
        };
        let data = encode_companion_record_body(&ended)?;
        self.apply_companion_record_body(&mut wtxn, id, input.ended_at, data)?;

        let goodbye_artifact = if input.ended_badly || already_ended {
            None
        } else {
            let task = CompanionTask::new(CompanionTaskKind::GoodbyeArtifact, ended.key())?;
            let payload = encode_companion_task_payload(&task)?;
            let outcome = JobQueue::new(self).enqueue_in_txn(
                &mut wtxn,
                EnqueueJob {
                    kind: COMPANION_TASK_JOB_KIND.to_owned(),
                    payload,
                    dedupe_key: Some(task.dedupe_key()),
                    run_id: input.run_id,
                    now: input.ended_at,
                },
            )?;
            let status = |job| CompanionTaskStatus {
                job,
                task: task.clone(),
            };
            Some(match outcome {
                EnqueueOutcome::Enqueued(job) => EnqueueCompanionTaskOutcome::Enqueued(status(job)),
                EnqueueOutcome::Existing(job) => EnqueueCompanionTaskOutcome::Existing(status(job)),
            })
        };

        wtxn.commit()?;
        Ok(EndCompanionRelationshipOutcome {
            record: ended,
            goodbye_artifact,
            already_ended,
        })
    }

    /// Revives a retired companion register record as a new active row.
    ///
    /// The retired row remains readable and inactive; the new id receives an
    /// active copy with a typed revive event. Raw updates to retired rows still
    /// fail closed through the generic companion-register put validator.
    pub fn revive_companion_record(
        &self,
        retired_id: &EntityId,
        revived_id: &EntityId,
        record: &CompanionRecord,
        revived_at: u64,
    ) -> Result<CompanionRecord> {
        self.ensure_companion_register_kind()?;
        if record.lifecycle != ClaimLifecycleStatus::Active {
            return Err(Error::InvalidClaimBody(
                "companion record revive payload must be active",
            ));
        }
        let mut wtxn = self.store.env.write_txn()?;
        let retired = self.read_companion_record_in_txn(&wtxn, retired_id)?;
        if retired.lifecycle != ClaimLifecycleStatus::Retracted {
            return Err(Error::InvalidClaimBody(
                "companion record revive requires retired record",
            ));
        }
        if retired.key() != record.key() {
            return Err(Error::InvalidClaimBody(
                "companion record revive key cannot change",
            ));
        }
        let mut revived_seed = record.clone();
        revived_seed.lifecycle = ClaimLifecycleStatus::Retracted;
        revived_seed.lifecycle_events = retired.lifecycle_events;
        let revived = revived_seed.revived_at(revived_at)?;
        let key = revived.key();
        if self
            .store
            .entities
            .get(&wtxn, revived_id.as_bytes())?
            .is_some()
            || companion_record_id_for_key_in_txn(&self.store, &wtxn, &key)?.is_some()
        {
            return Err(Error::CompanionRecordAlreadyExists);
        }
        let data = encode_companion_record_body(&revived)?;
        self.apply_companion_record_body(&mut wtxn, revived_id, revived_at, data)?;
        wtxn.commit()?;
        Ok(revived)
    }

    /// Returns the entity id for a companion register key, if present.
    pub fn companion_record_id_for_key(
        &self,
        key: &CompanionRecordKey,
    ) -> Result<Option<EntityId>> {
        let rtxn = self.store.env.read_txn()?;
        companion_record_id_for_key_in_txn(&self.store, &rtxn, key)
    }

    /// Reads all companion records into an in-memory register snapshot.
    pub fn companion_register(&self) -> Result<CompanionRegister> {
        let rtxn = self.store.env.read_txn()?;
        let mut register = CompanionRegister::new();
        for index_entry in self
            .store
            .type_index
            .prefix_iter(&rtxn, &[ENTITY_TYPE_COMPANION_REGISTER])?
        {
            let (type_key, _) = index_entry?;
            let id = entity_id_from_type_index_key(type_key)?;
            let Some(raw) = self.store.entities.get(&rtxn, id.as_bytes())? else {
                return Err(Error::CorruptedIndex("companion register type index"));
            };
            let header =
                EntityMetadataHeader::parse(raw).ok_or(Error::CorruptedIndex("entity header"))?;
            if header.entity_type != ENTITY_TYPE_COMPANION_REGISTER {
                return Err(Error::CorruptedIndex("companion register type index"));
            }
            let record = decode_companion_record_body(&raw[ENTITY_METADATA_HEADER_LEN..])?;
            if record.lifecycle != ClaimLifecycleStatus::Active {
                continue;
            }
            if register.register(record)?.is_some() {
                return Err(Error::CorruptedIndex("companion register duplicate key"));
            }
        }
        Ok(register)
    }

    fn apply_standing_outbound_grant_body(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        id: &EntityId,
        learned_at: u64,
        data: Vec<u8>,
    ) -> Result<()> {
        let new_grant = decode_standing_outbound_grant_body(&data)?;
        let new_index_key =
            standing_outbound_grant_principal_index_key(&new_grant.principal_ref, id)?;
        let old_index_key = if let Some(raw) = self.store.entities.get(&*wtxn, id.as_bytes())? {
            let Some(header) = EntityMetadataHeader::parse(raw) else {
                return Err(Error::CorruptedIndex("outbound grant entity header"));
            };
            if header.entity_type != ENTITY_TYPE_OUTBOUND_GRANT {
                return Err(Error::CorruptedIndex("outbound grant entity type"));
            }
            let old_grant = decode_standing_outbound_grant_body(
                &raw[crate::batch::ENTITY_METADATA_HEADER_LEN..],
            )?;
            Some(standing_outbound_grant_principal_index_key(
                &old_grant.principal_ref,
                id,
            )?)
        } else {
            None
        };
        apply_ops(
            &self.store,
            &self.config,
            &self.analyzer,
            wtxn,
            vec![BatchOp::Put {
                id: *id,
                entity_type: ENTITY_TYPE_OUTBOUND_GRANT,
                occurred: TimeRange {
                    start: learned_at,
                    end: learned_at,
                },
                learned_at,
                data,
                allow_maintenance: true,
                allow_reserved_predicate: false,
            }],
            self.text_index_trusted
                .load(std::sync::atomic::Ordering::Acquire),
            false,
            true,
        )?;
        if let Some(old_index_key) = old_index_key.as_ref()
            && old_index_key != &new_index_key
        {
            self.store.vault_meta.delete(wtxn, old_index_key)?;
        }
        self.store.vault_meta.put(wtxn, &new_index_key, &[])?;
        Ok(())
    }

    pub(crate) fn apply_channel_identity_body(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        id: &EntityId,
        learned_at: u64,
        data: Vec<u8>,
    ) -> Result<()> {
        apply_ops(
            &self.store,
            &self.config,
            &self.analyzer,
            wtxn,
            vec![BatchOp::Put {
                id: *id,
                entity_type: ENTITY_TYPE_CHANNEL_IDENTITY,
                occurred: TimeRange {
                    start: learned_at,
                    end: learned_at,
                },
                learned_at,
                data,
                allow_maintenance: true,
                allow_reserved_predicate: false,
            }],
            self.text_index_trusted
                .load(std::sync::atomic::Ordering::Acquire),
            false,
            true,
        )
    }

    fn apply_counterparty_contact_body(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        id: &EntityId,
        learned_at: u64,
        data: Vec<u8>,
    ) -> Result<()> {
        let record = decode_counterparty_contact_body(&data)?;
        let new_index_key = counterparty_contact_index_key_for_record(&record)?;
        if let Some(raw_id) = self.store.vault_meta.get(&*wtxn, &new_index_key)? {
            let existing_id = decode_counterparty_contact_index_value(raw_id)?;
            if existing_id != *id {
                return Err(Error::CounterpartyContactAlreadyExists);
            }
        }

        let old_index_key = if let Some(raw) = self.store.entities.get(&*wtxn, id.as_bytes())? {
            let header =
                EntityMetadataHeader::parse(raw).ok_or(Error::CorruptedIndex("entity header"))?;
            if header.entity_type != ENTITY_TYPE_COUNTERPARTY_CONTACT {
                return Err(Error::InvalidEntityType(header.entity_type));
            }
            let old_record = decode_counterparty_contact_body(&raw[ENTITY_METADATA_HEADER_LEN..])?;
            Some(counterparty_contact_index_key_for_record(&old_record)?)
        } else {
            None
        };

        if let Some(old_index_key) = old_index_key.as_ref()
            && old_index_key != &new_index_key
        {
            self.store.vault_meta.delete(wtxn, old_index_key)?;
        }

        apply_ops(
            &self.store,
            &self.config,
            &self.analyzer,
            wtxn,
            vec![BatchOp::Put {
                id: *id,
                entity_type: ENTITY_TYPE_COUNTERPARTY_CONTACT,
                occurred: TimeRange {
                    start: learned_at,
                    end: learned_at,
                },
                learned_at,
                data,
                allow_maintenance: true,
                allow_reserved_predicate: false,
            }],
            self.text_index_trusted
                .load(std::sync::atomic::Ordering::Acquire),
            false,
            true,
        )?;
        let index_value = encode_counterparty_contact_index_value(id);
        self.store
            .vault_meta
            .put(wtxn, &new_index_key, &index_value)?;
        Ok(())
    }

    pub(crate) fn ensure_companion_register_kind(&self) -> Result<()> {
        if self.companion_register_kind_registered()? {
            Ok(())
        } else {
            Err(Error::InvalidEntityType(ENTITY_TYPE_COMPANION_REGISTER))
        }
    }

    fn companion_register_kind_registered(&self) -> Result<bool> {
        let static_registered = entity_type_registry_entry(ENTITY_TYPE_COMPANION_REGISTER)
            .is_some_and(|entry| {
                entry.short_id_prefix == Some(COMPANION_REGISTER_SHORT_ID_PREFIX)
                    && entry.classification == EntityClassification::Pack
                    && entry.band == TypeByteBand::Companion
            });
        if !static_registered {
            return Ok(false);
        }

        if let Some(registration) = self
            .store
            .structural_kind_registration(ENTITY_TYPE_COMPANION_REGISTER)
        {
            let compatible_legacy_row = registration.short_id_prefix
                == COMPANION_REGISTER_SHORT_ID_PREFIX
                && registration.band == TypeByteBand::Companion
                && registration.pack == COMPANION_REGISTER_PACK_ID;
            if !compatible_legacy_row {
                tracing::warn!(
                    type_byte = ENTITY_TYPE_COMPANION_REGISTER,
                    short_id_prefix = %registration.short_id_prefix,
                    pack = %registration.pack,
                    "companion register static kind collides with incompatible dynamic metadata"
                );
                return Err(Error::StructuralKindTypeByteCollision(
                    ENTITY_TYPE_COMPANION_REGISTER,
                ));
            }
            tracing::warn!(
                type_byte = ENTITY_TYPE_COMPANION_REGISTER,
                "companion register static kind found a redundant legacy dynamic metadata row"
            );
        }

        Ok(true)
    }

    fn read_companion_record_in_txn(
        &self,
        txn: &heed::RwTxn<'_>,
        id: &EntityId,
    ) -> Result<CompanionRecord> {
        let raw = self
            .store
            .entities
            .get(txn, id.as_bytes())?
            .ok_or(Error::EntityNotFound)?;
        let header =
            EntityMetadataHeader::parse(raw).ok_or(Error::CorruptedIndex("entity header"))?;
        if header.entity_type != ENTITY_TYPE_COMPANION_REGISTER {
            return Err(Error::InvalidEntityType(header.entity_type));
        }
        decode_companion_record_body(&raw[ENTITY_METADATA_HEADER_LEN..])
    }

    fn apply_companion_record_body(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        id: &EntityId,
        learned_at: u64,
        data: Vec<u8>,
    ) -> Result<()> {
        apply_ops(
            &self.store,
            &self.config,
            &self.analyzer,
            wtxn,
            vec![BatchOp::Put {
                id: *id,
                entity_type: ENTITY_TYPE_COMPANION_REGISTER,
                occurred: TimeRange {
                    start: learned_at,
                    end: learned_at,
                },
                learned_at,
                data,
                allow_maintenance: false,
                allow_reserved_predicate: false,
            }],
            self.text_index_trusted
                .load(std::sync::atomic::Ordering::Acquire),
            false,
            true,
        )
    }

    /// Writes a typed CLAIM (type 0) entity with full structural validation
    /// (D11 key set, D17 predicate gate, D18 fail-closed body validation).
    ///
    /// `occurred` and `learned_at` are caller-supplied, exactly like
    /// [`Vault::put_entity`] — the valid_from/to ↔ envelope sentinel mapping
    /// (D15) is the provenance unit's concern, not this method's.
    ///
    /// For an entity subject ([`ClaimSubject::Entity`]) this also writes the
    /// `claim_of` edge (u8 = 5, structural 12 B) Claim → subject in the SAME
    /// write transaction, and rejects with [`Error::EntityNotFound`] if the
    /// subject entity does not exist — nothing is written on rejection. An
    /// EdgeRef subject ([`ClaimSubject::Edge`]) is shape-validated only; its
    /// `claim_of` wiring belongs to the provenance path, which is also the
    /// only path allowed to write reserved `edge.*` predicates.
    pub fn put_claim(
        &self,
        id: &EntityId,
        body: &ClaimBody,
        occurred: TimeRange,
        learned_at: u64,
    ) -> Result<()> {
        let data = encode_claim_body(body)?;
        // Public-path gate: full structural validation + reserved-namespace
        // rejection before any transaction is opened. `apply_ops` re-runs
        // the same validator at the write chokepoint.
        validate_claim_body_bytes(&data, false)?;

        let mut ops = vec![BatchOp::Put {
            id: *id,
            entity_type: ENTITY_TYPE_CLAIM,
            occurred,
            learned_at,
            data,
            allow_maintenance: false,
            allow_reserved_predicate: false,
        }];

        let mut wtxn = self.store.env.write_txn()?;
        if let ClaimSubject::Entity(subject) = body.subject {
            if self
                .store
                .entities
                .get(&wtxn, subject.as_bytes())?
                .is_none()
            {
                return Err(Error::EntityNotFound);
            }
            ops.push(BatchOp::Edge {
                src: *id,
                kind: EdgeKind::ClaimOf,
                tgt: subject,
                weight: CLAIM_OF_DEFAULT_WEIGHT,
                vad: Vad::NEUTRAL,
            });
        }
        apply_ops(
            &self.store,
            &self.config,
            &self.analyzer,
            &mut wtxn,
            ops,
            self.text_index_trusted
                .load(std::sync::atomic::Ordering::Acquire),
            false,
            true,
        )?;
        wtxn.commit()?;
        Ok(())
    }

    pub(crate) fn put_claim_candidate_without_lexical_query_reconcile(
        &self,
        id: &EntityId,
        candidate: ClaimCandidate,
        envelope: &WriteEnvelope,
        occurred: TimeRange,
        learned_at: u64,
    ) -> Result<()> {
        let mut wtxn = self.store.env.write_txn()?;
        apply_ops_with_gate_mode(
            &self.store,
            &self.config,
            &self.analyzer,
            &mut wtxn,
            vec![BatchOp::ClaimCandidate {
                id: *id,
                candidate: Box::new(candidate),
                envelope: envelope.clone(),
                occurred,
                learned_at,
                internal_lexical_query_hint: false,
            }],
            self.text_index_trusted
                .load(std::sync::atomic::Ordering::Acquire),
            ApplyOpsGateMode::new(false, true).with_source_in_gate_input(),
        )?;
        wtxn.commit()?;
        Ok(())
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "code-run write trap commits both typed gate checks and transition atomically"
    )]
    pub(crate) fn supersede_claim_for_code_run_trap(
        &self,
        new_id: &EntityId,
        old_id: &EntityId,
        now: u64,
        envelope: &WriteEnvelope,
        claim_gate_id: EntityId,
        claim_gate_body: &ClaimBody,
        edge_gate_id: EntityId,
        edge_gate_body: &ClaimBody,
    ) -> Result<()> {
        if new_id == old_id {
            return Err(Error::ClaimSelfSupersession);
        }

        let mut wtxn = self.store.env.write_txn()?;
        self.validate_code_run_write_actor_binding_in_txn(&wtxn, envelope)?;
        let policy = crate::gate::resolve_policy_manifest(&self.store, &wtxn)?;
        if let Err(err) = self.check_code_run_write_gate_in_txn(
            &mut wtxn,
            claim_gate_id,
            claim_gate_body,
            envelope,
            &policy,
            false,
        ) {
            wtxn.commit()?;
            return Err(err);
        }
        if let Err(err) = self.check_code_run_write_gate_in_txn(
            &mut wtxn,
            edge_gate_id,
            edge_gate_body,
            envelope,
            &policy,
            false,
        ) {
            wtxn.commit()?;
            return Err(err);
        }

        let (new_body, _new_header) = self.claim_for_lifecycle_in(&wtxn, new_id)?;
        Self::require_active_claim(&new_body)?;
        let (mut old_body, old_header) = self.claim_for_lifecycle_in(&wtxn, old_id)?;
        Self::require_active_claim(&old_body)?;
        Self::require_source_trust_supersession_rights(&new_body, &old_body)?;

        old_body.lifecycle = ClaimLifecycleStatus::Superseded;
        old_body.valid_to = Some(now);
        let data = encode_claim_body(&old_body)?;

        apply_ops_with_gate_mode(
            &self.store,
            &self.config,
            &self.analyzer,
            &mut wtxn,
            vec![
                BatchOp::Put {
                    id: *old_id,
                    entity_type: ENTITY_TYPE_CLAIM,
                    occurred: TimeRange {
                        start: old_header.occurred_start,
                        end: now,
                    },
                    learned_at: old_header.learned_at,
                    data,
                    allow_maintenance: false,
                    allow_reserved_predicate: false,
                },
                BatchOp::EdgeWithCreatedAt {
                    src: *new_id,
                    kind: EdgeKind::Supersedes,
                    tgt: *old_id,
                    weight: SUPERSEDES_DEFAULT_WEIGHT,
                    created_at: now,
                    vad: Vad::NEUTRAL,
                    provenance: None,
                },
            ],
            self.text_index_trusted
                .load(std::sync::atomic::Ordering::Acquire),
            ApplyOpsGateMode::new(false, false),
        )?;
        wtxn.commit()?;
        Ok(())
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "code-run edge trap carries gate material plus edge tuple"
    )]
    pub(crate) fn put_edge_for_code_run_trap(
        &self,
        src: &EntityId,
        kind: EdgeKind,
        tgt: &EntityId,
        weight: f32,
        envelope: &WriteEnvelope,
        gate_id: EntityId,
        gate_body: &ClaimBody,
    ) -> Result<()> {
        let mut wtxn = self.store.env.write_txn()?;
        self.validate_code_run_write_actor_binding_in_txn(&wtxn, envelope)?;
        let policy = crate::gate::resolve_policy_manifest(&self.store, &wtxn)?;
        if let Err(err) = self.check_code_run_write_gate_in_txn(
            &mut wtxn, gate_id, gate_body, envelope, &policy, false,
        ) {
            wtxn.commit()?;
            return Err(err);
        }

        apply_ops(
            &self.store,
            &self.config,
            &self.analyzer,
            &mut wtxn,
            vec![BatchOp::Edge {
                src: *src,
                kind,
                tgt: *tgt,
                weight,
                vad: Vad::NEUTRAL,
            }],
            self.text_index_trusted
                .load(std::sync::atomic::Ordering::Acquire),
            false,
            true,
        )?;
        wtxn.commit()?;
        Ok(())
    }

    fn validate_code_run_write_actor_binding_in_txn(
        &self,
        wtxn: &heed::RwTxn<'_>,
        envelope: &WriteEnvelope,
    ) -> Result<()> {
        crate::gate::validate_write_envelope(envelope)?;
        let actor = envelope.actor();
        let actor_raw = self
            .store
            .entities
            .get(wtxn, actor.entity_ref().as_bytes())?
            .ok_or(Error::EntityNotFound)?;
        let actor_header =
            EntityMetadataHeader::parse(actor_raw).ok_or(Error::CorruptedIndex("entity header"))?;
        validate_actor_class(actor_header.entity_type, actor.actor_class())
    }

    fn check_code_run_write_gate_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        id: EntityId,
        body: &ClaimBody,
        envelope: &WriteEnvelope,
        policy: &crate::gate::PolicyManifestResolution,
        can_resolve_pending_consent: bool,
    ) -> Result<()> {
        crate::gate::check_claim_policy_for_write(
            &self.store,
            wtxn,
            &id,
            body,
            Some(envelope),
            policy,
            crate::gate::GateWriteMode {
                record_decision: true,
                persist_pending_consent: false,
                resolve_pending: false,
                can_resolve_pending_consent,
                include_source_in_gate_input: true,
            },
        )
    }

    /// Retrieves and decodes a CLAIM (type 0) entity body.
    ///
    /// Returns `Ok(None)` when no entity exists under `id`, and a typed
    /// [`Error::InvalidClaimBody`] when the stored entity is not a type-0
    /// CLAIM or its body fails the pinned structural validation. The read
    /// path allows reserved `edge.*` predicates so stored provenance Claims
    /// stay decodable.
    ///
    /// DELIBERATELY UNGATED (D19): unlike the retrieval read paths
    /// (pipeline / context pack), this targeted read returns claims of
    /// EVERY `appr`/`life`/`stale` status — it is the history and
    /// consent-review door ("all non-current states are still stored",
    /// ARCH-0003), and the edge-provenance lifecycle readers likewise must
    /// see closed Claims to compute winner stamps.
    pub fn get_claim(&self, id: &EntityId) -> Result<Option<ClaimBody>> {
        let rtxn = self.store.env.read_txn()?;
        self.get_claim_in_txn(&rtxn, id)
    }

    /// Transaction-composable [`Vault::get_claim`]: reads and decodes a CLAIM
    /// body through the caller's txn (so it composes inside a write txn, where a
    /// nested read txn would be illegal).
    pub(crate) fn get_claim_in_txn(
        &self,
        rtxn: &heed::RoTxn<'_>,
        id: &EntityId,
    ) -> Result<Option<ClaimBody>> {
        let Some(raw) = self.store.entities.get(rtxn, id.as_bytes())? else {
            return Ok(None);
        };
        let header =
            EntityMetadataHeader::parse(raw).ok_or(Error::CorruptedIndex("entity header"))?;
        if header.entity_type != ENTITY_TYPE_CLAIM {
            return Err(Error::InvalidClaimBody("entity is not a type-0 CLAIM"));
        }
        crate::claim::decode_claim_body(&raw[ENTITY_METADATA_HEADER_LEN..], true).map(Some)
    }

    /// Returns the CLAIM entity ids attached to `subject` via inbound
    /// `claim_of` edges — a thin wrapper over
    /// `sources(subject, EdgeKind::ClaimOf, Some(ENTITY_TYPE_CLAIM))`.
    pub fn claims_for_subject(&self, subject: &EntityId) -> Result<Vec<EntityId>> {
        self.sources(subject, EdgeKind::ClaimOf, Some(ENTITY_TYPE_CLAIM))
    }

    /// Transaction-composable [`Vault::claims_for_subject`]: resolves inbound
    /// `claim_of` edges through the caller's txn.
    pub(crate) fn claims_for_subject_in_txn(
        &self,
        rtxn: &heed::RoTxn<'_>,
        subject: &EntityId,
    ) -> Result<Vec<EntityId>> {
        self.filtered_edge_peers(
            rtxn,
            &self.store.edges_in,
            subject,
            EdgeKind::ClaimOf,
            Some(ENTITY_TYPE_CLAIM),
            "claims for subject",
        )
    }

    pub(crate) fn claim_bodies_for_subjects_matching(
        &self,
        subjects: &[EntityId],
        mut matches: impl FnMut(&ClaimBody, &EntityId) -> bool,
    ) -> Result<Vec<ClaimBody>> {
        let rtxn = self.store.env.read_txn()?;
        let mut claims = Vec::new();
        for subject in subjects {
            let prefix = edge_kind_prefix(subject, EdgeKind::ClaimOf);
            for (scanned, entry) in self.store.edges_in.prefix_iter(&rtxn, &prefix)?.enumerate() {
                if scanned >= MAX_EDGE_QUERY_RESULTS {
                    return Err(Error::IndexOverflow("claim_bodies_for_subjects"));
                }
                let (key, value) = entry?;
                let claim_id = parse_edge_record(key, value)?.target;
                let Some(raw) = self.store.entities.get(&rtxn, claim_id.as_bytes())? else {
                    continue;
                };
                let Some(header) = EntityMetadataHeader::parse(raw) else {
                    continue;
                };
                if header.entity_type != ENTITY_TYPE_CLAIM {
                    continue;
                }
                let body =
                    crate::claim::decode_claim_body(&raw[ENTITY_METADATA_HEADER_LEN..], true)?;
                if matches(&body, subject) {
                    claims.push(body);
                }
            }
        }
        Ok(claims)
    }

    /// Writes an `edge.provenance` Claim for an EXISTING semantic edge,
    /// applies the contract's SUPERSEDE lifecycle to prior live Claims, and
    /// re-stamps the edge's two hot flags from the deterministic WINNER —
    /// the atomic provenanced-write API and (with
    /// [`Vault::supersede_edge_provenance`] and
    /// [`Vault::retract_edge_provenance`]) the ONLY public door to
    /// provenance flags (D10: the Claim is truth; the 26-byte stamp
    /// primitive stays `pub(crate)`).
    ///
    /// One LMDB write transaction performs ALL of:
    ///
    /// 1. write-once id gate — `claim_id` must not already name a stored
    ///    entity ([`Error::ProvenanceClaimIdInUse`]; re-putting an existing
    ///    id would resurrect a closed Claim in place — the lifecycle
    ///    operations are the only mutators of a stored provenance Claim);
    /// 2. subject-edge gate — `subject.kind` must be a SEMANTIC kind
    ///    ([`Error::ProvenanceOnStructuralEdge`] otherwise) and the edge must
    ///    already exist ([`Error::EdgeNotFound`]; the path never upserts — it
    ///    would have to invent `weight`/`created_at`);
    /// 3. actor gate (D13) — `body.actor_entity_ref` must exist
    ///    ([`Error::EntityNotFound`]) and the CALLER-SUPPLIED `actor_class`
    ///    must be compatible with the actor entity's kind
    ///    ([`Error::ActorClassMismatch`]; never defaulted). The validated
    ///    class is persisted as the value record's `actor_class` BODY key
    ///    (ONE-1138 / ONE-1112 C2 relocation — the wrapper's `evid` stays
    ///    empty) so a later winner refresh can restamp a HISTORICAL Claim's
    ///    flags (see the provenance module docs). A caller-set
    ///    `body.actor_class` that CONFLICTS with the `actor_class` parameter
    ///    is rejected typed ([`Error::InvalidProvenanceBody`]);
    /// 4. substrate gate (ONE-1138) — when `body.substrate_ref` is present
    ///    it must name a stored MODEL (type byte 121) entity
    ///    ([`Error::InvalidModelSubstrate`] otherwise); absent =
    ///    unrecorded-and-valid;
    /// 5. supersession (retractionRules SUPERSEDE + D14) — an incoming
    ///    `learned_at` OLDER than the live frontier for this EdgeRef is
    ///    rejected typed ([`Error::ProvenancePrecedenceViolation`]); every
    ///    live Claim STRICTLY older than the incoming one is closed in the
    ///    same transaction (`life` = superseded, `valid_to` set to the
    ///    incoming `learned_at` when absent, envelope `occurred.end`
    ///    refreshed per D15 — closed, not deleted, still readable);
    ///    equal-`learned_at` Claims COEXIST live;
    /// 6. the Claim entity (type 0, predicate
    ///    [`crate::provenance::PREDICATE_EDGE_PROVENANCE`], `subj` = the
    ///    33-byte EdgeRef, `val` = the pinned 10-key record) is written
    ///    through the `pub(crate)` reserved-namespace door with full ONE-1104
    ///    structural validation;
    /// 7. a `claim_of` edge (u8 = 5, structural 12 B) is written from the
    ///    Claim to the subject edge's SOURCE entity (D12);
    /// 8. the subject edge value is re-stamped to 26 bytes from the WINNER
    ///    among post-write live Claims under the documented total D14 order
    ///    (greatest `learned_at`, then `confidence`, then claim-id bytes) —
    ///    NOT necessarily this Claim — with IDENTICAL bytes in `edges_out`
    ///    and `edges_in` and the first 24 bytes preserved verbatim;
    /// 9. PPR caches for the subject edge's endpoints are invalidated.
    ///
    /// The Claim envelope's `occurred` interval derives from the validity
    /// window per D15: absent `valid_from` → `learned_at`; absent `valid_to`
    /// → `u64::MAX`. A derived interval with `start > end` is rejected with
    /// [`Error::InvalidProvenanceBody`] — never reordered. The wrapping
    /// Claim stores `conf` = `body.confidence` and `from`/`to` =
    /// `valid_from`/`valid_to` (claim-layer mirrors of the authoritative
    /// 10-key record) with `appr` = `auto`, `life` = `active`.
    pub fn put_edge_provenance(
        &self,
        claim_id: &EntityId,
        subject: &EdgeRef,
        body: &EdgeProvenanceClaimBody,
        actor_class: EdgeActorClass,
        learned_at: u64,
    ) -> Result<()> {
        self.write_edge_provenance(claim_id, subject, body, actor_class, learned_at, None)
    }

    /// Explicitly supersedes the live `edge.provenance` Claim
    /// `prior_claim_id` with the NEWER Claim `new_claim_id` for the SAME
    /// EdgeRef (retractionRules SUPERSEDE + D14): one write transaction
    /// writes the new Claim exactly like [`Vault::put_edge_provenance`],
    /// closes the named prior (`life` = superseded, `valid_to` set to
    /// `learned_at` when the record had none, envelope `occurred.end`
    /// refreshed — the prior Claim entity stays readable), closes any other
    /// live Claim strictly older than `learned_at`, and re-stamps the edge
    /// from the deterministic WINNER among the surviving live Claims.
    ///
    /// Unlike the implicit path, the named prior is closed even on a
    /// `learned_at` tie.
    ///
    /// Typed failure modes (nothing is written on any of them):
    /// * `prior_claim_id == new_claim_id` →
    ///   [`Error::ProvenanceSelfSupersession`];
    /// * `new_claim_id` already names a stored entity →
    ///   [`Error::ProvenanceClaimIdInUse`] (claim ids are write-once);
    /// * prior entity missing → [`Error::EntityNotFound`];
    /// * prior is not a type-0 Claim or its predicate is not
    ///   `edge.provenance` → [`Error::NotAProvenanceClaim`];
    /// * prior addresses a different EdgeRef than `subject` →
    ///   [`Error::ProvenanceSubjectMismatch`];
    /// * prior is no longer live → [`Error::ProvenanceClaimAlreadyClosed`];
    /// * `learned_at` older than the live frontier →
    ///   [`Error::ProvenancePrecedenceViolation`].
    pub fn supersede_edge_provenance(
        &self,
        prior_claim_id: &EntityId,
        new_claim_id: &EntityId,
        subject: &EdgeRef,
        body: &EdgeProvenanceClaimBody,
        actor_class: EdgeActorClass,
        learned_at: u64,
    ) -> Result<()> {
        self.write_edge_provenance(
            new_claim_id,
            subject,
            body,
            actor_class,
            learned_at,
            Some(prior_claim_id),
        )
    }

    /// Retracts a live `edge.provenance` Claim (retractionRules RETRACT):
    /// ONE write transaction sets the value record's `supersession_status` =
    /// retracted and `valid_to` = `now`, mirrors `life` = retracted / `to` =
    /// `now` on the wrapping Claim, re-puts the Claim with the envelope
    /// `occurred.end` refreshed per D15, and re-stamps the subject edge:
    ///
    /// * other live Claims remain → flags refresh from the deterministic
    ///   D14 WINNER among them (greatest `learned_at`, then `confidence`,
    ///   then claim-id bytes);
    /// * no live Claim remains → `confirmation_status` = retracted (3) with
    ///   the retracted Claim's own persisted `actor_class` — "the edge is
    ///   KEPT … the edge is not physically removed on retraction".
    ///
    /// Typed failure modes (nothing is written on any of them): missing
    /// claim → [`Error::EntityNotFound`]; not an `edge.provenance` Claim →
    /// [`Error::NotAProvenanceClaim`]; already closed (double-retract /
    /// retract-after-supersede) → [`Error::ProvenanceClaimAlreadyClosed`];
    /// `now` earlier than the record's `valid_from` (or derived envelope
    /// start) → [`Error::InvalidProvenanceBody`]; subject edge missing →
    /// [`Error::EdgeNotFound`].
    pub fn retract_edge_provenance(&self, claim_id: &EntityId, now: u64) -> Result<()> {
        let mut wtxn = self.store.env.write_txn()?;

        let claim = self.load_provenance_claim_in_txn(&wtxn, claim_id)?;
        if claim.wrapper.lifecycle != ClaimLifecycleStatus::Active {
            return Err(Error::ProvenanceClaimAlreadyClosed {
                lifecycle: claim.wrapper.lifecycle.as_str(),
            });
        }
        let retracted = retract_record(&claim.record, now)?;
        let (occurred, learned_at, retracted_claim_body, data) =
            closed_claim_put_payload(&claim, &retracted, ClaimLifecycleStatus::Retracted)?;

        // The subject edge must still exist — the retraction KEEPS it and
        // only refreshes the two flag bytes.
        let subject = claim.subject;
        let edge_key = Store::encode_edge_key(&subject.source, subject.kind, &subject.target);
        if self.store.edges_out.get(&wtxn, &edge_key)?.is_none() {
            return Err(Error::EdgeNotFound);
        }

        let policy = crate::gate::resolve_policy_manifest(&self.store, &wtxn)?;
        crate::gate::check_edge_provenance_claim_policy(
            &retracted_claim_body,
            &retracted,
            claim.actor_class,
            &policy,
        )?;

        // Flags refresh: the D14 winner among REMAINING live Claims, else
        // the contract's retracted stamp with this Claim's persisted class.
        let survivors = self.live_edge_provenance_claims_in_txn(&wtxn, &subject, Some(claim_id))?;
        let precedence: Vec<ProvenancePrecedence> = survivors
            .iter()
            .map(StoredProvenanceClaim::precedence)
            .collect();
        let flags = match winner_index(&precedence) {
            Some(index) => survivors[index].flags(),
            None => EdgeProvenanceFlags {
                confirmation_status: EdgeConfirmationStatus::Retracted,
                actor_class: claim.actor_class,
            },
        };

        self.batch_in()
            .put_reserved_claim(claim_id, occurred, learned_at, &data)
            .apply(&mut wtxn)?;
        restamp_edge_flags(&self.store, &mut wtxn, &subject, flags)?;
        ppr::invalidate_ppr_for_edge(&self.store, &mut wtxn, &subject.source, &subject.target)?;
        // The edge bytes changed without an edge BatchOp in this txn, so the
        // graph version is bumped explicitly (apply_ops does it for edge ops).
        ppr::increment_graph_version(&self.store, &mut wtxn)?;
        wtxn.commit()?;
        Ok(())
    }

    /// Engine-authored get-or-create door for MODEL substrate entities
    /// (type byte 121, maintenance band — ONE-1138 ratified): a MODEL entity
    /// is "written when a substrate first appears in a write path", keyed by
    /// `(name, version)`. Model name + version live ON the MODEL entity so
    /// provenance records dedup to a 16-byte ref — the returned id is what
    /// [`EdgeProvenanceClaimBody`]'s `substrate_ref` should carry.
    ///
    /// Behavior, all in ONE write transaction:
    /// * an existing MODEL entity whose body matches `(name, version)` →
    ///   its id is returned and NOTHING is written (idempotent get);
    /// * otherwise a new MODEL entity (engine-shaped MessagePack body
    ///   `{"name", "version"}`) is created through the engine-internal
    ///   maintenance door with the full `apply_put` index footprint
    ///   (type_index, temporal point event at `now`, reserved `mo`
    ///   short-id);
    /// * `name` / `version` must be non-empty and at most
    ///   [`crate::provenance::MODEL_SUBSTRATE_FIELD_MAX_BYTES`] bytes —
    ///   [`Error::InvalidModelSubstrate`] otherwise;
    /// * a stored type-121 entity whose body fails the engine-shape decode
    ///   is on-disk corruption → [`Error::CorruptedIndex`], never skipped.
    ///
    /// Public puts of type byte 121 stay rejected with
    /// [`Error::MaintenanceKindNotWritable`]: this method is the ONLY public
    /// door, and it only ever writes the engine-shaped body.
    pub fn ensure_model_substrate(&self, name: &str, version: &str, now: u64) -> Result<EntityId> {
        validate_model_substrate_field(name, "model name must be non-empty and at most 256 bytes")?;
        validate_model_substrate_field(
            version,
            "model version must be non-empty and at most 256 bytes",
        )?;
        let body = encode_model_entity_body(name, version)?;

        let mut wtxn = self.store.env.write_txn()?;

        // GET: scan the MODEL partition of type_index — one row per distinct
        // substrate, so the partition stays tiny — for a (name, version)
        // match. The scan and the create share the write transaction, so the
        // get-or-create is race-free under LMDB's single-writer model.
        let mut existing: Option<EntityId> = None;
        for entry in self
            .store
            .type_index
            .prefix_iter(&wtxn, &[ENTITY_TYPE_MODEL])?
        {
            let (key, _) = entry?;
            require_key_len(key, 17, "type index key")?;
            let id = EntityId::from_bytes(
                key[1..17]
                    .try_into()
                    .map_err(|_| Error::CorruptedIndex("type index key"))?,
            )
            .map_err(|_| Error::CorruptedIndex("type index key"))?;
            let raw = self
                .store
                .entities
                .get(&wtxn, id.as_bytes())?
                .ok_or(Error::CorruptedIndex("type index row without entity"))?;
            let (stored_name, stored_version) =
                decode_model_entity_body(&raw[ENTITY_METADATA_HEADER_LEN..])?;
            if stored_name == name && stored_version == version {
                existing = Some(id);
                break;
            }
        }
        if let Some(id) = existing {
            return Ok(id);
        }

        // CREATE: engine-internal maintenance door (allow_maintenance), the
        // same admit flag the sync replay path uses for REDACTION_AUDIT —
        // public puts of the byte keep failing MaintenanceKindNotWritable.
        let id = EntityId::now();
        let ops = vec![BatchOp::Put {
            id,
            entity_type: ENTITY_TYPE_MODEL,
            occurred: TimeRange {
                start: now,
                end: now,
            },
            learned_at: now,
            data: body,
            allow_maintenance: true,
            allow_reserved_predicate: false,
        }];
        apply_ops(
            &self.store,
            &self.config,
            &self.analyzer,
            &mut wtxn,
            ops,
            self.text_index_trusted
                .load(std::sync::atomic::Ordering::Acquire),
            false,
            true,
        )?;
        wtxn.commit()?;
        Ok(id)
    }

    /// Shared implementation of [`Vault::put_edge_provenance`] (implicit
    /// supersession) and [`Vault::supersede_edge_provenance`] (explicit
    /// prior). See those methods for the full documented semantics.
    fn write_edge_provenance(
        &self,
        claim_id: &EntityId,
        subject: &EdgeRef,
        body: &EdgeProvenanceClaimBody,
        actor_class: EdgeActorClass,
        learned_at: u64,
        explicit_prior: Option<&EntityId>,
    ) -> Result<()> {
        if explicit_prior == Some(claim_id) {
            return Err(Error::ProvenanceSelfSupersession);
        }

        // ONE-1138 / ONE-1112 C2: the validated caller-supplied class is
        // persisted as the record's `actor_class` BODY key. A caller-set
        // body class that disagrees with the parameter is ambiguous —
        // rejected, never reconciled silently.
        if let Some(body_class) = body.actor_class
            && body_class != actor_class
        {
            return Err(Error::InvalidProvenanceBody(
                "body actor_class conflicts with the caller-supplied actor_class parameter",
            ));
        }
        let mut record = body.clone();
        record.actor_class = Some(actor_class);

        // Pure validation before any transaction is opened. Encoding does
        // not validate; the decode validator is the single gate.
        let value = encode_edge_provenance_value(&record);
        validate_edge_provenance_value(&value)?;

        // Provenance only attaches to SEMANTIC kinds — a static property of
        // the kind, checked before any I/O.
        if edge_value_layout_for_kind(subject.kind, false) == EdgeValueLayout::Structural {
            return Err(Error::ProvenanceOnStructuralEdge {
                kind: subject.kind as u8,
            });
        }

        // D15 envelope sentinels (index-key derivation only; the
        // authoritative optionality stays in the MessagePack body).
        let occurred = TimeRange {
            start: body.valid_from.unwrap_or(learned_at),
            end: body.valid_to.unwrap_or(u64::MAX),
        };
        if occurred.start > occurred.end {
            return Err(Error::InvalidProvenanceBody(
                "derived occurred envelope start exceeds end (valid_to before valid_from/learned_at)",
            ));
        }

        let mut claim_body = ClaimBody::new(
            PREDICATE_EDGE_PROVENANCE,
            ClaimSubject::from(*subject),
            value,
            body.confidence,
            ClaimApprovalStatus::Auto,
            ClaimLifecycleStatus::Active,
        );
        claim_body.valid_from = body.valid_from;
        claim_body.valid_to = body.valid_to;
        // The write-time validated actor_class is persisted as the record's
        // BODY key (set above, ONE-1138); the wrapper's `evid` stays empty —
        // evidence purity, no legacy `{"actor_class": u8}` map.
        let data = encode_claim_body(&claim_body)?;
        validate_claim_body_bytes(&data, true)?;

        let mut wtxn = self.store.env.write_txn()?;

        // WRITE-ONCE ids: a `claim_id` that already names ANY stored entity
        // is rejected before a single byte moves. Re-putting an existing id
        // would overwrite the stored Claim in place — resurrecting a
        // retracted/superseded wrapper as a fresh `active` body and
        // bypassing [`Error::ProvenanceClaimAlreadyClosed`] (ARCH-0003:
        // "claims are never silently deleted"). The lifecycle operations
        // (retract / supersede) are the ONLY mutators of an existing
        // provenance Claim.
        if self
            .store
            .entities
            .get(&wtxn, claim_id.as_bytes())?
            .is_some()
        {
            return Err(Error::ProvenanceClaimIdInUse);
        }

        // Subject edge must exist — no upsert.
        let edge_key = Store::encode_edge_key(&subject.source, subject.kind, &subject.target);
        if self.store.edges_out.get(&wtxn, &edge_key)?.is_none() {
            return Err(Error::EdgeNotFound);
        }

        // Actor entity must exist; the caller-supplied class is validated
        // against its kind (D13) — never defaulted.
        let actor_raw = self
            .store
            .entities
            .get(&wtxn, body.actor_entity_ref.as_bytes())?
            .ok_or(Error::EntityNotFound)?;
        let actor_header =
            EntityMetadataHeader::parse(actor_raw).ok_or(Error::CorruptedIndex("entity header"))?;
        validate_actor_class(actor_header.entity_type, actor_class)?;

        // Substrate gate (ONE-1138): a present substrate_ref must name a
        // stored MODEL (type byte 121) entity — actor = WHO, substrate =
        // WITH-WHAT; any other kind is never a substrate. Absent =
        // unrecorded-and-valid, no gate.
        if let Some(substrate_ref) = record.substrate_ref {
            let substrate_raw = self
                .store
                .entities
                .get(&wtxn, substrate_ref.as_bytes())?
                .ok_or(Error::InvalidModelSubstrate(
                    "substrate_ref does not name a stored entity",
                ))?;
            let substrate_header = EntityMetadataHeader::parse(substrate_raw)
                .ok_or(Error::CorruptedIndex("entity header"))?;
            if substrate_header.entity_type != ENTITY_TYPE_MODEL {
                return Err(Error::InvalidModelSubstrate(
                    "substrate_ref must name a MODEL (type byte 121) entity",
                ));
            }
            // A present, type-correct (type-121) substrate row whose body
            // fails the engine MODEL shape ({name, version} ≤256B) is
            // ambiguous on-disk corruption — e.g. a remote-replay-deposited
            // malformed type-121 row — and is rejected fail-closed as
            // CorruptedIndex("model entity body") BEFORE the provenance Claim
            // is staged, mirroring the get-or-create GET scan's own strict
            // decode (single decoder, one source of truth). Never downgraded
            // to a silent skip; InvalidModelSubstrate stays reserved for the
            // clean referential rejections above (wrong kind, dangling ref).
            decode_model_entity_body(&substrate_raw[ENTITY_METADATA_HEADER_LEN..])?;
        }

        let policy = crate::gate::resolve_policy_manifest(&self.store, &wtxn)?;
        crate::gate::check_edge_provenance_claim_policy(
            &claim_body,
            &record,
            actor_class,
            &policy,
        )?;

        // Explicit-prior gates (supersede path): the named Claim must be a
        // live edge.provenance Claim addressing the SAME EdgeRef.
        let prior_id = explicit_prior
            .map(|prior_id| -> Result<EntityId> {
                let prior = self.load_provenance_claim_in_txn(&wtxn, prior_id)?;
                if prior.subject != *subject {
                    return Err(Error::ProvenanceSubjectMismatch);
                }
                if prior.wrapper.lifecycle != ClaimLifecycleStatus::Active {
                    return Err(Error::ProvenanceClaimAlreadyClosed {
                        lifecycle: prior.wrapper.lifecycle.as_str(),
                    });
                }
                Ok(prior.id)
            })
            .transpose()?;

        // D14 precedence: the incoming Claim may never be OLDER than the
        // live frontier — it could never take precedence.
        let live = self.live_edge_provenance_claims_in_txn(&wtxn, subject, Some(claim_id))?;
        if let Some(frontier) = live.iter().map(|claim| claim.learned_at).max()
            && learned_at < frontier
        {
            return Err(Error::ProvenancePrecedenceViolation {
                incoming_learned_at: learned_at,
                frontier_learned_at: frontier,
            });
        }
        if let Some(prior_id) = prior_id
            && !live.iter().any(|claim| claim.id == prior_id)
        {
            // The prior passed the live + same-subject gates, so its
            // claim_of edge must surface it in the live scan.
            return Err(Error::CorruptedIndex("provenance claim_of edge"));
        }

        // Closures: every live Claim strictly older than the incoming one,
        // plus the explicitly named prior (closed even on a learned_at tie).
        let close_at = learned_at;
        let (closures, survivors): (Vec<&StoredProvenanceClaim>, Vec<&StoredProvenanceClaim>) =
            live.iter()
                .partition(|claim| claim.learned_at < learned_at || Some(claim.id) == prior_id);

        // Deterministic winner among the post-write live cohort (D14).
        let mut precedence: Vec<ProvenancePrecedence> =
            survivors.iter().map(|claim| claim.precedence()).collect();
        precedence.push(ProvenancePrecedence {
            learned_at,
            confidence: body.confidence,
            claim_id: *claim_id,
        });
        let winner = winner_index(&precedence)
            .ok_or(Error::InvariantViolation("provenance winner set is empty"))?;
        let flags = if winner == precedence.len() - 1 {
            EdgeProvenanceFlags {
                confirmation_status: derive_confirmation_status(body.supersession_status),
                actor_class,
            }
        } else {
            survivors[winner].flags()
        };

        let mut closure_payloads = Vec::with_capacity(closures.len());
        for closure in &closures {
            let closed_record = close_record_for_supersession(&closure.record, close_at)?;
            let (closed_occurred, closed_learned_at, closed_claim_body, closed_data) =
                closed_claim_put_payload(
                    closure,
                    &closed_record,
                    ClaimLifecycleStatus::Superseded,
                )?;
            crate::gate::check_edge_provenance_claim_policy(
                &closed_claim_body,
                &closed_record,
                closure.actor_class,
                &policy,
            )?;
            closure_payloads.push((closure.id, closed_occurred, closed_learned_at, closed_data));
        }

        // New Claim through the reserved-namespace door + claim_of → the
        // subject edge's SOURCE entity (D12) + closure re-puts, all with
        // full Gate checks before apply and full type-0 validation at apply,
        // all in this one transaction.
        let mut builder = self
            .batch_in()
            .put_reserved_claim(claim_id, occurred, learned_at, &data)
            .edge(
                claim_id,
                EdgeKind::ClaimOf,
                &subject.source,
                CLAIM_OF_DEFAULT_WEIGHT,
            );
        for (closure_id, closed_occurred, closed_learned_at, closed_data) in closure_payloads {
            builder = builder.put_reserved_claim(
                &closure_id,
                closed_occurred,
                closed_learned_at,
                &closed_data,
            );
        }
        builder.apply(&mut wtxn)?;

        // Re-stamp the subject edge (both directions, identical bytes) and
        // invalidate the PPR caches its endpoints feed.
        restamp_edge_flags(&self.store, &mut wtxn, subject, flags)?;
        ppr::invalidate_ppr_for_edge(&self.store, &mut wtxn, &subject.source, &subject.target)?;

        wtxn.commit()?;
        Ok(())
    }

    /// Reads, decodes, and gates a claim for a generic lifecycle transition
    /// (`supersede_claim` / `retract_claim`). Fail-closed:
    ///
    /// * no entity under `id` → [`Error::EntityNotFound`];
    /// * entity is not type 0 → [`Error::InvalidClaimBody`];
    /// * reserved `edge.*` predicate → [`Error::ProvenanceClaimLifecycle`]
    ///   — provenance Claims drive the subject edge's derived hot flags, so
    ///   their lifecycle is owned exclusively by the edge-provenance API
    ///   (`put_edge_provenance` / `retract_edge_provenance`); the generic
    ///   ops REJECT rather than delegate, so they can never bypass the
    ///   edge re-stamp.
    fn claim_for_lifecycle_in(
        &self,
        rtxn: &heed::RoTxn<'_>,
        id: &EntityId,
    ) -> Result<(ClaimBody, EntityMetadataHeader)> {
        let Some(raw) = self.store.entities.get(rtxn, id.as_bytes())? else {
            return Err(Error::EntityNotFound);
        };
        let header =
            EntityMetadataHeader::parse(raw).ok_or(Error::CorruptedIndex("entity header"))?;
        if header.entity_type != ENTITY_TYPE_CLAIM {
            return Err(Error::InvalidClaimBody("entity is not a type-0 CLAIM"));
        }
        let body = crate::claim::decode_claim_body(&raw[ENTITY_METADATA_HEADER_LEN..], true)?;
        if is_reserved_predicate(&body.predicate) {
            return Err(Error::ProvenanceClaimLifecycle {
                predicate: body.predicate,
            });
        }
        Ok((body, header))
    }

    /// Gates a lifecycle transition on the claim still being open: any
    /// non-`active` `life` status is closed history and rejects with
    /// [`Error::ClaimAlreadyClosed`] (ARCH-0003: superseded carries history,
    /// retracted is a deliberate withdrawal — never edited again).
    fn require_active_claim(body: &ClaimBody) -> Result<()> {
        if body.lifecycle != ClaimLifecycleStatus::Active {
            return Err(Error::ClaimAlreadyClosed {
                status: body.lifecycle,
            });
        }
        Ok(())
    }

    /// Blocks generated-origin claims from superseding protected user truth.
    /// New generated code-revision claims are rejected first so they keep the
    /// fail-closed code-revision diagnostic; otherwise old code-revision truth
    /// gets its own diagnostic, and non-code user/legacy truth uses the
    /// general claim-body error. Missing old `src` is protected as legacy
    /// user truth for this guard.
    fn require_source_trust_supersession_rights(
        new_body: &ClaimBody,
        old_body: &ClaimBody,
    ) -> Result<()> {
        let old_is_protected_user_truth =
            matches!(old_body.source, None | Some(ClaimSource::UserStated));
        if !claim_generated_origin(new_body) || !old_is_protected_user_truth {
            return Ok(());
        }
        if new_body.predicate == crate::code_revision::CODE_REVISION_CLAIM_PREDICATE {
            return Err(Error::InvalidCodeArtifactBody(
                "generated code revision claim cannot supersede user-stated truth",
            ));
        }
        if old_body.predicate == crate::code_revision::CODE_REVISION_CLAIM_PREDICATE {
            return Err(Error::InvalidCodeArtifactBody(
                "generated claim cannot supersede user-stated code revision truth",
            ));
        }
        Err(Error::InvalidClaimBody(
            "generated claim cannot supersede user-stated truth",
        ))
    }

    /// Supersedes the active claim `old_id` with the claim `new_id` — the
    /// general ARCH-0003 claim lifecycle mechanics, in ONE write
    /// transaction:
    ///
    /// * the old claim's body is closed: `life` = `superseded`, `to` = `now`;
    /// * the old claim's envelope `occurred_end` is refreshed to `now` (the
    ///   envelope copy mirrors the body's validity window for temporal
    ///   index-key derivation, per the D15 principle);
    /// * a `supersedes` edge (u8 = 3, structural 12 B, weight 0.3) is
    ///   written `new_id` → `old_id` — the edge is canonical; no
    ///   `supersedesId` body field is stored (D11).
    ///
    /// The old claim is KEPT fully readable: superseded carries history —
    /// "all non-current states are still stored — claims are never silently
    /// deleted" (ARCH-0003). Fail-closed, nothing written on any rejection:
    ///
    /// * `new_id == old_id` → [`Error::ClaimSelfSupersession`];
    /// * either id missing → [`Error::EntityNotFound`]; either entity not
    ///   type 0 → [`Error::InvalidClaimBody`];
    /// * either claim carrying a reserved `edge.*` provenance predicate →
    ///   [`Error::ProvenanceClaimLifecycle`] (the edge-provenance API owns
    ///   that lifecycle; see `Vault::claim_for_lifecycle_in`);
    /// * either claim's `life` ≠ `active` → [`Error::ClaimAlreadyClosed`]
    ///   (closed claims neither supersede nor get superseded again).
    ///
    /// Deciding WHICH claims conflict (conflictSet), consent routing, and
    /// predicate semantics stay above the engine (ARCH-0003 §G.1, D20) —
    /// this method is transition mechanics only.
    pub fn supersede_claim(&self, new_id: &EntityId, old_id: &EntityId, now: u64) -> Result<()> {
        let mut wtxn = self.store.env.write_txn()?;
        self.supersede_claim_in_txn(&mut wtxn, new_id, old_id, now)?;
        wtxn.commit()?;
        Ok(())
    }

    /// Supersedes `old_id` with `new_id` INSIDE the caller's write
    /// transaction, running the same fail-closed guards as
    /// [`Vault::supersede_claim`] (self-supersession, type-0 / reserved
    /// predicate, both-`active`, source-trust) but composing into an existing
    /// txn instead of opening its own. A caller that first writes the
    /// replacement head and then supersedes the old head in one `wtxn` commits
    /// or rolls back BOTH together, so a rejected supersession never leaves a
    /// torn two-`active`-heads window. `new_id` must already have been written
    /// into the same `wtxn` before this is called.
    pub(crate) fn supersede_claim_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        new_id: &EntityId,
        old_id: &EntityId,
        now: u64,
    ) -> Result<()> {
        if new_id == old_id {
            return Err(Error::ClaimSelfSupersession);
        }

        let (new_body, _new_header) = self.claim_for_lifecycle_in(&*wtxn, new_id)?;
        Self::require_active_claim(&new_body)?;
        let (mut old_body, old_header) = self.claim_for_lifecycle_in(&*wtxn, old_id)?;
        Self::require_active_claim(&old_body)?;
        Self::require_source_trust_supersession_rights(&new_body, &old_body)?;

        old_body.lifecycle = ClaimLifecycleStatus::Superseded;
        old_body.valid_to = Some(now);
        let data = encode_claim_body(&old_body)?;

        let ops = vec![
            BatchOp::Put {
                id: *old_id,
                entity_type: ENTITY_TYPE_CLAIM,
                occurred: TimeRange {
                    start: old_header.occurred_start,
                    end: now,
                },
                learned_at: old_header.learned_at,
                data,
                allow_maintenance: false,
                allow_reserved_predicate: false,
            },
            BatchOp::EdgeWithCreatedAt {
                src: *new_id,
                kind: EdgeKind::Supersedes,
                tgt: *old_id,
                weight: SUPERSEDES_DEFAULT_WEIGHT,
                created_at: now,
                vad: Vad::NEUTRAL,
                provenance: None,
            },
        ];
        apply_ops(
            &self.store,
            &self.config,
            &self.analyzer,
            wtxn,
            ops,
            self.text_index_trusted
                .load(std::sync::atomic::Ordering::Acquire),
            false,
            true,
        )?;
        Ok(())
    }

    /// Retracts the active claim `id` — a deliberate withdrawal (ARCH-0003
    /// general claim lifecycle), in ONE write transaction: the body is
    /// closed (`life` = `retracted`, `to` = `now`) and the envelope
    /// `occurred_end` is refreshed to `now` (body ↔ envelope mirror, D15
    /// principle). The record is PRESERVED — retraction never deletes.
    ///
    /// Fail-closed, nothing written on any rejection: missing id →
    /// [`Error::EntityNotFound`]; not type 0 → [`Error::InvalidClaimBody`];
    /// reserved `edge.*` provenance predicate →
    /// [`Error::ProvenanceClaimLifecycle`] (the edge-provenance API owns
    /// that lifecycle); `life` ≠ `active` → [`Error::ClaimAlreadyClosed`].
    pub fn retract_claim(&self, id: &EntityId, now: u64) -> Result<()> {
        let mut wtxn = self.store.env.write_txn()?;
        let (mut body, header) = self.claim_for_lifecycle_in(&wtxn, id)?;
        Self::require_active_claim(&body)?;

        body.lifecycle = ClaimLifecycleStatus::Retracted;
        body.valid_to = Some(now);
        let data = encode_claim_body(&body)?;

        let ops = vec![BatchOp::Put {
            id: *id,
            entity_type: ENTITY_TYPE_CLAIM,
            occurred: TimeRange {
                start: header.occurred_start,
                end: now,
            },
            learned_at: header.learned_at,
            data,
            allow_maintenance: false,
            allow_reserved_predicate: false,
        }];
        apply_ops(
            &self.store,
            &self.config,
            &self.analyzer,
            &mut wtxn,
            ops,
            self.text_index_trusted
                .load(std::sync::atomic::Ordering::Acquire),
            false,
            true,
        )?;
        wtxn.commit()?;
        Ok(())
    }

    /// Loads one `edge.provenance` Claim for a lifecycle operation, with the
    /// typed gate chain: missing → [`Error::EntityNotFound`]; not a type-0
    /// Claim or wrong predicate → [`Error::NotAProvenanceClaim`]; malformed
    /// stored body / record / persisted class → typed decode errors.
    fn load_provenance_claim_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        claim_id: &EntityId,
    ) -> Result<StoredProvenanceClaim> {
        let raw = self
            .store
            .entities
            .get(txn, claim_id.as_bytes())?
            .ok_or(Error::EntityNotFound)?;
        let header =
            EntityMetadataHeader::parse(raw).ok_or(Error::CorruptedIndex("entity header"))?;
        if header.entity_type != ENTITY_TYPE_CLAIM {
            return Err(Error::NotAProvenanceClaim("entity is not a type-0 CLAIM"));
        }
        let wrapper = crate::claim::decode_claim_body(&raw[ENTITY_METADATA_HEADER_LEN..], true)?;
        if wrapper.predicate != PREDICATE_EDGE_PROVENANCE {
            return Err(Error::NotAProvenanceClaim(
                "claim predicate is not edge.provenance",
            ));
        }
        let ClaimSubject::Edge {
            source,
            kind,
            target,
        } = wrapper.subject
        else {
            return Err(Error::InvalidProvenanceBody(
                "edge.provenance claim subject is not a 33-byte EdgeRef",
            ));
        };
        let record = decode_edge_provenance_body(&wrapper.value)?;
        let actor_class = resolve_persisted_actor_class(&record, wrapper.evidence.as_ref())?;
        Ok(StoredProvenanceClaim {
            id: *claim_id,
            occurred_start: header.occurred_start,
            learned_at: header.learned_at,
            subject: EdgeRef::new(source, kind, target),
            wrapper,
            record,
            actor_class,
        })
    }

    /// Enumerates the LIVE (`life` = active) `edge.provenance` Claims for
    /// `subject` — the live cohort the D14 winner stamp is chosen from. Thin
    /// wrapper over [`Self::edge_provenance_claims_in_txn`].
    fn live_edge_provenance_claims_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        subject: &EdgeRef,
        exclude: Option<&EntityId>,
    ) -> Result<Vec<StoredProvenanceClaim>> {
        self.edge_provenance_claims_in_txn(txn, subject, exclude, ClaimLifecycleStatus::Active)
    }

    /// Enumerates the RETRACTED `edge.provenance` Claims for `subject` — the
    /// surviving WITHDRAWN truth the edge's retracted dampening flag caches.
    /// The D16 delete-refresh consults this when NO active Claim survives, to
    /// decide whether the deleted Claim's EdgeRef still has a retracted
    /// truth-Claim to KEEP the 26 B retracted stamp for (else 24 B bare). Thin
    /// wrapper over [`Self::edge_provenance_claims_in_txn`].
    fn retracted_edge_provenance_claims_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        subject: &EdgeRef,
        exclude: Option<&EntityId>,
    ) -> Result<Vec<StoredProvenanceClaim>> {
        self.edge_provenance_claims_in_txn(txn, subject, exclude, ClaimLifecycleStatus::Retracted)
    }

    /// Enumerates the `edge.provenance` Claims for `subject` whose wrapping
    /// Claim `life` equals `lifecycle`, via the inbound `claim_of` edges of
    /// the subject edge's SOURCE entity (D12). Non-claim sources, other
    /// predicates, claims of OTHER EdgeRefs, bodiless SoftErase shells, and
    /// claims of any other lifecycle are skipped; corrupt rows fail closed.
    /// `exclude` drops the claim currently being re-put or deleted.
    fn edge_provenance_claims_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        subject: &EdgeRef,
        exclude: Option<&EntityId>,
        lifecycle: ClaimLifecycleStatus,
    ) -> Result<Vec<StoredProvenanceClaim>> {
        let prefix = edge_kind_prefix(&subject.source, EdgeKind::ClaimOf);
        let mut matched = Vec::new();
        for (scanned, entry) in self.store.edges_in.prefix_iter(txn, &prefix)?.enumerate() {
            if scanned >= MAX_EDGE_QUERY_RESULTS {
                return Err(Error::IndexOverflow("live provenance claims"));
            }
            let (key, value) = entry?;
            let claim_id = parse_edge_record(key, value)?.target;
            if exclude == Some(&claim_id) {
                continue;
            }
            let Some(raw) = self.store.entities.get(txn, claim_id.as_bytes())? else {
                return Err(Error::CorruptedIndex("claim_of edge without claim entity"));
            };
            let header =
                EntityMetadataHeader::parse(raw).ok_or(Error::CorruptedIndex("entity header"))?;
            if header.entity_type != ENTITY_TYPE_CLAIM {
                continue;
            }
            if raw.len() == ENTITY_METADATA_HEADER_LEN {
                // An ARCH-0038 SoftErase scrubbed this Claim's body but kept
                // its structural edges. A bodiless 25 B Claim shell is a
                // tombstone, never live — skip it. Safe because EVERY local
                // SoftErase (the user_delete branch AND the gdpr/policy
                // pre-purge step) commits the D16 edge refresh in the SAME
                // transaction that scrubs the body, so a shell can never
                // coexist with a stale subject-edge stamp.
                continue;
            }
            let wrapper =
                crate::claim::decode_claim_body(&raw[ENTITY_METADATA_HEADER_LEN..], true)?;
            if wrapper.predicate != PREDICATE_EDGE_PROVENANCE {
                continue;
            }
            let ClaimSubject::Edge {
                source,
                kind,
                target,
            } = wrapper.subject
            else {
                continue;
            };
            if EdgeRef::new(source, kind, target) != *subject {
                continue;
            }
            if wrapper.lifecycle != lifecycle {
                continue;
            }
            let record = decode_edge_provenance_body(&wrapper.value)?;
            let actor_class = resolve_persisted_actor_class(&record, wrapper.evidence.as_ref())?;
            matched.push(StoredProvenanceClaim {
                id: claim_id,
                occurred_start: header.occurred_start,
                learned_at: header.learned_at,
                subject: *subject,
                wrapper,
                record,
                actor_class,
            });
        }
        Ok(matched)
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
        if is_delete_protected_engine_record(header.entity_type) {
            return Err(Error::MaintenanceKindNotWritable(header.entity_type));
        }
        // ONE-1149 race-test rendezvous: the header is proven `Some` (the
        // lock-free `read_entity_header` read_txn has completed and committed
        // the headerful path) but no write lock is held yet. The deterministic
        // raced-delete harness recv()s here so the eraser commits AFTER this
        // header read, forcing the headerful leg every run. No-op in
        // production.
        signal_after_header_read();
        // ONE-1132: ONE deletion request UUID correlates the CRDT tombstone's
        // `request_id` with the REDACTION_AUDIT receipt's `request_id`.
        // ONE-1149: minted only AFTER the header read proves there is
        // something to erase — a delete that finds nothing must never mint a
        // request id (the headerless leg mints after its own scope probe).
        let request_uuid = Uuid::now_v7();

        let tombstone = TombstoneValueV2 {
            reason: reason.into(),
            deleted_at: requested_at,
            request_id: *request_uuid.as_bytes(),
        };
        let window_label = window_label_from_timestamp(header.learned_at);

        // ARCH-0038 DELETE interplay: an `edge.provenance` Claim's subject
        // EdgeRef and sweep refs are only readable PRE-purge (SoftErase
        // truncates the payload to the 25 B header) — capture them now.
        // `None` for every non-Claim / non-provenance entity: zero new
        // behavior on those paths.
        let captured = self.capture_provenance_delete(id)?;

        if !reason.active_store_hard_purge_v1() {
            // `user_delete` keeps the local 25 B shell (ARCH-0038 "Tombstone
            // revision (empty content); keep the message shell") but now
            // writes a reason=user_delete CRDT tombstone (ONE-1090 write
            // side): a soft delete with NO cross-device record would leave
            // the deleted body live on every other device.
            let mut wtxn = self.store.env.write_txn()?;
            let (existed, had_vector) = self.soft_erase_active_store_in_txn(&mut wtxn, id)?;
            if had_vector {
                crate::hnsw::increment_vector_version(&self.store, &mut wtxn)?;
            }
            // D16: SoftErase tombstones the Claim, and "the derived edge
            // flag follows the Claim" — refresh in the SAME transaction.
            if existed && let Some(captured) = &captured {
                self.refresh_subject_edge_after_claim_delete_in_txn(
                    &mut wtxn,
                    id,
                    &captured.subject,
                )?;
            }
            if existed {
                // OWNER-DECISION (cfg-off durability): the pending-tombstone
                // marker rides the SAME txn as the shell scrub.
                self.put_pending_tombstone_in_txn(&mut wtxn, &window_label, id, &tombstone)?;
            }
            wtxn.commit()?;
            if existed {
                let crdt_persisted =
                    self.write_crdt_tombstone(id, header.learned_at, &tombstone)?;
                if crdt_persisted {
                    self.clear_pending_tombstone(&window_label, id)?;
                }
            }
            return Ok(DeleteEntityOutcome {
                existed,
                receipt_id: None,
                sweep_key: None,
            });
        }

        // LOCKED ordering (ARCH-0038): CRDT tombstone FIRST — prevents sync
        // resurrection before the destructive purge touches payloads.
        let crdt_persisted = self.write_crdt_tombstone(id, header.learned_at, &tombstone)?;
        let tombstone_complete_at = unix_seconds_now();

        let soft_complete_at = if matches!(
            reason,
            DeleteReason::GdprDelete | DeleteReason::PolicyDelete
        ) {
            // The SoftErase scrubs the truth-Claim's body — the ONLY carrier
            // of the subject EdgeRef (D12) — so the D16 edge refresh MUST
            // commit atomically with it, mirroring the user_delete branch
            // above. Committing the SoftErase alone first would leave a
            // crash window in which a stale 26 B flag outlives its
            // truth-Claim and a RETRY cannot heal it (capture sees the
            // bodiless shell ⇒ `None`). The purge txn below re-runs the
            // refresh as an idempotent second pass.
            let mut wtxn = self.store.env.write_txn()?;
            let (existed, had_vector) = self.soft_erase_active_store_in_txn(&mut wtxn, id)?;
            if had_vector {
                crate::hnsw::increment_vector_version(&self.store, &mut wtxn)?;
            }
            if existed && let Some(captured) = &captured {
                self.refresh_subject_edge_after_claim_delete_in_txn(
                    &mut wtxn,
                    id,
                    &captured.subject,
                )?;
            }
            wtxn.commit()?;
            unix_seconds_now()
        } else {
            tombstone_complete_at
        };

        let receipt_id = EntityId::now();
        let scope = RedactionScope::entity(id);
        let mut wtxn = self.store.env.write_txn()?;
        let marker_key = local_hard_delete_key(id);
        // ONE-1149 ownership claim: probe the FULL delete scope INSIDE the
        // erasing txn. LMDB's single writer makes this race-free — if the
        // probe sees state, this txn's purge erases it; if a concurrent
        // delete raced everything away first, this delete must not claim it
        // erased anything (no receipt, no sweep row). Mirrors the
        // receiver-side `apply_replayed_tombstone` nothing-local branch:
        // ONLY the durable `dt:` marker is written (hard-once-seen — the
        // CRDT tombstone above is already published, so the id IS
        // hard-deleted), guarded so an existing marker is never overwritten.
        if !self.active_delete_scope_exists_in_txn(&wtxn, id)? {
            if self.store.sync_state.get(&wtxn, &marker_key)?.is_none() {
                self.store
                    .sync_state
                    .put(&mut wtxn, &marker_key, &tombstone.encode())?;
                wtxn.commit()?;
            }
            return Ok(DeleteEntityOutcome::missing());
        }
        // ONE-1122 `dt:` local hard-delete marker: the permanent local truth
        // the Observer-B materialization gate consults when a crafted update
        // REMOVES the CRDT tombstone (nothing else id-keyed survives a hard
        // delete locally — the receipt id is fresh, h: is seq-keyed, pt: is
        // cleared after replay). Written in the SAME txn as the active-store
        // purge. PRESENCE-ONLY for gates; the 25 B value body (the tombstone
        // wire bytes) is informational. Un-cfg'd on every build: `sync_state`
        // is unconditional and the marker is local delete truth, not
        // sync-only state (ONE-1132 cfg-off durability).
        self.store
            .sync_state
            .put(&mut wtxn, &marker_key, &tombstone.encode())?;
        let existed = self.purge_entity_active_store_in_txn(&mut wtxn, id)?;

        // ARCH-0038 DELETE: "The derived edge flag follows the Claim" — the
        // subject edge is refreshed in the SAME transaction as the purge.
        // Gated on `existed` (the entity record was erased by THIS txn): a
        // captured Claim whose record was raced away was already refreshed
        // by the racer's own delete txn.
        if existed && let Some(captured) = &captured {
            self.refresh_subject_edge_after_claim_delete_in_txn(&mut wtxn, id, &captured.subject)?;
        }

        // OWNER-DECISION (cfg-off durability): the pending-tombstone marker
        // rides the SAME txn as the active-store purge — on every build.
        self.put_pending_tombstone_in_txn(&mut wtxn, &window_label, id, &tombstone)?;

        let hard_purge_complete_at = unix_seconds_now();
        let sweep_key = self.write_redaction_receipt_and_sweep_in_txn(
            &mut wtxn,
            &receipt_id,
            RedactionReceiptInput {
                request_id: request_uuid.to_string(),
                scope,
                reason,
                requested_at,
                soft_complete_at,
                hard_purge_complete_at,
                sweep_queued_at: reason
                    .queues_historical_sweep()
                    .then_some(hard_purge_complete_at),
            },
            sweep_extras(captured.as_ref()),
        )?;

        wtxn.commit()?;
        // The CRDT record (tombstone-first, above) is durable — the crash
        // marker has served its purpose. In non-`sync` builds the marker
        // STAYS: it is the deletion's only propagation intent until a
        // sync-enabled boot replays it.
        if crdt_persisted {
            self.clear_pending_tombstone(&window_label, id)?;
        }
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
        // Probe first so a fully-missing id stays a strict no-op — deleting
        // a nonexistent entity must not mint tombstones or receipts.
        {
            let rtxn = self.store.env.read_txn()?;
            if !self.active_delete_scope_exists_in_txn(&rtxn, id)? {
                return Ok(DeleteEntityOutcome::missing());
            }
        }
        // ONE-1149: the deletion request UUID is minted only AFTER the probe
        // above says there is something to erase.
        let request_uuid = Uuid::now_v7();

        // ONE-1132: headerless residue previously left NO CRDT record, so
        // the orphan id could re-sync forever. There is no `learned_at` to
        // address a window with, so the tombstone lands under
        // `WindowKey::from_timestamp(now)` — a propagation address, not a
        // truth claim.
        let tombstone = TombstoneValueV2 {
            reason: reason.into(),
            deleted_at: requested_at,
            request_id: *request_uuid.as_bytes(),
        };
        let window_label = window_label_from_timestamp(requested_at);
        let crdt_persisted = self.write_crdt_tombstone(id, requested_at, &tombstone)?;

        let mut wtxn = self.store.env.write_txn()?;
        let marker_key = local_hard_delete_key(id);
        // ONE-1149 ownership claim: re-probe the FULL delete scope INSIDE
        // the erasing txn (race-free under LMDB's single writer). The read
        // probe above gated the tombstone publish; THIS probe gates the
        // erasure audit. A concurrent delete that raced the residue away
        // between the two means this delete erased nothing: no receipt, no
        // sweep row, no `pt:` marker — only the durable `dt:` marker for
        // hard reasons (hard-once-seen; the CRDT tombstone above is already
        // published), guarded exactly like the receiver-side
        // `apply_replayed_tombstone` nothing-local branch.
        if !self.active_delete_scope_exists_in_txn(&wtxn, id)? {
            if reason.active_store_hard_purge_v1()
                && self.store.sync_state.get(&wtxn, &marker_key)?.is_none()
            {
                self.store
                    .sync_state
                    .put(&mut wtxn, &marker_key, &tombstone.encode())?;
                wtxn.commit()?;
            }
            return Ok(DeleteEntityOutcome::missing());
        }
        let existed = self.purge_entity_active_store_in_txn(&mut wtxn, id)?;
        // OWNER-DECISION (cfg-off durability): marker in the SAME purge txn.
        self.put_pending_tombstone_in_txn(&mut wtxn, &window_label, id, &tombstone)?;
        if reason.active_store_hard_purge_v1() {
            // `dt:` local hard-delete marker (pinned: presence-only 25 B
            // `[reason:1][deleted_at:8 LE][request_id:16]` value, GLOBAL
            // lowercase key, permanent, no GC), headerless leg — in the
            // SAME txn as the purge, mirroring the receiver-side hard
            // apply. The CRDT tombstone above is mutable remote-facing
            // state; without the local marker a hostile tombstone removal
            // + re-put would resurrect this id through the
            // materialization gates.
            self.store
                .sync_state
                .put(&mut wtxn, &marker_key, &tombstone.encode())?;
        }
        if !reason.writes_receipt() {
            wtxn.commit()?;
            if crdt_persisted {
                self.clear_pending_tombstone(&window_label, id)?;
            }
            return Ok(DeleteEntityOutcome {
                existed,
                receipt_id: None,
                sweep_key: None,
            });
        }

        let receipt_id = EntityId::now();
        let hard_purge_complete_at = unix_seconds_now();
        // A headerless residue has no decodable body, so no provenance
        // capture is possible (ARCH-0038: no body ⇒ no EdgeRef to refresh,
        // no refs for the sweep scope).
        let sweep_key = self.write_redaction_receipt_and_sweep_in_txn(
            &mut wtxn,
            &receipt_id,
            RedactionReceiptInput {
                request_id: request_uuid.to_string(),
                scope: RedactionScope::entity(id),
                reason,
                requested_at,
                soft_complete_at: hard_purge_complete_at,
                hard_purge_complete_at,
                sweep_queued_at: reason
                    .queues_historical_sweep()
                    .then_some(hard_purge_complete_at),
            },
            HardEraseSweepExtras::default(),
        )?;
        wtxn.commit()?;
        if crdt_persisted {
            self.clear_pending_tombstone(&window_label, id)?;
        }
        Ok(DeleteEntityOutcome {
            existed,
            receipt_id: Some(receipt_id),
            sweep_key: Some(sweep_key),
        })
    }

    /// Pre-purge ARCH-0038 capture for the local delete paths: decodes the
    /// entity ABOUT to be purged or SoftErased and, when it is an
    /// `edge.provenance` Claim, captures the subject EdgeRef (for the D16
    /// flag refresh) plus the `body_snapshot_ref` / `source_revision_ref`
    /// the queued historical-carrier sweep needs to locate residual
    /// snapshot/update bytes.
    ///
    /// Discrimination order — the hook stays inert for everything else:
    /// type byte FIRST (non-CLAIM ⇒ `None`), then the predicate (non-
    /// `edge.provenance` Claim ⇒ `None`). A bodiless 25 B Claim shell ⇒
    /// `None`: every local SoftErase commits the D16 edge refresh in the
    /// SAME transaction that scrubs the body, so a shell's subject edge is
    /// already consistent and the refs the sweep would need are gone with
    /// the body. A type-0 record whose NON-empty body fails
    /// claim/provenance decoding fails CLOSED with the decoder's typed error
    /// — the ONE-1104 invariant (every type-0 write is validated) is broken
    /// and the delete must not guess.
    fn capture_provenance_delete(&self, id: &EntityId) -> Result<Option<CapturedProvenanceDelete>> {
        let rtxn = self.store.env.read_txn()?;
        let Some(raw) = self.store.entities.get(&rtxn, id.as_bytes())? else {
            return Ok(None);
        };
        let header =
            EntityMetadataHeader::parse(raw).ok_or(Error::CorruptedIndex("entity header"))?;
        if header.entity_type != ENTITY_TYPE_CLAIM {
            return Ok(None);
        }
        let body = &raw[ENTITY_METADATA_HEADER_LEN..];
        if body.is_empty() {
            return Ok(None);
        }
        let wrapper = crate::claim::decode_claim_body(body, true)?;
        if wrapper.predicate != PREDICATE_EDGE_PROVENANCE {
            return Ok(None);
        }
        let ClaimSubject::Edge {
            source,
            kind,
            target,
        } = wrapper.subject
        else {
            return Err(Error::InvalidProvenanceBody(
                "edge.provenance claim subject is not a 33-byte EdgeRef",
            ));
        };
        let record = decode_edge_provenance_body(&wrapper.value)?;
        Ok(Some(CapturedProvenanceDelete {
            subject: EdgeRef::new(source, kind, target),
            source_revision_ref: record.source_revision_ref,
            body_snapshot_ref: record.body_snapshot_ref,
        }))
    }

    /// ARCH-0038 DELETE interplay (D16), run in the SAME transaction that
    /// purged / SoftErased the provenance Claim: refresh the subject edge's
    /// cached flags — restamp from the deterministic D14 winner among the
    /// REMAINING live Claims; else, when a RETRACTED `edge.provenance` Claim
    /// for the same EdgeRef still survives, KEEP the 26 B retracted dampening
    /// stamp (the withdrawn provenance must stay dampened — retractionRules
    /// RETRACT); only when NO provenance Claim of ANY lifecycle survives is
    /// the cached flag unauditable and the edge downgraded 26 B → 24 B bare.
    /// Both `edges_out` and `edges_in` carry identical bytes; when the edge
    /// bytes changed, the endpoints' PPR caches are invalidated and the graph
    /// version bumped. A subject edge that no longer exists (deleted
    /// independently of its Claims) leaves nothing to refresh — no-op.
    fn refresh_subject_edge_after_claim_delete_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        deleted_claim_id: &EntityId,
        subject: &EdgeRef,
    ) -> Result<()> {
        let edge_key = Store::encode_edge_key(&subject.source, subject.kind, &subject.target);
        if self.store.edges_out.get(wtxn, &edge_key)?.is_none() {
            return Ok(());
        }
        let survivors =
            self.live_edge_provenance_claims_in_txn(wtxn, subject, Some(deleted_claim_id))?;
        let precedence: Vec<ProvenancePrecedence> = survivors
            .iter()
            .map(StoredProvenanceClaim::precedence)
            .collect();
        let changed = match winner_index(&precedence) {
            Some(index) => {
                restamp_edge_flags(&self.store, wtxn, subject, survivors[index].flags())?;
                true
            }
            // No ACTIVE survivor. "The derived edge flag follows the Claim"
            // (ARCH-0038 D16) — but a RETRACTED `edge.provenance` Claim is
            // still readable truth, so it KEEPS the 26 B retracted dampening
            // stamp rather than downgrading to a bare 24 B edge that would
            // re-enable PPR propagation of the WITHDRAWN provenance. Only when
            // no provenance Claim of ANY lifecycle survives is the flag
            // unauditable and the edge downgraded to bare.
            None => self.refresh_to_retracted_survivor_or_bare(wtxn, deleted_claim_id, subject)?,
        };
        if changed {
            ppr::invalidate_ppr_for_edge(&self.store, wtxn, &subject.source, &subject.target)?;
            ppr::increment_graph_version(&self.store, wtxn)?;
        }
        Ok(())
    }

    /// D16 fallback when the deleted Claim left NO active survivor: if a
    /// RETRACTED `edge.provenance` Claim for `subject` still exists, restamp
    /// the edge with `confirmation_status` = retracted (3) and the retracted
    /// WINNER's persisted `actor_class` — keeping the 26 B retracted dampening
    /// stamp the contract mandates (retractionRules RETRACT), mirroring
    /// `retract_edge_provenance`'s own None-branch so the two paths agree.
    /// Otherwise downgrade 26 B → 24 B bare (no truth-Claim of any lifecycle
    /// survives ⇒ an unauditable cached flag). Returns whether the bytes
    /// changed.
    fn refresh_to_retracted_survivor_or_bare(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        deleted_claim_id: &EntityId,
        subject: &EdgeRef,
    ) -> Result<bool> {
        let retracted =
            self.retracted_edge_provenance_claims_in_txn(wtxn, subject, Some(deleted_claim_id))?;
        let precedence: Vec<ProvenancePrecedence> = retracted
            .iter()
            .map(StoredProvenanceClaim::precedence)
            .collect();
        match winner_index(&precedence) {
            Some(index) => {
                restamp_edge_flags(
                    &self.store,
                    wtxn,
                    subject,
                    EdgeProvenanceFlags {
                        confirmation_status: EdgeConfirmationStatus::Retracted,
                        actor_class: retracted[index].actor_class,
                    },
                )?;
                Ok(true)
            }
            None => downgrade_edge_to_bare(&self.store, wtxn, subject),
        }
    }

    // NOTE (ONE-1133): the bare non-txn `purge_entity_active_store` wrapper
    // was removed — both sync replay surfaces now route through the
    // reason-aware `apply_replayed_tombstone`, and a bare purge entry point
    // would be an invitation to bypass the ARCH-0038 reason semantics.

    fn purge_entity_active_store_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        id: &EntityId,
    ) -> Result<bool> {
        let (existed, had_vector, had_graph_mutation, neighbors) =
            deindex_entity(&self.store, wtxn, id)?;
        crate::codebase::delete_codebase_snapshot_in_txn(&self.store, wtxn, id)?;
        ppr::invalidate_ppr_for_delete(&self.store, wtxn, id, &neighbors)?;
        if had_graph_mutation {
            ppr::increment_graph_version(&self.store, wtxn)?;
        }
        if had_vector {
            crate::hnsw::increment_vector_version(&self.store, wtxn)?;
        }
        Ok(existed)
    }

    fn soft_erase_active_store_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        id: &EntityId,
    ) -> Result<(bool, bool)> {
        let (hint_had_vector, hint_had_graph_mutation, _hint_neighbors) =
            deindex_lexical_query_hints_for_target(&self.store, wtxn, id)?;
        if hint_had_graph_mutation {
            ppr::increment_graph_version(&self.store, wtxn)?;
        }
        bm25::deindex_text(&self.store, wtxn, id)?;
        delete_from_phonetic_postings(&self.store, wtxn, id)?;
        crate::code_revision::delete_code_revision_lifecycle_in_txn(&self.store, wtxn, id)?;
        crate::codebase::delete_codebase_snapshot_in_txn(&self.store, wtxn, id)?;
        let blob_cleanup =
            crate::blob_artifact::delete_blob_artifact_lifecycle_in_txn(&self.store, wtxn, id)?;
        if blob_cleanup.had_graph_mutation {
            ppr::increment_graph_version(&self.store, wtxn)?;
        }
        self.store.clear_pending_embedding(wtxn, id)?;
        let entity_had_vector = self.store.vectors.delete(wtxn, id.as_bytes())?;
        let mut had_vector = hint_had_vector | entity_had_vector | blob_cleanup.had_vector;
        crate::hnsw::hnsw_deindex(&self.store, wtxn, id)?;

        let Some(entity_record) = self.store.entities.get(wtxn, id.as_bytes())? else {
            let cleanup = delete_vad_annotation_metadata_in_txn(&self.store, wtxn, id)?;
            had_vector |= cleanup.had_vector;
            if cleanup.had_graph_mutation {
                ppr::invalidate_ppr_for_delete(&self.store, wtxn, id, &cleanup.neighbors)?;
                ppr::increment_graph_version(&self.store, wtxn)?;
            }
            return Ok((false, had_vector));
        };
        let header = EntityMetadataHeader::parse(entity_record)
            .ok_or(Error::CorruptedIndex("entity metadata"))?;
        let payload = entity_record[..ENTITY_METADATA_HEADER_LEN].to_vec();
        let mut cleanup = VadAnnotationCleanup::default();
        delete_vad_annotation_metadata_for_type_in_txn(
            &self.store,
            wtxn,
            id,
            header.entity_type,
            &mut cleanup,
        )?;
        had_vector |= cleanup.had_vector;
        if cleanup.had_graph_mutation {
            ppr::invalidate_ppr_for_delete(&self.store, wtxn, id, &cleanup.neighbors)?;
            ppr::increment_graph_version(&self.store, wtxn)?;
        }

        crate::dreamer_runner::deindex_dreamer_milestone_claim(&self.store, wtxn, id)?;
        self.store.entities.put(wtxn, id.as_bytes(), &payload)?;
        Ok((true, had_vector))
    }

    /// Reason-aware replay of a CRDT tombstone into the LOCAL active store —
    /// the ONE primitive every sync replay surface routes through (Observer
    /// B's tombstone phase and `forward_rematerialize`'s tombstone pass), so
    /// a remote delete can never diverge from the pinned ARCH-0038 reason
    /// semantics. OWNER-DECISION (M4-06 / ONE-1133, fail-closed): replay
    /// routes through this reason-aware delete primitive, never bare purge.
    ///
    /// * KNOWN-soft value (`reason = user_delete`) → shell-preserving
    ///   SoftErase: payload truncated to the 25 B entity header,
    ///   text/phonetic/vector/hnsw deindexed, and — when the entity was a
    ///   live `edge.provenance` Claim — the D16 subject-edge refresh
    ///   committed in the SAME transaction. No receipt, no sweep row
    ///   (contracts.ts `user_delete`: activeStoreHardPurgeV1 = false,
    ///   receipt = false).
    /// * Hard value (known hard reason, legacy 8-byte, reserved 0, unknown
    ///   byte, malformed) → destructive purge of the payload plus every
    ///   active index entry, the D16 refresh in the SAME transaction, and —
    ///   when local state was actually erased — a LOCAL `h:{seq:8BE}`
    ///   historical-carrier sweep row (`deadline_at` ≤ queued_at + 30 d,
    ///   GDPR Art. 12(3)) and a LOCAL REDACTION_AUDIT receipt whose
    ///   `request_id` comes from the wire value (OWNER-DECISION: Art. 5(2)
    ///   accountability attaches to each replica actually erasing, so N
    ///   devices yield N receipts for one request). Ambiguity resolves to
    ///   MORE deletion, never less.
    /// * Never-downgrade on receive: a soft value for an id this replica
    ///   already hard-purged finds no row to scrub and is a no-op — it
    ///   never recreates a shell.
    /// * Idempotent: after a completed hard apply the delete-scope probe
    ///   finds nothing, so re-application (every-boot forward
    ///   re-materialization, repeated delta delivery) is a receipt-free
    ///   no-op.
    #[cfg_attr(not(feature = "sync"), allow(dead_code))]
    pub(crate) fn apply_replayed_tombstone(
        &self,
        id: &EntityId,
        raw_value: &[u8],
    ) -> Result<ReplayedTombstoneOutcome> {
        let decoded = decode_tombstone_value(raw_value);
        if let Some(header) = self.read_entity_header(id)?
            && is_delete_protected_engine_record(header.entity_type)
        {
            return Err(Error::MaintenanceKindNotWritable(header.entity_type));
        }
        // ARCH-0038 DELETE interplay: an `edge.provenance` Claim's subject
        // EdgeRef and sweep refs are only readable PRE-scrub.
        let captured = self.capture_provenance_delete(id)?;

        if !decoded.is_hard() {
            let mut wtxn = self.store.env.write_txn()?;
            let had_body = self
                .store
                .entities
                .get(&wtxn, id.as_bytes())?
                .is_some_and(|raw| raw.len() > ENTITY_METADATA_HEADER_LEN);
            let (existed, had_vector) = self.soft_erase_active_store_in_txn(&mut wtxn, id)?;
            if had_vector {
                crate::hnsw::increment_vector_version(&self.store, &mut wtxn)?;
            }
            // D16: SoftErase tombstones the Claim, and "the derived edge
            // flag follows the Claim" — refresh in the SAME transaction.
            if existed && let Some(captured) = &captured {
                self.refresh_subject_edge_after_claim_delete_in_txn(
                    &mut wtxn,
                    id,
                    &captured.subject,
                )?;
            }
            wtxn.commit()?;
            return Ok(ReplayedTombstoneOutcome::SoftErased {
                changed: had_body || had_vector,
            });
        }

        let mut wtxn = self.store.env.write_txn()?;
        let marker_key = local_hard_delete_key(id);
        let marker_value = decoded.local_hard_delete_marker_value();
        // Probe the FULL delete scope (entity row, vectors, text, phonetic,
        // short-ids, edges): orphan residue without an entities row still
        // counts as local state to erase, mirroring the local
        // `delete_entity_without_header` semantics.
        if !self.active_delete_scope_exists_in_txn(&wtxn, id)? {
            // Hard-once-seen is durable LOCAL truth even when nothing local
            // was erased (never-materialized id): the permanent `dt:` marker
            // still gates a future re-put after hostile tombstone-map
            // manipulation. The guarded write keeps every-boot replay a
            // read-only no-op once the marker exists.
            if self.store.sync_state.get(&wtxn, &marker_key)?.is_none() {
                self.store
                    .sync_state
                    .put(&mut wtxn, &marker_key, &marker_value)?;
                wtxn.commit()?;
            }
            return Ok(ReplayedTombstoneOutcome::HardPurged {
                erased: false,
                receipt_id: None,
                sweep_key: None,
            });
        }
        self.purge_entity_active_store_in_txn(&mut wtxn, id)?;
        // Receiver-side `dt:` local hard-delete marker (pinned: presence-only
        // value, GLOBAL key, permanent, no GC) — written in the SAME txn as
        // the purge so local delete truth survives CRDT-map manipulation.
        self.store
            .sync_state
            .put(&mut wtxn, &marker_key, &marker_value)?;
        // ARCH-0038 DELETE: "The derived edge flag follows the Claim" — the
        // subject edge is refreshed in the SAME transaction as the purge.
        if let Some(captured) = &captured {
            self.refresh_subject_edge_after_claim_delete_in_txn(&mut wtxn, id, &captured.subject)?;
        }
        let applied_at = unix_seconds_now();
        let receipt_id = EntityId::now();
        let sweep_key = self.write_redaction_receipt_and_sweep_in_txn(
            &mut wtxn,
            &receipt_id,
            RedactionReceiptInput {
                request_id: decoded.receipt_request_id(),
                scope: RedactionScope::entity(id),
                reason: decoded.receipt_hard_reason(),
                // The origin's request time, straight off the wire (0 for
                // malformed shapes); completion stamps are device-local
                // facts on the replica that erased.
                requested_at: decoded.deleted_at,
                soft_complete_at: applied_at,
                hard_purge_complete_at: applied_at,
                sweep_queued_at: Some(applied_at),
            },
            sweep_extras(captured.as_ref()),
        )?;
        wtxn.commit()?;
        Ok(ReplayedTombstoneOutcome::HardPurged {
            erased: true,
            receipt_id: Some(receipt_id),
            sweep_key: Some(sweep_key),
        })
    }

    #[cfg(feature = "sync")]
    pub(crate) fn apply_replayed_tombstone_for_sync(
        &self,
        id: &EntityId,
        raw_value: &[u8],
    ) -> Result<ReplayedTombstoneOutcome> {
        if let Some(header) = self.read_entity_header(id)?
            && is_delete_protected_engine_record(header.entity_type)
        {
            return Ok(ReplayedTombstoneOutcome::HardPurged {
                erased: false,
                receipt_id: None,
                sweep_key: None,
            });
        }
        self.apply_replayed_tombstone(id, raw_value)
    }

    pub(crate) fn read_entity_header(&self, id: &EntityId) -> Result<Option<EntityMetadataHeader>> {
        let rtxn = self.store.env.read_txn()?;
        let Some(raw) = self.store.entities.get(&rtxn, id.as_bytes())? else {
            return Ok(None);
        };
        EntityMetadataHeader::parse(raw)
            .ok_or(Error::CorruptedIndex("entity metadata"))
            .map(Some)
    }

    /// Presence-only check for the permanent `dt:{entity_hex}` local
    /// hard-delete marker. Materialization gates OR this with the CRDT
    /// tombstones-map presence so LOCAL delete truth survives hostile
    /// tombstone-map manipulation (a removed tombstone + re-put entity must
    /// not resurrect). The value is NEVER decoded (pinned presence-only
    /// semantics).
    #[cfg_attr(not(feature = "sync"), allow(dead_code))]
    pub(crate) fn local_hard_delete_marker_exists_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        id: &EntityId,
    ) -> Result<bool> {
        Ok(self
            .store
            .sync_state
            .get(txn, &local_hard_delete_key(id))?
            .is_some())
    }

    fn active_delete_scope_exists_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
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
        if edges_in.next().transpose()?.is_some() {
            return Ok(true);
        }

        vad_annotation_delete_scope_exists_in_txn(&self.store, txn, id)
    }

    /// Writes the ARCH-0038 CRDT tombstone (v2 wire value, ONE-1132) into
    /// the window doc addressed by `window_ts`. In the SAME CRDT commit as
    /// the tombstone insert, the live `entities[id]` copy (an ACTIVE
    /// carrier, not history) and — for hard reasons — the entity's
    /// edges-map keys are removed; op-history bytes remain for the bounded
    /// `h:` sweep (ONE-1091). Returns whether the CRDT record was
    /// persisted: `false` only in non-`sync` builds, where the `pt:`
    /// pending-tombstone marker carries the deletion intent until a
    /// sync-enabled boot replays it.
    ///
    /// ONE-1135 (delete-propagation transport):
    /// - **Live routing**: when the window is OPEN (registry lookup via the
    ///   attached [`crate::sync::WindowManager`]), the tombstone commits
    ///   through the registry-owned live doc — Observer A persists the `u:`
    ///   row and every registry holder sees the delete — never through a
    ///   parallel transient copy whose `d:w:` export a live
    ///   `persist_state` would clobber.
    /// - **Transient path** (window NOT open): the doc is import-merged
    ///   from the persisted snapshot + pending `u:` rows
    ///   ([`crate::sync::window::load_window_from_state`]) — never a blind
    ///   overwrite.
    /// - **Delete-bearing queue row**: the tombstone-commit delta is pushed
    ///   to the offline queue with the `d:{seq}` sidecar marker, so an
    ///   OFFLINE delete is delivered on next connect and survives the
    ///   optimistic clear until VV-confirmed (M4-12).
    /// - **Carrier-15 scrub** (hard reasons): pre-existing `q:` rows for
    ///   this window and the persisted `u:w:` rows the snapshot subsumed
    ///   are dropped, and the `fr:w:{key}` full-resync marker is set
    ///   (ARCH-0038 carriers 13–15; fail-closed — over-drop + full resync,
    ///   never leak).
    ///
    /// OWNER-DECISION (ONE-1135, live-path commit origin): the live-doc
    /// commit is tagged `BRIDGE_ORIGIN`. Observer A fires for ALL local
    /// commits and still persists the `u:` row; Observer B MUST skip it —
    /// the local delete path owns the LMDB purge under the pinned
    /// tombstone → purge → receipt ordering, and a B-side replay here would
    /// purge BEFORE the purge transaction, voiding the local receipt and
    /// the `DeleteEntityOutcome` (mirrors `replay_pending_tombstones`).
    #[cfg(feature = "sync")]
    fn write_crdt_tombstone(
        &self,
        id: &EntityId,
        window_ts: u64,
        value: &TombstoneValueV2,
    ) -> Result<bool> {
        use crate::sync::bridge::BRIDGE_ORIGIN;
        use crate::sync::loro_support::{doc_version_vector, export_snapshot};
        use crate::sync::schema::create_window_doc;
        use crate::sync::types::WindowKey;
        use crate::sync::window::{
            apply_tombstone_to_window_doc, export_tombstone_commit_delta, load_window_from_state,
            merge_persisted_state_into_doc,
        };
        use loro::CommitOptions;

        let window_key = WindowKey::from_timestamp(window_ts);

        if let Some((window, materializer)) = self.live_window(&window_key) {
            // Live path: merge the on-disk record first (clobber guard —
            // a tombstone persisted transiently while this window was open
            // must survive the snapshot export below), then commit the
            // delete through the SHARED doc.
            //
            // The merge runs OUTSIDE the materializer lock: importing into
            // an observed doc fires Observer B synchronously on this
            // thread, and the callback takes the (non-reentrant) lock
            // itself.
            let merged_update_keys =
                merge_persisted_state_into_doc(self, &window.doc, &window_key)?;
            // The tombstone commit + exports run UNDER the materializer
            // lock: Observer B's tombstone-check + LMDB-materialize is
            // atomic under that lock, so a concurrent remote re-put can no
            // longer check the tombstones map BEFORE this commit and write
            // the deleted body back AFTER the purge txn that follows
            // (resurrection race). Deadlock-free: the BRIDGE_ORIGIN commit
            // is rejected by Observer B callbacks BEFORE they lock, and
            // Observer A never takes this lock. Lock order materializer →
            // LMDB txn matches every other holder; the registry lock is
            // NOT held here (manager lock-order pin).
            let (delete_update, snapshot, vv) = {
                let _guard = materializer.lock();
                let vv_before = window.doc.oplog_vv();
                apply_tombstone_to_window_doc(&window.doc, id, &value.encode())?;
                window
                    .doc
                    .commit_with(CommitOptions::new().origin(BRIDGE_ORIGIN));
                let delete_update = export_tombstone_commit_delta(&window.doc, &vv_before)?;
                let snapshot = export_snapshot(&window.doc)?;
                let vv = doc_version_vector(&window.doc);
                (delete_update, snapshot, vv)
            };
            self.finish_crdt_tombstone_persist(
                &window_key,
                &snapshot,
                &vv,
                value,
                delete_update.as_ref(),
                &merged_update_keys,
            )?;
            return Ok(true);
        }

        // Transient path (window not open): the loaded doc IS the
        // import-merge of `d:w:` + pending `u:` rows.
        let merged_update_keys = self.sync_state_keys_with_prefix(&format!("u:w:{window_key}:"))?;
        let doc = match load_window_from_state(self, "local", &window_key) {
            Ok(doc) => doc,
            Err(Error::WindowNotFound { .. }) => create_window_doc("local", &window_key),
            Err(err) => return Err(err),
        };
        let vv_before = doc.oplog_vv();
        apply_tombstone_to_window_doc(&doc, id, &value.encode())?;
        doc.commit();
        let delete_update = export_tombstone_commit_delta(&doc, &vv_before)?;

        let snapshot = export_snapshot(&doc)?;
        let vv = doc_version_vector(&doc);
        self.finish_crdt_tombstone_persist(
            &window_key,
            &snapshot,
            &vv,
            value,
            delete_update.as_ref(),
            &merged_update_keys,
        )?;
        Ok(true)
    }

    /// One transaction for the delete path's sync_state / sync_queue
    /// bookkeeping (both DBs share the LMDB env): persist the window-doc
    /// snapshot triple, queue the delete-bearing update, and — for hard
    /// reasons — run the carrier-15 scrub + set the `fr:w:{key}`
    /// full-resync marker (consumer lands in M4-12).
    #[cfg(feature = "sync")]
    fn finish_crdt_tombstone_persist(
        &self,
        window_key: &crate::sync::WindowKey,
        snapshot: &[u8],
        vv: &[u8],
        value: &TombstoneValueV2,
        delete_update: Option<&crate::sync::window::DeleteBearingUpdate>,
        scrubbed_update_keys: &[String],
    ) -> Result<()> {
        let is_hard = value.reason.is_hard();
        self.with_write_txn(|wtxn| {
            crate::sync::window::persist_window_doc_in_txn(self, wtxn, window_key, snapshot, vv)?;
            if is_hard {
                // ARCH-0038 carrier 15: pending `q:` rows for this window
                // may carry the deleted payload — drop them all (fail-closed
                // over-drop; delete-bearing rows are preserved inside the
                // scrub). The `u:w:` rows the snapshot just subsumed are
                // active payload carriers too.
                crate::sync::queue::scrub_window_updates_in_txn(self, wtxn, window_key.as_str())?;
                for update_key in scrubbed_update_keys {
                    self.store.sync_state.delete(wtxn, update_key)?;
                }
                // Carriers 13–14: this window's sync state is no longer a
                // faithful delta source — mark it for a full per-window
                // resync on the next connect.
                let fr_key = format!("fr:w:{window_key}");
                self.store.sync_state.put(wtxn, &fr_key, &[1_u8])?;
            }
            if let Some(update) = delete_update {
                crate::sync::queue::push_delete_bearing_in_txn(
                    self,
                    wtxn,
                    window_key.as_str(),
                    update,
                )?;
            }
            // svf LAST (ONE-1151): the hard branch scrubbed the merged u:w:
            // rows above; the soft branch kept them. Recompute freshness from
            // the FINAL u:w: set so a surviving row reads stale (the
            // fast-reconnect reader then full-opens instead of trusting an
            // sv:w: VV that omits the survivor's ops).
            crate::sync::window::write_window_svf_in_txn(self, wtxn, window_key)
        })
    }

    #[cfg(not(feature = "sync"))]
    #[allow(clippy::unnecessary_wraps)]
    fn write_crdt_tombstone(
        &self,
        _id: &EntityId,
        _window_ts: u64,
        _value: &TombstoneValueV2,
    ) -> Result<bool> {
        // No CRDT in this build — the `pt:` marker written in the purge /
        // scrub txn is the deletion's durable propagation intent.
        Ok(false)
    }

    /// Writes the CRDT-independent `pt:{window}:{entity_hex}` marker in the
    /// caller's purge / shell-scrub transaction (ONE-1132 OWNER-DECISION:
    /// deletion durability must not depend on the `sync` cargo feature).
    /// Value = the v2 tombstone wire value, so a sync-enabled boot can
    /// replay it verbatim.
    fn put_pending_tombstone_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        window_label: &str,
        id: &EntityId,
        value: &TombstoneValueV2,
    ) -> Result<()> {
        let key = pending_tombstone_key(window_label, id);
        self.store.sync_state.put(wtxn, &key, &value.encode())?;
        Ok(())
    }

    /// Clears the pending-tombstone marker. Only called once the CRDT
    /// commit + snapshot persistence have succeeded — never before.
    fn clear_pending_tombstone(&self, window_label: &str, id: &EntityId) -> Result<()> {
        self.with_write_txn(|wtxn| {
            let key = pending_tombstone_key(window_label, id);
            self.store.sync_state.delete(wtxn, &key)?;
            Ok(())
        })
    }

    /// Writes a REDACTION_AUDIT receipt as a normal entity-envelope record
    /// (contracts.ts `redactionAuditReceipt.storage`), maintaining the same
    /// index footprint `apply_put` gives every other envelope write. The
    /// receipt is a point event (`occurred_start == occurred_end ==
    /// learned_at`), so per the `apply_put` convention it gets a
    /// `temporal_occurred_start` row but NO `temporal_occurred_end` row and
    /// no `temporal_long_intervals` row. Maintenance kinds carry no short ID.
    fn put_redaction_audit_receipt_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        receipt_id: &EntityId,
        learned_at: u64,
        body: &[u8],
    ) -> Result<()> {
        // Shared header helper (ONE-1140): the attestation transcript signs
        // EXACTLY these stored header bytes — one assembly point, no drift.
        let mut payload = Vec::with_capacity(ENTITY_METADATA_HEADER_LEN + body.len());
        payload.extend_from_slice(&crate::deletion::receipt_envelope_header(learned_at));
        payload.extend_from_slice(body);
        self.store
            .entities
            .put(wtxn, receipt_id.as_bytes(), &payload)?;

        let type_key = Store::encode_type_key(ENTITY_TYPE_REDACTION_AUDIT, receipt_id);
        self.store.type_index.put(wtxn, &type_key, &[])?;

        let occurred_start_key = Store::encode_temporal_key(learned_at, receipt_id);
        self.store
            .temporal_occurred_start
            .put(wtxn, &occurred_start_key, &[])?;

        let learned_key = Store::encode_temporal_key(learned_at, receipt_id);
        self.store.temporal_learned.put(wtxn, &learned_key, &[])?;
        Ok(())
    }

    fn write_redaction_receipt_and_sweep_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        receipt_id: &EntityId,
        input: RedactionReceiptInput,
        sweep_extras: HardEraseSweepExtras,
    ) -> Result<Vec<u8>> {
        let sweep_key = if let Some(queued_at) = input.sweep_queued_at {
            self.enqueue_hard_erase_sweep_in_txn(
                wtxn,
                input.scope.clone(),
                sweep_extras,
                queued_at,
            )?
        } else {
            Vec::new()
        };

        // ONE-1140 (OD-2/OD-6): every receipt is signed at mint. The device
        // identity (client id + Ed25519 keypair) is lazily self-provisioned
        // in THIS txn — all receipt-mint paths funnel through here, so this
        // is the single in-txn hook.
        let identity = crate::identity::ensure_device_identity_in_txn(self, wtxn)?;
        let hard_purge_complete_at = input.hard_purge_complete_at;
        let body = encode_redaction_audit_receipt(input, receipt_id, &identity)?;
        self.put_redaction_audit_receipt_in_txn(wtxn, receipt_id, hard_purge_complete_at, &body)?;
        Ok(sweep_key)
    }

    fn enqueue_hard_erase_sweep_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        scope: RedactionScope,
        extras: HardEraseSweepExtras,
        queued_at: u64,
    ) -> Result<Vec<u8>> {
        let seq = self.allocate_next_hard_erase_sweep_seq(wtxn)?;
        let key = encode_hard_erase_sweep_key(seq);
        let value = encode_hard_erase_sweep_job(scope, extras, queued_at)?;
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
        Ok(self.search_vector_with_telemetry(query, limit)?.value)
    }

    /// Searches nearest neighbors by cosine similarity and returns the
    /// retrieval telemetry run id when the best-effort telemetry row was
    /// persisted.
    pub fn search_vector_with_telemetry(
        &self,
        query: &[f32],
        limit: usize,
    ) -> Result<RetrievalWithTelemetry<Vec<ScoredEntity>>> {
        if query.len() != self.config.dimensions {
            return Err(Error::DimensionMismatch {
                expected: self.config.dimensions,
                got: query.len(),
            });
        }
        if let Some(error) = Error::invalid_vector_component(query) {
            return Err(error);
        }

        let started_at = unix_seconds_now();
        let started = Instant::now();
        let results = {
            let rtxn = self.store.env.read_txn()?;
            hnsw::hnsw_search(&self.store, &self.config, &rtxn, query, limit)?
        };
        let run_id = self.record_vault_search_retrieval_run(
            RetrievalSignal::Vector,
            started_at,
            started,
            &results,
            limit,
        );
        Ok(RetrievalWithTelemetry {
            value: results,
            run_id,
        })
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

    /// Operational weight setter (ONE-1113, ARCH-0034 #write-protection
    /// carve-out): rewrites ONLY the weight bytes (f32 LE at offset 0..4) of
    /// an EXISTING edge, writing IDENTICAL bytes to both `edges_out` and
    /// `edges_in`. Weight is a LOCAL operational field (M3 weight pin) — the
    /// provenance Claim asserts the relation, never the weight — so this
    /// setter works on bare AND provenanced edges alike, preserves the
    /// 26-byte hot-flag bytes verbatim, and never touches provenance Claims.
    /// Exempt from the [`Error::EdgeIsProvenanced`] reject gate by
    /// construction.
    ///
    /// For decay / retrieval-feedback loops use the batch form
    /// [`BatchBuilder::set_edge_weight`].
    ///
    /// Fail-closed: [`Error::EdgeNotFound`] when the edge does not exist
    /// (the setter never upserts); [`Error::InvalidEdgeWeight`] outside the
    /// contract \[0, 1\]. PPR caches for the edge endpoints are invalidated
    /// exactly like a plain edge write.
    pub fn set_edge_weight(
        &self,
        src: &EntityId,
        kind: EdgeKind,
        tgt: &EntityId,
        weight: f32,
    ) -> Result<()> {
        self.batch()
            .set_edge_weight(src, kind, tgt, weight)
            .commit()
    }

    /// Operational VAD setter (ONE-1113, ARCH-0034 #write-protection
    /// carve-out): rewrites ONLY the VAD bytes (three f32 LE at offset
    /// 12..24) of an EXISTING semantic edge, writing IDENTICAL bytes to both
    /// directions. Weight, `created_at`, the value LENGTH (a 24-byte bare
    /// value stays 24 B; a 26-byte provenanced value keeps its hot-flag
    /// bytes verbatim), and provenance Claims are untouched. Exempt from the
    /// [`Error::EdgeIsProvenanced`] reject gate by construction.
    ///
    /// For batched feedback loops use [`BatchBuilder::set_edge_vad`].
    ///
    /// Fail-closed: [`Error::EdgeNotFound`] when the edge does not exist;
    /// [`Error::InvalidVad`] on non-finite/out-of-range components; a typed
    /// rejection on structural 12-byte kinds (the contract layout table —
    /// structural edges carry no VAD).
    pub fn set_edge_vad(
        &self,
        src: &EntityId,
        kind: EdgeKind,
        tgt: &EntityId,
        vad: Vad,
    ) -> Result<()> {
        self.batch().set_edge_vad(src, kind, tgt, vad).commit()
    }

    /// Binds an actor to a session-scoped write handle (ONE-1113 ruling,
    /// session ergonomics): bind the actor ONCE, then write provenanced
    /// edges normally — the handle injects `actor_entity_ref` +
    /// `actor_class` on every provenance-path write, so prod callers (e.g.
    /// the MCP daemon's named-writes lane, ARCH-0028) never type provenance
    /// by hand.
    ///
    /// The handle is pure ergonomics: NO sessions registry, NO
    /// authorization — "sessions are correlation-only, never authorization".
    /// Binding validates nothing by itself; every write through the handle
    /// runs the full [`Vault::put_edge_provenance`] gate chain (actor
    /// existence, D13 class validation, D14 precedence, …).
    ///
    /// NAMING: `as_actor` / [`ActorBound`] are INDICATIVE, engine-internal
    /// names (the ruling pins the semantics, not the ABI surface); the
    /// public ABI name is pinned at the FFI/NAPI milestone.
    #[must_use]
    pub fn as_actor(&self, actor: EntityId, actor_class: EdgeActorClass) -> ActorBound<'_> {
        ActorBound {
            vault: self,
            actor,
            actor_class,
        }
    }

    pub(crate) fn scoped_read_search_candidate_limit(
        &self,
        requested: usize,
        include_text: bool,
        include_vector: bool,
    ) -> Result<usize> {
        if requested == 0 {
            return Ok(0);
        }

        let rtxn = self.store.env.read_txn()?;
        let mut limit = requested;
        let mut hybrid_union_limit = 0usize;
        if include_text {
            let indexed_docs = usize::try_from(crate::bm25::read_total_docs(&self.store, &rtxn)?)
                .map_err(|_| Error::IndexOverflow("bm25 total docs"))?;
            hybrid_union_limit = hybrid_union_limit.saturating_add(indexed_docs);
            limit = limit.max(indexed_docs);
        }
        if include_vector {
            let indexed_vectors = crate::hnsw::hnsw_entity_count(&self.store, &rtxn)?;
            hybrid_union_limit = hybrid_union_limit.saturating_add(indexed_vectors);
            limit = limit.max(indexed_vectors);
        }
        if include_text && include_vector {
            limit = limit.max(hybrid_union_limit);
        }
        Ok(limit)
    }

    pub(crate) fn claim_facet_refs_in(
        &self,
        rtxn: &heed::RoTxn<'_>,
        id: &EntityId,
    ) -> Result<Vec<EntityId>> {
        let mut prefix = [0_u8; ENTITY_ID_LEN + 1];
        prefix[..ENTITY_ID_LEN].copy_from_slice(id.as_bytes());
        prefix[ENTITY_ID_LEN] = EdgeKind::FacetOf as u8;

        let mut facets = Vec::new();
        for entry in self.store.edges_out.prefix_iter(rtxn, prefix.as_slice())? {
            if facets.len() >= MAX_EDGE_QUERY_RESULTS {
                return Err(Error::IndexOverflow("claim_facet_refs"));
            }
            let (key, _) = entry?;
            require_key_len(key, ENTITY_ID_LEN + 1 + ENTITY_ID_LEN, "facet edge key")?;
            let target = EntityId::from_bytes(
                key[ENTITY_ID_LEN + 1..]
                    .try_into()
                    .map_err(|_| Error::CorruptedIndex("facet edge key"))?,
            )
            .map_err(|_| Error::CorruptedIndex("facet edge key"))?;
            facets.push(target);
        }
        Ok(facets)
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

    /// Returns BM25 text matches for a query under the contract-default
    /// rank profile.
    pub fn search_text(&self, query: &str, limit: usize) -> Result<Vec<ScoredEntity>> {
        Ok(self.search_text_with_telemetry(query, limit)?.value)
    }

    /// Returns BM25 text matches and the retrieval telemetry run id when the
    /// best-effort telemetry row was persisted.
    pub fn search_text_with_telemetry(
        &self,
        query: &str,
        limit: usize,
    ) -> Result<RetrievalWithTelemetry<Vec<ScoredEntity>>> {
        self.search_text_with_profile_and_telemetry(
            query,
            limit,
            &crate::config::Bm25RankProfile::default(),
        )
    }

    /// Returns BM25 text matches for a query under a caller-supplied
    /// scoring-only rank profile (ARCH-0031: Okapi vs `Plus { delta }`,
    /// per-channel weight / `b`). The profile never touches the on-disk
    /// index or the open-time manifest handshake — changing it does not
    /// require a reindex. Invalid profiles fail closed with
    /// [`crate::Error::InvalidRankProfile`].
    pub fn search_text_with_profile(
        &self,
        query: &str,
        limit: usize,
        profile: &crate::config::Bm25RankProfile,
    ) -> Result<Vec<ScoredEntity>> {
        Ok(self
            .search_text_with_profile_and_telemetry(query, limit, profile)?
            .value)
    }

    /// Returns BM25 text matches for a caller-supplied profile and the
    /// retrieval telemetry run id when the best-effort telemetry row was
    /// persisted.
    pub fn search_text_with_profile_and_telemetry(
        &self,
        query: &str,
        limit: usize,
        profile: &crate::config::Bm25RankProfile,
    ) -> Result<RetrievalWithTelemetry<Vec<ScoredEntity>>> {
        let config = profile.to_bm25_config()?;
        self.ensure_text_index_trusted()?;
        let started_at = unix_seconds_now();
        let started = Instant::now();
        let results = {
            let rtxn = self.store.env.read_txn()?;
            bm25::search_text(&self.store, &rtxn, &self.analyzer, &config, query, limit)?
        };
        let run_id = self.record_vault_search_retrieval_run(
            RetrievalSignal::Text,
            started_at,
            started,
            &results,
            limit,
        );
        Ok(RetrievalWithTelemetry {
            value: results,
            run_id,
        })
    }

    fn record_vault_search_retrieval_run(
        &self,
        signal: RetrievalSignal,
        started_at: u64,
        started: Instant,
        results: &[ScoredEntity],
        limit: usize,
    ) -> Option<RetrievalRunId> {
        let score_breakdown = vault_search_score_breakdown(signal, results);
        let run_id = RetrievalRunId::now();
        let record = RetrievalRunRecord::new(
            run_id,
            RetrievalAction::VaultSearch,
            started_at,
            started.elapsed().as_micros().min(u64::MAX as u128) as u64,
            vec![signal],
            score_breakdown,
            results.len(),
            0,
            (limit > 0 && results.is_empty()).then(|| "NoData".to_owned()),
        );
        if let Err(error) = self.store.record_retrieval_run(&record) {
            tracing::warn!(
                ?error,
                "vault search retrieval telemetry write failed; continuing retrieval"
            );
            None
        } else {
            Some(run_id)
        }
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

    /// Returns the newest retrieval telemetry run rows, newest first.
    pub fn retrieval_runs(&self, limit: usize) -> Result<Vec<RetrievalRunRecord>> {
        self.store.retrieval_runs(limit)
    }

    /// Returns one published retrieval telemetry row by id.
    pub fn retrieval_run(&self, run_id: RetrievalRunId) -> Result<Option<RetrievalRunRecord>> {
        self.store.retrieval_run(run_id)
    }

    /// Returns the published trace keyed by a content-addressed fork hash.
    pub fn retrieval_trace_by_fork_hash(
        &self,
        fork_hash: RetrievalTraceForkHash,
    ) -> Result<Option<RetrievalTrace>> {
        self.store.retrieval_trace_by_fork_hash(fork_hash)
    }

    /// Returns the active RET-010 retrieval-blend weight table entry.
    pub fn retrieval_blend_weight_table(&self) -> Result<RetrievalBlendWeightTableEntry> {
        self.store.retrieval_blend_weight_table()
    }

    /// Tunes and persists the active RET-010 retrieval-blend weight table
    /// from persisted retrieval rewards.
    pub fn tune_retrieval_blend_weights(
        &self,
        config: RetrievalBlendTuningConfig,
    ) -> Result<RetrievalBlendWeightTableEntry> {
        self.store.tune_retrieval_blend_weights(config)
    }

    /// Idempotently writes or replaces a retrieval outcome row for one run.
    pub fn record_retrieval_outcome(&self, outcome: RetrievalOutcome) -> Result<()> {
        self.store.record_retrieval_outcome(outcome)
    }

    /// Returns outcome rows recorded for `run_id`, sorted by outcome key.
    pub fn retrieval_outcomes(
        &self,
        run_id: RetrievalRunId,
    ) -> Result<Vec<RetrievalOutcomeRecord>> {
        self.store.retrieval_outcomes(run_id)
    }

    /// Returns pending Gate consent proposals ordered by their write decision.
    pub fn pending_gate_consents(&self, limit: usize) -> Result<Vec<PendingGateConsentRecord>> {
        self.store.pending_gate_consents(limit)
    }

    /// Returns recent Gate decisions ordered from newest to oldest.
    pub fn gate_decisions(&self, limit: usize) -> Result<Vec<GateDecisionRecord>> {
        self.store.gate_decisions(limit)
    }

    /// Checks whether the active Gate policy has an actor-ceiling row for an actor.
    pub fn gate_actor_ceiling_exists(&self, actor_class: &str, actor_ref: &str) -> Result<bool> {
        let rtxn = self.store.env.read_txn()?;
        let policy = crate::gate::resolve_policy_manifest(&self.store, &rtxn)?;
        Ok(policy.has_matching_actor_ceiling(actor_class, Some(actor_ref)))
    }

    /// Returns pending Gate consent proposals grouped by Dreamer run id.
    ///
    /// Proposals without a Dreamer run id are returned in the default lane,
    /// represented by a group with `dreamer_run_id == None`.
    pub fn pending_gate_consent_groups(
        &self,
        limit: usize,
    ) -> Result<Vec<PendingGateConsentGroup>> {
        self.store.pending_gate_consent_groups(limit)
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

    /// Returns the greatest `learned_at` timestamp present in the temporal index.
    pub fn latest_learned_at(&self) -> Result<Option<u64>> {
        let rtxn = self.store.env.read_txn()?;
        let Some((key, _)) = self.store.temporal_learned.last(&rtxn)? else {
            return Ok(None);
        };
        require_key_len(key, 24, "temporal learned key")?;
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
            require_key_len(key, 24, "temporal learned key")?;
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
                EntityMetadataHeader::parse(raw).ok_or(Error::CorruptedIndex("entity header"))?;
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
        self.try_with_write_txn(f)
    }

    /// Executes a closure within a single LMDB write transaction and allows
    /// callers to return their own error type.
    ///
    /// The transaction commits on `Ok` return and rolls back on `Err`.
    pub fn try_with_write_txn<F, T, E>(&self, f: F) -> std::result::Result<T, E>
    where
        F: FnOnce(&mut heed::RwTxn<'_>) -> std::result::Result<T, E>,
        E: From<Error>,
    {
        let mut wtxn = self.store.env.write_txn().map_err(Error::from)?;
        let result = {
            let _active_write_txn = crate::store::active_write_txn_guard();
            f(&mut wtxn)?
        };
        wtxn.commit().map_err(Error::from)?;
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

    /// Resolves a context-pack short reference to a live or soft-deleted entity.
    ///
    /// The caller supplies the parsed short id and one-byte content hash from
    /// the public `short_id:hash` form. `Ok(None)` means no short-id row exists.
    /// `Ok(Some(result))` with `result.body == None` means the short id resolves
    /// to a deleted shell or dangling row; a live entity returns its body bytes.
    pub fn hydrate_short_id(
        &self,
        short_id: &str,
        content_hash: u8,
    ) -> Result<Option<HydratedShortId>> {
        let rtxn = self.store.env.read_txn()?;
        let forward_key = encode_short_id_forward_key(short_id, content_hash);
        let Some(raw_id) = self.store.short_ids.get(&rtxn, &forward_key)? else {
            return Ok(None);
        };
        require_key_len(raw_id, ENTITY_ID_LEN, "short id entity id")?;
        let id = EntityId::from_bytes(
            raw_id
                .try_into()
                .map_err(|_| Error::CorruptedIndex("short id entity id"))?,
        )
        .map_err(|_| Error::CorruptedIndex("short id entity id"))?;

        let Some(raw) = self.store.entities.get(&rtxn, id.as_bytes())? else {
            return Ok(Some(HydratedShortId {
                id,
                entity_type: 0,
                learned_at: 0,
                deletion: Some(HydratedShortIdDeletion {
                    source: HydratedShortIdDeletionSource::DanglingShortId,
                    reason: None,
                    deleted_at: None,
                    request_id: None,
                    // No entity row remains to inspect, so hydrate treats this
                    // as an effectively hard deletion and keeps the source explicit.
                    hard: true,
                }),
                body: None,
            }));
        };
        let header =
            EntityMetadataHeader::parse(raw).ok_or(Error::CorruptedIndex("entity header"))?;
        let entity_type = header.entity_type;
        let learned_at = header.learned_at;
        let body = raw[ENTITY_METADATA_HEADER_LEN..].to_vec();
        drop(rtxn);

        if body.is_empty()
            && let Some(deletion) = self.entity_deletion_metadata(&id, learned_at)?
        {
            return Ok(Some(HydratedShortId {
                id,
                entity_type,
                learned_at,
                deletion: Some(deletion),
                body: None,
            }));
        }

        Ok(Some(HydratedShortId {
            id,
            entity_type,
            learned_at,
            deletion: None,
            body: Some(body),
        }))
    }

    /// Returns true when an entity row is a soft-delete shell, not a live
    /// zero-byte payload.
    pub fn is_deleted_shell(&self, id: &EntityId) -> Result<bool> {
        let rtxn = self.store.env.read_txn()?;
        let Some(raw) = self.store.entities.get(&rtxn, id.as_bytes())? else {
            return Ok(false);
        };
        let header =
            EntityMetadataHeader::parse(raw).ok_or(Error::CorruptedIndex("entity header"))?;
        if raw.len() != ENTITY_METADATA_HEADER_LEN {
            return Ok(false);
        }
        drop(rtxn);

        Ok(self
            .entity_deletion_metadata(id, header.learned_at)?
            .is_some())
    }

    /// Returns stable, renderer-facing data for the supersession chain that
    /// contains `anchor`.
    pub fn memory_timeline(&self, anchor: &EntityId) -> Result<MemoryTimeline> {
        let mut ids = std::collections::BTreeSet::new();
        let mut edges = std::collections::BTreeMap::new();
        let mut stack = vec![*anchor];
        ids.insert(*anchor);

        while let Some(id) = stack.pop() {
            let older = self.targets(&id, EdgeKind::Supersedes, None)?;
            let newer = self.sources(&id, EdgeKind::Supersedes, None)?;
            edges.insert(id, (older.clone(), newer.clone()));
            for next in older.into_iter().chain(newer) {
                if ids.insert(next) {
                    if ids.len() > MAX_MEMORY_TIMELINE_RECORDS {
                        return Err(Error::IndexOverflow("memory_timeline"));
                    }
                    stack.push(next);
                }
            }
        }

        let mut records = Vec::with_capacity(ids.len());
        for id in ids {
            let (supersedes, superseded_by) = edges.remove(&id).unwrap_or_default();
            records.push(self.memory_timeline_record(&id, supersedes, superseded_by)?);
        }
        records.sort_unstable_by(memory_timeline_record_cmp);

        Ok(MemoryTimeline {
            anchor: *anchor,
            records,
        })
    }

    fn memory_timeline_record(
        &self,
        id: &EntityId,
        mut supersedes: Vec<EntityId>,
        mut superseded_by: Vec<EntityId>,
    ) -> Result<MemoryTimelineRecord> {
        supersedes.sort_unstable();
        superseded_by.sort_unstable();

        let Some(raw) = self.get_raw(id)? else {
            return Ok(MemoryTimelineRecord {
                id: *id,
                state: MemoryTimelineRecordState::Missing,
                entity_type: None,
                occurred_start: None,
                occurred_end: None,
                learned_at: None,
                body_bytes: None,
                deletion: None,
                supersedes,
                superseded_by,
            });
        };

        let header =
            EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
        let body_bytes = raw.len().saturating_sub(ENTITY_METADATA_HEADER_LEN);
        let deletion = if body_bytes == 0 {
            self.entity_deletion_metadata(id, header.learned_at)?
        } else {
            None
        };
        let lifecycle =
            if deletion.is_none() && header.entity_type == ENTITY_TYPE_CLAIM && body_bytes > 0 {
                self.get_claim(id)?.map(|claim| claim.lifecycle)
            } else {
                None
            };
        let state = if deletion.is_some() {
            MemoryTimelineRecordState::Deleted
        } else if lifecycle == Some(ClaimLifecycleStatus::Retracted) {
            MemoryTimelineRecordState::Retracted
        } else if lifecycle == Some(ClaimLifecycleStatus::Superseded) || !superseded_by.is_empty() {
            MemoryTimelineRecordState::Superseded
        } else {
            MemoryTimelineRecordState::Live
        };

        Ok(MemoryTimelineRecord {
            id: *id,
            state,
            entity_type: Some(header.entity_type),
            occurred_start: Some(header.occurred_start),
            occurred_end: Some(header.occurred_end),
            learned_at: Some(header.learned_at),
            body_bytes: Some(body_bytes),
            deletion,
            supersedes,
            superseded_by,
        })
    }

    fn entity_deletion_metadata(
        &self,
        id: &EntityId,
        learned_at: u64,
    ) -> Result<Option<HydratedShortIdDeletion>> {
        let window_label = window_label_from_timestamp(learned_at);
        let pending_key = pending_tombstone_key(&window_label, id);
        let rtxn = self.store.env.read_txn()?;
        if let Some(value) = self.store.sync_state.get(&rtxn, pending_key.as_str())? {
            return Ok(Some(Self::deletion_metadata_from_tombstone_value(
                HydratedShortIdDeletionSource::PendingTombstone,
                value,
            )));
        }
        drop(rtxn);

        #[cfg(feature = "sync")]
        {
            use crate::sync::loro_support::tombstone_values_for_id;
            use crate::sync::types::WindowKey;

            let window_key = WindowKey::from_timestamp(learned_at);
            match crate::sync::window::load_window_from_state(self, "local", &window_key) {
                Ok(doc) => Ok(
                    Self::select_tombstone_metadata_value(&tombstone_values_for_id(
                        &doc.get_map("tombstones"),
                        id,
                    ))
                    .map(|value| {
                        Self::deletion_metadata_from_tombstone_value(
                            HydratedShortIdDeletionSource::Tombstone,
                            value,
                        )
                    }),
                ),
                Err(Error::WindowNotFound { .. }) => Ok(None),
                Err(error) => Err(error),
            }
        }

        #[cfg(not(feature = "sync"))]
        {
            Ok(None)
        }
    }

    fn deletion_metadata_from_tombstone_value(
        source: HydratedShortIdDeletionSource,
        value: &[u8],
    ) -> HydratedShortIdDeletion {
        let decoded = decode_tombstone_value(value);
        HydratedShortIdDeletion {
            source,
            reason: decoded.reason.map(Self::hydrate_deletion_reason),
            deleted_at: (decoded.deleted_at != 0).then_some(decoded.deleted_at),
            request_id: decoded
                .request_id
                .map(|request_id| Uuid::from_bytes(request_id).to_string()),
            hard: decoded.is_hard(),
        }
    }

    fn hydrate_deletion_reason(
        reason: crate::deletion::TombstoneReason,
    ) -> HydratedShortIdDeletionReason {
        match reason {
            crate::deletion::TombstoneReason::UserDelete => {
                HydratedShortIdDeletionReason::UserDelete
            }
            crate::deletion::TombstoneReason::UserHardDelete => {
                HydratedShortIdDeletionReason::UserHardDelete
            }
            crate::deletion::TombstoneReason::GdprDelete => {
                HydratedShortIdDeletionReason::GdprDelete
            }
            crate::deletion::TombstoneReason::PolicyDelete => {
                HydratedShortIdDeletionReason::PolicyDelete
            }
        }
    }

    #[cfg(feature = "sync")]
    fn select_tombstone_metadata_value(values: &[Vec<u8>]) -> Option<&[u8]> {
        values
            .iter()
            .find(|value| decode_tombstone_value(value).is_hard())
            .or_else(|| values.first())
            .map(Vec::as_slice)
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
            ids.push(entity_id_from_type_index_key(key)?);
        }
        Ok(ids)
    }

    /// Returns at most `limit` entity IDs of a given type after `after`.
    ///
    /// This is the bounded counterpart to [`Self::entities_by_type`] for
    /// callers that must walk large type indexes incrementally. Results follow
    /// the same LMDB type-index key order as `entities_by_type`; `after` is an
    /// exclusive lower bound.
    pub fn entities_by_type_page(
        &self,
        entity_type: u8,
        after: Option<&EntityId>,
        limit: usize,
    ) -> Result<Vec<EntityId>> {
        if limit == 0 {
            return Ok(Vec::new());
        }

        let limit = limit.min(MAX_TYPE_QUERY_RESULTS);
        let rtxn = self.store.env.read_txn()?;
        let start_key = match after {
            Some(id) => Store::encode_type_key(entity_type, id).to_vec(),
            None => vec![entity_type],
        };
        let start_bound: std::ops::Bound<&[u8]> = match after {
            Some(_) => std::ops::Bound::Excluded(&start_key[..]),
            None => std::ops::Bound::Included(&start_key[..]),
        };
        let end_bound: std::ops::Bound<&[u8]> = std::ops::Bound::Unbounded;

        let mut ids = Vec::with_capacity(limit.min(1024));
        for entry in self
            .store
            .type_index
            .range(&rtxn, &(start_bound, end_bound))?
        {
            let (key, _) = entry?;
            if key.first() != Some(&entity_type) {
                break;
            }
            ids.push(entity_id_from_type_index_key(key)?);
            if ids.len() >= limit {
                break;
            }
        }
        Ok(ids)
    }

    /// Returns up to `limit` latest entity bodies of a given type.
    ///
    /// Scans at most `scan_limit` rows from the `temporal_learned` index in
    /// newest-first order and reads matching entity bodies from the same LMDB
    /// snapshot, returning `(id, learned_at, body)` tuples.
    pub fn latest_entity_bodies_by_type(
        &self,
        entity_type: u8,
        limit: usize,
        scan_limit: usize,
    ) -> Result<Vec<(EntityId, u64, Vec<u8>)>> {
        if limit == 0 || scan_limit == 0 {
            return Ok(Vec::new());
        }

        let rtxn = self.store.env.read_txn()?;
        let lower: std::ops::Bound<&[u8]> = std::ops::Bound::Unbounded;
        let upper: std::ops::Bound<&[u8]> = std::ops::Bound::Unbounded;
        let mut rows = Vec::with_capacity(limit.min(1024));
        for (scanned, entry) in self
            .store
            .temporal_learned
            .rev_range(&rtxn, &(lower, upper))?
            .enumerate()
        {
            if scanned >= scan_limit {
                break;
            }

            let (key, _) = entry?;
            require_key_len(key, 24, "temporal learned key")?;
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

            let Some(raw) = self.store.entities.get(&rtxn, id.as_bytes())? else {
                continue;
            };
            let header =
                EntityMetadataHeader::parse(raw).ok_or(Error::CorruptedIndex("entity header"))?;
            if header.entity_type != entity_type {
                continue;
            }
            if header.learned_at != learned_at {
                return Err(Error::CorruptedIndex("temporal learned key"));
            }
            rows.push((
                id,
                header.learned_at,
                raw[ENTITY_METADATA_HEADER_LEN..].to_vec(),
            ));
            if rows.len() >= limit {
                break;
            }
        }
        Ok(rows)
    }

    /// Counts entity IDs of a given type via the `type_index` prefix path.
    ///
    /// This is the exact count primitive for deterministic paginated list
    /// metadata. It does not materialize entity IDs or read entity bodies.
    pub fn count_entities_by_type(&self, entity_type: u8) -> Result<u64> {
        let rtxn = self.store.env.read_txn()?;
        let mut total = 0_u64;
        for entry in self.store.type_index.prefix_iter(&rtxn, &[entity_type])? {
            let (key, _) = entry?;
            entity_id_from_type_index_key(key)?;
            total = total
                .checked_add(1)
                .ok_or(Error::IndexOverflow("count_entities_by_type"))?;
        }
        Ok(total)
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

    /// Returns at most `limit` inbound edge sources after `after_source`.
    ///
    /// This is the bounded counterpart to [`Self::sources`]. Results follow
    /// the LMDB inbound edge key order `[target | kind | source]`, so
    /// `after_source` is an exclusive lower bound on the source entity id.
    pub fn sources_page(
        &self,
        tgt: &EntityId,
        kind: EdgeKind,
        source_type: Option<u8>,
        after_source: Option<&EntityId>,
        limit: usize,
    ) -> Result<Vec<EntityId>> {
        self.filtered_edge_peers_page(
            &self.store.edges_in,
            tgt,
            kind,
            source_type,
            after_source,
            limit,
        )
    }

    /// Scans an edge database (edges_out or edges_in) for entries matching `kind`,
    /// returning the peer entity IDs. Optionally filters by the peer's entity type.
    ///
    /// Capped at `MAX_EDGE_QUERY_RESULTS` scanned peer rows to prevent
    /// unbounded allocation and worst-case filtered scans.
    pub(crate) fn filtered_edge_peers(
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

    fn filtered_edge_peers_page(
        &self,
        db: &Database<Bytes, Bytes>,
        prefix_id: &EntityId,
        kind: EdgeKind,
        peer_type: Option<u8>,
        after_peer: Option<&EntityId>,
        limit: usize,
    ) -> Result<Vec<EntityId>> {
        if limit == 0 {
            return Ok(Vec::new());
        }

        let limit = limit.min(MAX_EDGE_QUERY_RESULTS);
        let rtxn = self.store.env.read_txn()?;
        let prefix = edge_kind_prefix(prefix_id, kind);
        let start_key = match after_peer {
            Some(peer) => Store::encode_edge_key(prefix_id, kind, peer).to_vec(),
            None => prefix.to_vec(),
        };
        let start_bound: std::ops::Bound<&[u8]> = match after_peer {
            Some(_) => std::ops::Bound::Excluded(&start_key[..]),
            None => std::ops::Bound::Included(&start_key[..]),
        };
        let end_bound: std::ops::Bound<&[u8]> = std::ops::Bound::Unbounded;

        let mut ids = Vec::with_capacity(limit.min(1024));
        for entry in db.range(&rtxn, &(start_bound, end_bound))? {
            let (key, value) = entry?;
            if !key.starts_with(&prefix) {
                break;
            }
            let peer = parse_edge_record(key, value)?.target;

            if let Some(req_type) = peer_type
                && !self.entity_has_type(&rtxn, &peer, req_type)?
            {
                continue;
            }

            ids.push(peer);
            if ids.len() >= limit {
                break;
            }
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

pub(crate) fn is_delete_protected_engine_record(entity_type: u8) -> bool {
    matches!(
        entity_type,
        ENTITY_TYPE_POLICY_MANIFEST | ENTITY_TYPE_AUTHORITY_LOG
    )
}

/// A session-scoped actor binding created by [`Vault::as_actor`]
/// (ONE-1113 ruling, session ergonomics): the handle carries
/// `actor_entity_ref` + the caller-supplied D13 `actor_class` and injects
/// both on every provenance-path write, so a bound caller "writes normally"
/// after binding once. The MCP daemon injects the session actor on the
/// named-writes lane (ARCH-0028) through exactly this surface.
///
/// The binding is correlation-only ergonomics — NO sessions registry, NO
/// authorization, NO stored state. Every write delegates to
/// [`Vault::put_edge_provenance`] and runs its full fail-closed gate chain.
///
/// NAMING: engine-internal until ABI-pinned (the ruling pins semantics, not
/// names); expect the public surface name to be ratified at the FFI/NAPI
/// milestone.
#[derive(Clone, Copy)]
pub struct ActorBound<'a> {
    vault: &'a Vault,
    actor: EntityId,
    actor_class: EdgeActorClass,
}

impl ActorBound<'_> {
    /// The bound actor entity reference.
    #[must_use]
    pub fn actor(&self) -> EntityId {
        self.actor
    }

    /// The bound caller-supplied D13 actor class.
    #[must_use]
    pub fn actor_class(&self) -> EdgeActorClass {
        self.actor_class
    }

    /// Builds an `edge.provenance` value record pre-filled with the BOUND
    /// actor — the "write normally" entry point: fill `confidence` +
    /// `supersession_status`, set optional fields on the returned record,
    /// then pass it to [`ActorBound::put_edge_provenance`].
    #[must_use]
    pub fn provenance_body(
        &self,
        confidence: f32,
        supersession_status: SupersessionStatus,
    ) -> EdgeProvenanceClaimBody {
        EdgeProvenanceClaimBody::new(self.actor, confidence, supersession_status)
    }

    /// Writes an `edge.provenance` Claim for `subject` carrying the BOUND
    /// actor + class — delegates to [`Vault::put_edge_provenance`] with the
    /// bound `actor_class` injected, running the full gate chain (write-once
    /// id, subject-edge existence, D13 actor validation, D14 precedence,
    /// implicit supersession, winner restamp, PPR invalidation).
    ///
    /// Fail-closed binding check: a `body.actor_entity_ref` that names a
    /// DIFFERENT entity than the bound actor is rejected typed
    /// ([`Error::InvalidProvenanceBody`]) — the handle injects the actor, it
    /// never silently rewrites a conflicting one. Construct the record via
    /// [`ActorBound::provenance_body`] to avoid the mismatch entirely.
    pub fn put_edge_provenance(
        &self,
        claim_id: &EntityId,
        subject: &EdgeRef,
        body: &EdgeProvenanceClaimBody,
        learned_at: u64,
    ) -> Result<()> {
        if body.actor_entity_ref != self.actor {
            return Err(Error::InvalidProvenanceBody(
                "body actor_entity_ref conflicts with the session-bound actor",
            ));
        }
        self.vault
            .put_edge_provenance(claim_id, subject, body, self.actor_class, learned_at)
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

fn memory_timeline_record_cmp(
    left: &MemoryTimelineRecord,
    right: &MemoryTimelineRecord,
) -> std::cmp::Ordering {
    left.occurred_start
        .unwrap_or(u64::MAX)
        .cmp(&right.occurred_start.unwrap_or(u64::MAX))
        .then_with(|| {
            left.learned_at
                .unwrap_or(u64::MAX)
                .cmp(&right.learned_at.unwrap_or(u64::MAX))
        })
        .then_with(|| {
            left.occurred_end
                .unwrap_or(u64::MAX)
                .cmp(&right.occurred_end.unwrap_or(u64::MAX))
        })
        .then_with(|| left.id.as_bytes().cmp(right.id.as_bytes()))
}

fn vault_search_score_breakdown(
    signal: RetrievalSignal,
    results: &[ScoredEntity],
) -> Vec<RetrievalScoreBreakdown> {
    results
        .iter()
        .enumerate()
        .map(|(index, result)| {
            let rank = u32::try_from(index.saturating_add(1)).unwrap_or(u32::MAX);
            RetrievalScoreBreakdown {
                result_id: *result.id.as_bytes(),
                final_rank: rank,
                final_score: result.score,
                components: vec![RetrievalScoreComponent {
                    signal,
                    rank,
                    score: result.score,
                }],
            }
        })
        .collect()
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

/// ARCH-0038 delete-interplay refs captured from an `edge.provenance` Claim
/// BEFORE its body is purged or SoftErased: the subject EdgeRef whose cached
/// flags must be refreshed post-purge (D16), and the opaque refs the queued
/// historical-carrier sweep rides on (the ONE-1091 executor's seam).
struct CapturedProvenanceDelete {
    subject: EdgeRef,
    source_revision_ref: Option<[u8; 16]>,
    body_snapshot_ref: Option<[u8; 16]>,
}

/// Builds the queued sweep row's delete-interplay extras from a pre-purge
/// provenance capture: opaque lowercase-hex identifiers only — never content
/// or predicate strings. Empty for non-provenance deletes, so their queued
/// row shape gains nothing.
fn sweep_extras(captured: Option<&CapturedProvenanceDelete>) -> HardEraseSweepExtras {
    let Some(captured) = captured else {
        return HardEraseSweepExtras::default();
    };
    HardEraseSweepExtras {
        revision_ids: captured
            .source_revision_ref
            .iter()
            .map(|reference| bytes_to_hex_lower(reference))
            .collect(),
        body_snapshot_refs: captured
            .body_snapshot_ref
            .iter()
            .map(|reference| bytes_to_hex_lower(reference))
            .collect(),
    }
}

/// One stored `edge.provenance` Claim loaded for a lifecycle operation
/// (retract / supersede / winner refresh).
struct StoredProvenanceClaim {
    id: EntityId,
    /// Envelope `occurred.start`, preserved verbatim on closing re-puts.
    occurred_start: u64,
    /// Envelope `learned_at` — the D14 precedence key. NEVER changed by a
    /// lifecycle re-put.
    learned_at: u64,
    /// The 33-byte EdgeRef the Claim addresses (from its `subj`).
    subject: EdgeRef,
    /// The wrapping type-0 Claim body.
    wrapper: ClaimBody,
    /// The decoded 10-key `edge.provenance` value record (ONE-1138).
    record: EdgeProvenanceClaimBody,
    /// The write-time validated actor class, resolved from the record's
    /// `actor_class` body key (new shape) or the wrapper's legacy `evid`
    /// map (pre-ONE-1138 claims) — see the provenance module docs.
    actor_class: EdgeActorClass,
}

impl StoredProvenanceClaim {
    /// This Claim's D14 precedence key.
    fn precedence(&self) -> ProvenancePrecedence {
        ProvenancePrecedence {
            learned_at: self.learned_at,
            confidence: self.record.confidence,
            claim_id: self.id,
        }
    }

    /// The edge flags this Claim derives (contracts.ts `derivesEdgeFlags`):
    /// `confirmation_status` ← `supersession_status` identity mirror;
    /// `actor_class` ← the persisted write-time validated class.
    fn flags(&self) -> EdgeProvenanceFlags {
        EdgeProvenanceFlags {
            confirmation_status: derive_confirmation_status(self.record.supersession_status),
            actor_class: self.actor_class,
        }
    }
}

/// Builds the re-put payload for a CLOSED provenance Claim: the wrapper's
/// `val` is replaced with the closed record, `to` mirrors the effective
/// `valid_to`, `life` becomes `lifecycle`, and the envelope keeps its
/// original `occurred.start` and `learned_at` (the D14 precedence key) while
/// `occurred.end` refreshes to the effective `valid_to` per D15. Fails typed
/// when the refreshed envelope would be inverted.
fn closed_claim_put_payload(
    claim: &StoredProvenanceClaim,
    closed_record: &EdgeProvenanceClaimBody,
    lifecycle: ClaimLifecycleStatus,
) -> Result<(TimeRange, u64, ClaimBody, Vec<u8>)> {
    let valid_to = closed_record.valid_to.ok_or(Error::InvariantViolation(
        "closed provenance record must carry valid_to",
    ))?;
    let occurred = TimeRange {
        start: claim.occurred_start,
        end: valid_to,
    };
    if occurred.start > occurred.end {
        return Err(Error::InvalidProvenanceBody(
            "closing valid_to precedes the claim's occurred start",
        ));
    }
    let mut wrapper = claim.wrapper.clone();
    wrapper.value = encode_edge_provenance_value(closed_record);
    wrapper.valid_to = Some(valid_to);
    wrapper.lifecycle = lifecycle;
    let data = encode_claim_body(&wrapper)?;
    validate_claim_body_bytes(&data, true)?;
    Ok((occurred, claim.learned_at, wrapper, data))
}

/// Parses one `edges_out` / `edges_in` row into an [`EdgeInfo`].
///
/// Compatibility wrapper over [`crate::edge::parse_strict_edge_record`] so
/// Vault and context-pack readers classify malformed edge rows identically.
pub(crate) fn parse_edge_record(key: &[u8], value: &[u8]) -> Result<EdgeInfo> {
    Ok(parse_strict_edge_record(key, value)?.into_edge_info())
}

#[cfg(test)]
mod tests;
