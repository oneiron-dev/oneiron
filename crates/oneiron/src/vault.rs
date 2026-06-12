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
    BatchOp, ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader, apply_ops, deindex_entity,
    delete_from_phonetic_postings,
};
use crate::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject, encode_claim_body,
    is_reserved_predicate, validate_claim_body_bytes,
};
use crate::deletion::{
    DeleteEntityOutcome, DeleteReason, HARD_ERASE_SWEEP_PREFIX, HardEraseSweepExtras,
    LAST_HARD_ERASE_SWEEP_SEQ_KEY, RedactionReceiptInput, RedactionScope, ReplayedTombstoneOutcome,
    TombstoneValueV2, decode_hard_erase_sweep_seq, decode_tombstone_value,
    encode_hard_erase_sweep_job, encode_hard_erase_sweep_key, encode_redaction_audit_receipt,
    local_hard_delete_key, pending_tombstone_key, window_label_from_timestamp,
};
use crate::error::{Error, Result};
use crate::limits::{
    ERR_CHILD_OF_CYCLE_CHECK, MAX_ANCESTOR_DEPTH, MAX_CHILD_OF_CYCLE_TRAVERSAL_STEPS,
};
use crate::provenance::{
    EdgeProvenanceClaimBody, EdgeRef, PREDICATE_EDGE_PROVENANCE, ProvenancePrecedence,
    SupersessionStatus, close_record_for_supersession, decode_actor_class_evidence,
    decode_edge_provenance_body, derive_confirmation_status, downgrade_edge_to_bare,
    encode_actor_class_evidence, encode_edge_provenance_value, restamp_edge_flags, retract_record,
    validate_actor_class, validate_edge_provenance_value, winner_index,
};
use crate::store::{
    DB_MANIFEST, HnswCompatibilityState, MODEL_ID_KEY, STORAGE_ABI_VERSION_KEY,
    STORAGE_SCHEMA_VERSION_KEY, Store, TEXT_ANALYZER_MANIFEST_HASH_KEY, TEXT_ANALYZER_MANIFEST_KEY,
    TEXT_BM25_FIELD_SCHEMA_HASH_KEY, TEXT_INDEX_SCHEMA_VERSION, TEXT_INDEX_SCHEMA_VERSION_KEY,
    lmdb_database_open_guard,
};
use crate::types::{
    EDGE_KEY_LEN, ENTITY_ID_LEN, ENTITY_TYPE_CLAIM, ENTITY_TYPE_REDACTION_AUDIT, EdgeActorClass,
    EdgeConfirmationStatus, EdgeInfo, EdgeKind, EdgeProvenanceFlags, EdgeValueLayout, EntityId,
    ScoredEntity, TimeRange, Vad, VaultConfig, bytes_to_hex_lower, decode_edge_value_for_kind,
    edge_value_layout_for_kind,
};
use crate::{
    BatchBuilder, ContextPackBuilder, MaintenanceBuilder, PipelineBuilder, TxnBatchBuilder, bm25,
    hnsw, le_bytes_to_f32_vec, ppr, unix_seconds_now,
};

const MIN_MAP_SIZE_BYTES: usize = 1 << 20;

/// Contract stored-weight prior for `claim_of` edges (contracts.ts
/// `edgeKinds.pprWeight` = 1.0), unwrapped at COMPILE time: the writers below
/// hardwire kinds whose prior is pinned non-null, so a contract change to
/// `null` fails the build instead of the write.
const CLAIM_OF_DEFAULT_WEIGHT: f32 = match EdgeKind::ClaimOf.default_weight() {
    Some(weight) => weight,
    None => panic!("contract pins a non-null pprWeight for claim_of"),
};

/// Contract stored-weight prior for `supersedes` edges (contracts.ts
/// `edgeKinds.pprWeight` = 0.3); compile-time unwrapped like
/// [`CLAIM_OF_DEFAULT_WEIGHT`].
const SUPERSEDES_DEFAULT_WEIGHT: f32 = match EdgeKind::Supersedes.default_weight() {
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
    /// Live-window delete-routing seam (M4-10 / ONE-1135): a `Weak` to the
    /// production [`crate::sync::manager::WindowManager`], set by
    /// [`crate::sync::manager::WindowManager::attach_to_vault`]. When a
    /// deleted entity's window is OPEN, `write_crdt_tombstone` commits
    /// through the registry-owned live doc instead of a transient snapshot
    /// copy. `Weak` so the vault never keeps a dropped manager (and its
    /// observer subscriptions) alive.
    #[cfg(feature = "sync")]
    pub(crate) live_window_manager: std::sync::Mutex<std::sync::Weak<crate::sync::WindowManager>>,
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
            #[cfg(feature = "sync")]
            live_window_manager: std::sync::Mutex::new(std::sync::Weak::new()),
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
    fn live_window(
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
        apply_ops(&self.store, &self.config, &self.analyzer, &mut wtxn, ops)?;
        wtxn.commit()?;
        Ok(())
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
        let Some(raw) = self.store.entities.get(&rtxn, id.as_bytes())? else {
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
    ///    class is persisted on the wrapping Claim's `evid` field so a later
    ///    winner refresh can restamp a HISTORICAL Claim's flags (see the
    ///    provenance module docs);
    /// 4. supersession (retractionRules SUPERSEDE + D14) — an incoming
    ///    `learned_at` OLDER than the live frontier for this EdgeRef is
    ///    rejected typed ([`Error::ProvenancePrecedenceViolation`]); every
    ///    live Claim STRICTLY older than the incoming one is closed in the
    ///    same transaction (`life` = superseded, `valid_to` set to the
    ///    incoming `learned_at` when absent, envelope `occurred.end`
    ///    refreshed per D15 — closed, not deleted, still readable);
    ///    equal-`learned_at` Claims COEXIST live;
    /// 5. the Claim entity (type 0, predicate
    ///    [`crate::provenance::PREDICATE_EDGE_PROVENANCE`], `subj` = the
    ///    33-byte EdgeRef, `val` = the pinned 7-field record) is written
    ///    through the `pub(crate)` reserved-namespace door with full ONE-1104
    ///    structural validation;
    /// 6. a `claim_of` edge (u8 = 5, structural 12 B) is written from the
    ///    Claim to the subject edge's SOURCE entity (D12);
    /// 7. the subject edge value is re-stamped to 26 bytes from the WINNER
    ///    among post-write live Claims under the documented total D14 order
    ///    (greatest `learned_at`, then `confidence`, then claim-id bytes) —
    ///    NOT necessarily this Claim — with IDENTICAL bytes in `edges_out`
    ///    and `edges_in` and the first 24 bytes preserved verbatim;
    /// 8. PPR caches for the subject edge's endpoints are invalidated.
    ///
    /// The Claim envelope's `occurred` interval derives from the validity
    /// window per D15: absent `valid_from` → `learned_at`; absent `valid_to`
    /// → `u64::MAX`. A derived interval with `start > end` is rejected with
    /// [`Error::InvalidProvenanceBody`] — never reordered. The wrapping
    /// Claim stores `conf` = `body.confidence` and `from`/`to` =
    /// `valid_from`/`valid_to` (claim-layer mirrors of the authoritative
    /// 7-field record) with `appr` = `auto`, `life` = `active`.
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
        let (occurred, learned_at, data) =
            closed_claim_put_payload(&claim, &retracted, ClaimLifecycleStatus::Retracted)?;

        // The subject edge must still exist — the retraction KEEPS it and
        // only refreshes the two flag bytes.
        let subject = claim.subject;
        let edge_key = Store::encode_edge_key(&subject.source, subject.kind, &subject.target);
        if self.store.edges_out.get(&wtxn, &edge_key)?.is_none() {
            return Err(Error::EdgeNotFound);
        }

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

        // Pure validation before any transaction is opened. Encoding does
        // not validate; the decode validator is the single gate.
        let value = encode_edge_provenance_value(body);
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
        // Persist the write-time validated actor_class so winner refreshes
        // can restamp this Claim's flags later (provenance module docs).
        claim_body.evidence = Some(encode_actor_class_evidence(actor_class));
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

        // New Claim through the reserved-namespace door + claim_of → the
        // subject edge's SOURCE entity (D12) + closure re-puts, all with
        // full type-0 validation at apply, all in this one transaction.
        let mut builder = self
            .batch_in()
            .put_reserved_claim(claim_id, occurred, learned_at, &data)
            .edge(
                claim_id,
                EdgeKind::ClaimOf,
                &subject.source,
                CLAIM_OF_DEFAULT_WEIGHT,
            );
        for closure in &closures {
            let closed_record = close_record_for_supersession(&closure.record, close_at)?;
            let (closed_occurred, closed_learned_at, closed_data) = closed_claim_put_payload(
                closure,
                &closed_record,
                ClaimLifecycleStatus::Superseded,
            )?;
            builder = builder.put_reserved_claim(
                &closure.id,
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
    ///   that lifecycle; see [`Vault::claim_for_lifecycle_in`]);
    /// * either claim's `life` ≠ `active` → [`Error::ClaimAlreadyClosed`]
    ///   (closed claims neither supersede nor get superseded again).
    ///
    /// Deciding WHICH claims conflict (conflictSet), consent routing, and
    /// predicate semantics stay above the engine (ARCH-0003 §G.1, D20) —
    /// this method is transition mechanics only.
    pub fn supersede_claim(&self, new_id: &EntityId, old_id: &EntityId, now: u64) -> Result<()> {
        if new_id == old_id {
            return Err(Error::ClaimSelfSupersession);
        }

        let mut wtxn = self.store.env.write_txn()?;
        let (new_body, _new_header) = self.claim_for_lifecycle_in(&wtxn, new_id)?;
        Self::require_active_claim(&new_body)?;
        let (mut old_body, old_header) = self.claim_for_lifecycle_in(&wtxn, old_id)?;
        Self::require_active_claim(&old_body)?;

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
        apply_ops(&self.store, &self.config, &self.analyzer, &mut wtxn, ops)?;
        wtxn.commit()?;
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
        apply_ops(&self.store, &self.config, &self.analyzer, &mut wtxn, ops)?;
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
        let actor_class = decode_actor_class_evidence(wrapper.evidence.as_ref())?;
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
            let actor_class = decode_actor_class_evidence(wrapper.evidence.as_ref())?;
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
        // ONE-1132: ONE deletion request UUID correlates the CRDT tombstone's
        // `request_id` with the REDACTION_AUDIT receipt's `request_id`.
        let request_uuid = Uuid::now_v7();
        let Some(header) = self.read_entity_header(id)? else {
            return self.delete_entity_without_header(id, reason, requested_at, request_uuid);
        };

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
        // ONE-1122 `dt:` local hard-delete marker: the permanent local truth
        // the Observer-B materialization gate consults when a crafted update
        // REMOVES the CRDT tombstone (nothing else id-keyed survives a hard
        // delete locally — the receipt id is fresh, h: is seq-keyed, pt: is
        // cleared after replay). Written in the SAME txn as the active-store
        // purge, including the purge-raced-to-missing branch below: the CRDT
        // tombstone above is already published, so the id IS hard-deleted.
        // PRESENCE-ONLY for gates; the 25 B value body (the tombstone wire
        // bytes) is informational. Un-cfg'd on every build: `sync_state` is
        // unconditional and the marker is local delete truth, not sync-only
        // state (ONE-1132 cfg-off durability).
        self.store
            .sync_state
            .put(&mut wtxn, &local_hard_delete_key(id), &tombstone.encode())?;
        let existed = self.purge_entity_active_store_in_txn(&mut wtxn, id)?;
        if !existed {
            wtxn.commit()?;
            return Ok(DeleteEntityOutcome::missing());
        }

        // ARCH-0038 DELETE: "The derived edge flag follows the Claim" — the
        // subject edge is refreshed in the SAME transaction as the purge.
        if let Some(captured) = &captured {
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
        request_uuid: Uuid,
    ) -> Result<DeleteEntityOutcome> {
        // Probe first so a fully-missing id stays a strict no-op — deleting
        // a nonexistent entity must not mint tombstones or receipts.
        {
            let rtxn = self.store.env.read_txn()?;
            if !self.active_delete_scope_exists_in_txn(&rtxn, id)? {
                return Ok(DeleteEntityOutcome::missing());
            }
        }

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
            self.store.sync_state.put(
                &mut wtxn,
                &local_hard_delete_key(id),
                &tombstone.encode(),
            )?;
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
    pub(crate) fn apply_replayed_tombstone(
        &self,
        id: &EntityId,
        raw_value: &[u8],
    ) -> Result<ReplayedTombstoneOutcome> {
        let decoded = decode_tombstone_value(raw_value);
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

    fn read_entity_header(&self, id: &EntityId) -> Result<Option<EntityMetadataHeader>> {
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
        Ok(edges_in.next().transpose()?.is_some())
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
            Ok(())
        })
    }

    #[cfg(not(feature = "sync"))]
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

        let hard_purge_complete_at = input.hard_purge_complete_at;
        let body = encode_redaction_audit_receipt(input)?;
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
        self.search_text_with_profile(query, limit, &crate::types::Bm25RankProfile::default())
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
        profile: &crate::types::Bm25RankProfile,
    ) -> Result<Vec<ScoredEntity>> {
        let config = profile.to_bm25_config()?;
        self.ensure_text_index_trusted()?;
        let rtxn = self.store.env.read_txn()?;
        bm25::search_text(&self.store, &rtxn, &self.analyzer, &config, query, limit)
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
    /// The decoded 7-field `edge.provenance` value record.
    record: EdgeProvenanceClaimBody,
    /// The write-time validated actor class, persisted on the wrapper's
    /// `evid` field (see the provenance module docs).
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
) -> Result<(TimeRange, u64, Vec<u8>)> {
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
    Ok((occurred, claim.learned_at, data))
}

/// Parses one `edges_out` / `edges_in` row into an [`EdgeInfo`], failing
/// closed: a key that is not `EDGE_KEY_LEN` bytes, an unknown edge-kind
/// byte, a reserved/invalid peer id, or a value that does not decode as a
/// valid layout for the kind (12/24/26 B per ARCH-0034) is
/// `Error::CorruptedIndex("edge record")`. Shared with the context-pack
/// read path so every reader classifies the same bytes identically
/// (ONE-1101 / pinned decision D9).
pub(crate) fn parse_edge_record(key: &[u8], value: &[u8]) -> Result<EdgeInfo> {
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
                .put(&a, 1, range(1, 1), 1, b"a")
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
                .put(&a, 1, range(1, 1), 1, b"a")
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
                    .put(&a, 1, range(1, 1), 1, b"a")
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

    /// AC2 (ONE-1119): the rank profile stays OUT of the on-disk
    /// manifest handshake. Querying through both public profile paths
    /// with a thoroughly non-default profile must leave every
    /// `vault_meta` handshake row byte-identical, and a plain reopen
    /// must still pass the handshake — a profile change never requires
    /// a reindex (ARCH-0031).
    #[test]
    fn rank_profile_change_does_not_require_reindex() -> Result<()> {
        use crate::analyzer::AnalyzerChannel;
        use crate::types::Bm25RankProfile;

        const HANDSHAKE_KEYS: [&[u8]; 4] = [
            TEXT_INDEX_SCHEMA_VERSION_KEY,
            TEXT_ANALYZER_MANIFEST_KEY,
            TEXT_ANALYZER_MANIFEST_HASH_KEY,
            TEXT_BM25_FIELD_SCHEMA_HASH_KEY,
        ];

        fn handshake_rows(vault: &Vault) -> Result<Vec<Option<Vec<u8>>>> {
            let rtxn = vault.store.env.read_txn()?;
            let mut rows = Vec::with_capacity(HANDSHAKE_KEYS.len());
            for key in HANDSHAKE_KEYS {
                rows.push(vault.store.vault_meta.get(&rtxn, key)?.map(<[u8]>::to_vec));
            }
            Ok(rows)
        }

        let tmp = tempfile::tempdir()?;
        let a = entity(81);

        let vault = Vault::open(tmp.path(), test_config())?;
        vault
            .batch()
            .put(&a, 1, range(1, 1), 1, b"a")
            .text(&a, &[("body", "hello world")])
            .commit()?;

        let before = handshake_rows(&vault)?;
        assert!(
            before.iter().all(Option::is_some),
            "handshake rows must exist after first index write",
        );

        let profile = Bm25RankProfile::default()
            .with_formula(bm25::Bm25Formula::Plus { delta: 1.0 })
            .with_channel_weight(AnalyzerChannel::Stem, 0.0)
            .with_channel_b(AnalyzerChannel::Surface, 0.2);

        let hits = vault.search_text_with_profile("hello", 10, &profile)?;
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].id, a);

        let hits = vault
            .query()
            .search_text("hello", 10)
            .rank_profile(profile)
            .run()?;
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].id, a);

        let after = handshake_rows(&vault)?;
        assert_eq!(
            before, after,
            "rank profile must never touch the vault_meta handshake rows",
        );
        drop(vault);

        // Plain reopen passes the handshake — no clear_text_index, no
        // reindex, and the default profile still finds the doc.
        let vault = Vault::open(tmp.path(), test_config())?;
        assert_eq!(vault.search_text("hello", 10)?.len(), 1);
        Ok(())
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
                .put(&a, 1, range(1, 1), 1, b"a")
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
                .put(&a, 1, range(1, 1), 1, b"a")
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
                .put(&a, 1, range(1, 1), 1, b"a")
                .text(&a, &[("body", "hello world")])
                .commit()?;
        }

        let mut cfg = test_config();
        cfg.skip_text_index_manifest_check = true;
        let vault = Vault::open(tmp.path(), cfg)?;
        let err = vault
            .batch()
            .put(&b, 1, range(1, 1), 1, b"b")
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
            .put(&a, 1, range(1, 1), 1, b"a")
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
            .put(&b, 1, range(1, 1), 1, b"b")
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
                .put(&a, 1, range(1, 1), 1, b"a")
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
            .put(&a, 1, range(1, 1), 1, b"a")
            .put(&b, 1, range(1, 1), 1, b"b")
            .text(&a, &[("body", "first")])
            .text(&b, &[("body", "second")])
            .commit()?;

        assert_eq!(vault.text_index_status()?.total_docs, 2);
        Ok(())
    }
}
