//! LMDB store: one environment per vault plus the 28 named databases pinned
//! by the ARCH-0019 manifest, and the fail-closed open-time gates.
//!
//! # Canonical open-gate sequence (`Store::open` → `Vault::open`)
//!
//! Gates run in this exact order. The FIRST failing gate aborts the open with
//! its typed error and **no usable `Store`/`Vault` handle is returned**. Every
//! error path also releases the process-local path registration, so a retry
//! observes the same gate failure again rather than a phantom
//! "vault path is already open" error.
//!
//! `Store::open` — steps 1–4 run inside a single write transaction while
//! holding `lmdb_database_open_guard` (`mdb_dbi_open` is transaction-scoped:
//! the txn that opens a DBI must finish before another txn opens one):
//!
//! 0. **`preflight_vault_root`** — before the unsafe LMDB open, the root must
//!    contain either no LMDB files (new vault) or exactly one regular,
//!    non-symlink, single-link `data.mdb` plus one matching `lock.mdb`
//!    (existing vault). Partial, aliased, hard-linked, or already-live roots
//!    fail with [`VaultRootPreflight`].
//! 1. **`vault_meta` (manifest DB #5) is created/opened FIRST.** Rationale:
//!    the storage-version gate (step 2) reads its versions FROM `vault_meta`,
//!    so an existing vault with a missing/blank `vault_meta` is caught by the
//!    ABI gate as [`StorageAbiVersionChanged`]`{ stored: None, .. }` — not by
//!    the manifest gate. Creating it first cannot mask a genuinely missing
//!    database: the manifest-set gate (step 3) runs BEFORE the other 27
//!    manifest DBs are (re)created in this transaction, so any of those
//!    missing is still detected.
//! 2. **`gate_storage_versions`** — storage ABI gate, then schema gate.
//!    * `vault_meta["storage_abi_version"]` (u16 LE) ≠
//!      [`STORAGE_ABI_VERSION`], or absent on an existing vault →
//!      [`StorageAbiVersionChanged`].
//!    * `vault_meta["schema_version"]` (u16 LE) ≠ [`STORAGE_SCHEMA_VERSION`],
//!      or absent on an existing vault → [`StorageSchemaVersionChanged`].
//!    * New vaults stamp both current versions instead of gating.
//! 3. **`validate_db_manifest_set`** (existing vaults) — the named-database
//!    set in the environment must equal the 28-entry [`DB_MANIFEST`] exactly;
//!    any missing or unexpected name → [`DbManifestMismatch`]. New vaults run
//!    this validation after step 4 instead (nothing pre-exists to validate).
//! 4. The remaining 27 manifest DBs are created/opened, the transaction
//!    commits, and the DBI-open guard is released.
//! 5. **`preflight_hnsw_config`** — `hnsw_meta["hnsw_config"]` (27-byte v2
//!    record: dimensions, m_max_0, ef_construction, distance_metric,
//!    index_structure; `ef_search` is a search-time knob and deliberately
//!    excluded). A mismatch, or a legacy-shape record on a vault with
//!    persisted vector/HNSW data → [`HnswConfigChanged`]; a missing record on
//!    a populated vault → [`InvalidConfig`].
//! 6. **`preflight_embedding_model`** — `hnsw_meta["model_id"]` (UTF-8).
//!    Stored ≠ requested → [`EmbeddingModelChanged`]; a populated vault whose
//!    stored id is missing, or a populated vault opened without a requested
//!    model → [`InvalidConfig`]. Then **`preflight_embedding_transform`** —
//!    `hnsw_meta["embedding_transform"]` (UTF-8), only when a transform is
//!    requested: stored ≠ requested → `EmbeddingTransformChanged`; none
//!    stored → the requested one is written.
//! 7. `migrate_temporal_long_intervals_if_needed`
//!    (`hnsw_meta["temporal_long_intervals_schema_version"]`), then the
//!    persist-if-missing writes for the HNSW config / model id validated above
//!    (each re-checks under its own write transaction).
//!
//! `Vault::open` — after `Store::open` returns:
//!
//! 8. **Analyzer / BM25F handshake** (`handshake_text_index_manifest`) — keys
//!    `vault_meta["text_index_schema_version"]`,
//!    `vault_meta["text_analyzer_manifest"]` /
//!    `vault_meta["text_analyzer_manifest_hash"]`, and
//!    `vault_meta["text_bm25_field_schema_hash"]`. On a populated text index:
//!    a per-language analyzer mode flip (or a pre-ONE-317 / corrupt manifest)
//!    → [`IncompatibleAnalyzer`]; a diverged BM25F field schema →
//!    [`Bm25FieldSchemaChanged`]. The
//!    [`VaultConfig::skip_text_index_manifest_check`] escape hatch sits HERE
//!    and only here: it bypasses this analyzer gate so
//!    `MaintenanceBuilder::clear_text_index` can run; on a populated index it
//!    marks the text index untrusted so text reads/writes fail closed with
//!    `Error::CorruptedIndex` until the clear commits.
//! 9. The independent skill content-hash index sentinel migration
//!    (`vault_meta["skill_hub/content_hash_index_schema_version"]`) runs after
//!    the Vault claim doors are assembled, so pre-global scan verdicts can be
//!    reconciled transactionally. It still finishes before `Vault::open`
//!    returns a handle.
//!
//! # Compat-key homes (ONE-1097 owner decision: documented, not consolidated)
//!
//! `vault_meta` (#5) owns the storage/schema and text-index identity keys,
//! plus the per-type short-id counters (`b"sid_counter:" ‖ type_byte` → u64
//! LE, see `SHORT_ID_COUNTER_KEY_PREFIX`); `hnsw_meta` (#8) owns the
//! vector-side compatibility keys (`model_id`, `hnsw_config`) alongside HNSW
//! runtime metadata (`entry_point`, `count`, graph/vector version counters).
//! Consolidating the vector compat keys into `vault_meta` would be a storage
//! migration with no behavioral win, so the split is intentional and
//! documented here instead.
//!
//! [`StorageAbiVersionChanged`]: crate::error::StoreError::StorageAbiVersionChanged
//! [`StorageSchemaVersionChanged`]: crate::error::StoreError::StorageSchemaVersionChanged
//! [`DbManifestMismatch`]: crate::error::StoreError::DbManifestMismatch
//! [`VaultRootPreflight`]: crate::error::StoreError::VaultRootPreflight
//! [`HnswConfigChanged`]: crate::error::StoreError::HnswConfigChanged
//! [`EmbeddingModelChanged`]: crate::error::StoreError::EmbeddingModelChanged
//! [`InvalidConfig`]: crate::error::Error::InvalidConfig
//! [`IncompatibleAnalyzer`]: crate::error::StoreError::IncompatibleAnalyzer
//! [`Bm25FieldSchemaChanged`]: crate::error::StoreError::Bm25FieldSchemaChanged
//! [`VaultConfig::skip_text_index_manifest_check`]: crate::config::VaultConfig::skip_text_index_manifest_check

/// Backend-neutral storage contracts and injectable time sources.
/// Implementations compose in a caller-owned transaction; they never commit it.
mod extraction_work;
pub use extraction_work::ExtractionWork;

pub mod ports {
    pub use crate::ports::{
        BlobStore, ChangeLogRecord, ChangeLogStore, ChangeOp, ClaimStore, Clock, DependencyIndex,
        EdgeDirection, EdgeStore, EntityRecord, EntityStore, IdGen, JobQueue, JobScope,
        ManualClock, PlaceStore, RetrievalIndex, ShortIdStore, SourceSpan, StoreClock,
        TombstoneStore, Transactions, safe_read_asset_text, safe_read_text,
    };
    pub use crate::ports::{
        ChangeLogStoreRead, DeletionFamily, DeletionMarker, DeletionState, EdgeStoreRead,
        EntityStoreRead, EntityTime, EntityWriteSegmentRead, JobQueueRead, PortRows,
        RetrievalIndexRead, ShortIdStoreRead, TimeAxis, TimelineQuery, TombstoneStoreRead,
    };
}

pub(crate) mod agent_birth_custody;
pub(crate) mod agent_birth_identity;
pub mod agent_record;
pub mod attempt_cleanup;
pub mod attempt_inputs;
pub mod attempt_lease;
pub mod attempt_manifest;
pub mod attempt_result;
pub mod canonical_document;
pub mod checkout_task;
pub use oneiron_store::checkpoint_host_recipient;
pub mod code_tree_blob;
pub mod conversation_body;
pub use oneiron_store::conversation_record;
pub mod custody_retirement_status;
#[cfg(feature = "sync")]
pub mod document_frame_tags;
pub mod housekeeping_report;
pub mod housekeeping_schedule;
#[cfg(feature = "sync")]
pub(crate) mod loro_document;
#[cfg(feature = "sync")]
pub(crate) mod loro_tombstones;
#[cfg(feature = "sync")]
pub mod materialization_event;
pub mod model_description_rows;
pub mod model_score_diff;
pub(crate) mod model_stream_row;
pub mod outbound_outcome;
pub mod outbound_trigger;
pub mod pack_hook_actor_class;
#[cfg(feature = "sync")]
pub(crate) mod pad_object_membership;
pub(crate) mod project_kind;
pub mod proposal_spool;
pub mod recovery_write_budget;
pub(crate) mod repo_environment;
pub mod repo_fork;
pub mod restore_admission;
pub mod result_body_pins;
pub mod result_memory;
pub use oneiron_store::retained_memory;
pub mod sandbox_import;
pub mod verb_invocation;
#[cfg(feature = "sync")]
pub mod window_protocol;
#[cfg(feature = "sync")]
pub(crate) mod window_rows;

pub mod consolidation_scope;
pub(crate) mod conversation_span;
pub mod dreamer_attempt_kind;
pub mod setting_seed;
pub mod snapshot_key;
pub mod snapshot_lock_result;

mod active_write_txn;
pub(crate) use active_write_txn::{active_write_txn_depth, active_write_txn_guard};
mod archive_scratch;
#[cfg(unix)]
mod asset_body;
mod backup_change;
pub mod blob_fingerprint;
#[cfg(unix)]
mod body_envelope;
#[cfg(unix)]
mod body_store;
mod channel_identity_receipts;
pub(crate) mod checkpoint_payload;
pub mod claim_descriptors;
mod claim_vad_owed;
pub mod code_artifact_body;
pub mod code_document_values;
pub mod code_memory_values;
pub mod code_snapshot;
pub(crate) mod query_memo_codec;
pub mod query_memos;
pub(crate) use claim_vad_owed::{
    claim_vad_owed_in_txn, owe_claim_vad_in_txn, owed_claim_vad_count_in_txn,
    settle_claim_vad_in_txn,
};
pub mod body_descriptor;
mod commitment_due;
mod credential_custody;
mod deadline_jobs;
pub mod decision_ask_role;
pub(crate) mod decision_question_watches;
pub mod derivation;
pub mod diagnostic_record;
mod diagnostics;
pub mod document_segments;
pub mod embedding;
mod gate_decision;
pub(crate) mod file_key_masks;
pub(crate) mod found_key_notice_queue;
pub(crate) mod graph_version;
pub(crate) mod known_value_index;
pub(crate) mod l2_evidence;
pub mod receipt_identity;
pub(crate) mod result_body_erasure;
pub(crate) mod result_body_rows;
pub mod retrieval_deadline;
pub mod retrieval_signal;
pub mod row_birth;
pub(crate) mod pending_custody_revoke;
pub(crate) mod secret_handle_labels;
pub(crate) mod secret_name_index;
mod scan_checks;
mod scan_kind;
mod scan_kind_table;
pub(crate) mod text_index;
pub(crate) mod vector_index;
pub mod workflow_definition;

pub use scan_checks::ScanCheck;
pub(crate) use scan_checks::{CheckKey, PendingScanChecks};
pub use scan_kind::{DEFAULT_SCAN_CHECK_THRESHOLD, EngineScan};
mod group_commit;
mod handle;
pub(crate) mod replay_only_commits;
pub mod world_registration_keys;
pub(crate) mod world_pad_rows;
// FIX 7907, 7958: a federation grant's scope opening keys.
pub(crate) mod grant_scope_custody;
mod host_issuer_custody;
// FIX 8875: the home handoff's custody contract, for L03's carrier.
pub(crate) mod home_handoff_custody;
mod idempotency_intent;
pub mod identity_hints;
mod inference_snapshot_custody;
pub(crate) mod install_identity;
mod invocation_claims;
mod key_custody;
mod key_encoding;
mod known_history;
pub(crate) mod legal_hold;
pub(crate) mod linear_pull_cursor;
mod local_queue_budget;
pub(crate) use local_queue_budget::check_queue_capacity;
#[cfg(feature = "sync")]
pub(crate) mod local_replica;
#[cfg(feature = "sync")]
pub(crate) mod replica_edge_key;
mod notification_updates;
mod open_gates;
mod outbound_send_receipt;
mod page_bound;
mod pending_embedding;
mod pending_gate_consent;
mod ppr_community;
mod ppr_community_indexed;
pub(crate) mod reader_fold_receipt;
pub(crate) mod refinement_carrier;
pub mod result_manifest;
pub mod retrieval_policy;
mod retrieval_telemetry;
pub mod retrieval_values;
#[cfg(unix)]
mod root_directory;
mod send_receipt_audit;
mod served_vaults;
mod short_id_alias;
pub(crate) mod skill_content_index;
pub mod skill_hub_predicates;
pub mod skill_package;
pub(crate) mod skill_refinement_custody;
pub(crate) mod skill_source_carrier;
pub(crate) mod skill_source_custody;
mod structural_kind_registry;
mod sync_responses;
pub(crate) mod task_body_checks;
mod training_link;
pub(crate) mod turn_missing;
mod usage_sources;
mod world_pad_custody;
mod writer_lease;

#[cfg(test)]
pub(crate) mod test_hooks;
#[cfg(test)]
mod tests;

pub(crate) use archive_scratch::ScratchEnv;
#[cfg(unix)]
pub(crate) use asset_body::{
    ASSET_FILE_PLANE, ASSET_INLINE_BODY_BYTES, AssetBodyFacts, AssetFileKind, AssetFileManifest,
    CheckedAssetBody, asset_body_file_of_row, asset_file_in_txn, asset_file_of_raw_in_txn,
    file_put_body_in_txn, short_content_hash_in_txn, stage_asset_body_in_txn,
};
#[cfg(unix)]
#[allow(
    unused_imports,
    reason = "FIX 5489 PR2 and PR3 receive bodies through these"
)]
pub(crate) use asset_body::{AssetBodySpool, StagedAssetBody, StagedHold};
pub(crate) use served_vaults::served_vault_at;
// FIX 6730: what a commit changes for the backup watermark.
#[cfg(feature = "sync")]
pub(crate) use backup_change::telemetry_batch_class;
pub(crate) use backup_change::{BackupWriteClass, backup_content_txn_in_txn};
#[cfg(unix)]
pub(crate) use body_envelope::{
    BODY_FILE_SHRED_SCOPE, BODY_FILE_WRAP_CONTEXT, BODY_INSTANCES, BODY_KEYS, BodyFile, BodyKeyRow,
    BodyMint, BodySeal, BodySealSlot, BodySpill, DirSeal, FileKey, INLINE_ASSETS, KeyScope,
    SealedStream, SealingStream, SpilledBody, StagedBodyKey, bind_body_key_in_txn,
    body_instances_in_rows, body_key_in, body_key_row_in_txn, body_mint_in, custody_unavailable,
    erase_bodies_in_txn, instance_id, keep_promoted_body_key_in_txn, pin_body_custody_in_txn,
    prune_retired_bodies_in_rows, release_body_in_txn, remember_body_instances_in_txn,
    remembered_body_instances_in_txn, require_body_instances, retire_body_key_in_txn,
    sealed_body_file_name,
};
// FIX 6225: a step response's ASSET under its claim's erase, and the debt
// a shared one's final teardown settles.
#[cfg(unix)]
pub(crate) use body_envelope::{
    erase_bodies_for_owner_in_txn, note_settled_inline_in_txn, settle_inline_asset_in_txn,
};
// KS-2B1: row-held responses under body custody.
#[cfg(unix)]
pub(crate) use body_envelope::{
    RESPONSE_BINDINGS, ResponseBinding, ResponseCarriage, ResponseDb, ResponseFamily,
    ResponseOwners, ResponseRead, ResponseScan, bind_response_in_txn, carrier_row,
    erase_response_owner_in_txn, is_opaque_erased, opaque_retired_at, release_response_in_txn,
    response_binding_in_txn, response_carrier, response_owed_to_all_in_txn,
    settle_shared_response_in_txn, stamp_opaque_erased,
};
#[cfg(unix)]
pub(crate) use body_store::{
    BodyDir, BodyFacts, BodyMeter, BodySink, LINE_INDEX_BLOCK_BYTES, LINE_INDEX_SUFFIX, SunkBody,
    body_file_name, read_body_range,
};
pub use channel_identity_receipts::*;
#[cfg(test)]
pub(crate) use commitment_due::*;
// KS-6: credential values and carriers in typed custody.
pub(crate) use credential_custody::{
    CredentialFences, CredentialLeaf, FenceLookup, PlannedCredential, credential_erases_staged,
    credential_kind, credential_value_leaf_in, plan_credential_value,
};
pub(crate) use deadline_jobs::DeadlineJobs;
pub use deadline_jobs::{DEADLINE_JOBS_CHECK_KIND, DeadlineJob};
pub use diagnostics::Diagnostics;
pub use gate_decision::*;
pub use group_commit::GroupCommitStats;
pub(crate) use group_commit::{
    AfterCommit, Callback, DetachedWrite, GroupCommit, GroupCommitCounters, Rows,
    release_vault_handle,
};
pub use handle::*;
pub(crate) use inference_snapshot_custody::INFERENCE_SNAPSHOT_WRAPPED_KEY_BYTES;
pub(crate) use key_custody::ForkedCustodyDir;
pub use key_custody::custody_container_path;
pub use key_custody::protocol as custody_protocol;
pub use key_custody::sync_dir;
pub(crate) use key_custody::{
    CUSTODY_COMPLETION_NEEDS_ANCHOR, CUSTODY_HEAD_WRAP_CONTEXT, CustodyBinding, CustodyKind,
    CustodyPlan, CustodyRecipients, CustodyRequirement, CustodyRoute, CustodySourceAt,
    CustodySubject, FileAnchor, FolderTarget, MemberProgress, OutboxTarget, PreparedTakeover,
    Publication, PublicationState, ROLLBACK_NOT_PROVEN, RecipientRetirement, RetirementProgress,
    TakeoverRefusal, TargetRecipients, refuse_foreign_binding, retirement_in_txn, route_custody,
    standing_retirements_in_txn, unbind_in_txn as unbind_custody_in_txn,
};
// FIX 6706 (L04 half): world pad compartments, for L03's pad hydration.
#[allow(
    unused_imports,
    reason = "L03 02A's pad hydration (FIX 6706) calls these"
)]
pub(crate) use key_custody::{
    OpenedWorldPads, PadRecipients, SealedWorldPads, WorldPadScope, open_world_pad_compartment,
    seal_world_pad_compartment,
};
pub(crate) use key_encoding::*;
// KS-3: the known-value index's master and history in typed custody.
pub(crate) use known_history::{
    KNOWN_TAG_BYTES, KnownEntry, KnownHistory, KnownHistoryIds, known_history_prefixes,
    read_back_known_history, require_known_history,
};
pub use open_gates::*;
pub(crate) use outbound_send_receipt::*;
pub(crate) use page_bound::{PageLayout, TreeRows};
pub(in crate::store) use pending_embedding::*;
pub use pending_gate_consent::*;
pub use retrieval_telemetry::*;
#[cfg(all(unix, test))]
pub(crate) use root_directory::arm_after_root_entry_removed;
#[cfg(unix)]
pub use root_directory::{
    SharedPath, refuse_shared_path, refuse_shared_vault_root, remove_held_directory, shared_path,
    shared_vault_root,
};
pub use short_id_alias::*;
use structural_kind_registry::*;
#[cfg(test)]
pub(crate) use structural_kind_registry::{
    STRUCTURAL_KIND_REGISTRY_KEY_PREFIX, STRUCTURAL_KIND_REGISTRY_RECORD_VERSION,
    structural_kind_registry_key,
};
// FIX 10379: the intent a keyed request's route writes under, counted by
// each write it commits.
#[doc(hidden)]
pub use idempotency_intent::{
    IdempotencyIntent, carry_idempotency_intent, with_idempotency_intent,
};
#[doc(hidden)]
pub use invocation_claims::{
    InvocationClaimEntry, InvocationClaimRelease, StoredPeerMachine,
    invocation_claim_opaque_retired_at, invocation_claim_response_read,
};
pub(crate) use invocation_claims::{
    erase_invocation_claim_owner_in_txn, invocation_claim_owners, invocation_claim_scan,
};
// KS-2B2: the host's row-held responses in `sync_state`, read by the engine.
#[cfg(feature = "sync")]
pub(crate) use sync_responses::media_job_put_fenced_in_txn;
#[doc(hidden)]
pub use sync_responses::{
    IdempotencyEntry, ResponseStamps, http_opaque_retired_at, http_response_read,
    media_job_erased_state, media_response_read,
};
pub(crate) use sync_responses::{
    MediaKey, erase_sync_response_owner_in_txn, http_erase_drop_caller, http_owners, http_scan,
    media_job_owners, media_job_scan, media_key, media_part_carriage,
};
#[cfg(test)]
pub(crate) use test_hooks::TestHooks;
pub(crate) use training_link::TrainingLinkSlot;
pub(crate) use usage_sources::erase_usage_source_in_txn;
pub(crate) use world_pad_custody::{PlannedPad, WorldPadCustody, plan_world_pad};
pub use writer_lease::{VAULT_WRITER_LEASE_HELD, VAULT_WRITER_LOCK_FILE, VaultWriterLease};

// The lift sweep's typed acceptance for this module's authored side
// tables (FIX 2680), named by their declarations.
pub(crate) use self::outbound_send_receipt::send_receipt_summary_accepts_masked;

pub mod dispatch_attempt_kind;

pub mod checkout_lease;

pub mod repo_mutation_record;

pub mod code_commit_metadata;

pub mod code_import_manifest;

pub mod own_rate_record;

pub mod repo_provenance_trailer;

pub mod code_revision_identity;

pub mod recovery_kit;

pub mod code_promotion_gap;

pub mod code_revision_record;

pub mod sandbox_path;

pub mod sandbox_credential;

pub mod sandbox_contract;

pub mod critic_lens;

pub mod verb_domain;

pub mod reaction_predicate;

pub mod repo_proposal_record;

pub mod repo_import_predicate;
