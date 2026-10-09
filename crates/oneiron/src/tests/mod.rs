use core::assert_matches;
use std::collections::{BTreeSet, HashSet};
use std::path::Path;
use std::str;
#[cfg(feature = "sync")]
use std::sync::Arc;

use crate::edge::{
    EDGE_VALUE_SEMANTIC_LEN, EDGE_VALUE_SEMANTIC_PROVENANCED_LEN, EDGE_VALUE_STRUCTURAL_LEN,
    EdgeActorClass, EdgeConfirmationStatus, EdgeProvenanceFlags, decode_edge_value,
    decode_edge_value_for_kind, encode_edge_value,
};
#[cfg(feature = "sync")]
use crate::embed::{Embedder, EmbedderLocality, PendingEmbeddingInput, PendingEmbeddingReconciler};
use crate::entity_id::ENTITY_ID_LEN;
use crate::habit::TaskRole;
#[cfg(feature = "sync")]
use crate::registry::ENTITY_TYPE_CLAIM;
use crate::registry::{
    ENTITY_TYPE_ACCESS_GRANT, ENTITY_TYPE_COUNTERPARTY_CONTACT, ENTITY_TYPE_FEDERATION_GRANT,
    ENTITY_TYPE_MACHINE, ENTITY_TYPE_MESSAGE, ENTITY_TYPE_MODEL, ENTITY_TYPE_OUTBOUND_GRANT,
    ENTITY_TYPE_PERSON, ENTITY_TYPE_POLICY_MANIFEST, ENTITY_TYPE_REDACTION_AUDIT, ENTITY_TYPE_TASK,
    ENTITY_TYPE_TASK_LIST, ENTITY_TYPE_TURN,
};
use heed::EnvOpenOptions;
use heed::types::{Bytes, Str};
use sha2::{Digest, Sha256};
use xxhash_rust::xxh32::xxh32;

use super::*;
use crate::affect::coping::{
    COPING_OUTCOME_PREDICATE, CopingOutcomeValue, CopingStrategy, coping_outcome_value,
    decode_coping_outcome_claim,
};
use crate::affect::{CLAIM_VAD_REAPPRAISAL_PREDICATE, VadComponent, VadDelta};
use crate::affect::{VAD_ANNOTATION_META, vad_annotation_claim_id, vad_annotation_meta_key};
use crate::analyzer::{ANALYZER_VERSION, AnalyzerManifest};
use crate::batch::{
    ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader, LONG_INTERVAL_THRESHOLD_SECS,
};
use crate::companion::ENTITY_TYPE_COMPANION_REGISTER;
use crate::deletion::DeleteEntityOutcome;
use crate::deletion::{
    DeleteReason, HardEraseSweepExtras, LAST_HARD_ERASE_SWEEP_SEQ_KEY, RedactionScope,
    ReplayedTombstoneOutcome, encode_hard_erase_sweep_job, encode_hard_erase_sweep_key,
};
use crate::edge::EdgeValueLayout;
use crate::error::{VaultRootEntry, VaultRootProblem};
use crate::hnsw::COUNT_KEY;
use crate::provenance::{
    EdgeProvenanceClaimBody, EdgeRef, PREDICATE_EDGE_PROVENANCE, SupersessionStatus,
    decode_edge_provenance_body,
};
use crate::registry::ENTITY_TYPE_AUTHORITY_LOG;
#[cfg(feature = "sync")]
use crate::store::EMBEDDING_MODEL_EPOCH_KEY;
use crate::store::{
    DB_MANIFEST, GRAPH_VERSION_KEY, HNSW_CONFIG_KEY, MAX_DBS, MODEL_ID_KEY, STORAGE_ABI_VERSION,
    STORAGE_ABI_VERSION_KEY, STORAGE_SCHEMA_VERSION, STORAGE_SCHEMA_VERSION_KEY,
    STRUCTURAL_KIND_REGISTRY_KEY_PREFIX, STRUCTURAL_KIND_REGISTRY_RECORD_VERSION, Store,
    TEMPORAL_LONG_INTERVALS_SCHEMA_VERSION_KEY, VECTOR_VERSION_KEY, lmdb_database_open_guard,
    short_id_counter_key, structural_kind_registry_key,
};
#[cfg(feature = "sync")]
use crate::sync::SyncQueue;

pub(crate) mod batch_temporal;
pub(crate) mod claim_lifecycle;
pub(crate) mod claim_vad;
pub(crate) mod claims;
pub(crate) mod deletion;
pub(crate) mod edge_prov_lifecycle;
pub(crate) mod embedding;
pub(crate) mod entity_edge_kinds;
pub(crate) mod graph_topology;
pub(crate) mod identity_topology_delete_interlock;
pub(crate) mod open_gates;
pub(crate) mod prov_deletes;
pub(crate) mod reput_phonetic;
pub(crate) mod session_misc;
pub(crate) mod short_ids;
mod support;
pub(crate) mod text_search;
pub(crate) mod tombstones;
pub(crate) mod type_registry;
pub(crate) mod vad_annotations;
pub(crate) mod vectors_hnsw;
use support::*;

fn test_config() -> VaultConfig {
    // Build from the public preset so tests exercise the same construction
    // path external callers must use with `#[non_exhaustive]` VaultConfig.
    let mut config = VaultConfig::device();
    config.map_size = 16 * 1024 * 1024;
    config.dimensions = 4;
    config.embedding_model = Some("test/model@v1".to_owned());
    config.max_readers = 16;
    config.hnsw = HnswConfig::default();
    config.hnsw.m_max_0 = 64;
    config.hnsw.ef_construction = 200;
    config.hnsw.ef_search = 128;
    config
}

const EXPECTED_HNSW_COMPATIBILITY_VERSION: u8 = 3;
const EXPECTED_HNSW_COMPATIBILITY_LEN: usize = 29;
const EXPECTED_HNSW_DISTANCE_METRIC_COSINE: u8 = 1;
const EXPECTED_HNSW_INDEX_STRUCTURE_FLAT_NSW: u8 = 1;
const LEGACY_HNSW_COMPATIBILITY_LEN: usize = 25;

fn large_test_config() -> VaultConfig {
    let mut config = test_config();
    config.map_size = 128 * 1024 * 1024;
    config
}

fn open_test_vault() -> (tempfile::TempDir, Vault) {
    crate::test_util::open_test_vault_with(test_config())
}

fn test_time_range(start: u64, end: u64) -> TimeRange {
    TimeRange { start, end }
}

/// Seeds one MESSAGE row for a fixture that only needs the row to EXIST.
///
/// ONE-1686 closed the public raw MESSAGE door — a MESSAGE body is a gated
/// witness envelope now — so these fixtures carry canonical envelope bytes and
/// go through the crate's test-only seeding door instead of `put_entity`. They
/// deliberately do NOT witness: a real witness call would also mint the
/// conversation, turn and edges these tests are counting.
fn seed_message_fixture(vault: &Vault, id: &EntityId, content: &str, at: u64) -> Result<()> {
    let body = crate::gate::canonical_witness_message_body_for_test(
        "companion",
        "dialogue",
        content,
        true,
        0,
    )?;
    vault
        .batch()
        .put_canonical_message_for_test(id, test_time_range(at, at), at, &body)
        .commit()
}

fn block_on_ready<F: std::future::Future>(future: F) -> F::Output {
    let waker = std::task::Waker::noop();
    let mut context = std::task::Context::from_waker(waker);
    let mut future = std::pin::pin!(future);
    match future.as_mut().poll(&mut context) {
        std::task::Poll::Ready(output) => output,
        std::task::Poll::Pending => panic!("test future unexpectedly yielded"),
    }
}

fn seeded_entity_id(counter: u128) -> EntityId {
    let mut bytes = counter.to_be_bytes();
    bytes[0] = 0x7e;
    EntityId::from_bytes(bytes).expect("seeded test id should be valid")
}

// ═══════════════════════════════════════════════════════════════════════
// ONE-1133 — reason-aware tombstone replay primitive
// (`Vault::apply_replayed_tombstone`): soft = shell-preserving SoftErase,
// hard/legacy/unknown/malformed = destructive purge + LOCAL receipt +
// LOCAL `h:` sweep row; never-downgrade on receive; D16 in the same txn.
// ═══════════════════════════════════════════════════════════════════════

const PINNED_EDGE_KIND_DISCRIMINANTS: [(u8, EdgeKind); 31] = [
    (0, EdgeKind::AuthoredBy),
    (1, EdgeKind::ScopedTo),
    (2, EdgeKind::PartOf),
    (3, EdgeKind::Supersedes),
    (4, EdgeKind::BelongsTo),
    (5, EdgeKind::ClaimOf),
    (6, EdgeKind::ChildOf),
    (7, EdgeKind::AssignedTo),
    (8, EdgeKind::DerivedFrom),
    (9, EdgeKind::Mentions),
    (10, EdgeKind::About),
    (11, EdgeKind::Supports),
    (12, EdgeKind::Opposes),
    (13, EdgeKind::ParticipatesIn),
    (14, EdgeKind::Attached),
    (15, EdgeKind::EmployedBy),
    (16, EdgeKind::HasFacet),
    (17, EdgeKind::FacetOf),
    (18, EdgeKind::InWorld),
    (19, EdgeKind::SetIn),
    // ONE-1414: byte 20 is now MINTED — the cross-vault `same_as` link this
    // slot was parked for. It is the only byte that ticket allocates.
    (20, EdgeKind::SameAs),
    (21, EdgeKind::MergedInto),
    (22, EdgeKind::SplitInto),
    // ONE-1924: minted at byte 23, above the 21/22 identity-redirect pair and
    // clear of the byte-20 ONE-1414 `same_as` slot.
    (23, EdgeKind::BlockedBy),
    // ONE-1608: minted at byte 24, appended last. Byte 23 stays ONE-1924's
    // TASK-plane `blocked_by`; this is the ARCH-0050 L2 readiness edge.
    (24, EdgeKind::Blocks),
    // ONE-1541 (CMT-4): the brief-fulfillment pair, appended above every
    // landed byte. `discharged_by` is the inverse traversal edge, not a
    // creation-causation claim.
    (25, EdgeKind::Fulfills),
    (26, EdgeKind::DischargedBy),
    (27, EdgeKind::Parent),
    (28, EdgeKind::SpawnedBy),
    (29, EdgeKind::AddressedTo),
    (30, EdgeKind::RepliesTo),
];

// ─── Phase 2A: Tree Query API ─────────────────────────────

// Shared helper for both `batch()` and `batch_in()` reparent variants.
// `apply_reparent` is a closure that, given the vault and the three entity ids,
// performs the reparent operation (add edge to parent_b + delete edge to parent_a)
// via the API surface under test.

// ─── ONE-1930: the two-layer id lane (parse is syntax, resolve is registry) ───

// ONE-215: the synchronous door is only a delegate, never a second trust mode.
