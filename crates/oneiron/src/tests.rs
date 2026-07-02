use core::assert_matches;
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::path::Path;
use std::str;
use std::time::Instant;

use crate::limits::{MAX_ANCESTOR_DEPTH, MAX_CHILD_OF_CYCLE_TRAVERSAL_STEPS};
use crate::types::{
    EDGE_VALUE_SEMANTIC_LEN, EDGE_VALUE_SEMANTIC_PROVENANCED_LEN, EDGE_VALUE_STRUCTURAL_LEN,
    ENTITY_ID_LEN, ENTITY_TYPE_ACCESS_GRANT, ENTITY_TYPE_FEDERATION_GRANT, ENTITY_TYPE_MACHINE,
    ENTITY_TYPE_MESSAGE, ENTITY_TYPE_MODEL, ENTITY_TYPE_NOTIFICATION, ENTITY_TYPE_PERSON,
    ENTITY_TYPE_POLICY_MANIFEST, ENTITY_TYPE_PSYCH_PROFILE, ENTITY_TYPE_REDACTION_AUDIT,
    ENTITY_TYPE_TASK, ENTITY_TYPE_TASK_LIST, ENTITY_TYPE_TURN, EdgeActorClass,
    EdgeConfirmationStatus, EdgeProvenanceFlags, decode_edge_value, decode_edge_value_for_kind,
    encode_edge_value,
};
use heed::EnvOpenOptions;
use heed::types::{Bytes, Str};
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use sha2::{Digest, Sha256};
use xxhash_rust::xxh32::xxh32;

use super::*;
use crate::batch::{
    ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader, LONG_INTERVAL_THRESHOLD_SECS,
};
use crate::deletion::{
    DeleteReason, HardEraseSweepExtras, LAST_HARD_ERASE_SWEEP_SEQ_KEY, RedactionScope,
    ReplayedTombstoneOutcome, encode_hard_erase_sweep_job, encode_hard_erase_sweep_key,
};
use crate::error::{VaultRootEntry, VaultRootProblem};
use crate::hnsw::COUNT_KEY;
use crate::store::{
    DB_MANIFEST, GRAPH_VERSION_KEY, HNSW_CONFIG_KEY, MAX_DBS, MODEL_ID_KEY, STORAGE_ABI_VERSION,
    STORAGE_ABI_VERSION_KEY, STORAGE_SCHEMA_VERSION, STORAGE_SCHEMA_VERSION_KEY,
    STRUCTURAL_KIND_REGISTRY_KEY_PREFIX, Store, TEMPORAL_LONG_INTERVALS_SCHEMA_VERSION_KEY,
    VECTOR_VERSION_KEY, lmdb_database_open_guard, short_id_counter_key,
    structural_kind_registry_key,
};
use crate::vault::{vad_annotation_claim_id, vad_annotation_meta_key};

fn test_config() -> VaultConfig {
    // Build from the public preset so tests exercise the same construction
    // path external callers must use with `#[non_exhaustive]` VaultConfig.
    let mut config = VaultConfig::device();
    config.map_size = 16 * 1024 * 1024;
    config.dimensions = 4;
    config.embedding_model = Some("test-model-v1".to_owned());
    config.max_readers = 16;
    config.hnsw = HnswConfig::default();
    config.hnsw.m_max_0 = 64;
    config.hnsw.ef_construction = 200;
    config.hnsw.ef_search = 128;
    config
}

const EXPECTED_HNSW_COMPATIBILITY_VERSION: u8 = 2;
const EXPECTED_HNSW_COMPATIBILITY_LEN: usize = 27;
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

fn block_on_ready<F: std::future::Future>(future: F) -> F::Output {
    let waker = std::task::Waker::noop();
    let mut context = std::task::Context::from_waker(waker);
    let mut future = std::pin::pin!(future);
    match future.as_mut().poll(&mut context) {
        std::task::Poll::Ready(output) => output,
        std::task::Poll::Pending => panic!("test future unexpectedly yielded"),
    }
}

fn sample_resume_bundle(tokens_used: u64, tokens_limit: u64) -> ResumeBundle {
    ResumeBundle::new(
        SessionContext {
            api_version: "v1".to_owned(),
            counts: BTreeMap::from([("16".to_owned(), 1)]),
            last_activity: Some(42),
            rag_state: EiriSessionRagState::new("default"),
        },
        vec![NotificationItem {
            id: seeded_entity_id(0x2141).to_hex(),
            learned_at: 42,
            body: serde_json::json!({"message": "fresh"}),
        }],
        Vec::new(),
        ResumeBudget::from_meter(tokens_used, tokens_limit),
    )
}

#[test]
fn resume_budget_invariant_uses_meter_delta() {
    let bundle = sample_resume_bundle(400, 1_000);
    assert_eq!(bundle.budget.tokens_used, 400);
    assert_eq!(bundle.budget.tokens_limit, 1_000);
    assert_eq!(bundle.budget.tokens_remaining, 600);
}

#[test]
fn resume_budget_saturates_when_used_exceeds_limit() {
    let budget = ResumeBudget::from_meter(1_200, 1_000);
    assert_eq!(budget.tokens_used, 1_200);
    assert_eq!(budget.tokens_limit, 1_000);
    assert_eq!(budget.tokens_remaining, 0);
}

#[test]
fn resume_bundle_serde_top_level_keys_are_exact() {
    let value = serde_json::to_value(sample_resume_bundle(400, 1_000)).unwrap();
    let object = value
        .as_object()
        .expect("resume bundle should be an object");
    let keys = object.keys().map(String::as_str).collect::<BTreeSet<_>>();
    assert_eq!(
        keys,
        BTreeSet::from(["budget", "notifications", "session", "unprocessed"])
    );
}

#[test]
fn resume_bundle_empty_surfaces_serialize_as_empty_arrays() {
    let bundle = ResumeBundle::new(
        SessionContext {
            api_version: "v1".to_owned(),
            counts: BTreeMap::new(),
            last_activity: None,
            rag_state: EiriSessionRagState::new("default"),
        },
        Vec::new(),
        Vec::new(),
        ResumeBudget::from_meter(0, 0),
    );

    assert_eq!(bundle.notifications, Vec::<NotificationItem>::new());
    assert_eq!(bundle.unprocessed, Vec::<UnprocessedItem>::new());

    let json = String::from_utf8(crate::serialize::serialize_resume_bundle(&bundle)).unwrap();
    assert!(
        json.contains("\"notifications\":[]"),
        "notifications must serialize as an empty array: {json}"
    );
    assert!(
        json.contains("\"unprocessed\":[]"),
        "unprocessed must serialize as an empty array: {json}"
    );
}

#[test]
fn session_context_deserializes_legacy_without_rag_state() {
    let session: SessionContext = serde_json::from_value(serde_json::json!({
        "api_version": "v1",
        "counts": {},
        "last_activity": null
    }))
    .expect("legacy session context should deserialize");

    assert_eq!(session.rag_state, EiriSessionRagState::default());
}

fn seeded_entity_id(counter: u128) -> EntityId {
    let mut bytes = counter.to_be_bytes();
    bytes[0] = 0x7e;
    EntityId::from_bytes(bytes).expect("seeded test id should be valid")
}

fn valid_edge_value() -> Vec<u8> {
    encode_edge_value(EdgeKind::BelongsTo, 0.0, 0, Vad::NEUTRAL, None)
        .expect("valid structural edge value")
}

/// Builds a structurally valid CLAIM body (D11 pinned keys) for raw type-0
/// writes. The subject is an arbitrary valid entity id — the raw write path
/// validates structure only; subject existence is `put_claim`'s concern.
fn valid_claim_body_bytes(pred: &str, val: &str) -> Vec<u8> {
    let body = crate::claim::ClaimBody::new(
        pred,
        crate::claim::ClaimSubject::Entity(seeded_entity_id(0xC1A1)),
        rmpv::Value::from(val),
        0.9,
        crate::claim::ClaimApprovalStatus::Auto,
        crate::claim::ClaimLifecycleStatus::Active,
    );
    crate::claim::encode_claim_body(&body).expect("encode valid claim body")
}

fn read_meta_u16(vault: &Vault, key: &[u8]) -> Result<Option<u16>> {
    let rtxn = vault.store.env.read_txn()?;
    let Some(raw) = vault.store.vault_meta.get(&rtxn, key)? else {
        return Ok(None);
    };
    let bytes: [u8; 2] = raw.try_into().map_err(|_| Error::InvalidKey)?;
    Ok(Some(u16::from_le_bytes(bytes)))
}

fn vault_meta_rows_with_prefix(vault: &Vault, prefix: &[u8]) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
    let rtxn = vault.store.env.read_txn()?;
    let mut rows = Vec::new();
    for row in vault.store.vault_meta.prefix_iter(&rtxn, prefix)? {
        let (key, value) = row?;
        rows.push((key.to_vec(), value.to_vec()));
    }
    Ok(rows)
}

fn legacy_hnsw_compatibility_record(config: &VaultConfig) -> [u8; LEGACY_HNSW_COMPATIBILITY_LEN] {
    let dimensions = u64::try_from(config.dimensions).expect("test dimensions fit in u64");
    let m_max_0 = u64::try_from(config.hnsw.m_max_0).expect("test m_max_0 fits in u64");
    let ef_construction =
        u64::try_from(config.hnsw.ef_construction).expect("test ef_construction fits in u64");

    let mut encoded = [0_u8; LEGACY_HNSW_COMPATIBILITY_LEN];
    encoded[0] = 1;
    encoded[1..9].copy_from_slice(&dimensions.to_le_bytes());
    encoded[9..17].copy_from_slice(&m_max_0.to_le_bytes());
    encoded[17..25].copy_from_slice(&ef_construction.to_le_bytes());
    encoded
}

fn read_hnsw_config_record(vault: &Vault) -> Result<Vec<u8>> {
    let rtxn = vault.store.env.read_txn()?;
    let Some(raw) = vault.store.hnsw_meta.get(&rtxn, HNSW_CONFIG_KEY)? else {
        return Err(Error::InvalidKey);
    };
    Ok(raw.to_vec())
}

fn write_hnsw_config_record(vault: &Vault, raw: &[u8]) -> Result<()> {
    let mut wtxn = vault.store.env.write_txn()?;
    vault.store.hnsw_meta.put(&mut wtxn, HNSW_CONFIG_KEY, raw)?;
    wtxn.commit()?;
    Ok(())
}

fn redaction_audit_receipts(vault: &Vault) -> Result<Vec<EntityId>> {
    vault.entities_by_type(ENTITY_TYPE_REDACTION_AUDIT)
}

fn hard_erase_sweep_rows(vault: &Vault) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
    let rtxn = vault.store.env.read_txn()?;
    let mut rows = Vec::new();
    for row in vault.store.sync_queue.prefix_iter(&rtxn, b"h:")? {
        let (key, value) = row?;
        rows.push((key.to_vec(), value.to_vec()));
    }
    Ok(rows)
}

fn receipt_body(raw: &[u8]) -> serde_json::Value {
    rmp_serde::from_slice(&raw[ENTITY_METADATA_HEADER_LEN..]).expect("decode receipt body")
}

fn assert_receipt_fields(receipt: &serde_json::Value) {
    let object = receipt.as_object().expect("receipt must be object");
    let mut fields: Vec<&str> = object.keys().map(String::as_str).collect();
    fields.sort_unstable();
    assert_eq!(
        fields,
        vec![
            "affected_revision_ids",
            "hard_purge_complete_at",
            "reason",
            "request_id",
            "requested_at",
            "scope",
            "soft_complete_at",
            "sweep_complete_at",
            "sweep_queued_at",
            "verification",
        ]
    );
}

fn assert_no_receipt_payload_leak(raw: &[u8], needles: &[&[u8]]) {
    for needle in needles {
        assert!(
            !raw.windows(needle.len()).any(|window| window == *needle),
            "receipt leaked forbidden content bytes: {:?}",
            String::from_utf8_lossy(needle)
        );
    }
}

fn materialized_database_names(vault: &Vault) -> Result<Vec<String>> {
    let _guard = lmdb_database_open_guard()?;
    let rtxn = vault.store.env.read_txn()?;
    let main = vault
        .store
        .env
        .open_database::<Bytes, Bytes>(&rtxn, None)?
        .ok_or(Error::InvariantViolation("missing unnamed lmdb database"))?;

    let mut names = Vec::new();
    for row in main.iter(&rtxn)? {
        let (key, _) = row?;
        if key.contains(&0) {
            continue;
        }
        names.push(
            str::from_utf8(key)
                .map_err(|_| Error::InvalidKey)?
                .to_owned(),
        );
    }
    names.sort();
    Ok(names)
}

fn expected_manifest_names() -> Vec<&'static str> {
    let mut names: Vec<&'static str> = DB_MANIFEST.iter().map(|entry| entry.name).collect();
    names.sort_unstable();
    names
}

fn create_raw_vault_missing_manifest_name(path: &Path, missing: &str) -> Result<()> {
    let mut names = expected_manifest_names();
    names.retain(|name| *name != missing);
    create_raw_vault_with_manifest_names(path, &names)
}

fn set_raw_storage_abi_version(path: &std::path::Path, value: Option<u16>) -> Result<()> {
    let mut config = test_config();
    config.map_size = 16 * 1024 * 1024;
    let _guard = lmdb_database_open_guard()?;
    // SAFETY: the normal Vault/Store handle has been dropped before this helper
    // is called, and tests open only local temporary LMDB directories.
    let env = unsafe {
        EnvOpenOptions::new()
            .map_size(config.map_size)
            .max_readers(config.max_readers)
            .max_dbs(MAX_DBS)
            .open(path)?
    };
    let mut wtxn = env.write_txn()?;
    let vault_meta = env.create_database::<Bytes, Bytes>(&mut wtxn, Some("vault_meta"))?;
    match value {
        Some(value) => vault_meta.put(&mut wtxn, STORAGE_ABI_VERSION_KEY, &value.to_le_bytes())?,
        None => {
            vault_meta.delete(&mut wtxn, STORAGE_ABI_VERSION_KEY)?;
        }
    }
    wtxn.commit()?;
    Ok(())
}

fn create_raw_vault_with_manifest_names(path: &Path, names: &[&str]) -> Result<()> {
    let config = test_config();
    let _guard = lmdb_database_open_guard()?;
    // SAFETY: test-only creation of a local temporary LMDB environment.
    let env = unsafe {
        EnvOpenOptions::new()
            .map_size(config.map_size)
            .max_readers(config.max_readers)
            .max_dbs(MAX_DBS)
            .open(path)?
    };
    let mut wtxn = env.write_txn()?;
    for name in names {
        if *name == "sync_state" {
            let _: heed::Database<Str, Bytes> = env.create_database(&mut wtxn, Some(name))?;
        } else {
            let _: heed::Database<Bytes, Bytes> = env.create_database(&mut wtxn, Some(name))?;
        }
    }
    let vault_meta = env.create_database::<Bytes, Bytes>(&mut wtxn, Some("vault_meta"))?;
    vault_meta.put(
        &mut wtxn,
        STORAGE_ABI_VERSION_KEY,
        &STORAGE_ABI_VERSION.to_le_bytes(),
    )?;
    vault_meta.put(
        &mut wtxn,
        STORAGE_SCHEMA_VERSION_KEY,
        &STORAGE_SCHEMA_VERSION.to_le_bytes(),
    )?;
    wtxn.commit()?;
    Ok(())
}

fn create_raw_named_database(path: &Path, name: &str) -> Result<()> {
    let config = test_config();
    let _guard = lmdb_database_open_guard()?;
    // SAFETY: test-only reopen of a local temporary LMDB environment after
    // the normal Vault/Store handle has been dropped.
    let env = unsafe {
        EnvOpenOptions::new()
            .map_size(config.map_size)
            .max_readers(config.max_readers)
            .max_dbs(MAX_DBS)
            .open(path)?
    };
    let mut wtxn = env.write_txn()?;
    let _: heed::Database<Bytes, Bytes> = env.create_database(&mut wtxn, Some(name))?;
    wtxn.commit()?;
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ContractEdgeLayout {
    Structural,
    SemanticBare,
}

impl ContractEdgeLayout {
    fn bytes(self) -> usize {
        match self {
            Self::Structural => EDGE_VALUE_STRUCTURAL_LEN,
            Self::SemanticBare => EDGE_VALUE_SEMANTIC_LEN,
        }
    }
}

const CONTRACT_EDGE_VALUE_LAYOUTS: [(EdgeKind, ContractEdgeLayout); 20] = [
    (EdgeKind::AuthoredBy, ContractEdgeLayout::Structural),
    (EdgeKind::ScopedTo, ContractEdgeLayout::Structural),
    (EdgeKind::PartOf, ContractEdgeLayout::Structural),
    (EdgeKind::Supersedes, ContractEdgeLayout::Structural),
    (EdgeKind::BelongsTo, ContractEdgeLayout::Structural),
    (EdgeKind::ClaimOf, ContractEdgeLayout::Structural),
    (EdgeKind::ChildOf, ContractEdgeLayout::Structural),
    (EdgeKind::AssignedTo, ContractEdgeLayout::Structural),
    (EdgeKind::DerivedFrom, ContractEdgeLayout::Structural),
    (EdgeKind::Mentions, ContractEdgeLayout::SemanticBare),
    (EdgeKind::About, ContractEdgeLayout::SemanticBare),
    (EdgeKind::Supports, ContractEdgeLayout::SemanticBare),
    (EdgeKind::Opposes, ContractEdgeLayout::SemanticBare),
    (EdgeKind::ParticipatesIn, ContractEdgeLayout::SemanticBare),
    (EdgeKind::Attached, ContractEdgeLayout::SemanticBare),
    (EdgeKind::EmployedBy, ContractEdgeLayout::SemanticBare),
    (EdgeKind::HasFacet, ContractEdgeLayout::SemanticBare),
    (EdgeKind::FacetOf, ContractEdgeLayout::SemanticBare),
    (EdgeKind::InWorld, ContractEdgeLayout::SemanticBare),
    (EdgeKind::SetIn, ContractEdgeLayout::SemanticBare),
];

fn assert_f32_exact(actual: f32, expected: f32) {
    assert_eq!(actual.to_bits(), expected.to_bits());
}

fn assert_vad_exact(actual: Vad, expected: Vad) {
    assert_f32_exact(actual.valence, expected.valence);
    assert_f32_exact(actual.arousal, expected.arousal);
    assert_f32_exact(actual.dominance, expected.dominance);
}

fn contract_vad(i: usize) -> Vad {
    Vad {
        valence: -0.75 + (i as f32 * 0.05),
        arousal: 0.10 + (i as f32 * 0.02),
        dominance: 0.20 + (i as f32 * 0.03),
    }
}

fn assert_common_edge_value_fields(value: &[u8], weight: f32, created_at: u64) {
    assert_eq!(&value[0..4], &weight.to_le_bytes());
    assert_eq!(&value[4..12], &created_at.to_le_bytes());
}

fn assert_vad_bytes(value: &[u8], vad: Vad) {
    assert_eq!(&value[12..16], &vad.valence.to_le_bytes());
    assert_eq!(&value[16..20], &vad.arousal.to_le_bytes());
    assert_eq!(&value[20..24], &vad.dominance.to_le_bytes());
}

fn contract_structural_value(weight: f32, created_at: u64) -> Vec<u8> {
    let mut value = Vec::with_capacity(EDGE_VALUE_STRUCTURAL_LEN);
    value.extend_from_slice(&weight.to_le_bytes());
    value.extend_from_slice(&created_at.to_le_bytes());
    assert_eq!(value.len(), EDGE_VALUE_STRUCTURAL_LEN);
    value
}

fn contract_semantic_bare_value(weight: f32, created_at: u64, vad: Vad) -> Vec<u8> {
    let mut value = contract_structural_value(weight, created_at);
    value.extend_from_slice(&vad.valence.to_le_bytes());
    value.extend_from_slice(&vad.arousal.to_le_bytes());
    value.extend_from_slice(&vad.dominance.to_le_bytes());
    assert_eq!(value.len(), EDGE_VALUE_SEMANTIC_LEN);
    value
}

fn contract_semantic_provenanced_value(weight: f32, created_at: u64, vad: Vad) -> Vec<u8> {
    let mut value = contract_semantic_bare_value(weight, created_at, vad);
    value.push(1); // confirmation_status = confirmed
    value.push(1); // actor_class = agent
    assert_eq!(value.len(), EDGE_VALUE_SEMANTIC_PROVENANCED_LEN);
    value
}

fn encoded_entity_record(entity_type: u8, payload: &[u8]) -> Vec<u8> {
    let mut row = Vec::with_capacity(ENTITY_METADATA_HEADER_LEN + payload.len());
    row.push(entity_type);
    row.extend_from_slice(&0_u64.to_be_bytes());
    row.extend_from_slice(&0_u64.to_be_bytes());
    row.extend_from_slice(&0_u64.to_be_bytes());
    row.extend_from_slice(payload);
    row
}

fn content_hash(data: &[u8]) -> u8 {
    (xxh32(data, 0) % 256) as u8
}

fn decode_short_id_value(value: &[u8]) -> Result<(String, u8)> {
    if value.len() < 2 {
        return Err(Error::InvalidKey);
    }

    let (short_id, hash) = value.split_at(value.len() - 1);
    let short_id = str::from_utf8(short_id)
        .map_err(|_| Error::InvalidKey)?
        .to_owned();
    Ok((short_id, hash[0]))
}

/// Reads the entity-keyed `short_ids_reverse` row (ARCH-0019 manifest row n4:
/// entity_id -> `short_id bytes ‖ content_hash u8`).
fn read_short_id_value(vault: &Vault, id: &EntityId) -> Result<Vec<u8>> {
    let rtxn = vault.store.env.read_txn()?;
    vault
        .store
        .short_ids_reverse
        .get(&rtxn, id.as_bytes())?
        .map(|bytes| bytes.to_vec())
        .ok_or(Error::EntityNotFound)
}

fn read_raw_entity(vault: &Vault, id: &EntityId) -> Result<Vec<u8>> {
    let rtxn = vault.store.env.read_txn()?;
    vault
        .store
        .entities
        .get(&rtxn, id.as_bytes())?
        .map(|bytes| bytes.to_vec())
        .ok_or(Error::EntityNotFound)
}

fn read_hnsw_meta_u64(vault: &Vault, key: &[u8]) -> Result<u64> {
    let rtxn = vault.store.env.read_txn()?;
    let Some(raw) = vault.store.hnsw_meta.get(&rtxn, key)? else {
        return Ok(0);
    };
    Ok(u64::from_le_bytes(
        raw.try_into().map_err(|_| Error::InvalidKey)?,
    ))
}

fn read_model_id(vault: &Vault) -> Result<Option<String>> {
    let rtxn = vault.store.env.read_txn()?;
    let Some(raw) = vault.store.hnsw_meta.get(&rtxn, MODEL_ID_KEY)? else {
        return Ok(None);
    };
    String::from_utf8(raw.to_vec())
        .map(Some)
        .map_err(|_| Error::InvalidKey)
}

fn decode_forward_codes(raw: &[u8]) -> Result<Vec<String>> {
    if raw.is_empty() {
        return Ok(Vec::new());
    }

    let mut codes: Vec<String> = raw
        .split(|b| *b == 0)
        .map(|chunk| {
            if chunk.is_empty() {
                return Err(Error::CorruptedIndex("phonetic forward test decode"));
            }
            str::from_utf8(chunk)
                .map(str::to_owned)
                .map_err(|_| Error::CorruptedIndex("phonetic forward test decode"))
        })
        .collect::<Result<_>>()?;
    codes.sort();
    Ok(codes)
}

#[test]
fn encode_edge_key_has_exact_layout() {
    let src = EntityId::from_bytes_unchecked([0x11; 16]);
    let tgt = EntityId::from_bytes_unchecked([0x22; 16]);
    let kind = EdgeKind::DerivedFrom;

    let key = Store::encode_edge_key(&src, kind, &tgt);

    assert_eq!(key.len(), 33);
    assert_eq!(&key[..16], src.as_bytes());
    assert_eq!(key[16], kind as u8);
    assert_eq!(&key[17..], tgt.as_bytes());
}

#[test]
fn open_put_get_delete_entities() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let id = EntityId::now();
    let data = b"entity-payload";

    vault.put_entity(&id, 1, test_time_range(10, 20), 30, data)?;
    let got = vault.get(&id)?.ok_or(Error::EntityNotFound)?;
    assert_eq!(got, data);

    assert!(vault.delete_entity(&id)?);
    assert!(vault.get(&id)?.is_none());
    assert!(!vault.delete_entity(&id)?);

    Ok(())
}

#[test]
fn user_delete_soft_erases_active_payload_without_receipt_or_sweep() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let id = EntityId::now();
    let secret = b"soft-erase-active-secret";

    vault
        .batch()
        .put(&id, 1, test_time_range(10, 10), 20, secret)
        .text(&id, &[("body", "soft-erase-active-secret")])
        .commit()?;

    assert_eq!(vault.get(&id)?.as_deref(), Some(secret.as_slice()));
    assert_eq!(vault.search_text("active-secret", 10)?.len(), 1);

    let outcome = vault.delete_entity_with_reason(&id, DeleteReason::UserDelete)?;

    assert!(outcome.existed);
    assert!(outcome.receipt_id.is_none());
    assert!(outcome.sweep_key.is_none());
    assert_eq!(vault.get(&id)?.as_deref(), Some([].as_slice()));
    assert!(vault.search_text("active-secret", 10)?.is_empty());
    assert!(vault.entities_by_type(1)?.contains(&id));
    assert!(redaction_audit_receipts(&vault)?.is_empty());
    assert!(hard_erase_sweep_rows(&vault)?.is_empty());
    Ok(())
}

#[test]
fn user_hard_delete_writes_opaque_redaction_audit_receipt() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let id = EntityId::now();
    let payload = b"Alice secret body predicate should never enter receipt";

    vault.put_entity(&id, 1, test_time_range(100, 100), 101, payload)?;

    let outcome = vault.delete_entity_with_reason(&id, DeleteReason::UserHardDelete)?;
    let receipt_id = outcome
        .receipt_id
        .expect("user_hard_delete must write REDACTION_AUDIT receipt");
    assert_eq!(
        vault.get_entity_type(&receipt_id)?,
        Some(ENTITY_TYPE_REDACTION_AUDIT)
    );

    let raw = vault
        .get_raw(&receipt_id)?
        .expect("receipt entity should be persisted");
    assert_no_receipt_payload_leak(&raw, &[b"Alice", b"secret body", b"predicate"]);

    let receipt = receipt_body(&raw);
    assert_receipt_fields(&receipt);
    assert_eq!(receipt["reason"], "user_hard_delete");
    assert_eq!(receipt["scope"]["entity_ids"][0], id.to_hex());
    assert_eq!(
        receipt["scope"]["revision_ids"].as_array().unwrap().len(),
        0
    );
    assert!(
        receipt["affected_revision_ids"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    assert!(receipt["sweep_queued_at"].as_u64().is_some());
    assert!(receipt["sweep_complete_at"].is_null());
    // ONE-1140 (OD-6) versions the M4 "verification empty" pin: every
    // minted receipt now carries EXACTLY the four att_ attestation entries
    // (lowercase hex strings, pinned lengths). Still opaque — hex
    // identifiers and a signature, never content.
    let verification = receipt["verification"].as_object().unwrap();
    let mut keys: Vec<&str> = verification.keys().map(String::as_str).collect();
    keys.sort_unstable();
    assert_eq!(keys, vec!["att_client", "att_pk", "att_sig", "att_v"]);
    let is_lower_hex = |s: &str| {
        s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    };
    let att_client = verification["att_client"].as_str().unwrap();
    assert_eq!(att_client.len(), 16);
    assert!(is_lower_hex(att_client));
    let att_pk = verification["att_pk"].as_str().unwrap();
    assert_eq!(att_pk.len(), 64);
    assert!(is_lower_hex(att_pk));
    let att_sig = verification["att_sig"].as_str().unwrap();
    assert_eq!(att_sig.len(), 128);
    assert!(is_lower_hex(att_sig));
    assert_eq!(verification["att_v"], "1");
    Ok(())
}

#[test]
fn redaction_receipt_indexes_temporal_occurred_start_as_point_event() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let id = EntityId::now();
    // Seed the to-be-deleted subject as TURN (type 1), a non-claim type whose
    // body stays opaque: type 0 is CLAIM and gains a validated body ABI
    // (ONE-1104), which would reject this seed before the hard delete runs.
    vault.put_entity(&id, 1, test_time_range(300, 300), 301, b"index-me")?;

    let outcome = vault.delete_entity_with_reason(&id, DeleteReason::UserHardDelete)?;
    let receipt_id = outcome.receipt_id.expect("receipt id");

    // The `hard_purge_complete_at` timestamp inside the receipt BODY is the
    // independent oracle: the receipt writer sets occurred_start ==
    // occurred_end == learned_at == hard_purge_complete_at (point event).
    let raw = vault.get_raw(&receipt_id)?.expect("receipt record");
    let receipt = receipt_body(&raw);
    let purge_at = receipt["hard_purge_complete_at"]
        .as_u64()
        .expect("hard_purge_complete_at");

    // contracts.ts dbManifest n:18 — temporal_occurred_start key is
    // (timestamp, entity_id) with value (): timestamp u64 BE (8 B) followed
    // by the entity id (16 B), exactly the shape apply_put writes.
    let mut expected_key = [0_u8; 24];
    expected_key[..8].copy_from_slice(&purge_at.to_be_bytes());
    expected_key[8..].copy_from_slice(receipt_id.as_bytes());

    let rtxn = vault.store.env.read_txn()?;
    let lower = purge_at.to_be_bytes();
    let upper = purge_at.checked_add(1).expect("range upper").to_be_bytes();
    let mut matches = 0_usize;
    for entry in vault.store.temporal_occurred_start.range(
        &rtxn,
        &(
            std::ops::Bound::Included(&lower[..]),
            std::ops::Bound::Excluded(&upper[..]),
        ),
    )? {
        let (key, value) = entry?;
        assert_eq!(key.len(), 24, "temporal_occurred_start key must be 24 B");
        if key[8..] == receipt_id.as_bytes()[..] {
            assert_eq!(key, expected_key.as_slice());
            assert!(value.is_empty(), "n:18 value must be ()");
            matches += 1;
        }
    }
    assert_eq!(
        matches, 1,
        "receipt must be discoverable via a temporal_occurred_start range scan"
    );

    // Point-event semantics IDENTICAL to apply_put (start == end): no
    // temporal_occurred_end row and no temporal_long_intervals row may exist
    // for the receipt anywhere in either DB.
    for entry in vault.store.temporal_occurred_end.iter(&rtxn)? {
        let (key, _) = entry?;
        assert_eq!(key.len(), 24, "temporal_occurred_end key must be 24 B");
        assert!(
            key[8..] != receipt_id.as_bytes()[..],
            "point-event receipt must not write a temporal_occurred_end row"
        );
    }
    for entry in vault.store.temporal_long_intervals.iter(&rtxn)? {
        let (key, _) = entry?;
        assert_eq!(key.len(), 24, "temporal_long_intervals key must be 24 B");
        assert!(
            key[8..] != receipt_id.as_bytes()[..],
            "zero-span receipt must not write a temporal_long_intervals row"
        );
    }

    // Pre-existing receipt index footprint is unchanged.
    let learned_key = Store::encode_temporal_key(purge_at, &receipt_id);
    assert!(
        vault
            .store
            .temporal_learned
            .get(&rtxn, &learned_key)?
            .is_some()
    );
    let type_key = Store::encode_type_key(ENTITY_TYPE_REDACTION_AUDIT, &receipt_id);
    assert!(vault.store.type_index.get(&rtxn, &type_key)?.is_some());
    // Maintenance kinds carry no short ID.
    assert!(
        vault
            .store
            .short_ids
            .get(&rtxn, receipt_id.as_bytes())?
            .is_none()
    );
    Ok(())
}

#[test]
fn hard_delete_enqueues_bounded_historical_carrier_sweep() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let id = EntityId::now();

    vault.put_entity(&id, 1, test_time_range(200, 200), 201, b"sweep-me")?;

    let outcome = vault.delete_entity_with_reason(&id, DeleteReason::UserHardDelete)?;
    let sweep_key = outcome
        .sweep_key
        .expect("user_hard_delete must enqueue historical-carrier sweep");
    assert!(sweep_key.starts_with(b"h:"));

    let rows = hard_erase_sweep_rows(&vault)?;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].0, sweep_key);

    let job: serde_json::Value = rmp_serde::from_slice(&rows[0].1).expect("decode sweep job");
    let mut job_fields: Vec<&str> = job
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    job_fields.sort_unstable();
    assert_eq!(job_fields, vec!["retry_state", "scope"]);
    assert_eq!(job["scope"]["entity_ids"][0], id.to_hex());
    assert_eq!(
        job["scope"]["carrier_classes"],
        serde_json::json!([
            "historical_loro_updates",
            "historical_loro_snapshots",
            "derived_carriers"
        ])
    );
    assert_eq!(job["retry_state"]["attempt_count"], 0);
    assert!(job["retry_state"]["last_error_code"].is_null());
    let queued_at = job["retry_state"]["queued_at"].as_u64().unwrap();
    let deadline_at = job["retry_state"]["deadline_at"].as_u64().unwrap();
    assert!(deadline_at >= queued_at);
    assert!(deadline_at <= queued_at + 30 * 86_400);

    let receipt_id = outcome.receipt_id.expect("receipt id");
    let receipt_raw = vault.get_raw(&receipt_id)?.expect("receipt");
    let receipt = receipt_body(&receipt_raw);
    assert_eq!(receipt["sweep_queued_at"].as_u64(), Some(queued_at));
    assert!(receipt["sweep_complete_at"].is_null());
    Ok(())
}

#[test]
fn hard_delete_sweep_sequence_self_heals_stale_cursor_on_collision() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let id = EntityId::now();
    vault.put_entity(
        &id,
        1,
        test_time_range(250, 250),
        251,
        b"repair-sweep-cursor",
    )?;

    let stale_seq = 6_u64;
    let existing_seq = 7_u64;
    let repaired_seq = 8_u64;
    let existing_key = encode_hard_erase_sweep_key(existing_seq);
    let existing_value = encode_hard_erase_sweep_job(
        RedactionScope::entity(&EntityId::now()),
        HardEraseSweepExtras::default(),
        1_772_000_000,
    )?;

    vault.with_write_txn(|wtxn| {
        vault.store.sync_queue.put(
            wtxn,
            LAST_HARD_ERASE_SWEEP_SEQ_KEY,
            &stale_seq.to_le_bytes(),
        )?;
        vault
            .store
            .sync_queue
            .put(wtxn, &existing_key, &existing_value)?;
        Ok(())
    })?;

    let outcome = vault.delete_entity_with_reason(&id, DeleteReason::UserHardDelete)?;
    assert_eq!(
        outcome.sweep_key.as_deref(),
        Some(encode_hard_erase_sweep_key(repaired_seq).as_slice())
    );

    let rtxn = vault.store.env.read_txn()?;
    assert_eq!(
        vault
            .store
            .sync_queue
            .get(&rtxn, LAST_HARD_ERASE_SWEEP_SEQ_KEY)?,
        Some(repaired_seq.to_le_bytes().as_slice())
    );
    assert!(
        vault
            .store
            .sync_queue
            .get(&rtxn, &encode_hard_erase_sweep_key(repaired_seq))?
            .is_some(),
        "new sweep job should be written after repairing the stale cursor",
    );
    Ok(())
}

#[test]
fn gdpr_and_policy_deletes_soft_erase_then_active_purge_with_receipts() -> Result<()> {
    for reason in [DeleteReason::GdprDelete, DeleteReason::PolicyDelete] {
        let (_dir, vault) = open_test_vault();
        let id = EntityId::now();
        vault
            .batch()
            .put(&id, 1, test_time_range(300, 300), 301, b"regulated secret")
            .text(&id, &[("body", "regulated secret")])
            .commit()?;

        let outcome = vault.delete_entity_with_reason(&id, reason)?;

        assert!(outcome.existed);
        assert!(vault.get(&id)?.is_none());
        assert!(vault.search_text("regulated", 10)?.is_empty());
        assert!(outcome.receipt_id.is_some());
        assert!(outcome.sweep_key.is_some());

        let receipt_raw = vault
            .get_raw(&outcome.receipt_id.unwrap())?
            .expect("receipt should be persisted");
        let receipt = receipt_body(&receipt_raw);
        assert_eq!(receipt["reason"], reason.as_str());
        assert!(
            receipt["soft_complete_at"].as_u64().unwrap()
                <= receipt["hard_purge_complete_at"].as_u64().unwrap()
        );
    }
    Ok(())
}

#[test]
fn receipt_reason_purges_orphan_vector_with_receipt_and_sweep() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let id = EntityId::now();

    vault.put_vector(&id, &[0.1, 0.2, 0.3, 0.4])?;
    assert!(vault.get(&id)?.is_none());
    assert!(vault.get_vector(&id)?.is_some());

    let outcome = vault.delete_entity_with_reason(&id, DeleteReason::GdprDelete)?;

    assert!(
        !outcome.existed,
        "orphan cleanup should not report an entity payload"
    );
    assert!(
        outcome.receipt_id.is_some(),
        "receipt-writing delete must account for orphan active data"
    );
    assert!(
        outcome.sweep_key.is_some(),
        "orphan active purge still queues the bounded historical-carrier sweep"
    );
    assert!(vault.get_vector(&id)?.is_none());

    let receipt_raw = vault
        .get_raw(&outcome.receipt_id.unwrap())?
        .expect("orphan purge receipt should be persisted");
    let receipt = receipt_body(&receipt_raw);
    assert_eq!(receipt["reason"], "gdpr_delete");
    assert_eq!(receipt["scope"]["entity_ids"][0], id.to_hex());
    assert!(receipt["sweep_complete_at"].is_null());

    let rows = hard_erase_sweep_rows(&vault)?;
    assert_eq!(rows.len(), 1);
    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════
// ONE-1149 — delete TOCTOU: receipt/sweep/`pt:` emission is serialized with
// the txn that actually erases. Two genuinely different cases must never
// collapse into one:
//   • FULLY-MISSING (an id that never had scope) = strict no-op, no publish
//     at all — not even a propagating tombstone.
//   • RACED-TO-NOTHING (scope existed at the read-probe, raced away before
//     the purge txn) = the already-published CRDT tombstone + `d:`/`q:`
//     propagation rows + a guarded `dt:` marker for hard reasons legitimately
//     survive as idempotent propagation intent; ONLY the receipt + `h:` sweep
//     + `pt:` marker are suppressed (the in-txn full-scope ownership probe).
//     It is NEVER "`dt:`-only": the propagating CRDT tombstone is the
//     cross-device convergence net (a peer that still holds the id needs it).
// A delete that erased NOTHING must never claim it did (no receipt, no `h:`
// sweep row, no `pt:` marker); a delete that erased a PARTIAL residue must
// still audit it (the false-NEGATIVE mirror).
// ═══════════════════════════════════════════════════════════════════════

fn sync_state_value(vault: &Vault, key: &str) -> Result<Option<Vec<u8>>> {
    let rtxn = vault.store.env.read_txn()?;
    Ok(vault.store.sync_state.get(&rtxn, key)?.map(<[u8]>::to_vec))
}

fn sync_state_keys_with_prefix_raw(vault: &Vault, prefix: &str) -> Result<Vec<String>> {
    let rtxn = vault.store.env.read_txn()?;
    let mut keys = Vec::new();
    for row in vault.store.sync_state.prefix_iter(&rtxn, prefix)? {
        let (key, _) = row?;
        keys.push(key.to_owned());
    }
    Ok(keys)
}

fn sync_queue_row_count_with_prefix(vault: &Vault, prefix: &[u8]) -> Result<usize> {
    let rtxn = vault.store.env.read_txn()?;
    let mut count = 0;
    for row in vault.store.sync_queue.prefix_iter(&rtxn, prefix)? {
        row?;
        count += 1;
    }
    Ok(count)
}

/// ONE-1149: ZERO erasure-audit artifacts — no REDACTION_AUDIT receipt
/// entity, no `h:` historical-carrier sweep row, no `pt:` pending-tombstone
/// marker. Asserted after every delete that erased nothing.
fn assert_no_erasure_audit_artifacts(vault: &Vault) -> Result<()> {
    assert!(
        redaction_audit_receipts(vault)?.is_empty(),
        "a delete that erased nothing must not write a REDACTION_AUDIT receipt"
    );
    assert!(
        hard_erase_sweep_rows(vault)?.is_empty(),
        "a delete that erased nothing must not queue an h: sweep row"
    );
    assert!(
        sync_state_keys_with_prefix_raw(vault, "pt:")?.is_empty(),
        "a delete that erased nothing must not leave a pt: pending-tombstone marker"
    );
    Ok(())
}

/// ONE-1149 FULLY-MISSING case: an id that NEVER had a delete scope is a
/// STRICT no-op for every reason — `missing()` outcome and ZERO side
/// effects, not even a propagating tombstone: no CRDT tombstone publish
/// (`d:w:` snapshot), no `q:`/`d:` queue rows, no `dt:` marker, no `pt:`
/// marker, no receipt, no sweep row. This is the deliberate contrast to the
/// RACED-TO-NOTHING case (`*_raced_to_nothing_*` below), where the scope
/// existed at the read-probe and only raced away before the purge txn, so
/// the already-published CRDT tombstone + `d:`/`q:` propagation rows + a
/// guarded `dt:` marker legitimately survive as idempotent propagation
/// intent. A wrong implementation that mints/publishes the tombstone before
/// proving there is something to erase leaves a `d:w:` row or queue rows
/// behind and fails this test.
#[test]
fn delete_missing_id_is_strict_noop_for_every_reason() -> Result<()> {
    for reason in [
        DeleteReason::UserDelete,
        DeleteReason::UserHardDelete,
        DeleteReason::GdprDelete,
        DeleteReason::PolicyDelete,
    ] {
        let (_dir, vault) = open_test_vault();
        let id = EntityId::now();

        let outcome = vault.delete_entity_with_reason(&id, reason)?;

        assert_eq!(
            outcome,
            DeleteEntityOutcome {
                existed: false,
                receipt_id: None,
                sweep_key: None,
            },
            "{reason:?}: a fully-missing id must report missing()"
        );
        assert_no_erasure_audit_artifacts(&vault)?;
        assert!(
            sync_state_value(&vault, &format!("dt:{}", id.to_hex()))?.is_none(),
            "{reason:?}: a fully-missing id must not gain a dt: hard-delete marker"
        );
        assert!(
            sync_state_keys_with_prefix_raw(&vault, "d:w:")?.is_empty(),
            "{reason:?}: no CRDT tombstone may be published for a fully-missing id"
        );
        assert_eq!(
            sync_queue_row_count_with_prefix(&vault, b"q:")?,
            0,
            "{reason:?}: no update queue row may exist for a fully-missing id"
        );
        assert_eq!(
            sync_queue_row_count_with_prefix(&vault, b"d:")?,
            0,
            "{reason:?}: no delete-bearing queue row may exist for a fully-missing id"
        );
    }
    Ok(())
}

/// ONE-1149 RACED-TO-NOTHING construction (delete-safety), DETERMINISTIC —
/// no timing sleep. Builds the RACED-TO-NOTHING case (scope existed at the
/// deleter's read-probe, then raced away before its purge txn), NOT the
/// FULLY-MISSING case (an id that never had scope). The eraser thread opens
/// the single LMDB write txn, STAGES the scope erasure inside it but leaves
/// it UNCOMMITTED (MVCC keeps it invisible to any read txn), then meets the
/// deleter at a `Barrier`. After the barrier the deleter takes its read
/// snapshot — a µs in-memory read that still sees the full scope because the
/// erasure is uncommitted — and blocks on the held write lock, while the
/// eraser commits (a ms-scale fsync). The read-vs-commit asymmetry makes the
/// deleter observe the pre-erase scope every run, so its purge txn
/// deterministically finds nothing once the eraser's commit lands. The
/// astronomically-rare scheduling miss (the deleter is descheduled until
/// after the commit) takes the FULLY-MISSING strict-noop path instead;
/// callers detect it via the absent `dt:` marker and retry.
fn run_raced_delete<F>(
    vault: &Vault,
    id: &EntityId,
    reason: DeleteReason,
    erase_scope: F,
) -> Result<DeleteEntityOutcome>
where
    F: FnOnce(&mut heed::RwTxn<'_>) -> Result<()>,
{
    run_raced_delete_inner(vault, id, reason, erase_scope, false)
}

/// ONE-1149 rendezvous variant: forces the deleter's lock-free
/// `read_entity_header` read to complete BEFORE the eraser commits, via the
/// `#[cfg(test)]` `AFTER_HEADER_READ` seam in `vault.rs`. The eraser `recv()`s
/// the deleter's post-header-read signal immediately before `commit()`, so the
/// HEADERFUL leg is exercised every run (the bare-barrier variant can rarely
/// lose the read-vs-commit race and divert to the headerless path). Only valid
/// for HEADERFUL deletes — the deleter MUST reach the signal after the header
/// gate; a headerless deleter never signals and would hang the recv.
fn run_raced_delete_rendezvous<F>(
    vault: &Vault,
    id: &EntityId,
    reason: DeleteReason,
    erase_scope: F,
) -> Result<DeleteEntityOutcome>
where
    F: FnOnce(&mut heed::RwTxn<'_>) -> Result<()>,
{
    run_raced_delete_inner(vault, id, reason, erase_scope, true)
}

fn run_raced_delete_inner<F>(
    vault: &Vault,
    id: &EntityId,
    reason: DeleteReason,
    erase_scope: F,
    rendezvous: bool,
) -> Result<DeleteEntityOutcome>
where
    F: FnOnce(&mut heed::RwTxn<'_>) -> Result<()>,
{
    let gate = std::sync::Arc::new(std::sync::Barrier::new(2));
    // ONE-1149 rendezvous: a rendezvous (`sync_channel(0)`) sender installed
    // into the production `#[cfg(test)]` seam. The deleter sends after it
    // proves the header `Some` (still holding no write lock); the eraser
    // recv()s just before its commit. Installed BEFORE the deleter is released
    // so the seam is armed by the time the header read happens.
    let rendezvous_rx = if rendezvous {
        let (tx, rx) = std::sync::mpsc::sync_channel::<()>(0);
        crate::vault::install_after_header_read_signal(tx);
        Some(rx)
    } else {
        None
    };
    std::thread::scope(|scope| -> Result<DeleteEntityOutcome> {
        let mut wtxn = vault.store.env.write_txn()?;
        // Stage the scope erasure in the held txn but DO NOT commit yet —
        // LMDB MVCC keeps it invisible to the deleter's read probe, so the
        // deleter is guaranteed to pass that probe with the scope present.
        erase_scope(&mut wtxn)?;
        let deleter_gate = std::sync::Arc::clone(&gate);
        let deleter = scope.spawn(move || {
            deleter_gate.wait();
            vault.delete_entity_with_reason(id, reason)
        });
        // Release the deleter; it reads its scope (still present) and blocks
        // on this thread's single write lock. Committing the erasure here
        // unblocks it into a purge txn that now deterministically finds
        // nothing to erase.
        gate.wait();
        if let Some(rx) = &rendezvous_rx {
            // Deadlock-free: the deleter reaches the post-header-read signal
            // BEFORE it needs any write lock, so this recv() unblocks; we then
            // commit (releasing the write lock the deleter's purge txn is
            // waiting on). deleter reads header present -> signals -> we commit
            // + release lock -> deleter's purge txn proceeds and finds the
            // scope scrubbed.
            rx.recv()
                .expect("deleter must signal after the header read");
        }
        wtxn.commit()?;
        deleter.join().expect("deleter thread must not panic")
    })
}

/// Shared assertions for both raced-to-nothing legs. `reason_byte` is the
/// pinned v2 wire byte for the reason under test.
fn assert_raced_delete_artifacts(
    vault: &Vault,
    outcome: &DeleteEntityOutcome,
    dt_marker: &[u8],
    reason_byte: u8,
) -> Result<()> {
    assert_eq!(
        *outcome,
        DeleteEntityOutcome {
            existed: false,
            receipt_id: None,
            sweep_key: None,
        },
        "a raced-to-nothing delete must report missing() with no receipt/sweep"
    );
    assert_no_erasure_audit_artifacts(vault)?;
    // The dt: marker IS allowed (hard-once-seen, mirrors the receiver-side
    // nothing-local branch) and carries the pinned 25 B v2 value
    // [reason:1][deleted_at:8 LE][request_id:16].
    assert_eq!(
        dt_marker.len(),
        25,
        "dt: marker value must be the pinned 25 B v2 tombstone layout"
    );
    assert_eq!(
        dt_marker[0], reason_byte,
        "dt: marker reason byte must be the pinned wire byte for the reason"
    );
    // The CRDT tombstone publish happened BEFORE the ownership claim and is
    // ALLOWED to survive: it is idempotent propagation intent, not an
    // erasure claim. In sync builds that means the d:w: snapshot plus
    // exactly one q:/d: delete-bearing queue pair; in non-sync builds
    // write_crdt_tombstone is a no-op, so nothing may exist.
    #[cfg(feature = "sync")]
    {
        assert!(
            !sync_state_keys_with_prefix_raw(vault, "d:w:")?.is_empty(),
            "sync build: the published CRDT tombstone snapshot legitimately survives"
        );
        assert_eq!(
            sync_queue_row_count_with_prefix(vault, b"q:")?,
            1,
            "sync build: exactly the delete's own queued update row"
        );
        assert_eq!(
            sync_queue_row_count_with_prefix(vault, b"d:")?,
            1,
            "sync build: exactly the delete's own delete-bearing sidecar row"
        );
    }
    #[cfg(not(feature = "sync"))]
    {
        assert!(
            sync_state_keys_with_prefix_raw(vault, "d:w:")?.is_empty(),
            "non-sync build: no CRDT snapshot rows exist"
        );
        assert_eq!(
            sync_queue_row_count_with_prefix(vault, b"q:")?,
            0,
            "non-sync build: no queue rows exist"
        );
        assert_eq!(
            sync_queue_row_count_with_prefix(vault, b"d:")?,
            0,
            "non-sync build: no delete-bearing rows exist"
        );
    }
    Ok(())
}

/// ONE-1149 headerless RACED-TO-NOTHING leg: a hard delete of orphan
/// residue whose scope existed at the read probe but is raced away before
/// the purge txn must NOT emit a receipt, sweep row, or `pt:` marker (the
/// pre-fix code emitted all three — a false GDPR audit). Only the guarded
/// `dt:` marker and the already-published idempotent CRDT tombstone (with
/// its `d:`/`q:` propagation rows) legitimately survive.
#[test]
fn headerless_delete_raced_to_nothing_emits_no_receipt_sweep_or_pt() -> Result<()> {
    let (_dir, vault) = open_test_vault();

    for attempt in 0..3 {
        let id = EntityId::now();
        vault.put_vector(&id, &[0.1, 0.2, 0.3, 0.4])?;

        let outcome = run_raced_delete(&vault, &id, DeleteReason::GdprDelete, |wtxn| {
            crate::hnsw::hnsw_deindex(&vault.store, wtxn, &id)?;
            vault.store.vectors.delete(wtxn, id.as_bytes())?;
            Ok(())
        })?;

        let Some(dt_marker) = sync_state_value(&vault, &format!("dt:{}", id.to_hex()))? else {
            // Scheduling miss: the deleter probed after the commit and took
            // the strict-noop path. Verify it wrote nothing, then retry.
            assert_eq!(outcome, DeleteEntityOutcome::missing());
            assert_no_erasure_audit_artifacts(&vault)?;
            assert!(
                attempt < 2,
                "raced branch was never constructed in 3 attempts"
            );
            continue;
        };

        // gdpr_delete pinned wire byte = 3.
        assert_raced_delete_artifacts(&vault, &outcome, &dt_marker, 3)?;
        return Ok(());
    }
    unreachable!("the attempt loop either returns or panics");
}

/// ONE-1149 headerful RACED-TO-NOTHING leg: a hard delete whose entity (and
/// full delete scope) existed at the header read but is raced away before
/// the purge txn must NOT emit a receipt, sweep row, or `pt:` marker. Only
/// the guarded `dt:` marker and the already-published idempotent CRDT
/// tombstone (with its `d:`/`q:` propagation rows) legitimately survive.
#[test]
fn headerful_delete_raced_to_nothing_emits_no_receipt_sweep_or_pt() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let learned_at = 1_772_000_000;

    for attempt in 0..3 {
        let id = EntityId::now();
        vault
            .batch()
            .put(
                &id,
                1,
                test_time_range(learned_at, learned_at),
                learned_at,
                b"raced-away-before-purge",
            )
            .commit()?;

        let outcome = run_raced_delete(&vault, &id, DeleteReason::UserHardDelete, |wtxn| {
            // Erase the FULL delete scope the way a racing hard delete would.
            crate::batch::deindex_entity(&vault.store, wtxn, &id)?;
            Ok(())
        })?;

        let Some(dt_marker) = sync_state_value(&vault, &format!("dt:{}", id.to_hex()))? else {
            assert_eq!(outcome, DeleteEntityOutcome::missing());
            assert_no_erasure_audit_artifacts(&vault)?;
            assert!(
                attempt < 2,
                "raced branch was never constructed in 3 attempts"
            );
            continue;
        };

        // user_hard_delete pinned wire byte = 2.
        assert_raced_delete_artifacts(&vault, &outcome, &dt_marker, 2)?;
        return Ok(());
    }
    unreachable!("the attempt loop either returns or panics");
}

/// ONE-1149 false-NEGATIVE guard (delete-safety): the headerful delete's
/// IN-TXN ownership probe checks the FULL delete scope, not just the
/// entities row. A headerful entity whose entities row is raced away while a
/// vector + a BM25 posting survive keeps `active_delete_scope_exists_in_txn`
/// TRUE, so the purge runs, the residue IS erased, and a REAL receipt is
/// emitted even though the outcome reports `existed:false` (the entities row
/// was already gone — the two meanings of "existed": entities-row erased vs
/// any-scope erased). A "gate the receipt on the entities-row `existed`" /
/// "return early on the missing header" implementation would skip the
/// receipt and silently erase the residue with NO audit — the mirror of the
/// raced-to-nothing false-POSITIVE this ticket also closes. `UserHardDelete`
/// is used deliberately: unlike `GdprDelete`/`PolicyDelete` it runs no
/// pre-purge SoftErase, so the vector + BM25 residue survives to the in-txn
/// probe.
///
/// DETERMINISM (ONE-1149 round-2): the deleter now races through the
/// `run_raced_delete_rendezvous` seam, which orders its lock-free
/// `read_entity_header` read BEFORE the eraser commit, so the HEADERFUL leg
/// runs EVERY run (the bare-barrier variant could rarely lose the
/// read-vs-commit race and divert to the headerless path, leaving this test
/// nondeterministic). With the headerful leg pinned, a DISCRIMINATOR assertion
/// proves the published CRDT tombstone landed in the HEADERFUL window
/// `window_label_from_timestamp(header.learned_at)` (computed from the entity's
/// stored `learned_at`), NOT the now-derived window the headerless leg
/// addresses (`window_label_from_timestamp(now)`). A wrong impl that takes the
/// headerless path lands the tombstone in the now-window and fails; a wrong
/// impl that early-returns on the missing header emits no receipt and fails the
/// receipt assertion — non-tautological in both directions.
#[test]
fn headerful_delete_partial_residue_survives_emits_receipt_existed_false() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let learned_at = 1_772_000_000;
    let id = EntityId::now();
    vault
        .batch()
        .put(
            &id,
            1,
            test_time_range(learned_at, learned_at),
            learned_at,
            b"partial-residue",
        )
        .text(&id, &[("body", "partial-residue")])
        .commit()?;
    vault.put_vector(&id, &[0.1, 0.2, 0.3, 0.4])?;
    assert_eq!(vault.search_text("partial-residue", 10)?.len(), 1);

    // DISCRIMINATOR setup: the headerful leg addresses the tombstone window by
    // the entity's stored `learned_at`; the headerless leg would address it by
    // `now`. Assert the two windows are genuinely different so the
    // discriminator below is meaningful (a same-window fixture would make the
    // assertion vacuous).
    let headerful_window = crate::deletion::window_label_from_timestamp(learned_at);
    let now_window = crate::deletion::window_label_from_timestamp(crate::unix_seconds_now());
    assert_ne!(
        headerful_window, now_window,
        "fixture invariant: learned_at must fall in a different window than now, \
         else the headerful-vs-headerless window discriminator is vacuous"
    );

    // The race erases ONLY the entities row (header), the way a concurrent
    // delete that lost the purge race would, leaving the vector + BM25
    // posting as live residue the in-txn full-scope probe must still catch.
    // The rendezvous seam forces the deleter's header read to win, so the
    // HEADERFUL leg runs deterministically every run.
    let outcome = run_raced_delete_rendezvous(&vault, &id, DeleteReason::UserHardDelete, |wtxn| {
        vault.store.entities.delete(wtxn, id.as_bytes())?;
        Ok(())
    })?;

    // existed:false (the entities row was raced away) BUT a real erasure
    // happened and is audited.
    assert!(
        !outcome.existed,
        "the entities row was raced away ⇒ outcome reports existed:false"
    );
    assert!(
        outcome.receipt_id.is_some(),
        "surviving residue ⇒ a REAL receipt is emitted (false-NEGATIVE guard)"
    );
    assert!(
        outcome.sweep_key.is_some(),
        "surviving residue ⇒ an h: sweep row is queued"
    );
    assert_eq!(
        redaction_audit_receipts(&vault)?.len(),
        1,
        "exactly one REDACTION_AUDIT receipt for the erased residue"
    );
    assert_eq!(
        hard_erase_sweep_rows(&vault)?.len(),
        1,
        "exactly one h: sweep row for the erased residue"
    );
    // The residue is actually erased — no leak past the audit.
    assert!(
        vault.get_vector(&id)?.is_none(),
        "the surviving vector residue must be purged"
    );
    assert!(
        vault.search_text("partial-residue", 10)?.is_empty(),
        "the surviving BM25 posting must be purged"
    );

    // DISCRIMINATOR: the published tombstone is addressed by the HEADERFUL
    // window (`learned_at`), proving the headerful leg ran. In sync builds the
    // CRDT tombstone snapshot is a `d:w:{window}` row; in non-sync builds
    // `write_crdt_tombstone` is a no-op so the surviving `pt:{window}:{id}`
    // pending-tombstone marker (kept because `crdt_persisted` is false) is the
    // window witness. Either way the window segment MUST be the headerful
    // window and never the now-window.
    #[cfg(feature = "sync")]
    {
        // The persisted snapshot key is exactly `d:w:{window}` (no trailing
        // colon — that's the `u:w:{window}:` update-row grammar).
        let dw_keys = sync_state_keys_with_prefix_raw(&vault, "d:w:")?;
        assert_eq!(
            dw_keys.len(),
            1,
            "exactly one CRDT tombstone snapshot row for the headerful delete"
        );
        assert_eq!(
            dw_keys[0],
            format!("d:w:{headerful_window}"),
            "the CRDT tombstone must land in the HEADERFUL window \
             (window_label_from_timestamp(header.learned_at)); a headerless-path \
             execution would key it to the now-window (d:w:{now_window}) instead"
        );
        assert_ne!(
            dw_keys[0],
            format!("d:w:{now_window}"),
            "the CRDT tombstone must NOT land in the now-window (the headerless leg's address)"
        );
    }
    #[cfg(not(feature = "sync"))]
    {
        let pt_keys = sync_state_keys_with_prefix_raw(&vault, "pt:")?;
        assert_eq!(
            pt_keys.len(),
            1,
            "non-sync: the pending-tombstone marker survives (crdt_persisted=false) \
             and is the headerful-window witness"
        );
        assert_eq!(
            pt_keys[0],
            format!("pt:{headerful_window}:{}", id.to_hex()),
            "the pt: marker must be keyed to the HEADERFUL window \
             (window_label_from_timestamp(header.learned_at)), never the now-window"
        );
    }
    Ok(())
}

/// ONE-1149 end-to-end convergence — the anti-(A) invariant (delete-safety).
/// A `GdprDelete` that LOSES the race to a tombstone-LESS full-scope batch
/// erase (`vault.batch().delete(E)` ⇒ `BatchOp::Delete` ⇒ `deindex_entity`,
/// which publishes NO CRDT tombstone) erases nothing locally — so it emits
/// no receipt / sweep / `pt:` (RACED-TO-NOTHING) — but it STILL publishes
/// its own CRDT tombstone + `d:`/`q:` propagation rows BEFORE claiming write
/// ownership. That published tombstone is the ONLY convergence net: the
/// rejected "reorder to `dt:`-only / suppress the tombstone publish"
/// implementation would leave NO propagating record, and a peer that still
/// holds E would keep it forever — a silently dropped GDPR delete. This test
/// pins that the origin's window, applied to a peer that still holds E,
/// purges E. (A wrong `dt:`-only impl FAILS the convergence assertion.)
#[cfg(feature = "sync")]
#[test]
fn raced_gdpr_delete_against_batch_delete_still_converges() -> Result<()> {
    use crate::sync::bridge::Materializer;
    use crate::sync::loro_support::map_contains_binary;
    use crate::sync::types::WindowKey;
    use crate::sync::window;

    let learned_at = 1_772_000_000;
    let window_key = WindowKey::from_timestamp(learned_at);

    for attempt in 0..3 {
        let (_dir, vault) = open_test_vault();
        let id = EntityId::now();
        vault
            .batch()
            .put(
                &id,
                1,
                test_time_range(learned_at, learned_at),
                learned_at,
                b"converge-secret",
            )
            .commit()?;

        // GdprDelete races the tombstone-LESS full-scope erase that
        // `BatchOp::Delete` performs (`deindex_entity`): the delete reads
        // E's header, the racer erases the whole scope, and the delete's
        // purge txn finds nothing.
        let outcome = run_raced_delete(&vault, &id, DeleteReason::GdprDelete, |wtxn| {
            crate::batch::deindex_entity(&vault.store, wtxn, &id)?;
            Ok(())
        })?;

        let Some(dt_marker) = sync_state_value(&vault, &format!("dt:{}", id.to_hex()))? else {
            // Scheduling miss: the deleter probed after the commit and took
            // the FULLY-MISSING strict-noop path. Verify, then retry.
            assert_eq!(outcome, DeleteEntityOutcome::missing());
            assert_no_erasure_audit_artifacts(&vault)?;
            assert!(
                attempt < 2,
                "raced branch was never constructed in 3 attempts"
            );
            continue;
        };

        // Origin RACED-TO-NOTHING: no false audit, but the convergent CRDT
        // tombstone + exactly one d:/q: propagation pair survive. gdpr_delete
        // pinned wire byte = 3.
        assert_raced_delete_artifacts(&vault, &outcome, &dt_marker, 3)?;
        let origin_doc = window::load_window_from_state(&vault, "origin", &window_key)?;
        assert!(
            map_contains_binary(&origin_doc.get_map("tombstones"), id.to_hex().as_str()),
            "the raced GdprDelete must still publish a convergent CRDT tombstone"
        );

        // A fresh peer still holds E; applying the origin window must
        // converge it away (the dropped-GDPR-delete net the anti-(A)
        // invariant guarantees).
        let (_peer_dir, peer) = open_test_vault();
        peer.batch()
            .put(
                &id,
                1,
                test_time_range(learned_at, learned_at),
                learned_at,
                b"converge-secret",
            )
            .commit()?;
        assert!(
            peer.get_raw(&id)?.is_some(),
            "peer fixture must hold E before convergence"
        );

        let materializer = Materializer::new();
        window::forward_rematerialize(&peer, &origin_doc, &materializer, &window_key)?;
        assert!(
            peer.get_raw(&id)?.is_none(),
            "applying the origin window to the peer must purge E (convergence net)"
        );
        return Ok(());
    }
    unreachable!("the attempt loop either returns or panics");
}

// ═══════════════════════════════════════════════════════════════════════
// ONE-1133 — reason-aware tombstone replay primitive
// (`Vault::apply_replayed_tombstone`): soft = shell-preserving SoftErase,
// hard/legacy/unknown/malformed = destructive purge + LOCAL receipt +
// LOCAL `h:` sweep row; never-downgrade on receive; D16 in the same txn.
// ═══════════════════════════════════════════════════════════════════════

/// Builds a v2 tombstone wire value from LITERAL parts (never via the
/// engine's encoder — these bytes are the test INPUT, and the layout under
/// test is the pinned `[reason:1][deleted_at:8 LE][request_id:16]`).
fn wire_tombstone(reason_byte: u8, deleted_at: u64, request_byte: u8) -> Vec<u8> {
    let mut value = vec![reason_byte];
    value.extend_from_slice(&deleted_at.to_le_bytes());
    value.extend_from_slice(&[request_byte; 16]);
    value
}

#[test]
fn replayed_soft_tombstone_keeps_shell_and_deindexes_without_receipt_or_sweep() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let id = EntityId::now();
    vault
        .batch()
        .put(&id, 1, test_time_range(10, 10), 20, b"replay-soft-secret")
        .text(&id, &[("body", "replay-soft-secret")])
        .commit()?;
    vault.put_vector(&id, &[0.1, 0.2, 0.3, 0.4])?;
    assert_eq!(vault.search_text("replay-soft-secret", 10)?.len(), 1);

    // reason byte 1 = user_delete (the ONLY soft wire reason).
    let outcome = vault.apply_replayed_tombstone(&id, &wire_tombstone(1, 1_771_027_200, 0x5A))?;
    assert_eq!(
        outcome,
        ReplayedTombstoneOutcome::SoftErased { changed: true }
    );

    // Shell-preserving SoftErase: the 25 B header row SURVIVES (a hard
    // purge of the row FAILS here), the payload and every retrieval index
    // entry are gone.
    let raw = vault
        .get_raw(&id)?
        .expect("user_delete replay must keep the 25 B shell");
    assert_eq!(raw.len(), ENTITY_METADATA_HEADER_LEN);
    assert_eq!(vault.get(&id)?.as_deref(), Some([].as_slice()));
    assert!(vault.search_text("replay-soft-secret", 10)?.is_empty());
    assert!(vault.get_vector(&id)?.is_none());
    assert!(vault.entities_by_type(1)?.contains(&id));

    // contracts.ts user_delete: receipt = false, historicalSweepQueued =
    // false — NO local receipt, NO h: sweep row.
    assert!(redaction_audit_receipts(&vault)?.is_empty());
    assert!(hard_erase_sweep_rows(&vault)?.is_empty());

    // Idempotent: re-applying the same soft value over the shell reports
    // no change (every-boot forward remat must not count it forever).
    let again = vault.apply_replayed_tombstone(&id, &wire_tombstone(1, 1_771_027_200, 0x5A))?;
    assert_eq!(
        again,
        ReplayedTombstoneOutcome::SoftErased { changed: false }
    );
    Ok(())
}

#[test]
fn replayed_hard_tombstone_purges_and_writes_local_receipt_and_sweep_row() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let id = EntityId::now();
    vault
        .batch()
        .put(&id, 1, test_time_range(30, 30), 40, b"Alice replay secret")
        .text(&id, &[("body", "Alice replay secret")])
        .commit()?;

    // reason byte 3 = gdpr_delete; deleted_at and request_id are literals.
    let value = wire_tombstone(3, 1_771_027_200, 0xAB);
    let outcome = vault.apply_replayed_tombstone(&id, &value)?;
    let ReplayedTombstoneOutcome::HardPurged {
        erased: true,
        receipt_id: Some(receipt_id),
        sweep_key: Some(sweep_key),
    } = outcome
    else {
        panic!("hard replay over local state must erase + receipt + sweep, got {outcome:?}");
    };

    // Destructive purge: row AND index entries gone (a shell-keeping
    // implementation FAILS here).
    assert!(vault.get_raw(&id)?.is_none());
    assert!(vault.search_text("replay", 10)?.is_empty());
    assert!(!vault.entities_by_type(1)?.contains(&id));

    // LOCAL receipt: request_id comes from the WIRE value (Art. 5(2)
    // correlation across replicas), reason from the wire byte, requested_at
    // from the wire deleted_at; minimization = opaque ids + timestamps only.
    let receipt_raw = vault.get_raw(&receipt_id)?.expect("local receipt");
    assert_no_receipt_payload_leak(&receipt_raw, &[b"Alice", b"replay secret"]);
    let receipt = receipt_body(&receipt_raw);
    assert_receipt_fields(&receipt);
    assert_eq!(receipt["reason"], "gdpr_delete");
    assert_eq!(
        receipt["request_id"], "abababab-abab-abab-abab-abababababab",
        "receipt request_id must be the wire value's UUID, hyphenated"
    );
    assert_eq!(receipt["requested_at"].as_u64(), Some(1_771_027_200));
    assert_eq!(receipt["scope"]["entity_ids"][0], id.to_hex());

    // LOCAL h:{seq:8BE} sweep row, deadline_at ≤ queued_at + 30 d
    // (GDPR Art. 12(3) one-month anchor — the ≤30 d clock must run on THIS
    // replica, not only on the origin device).
    assert!(sweep_key.starts_with(b"h:"));
    let rows = hard_erase_sweep_rows(&vault)?;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].0, sweep_key);
    let job: serde_json::Value = rmp_serde::from_slice(&rows[0].1).expect("decode sweep job");
    assert_eq!(job["scope"]["entity_ids"][0], id.to_hex());
    let queued_at = job["retry_state"]["queued_at"].as_u64().unwrap();
    let deadline_at = job["retry_state"]["deadline_at"].as_u64().unwrap();
    assert!(deadline_at >= queued_at);
    assert!(deadline_at <= queued_at + 30 * 86_400);
    assert_eq!(receipt["sweep_queued_at"].as_u64(), Some(queued_at));

    // Idempotent: nothing local remains, so re-applying the same tombstone
    // is a receipt-free no-op (every-boot replay must not multiply
    // receipts or sweep rows on one replica).
    let again = vault.apply_replayed_tombstone(&id, &value)?;
    assert_eq!(
        again,
        ReplayedTombstoneOutcome::HardPurged {
            erased: false,
            receipt_id: None,
            sweep_key: None,
        }
    );
    assert_eq!(redaction_audit_receipts(&vault)?.len(), 1);
    assert_eq!(hard_erase_sweep_rows(&vault)?.len(), 1);
    Ok(())
}

/// Every non-soft wire shape — legacy 8-byte, reserved byte 0, unknown
/// reason byte, malformed length — replays as a DESTRUCTIVE purge
/// (fail-closed: ambiguity resolves to MORE deletion, never less), with the
/// pinned receipt fallbacks: reason = `user_hard_delete` (the engine's
/// destructive default) and request_id = the wire UUID when the value
/// carried one, else the NIL UUID (never a fabricated identifier).
#[test]
fn replayed_ambiguous_tombstones_hard_purge_with_fail_closed_receipt() -> Result<()> {
    struct Case {
        name: &'static str,
        value: Vec<u8>,
        want_request_id: &'static str,
        want_requested_at: u64,
    }
    let cases = [
        Case {
            name: "legacy 8-byte",
            value: 1_771_000_000_u64.to_le_bytes().to_vec(),
            want_request_id: "00000000-0000-0000-0000-000000000000",
            want_requested_at: 1_771_000_000,
        },
        Case {
            name: "reserved byte 0",
            value: wire_tombstone(0, 1_771_000_111, 0x11),
            want_request_id: "11111111-1111-1111-1111-111111111111",
            want_requested_at: 1_771_000_111,
        },
        Case {
            name: "unknown reason byte 9",
            value: wire_tombstone(9, 1_771_000_222, 0x22),
            want_request_id: "22222222-2222-2222-2222-222222222222",
            want_requested_at: 1_771_000_222,
        },
        Case {
            name: "malformed 26-byte",
            value: vec![7_u8; 26],
            want_request_id: "00000000-0000-0000-0000-000000000000",
            want_requested_at: 0,
        },
    ];

    for case in cases {
        let (_dir, vault) = open_test_vault();
        let id = EntityId::now();
        vault.put_entity(&id, 1, test_time_range(50, 50), 60, b"ambiguous-target")?;

        let outcome = vault.apply_replayed_tombstone(&id, &case.value)?;
        let ReplayedTombstoneOutcome::HardPurged {
            erased: true,
            receipt_id: Some(receipt_id),
            sweep_key: Some(_),
        } = outcome
        else {
            panic!(
                "{}: must hard-purge with receipt, got {outcome:?}",
                case.name
            );
        };
        assert!(vault.get_raw(&id)?.is_none(), "{}", case.name);

        let receipt = receipt_body(&vault.get_raw(&receipt_id)?.expect("receipt"));
        assert_eq!(receipt["reason"], "user_hard_delete", "{}", case.name);
        assert_eq!(receipt["request_id"], case.want_request_id, "{}", case.name);
        assert_eq!(
            receipt["requested_at"].as_u64(),
            Some(case.want_requested_at),
            "{}",
            case.name
        );
        assert_eq!(hard_erase_sweep_rows(&vault)?.len(), 1, "{}", case.name);
    }
    Ok(())
}

/// Never-downgrade on receive: a SOFT tombstone replayed for an id this
/// replica already hard-purged is a strict no-op — it must NOT recreate a
/// shell, mint a receipt, or queue a sweep row.
#[test]
fn replayed_soft_tombstone_after_hard_purge_is_noop() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let id = EntityId::now();
    vault.put_entity(&id, 1, test_time_range(70, 70), 80, b"downgrade-target")?;

    // Hard apply first (reason byte 2 = user_hard_delete).
    let hard = vault.apply_replayed_tombstone(&id, &wire_tombstone(2, 1_771_100_000, 0xDD))?;
    assert!(hard.changed_local_state());
    assert!(vault.get_raw(&id)?.is_none());
    assert_eq!(redaction_audit_receipts(&vault)?.len(), 1);
    assert_eq!(hard_erase_sweep_rows(&vault)?.len(), 1);

    // Stale/concurrent soft value arrives after the hard purge.
    let soft = vault.apply_replayed_tombstone(&id, &wire_tombstone(1, 1_771_200_000, 0x99))?;
    assert_eq!(
        soft,
        ReplayedTombstoneOutcome::SoftErased { changed: false }
    );
    assert!(
        vault.get_raw(&id)?.is_none(),
        "a replayed soft tombstone must never resurrect a shell for a hard-purged id"
    );
    assert_eq!(redaction_audit_receipts(&vault)?.len(), 1);
    assert_eq!(hard_erase_sweep_rows(&vault)?.len(), 1);
    assert!(!vault.entities_by_type(1)?.contains(&id));
    Ok(())
}

/// ARCH-0038 D16 on the REPLAY path (the M2-flagged replica staleness bug):
/// a replayed tombstone on an `edge.provenance` Claim refreshes the subject
/// edge in the SAME transaction — winner restamp on hard, downgrade-to-bare
/// when the soft erase scrubs the last live Claim. The sweep row carries the
/// pre-purge captured opaque refs.
#[test]
fn replayed_tombstone_on_provenance_claim_runs_d16_refresh() -> Result<()> {
    let fx = lifecycle_fixture()?;
    let vault = &fx.vault;
    let subject = fx.subject;
    let person2 = EntityId::now();
    vault.put_entity(&person2, 4, test_time_range(1, 1), 1, b"person2")?;

    // Live tie cohort @ learned_at 2000: `winner` (conf 0.6,
    // confirmed/system) outranks `runner_up` (conf 0.4, disputed/agent).
    let winner = EntityId::now();
    let mut winner_body =
        EdgeProvenanceClaimBody::new(fx.machine, 0.6, SupersessionStatus::Confirmed);
    winner_body.source_revision_ref = Some([0x61; 16]);
    winner_body.body_snapshot_ref = Some([0x62; 16]);
    vault.put_edge_provenance(
        &winner,
        &subject,
        &winner_body,
        EdgeActorClass::System,
        2_000,
    )?;
    let runner_up = EntityId::now();
    vault.put_edge_provenance(
        &runner_up,
        &subject,
        &EdgeProvenanceClaimBody::new(person2, 0.4, SupersessionStatus::Disputed),
        EdgeActorClass::Agent,
        2_000,
    )?;
    let (before, _) = raw_edge_values(vault, &subject)?;
    let before = before.expect("stamped edge");
    assert_eq!((before[24], before[25]), (1, 2), "winner stamps pre-replay");

    // Remote HARD tombstone for the WINNER claim: purge + D16 restamp from
    // the surviving runner-up in the same txn. A bare-purge replay (the
    // pre-ONE-1133 behavior) leaves the stale (1, 2) stamp and FAILS here.
    let outcome =
        vault.apply_replayed_tombstone(&winner, &wire_tombstone(2, 1_771_300_000, 0xC1))?;
    assert!(outcome.changed_local_state());
    assert!(vault.get(&winner)?.is_none(), "claim entity hard-purged");
    let (out, inn) = raw_edge_values(vault, &subject)?;
    let out = out.expect("edges_out row survives the claim replay");
    assert_eq!(out.len(), EDGE_VALUE_SEMANTIC_PROVENANCED_LEN);
    assert_eq!(
        (out[24], out[25]),
        (2, 1),
        "restamped from the surviving runner-up (disputed/agent)"
    );
    assert_eq!(&out[..24], &before[..24], "first 24 bytes preserved");
    assert_eq!(inn.as_deref(), Some(out.as_slice()));

    // The queued sweep row rode the PRE-purge captured opaque refs
    // (ARCH-0038 delete-interplay: refs are only readable before the purge).
    let rows = hard_erase_sweep_rows(vault)?;
    assert_eq!(rows.len(), 1);
    let job: serde_json::Value = rmp_serde::from_slice(&rows[0].1).expect("decode sweep job");
    assert_eq!(
        job["scope"]["revision_ids"][0],
        crate::types::bytes_to_hex_lower(&[0x61; 16])
    );
    assert_eq!(
        job["scope"]["body_snapshot_refs"][0],
        crate::types::bytes_to_hex_lower(&[0x62; 16])
    );

    // Remote SOFT tombstone for the RUNNER-UP: shell + D16 downgrade-to-bare
    // (no live Claim of any lifecycle survives) — still no NEW receipt.
    let outcome =
        vault.apply_replayed_tombstone(&runner_up, &wire_tombstone(1, 1_771_300_100, 0xC2))?;
    assert_eq!(
        outcome,
        ReplayedTombstoneOutcome::SoftErased { changed: true }
    );
    assert_eq!(
        vault.get(&runner_up)?.as_deref(),
        Some([].as_slice()),
        "soft replay keeps the 25 B Claim shell"
    );
    let (out, inn) = raw_edge_values(vault, &subject)?;
    let out = out.expect("edges_out row survives");
    assert_eq!(out.len(), EDGE_VALUE_SEMANTIC_LEN, "26 B → 24 B downgrade");
    assert_eq!(out.as_slice(), &before[..24]);
    assert_eq!(inn.as_deref(), Some(out.as_slice()));
    assert_eq!(
        redaction_audit_receipts(vault)?.len(),
        1,
        "the soft replay must not mint a second receipt"
    );
    assert_eq!(hard_erase_sweep_rows(vault)?.len(), 1);
    Ok(())
}

/// ONE-1090 write side (ONE-1132 AC3) — CONTRACT CORRECTION: replaces
/// `user_delete_soft_shell_survives_sync_rematerialization`, which pinned
/// the pre-ONE-1090 gap where a soft delete left NO CRDT record at all (so
/// the deleted body stayed live on every other device forever).
///
/// `user_delete` now writes a reason=user_delete v2 tombstone into the
/// window doc and removes the live `entities[id]` map copy (the full body
/// bytes in that map are an ACTIVE carrier of content the user deleted).
/// Local shell semantics are unchanged: the body scrub keeps the 25 B
/// shell. The receiver-side soft/hard branch is ONE-1133
/// (`Vault::apply_replayed_tombstone`): a known-soft value keeps the remote
/// replica's 25 B shell; everything else stays a fail-closed hard purge.
#[cfg(feature = "sync")]
#[test]
fn user_delete_writes_soft_v2_tombstone_into_crdt() -> Result<()> {
    use crate::sync::loro_support::{map_contains_binary, map_get_bytes};
    use crate::sync::types::WindowKey;
    use crate::sync::window;

    let (_dir, vault) = open_test_vault();
    let id = EntityId::now();
    let learned_at = 1_772_000_000;

    vault
        .batch()
        .put(
            &id,
            1,
            test_time_range(learned_at, learned_at),
            learned_at,
            b"soft-delete-sync-body",
        )
        .commit()?;

    let outcome = vault.delete_entity_with_reason(&id, DeleteReason::UserDelete)?;
    assert!(outcome.existed);
    assert_eq!(
        vault.get(&id)?.as_deref(),
        Some([].as_slice()),
        "user_delete keeps the local 25 B shell (D16 scrub semantics unchanged)"
    );

    let window_key = WindowKey::from_timestamp(learned_at);
    let doc = window::load_window_from_state(&vault, "local", &window_key)?;

    let tombstones = doc.get_map("tombstones");
    let value = map_get_bytes(&tombstones, id.to_hex().as_str())
        .expect("user_delete must write a CRDT tombstone (ONE-1090 write side)");
    assert_eq!(value.len(), 25, "tombstone value must be the v2 layout");
    assert_eq!(
        value[0], 1,
        "reason must be the pinned user_delete wire byte (soft)"
    );
    assert!(
        !map_contains_binary(&doc.get_map("entities"), id.to_hex().as_str()),
        "the live entities-map copy is an active carrier and must be removed"
    );

    // The pt: crash marker is cleared once the CRDT record is persisted.
    let pt_key = format!("pt:{window_key}:{}", id.to_hex());
    assert!(
        vault.sync_state_get(&pt_key)?.is_none(),
        "pending-tombstone marker must be cleared after CRDT persistence"
    );
    Ok(())
}

#[cfg(feature = "sync")]
#[test]
fn hard_delete_persists_crdt_tombstone_before_active_purge() -> Result<()> {
    use crate::sync::loro_support::map_contains_binary;
    use crate::sync::types::WindowKey;
    use crate::sync::window;

    let (_dir, vault) = open_test_vault();
    let id = EntityId::now();
    let target = EntityId::now();
    let learned_at = 1_772_000_000;

    vault
        .batch()
        .put(
            &id,
            1,
            test_time_range(learned_at, learned_at),
            learned_at,
            b"must-tombstone-before-purge",
        )
        .commit()?;
    vault.with_write_txn(|wtxn| {
        let key = Store::encode_edge_key(&id, EdgeKind::Supports, &target);
        vault.store.edges_out.put(wtxn, &key, &[0_u8; 3])?;
        Ok(())
    })?;

    let err = vault
        .delete_entity_with_reason(&id, DeleteReason::UserHardDelete)
        .expect_err("corrupted edge record should fail active purge");
    assert_matches!(err, Error::CorruptedIndex("edge record"));
    assert!(
        vault.entity_exists(&id)?,
        "active purge failed, so entity payload should remain for retry"
    );

    let window_key = WindowKey::from_timestamp(learned_at);
    let doc = window::load_window_from_state(&vault, "local", &window_key)?;
    let tombstones = doc.get_map("tombstones");
    assert!(
        map_contains_binary(&tombstones, id.to_hex().as_str()),
        "CRDT tombstone must persist before destructive purge starts"
    );
    Ok(())
}

/// Regression: `learned_at` is caller-supplied, and the hard-delete
/// tombstone path routes it through `WindowKey::from_timestamp`. A
/// far-future timestamp previously either hung (one loop iteration per
/// year toward ~year 292e9) or produced a window key outside the pinned
/// ARCH-0023b `YYYY-MM` format, so the tombstone-first guarantee silently
/// broke: the `d:w:…` row landed under a key every validated reader
/// rejects. The delete must complete promptly and persist its tombstone in
/// the clamped, format-valid "9999-12" window.
#[cfg(feature = "sync")]
#[test]
fn hard_delete_with_far_future_learned_at_tombstones_into_valid_window() -> Result<()> {
    use crate::sync::loro_support::map_contains_binary;
    use crate::sync::types::WindowKey;
    use crate::sync::window;

    let (_dir, vault) = open_test_vault();
    let id = EntityId::now();

    vault
        .batch()
        .put(
            &id,
            1,
            test_time_range(u64::MAX, u64::MAX),
            u64::MAX,
            b"far-future-learned-at",
        )
        .commit()?;

    let outcome = vault.delete_entity_with_reason(&id, DeleteReason::GdprDelete)?;
    assert!(outcome.existed);
    assert!(outcome.receipt_id.is_some());
    assert!(vault.get(&id)?.is_none());

    let window_key = WindowKey::from_timestamp(u64::MAX);
    assert_eq!(window_key.as_str(), "9999-12");
    let doc = window::load_window_from_state(&vault, "local", &window_key)?;
    let tombstones = doc.get_map("tombstones");
    assert!(
        map_contains_binary(&tombstones, id.to_hex().as_str()),
        "tombstone must land in the clamped format-valid window"
    );
    Ok(())
}

/// Reads the raw `pt:{window}:{hex}` pending-tombstone marker (ONE-1132).
#[cfg(not(feature = "sync"))]
fn pending_tombstone_row(vault: &Vault, window: &str, id: &EntityId) -> Result<Option<Vec<u8>>> {
    let rtxn = vault.store.env.read_txn()?;
    let key = format!("pt:{window}:{}", id.to_hex());
    Ok(vault.store.sync_state.get(&rtxn, &key)?.map(<[u8]>::to_vec))
}

/// ONE-1132 OWNER-DECISION (cfg-off durability): a build WITHOUT the `sync`
/// feature cannot write the CRDT tombstone, so the purge txn's
/// CRDT-independent `pt:` marker must SURVIVE the delete — it is the
/// deletion's only durable propagation intent until a sync-enabled boot
/// replays it. Asserts the exact pinned v2 value layout and that the
/// embedded request_id correlates with the REDACTION_AUDIT receipt.
#[cfg(not(feature = "sync"))]
#[test]
fn hard_delete_without_sync_feature_leaves_pending_tombstone_marker() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let id = EntityId::now();
    // 2026-02-15 ≈ unix 1_771_027_200 ⇒ window label "2026-02".
    let learned_at = 1_771_027_200;
    vault.put_entity(
        &id,
        1,
        test_time_range(learned_at, learned_at),
        learned_at,
        b"cfg-off-durability",
    )?;

    let outcome = vault.delete_entity_with_reason(&id, DeleteReason::UserHardDelete)?;
    assert!(outcome.existed);
    let receipt_raw = vault
        .get_raw(&outcome.receipt_id.expect("receipt id"))?
        .expect("receipt raw");
    let receipt = receipt_body(&receipt_raw);

    let value = pending_tombstone_row(&vault, "2026-02", &id)?
        .expect("pt: marker must survive a hard delete in a sync-OFF build");
    assert_eq!(value.len(), 25, "marker value must be the v2 layout");
    assert_eq!(
        value[0], 2,
        "reason must be the pinned user_hard_delete wire byte"
    );
    let deleted_at = u64::from_le_bytes(value[1..9].try_into().expect("8-byte slice"));
    assert_eq!(
        deleted_at,
        receipt["requested_at"].as_u64().expect("requested_at"),
        "deleted_at must be the deletion request time (u64 LE at offset 1)"
    );
    let receipt_request_hex = receipt["request_id"]
        .as_str()
        .expect("request_id")
        .replace('-', "");
    let marker_request_hex: String = value[9..25].iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(
        marker_request_hex, receipt_request_hex,
        "tombstone request_id must correlate with the receipt's request_id"
    );
    Ok(())
}

/// ONE-1132: `user_delete` in a sync-OFF build leaves a SOFT (reason byte 1)
/// pending-tombstone marker in the same txn as the shell scrub, while the
/// local shell semantics stay unchanged.
#[cfg(not(feature = "sync"))]
#[test]
fn user_delete_without_sync_feature_leaves_soft_pending_tombstone_marker() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let id = EntityId::now();
    let learned_at = 1_771_027_200;
    vault.put_entity(
        &id,
        1,
        test_time_range(learned_at, learned_at),
        learned_at,
        b"cfg-off-soft-delete",
    )?;

    let outcome = vault.delete_entity_with_reason(&id, DeleteReason::UserDelete)?;
    assert!(outcome.existed);
    assert_eq!(
        vault.get(&id)?.as_deref(),
        Some([].as_slice()),
        "shell semantics unchanged"
    );

    let value = pending_tombstone_row(&vault, "2026-02", &id)?
        .expect("pt: marker must survive a user_delete in a sync-OFF build");
    assert_eq!(value.len(), 25);
    assert_eq!(
        value[0], 1,
        "reason must be the pinned user_delete wire byte"
    );
    Ok(())
}

#[test]
fn put_get_vectors_and_validate_dimensions() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let id = EntityId::now();
    let vector = [0.1_f32, 0.2, 0.3, 0.4];

    vault.put_vector(&id, &vector)?;
    let got = vault.get_vector(&id)?.ok_or(Error::EntityNotFound)?;
    assert_eq!(got, vector);

    let bad = [1.0_f32, 2.0, 3.0];
    let err = vault
        .put_vector(&EntityId::now(), &bad)
        .expect_err("expected dimension mismatch");
    assert_matches!(
        err,
        Error::DimensionMismatch {
            expected: 4,
            got: 3
        }
    );

    Ok(())
}

#[test]
fn put_vector_routes_through_hnsw_insert() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let id = EntityId::now();
    let vector = [0.1_f32, 0.2, 0.3, 0.4];

    vault.put_vector(&id, &vector)?;

    let rtxn = vault.store.env.read_txn()?;
    let count_raw = vault
        .store
        .hnsw_meta
        .get(&rtxn, b"count")?
        .ok_or(Error::EntityNotFound)?;
    let count = u64::from_le_bytes(count_raw.try_into().map_err(|_| Error::InvalidKey)?);
    assert_eq!(count, 1);

    let entry_point = vault
        .store
        .hnsw_meta
        .get(&rtxn, b"entry_point")?
        .ok_or(Error::EntityNotFound)?;
    assert_eq!(entry_point, id.as_bytes());

    assert!(
        vault
            .store
            .hnsw_neighbors
            .get(&rtxn, id.as_bytes())?
            .is_some()
    );
    Ok(())
}

#[test]
fn vector_version_bumps_once_per_batch_commit() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let a = EntityId::now();
    let b = EntityId::now();

    assert_eq!(read_hnsw_meta_u64(&vault, VECTOR_VERSION_KEY)?, 0);

    vault
        .batch()
        .vector(&a, &[0.1_f32, 0.2, 0.3, 0.4])
        .vector(&b, &[0.4_f32, 0.3, 0.2, 0.1])
        .commit()?;
    assert_eq!(read_hnsw_meta_u64(&vault, VECTOR_VERSION_KEY)?, 1);

    vault.batch().delete(&a).delete(&b).commit()?;
    assert_eq!(read_hnsw_meta_u64(&vault, VECTOR_VERSION_KEY)?, 2);
    Ok(())
}

#[test]
fn search_vector_empty_graph_and_dimension_validation() -> Result<()> {
    let (_dir, vault) = open_test_vault();

    let empty = vault.search_vector(&[0.1_f32, 0.2, 0.3, 0.4], 10)?;
    assert!(empty.is_empty());

    let err = vault
        .search_vector(&[1.0_f32, 2.0, 3.0], 5)
        .expect_err("expected dimension mismatch");
    assert_matches!(
        err,
        Error::DimensionMismatch {
            expected: 4,
            got: 3
        }
    );
    Ok(())
}

#[test]
fn search_vector_skips_deleted_nodes() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let entry = EntityId::now();
    let deleted = EntityId::now();
    let live = EntityId::now();

    for id in [entry, deleted, live] {
        vault.put_entity(&id, 1, test_time_range(1, 1), 1, b"vector-node")?;
    }

    vault.put_vector(&entry, &[1.0_f32, 0.0, 0.0, 0.0])?;
    vault.put_vector(&deleted, &[0.98_f32, 0.05, 0.0, 0.0])?;
    vault.put_vector(&live, &[0.0_f32, 1.0, 0.0, 0.0])?;

    assert!(vault.delete_entity(&deleted)?);

    let results = vault.search_vector(&[0.98_f32, 0.05, 0.0, 0.0], 3)?;
    assert!(!results.iter().any(|item| item.id == deleted));
    assert!(results.iter().any(|item| item.id == entry));
    Ok(())
}

#[test]
fn search_vector_ignores_reserved_sentinel_neighbors() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let entry = EntityId::now();
    let live = EntityId::now();

    vault.put_entity(&entry, 1, test_time_range(1, 1), 1, b"entry")?;
    vault.put_entity(&live, 1, test_time_range(1, 1), 1, b"live")?;
    vault.put_vector(&entry, &[1.0_f32, 0.0, 0.0, 0.0])?;
    vault.put_vector(&live, &[0.0_f32, 1.0, 0.0, 0.0])?;

    let mut corrupted = Vec::with_capacity(ENTITY_ID_LEN * 2);
    corrupted.extend_from_slice(&[0x00; ENTITY_ID_LEN]);
    corrupted.extend_from_slice(live.as_bytes());

    let mut wtxn = vault.store.env.write_txn()?;
    vault
        .store
        .hnsw_neighbors
        .put(&mut wtxn, entry.as_bytes(), &corrupted)?;
    wtxn.commit()?;

    let results = vault.search_vector(&[0.0_f32, 1.0, 0.0, 0.0], 5)?;
    assert!(results.iter().any(|item| item.id == live));
    Ok(())
}

#[test]
fn search_after_entry_point_deleted() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let entry = EntityId::now();
    let survivor = EntityId::now();

    vault.put_entity(&entry, 1, test_time_range(1, 1), 1, b"entry")?;
    vault.put_entity(&survivor, 1, test_time_range(1, 1), 1, b"survivor")?;
    vault.put_vector(&entry, &[1.0_f32, 0.0, 0.0, 0.0])?;
    vault.put_vector(&survivor, &[0.0_f32, 1.0, 0.0, 0.0])?;

    assert_eq!(vault.search_vector(&[1.0_f32, 0.0, 0.0, 0.0], 5)?.len(), 2);
    assert!(vault.delete_entity(&entry)?);

    let results = vault.search_vector(&[0.0_f32, 1.0, 0.0, 0.0], 5)?;
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].id, survivor);

    Ok(())
}

#[test]
fn validates_non_finite_vector_and_edge_weights() {
    let (_dir, vault) = open_test_vault();

    let vector_err = vault
        .put_vector(&EntityId::now(), &[1.0_f32, f32::NAN, 2.0, 3.0])
        .expect_err("expected invalid vector");
    let vector_message = vector_err.to_string();
    let Error::InvalidVector { index, value } = vector_err else {
        panic!("expected invalid vector, got {vector_err:?}");
    };
    assert_eq!(index, 1);
    assert!(value.is_nan());
    assert!(vector_message.contains("index 1"));
    assert!(vector_message.contains("NaN"));

    let edge_err = vault
        .put_edge(
            &EntityId::now(),
            EdgeKind::Supports,
            &EntityId::now(),
            f32::INFINITY,
        )
        .expect_err("expected invalid edge weight");
    let edge_message = edge_err.to_string();
    let Error::InvalidEdgeWeight { value } = edge_err else {
        panic!("expected invalid edge weight, got {edge_err:?}");
    };
    assert!(value.is_infinite());
    assert!(edge_message.contains("inf"));
}

#[test]
fn error_kind_and_retryable_classify_validation_errors() {
    let vector = Error::InvalidVector {
        index: 0,
        value: f32::NAN,
    };
    assert_eq!(vector.kind(), ErrorKind::InvalidVector);
    assert!(!vector.is_retryable());

    let concurrent = Error::ConcurrentWrite("retry maintenance");
    assert_eq!(concurrent.kind(), ErrorKind::ConcurrentWrite);
    assert!(concurrent.is_retryable());

    let timeout = Error::Io(std::io::Error::from(std::io::ErrorKind::TimedOut));
    assert_eq!(timeout.kind(), ErrorKind::Io);
    assert!(timeout.is_retryable());
}

#[test]
fn hnsw_recall_at_10_vs_bruteforce() -> Result<()> {
    const DIMENSIONS: usize = 128;
    const NODE_COUNT: usize = 1_000;
    const LIMIT: usize = 10;
    const QUERY_COUNT: usize = 25;

    let temp_dir = tempfile::tempdir()?;
    let mut config = test_config();
    config.dimensions = DIMENSIONS;
    config.map_size = 128 * 1024 * 1024;
    config.hnsw.m_max_0 = 64;
    config.hnsw.ef_construction = 256;
    config.hnsw.ef_search = 256;

    let vault = Vault::open(temp_dir.path(), config)?;
    let mut rng = StdRng::seed_from_u64(42);
    let mut corpus = Vec::with_capacity(NODE_COUNT);

    let insert_started = Instant::now();
    for _ in 0..NODE_COUNT {
        let id = EntityId::now();
        let vector: Vec<f32> = (0..DIMENSIONS)
            .map(|_| rng.gen_range(-1.0_f32..1.0_f32))
            .collect();

        vault.put_entity(&id, 1, test_time_range(1, 1), 1, b"recall-node")?;
        vault.put_vector(&id, &vector)?;
        corpus.push((id, vector));
    }
    let insert_elapsed = insert_started.elapsed();

    let search_started = Instant::now();
    let mut recall_sum = 0.0_f32;
    for query_idx in 0..QUERY_COUNT {
        let stride = NODE_COUNT / QUERY_COUNT;
        let query_vector = &corpus[query_idx * stride].1;

        let ann = vault.search_vector(query_vector, LIMIT)?;
        let ann_ids: HashSet<EntityId> = ann.iter().map(|item| item.id).collect();

        let mut brute_force: Vec<(EntityId, f32)> = corpus
            .iter()
            .map(|(id, vector)| (*id, crate::distance::cosine_distance(query_vector, vector)))
            .collect();
        brute_force.sort_by(|left, right| {
            left.1
                .total_cmp(&right.1)
                .then_with(|| left.0.as_bytes().cmp(right.0.as_bytes()))
        });

        let brute_ids: HashSet<EntityId> =
            brute_force.iter().take(LIMIT).map(|(id, _)| *id).collect();
        let hits = brute_ids.intersection(&ann_ids).count();
        recall_sum += hits as f32 / LIMIT as f32;
    }
    let search_elapsed = search_started.elapsed();

    let recall_at_10 = recall_sum / QUERY_COUNT as f32;
    eprintln!(
        "hnsw recall@10={recall_at_10:.4}, insert_ms={}, search_ms={}",
        insert_elapsed.as_millis(),
        search_elapsed.as_millis()
    );

    assert!(
        recall_at_10 > 0.95,
        "expected recall@10 > 0.95, got {recall_at_10:.4}"
    );

    Ok(())
}

/// ONE-324 AC9: recall under refresh churn. Re-puts ≥ 10% of the vault's
/// vectors with new values through the localized symmetric refresh path,
/// then requires recall@10 vs brute force on the UPDATED corpus to stay
/// above the same 0.95 gate as the build-time recall test.
#[test]
fn hnsw_recall_at_10_after_refresh_churn() -> Result<()> {
    const DIMENSIONS: usize = 128;
    const NODE_COUNT: usize = 1_000;
    const CHURN_COUNT: usize = 100; // 10% of the vault
    const LIMIT: usize = 10;
    const QUERY_COUNT: usize = 25;

    let temp_dir = tempfile::tempdir()?;
    let mut config = test_config();
    config.dimensions = DIMENSIONS;
    config.map_size = 128 * 1024 * 1024;
    config.hnsw.m_max_0 = 64;
    config.hnsw.ef_construction = 256;
    config.hnsw.ef_search = 256;

    let vault = Vault::open(temp_dir.path(), config)?;
    let mut rng = StdRng::seed_from_u64(43);
    let mut corpus = Vec::with_capacity(NODE_COUNT);

    for _ in 0..NODE_COUNT {
        let id = EntityId::now();
        let vector: Vec<f32> = (0..DIMENSIONS)
            .map(|_| rng.gen_range(-1.0_f32..1.0_f32))
            .collect();

        vault.put_entity(&id, 1, test_time_range(1, 1), 1, b"churn-node")?;
        vault.put_vector(&id, &vector)?;
        corpus.push((id, vector));
    }

    let refresh_started = Instant::now();
    let stride = NODE_COUNT / CHURN_COUNT;
    for churn_idx in 0..CHURN_COUNT {
        let corpus_idx = churn_idx * stride;
        let new_vector: Vec<f32> = (0..DIMENSIONS)
            .map(|_| rng.gen_range(-1.0_f32..1.0_f32))
            .collect();
        let id = corpus[corpus_idx].0;
        vault.put_vector(&id, &new_vector)?;
        corpus[corpus_idx].1 = new_vector;
    }
    let refresh_elapsed = refresh_started.elapsed();

    // The vault is API-built, so every re-put must take the localized
    // refresh path — count stays exact and no node may be lost.
    {
        let rtxn = vault.store.env.read_txn()?;
        let count_raw = vault
            .store
            .hnsw_meta
            .get(&rtxn, b"count")?
            .ok_or(Error::EntityNotFound)?;
        let count = u64::from_le_bytes(count_raw.try_into().map_err(|_| Error::InvalidKey)?);
        assert_eq!(count, NODE_COUNT as u64);
    }

    let mut recall_sum = 0.0_f32;
    for query_idx in 0..QUERY_COUNT {
        let stride = NODE_COUNT / QUERY_COUNT;
        let query_vector = &corpus[query_idx * stride].1;

        let ann = vault.search_vector(query_vector, LIMIT)?;
        let ann_ids: HashSet<EntityId> = ann.iter().map(|item| item.id).collect();

        let mut brute_force: Vec<(EntityId, f32)> = corpus
            .iter()
            .map(|(id, vector)| (*id, crate::distance::cosine_distance(query_vector, vector)))
            .collect();
        brute_force.sort_by(|left, right| {
            left.1
                .total_cmp(&right.1)
                .then_with(|| left.0.as_bytes().cmp(right.0.as_bytes()))
        });

        let brute_ids: HashSet<EntityId> =
            brute_force.iter().take(LIMIT).map(|(id, _)| *id).collect();
        let hits = brute_ids.intersection(&ann_ids).count();
        recall_sum += hits as f32 / LIMIT as f32;
    }

    let recall_at_10 = recall_sum / QUERY_COUNT as f32;
    eprintln!(
        "refresh-churn recall@10={recall_at_10:.4}, churn={CHURN_COUNT}/{NODE_COUNT}, refresh_ms={}",
        refresh_elapsed.as_millis()
    );

    assert!(
        recall_at_10 > 0.95,
        "expected refresh-churn recall@10 > 0.95, got {recall_at_10:.4}"
    );

    Ok(())
}

#[test]
fn put_query_and_delete_edges() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let src = EntityId::now();
    let tgt = EntityId::now();
    let kind = EdgeKind::Supports;
    let weight = 0.75_f32;

    vault.put_edge(&src, kind, &tgt, weight)?;

    let out = vault.edges_out(&src)?;
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].kind, kind);
    assert_eq!(out[0].target, tgt);
    assert!((out[0].weight - weight).abs() < f32::EPSILON);

    let inbound = vault.edges_in(&tgt)?;
    assert_eq!(inbound.len(), 1);
    assert_eq!(inbound[0].kind, kind);
    assert_eq!(inbound[0].target, src);
    assert!((inbound[0].weight - weight).abs() < f32::EPSILON);

    assert!(vault.delete_edge(&src, kind, &tgt)?);
    assert!(vault.edges_out(&src)?.is_empty());
    assert!(vault.edges_in(&tgt)?.is_empty());
    assert!(!vault.delete_edge(&src, kind, &tgt)?);

    Ok(())
}

#[test]
fn delete_edge_cleans_inbound_orphans() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let src = EntityId::now();
    let tgt = EntityId::now();
    let kind = EdgeKind::Supports;

    vault.put_edge(&src, kind, &tgt, 0.5)?;

    let key_out = Store::encode_edge_key(&src, kind, &tgt);
    let key_in = Store::encode_edge_key(&tgt, kind, &src);
    let mut wtxn = vault.store.env.write_txn()?;
    assert!(vault.store.edges_out.delete(&mut wtxn, &key_out)?);
    wtxn.commit()?;

    assert!(!vault.delete_edge(&src, kind, &tgt)?);

    let rtxn = vault.store.env.read_txn()?;
    assert!(vault.store.edges_in.get(&rtxn, &key_in)?.is_none());
    Ok(())
}

#[test]
fn batch_put_multiple_entities_atomically() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let id_a = EntityId::now();
    let id_b = EntityId::now();
    let id_c = EntityId::now();

    vault
        .batch()
        .put(&id_a, 1, test_time_range(100, 100), 101, b"a")
        .put(&id_b, 1, test_time_range(200, 201), 202, b"b")
        .put(&id_c, 6, test_time_range(300, 400), 401, b"c")
        .commit()?;

    assert_eq!(vault.get(&id_a)?.ok_or(Error::EntityNotFound)?, b"a");
    assert_eq!(vault.get(&id_b)?.ok_or(Error::EntityNotFound)?, b"b");
    assert_eq!(vault.get(&id_c)?.ok_or(Error::EntityNotFound)?, b"c");
    Ok(())
}

#[test]
fn batch_put_writes_type_index() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let id = EntityId::now();
    let entity_type = 1_u8;

    vault
        .batch()
        .put(&id, entity_type, test_time_range(10, 20), 30, b"type-index")
        .commit()?;

    let key = Store::encode_type_key(entity_type, &id);
    let rtxn = vault.store.env.read_txn()?;
    assert!(vault.store.type_index.get(&rtxn, &key)?.is_some());

    let mut hits = 0_usize;
    for entry in vault.store.type_index.prefix_iter(&rtxn, &[entity_type])? {
        let (found_key, _) = entry?;
        if found_key == key {
            hits += 1;
        }
    }
    assert_eq!(hits, 1);
    Ok(())
}

#[test]
fn batch_put_writes_temporal_indexes() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let id = EntityId::now();

    vault
        .batch()
        .put(&id, 6, test_time_range(1_000, 2_000), 3_000, b"range")
        .commit()?;

    {
        let rtxn = vault.store.env.read_txn()?;
        let start_key = Store::encode_temporal_key(1_000, &id);
        let end_key = Store::encode_temporal_key(2_000, &id);
        let learned_key = Store::encode_temporal_key(3_000, &id);
        assert!(
            vault
                .store
                .temporal_occurred_start
                .get(&rtxn, &start_key)?
                .is_some()
        );
        assert!(
            vault
                .store
                .temporal_occurred_end
                .get(&rtxn, &end_key)?
                .is_some()
        );
        assert!(
            vault
                .store
                .temporal_learned
                .get(&rtxn, &learned_key)?
                .is_some()
        );
    }

    let point_id = EntityId::now();
    vault
        .batch()
        .put(
            &point_id,
            6,
            test_time_range(7_777, 7_777),
            8_888,
            b"point-event",
        )
        .commit()?;
    let point_end_key = Store::encode_temporal_key(7_777, &point_id);
    let rtxn = vault.store.env.read_txn()?;
    assert!(
        vault
            .store
            .temporal_occurred_end
            .get(&rtxn, &point_end_key)?
            .is_none()
    );

    Ok(())
}

#[test]
fn entities_in_learned_range_rejects_corrupted_temporal_key() -> Result<()> {
    let (_dir, vault) = open_test_vault();

    let mut key = [0_u8; 24];
    key[..8].copy_from_slice(&50_u64.to_be_bytes());
    key[8..].fill(0xFF);

    vault.with_write_txn(|wtxn| {
        vault.store.temporal_learned.put(wtxn, &key, &[])?;
        Ok(())
    })?;

    let result = vault.entities_in_learned_range(40, 60);
    assert!(
        matches!(result, Err(Error::CorruptedIndex("temporal learned key"))),
        "expected corrupted temporal learned key, got {result:?}"
    );

    Ok(())
}

#[test]
fn batch_put_writes_long_interval_index_by_end_time() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let id = EntityId::now();
    let end = 1_000 + crate::batch::LONG_INTERVAL_THRESHOLD_SECS + 1;

    vault
        .batch()
        .put(&id, 6, test_time_range(1_000, end), 3_000, b"long-range")
        .commit()?;

    let key = Store::encode_temporal_key(end, &id);
    let rtxn = vault.store.env.read_txn()?;
    let value = vault
        .store
        .temporal_long_intervals
        .get(&rtxn, &key)?
        .ok_or(Error::EntityNotFound)?;
    assert_eq!(
        u64::from_be_bytes(value.try_into().map_err(|_| Error::InvalidKey)?),
        1_000
    );
    Ok(())
}

#[test]
fn batch_put_and_deindex_pin_temporal_boundary_comparisons() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let exact_id = seeded_entity_id(0xB0A0);
    let over_id = seeded_entity_id(0xB0A1);
    let start = 1_000_u64;
    let exact_end = start + LONG_INTERVAL_THRESHOLD_SECS;
    let over_end = exact_end + 1;

    vault
        .batch()
        .put(
            &exact_id,
            6,
            test_time_range(start, exact_end),
            3_000,
            b"exact-threshold",
        )
        .put(
            &over_id,
            6,
            test_time_range(start, over_end),
            3_001,
            b"over-threshold",
        )
        .commit()?;

    let exact_long_key = Store::encode_temporal_key(exact_end, &exact_id);
    let over_long_key = Store::encode_temporal_key(over_end, &over_id);
    {
        let rtxn = vault.store.env.read_txn()?;
        assert!(
            vault
                .store
                .temporal_long_intervals
                .get(&rtxn, &exact_long_key)?
                .is_none(),
            "span == LONG_INTERVAL_THRESHOLD_SECS is not a long interval"
        );
        assert_eq!(
            vault
                .store
                .temporal_long_intervals
                .get(&rtxn, &over_long_key)?,
            Some(&start.to_be_bytes()[..]),
            "span > LONG_INTERVAL_THRESHOLD_SECS must be indexed"
        );
    }

    let exact_sentinel = [0xA5_u8; 8];
    {
        let mut wtxn = vault.store.env.write_txn()?;
        vault
            .store
            .temporal_long_intervals
            .put(&mut wtxn, &exact_long_key, &exact_sentinel)?;
        wtxn.commit()?;
    }
    vault.put_entity(
        &exact_id,
        6,
        test_time_range(start, exact_end),
        3_010,
        b"exact-threshold-updated",
    )?;
    {
        let rtxn = vault.store.env.read_txn()?;
        assert_eq!(
            vault
                .store
                .temporal_long_intervals
                .get(&rtxn, &exact_long_key)?,
            Some(&exact_sentinel[..]),
            "exact-threshold re-put must not run the old/new long-interval branches"
        );
    }

    assert!(vault.delete_entity(&over_id)?);
    {
        let rtxn = vault.store.env.read_txn()?;
        assert!(
            vault
                .store
                .temporal_long_intervals
                .get(&rtxn, &over_long_key)?
                .is_none(),
            "deindex_entity must remove real over-threshold long intervals"
        );
    }

    assert!(vault.delete_entity(&exact_id)?);
    {
        let rtxn = vault.store.env.read_txn()?;
        assert_eq!(
            vault
                .store
                .temporal_long_intervals
                .get(&rtxn, &exact_long_key)?,
            Some(&exact_sentinel[..]),
            "deindex_entity must not treat an exact-threshold span as long"
        );
    }

    let point_id = seeded_entity_id(0xB0A2);
    let point_ts = 7_000_u64;
    vault.put_entity(
        &point_id,
        6,
        test_time_range(point_ts, point_ts),
        8_000,
        b"point",
    )?;
    let point_end_key = Store::encode_temporal_key(point_ts, &point_id);
    let point_sentinel = [0xC3_u8; 4];
    {
        let mut wtxn = vault.store.env.write_txn()?;
        vault
            .store
            .temporal_occurred_end
            .put(&mut wtxn, &point_end_key, &point_sentinel)?;
        wtxn.commit()?;
    }
    vault.put_entity(
        &point_id,
        6,
        test_time_range(point_ts, point_ts),
        8_001,
        b"point-updated",
    )?;
    let rtxn = vault.store.env.read_txn()?;
    assert_eq!(
        vault
            .store
            .temporal_occurred_end
            .get(&rtxn, &point_end_key)?,
        Some(&point_sentinel[..]),
        "point re-put must not run the old range-end delete branch"
    );
    Ok(())
}

#[test]
fn open_migrates_legacy_long_interval_rows() -> Result<()> {
    let temp_dir = tempfile::tempdir()?;
    let path = temp_dir.path();
    let id = EntityId::now();
    let end = 1_000 + crate::batch::LONG_INTERVAL_THRESHOLD_SECS + 10;

    let vault = Vault::open(path, test_config())?;
    vault
        .batch()
        .put(
            &id,
            6,
            test_time_range(1_000, end),
            3_000,
            b"legacy-long-range",
        )
        .commit()?;

    let new_key = Store::encode_temporal_key(end, &id);
    let mut legacy_value = [0_u8; 16];
    legacy_value[..8].copy_from_slice(&1_000_u64.to_be_bytes());
    legacy_value[8..].copy_from_slice(&end.to_be_bytes());

    let mut wtxn = vault.store.env.write_txn()?;
    vault
        .store
        .temporal_long_intervals
        .delete(&mut wtxn, &new_key)?;
    vault
        .store
        .temporal_long_intervals
        .put(&mut wtxn, id.as_bytes(), &legacy_value)?;
    vault
        .store
        .hnsw_meta
        .delete(&mut wtxn, TEMPORAL_LONG_INTERVALS_SCHEMA_VERSION_KEY)?;
    wtxn.commit()?;
    drop(vault);

    let reopened = Vault::open(path, test_config())?;
    let rtxn = reopened.store.env.read_txn()?;
    assert!(
        reopened
            .store
            .temporal_long_intervals
            .get(&rtxn, id.as_bytes())?
            .is_none()
    );
    let value = reopened
        .store
        .temporal_long_intervals
        .get(&rtxn, &new_key)?
        .ok_or(Error::EntityNotFound)?;
    assert_eq!(
        u64::from_be_bytes(value.try_into().map_err(|_| Error::InvalidKey)?),
        1_000
    );
    Ok(())
}

#[test]
fn open_rejects_newer_long_interval_schema_version() -> Result<()> {
    let temp_dir = tempfile::tempdir()?;
    let path = temp_dir.path();

    let vault = Vault::open(path, test_config())?;
    let mut wtxn = vault.store.env.write_txn()?;
    vault.store.hnsw_meta.put(
        &mut wtxn,
        TEMPORAL_LONG_INTERVALS_SCHEMA_VERSION_KEY,
        &[3_u8],
    )?;
    wtxn.commit()?;
    drop(vault);

    let Err(err) = Vault::open(path, test_config()) else {
        panic!("expected invalid key");
    };
    assert_matches!(err, Error::InvalidKey);
    Ok(())
}

#[test]
fn open_checks_model_id_before_migrating_long_interval_schema() -> Result<()> {
    let temp_dir = tempfile::tempdir()?;
    let path = temp_dir.path();
    let id = EntityId::now();
    let end = 1_000 + crate::batch::LONG_INTERVAL_THRESHOLD_SECS + 10;

    let mut cfg = test_config();
    cfg.embedding_model = Some("model-a".to_owned());
    let vault = Vault::open(path, cfg)?;
    vault
        .batch()
        .put(
            &id,
            6,
            test_time_range(1_000, end),
            3_000,
            b"legacy-long-range",
        )
        .commit()?;

    let new_key = Store::encode_temporal_key(end, &id);
    let mut legacy_value = [0_u8; 16];
    legacy_value[..8].copy_from_slice(&1_000_u64.to_be_bytes());
    legacy_value[8..].copy_from_slice(&end.to_be_bytes());

    let mut wtxn = vault.store.env.write_txn()?;
    vault
        .store
        .temporal_long_intervals
        .delete(&mut wtxn, &new_key)?;
    vault
        .store
        .temporal_long_intervals
        .put(&mut wtxn, id.as_bytes(), &legacy_value)?;
    vault
        .store
        .hnsw_meta
        .delete(&mut wtxn, TEMPORAL_LONG_INTERVALS_SCHEMA_VERSION_KEY)?;
    wtxn.commit()?;
    drop(vault);

    let mut mismatch_cfg = test_config();
    mismatch_cfg.embedding_model = Some("model-b".to_owned());
    let Err(err) = Vault::open(path, mismatch_cfg) else {
        panic!("expected embedding model change rejection");
    };
    assert_matches!(err, Error::EmbeddingModelChanged { .. });

    let cfg = test_config();
    let _guard = lmdb_database_open_guard()?;
    // SAFETY: test-only reopen of the same LMDB path. The prior Vault has
    // been dropped; single-Env-per-path invariant holds inside the test
    // scope. tmp path is local (not NFS), and map_size matches the
    // original open above.
    let env = unsafe {
        heed::EnvOpenOptions::new()
            .map_size(cfg.map_size)
            .max_readers(cfg.max_readers)
            .max_dbs(32)
            .open(path)?
    };
    let rtxn = env.read_txn()?;
    let hnsw_meta = env
        .open_database::<Bytes, Bytes>(&rtxn, Some("hnsw_meta"))?
        .ok_or(Error::EntityNotFound)?;
    let temporal_long_intervals = env
        .open_database::<Bytes, Bytes>(&rtxn, Some("temporal_long_intervals"))?
        .ok_or(Error::EntityNotFound)?;

    assert!(temporal_long_intervals.get(&rtxn, id.as_bytes())?.is_some());
    assert!(temporal_long_intervals.get(&rtxn, &new_key)?.is_none());
    assert!(
        hnsw_meta
            .get(&rtxn, TEMPORAL_LONG_INTERVALS_SCHEMA_VERSION_KEY)?
            .is_none()
    );
    Ok(())
}

#[test]
fn batch_put_assigns_short_id() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let id1 = EntityId::now();
    let id2 = EntityId::now();
    let data1 = b"entity-one";
    let data2 = b"entity-two";

    vault
        .batch()
        .put(&id1, 1, test_time_range(1, 1), 2, data1)
        .put(&id2, 1, test_time_range(3, 3), 4, data2)
        .commit()?;

    let (short_id1, hash1) = decode_short_id_value(&read_short_id_value(&vault, &id1)?)?;
    let (short_id2, hash2) = decode_short_id_value(&read_short_id_value(&vault, &id2)?)?;
    assert_eq!(short_id1, "tn1");
    assert_eq!(short_id2, "tn2");
    assert_eq!(hash1, content_hash(data1));
    assert_eq!(hash2, content_hash(data2));
    Ok(())
}

#[test]
fn batch_put_short_id_round_trips_both_directions() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let id = EntityId::now();
    let data = b"reverse";

    // TURN (type 1), not CLAIM (type 0): the parallel ONE-1104 branch validates
    // all type-0 bodies (claim ABI), and merge rehearsal twice caught one of its
    // bulk 0->1 migration hunks silently anchoring into the wrong test. Seeding
    // type 1 keeps the round-trip purpose intact and removes the landmine.
    vault
        .batch()
        .put(&id, 1, test_time_range(100, 100), 101, data)
        .commit()?;

    // Reverse direction (row n4): entity_id -> (short_id, content_hash).
    let short_id_value = read_short_id_value(&vault, &id)?;
    let (short_id, hash) = decode_short_id_value(&short_id_value)?;
    assert_eq!(short_id, "tn1");
    assert_eq!(hash, content_hash(data));

    // Forward direction (row n3): (short_id, content_hash) -> entity_id.
    let mut forward_key = short_id.as_bytes().to_vec();
    forward_key.push(hash);
    let rtxn = vault.store.env.read_txn()?;
    let forward = vault
        .store
        .short_ids
        .get(&rtxn, &forward_key)?
        .ok_or(Error::EntityNotFound)?;
    assert_eq!(forward, id.as_bytes());

    // A stale forward probe (wrong content hash) must NOT resolve: the hash
    // is part of the key, so it acts as a staleness check on resolution.
    let mut stale_key = short_id.as_bytes().to_vec();
    stale_key.push(hash.wrapping_add(1));
    assert!(vault.store.short_ids.get(&rtxn, &stale_key)?.is_none());
    Ok(())
}

/// ARCH-0019 dbManifest rows pinned byte-for-byte via a direct raw cursor
/// (NOT the short-id API):
///
/// * row n3 `short_ids`: key `(short_id, content_hash)` → value `entity_id`
/// * row n4 `short_ids_reverse`: key `entity_id` → value `(short_id, content_hash)`
///
/// A still-swapped implementation (short_ids keyed by the 16-byte entity id,
/// short_ids_reverse keyed by the bare short id) FAILS every assertion here.
#[test]
fn short_id_dbs_match_pinned_manifest_rows_raw_layout() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let id = EntityId::now();
    let data = b"short-id-layout-spec";

    // Type 1 (TURN) fixture: keeps this raw-layout spec off the CLAIM type
    // byte, whose body bytes are validated by the claim-body ABI.
    vault
        .batch()
        .put(&id, 1, test_time_range(7, 7), 8, data)
        .commit()?;

    // content_hash = xxh32(data, 0) % 256; first issued TURN short id = "tn1".
    let expected_hash = content_hash(data);
    let mut expected_pair = b"tn1".to_vec();
    expected_pair.push(expected_hash);

    let rtxn = vault.store.env.read_txn()?;

    // Row n3: exactly ONE forward row — key = short_id bytes ‖ content_hash
    // u8, value = the 16-byte entity id. No counter sentinel rows.
    let forward_rows: Vec<(Vec<u8>, Vec<u8>)> = vault
        .store
        .short_ids
        .iter(&rtxn)?
        .map(|entry| entry.map(|(k, v)| (k.to_vec(), v.to_vec())))
        .collect::<std::result::Result<_, _>>()?;
    assert_eq!(
        forward_rows.len(),
        1,
        "short_ids must hold only the manifest row (no sentinels): {forward_rows:?}"
    );
    assert_eq!(forward_rows[0].0, expected_pair, "forward KEY bytes");
    assert_eq!(
        forward_rows[0].1,
        id.as_bytes().to_vec(),
        "forward VALUE = 16-byte entity id"
    );

    // Row n4: exactly ONE reverse row — key = 16-byte entity id, value =
    // short_id bytes ‖ content_hash u8.
    let reverse_rows: Vec<(Vec<u8>, Vec<u8>)> = vault
        .store
        .short_ids_reverse
        .iter(&rtxn)?
        .map(|entry| entry.map(|(k, v)| (k.to_vec(), v.to_vec())))
        .collect::<std::result::Result<_, _>>()?;
    assert_eq!(reverse_rows.len(), 1);
    assert_eq!(
        reverse_rows[0].0,
        id.as_bytes().to_vec(),
        "reverse KEY = 16-byte entity id"
    );
    assert_eq!(reverse_rows[0].1, expected_pair, "reverse VALUE bytes");
    Ok(())
}

/// Per-type short-id counters live in `vault_meta` under the documented
/// `b"sid_counter:" ‖ type_byte` scheme (u64 LE value) — NOT as
/// `[type_byte, 0xFF×15]` sentinel rows inside `short_ids` (pre-ABI-v3
/// layout). Scans the whole `short_ids` DB and asserts no sentinel remains.
#[test]
fn short_id_counters_live_in_vault_meta_not_short_ids() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let turn_a = EntityId::now();
    let turn_b = EntityId::now();
    let session = EntityId::now();

    // Types 1 (TURN) and 2 (SESSION) exercise two distinct per-type counters
    // while keeping fixtures off the CLAIM type byte, whose body bytes are
    // validated by the claim-body ABI.
    vault
        .batch()
        .put(&turn_a, 1, test_time_range(1, 1), 2, b"turn-a")
        .put(&turn_b, 1, test_time_range(3, 3), 4, b"turn-b")
        .put(&session, 2, test_time_range(5, 5), 6, b"session-a")
        .commit()?;

    let rtxn = vault.store.env.read_txn()?;

    for entry in vault.store.short_ids.iter(&rtxn)? {
        let (key, value) = entry?;
        assert!(
            !(key.len() == 16 && key[1..].iter().all(|&b| b == 0xFF)),
            "short_ids must not contain [type_byte, 0xFF x15] counter sentinels: {key:?}"
        );
        assert_eq!(
            value.len(),
            16,
            "every short_ids value must be a 16-byte entity id (counter rows were 8-byte): {value:?}"
        );
    }

    // Documented key scheme, pinned as literal bytes: 12-byte ASCII prefix
    // "sid_counter:" + raw type byte; value = last issued counter u64 LE.
    let turn_counter = vault
        .store
        .vault_meta
        .get(&rtxn, b"sid_counter:\x01")?
        .expect("TURN counter must live in vault_meta");
    assert_eq!(turn_counter, 2_u64.to_le_bytes());
    let session_counter = vault
        .store
        .vault_meta
        .get(&rtxn, b"sid_counter:\x02")?
        .expect("SESSION counter must live in vault_meta");
    assert_eq!(session_counter, 1_u64.to_le_bytes());
    Ok(())
}

/// Pins the short-id content hash formula `xxh32(data, 0) % 256` (u8) with a
/// precomputed literal so a formula/seed/width drift FAILS without relying on
/// the engine's own helper.
#[test]
fn short_id_content_hash_is_xxh32_of_data_mod_256() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let id = EntityId::now();
    // xxh32(b"short-id-hash-pin", seed 0) = 0xc8d57569; 0xc8d57569 % 256 = 105.
    let data = b"short-id-hash-pin";
    const EXPECTED_CONTENT_HASH: u8 = 105;

    // Type 1 (TURN) fixture: the hash formula is type-independent, and this
    // keeps the fixture off the CLAIM type byte, whose body bytes are
    // validated by the claim-body ABI. First issued TURN short id = "tn1".
    vault
        .batch()
        .put(&id, 1, test_time_range(1, 1), 2, data)
        .commit()?;

    let (_, hash) = decode_short_id_value(&read_short_id_value(&vault, &id)?)?;
    assert_eq!(hash, EXPECTED_CONTENT_HASH);

    // The same byte is embedded in the forward KEY.
    let mut forward_key = b"tn1".to_vec();
    forward_key.push(EXPECTED_CONTENT_HASH);
    let rtxn = vault.store.env.read_txn()?;
    assert_eq!(
        vault.store.short_ids.get(&rtxn, &forward_key)?,
        Some(id.as_bytes().as_slice())
    );
    Ok(())
}

/// M0-4 fail-closed gate over the M2-5 bump: vaults written under storage ABI
/// v2 (pre short-id direction swap) are REJECTED at open with the typed gate
/// error. Pins the literal stored version 2 against the current constant —
/// an implementation that skipped the bump would open the old vault and FAIL
/// this test.
#[test]
fn open_rejects_abi_v2_vault_after_short_id_swap() -> Result<()> {
    let temp_dir = tempfile::tempdir()?;
    let path = temp_dir.path();

    {
        let _vault = Vault::open(path, test_config())?;
    }
    set_raw_storage_abi_version(path, Some(2))?;

    let err = match Vault::open(path, test_config()) {
        Ok(_) => panic!("expected Vault::open to reject a pre-swap ABI v2 vault"),
        Err(err) => err,
    };
    assert!(
        matches!(
            err,
            Error::StorageAbiVersionChanged {
                stored: Some(2),
                current: STORAGE_ABI_VERSION,
            }
        ),
        "expected StorageAbiVersionChanged {{ stored: Some(2), current: {STORAGE_ABI_VERSION} }}, got {err:?}"
    );
    Ok(())
}

/// ONE-1293 fail-closed gate over the maintenance-band type-byte realignment:
/// vaults written under storage ABI v4 have POLICY_MANIFEST at 122 and
/// FEDERATION_GRANT at 123, while v5 reserves 122 for AUTHORITY_LOG and moves
/// those kinds to 123/124. There is NO silent migration.
#[test]
fn open_rejects_abi_v4_vault_after_maintenance_band_reallocation() -> Result<()> {
    assert_eq!(
        STORAGE_ABI_VERSION, 6,
        "ONE-1204 pins the current storage ABI at 6",
    );

    let temp_dir = tempfile::tempdir()?;
    let path = temp_dir.path();

    {
        let _vault = Vault::open(path, test_config())?;
    }
    set_raw_storage_abi_version(path, Some(4))?;

    let err = match Vault::open(path, test_config()) {
        Ok(_) => panic!("expected Vault::open to reject a pre-ONE-1293 ABI v4 vault"),
        Err(err) => err,
    };
    assert!(
        matches!(
            err,
            Error::StorageAbiVersionChanged {
                stored: Some(4),
                current: STORAGE_ABI_VERSION,
            }
        ),
        "expected StorageAbiVersionChanged {{ stored: Some(4), current: {STORAGE_ABI_VERSION} }}, got {err:?}"
    );
    Ok(())
}

/// ONE-1204 fail-closed gate over registering persistent maintenance type
/// PSYCH_PROFILE at byte 129: v5 code does not know this persistent entity
/// kind, so v5 vaults must not open under ABI v6 without rebuild.
#[test]
fn open_rejects_abi_v5_vault_after_psych_profile_type_registration() -> Result<()> {
    assert_eq!(
        STORAGE_ABI_VERSION, 6,
        "ONE-1204 pins the current storage ABI at 6",
    );

    let temp_dir = tempfile::tempdir()?;
    let path = temp_dir.path();

    {
        let _vault = Vault::open(path, test_config())?;
    }
    set_raw_storage_abi_version(path, Some(5))?;

    let err = match Vault::open(path, test_config()) {
        Ok(_) => panic!("expected Vault::open to reject a pre-ONE-1204 ABI v5 vault"),
        Err(err) => err,
    };
    assert!(
        matches!(
            err,
            Error::StorageAbiVersionChanged {
                stored: Some(5),
                current: STORAGE_ABI_VERSION,
            }
        ),
        "expected StorageAbiVersionChanged {{ stored: Some(5), current: {STORAGE_ABI_VERSION} }}, got {err:?}"
    );
    Ok(())
}

#[test]
fn batch_put_updates_content_hash_on_reput() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let id = EntityId::now();
    let data1 = b"initial";
    let mut data2 = b"updated".to_vec();
    while content_hash(data1) == content_hash(&data2) {
        data2.push(0_u8);
    }

    vault
        .batch()
        .put(&id, 1, test_time_range(10, 10), 11, data1)
        .commit()?;
    let (short_id1, hash1) = decode_short_id_value(&read_short_id_value(&vault, &id)?)?;

    vault
        .batch()
        .put(&id, 1, test_time_range(10, 10), 11, &data2)
        .commit()?;
    let (short_id2, hash2) = decode_short_id_value(&read_short_id_value(&vault, &id)?)?;

    assert_eq!(short_id1, short_id2);
    assert_eq!(hash1, content_hash(data1));
    assert_eq!(hash2, content_hash(&data2));
    assert_ne!(hash1, hash2);

    // The content hash is part of the forward KEY (manifest row n3), so the
    // re-put must reap the stale forward row and write the refreshed one — an
    // implementation that leaves the old `(short_id, old_hash)` row FAILS.
    let mut stale_forward_key = short_id1.as_bytes().to_vec();
    stale_forward_key.push(hash1);
    let mut fresh_forward_key = short_id1.as_bytes().to_vec();
    fresh_forward_key.push(hash2);
    let rtxn = vault.store.env.read_txn()?;
    assert!(
        vault
            .store
            .short_ids
            .get(&rtxn, &stale_forward_key)?
            .is_none(),
        "stale forward short_ids row must be deleted on content update"
    );
    assert_eq!(
        vault.store.short_ids.get(&rtxn, &fresh_forward_key)?,
        Some(id.as_bytes().as_slice())
    );
    Ok(())
}

#[test]
fn reput_deindexes_stale_secondary_indexes() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let id = EntityId::now();
    // The type byte is immutable on re-put (D2, Error::EntityTypeImmutable);
    // re-typing coverage lives in the EntityTypeImmutable tests. This test
    // pins that a same-type re-put re-homes the temporal indexes while the
    // short id stays stable and the content hash refreshes. Type byte 2
    // (SESSION) keeps the body opaque — type 0 is reserved for CLAIM, whose
    // bodies are structurally validated (D18).
    let entity_type = 2_u8;
    let old_occurred = test_time_range(100, 200);
    let old_learned = 300_u64;
    let old_data = b"old-data";
    let new_occurred = test_time_range(400, 500);
    let new_learned = 600_u64;
    let mut new_data = b"new-data".to_vec();
    while content_hash(old_data) == content_hash(&new_data) {
        new_data.push(0_u8);
    }

    vault
        .batch()
        .put(&id, entity_type, old_occurred, old_learned, old_data)
        .commit()?;

    let type_key = Store::encode_type_key(entity_type, &id);
    let old_start_key = Store::encode_temporal_key(old_occurred.start, &id);
    let old_end_key = Store::encode_temporal_key(old_occurred.end, &id);
    let old_learned_key = Store::encode_temporal_key(old_learned, &id);

    {
        let rtxn = vault.store.env.read_txn()?;
        assert!(vault.store.type_index.get(&rtxn, &type_key)?.is_some());
        assert!(
            vault
                .store
                .temporal_occurred_start
                .get(&rtxn, &old_start_key)?
                .is_some()
        );
        assert!(
            vault
                .store
                .temporal_occurred_end
                .get(&rtxn, &old_end_key)?
                .is_some()
        );
        assert!(
            vault
                .store
                .temporal_learned
                .get(&rtxn, &old_learned_key)?
                .is_some()
        );
    }

    let (short_id_before, hash_before) = decode_short_id_value(&read_short_id_value(&vault, &id)?)?;

    vault
        .batch()
        .put(&id, entity_type, new_occurred, new_learned, &new_data)
        .commit()?;

    let new_start_key = Store::encode_temporal_key(new_occurred.start, &id);
    let new_end_key = Store::encode_temporal_key(new_occurred.end, &id);
    let new_learned_key = Store::encode_temporal_key(new_learned, &id);

    {
        let rtxn = vault.store.env.read_txn()?;
        assert!(vault.store.type_index.get(&rtxn, &type_key)?.is_some());
        assert!(
            vault
                .store
                .temporal_occurred_start
                .get(&rtxn, &old_start_key)?
                .is_none()
        );
        assert!(
            vault
                .store
                .temporal_occurred_end
                .get(&rtxn, &old_end_key)?
                .is_none()
        );
        assert!(
            vault
                .store
                .temporal_learned
                .get(&rtxn, &old_learned_key)?
                .is_none()
        );
        assert!(
            vault
                .store
                .temporal_occurred_start
                .get(&rtxn, &new_start_key)?
                .is_some()
        );
        assert!(
            vault
                .store
                .temporal_occurred_end
                .get(&rtxn, &new_end_key)?
                .is_some()
        );
        assert!(
            vault
                .store
                .temporal_learned
                .get(&rtxn, &new_learned_key)?
                .is_some()
        );
    }

    assert_eq!(vault.get(&id)?.ok_or(Error::EntityNotFound)?, new_data);
    let (short_id_after, hash_after) = decode_short_id_value(&read_short_id_value(&vault, &id)?)?;
    assert_eq!(short_id_before, short_id_after);
    assert_eq!(hash_before, content_hash(old_data));
    assert_eq!(hash_after, content_hash(&new_data));
    assert_ne!(hash_before, hash_after);

    Ok(())
}

#[test]
fn reput_range_to_point_deindexes_stale_end_key() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let id = EntityId::now();

    vault
        .batch()
        .put(&id, 1, test_time_range(100, 200), 300, b"range")
        .commit()?;

    let old_end_key = Store::encode_temporal_key(200, &id);
    {
        let rtxn = vault.store.env.read_txn()?;
        assert!(
            vault
                .store
                .temporal_occurred_end
                .get(&rtxn, &old_end_key)?
                .is_some()
        );
    }

    vault
        .batch()
        .put(&id, 1, test_time_range(200, 200), 300, b"point")
        .commit()?;

    {
        let rtxn = vault.store.env.read_txn()?;
        assert!(
            vault
                .store
                .temporal_occurred_end
                .get(&rtxn, &old_end_key)?
                .is_none(),
            "stale occurred_end key should be deleted on range→point transition"
        );
    }

    assert!(vault.delete_entity(&id)?);
    Ok(())
}

#[test]
fn reput_rekeys_long_interval_index_and_drops_shortened_range() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let id = EntityId::now();
    let old_end = 1_000 + crate::batch::LONG_INTERVAL_THRESHOLD_SECS + 10;
    let new_end = 5_000 + crate::batch::LONG_INTERVAL_THRESHOLD_SECS + 20;

    vault
        .batch()
        .put(&id, 1, test_time_range(1_000, old_end), 300, b"long-old")
        .commit()?;

    let old_key = Store::encode_temporal_key(old_end, &id);
    let new_key = Store::encode_temporal_key(new_end, &id);

    vault
        .batch()
        .put(&id, 1, test_time_range(5_000, new_end), 300, b"long-new")
        .commit()?;

    {
        let rtxn = vault.store.env.read_txn()?;
        assert!(
            vault
                .store
                .temporal_long_intervals
                .get(&rtxn, &old_key)?
                .is_none()
        );
        let value = vault
            .store
            .temporal_long_intervals
            .get(&rtxn, &new_key)?
            .ok_or(Error::EntityNotFound)?;
        assert_eq!(
            u64::from_be_bytes(value.try_into().map_err(|_| Error::InvalidKey)?),
            5_000
        );
    }

    vault
        .batch()
        .put(&id, 1, test_time_range(10_000, 10_001), 300, b"short")
        .commit()?;

    let rtxn = vault.store.env.read_txn()?;
    assert!(
        vault
            .store
            .temporal_long_intervals
            .get(&rtxn, &new_key)?
            .is_none()
    );
    Ok(())
}

#[test]
fn batch_phonetic_index() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let id = EntityId::now();

    vault
        .batch()
        .put(&id, 1, test_time_range(1, 1), 2, b"phonetic")
        .phonetic(&id, &["SMTH", "SMT"])
        .commit()?;

    let rtxn = vault.store.env.read_txn()?;
    for code in ["SMTH", "SMT"] {
        let posting = vault
            .store
            .phonetic_index
            .get(&rtxn, code.as_bytes())?
            .ok_or(Error::EntityNotFound)?;
        assert!(posting.len().is_multiple_of(16));
        assert!(posting.chunks_exact(16).any(|chunk| chunk == id.as_bytes()));
    }

    let forward = vault
        .store
        .phonetic_forward
        .get(&rtxn, id.as_bytes())?
        .ok_or(Error::EntityNotFound)?;
    assert_eq!(
        decode_forward_codes(forward)?,
        vec!["SMT".to_owned(), "SMTH".to_owned()]
    );
    Ok(())
}

#[test]
fn phonetic_dedup_on_reindex() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let id = EntityId::now();

    vault
        .batch()
        .put(&id, 1, test_time_range(1, 2), 3, b"dedup")
        .phonetic(&id, &["ABC"])
        .commit()?;

    vault.batch().phonetic(&id, &["ABC"]).commit()?;

    let rtxn = vault.store.env.read_txn()?;
    let posting = vault
        .store
        .phonetic_index
        .get(&rtxn, b"ABC")?
        .ok_or(Error::EntityNotFound)?;
    assert_eq!(posting.len(), 16);
    let count = posting
        .chunks_exact(16)
        .filter(|chunk| *chunk == id.as_bytes())
        .count();
    assert_eq!(count, 1);

    let forward = vault
        .store
        .phonetic_forward
        .get(&rtxn, id.as_bytes())?
        .ok_or(Error::EntityNotFound)?;
    assert_eq!(decode_forward_codes(forward)?, vec!["ABC".to_owned()]);
    Ok(())
}

#[test]
fn phonetic_dedups_duplicate_codes_within_single_batch() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let id = EntityId::now();

    vault
        .batch()
        .put(&id, 1, test_time_range(1, 2), 3, b"dedup-in-batch")
        .phonetic(&id, &["ABC", "ABC"])
        .commit()?;

    let rtxn = vault.store.env.read_txn()?;
    let posting = vault
        .store
        .phonetic_index
        .get(&rtxn, b"ABC")?
        .ok_or(Error::EntityNotFound)?;
    assert!(posting.len().is_multiple_of(ENTITY_ID_LEN));
    let count = posting
        .chunks_exact(ENTITY_ID_LEN)
        .filter(|chunk| *chunk == id.as_bytes())
        .count();
    assert_eq!(count, 1);

    let forward = vault
        .store
        .phonetic_forward
        .get(&rtxn, id.as_bytes())?
        .ok_or(Error::EntityNotFound)?;
    assert_eq!(decode_forward_codes(forward)?, vec!["ABC".to_owned()]);
    Ok(())
}

#[test]
fn phonetic_reindex_remains_additive() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let id = EntityId::now();

    vault
        .batch()
        .put(&id, 1, test_time_range(1, 2), 3, b"union")
        .phonetic(&id, &["ABC"])
        .commit()?;

    vault.batch().phonetic(&id, &["DEF"]).commit()?;

    let rtxn = vault.store.env.read_txn()?;
    for code in ["ABC", "DEF"] {
        let posting = vault
            .store
            .phonetic_index
            .get(&rtxn, code.as_bytes())?
            .ok_or(Error::EntityNotFound)?;
        assert!(posting.chunks_exact(16).any(|chunk| chunk == id.as_bytes()));
    }

    let forward = vault
        .store
        .phonetic_forward
        .get(&rtxn, id.as_bytes())?
        .ok_or(Error::EntityNotFound)?;
    assert_eq!(
        decode_forward_codes(forward)?,
        vec!["ABC".to_owned(), "DEF".to_owned()]
    );
    Ok(())
}

#[test]
fn phonetic_reindex_repairs_missing_forward_codes() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let id = EntityId::now();

    vault
        .batch()
        .put(&id, 1, test_time_range(1, 2), 3, b"migrated")
        .phonetic(&id, &["ABC"])
        .commit()?;

    let mut wtxn = vault.store.env.write_txn()?;
    vault
        .store
        .phonetic_forward
        .delete(&mut wtxn, id.as_bytes())?;
    wtxn.commit()?;

    vault.batch().phonetic(&id, &["ABC", "DEF"]).commit()?;

    let rtxn = vault.store.env.read_txn()?;
    let forward = vault
        .store
        .phonetic_forward
        .get(&rtxn, id.as_bytes())?
        .ok_or(Error::EntityNotFound)?;
    assert_eq!(
        decode_forward_codes(forward)?,
        vec!["ABC".to_owned(), "DEF".to_owned()]
    );
    drop(rtxn);

    assert!(vault.delete_entity(&id)?);

    let rtxn = vault.store.env.read_txn()?;
    for code in ["ABC", "DEF"] {
        if let Some(posting) = vault.store.phonetic_index.get(&rtxn, code.as_bytes())? {
            assert!(!posting.chunks_exact(16).any(|chunk| chunk == id.as_bytes()));
        }
    }
    Ok(())
}

#[test]
fn phonetic_rejects_invalid_codes_atomically() -> Result<()> {
    // (case_name, invalid_code, payload)
    let cases: &[(&str, &str, &[u8])] = &[
        ("embedded_nul", "BAD\0CODE", b"phonetic-invalid"),
        ("empty", "", b"phonetic-empty"),
    ];

    for (name, code, payload) in cases {
        let (_dir, vault) = open_test_vault();
        let id = EntityId::now();

        let result = vault
            .batch()
            .put(&id, 1, test_time_range(1, 1), 2, payload)
            .phonetic(&id, &[*code])
            .commit();
        let err = result
            .err()
            .unwrap_or_else(|| panic!("case {name}: expected invalid phonetic code to fail"));
        assert!(
            matches!(err, Error::InvalidKey),
            "case {name}: expected InvalidKey, got {err:?}"
        );
        assert!(
            vault.get(&id)?.is_none(),
            "case {name}: batch should remain atomic on phonetic validation failure"
        );
    }
    Ok(())
}

#[test]
fn full_delete_deindexes_everything() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let id = EntityId::now();
    let out_target = EntityId::now();
    let in_source = EntityId::now();
    let occurred = test_time_range(10_000, 20_000);
    let learned_at = 30_000;

    vault
        .batch()
        .put(&id, 1, occurred, learned_at, b"delete-me")
        .put(&out_target, 4, test_time_range(1, 1), 2, b"target")
        .put(&in_source, 4, test_time_range(3, 3), 4, b"source")
        .vector(&id, &[0.1, 0.2, 0.3, 0.4])
        .edge(&id, EdgeKind::Supports, &out_target, 0.9)
        .edge(&in_source, EdgeKind::Mentions, &id, 0.7)
        .phonetic(&id, &["SMTH", "SMT"])
        .commit()?;

    // The reverse VALUE bytes double as the forward KEY (short_id ‖ hash).
    let forward_key_before_delete = read_short_id_value(&vault, &id)?;

    assert!(vault.delete_entity(&id)?);
    assert!(vault.get(&id)?.is_none());
    assert!(vault.get_vector(&id)?.is_none());
    assert!(vault.edges_out(&id)?.is_empty());
    assert!(vault.edges_in(&id)?.is_empty());
    assert!(vault.edges_in(&out_target)?.is_empty());
    assert!(vault.edges_out(&in_source)?.is_empty());

    let type_key = Store::encode_type_key(0, &id);
    let start_key = Store::encode_temporal_key(occurred.start, &id);
    let end_key = Store::encode_temporal_key(occurred.end, &id);
    let learned_key = Store::encode_temporal_key(learned_at, &id);
    let rtxn = vault.store.env.read_txn()?;
    assert!(vault.store.type_index.get(&rtxn, &type_key)?.is_none());
    assert!(
        vault
            .store
            .temporal_occurred_start
            .get(&rtxn, &start_key)?
            .is_none()
    );
    assert!(
        vault
            .store
            .temporal_occurred_end
            .get(&rtxn, &end_key)?
            .is_none()
    );
    assert!(
        vault
            .store
            .temporal_learned
            .get(&rtxn, &learned_key)?
            .is_none()
    );

    for code in ["SMTH", "SMT"] {
        if let Some(posting) = vault.store.phonetic_index.get(&rtxn, code.as_bytes())? {
            assert!(!posting.chunks_exact(16).any(|chunk| chunk == id.as_bytes()));
        }
    }
    assert!(
        vault
            .store
            .phonetic_forward
            .get(&rtxn, id.as_bytes())?
            .is_none()
    );

    assert!(
        vault
            .store
            .short_ids_reverse
            .get(&rtxn, id.as_bytes())?
            .is_none()
    );
    assert!(
        vault
            .store
            .short_ids
            .get(&rtxn, &forward_key_before_delete)?
            .is_none()
    );
    Ok(())
}

#[test]
fn delete_entity_phonetic_fallback_variants() -> Result<()> {
    /// What kind of phonetic-index corruption to inject before `delete_entity`.
    enum Corruption {
        /// `phonetic_forward[id]` row deleted entirely.
        Missing,
        /// One of the `phonetic_index[code]` postings deleted (forward row intact).
        StaleIndex,
        /// `phonetic_forward[id]` overwritten with empty bytes.
        EmptyForward,
        /// `phonetic_forward[id]` overwritten with a subset of original codes.
        SubsetForward,
    }

    // Every variant inserts an entity with the same two phonetic codes,
    // injects its corruption, then asserts:
    //  1. `delete_entity` returns Ok(true)
    //  2. Both phonetic postings no longer reference the deleted entity
    //  3. (variants StaleIndex, EmptyForward, SubsetForward) phonetic_forward is cleared
    let cases: &[(&str, &[u8], Corruption)] = &[
        ("missing", b"phonetic-fallback", Corruption::Missing),
        (
            "stale_index",
            b"phonetic-stale-forward",
            Corruption::StaleIndex,
        ),
        (
            "empty_forward",
            b"phonetic-empty-forward",
            Corruption::EmptyForward,
        ),
        (
            "subset_forward",
            b"phonetic-subset-forward",
            Corruption::SubsetForward,
        ),
    ];

    for (name, payload, corruption) in cases {
        let (_dir, vault) = open_test_vault();
        let id = EntityId::now();

        vault
            .batch()
            .put(&id, 1, test_time_range(1, 1), 2, payload)
            .phonetic(&id, &["SMTH", "SMT"])
            .commit()?;

        let mut wtxn = vault.store.env.write_txn()?;
        match corruption {
            Corruption::Missing => {
                vault
                    .store
                    .phonetic_forward
                    .delete(&mut wtxn, id.as_bytes())?;
            }
            Corruption::StaleIndex => {
                vault.store.phonetic_index.delete(&mut wtxn, b"SMTH")?;
            }
            Corruption::EmptyForward => {
                vault
                    .store
                    .phonetic_forward
                    .put(&mut wtxn, id.as_bytes(), &[])?;
            }
            Corruption::SubsetForward => {
                vault
                    .store
                    .phonetic_forward
                    .put(&mut wtxn, id.as_bytes(), b"SMT")?;
            }
        }
        wtxn.commit()?;

        assert!(
            vault.delete_entity(&id)?,
            "case {name}: delete_entity should return true"
        );

        let rtxn = vault.store.env.read_txn()?;

        // Variants that wrote to phonetic_forward must end with it cleared.
        let must_clear_forward = matches!(
            corruption,
            Corruption::StaleIndex | Corruption::EmptyForward | Corruption::SubsetForward
        );
        if must_clear_forward {
            assert!(
                vault
                    .store
                    .phonetic_forward
                    .get(&rtxn, id.as_bytes())?
                    .is_none(),
                "case {name}: phonetic_forward should be cleared after delete"
            );
        }

        // For the stale_index variant the SMTH posting was already deleted; only
        // assert SMT (the surviving posting) no longer references the entity.
        let codes_to_check: &[&[u8]] = match corruption {
            Corruption::StaleIndex => &[b"SMT"],
            _ => &[b"SMTH", b"SMT"],
        };
        for code in codes_to_check {
            if let Some(posting) = vault.store.phonetic_index.get(&rtxn, code)? {
                assert!(
                    !posting.chunks_exact(16).any(|chunk| chunk == id.as_bytes()),
                    "case {name}: code {:?} still references deleted entity",
                    std::str::from_utf8(code).unwrap_or("<bin>")
                );
            }
        }
    }

    Ok(())
}

#[test]
fn delete_entity_corrupted_edge_record_returns_error_not_panic() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let id = EntityId::now();
    let target = EntityId::now();

    vault
        .batch()
        .put(&id, 1, test_time_range(1, 2), 3, b"exists")
        .commit()?;

    vault.with_write_txn(|wtxn| {
        let key = Store::encode_edge_key(&id, EdgeKind::Supports, &target);
        let value = [0_u8; 3];
        vault.store.edges_out.put(wtxn, &key, &value)?;
        Ok(())
    })?;

    let err = vault
        .delete_entity(&id)
        .expect_err("corrupted edge record should fail loud");
    assert_matches!(err, Error::CorruptedIndex("edge record"));
    Ok(())
}

#[test]
fn delete_entity_cleans_edge_only_nodes_and_bumps_graph_version() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let src = EntityId::now();
    let tgt = EntityId::now();

    vault.put_edge(&src, EdgeKind::Supports, &tgt, 0.9)?;
    let before = read_hnsw_meta_u64(&vault, GRAPH_VERSION_KEY)?;

    assert!(!vault.delete_entity(&src)?);
    assert!(vault.edges_out(&src)?.is_empty());
    assert!(vault.edges_in(&tgt)?.is_empty());

    let after = read_hnsw_meta_u64(&vault, GRAPH_VERSION_KEY)?;
    assert_eq!(after, before + 1);
    Ok(())
}

#[test]
fn put_entity_simple_api_uses_batch() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let id = EntityId::now();
    let occurred = test_time_range(123, 456);
    let learned_at = 789;
    let data = b"simple-api";

    vault.put_entity(&id, 1, occurred, learned_at, data)?;
    assert_eq!(vault.get(&id)?.ok_or(Error::EntityNotFound)?, data);

    let rtxn = vault.store.env.read_txn()?;
    let raw = vault
        .store
        .entities
        .get(&rtxn, id.as_bytes())?
        .ok_or(Error::EntityNotFound)?;
    assert_eq!(raw.len(), ENTITY_METADATA_HEADER_LEN + data.len());
    assert_eq!(&raw[ENTITY_METADATA_HEADER_LEN..], data);

    let type_key = Store::encode_type_key(1, &id);
    let start_key = Store::encode_temporal_key(occurred.start, &id);
    let end_key = Store::encode_temporal_key(occurred.end, &id);
    let learned_key = Store::encode_temporal_key(learned_at, &id);
    assert!(vault.store.type_index.get(&rtxn, &type_key)?.is_some());
    assert!(
        vault
            .store
            .temporal_occurred_start
            .get(&rtxn, &start_key)?
            .is_some()
    );
    assert!(
        vault
            .store
            .temporal_occurred_end
            .get(&rtxn, &end_key)?
            .is_some()
    );
    assert!(
        vault
            .store
            .temporal_learned
            .get(&rtxn, &learned_key)?
            .is_some()
    );
    assert!(
        vault
            .store
            .short_ids_reverse
            .get(&rtxn, id.as_bytes())?
            .is_some()
    );

    Ok(())
}

#[test]
fn get_learned_at_rejects_truncated_entity_header() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let id = EntityId::now();

    vault.with_write_txn(|wtxn| {
        let truncated = [0_u8; ENTITY_METADATA_HEADER_LEN - 1];
        vault.store.entities.put(wtxn, id.as_bytes(), &truncated)?;
        Ok(())
    })?;

    let err = vault
        .get_learned_at(&id)
        .expect_err("truncated entity header should fail loud");
    assert_matches!(err, Error::CorruptedIndex("entity header"));

    Ok(())
}

#[test]
fn validates_dimensions_hnsw_and_map_size() -> Result<()> {
    let temp_dir = tempfile::tempdir()?;

    let mut invalid_dims = test_config();
    invalid_dims.dimensions = 0;
    let err = match Vault::open(temp_dir.path(), invalid_dims) {
        Ok(_) => panic!("expected invalid config"),
        Err(err) => err,
    };
    assert_matches!(err, Error::InvalidConfig(_));

    let mut invalid_hnsw = test_config();
    invalid_hnsw.hnsw.m_max_0 = 0;
    let err = match Vault::open(temp_dir.path(), invalid_hnsw) {
        Ok(_) => panic!("expected invalid config"),
        Err(err) => err,
    };
    assert_matches!(err, Error::InvalidConfig(ref message) if message == "hnsw m_max_0 must be greater than zero");

    let mut invalid_map = test_config();
    invalid_map.map_size = 0;
    let err = match Vault::open(temp_dir.path(), invalid_map) {
        Ok(_) => panic!("expected invalid config"),
        Err(err) => err,
    };
    assert_matches!(err, Error::InvalidConfig(_));
    Ok(())
}

#[test]
fn vault_open_rejects_second_live_env_for_same_path() -> Result<()> {
    let temp_dir = tempfile::tempdir()?;
    let path = temp_dir.path();

    let first_vault = Vault::open(path, test_config())?;
    let Err(err) = Vault::open(path, test_config()) else {
        panic!("expected second live vault open to fail");
    };
    assert_matches!(
        err,
        Error::VaultRootPreflight {
            problem: VaultRootProblem::DuplicateOpenRoot { .. },
            ..
        }
    );

    drop(first_vault);
    let reopened = Vault::open(path, test_config())?;
    drop(reopened);
    Ok(())
}

#[cfg(unix)]
#[test]
fn vault_open_rejects_second_live_env_for_symlinked_path() -> Result<()> {
    let temp_dir = tempfile::tempdir()?;
    let real_path = temp_dir.path().join("vault");
    let link_path = temp_dir.path().join("vault-link");
    std::fs::create_dir_all(&real_path)?;
    std::os::unix::fs::symlink(&real_path, &link_path)?;

    let first_vault = Vault::open(&real_path, test_config())?;
    let Err(err) = Vault::open(&link_path, test_config()) else {
        panic!("expected symlinked second live vault open to fail");
    };
    assert_matches!(
        err,
        Error::VaultRootPreflight {
            problem: VaultRootProblem::DuplicateOpenRoot { .. },
            ..
        }
    );

    drop(first_vault);
    let reopened = Vault::open(&link_path, test_config())?;
    drop(reopened);
    Ok(())
}

#[test]
fn dropping_last_vault_handle_closes_lmdb_env() -> Result<()> {
    let temp_dir = tempfile::tempdir()?;
    let path = temp_dir.path();

    let vault = Vault::open(path, test_config())?;
    // heed registers opened environments by canonicalized path; a live
    // registration is observable as `Some(closing_event)`.
    let canonical = path.canonicalize()?;
    let closing_event =
        heed::env_closing_event(&canonical).expect("open vault must have a live env registration");

    drop(vault);
    // `Store`'s drop runs `prepare_for_closing` and the wrapped env is the
    // last clone, so the close is synchronous by the time `drop` returns;
    // the timeout only bounds the failure mode.
    assert!(
        closing_event.wait_timeout(std::time::Duration::from_secs(5)),
        "LMDB env did not close after dropping the last vault handle"
    );
    assert!(
        heed::env_closing_event(&canonical).is_none(),
        "closed env still present in heed's process-global registry"
    );

    // Single-writer reopen of the same path works after the close.
    let reopened = Vault::open(path, test_config())?;
    drop(reopened);
    assert!(heed::env_closing_event(&canonical).is_none());
    Ok(())
}

#[test]
fn vault_open_rejects_partial_lmdb_root_before_open() -> Result<()> {
    let temp_dir = tempfile::tempdir()?;
    let path = temp_dir.path();
    let canonical = path.canonicalize()?;
    std::fs::write(path.join("lock.mdb"), b"stale lock")?;

    let Err(err) = Vault::open(path, test_config()) else {
        panic!("expected partial LMDB root to fail preflight");
    };
    assert_matches!(
        err,
        Error::VaultRootPreflight {
            ref path,
            problem: VaultRootProblem::IncompleteLmdbPair {
                present: VaultRootEntry::Lock,
                missing: VaultRootEntry::Data,
            },
        } if path == &canonical
    );
    assert!(
        !temp_dir.path().join("data.mdb").exists(),
        "preflight must reject before LMDB creates data.mdb"
    );
    Ok(())
}

#[cfg(unix)]
#[test]
fn vault_open_rejects_hardlinked_lmdb_root_before_open() -> Result<()> {
    let temp_dir = tempfile::tempdir()?;
    let real_path = temp_dir.path().join("vault");
    let duplicate_path = temp_dir.path().join("vault-hardlink");
    let _vault = Vault::open(&real_path, test_config())?;
    std::fs::create_dir_all(&duplicate_path)?;
    std::fs::hard_link(real_path.join("data.mdb"), duplicate_path.join("data.mdb"))?;
    std::fs::hard_link(real_path.join("lock.mdb"), duplicate_path.join("lock.mdb"))?;
    let canonical_duplicate = duplicate_path.canonicalize()?;

    let Err(err) = Vault::open(&duplicate_path, test_config()) else {
        panic!("expected hardlinked LMDB root to fail preflight");
    };
    assert_matches!(
        err,
        Error::VaultRootPreflight {
            ref path,
            problem: VaultRootProblem::MultipleHardLinks {
                entry: VaultRootEntry::Data,
                link_count,
            },
        } if path == &canonical_duplicate && link_count >= 2
    );
    Ok(())
}

#[cfg(unix)]
#[test]
fn vault_open_rejects_new_vault_hardlink_alias_before_second_lmdb_open() -> Result<()> {
    let temp_dir = tempfile::tempdir()?;
    let real_path = temp_dir.path().join("vault");
    let duplicate_path = temp_dir.path().join("vault-hardlink");
    let duplicate_for_hook = duplicate_path.clone();
    std::fs::create_dir_all(&real_path)?;
    let canonical_real_path = real_path.canonicalize()?;

    let (hardlinks_ready_tx, hardlinks_ready_rx) = std::sync::mpsc::channel();
    let (resume_tx, resume_rx) = std::sync::mpsc::channel();
    crate::store::test_hooks::arm_after_lmdb_open(canonical_real_path, move |canonical_root| {
        let result = (|| -> std::io::Result<()> {
            std::fs::create_dir_all(&duplicate_for_hook)?;
            std::fs::hard_link(
                canonical_root.join("data.mdb"),
                duplicate_for_hook.join("data.mdb"),
            )?;
            std::fs::hard_link(
                canonical_root.join("lock.mdb"),
                duplicate_for_hook.join("lock.mdb"),
            )?;
            Ok(())
        })();
        hardlinks_ready_tx
            .send(result)
            .expect("hardlink readiness receiver dropped");
        resume_rx
            .recv_timeout(std::time::Duration::from_secs(10))
            .expect("test did not resume paused vault open");
    });

    let first_path = real_path;
    let first_open = std::thread::spawn(move || Vault::open(&first_path, test_config()).map(drop));
    match hardlinks_ready_rx
        .recv_timeout(std::time::Duration::from_secs(10))
        .expect("paused vault open did not create hardlink alias")
    {
        Ok(()) => {}
        Err(err) => {
            let _ = resume_tx.send(());
            panic!("failed to create hardlink alias during vault open: {err}");
        }
    }

    let second_path = duplicate_path;
    let second_open =
        std::thread::spawn(move || Vault::open(&second_path, test_config()).map(drop));

    std::thread::sleep(std::time::Duration::from_millis(50));
    resume_tx.send(()).expect("paused vault open exited early");

    let first_err = match first_open.join().expect("first vault open panicked") {
        Ok(()) => panic!("first vault open must fail closed on new hardlink alias"),
        Err(err) => err,
    };
    let second_err = match second_open.join().expect("second vault open panicked") {
        Ok(()) => panic!("second vault open must fail closed on new hardlink alias"),
        Err(err) => err,
    };

    assert_matches!(
        first_err,
        Error::VaultRootPreflight {
            problem: VaultRootProblem::MultipleHardLinks { link_count, .. },
            ..
        } if link_count >= 2
    );
    assert_matches!(
        second_err,
        Error::VaultRootPreflight {
            problem: VaultRootProblem::MultipleHardLinks { link_count, .. },
            ..
        } if link_count >= 2
    );
    Ok(())
}

/// ONE-1142 regression: without the `OwnedEnv` close path every
/// `Vault::open` leaks one pthread TLS key (LMDB allocates it in
/// `mdb_env_setup_locks`; only `mdb_env_close` frees it), and macOS caps a
/// process at `PTHREAD_KEYS_MAX = 512` keys — open #~509 fails with
/// `Io(EAGAIN)`. 600 sequential open→drop cycles in ONE process must all
/// succeed; only one env is alive at a time, so the loop is cheap.
#[test]
fn vault_open_drop_cycles_survive_pthread_key_limit() -> Result<()> {
    let mut config = test_config();
    config.map_size = 4 << 20;

    for i in 0..600_usize {
        let dir = tempfile::tempdir()?;
        let vault = Vault::open(dir.path(), config.clone()).unwrap_or_else(|err| {
            panic!("vault open #{i} failed (pthread-key leak regression): {err:?}")
        });
        drop(vault);
    }
    Ok(())
}

#[test]
fn batch_with_edges_and_entities() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let src = EntityId::now();
    let tgt = EntityId::now();
    let vector = [0.9_f32, 0.8, 0.7, 0.6];

    vault
        .batch()
        .put(&src, 1, test_time_range(1, 2), 3, b"src")
        .put(&tgt, 4, test_time_range(4, 5), 6, b"tgt")
        .vector(&src, &vector)
        .edge(&src, EdgeKind::BelongsTo, &tgt, 0.5)
        .commit()?;

    assert_eq!(vault.get(&src)?.ok_or(Error::EntityNotFound)?, b"src");
    assert_eq!(vault.get(&tgt)?.ok_or(Error::EntityNotFound)?, b"tgt");
    assert_eq!(
        vault.get_vector(&src)?.ok_or(Error::EntityNotFound)?,
        vector
    );

    let out = vault.edges_out(&src)?;
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].kind, EdgeKind::BelongsTo);
    assert_eq!(out[0].target, tgt);
    Ok(())
}

#[test]
fn edges_out_returns_all_edges_for_same_source() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let src = EntityId::now();
    let tgt_a = EntityId::now();
    let tgt_b = EntityId::now();
    let tgt_c = EntityId::now();
    let expected = [
        (EdgeKind::BelongsTo, tgt_a, 1.0_f32),
        (EdgeKind::Mentions, tgt_b, 0.6_f32),
        (EdgeKind::Supports, tgt_c, 0.9_f32),
    ];

    vault.put_edge(&src, expected[0].0, &expected[0].1, expected[0].2)?;
    vault.put_edge(&src, expected[1].0, &expected[1].1, expected[1].2)?;
    vault.put_edge(&src, expected[2].0, &expected[2].1, expected[2].2)?;

    let out = vault.edges_out(&src)?;
    assert_eq!(out.len(), expected.len());
    for (kind, target, weight) in expected {
        assert!(
            out.iter().any(|e| {
                e.kind == kind && e.target == target && (e.weight - weight).abs() < f32::EPSILON
            }),
            "missing edge ({kind:?}, {target:?}, {weight})"
        );
    }

    Ok(())
}

#[test]
fn opens_empty_vault_without_embedding_model() -> Result<()> {
    let temp_dir = tempfile::tempdir()?;
    let mut cfg = test_config();
    cfg.embedding_model = None;
    let vault = Vault::open(temp_dir.path(), cfg)?;
    assert_eq!(read_model_id(&vault)?, None);

    Ok(())
}

#[test]
fn stamps_embedding_model_on_empty_vault_open() -> Result<()> {
    let temp_dir = tempfile::tempdir()?;
    let mut cfg = test_config();
    cfg.embedding_model = Some("model-a".to_owned());
    let vault = Vault::open(temp_dir.path(), cfg)?;
    assert_eq!(read_model_id(&vault)?, Some("model-a".to_owned()));

    Ok(())
}

#[test]
fn opens_populated_vault_with_matching_embedding_model() -> Result<()> {
    let temp_dir = tempfile::tempdir()?;
    let mut cfg = test_config();
    cfg.embedding_model = Some("model-a".to_owned());
    let vault = Vault::open(temp_dir.path(), cfg.clone())?;
    let id = EntityId::now();
    vault.put_entity(&id, 1, test_time_range(1, 1), 1, b"node")?;
    vault.put_vector(&id, &[0.1, 0.2, 0.3, 0.4])?;
    drop(vault);

    let reopened = Vault::open(temp_dir.path(), cfg)?;
    assert_eq!(reopened.get_vector(&id)?, Some(vec![0.1, 0.2, 0.3, 0.4]));

    Ok(())
}

#[test]
fn rejects_populated_vault_missing_embedding_model_identity() -> Result<()> {
    let temp_dir = tempfile::tempdir()?;
    let path = temp_dir.path();
    let mut cfg = test_config();
    cfg.embedding_model = Some("model-a".to_owned());
    let vault = Vault::open(path, cfg.clone())?;
    let id = EntityId::now();
    vault.put_entity(&id, 1, test_time_range(1, 1), 1, b"node")?;
    vault.put_vector(&id, &[0.1, 0.2, 0.3, 0.4])?;

    {
        let mut wtxn = vault.store.env.write_txn()?;
        vault.store.hnsw_meta.delete(&mut wtxn, MODEL_ID_KEY)?;
        wtxn.commit()?;
    }
    drop(vault);

    let Err(err) = Vault::open(path, cfg) else {
        panic!("expected missing embedding model identity rejection");
    };
    assert_matches!(err, Error::InvalidConfig(ref message)
            if message.contains("missing embedding model identity"));

    Ok(())
}

#[test]
fn rejects_vault_missing_model_identity_when_hnsw_meta_marks_population() -> Result<()> {
    let temp_dir = tempfile::tempdir()?;
    let path = temp_dir.path();
    let mut cfg = test_config();
    cfg.embedding_model = Some("model-a".to_owned());
    let vault = Vault::open(path, cfg.clone())?;

    {
        let mut wtxn = vault.store.env.write_txn()?;
        vault.store.hnsw_meta.delete(&mut wtxn, MODEL_ID_KEY)?;
        vault
            .store
            .hnsw_meta
            .put(&mut wtxn, COUNT_KEY, &1_u64.to_le_bytes())?;
        wtxn.commit()?;
    }
    drop(vault);

    let Err(err) = Vault::open(path, cfg) else {
        panic!("expected missing embedding model identity rejection");
    };
    assert_matches!(err, Error::InvalidConfig(ref message)
            if message.contains("missing embedding model identity"));

    Ok(())
}

#[test]
fn rejects_populated_vault_open_without_requested_embedding_model() -> Result<()> {
    let temp_dir = tempfile::tempdir()?;
    let path = temp_dir.path();
    let mut cfg = test_config();
    cfg.embedding_model = Some("model-a".to_owned());
    let vault = Vault::open(path, cfg)?;
    let id = EntityId::now();
    vault.put_entity(&id, 1, test_time_range(1, 1), 1, b"node")?;
    vault.put_vector(&id, &[0.1, 0.2, 0.3, 0.4])?;
    drop(vault);

    let mut cfg = test_config();
    cfg.embedding_model = None;
    let Err(err) = Vault::open(path, cfg) else {
        panic!("expected missing requested embedding model rejection");
    };
    assert_matches!(err, Error::InvalidConfig(ref message)
            if message.contains("embedding model is required to open"));

    Ok(())
}

#[test]
fn detects_embedding_model_mismatch_on_populated_open() -> Result<()> {
    let temp_dir = tempfile::tempdir()?;
    let mut cfg = test_config();
    cfg.embedding_model = Some("model-a".to_owned());
    let vault = Vault::open(temp_dir.path(), cfg)?;
    let id = EntityId::now();
    vault.put_entity(&id, 1, test_time_range(1, 1), 1, b"node")?;
    vault.put_vector(&id, &[0.1, 0.2, 0.3, 0.4])?;
    drop(vault);

    let mut cfg = test_config();
    cfg.embedding_model = Some("model-b".to_owned());
    let Err(err) = Vault::open(temp_dir.path(), cfg) else {
        panic!("expected mismatch");
    };
    assert_matches!(err, Error::EmbeddingModelChanged {
            ref stored,
            ref requested
        } if stored == "model-a" && requested == "model-b");

    Ok(())
}

#[test]
fn rejects_vector_write_without_embedding_model_identity() -> Result<()> {
    let temp_dir = tempfile::tempdir()?;
    let mut cfg = test_config();
    cfg.embedding_model = None;
    let vault = Vault::open(temp_dir.path(), cfg)?;
    let id = EntityId::now();
    vault.put_entity(&id, 1, test_time_range(1, 1), 1, b"node")?;

    let Err(err) = vault.put_vector(&id, &[0.1, 0.2, 0.3, 0.4]) else {
        panic!("expected missing embedding model rejection");
    };
    assert_matches!(err, Error::InvalidConfig(ref message)
            if message.contains("embedding model is required before writing vectors"));
    assert_eq!(vault.get_vector(&id)?, None);

    Ok(())
}

#[test]
fn persists_hnsw_metric_and_structure_tags() -> Result<()> {
    let (temp_dir, vault) = open_test_vault();
    let raw = read_hnsw_config_record(&vault)?;
    assert_eq!(raw.len(), EXPECTED_HNSW_COMPATIBILITY_LEN);
    assert_eq!(raw[0], EXPECTED_HNSW_COMPATIBILITY_VERSION);
    assert_eq!(raw[25], EXPECTED_HNSW_DISTANCE_METRIC_COSINE);
    assert_eq!(raw[26], EXPECTED_HNSW_INDEX_STRUCTURE_FLAT_NSW);
    drop(vault);

    let reopened = Vault::open(temp_dir.path(), test_config())?;
    let raw = read_hnsw_config_record(&reopened)?;
    assert_eq!(raw.len(), EXPECTED_HNSW_COMPATIBILITY_LEN);
    assert_eq!(raw[0], EXPECTED_HNSW_COMPATIBILITY_VERSION);
    assert_eq!(raw[25], EXPECTED_HNSW_DISTANCE_METRIC_COSINE);
    assert_eq!(raw[26], EXPECTED_HNSW_INDEX_STRUCTURE_FLAT_NSW);
    Ok(())
}

#[test]
fn upgrades_empty_vault_with_legacy_hnsw_compatibility_record() -> Result<()> {
    let temp_dir = tempfile::tempdir()?;
    let path = temp_dir.path();
    let cfg = test_config();
    let vault = Vault::open(path, cfg.clone())?;
    let legacy = legacy_hnsw_compatibility_record(&cfg);
    write_hnsw_config_record(&vault, &legacy)?;
    drop(vault);

    let reopened = Vault::open(path, cfg)?;
    let raw = read_hnsw_config_record(&reopened)?;
    assert_eq!(raw.len(), EXPECTED_HNSW_COMPATIBILITY_LEN);
    assert_eq!(raw[0], EXPECTED_HNSW_COMPATIBILITY_VERSION);
    assert_eq!(raw[25], EXPECTED_HNSW_DISTANCE_METRIC_COSINE);
    assert_eq!(raw[26], EXPECTED_HNSW_INDEX_STRUCTURE_FLAT_NSW);
    Ok(())
}

#[test]
fn rejects_populated_vault_with_legacy_hnsw_compatibility_record() -> Result<()> {
    let temp_dir = tempfile::tempdir()?;
    let path = temp_dir.path();
    let cfg = test_config();
    let vault = Vault::open(path, cfg.clone())?;
    let id = EntityId::now();
    vault.put_entity(&id, 1, test_time_range(1, 1), 1, b"node")?;
    vault.put_vector(&id, &[0.1, 0.2, 0.3, 0.4])?;
    let legacy = legacy_hnsw_compatibility_record(&cfg);
    write_hnsw_config_record(&vault, &legacy)?;
    drop(vault);

    let Err(err) = Vault::open(path, cfg) else {
        panic!("expected legacy hnsw compatibility rejection");
    };
    assert_matches!(err, Error::HnswConfigChanged {
            ref stored,
            ref requested
        } if stored == "dimensions=4,m_max_0=64,ef_construction=200,distance_metric=missing,index_structure=missing"
            && requested == "dimensions=4,m_max_0=64,ef_construction=200,distance_metric=cosine,index_structure=flat_nsw");
    Ok(())
}

#[test]
fn detects_hnsw_metric_and_structure_mismatch_on_open() -> Result<()> {
    let (temp_dir, vault) = open_test_vault();
    let mut raw = read_hnsw_config_record(&vault)?;
    assert_eq!(raw.len(), EXPECTED_HNSW_COMPATIBILITY_LEN);
    raw[25] = 2;
    raw[26] = 2;
    write_hnsw_config_record(&vault, &raw)?;
    drop(vault);

    let Err(err) = Vault::open(temp_dir.path(), test_config()) else {
        panic!("expected hnsw metric/structure mismatch");
    };
    assert_matches!(err, Error::HnswConfigChanged {
            ref stored,
            ref requested
        } if stored == "dimensions=4,m_max_0=64,ef_construction=200,distance_metric=unknown(2),index_structure=unknown(2)"
            && requested == "dimensions=4,m_max_0=64,ef_construction=200,distance_metric=cosine,index_structure=flat_nsw");
    Ok(())
}

/// Consolidated from two single-knob clones (ONE-1145): each case flips one
/// knob of the persisted HNSW config identity and pins the EXACT
/// stored/requested literal strings of the typed gate error.
#[test]
fn detects_hnsw_config_and_dimension_mismatch_on_open() {
    type Reconfigure = fn(&mut VaultConfig);
    let cases: &[(&str, Reconfigure, &str)] = &[
        (
            "ef_construction_flip",
            |cfg: &mut VaultConfig| cfg.hnsw.ef_construction += 1,
            "dimensions=4,m_max_0=64,ef_construction=201,distance_metric=cosine,index_structure=flat_nsw",
        ),
        (
            "dimensions_flip",
            |cfg: &mut VaultConfig| cfg.dimensions = 8,
            "dimensions=8,m_max_0=64,ef_construction=200,distance_metric=cosine,index_structure=flat_nsw",
        ),
    ];

    for (case_name, reconfigure, requested_literal) in cases {
        let (temp_dir, vault) = open_test_vault();
        drop(vault);

        let mut cfg = test_config();
        reconfigure(&mut cfg);
        let Err(err) = Vault::open(temp_dir.path(), cfg) else {
            panic!("case {case_name}: expected hnsw config mismatch");
        };
        match err {
            Error::HnswConfigChanged { stored, requested } => {
                assert_eq!(
                    stored,
                    "dimensions=4,m_max_0=64,ef_construction=200,distance_metric=cosine,index_structure=flat_nsw",
                    "case {case_name}: stored literal"
                );
                assert_eq!(
                    requested, *requested_literal,
                    "case {case_name}: requested literal"
                );
            }
            other => panic!("case {case_name}: expected HnswConfigChanged, got {other:?}"),
        }
    }
}

#[test]
fn allows_ef_search_retuning_on_open() -> Result<()> {
    let (temp_dir, vault) = open_test_vault();
    let id = EntityId::now();
    vault.put_entity(&id, 1, test_time_range(1, 1), 1, b"node")?;
    vault.put_vector(&id, &[0.1, 0.2, 0.3, 0.4])?;
    drop(vault);

    let mut cfg = test_config();
    cfg.hnsw.ef_search = 512;
    let reopened = Vault::open(temp_dir.path(), cfg)?;
    drop(reopened);
    Ok(())
}

#[test]
fn rejects_populated_vault_missing_hnsw_compatibility_metadata() -> Result<()> {
    let temp_dir = tempfile::tempdir()?;
    let path = temp_dir.path();
    let vault = Vault::open(path, test_config())?;
    let id = EntityId::now();
    vault.put_entity(&id, 1, test_time_range(1, 1), 1, b"node")?;
    vault.put_vector(&id, &[0.1, 0.2, 0.3, 0.4])?;

    {
        let mut wtxn = vault.store.env.write_txn()?;
        vault.store.hnsw_meta.delete(&mut wtxn, HNSW_CONFIG_KEY)?;
        wtxn.commit()?;
    }
    drop(vault);

    let Err(err) = Vault::open(path, test_config()) else {
        panic!("expected missing compatibility metadata rejection");
    };
    assert_matches!(err, Error::InvalidConfig(ref message)
            if message.contains("missing complete vector/hnsw compatibility metadata"));
    Ok(())
}

#[test]
fn embedding_model_first_write_is_atomic() -> Result<()> {
    let temp_dir = tempfile::tempdir()?;
    let mut cfg = test_config();
    cfg.embedding_model = Some("model-x".to_owned());

    let vault = Vault::open(temp_dir.path(), cfg.clone())?;
    drop(vault);

    let vault = Vault::open(temp_dir.path(), cfg)?;
    drop(vault);

    let mut cfg2 = test_config();
    cfg2.embedding_model = Some("model-y".to_owned());
    let Err(err) = Vault::open(temp_dir.path(), cfg2) else {
        panic!("expected embedding model change rejection");
    };
    assert_matches!(err, Error::EmbeddingModelChanged { .. });

    Ok(())
}

#[test]
fn creates_contract_manifest_databases() -> Result<()> {
    // Also pins ONE-1093 feature-independence (formerly a separate test,
    // consolidated by ONE-1145): this test compiles and runs under BOTH the
    // default and `--features sync` configs and asserts the same 25-name
    // materialized set, including the sync_state/sync_queue rows below.
    let (_dir, vault) = open_test_vault();

    let contract_names: Vec<&str> = DB_MANIFEST.iter().map(|entry| entry.name).collect();
    assert_eq!(contract_names.len(), 25);
    assert_eq!(MAX_DBS, 32);
    assert_eq!(DB_MANIFEST[23].n, 24);
    assert_eq!(DB_MANIFEST[23].name, "sync_state");
    assert_eq!(DB_MANIFEST[24].n, 25);
    assert_eq!(DB_MANIFEST[24].name, "sync_queue");

    let expected_materialized: Vec<String> = expected_manifest_names()
        .iter()
        .map(|name| (*name).to_owned())
        .collect();
    assert_eq!(materialized_database_names(&vault)?, expected_materialized);

    Ok(())
}

#[test]
fn open_valid_existing_vault_passes_manifest_set_gate() -> Result<()> {
    let temp_dir = tempfile::tempdir()?;
    let path = temp_dir.path();
    {
        let vault = Vault::open(path, test_config())?;
        assert_eq!(
            materialized_database_names(&vault)?,
            expected_manifest_names()
                .iter()
                .map(|name| (*name).to_owned())
                .collect::<Vec<_>>()
        );
    }

    let reopened = Vault::open(path, test_config())?;
    drop(reopened);
    Ok(())
}

#[test]
fn open_rejects_rogue_manifest_database_name() -> Result<()> {
    let temp_dir = tempfile::tempdir()?;
    let path = temp_dir.path();
    {
        let vault = Vault::open(path, test_config())?;
        drop(vault);
    }
    create_raw_named_database(path, "future_manifest_26")?;

    let err = match Vault::open(path, test_config()) {
        Ok(_) => panic!("expected Vault::open to fail closed on rogue named DB"),
        Err(err) => err,
    };
    assert!(
        matches!(
            err,
            Error::DbManifestMismatch {
                ref missing,
                ref unexpected
            } if missing.is_empty() && unexpected == &vec!["future_manifest_26".to_owned()]
        ),
        "expected DB manifest mismatch for rogue name, got {err:?}"
    );
    Ok(())
}

/// Consolidated from three name-only clones (ONE-1145): one core DB plus the
/// two sync-era DBs (manifest rows 24/25). Removing ANY required manifest
/// name must fail closed with the exact missing-name payload — including the
/// sync DBs, which are part of the 25-name set regardless of features.
#[test]
fn open_rejects_missing_required_manifest_database_name() -> Result<()> {
    for missing_name in ["hnsw_meta", "sync_state", "sync_queue"] {
        let temp_dir = tempfile::tempdir()?;
        create_raw_vault_missing_manifest_name(temp_dir.path(), missing_name)?;

        let err = match Vault::open(temp_dir.path(), test_config()) {
            Ok(_) => panic!("expected Vault::open to fail closed on missing {missing_name}"),
            Err(err) => err,
        };
        assert!(
            matches!(
                err,
                Error::DbManifestMismatch {
                    ref missing,
                    ref unexpected
                } if missing == &vec![missing_name.to_owned()] && unexpected.is_empty()
            ),
            "expected DB manifest mismatch for missing {missing_name}, got {err:?}"
        );
    }
    Ok(())
}

#[test]
fn open_rejects_pre_fix_manifest_shape_at_storage_abi_gate() -> Result<()> {
    let temp_dir = tempfile::tempdir()?;
    let path = temp_dir.path();
    let stale_abi = STORAGE_ABI_VERSION - 1;
    create_raw_vault_missing_manifest_name(path, "sync_state")?;
    set_raw_storage_abi_version(path, Some(stale_abi))?;

    let err = match Vault::open(path, test_config()) {
        Ok(_) => panic!("expected Vault::open to reject stale ABI before manifest validation"),
        Err(err) => err,
    };
    assert!(
        matches!(
            err,
            Error::StorageAbiVersionChanged {
                stored: Some(stored),
                current: STORAGE_ABI_VERSION
            } if stored == stale_abi
        ),
        "expected storage ABI rejection for pre-fix manifest shape, got {err:?}"
    );
    Ok(())
}

#[test]
fn open_persists_storage_versions_on_create() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    assert_eq!(
        read_meta_u16(&vault, STORAGE_ABI_VERSION_KEY)?,
        Some(STORAGE_ABI_VERSION)
    );
    assert_eq!(
        read_meta_u16(&vault, STORAGE_SCHEMA_VERSION_KEY)?,
        Some(STORAGE_SCHEMA_VERSION)
    );
    Ok(())
}

#[test]
fn doctor_reflects_persisted_open_compatibility_values() -> Result<()> {
    let temp_dir = tempfile::tempdir()?;
    let mut cfg = test_config();
    cfg.embedding_model = Some("doctor-model-v1".to_owned());
    let vault = Vault::open(temp_dir.path(), cfg)?;

    let report = vault.doctor()?;
    serde_json::to_value(&report).expect("doctor report must serialize");

    assert_eq!(report.storage_abi_version, Some(STORAGE_ABI_VERSION));
    assert_eq!(report.storage_schema_version, Some(STORAGE_SCHEMA_VERSION));
    assert_eq!(
        report.embedding_model_id,
        Some("doctor-model-v1".to_owned())
    );
    assert_eq!(
        report.hnsw.record_state,
        VaultDoctorHnswRecordState::Current
    );
    assert_eq!(report.hnsw.vector_dimensions, Some(4));
    assert_eq!(report.hnsw.m_max_0, Some(64));
    assert_eq!(report.hnsw.ef_construction, Some(200));
    assert_eq!(report.hnsw.distance_metric.as_deref(), Some("cosine"));
    assert_eq!(report.hnsw.index_structure.as_deref(), Some("flat_nsw"));
    // Pinned hash of the portable analyzer manifest at ANALYZER_VERSION
    // "v3" (ONE-1118 emoji grapheme lane). Any manifest-affecting change
    // (version bump, channel set, normalization policy) must re-pin this.
    assert_eq!(
        report.analyzer_manifest_hash.as_deref(),
        Some("e0da35956883bf26e26881b73c515f2c9c7d11087ef813da026dc51c303e1002")
    );
    // Sha256 over the field-schema records with
    // POSTINGS_VALUE_FORMAT_VERSION = 2 (ONE-299 DUP_SORT postings).
    assert_eq!(
        report.bm25_field_schema_hash.as_deref(),
        Some("b7b78821908fdabc95ac85de7e17f157b0482d105037e8f6ecfa71e1ff158d6f")
    );
    assert_eq!(report.text_index_schema_version, Some(2));
    assert!(report.unreadable_fields.is_empty());
    assert_eq!(report.db_manifest.expected_count, 25);
    assert_eq!(report.db_manifest.present_count, 25);
    assert!(report.db_manifest.missing_names.is_empty());
    assert!(report.db_manifest.unexpected_names.is_empty());
    assert!(
        report
            .db_manifest
            .present_names
            .contains(&"vault_meta".to_owned())
    );
    assert!(
        report
            .db_manifest
            .present_names
            .contains(&"hnsw_meta".to_owned())
    );
    Ok(())
}

#[test]
fn doctor_reads_persisted_text_hash_keys() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let analyzer_hash = [0xAB; 32];
    let field_schema_hash = [0xCD; 32];

    {
        let mut wtxn = vault.store.env.write_txn()?;
        vault.store.vault_meta.put(
            &mut wtxn,
            crate::store::TEXT_ANALYZER_MANIFEST_HASH_KEY,
            &analyzer_hash,
        )?;
        vault.store.vault_meta.put(
            &mut wtxn,
            crate::store::TEXT_BM25_FIELD_SCHEMA_HASH_KEY,
            &field_schema_hash,
        )?;
        wtxn.commit()?;
    }

    let report = vault.doctor()?;
    assert_eq!(
        report.analyzer_manifest_hash.as_deref(),
        Some("abababababababababababababababababababababababababababababababab")
    );
    assert_eq!(
        report.bm25_field_schema_hash.as_deref(),
        Some("cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd")
    );
    assert!(report.unreadable_fields.is_empty());
    Ok(())
}

#[test]
fn doctor_does_not_write_data_file() -> Result<()> {
    let (temp_dir, vault) = open_test_vault();
    let data_file = temp_dir.path().join("data.mdb");
    let before = std::fs::metadata(&data_file)?;
    let before_modified = before.modified()?;
    let before_digest = Sha256::digest(std::fs::read(&data_file)?);

    let report = vault.doctor()?;
    assert_eq!(report.db_manifest.present_count, 25);

    let after = std::fs::metadata(&data_file)?;
    let after_digest = Sha256::digest(std::fs::read(&data_file)?);
    assert_eq!(after.len(), before.len());
    assert_eq!(after.modified()?, before_modified);
    assert_eq!(after_digest, before_digest);
    Ok(())
}

#[test]
fn doctor_reports_missing_and_legacy_metadata_without_gating() -> Result<()> {
    let temp_dir = tempfile::tempdir()?;
    let cfg = test_config();
    let vault = Vault::open(temp_dir.path(), cfg.clone())?;

    {
        let mut wtxn = vault.store.env.write_txn()?;
        vault
            .store
            .vault_meta
            .delete(&mut wtxn, STORAGE_ABI_VERSION_KEY)?;
        vault
            .store
            .vault_meta
            .delete(&mut wtxn, STORAGE_SCHEMA_VERSION_KEY)?;
        vault
            .store
            .vault_meta
            .delete(&mut wtxn, crate::store::TEXT_INDEX_SCHEMA_VERSION_KEY)?;
        vault
            .store
            .vault_meta
            .delete(&mut wtxn, crate::store::TEXT_ANALYZER_MANIFEST_HASH_KEY)?;
        vault
            .store
            .vault_meta
            .delete(&mut wtxn, crate::store::TEXT_BM25_FIELD_SCHEMA_HASH_KEY)?;
        vault.store.hnsw_meta.delete(&mut wtxn, MODEL_ID_KEY)?;
        vault.store.hnsw_meta.delete(&mut wtxn, HNSW_CONFIG_KEY)?;
        wtxn.commit()?;
    }

    let report = vault.doctor()?;
    assert_eq!(report.storage_abi_version, None);
    assert_eq!(report.storage_schema_version, None);
    assert_eq!(report.embedding_model_id, None);
    assert_eq!(
        report.hnsw.record_state,
        VaultDoctorHnswRecordState::Missing
    );
    assert_eq!(report.hnsw.vector_dimensions, None);
    assert_eq!(report.hnsw.distance_metric, None);
    assert_eq!(report.analyzer_manifest_hash, None);
    assert_eq!(report.bm25_field_schema_hash, None);
    assert_eq!(report.text_index_schema_version, None);
    assert!(report.unreadable_fields.is_empty());

    let legacy = legacy_hnsw_compatibility_record(&cfg);
    write_hnsw_config_record(&vault, &legacy)?;
    let report = vault.doctor()?;
    assert_eq!(report.hnsw.record_state, VaultDoctorHnswRecordState::Legacy);
    assert_eq!(report.hnsw.vector_dimensions, Some(4));
    assert_eq!(report.hnsw.m_max_0, Some(64));
    assert_eq!(report.hnsw.ef_construction, Some(200));
    assert_eq!(report.hnsw.distance_metric, None);
    assert_eq!(report.hnsw.index_structure, None);
    assert!(report.unreadable_fields.is_empty());
    Ok(())
}

#[test]
fn doctor_surfaces_corrupt_metadata_without_gating() -> Result<()> {
    let (_dir, vault) = open_test_vault();

    {
        let mut wtxn = vault.store.env.write_txn()?;
        vault
            .store
            .vault_meta
            .put(&mut wtxn, STORAGE_ABI_VERSION_KEY, &[0x01])?;
        wtxn.commit()?;
    }

    let report = vault.doctor()?;
    assert_eq!(report.storage_abi_version, None);
    assert!(
        report
            .unreadable_fields
            .contains(&"vault_meta.storage_abi_version".to_owned())
    );
    assert!(
        !report
            .unreadable_fields
            .contains(&"vault_meta.schema_version".to_owned())
    );
    Ok(())
}

#[test]
fn open_rejects_missing_or_stale_storage_abi_version() -> Result<()> {
    for (case_name, stale_value) in [("missing", None), ("older", Some(0_u16))] {
        let temp_dir = tempfile::tempdir()?;
        let path = temp_dir.path();
        {
            let _vault = Vault::open(path, test_config())?;
        }

        set_raw_storage_abi_version(path, stale_value)?;
        let err = match Vault::open(path, test_config()) {
            Ok(_) => panic!("case {case_name}: expected Vault::open to fail closed"),
            Err(err) => err,
        };
        assert!(
            matches!(err, Error::StorageAbiVersionChanged { .. }),
            "case {case_name}: expected storage ABI version error, got {err:?}"
        );
    }

    Ok(())
}

/// ONE-1097: fail-closed open-gate integration matrix.
///
/// Spec-derived from the canonical gate sequence documented at the top of
/// `crate::store` (ARCH-0019 storage invariants: "Schema versioned in
/// vault_meta. Reopen fails closed on analyzer or field-schema mismatch" +
/// the ARCH-0031 manifest-handshake state table). Every incompatible
/// config/model/analyzer state must abort `Vault::open` with its specific
/// typed [`ErrorKind`] BEFORE any usable `Vault` handle exists.
///
/// Per case this asserts:
/// 1. `Vault::open` fails with the contract-expected `ErrorKind` (the `Err`
///    return means no partial `Vault` is observable — there is no handle to
///    read or write through);
/// 2. a second open of the same directory reproduces the same gate error —
///    a leaked path registration would instead surface as
///    `VaultRootPreflight(DuplicateOpenRoot)`, and
///    partially-initialized state would change the error.
///
/// The `*_precedes_*` cases pin the documented gate ORDERING: ABI gate before
/// the DB-manifest gate (vault_meta is created first because the ABI gate
/// reads the version from it, so a missing `storage_abi_version` row is an
/// ABI-gate failure, not a manifest-gate failure), HNSW/dimension gate before
/// the embedding-model gate, and the model gate before the analyzer/BM25F
/// handshake in `Vault::open`.
#[test]
fn open_gate_matrix_fails_closed() -> Result<()> {
    struct GateCase {
        name: &'static str,
        /// Builds the vault directory in the incompatible state under test.
        prepare: fn(&Path) -> Result<()>,
        /// Config used for the (expected-to-fail) open attempts.
        open_config: fn() -> VaultConfig,
        expected_kind: ErrorKind,
    }

    fn create_default_vault(path: &Path) -> Result<()> {
        let _vault = Vault::open(path, test_config())?;
        Ok(())
    }

    fn populate_vector_data(vault: &Vault) -> Result<()> {
        let id = EntityId::now();
        vault.put_entity(&id, 1, test_time_range(1, 1), 1, b"gate-node")?;
        vault.put_vector(&id, &[0.1, 0.2, 0.3, 0.4])?;
        Ok(())
    }

    fn create_populated_vector_vault(path: &Path) -> Result<()> {
        let vault = Vault::open(path, test_config())?;
        populate_vector_data(&vault)
    }

    fn create_populated_text_vault(path: &Path) -> Result<()> {
        let vault = Vault::open(path, test_config())?;
        let id = EntityId::now();
        vault
            .batch()
            .put(&id, 1, test_time_range(1, 1), 1, b"gate-text")
            .text(&id, &[("body", "open gate matrix corpus")])
            .commit()?;
        Ok(())
    }

    fn put_vault_meta_row(path: &Path, key: &[u8], value: &[u8]) -> Result<()> {
        let vault = Vault::open(path, test_config())?;
        let mut wtxn = vault.store.env.write_txn()?;
        vault.store.vault_meta.put(&mut wtxn, key, value)?;
        wtxn.commit()?;
        Ok(())
    }

    fn delete_hnsw_meta_row(path: &Path, key: &[u8]) -> Result<()> {
        let vault = Vault::open(path, test_config())?;
        let mut wtxn = vault.store.env.write_txn()?;
        vault.store.hnsw_meta.delete(&mut wtxn, key)?;
        wtxn.commit()?;
        Ok(())
    }

    fn config_with_model(model: &str) -> VaultConfig {
        let mut cfg = test_config();
        cfg.embedding_model = Some(model.to_owned());
        cfg
    }

    // ── prepare fns, one per matrix row ────────────────────────────────

    fn prep_stale_abi(path: &Path) -> Result<()> {
        create_default_vault(path)?;
        set_raw_storage_abi_version(path, Some(STORAGE_ABI_VERSION - 1))
    }
    fn prep_missing_abi_row(path: &Path) -> Result<()> {
        create_default_vault(path)?;
        set_raw_storage_abi_version(path, None)
    }
    fn prep_unknown_schema(path: &Path) -> Result<()> {
        create_default_vault(path)?;
        put_vault_meta_row(
            path,
            STORAGE_SCHEMA_VERSION_KEY,
            &(STORAGE_SCHEMA_VERSION + 1).to_le_bytes(),
        )
    }
    fn prep_missing_manifest_db(path: &Path) -> Result<()> {
        create_raw_vault_missing_manifest_name(path, "edges_in")
    }
    fn prep_rogue_manifest_db(path: &Path) -> Result<()> {
        create_default_vault(path)?;
        create_raw_named_database(path, "rogue_gate_db_26")
    }
    fn prep_stale_abi_and_missing_manifest_db(path: &Path) -> Result<()> {
        create_raw_vault_missing_manifest_name(path, "edges_in")?;
        set_raw_storage_abi_version(path, Some(STORAGE_ABI_VERSION - 1))
    }
    fn prep_hnsw_metric_structure_flip(path: &Path) -> Result<()> {
        let vault = Vault::open(path, test_config())?;
        let mut raw = read_hnsw_config_record(&vault)?;
        assert!(
            raw.len() >= 27,
            "hnsw config record too short ({}) to flip metric/structure bytes",
            raw.len()
        );
        raw[25] = 2;
        raw[26] = 2;
        write_hnsw_config_record(&vault, &raw)
    }
    fn prep_legacy_hnsw_on_populated(path: &Path) -> Result<()> {
        let vault = Vault::open(path, test_config())?;
        populate_vector_data(&vault)?;
        let legacy = legacy_hnsw_compatibility_record(&test_config());
        write_hnsw_config_record(&vault, &legacy)
    }
    fn prep_populated_missing_hnsw_compat(path: &Path) -> Result<()> {
        create_populated_vector_vault(path)?;
        delete_hnsw_meta_row(path, HNSW_CONFIG_KEY)
    }
    fn prep_populated_missing_model_id(path: &Path) -> Result<()> {
        create_populated_vector_vault(path)?;
        delete_hnsw_meta_row(path, MODEL_ID_KEY)
    }
    fn prep_analyzer_hash_flip(path: &Path) -> Result<()> {
        create_populated_text_vault(path)?;
        put_vault_meta_row(
            path,
            crate::store::TEXT_ANALYZER_MANIFEST_HASH_KEY,
            &[0xCC; 32],
        )
    }
    fn prep_bm25_field_schema_flip(path: &Path) -> Result<()> {
        create_populated_text_vault(path)?;
        put_vault_meta_row(
            path,
            crate::store::TEXT_BM25_FIELD_SCHEMA_HASH_KEY,
            &[0xEE; 32],
        )
    }
    fn prep_text_and_vector_with_analyzer_flip(path: &Path) -> Result<()> {
        let vault = Vault::open(path, test_config())?;
        let id = EntityId::now();
        vault
            .batch()
            .put(&id, 1, test_time_range(1, 1), 1, b"gate-both")
            .text(&id, &[("body", "ordering corpus")])
            .commit()?;
        populate_vector_data(&vault)?;
        drop(vault);
        put_vault_meta_row(
            path,
            crate::store::TEXT_ANALYZER_MANIFEST_HASH_KEY,
            &[0xCC; 32],
        )
    }

    // ── open-config fns ────────────────────────────────────────────────

    fn cfg_default() -> VaultConfig {
        test_config()
    }
    fn cfg_dimensions_8() -> VaultConfig {
        let mut cfg = test_config();
        cfg.dimensions = 8;
        cfg
    }
    fn cfg_model_b() -> VaultConfig {
        config_with_model("matrix-model-b")
    }
    fn cfg_no_model() -> VaultConfig {
        let mut cfg = test_config();
        cfg.embedding_model = None;
        cfg
    }
    fn cfg_dimensions_8_and_model_b() -> VaultConfig {
        let mut cfg = config_with_model("matrix-model-b");
        cfg.dimensions = 8;
        cfg
    }

    let cases: Vec<GateCase> = vec![
        // Gate 2a: storage ABI (vault_meta["storage_abi_version"], u16 LE).
        GateCase {
            name: "stale_storage_abi_version",
            prepare: prep_stale_abi,
            open_config: cfg_default,
            expected_kind: ErrorKind::StorageAbiVersionChanged,
        },
        // The vault_meta-ordering rationale: a missing version row on an
        // existing vault is an ABI-gate failure (stored: None), NOT a
        // manifest-gate failure, because vault_meta is created/opened first
        // and the ABI gate reads from it.
        GateCase {
            name: "missing_storage_abi_row_is_abi_gate_not_manifest_gate",
            prepare: prep_missing_abi_row,
            open_config: cfg_default,
            expected_kind: ErrorKind::StorageAbiVersionChanged,
        },
        // Gate 2b: storage schema (vault_meta["schema_version"], u16 LE).
        GateCase {
            name: "unknown_storage_schema_version",
            prepare: prep_unknown_schema,
            open_config: cfg_default,
            expected_kind: ErrorKind::StorageSchemaVersionChanged,
        },
        // Gate 3: the 25-name DB manifest set (M1-1).
        GateCase {
            name: "missing_required_manifest_db",
            prepare: prep_missing_manifest_db,
            open_config: cfg_default,
            expected_kind: ErrorKind::DbManifestMismatch,
        },
        GateCase {
            name: "rogue_manifest_db",
            prepare: prep_rogue_manifest_db,
            open_config: cfg_default,
            expected_kind: ErrorKind::DbManifestMismatch,
        },
        // Ordering: ABI gate runs BEFORE the manifest gate.
        GateCase {
            name: "abi_gate_precedes_manifest_gate",
            prepare: prep_stale_abi_and_missing_manifest_db,
            open_config: cfg_default,
            expected_kind: ErrorKind::StorageAbiVersionChanged,
        },
        // Gate 5: HNSW/dimension compatibility (hnsw_meta["hnsw_config"], M1-3).
        GateCase {
            name: "hnsw_dimension_mismatch",
            prepare: create_default_vault,
            open_config: cfg_dimensions_8,
            expected_kind: ErrorKind::HnswConfigChanged,
        },
        GateCase {
            name: "hnsw_distance_metric_and_structure_mismatch",
            prepare: prep_hnsw_metric_structure_flip,
            open_config: cfg_default,
            expected_kind: ErrorKind::HnswConfigChanged,
        },
        GateCase {
            name: "legacy_hnsw_record_on_populated_vault",
            prepare: prep_legacy_hnsw_on_populated,
            open_config: cfg_default,
            expected_kind: ErrorKind::HnswConfigChanged,
        },
        GateCase {
            name: "populated_vault_missing_hnsw_compat_metadata",
            prepare: prep_populated_missing_hnsw_compat,
            open_config: cfg_default,
            expected_kind: ErrorKind::InvalidConfig,
        },
        // Gate 6: embedding-model identity (hnsw_meta["model_id"], M1-2).
        GateCase {
            name: "embedding_model_changed",
            prepare: create_populated_vector_vault,
            open_config: cfg_model_b,
            expected_kind: ErrorKind::EmbeddingModelChanged,
        },
        GateCase {
            name: "populated_vault_missing_model_id",
            prepare: prep_populated_missing_model_id,
            open_config: cfg_default,
            expected_kind: ErrorKind::InvalidConfig,
        },
        GateCase {
            name: "populated_vault_opened_without_model",
            prepare: create_populated_vector_vault,
            open_config: cfg_no_model,
            expected_kind: ErrorKind::InvalidConfig,
        },
        // Ordering: HNSW gate runs BEFORE the model gate.
        GateCase {
            name: "hnsw_gate_precedes_model_gate",
            prepare: create_populated_vector_vault,
            open_config: cfg_dimensions_8_and_model_b,
            expected_kind: ErrorKind::HnswConfigChanged,
        },
        // Gate 8: analyzer / BM25F handshake (vault_meta text-index keys,
        // ARCH-0031 state table: lang-flip → IncompatibleAnalyzer,
        // field-schema → Bm25FieldSchemaChanged).
        GateCase {
            name: "analyzer_manifest_hash_changed",
            prepare: prep_analyzer_hash_flip,
            open_config: cfg_default,
            expected_kind: ErrorKind::IncompatibleAnalyzer,
        },
        GateCase {
            name: "bm25_field_schema_changed",
            prepare: prep_bm25_field_schema_flip,
            open_config: cfg_default,
            expected_kind: ErrorKind::Bm25FieldSchemaChanged,
        },
        // Ordering: the model gate (Store::open) runs BEFORE the analyzer
        // handshake (Vault::open).
        GateCase {
            name: "model_gate_precedes_analyzer_gate",
            prepare: prep_text_and_vector_with_analyzer_flip,
            open_config: cfg_model_b,
            expected_kind: ErrorKind::EmbeddingModelChanged,
        },
    ];

    for case in &cases {
        let temp_dir = tempfile::tempdir()?;
        let path = temp_dir.path();
        (case.prepare)(path)
            .unwrap_or_else(|e| panic!("case {}: prepare failed: {e:?}", case.name));

        let err = match Vault::open(path, (case.open_config)()) {
            Ok(_) => panic!(
                "case {}: expected Vault::open to fail closed with {:?}",
                case.name, case.expected_kind
            ),
            Err(err) => err,
        };
        assert_eq!(
            err.kind(),
            case.expected_kind,
            "case {}: wrong gate fired: {err:?}",
            case.name
        );

        // Fail-closed also means no partial state survives the rejected
        // open: a second attempt must hit the SAME gate. A leaked path
        // registration would yield VaultRootPreflight(DuplicateOpenRoot)
        // instead; partially-initialized vault state would change which gate
        // fires.
        let second = match Vault::open(path, (case.open_config)()) {
            Ok(_) => panic!(
                "case {}: second open must fail closed identically",
                case.name
            ),
            Err(err) => err,
        };
        assert_eq!(
            second.kind(),
            case.expected_kind,
            "case {}: second open hit a different gate (partial state or \
             leaked path registration?): {second:?}",
            case.name
        );
        // Assert the re-open re-hit the GATE, not a leaked registration.
        assert!(
            !matches!(
                second,
                Error::VaultRootPreflight {
                    problem: VaultRootProblem::DuplicateOpenRoot { .. },
                    ..
                }
            ),
            "case {}: second open leaked a path registration instead of \
             re-hitting the gate: {second:?}",
            case.name
        );
    }

    Ok(())
}

#[test]
fn context_pack_run_serialized_toon_end_to_end() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let a = EntityId::now();
    let b = EntityId::now();
    let claim_subject = seeded_entity_id(0xC1A1);

    let payload_a = valid_claim_body_bytes("goal.learning", "Learn Japanese by June");
    let payload_b = rmp_serde::to_vec_named(&serde_json::json!({ "name": "Alice" }))
        .map_err(|_| Error::InvalidKey)?;

    vault
        .batch()
        .put(&claim_subject, 4, test_time_range(99, 99), 100, b"subject")
        .put(&a, 0, test_time_range(100, 100), 101, &payload_a)
        .text(&a, &[("body", "learn japanese")])
        .put(&b, 4, test_time_range(102, 102), 103, &payload_b)
        .edge(&a, EdgeKind::Mentions, &b, 1.0)
        .commit()?;

    let output = vault
        .context_pack()
        .search_text("japanese", 10)
        .edge_hop(1)
        .format(PackFormat::Toon)
        .run_serialized()?;
    assert!(!output.is_empty());

    let text = String::from_utf8(output).map_err(|_| Error::InvalidKey)?;
    assert!(text.contains("claims"));
    Ok(())
}

/// ONE-1118 AC3 round-trip at the vault level (ARCH-0031 dispatch row
/// "Emoji / unknown → Grapheme per token"): an emoji-only doc is
/// retrievable by an emoji-only query, and a multi-codepoint ZWJ cluster
/// indexes as exactly ONE token — a member-emoji query must not match it.
#[test]
fn emoji_doc_round_trips_through_text_search() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let crab_doc = EntityId::now();
    let family_doc = EntityId::now();
    let family = "\u{1F468}\u{200D}\u{1F469}\u{200D}\u{1F467}\u{200D}\u{1F466}"; // 👨‍👩‍👧‍👦

    vault
        .batch()
        .put(&crab_doc, 1, test_time_range(1, 1), 1, b"emoji-crab")
        .text(&crab_doc, &[("body", "🦀🔥")])
        .put(&family_doc, 1, test_time_range(2, 2), 2, b"emoji-family")
        .text(&family_doc, &[("body", family)])
        .commit()?;

    // AC3: doc "🦀🔥" retrievable by query "🦀".
    let hits = vault.search_text("🦀", 10)?;
    assert!(
        hits.iter().any(|h| h.id == crab_doc),
        "emoji-only query must retrieve the emoji doc"
    );

    // A member emoji of the ZWJ cluster must NOT match: the cluster is one
    // token. A codepoint-per-token implementation would match here.
    let hits = vault.search_text("\u{1F468}", 10)?;
    assert!(
        !hits.iter().any(|h| h.id == family_doc),
        "ZWJ member emoji must not match the whole-cluster token"
    );

    // The whole-cluster query does match.
    let hits = vault.search_text(family, 10)?;
    assert!(
        hits.iter().any(|h| h.id == family_doc),
        "whole-cluster query must retrieve the ZWJ doc"
    );
    Ok(())
}

/// ONE-1118 AC4: a populated text index stamped by the previous analyzer
/// version must fail closed at `Vault::open` with `IncompatibleAnalyzer` —
/// never silently reopen and score v3 queries against postings written by
/// the emoji-dropping v2 tokenizer. The stored manifest is rewritten to be
/// byte-identical to the current one except `analyzer_version: "v2"`, with
/// a matching (self-consistent) hash, so ONLY the version bump trips the
/// handshake.
#[test]
fn populated_v2_analyzer_manifest_fails_closed_on_open() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let path = temp.path();

    {
        let vault = Vault::open(path, test_config())?;
        let id = EntityId::now();
        vault
            .batch()
            .put(&id, 1, test_time_range(1, 1), 1, b"emoji-handshake")
            .text(&id, &[("body", "emoji handshake corpus 🦀")])
            .commit()?;

        let mut wtxn = vault.store.env.write_txn()?;
        let stored = vault
            .store
            .vault_meta
            .get(&wtxn, crate::store::TEXT_ANALYZER_MANIFEST_KEY)?
            .expect("populated vault must have a stored analyzer manifest")
            .to_vec();
        let mut manifest: AnalyzerManifest =
            serde_json::from_slice(&stored).expect("stored manifest must parse");
        assert_eq!(manifest.analyzer_version, ANALYZER_VERSION);
        assert_eq!(manifest.analyzer_version, "v3");
        manifest.analyzer_version = "v2".to_owned();
        let json = manifest.canonical_json().expect("canonical json");
        let hash = manifest.canonical_hash().expect("canonical hash");
        vault.store.vault_meta.put(
            &mut wtxn,
            crate::store::TEXT_ANALYZER_MANIFEST_KEY,
            json.as_bytes(),
        )?;
        vault.store.vault_meta.put(
            &mut wtxn,
            crate::store::TEXT_ANALYZER_MANIFEST_HASH_KEY,
            &hash,
        )?;
        wtxn.commit()?;
    }

    let err = match Vault::open(path, test_config()) {
        Ok(_) => panic!("v2-stamped populated index must fail closed on open"),
        Err(err) => err,
    };
    assert_eq!(err.kind(), ErrorKind::IncompatibleAnalyzer);
    Ok(())
}

#[test]
fn entity_id_now_is_monotonic_lexicographically() {
    let mut prev = EntityId::now();
    let mut saw_increase = false;
    for _ in 0..128 {
        let next = EntityId::now();
        assert!(prev <= next, "EntityId::now() regressed: prev > next");
        saw_increase |= prev < next;
        prev = next;
    }
    assert!(
        saw_increase,
        "expected EntityId::now() to advance at least once"
    );
}

const PINNED_EDGE_KIND_DISCRIMINANTS: [(u8, EdgeKind); 20] = [
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
];

#[test]
fn edge_kind_discriminants_match_arch_0034_contract() {
    for (disc, kind) in PINNED_EDGE_KIND_DISCRIMINANTS {
        assert_eq!(kind as u8, disc, "{kind:?} discriminant drifted");
    }
}

#[test]
fn edge_kind_u8_round_trip_accepts_pinned_range() {
    for (disc, expected) in PINNED_EDGE_KIND_DISCRIMINANTS {
        let kind = EdgeKind::try_from_u8(disc).expect("valid discriminant");
        assert_eq!(kind, expected);
        assert_eq!(kind as u8, disc);
    }
    assert!(EdgeKind::try_from_u8(20).is_none());
}

#[test]
fn edge_value_layout_round_trips_all_contract_edge_kinds() -> Result<()> {
    for (i, (kind, layout)) in CONTRACT_EDGE_VALUE_LAYOUTS.iter().copied().enumerate() {
        let weight = 0.25 + (i as f32 * 0.03125);
        let created_at = 1_772_000_000 + i as u64;
        let vad = contract_vad(i);
        let encode_vad = match layout {
            ContractEdgeLayout::Structural => Vad::NEUTRAL,
            ContractEdgeLayout::SemanticBare => vad,
        };

        let value = encode_edge_value(kind, weight, created_at, encode_vad, None)?;
        assert_eq!(
            value.len(),
            layout.bytes(),
            "wrong value length for {kind:?}"
        );
        assert_common_edge_value_fields(&value, weight, created_at);

        let decoded = decode_edge_value_for_kind(kind, &value)?;
        assert_f32_exact(decoded.weight, weight);
        assert_eq!(decoded.created_at, created_at);
        assert_eq!(decoded.provenance, None);

        match layout {
            ContractEdgeLayout::Structural => {
                assert_eq!(decoded.vad, None, "structural {kind:?} must not carry VAD");
            }
            ContractEdgeLayout::SemanticBare => {
                assert_vad_bytes(&value, vad);
                let decoded_vad = decoded.vad.expect("semantic-bare edge must carry VAD");
                assert_vad_exact(decoded_vad, vad);
            }
        }
    }

    Ok(())
}

#[test]
fn semantic_provenance_round_trips_vad_and_hot_flags() -> Result<()> {
    let flags = EdgeProvenanceFlags {
        confirmation_status: EdgeConfirmationStatus::Confirmed,
        actor_class: EdgeActorClass::Agent,
    };

    for (i, (kind, layout)) in CONTRACT_EDGE_VALUE_LAYOUTS.iter().copied().enumerate() {
        if layout != ContractEdgeLayout::SemanticBare {
            continue;
        }

        let weight = 0.5 + (i as f32 * 0.015625);
        let created_at = 1_773_000_000 + i as u64;
        let vad = contract_vad(i);

        let value = encode_edge_value(kind, weight, created_at, vad, Some(flags))?;
        assert_eq!(
            value.len(),
            EDGE_VALUE_SEMANTIC_PROVENANCED_LEN,
            "provenanced {kind:?} must write {EDGE_VALUE_SEMANTIC_PROVENANCED_LEN} B"
        );
        assert_common_edge_value_fields(&value, weight, created_at);
        assert_vad_bytes(&value, vad);
        assert_eq!(value[24], EdgeConfirmationStatus::Confirmed as u8);
        assert_eq!(value[25], EdgeActorClass::Agent as u8);

        let decoded = decode_edge_value_for_kind(kind, &value)?;
        assert_f32_exact(decoded.weight, weight);
        assert_eq!(decoded.created_at, created_at);
        assert_vad_exact(decoded.vad.expect("provenanced edge must carry VAD"), vad);
        assert_eq!(decoded.provenance, Some(flags));
    }

    Ok(())
}

#[test]
fn decode_edge_value_rejects_non_contract_lengths() {
    for len in [0_usize, 13, 25, 27] {
        let value = vec![0_u8; len];
        let err = decode_edge_value(&value).expect_err("expected invalid edge value length");
        assert!(
            matches!(err, Error::CorruptedIndex("edge value")),
            "length {len} returned wrong error: {err:?}"
        );
    }
}

#[test]
fn decode_edge_value_for_kind_rejects_kind_layout_mismatches() {
    let vad = Vad {
        valence: 0.25,
        arousal: 0.5,
        dominance: 0.75,
    };
    let cases = [
        (
            "structural kind with semantic-bare value",
            EdgeKind::ChildOf,
            contract_semantic_bare_value(0.8, 1_772_000_100, vad),
        ),
        (
            "structural kind with semantic-provenanced value",
            EdgeKind::AssignedTo,
            contract_semantic_provenanced_value(0.7, 1_772_000_101, vad),
        ),
        (
            "semantic kind with structural value",
            EdgeKind::Mentions,
            contract_structural_value(0.6, 1_772_000_102),
        ),
    ];

    for (name, kind, value) in cases {
        let err = decode_edge_value_for_kind(kind, &value).expect_err(name);
        assert!(
            matches!(err, Error::CorruptedIndex("edge value")),
            "{name}: wrong error: {err:?}"
        );
    }
}

#[test]
fn encode_edge_value_rejects_structural_non_neutral_vad() {
    let err = encode_edge_value(
        EdgeKind::BelongsTo,
        0.5,
        1_772_000_103,
        Vad {
            valence: 0.25,
            arousal: 0.0,
            dominance: 0.0,
        },
        None,
    )
    .expect_err("structural edge must reject non-neutral VAD");

    assert!(
        matches!(
            err,
            Error::InvariantViolation("structural edges do not carry VAD")
        ),
        "wrong error: {err:?}"
    );
}

#[test]
fn all_entity_type_prefixes() {
    use crate::types::{
        ENTITY_TYPE_REGISTRY, EntityClassification, TypeByteBand, band_of, is_structural_kind,
        short_id_prefix,
    };

    // ARCH-0002 / oneiron-contracts.ts §1 pinned storage ABI: per registry
    // row (kind id, type byte, short-id prefix, classification, band).
    // CLAIM=semantic ("deliberately NOT a StructuralKind"); TURN..NOTIFICATION
    // = core (band 1–63); COMPANION_REGISTER = companion pack (band
    // 64–79); TASK_LIST/TASK/MACHINE/CODE_ARTIFACT = productivity pack
    // (band 80–99); REDACTION_AUDIT/MODEL/POLICY_MANIFEST/
    // FEDERATION_GRANT/ACCESS_GRANT/PSYCH_PROFILE = maintenance (band 120+).
    type RegistryRow = (
        &'static str,
        u8,
        Option<&'static str>,
        EntityClassification,
        TypeByteBand,
    );
    let expected: &[RegistryRow] = &[
        (
            "CLAIM",
            0,
            Some("cl"),
            EntityClassification::Semantic,
            TypeByteBand::Semantic,
        ),
        (
            "TURN",
            1,
            Some("tn"),
            EntityClassification::Core,
            TypeByteBand::Core,
        ),
        (
            "SESSION",
            2,
            Some("ss"),
            EntityClassification::Core,
            TypeByteBand::Core,
        ),
        (
            "MESSAGE",
            3,
            Some("ms"),
            EntityClassification::Core,
            TypeByteBand::Core,
        ),
        (
            "PERSON",
            4,
            Some("pr"),
            EntityClassification::Core,
            TypeByteBand::Core,
        ),
        (
            "RELATIONSHIP",
            5,
            Some("rl"),
            EntityClassification::Core,
            TypeByteBand::Core,
        ),
        (
            "EVENT",
            6,
            Some("ev"),
            EntityClassification::Core,
            TypeByteBand::Core,
        ),
        (
            "SKILL",
            7,
            Some("sk"),
            EntityClassification::Core,
            TypeByteBand::Core,
        ),
        (
            "SUMMARY",
            8,
            Some("sm"),
            EntityClassification::Core,
            TypeByteBand::Core,
        ),
        (
            "PLACE",
            9,
            Some("pl"),
            EntityClassification::Core,
            TypeByteBand::Core,
        ),
        (
            "ASSET_TEXT",
            10,
            Some("tx"),
            EntityClassification::Core,
            TypeByteBand::Core,
        ),
        (
            "CONVERSATION",
            11,
            Some("cv"),
            EntityClassification::Core,
            TypeByteBand::Core,
        ),
        (
            "ORG",
            12,
            Some("og"),
            EntityClassification::Core,
            TypeByteBand::Core,
        ),
        (
            "FACET",
            13,
            Some("fc"),
            EntityClassification::Core,
            TypeByteBand::Core,
        ),
        (
            "WORLD",
            14,
            Some("wd"),
            EntityClassification::Core,
            TypeByteBand::Core,
        ),
        (
            "ASSET",
            15,
            Some("as"),
            EntityClassification::Core,
            TypeByteBand::Core,
        ),
        (
            "NOTIFICATION",
            16,
            Some("nt"),
            EntityClassification::Core,
            TypeByteBand::Core,
        ),
        (
            "COMPANION_REGISTER",
            64,
            Some("cr"),
            EntityClassification::Pack,
            TypeByteBand::Companion,
        ),
        (
            "TASK_LIST",
            80,
            Some("tl"),
            EntityClassification::Pack,
            TypeByteBand::Productivity,
        ),
        (
            "TASK",
            81,
            Some("tk"),
            EntityClassification::Pack,
            TypeByteBand::Productivity,
        ),
        (
            "MACHINE",
            82,
            Some("mc"),
            EntityClassification::Pack,
            TypeByteBand::Productivity,
        ),
        (
            "CODE_ARTIFACT",
            83,
            Some("cd"),
            EntityClassification::Pack,
            TypeByteBand::Productivity,
        ),
        (
            "REDACTION_AUDIT",
            120,
            None,
            EntityClassification::Maintenance,
            TypeByteBand::InducedDynamicMaintenance,
        ),
        // ONE-1138 ratified: MODEL = engine-authored maintenance kind, type
        // byte 121, short-ID prefix `mo` RESERVED, band 120+ — MACHINE (82)
        // reuse rejected (kind = shape, DEC-0005 §7).
        (
            "MODEL",
            121,
            Some("mo"),
            EntityClassification::Maintenance,
            TypeByteBand::InducedDynamicMaintenance,
        ),
        (
            "POLICY_MANIFEST",
            123,
            None,
            EntityClassification::Maintenance,
            TypeByteBand::InducedDynamicMaintenance,
        ),
        (
            "FEDERATION_GRANT",
            124,
            None,
            EntityClassification::Maintenance,
            TypeByteBand::InducedDynamicMaintenance,
        ),
        (
            "ACCESS_GRANT",
            128,
            None,
            EntityClassification::Maintenance,
            TypeByteBand::InducedDynamicMaintenance,
        ),
        (
            "PSYCH_PROFILE",
            ENTITY_TYPE_PSYCH_PROFILE,
            None,
            EntityClassification::Maintenance,
            TypeByteBand::InducedDynamicMaintenance,
        ),
    ];

    let actual: Vec<RegistryRow> = ENTITY_TYPE_REGISTRY
        .iter()
        .map(|entry| {
            (
                entry.kind,
                entry.type_byte,
                entry.short_id_prefix,
                entry.classification,
                entry.band,
            )
        })
        .collect();
    assert_eq!(actual.as_slice(), expected);

    for (name, byte, prefix, classification, band) in expected {
        match prefix {
            Some(prefix) => {
                let got = short_id_prefix(*byte).unwrap_or_else(|err| {
                    panic!("case {name}: expected prefix {prefix:?}, got err {err:?}")
                });
                assert_eq!(
                    got, *prefix,
                    "case {name}: expected prefix {prefix:?}, got {got:?}"
                );
            }
            None => assert!(
                short_id_prefix(*byte).is_err(),
                "case {name}: expected no short-id prefix"
            ),
        }

        // Registry band metadata must agree with the total band function.
        assert_eq!(
            band_of(*byte),
            *band,
            "case {name}: band_of({byte}) disagrees with registry band"
        );

        // StructuralKind = registered core|pack rows ONLY. CLAIM (semantic)
        // and REDACTION_AUDIT (maintenance) are NOT StructuralKinds.
        let expect_structural = matches!(
            classification,
            EntityClassification::Core | EntityClassification::Pack
        );
        assert_eq!(
            is_structural_kind(*byte),
            expect_structural,
            "case {name}: is_structural_kind({byte})"
        );
    }

    assert!(short_id_prefix(99).is_err());
    assert!(short_id_prefix(255).is_err());
}

#[test]
fn type_byte_band_allocation_matches_contract() {
    use crate::types::{
        TYPE_BYTE_BAND_COMPANION_END, TYPE_BYTE_BAND_COMPANION_START, TYPE_BYTE_BAND_CORE_END,
        TYPE_BYTE_BAND_CORE_START, TYPE_BYTE_BAND_CRM_END, TYPE_BYTE_BAND_CRM_START,
        TYPE_BYTE_BAND_MAINTENANCE_START, TYPE_BYTE_BAND_PRODUCTIVITY_END,
        TYPE_BYTE_BAND_PRODUCTIVITY_START, TYPE_BYTE_SEMANTIC, TypeByteBand, band_of,
        is_structural_kind, validate_entity_type,
    };

    // contracts.ts §1 typeByteBands — the LOCKED 6-band allocation:
    // 0 semantic / 1–63 CORE / 64–79 companion / 80–99 productivity /
    // 100–119 CRM / 120+ induced-dynamic-maintenance. Boundary constants
    // pinned as literals so an off-by-one allocation FAILS here.
    assert_eq!(TYPE_BYTE_SEMANTIC, 0);
    assert_eq!(TYPE_BYTE_BAND_CORE_START, 1);
    assert_eq!(TYPE_BYTE_BAND_CORE_END, 63);
    assert_eq!(TYPE_BYTE_BAND_COMPANION_START, 64);
    assert_eq!(TYPE_BYTE_BAND_COMPANION_END, 79);
    assert_eq!(TYPE_BYTE_BAND_PRODUCTIVITY_START, 80);
    assert_eq!(TYPE_BYTE_BAND_PRODUCTIVITY_END, 99);
    assert_eq!(TYPE_BYTE_BAND_CRM_START, 100);
    assert_eq!(TYPE_BYTE_BAND_CRM_END, 119);
    assert_eq!(TYPE_BYTE_BAND_MAINTENANCE_START, 120);

    // band_of is total over all 256 bytes. Expected values are written from
    // the contract's literal band edges, independent of the implementation.
    for byte in u8::MIN..=u8::MAX {
        let expected = if byte == 0 {
            TypeByteBand::Semantic
        } else if byte <= 63 {
            TypeByteBand::Core
        } else if byte <= 79 {
            TypeByteBand::Companion
        } else if byte <= 99 {
            TypeByteBand::Productivity
        } else if byte <= 119 {
            TypeByteBand::Crm
        } else {
            TypeByteBand::InducedDynamicMaintenance
        };
        assert_eq!(band_of(byte), expected, "band_of({byte})");
    }

    // is_structural_kind: false for the semantic byte 0 and the registered
    // maintenance kinds 120/121/123/124/128; true for every REGISTERED core
    // (1..=16) and pack (64/80/81/82/83) kind. Byte 122 is reserved for
    // AUTHORITY_LOG, and 125..=127 are reserved for future maintenance
    // substrates, but none are registered yet.
    assert!(!is_structural_kind(0), "CLAIM is NOT a StructuralKind");
    assert!(
        !is_structural_kind(120),
        "REDACTION_AUDIT is NOT a StructuralKind"
    );
    assert!(
        !is_structural_kind(121),
        "MODEL is NOT a StructuralKind (ONE-1138: engine-authored maintenance)"
    );
    assert!(
        !is_structural_kind(122),
        "AUTHORITY_LOG byte 122 is reserved but not a StructuralKind"
    );
    assert!(
        !is_structural_kind(123),
        "POLICY_MANIFEST is NOT a StructuralKind (GATE-001: vault-resident maintenance)"
    );
    assert!(
        !is_structural_kind(124),
        "FEDERATION_GRANT is NOT a StructuralKind (FED-001: shared-vault membership)"
    );
    assert!(
        !is_structural_kind(125),
        "CONNECTION_RECORD byte 125 is reserved but not a StructuralKind"
    );
    assert!(
        !is_structural_kind(126),
        "DIAGNOSTIC byte 126 is reserved but not a StructuralKind"
    );
    assert!(
        !is_structural_kind(127),
        "FEDERATION_KEY_ENVELOPE byte 127 is reserved but not a StructuralKind"
    );
    assert!(
        !is_structural_kind(128),
        "ACCESS_GRANT is NOT a StructuralKind (EIRI-004: companion control plane)"
    );
    for byte in 1..=16_u8 {
        assert!(is_structural_kind(byte), "core byte {byte}");
    }
    for byte in [64_u8, 80, 81, 82, 83] {
        assert!(is_structural_kind(byte), "pack byte {byte}");
    }

    // Unregistered bytes — including bytes INSIDE structural bands — are not
    // StructuralKinds, and the existing write-path gate still rejects them
    // with the same typed error. (122 is reserved for AUTHORITY_LOG, while
    // 125..=127 are reserved for future maintenance substrates, but all
    // remain unregistered.)
    for byte in [17_u8, 63, 79, 84, 99, 100, 119, 122, 125, 126, 127, 255] {
        assert!(!is_structural_kind(byte), "unregistered byte {byte}");
        assert!(
            matches!(
                validate_entity_type(byte),
                Err(Error::InvalidEntityType(rejected)) if rejected == byte
            ),
            "unregistered byte {byte} must stay rejected by validate_entity_type"
        );
    }
}

#[test]
fn structural_kind_registration_vets_bands_and_collisions_transactionally() -> Result<()> {
    use crate::types::{TypeByteBand, entity_type_registry_entry};

    let (_dir, vault) = open_test_vault();

    let err = vault
        .register_structural_kind(63, "cx", TypeByteBand::Core, "bad-core")
        .expect_err("CORE bytes must not be dynamically registered");
    assert_eq!(err.kind(), ErrorKind::StructuralKindBandViolation);
    let err = vault
        .register_structural_kind(0, "sx", TypeByteBand::Semantic, "bad-semantic")
        .expect_err("semantic byte 0 must not be dynamically registered");
    assert_eq!(err.kind(), ErrorKind::StructuralKindBandViolation);
    assert!(
        vault_meta_rows_with_prefix(&vault, STRUCTURAL_KIND_REGISTRY_KEY_PREFIX)?.is_empty(),
        "rejected band claims must not persist registry rows"
    );

    let err = vault
        .register_structural_kind(64, "np", TypeByteBand::Companion, "notes-pack")
        .expect_err("companion register byte 64 is statically reserved");
    assert_eq!(err.kind(), ErrorKind::StructuralKindCollision);
    assert_matches!(err, Error::StructuralKindTypeByteCollision(64));
    assert!(
        vault_meta_rows_with_prefix(&vault, STRUCTURAL_KIND_REGISTRY_KEY_PREFIX)?.is_empty(),
        "static-byte rejection must not persist registry rows"
    );

    let companion =
        vault.register_structural_kind(65, "np", TypeByteBand::Companion, "notes-pack")?;
    assert_eq!(companion.type_byte, 65);
    assert_eq!(companion.short_id_prefix, "np");
    assert!(entity_type_registry_entry(companion.type_byte).is_none());

    let err = vault
        .register_structural_kind(80, "cx", TypeByteBand::Companion, "wrong-band")
        .expect_err("byte 80 is productivity, not companion");
    assert_eq!(err.kind(), ErrorKind::StructuralKindBandViolation);
    let err = vault
        .register_structural_kind(100, "cx", TypeByteBand::Companion, "wrong-band")
        .expect_err("byte 100 is CRM, not companion");
    assert_eq!(err.kind(), ErrorKind::StructuralKindBandViolation);

    vault.register_structural_kind(84, "pd", TypeByteBand::Productivity, "productivity-pack")?;
    vault.register_structural_kind(100, "cm", TypeByteBand::Crm, "crm-pack")?;

    let before = vault_meta_rows_with_prefix(&vault, STRUCTURAL_KIND_REGISTRY_KEY_PREFIX)?;
    let err = vault
        .register_structural_kind(65, "nx", TypeByteBand::Companion, "duplicate-byte")
        .expect_err("duplicate type byte must be rejected");
    assert_eq!(err.kind(), ErrorKind::StructuralKindCollision);
    assert_matches!(err, Error::StructuralKindTypeByteCollision(65));
    assert_eq!(
        vault_meta_rows_with_prefix(&vault, STRUCTURAL_KIND_REGISTRY_KEY_PREFIX)?,
        before,
        "duplicate-byte rejection must not mutate vault_meta"
    );

    let err = vault
        .register_structural_kind(66, "np", TypeByteBand::Companion, "duplicate-prefix")
        .expect_err("duplicate dynamic prefix must be rejected");
    assert_eq!(err.kind(), ErrorKind::StructuralKindCollision);
    assert_matches!(err, Error::StructuralKindPrefixCollision(ref prefix) if prefix == "np");
    assert_eq!(
        vault_meta_rows_with_prefix(&vault, STRUCTURAL_KIND_REGISTRY_KEY_PREFIX)?,
        before,
        "duplicate-prefix rejection must not mutate vault_meta"
    );

    let err = vault
        .register_structural_kind(66, "tn", TypeByteBand::Companion, "static-prefix")
        .expect_err("static short-id prefixes must not be reused");
    assert_eq!(err.kind(), ErrorKind::StructuralKindCollision);
    assert_matches!(err, Error::StructuralKindPrefixCollision(ref prefix) if prefix == "tn");
    assert_eq!(
        vault_meta_rows_with_prefix(&vault, STRUCTURAL_KIND_REGISTRY_KEY_PREFIX)?,
        before,
        "static-prefix rejection must not mutate vault_meta"
    );

    let err = vault
        .register_structural_kind(66, "cr", TypeByteBand::Companion, "static-prefix")
        .expect_err("companion register short-id prefix must not be reused");
    assert_eq!(err.kind(), ErrorKind::StructuralKindCollision);
    assert_matches!(err, Error::StructuralKindPrefixCollision(ref prefix) if prefix == "cr");
    assert_eq!(
        vault_meta_rows_with_prefix(&vault, STRUCTURAL_KIND_REGISTRY_KEY_PREFIX)?,
        before,
        "static-prefix rejection must not mutate vault_meta"
    );

    let err = vault
        .register_structural_kind(80, "px", TypeByteBand::Productivity, "static-byte")
        .expect_err("static pack bytes must not be shadowed");
    assert_eq!(err.kind(), ErrorKind::StructuralKindCollision);
    assert_matches!(err, Error::StructuralKindTypeByteCollision(80));
    assert_eq!(
        vault_meta_rows_with_prefix(&vault, STRUCTURAL_KIND_REGISTRY_KEY_PREFIX)?,
        before,
        "static-byte rejection must not mutate vault_meta"
    );

    Ok(())
}

#[test]
fn structural_kind_registry_handles_legacy_dynamic_companion_byte() -> Result<()> {
    use crate::types::{COMPANION_REGISTER_PACK_ID, COMPANION_REGISTER_SHORT_ID_PREFIX};

    fn legacy_row(prefix: &str, pack: &str) -> Vec<u8> {
        let mut raw = vec![1, 64, 2, 2];
        raw.extend_from_slice(
            &u16::try_from(pack.len())
                .expect("test pack length fits u16")
                .to_le_bytes(),
        );
        raw.extend_from_slice(prefix.as_bytes());
        raw.extend_from_slice(pack.as_bytes());
        raw
    }

    let compatible_dir = tempfile::tempdir()?;
    {
        let vault = Vault::open(compatible_dir.path(), test_config())?;
        let key = structural_kind_registry_key(64);
        let raw = legacy_row(
            COMPANION_REGISTER_SHORT_ID_PREFIX,
            COMPANION_REGISTER_PACK_ID,
        );

        let mut wtxn = vault.store.env.write_txn()?;
        vault.store.vault_meta.put(&mut wtxn, &key, &raw)?;
        wtxn.commit()?;
    }
    let compatible = Vault::open(compatible_dir.path(), test_config())?;
    assert!(
        compatible.structural_kind_registration(64).is_none(),
        "compatible legacy row must be ignored so the static registry owns byte 64"
    );

    let incompatible_dir = tempfile::tempdir()?;
    {
        let vault = Vault::open(incompatible_dir.path(), test_config())?;
        let key = structural_kind_registry_key(64);
        let raw = legacy_row("np", "legacy-pack");

        let mut wtxn = vault.store.env.write_txn()?;
        vault.store.vault_meta.put(&mut wtxn, &key, &raw)?;
        wtxn.commit()?;
    }

    let err = match Vault::open(incompatible_dir.path(), test_config()) {
        Ok(_) => panic!("incompatible legacy dynamic byte 64 row must fail closed"),
        Err(err) => err,
    };
    assert_eq!(err.kind(), ErrorKind::CorruptedIndex);
    assert_matches!(err, Error::CorruptedIndex("structural kind registry"));
    Ok(())
}

#[test]
fn structural_kind_registration_persists_and_loads_on_reopen() -> Result<()> {
    use crate::types::TypeByteBand;

    let dir = tempfile::tempdir()?;
    {
        let vault = Vault::open(dir.path(), test_config())?;
        vault.register_structural_kind(72, "np", TypeByteBand::Companion, "notes-pack")?;

        let key = structural_kind_registry_key(72);
        let rows = vault_meta_rows_with_prefix(&vault, STRUCTURAL_KIND_REGISTRY_KEY_PREFIX)?;
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].0, key.to_vec());
    }

    let reopened = Vault::open(dir.path(), test_config())?;
    let registration = reopened
        .structural_kind_registration(72)
        .expect("registration must load from vault_meta on reopen");
    assert_eq!(registration.type_byte, 72);
    assert_eq!(registration.short_id_prefix, "np");
    assert_eq!(registration.band, TypeByteBand::Companion);
    assert_eq!(registration.pack, "notes-pack");
    assert_eq!(
        reopened.structural_kind_registrations(),
        vec![registration],
        "runtime registry must mirror persisted dynamic rows only"
    );
    Ok(())
}

#[test]
fn registered_structural_kind_unblocks_writes_and_short_ids() -> Result<()> {
    use crate::types::TypeByteBand;

    let (_dir, vault) = open_test_vault();
    let before = EntityId::now();
    let err = vault
        .put_entity(&before, 72, test_time_range(1, 1), 2, b"before-register")
        .expect_err("unregistered dynamic byte must fail closed");
    assert_eq!(err.kind(), ErrorKind::InvalidEntityType);
    assert_matches!(err, Error::InvalidEntityType(72));
    assert_no_entity_state(&vault, &before)?;

    vault.register_structural_kind(72, "np", TypeByteBand::Companion, "notes-pack")?;

    let after = EntityId::now();
    vault.put_entity(&after, 72, test_time_range(3, 3), 4, b"after-register")?;
    assert_eq!(
        vault.get(&after)?.ok_or(Error::EntityNotFound)?,
        b"after-register"
    );

    let short_id = find_short_id_any_schema(&vault, &after)?
        .expect("registered dynamic kind must mint a short id");
    assert_eq!(short_id, "np1");

    let rtxn = vault.store.env.read_txn()?;
    let counter = vault
        .store
        .vault_meta
        .get(&rtxn, &short_id_counter_key(72))?
        .expect("dynamic type short-id counter must live in vault_meta");
    assert_eq!(counter, 1_u64.to_le_bytes());
    Ok(())
}

#[test]
fn persisted_structural_kind_registry_matches_runtime_config() -> Result<()> {
    use crate::types::{TypeByteBand, band_of, entity_type_registry_entry};

    let (_dir, vault) = open_test_vault();
    vault.register_structural_kind(72, "np", TypeByteBand::Companion, "notes-pack")?;
    vault.register_structural_kind(84, "pd", TypeByteBand::Productivity, "productivity-pack")?;
    vault.register_structural_kind(101, "cc", TypeByteBand::Crm, "crm-pack")?;

    let rows = vault.structural_kind_registrations();
    assert_eq!(rows.len(), 3);
    for registration in rows {
        assert_eq!(
            band_of(registration.type_byte),
            registration.band,
            "persisted registry band must match band_of({})",
            registration.type_byte
        );
        assert!(
            entity_type_registry_entry(registration.type_byte).is_none(),
            "runtime registry must not shadow static registry byte {}",
            registration.type_byte
        );
    }
    Ok(())
}

#[test]
fn entity_value_envelope_matches_arch_0002_layout() -> Result<()> {
    use crate::batch::{
        ENTITY_BODY_OFFSET, ENTITY_LEARNED_AT_OFFSET, ENTITY_OCCURRED_END_OFFSET,
        ENTITY_OCCURRED_START_OFFSET, ENTITY_TYPE_OFFSET, EntityMetadataHeader,
    };

    let (_dir, vault) = open_test_vault();
    let id = EntityId::now();
    let entity_type = 1_u8;
    let occurred = test_time_range(0x0102_0304_0506_0708, 0x1112_1314_1516_1718);
    let learned_at = 0x2122_2324_2526_2728;
    let body_value = serde_json::json!({
        "kind": "envelope-pin",
        "value": 42,
    });
    let body = rmp_serde::to_vec_named(&body_value).expect("encode MessagePack body");

    vault.put_entity(&id, entity_type, occurred, learned_at, &body)?;

    let rtxn = vault.store.env.read_txn()?;
    let raw = vault
        .store
        .entities
        .get(&rtxn, id.as_bytes())?
        .ok_or(Error::EntityNotFound)?;

    assert_eq!(raw.len(), ENTITY_METADATA_HEADER_LEN + body.len());
    assert_eq!(ENTITY_METADATA_HEADER_LEN, ENTITY_BODY_OFFSET);
    assert_eq!(raw[ENTITY_TYPE_OFFSET], entity_type);
    assert_eq!(
        &raw[ENTITY_OCCURRED_START_OFFSET..ENTITY_OCCURRED_END_OFFSET],
        occurred.start.to_be_bytes().as_slice()
    );
    assert_eq!(
        &raw[ENTITY_OCCURRED_END_OFFSET..ENTITY_LEARNED_AT_OFFSET],
        occurred.end.to_be_bytes().as_slice()
    );
    assert_eq!(
        &raw[ENTITY_LEARNED_AT_OFFSET..ENTITY_BODY_OFFSET],
        learned_at.to_be_bytes().as_slice()
    );
    assert_eq!(&raw[ENTITY_BODY_OFFSET..], body.as_slice());

    let header = EntityMetadataHeader::parse(raw).expect("parse entity header");
    assert_eq!(header.entity_type, entity_type);
    assert_eq!(header.occurred_start, occurred.start);
    assert_eq!(header.occurred_end, occurred.end);
    assert_eq!(header.learned_at, learned_at);

    let decoded: serde_json::Value =
        rmp_serde::from_slice(&raw[ENTITY_BODY_OFFSET..]).expect("decode MessagePack body");
    assert_eq!(decoded, body_value);
    Ok(())
}

#[test]
fn put_edge_with_vad_round_trip() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let src = EntityId::now();
    let tgt = EntityId::now();

    vault
        .batch()
        .put(&src, 1, test_time_range(1, 2), 3, b"src")
        .put(&tgt, 4, test_time_range(4, 5), 6, b"tgt")
        .commit()?;

    vault.put_edge_with_vad(
        &src,
        EdgeKind::Supports,
        &tgt,
        0.8,
        Vad {
            valence: 0.6,
            arousal: 0.3,
            dominance: 0.9,
        },
    )?;

    let out = vault.edges_out(&src)?;
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].kind, EdgeKind::Supports);
    assert_eq!(out[0].target, tgt);
    assert!((out[0].weight - 0.8).abs() < f32::EPSILON);
    let vad = out[0].vad.expect("semantic edge should hydrate VAD");
    assert!((vad.valence - 0.6).abs() < f32::EPSILON);
    assert!((vad.arousal - 0.3).abs() < f32::EPSILON);
    assert!((vad.dominance - 0.9).abs() < f32::EPSILON);
    Ok(())
}

#[test]
fn put_edge_with_vad_rejects_non_finite() {
    let (_dir, vault) = open_test_vault();
    let src = EntityId::now();
    let tgt = EntityId::now();

    let err = vault
        .put_edge_with_vad(
            &src,
            EdgeKind::Supports,
            &tgt,
            0.5,
            Vad {
                valence: f32::NAN,
                arousal: 0.0,
                dominance: 0.0,
            },
        )
        .expect_err("expected invalid vad");
    assert_invalid_vad(err, VadComponent::Valence, f32::NAN);

    let err = vault
        .put_edge_with_vad(
            &src,
            EdgeKind::Supports,
            &tgt,
            0.5,
            Vad {
                valence: 0.0,
                arousal: f32::INFINITY,
                dominance: 0.0,
            },
        )
        .expect_err("expected invalid vad");
    assert_invalid_vad(err, VadComponent::Arousal, f32::INFINITY);

    let err = vault
        .put_edge_with_vad(
            &src,
            EdgeKind::Supports,
            &tgt,
            0.5,
            Vad {
                valence: 1.5,
                arousal: 0.0,
                dominance: 0.0,
            },
        )
        .expect_err("expected invalid vad for out-of-range valence");
    assert_invalid_vad(err, VadComponent::Valence, 1.5);

    let err = vault
        .put_edge_with_vad(
            &src,
            EdgeKind::Supports,
            &tgt,
            0.5,
            Vad {
                valence: 0.0,
                arousal: -0.1,
                dominance: 0.0,
            },
        )
        .expect_err("expected invalid vad for negative arousal");
    assert_invalid_vad(err, VadComponent::Arousal, -0.1);

    let err = vault
        .put_edge_with_vad(
            &src,
            EdgeKind::Supports,
            &tgt,
            0.5,
            Vad {
                valence: 0.0,
                arousal: 0.0,
                dominance: 1.1,
            },
        )
        .expect_err("expected invalid vad for out-of-range dominance");
    assert_invalid_vad(err, VadComponent::Dominance, 1.1);
}

fn assert_invalid_vad(err: Error, expected_component: VadComponent, expected_value: f32) {
    let message = err.to_string();
    let Error::InvalidVad { component, value } = err else {
        panic!("expected invalid vad, got {err:?}");
    };
    assert_eq!(component, expected_component);
    if expected_value.is_nan() {
        assert!(value.is_nan());
    } else {
        assert_eq!(value, expected_value);
    }

    assert!(message.contains(&format!("{expected_component:?}")));
    assert!(message.contains(&expected_value.to_string()));
}

#[test]
fn turn_vad_annotation_persists_supported_sources() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let turn = EntityId::now();
    let body = rmp_serde::to_vec_named(&serde_json::json!({
        "txt": "turn-level affect",
        "spkr": "user",
        "at": 100_u64,
    }))
    .expect("encode turn body");
    vault.put_entity(
        &turn,
        ENTITY_TYPE_TURN,
        test_time_range(100, 100),
        100,
        &body,
    )?;
    vault
        .batch()
        .text(&turn, &[("body", "turnlevel_affect_unique")])
        .commit()?;
    let raw_before = vault.get_raw(&turn)?.expect("turn raw body");
    let text_forward_before = text_forward_row(&vault, &turn)?;
    assert_eq!(vault.get_learned_at(&turn)?, 100);
    assert_eq!(vault.search_text("turnlevel_affect_unique", 10)?.len(), 1);

    let model_annotation = VadAnnotation::new(
        Vad {
            valence: 0.25,
            arousal: 0.5,
            dominance: 0.75,
        },
        VadAnnotationSource::ModelInference,
        200,
    )?;
    assert_eq!(
        vault.annotate_turn_vad(&turn, model_annotation)?,
        model_annotation
    );
    assert_eq!(
        vault.get_turn_vad_annotation(&turn)?,
        Some(model_annotation)
    );
    assert_eq!(
        vault.get_raw(&turn)?.as_deref(),
        Some(raw_before.as_slice()),
        "annotation must not rewrite the turn entity body/header"
    );
    assert_eq!(vault.get_learned_at(&turn)?, 100);
    assert_eq!(text_forward_row(&vault, &turn)?, text_forward_before);
    assert_eq!(vault.search_text("turnlevel_affect_unique", 10)?.len(), 1);

    let report_annotation = VadAnnotation::new(
        Vad {
            valence: -0.5,
            arousal: 0.25,
            dominance: 0.5,
        },
        VadAnnotationSource::UserSelfReport,
        201,
    )?;
    vault.annotate_turn_vad(&turn, report_annotation)?;

    assert_eq!(
        vault.get_raw(&turn)?.as_deref(),
        Some(raw_before.as_slice()),
        "annotation replacement must not rewrite the turn entity body/header"
    );
    assert_eq!(vault.get_learned_at(&turn)?, 100);
    assert_eq!(text_forward_row(&vault, &turn)?, text_forward_before);
    assert_eq!(vault.search_text("turnlevel_affect_unique", 10)?.len(), 1);
    assert_eq!(
        vault.get_turn_vad_annotation(&turn)?,
        Some(report_annotation)
    );
    Ok(())
}

#[test]
fn message_vad_annotation_round_trip() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let message = EntityId::now();
    let body = rmp_serde::to_vec_named(&serde_json::json!({
        "txt": "message-level affect",
        "spkr": "assistant",
        "at": 110_u64,
    }))
    .expect("encode message body");
    vault.put_entity(
        &message,
        ENTITY_TYPE_MESSAGE,
        test_time_range(110, 110),
        110,
        &body,
    )?;
    let raw_before = vault.get_raw(&message)?.expect("message raw body");

    let annotation = VadAnnotation::new(
        Vad {
            valence: 0.1,
            arousal: 0.2,
            dominance: 0.3,
        },
        VadAnnotationSource::ModelInference,
        210,
    )?;

    assert_eq!(
        vault.annotate_message_vad(&message, annotation)?,
        annotation
    );
    assert_eq!(
        vault.get_message_vad_annotation(&message)?,
        Some(annotation)
    );
    assert_eq!(
        vault.get_raw(&message)?.as_deref(),
        Some(raw_before.as_slice()),
        "annotation must not rewrite the message entity body/header"
    );
    assert_eq!(vault.get_learned_at(&message)?, 110);
    assert_eq!(
        vault
            .get_turn_vad_annotation(&message)
            .expect_err("wrong entity type")
            .kind(),
        ErrorKind::InvalidEntityType
    );
    Ok(())
}

fn assert_vad_annotation_claim_present(
    vault: &Vault,
    claim_id: &EntityId,
    annotated_id: &EntityId,
) -> Result<()> {
    let rtxn = vault.store.env.read_txn()?;
    assert!(
        vault
            .store
            .entities
            .get(&rtxn, claim_id.as_bytes())?
            .is_some(),
        "derived VAD claim entity must exist before deletion"
    );
    let edge_out = Store::encode_edge_key(claim_id, EdgeKind::ClaimOf, annotated_id);
    let edge_in = Store::encode_edge_key(annotated_id, EdgeKind::ClaimOf, claim_id);
    assert!(
        vault.store.edges_out.get(&rtxn, &edge_out)?.is_some(),
        "derived VAD claim_of edge must exist before deletion"
    );
    assert!(
        vault.store.edges_in.get(&rtxn, &edge_in)?.is_some(),
        "derived VAD claim_of reverse edge must exist before deletion"
    );
    Ok(())
}

fn assert_vad_annotation_claim_removed(
    vault: &Vault,
    claim_id: &EntityId,
    annotated_id: &EntityId,
) -> Result<()> {
    let rtxn = vault.store.env.read_txn()?;
    assert!(
        vault
            .store
            .entities
            .get(&rtxn, claim_id.as_bytes())?
            .is_none(),
        "derived VAD claim entity must be removed"
    );
    let edge_out = Store::encode_edge_key(claim_id, EdgeKind::ClaimOf, annotated_id);
    let edge_in = Store::encode_edge_key(annotated_id, EdgeKind::ClaimOf, claim_id);
    assert!(
        vault.store.edges_out.get(&rtxn, &edge_out)?.is_none(),
        "derived VAD claim_of edge must be removed"
    );
    assert!(
        vault.store.edges_in.get(&rtxn, &edge_in)?.is_none(),
        "derived VAD claim_of reverse edge must be removed"
    );
    Ok(())
}

#[test]
fn batch_delete_removes_turn_vad_annotation_claim_and_edges() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let turn = EntityId::now();
    let body = rmp_serde::to_vec_named(&serde_json::json!({
        "txt": "turn delete affect",
        "spkr": "user",
        "at": 130_u64,
    }))
    .expect("encode turn body");
    vault.put_entity(
        &turn,
        ENTITY_TYPE_TURN,
        test_time_range(130, 130),
        130,
        &body,
    )?;
    let annotation = VadAnnotation::new(
        Vad {
            valence: 0.6,
            arousal: 0.4,
            dominance: 0.8,
        },
        VadAnnotationSource::ModelInference,
        230,
    )?;
    vault.annotate_turn_vad(&turn, annotation)?;

    let claim_id = vad_annotation_claim_id(ENTITY_TYPE_TURN, &turn)?;
    assert_vad_annotation_claim_present(&vault, &claim_id, &turn)?;

    vault.batch().delete(&turn).commit()?;

    assert_eq!(vault.get_turn_vad_annotation(&turn)?, None);
    assert_vad_annotation_claim_removed(&vault, &claim_id, &turn)?;
    assert_eq!(vault.get_turn_vad_annotation(&turn)?, None);
    assert_vad_annotation_claim_removed(&vault, &claim_id, &turn)?;
    Ok(())
}

#[test]
fn soft_delete_removes_message_vad_annotation_claim_and_edges() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let message = EntityId::now();
    let body = rmp_serde::to_vec_named(&serde_json::json!({
        "txt": "message soft delete affect",
        "spkr": "assistant",
        "at": 131_u64,
    }))
    .expect("encode message body");
    vault.put_entity(
        &message,
        ENTITY_TYPE_MESSAGE,
        test_time_range(131, 131),
        131,
        &body,
    )?;
    let annotation = VadAnnotation::new(
        Vad {
            valence: 0.2,
            arousal: 0.7,
            dominance: 0.3,
        },
        VadAnnotationSource::UserSelfReport,
        231,
    )?;
    vault.annotate_message_vad(&message, annotation)?;

    let claim_id = vad_annotation_claim_id(ENTITY_TYPE_MESSAGE, &message)?;
    assert_vad_annotation_claim_present(&vault, &claim_id, &message)?;

    let outcome = vault.delete_entity_with_reason(&message, DeleteReason::UserDelete)?;

    assert!(outcome.existed);
    assert_eq!(vault.get_message_vad_annotation(&message)?, None);
    assert_vad_annotation_claim_removed(&vault, &claim_id, &message)?;
    assert_eq!(vault.get_message_vad_annotation(&message)?, None);
    assert_vad_annotation_claim_removed(&vault, &claim_id, &message)?;
    Ok(())
}

#[test]
fn soft_deleted_vad_claim_shell_is_absent_for_reads_cleanup_and_reannotation() -> Result<()> {
    let (_delete_dir, delete_vault) = open_test_vault();
    let turn = EntityId::now();
    let turn_body = rmp_serde::to_vec_named(&serde_json::json!({
        "txt": "turn claim shell",
        "spkr": "user",
        "at": 133_u64,
    }))
    .expect("encode turn body");
    delete_vault.put_entity(
        &turn,
        ENTITY_TYPE_TURN,
        test_time_range(133, 133),
        133,
        &turn_body,
    )?;
    let annotation = VadAnnotation::new(
        Vad {
            valence: 0.45,
            arousal: 0.55,
            dominance: 0.65,
        },
        VadAnnotationSource::ModelInference,
        234,
    )?;
    delete_vault.annotate_turn_vad(&turn, annotation)?;
    let turn_claim = vad_annotation_claim_id(ENTITY_TYPE_TURN, &turn)?;

    let claim_delete =
        delete_vault.delete_entity_with_reason(&turn_claim, DeleteReason::UserDelete)?;

    assert!(claim_delete.existed);
    assert_eq!(
        delete_vault.get_raw(&turn_claim)?.as_ref().map(Vec::len),
        Some(ENTITY_METADATA_HEADER_LEN),
        "soft-deleting the derived VAD claim must leave a header-only shell"
    );
    assert_eq!(delete_vault.get_turn_vad_annotation(&turn)?, None);
    let turn_delete =
        delete_vault.delete_entity_with_reason(&turn, DeleteReason::UserHardDelete)?;
    assert!(turn_delete.existed);
    assert_eq!(delete_vault.get_turn_vad_annotation(&turn)?, None);

    let (_annotate_dir, annotate_vault) = open_test_vault();
    let message = EntityId::now();
    let message_body = rmp_serde::to_vec_named(&serde_json::json!({
        "txt": "message claim shell",
        "spkr": "assistant",
        "at": 134_u64,
    }))
    .expect("encode message body");
    annotate_vault.put_entity(
        &message,
        ENTITY_TYPE_MESSAGE,
        test_time_range(134, 134),
        134,
        &message_body,
    )?;
    let first = VadAnnotation::new(
        Vad {
            valence: 0.15,
            arousal: 0.25,
            dominance: 0.35,
        },
        VadAnnotationSource::UserSelfReport,
        235,
    )?;
    annotate_vault.annotate_message_vad(&message, first)?;
    let message_claim = vad_annotation_claim_id(ENTITY_TYPE_MESSAGE, &message)?;
    let claim_delete =
        annotate_vault.delete_entity_with_reason(&message_claim, DeleteReason::UserDelete)?;
    assert!(claim_delete.existed);
    assert_eq!(
        annotate_vault
            .get_raw(&message_claim)?
            .as_ref()
            .map(Vec::len),
        Some(ENTITY_METADATA_HEADER_LEN),
        "soft-deleting the derived VAD claim must leave a header-only shell"
    );
    assert_eq!(annotate_vault.get_message_vad_annotation(&message)?, None);

    let replacement = VadAnnotation::new(
        Vad {
            valence: -0.15,
            arousal: 0.35,
            dominance: 0.75,
        },
        VadAnnotationSource::ModelInference,
        236,
    )?;
    assert_eq!(
        annotate_vault.annotate_message_vad(&message, replacement)?,
        replacement
    );
    assert_eq!(
        annotate_vault.get_message_vad_annotation(&message)?,
        Some(replacement)
    );
    assert_vad_annotation_claim_present(&annotate_vault, &message_claim, &message)?;
    Ok(())
}

#[test]
fn headerless_delete_treats_vad_only_residue_as_active_scope() -> Result<()> {
    let (_legacy_dir, legacy_vault) = open_test_vault();
    let legacy_turn = EntityId::now();
    let legacy_annotation = VadAnnotation::new(
        Vad {
            valence: 0.4,
            arousal: 0.5,
            dominance: 0.6,
        },
        VadAnnotationSource::ModelInference,
        232,
    )?;
    let legacy_key = vad_annotation_meta_key(ENTITY_TYPE_TURN, &legacy_turn);
    let legacy_bytes = rmp_serde::to_vec_named(&legacy_annotation).expect("encode legacy VAD");
    {
        let mut wtxn = legacy_vault.store.env.write_txn()?;
        legacy_vault
            .store
            .vault_meta
            .put(&mut wtxn, &legacy_key, &legacy_bytes)?;
        wtxn.commit()?;
    }

    let legacy_outcome =
        legacy_vault.delete_entity_with_reason(&legacy_turn, DeleteReason::UserHardDelete)?;

    assert!(
        legacy_outcome.receipt_id.is_some(),
        "VAD-only legacy metadata must count as active delete scope"
    );
    {
        let rtxn = legacy_vault.store.env.read_txn()?;
        assert!(
            legacy_vault
                .store
                .vault_meta
                .get(&rtxn, &legacy_key)?
                .is_none(),
            "headerless delete must remove legacy VAD metadata residue"
        );
    }

    let (_claim_dir, claim_vault) = open_test_vault();
    let message = EntityId::now();
    let body = rmp_serde::to_vec_named(&serde_json::json!({
        "txt": "message claim residue",
        "spkr": "assistant",
        "at": 132_u64,
    }))
    .expect("encode message body");
    claim_vault.put_entity(
        &message,
        ENTITY_TYPE_MESSAGE,
        test_time_range(132, 132),
        132,
        &body,
    )?;
    let annotation = VadAnnotation::new(
        Vad {
            valence: 0.3,
            arousal: 0.8,
            dominance: 0.4,
        },
        VadAnnotationSource::UserSelfReport,
        233,
    )?;
    claim_vault.annotate_message_vad(&message, annotation)?;
    let claim_id = vad_annotation_claim_id(ENTITY_TYPE_MESSAGE, &message)?;
    let edge_out = Store::encode_edge_key(&claim_id, EdgeKind::ClaimOf, &message);
    let edge_in = Store::encode_edge_key(&message, EdgeKind::ClaimOf, &claim_id);
    {
        let mut wtxn = claim_vault.store.env.write_txn()?;
        claim_vault
            .store
            .entities
            .delete(&mut wtxn, message.as_bytes())?;
        claim_vault.store.type_index.delete(
            &mut wtxn,
            &Store::encode_type_key(ENTITY_TYPE_MESSAGE, &message),
        )?;
        claim_vault
            .store
            .temporal_occurred_start
            .delete(&mut wtxn, &Store::encode_temporal_key(132, &message))?;
        claim_vault
            .store
            .temporal_learned
            .delete(&mut wtxn, &Store::encode_temporal_key(132, &message))?;
        claim_vault.store.edges_out.delete(&mut wtxn, &edge_out)?;
        claim_vault.store.edges_in.delete(&mut wtxn, &edge_in)?;
        wtxn.commit()?;
    }

    let claim_outcome =
        claim_vault.delete_entity_with_reason(&message, DeleteReason::UserHardDelete)?;

    assert!(
        claim_outcome.receipt_id.is_some(),
        "derived VAD claim without claim_of edge must count as active delete scope"
    );
    assert_vad_annotation_claim_removed(&claim_vault, &claim_id, &message)?;
    Ok(())
}

#[test]
fn turn_vad_annotation_rejects_edge_vad_range_violations() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let turn = EntityId::now();
    let body = rmp_serde::to_vec_named(&serde_json::json!({
        "txt": "invalid affect",
    }))
    .expect("encode turn body");
    vault.put_entity(
        &turn,
        ENTITY_TYPE_TURN,
        test_time_range(120, 120),
        120,
        &body,
    )?;

    let invalid = VadAnnotation {
        vad: Vad {
            valence: 0.0,
            arousal: -0.01,
            dominance: 0.5,
        },
        source: VadAnnotationSource::UserSelfReport,
        annotated_at: 220,
    };
    let err = vault
        .annotate_turn_vad(&turn, invalid)
        .expect_err("invalid turn VAD must reject");
    assert_invalid_vad(err, VadComponent::Arousal, -0.01);
    assert_eq!(vault.get_turn_vad_annotation(&turn)?, None);
    Ok(())
}

fn put_claim_vad_turn(vault: &Vault, id: &EntityId, learned_at: u64, vad: Vad) -> Result<()> {
    let body = rmp_serde::to_vec_named(&serde_json::json!({
        "txt": "claim VAD fixture turn",
    }))
    .expect("encode turn body");
    vault.put_entity(
        id,
        ENTITY_TYPE_TURN,
        test_time_range(learned_at, learned_at),
        learned_at,
        &body,
    )?;
    vault.annotate_turn_vad(
        id,
        VadAnnotation::new(vad, VadAnnotationSource::ModelInference, learned_at + 10)?,
    )?;
    Ok(())
}

fn claim_vad_fixture_body(subject: EntityId, turns: &[EntityId]) -> ClaimBody {
    let mut body = ClaimBody::new(
        "dream.symbol",
        ClaimSubject::Entity(subject),
        rmpv::Value::from("blue door"),
        0.9,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    );
    body.evidence = Some(rmpv::Value::Array(
        turns
            .iter()
            .map(|turn| rmpv::Value::Binary(turn.as_bytes().to_vec()))
            .collect(),
    ));
    body.source = Some(ClaimSource::Inferred);
    body
}

fn assert_vad_close(actual: Vad, expected: Vad) {
    const EPSILON: f32 = 0.000_001;
    assert!((actual.valence - expected.valence).abs() < EPSILON);
    assert!((actual.arousal - expected.arousal).abs() < EPSILON);
    assert!((actual.dominance - expected.dominance).abs() < EPSILON);
}

fn entity_header(vault: &Vault, id: &EntityId) -> Result<EntityMetadataHeader> {
    let rtxn = vault.store.env.read_txn()?;
    let raw = vault
        .store
        .entities
        .get(&rtxn, id.as_bytes())?
        .ok_or(Error::EntityNotFound)?;
    EntityMetadataHeader::parse(raw).ok_or(Error::CorruptedIndex("entity header"))
}

fn coping_outcome_fixture_body(
    affected_person: EntityId,
    strategy_ref: EntityId,
    strategy: CopingStrategy,
    vad_delta: VadDelta,
    confidence: f32,
    lifecycle: ClaimLifecycleStatus,
    valid_from: u64,
) -> Result<ClaimBody> {
    let value = CopingOutcomeValue::new(
        affected_person,
        strategy_ref,
        strategy,
        vad_delta,
        confidence,
        1,
    )?;
    let mut body = ClaimBody::new(
        COPING_OUTCOME_PREDICATE,
        ClaimSubject::Entity(affected_person),
        coping_outcome_value(&value),
        confidence,
        ClaimApprovalStatus::Auto,
        lifecycle,
    );
    body.source = Some(ClaimSource::Inferred);
    body.valid_from = Some(valid_from);
    if lifecycle != ClaimLifecycleStatus::Active {
        body.valid_to = Some(valid_from + 1);
    }
    Ok(body)
}

fn assert_f32_close(actual: f32, expected: f32) {
    const EPSILON: f32 = 0.000_001;
    assert!(
        (actual - expected).abs() < EPSILON,
        "expected {expected}, got {actual}"
    );
}

#[test]
fn claim_vad_consolidation_populates_semantic_edges_from_fixture_turns() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let subject = EntityId::now();
    let actor = EntityId::now();
    let turn_a = EntityId::now();
    let turn_b = EntityId::now();
    let claim = EntityId::now();

    vault.put_entity(
        &subject,
        ENTITY_TYPE_PERSON,
        test_time_range(1, 1),
        1,
        b"subject",
    )?;
    vault.put_entity(
        &actor,
        ENTITY_TYPE_PERSON,
        test_time_range(1, 1),
        1,
        b"actor",
    )?;
    put_claim_vad_turn(
        &vault,
        &turn_a,
        10,
        Vad {
            valence: 0.2,
            arousal: 0.4,
            dominance: 0.6,
        },
    )?;
    put_claim_vad_turn(
        &vault,
        &turn_b,
        20,
        Vad {
            valence: 0.6,
            arousal: 0.2,
            dominance: 0.4,
        },
    )?;

    let body = claim_vad_fixture_body(subject, &[turn_a, turn_b]);
    vault.put_claim(&claim, &body, test_time_range(30, 30), 30)?;
    vault.put_edge(&claim, EdgeKind::Mentions, &subject, 0.6)?;
    vault.put_edge(&actor, EdgeKind::Supports, &claim, 1.0)?;
    vault.put_edge(&claim, EdgeKind::BelongsTo, &subject, 1.0)?;

    let outcome = block_on_ready(vault.consolidate_claim_vad(&claim, 100))?;
    let expected = Vad {
        valence: 0.4,
        arousal: 0.3,
        dominance: 0.5,
    };
    assert_vad_close(outcome.vad.expect("computed VAD"), expected);
    assert_eq!(outcome.evidence_turns.len(), 2);
    assert_eq!(outcome.semantic_edges_updated, 2);
    assert!(
        outcome.structural_edges_skipped >= 2,
        "claim_of and belongs_to stay structural"
    );

    let outgoing = vault.edges_out(&claim)?;
    let mentions = outgoing
        .iter()
        .find(|edge| edge.kind == EdgeKind::Mentions && edge.target == subject)
        .expect("semantic claim edge");
    assert_vad_close(mentions.vad.expect("semantic edge VAD"), expected);

    let incoming = vault.edges_in(&claim)?;
    let supports = incoming
        .iter()
        .find(|edge| edge.kind == EdgeKind::Supports && edge.target == actor)
        .expect("incoming semantic claim edge");
    assert_vad_close(supports.vad.expect("incoming semantic edge VAD"), expected);

    let belongs_to = EdgeRef::new(claim, EdgeKind::BelongsTo, subject);
    let (structural_out, structural_in) = raw_edge_values(&vault, &belongs_to)?;
    let structural_out = structural_out.expect("belongs_to edge");
    assert_eq!(structural_out.len(), EDGE_VALUE_STRUCTURAL_LEN);
    assert_eq!(structural_in.as_deref(), Some(structural_out.as_slice()));
    assert_eq!(
        decode_edge_value_for_kind(EdgeKind::BelongsTo, &structural_out)?.vad,
        None
    );

    let state_id = outcome
        .reappraisal
        .created_claim_id
        .expect("first consolidation creates state");
    let state = vault.get_claim(&state_id)?.expect("claim-VAD state claim");
    assert_eq!(state.predicate, CLAIM_VAD_REAPPRAISAL_PREDICATE);
    assert_eq!(state.subject, ClaimSubject::Entity(claim));
    assert_eq!(state.source, Some(ClaimSource::Inferred));
    assert_eq!(state.lifecycle, ClaimLifecycleStatus::Active);
    let state_header = entity_header(&vault, &state_id)?;
    assert_eq!(state_header.occurred_start, 100);
    assert_eq!(state_header.occurred_end, u64::MAX);
    assert!(
        state.evidence.is_some(),
        "turn evidence provenance is stored"
    );
    Ok(())
}

#[test]
fn claim_vad_reappraisal_preserves_provenance_and_supersession() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let subject = EntityId::now();
    let turn = EntityId::now();
    let claim = EntityId::now();

    vault.put_entity(
        &subject,
        ENTITY_TYPE_PERSON,
        test_time_range(1, 1),
        1,
        b"subject",
    )?;
    put_claim_vad_turn(
        &vault,
        &turn,
        10,
        Vad {
            valence: 0.1,
            arousal: 0.2,
            dominance: 0.3,
        },
    )?;
    let body = claim_vad_fixture_body(subject, &[turn]);
    vault.put_claim(&claim, &body, test_time_range(30, 30), 30)?;
    vault.put_edge(&claim, EdgeKind::Mentions, &subject, 0.6)?;

    let first = block_on_ready(vault.consolidate_claim_vad(&claim, 100))?;
    let old_state_id = first
        .reappraisal
        .created_claim_id
        .expect("initial state claim");
    let old_before = vault
        .get_claim(&old_state_id)?
        .expect("initial state remains readable");

    vault.annotate_turn_vad(
        &turn,
        VadAnnotation::new(
            Vad {
                valence: 0.7,
                arousal: 0.6,
                dominance: 0.5,
            },
            VadAnnotationSource::UserSelfReport,
            150,
        )?,
    )?;
    let second = block_on_ready(vault.consolidate_claim_vad(&claim, 200))?;
    let new_state_id = second
        .reappraisal
        .created_claim_id
        .expect("changed evidence creates a reappraisal");
    assert_eq!(second.reappraisal.superseded_claim_ids, vec![old_state_id]);
    assert_ne!(new_state_id, old_state_id);

    let old_after = vault
        .get_claim(&old_state_id)?
        .expect("superseded state stays readable");
    assert_eq!(old_after.lifecycle, ClaimLifecycleStatus::Superseded);
    assert_eq!(old_after.valid_to, Some(200));
    assert_eq!(entity_header(&vault, &old_state_id)?.occurred_end, 200);
    assert_eq!(old_after.source, old_before.source);
    assert_eq!(old_after.evidence, old_before.evidence);

    let new_state = vault
        .get_claim(&new_state_id)?
        .expect("new state claim readable");
    assert_eq!(new_state.lifecycle, ClaimLifecycleStatus::Active);
    assert_eq!(new_state.source, Some(ClaimSource::Inferred));
    assert!(new_state.evidence.is_some());
    assert_eq!(entity_header(&vault, &new_state_id)?.occurred_end, u64::MAX);

    let supersedes = EdgeRef::new(new_state_id, EdgeKind::Supersedes, old_state_id);
    let (out, inn) = raw_edge_values(&vault, &supersedes)?;
    let out = out.expect("supersedes edge");
    assert_eq!(out.len(), EDGE_VALUE_STRUCTURAL_LEN);
    assert_eq!(inn.as_deref(), Some(out.as_slice()));
    assert_eq!(
        decode_edge_value_for_kind(EdgeKind::Supersedes, &out)?.vad,
        None
    );

    let expected = Vad {
        valence: 0.7,
        arousal: 0.6,
        dominance: 0.5,
    };
    let mentions = vault
        .edges_out(&claim)?
        .into_iter()
        .find(|edge| edge.kind == EdgeKind::Mentions && edge.target == subject)
        .expect("semantic edge survives");
    assert_vad_close(mentions.vad.expect("updated VAD"), expected);
    Ok(())
}

#[test]
fn claim_vad_consolidation_rejects_derived_state_claims() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let subject = EntityId::now();
    let turn = EntityId::now();
    let claim = EntityId::now();

    vault.put_entity(
        &subject,
        ENTITY_TYPE_PERSON,
        test_time_range(1, 1),
        1,
        b"subject",
    )?;
    put_claim_vad_turn(
        &vault,
        &turn,
        10,
        Vad {
            valence: 0.1,
            arousal: 0.2,
            dominance: 0.3,
        },
    )?;
    let body = claim_vad_fixture_body(subject, &[turn]);
    vault.put_claim(&claim, &body, test_time_range(30, 30), 30)?;

    let outcome = block_on_ready(vault.consolidate_claim_vad(&claim, 100))?;
    let state_id = outcome
        .reappraisal
        .created_claim_id
        .expect("initial state claim");
    let err = block_on_ready(vault.consolidate_claim_vad(&state_id, 110))
        .expect_err("derived state claims must not recursively consolidate");
    assert_matches!(
        err,
        Error::InvalidClaimBody("claim VAD state claims cannot be consolidated")
    );
    Ok(())
}

#[test]
fn claim_vad_consolidation_rejects_turn_vad_annotation_claims() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let turn = EntityId::now();

    put_claim_vad_turn(
        &vault,
        &turn,
        10,
        Vad {
            valence: 0.2,
            arousal: 0.4,
            dominance: 0.6,
        },
    )?;
    let annotation_claim_id = vad_annotation_claim_id(ENTITY_TYPE_TURN, &turn)?;
    let err = block_on_ready(vault.consolidate_claim_vad(&annotation_claim_id, 110))
        .expect_err("turn VAD annotation claims must not recursively consolidate");
    assert_matches!(
        err,
        Error::InvalidClaimBody("turn VAD annotation claims cannot be consolidated")
    );
    Ok(())
}

#[test]
fn claim_vad_consolidation_averages_boundary_vad_without_drift() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let subject = EntityId::now();
    let claim = EntityId::now();
    let mut turns = Vec::new();

    vault.put_entity(
        &subject,
        ENTITY_TYPE_PERSON,
        test_time_range(1, 1),
        1,
        b"subject",
    )?;
    for learned_at in 10..20 {
        let turn = EntityId::now();
        put_claim_vad_turn(
            &vault,
            &turn,
            learned_at,
            Vad {
                valence: 1.0,
                arousal: 1.0,
                dominance: 1.0,
            },
        )?;
        turns.push(turn);
    }
    let body = claim_vad_fixture_body(subject, &turns);
    vault.put_claim(&claim, &body, test_time_range(30, 30), 30)?;
    vault.put_edge(&claim, EdgeKind::Mentions, &subject, 0.6)?;

    let outcome = block_on_ready(vault.consolidate_claim_vad(&claim, 100))?;
    assert_vad_close(
        outcome.vad.expect("computed VAD"),
        Vad {
            valence: 1.0,
            arousal: 1.0,
            dominance: 1.0,
        },
    );
    assert_eq!(outcome.evidence_turns.len(), 10);
    Ok(())
}

#[test]
fn claim_vad_consolidation_rejects_missing_and_closed_claims() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let missing = EntityId::now();
    let err = block_on_ready(vault.consolidate_claim_vad(&missing, 10))
        .expect_err("missing claim must fail");
    assert_matches!(err, Error::EntityNotFound);

    let subject = EntityId::now();
    let claim = EntityId::now();
    vault.put_entity(
        &subject,
        ENTITY_TYPE_PERSON,
        test_time_range(1, 1),
        1,
        b"subject",
    )?;
    let body = claim_vad_fixture_body(subject, &[]);
    vault.put_claim(&claim, &body, test_time_range(30, 30), 30)?;
    vault.retract_claim(&claim, 40)?;

    let err = block_on_ready(vault.consolidate_claim_vad(&claim, 50))
        .expect_err("closed claim must fail");
    assert_matches!(
        err,
        Error::ClaimAlreadyClosed {
            status: ClaimLifecycleStatus::Retracted
        }
    );
    Ok(())
}

#[test]
fn claim_vad_consolidation_without_evidence_clears_edges_without_state() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let subject = EntityId::now();
    let claim = EntityId::now();

    vault.put_entity(
        &subject,
        ENTITY_TYPE_PERSON,
        test_time_range(1, 1),
        1,
        b"subject",
    )?;
    let body = claim_vad_fixture_body(subject, &[]);
    vault.put_claim(&claim, &body, test_time_range(30, 30), 30)?;
    vault.put_edge_with_vad(
        &claim,
        EdgeKind::Mentions,
        &subject,
        0.6,
        Vad {
            valence: 0.9,
            arousal: 0.7,
            dominance: 0.8,
        },
    )?;

    let outcome = block_on_ready(vault.consolidate_claim_vad(&claim, 100))?;
    assert_eq!(outcome.vad, None);
    assert!(outcome.evidence_turns.is_empty());
    assert_eq!(outcome.semantic_edges_updated, 1);
    assert_eq!(outcome.reappraisal.active_claim_id, None);
    assert_eq!(outcome.reappraisal.created_claim_id, None);
    assert!(outcome.reappraisal.superseded_claim_ids.is_empty());

    let mentions = vault
        .edges_out(&claim)?
        .into_iter()
        .find(|edge| edge.kind == EdgeKind::Mentions && edge.target == subject)
        .expect("semantic edge survives");
    assert_vad_close(mentions.vad.expect("cleared VAD"), Vad::NEUTRAL);

    let mut active_claim_vad_states = Vec::new();
    for state_id in vault.claims_for_subject(&claim)? {
        let Some(state) = vault.get_claim(&state_id)? else {
            continue;
        };
        if state.predicate == CLAIM_VAD_REAPPRAISAL_PREDICATE
            && state.lifecycle == ClaimLifecycleStatus::Active
        {
            active_claim_vad_states.push(state_id);
        }
    }
    assert!(active_claim_vad_states.is_empty());
    Ok(())
}

#[test]
fn claim_vad_reappraisal_clears_state_when_turn_evidence_disappears() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let subject = EntityId::now();
    let turn = EntityId::now();
    let claim = EntityId::now();

    vault.put_entity(
        &subject,
        ENTITY_TYPE_PERSON,
        test_time_range(1, 1),
        1,
        b"subject",
    )?;
    put_claim_vad_turn(
        &vault,
        &turn,
        10,
        Vad {
            valence: 0.6,
            arousal: 0.4,
            dominance: 0.8,
        },
    )?;
    let body = claim_vad_fixture_body(subject, &[turn]);
    vault.put_claim(&claim, &body, test_time_range(30, 30), 30)?;
    vault.put_edge(&claim, EdgeKind::Mentions, &subject, 0.6)?;

    let first = block_on_ready(vault.consolidate_claim_vad(&claim, 100))?;
    assert!(first.vad.is_some());
    let old_state_id = first
        .reappraisal
        .created_claim_id
        .expect("initial state claim");
    let old_before = vault
        .get_claim(&old_state_id)?
        .expect("initial state remains readable");

    vault.batch().delete(&turn).commit()?;
    assert_eq!(vault.get_turn_vad_annotation(&turn)?, None);

    let second = block_on_ready(vault.consolidate_claim_vad(&claim, 200))?;
    assert_eq!(second.vad, None);
    assert!(second.evidence_turns.is_empty());
    assert_eq!(second.semantic_edges_updated, 1);
    assert_eq!(second.reappraisal.active_claim_id, None);
    assert_eq!(second.reappraisal.created_claim_id, None);
    assert_eq!(second.reappraisal.superseded_claim_ids, vec![old_state_id]);

    let old_after = vault
        .get_claim(&old_state_id)?
        .expect("superseded state stays readable");
    assert_eq!(old_after.lifecycle, ClaimLifecycleStatus::Superseded);
    assert_eq!(old_after.valid_to, Some(200));
    assert_eq!(old_after.source, old_before.source);
    assert_eq!(old_after.evidence, old_before.evidence);

    let mentions = vault
        .edges_out(&claim)?
        .into_iter()
        .find(|edge| edge.kind == EdgeKind::Mentions && edge.target == subject)
        .expect("semantic edge survives");
    assert_vad_close(mentions.vad.expect("cleared VAD"), Vad::NEUTRAL);

    let mut active_claim_vad_states = Vec::new();
    for state_id in vault.claims_for_subject(&claim)? {
        let Some(state) = vault.get_claim(&state_id)? else {
            continue;
        };
        if state.predicate == CLAIM_VAD_REAPPRAISAL_PREDICATE
            && state.lifecycle == ClaimLifecycleStatus::Active
        {
            active_claim_vad_states.push(state_id);
        }
    }
    assert!(
        active_claim_vad_states.is_empty(),
        "removed evidence must not leave an active claim-VAD state"
    );
    Ok(())
}

#[test]
fn coping_outcome_claim_validation_requires_bitemporal_confidence() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let person = EntityId::now();
    let strategy_ref = EntityId::now();
    let outcome = EntityId::now();

    vault.put_entity(
        &person,
        ENTITY_TYPE_PERSON,
        test_time_range(1, 1),
        1,
        b"person",
    )?;

    let value = CopingOutcomeValue::new(
        person,
        strategy_ref,
        CopingStrategy::SitSel,
        VadDelta::new(0.2, -0.1, 0.1)?,
        0.7,
        1,
    )?;
    let missing_valid_time = ClaimBody::new(
        COPING_OUTCOME_PREDICATE,
        ClaimSubject::Entity(person),
        coping_outcome_value(&value),
        value.confidence(),
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    );
    let err = vault
        .put_claim(
            &outcome,
            &missing_valid_time,
            test_time_range(10, u64::MAX),
            10,
        )
        .expect_err("coping outcomes must carry valid_from");
    assert_matches!(
        err,
        Error::InvalidClaimBody("coping.outcome valid_from is required")
    );

    let mut mismatched_confidence = ClaimBody::new(
        COPING_OUTCOME_PREDICATE,
        ClaimSubject::Entity(person),
        coping_outcome_value(&value),
        0.6,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    );
    mismatched_confidence.valid_from = Some(10);
    let err = vault
        .put_claim(
            &outcome,
            &mismatched_confidence,
            test_time_range(10, u64::MAX),
            10,
        )
        .expect_err("wrapper confidence must mirror the value");
    assert_matches!(
        err,
        Error::InvalidClaimBody("coping.outcome wrapper confidence must mirror value confidence")
    );
    Ok(())
}

#[test]
fn coping_outcome_update_from_later_turn_vad_delta_supersedes_previous_claim() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let person = EntityId::now();
    let baseline_turn = EntityId::now();
    let later_turn = EntityId::now();
    let outcome = EntityId::now();

    vault.put_entity(
        &person,
        ENTITY_TYPE_PERSON,
        test_time_range(1, 1),
        1,
        b"person",
    )?;
    put_claim_vad_turn(
        &vault,
        &baseline_turn,
        10,
        Vad {
            valence: -0.5,
            arousal: 0.9,
            dominance: 0.2,
        },
    )?;
    put_claim_vad_turn(
        &vault,
        &later_turn,
        20,
        Vad {
            valence: 0.3,
            arousal: 0.4,
            dominance: 0.7,
        },
    )?;

    let body = coping_outcome_fixture_body(
        person,
        baseline_turn,
        CopingStrategy::CogChg,
        VadDelta::new(-0.2, 0.2, -0.1)?,
        0.4,
        ClaimLifecycleStatus::Active,
        50,
    )?;
    vault.put_claim(&outcome, &body, test_time_range(50, u64::MAX), 50)?;

    let update = vault.update_coping_outcome_from_turn_vad(
        &outcome,
        &baseline_turn,
        &later_turn,
        0.8,
        200,
    )?;

    assert_eq!(update.prior_claim_id, outcome);
    assert_eq!(update.superseded_claim_ids, vec![outcome]);
    assert_ne!(update.active_claim_id, outcome);
    assert_eq!(update.value.strategy(), CopingStrategy::CogChg);
    assert!(update.value.successful());
    assert_eq!(update.value.observed_n(), 2);
    assert_f32_close(update.value.vad_delta().valence(), 0.3);
    assert_f32_close(update.value.vad_delta().arousal(), -0.15);
    assert_f32_close(update.value.vad_delta().dominance(), 0.2);
    assert_f32_close(update.value.confidence(), 0.6);

    let old = vault
        .get_claim(&outcome)?
        .expect("superseded outcome remains readable");
    assert_eq!(old.lifecycle, ClaimLifecycleStatus::Superseded);
    assert_eq!(old.valid_to, Some(200));
    assert_eq!(entity_header(&vault, &outcome)?.occurred_end, 200);

    let active = vault
        .get_claim(&update.active_claim_id)?
        .expect("updated outcome claim");
    assert_eq!(active.lifecycle, ClaimLifecycleStatus::Active);
    assert_eq!(active.valid_from, Some(200));
    assert_eq!(
        active.confidence.to_bits(),
        update.value.confidence().to_bits()
    );
    assert!(active.evidence.is_some());
    assert_eq!(
        decode_coping_outcome_claim(&active)?.expect("typed outcome"),
        update.value
    );
    assert!(vault.edge_exists(&update.active_claim_id, EdgeKind::ClaimOf, &person)?);
    assert!(vault.edge_exists(&update.active_claim_id, EdgeKind::Supersedes, &outcome)?);
    Ok(())
}

#[test]
fn coping_outcome_update_rejects_backfilled_supersession_timestamp() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let person = EntityId::now();
    let strategy_ref = EntityId::now();
    let outcome = EntityId::now();

    vault.put_entity(
        &person,
        ENTITY_TYPE_PERSON,
        test_time_range(1, 1),
        1,
        b"person",
    )?;
    let body = coping_outcome_fixture_body(
        person,
        strategy_ref,
        CopingStrategy::CogChg,
        VadDelta::new(0.2, -0.1, 0.1)?,
        0.7,
        ClaimLifecycleStatus::Active,
        50,
    )?;
    vault.put_claim(&outcome, &body, test_time_range(50, u64::MAX), 50)?;

    let err = vault
        .update_coping_outcome_from_turn_vad_delta(
            &outcome,
            strategy_ref,
            VadDelta::new(0.1, -0.1, 0.1)?,
            0.8,
            40,
        )
        .expect_err("backfilled supersession must not invert the active interval");
    assert_matches!(
        err,
        Error::InvalidClaimBody(
            "coping.outcome update timestamp must not precede active valid_from"
        )
    );

    let old = vault
        .get_claim(&outcome)?
        .expect("rejected update leaves prior outcome readable");
    assert_eq!(old.lifecycle, ClaimLifecycleStatus::Active);
    assert_eq!(old.valid_to, None);
    assert_eq!(entity_header(&vault, &outcome)?.occurred_end, u64::MAX);
    let claims = vault.claims_for_subject(&person)?;
    assert_eq!(claims, vec![outcome]);
    Ok(())
}

#[test]
fn coping_outcome_update_rejects_unrelated_baseline_turn() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let person = EntityId::now();
    let baseline_turn = EntityId::now();
    let wrong_baseline_turn = EntityId::now();
    let later_turn = EntityId::now();
    let outcome = EntityId::now();

    vault.put_entity(
        &person,
        ENTITY_TYPE_PERSON,
        test_time_range(1, 1),
        1,
        b"person",
    )?;
    put_claim_vad_turn(
        &vault,
        &baseline_turn,
        10,
        Vad {
            valence: -0.5,
            arousal: 0.8,
            dominance: 0.1,
        },
    )?;
    put_claim_vad_turn(
        &vault,
        &wrong_baseline_turn,
        11,
        Vad {
            valence: 0.5,
            arousal: 0.1,
            dominance: 0.9,
        },
    )?;
    put_claim_vad_turn(
        &vault,
        &later_turn,
        20,
        Vad {
            valence: 0.3,
            arousal: 0.4,
            dominance: 0.7,
        },
    )?;

    let body = coping_outcome_fixture_body(
        person,
        baseline_turn,
        CopingStrategy::CogChg,
        VadDelta::new(-0.2, 0.2, -0.1)?,
        0.4,
        ClaimLifecycleStatus::Active,
        50,
    )?;
    vault.put_claim(&outcome, &body, test_time_range(50, u64::MAX), 50)?;

    let err = vault
        .update_coping_outcome_from_turn_vad(&outcome, &wrong_baseline_turn, &later_turn, 0.8, 200)
        .expect_err("unrelated baseline turn must not update the outcome ledger");
    assert_matches!(
        err,
        Error::InvalidClaimBody("baseline turn must match coping.outcome strategyRef")
    );

    let old = vault
        .get_claim(&outcome)?
        .expect("rejected update leaves prior outcome readable");
    assert_eq!(old.lifecycle, ClaimLifecycleStatus::Active);
    assert_eq!(old.valid_to, None);
    assert_eq!(entity_header(&vault, &outcome)?.occurred_end, u64::MAX);
    let claims = vault.claims_for_subject(&person)?;
    assert_eq!(claims, vec![outcome]);
    Ok(())
}

#[test]
fn coping_outcome_retrieval_queries_prior_successful_strategies() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let person = EntityId::now();
    let other_person = EntityId::now();
    let ref_a = EntityId::now();
    let ref_b = EntityId::now();
    let ref_c = EntityId::now();
    let success_old = EntityId::now();
    let failed = EntityId::now();
    let success_new = EntityId::now();
    let superseded = EntityId::now();
    let other_success = EntityId::now();

    for id in [person, other_person] {
        vault.put_entity(&id, ENTITY_TYPE_PERSON, test_time_range(1, 1), 1, b"person")?;
    }

    vault.put_claim(
        &success_old,
        &coping_outcome_fixture_body(
            person,
            ref_a,
            CopingStrategy::SitSel,
            VadDelta::new(0.2, 0.0, 0.0)?,
            0.7,
            ClaimLifecycleStatus::Active,
            10,
        )?,
        test_time_range(10, u64::MAX),
        10,
    )?;
    vault.put_claim(
        &failed,
        &coping_outcome_fixture_body(
            person,
            ref_b,
            CopingStrategy::AttDep,
            VadDelta::new(-0.1, 0.1, -0.1)?,
            0.8,
            ClaimLifecycleStatus::Active,
            20,
        )?,
        test_time_range(20, u64::MAX),
        20,
    )?;
    vault.put_claim(
        &success_new,
        &coping_outcome_fixture_body(
            person,
            ref_c,
            CopingStrategy::ResMod,
            VadDelta::new(0.0, -0.2, 0.0)?,
            0.9,
            ClaimLifecycleStatus::Active,
            30,
        )?,
        test_time_range(30, u64::MAX),
        30,
    )?;
    vault.put_claim(
        &superseded,
        &coping_outcome_fixture_body(
            person,
            EntityId::now(),
            CopingStrategy::ERFlex,
            VadDelta::new(0.3, 0.0, 0.0)?,
            0.9,
            ClaimLifecycleStatus::Superseded,
            40,
        )?,
        test_time_range(40, 41),
        40,
    )?;
    vault.put_claim(
        &other_success,
        &coping_outcome_fixture_body(
            other_person,
            EntityId::now(),
            CopingStrategy::SitMod,
            VadDelta::new(0.4, 0.0, 0.0)?,
            0.9,
            ClaimLifecycleStatus::Active,
            50,
        )?,
        test_time_range(50, u64::MAX),
        50,
    )?;

    let records = vault
        .query()
        .prior_successful_coping_strategies(&person, 10)?;

    assert_eq!(records.len(), 2);
    assert_eq!(records[0].claim_id, success_new);
    assert_eq!(records[0].value.strategy(), CopingStrategy::ResMod);
    assert_eq!(records[1].claim_id, success_old);
    assert_eq!(records[1].value.strategy(), CopingStrategy::SitSel);
    assert!(
        records
            .iter()
            .all(|record| record.value.affected_person() == person && record.value.successful())
    );

    let limited = vault
        .query()
        .prior_successful_coping_strategies(&person, 1)?;
    assert_eq!(limited.len(), 1);
    assert_eq!(limited[0].claim_id, success_new);
    Ok(())
}

#[test]
fn batch_edge_with_vad_api() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let src = EntityId::now();
    let tgt = EntityId::now();

    vault
        .batch()
        .put(&src, 1, test_time_range(1, 2), 3, b"src")
        .put(&tgt, 4, test_time_range(4, 5), 6, b"tgt")
        .edge_with_vad(
            &src,
            EdgeKind::HasFacet,
            &tgt,
            0.7,
            Vad {
                valence: 0.5,
                arousal: 0.4,
                dominance: 0.3,
            },
        )
        .commit()?;

    let out = vault.edges_out(&src)?;
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].kind, EdgeKind::HasFacet);
    Ok(())
}

// ─── Phase 2A: Productivity Entity Types ──────────────────

#[test]
fn productivity_entity_types_round_trip() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let task_list = EntityId::now();
    let task = EntityId::now();

    vault
        .batch()
        .put(
            &task_list,
            ENTITY_TYPE_TASK_LIST,
            test_time_range(100, 100),
            101,
            b"project",
        )
        .put(
            &task,
            ENTITY_TYPE_TASK,
            test_time_range(200, 200),
            201,
            b"task-data",
        )
        .commit()?;

    assert_eq!(vault.get(&task_list)?.unwrap(), b"project");
    assert_eq!(vault.get(&task)?.unwrap(), b"task-data");
    Ok(())
}

#[test]
fn entity_id_rejects_reserved_sentinel_bytes() {
    assert!(EntityId::from_bytes([0x00; 16]).is_err());
    assert!(EntityId::from_bytes([0xFF; 16]).is_err());

    let mut claim_counter = [0xFF; 16];
    claim_counter[0] = 0;
    assert!(EntityId::from_bytes(claim_counter).is_err());

    let mut task_list_counter = [0xFF; 16];
    task_list_counter[0] = ENTITY_TYPE_TASK_LIST;
    assert!(EntityId::from_bytes(task_list_counter).is_err());

    let mut non_reserved = [0xFF; 16];
    non_reserved[0] = ENTITY_TYPE_REDACTION_AUDIT;
    assert!(EntityId::from_bytes(non_reserved).is_ok());
}

#[test]
fn entity_id_from_hex_rejects_reserved_sentinel_bytes() {
    assert!(EntityId::from_hex("00000000000000000000000000000000").is_err());
    assert!(EntityId::from_hex("ffffffffffffffffffffffffffffffff").is_err());
    assert!(EntityId::from_hex("00ffffffffffffffffffffffffffffff").is_err());
    assert!(EntityId::from_hex("50ffffffffffffffffffffffffffffff").is_err());
}

#[test]
fn batch_put_invalid_entity_type_returns_early_error() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let id = EntityId::now();

    let err = vault
        .batch()
        .put(&id, 255, test_time_range(1, 1), 2, b"bad-type")
        .commit()
        .expect_err("expected InvalidEntityType for type 255");
    assert!(
        matches!(err, Error::InvalidEntityType(255)),
        "expected InvalidEntityType(255), got {err:?}"
    );

    // Verify nothing was written
    assert!(vault.get(&id)?.is_none());
    Ok(())
}

#[test]
fn txn_batch_put_invalid_entity_type_returns_error() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let id = EntityId::now();

    let err = vault
        .with_write_txn(|wtxn| {
            vault
                .batch_in()
                .put(&id, 255, test_time_range(1, 1), 2, b"bad-type")
                .apply(wtxn)
        })
        .expect_err("expected InvalidEntityType for type 255");
    assert!(
        matches!(err, Error::InvalidEntityType(255)),
        "expected InvalidEntityType(255), got {err:?}"
    );
    assert!(vault.get(&id)?.is_none());

    Ok(())
}

/// D5: public puts of a REGISTERED maintenance-band kind must fail with the
/// distinct `MaintenanceKindNotWritable` error — not the misleading
/// `InvalidEntityType` — and must write nothing. The engine-internal writers
/// are unaffected (the receipt writer, see
/// `redaction_receipt_indexes_temporal_occurred_start_as_point_event`, the
/// `ensure_model_substrate` door, and grant/policy substrate writers).
#[test]
fn public_put_of_maintenance_kind_rejected_with_distinct_typed_error() -> Result<()> {
    let (_dir, vault) = open_test_vault();

    for (kind_byte, payload) in [
        (ENTITY_TYPE_REDACTION_AUDIT, b"forged-receipt".as_slice()),
        (ENTITY_TYPE_MODEL, b"forged-model".as_slice()),
        (ENTITY_TYPE_POLICY_MANIFEST, b"forged-policy".as_slice()),
        (ENTITY_TYPE_FEDERATION_GRANT, b"forged-grant".as_slice()),
        (ENTITY_TYPE_ACCESS_GRANT, b"forged-access-grant".as_slice()),
    ] {
        let id = EntityId::now();

        // put_entity (routes through BatchBuilder; eager gate).
        let err = vault
            .put_entity(&id, kind_byte, test_time_range(1, 1), 2, payload)
            .expect_err("public put of a maintenance kind must fail");
        assert!(
            matches!(err, Error::MaintenanceKindNotWritable(byte) if byte == kind_byte),
            "expected MaintenanceKindNotWritable({kind_byte}), got {err:?}"
        );
        assert_eq!(err.kind(), ErrorKind::MaintenanceKindNotWritable);
        assert_ne!(err.kind(), ErrorKind::InvalidEntityType);

        // TxnBatchBuilder (apply-time gate in apply_put).
        let err = vault
            .with_write_txn(|wtxn| {
                vault
                    .batch_in()
                    .put(&id, kind_byte, test_time_range(1, 1), 2, payload)
                    .apply(wtxn)
            })
            .expect_err("txn batch put of a maintenance kind must fail");
        assert!(
            matches!(err, Error::MaintenanceKindNotWritable(byte) if byte == kind_byte),
            "expected MaintenanceKindNotWritable({kind_byte}), got {err:?}"
        );

        // Nothing was written by either path.
        assert!(vault.get(&id)?.is_none());
        assert!(vault.entities_by_type(kind_byte)?.is_empty());
        let rtxn = vault.store.env.read_txn()?;
        let type_key = Store::encode_type_key(kind_byte, &id);
        assert!(vault.store.type_index.get(&rtxn, &type_key)?.is_none());
        let occurred_key = Store::encode_temporal_key(1, &id);
        assert!(
            vault
                .store
                .temporal_occurred_start
                .get(&rtxn, &occurred_key)?
                .is_none()
        );
        let learned_key = Store::encode_temporal_key(2, &id);
        assert!(
            vault
                .store
                .temporal_learned
                .get(&rtxn, &learned_key)?
                .is_none()
        );
        assert!(vault.store.short_ids.get(&rtxn, id.as_bytes())?.is_none());
        // No short-id counter sentinel was allocated for the maintenance band.
        let mut sentinel = [0xFF_u8; ENTITY_ID_LEN];
        sentinel[0] = kind_byte;
        assert!(vault.store.short_ids.get(&rtxn, &sentinel)?.is_none());
    }

    Ok(())
}

/// D5 counterpart: `InvalidEntityType` still covers genuinely UNKNOWN bytes,
/// including unregistered bytes inside the 120+ maintenance band — the
/// distinct maintenance error is reserved for registered maintenance kinds.
#[test]
fn unknown_type_bytes_still_fail_with_invalid_entity_type() -> Result<()> {
    let (_dir, vault) = open_test_vault();

    // 121 left this list when ONE-1138 registered MODEL; 123 left it when
    // GATE-001 registered POLICY_MANIFEST; 124 left it when FED-001
    // registered FEDERATION_GRANT; 128 left it when EIRI-004 registered
    // ACCESS_GRANT. Public puts of those bytes now fail
    // MaintenanceKindNotWritable — covered by the D5 gate test. Byte 122 is
    // reserved for AUTHORITY_LOG, and 125..=127 are reserved for future
    // maintenance substrates, but all remain unregistered.
    for unknown in [99_u8, 122, 125, 126, 127, 200] {
        let id = EntityId::now();
        let err = vault
            .put_entity(&id, unknown, test_time_range(1, 1), 2, b"unknown-type")
            .expect_err("unregistered type byte must fail");
        assert!(
            matches!(err, Error::InvalidEntityType(byte) if byte == unknown),
            "expected InvalidEntityType({unknown}), got {err:?}"
        );
        assert_eq!(err.kind(), ErrorKind::InvalidEntityType);
        assert!(vault.get(&id)?.is_none());
    }

    Ok(())
}

#[test]
fn reput_with_different_type_byte_is_rejected_with_no_index_residue() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let id = EntityId::now();

    vault
        .batch()
        .put(&id, 1, test_time_range(100, 200), 300, b"old-data")
        .commit()?;
    let record_before = read_raw_entity(&vault, &id)?;
    let short_id_before = read_short_id_value(&vault, &id)?;

    // D2: the type byte is immutable once a record exists. The pre-D2 engine
    // silently re-homed the type_index row and kept the old short id, leaving
    // a SESSION entity addressed as "tn1".
    let err = vault
        .batch()
        .put(&id, 2, test_time_range(400, 500), 600, b"new-data")
        .commit()
        .expect_err("re-put with a different type byte must be rejected");
    assert!(
        matches!(
            err,
            Error::EntityTypeImmutable {
                id: err_id,
                existing: 1,
                attempted: 2,
            } if err_id == id
        ),
        "expected EntityTypeImmutable {{ existing: 1, attempted: 2 }}, got {err:?}"
    );

    // Stored record and short-id row are byte-for-byte unchanged.
    assert_eq!(read_raw_entity(&vault, &id)?, record_before);
    assert_eq!(read_short_id_value(&vault, &id)?, short_id_before);

    // Original index rows intact; no rows for the rejected attempt.
    let rtxn = vault.store.env.read_txn()?;
    assert!(
        vault
            .store
            .type_index
            .get(&rtxn, &Store::encode_type_key(1, &id))?
            .is_some()
    );
    assert!(
        vault
            .store
            .type_index
            .get(&rtxn, &Store::encode_type_key(2, &id))?
            .is_none()
    );
    assert!(
        vault
            .store
            .temporal_occurred_start
            .get(&rtxn, &Store::encode_temporal_key(100, &id))?
            .is_some()
    );
    assert!(
        vault
            .store
            .temporal_occurred_end
            .get(&rtxn, &Store::encode_temporal_key(200, &id))?
            .is_some()
    );
    assert!(
        vault
            .store
            .temporal_learned
            .get(&rtxn, &Store::encode_temporal_key(300, &id))?
            .is_some()
    );
    assert!(
        vault
            .store
            .temporal_occurred_start
            .get(&rtxn, &Store::encode_temporal_key(400, &id))?
            .is_none()
    );
    assert!(
        vault
            .store
            .temporal_occurred_end
            .get(&rtxn, &Store::encode_temporal_key(500, &id))?
            .is_none()
    );
    assert!(
        vault
            .store
            .temporal_learned
            .get(&rtxn, &Store::encode_temporal_key(600, &id))?
            .is_none()
    );

    Ok(())
}

#[test]
fn txn_batch_reput_with_different_type_byte_rejects_before_staging_writes() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let id = EntityId::now();

    vault.put_entity(&id, 1, test_time_range(100, 200), 300, b"old-data")?;
    let record_before = read_raw_entity(&vault, &id)?;
    let short_id_before = read_short_id_value(&vault, &id)?;

    // Commit the externally-owned transaction DESPITE the error: the
    // apply-time gate must reject before staging any write, so an
    // implementation that re-homes index rows before checking the type byte
    // leaves residue these assertions catch.
    let mut wtxn = vault.store.env.write_txn()?;
    let err = vault
        .batch_in()
        .put(&id, 2, test_time_range(400, 500), 600, b"new-data")
        .apply(&mut wtxn)
        .expect_err("re-put with a different type byte must be rejected");
    assert!(
        matches!(
            err,
            Error::EntityTypeImmutable {
                id: err_id,
                existing: 1,
                attempted: 2,
            } if err_id == id
        ),
        "expected EntityTypeImmutable {{ existing: 1, attempted: 2 }}, got {err:?}"
    );
    wtxn.commit()?;

    assert_eq!(read_raw_entity(&vault, &id)?, record_before);
    assert_eq!(read_short_id_value(&vault, &id)?, short_id_before);

    let rtxn = vault.store.env.read_txn()?;
    assert!(
        vault
            .store
            .type_index
            .get(&rtxn, &Store::encode_type_key(2, &id))?
            .is_none()
    );
    assert!(
        vault
            .store
            .temporal_occurred_start
            .get(&rtxn, &Store::encode_temporal_key(400, &id))?
            .is_none()
    );
    assert!(
        vault
            .store
            .temporal_occurred_end
            .get(&rtxn, &Store::encode_temporal_key(500, &id))?
            .is_none()
    );
    assert!(
        vault
            .store
            .temporal_learned
            .get(&rtxn, &Store::encode_temporal_key(600, &id))?
            .is_none()
    );

    Ok(())
}

#[test]
fn txn_batch_reput_with_different_type_byte_preserves_long_interval_row() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let id = EntityId::now();

    // Seed an entity whose occurred span exceeds the long-interval threshold,
    // so a temporal_long_intervals row exists (manifest DB n21: key
    // encode_temporal_key(occurred_end, id), value occurred_start BE).
    let old_start = 100_u64;
    let old_end = old_start + LONG_INTERVAL_THRESHOLD_SECS + 1;
    vault.put_entity(
        &id,
        1,
        test_time_range(old_start, old_end),
        300,
        b"old-data",
    )?;

    let long_interval_key = Store::encode_temporal_key(old_end, &id);
    {
        let rtxn = vault.store.env.read_txn()?;
        let value = vault
            .store
            .temporal_long_intervals
            .get(&rtxn, &long_interval_key)?
            .expect("seed entity must have a temporal_long_intervals row");
        assert_eq!(value, &old_start.to_be_bytes()[..]);
    }

    // D2 ordering: the immutability gate must fire BEFORE the old-row deletes
    // in apply_put — a wrong implementation that runs the old-long-interval
    // delete first would drop the row, then error. Commit the externally-owned
    // transaction DESPITE the error to expose any such pre-gate delete.
    let mut wtxn = vault.store.env.write_txn()?;
    let err = vault
        .batch_in()
        .put(&id, 2, test_time_range(400, 500), 600, b"new-data")
        .apply(&mut wtxn)
        .expect_err("re-put with a different type byte must be rejected");
    assert!(
        matches!(
            err,
            Error::EntityTypeImmutable {
                id: err_id,
                existing: 1,
                attempted: 2,
            } if err_id == id
        ),
        "expected EntityTypeImmutable {{ existing: 1, attempted: 2 }}, got {err:?}"
    );
    wtxn.commit()?;

    // The long-interval row survives the failed re-type, byte-for-byte.
    let rtxn = vault.store.env.read_txn()?;
    let value = vault
        .store
        .temporal_long_intervals
        .get(&rtxn, &long_interval_key)?
        .expect("temporal_long_intervals row must survive a rejected re-type");
    assert_eq!(value, &old_start.to_be_bytes()[..]);

    Ok(())
}

#[test]
fn batch_double_put_same_id_different_type_rejects_and_writes_nothing() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let id = EntityId::now();

    // Same-batch TOCTOU vector: two puts for the same id with different type
    // bytes in one batch. The apply-time gate reads the stored envelope inside
    // the batch's own write transaction (read-your-own-writes), so the second
    // put must see the first put's staged record and reject.
    let err = vault
        .batch()
        .put(&id, 1, test_time_range(100, 200), 300, b"first")
        .put(&id, 2, test_time_range(400, 500), 600, b"second")
        .commit()
        .expect_err("second put with a different type byte must reject the batch");
    assert!(
        matches!(
            err,
            Error::EntityTypeImmutable {
                id: err_id,
                existing: 1,
                attempted: 2,
            } if err_id == id
        ),
        "expected EntityTypeImmutable {{ existing: 1, attempted: 2 }}, got {err:?}"
    );

    // Batch-abort atomicity: the builder owns the transaction and aborts on
    // error, so NO record survives — not even the first (valid) put.
    let rtxn = vault.store.env.read_txn()?;
    assert!(vault.store.entities.get(&rtxn, id.as_bytes())?.is_none());
    assert!(vault.store.short_ids.get(&rtxn, id.as_bytes())?.is_none());
    assert!(
        vault
            .store
            .type_index
            .get(&rtxn, &Store::encode_type_key(1, &id))?
            .is_none()
    );
    assert!(
        vault
            .store
            .type_index
            .get(&rtxn, &Store::encode_type_key(2, &id))?
            .is_none()
    );
    assert!(
        vault
            .store
            .temporal_occurred_start
            .get(&rtxn, &Store::encode_temporal_key(100, &id))?
            .is_none()
    );
    assert!(
        vault
            .store
            .temporal_learned
            .get(&rtxn, &Store::encode_temporal_key(300, &id))?
            .is_none()
    );

    Ok(())
}

#[test]
fn put_with_reversed_occurred_range_is_rejected_and_nothing_is_written() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let id = EntityId::now();

    // D3: occurred_start > occurred_end is rejected with a typed error. The
    // pre-D3 engine silently swapped the bounds and stored (100, 300).
    // Type byte 1 (TURN) keeps the body opaque so this isolates the time-range
    // gate — type 0 is reserved for CLAIM, whose bodies are validated (D18).
    let err = vault
        .batch()
        .put(&id, 1, test_time_range(300, 100), 400, b"payload")
        .commit()
        .expect_err("occurred_start > occurred_end must be rejected");
    assert!(
        matches!(
            err,
            Error::InvalidTimeRange {
                start: 300,
                end: 100
            }
        ),
        "expected InvalidTimeRange {{ start: 300, end: 100 }}, got {err:?}"
    );

    {
        let rtxn = vault.store.env.read_txn()?;
        assert!(vault.store.entities.get(&rtxn, id.as_bytes())?.is_none());
        assert!(vault.store.short_ids.get(&rtxn, id.as_bytes())?.is_none());
        assert!(
            vault
                .store
                .type_index
                .get(&rtxn, &Store::encode_type_key(1, &id))?
                .is_none()
        );
        // The pre-D3 swap stored (start: 100, end: 300) — assert both
        // orientations are absent from every temporal index.
        for ts in [100_u64, 300] {
            let key = Store::encode_temporal_key(ts, &id);
            assert!(
                vault
                    .store
                    .temporal_occurred_start
                    .get(&rtxn, &key)?
                    .is_none()
            );
            assert!(
                vault
                    .store
                    .temporal_occurred_end
                    .get(&rtxn, &key)?
                    .is_none()
            );
        }
        assert!(
            vault
                .store
                .temporal_learned
                .get(&rtxn, &Store::encode_temporal_key(400, &id))?
                .is_none()
        );
    }

    // A reversed range whose swapped span exceeds the long-interval
    // threshold: the pre-D3 swap would also have written a
    // temporal_long_intervals row keyed on the (swapped) occurred_end.
    let long_id = EntityId::now();
    let reversed_start = 300 + LONG_INTERVAL_THRESHOLD_SECS + 1;
    let err = vault
        .batch()
        .put(
            &long_id,
            1,
            test_time_range(reversed_start, 100),
            400,
            b"payload",
        )
        .commit()
        .expect_err("reversed long interval must be rejected");
    assert!(
        matches!(err, Error::InvalidTimeRange { start, end: 100 } if start == reversed_start),
        "expected InvalidTimeRange {{ start: {reversed_start}, end: 100 }}, got {err:?}"
    );

    let rtxn = vault.store.env.read_txn()?;
    assert!(
        vault
            .store
            .entities
            .get(&rtxn, long_id.as_bytes())?
            .is_none()
    );
    assert!(
        vault
            .store
            .temporal_long_intervals
            .get(&rtxn, &Store::encode_temporal_key(reversed_start, &long_id))?
            .is_none()
    );

    Ok(())
}

#[test]
fn txn_batch_put_with_reversed_occurred_range_rejected_at_apply_time() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let id = EntityId::now();

    // TxnBatchBuilder has no eager validation — this exercises the
    // authoritative apply-time gate in apply_put. Commit the transaction
    // despite the error to prove the gate rejected before staging any write.
    let mut wtxn = vault.store.env.write_txn()?;
    let err = vault
        .batch_in()
        .put(&id, 1, test_time_range(300, 100), 400, b"payload")
        .apply(&mut wtxn)
        .expect_err("occurred_start > occurred_end must be rejected");
    assert!(
        matches!(
            err,
            Error::InvalidTimeRange {
                start: 300,
                end: 100
            }
        ),
        "expected InvalidTimeRange {{ start: 300, end: 100 }}, got {err:?}"
    );
    wtxn.commit()?;

    let rtxn = vault.store.env.read_txn()?;
    assert!(vault.store.entities.get(&rtxn, id.as_bytes())?.is_none());
    assert!(vault.store.short_ids.get(&rtxn, id.as_bytes())?.is_none());
    for ts in [100_u64, 300] {
        let key = Store::encode_temporal_key(ts, &id);
        assert!(
            vault
                .store
                .temporal_occurred_start
                .get(&rtxn, &key)?
                .is_none()
        );
        assert!(
            vault
                .store
                .temporal_occurred_end
                .get(&rtxn, &key)?
                .is_none()
        );
    }

    Ok(())
}

#[test]
fn point_event_start_equals_end_stays_accepted() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let id = EntityId::now();

    // D3 boundary: start == end is a legal point event.
    vault
        .batch()
        .put(&id, 1, test_time_range(777, 777), 800, b"point")
        .commit()?;

    let rtxn = vault.store.env.read_txn()?;
    let raw = vault
        .store
        .entities
        .get(&rtxn, id.as_bytes())?
        .ok_or(Error::EntityNotFound)?;
    assert_eq!(raw[1..9], 777_u64.to_be_bytes());
    assert_eq!(raw[9..17], 777_u64.to_be_bytes());

    // Point-event index convention: occurred_start row only, no occurred_end
    // row (apply_put writes temporal_occurred_end only when start != end).
    let key = Store::encode_temporal_key(777, &id);
    assert!(
        vault
            .store
            .temporal_occurred_start
            .get(&rtxn, &key)?
            .is_some()
    );
    assert!(
        vault
            .store
            .temporal_occurred_end
            .get(&rtxn, &key)?
            .is_none()
    );

    Ok(())
}

#[test]
fn edge_kinds_child_of_and_assigned_to() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let child = EntityId::now();
    let parent = EntityId::now();
    let machine = EntityId::now();

    vault.put_edge(&child, EdgeKind::ChildOf, &parent, 1.0)?;
    vault.put_edge(&child, EdgeKind::AssignedTo, &machine, 0.8)?;

    let out = vault.edges_out(&child)?;
    assert_eq!(out.len(), 2);
    assert!(
        out.iter()
            .any(|e| e.kind == EdgeKind::ChildOf && e.target == parent)
    );
    assert!(
        out.iter()
            .any(|e| e.kind == EdgeKind::AssignedTo && e.target == machine)
    );

    // Contract pprWeight is null for both kinds (contracts.ts edgeKinds u8=6/7):
    // no stored-weight prior exists, so callers pick the weight explicitly.
    assert_eq!(EdgeKind::ChildOf.default_weight(), None);
    assert_eq!(EdgeKind::AssignedTo.default_weight(), None);
    Ok(())
}

/// ONE-1115 AC2 — `EdgeKind::default_weight` must equal the contract's
/// LITERAL `edgeKinds.pprWeight` column (oneiron-docs
/// `site/src/data/oneiron-contracts.ts`). `child_of` and `assigned_to` are
/// the only `pprWeight: null` rows; any single-row drift fails this test.
#[test]
fn default_weight_matches_contract_ppr_weight_literals() {
    let expected: [(EdgeKind, Option<f32>); 20] = [
        (EdgeKind::AuthoredBy, Some(0.9)),
        (EdgeKind::ScopedTo, Some(0.7)),
        (EdgeKind::PartOf, Some(0.8)),
        (EdgeKind::Supersedes, Some(0.3)),
        (EdgeKind::BelongsTo, Some(1.0)),
        (EdgeKind::ClaimOf, Some(1.0)),
        (EdgeKind::ChildOf, None),
        (EdgeKind::AssignedTo, None),
        (EdgeKind::DerivedFrom, Some(0.2)),
        (EdgeKind::Mentions, Some(0.6)),
        (EdgeKind::About, Some(0.5)),
        (EdgeKind::Supports, Some(1.0)),
        (EdgeKind::Opposes, Some(0.0)),
        (EdgeKind::ParticipatesIn, Some(1.0)),
        (EdgeKind::Attached, Some(0.8)),
        (EdgeKind::EmployedBy, Some(0.8)),
        (EdgeKind::HasFacet, Some(0.7)),
        (EdgeKind::FacetOf, Some(0.7)),
        (EdgeKind::InWorld, Some(0.7)),
        (EdgeKind::SetIn, Some(0.7)),
    ];
    for (kind, weight) in expected {
        assert_eq!(
            kind.default_weight(),
            weight,
            "stored-weight prior mismatch for {kind:?}"
        );
    }
}

/// ONE-1115 AC4 — edge weights are pinned to the contract range \[0, 1\]
/// (contracts.ts `edgeKinds`) at write time: the value encoder and the batch
/// apply path both reject out-of-range and non-finite weights with the typed
/// `InvalidEdgeWeight`, and the boundary values 0.0 / 1.0 are accepted.
#[test]
fn edge_weight_outside_unit_range_rejected_at_write() -> Result<()> {
    fn assert_invalid_weight(err: Error, rejected: f32) {
        let Error::InvalidEdgeWeight { value } = err else {
            panic!("expected InvalidEdgeWeight for {rejected}, got {err:?}");
        };
        if rejected.is_nan() {
            assert!(value.is_nan(), "error payload must echo NaN, got {value}");
        } else {
            assert_eq!(
                value.to_bits(),
                rejected.to_bits(),
                "error payload must echo the rejected weight"
            );
        }
    }

    let (_dir, vault) = open_test_vault();

    for bad in [-0.1_f32, 1.1, f32::NAN, f32::INFINITY, f32::NEG_INFINITY] {
        // Value encoder (types::encode_edge_value).
        let encode_err = encode_edge_value(EdgeKind::Mentions, bad, 0, Vad::NEUTRAL, None)
            .expect_err("encoder must reject out-of-range weight");
        assert_invalid_weight(encode_err, bad);

        // Batch apply path (put_edge → apply_edge_with_created_at).
        let apply_err = vault
            .put_edge(&EntityId::now(), EdgeKind::Mentions, &EntityId::now(), bad)
            .expect_err("apply path must reject out-of-range weight");
        assert_invalid_weight(apply_err, bad);
    }

    // Closed-interval boundaries are valid weights on both paths.
    for good in [0.0_f32, 1.0] {
        encode_edge_value(EdgeKind::Mentions, good, 0, Vad::NEUTRAL, None)
            .expect("boundary weight must encode");

        let src = EntityId::now();
        let tgt = EntityId::now();
        vault.put_edge(&src, EdgeKind::Mentions, &tgt, good)?;
        let out = vault.edges_out(&src)?;
        assert_eq!(out.len(), 1);
        assert_eq!(
            out[0].weight.to_bits(),
            good.to_bits(),
            "boundary weight must round-trip the write gate"
        );
    }
    Ok(())
}

// ─── Phase 2A: Tree Query API ─────────────────────────────

#[test]
fn entities_by_type_returns_correct_ids() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let tl1 = EntityId::now();
    let tl2 = EntityId::now();
    let tk1 = EntityId::now();

    vault
        .batch()
        .put(
            &tl1,
            ENTITY_TYPE_TASK_LIST,
            test_time_range(1, 1),
            2,
            b"project-1",
        )
        .put(
            &tl2,
            ENTITY_TYPE_TASK_LIST,
            test_time_range(3, 3),
            4,
            b"project-2",
        )
        .put(&tk1, ENTITY_TYPE_TASK, test_time_range(5, 5), 6, b"task-1")
        .commit()?;

    let task_lists = vault.entities_by_type(ENTITY_TYPE_TASK_LIST)?;
    assert_eq!(task_lists.len(), 2);
    assert!(task_lists.contains(&tl1));
    assert!(task_lists.contains(&tl2));

    let tasks = vault.entities_by_type(ENTITY_TYPE_TASK)?;
    assert_eq!(tasks.len(), 1);
    assert!(tasks.contains(&tk1));

    let empty = vault.entities_by_type(ENTITY_TYPE_MACHINE)?;
    assert!(empty.is_empty());
    Ok(())
}

#[test]
fn entities_by_type_rejects_corrupted_type_index_key() -> Result<()> {
    let entity_type = ENTITY_TYPE_TASK_LIST;

    {
        let (_dir, vault) = open_test_vault();
        let short_key = [entity_type, 0xaa];

        vault.with_write_txn(|wtxn| {
            vault.store.type_index.put(wtxn, &short_key, &[])?;
            Ok(())
        })?;

        let err = vault
            .entities_by_type(entity_type)
            .expect_err("short type index key should fail loud");
        assert_matches!(err, Error::CorruptedIndex("type index key"));
    }

    {
        let (_dir, vault) = open_test_vault();
        let mut reserved_id_key = [0_u8; 17];
        reserved_id_key[0] = entity_type;

        vault.with_write_txn(|wtxn| {
            vault.store.type_index.put(wtxn, &reserved_id_key, &[])?;
            Ok(())
        })?;

        let err = vault
            .entities_by_type(entity_type)
            .expect_err("reserved-id type index key should fail loud");
        assert_matches!(err, Error::CorruptedIndex("type index key"));
    }

    Ok(())
}

#[test]
fn entities_by_type_allows_exact_cap_and_overflows_on_next_row() -> Result<()> {
    const TYPE_CAP: usize = 100_000;

    let temp_dir = tempfile::tempdir()?;
    let vault = Vault::open(temp_dir.path(), large_test_config())?;

    vault.with_write_txn(|wtxn| {
        for i in 0..TYPE_CAP {
            let id = seeded_entity_id(i as u128);
            let key = Store::encode_type_key(ENTITY_TYPE_TASK_LIST, &id);
            vault.store.type_index.put(wtxn, &key, &[])?;
        }
        Ok(())
    })?;

    let ids = vault.entities_by_type(ENTITY_TYPE_TASK_LIST)?;
    assert_eq!(ids.len(), TYPE_CAP);

    let overflow_id = seeded_entity_id(TYPE_CAP as u128);
    vault.with_write_txn(|wtxn| {
        let key = Store::encode_type_key(ENTITY_TYPE_TASK_LIST, &overflow_id);
        vault.store.type_index.put(wtxn, &key, &[])?;
        Ok(())
    })?;

    let err = vault
        .entities_by_type(ENTITY_TYPE_TASK_LIST)
        .expect_err("type scan should fail loud once cap is exceeded");
    assert_matches!(err, Error::IndexOverflow("entities_by_type"));
    Ok(())
}

#[test]
fn entities_by_type_page_paginates_past_materialization_cap() -> Result<()> {
    const TYPE_CAP: usize = 100_000;
    const EXTRA_ROWS: usize = 3;
    const PAGE_SIZE: usize = 4_096;

    let temp_dir = tempfile::tempdir()?;
    let vault = Vault::open(temp_dir.path(), large_test_config())?;

    vault.with_write_txn(|wtxn| {
        for i in 0..(TYPE_CAP + EXTRA_ROWS) {
            let id = seeded_entity_id(i as u128);
            let key = Store::encode_type_key(ENTITY_TYPE_TASK_LIST, &id);
            vault.store.type_index.put(wtxn, &key, &[])?;
        }
        Ok(())
    })?;

    let mut after = None;
    let mut first = None;
    let mut last = None;
    let mut total = 0;
    loop {
        let page = vault.entities_by_type_page(ENTITY_TYPE_TASK_LIST, after.as_ref(), PAGE_SIZE)?;
        let Some(page_last) = page.last().copied() else {
            break;
        };
        if let Some(previous) = after {
            assert!(previous < page[0]);
        }
        first.get_or_insert(page[0]);
        total += page.len();
        last = Some(page_last);
        after = Some(page_last);
    }

    assert_eq!(total, TYPE_CAP + EXTRA_ROWS);
    assert_eq!(first, Some(seeded_entity_id(0)));
    assert_eq!(
        last,
        Some(seeded_entity_id((TYPE_CAP + EXTRA_ROWS - 1) as u128))
    );
    assert!(
        vault
            .entities_by_type_page(
                ENTITY_TYPE_TASK_LIST,
                Some(&seeded_entity_id((TYPE_CAP + EXTRA_ROWS - 1) as u128)),
                PAGE_SIZE
            )?
            .is_empty()
    );
    assert!(
        vault
            .entities_by_type_page(ENTITY_TYPE_TASK_LIST, None, 0)?
            .is_empty()
    );
    Ok(())
}

#[test]
fn latest_entity_bodies_by_type_returns_bounded_latest_snapshot_rows() -> Result<()> {
    let temp_dir = tempfile::tempdir()?;
    let vault = Vault::open(temp_dir.path(), test_config())?;
    let old = seeded_entity_id(0x2140);
    let newest = seeded_entity_id(0x2141);
    let other_type = seeded_entity_id(0x2142);

    vault
        .batch()
        .put(
            &old,
            ENTITY_TYPE_NOTIFICATION,
            test_time_range(1, 1),
            10,
            b"old",
        )
        .put(
            &newest,
            ENTITY_TYPE_NOTIFICATION,
            test_time_range(2, 2),
            30,
            b"new",
        )
        .put(
            &other_type,
            ENTITY_TYPE_TASK,
            test_time_range(3, 3),
            40,
            b"task",
        )
        .commit()?;

    let latest = vault.latest_entity_bodies_by_type(ENTITY_TYPE_NOTIFICATION, 2, 3)?;
    assert_eq!(
        latest,
        vec![(newest, 30, b"new".to_vec()), (old, 10, b"old".to_vec())]
    );

    let scan_limited = vault.latest_entity_bodies_by_type(ENTITY_TYPE_NOTIFICATION, 2, 1)?;
    assert!(scan_limited.is_empty());

    let result_limited = vault.latest_entity_bodies_by_type(ENTITY_TYPE_NOTIFICATION, 1, 3)?;
    assert_eq!(result_limited, vec![(newest, 30, b"new".to_vec())]);

    Ok(())
}

#[test]
fn targets_and_sources_with_kind_filter() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let child = EntityId::now();
    let parent = EntityId::now();
    let sibling = EntityId::now();
    let task_list = EntityId::now();

    vault
        .batch()
        .put(&child, ENTITY_TYPE_TASK, test_time_range(1, 1), 2, b"child")
        .put(
            &parent,
            ENTITY_TYPE_TASK,
            test_time_range(3, 3),
            4,
            b"parent",
        )
        .put(
            &sibling,
            ENTITY_TYPE_TASK,
            test_time_range(5, 5),
            6,
            b"sibling",
        )
        .put(
            &task_list,
            ENTITY_TYPE_TASK_LIST,
            test_time_range(7, 7),
            8,
            b"project",
        )
        .edge(&child, EdgeKind::ChildOf, &parent, 1.0)
        .edge(&sibling, EdgeKind::ChildOf, &parent, 1.0)
        .edge(&child, EdgeKind::BelongsTo, &task_list, 1.0)
        .commit()?;

    // targets(child, ChildOf) should return the parent
    let parents = vault.targets(&child, EdgeKind::ChildOf, None)?;
    assert_eq!(parents, vec![parent]);

    // sources(parent, ChildOf) should return both children
    let children = vault.sources(&parent, EdgeKind::ChildOf, None)?;
    assert_eq!(children.len(), 2);
    assert!(children.contains(&child));
    assert!(children.contains(&sibling));

    // targets with type filter: child's BelongsTo targets of task-list type
    let lists = vault.targets(&child, EdgeKind::BelongsTo, Some(ENTITY_TYPE_TASK_LIST))?;
    assert_eq!(lists, vec![task_list]);

    // targets with wrong type filter: should be empty
    let wrong = vault.targets(&child, EdgeKind::BelongsTo, Some(ENTITY_TYPE_TASK))?;
    assert!(wrong.is_empty());
    Ok(())
}

#[test]
fn targets_and_sources_overflow_when_peer_cap_exceeded() -> Result<()> {
    const EDGE_CAP: usize = 100_000;

    let temp_dir = tempfile::tempdir()?;
    let vault = Vault::open(temp_dir.path(), large_test_config())?;
    let src = seeded_entity_id(1);
    let tgt = seeded_entity_id(2);
    let value = valid_edge_value();

    vault.with_write_txn(|wtxn| {
        for i in 0..EDGE_CAP {
            let peer = seeded_entity_id(10 + i as u128);
            let out_key = Store::encode_edge_key(&src, EdgeKind::BelongsTo, &peer);
            let in_key = Store::encode_edge_key(&tgt, EdgeKind::BelongsTo, &peer);
            vault.store.edges_out.put(wtxn, &out_key, &value)?;
            vault.store.edges_in.put(wtxn, &in_key, &value)?;
        }
        Ok(())
    })?;

    assert_eq!(
        vault.targets(&src, EdgeKind::BelongsTo, None)?.len(),
        EDGE_CAP
    );
    assert_eq!(
        vault.sources(&tgt, EdgeKind::BelongsTo, None)?.len(),
        EDGE_CAP
    );

    let overflow_target = seeded_entity_id(10 + EDGE_CAP as u128);
    let overflow_source = seeded_entity_id(11 + EDGE_CAP as u128);
    vault.with_write_txn(|wtxn| {
        let out_key = Store::encode_edge_key(&src, EdgeKind::BelongsTo, &overflow_target);
        let in_key = Store::encode_edge_key(&tgt, EdgeKind::BelongsTo, &overflow_source);
        vault.store.edges_out.put(wtxn, &out_key, &value)?;
        vault.store.edges_in.put(wtxn, &in_key, &value)?;
        Ok(())
    })?;

    let targets_err = vault
        .targets(&src, EdgeKind::BelongsTo, None)
        .expect_err("targets should fail loud once cap is exceeded");
    assert_matches!(targets_err, Error::IndexOverflow("targets"));

    let sources_err = vault
        .sources(&tgt, EdgeKind::BelongsTo, None)
        .expect_err("sources should fail loud once cap is exceeded");
    assert_matches!(sources_err, Error::IndexOverflow("sources"));
    Ok(())
}

#[test]
fn targets_and_sources_fail_loud_when_type_filter_overscans_peer_cap() -> Result<()> {
    const EDGE_CAP: usize = 100_000;

    let temp_dir = tempfile::tempdir()?;
    let vault = Vault::open(temp_dir.path(), large_test_config())?;
    let src = seeded_entity_id(100_000);
    let tgt = seeded_entity_id(200_000);
    let value = valid_edge_value();

    vault.with_write_txn(|wtxn| {
        for i in 0..EDGE_CAP {
            let peer = seeded_entity_id(300_000 + i as u128);
            let row = encoded_entity_record(ENTITY_TYPE_TASK, b"peer");
            let out_key = Store::encode_edge_key(&src, EdgeKind::BelongsTo, &peer);
            let in_key = Store::encode_edge_key(&tgt, EdgeKind::BelongsTo, &peer);
            vault.store.entities.put(wtxn, peer.as_bytes(), &row)?;
            vault.store.edges_out.put(wtxn, &out_key, &value)?;
            vault.store.edges_in.put(wtxn, &in_key, &value)?;
        }

        let matching_peer = seeded_entity_id(400_001);
        let matching_row = encoded_entity_record(ENTITY_TYPE_TASK_LIST, b"peer");
        let out_key = Store::encode_edge_key(&src, EdgeKind::BelongsTo, &matching_peer);
        let in_key = Store::encode_edge_key(&tgt, EdgeKind::BelongsTo, &matching_peer);
        vault
            .store
            .entities
            .put(wtxn, matching_peer.as_bytes(), &matching_row)?;
        vault.store.edges_out.put(wtxn, &out_key, &value)?;
        vault.store.edges_in.put(wtxn, &in_key, &value)?;
        Ok(())
    })?;

    let targets_err = vault
        .targets(&src, EdgeKind::BelongsTo, Some(ENTITY_TYPE_TASK_LIST))
        .expect_err("type-filtered targets should fail loud once scan cap is exceeded");
    assert_matches!(targets_err, Error::IndexOverflow("targets"));

    let sources_err = vault
        .sources(&tgt, EdgeKind::BelongsTo, Some(ENTITY_TYPE_TASK_LIST))
        .expect_err("type-filtered sources should fail loud once scan cap is exceeded");
    assert_matches!(sources_err, Error::IndexOverflow("sources"));
    Ok(())
}

#[test]
fn subtree_four_level_tree() -> Result<()> {
    let (_dir, vault) = open_test_vault();

    // Build: root → child1 → grandchild → great_grandchild
    //             → child2
    let root = EntityId::now();
    let child1 = EntityId::now();
    let child2 = EntityId::now();
    let grandchild = EntityId::now();
    let great_grandchild = EntityId::now();

    vault
        .batch()
        .put(&root, ENTITY_TYPE_TASK, test_time_range(1, 1), 2, b"root")
        .put(
            &child1,
            ENTITY_TYPE_TASK,
            test_time_range(3, 3),
            4,
            b"child1",
        )
        .put(
            &child2,
            ENTITY_TYPE_TASK,
            test_time_range(5, 5),
            6,
            b"child2",
        )
        .put(
            &grandchild,
            ENTITY_TYPE_TASK,
            test_time_range(7, 7),
            8,
            b"gc",
        )
        .put(
            &great_grandchild,
            ENTITY_TYPE_TASK,
            test_time_range(9, 9),
            10,
            b"ggc",
        )
        .edge(&child1, EdgeKind::ChildOf, &root, 1.0)
        .edge(&child2, EdgeKind::ChildOf, &root, 1.0)
        .edge(&grandchild, EdgeKind::ChildOf, &child1, 1.0)
        .edge(&great_grandchild, EdgeKind::ChildOf, &grandchild, 1.0)
        .commit()?;

    let tree = vault.subtree(&root, 10)?;
    assert_eq!(tree.len(), 4); // child1, child2, grandchild, great_grandchild

    // Verify depths
    let depth_of = |id: EntityId| tree.iter().find(|(i, _)| *i == id).map(|(_, d)| *d);
    assert_eq!(depth_of(child1), Some(1));
    assert_eq!(depth_of(child2), Some(1));
    assert_eq!(depth_of(grandchild), Some(2));
    assert_eq!(depth_of(great_grandchild), Some(3));

    // max_depth=1 should only return direct children
    let shallow = vault.subtree(&root, 1)?;
    assert_eq!(shallow.len(), 2);
    assert!(shallow.iter().all(|(_, d)| *d == 1));

    Ok(())
}

#[test]
fn subtree_allows_exact_cap_and_overflows_on_next_descendant() -> Result<()> {
    const SUBTREE_CAP: usize = 50_000;

    let temp_dir = tempfile::tempdir()?;
    let vault = Vault::open(temp_dir.path(), large_test_config())?;
    let root = seeded_entity_id(1);
    let value = valid_edge_value();

    vault.with_write_txn(|wtxn| {
        for i in 0..SUBTREE_CAP {
            let child = seeded_entity_id(100 + i as u128);
            let key = Store::encode_edge_key(&root, EdgeKind::ChildOf, &child);
            vault.store.edges_in.put(wtxn, &key, &value)?;
        }
        Ok(())
    })?;

    let tree = vault.subtree(&root, 1)?;
    assert_eq!(tree.len(), SUBTREE_CAP);

    let overflow_child = seeded_entity_id(100 + SUBTREE_CAP as u128);
    vault.with_write_txn(|wtxn| {
        let key = Store::encode_edge_key(&root, EdgeKind::ChildOf, &overflow_child);
        vault.store.edges_in.put(wtxn, &key, &value)?;
        Ok(())
    })?;

    let err = vault
        .subtree(&root, 1)
        .expect_err("subtree should fail loud once cap is exceeded");
    assert_matches!(err, Error::IndexOverflow("subtree"));
    Ok(())
}

#[test]
fn ancestors_walks_to_root() -> Result<()> {
    let (_dir, vault) = open_test_vault();

    let root = EntityId::now();
    let mid = EntityId::now();
    let leaf = EntityId::now();

    vault
        .batch()
        .put(&root, ENTITY_TYPE_TASK, test_time_range(1, 1), 2, b"root")
        .put(&mid, ENTITY_TYPE_TASK, test_time_range(3, 3), 4, b"mid")
        .put(&leaf, ENTITY_TYPE_TASK, test_time_range(5, 5), 6, b"leaf")
        .edge(&mid, EdgeKind::ChildOf, &root, 1.0)
        .edge(&leaf, EdgeKind::ChildOf, &mid, 1.0)
        .commit()?;

    let anc = vault.ancestors(&leaf)?;
    assert_eq!(anc, vec![mid, root]);

    // Root has no ancestors
    let root_anc = vault.ancestors(&root)?;
    assert!(root_anc.is_empty());

    Ok(())
}

#[test]
fn cycle_prevention_rejects_self_parent() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let node = EntityId::now();
    vault.put_entity(&node, ENTITY_TYPE_TASK, test_time_range(1, 1), 2, b"self")?;

    assert!(vault.would_create_cycle(&node, &node)?);
    Ok(())
}

#[test]
fn cycle_prevention_detects_ancestor_cycle() -> Result<()> {
    let (_dir, vault) = open_test_vault();

    // A → B → C (ChildOf chain)
    let a = EntityId::now();
    let b = EntityId::now();
    let c = EntityId::now();

    vault
        .batch()
        .put(&a, ENTITY_TYPE_TASK, test_time_range(1, 1), 2, b"a")
        .put(&b, ENTITY_TYPE_TASK, test_time_range(3, 3), 4, b"b")
        .put(&c, ENTITY_TYPE_TASK, test_time_range(5, 5), 6, b"c")
        .edge(&b, EdgeKind::ChildOf, &a, 1.0)
        .edge(&c, EdgeKind::ChildOf, &b, 1.0)
        .commit()?;

    // Making A a child of C would create A → B → C → A
    assert!(vault.would_create_cycle(&a, &c)?);

    // Making D a child of C is fine (D doesn't appear in C's ancestors)
    let d = EntityId::now();
    vault.put_entity(&d, ENTITY_TYPE_TASK, test_time_range(7, 7), 8, b"d")?;
    assert!(!vault.would_create_cycle(&d, &c)?);

    Ok(())
}

#[test]
fn test_deep_ancestor_chain() -> Result<()> {
    let (_dir, vault) = open_test_vault();

    // Build a 200-deep ChildOf chain: node[0] ← node[1] ← ... ← node[200]
    // (each node[i+1] --ChildOf--> node[i])
    const DEPTH: usize = 200;
    let mut nodes = Vec::with_capacity(DEPTH + 1);
    for _ in 0..=DEPTH {
        nodes.push(EntityId::now());
    }

    // Put all entities
    {
        let mut batch = vault.batch();
        for (i, node) in nodes.iter().enumerate() {
            batch = batch.put(
                node,
                ENTITY_TYPE_TASK,
                test_time_range(i as u64, i as u64),
                i as u64 + 1,
                format!("node-{i}").as_bytes(),
            );
        }
        // Build ChildOf edges: node[i+1] --ChildOf--> node[i]
        for [parent, child] in nodes.array_windows::<2>() {
            batch = batch.edge(child, EdgeKind::ChildOf, parent, 1.0);
        }
        batch.commit()?;
    }

    // ancestors(node[200]) should return all 200 ancestors: node[199], ..., node[0]
    let anc = vault.ancestors(&nodes[DEPTH])?;
    assert_eq!(
        anc.len(),
        DEPTH,
        "expected {DEPTH} ancestors, got {}",
        anc.len()
    );
    // Verify order: nearest first (node[199]) to root (node[0])
    for (i, ancestor) in anc.iter().enumerate() {
        assert_eq!(
            *ancestor,
            nodes[DEPTH - 1 - i],
            "ancestor at position {i} should be node[{}]",
            DEPTH - 1 - i
        );
    }

    // would_create_cycle: making node[0] a child of node[200] would create a cycle
    assert!(vault.would_create_cycle(&nodes[0], &nodes[DEPTH])?);

    // would_create_cycle: an unrelated node should not create a cycle
    let unrelated = EntityId::now();
    vault.put_entity(
        &unrelated,
        ENTITY_TYPE_TASK,
        test_time_range(999, 999),
        1000,
        b"unrelated",
    )?;
    assert!(!vault.would_create_cycle(&unrelated, &nodes[DEPTH])?);

    Ok(())
}

#[test]
fn ancestors_and_cycle_checks_overflow_on_depth_cap() -> Result<()> {
    const ANCESTOR_CAP: usize = MAX_ANCESTOR_DEPTH;

    let temp_dir = tempfile::tempdir()?;
    let vault = Vault::open(temp_dir.path(), large_test_config())?;
    let value = valid_edge_value();

    let exact_nodes: Vec<_> = (0..=ANCESTOR_CAP)
        .map(|i| seeded_entity_id(1_000_000 + i as u128))
        .collect();

    vault.with_write_txn(|wtxn| {
        for [parent, child] in exact_nodes.array_windows::<2>() {
            let key = Store::encode_edge_key(child, EdgeKind::ChildOf, parent);
            vault.store.edges_out.put(wtxn, &key, &value)?;
        }
        Ok(())
    })?;

    let ancestors = vault.ancestors(&exact_nodes[ANCESTOR_CAP])?;
    assert_eq!(ancestors.len(), ANCESTOR_CAP);

    let overflow_root = seeded_entity_id(2_000_000);
    vault.with_write_txn(|wtxn| {
        let key = Store::encode_edge_key(&exact_nodes[0], EdgeKind::ChildOf, &overflow_root);
        vault.store.edges_out.put(wtxn, &key, &value)?;
        Ok(())
    })?;

    let anc_err = vault
        .ancestors(&exact_nodes[ANCESTOR_CAP])
        .expect_err("ancestors should fail loud once depth cap is exceeded");
    assert_matches!(anc_err, Error::IndexOverflow("ancestors"));

    let unrelated = seeded_entity_id(3_000_000);
    let cycle_err = vault
        .would_create_cycle(&unrelated, &exact_nodes[ANCESTOR_CAP])
        .expect_err("public cycle check should fail loud once depth cap is exceeded");
    assert_matches!(cycle_err, Error::IndexOverflow("child_of_cycle_check"));

    let batch_err = vault
        .batch()
        .edge_checked(&unrelated, &exact_nodes[ANCESTOR_CAP], 1.0)
        .commit()
        .expect_err("batch cycle check should fail loud once depth cap is exceeded");
    assert_matches!(batch_err, Error::IndexOverflow("child_of_cycle_check"));
    Ok(())
}

#[test]
fn cycle_checks_fail_loud_before_positive_match_beyond_traversal_cap() -> Result<()> {
    const TRAVERSAL_CAP: usize = MAX_CHILD_OF_CYCLE_TRAVERSAL_STEPS;

    let temp_dir = tempfile::tempdir()?;
    let vault = Vault::open(temp_dir.path(), large_test_config())?;
    let value = valid_edge_value();

    let nodes: Vec<_> = (0..=TRAVERSAL_CAP + 1)
        .map(|i| seeded_entity_id(4_000_000 + i as u128))
        .collect();

    vault.with_write_txn(|wtxn| {
        for [parent, child] in nodes.array_windows::<2>() {
            let key = Store::encode_edge_key(child, EdgeKind::ChildOf, parent);
            vault.store.edges_out.put(wtxn, &key, &value)?;
        }
        Ok(())
    })?;

    let public_err = vault
        .would_create_cycle(&nodes[0], &nodes[TRAVERSAL_CAP + 1])
        .expect_err("public cycle check should overflow before reporting a deep positive match");
    assert_matches!(public_err, Error::IndexOverflow("child_of_cycle_check"));

    let batch_err = vault
        .batch()
        .edge_checked(&nodes[0], &nodes[TRAVERSAL_CAP + 1], 1.0)
        .commit()
        .expect_err("batch cycle check should overflow before reporting a deep positive match");
    assert_matches!(batch_err, Error::IndexOverflow("child_of_cycle_check"));
    Ok(())
}

#[test]
fn get_entity_type_returns_correct_type() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let tl = EntityId::now();
    let tk = EntityId::now();

    vault
        .batch()
        .put(&tl, ENTITY_TYPE_TASK_LIST, test_time_range(1, 1), 2, b"tl")
        .put(&tk, ENTITY_TYPE_TASK, test_time_range(3, 3), 4, b"tk")
        .commit()?;

    assert_eq!(vault.get_entity_type(&tl)?, Some(ENTITY_TYPE_TASK_LIST));
    assert_eq!(vault.get_entity_type(&tk)?, Some(ENTITY_TYPE_TASK));
    assert_eq!(vault.get_entity_type(&EntityId::now())?, None);
    Ok(())
}

/// ONE-1100 AC1 — `child_of` is NEVER traversed by PPR (contract
/// `lambda: null`, "Not traversed."): a deep ChildOf chain carries zero
/// propagated mass from any seed, while the tree remains reachable through
/// the dedicated `subtree` / `ancestors` read APIs.
#[test]
fn child_of_chain_carries_no_ppr_mass() -> Result<()> {
    let (_dir, vault) = open_test_vault();

    // Build a 5-level deep ChildOf chain: e → d → c → b → a (child → parent).
    let a = EntityId::now();
    let b = EntityId::now();
    let c = EntityId::now();
    let d = EntityId::now();
    let e = EntityId::now();

    vault
        .batch()
        .put(&a, ENTITY_TYPE_TASK, test_time_range(1, 1), 2, b"a")
        .put(&b, ENTITY_TYPE_TASK, test_time_range(3, 3), 4, b"b")
        .put(&c, ENTITY_TYPE_TASK, test_time_range(5, 5), 6, b"c")
        .put(&d, ENTITY_TYPE_TASK, test_time_range(7, 7), 8, b"d")
        .put(&e, ENTITY_TYPE_TASK, test_time_range(9, 9), 10, b"e")
        .edge(&b, EdgeKind::ChildOf, &a, 1.0)
        .edge(&c, EdgeKind::ChildOf, &b, 1.0)
        .edge(&d, EdgeKind::ChildOf, &c, 1.0)
        .edge(&e, EdgeKind::ChildOf, &d, 1.0)
        .commit()?;

    // PPR from e must reach NOTHING: the only edges are ChildOf, which carry
    // no PPR weight regardless of the stored 1.0 weight bytes.
    {
        let rtxn = vault.store.env.read_txn()?;
        let scores = ppr::ppr_compute(&vault.store, &rtxn, &[e], 6, 0.15)?;
        assert_eq!(
            scores.len(),
            1,
            "ChildOf must not propagate; only the seed may be scored"
        );
        assert_eq!(scores[0].id, e);
    }

    // The tree APIs — not PPR — are the ChildOf read path: the full ancestor
    // chain stays reachable.
    let ancestors = vault.ancestors(&e)?;
    assert_eq!(ancestors, vec![d, c, b, a]);

    // PartOf comparison: its traversal is hop-capped at 2, so p1 (4 hops from
    // p5) is blocked.
    let p1 = EntityId::now();
    let p2 = EntityId::now();
    let p3 = EntityId::now();
    let p4 = EntityId::now();
    let p5 = EntityId::now();

    vault
        .batch()
        .put(&p1, 9, test_time_range(1, 1), 2, b"p1")
        .put(&p2, 9, test_time_range(3, 3), 4, b"p2")
        .put(&p3, 9, test_time_range(5, 5), 6, b"p3")
        .put(&p4, 9, test_time_range(7, 7), 8, b"p4")
        .put(&p5, 9, test_time_range(9, 9), 10, b"p5")
        .edge(&p2, EdgeKind::PartOf, &p1, 1.0)
        .edge(&p3, EdgeKind::PartOf, &p2, 1.0)
        .edge(&p4, EdgeKind::PartOf, &p3, 1.0)
        .edge(&p5, EdgeKind::PartOf, &p4, 1.0)
        .commit()?;

    {
        let rtxn = vault.store.env.read_txn()?;
        let part_of_scores = ppr::ppr_compute(&vault.store, &rtxn, &[p5], 6, 0.15)?;
        let p1_score = part_of_scores
            .iter()
            .find(|s| s.id == p1)
            .map(|s| s.score)
            .unwrap_or(0.0);
        // p1 is 4 PartOf hops from p5 — should be blocked (only 2 PartOf hops allowed)
        assert!(
            p1_score < 1e-6,
            "PartOf should block at 3rd hop, but p1 got score={p1_score}"
        );
    }

    Ok(())
}

/// ONE-1100 AC1 — a mixed path whose first edge is `child_of` carries zero
/// PPR mass past that edge: ChildOf is never traversed, so the PartOf tail
/// of the path is unreachable from the task seed.
#[test]
fn mixed_path_through_child_of_carries_no_ppr_mass() -> Result<()> {
    let (_dir, vault) = open_test_vault();

    // place1 --PartOf--> place2 --PartOf--> place3 --ChildOf--> task
    let place1 = EntityId::now();
    let place2 = EntityId::now();
    let place3 = EntityId::now();
    let task = EntityId::now();

    vault
        .batch()
        .put(&place1, 9, test_time_range(1, 1), 2, b"p1") // Place
        .put(&place2, 9, test_time_range(3, 3), 4, b"p2")
        .put(&place3, 9, test_time_range(5, 5), 6, b"p3")
        .put(&task, ENTITY_TYPE_TASK, test_time_range(7, 7), 8, b"task")
        .edge(&place2, EdgeKind::PartOf, &place1, 1.0)
        .edge(&place3, EdgeKind::PartOf, &place2, 1.0)
        .edge(&task, EdgeKind::ChildOf, &place3, 1.0)
        .commit()?;

    let rtxn = vault.store.env.read_txn()?;
    let scores = ppr::ppr_compute(&vault.store, &rtxn, &[task], 6, 0.15)?;

    // The only edge at the seed is ChildOf (never traversed), so no node
    // beyond the seed may receive mass — including the PartOf tail.
    assert_eq!(
        scores.len(),
        1,
        "ChildOf must block the entire mixed path; only the seed may be scored"
    );
    assert_eq!(scores[0].id, task);

    Ok(())
}

#[test]
fn generic_child_of_writes_reject_cycles() -> Result<()> {
    let (_dir, vault) = open_test_vault();

    let a = EntityId::now();
    let b = EntityId::now();
    let c = EntityId::now();

    vault
        .batch()
        .put(&a, ENTITY_TYPE_TASK, test_time_range(1, 1), 2, b"a")
        .put(&b, ENTITY_TYPE_TASK, test_time_range(3, 3), 4, b"b")
        .put(&c, ENTITY_TYPE_TASK, test_time_range(5, 5), 6, b"c")
        .edge(&b, EdgeKind::ChildOf, &a, 1.0)
        .edge(&c, EdgeKind::ChildOf, &b, 1.0)
        .commit()?;

    let err = vault
        .put_edge(&a, EdgeKind::ChildOf, &c, 1.0)
        .expect_err("generic ChildOf write should reject cycles");
    assert_matches!(err, Error::CycleDetected);
    assert!(!vault.edge_exists(&a, EdgeKind::ChildOf, &c)?);
    Ok(())
}

#[test]
fn generic_child_of_writes_reject_second_parent() -> Result<()> {
    let (_dir, vault) = open_test_vault();

    let child = EntityId::now();
    let parent_a = EntityId::now();
    let parent_b = EntityId::now();

    vault
        .batch()
        .put(&child, ENTITY_TYPE_TASK, test_time_range(1, 1), 2, b"child")
        .put(&parent_a, ENTITY_TYPE_TASK, test_time_range(3, 3), 4, b"pa")
        .put(&parent_b, ENTITY_TYPE_TASK, test_time_range(5, 5), 6, b"pb")
        .edge(&child, EdgeKind::ChildOf, &parent_a, 1.0)
        .commit()?;

    let err = vault
        .batch()
        .edge(&child, EdgeKind::ChildOf, &parent_b, 1.0)
        .commit()
        .expect_err("generic ChildOf write should reject second parent");
    assert_matches!(err, Error::ChildOfCardinality);
    assert!(!vault.edge_exists(&child, EdgeKind::ChildOf, &parent_b)?);

    vault.put_edge(&child, EdgeKind::ChildOf, &parent_a, 0.5)?;
    let parents = vault.targets(&child, EdgeKind::ChildOf, None)?;
    assert_eq!(parents, vec![parent_a]);
    Ok(())
}

// Shared helper for both `batch()` and `batch_in()` reparent variants.
// `apply_reparent` is a closure that, given the vault and the three entity ids,
// performs the reparent operation (add edge to parent_b + delete edge to parent_a)
// via the API surface under test.
fn assert_reparent_order_independent<F>(apply_reparent: F) -> Result<()>
where
    F: FnOnce(&Vault, EntityId, EntityId, EntityId) -> Result<()>,
{
    let (_dir, vault) = open_test_vault();

    let child = EntityId::now();
    let parent_a = EntityId::now();
    let parent_b = EntityId::now();

    vault
        .batch()
        .put(&child, ENTITY_TYPE_TASK, test_time_range(1, 1), 2, b"child")
        .put(&parent_a, ENTITY_TYPE_TASK, test_time_range(3, 3), 4, b"pa")
        .put(&parent_b, ENTITY_TYPE_TASK, test_time_range(5, 5), 6, b"pb")
        .edge(&child, EdgeKind::ChildOf, &parent_a, 1.0)
        .commit()?;

    apply_reparent(&vault, child, parent_a, parent_b)?;

    let parents = vault.targets(&child, EdgeKind::ChildOf, None)?;
    assert_eq!(parents, vec![parent_b]);
    Ok(())
}

#[test]
fn generic_child_of_reparent_is_order_independent() -> Result<()> {
    assert_reparent_order_independent(|vault, child, parent_a, parent_b| {
        vault
            .batch()
            .edge(&child, EdgeKind::ChildOf, &parent_b, 1.0)
            .delete_edge(&child, EdgeKind::ChildOf, &parent_a)
            .commit()
    })
}

#[test]
fn txn_batch_child_of_reparent_is_order_independent() -> Result<()> {
    assert_reparent_order_independent(|vault, child, parent_a, parent_b| {
        vault.with_write_txn(|wtxn| {
            vault
                .batch_in()
                .edge(&child, EdgeKind::ChildOf, &parent_b, 1.0)
                .delete_edge(&child, EdgeKind::ChildOf, &parent_a)
                .apply(wtxn)
        })
    })
}

#[test]
fn child_of_batch_allows_add_delete_then_reverse_edge() -> Result<()> {
    let (_dir, vault) = open_test_vault();

    let a = EntityId::now();
    let b = EntityId::now();

    vault
        .batch()
        .put(&a, ENTITY_TYPE_TASK, test_time_range(1, 1), 2, b"a")
        .put(&b, ENTITY_TYPE_TASK, test_time_range(3, 3), 4, b"b")
        .edge(&a, EdgeKind::ChildOf, &b, 1.0)
        .delete_edge(&a, EdgeKind::ChildOf, &b)
        .edge(&b, EdgeKind::ChildOf, &a, 1.0)
        .commit()?;

    assert!(!vault.edge_exists(&a, EdgeKind::ChildOf, &b)?);
    assert!(vault.edge_exists(&b, EdgeKind::ChildOf, &a)?);
    Ok(())
}

#[test]
fn edge_checked_detects_cycle_atomically() -> Result<()> {
    let (_dir, vault) = open_test_vault();

    // Build: a → b → c (ChildOf chain)
    let a = EntityId::now();
    let b = EntityId::now();
    let c = EntityId::now();

    vault
        .batch()
        .put(&a, ENTITY_TYPE_TASK, test_time_range(1, 1), 2, b"a")
        .put(&b, ENTITY_TYPE_TASK, test_time_range(3, 3), 4, b"b")
        .put(&c, ENTITY_TYPE_TASK, test_time_range(5, 5), 6, b"c")
        .edge(&b, EdgeKind::ChildOf, &a, 1.0)
        .edge(&c, EdgeKind::ChildOf, &b, 1.0)
        .commit()?;

    // Try to make a a child of c — would create cycle a→b→c→a
    let result = vault.batch().edge_checked(&a, &c, 1.0).commit();
    assert!(
        matches!(result, Err(Error::CycleDetected)),
        "expected CycleDetected, got {result:?}"
    );

    // Verify the rejected edge was not written
    assert!(
        !vault.edge_exists(&a, EdgeKind::ChildOf, &c)?,
        "cyclic edge should not have been persisted"
    );

    // Non-cyclic edge should succeed
    let d = EntityId::now();
    vault
        .batch()
        .put(&d, ENTITY_TYPE_TASK, test_time_range(7, 7), 8, b"d")
        .edge_checked(&d, &c, 1.0)
        .commit()?;

    // Verify d is a child of c
    let children = vault.sources(&c, EdgeKind::ChildOf, None)?;
    assert!(children.contains(&d));

    Ok(())
}

#[test]
fn edge_checked_rejects_self_cycle() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let node = EntityId::now();

    vault
        .batch()
        .put(&node, ENTITY_TYPE_TASK, test_time_range(1, 1), 2, b"self")
        .commit()?;

    let result = vault.batch().edge_checked(&node, &node, 1.0).commit();
    assert!(
        matches!(result, Err(Error::CycleDetected)),
        "self-cycle should be rejected, got {result:?}"
    );
    assert!(
        !vault.edge_exists(&node, EdgeKind::ChildOf, &node)?,
        "self-cycle edge should not have been persisted"
    );

    Ok(())
}

#[test]
fn subtree_excludes_root() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let root = EntityId::now();
    let child = EntityId::now();

    vault
        .batch()
        .put(&root, ENTITY_TYPE_TASK, test_time_range(1, 1), 2, b"root")
        .put(&child, ENTITY_TYPE_TASK, test_time_range(3, 3), 4, b"child")
        .edge(&child, EdgeKind::ChildOf, &root, 1.0)
        .commit()?;

    let tree = vault.subtree(&root, 10)?;
    assert_eq!(tree.len(), 1);
    assert_eq!(tree[0].0, child);
    assert!(
        !tree.iter().any(|(id, _)| *id == root),
        "root should not appear in its own subtree"
    );

    Ok(())
}

#[test]
fn learned_at_accessor() {
    let temp = tempfile::tempdir().unwrap();
    let vault = Vault::open(temp.path(), test_config()).unwrap();
    let id = EntityId::now();
    let learned = 1_772_000_000u64;

    vault
        .put_entity(
            &id,
            1,
            TimeRange {
                start: learned,
                end: learned,
            },
            learned,
            b"first",
        )
        .unwrap();

    assert_eq!(vault.get_learned_at(&id).unwrap(), learned);
}

#[test]
fn entity_exists_and_edge_exists() {
    let temp = tempfile::tempdir().unwrap();
    let vault = Vault::open(temp.path(), test_config()).unwrap();
    let id = EntityId::now();
    let other = EntityId::now();

    assert!(!vault.entity_exists(&id).unwrap());

    vault
        .put_entity(&id, 1, TimeRange { start: 1, end: 1 }, 1, b"exists")
        .unwrap();
    vault
        .put_entity(&other, 1, TimeRange { start: 1, end: 1 }, 1, b"other")
        .unwrap();

    assert!(vault.entity_exists(&id).unwrap());
    assert!(!vault.edge_exists(&id, EdgeKind::Mentions, &other).unwrap());

    vault
        .put_edge(&id, EdgeKind::Mentions, &other, 0.5)
        .unwrap();
    assert!(vault.edge_exists(&id, EdgeKind::Mentions, &other).unwrap());
}

#[test]
fn entities_in_learned_range() {
    let temp = tempfile::tempdir().unwrap();
    let vault = Vault::open(temp.path(), test_config()).unwrap();

    let id1 = EntityId::now();
    let id2 = EntityId::now();
    let id3 = EntityId::now();

    vault
        .put_entity(
            &id1,
            1,
            TimeRange {
                start: 100,
                end: 100,
            },
            100,
            b"a",
        )
        .unwrap();
    vault
        .put_entity(
            &id2,
            1,
            TimeRange {
                start: 200,
                end: 200,
            },
            200,
            b"b",
        )
        .unwrap();
    vault
        .put_entity(
            &id3,
            1,
            TimeRange {
                start: 300,
                end: 300,
            },
            300,
            b"c",
        )
        .unwrap();

    let range = vault.entities_in_learned_range(100, 300).unwrap();
    assert_eq!(range.len(), 2);
    assert!(range.contains(&id1));
    assert!(range.contains(&id2));
    assert!(!range.contains(&id3));
}

#[test]
fn with_write_txn_and_batch_in() {
    let temp = tempfile::tempdir().unwrap();
    let vault = Vault::open(temp.path(), test_config()).unwrap();
    let id = EntityId::now();

    vault
        .with_write_txn(|wtxn| {
            vault
                .batch_in()
                .put(&id, 1, TimeRange { start: 1, end: 1 }, 1, b"atomic")
                .apply(wtxn)?;
            Ok(())
        })
        .unwrap();

    assert_eq!(vault.get(&id).unwrap().unwrap(), b"atomic");
}

#[test]
fn batch_edge_with_created_at() {
    let temp = tempfile::tempdir().unwrap();
    let vault = Vault::open(temp.path(), test_config()).unwrap();
    let src = EntityId::now();
    let tgt = EntityId::now();

    vault
        .batch()
        .put(&src, 1, TimeRange { start: 1, end: 1 }, 1, b"src")
        .put(&tgt, 1, TimeRange { start: 1, end: 1 }, 1, b"tgt")
        .edge_with_created_at(&src, EdgeKind::Mentions, &tgt, 0.8, 99999)
        .commit()
        .unwrap();

    let edges = vault.edges_out(&src).unwrap();
    assert_eq!(edges.len(), 1);
    assert_eq!(edges[0].created_at, 99999);
    assert!((edges[0].weight - 0.8).abs() < f32::EPSILON);
}

// ═══════════════════════════════════════════════════════════════════════
// ONE-1104 — CLAIM body ABI + typed Claim API spec tests
// (D11 pinned keys · D17 predicate gate · D18 fail-closed type-0 writes)
// ═══════════════════════════════════════════════════════════════════════

/// Asserts that no entity-record or index row anywhere references `id`.
/// Used by every negative claim test to prove a rejected write left nothing.
fn assert_no_entity_state(vault: &Vault, id: &EntityId) -> Result<()> {
    let rtxn = vault.store.env.read_txn()?;
    assert!(
        vault.store.entities.get(&rtxn, id.as_bytes())?.is_none(),
        "entities row leaked for rejected write"
    );
    // Entity-keyed direct probe (ONE-1152): `short_ids_reverse` is the
    // entity-keyed table per the pinned 25-DB manifest (key entity_id ->
    // short_id ‖ content_hash). The pre-fix probe read the FORWARD
    // `short_ids` table by entity bytes — a guaranteed miss against its
    // `(short_id bytes ‖ content_hash u8)` key layout, i.e. a vacuous
    // assertion.
    assert!(
        vault
            .store
            .short_ids_reverse
            .get(&rtxn, id.as_bytes())?
            .is_none(),
        "short_ids_reverse row leaked for rejected write"
    );
    let scans = [
        ("type_index", &vault.store.type_index),
        (
            "temporal_occurred_start",
            &vault.store.temporal_occurred_start,
        ),
        ("temporal_occurred_end", &vault.store.temporal_occurred_end),
        ("temporal_learned", &vault.store.temporal_learned),
        (
            "temporal_long_intervals",
            &vault.store.temporal_long_intervals,
        ),
        // ONE-1152: forward rows carry the entity id in the VALUE — without
        // this scan a leaked forward row escaped the oracle entirely.
        ("short_ids", &vault.store.short_ids),
        ("short_ids_reverse", &vault.store.short_ids_reverse),
        ("edges_out", &vault.store.edges_out),
        ("edges_in", &vault.store.edges_in),
    ];
    for (name, db) in scans {
        for entry in db.iter(&rtxn)? {
            let (key, value) = entry?;
            assert!(
                !slice_contains(key, id.as_bytes()) && !slice_contains(value, id.as_bytes()),
                "{name} row references rejected entity"
            );
        }
    }
    Ok(())
}

fn slice_contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

/// ONE-1152 (a) oracle self-test: a leaked FORWARD short-id row — keyed
/// `(short_id bytes ‖ content_hash u8)` with the entity id in the VALUE
/// (pinned 25-DB manifest direction, ARCH-0019) — must trip
/// [`assert_no_entity_state`]. Pre-fix, the oracle probed `short_ids` BY
/// ENTITY KEY (a guaranteed miss against the forward layout) and never
/// scanned forward values, so this exact plant escaped silently.
#[test]
#[should_panic(expected = "short_ids row references rejected entity")]
fn assert_no_entity_state_catches_leaked_forward_short_id_row() {
    let temp = tempfile::tempdir().unwrap();
    let vault = Vault::open(temp.path(), test_config()).unwrap();
    let id = EntityId::now();

    // Forward row: key = ASCII short id ‖ content-hash byte, value = id.
    let mut forward_key = b"cl1".to_vec();
    forward_key.push(0x42);
    let mut wtxn = vault.store.env.write_txn().unwrap();
    vault
        .store
        .short_ids
        .put(&mut wtxn, &forward_key, id.as_bytes())
        .unwrap();
    wtxn.commit().unwrap();

    assert_no_entity_state(&vault, &id).unwrap();
}

/// Schema-agnostic short-id lookup: scans BOTH short-id DBs raw and accepts
/// whichever row links `id` to an ASCII `<prefix><counter>` short id.
///
/// WHY (cross-branch schema compat, ONE-1102): the parallel ONE-1102 branch
/// swaps the short-id table direction per the pinned 25-DB manifest
/// (`short_ids`: key short_id bytes + content_hash u8 -> entity_id;
/// `short_ids_reverse`: key entity_id -> short_id + hash), while this branch
/// still carries the pre-1102 orientation (`short_ids`: entity_id ->
/// short_id + hash; `short_ids_reverse`: short_id -> entity_id). Reading one
/// fixed layout here would break this test on whichever side merges second,
/// so callers' prefix assertions stay green on this branch standalone AND
/// after ONE-1102 lands.
fn find_short_id_any_schema(vault: &Vault, id: &EntityId) -> Result<Option<String>> {
    // A short id is a two-letter lowercase type prefix plus a decimal
    // counter. The strict format check disambiguates the 1-byte content
    // hash riding next to the short id in one of the two orientations.
    fn parse_short_id(bytes: &[u8]) -> Option<String> {
        if bytes.len() < 3 {
            return None;
        }
        let (prefix, counter) = bytes.split_at(2);
        let well_formed =
            prefix.iter().all(u8::is_ascii_lowercase) && counter.iter().all(u8::is_ascii_digit);
        if !well_formed {
            return None;
        }
        str::from_utf8(bytes).ok().map(str::to_owned)
    }

    // Candidate bytes are either the bare short id or short id + hash u8.
    fn parse_with_optional_hash(bytes: &[u8]) -> Option<String> {
        parse_short_id(bytes).or_else(|| {
            bytes
                .split_last()
                .and_then(|(_hash, head)| parse_short_id(head))
        })
    }

    let rtxn = vault.store.env.read_txn()?;
    for db in [&vault.store.short_ids, &vault.store.short_ids_reverse] {
        for entry in db.iter(&rtxn)? {
            let (key, value) = entry?;
            // Orientation 1: entity_id -> short_id (+ hash).
            if key == id.as_bytes()
                && let Some(short_id) = parse_with_optional_hash(value)
            {
                return Ok(Some(short_id));
            }
            // Orientation 2: short_id (+ hash) -> entity_id.
            if value == id.as_bytes()
                && let Some(short_id) = parse_with_optional_hash(key)
            {
                return Ok(Some(short_id));
            }
        }
    }
    Ok(None)
}

fn rmpv_map_bytes(entries: &[(rmpv::Value, rmpv::Value)]) -> Vec<u8> {
    let mut out = Vec::new();
    rmpv::encode::write_value(&mut out, &rmpv::Value::Map(entries.to_vec()))
        .expect("encode msgpack map");
    out
}

/// Structurally-VALID `edge.provenance` ClaimBody for door tests: a real
/// value record + the engine-owned actor-class evidence map. Since ONE-1159
/// the write chokepoint validates provenance STRUCTURE (value record +
/// persisted actor_class), so reserved-door tests can no longer carry an
/// opaque junk `val`.
fn valid_provenance_claim_body(actor: EntityId, source: EntityId, target: EntityId) -> ClaimBody {
    let mut body = ClaimBody::new(
        "edge.provenance",
        ClaimSubject::Edge {
            source,
            kind: EdgeKind::Mentions,
            target,
        },
        crate::provenance::encode_edge_provenance_value(
            &crate::provenance::EdgeProvenanceClaimBody::new(
                actor,
                0.9,
                crate::provenance::SupersessionStatus::Confirmed,
            ),
        ),
        0.9,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    );
    body.evidence = Some(crate::provenance::encode_actor_class_evidence(
        EdgeActorClass::Human,
    ));
    body
}

/// Baseline VALID claim-body map entries (the six required fields).
fn base_claim_entries(pred: &str, subj: Vec<u8>) -> Vec<(rmpv::Value, rmpv::Value)> {
    vec![
        ("pred".into(), pred.into()),
        ("val".into(), "x".into()),
        ("conf".into(), rmpv::Value::F32(0.5)),
        ("subj".into(), rmpv::Value::Binary(subj)),
        ("appr".into(), "auto".into()),
        ("life".into(), "active".into()),
    ]
}

fn entries_without(
    base: &[(rmpv::Value, rmpv::Value)],
    key: &str,
) -> Vec<(rmpv::Value, rmpv::Value)> {
    base.iter()
        .filter(|(k, _)| k.as_str() != Some(key))
        .cloned()
        .collect()
}

fn entries_replacing(
    base: &[(rmpv::Value, rmpv::Value)],
    key: &str,
    value: rmpv::Value,
) -> Vec<(rmpv::Value, rmpv::Value)> {
    base.iter()
        .map(|(k, v)| {
            if k.as_str() == Some(key) {
                (k.clone(), value.clone())
            } else {
                (k.clone(), v.clone())
            }
        })
        .collect()
}

#[test]
fn claim_body_keys_pin_d11_vocabulary() {
    // The pinned ON-DISK key set, literal (D11). A renamed, reordered, or
    // re-cased vocabulary must fail here.
    assert_eq!(
        CLAIM_BODY_KEYS,
        [
            "pred", "val", "conf", "sal", "evid", "from", "to", "src", "world", "subj", "scope",
            "appr", "life", "stale",
        ]
    );
    // fusion.rs consumes the SAME constants — pinned to the short keys.
    assert_eq!(crate::claim::KEY_SAL, "sal");
    assert_eq!(crate::claim::KEY_CONF, "conf");
    // Context-pack profiles are prefixes of the pinned set.
    assert_eq!(crate::claim::CLAIM_FIELDS_MINIMAL, ["pred", "val"]);
    assert_eq!(
        crate::claim::CLAIM_FIELDS_STANDARD,
        ["pred", "val", "conf", "sal", "evid"]
    );
    assert_eq!(
        crate::claim::CLAIM_FIELDS_FULL,
        [
            "pred", "val", "conf", "sal", "evid", "from", "to", "src", "world", "subj", "scope"
        ]
    );
}

#[test]
fn stored_claim_body_serves_fusion_boosts_and_context_pack_profiles() -> Result<()> {
    // ONE body written through put_claim must BOTH fire the fusion boosts
    // (sal/conf short keys) AND project through the context-pack CLAIM
    // field profiles — the pre-fix engine read "salience"/"confidence" in
    // fusion and "sal"/"conf" in profiles, so no single body could do both.
    let (_dir, vault) = open_test_vault();
    let subject = EntityId::now();
    vault.put_entity(&subject, 4, test_time_range(1, 1), 1, b"person")?;

    let claim = EntityId::now();
    let mut body = ClaimBody::new(
        "preference.food",
        ClaimSubject::Entity(subject),
        rmpv::Value::from("matcha"),
        0.8,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    );
    body.salience = Some(0.5);
    vault.put_claim(&claim, &body, test_time_range(10, 10), 11)?;
    vault
        .batch()
        .text(&claim, &[("body", "matcha preference")])
        .commit()?;

    let baseline = vault.query().search_text("matcha", 10).run()?;
    assert_eq!(baseline.len(), 1);
    let base_score = baseline[0].score;

    // boost_salience alone: score × (1 + sal) = × 1.5. A key-swapped
    // implementation (reading conf) would yield × 1.8 and fail.
    let sal_boosted = vault
        .query()
        .search_text("matcha", 10)
        .boost_salience()
        .run()?;
    assert_eq!(sal_boosted.len(), 1);
    let expected_sal = base_score * 1.5;
    assert!(
        (sal_boosted[0].score - expected_sal).abs() < 1e-5,
        "salience boost drifted: got {}, expected {expected_sal}",
        sal_boosted[0].score
    );

    // boost_confidence alone: score × (0.5 + 0.5 × conf) = × 0.9. A
    // key-swapped implementation (reading sal) would yield × 0.75 and fail.
    let conf_boosted = vault
        .query()
        .search_text("matcha", 10)
        .boost_confidence()
        .run()?;
    assert_eq!(conf_boosted.len(), 1);
    let expected_conf = base_score * 0.9;
    assert!(
        (conf_boosted[0].score - expected_conf).abs() < 1e-5,
        "confidence boost drifted: got {}, expected {expected_conf}",
        conf_boosted[0].score
    );

    // The SAME stored body projects through the CLAIM Full profile.
    let full = vault
        .context_pack()
        .search_text("matcha", 10)
        .field_profile(FieldProfile::Full)
        .format(PackFormat::Json)
        .run_serialized()?;
    let full = String::from_utf8(full).map_err(|_| Error::InvalidKey)?;
    assert!(full.contains("\"pred\""), "Full profile must surface pred");
    assert!(full.contains("preference.food"));
    assert!(full.contains("\"conf\""), "Full profile must surface conf");
    assert!(full.contains("\"sal\""), "Full profile must surface sal");

    // Minimal profile allowlists pred/val only.
    let minimal = vault
        .context_pack()
        .search_text("matcha", 10)
        .field_profile(FieldProfile::Minimal)
        .format(PackFormat::Json)
        .run_serialized()?;
    let minimal = String::from_utf8(minimal).map_err(|_| Error::InvalidKey)?;
    assert!(minimal.contains("\"pred\""));
    assert!(!minimal.contains("\"sal\""), "Minimal must not surface sal");
    assert!(
        !minimal.contains("\"conf\""),
        "Minimal must not surface conf"
    );
    Ok(())
}

#[test]
fn put_claim_round_trip_and_pinned_on_disk_bytes() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let subject = EntityId::now();
    vault.put_entity(&subject, 4, test_time_range(1, 1), 1, b"person")?;

    let claim = EntityId::now();
    let mut body = ClaimBody::new(
        "profile.lives_in",
        ClaimSubject::Entity(subject),
        rmpv::Value::from("tokyo"),
        0.75,
        ClaimApprovalStatus::Proposed,
        ClaimLifecycleStatus::Active,
    );
    body.salience = Some(0.25);
    body.evidence = Some(rmpv::Value::Array(vec!["tn1".into()]));
    body.valid_from = Some(100);
    body.valid_to = Some(200);
    body.source = Some(ClaimSource::UserStated);
    let world_id = EntityId::from_bytes([0x5A; 16])?;
    body.world = Some(world_id);
    body.scope = Some("rel1".into());
    body.stale = true;
    vault.put_claim(&claim, &body, test_time_range(100, 200), 300)?;

    // Pin the EXACT on-disk bytes: pinned short keys, canonical order. The
    // expected map is built with LITERAL key strings so an encoder writing
    // camelCase keys, long names, or a different order fails byte equality.
    let raw = vault.get_raw(&claim)?.ok_or(Error::EntityNotFound)?;
    let expected = rmpv_map_bytes(&[
        ("pred".into(), "profile.lives_in".into()),
        ("val".into(), "tokyo".into()),
        ("conf".into(), rmpv::Value::F32(0.75)),
        ("sal".into(), rmpv::Value::F32(0.25)),
        ("evid".into(), rmpv::Value::Array(vec!["tn1".into()])),
        ("from".into(), rmpv::Value::from(100_u64)),
        ("to".into(), rmpv::Value::from(200_u64)),
        ("src".into(), "user_stated".into()),
        (
            "world".into(),
            rmpv::Value::Binary(world_id.as_bytes().to_vec()),
        ),
        (
            "subj".into(),
            rmpv::Value::Binary(subject.as_bytes().to_vec()),
        ),
        ("scope".into(), "rel1".into()),
        ("appr".into(), "proposed".into()),
        ("life".into(), "active".into()),
        ("stale".into(), rmpv::Value::Boolean(true)),
    ]);
    assert_eq!(
        &raw[ENTITY_METADATA_HEADER_LEN..],
        expected.as_slice(),
        "on-disk claim body bytes drifted from the pinned D11 ABI"
    );

    let read = vault.get_claim(&claim)?.expect("claim must decode");
    assert_eq!(read, body);

    // Minimal claim: optionals absent, stale defaults to false on decode.
    let minimal_id = EntityId::now();
    let minimal = ClaimBody::new(
        "profile.name",
        ClaimSubject::Entity(subject),
        rmpv::Value::from("Alice"),
        1.0,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    );
    vault.put_claim(&minimal_id, &minimal, test_time_range(1, 1), 2)?;
    let read = vault.get_claim(&minimal_id)?.expect("minimal claim");
    assert!(!read.stale, "absent stale must decode to false");
    assert_eq!(read.salience, None);
    assert_eq!(read.source, None);
    assert_eq!(read.valid_from, None);
    assert_eq!(read.valid_to, None);

    // The minimal body must NOT contain a stale key on disk (default elided).
    let raw = vault.get_raw(&minimal_id)?.ok_or(Error::EntityNotFound)?;
    assert!(
        !slice_contains(&raw[ENTITY_METADATA_HEADER_LEN..], b"stale"),
        "stale=false must be elided from the stored body"
    );

    // Claims carry the pinned 'cl' short-id prefix. The lookup is
    // intentionally schema-agnostic (see find_short_id_any_schema): the
    // parallel ONE-1102 branch flips the short_ids key direction per the
    // pinned manifest, and this assertion must hold on this branch
    // standalone AND after ONE-1102 merges.
    let short_id = find_short_id_any_schema(&vault, &claim)?
        .expect("claim short id missing from both short-id DBs");
    assert!(
        short_id.starts_with("cl"),
        "CLAIM short-id prefix must be 'cl', got {short_id}"
    );
    let counter = &short_id[2..];
    assert!(
        !counter.is_empty() && counter.bytes().all(|b| b.is_ascii_digit()),
        "CLAIM short id must be 'cl' + decimal counter, got {short_id}"
    );
    Ok(())
}

#[test]
fn put_claim_writes_claim_of_edge_atomically() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let subject = EntityId::now();
    vault.put_entity(&subject, 4, test_time_range(1, 1), 1, b"person")?;

    let claim = EntityId::now();
    let body = ClaimBody::new(
        "profile.name",
        ClaimSubject::Entity(subject),
        rmpv::Value::from("Alice"),
        0.9,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    );
    vault.put_claim(&claim, &body, test_time_range(1, 1), 2)?;

    // claim_of (u8 = 5) Claim → subject, structural 12-byte value, present
    // in BOTH edge directions with identical bytes.
    let key_out = Store::encode_edge_key(&claim, EdgeKind::ClaimOf, &subject);
    let key_in = Store::encode_edge_key(&subject, EdgeKind::ClaimOf, &claim);
    assert_eq!(key_out[16], 5, "claim_of discriminant must be 5");
    let rtxn = vault.store.env.read_txn()?;
    let out_value = vault
        .store
        .edges_out
        .get(&rtxn, &key_out)?
        .expect("claim_of edge missing from edges_out");
    let in_value = vault
        .store
        .edges_in
        .get(&rtxn, &key_in)?
        .expect("claim_of edge missing from edges_in");
    assert_eq!(out_value.len(), 12, "claim_of must be structural 12 B");
    assert_eq!(out_value, in_value);
    // Weight f32 LE @0 = the contract's pinned claim_of pprWeight 1.0
    // (contracts.ts edgeKinds u8 = 5).
    assert_eq!(&out_value[0..4], &1.0_f32.to_le_bytes());
    drop(rtxn);

    // claims_for_subject = sources(ClaimOf, Some(0)).
    assert_eq!(vault.claims_for_subject(&subject)?, vec![claim]);

    // Nonexistent subject → typed reject, NOTHING written (no entity, no
    // claim_of rows, no index rows).
    let ghost = seeded_entity_id(0xDEAD);
    let orphan = EntityId::now();
    let body = ClaimBody::new(
        "profile.name",
        ClaimSubject::Entity(ghost),
        rmpv::Value::from("Bob"),
        0.9,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    );
    let err = vault
        .put_claim(&orphan, &body, test_time_range(1, 1), 2)
        .expect_err("nonexistent subject must be rejected");
    assert_eq!(err.kind(), ErrorKind::EntityNotFound);
    assert_no_entity_state(&vault, &orphan)?;
    assert!(vault.claims_for_subject(&ghost)?.is_empty());
    Ok(())
}

#[test]
fn put_claim_edge_ref_subject_validates_shape_without_claim_of() -> Result<()> {
    // An EdgeRef subject is shape-validated and stored, but claim_of wiring
    // for edge subjects belongs to the provenance path — no edge is written.
    let (_dir, vault) = open_test_vault();
    let a = EntityId::now();
    let b = EntityId::now();
    vault.put_entity(&a, 4, test_time_range(1, 1), 1, b"a")?;
    vault.put_entity(&b, 4, test_time_range(1, 1), 1, b"b")?;

    let claim = EntityId::now();
    let body = ClaimBody::new(
        "graph.observation",
        ClaimSubject::Edge {
            source: a,
            kind: EdgeKind::Supports,
            target: b,
        },
        rmpv::Value::from("noted"),
        0.5,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    );
    vault.put_claim(&claim, &body, test_time_range(1, 1), 2)?;

    let read = vault.get_claim(&claim)?.expect("edge-subject claim");
    assert_eq!(
        read.subject,
        ClaimSubject::Edge {
            source: a,
            kind: EdgeKind::Supports,
            target: b,
        }
    );
    assert!(
        vault.edges_out(&claim)?.is_empty(),
        "EdgeRef-subject put_claim must not write claim_of edges"
    );
    Ok(())
}

#[test]
fn type0_validation_guards_every_write_path() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let garbage: &[u8] = b"definitely not msgpack";

    // Path 1: Vault::put_entity.
    let id = EntityId::now();
    let err = vault
        .put_entity(&id, 0, test_time_range(1, 1), 1, garbage)
        .expect_err("raw put_entity must validate type-0 bodies");
    assert_eq!(err.kind(), ErrorKind::InvalidClaimBody);
    assert_no_entity_state(&vault, &id)?;

    // Path 2: BatchBuilder::put → commit.
    let id = EntityId::now();
    let err = vault
        .batch()
        .put(&id, 0, test_time_range(1, 1), 1, garbage)
        .commit()
        .expect_err("BatchBuilder must validate type-0 bodies");
    assert_eq!(err.kind(), ErrorKind::InvalidClaimBody);
    assert_no_entity_state(&vault, &id)?;

    // Path 3: TxnBatchBuilder::apply (the sync-replay path) — the failed
    // transaction is dropped without commit, so nothing lands.
    let id = EntityId::now();
    let err = vault
        .with_write_txn(|wtxn| {
            vault
                .batch_in()
                .put(&id, 0, test_time_range(1, 1), 1, garbage)
                .apply(wtxn)
        })
        .expect_err("TxnBatchBuilder must validate type-0 bodies");
    assert_eq!(err.kind(), ErrorKind::InvalidClaimBody);
    assert_no_entity_state(&vault, &id)?;

    // A structurally VALID legacy claim body with no caller-supplied source
    // remains a raw compatibility case.
    let id = EntityId::now();
    vault.put_entity(
        &id,
        0,
        test_time_range(1, 1),
        1,
        &valid_claim_body_bytes("profile.name", "Alice"),
    )?;
    assert!(vault.get_claim(&id)?.is_some());

    // Bodies of non-zero types stay OPAQUE: the same garbage commits fine
    // and round-trips byte-for-byte.
    let id = EntityId::now();
    vault.put_entity(&id, 1, test_time_range(1, 1), 1, garbage)?;
    assert_eq!(vault.get(&id)?.as_deref(), Some(garbage));
    Ok(())
}

#[test]
fn claim_negative_matrix_rejects_typed_and_writes_nothing() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let subj_bytes = seeded_entity_id(0xAA01).as_bytes().to_vec();
    let base = base_claim_entries("profile.name", subj_bytes.clone());

    let valid_map_plus_trailing = {
        let mut bytes = rmpv_map_bytes(&base);
        bytes.push(0xC0);
        bytes
    };

    let cases: Vec<(&str, Vec<u8>, ErrorKind)> = vec![
        (
            "garbage bytes",
            b"\xFF\xFF\xFF garbage".to_vec(),
            ErrorKind::InvalidClaimBody,
        ),
        ("empty body", Vec::new(), ErrorKind::InvalidClaimBody),
        (
            "non-map body",
            {
                let mut out = Vec::new();
                rmpv::encode::write_value(&mut out, &rmpv::Value::from("just a string"))
                    .expect("encode");
                out
            },
            ErrorKind::InvalidClaimBody,
        ),
        (
            "trailing bytes",
            valid_map_plus_trailing,
            ErrorKind::InvalidClaimBody,
        ),
        (
            "missing pred",
            rmpv_map_bytes(&entries_without(&base, "pred")),
            ErrorKind::InvalidClaimBody,
        ),
        (
            "missing subj",
            rmpv_map_bytes(&entries_without(&base, "subj")),
            ErrorKind::InvalidClaimBody,
        ),
        (
            "missing val",
            rmpv_map_bytes(&entries_without(&base, "val")),
            ErrorKind::InvalidClaimBody,
        ),
        (
            "missing conf",
            rmpv_map_bytes(&entries_without(&base, "conf")),
            ErrorKind::InvalidClaimBody,
        ),
        (
            "missing appr",
            rmpv_map_bytes(&entries_without(&base, "appr")),
            ErrorKind::InvalidClaimBody,
        ),
        (
            "missing life",
            rmpv_map_bytes(&entries_without(&base, "life")),
            ErrorKind::InvalidClaimBody,
        ),
        (
            "conf NaN",
            rmpv_map_bytes(&entries_replacing(
                &base,
                "conf",
                rmpv::Value::F32(f32::NAN),
            )),
            ErrorKind::InvalidClaimBody,
        ),
        (
            "conf -0.1",
            rmpv_map_bytes(&entries_replacing(&base, "conf", rmpv::Value::F64(-0.1))),
            ErrorKind::InvalidClaimBody,
        ),
        (
            "conf 1.1",
            rmpv_map_bytes(&entries_replacing(&base, "conf", rmpv::Value::F64(1.1))),
            ErrorKind::InvalidClaimBody,
        ),
        (
            "appr unknown enum",
            rmpv_map_bytes(&entries_replacing(&base, "appr", "maybe".into())),
            ErrorKind::InvalidClaimBody,
        ),
        (
            "life unknown enum",
            rmpv_map_bytes(&entries_replacing(&base, "life", "zombie".into())),
            ErrorKind::InvalidClaimBody,
        ),
        (
            "src unknown enum",
            {
                let mut entries = base.clone();
                entries.push(("src".into(), "psychic".into()));
                rmpv_map_bytes(&entries)
            },
            ErrorKind::InvalidClaimBody,
        ),
        (
            "sal out of range",
            {
                let mut entries = base.clone();
                entries.push(("sal".into(), rmpv::Value::F64(1.5)));
                rmpv_map_bytes(&entries)
            },
            ErrorKind::InvalidClaimBody,
        ),
        (
            "subj 17 bytes",
            rmpv_map_bytes(&entries_replacing(
                &base,
                "subj",
                rmpv::Value::Binary(vec![0x44; 17]),
            )),
            ErrorKind::InvalidClaimBody,
        ),
        (
            "subj not binary",
            rmpv_map_bytes(&entries_replacing(&base, "subj", "stringy".into())),
            ErrorKind::InvalidClaimBody,
        ),
        (
            "stale not boolean",
            {
                let mut entries = base.clone();
                entries.push(("stale".into(), rmpv::Value::from(1_u64)));
                rmpv_map_bytes(&entries)
            },
            ErrorKind::InvalidClaimBody,
        ),
        (
            "unknown camelCase key",
            {
                let mut entries = base.clone();
                entries.push(("valueKey".into(), "s:x".into()));
                rmpv_map_bytes(&entries)
            },
            ErrorKind::InvalidClaimBody,
        ),
        (
            "duplicate key",
            {
                let mut entries = base.clone();
                entries.push(("pred".into(), "profile.other".into()));
                rmpv_map_bytes(&entries)
            },
            ErrorKind::InvalidClaimBody,
        ),
        (
            "uppercase predicate Edge.Provenance",
            rmpv_map_bytes(&base_claim_entries("Edge.Provenance", subj_bytes.clone())),
            ErrorKind::InvalidPredicate,
        ),
        (
            "single-segment predicate profile",
            rmpv_map_bytes(&base_claim_entries("profile", subj_bytes.clone())),
            ErrorKind::InvalidPredicate,
        ),
        (
            "reserved edge.provenance via public path",
            rmpv_map_bytes(&base_claim_entries("edge.provenance", subj_bytes)),
            ErrorKind::ReservedPredicate,
        ),
    ];

    for (name, bytes, expected_kind) in cases {
        let id = EntityId::now();
        let err = match vault.put_entity(&id, 0, test_time_range(1, 1), 1, &bytes) {
            Ok(()) => panic!("case {name}: write must be rejected"),
            Err(err) => err,
        };
        assert_eq!(err.kind(), expected_kind, "case {name}: got {err:?}");
        assert_no_entity_state(&vault, &id)?;
    }
    Ok(())
}

#[test]
fn put_claim_typed_api_rejects_invalid_confidence() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let subject = EntityId::now();
    vault.put_entity(&subject, 4, test_time_range(1, 1), 1, b"person")?;

    for bad_conf in [f32::NAN, -0.1, 1.1, f32::INFINITY] {
        let id = EntityId::now();
        let body = ClaimBody::new(
            "profile.name",
            ClaimSubject::Entity(subject),
            rmpv::Value::from("Alice"),
            bad_conf,
            ClaimApprovalStatus::Auto,
            ClaimLifecycleStatus::Active,
        );
        let err = vault
            .put_claim(&id, &body, test_time_range(1, 1), 2)
            .expect_err("invalid conf must be rejected");
        assert_eq!(err.kind(), ErrorKind::InvalidClaimBody, "conf {bad_conf}");
        assert_no_entity_state(&vault, &id)?;
    }
    Ok(())
}

#[test]
fn unknown_well_formed_predicate_accepted_without_registry() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let subject = EntityId::now();
    vault.put_entity(&subject, 4, test_time_range(1, 1), 1, b"person")?;

    let claim = EntityId::now();
    let body = ClaimBody::new(
        "hobby.collects",
        ClaimSubject::Entity(subject),
        rmpv::Value::from("fountain pens"),
        0.7,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    );
    vault.put_claim(&claim, &body, test_time_range(1, 1), 2)?;
    let read = vault.get_claim(&claim)?.expect("unknown predicate stored");
    assert_eq!(read.predicate, "hobby.collects");
    Ok(())
}

#[test]
fn reserved_predicate_rejected_publicly_but_door_writes_and_reads_back() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let a = EntityId::now();
    let b = EntityId::now();
    vault.put_entity(&a, 4, test_time_range(1, 1), 1, b"a")?;
    vault.put_entity(&b, 4, test_time_range(1, 1), 1, b"b")?;

    // Structurally valid since ONE-1159: the door validates the provenance
    // value record + actor-class evidence, not just the D18 wrapper.
    let body = valid_provenance_claim_body(a, a, b);
    let bytes = crate::claim::encode_claim_body(&body)?;

    // Public typed API → ReservedPredicate, nothing written.
    let id = EntityId::now();
    let err = vault
        .put_claim(&id, &body, test_time_range(1, 1), 2)
        .expect_err("public put_claim must reject edge.*");
    assert_eq!(err.kind(), ErrorKind::ReservedPredicate);
    assert_no_entity_state(&vault, &id)?;

    // Public raw path → ReservedPredicate, nothing written.
    let err = vault
        .put_entity(&id, 0, test_time_range(1, 1), 2, &bytes)
        .expect_err("public put_entity must reject edge.*");
    assert_eq!(err.kind(), ErrorKind::ReservedPredicate);
    assert_no_entity_state(&vault, &id)?;

    // The pub(crate) reserved-namespace door (provenance unit) succeeds and
    // the stored claim reads back through get_claim.
    vault.with_write_txn(|wtxn| {
        vault
            .batch_in()
            .put_reserved_claim(&id, test_time_range(1, 1), 2, &bytes)
            .apply(wtxn)
    })?;
    let read = vault.get_claim(&id)?.expect("door-written claim");
    assert_eq!(read.predicate, "edge.provenance");
    assert_eq!(
        read.subject,
        ClaimSubject::Edge {
            source: a,
            kind: EdgeKind::Mentions,
            target: b,
        }
    );

    // The door still enforces grammar + structural validation.
    let ungrammatical = rmpv_map_bytes(&base_claim_entries(
        "Edge.Provenance",
        a.as_bytes().to_vec(),
    ));
    let bad_id = EntityId::now();
    let err = vault
        .with_write_txn(|wtxn| {
            vault
                .batch_in()
                .put_reserved_claim(&bad_id, test_time_range(1, 1), 2, &ungrammatical)
                .apply(wtxn)
        })
        .expect_err("door must still enforce the predicate grammar");
    assert_eq!(err.kind(), ErrorKind::InvalidPredicate);
    assert_no_entity_state(&vault, &bad_id)?;
    Ok(())
}

/// ONE-1123: the sync-replay door (`put_replicated`) admits a reserved
/// `edge.provenance` Claim on BOTH builder flavors — the truth-Claim behind
/// the 26 B edge flag cache (contracts.ts edgeProvenanceClaim: "the edge
/// flags are a DERIVED CACHE of that Claim, and the Claim is truth";
/// storedAs "Normal CLAIM entity") — while every public path keeps
/// rejecting the reserved namespace (covered by the neighboring tests and
/// the claim.rs grammar tests).
#[cfg(feature = "sync")]
#[test]
fn replicated_door_admits_reserved_claim_on_both_builders() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let a = EntityId::now();
    let b = EntityId::now();
    vault.put_entity(&a, 4, test_time_range(1, 1), 1, b"a")?;
    vault.put_entity(&b, 4, test_time_range(1, 1), 1, b"b")?;

    // Structurally valid since ONE-1159: the replicated door validates the
    // provenance value record + actor-class evidence, not just D18.
    let body = valid_provenance_claim_body(a, a, b);
    let bytes = crate::claim::encode_claim_body(&body)?;

    // TxnBatchBuilder flavor (Observer B's replay door).
    let txn_id = EntityId::now();
    vault.with_write_txn(|wtxn| {
        vault
            .batch_in()
            .put_replicated(
                &txn_id,
                crate::types::ENTITY_TYPE_CLAIM,
                test_time_range(1, 1),
                2,
                &bytes,
            )
            .apply(wtxn)
    })?;
    let read = vault.get_claim(&txn_id)?.expect("txn-door claim stored");
    assert_eq!(read.predicate, "edge.provenance");

    // BatchBuilder flavor (forward_rematerialize's replay door).
    let batch_id = EntityId::now();
    vault
        .batch()
        .put_replicated(
            &batch_id,
            crate::types::ENTITY_TYPE_CLAIM,
            test_time_range(1, 1),
            2,
            &bytes,
        )
        .commit()?;
    let read = vault
        .get_claim(&batch_id)?
        .expect("batch-door claim stored");
    assert_eq!(read.predicate, "edge.provenance");
    assert_eq!(
        read.subject,
        ClaimSubject::Edge {
            source: a,
            kind: EdgeKind::Mentions,
            target: b,
        }
    );
    Ok(())
}

/// ONE-1123: a trusted door still validates structure. `put_replicated`
/// opens ONLY the two engine-authored band rejections; the D17 grammar, the
/// D18 body validation, and the type registry all still fail typed, and
/// nothing is written on failure.
#[cfg(feature = "sync")]
#[test]
fn replicated_door_still_fails_typed_on_structural_violations() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let a = EntityId::now();
    vault.put_entity(&a, 4, test_time_range(1, 1), 1, b"a")?;

    // Ungrammatical reserved predicate: "Edge.Provenance" violates the D17
    // segment grammar `[a-z][a-z0-9_]*`, so it fails InvalidPredicate even
    // through the door — `allow_reserved` skips ONLY the ReservedPredicate
    // arm, never the grammar.
    let ungrammatical = rmpv_map_bytes(&base_claim_entries(
        "Edge.Provenance",
        a.as_bytes().to_vec(),
    ));
    let bad_txn = EntityId::now();
    let err = vault
        .with_write_txn(|wtxn| {
            vault
                .batch_in()
                .put_replicated(
                    &bad_txn,
                    crate::types::ENTITY_TYPE_CLAIM,
                    test_time_range(1, 1),
                    2,
                    &ungrammatical,
                )
                .apply(wtxn)
        })
        .expect_err("txn replay door must still enforce the D17 grammar");
    assert_eq!(err.kind(), ErrorKind::InvalidPredicate);
    assert_no_entity_state(&vault, &bad_txn)?;

    let bad_batch = EntityId::now();
    let err = vault
        .batch()
        .put_replicated(
            &bad_batch,
            crate::types::ENTITY_TYPE_CLAIM,
            test_time_range(1, 1),
            2,
            &ungrammatical,
        )
        .commit()
        .expect_err("batch replay door must still enforce the D17 grammar");
    assert_eq!(err.kind(), ErrorKind::InvalidPredicate);
    assert_no_entity_state(&vault, &bad_batch)?;

    // Malformed type-0 body (not a MessagePack map) → InvalidClaimBody.
    let bad_body = EntityId::now();
    let err = vault
        .batch()
        .put_replicated(
            &bad_body,
            crate::types::ENTITY_TYPE_CLAIM,
            test_time_range(1, 1),
            2,
            b"not a msgpack map",
        )
        .commit()
        .expect_err("replay door must still enforce D18 body validation");
    assert_eq!(err.kind(), ErrorKind::InvalidClaimBody);
    assert_no_entity_state(&vault, &bad_body)?;

    // Genuinely unknown type byte → InvalidEntityType (registry gate; the
    // door admits the REGISTERED maintenance band, not arbitrary bytes).
    let bad_type = EntityId::now();
    let err = vault
        .batch()
        .put_replicated(&bad_type, 200, test_time_range(1, 1), 2, b"")
        .commit()
        .expect_err("replay door must still reject unregistered type bytes");
    assert_eq!(err.kind(), ErrorKind::InvalidEntityType);
    assert_no_entity_state(&vault, &bad_type)?;
    Ok(())
}

/// FED-001: `put_replicated` admits the registered maintenance type byte for
/// FEDERATION_GRANT, but the body still has to fail closed before storage or
/// indexes are written.
#[cfg(feature = "sync")]
fn federation_grant_body_with_role_and_preset(role: &str, preset: &str) -> Vec<u8> {
    let member_ref = seeded_entity_id(0xFEDA).to_hex();
    rmpv_map_bytes(&[
        (
            "schema_version".into(),
            rmpv::Value::from(crate::federation::FEDERATION_GRANT_SCHEMA_VERSION),
        ),
        (
            "scope".into(),
            rmpv::Value::Map(vec![
                ("kind".into(), "vault".into()),
                ("vault_id".into(), rmpv::Value::from(7_u64)),
            ]),
        ),
        ("member_ref".into(), rmpv::Value::from(member_ref.as_str())),
        ("role".into(), rmpv::Value::from(role)),
        ("preset".into(), rmpv::Value::from(preset)),
    ])
}

#[cfg(feature = "sync")]
#[test]
fn replicated_door_fails_closed_on_malformed_federation_grant_body() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let malformed = b"not a federation grant body";

    let bad_txn = EntityId::now();
    let err = vault
        .with_write_txn(|wtxn| {
            vault
                .batch_in()
                .put_replicated(
                    &bad_txn,
                    ENTITY_TYPE_FEDERATION_GRANT,
                    test_time_range(1, 1),
                    2,
                    malformed,
                )
                .apply(wtxn)
        })
        .expect_err("txn replay door must reject malformed federation grants");
    assert_eq!(err.kind(), ErrorKind::InvalidFederationGrantBody);
    assert_no_entity_state(&vault, &bad_txn)?;

    let bad_batch = EntityId::now();
    let err = vault
        .batch()
        .put_replicated(
            &bad_batch,
            ENTITY_TYPE_FEDERATION_GRANT,
            test_time_range(1, 1),
            2,
            malformed,
        )
        .commit()
        .expect_err("batch replay door must reject malformed federation grants");
    assert_eq!(err.kind(), ErrorKind::InvalidFederationGrantBody);
    assert_no_entity_state(&vault, &bad_batch)?;
    Ok(())
}

/// FED-001: syntactically valid FEDERATION_GRANT bodies still fail closed at
/// the replicated write chokepoint when role/preset policy is invalid.
#[cfg(feature = "sync")]
#[test]
fn replicated_door_fails_closed_on_invalid_federation_grant_policy() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let invalid_policy = federation_grant_body_with_role_and_preset("admin", "read_only");

    let bad_txn = EntityId::now();
    let err = vault
        .with_write_txn(|wtxn| {
            vault
                .batch_in()
                .put_replicated(
                    &bad_txn,
                    ENTITY_TYPE_FEDERATION_GRANT,
                    test_time_range(1, 1),
                    2,
                    &invalid_policy,
                )
                .apply(wtxn)
        })
        .expect_err("txn replay door must reject role/preset mismatches");
    assert_eq!(err.kind(), ErrorKind::InvalidFederationGrantBody);
    assert_no_entity_state(&vault, &bad_txn)?;

    let bad_batch = EntityId::now();
    let err = vault
        .batch()
        .put_replicated(
            &bad_batch,
            ENTITY_TYPE_FEDERATION_GRANT,
            test_time_range(1, 1),
            2,
            &invalid_policy,
        )
        .commit()
        .expect_err("batch replay door must reject role/preset mismatches");
    assert_eq!(err.kind(), ErrorKind::InvalidFederationGrantBody);
    assert_no_entity_state(&vault, &bad_batch)?;
    Ok(())
}

#[test]
fn get_claim_rejects_non_claim_types_and_handles_missing() -> Result<()> {
    let (_dir, vault) = open_test_vault();

    // Missing entity → Ok(None).
    assert!(vault.get_claim(&seeded_entity_id(0xBEEF))?.is_none());

    // Non-claim type byte → typed InvalidClaimBody, not a silent decode.
    let person = EntityId::now();
    vault.put_entity(&person, 4, test_time_range(1, 1), 1, b"person")?;
    let err = vault
        .get_claim(&person)
        .expect_err("get_claim on a PERSON must fail typed");
    assert_eq!(err.kind(), ErrorKind::InvalidClaimBody);
    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════
// ONE-1105: edge.provenance module + atomic provenanced-write API
// ═══════════════════════════════════════════════════════════════════════

/// Raw `(edges_out, edges_in)` value bytes for one edge.
type RawEdgeValuePair = (Option<Vec<u8>>, Option<Vec<u8>>);

/// Reads the raw `edges_out` / `edges_in` values for `edge` (both directions)
/// without any decoding — byte-level test oracle.
fn raw_edge_values(vault: &Vault, edge: &EdgeRef) -> Result<RawEdgeValuePair> {
    let rtxn = vault.store.env.read_txn()?;
    let key_out = Store::encode_edge_key(&edge.source, edge.kind, &edge.target);
    let key_in = Store::encode_edge_key(&edge.target, edge.kind, &edge.source);
    let out = vault
        .store
        .edges_out
        .get(&rtxn, &key_out)?
        .map(<[u8]>::to_vec);
    let inn = vault
        .store
        .edges_in
        .get(&rtxn, &key_in)?
        .map(<[u8]>::to_vec);
    Ok((out, inn))
}

#[test]
fn put_edge_provenance_atomic_write_restamps_and_indexes() -> Result<()> {
    let (dir, vault) = open_test_vault();
    let actor = EntityId::now();
    let source = EntityId::now();
    let target = EntityId::now();
    vault.put_entity(&actor, 4, test_time_range(1, 1), 1, b"person-actor")?;
    vault.put_entity(&source, 4, test_time_range(1, 1), 1, b"src")?;
    vault.put_entity(&target, 4, test_time_range(1, 1), 1, b"tgt")?;

    let vad = Vad {
        valence: 0.25,
        arousal: 0.5,
        dominance: 0.75,
    };
    vault.put_edge_with_vad(&source, EdgeKind::Mentions, &target, 0.875, vad)?;
    let subject = EdgeRef::new(source, EdgeKind::Mentions, target);

    let (before_out, before_in) = raw_edge_values(&vault, &subject)?;
    let before_out = before_out.expect("subject edge missing");
    assert_eq!(
        before_out.len(),
        EDGE_VALUE_SEMANTIC_LEN,
        "pre-provenance edge must be 24 B"
    );
    assert_eq!(before_in.as_deref(), Some(before_out.as_slice()));

    // Plant malformed PPR cache rows (3 B < header length) keyed to both
    // endpoints so the AC5e invalidation is observable: invalidation
    // DELETES sub-header cache rows.
    let src_hash = [0xAB_u8; 16];
    let tgt_hash = [0xAC_u8; 16];
    {
        let mut wtxn = vault.store.env.write_txn()?;
        let mut src_dep = [0_u8; 32];
        src_dep[..16].copy_from_slice(source.as_bytes());
        src_dep[16..].copy_from_slice(&src_hash);
        let mut tgt_dep = [0_u8; 32];
        tgt_dep[..16].copy_from_slice(target.as_bytes());
        tgt_dep[16..].copy_from_slice(&tgt_hash);
        vault
            .store
            .ppr_cache
            .put(&mut wtxn, &src_hash, &[1, 2, 3])?;
        vault
            .store
            .ppr_cache
            .put(&mut wtxn, &tgt_hash, &[1, 2, 3])?;
        vault.store.ppr_cache_deps.put(&mut wtxn, &src_dep, &[])?;
        vault.store.ppr_cache_deps.put(&mut wtxn, &tgt_dep, &[])?;
        wtxn.commit()?;
    }

    let claim_id = EntityId::now();
    let mut body = EdgeProvenanceClaimBody::new(actor, 0.75, SupersessionStatus::Confirmed);
    body.source_revision_ref = Some([0x51; 16]);
    body.body_snapshot_ref = Some([0x52; 16]);
    let learned_at = 1_000_000_u64;
    vault.put_edge_provenance(
        &claim_id,
        &subject,
        &body,
        EdgeActorClass::Human,
        learned_at,
    )?;

    // 26-byte restamp at the pinned offsets, first 24 bytes preserved
    // verbatim, IDENTICAL bytes in BOTH directions (read raw).
    let (after_out, after_in) = raw_edge_values(&vault, &subject)?;
    let after_out = after_out.expect("edges_out row");
    let after_in = after_in.expect("edges_in row");
    assert_eq!(after_out.len(), EDGE_VALUE_SEMANTIC_PROVENANCED_LEN);
    assert_eq!(
        &after_out[..24],
        before_out.as_slice(),
        "weight/created_at/VAD bytes must survive the restamp"
    );
    assert_eq!(after_out[24], 1, "confirmed = 1 at offset 24");
    assert_eq!(after_out[25], 0, "human = 0 at offset 25");
    assert_eq!(
        after_in, after_out,
        "edges_in must mirror edges_out byte-for-byte"
    );

    // PPR caches for both subject-edge endpoints invalidated (AC5e).
    {
        let rtxn = vault.store.env.read_txn()?;
        assert!(
            vault.store.ppr_cache.get(&rtxn, &src_hash)?.is_none(),
            "source-endpoint PPR cache must be invalidated"
        );
        assert!(
            vault.store.ppr_cache.get(&rtxn, &tgt_hash)?.is_none(),
            "target-endpoint PPR cache must be invalidated"
        );
    }

    // The Claim entity is a type-0 record whose envelope carries the D15
    // open-window sentinels: start = learned_at, end = u64::MAX.
    let raw = vault.get_raw(&claim_id)?.expect("claim entity");
    assert_eq!(raw[0], 0, "claim type byte must be 0");
    assert_eq!(
        u64::from_be_bytes(raw[1..9].try_into().expect("occurred_start")),
        learned_at,
        "absent valid_from must derive occurred.start = learned_at (D15)"
    );
    assert_eq!(
        u64::from_be_bytes(raw[9..17].try_into().expect("occurred_end")),
        u64::MAX,
        "absent valid_to must derive occurred.end = u64::MAX (D15)"
    );

    // claim_of (u8 = 5, structural 12 B) Claim → SOURCE entity (D12), and
    // NOT to the target.
    let rtxn = vault.store.env.read_txn()?;
    let claim_of_src = Store::encode_edge_key(&claim_id, EdgeKind::ClaimOf, &source);
    let claim_of_tgt = Store::encode_edge_key(&claim_id, EdgeKind::ClaimOf, &target);
    let link = vault
        .store
        .edges_out
        .get(&rtxn, &claim_of_src)?
        .expect("claim_of edge to the subject edge's source");
    assert_eq!(link.len(), EDGE_VALUE_STRUCTURAL_LEN);
    // Weight f32 LE @0 = the contract's pinned claim_of pprWeight 1.0
    // (contracts.ts edgeKinds u8 = 5).
    assert_eq!(&link[0..4], &1.0_f32.to_le_bytes());
    assert!(
        vault.store.edges_out.get(&rtxn, &claim_of_tgt)?.is_none(),
        "claim_of must target the SOURCE entity only (D12)"
    );
    drop(rtxn);
    assert_eq!(vault.claims_for_subject(&source)?, vec![claim_id]);

    // The wrapping claim decodes: pinned predicate, EdgeRef subject, the
    // 10-key value record, and the conf mirror. NEW behavior pinned by the
    // ONE-1138 ruling (ONE-1112 C2 relocation): the persisted record carries
    // the validated caller-supplied actor_class as a BODY key, and the
    // wrapper's `evid` stays empty (evidence purity — no legacy map).
    let claim = vault.get_claim(&claim_id)?.expect("claim body");
    assert_eq!(claim.predicate, PREDICATE_EDGE_PROVENANCE);
    assert_eq!(claim.subject, ClaimSubject::from(subject));
    assert_eq!(claim.confidence.to_bits(), 0.75_f32.to_bits());
    assert!(
        claim.evidence.is_none(),
        "post-ONE-1138 writers must leave the wrapper evid empty"
    );
    let value = decode_edge_provenance_body(&claim.value)?;
    let mut expected = body;
    expected.actor_class = Some(EdgeActorClass::Human);
    assert_eq!(value, expected);

    // D15 temporal interplay: the open window indexes occurred_start at
    // learned_at and occurred_end + long_intervals at u64::MAX.
    let rtxn = vault.store.env.read_txn()?;
    let start_key = Store::encode_temporal_key(learned_at, &claim_id);
    let end_key = Store::encode_temporal_key(u64::MAX, &claim_id);
    assert!(
        vault
            .store
            .temporal_occurred_start
            .get(&rtxn, &start_key)?
            .is_some()
    );
    assert!(
        vault
            .store
            .temporal_occurred_end
            .get(&rtxn, &end_key)?
            .is_some()
    );
    let long_row = vault
        .store
        .temporal_long_intervals
        .get(&rtxn, &end_key)?
        .expect("open validity window must index as a long interval");
    assert_eq!(long_row, learned_at.to_be_bytes());
    drop(rtxn);

    // A SECOND provenance claim restamps only the two flag bytes
    // (disputed = 2, agent = 1); the value stays 26 B with the original
    // 24-byte prefix.
    let claim2 = EntityId::now();
    let body2 = EdgeProvenanceClaimBody::new(actor, 0.5, SupersessionStatus::Disputed);
    vault.put_edge_provenance(
        &claim2,
        &subject,
        &body2,
        EdgeActorClass::Agent,
        learned_at + 1,
    )?;
    let (out2, in2) = raw_edge_values(&vault, &subject)?;
    let out2 = out2.expect("edges_out row");
    assert_eq!(out2.len(), EDGE_VALUE_SEMANTIC_PROVENANCED_LEN);
    assert_eq!(&out2[..24], before_out.as_slice());
    assert_eq!(out2[24], 2, "disputed = 2");
    assert_eq!(out2[25], 1, "agent = 1");
    assert_eq!(in2.as_deref(), Some(out2.as_slice()));

    // The u64::MAX envelope sentinel must not trip the long-interval
    // migration guard at open (store.rs open-gate step 7) — D15's pinned
    // verification.
    drop(vault);
    let reopened = Vault::open(dir.path(), test_config())?;
    assert!(reopened.get_claim(&claim_id)?.is_some());
    Ok(())
}

#[test]
fn put_edge_provenance_explicit_validity_window_maps_envelope() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let actor = EntityId::now();
    let a = EntityId::now();
    let b = EntityId::now();
    vault.put_entity(&actor, 4, test_time_range(1, 1), 1, b"person")?;
    vault.put_entity(&a, 4, test_time_range(1, 1), 1, b"a")?;
    vault.put_entity(&b, 4, test_time_range(1, 1), 1, b"b")?;
    vault.put_edge(&a, EdgeKind::About, &b, 0.5)?;
    let subject = EdgeRef::new(a, EdgeKind::About, b);

    let claim_id = EntityId::now();
    let mut body = EdgeProvenanceClaimBody::new(actor, 0.9, SupersessionStatus::Proposed);
    body.valid_from = Some(100);
    body.valid_to = Some(200);
    vault.put_edge_provenance(&claim_id, &subject, &body, EdgeActorClass::Human, 300)?;

    // Explicit window → envelope copies it verbatim (no sentinels).
    let raw = vault.get_raw(&claim_id)?.expect("claim entity");
    assert_eq!(
        u64::from_be_bytes(raw[1..9].try_into().expect("occurred_start")),
        100
    );
    assert_eq!(
        u64::from_be_bytes(raw[9..17].try_into().expect("occurred_end")),
        200
    );

    // 100-second span: NOT a long interval; closed end indexes normally.
    let rtxn = vault.store.env.read_txn()?;
    let end_key = Store::encode_temporal_key(200, &claim_id);
    assert!(
        vault
            .store
            .temporal_long_intervals
            .get(&rtxn, &end_key)?
            .is_none(),
        "a 100 s window must not index as a long interval"
    );
    assert!(
        vault
            .store
            .temporal_occurred_end
            .get(&rtxn, &end_key)?
            .is_some()
    );
    drop(rtxn);

    // The claim-layer from/to mirrors carry the same window; the 7-field
    // record stays authoritative.
    let claim = vault.get_claim(&claim_id)?.expect("claim body");
    assert_eq!(claim.valid_from, Some(100));
    assert_eq!(claim.valid_to, Some(200));
    let value = decode_edge_provenance_body(&claim.value)?;
    assert_eq!(value.valid_from, Some(100));
    assert_eq!(value.valid_to, Some(200));

    // valid_to earlier than learned_at with absent valid_from would derive
    // an inverted envelope — typed reject, nothing written, never silently
    // reordered.
    let bad_id = EntityId::now();
    let mut bad_body = EdgeProvenanceClaimBody::new(actor, 0.5, SupersessionStatus::Proposed);
    bad_body.valid_to = Some(50);
    let err = vault
        .put_edge_provenance(&bad_id, &subject, &bad_body, EdgeActorClass::Human, 100)
        .expect_err("inverted derived envelope must be rejected");
    assert_eq!(err.kind(), ErrorKind::InvalidProvenanceBody);
    assert_no_entity_state(&vault, &bad_id)?;
    Ok(())
}

#[test]
fn put_edge_provenance_negative_paths_write_nothing() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let person = EntityId::now();
    let machine = EntityId::now();
    let a = EntityId::now();
    let b = EntityId::now();
    vault.put_entity(&person, 4, test_time_range(1, 1), 1, b"person")?;
    vault.put_entity(
        &machine,
        ENTITY_TYPE_MACHINE,
        test_time_range(1, 1),
        1,
        b"machine",
    )?;
    vault.put_entity(&a, 4, test_time_range(1, 1), 1, b"a")?;
    vault.put_entity(&b, 4, test_time_range(1, 1), 1, b"b")?;

    // Structural-kind subject edge (part_of u8 = 2, 12 B) → typed reject
    // even though the edge EXISTS; the edge value is untouched.
    vault.put_edge(&a, EdgeKind::PartOf, &b, 1.0)?;
    let structural = EdgeRef::new(a, EdgeKind::PartOf, b);
    let claim_id = EntityId::now();
    let body = EdgeProvenanceClaimBody::new(person, 0.9, SupersessionStatus::Confirmed);
    let err = vault
        .put_edge_provenance(&claim_id, &structural, &body, EdgeActorClass::Human, 10)
        .expect_err("structural subject kind must be rejected");
    assert_eq!(err.kind(), ErrorKind::ProvenanceOnStructuralEdge);
    assert_no_entity_state(&vault, &claim_id)?;
    let (out, _) = raw_edge_values(&vault, &structural)?;
    assert_eq!(
        out.expect("structural edge").len(),
        EDGE_VALUE_STRUCTURAL_LEN,
        "structural edge must keep its 12 B value"
    );

    // Nonexistent semantic subject edge → EdgeNotFound (NO upsert — the
    // path must never invent weight/created_at).
    let missing = EdgeRef::new(a, EdgeKind::Mentions, b);
    let claim_id = EntityId::now();
    let err = vault
        .put_edge_provenance(&claim_id, &missing, &body, EdgeActorClass::Human, 10)
        .expect_err("missing subject edge must be rejected");
    assert_eq!(err.kind(), ErrorKind::EdgeNotFound);
    assert_no_entity_state(&vault, &claim_id)?;
    let (out, inn) = raw_edge_values(&vault, &missing)?;
    assert_eq!(out, None, "rejection must not upsert the edge");
    assert_eq!(inn, None);

    // From here on the subject edge exists as semantic-bare 24 B.
    vault.put_edge(&a, EdgeKind::Mentions, &b, 0.5)?;
    let subject = EdgeRef::new(a, EdgeKind::Mentions, b);
    let (before, _) = raw_edge_values(&vault, &subject)?;
    let before = before.expect("subject edge");
    assert_eq!(before.len(), EDGE_VALUE_SEMANTIC_LEN);

    // Nonexistent actor entity → typed EntityNotFound; edge untouched.
    let claim_id = EntityId::now();
    let ghost_body =
        EdgeProvenanceClaimBody::new(seeded_entity_id(0xD00D), 0.9, SupersessionStatus::Confirmed);
    let err = vault
        .put_edge_provenance(&claim_id, &subject, &ghost_body, EdgeActorClass::Human, 10)
        .expect_err("missing actor entity must be rejected");
    assert_eq!(err.kind(), ErrorKind::EntityNotFound);
    assert_no_entity_state(&vault, &claim_id)?;
    let (out, _) = raw_edge_values(&vault, &subject)?;
    assert_eq!(out.as_deref(), Some(before.as_slice()));

    // D13 mismatches: PERSON+system, MACHINE+human, MACHINE+agent — each a
    // typed ActorClassMismatch, nothing written, edge untouched in BOTH
    // directions.
    for (actor, class) in [
        (person, EdgeActorClass::System),
        (machine, EdgeActorClass::Human),
        (machine, EdgeActorClass::Agent),
    ] {
        let claim_id = EntityId::now();
        let body = EdgeProvenanceClaimBody::new(actor, 0.9, SupersessionStatus::Confirmed);
        let err = vault
            .put_edge_provenance(&claim_id, &subject, &body, class, 10)
            .expect_err("actor kind/class mismatch must be rejected");
        assert_eq!(err.kind(), ErrorKind::ActorClassMismatch, "class {class:?}");
        assert_no_entity_state(&vault, &claim_id)?;
        let (out, inn) = raw_edge_values(&vault, &subject)?;
        assert_eq!(
            out.as_deref(),
            Some(before.as_slice()),
            "subject edge must be untouched after a rejected write"
        );
        assert_eq!(inn.as_deref(), Some(before.as_slice()));
    }

    // Sanity: the SAME setup succeeds with a compatible pair — proving the
    // rejections above came from the stated violations.
    let ok_id = EntityId::now();
    let ok_body = EdgeProvenanceClaimBody::new(person, 0.9, SupersessionStatus::Confirmed);
    vault.put_edge_provenance(&ok_id, &subject, &ok_body, EdgeActorClass::Human, 10)?;
    Ok(())
}

#[test]
fn decode_edge_value_rejects_out_of_range_flag_bytes() {
    let flags = EdgeProvenanceFlags {
        confirmation_status: EdgeConfirmationStatus::Proposed,
        actor_class: EdgeActorClass::Human,
    };
    let valid = encode_edge_value(EdgeKind::Mentions, 0.5, 1_000, Vad::NEUTRAL, Some(flags))
        .expect("valid 26 B value");
    assert_eq!(valid.len(), EDGE_VALUE_SEMANTIC_PROVENANCED_LEN);

    // confirmation_status admits exactly {0, 1, 2, 3}: 4 is the first
    // invalid byte.
    for bad in [4_u8, 0x7F, 255] {
        let mut value = valid.clone();
        value[24] = bad;
        let err = decode_edge_value(&value).expect_err("confirmation byte > 3 must be rejected");
        assert!(
            matches!(err, Error::CorruptedIndex("edge value")),
            "byte {bad} returned wrong error: {err:?}"
        );
    }
    // actor_class admits exactly {0, 1, 2}: 3 is the first invalid byte.
    for bad in [3_u8, 0x7F, 255] {
        let mut value = valid.clone();
        value[25] = bad;
        let err = decode_edge_value(&value).expect_err("actor byte > 2 must be rejected");
        assert!(
            matches!(err, Error::CorruptedIndex("edge value")),
            "byte {bad} returned wrong error: {err:?}"
        );
    }
}

// ═══════════════════════════════════════════════════════════════════════
// ONE-1108: general Claim supersession / retraction mechanics (ARCH-0003
// lifecycle — active | superseded | retracted; supersedes edge u8 = 3).
// ═══════════════════════════════════════════════════════════════════════

/// Stores a minimal ACTIVE claim about `subject` (point occurred + learned
/// at `learned_at`) and returns its id.
fn put_active_claim(
    vault: &Vault,
    subject: &EntityId,
    pred: &str,
    val: &str,
    learned_at: u64,
) -> Result<EntityId> {
    put_active_claim_with_source(vault, subject, pred, val, None, learned_at)
}

fn put_active_claim_with_source(
    vault: &Vault,
    subject: &EntityId,
    pred: &str,
    val: &str,
    source: Option<ClaimSource>,
    learned_at: u64,
) -> Result<EntityId> {
    put_active_claim_with_source_and_approval(
        vault,
        subject,
        pred,
        val,
        source,
        ClaimApprovalStatus::Auto,
        learned_at,
    )
}

fn put_active_claim_with_source_and_approval(
    vault: &Vault,
    subject: &EntityId,
    pred: &str,
    val: &str,
    source: Option<ClaimSource>,
    approval: ClaimApprovalStatus,
    learned_at: u64,
) -> Result<EntityId> {
    let id = EntityId::now();
    let mut body = ClaimBody::new(
        pred,
        ClaimSubject::Entity(*subject),
        rmpv::Value::from(val),
        0.9,
        approval,
        ClaimLifecycleStatus::Active,
    );
    body.source = source;
    vault.put_claim(
        &id,
        &body,
        test_time_range(learned_at, learned_at),
        learned_at,
    )?;
    Ok(id)
}

/// Raw `[src(16) | kind_u8(1) | tgt(16)]` edge key built with a LITERAL
/// discriminant byte so a renumbered EdgeKind enum cannot mask drift.
fn raw_edge_key(src: &EntityId, kind_u8: u8, tgt: &EntityId) -> Vec<u8> {
    let mut key = Vec::with_capacity(33);
    key.extend_from_slice(src.as_bytes());
    key.push(kind_u8);
    key.extend_from_slice(tgt.as_bytes());
    key
}

#[test]
fn supersede_claim_closes_old_writes_edge_and_keeps_history() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let subject = EntityId::now();
    vault.put_entity(&subject, 4, test_time_range(1, 1), 1, b"person")?;
    let old = put_active_claim(&vault, &subject, "profile.lives_in", "osaka", 11)?;
    let new = put_active_claim(&vault, &subject, "profile.lives_in", "tokyo", 22)?;

    const NOW: u64 = 777;
    vault.supersede_claim(&new, &old, NOW)?;

    // Old body closed: life = superseded, to = now — and the old claim is
    // STILL readable. A purge implementation fails right here.
    let old_read = vault
        .get_claim(&old)?
        .expect("superseded claim must stay readable");
    assert_eq!(old_read.lifecycle, ClaimLifecycleStatus::Superseded);
    assert_eq!(old_read.valid_to, Some(NOW));
    assert!(
        vault.get(&old)?.is_some(),
        "superseded claim record must persist"
    );

    // Envelope occurred_end refreshed to now. Offsets are the pinned
    // 25-byte envelope LITERALS: type u8 @0, occurred_start u64 BE @1..9,
    // occurred_end u64 BE @9..17, learned_at u64 BE @17..25.
    let raw = vault.get_raw(&old)?.ok_or(Error::EntityNotFound)?;
    assert_eq!(raw[0], 0, "type byte must stay CLAIM (0)");
    assert_eq!(
        &raw[1..9],
        &11_u64.to_be_bytes(),
        "occurred_start untouched"
    );
    assert_eq!(&raw[9..17], &NOW.to_be_bytes(), "occurred_end refreshed");
    assert_eq!(&raw[17..25], &11_u64.to_be_bytes(), "learned_at untouched");

    // supersedes edge new → old: discriminant 3, structural 12 B (weight
    // f32 LE @0 = the contract's pinned pprWeight 0.3, created_at u64 LE
    // @4 = now), identical bytes in BOTH directions.
    let key_out = raw_edge_key(&new, 3, &old);
    let key_in = raw_edge_key(&old, 3, &new);
    let rtxn = vault.store.env.read_txn()?;
    let out_value = vault
        .store
        .edges_out
        .get(&rtxn, &key_out)?
        .expect("supersedes edge missing from edges_out")
        .to_vec();
    let in_value = vault
        .store
        .edges_in
        .get(&rtxn, &key_in)?
        .expect("supersedes edge missing from edges_in")
        .to_vec();
    drop(rtxn);
    assert_eq!(out_value.len(), 12, "supersedes must be structural 12 B");
    assert_eq!(out_value, in_value);
    assert_eq!(&out_value[0..4], &0.3_f32.to_le_bytes());
    assert_eq!(&out_value[4..12], &NOW.to_le_bytes());
    assert_eq!(
        vault.targets(&new, EdgeKind::Supersedes, Some(0))?,
        vec![old]
    );

    // The temporal index follows the refreshed envelope end.
    let rtxn = vault.store.env.read_txn()?;
    let end_key = Store::encode_temporal_key(NOW, &old);
    assert!(
        vault
            .store
            .temporal_occurred_end
            .get(&rtxn, &end_key)?
            .is_some(),
        "refreshed occurred_end must be indexed"
    );
    drop(rtxn);

    // The NEW claim is untouched — supersession closes only the old side.
    let new_read = vault.get_claim(&new)?.expect("new claim");
    assert_eq!(new_read.lifecycle, ClaimLifecycleStatus::Active);
    assert_eq!(new_read.valid_to, None);

    // History stays attached to the subject: BOTH claims remain linked.
    let mut linked = vault.claims_for_subject(&subject)?;
    linked.sort();
    let mut expected = vec![old, new];
    expected.sort();
    assert_eq!(linked, expected, "superseded claim must stay in the graph");
    Ok(())
}

#[test]
fn retract_claim_marks_retracted_and_preserves_record() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let subject = EntityId::now();
    vault.put_entity(&subject, 4, test_time_range(1, 1), 1, b"person")?;
    let claim = put_active_claim(&vault, &subject, "profile.lives_in", "osaka", 11)?;

    const NOW: u64 = 555;
    vault.retract_claim(&claim, NOW)?;

    let read = vault
        .get_claim(&claim)?
        .expect("retracted claim must stay readable");
    assert_eq!(read.lifecycle, ClaimLifecycleStatus::Retracted);
    assert_eq!(read.valid_to, Some(NOW));

    // Pin the EXACT closed on-disk body: pinned D11 short keys in
    // canonical order with the lifecycle fields stamped — to = now,
    // life = "retracted". A long-key / reordered / purging implementation
    // fails byte equality.
    let raw = vault.get_raw(&claim)?.ok_or(Error::EntityNotFound)?;
    let expected = rmpv_map_bytes(&[
        ("pred".into(), "profile.lives_in".into()),
        ("val".into(), "osaka".into()),
        ("conf".into(), rmpv::Value::F32(0.9)),
        ("to".into(), rmpv::Value::from(NOW)),
        (
            "subj".into(),
            rmpv::Value::Binary(subject.as_bytes().to_vec()),
        ),
        ("appr".into(), "auto".into()),
        ("life".into(), "retracted".into()),
    ]);
    assert_eq!(
        &raw[ENTITY_METADATA_HEADER_LEN..],
        expected.as_slice(),
        "retracted on-disk body drifted from the pinned D11 ABI"
    );

    // Envelope occurred_end refreshed to now; record + index preserved.
    assert_eq!(&raw[9..17], &NOW.to_be_bytes());
    assert!(
        vault.entities_by_type(0)?.contains(&claim),
        "retracted claim must remain type-indexed"
    );
    assert_eq!(vault.claims_for_subject(&subject)?, vec![claim]);
    Ok(())
}

/// Stores a minimal ACTIVE claim about `subject` with an INTERVAL
/// `occurred` window and returns its id. The interval (start != end)
/// matters: only interval entities own a `temporal_occurred_end` row, so
/// these fixtures create the PRE-EXISTING end row that a lifecycle
/// refresh must MOVE (delete stale, write refreshed) — an
/// add-without-delete implementation cannot pass against them.
fn put_active_interval_claim(
    vault: &Vault,
    subject: &EntityId,
    pred: &str,
    val: &str,
    occurred: TimeRange,
    learned_at: u64,
) -> Result<EntityId> {
    let id = EntityId::now();
    let body = ClaimBody::new(
        pred,
        ClaimSubject::Entity(*subject),
        rmpv::Value::from(val),
        0.9,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    );
    vault.put_claim(&id, &body, occurred, learned_at)?;
    Ok(id)
}

#[test]
fn supersede_claim_moves_temporal_occurred_end_row() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let subject = EntityId::now();
    vault.put_entity(&subject, 4, test_time_range(1, 1), 1, b"person")?;
    let old = put_active_interval_claim(
        &vault,
        &subject,
        "profile.lives_in",
        "osaka",
        test_time_range(11, 50),
        11,
    )?;
    let new = put_active_claim(&vault, &subject, "profile.lives_in", "tokyo", 22)?;

    // Fixture sanity: the interval claim pre-indexes occurred_end at
    // ts = 50, so the absence assertion after the supersede is
    // non-vacuous.
    let stale_end_key = Store::encode_temporal_key(50, &old);
    {
        let rtxn = vault.store.env.read_txn()?;
        assert!(
            vault
                .store
                .temporal_occurred_end
                .get(&rtxn, &stale_end_key)?
                .is_some(),
            "fixture must pre-index occurred_end at ts = 50"
        );
    }

    const NOW: u64 = 777;
    vault.supersede_claim(&new, &old, NOW)?;

    // The envelope refresh must MOVE the temporal_occurred_end row: the
    // stale ts = 50 row is deleted and the refreshed ts = 777 row is
    // written. An implementation that only hand-adds the new row (never
    // deleting the prior one) fails the first assertion.
    let refreshed_end_key = Store::encode_temporal_key(NOW, &old);
    let rtxn = vault.store.env.read_txn()?;
    assert!(
        vault
            .store
            .temporal_occurred_end
            .get(&rtxn, &stale_end_key)?
            .is_none(),
        "stale occurred_end row at ts = 50 must be deleted by the refresh"
    );
    assert!(
        vault
            .store
            .temporal_occurred_end
            .get(&rtxn, &refreshed_end_key)?
            .is_some(),
        "refreshed occurred_end row at ts = 777 must be indexed"
    );
    drop(rtxn);

    // The transition itself completed (close semantics are pinned in
    // depth by supersede_claim_closes_old_writes_edge_and_keeps_history).
    let old_read = vault.get_claim(&old)?.expect("superseded claim");
    assert_eq!(old_read.lifecycle, ClaimLifecycleStatus::Superseded);
    assert_eq!(old_read.valid_to, Some(NOW));
    Ok(())
}

#[test]
fn retract_claim_moves_temporal_occurred_end_row() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let subject = EntityId::now();
    vault.put_entity(&subject, 4, test_time_range(1, 1), 1, b"person")?;
    let claim = put_active_interval_claim(
        &vault,
        &subject,
        "profile.lives_in",
        "osaka",
        test_time_range(11, 50),
        11,
    )?;

    let stale_end_key = Store::encode_temporal_key(50, &claim);
    {
        let rtxn = vault.store.env.read_txn()?;
        assert!(
            vault
                .store
                .temporal_occurred_end
                .get(&rtxn, &stale_end_key)?
                .is_some(),
            "fixture must pre-index occurred_end at ts = 50"
        );
    }

    const NOW: u64 = 555;
    vault.retract_claim(&claim, NOW)?;

    let refreshed_end_key = Store::encode_temporal_key(NOW, &claim);
    let rtxn = vault.store.env.read_txn()?;
    assert!(
        vault
            .store
            .temporal_occurred_end
            .get(&rtxn, &stale_end_key)?
            .is_none(),
        "stale occurred_end row at ts = 50 must be deleted by the refresh"
    );
    assert!(
        vault
            .store
            .temporal_occurred_end
            .get(&rtxn, &refreshed_end_key)?
            .is_some(),
        "refreshed occurred_end row at ts = 555 must be indexed"
    );
    drop(rtxn);

    let read = vault.get_claim(&claim)?.expect("retracted claim");
    assert_eq!(read.lifecycle, ClaimLifecycleStatus::Retracted);
    assert_eq!(read.valid_to, Some(NOW));
    Ok(())
}

#[test]
fn supersede_claim_rehomes_temporal_long_interval_row() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let subject = EntityId::now();
    vault.put_entity(&subject, 4, test_time_range(1, 1), 1, b"person")?;

    // Span > LONG_INTERVAL_THRESHOLD_SECS: the old claim owns a
    // temporal_long_intervals row keyed by occurred_end, value =
    // occurred_start u64 BE.
    let old_end = 1_000 + crate::batch::LONG_INTERVAL_THRESHOLD_SECS + 10;
    let old = put_active_interval_claim(
        &vault,
        &subject,
        "profile.lives_in",
        "osaka",
        test_time_range(1_000, old_end),
        1_000,
    )?;
    let new = put_active_claim(&vault, &subject, "profile.lives_in", "tokyo", 22)?;

    let stale_key = Store::encode_temporal_key(old_end, &old);
    {
        let rtxn = vault.store.env.read_txn()?;
        let value = vault
            .store
            .temporal_long_intervals
            .get(&rtxn, &stale_key)?
            .ok_or(Error::EntityNotFound)?;
        assert_eq!(
            u64::from_be_bytes(value.try_into().map_err(|_| Error::InvalidKey)?),
            1_000,
            "fixture must pre-index the long interval (value = occurred_start BE)"
        );
    }

    // `now` keeps the refreshed window long (now − 1 000 > threshold), so
    // the long-interval row must be RE-HOMED: deleted at the stale end
    // key, re-written keyed by the refreshed occurred_end with the same
    // occurred_start value. A refresh that never touches
    // temporal_long_intervals fails both assertions.
    let now = 1_000 + 2 * crate::batch::LONG_INTERVAL_THRESHOLD_SECS;
    vault.supersede_claim(&new, &old, now)?;

    let rehomed_key = Store::encode_temporal_key(now, &old);
    let rtxn = vault.store.env.read_txn()?;
    assert!(
        vault
            .store
            .temporal_long_intervals
            .get(&rtxn, &stale_key)?
            .is_none(),
        "stale long-interval row must be deleted by the refresh"
    );
    let value = vault
        .store
        .temporal_long_intervals
        .get(&rtxn, &rehomed_key)?
        .expect("long-interval row must be re-homed to the refreshed occurred_end");
    assert_eq!(
        u64::from_be_bytes(value.try_into().map_err(|_| Error::InvalidKey)?),
        1_000,
        "re-homed long-interval value must keep occurred_start"
    );
    // The occurred_end row moves with it.
    assert!(
        vault
            .store
            .temporal_occurred_end
            .get(&rtxn, &stale_key)?
            .is_none(),
        "stale occurred_end row must be deleted by the refresh"
    );
    assert!(
        vault
            .store
            .temporal_occurred_end
            .get(&rtxn, &rehomed_key)?
            .is_some(),
        "refreshed occurred_end row must be indexed"
    );
    Ok(())
}

#[test]
fn supersede_claim_rejects_self_supersession() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let subject = EntityId::now();
    vault.put_entity(&subject, 4, test_time_range(1, 1), 1, b"person")?;
    let claim = put_active_claim(&vault, &subject, "profile.name", "Alice", 2)?;
    let before = vault.get_raw(&claim)?.expect("claim stored");

    let err = vault
        .supersede_claim(&claim, &claim, 9)
        .expect_err("self-supersession must fail");
    assert_eq!(err.kind(), ErrorKind::ClaimSelfSupersession);

    // Nothing written: body + envelope byte-identical, still active, no
    // supersedes edge (a self-loop edge would betray a partial write).
    assert_eq!(vault.get_raw(&claim)?.expect("still stored"), before);
    assert_eq!(
        vault.get_claim(&claim)?.expect("claim").lifecycle,
        ClaimLifecycleStatus::Active
    );
    assert!(
        vault
            .targets(&claim, EdgeKind::Supersedes, None)?
            .is_empty()
    );
    Ok(())
}

#[test]
fn generated_claim_cannot_supersede_user_stated_non_code_truth() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let subject = EntityId::now();
    vault.put_entity(&subject, 4, test_time_range(1, 1), 1, b"person")?;
    let old = put_active_claim_with_source(
        &vault,
        &subject,
        "profile.lives_in",
        "osaka",
        Some(ClaimSource::UserStated),
        11,
    )?;
    let new = put_active_claim_with_source_and_approval(
        &vault,
        &subject,
        "profile.lives_in",
        "tokyo",
        Some(ClaimSource::Generated),
        ClaimApprovalStatus::Proposed,
        22,
    )?;
    let old_before = vault.get_raw(&old)?.expect("old claim stored");

    let err = vault
        .supersede_claim(&new, &old, 777)
        .expect_err("generated non-code truth must not supersede user-stated truth");
    assert_eq!(err.kind(), ErrorKind::InvalidClaimBody);
    assert!(
        err.to_string()
            .contains("generated claim cannot supersede user-stated truth")
    );
    assert_eq!(
        vault.get_raw(&old)?.expect("old claim still stored"),
        old_before
    );
    assert_eq!(
        vault.get_claim(&old)?.expect("old claim").lifecycle,
        ClaimLifecycleStatus::Active
    );
    assert!(vault.targets(&new, EdgeKind::Supersedes, None)?.is_empty());
    Ok(())
}

#[test]
fn claim_lifecycle_ops_reject_non_claims_and_missing_ids() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let subject = EntityId::now();
    vault.put_entity(&subject, 4, test_time_range(1, 1), 1, b"person")?;
    let claim = put_active_claim(&vault, &subject, "profile.name", "Alice", 2)?;
    let before = vault.get_raw(&claim)?.expect("claim stored");

    // Non-claim id in either position → typed InvalidClaimBody.
    let err = vault
        .supersede_claim(&claim, &subject, 9)
        .expect_err("old = PERSON must fail typed");
    assert_eq!(err.kind(), ErrorKind::InvalidClaimBody);
    let err = vault
        .supersede_claim(&subject, &claim, 9)
        .expect_err("new = PERSON must fail typed");
    assert_eq!(err.kind(), ErrorKind::InvalidClaimBody);
    let err = vault
        .retract_claim(&subject, 9)
        .expect_err("retracting a PERSON must fail typed");
    assert_eq!(err.kind(), ErrorKind::InvalidClaimBody);

    // Missing id in either position → typed EntityNotFound.
    let ghost = seeded_entity_id(0x1108);
    let err = vault
        .supersede_claim(&ghost, &claim, 9)
        .expect_err("missing new id must fail typed");
    assert_eq!(err.kind(), ErrorKind::EntityNotFound);
    let err = vault
        .supersede_claim(&claim, &ghost, 9)
        .expect_err("missing old id must fail typed");
    assert_eq!(err.kind(), ErrorKind::EntityNotFound);
    let err = vault
        .retract_claim(&ghost, 9)
        .expect_err("retracting a missing id must fail typed");
    assert_eq!(err.kind(), ErrorKind::EntityNotFound);

    // Nothing was written by any failed attempt.
    assert_eq!(vault.get_raw(&claim)?.expect("still stored"), before);
    assert_eq!(
        vault.get_claim(&claim)?.expect("claim").lifecycle,
        ClaimLifecycleStatus::Active
    );
    assert!(
        vault
            .targets(&claim, EdgeKind::Supersedes, None)?
            .is_empty()
    );
    assert!(
        vault
            .targets(&subject, EdgeKind::Supersedes, None)?
            .is_empty()
    );
    assert_no_entity_state(&vault, &ghost)?;
    Ok(())
}

#[test]
fn claim_lifecycle_ops_reject_already_closed_claims() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let subject = EntityId::now();
    vault.put_entity(&subject, 4, test_time_range(1, 1), 1, b"person")?;
    let a = put_active_claim(&vault, &subject, "profile.lives_in", "osaka", 2)?;
    let b = put_active_claim(&vault, &subject, "profile.lives_in", "tokyo", 3)?;
    let c = put_active_claim(&vault, &subject, "profile.lives_in", "kyoto", 4)?;

    const T1: u64 = 100;
    const T2: u64 = 200;
    vault.supersede_claim(&b, &a, T1)?;

    // Superseding an already-superseded claim → typed already-closed; the
    // FIRST close timestamp must survive (T1, not T2).
    let err = vault
        .supersede_claim(&c, &a, T2)
        .expect_err("a is closed history");
    assert_eq!(err.kind(), ErrorKind::ClaimAlreadyClosed);
    assert_matches!(
        err,
        Error::ClaimAlreadyClosed {
            status: ClaimLifecycleStatus::Superseded
        }
    );
    let a_read = vault.get_claim(&a)?.expect("a");
    assert_eq!(
        a_read.valid_to,
        Some(T1),
        "failed supersede must not restamp `to`"
    );
    // …and the failed attempt wrote no c → a edge.
    let rtxn = vault.store.env.read_txn()?;
    assert!(
        vault
            .store
            .edges_out
            .get(&rtxn, &raw_edge_key(&c, 3, &a))?
            .is_none(),
        "failed supersede must not write a supersedes edge"
    );
    drop(rtxn);

    // Retracting a superseded claim → already-closed.
    let err = vault
        .retract_claim(&a, T2)
        .expect_err("retracting superseded must fail typed");
    assert_eq!(err.kind(), ErrorKind::ClaimAlreadyClosed);

    // Double retract → already-closed; the first timestamp survives.
    vault.retract_claim(&c, T1)?;
    let err = vault
        .retract_claim(&c, T2)
        .expect_err("double retract must fail typed");
    assert_eq!(err.kind(), ErrorKind::ClaimAlreadyClosed);
    assert_matches!(
        err,
        Error::ClaimAlreadyClosed {
            status: ClaimLifecycleStatus::Retracted
        }
    );
    assert_eq!(vault.get_claim(&c)?.expect("c").valid_to, Some(T1));

    // Superseding a retracted claim → already-closed.
    let err = vault
        .supersede_claim(&b, &c, T2)
        .expect_err("superseding retracted must fail typed");
    assert_eq!(err.kind(), ErrorKind::ClaimAlreadyClosed);

    // A closed claim cannot be the SUPERSEDING side either (fail-closed):
    // the new claim must itself be active.
    let d = put_active_claim(&vault, &subject, "profile.lives_in", "nara", 5)?;
    let err = vault
        .supersede_claim(&a, &d, T2)
        .expect_err("closed new side must fail typed");
    assert_eq!(err.kind(), ErrorKind::ClaimAlreadyClosed);
    assert_eq!(
        vault.get_claim(&d)?.expect("d").lifecycle,
        ClaimLifecycleStatus::Active
    );
    Ok(())
}

#[test]
fn claim_lifecycle_ops_reject_provenance_claims_toward_provenance_api() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let a = EntityId::now();
    let b = EntityId::now();
    vault.put_entity(&a, 4, test_time_range(1, 1), 1, b"a")?;
    vault.put_entity(&b, 4, test_time_range(1, 1), 1, b"b")?;

    // An edge.provenance Claim written through the pub(crate) reserved-
    // namespace door (the provenance unit's path).
    let prov = EntityId::now();
    // Structurally valid since ONE-1159 (the reserved door validates the
    // provenance value record + actor-class evidence).
    let prov_body = valid_provenance_claim_body(a, a, b);
    let prov_bytes = crate::claim::encode_claim_body(&prov_body)?;
    vault.with_write_txn(|wtxn| {
        vault
            .batch_in()
            .put_reserved_claim(&prov, test_time_range(1, 1), 2, &prov_bytes)
            .apply(wtxn)
    })?;
    let normal = put_active_claim(&vault, &a, "profile.name", "Alice", 2)?;
    let prov_before = vault.get_raw(&prov)?.expect("prov stored");
    let normal_before = vault.get_raw(&normal)?.expect("normal stored");

    // The generic ops must NOT bypass the edge-restamp lifecycle (M2-9):
    // provenance-predicate claims are rejected typed in EVERY position,
    // and the error points at the provenance API.
    let err = vault
        .retract_claim(&prov, 9)
        .expect_err("retracting an edge.provenance claim must fail typed");
    assert_eq!(err.kind(), ErrorKind::ProvenanceClaimLifecycle);
    assert!(
        err.to_string().contains("edge-provenance lifecycle API"),
        "error must point at the provenance API: {err}"
    );

    let err = vault
        .supersede_claim(&normal, &prov, 9)
        .expect_err("old = provenance claim must fail typed");
    assert_eq!(err.kind(), ErrorKind::ProvenanceClaimLifecycle);
    let err = vault
        .supersede_claim(&prov, &normal, 9)
        .expect_err("new = provenance claim must fail typed");
    assert_eq!(err.kind(), ErrorKind::ProvenanceClaimLifecycle);

    // Nothing was written: bodies + envelopes byte-identical, lifecycle
    // untouched, no supersedes edges anywhere.
    assert_eq!(vault.get_raw(&prov)?.expect("prov"), prov_before);
    assert_eq!(vault.get_raw(&normal)?.expect("normal"), normal_before);
    assert_eq!(
        vault.get_claim(&prov)?.expect("prov").lifecycle,
        ClaimLifecycleStatus::Active
    );
    assert!(vault.targets(&prov, EdgeKind::Supersedes, None)?.is_empty());
    assert!(
        vault
            .targets(&normal, EdgeKind::Supersedes, None)?
            .is_empty()
    );
    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════
// ONE-1106: provenance retract + supersede lifecycle
// (retractionRules RETRACT / SUPERSEDE / DERIVE · D14 winner · D15 envelope)
// ═══════════════════════════════════════════════════════════════════════

/// Lifecycle fixture: PERSON + MACHINE actors and one semantic
/// `a -mentions-> b` subject edge carrying VAD.
struct LifecycleFixture {
    _dir: tempfile::TempDir,
    vault: Vault,
    person: EntityId,
    machine: EntityId,
    subject: EdgeRef,
}

fn lifecycle_fixture() -> Result<LifecycleFixture> {
    let (dir, vault) = open_test_vault();
    let person = EntityId::now();
    let machine = EntityId::now();
    let a = EntityId::now();
    let b = EntityId::now();
    vault.put_entity(&person, 4, test_time_range(1, 1), 1, b"person")?;
    vault.put_entity(
        &machine,
        ENTITY_TYPE_MACHINE,
        test_time_range(1, 1),
        1,
        b"machine",
    )?;
    vault.put_entity(&a, 4, test_time_range(1, 1), 1, b"a")?;
    vault.put_entity(&b, 4, test_time_range(1, 1), 1, b"b")?;
    let vad = Vad {
        valence: 0.25,
        arousal: 0.5,
        dominance: 0.75,
    };
    vault.put_edge_with_vad(&a, EdgeKind::Mentions, &b, 0.875, vad)?;
    Ok(LifecycleFixture {
        _dir: dir,
        vault,
        person,
        machine,
        subject: EdgeRef::new(a, EdgeKind::Mentions, b),
    })
}

#[test]
fn retract_edge_provenance_keeps_edge_and_closes_claim() -> Result<()> {
    let fx = lifecycle_fixture()?;
    let vault = &fx.vault;
    let subject = fx.subject;

    let claim_id = EntityId::now();
    let body = EdgeProvenanceClaimBody::new(fx.person, 0.75, SupersessionStatus::Confirmed);
    vault.put_edge_provenance(&claim_id, &subject, &body, EdgeActorClass::Human, 1_000)?;
    let (stamped, _) = raw_edge_values(vault, &subject)?;
    let stamped = stamped.expect("stamped edge");
    assert_eq!(stamped[24], 1, "confirmed = 1 before the retract");

    vault.retract_edge_provenance(&claim_id, 2_000)?;

    // AC1: the edge row SURVIVES — edges_out AND edges_in still return it,
    // 26 B, status byte 3. A delete-the-edge implementation FAILS here.
    let out_infos = vault.edges_out(&subject.source)?;
    let edge_out = out_infos
        .iter()
        .find(|info| info.kind == EdgeKind::Mentions && info.target == subject.target)
        .expect("edges_out must still return the retracted edge");
    let in_infos = vault.edges_in(&subject.target)?;
    let edge_in = in_infos
        .iter()
        .find(|info| info.kind == EdgeKind::Mentions && info.target == subject.source)
        .expect("edges_in must still return the retracted edge");
    let expected_flags = EdgeProvenanceFlags {
        confirmation_status: EdgeConfirmationStatus::Retracted,
        actor_class: EdgeActorClass::Human,
    };
    assert_eq!(edge_out.provenance, Some(expected_flags));
    assert_eq!(edge_in.provenance, Some(expected_flags));

    let (out, inn) = raw_edge_values(vault, &subject)?;
    let out = out.expect("edges_out row must survive retraction");
    let inn = inn.expect("edges_in row must survive retraction");
    assert_eq!(out.len(), EDGE_VALUE_SEMANTIC_PROVENANCED_LEN, "26 B kept");
    assert_eq!(out[24], 3, "retracted = 3 at offset 24");
    assert_eq!(out[25], 0, "actor_class stays the claim's own human = 0");
    assert_eq!(
        &out[..24],
        &stamped[..24],
        "weight/created_at/VAD bytes preserved verbatim"
    );
    assert_eq!(inn, out, "edges_in must mirror edges_out byte-for-byte");

    // The Claim was re-put CLOSED, not deleted: supersession_status =
    // retracted + valid_to = now in the value record, mirrored on the
    // wrapper; confidence untouched.
    let wrapper = vault
        .get_claim(&claim_id)?
        .expect("retracted claim stays readable");
    assert_eq!(wrapper.lifecycle, ClaimLifecycleStatus::Retracted);
    assert_eq!(wrapper.valid_to, Some(2_000));
    let record = decode_edge_provenance_body(&wrapper.value)?;
    assert_eq!(record.supersession_status, SupersessionStatus::Retracted);
    assert_eq!(record.valid_to, Some(2_000));
    assert_eq!(record.confidence.to_bits(), 0.75_f32.to_bits());

    // D15: envelope occurred_end refreshed u64::MAX → now; occurred_start
    // and learned_at (the D14 precedence key) never move on a lifecycle
    // re-put.
    let raw = vault.get_raw(&claim_id)?.expect("claim entity");
    assert_eq!(raw[0], 0, "claim type byte must stay 0");
    assert_eq!(
        u64::from_be_bytes(raw[1..9].try_into().expect("occurred_start")),
        1_000
    );
    assert_eq!(
        u64::from_be_bytes(raw[9..17].try_into().expect("occurred_end")),
        2_000
    );
    assert_eq!(
        u64::from_be_bytes(raw[17..25].try_into().expect("learned_at")),
        1_000
    );

    // Temporal rows follow the refreshed envelope: the u64::MAX open-end
    // sentinel row and its long-interval row are gone; the closed end
    // indexes at now.
    let rtxn = vault.store.env.read_txn()?;
    let old_end_key = Store::encode_temporal_key(u64::MAX, &claim_id);
    let new_end_key = Store::encode_temporal_key(2_000, &claim_id);
    assert!(
        vault
            .store
            .temporal_occurred_end
            .get(&rtxn, &old_end_key)?
            .is_none(),
        "open-end sentinel row must be replaced"
    );
    assert!(
        vault
            .store
            .temporal_long_intervals
            .get(&rtxn, &old_end_key)?
            .is_none(),
        "long-interval row must be dropped with the closed window"
    );
    assert!(
        vault
            .store
            .temporal_occurred_end
            .get(&rtxn, &new_end_key)?
            .is_some()
    );
    drop(rtxn);
    Ok(())
}

#[test]
fn supersede_edge_provenance_closes_prior_and_restamps_winner() -> Result<()> {
    let fx = lifecycle_fixture()?;
    let vault = &fx.vault;
    let subject = fx.subject;

    let prior = EntityId::now();
    let prior_body = EdgeProvenanceClaimBody::new(fx.person, 0.9, SupersessionStatus::Proposed);
    vault.put_edge_provenance(&prior, &subject, &prior_body, EdgeActorClass::Human, 1_000)?;
    let (before, _) = raw_edge_values(vault, &subject)?;
    let before = before.expect("stamped edge");
    assert_eq!(
        (before[24], before[25]),
        (0, 0),
        "proposed/human before the supersede"
    );

    // D14: the newer claim wins on envelope learned_at even with LOWER
    // confidence (0.2 < 0.9) — a confidence-first implementation FAILS this
    // restamp.
    let newer = EntityId::now();
    let newer_body = EdgeProvenanceClaimBody::new(fx.machine, 0.2, SupersessionStatus::Disputed);
    vault.supersede_edge_provenance(
        &prior,
        &newer,
        &subject,
        &newer_body,
        EdgeActorClass::System,
        2_000,
    )?;

    let (out, inn) = raw_edge_values(vault, &subject)?;
    let out = out.expect("edges_out row");
    assert_eq!(out.len(), EDGE_VALUE_SEMANTIC_PROVENANCED_LEN);
    assert_eq!(out[24], 2, "disputed = 2 from the newer (winner) claim");
    assert_eq!(out[25], 2, "system = 2 from the newer (winner) claim");
    assert_eq!(&out[..24], &before[..24]);
    assert_eq!(inn.as_deref(), Some(out.as_slice()));

    // The prior is CLOSED, not deleted: still readable, life = superseded,
    // valid_to = the new claim's learned_at; its supersession_status is
    // untouched (closure lives in life + the validity window — only RETRACT
    // rewrites the status).
    let closed = vault.get_claim(&prior)?.expect("prior claim readable");
    assert_eq!(closed.lifecycle, ClaimLifecycleStatus::Superseded);
    assert_eq!(closed.valid_to, Some(2_000));
    let closed_record = decode_edge_provenance_body(&closed.value)?;
    assert_eq!(closed_record.valid_to, Some(2_000));
    assert_eq!(
        closed_record.supersession_status,
        SupersessionStatus::Proposed
    );
    // Prior envelope end refreshed per D15 (was the u64::MAX sentinel).
    let raw = vault.get_raw(&prior)?.expect("prior entity");
    assert_eq!(
        u64::from_be_bytes(raw[9..17].try_into().expect("occurred_end")),
        2_000
    );

    let new_claim = vault.get_claim(&newer)?.expect("new claim");
    assert_eq!(new_claim.lifecycle, ClaimLifecycleStatus::Active);
    Ok(())
}

#[test]
fn put_edge_provenance_implicitly_closes_strictly_older_live_claims() -> Result<()> {
    let fx = lifecycle_fixture()?;
    let vault = &fx.vault;
    let subject = fx.subject;

    let older = EntityId::now();
    vault.put_edge_provenance(
        &older,
        &subject,
        &EdgeProvenanceClaimBody::new(fx.person, 0.9, SupersessionStatus::Confirmed),
        EdgeActorClass::Human,
        1_000,
    )?;

    // AC2: writing a NEWER provenance Claim for the same EdgeRef closes the
    // prior live Claim — even through the plain put API.
    let newer = EntityId::now();
    vault.put_edge_provenance(
        &newer,
        &subject,
        &EdgeProvenanceClaimBody::new(fx.person, 0.1, SupersessionStatus::Proposed),
        EdgeActorClass::Agent,
        2_000,
    )?;

    let closed = vault.get_claim(&older)?.expect("prior claim readable");
    assert_eq!(closed.lifecycle, ClaimLifecycleStatus::Superseded);
    assert_eq!(
        closed.valid_to,
        Some(2_000),
        "absent valid_to closes at the incoming learned_at"
    );

    let (out, _) = raw_edge_values(vault, &subject)?;
    let out = out.expect("edge");
    assert_eq!(
        (out[24], out[25]),
        (0, 1),
        "flags restamp from the newer claim (proposed/agent)"
    );

    // Both claims remain attached to the source entity — history is kept.
    let ids: HashSet<EntityId> = vault
        .claims_for_subject(&subject.source)?
        .into_iter()
        .collect();
    assert_eq!(ids, HashSet::from([older, newer]));
    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════
// ONE-1113: reject-and-route + operational setters + session-bound actor
// (ARCH-0034 #write-protection ruling, ratified 2026-06-13)
// ═══════════════════════════════════════════════════════════════════════

/// Asserts one rejected plain-put attempt pinned the ONE-1113 contract: the
/// typed [`Error::EdgeIsProvenanced`] variant carrying the subject kind
/// byte, with a message that ROUTES the caller to the provenance path and
/// the operational setters ("reject-and-route" — a bare reject without the
/// route is half the ruling).
fn assert_edge_is_provenanced_reject(err: &Error, expected_kind: EdgeKind, context: &str) {
    match err {
        Error::EdgeIsProvenanced { kind } => {
            assert_eq!(*kind, expected_kind as u8, "{context}: kind byte");
        }
        other => panic!("{context}: expected EdgeIsProvenanced, got {other:?}"),
    }
    assert_eq!(err.kind(), ErrorKind::EdgeIsProvenanced, "{context}");
    let message = err.to_string();
    for route in [
        "put_edge_provenance",
        "as_actor",
        "set_edge_weight",
        "set_edge_vad",
    ] {
        assert!(
            message.contains(route),
            "{context}: rejection message must route the caller via {route:?}, got {message:?}"
        );
    }
}

/// THE regression for the pinned hole (M2 adversarial verify, PR #81):
/// before ONE-1113, every plain edge put re-encoded an already-provenanced
/// edge with `provenance: None`, silently dropping the 26-byte value to
/// 24 bytes in BOTH directions while the truth Claim stayed live. Ruling
/// pt 2: typed reject, routed; both directions byte-identical; the live
/// Claim untouched. A fix that strips, preserves-silently, or rejects only
/// `put_edge` (not the batch builders) FAILS here.
#[test]
fn plain_edge_reput_on_provenanced_edge_rejects_and_routes() -> Result<()> {
    let fx = lifecycle_fixture()?;
    let vault = &fx.vault;
    let subject = fx.subject;
    let (a, b) = (subject.source, subject.target);

    let claim_id = EntityId::now();
    vault.put_edge_provenance(
        &claim_id,
        &subject,
        &EdgeProvenanceClaimBody::new(fx.person, 0.75, SupersessionStatus::Confirmed),
        EdgeActorClass::Human,
        1_000,
    )?;
    let (before_out, before_in) = raw_edge_values(vault, &subject)?;
    let before_out = before_out.expect("provenanced edge");
    assert_eq!(before_out.len(), EDGE_VALUE_SEMANTIC_PROVENANCED_LEN);
    assert_eq!(before_in.as_deref(), Some(before_out.as_slice()));

    let vad = Vad {
        valence: 0.1,
        arousal: 0.2,
        dominance: 0.3,
    };
    // Every public plain-put surface the ruling names: the typed vault API,
    // both batch-builder flavors, and the txn-builder flavor.
    let attempts: Vec<(&str, Error)> = vec![
        (
            "put_edge",
            vault
                .put_edge(&a, EdgeKind::Mentions, &b, 0.5)
                .expect_err("put_edge must reject"),
        ),
        (
            "put_edge_with_vad",
            vault
                .put_edge_with_vad(&a, EdgeKind::Mentions, &b, 0.5, vad)
                .expect_err("put_edge_with_vad must reject"),
        ),
        (
            "batch().edge()",
            vault
                .batch()
                .edge(&a, EdgeKind::Mentions, &b, 0.5)
                .commit()
                .expect_err("batch edge must reject"),
        ),
        (
            "batch().edge_with_vad()",
            vault
                .batch()
                .edge_with_vad(&a, EdgeKind::Mentions, &b, 0.5, vad)
                .commit()
                .expect_err("batch edge_with_vad must reject"),
        ),
        (
            "batch_in().edge()",
            vault
                .with_write_txn(|wtxn| {
                    vault
                        .batch_in()
                        .edge(&a, EdgeKind::Mentions, &b, 0.5)
                        .apply(wtxn)
                })
                .expect_err("txn-builder edge must reject"),
        ),
    ];
    for (context, err) in &attempts {
        assert_edge_is_provenanced_reject(err, EdgeKind::Mentions, context);
    }

    // Atomicity: a batch mixing a VALID entity put with the offending edge
    // op aborts wholesale — the put must not survive the rejected commit.
    let orphan = EntityId::now();
    let err = vault
        .batch()
        .put(&orphan, 4, test_time_range(1, 1), 1, b"rider")
        .edge(&a, EdgeKind::Mentions, &b, 0.5)
        .commit()
        .expect_err("mixed batch must reject");
    assert_edge_is_provenanced_reject(&err, EdgeKind::Mentions, "mixed batch");
    assert!(
        vault.get_raw(&orphan)?.is_none(),
        "a rejected batch must not leak its rider put"
    );

    // Both directions byte-identical to the pre-attempt 26-byte value.
    let (after_out, after_in) = raw_edge_values(vault, &subject)?;
    assert_eq!(
        after_out.as_deref(),
        Some(before_out.as_slice()),
        "edges_out must stay byte-identical after every rejected put"
    );
    assert_eq!(
        after_in.as_deref(),
        Some(before_out.as_slice()),
        "edges_in must stay byte-identical after every rejected put"
    );

    // The live Claim is untouched truth.
    let claim = vault.get_claim(&claim_id)?.expect("claim readable");
    assert_eq!(claim.lifecycle, ClaimLifecycleStatus::Active);
    assert_eq!(
        decode_edge_provenance_body(&claim.value)?.supersession_status,
        SupersessionStatus::Confirmed
    );

    // Ruling pt 1 (positive control): a plain put on a NON-provenanced edge
    // is unchanged — absence of provenance is itself the anonymous
    // representation. Re-put a bare edge and a structural edge freely.
    let c = EntityId::now();
    vault.put_entity(&c, 4, test_time_range(1, 1), 1, b"c")?;
    vault.put_edge(&a, EdgeKind::About, &c, 0.25)?;
    vault.put_edge(&a, EdgeKind::About, &c, 0.75)?;
    let bare = EdgeRef::new(a, EdgeKind::About, c);
    let (out, inn) = raw_edge_values(vault, &bare)?;
    let out = out.expect("bare edge");
    assert_eq!(out.len(), EDGE_VALUE_SEMANTIC_LEN, "bare re-put stays 24 B");
    assert_eq!(&out[0..4], &0.75_f32.to_le_bytes(), "re-put weight applied");
    assert_eq!(inn.as_deref(), Some(out.as_slice()));
    vault.put_edge(&a, EdgeKind::BelongsTo, &c, 0.5)?;
    vault.put_edge(&a, EdgeKind::BelongsTo, &c, 0.9)?;
    Ok(())
}

/// ONE-1113 operational weight setter (ruling pt 5, M3 weight pin): the
/// carve-out rewrites ONLY bytes 0..4, preserves `created_at` + VAD + the
/// two hot-flag bytes verbatim on a 26-byte value, mirrors both directions,
/// never touches the Claim, and invalidates the endpoint PPR caches like
/// any edge write. An implementation that re-encodes the value (dropping
/// flags) or skips the reverse row FAILS here.
#[test]
fn set_edge_weight_rewrites_only_weight_bytes_and_preserves_provenance() -> Result<()> {
    let fx = lifecycle_fixture()?;
    let vault = &fx.vault;
    let subject = fx.subject;
    let (a, b) = (subject.source, subject.target);

    let claim_id = EntityId::now();
    vault.put_edge_provenance(
        &claim_id,
        &subject,
        &EdgeProvenanceClaimBody::new(fx.person, 0.75, SupersessionStatus::Confirmed),
        EdgeActorClass::Human,
        1_000,
    )?;
    let (before, _) = raw_edge_values(vault, &subject)?;
    let before = before.expect("provenanced edge");
    assert_eq!(before.len(), EDGE_VALUE_SEMANTIC_PROVENANCED_LEN);

    // Plant malformed PPR cache rows keyed to both endpoints so the
    // invalidation is observable (the same oracle as the ONE-1105 test).
    let src_hash = [0xB1_u8; 16];
    let tgt_hash = [0xB2_u8; 16];
    {
        let mut wtxn = vault.store.env.write_txn()?;
        let mut src_dep = [0_u8; 32];
        src_dep[..16].copy_from_slice(a.as_bytes());
        src_dep[16..].copy_from_slice(&src_hash);
        let mut tgt_dep = [0_u8; 32];
        tgt_dep[..16].copy_from_slice(b.as_bytes());
        tgt_dep[16..].copy_from_slice(&tgt_hash);
        vault
            .store
            .ppr_cache
            .put(&mut wtxn, &src_hash, &[1, 2, 3])?;
        vault
            .store
            .ppr_cache
            .put(&mut wtxn, &tgt_hash, &[1, 2, 3])?;
        vault.store.ppr_cache_deps.put(&mut wtxn, &src_dep, &[])?;
        vault.store.ppr_cache_deps.put(&mut wtxn, &tgt_dep, &[])?;
        wtxn.commit()?;
    }

    vault.set_edge_weight(&a, EdgeKind::Mentions, &b, 0.42)?;

    let (out, inn) = raw_edge_values(vault, &subject)?;
    let out = out.expect("edge survives");
    assert_eq!(out.len(), EDGE_VALUE_SEMANTIC_PROVENANCED_LEN);
    assert_eq!(
        &out[0..4],
        &0.42_f32.to_le_bytes(),
        "weight bytes rewritten"
    );
    assert_eq!(
        &out[4..],
        &before[4..],
        "created_at + VAD + hot-flag bytes (incl. 24/25) preserved verbatim"
    );
    assert_eq!(inn.as_deref(), Some(out.as_slice()), "both directions");
    {
        let rtxn = vault.store.env.read_txn()?;
        assert!(
            vault.store.ppr_cache.get(&rtxn, &src_hash)?.is_none(),
            "source-endpoint PPR cache must be invalidated"
        );
        assert!(
            vault.store.ppr_cache.get(&rtxn, &tgt_hash)?.is_none(),
            "target-endpoint PPR cache must be invalidated"
        );
    }
    // The truth Claim is untouched by the operational setter.
    let claim = vault.get_claim(&claim_id)?.expect("claim readable");
    assert_eq!(claim.lifecycle, ClaimLifecycleStatus::Active);

    // Contract [0, 1] + finiteness — typed reject, value unchanged.
    for bad in [1.5_f32, -0.1, f32::NAN] {
        let err = vault
            .set_edge_weight(&a, EdgeKind::Mentions, &b, bad)
            .expect_err("out-of-contract weight must reject");
        assert_eq!(err.kind(), ErrorKind::InvalidEdgeWeight, "weight {bad}");
    }
    let (unchanged, _) = raw_edge_values(vault, &subject)?;
    assert_eq!(unchanged.as_deref(), Some(out.as_slice()));

    // Never an upsert: a missing edge is the typed EdgeNotFound.
    let ghost = EntityId::now();
    let err = vault
        .set_edge_weight(&a, EdgeKind::Mentions, &ghost, 0.5)
        .expect_err("missing edge must reject");
    assert_eq!(err.kind(), ErrorKind::EdgeNotFound);

    // Weight lives at offset 0 on ALL layouts: a structural 12-byte edge is
    // settable and KEEPS its 12-byte layout.
    vault.put_edge(&a, EdgeKind::BelongsTo, &b, 0.5)?;
    vault.set_edge_weight(&a, EdgeKind::BelongsTo, &b, 0.125)?;
    let structural = EdgeRef::new(a, EdgeKind::BelongsTo, b);
    let (out, inn) = raw_edge_values(vault, &structural)?;
    let out = out.expect("structural edge");
    assert_eq!(out.len(), EDGE_VALUE_STRUCTURAL_LEN);
    assert_eq!(&out[0..4], &0.125_f32.to_le_bytes());
    assert_eq!(inn.as_deref(), Some(out.as_slice()));
    Ok(())
}

/// ONE-1113 operational VAD setter: rewrites ONLY bytes 12..24, preserves
/// weight/`created_at`/length (24 B stays 24 B; a 26-byte value keeps its
/// hot-flag bytes), mirrors both directions, and rejects structural
/// 12-byte kinds typed — the contract layout table gives them no VAD.
#[test]
fn set_edge_vad_rewrites_only_vad_bytes_and_preserves_layout() -> Result<()> {
    let fx = lifecycle_fixture()?;
    let vault = &fx.vault;
    let subject = fx.subject;
    let (a, b) = (subject.source, subject.target);

    // Component ranges are the pinned VAD contract: valence ∈ [-1, 1],
    // arousal/dominance ∈ [0, 1].
    let new_vad = Vad {
        valence: -0.5,
        arousal: 0.25,
        dominance: 0.875,
    };

    // 24-byte bare edge: VAD bytes rewritten in place, length preserved.
    let (before, _) = raw_edge_values(vault, &subject)?;
    let before = before.expect("bare fixture edge");
    assert_eq!(before.len(), EDGE_VALUE_SEMANTIC_LEN);
    vault.set_edge_vad(&a, EdgeKind::Mentions, &b, new_vad)?;
    let (out, inn) = raw_edge_values(vault, &subject)?;
    let out = out.expect("edge survives");
    assert_eq!(out.len(), EDGE_VALUE_SEMANTIC_LEN, "24 B stays 24 B");
    assert_eq!(&out[0..12], &before[0..12], "weight + created_at preserved");
    assert_eq!(&out[12..16], &(-0.5_f32).to_le_bytes());
    assert_eq!(&out[16..20], &0.25_f32.to_le_bytes());
    assert_eq!(&out[20..24], &0.875_f32.to_le_bytes());
    assert_eq!(inn.as_deref(), Some(out.as_slice()), "both directions");

    // 26-byte provenanced edge: hot-flag bytes 24/25 preserved verbatim.
    let claim_id = EntityId::now();
    vault.put_edge_provenance(
        &claim_id,
        &subject,
        &EdgeProvenanceClaimBody::new(fx.person, 0.75, SupersessionStatus::Disputed),
        EdgeActorClass::Agent,
        1_000,
    )?;
    let (stamped, _) = raw_edge_values(vault, &subject)?;
    let stamped = stamped.expect("stamped edge");
    assert_eq!(stamped.len(), EDGE_VALUE_SEMANTIC_PROVENANCED_LEN);
    vault.set_edge_vad(&a, EdgeKind::Mentions, &b, Vad::NEUTRAL)?;
    let (out, inn) = raw_edge_values(vault, &subject)?;
    let out = out.expect("edge survives");
    assert_eq!(out.len(), EDGE_VALUE_SEMANTIC_PROVENANCED_LEN);
    assert_eq!(&out[0..12], &stamped[0..12]);
    assert_eq!(&out[12..24], &[0_u8; 12][..], "VAD reset to NEUTRAL");
    assert_eq!(
        &out[24..26],
        &stamped[24..26],
        "hot-flag bytes (disputed=2, agent=1) must survive the VAD rewrite"
    );
    assert_eq!(inn.as_deref(), Some(out.as_slice()));
    assert_eq!(
        vault.get_claim(&claim_id)?.expect("claim").lifecycle,
        ClaimLifecycleStatus::Active,
        "the operational setter never touches the Claim"
    );

    // Structural kinds carry no VAD — typed reject, nothing written.
    vault.put_edge(&a, EdgeKind::BelongsTo, &b, 0.5)?;
    let err = vault
        .set_edge_vad(&a, EdgeKind::BelongsTo, &b, new_vad)
        .expect_err("structural VAD set must reject");
    assert_eq!(err.kind(), ErrorKind::InvariantViolation);
    assert!(
        err.to_string()
            .contains("structural edges do not carry VAD"),
        "got {err:?}"
    );
    let structural = EdgeRef::new(a, EdgeKind::BelongsTo, b);
    let (out, _) = raw_edge_values(vault, &structural)?;
    assert_eq!(
        out.expect("structural edge").len(),
        EDGE_VALUE_STRUCTURAL_LEN
    );

    // Component validation + never-upsert. NaN and the asymmetric range
    // pins (valence [-1, 1] admits -1; arousal [0, 1] rejects it).
    let err = vault
        .set_edge_vad(
            &a,
            EdgeKind::Mentions,
            &b,
            Vad {
                valence: f32::NAN,
                arousal: 0.0,
                dominance: 0.0,
            },
        )
        .expect_err("NaN VAD must reject");
    assert_eq!(err.kind(), ErrorKind::InvalidVad);
    let err = vault
        .set_edge_vad(
            &a,
            EdgeKind::Mentions,
            &b,
            Vad {
                valence: -1.0,
                arousal: -0.25,
                dominance: 0.0,
            },
        )
        .expect_err("arousal below [0, 1] must reject");
    assert!(
        matches!(
            err,
            Error::InvalidVad {
                component: VadComponent::Arousal,
                ..
            }
        ),
        "got {err:?}"
    );
    let ghost = EntityId::now();
    let err = vault
        .set_edge_vad(&a, EdgeKind::Mentions, &ghost, new_vad)
        .expect_err("missing edge must reject");
    assert_eq!(err.kind(), ErrorKind::EdgeNotFound);
    Ok(())
}

/// ONE-1113 batch forms (the decay / retrieval-feedback loop idiom): both
/// setters compose in one atomic batch, and one failing op aborts the WHOLE
/// transaction — staged sibling rewrites must not survive a rejected
/// commit.
#[test]
fn batch_set_edge_weight_and_vad_forms_apply_atomically() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let a = EntityId::now();
    let b = EntityId::now();
    let c = EntityId::now();
    vault.put_entity(&a, 4, test_time_range(1, 1), 1, b"a")?;
    vault.put_entity(&b, 4, test_time_range(1, 1), 1, b"b")?;
    vault.put_entity(&c, 4, test_time_range(1, 1), 1, b"c")?;
    vault.put_edge(&a, EdgeKind::Mentions, &b, 0.875)?;
    vault.put_edge(&a, EdgeKind::About, &c, 0.5)?;

    let vad = Vad {
        valence: 0.5,
        arousal: 0.25,
        dominance: 0.75,
    };
    vault
        .batch()
        .set_edge_weight(&a, EdgeKind::Mentions, &b, 0.4375)
        .set_edge_vad(&a, EdgeKind::About, &c, vad)
        .commit()?;
    let (mentions, _) = raw_edge_values(&vault, &EdgeRef::new(a, EdgeKind::Mentions, b))?;
    let mentions = mentions.expect("mentions edge");
    assert_eq!(&mentions[0..4], &0.4375_f32.to_le_bytes());
    let (about, _) = raw_edge_values(&vault, &EdgeRef::new(a, EdgeKind::About, c))?;
    let about = about.expect("about edge");
    assert_eq!(&about[12..16], &0.5_f32.to_le_bytes());
    assert_eq!(&about[16..20], &0.25_f32.to_le_bytes());

    // Atomicity: the second op targets a missing edge — the whole batch
    // aborts and the FIRST op's staged rewrite is discarded.
    let ghost = EntityId::now();
    let err = vault
        .batch()
        .set_edge_weight(&a, EdgeKind::Mentions, &b, 0.9)
        .set_edge_weight(&a, EdgeKind::Mentions, &ghost, 0.5)
        .commit()
        .expect_err("batch with a missing-edge op must reject");
    assert_eq!(err.kind(), ErrorKind::EdgeNotFound);
    let (mentions, _) = raw_edge_values(&vault, &EdgeRef::new(a, EdgeKind::Mentions, b))?;
    assert_eq!(
        &mentions.expect("mentions edge")[0..4],
        &0.4375_f32.to_le_bytes(),
        "a rejected batch must not leak its sibling weight rewrite"
    );
    Ok(())
}

/// ONE-1113 session-bound actor handle (ruling pt 4): bind the actor once,
/// write normally — the handle injects `actor_entity_ref` + `actor_class`
/// into the provenance path; a conflicting body actor is rejected typed
/// (never silently rewritten); the full gate chain (D13 class validation,
/// implicit supersession, winner restamp) still runs underneath.
#[test]
fn as_actor_bound_write_carries_bound_actor_and_rejects_conflicts() -> Result<()> {
    let fx = lifecycle_fixture()?;
    let vault = &fx.vault;
    let subject = fx.subject;

    let bound = vault.as_actor(fx.person, EdgeActorClass::Human);
    assert_eq!(bound.actor(), fx.person);
    assert_eq!(bound.actor_class(), EdgeActorClass::Human);

    // Bound write: the Claim carries the BOUND actor and the edge restamps
    // (confirmed = 1, human = 0) — composed with main's current actor shape
    // (the caller-supplied class parameter, persisted by the engine).
    let claim_id = EntityId::now();
    let body = bound.provenance_body(0.8, SupersessionStatus::Confirmed);
    bound.put_edge_provenance(&claim_id, &subject, &body, 1_000)?;
    let claim = vault.get_claim(&claim_id)?.expect("bound claim");
    assert_eq!(claim.lifecycle, ClaimLifecycleStatus::Active);
    assert_eq!(
        decode_edge_provenance_body(&claim.value)?.actor_entity_ref,
        fx.person,
        "the bound write must carry the bound actor_entity_ref"
    );
    let (out, inn) = raw_edge_values(vault, &subject)?;
    let out = out.expect("stamped edge");
    assert_eq!(out.len(), EDGE_VALUE_SEMANTIC_PROVENANCED_LEN);
    assert_eq!((out[24], out[25]), (1, 0), "confirmed/human stamp");
    assert_eq!(inn.as_deref(), Some(out.as_slice()));

    // Ruling pt 3 through the handle: a NEWER bound write modifies via the
    // supersession chain — the prior closes, history kept, flags restamp.
    let claim2 = EntityId::now();
    let body2 = bound.provenance_body(0.6, SupersessionStatus::Disputed);
    bound.put_edge_provenance(&claim2, &subject, &body2, 2_000)?;
    assert_eq!(
        vault.get_claim(&claim_id)?.expect("prior").lifecycle,
        ClaimLifecycleStatus::Superseded,
        "modification flows as a supersession chain (retraction is not excision)"
    );
    let (out, _) = raw_edge_values(vault, &subject)?;
    let out = out.expect("edge");
    assert_eq!(
        (out[24], out[25]),
        (2, 0),
        "flags restamp from the newer bound claim (disputed/human)"
    );

    // Fail-closed binding: a body naming a DIFFERENT actor is rejected
    // typed — the handle injects, it never silently rewrites.
    let conflicting = EdgeProvenanceClaimBody::new(fx.machine, 0.9, SupersessionStatus::Confirmed);
    let stray = EntityId::now();
    let err = bound
        .put_edge_provenance(&stray, &subject, &conflicting, 3_000)
        .expect_err("conflicting body actor must reject");
    assert!(
        matches!(
            &err,
            Error::InvalidProvenanceBody(msg)
                if msg.contains("session-bound actor")
        ),
        "got {err:?}"
    );
    assert!(
        vault.get_raw(&stray)?.is_none(),
        "a rejected bound write must store nothing"
    );

    // The handle is ergonomics, NOT authorization: D13 still validates the
    // bound class against the actor entity's kind underneath.
    let mismatched = vault.as_actor(fx.machine, EdgeActorClass::Human);
    let stray2 = EntityId::now();
    let body3 = mismatched.provenance_body(0.9, SupersessionStatus::Confirmed);
    let err = mismatched
        .put_edge_provenance(&stray2, &subject, &body3, 3_000)
        .expect_err("MACHINE+human must fail D13 through the handle");
    assert_eq!(err.kind(), ErrorKind::ActorClassMismatch);
    Ok(())
}

#[test]
fn multi_claim_winner_and_retract_refresh_to_runner_up() -> Result<()> {
    let fx = lifecycle_fixture()?;
    let vault = &fx.vault;
    let subject = fx.subject;
    // Distinct actor entity (PERSON) for the runner-up so the actor_class
    // refresh is observable on byte 25.
    let person2 = EntityId::now();
    vault.put_entity(&person2, 4, test_time_range(1, 1), 1, b"person2")?;

    // c1 @ t1 — auto-superseded once the t2 cohort lands.
    let c1 = EntityId::now();
    vault.put_edge_provenance(
        &c1,
        &subject,
        &EdgeProvenanceClaimBody::new(fx.person, 0.9, SupersessionStatus::Proposed),
        EdgeActorClass::Human,
        1_000,
    )?;
    // c2 @ t2, conf 0.6 — the winner.
    let c2 = EntityId::now();
    vault.put_edge_provenance(
        &c2,
        &subject,
        &EdgeProvenanceClaimBody::new(fx.machine, 0.6, SupersessionStatus::Confirmed),
        EdgeActorClass::System,
        2_000,
    )?;
    // c3 @ t2, conf 0.4 — learned_at TIE with c2, broken by confidence: c3
    // coexists live but the stamp stays c2's. A stamp-the-newest-write
    // implementation FAILS these assertions.
    let c3 = EntityId::now();
    vault.put_edge_provenance(
        &c3,
        &subject,
        &EdgeProvenanceClaimBody::new(person2, 0.4, SupersessionStatus::Disputed),
        EdgeActorClass::Agent,
        2_000,
    )?;

    let (out, _) = raw_edge_values(vault, &subject)?;
    let out = out.expect("edge");
    assert_eq!(
        (out[24], out[25]),
        (1, 2),
        "winner = c2 (confirmed/system): the t2 tie is broken by confidence 0.6 > 0.4"
    );

    // Lifecycles: c1 superseded by the t2 cohort; c2 and c3 BOTH live.
    assert_eq!(
        vault.get_claim(&c1)?.expect("c1").lifecycle,
        ClaimLifecycleStatus::Superseded
    );
    assert_eq!(
        vault.get_claim(&c2)?.expect("c2").lifecycle,
        ClaimLifecycleStatus::Active
    );
    assert_eq!(
        vault.get_claim(&c3)?.expect("c3").lifecycle,
        ClaimLifecycleStatus::Active
    );

    // AC4: retract the WINNER → flags refresh to the RUNNER-UP c3
    // (disputed = 2, agent = 1) — and NOT to the closed c1 even though its
    // confidence (0.9) is the highest on record: closed claims never win.
    vault.retract_edge_provenance(&c2, 3_000)?;
    let (out, inn) = raw_edge_values(vault, &subject)?;
    let out = out.expect("edge survives");
    assert_eq!(out.len(), EDGE_VALUE_SEMANTIC_PROVENANCED_LEN);
    assert_eq!(
        (out[24], out[25]),
        (2, 1),
        "runner-up c3 (disputed/agent) must stamp after the winner's retraction"
    );
    assert_eq!(inn.as_deref(), Some(out.as_slice()));

    // Retract the last live claim → zero live: the contract's retracted
    // stamp (3) with the retracted claim's own persisted actor class.
    vault.retract_edge_provenance(&c3, 4_000)?;
    let (out, inn) = raw_edge_values(vault, &subject)?;
    let out = out.expect("edge survives full retraction");
    assert_eq!(out.len(), EDGE_VALUE_SEMANTIC_PROVENANCED_LEN);
    assert_eq!(
        (out[24], out[25]),
        (3, 1),
        "no live claims: retracted = 3 with c3's agent class"
    );
    assert_eq!(inn.as_deref(), Some(out.as_slice()));

    // History: all three claims remain readable — never deleted.
    let ids: HashSet<EntityId> = vault
        .claims_for_subject(&subject.source)?
        .into_iter()
        .collect();
    assert_eq!(ids, HashSet::from([c1, c2, c3]));
    Ok(())
}

#[test]
fn provenance_lifecycle_negative_paths_fail_closed() -> Result<()> {
    let fx = lifecycle_fixture()?;
    let vault = &fx.vault;
    let subject = fx.subject;

    // A live claim to act against.
    let live = EntityId::now();
    vault.put_edge_provenance(
        &live,
        &subject,
        &EdgeProvenanceClaimBody::new(fx.person, 0.8, SupersessionStatus::Confirmed),
        EdgeActorClass::Human,
        2_000,
    )?;
    let (stamped, _) = raw_edge_values(vault, &subject)?;
    let stamped = stamped.expect("stamped edge");
    let live_before = vault.get_claim(&live)?.expect("live claim");
    let fresh_body = EdgeProvenanceClaimBody::new(fx.person, 0.5, SupersessionStatus::Proposed);

    // Retract: missing claim id → EntityNotFound.
    let err = vault
        .retract_edge_provenance(&seeded_entity_id(0xF00D), 3_000)
        .expect_err("missing claim must be rejected");
    assert_eq!(err.kind(), ErrorKind::EntityNotFound);

    // Retract on a non-claim entity (PERSON, type 4) → NotAProvenanceClaim.
    let err = vault
        .retract_edge_provenance(&fx.person, 3_000)
        .expect_err("a PERSON entity is not a provenance claim");
    assert_eq!(err.kind(), ErrorKind::NotAProvenanceClaim);

    // Retract on an ORDINARY claim (wrong predicate) → NotAProvenanceClaim;
    // the claim body is untouched.
    let ordinary = EntityId::now();
    let ordinary_body = ClaimBody::new(
        "hobby.collects",
        ClaimSubject::Entity(fx.person),
        rmpv::Value::from("stamps"),
        0.9,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
    );
    vault.put_claim(&ordinary, &ordinary_body, test_time_range(5, 5), 5)?;
    let err = vault
        .retract_edge_provenance(&ordinary, 3_000)
        .expect_err("ordinary claims must be rejected");
    assert_eq!(err.kind(), ErrorKind::NotAProvenanceClaim);
    assert_eq!(
        vault.get_claim(&ordinary)?.expect("ordinary claim intact"),
        ordinary_body
    );

    // Supersede with an ordinary-claim prior → NotAProvenanceClaim; the new
    // claim must not exist afterwards.
    let new_id = EntityId::now();
    let err = vault
        .supersede_edge_provenance(
            &ordinary,
            &new_id,
            &subject,
            &fresh_body,
            EdgeActorClass::Human,
            3_000,
        )
        .expect_err("ordinary prior must be rejected");
    assert_eq!(err.kind(), ErrorKind::NotAProvenanceClaim);
    assert_no_entity_state(vault, &new_id)?;

    // SUBJECT MISMATCH (AC3): the prior names a DIFFERENT EdgeRef than the
    // supersede call → typed; nothing written, prior untouched.
    let c = EntityId::now();
    vault.put_entity(&c, 4, test_time_range(1, 1), 1, b"c")?;
    vault.put_edge(&subject.source, EdgeKind::About, &c, 0.5)?;
    let other_subject = EdgeRef::new(subject.source, EdgeKind::About, c);
    let (other_before, _) = raw_edge_values(vault, &other_subject)?;
    let new_id = EntityId::now();
    let err = vault
        .supersede_edge_provenance(
            &live,
            &new_id,
            &other_subject,
            &fresh_body,
            EdgeActorClass::Human,
            3_000,
        )
        .expect_err("prior addressing a different EdgeRef must be rejected");
    assert_eq!(err.kind(), ErrorKind::ProvenanceSubjectMismatch);
    assert_no_entity_state(vault, &new_id)?;
    assert_eq!(
        vault.get_claim(&live)?.expect("live untouched"),
        live_before
    );
    let (other_after, _) = raw_edge_values(vault, &other_subject)?;
    assert_eq!(
        other_after, other_before,
        "the mismatched-subject edge must be untouched"
    );

    // Double-retract → ProvenanceClaimAlreadyClosed; the FIRST close wins.
    vault.retract_edge_provenance(&live, 3_000)?;
    let err = vault
        .retract_edge_provenance(&live, 4_000)
        .expect_err("double retract must be rejected");
    assert_eq!(err.kind(), ErrorKind::ProvenanceClaimAlreadyClosed);
    let after = vault.get_claim(&live)?.expect("claim");
    assert_eq!(
        after.valid_to,
        Some(3_000),
        "a rejected second retract must not move the close instant"
    );
    assert_eq!(after.lifecycle, ClaimLifecycleStatus::Retracted);

    // Supersede a CLOSED prior → ProvenanceClaimAlreadyClosed; nothing
    // written.
    let new_id = EntityId::now();
    let err = vault
        .supersede_edge_provenance(
            &live,
            &new_id,
            &subject,
            &fresh_body,
            EdgeActorClass::Human,
            5_000,
        )
        .expect_err("closed prior must be rejected");
    assert_eq!(err.kind(), ErrorKind::ProvenanceClaimAlreadyClosed);
    assert_no_entity_state(vault, &new_id)?;

    // D14 precedence: an incoming claim OLDER than the live frontier is
    // rejected with the exact typed payload, on BOTH the implicit put path
    // and the explicit supersede path.
    let c4 = EntityId::now();
    vault.put_edge_provenance(
        &c4,
        &subject,
        &EdgeProvenanceClaimBody::new(fx.person, 0.7, SupersessionStatus::Confirmed),
        EdgeActorClass::Human,
        6_000,
    )?;
    let new_id = EntityId::now();
    let err = vault
        .put_edge_provenance(&new_id, &subject, &fresh_body, EdgeActorClass::Human, 5_000)
        .expect_err("older-than-frontier put must be rejected");
    let Error::ProvenancePrecedenceViolation {
        incoming_learned_at,
        frontier_learned_at,
    } = err
    else {
        panic!("expected ProvenancePrecedenceViolation, got {err:?}");
    };
    assert_eq!(incoming_learned_at, 5_000);
    assert_eq!(frontier_learned_at, 6_000);
    assert_no_entity_state(vault, &new_id)?;
    let err = vault
        .supersede_edge_provenance(
            &c4,
            &new_id,
            &subject,
            &fresh_body,
            EdgeActorClass::Human,
            5_000,
        )
        .expect_err("older-than-prior explicit supersede must be rejected");
    assert_eq!(err.kind(), ErrorKind::ProvenancePrecedenceViolation);
    assert_no_entity_state(vault, &new_id)?;

    // Self-supersession → typed; the claim stays live.
    let err = vault
        .supersede_edge_provenance(
            &c4,
            &c4,
            &subject,
            &fresh_body,
            EdgeActorClass::Human,
            7_000,
        )
        .expect_err("self supersession must be rejected");
    assert_eq!(err.kind(), ErrorKind::ProvenanceSelfSupersession);
    assert_eq!(
        vault.get_claim(&c4)?.expect("c4").lifecycle,
        ClaimLifecycleStatus::Active
    );

    // Retract BEFORE valid_from would invert the validity window → typed
    // InvalidProvenanceBody, never silently reordered; claim untouched.
    let future = EntityId::now();
    let mut future_body =
        EdgeProvenanceClaimBody::new(fx.person, 0.6, SupersessionStatus::Proposed);
    future_body.valid_from = Some(9_000);
    vault.put_edge_provenance(
        &future,
        &subject,
        &future_body,
        EdgeActorClass::Human,
        6_000,
    )?;
    let err = vault
        .retract_edge_provenance(&future, 8_000)
        .expect_err("retract before valid_from must be rejected");
    assert_eq!(err.kind(), ErrorKind::InvalidProvenanceBody);
    let intact = vault.get_claim(&future)?.expect("future claim intact");
    assert_eq!(intact.lifecycle, ClaimLifecycleStatus::Active);
    assert_eq!(
        decode_edge_provenance_body(&intact.value)?.supersession_status,
        SupersessionStatus::Proposed
    );

    // Through every rejection above, the subject edge bytes never moved
    // from the last successful stamp (c4: confirmed/human) and the first 24
    // bytes never changed at all.
    let (out, _) = raw_edge_values(vault, &subject)?;
    let out = out.expect("edge");
    assert_eq!((out[24], out[25]), (1, 0));
    assert_eq!(&out[..24], &stamped[..24]);
    Ok(())
}

#[test]
fn provenance_claim_ids_are_write_once_no_closed_claim_resurrection() -> Result<()> {
    let fx = lifecycle_fixture()?;
    let vault = &fx.vault;
    let subject = fx.subject;

    // One claim, then retract it: a CLOSED wrapper is now persisted under
    // claim_id and the edge carries the retracted stamp (3, human = 0).
    let claim_id = EntityId::now();
    vault.put_edge_provenance(
        &claim_id,
        &subject,
        &EdgeProvenanceClaimBody::new(fx.person, 0.75, SupersessionStatus::Confirmed),
        EdgeActorClass::Human,
        1_000,
    )?;
    vault.retract_edge_provenance(&claim_id, 2_000)?;
    let closed_raw = vault.get_raw(&claim_id)?.expect("closed claim raw bytes");
    let (edge_before, edge_before_in) = raw_edge_values(vault, &subject)?;
    let edge_before = edge_before.expect("stamped edge");
    assert_eq!(
        (edge_before[24], edge_before[25]),
        (3, 0),
        "retracted/human stamp before the resurrection attempt"
    );

    // RESURRECTION ATTEMPT (the verifier's shipped-bug repro): re-put the
    // SAME id with a LATER learned_at. Without a write-once gate this
    // overwrites the closed wrapper with a fresh life=active body —
    // bypassing ProvenanceClaimAlreadyClosed and violating ARCH-0003
    // ("claims are never silently deleted"). An implementation that
    // tolerates the overwrite FAILS the expect_err below.
    let err = vault
        .put_edge_provenance(
            &claim_id,
            &subject,
            &EdgeProvenanceClaimBody::new(fx.person, 0.9, SupersessionStatus::Confirmed),
            EdgeActorClass::Human,
            3_000,
        )
        .expect_err("re-putting a retracted claim's id must be rejected");
    assert_eq!(err.kind(), ErrorKind::ProvenanceClaimIdInUse);

    // The closed claim's RAW bytes are untouched (envelope + wrapper +
    // record byte-for-byte) and its lifecycle is still retracted.
    assert_eq!(
        vault.get_raw(&claim_id)?.expect("closed claim survives"),
        closed_raw,
        "a rejected re-put must not touch the closed claim's stored bytes"
    );
    assert_eq!(
        vault.get_claim(&claim_id)?.expect("closed claim").lifecycle,
        ClaimLifecycleStatus::Retracted,
        "the closed claim must NOT come back life=active"
    );

    // The subject edge flags never moved, in BOTH directions.
    let (out, inn) = raw_edge_values(vault, &subject)?;
    assert_eq!(
        out.as_deref(),
        Some(edge_before.as_slice()),
        "edge bytes must be unchanged after the rejected re-put"
    );
    assert_eq!(inn, edge_before_in);

    // supersede_edge_provenance reusing an EXISTING id for its NEW claim is
    // rejected by the same write-once gate — and writes nothing: the live
    // prior stays open.
    let live_prior = EntityId::now();
    vault.put_edge_provenance(
        &live_prior,
        &subject,
        &EdgeProvenanceClaimBody::new(fx.machine, 0.6, SupersessionStatus::Disputed),
        EdgeActorClass::System,
        3_000,
    )?;
    let live_prior_raw = vault.get_raw(&live_prior)?.expect("live prior raw");
    let (edge_live, _) = raw_edge_values(vault, &subject)?;
    let edge_live = edge_live.expect("stamped edge");
    assert_eq!((edge_live[24], edge_live[25]), (2, 2), "disputed/system");
    let err = vault
        .supersede_edge_provenance(
            &live_prior,
            &claim_id,
            &subject,
            &EdgeProvenanceClaimBody::new(fx.person, 0.9, SupersessionStatus::Confirmed),
            EdgeActorClass::Human,
            4_000,
        )
        .expect_err("supersede must not reuse an existing id for its new claim");
    assert_eq!(err.kind(), ErrorKind::ProvenanceClaimIdInUse);
    assert_eq!(
        vault.get_raw(&claim_id)?.expect("closed claim survives"),
        closed_raw
    );
    assert_eq!(
        vault.get_claim(&live_prior)?.expect("prior").lifecycle,
        ClaimLifecycleStatus::Active,
        "a rejected supersede must NOT close the named prior"
    );

    // Write-once also covers a LIVE claim's id: re-putting it (which the
    // live-scan exclusion would otherwise tolerate as an in-place overwrite)
    // is rejected and the stored bytes stay put.
    let err = vault
        .put_edge_provenance(
            &live_prior,
            &subject,
            &EdgeProvenanceClaimBody::new(fx.person, 0.9, SupersessionStatus::Confirmed),
            EdgeActorClass::Human,
            5_000,
        )
        .expect_err("re-putting a LIVE claim's id must be rejected");
    assert_eq!(err.kind(), ErrorKind::ProvenanceClaimIdInUse);
    assert_eq!(
        vault.get_raw(&live_prior)?.expect("live prior survives"),
        live_prior_raw
    );

    // Edge flags through all three rejections: still the live prior's
    // disputed/system stamp, identical bytes both directions.
    let (out, inn) = raw_edge_values(vault, &subject)?;
    let out = out.expect("edge");
    assert_eq!((out[24], out[25]), (2, 2));
    assert_eq!(inn.as_deref(), Some(out.as_slice()));
    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════
// ONE-1107: ARCH-0038 delete interplay
// (retractionRules DELETE · D16 downgrade/restamp · sweep-scope seam)
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn hard_delete_of_sole_provenance_claim_downgrades_edge_to_bare() -> Result<()> {
    // AC1, "any hard reason": user_hard_delete purges directly;
    // gdpr/policy SoftErase first and then purge — all three must land on
    // the same D16 end state.
    for reason in [
        DeleteReason::UserHardDelete,
        DeleteReason::GdprDelete,
        DeleteReason::PolicyDelete,
    ] {
        let fx = lifecycle_fixture()?;
        let vault = &fx.vault;
        let subject = fx.subject;

        let (bare_out, _) = raw_edge_values(vault, &subject)?;
        let bare_out = bare_out.expect("pre-provenance edge");
        assert_eq!(bare_out.len(), EDGE_VALUE_SEMANTIC_LEN, "{reason:?}");

        let claim_id = EntityId::now();
        let mut body = EdgeProvenanceClaimBody::new(fx.person, 0.8, SupersessionStatus::Confirmed);
        body.source_revision_ref = Some([0x61; 16]);
        body.body_snapshot_ref = Some([0x62; 16]);
        vault.put_edge_provenance(&claim_id, &subject, &body, EdgeActorClass::Human, 1_000)?;
        let (stamped, _) = raw_edge_values(vault, &subject)?;
        let stamped = stamped.expect("stamped edge");
        assert_eq!(
            stamped.len(),
            EDGE_VALUE_SEMANTIC_PROVENANCED_LEN,
            "{reason:?}: the claim must stamp 26 B before the delete"
        );

        let outcome = vault.delete_entity_with_reason(&claim_id, reason)?;
        assert!(outcome.existed, "{reason:?}");
        assert!(
            vault.get(&claim_id)?.is_none(),
            "{reason:?}: the claim entity must be hard-purged"
        );

        // D16: the LAST live Claim is gone, so the cached flag may not
        // outlive its truth — the edge value downgrades 26 B → 24 B bare
        // with the first 24 bytes (weight + created_at + VAD) preserved
        // verbatim, IDENTICAL in BOTH directions.
        let (out, inn) = raw_edge_values(vault, &subject)?;
        let out = out.expect("edges_out row must survive the claim delete");
        let inn = inn.expect("edges_in row must survive the claim delete");
        assert_eq!(
            out.len(),
            EDGE_VALUE_SEMANTIC_LEN,
            "{reason:?}: 26 B must downgrade to 24 B"
        );
        assert_eq!(
            out.as_slice(),
            &stamped[..24],
            "{reason:?}: first 24 bytes preserved verbatim"
        );
        assert_eq!(
            out, bare_out,
            "{reason:?}: the downgrade restores the pre-provenance bytes"
        );
        assert_eq!(inn, out, "{reason:?}: edges_in must mirror edges_out");

        // Decoded reads agree: no cached flags remain.
        let info = vault
            .edges_out(&subject.source)?
            .into_iter()
            .find(|info| info.kind == EdgeKind::Mentions && info.target == subject.target)
            .expect("edge still listed after the claim delete");
        assert_eq!(info.provenance, None, "{reason:?}");
    }
    Ok(())
}

#[test]
fn soft_erase_of_provenance_claim_downgrades_edge_and_skips_dead_shell() -> Result<()> {
    let fx = lifecycle_fixture()?;
    let vault = &fx.vault;
    let subject = fx.subject;

    let claim_id = EntityId::now();
    vault.put_edge_provenance(
        &claim_id,
        &subject,
        &EdgeProvenanceClaimBody::new(fx.person, 0.8, SupersessionStatus::Disputed),
        EdgeActorClass::Human,
        1_000,
    )?;
    let (stamped, _) = raw_edge_values(vault, &subject)?;
    let stamped = stamped.expect("stamped edge");
    assert_eq!(
        (stamped[24], stamped[25]),
        (2, 0),
        "disputed/human before the SoftErase"
    );

    // user_delete = local SoftErase: no receipt, no sweep row.
    let outcome = vault.delete_entity_with_reason(&claim_id, DeleteReason::UserDelete)?;
    assert!(outcome.existed);
    assert!(outcome.receipt_id.is_none());
    assert!(outcome.sweep_key.is_none());
    assert!(hard_erase_sweep_rows(vault)?.is_empty());

    // The Claim shell survives (25 B header, empty payload) per SoftErase
    // semantics, but the edge downgrades 26 B → 24 B in BOTH directions:
    // the truth-Claim's body is scrubbed, so the cached flag goes with it.
    assert_eq!(vault.get(&claim_id)?.as_deref(), Some([].as_slice()));
    let (out, inn) = raw_edge_values(vault, &subject)?;
    let out = out.expect("edges_out row must survive the SoftErase");
    assert_eq!(out.len(), EDGE_VALUE_SEMANTIC_LEN, "26 B → 24 B");
    assert_eq!(out.as_slice(), &stamped[..24], "first 24 bytes preserved");
    assert_eq!(inn.as_deref(), Some(out.as_slice()));

    // The bodiless shell is NOT live: a fresh provenance Claim for the same
    // edge must succeed — the live scan skips the tombstoned shell instead
    // of failing closed on its empty body — and may even carry an OLDER
    // learned_at, because the live frontier is empty again.
    let fresh = EntityId::now();
    vault.put_edge_provenance(
        &fresh,
        &subject,
        &EdgeProvenanceClaimBody::new(fx.machine, 0.3, SupersessionStatus::Confirmed),
        EdgeActorClass::System,
        500,
    )?;
    let (out, _) = raw_edge_values(vault, &subject)?;
    let out = out.expect("restamped edge");
    assert_eq!(out.len(), EDGE_VALUE_SEMANTIC_PROVENANCED_LEN);
    assert_eq!(
        (out[24], out[25]),
        (1, 2),
        "the fresh claim stamps confirmed/system"
    );
    Ok(())
}

#[test]
fn delete_of_provenance_claim_with_survivors_restamps_from_winner() -> Result<()> {
    let fx = lifecycle_fixture()?;
    let vault = &fx.vault;
    let subject = fx.subject;
    let person2 = EntityId::now();
    vault.put_entity(&person2, 4, test_time_range(1, 1), 1, b"person2")?;

    // A live learned_at-tie cohort (t = 2000) so survivors exist after the
    // delete: `winner` (conf 0.6, confirmed/system) outranks `runner_up`
    // (conf 0.4, disputed/agent) under D14.
    let winner = EntityId::now();
    vault.put_edge_provenance(
        &winner,
        &subject,
        &EdgeProvenanceClaimBody::new(fx.machine, 0.6, SupersessionStatus::Confirmed),
        EdgeActorClass::System,
        2_000,
    )?;
    let runner_up = EntityId::now();
    vault.put_edge_provenance(
        &runner_up,
        &subject,
        &EdgeProvenanceClaimBody::new(person2, 0.4, SupersessionStatus::Disputed),
        EdgeActorClass::Agent,
        2_000,
    )?;
    let (before, _) = raw_edge_values(vault, &subject)?;
    let before = before.expect("stamped edge");
    assert_eq!(
        (before[24], before[25]),
        (1, 2),
        "the winner (confirmed/system) stamps while both claims are live"
    );

    // Hard-delete the WINNER: a live Claim remains, so the edge restamps
    // from the D14 winner among the SURVIVORS (disputed = 2, agent = 1) —
    // NOT a downgrade and NOT a stale stamp. A keep-the-old-flags
    // implementation FAILS here.
    let outcome = vault.delete_entity_with_reason(&winner, DeleteReason::UserHardDelete)?;
    assert!(outcome.existed);
    let (out, inn) = raw_edge_values(vault, &subject)?;
    let out = out.expect("edges_out row");
    assert_eq!(
        out.len(),
        EDGE_VALUE_SEMANTIC_PROVENANCED_LEN,
        "a surviving live claim keeps the edge 26 B"
    );
    assert_eq!(
        (out[24], out[25]),
        (2, 1),
        "restamped from the surviving runner-up"
    );
    assert_eq!(&out[..24], &before[..24], "first 24 bytes preserved");
    assert_eq!(inn.as_deref(), Some(out.as_slice()));

    // SoftErase the survivor: NO live Claim remains → D16 downgrade, both
    // directions.
    let outcome = vault.delete_entity_with_reason(&runner_up, DeleteReason::UserDelete)?;
    assert!(outcome.existed);
    let (out, inn) = raw_edge_values(vault, &subject)?;
    let out = out.expect("edges_out row");
    assert_eq!(out.len(), EDGE_VALUE_SEMANTIC_LEN);
    assert_eq!(out.as_slice(), &before[..24]);
    assert_eq!(inn.as_deref(), Some(out.as_slice()));
    Ok(())
}

#[test]
fn deleting_the_retracted_truth_claim_downgrades_the_retracted_stamp() -> Result<()> {
    let fx = lifecycle_fixture()?;
    let vault = &fx.vault;
    let subject = fx.subject;

    let claim_id = EntityId::now();
    vault.put_edge_provenance(
        &claim_id,
        &subject,
        &EdgeProvenanceClaimBody::new(fx.person, 0.9, SupersessionStatus::Confirmed),
        EdgeActorClass::Human,
        1_000,
    )?;
    vault.retract_edge_provenance(&claim_id, 2_000)?;
    let (retracted, _) = raw_edge_values(vault, &subject)?;
    let retracted = retracted.expect("retracted edge");
    assert_eq!(
        (retracted.len(), retracted[24]),
        (EDGE_VALUE_SEMANTIC_PROVENANCED_LEN, 3),
        "RETRACT keeps the 26 B retracted stamp — the Claim is still readable truth"
    );

    // DELETE removes the truth-Claim entirely: with NO provenance Claim of
    // any lifecycle left for this EdgeRef the retracted stamp would be
    // unauditable, so it must NOT survive — D16 downgrade to 24 B bare.
    let outcome = vault.delete_entity_with_reason(&claim_id, DeleteReason::GdprDelete)?;
    assert!(outcome.existed);
    let (out, inn) = raw_edge_values(vault, &subject)?;
    let out = out.expect("edges_out row");
    assert_eq!(out.len(), EDGE_VALUE_SEMANTIC_LEN, "26 B → 24 B");
    assert_eq!(out.as_slice(), &retracted[..24]);
    assert_eq!(inn.as_deref(), Some(out.as_slice()));
    Ok(())
}

#[test]
fn deleting_a_superseded_claim_keeps_the_surviving_retracted_dampening_stamp() -> Result<()> {
    // ONE-1107 blocker: deleting a SUPERSEDED/closed `edge.provenance` Claim
    // while a RETRACTED Claim for the SAME EdgeRef still survives must KEEP
    // the 26 B retracted dampening stamp — NOT downgrade to 24 B bare, which
    // would silently drop the contract-mandated retracted flag and re-enable
    // PPR propagation of withdrawn provenance (retractionRules RETRACT). This
    // matches `retract_edge_provenance`'s own None-branch. The pre-fix code
    // scans only ACTIVE survivors, sees none, and downgrades to bare — so it
    // FAILS the `EDGE_VALUE_SEMANTIC_PROVENANCED_LEN` / byte-24 == 3
    // assertions below.
    for reason in [DeleteReason::UserHardDelete, DeleteReason::GdprDelete] {
        let fx = lifecycle_fixture()?;
        let vault = &fx.vault;
        let subject = fx.subject;

        // A: PERSON / human (actor_class = 0) @ t = 1000, confirmed.
        let claim_a = EntityId::now();
        vault.put_edge_provenance(
            &claim_a,
            &subject,
            &EdgeProvenanceClaimBody::new(fx.person, 0.9, SupersessionStatus::Confirmed),
            EdgeActorClass::Human,
            1_000,
        )?;

        // B supersedes A: MACHINE / system (actor_class = 2) @ t = 2000.
        // Distinct class from A so byte 25 proves which truth-Claim the edge
        // follows after the delete.
        let claim_b = EntityId::now();
        vault.supersede_edge_provenance(
            &claim_a,
            &claim_b,
            &subject,
            &EdgeProvenanceClaimBody::new(fx.machine, 0.8, SupersessionStatus::Confirmed),
            EdgeActorClass::System,
            2_000,
        )?;
        // A is now closed (superseded); B is the live winner.
        assert_eq!(
            vault.get_claim(&claim_a)?.expect("a").lifecycle,
            ClaimLifecycleStatus::Superseded,
            "{reason:?}"
        );

        // Retract B → the edge carries the 26 B RETRACTED dampening stamp
        // (confirmation_status = retracted = 3, actor_class = system = 2).
        vault.retract_edge_provenance(&claim_b, 3_000)?;
        let (retracted, _) = raw_edge_values(vault, &subject)?;
        let retracted = retracted.expect("retracted edge");
        assert_eq!(
            (retracted.len(), retracted[24], retracted[25]),
            (EDGE_VALUE_SEMANTIC_PROVENANCED_LEN, 3, 2),
            "{reason:?}: B's retraction stamps 26 B retracted/system before the delete"
        );

        // DELETE the SUPERSEDED A while the RETRACTED B survives as readable
        // truth. The derived edge flag follows the surviving (retracted)
        // Claim: the edge STAYS 26 B with confirmation_status = retracted (3)
        // and B's persisted actor_class = system (2) — it must NOT downgrade
        // to 24 B bare, and it must NOT fall back to A's human (0) class.
        let outcome = vault.delete_entity_with_reason(&claim_a, reason)?;
        assert!(outcome.existed, "{reason:?}");
        assert!(
            vault.get(&claim_a)?.is_none(),
            "{reason:?}: the superseded claim A must be purged"
        );
        assert_eq!(
            vault.get_claim(&claim_b)?.expect("b").lifecycle,
            ClaimLifecycleStatus::Retracted,
            "{reason:?}: the retracted truth-Claim B survives the delete of A"
        );

        let (out, inn) = raw_edge_values(vault, &subject)?;
        let out = out.expect("edges_out row");
        assert_eq!(
            out.len(),
            EDGE_VALUE_SEMANTIC_PROVENANCED_LEN,
            "{reason:?}: a surviving retracted Claim KEEPS the 26 B stamp — must NOT downgrade to 24 B bare"
        );
        assert_eq!(
            out[24], 3,
            "{reason:?}: confirmation_status stays retracted = 3 (the dampening flag)"
        );
        assert_eq!(
            out[25], 2,
            "{reason:?}: actor_class follows the surviving retracted B (system = 2), not deleted A's human = 0"
        );
        assert_eq!(
            &out[..24],
            &retracted[..24],
            "{reason:?}: weight/created_at/VAD bytes preserved verbatim"
        );
        assert_eq!(
            inn.as_deref(),
            Some(out.as_slice()),
            "{reason:?}: edges_in must mirror edges_out byte-for-byte"
        );

        // Decoded read agrees: the cached dampening flag survives.
        let info = vault
            .edges_out(&subject.source)?
            .into_iter()
            .find(|info| info.kind == EdgeKind::Mentions && info.target == subject.target)
            .expect("edge still listed after the superseded-claim delete");
        assert_eq!(
            info.provenance,
            Some(EdgeProvenanceFlags {
                confirmation_status: EdgeConfirmationStatus::Retracted,
                actor_class: EdgeActorClass::System,
            }),
            "{reason:?}: decoded flags must be retracted/system, never None"
        );
    }
    Ok(())
}

#[test]
fn delete_hook_discriminates_by_type_byte_and_predicate() -> Result<()> {
    let fx = lifecycle_fixture()?;
    let vault = &fx.vault;
    let subject = fx.subject;

    // A provenanced 26 B edge that must NOT be touched by unrelated deletes.
    let anchor = EntityId::now();
    vault.put_edge_provenance(
        &anchor,
        &subject,
        &EdgeProvenanceClaimBody::new(fx.person, 0.9, SupersessionStatus::Confirmed),
        EdgeActorClass::Human,
        1_000,
    )?;
    let (before_out, before_in) = raw_edge_values(vault, &subject)?;

    // (a) an ORDINARY Claim (type 0, non-provenance predicate) about the
    // SAME source entity — the hook must discriminate on the PREDICATE.
    let ordinary = EntityId::now();
    let ordinary_body = ClaimBody::new(
        "hobby.collects",
        ClaimSubject::Entity(subject.source),
        rmpv::Value::from("stamps"),
        0.9,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
    );
    vault.put_claim(&ordinary, &ordinary_body, test_time_range(5, 5), 5)?;
    let outcome = vault.delete_entity_with_reason(&ordinary, DeleteReason::UserHardDelete)?;
    assert!(outcome.existed);

    // (b) a NON-Claim entity (TURN, type byte 1) — the hook must
    // discriminate on the TYPE BYTE.
    let turn = EntityId::now();
    vault.put_entity(&turn, 1, test_time_range(7, 7), 7, b"turn-payload")?;
    let outcome = vault.delete_entity_with_reason(&turn, DeleteReason::GdprDelete)?;
    assert!(outcome.existed);

    // Zero new behavior: the provenanced edge bytes never moved…
    let (after_out, after_in) = raw_edge_values(vault, &subject)?;
    assert_eq!(
        after_out, before_out,
        "unrelated deletes must not touch the edge"
    );
    assert_eq!(after_in, before_in);

    // …and neither queued sweep row carries provenance refs (empty slots,
    // not missing — the seam shape is uniform).
    let rows = hard_erase_sweep_rows(vault)?;
    assert_eq!(rows.len(), 2, "both receipt-writing deletes queue a sweep");
    for (_key, value) in &rows {
        let job: serde_json::Value = rmp_serde::from_slice(value).expect("decode sweep job");
        assert_eq!(
            job["scope"]["body_snapshot_refs"],
            serde_json::json!([]),
            "non-provenance deletes must queue an EMPTY body_snapshot_refs slot"
        );
        assert_eq!(job["scope"]["revision_ids"], serde_json::json!([]));
    }
    Ok(())
}

#[test]
fn corrupt_type_0_body_fails_the_delete_closed_with_zero_residue() -> Result<()> {
    let fx = lifecycle_fixture()?;
    let vault = &fx.vault;
    let subject = fx.subject;

    // A pre-existing provenanced 26 B edge that the aborted deletes must
    // never touch.
    let anchor = EntityId::now();
    vault.put_edge_provenance(
        &anchor,
        &subject,
        &EdgeProvenanceClaimBody::new(fx.person, 0.9, SupersessionStatus::Confirmed),
        EdgeActorClass::Human,
        1_000,
    )?;
    let (edge_before_out, edge_before_in) = raw_edge_values(vault, &subject)?;
    let receipts_before = redaction_audit_receipts(vault)?;

    // Raw-write a type-0 (CLAIM) record with a valid 25 B header and a
    // NON-empty garbage body (32 × 0xC1 — a reserved MessagePack byte that
    // can never decode). ONE-1104 pins that every type-0 write is
    // validated, so this record can only exist through corruption.
    let corrupt = EntityId::now();
    let mut raw = Vec::with_capacity(ENTITY_METADATA_HEADER_LEN + 32);
    raw.push(0); // type byte 0 = CLAIM
    raw.extend_from_slice(&5_u64.to_be_bytes()); // occurred_start
    raw.extend_from_slice(&5_u64.to_be_bytes()); // occurred_end
    raw.extend_from_slice(&5_u64.to_be_bytes()); // learned_at
    raw.extend_from_slice(&[0xC1; 32]);
    assert!(raw.len() >= ENTITY_METADATA_HEADER_LEN + 26);
    vault.with_write_txn(|wtxn| {
        vault.store.entities.put(wtxn, corrupt.as_bytes(), &raw)?;
        Ok(())
    })?;

    // The capture hook runs on EVERY delete reason BEFORE any mutation; an
    // undecodable non-empty type-0 body must abort the delete CLOSED with
    // the decoder's typed error on a hard reason AND on the local SoftErase
    // path. A warn-and-proceed or skip-on-decode-failure capture FAILS the
    // expect_err (the delete would go through and leave residue below).
    for reason in [DeleteReason::GdprDelete, DeleteReason::UserDelete] {
        let err = vault
            .delete_entity_with_reason(&corrupt, reason)
            .expect_err("undecodable non-empty type-0 body must fail the delete closed");
        assert_eq!(err.kind(), ErrorKind::InvalidClaimBody, "{reason:?}");

        // Zero residue: the corrupt record's stored bytes are untouched…
        let rtxn = vault.store.env.read_txn()?;
        assert_eq!(
            vault.store.entities.get(&rtxn, corrupt.as_bytes())?,
            Some(raw.as_slice()),
            "{reason:?}: the aborted delete must leave the record byte-identical"
        );
        drop(rtxn);
        // …no receipt was written and no sweep row was queued…
        assert_eq!(
            redaction_audit_receipts(vault)?,
            receipts_before,
            "{reason:?}: receipts must be unchanged by the aborted delete"
        );
        assert!(
            hard_erase_sweep_rows(vault)?.is_empty(),
            "{reason:?}: no sweep row may be queued by the aborted delete"
        );
        // …and the pre-existing provenanced edge's raw bytes never moved.
        let (out, inn) = raw_edge_values(vault, &subject)?;
        assert_eq!(out, edge_before_out, "{reason:?}");
        assert_eq!(inn, edge_before_in, "{reason:?}");
    }
    Ok(())
}

#[test]
fn deleting_a_provenance_claim_whose_subject_edge_is_gone_refreshes_nothing() -> Result<()> {
    let fx = lifecycle_fixture()?;
    let vault = &fx.vault;
    let subject = fx.subject;

    let claim_id = EntityId::now();
    vault.put_edge_provenance(
        &claim_id,
        &subject,
        &EdgeProvenanceClaimBody::new(fx.person, 0.7, SupersessionStatus::Confirmed),
        EdgeActorClass::Human,
        1_000,
    )?;
    assert!(vault.delete_edge(&subject.source, EdgeKind::Mentions, &subject.target)?);

    // The orphaned Claim still deletes cleanly: nothing is left to refresh,
    // and the missing subject edge is NOT an error.
    let outcome = vault.delete_entity_with_reason(&claim_id, DeleteReason::UserHardDelete)?;
    assert!(outcome.existed);
    assert!(vault.get(&claim_id)?.is_none());
    let (out, inn) = raw_edge_values(vault, &subject)?;
    assert_eq!(out, None, "the delete must not resurrect the edge");
    assert_eq!(inn, None);
    Ok(())
}

#[test]
fn provenance_claim_delete_invalidates_ppr_cache_for_subject_endpoints() -> Result<()> {
    let fx = lifecycle_fixture()?;
    let vault = &fx.vault;
    let subject = fx.subject;

    let claim_id = EntityId::now();
    vault.put_edge_provenance(
        &claim_id,
        &subject,
        &EdgeProvenanceClaimBody::new(fx.person, 0.8, SupersessionStatus::Confirmed),
        EdgeActorClass::Human,
        1_000,
    )?;

    // Plant malformed PPR cache rows keyed to both subject-edge endpoints
    // (mirrors the ONE-1105 restamp test): invalidation DELETES dependent
    // cache rows. The TARGET endpoint is the discriminating probe — the
    // purge's own invalidate_ppr_for_delete only reaches the claim's
    // claim_of neighbor (the SOURCE); only the D16 edge refresh touches the
    // target.
    let src_hash = [0xBD_u8; 16];
    let tgt_hash = [0xBE_u8; 16];
    {
        let mut wtxn = vault.store.env.write_txn()?;
        let mut src_dep = [0_u8; 32];
        src_dep[..16].copy_from_slice(subject.source.as_bytes());
        src_dep[16..].copy_from_slice(&src_hash);
        let mut tgt_dep = [0_u8; 32];
        tgt_dep[..16].copy_from_slice(subject.target.as_bytes());
        tgt_dep[16..].copy_from_slice(&tgt_hash);
        vault
            .store
            .ppr_cache
            .put(&mut wtxn, &src_hash, &[1, 2, 3])?;
        vault
            .store
            .ppr_cache
            .put(&mut wtxn, &tgt_hash, &[1, 2, 3])?;
        vault.store.ppr_cache_deps.put(&mut wtxn, &src_dep, &[])?;
        vault.store.ppr_cache_deps.put(&mut wtxn, &tgt_dep, &[])?;
        wtxn.commit()?;
    }

    vault.delete_entity_with_reason(&claim_id, DeleteReason::UserHardDelete)?;

    let rtxn = vault.store.env.read_txn()?;
    assert!(
        vault.store.ppr_cache.get(&rtxn, &src_hash)?.is_none(),
        "source-endpoint PPR cache must be invalidated by the downgrade"
    );
    assert!(
        vault.store.ppr_cache.get(&rtxn, &tgt_hash)?.is_none(),
        "target-endpoint PPR cache must be invalidated by the downgrade"
    );
    Ok(())
}

#[cfg(feature = "sync")]
#[test]
fn hard_delete_of_provenance_claim_carries_snapshot_ref_in_sweep_scope() -> Result<()> {
    let fx = lifecycle_fixture()?;
    let vault = &fx.vault;
    let subject = fx.subject;

    let claim_id = EntityId::now();
    let mut body = EdgeProvenanceClaimBody::new(fx.person, 0.8, SupersessionStatus::Confirmed);
    body.source_revision_ref = Some([0x5A; 16]);
    body.body_snapshot_ref = Some([0x5B; 16]);
    vault.put_edge_provenance(&claim_id, &subject, &body, EdgeActorClass::Human, 1_000)?;

    let outcome = vault.delete_entity_with_reason(&claim_id, DeleteReason::GdprDelete)?;
    assert!(outcome.existed);
    let sweep_key = outcome.sweep_key.expect("gdpr_delete must queue the sweep");
    assert!(sweep_key.starts_with(b"h:"));

    let rows = hard_erase_sweep_rows(vault)?;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].0, sweep_key);
    let raw_job = rows[0].1.as_slice();
    let job: serde_json::Value = rmp_serde::from_slice(raw_job).expect("decode sweep job");

    // hardEraseSweepQueue: value = "scope + retry state"; scope = opaque IDs
    // + carrier classes, no content. The captured body_snapshot_ref MUST
    // ride the queued row's scope — "body_snapshot_ref lets the queued
    // historical-carrier sweep locate residual snapshot/update bytes" — as
    // an opaque lowercase-hex id. The executor consuming it is ONE-1091
    // (deferred); only the seam is asserted here.
    let mut scope_fields: Vec<&str> = job["scope"]
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    scope_fields.sort_unstable();
    assert_eq!(
        scope_fields,
        vec![
            "body_snapshot_refs",
            "carrier_classes",
            "entity_ids",
            "revision_ids"
        ]
    );
    let snapshot_hex = "5b".repeat(16);
    let revision_hex = "5a".repeat(16);
    assert_eq!(
        job["scope"]["body_snapshot_refs"],
        serde_json::json!([snapshot_hex.as_str()])
    );
    // The captured source_revision_ref rides the scope's pinned
    // "revision UUIDs" slot.
    assert_eq!(
        job["scope"]["revision_ids"],
        serde_json::json!([revision_hex])
    );
    assert_eq!(job["scope"]["entity_ids"][0], claim_id.to_hex());
    assert_eq!(
        job["scope"]["carrier_classes"],
        serde_json::json!([
            "historical_loro_updates",
            "historical_loro_snapshots",
            "derived_carriers"
        ])
    );

    // Minimization: no content or predicate strings in the queued row.
    assert_no_receipt_payload_leak(
        raw_job,
        &[
            b"edge.provenance",
            b"actor_entity_ref",
            b"supersession_status",
        ],
    );

    // The RECEIPT is unchanged (AC3): pinned top-level fields, pinned scope
    // shape (entity UUIDs / revision UUIDs only — the captured sweep refs do
    // NOT enter the receipt), and no content/predicate/ref leak.
    let receipt_raw = vault
        .get_raw(&outcome.receipt_id.expect("receipt id"))?
        .expect("receipt persisted");
    assert_no_receipt_payload_leak(
        &receipt_raw,
        &[
            b"edge.provenance",
            b"actor_entity_ref",
            snapshot_hex.as_bytes(),
        ],
    );
    let receipt = receipt_body(&receipt_raw);
    assert_receipt_fields(&receipt);
    let mut receipt_scope_fields: Vec<&str> = receipt["scope"]
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    receipt_scope_fields.sort_unstable();
    assert_eq!(receipt_scope_fields, vec!["entity_ids", "revision_ids"]);
    assert_eq!(receipt["scope"]["entity_ids"][0], claim_id.to_hex());
    assert_eq!(
        receipt["scope"]["revision_ids"].as_array().unwrap().len(),
        0
    );
    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════
// ONE-1138: provenance substrate vocabulary bump
// (substrate_ref + reasoning_effort + actor_class relocation · MODEL kind
//  121 · legacy-evid transition semantics)
// ═══════════════════════════════════════════════════════════════════════

/// ONE-1138 MODEL kind + get-or-create door: `ensure_model_substrate` is the
/// ONLY public way to mint a type-121 entity ("written when a substrate
/// first appears in a write path"), keyed by `(name, version)`, idempotent,
/// with the reserved `mo` short-id prefix actually allocated; descriptor
/// validation is typed (`InvalidModelSubstrate`).
#[test]
fn ensure_model_substrate_get_or_create_pins_model_kind() -> Result<()> {
    let (_dir, vault) = open_test_vault();

    // CREATE on first appearance: engine-authored MODEL entity, type 121.
    let kimi = vault.ensure_model_substrate("kimi-k2.6", "2026-05", 1_000)?;
    assert_eq!(vault.get_entity_type(&kimi)?, Some(ENTITY_TYPE_MODEL));
    assert_eq!(ENTITY_TYPE_MODEL, 121, "ratified type byte");

    // The body dedups name + version ON the entity (never inline in
    // provenance records).
    let raw = vault.get_raw(&kimi)?.expect("model entity stored");
    let (name, version) =
        crate::provenance::decode_model_entity_body(&raw[ENTITY_METADATA_HEADER_LEN..])?;
    assert_eq!(name, "kimi-k2.6");
    assert_eq!(version, "2026-05");

    // GET: the same (name, version) returns the SAME id — idempotent, no
    // duplicate substrate row even at a different `now`.
    assert_eq!(
        vault.ensure_model_substrate("kimi-k2.6", "2026-05", 2_000)?,
        kimi
    );
    assert_eq!(vault.entities_by_type(ENTITY_TYPE_MODEL)?.len(), 1);

    // A different version IS a different substrate (selective
    // re-extraction needs per-version identity).
    let kimi_next = vault.ensure_model_substrate("kimi-k2.6", "2026-06", 3_000)?;
    assert_ne!(kimi_next, kimi);
    assert_eq!(vault.entities_by_type(ENTITY_TYPE_MODEL)?.len(), 2);

    // The reserved `mo` short-id prefix is allocated for engine-authored
    // rows (registry short_id_prefix = Some("mo"), unlike REDACTION_AUDIT).
    let rtxn = vault.store.env.read_txn()?;
    let reverse = vault
        .store
        .short_ids_reverse
        .get(&rtxn, kimi.as_bytes())?
        .expect("model entity must carry a short id");
    assert!(
        reverse.starts_with(b"mo"),
        "short id must use the reserved mo prefix, got {reverse:?}"
    );
    drop(rtxn);

    // Descriptor validation: empty or oversized name/version → typed
    // InvalidModelSubstrate, nothing written.
    let before = vault.entities_by_type(ENTITY_TYPE_MODEL)?.len();
    let oversized = "x".repeat(257);
    for (bad_name, bad_version) in [
        ("", "v1"),
        ("m", ""),
        (oversized.as_str(), "v1"),
        ("m", oversized.as_str()),
    ] {
        let err = vault
            .ensure_model_substrate(bad_name, bad_version, 1)
            .expect_err("invalid model descriptor must fail typed");
        assert_eq!(err.kind(), ErrorKind::InvalidModelSubstrate);
    }
    assert_eq!(vault.entities_by_type(ENTITY_TYPE_MODEL)?.len(), before);
    Ok(())
}

/// ONE-1138 write path: `substrate_ref` + `reasoning_effort` persist on the
/// stored 10-key record; the validated caller-supplied `actor_class` rides
/// the BODY key and the wrapper `evid` stays empty; lifecycle restamps
/// resolve the class from the body; the substrate gate rejects non-MODEL
/// refs (MACHINE-82 reuse REJECTED — kind = shape, DEC-0005 §7) and
/// dangling refs; a conflicting caller-set body class fails closed.
#[test]
fn put_edge_provenance_substrate_and_effort_round_trip_with_model_gate() -> Result<()> {
    let fx = lifecycle_fixture()?;
    let vault = &fx.vault;
    let model = vault.ensure_model_substrate("oneironer-tiny", "0.3", 500)?;

    let claim_id = EntityId::now();
    let mut body = EdgeProvenanceClaimBody::new(fx.person, 0.9, SupersessionStatus::Confirmed);
    body.substrate_ref = Some(model);
    body.reasoning_effort = Some("high".to_owned());
    vault.put_edge_provenance(&claim_id, &fx.subject, &body, EdgeActorClass::Agent, 1_000)?;

    let claim = vault.get_claim(&claim_id)?.expect("claim body");
    assert!(
        claim.evidence.is_none(),
        "post-bump writers leave evid empty (evidence purity)"
    );
    let record = decode_edge_provenance_body(&claim.value)?;
    assert_eq!(record.substrate_ref, Some(model));
    assert_eq!(record.reasoning_effort.as_deref(), Some("high"));
    assert_eq!(record.actor_class, Some(EdgeActorClass::Agent));

    // Lifecycle on a NEW-shape claim: retraction resolves the persisted
    // class from the BODY key and restamps retracted (3) + agent (1).
    vault.retract_edge_provenance(&claim_id, 2_000)?;
    let (out, _) = raw_edge_values(vault, &fx.subject)?;
    let out = out.expect("edge survives retraction");
    assert_eq!(out[24], 3, "retracted = 3");
    assert_eq!(out[25], 1, "agent = 1 resolved from the BODY actor_class");

    // Substrate gate: a MACHINE (82) entity is NOT a substrate.
    let bad_id = EntityId::now();
    let mut machine_substrate =
        EdgeProvenanceClaimBody::new(fx.person, 0.5, SupersessionStatus::Proposed);
    machine_substrate.substrate_ref = Some(fx.machine);
    let err = vault
        .put_edge_provenance(
            &bad_id,
            &fx.subject,
            &machine_substrate,
            EdgeActorClass::Human,
            3_000,
        )
        .expect_err("MACHINE substrate_ref must be rejected");
    assert_eq!(err.kind(), ErrorKind::InvalidModelSubstrate);
    assert!(vault.get(&bad_id)?.is_none(), "nothing written on reject");

    // Substrate gate: a ref that names no stored entity.
    let mut dangling = EdgeProvenanceClaimBody::new(fx.person, 0.5, SupersessionStatus::Proposed);
    dangling.substrate_ref = Some(EntityId::now());
    let err = vault
        .put_edge_provenance(
            &EntityId::now(),
            &fx.subject,
            &dangling,
            EdgeActorClass::Human,
            3_000,
        )
        .expect_err("dangling substrate_ref must be rejected");
    assert_eq!(err.kind(), ErrorKind::InvalidModelSubstrate);

    // Substrate gate: a REAL, indexed type-121 MODEL row whose MessagePack
    // body is MALFORMED (not the engine `{name, version}` shape). The remote
    // replay door admits the maintenance type byte (allow_maintenance) WITHOUT
    // body-shape validation, so a forged/corrupt body can physically land in
    // the entities table. The substrate gate runs the SAME strict decoder as
    // the get-or-create scan, so a type-byte-only gate would wrongly ACCEPT
    // this. It must fail closed as `CorruptedIndex` — distinct from the
    // `InvalidModelSubstrate` referential rejections (wrong kind / dangling) —
    // and stage NO provenance Claim.
    let forged_model = EntityId::now();
    {
        let mut wtxn = vault.store.env.write_txn()?;
        crate::batch::apply_ops(
            &vault.store,
            &vault.config,
            &vault.analyzer,
            &mut wtxn,
            vec![crate::batch::BatchOp::Put {
                id: forged_model,
                entity_type: ENTITY_TYPE_MODEL,
                occurred: TimeRange {
                    start: 400,
                    end: 400,
                },
                learned_at: 400,
                // Not a `{name, version}` MessagePack map → decode_model_entity_body fails.
                data: b"forged-model".to_vec(),
                allow_maintenance: true,
                allow_reserved_predicate: false,
            }],
            true,
            false,
            false,
        )?;
        wtxn.commit()?;
    }
    // It really is an indexed type-121 row, so the gate reaches the body
    // decode rather than tripping on a missing / wrong-type entity.
    assert_eq!(
        vault.get_entity_type(&forged_model)?,
        Some(ENTITY_TYPE_MODEL),
        "forged substrate must be a real indexed type-121 row"
    );
    let corrupt_claim_id = EntityId::now();
    let mut malformed_substrate =
        EdgeProvenanceClaimBody::new(fx.person, 0.5, SupersessionStatus::Proposed);
    malformed_substrate.substrate_ref = Some(forged_model);
    let err = vault
        .put_edge_provenance(
            &corrupt_claim_id,
            &fx.subject,
            &malformed_substrate,
            EdgeActorClass::Human,
            3_000,
        )
        .expect_err("malformed type-121 substrate body must be rejected");
    assert_eq!(
        err.kind(),
        ErrorKind::CorruptedIndex,
        "body-malformed type-121 substrate row is ambiguous on-disk corruption \
         (CorruptedIndex), NOT a clean referential rejection (InvalidModelSubstrate)"
    );
    assert!(
        vault.get(&corrupt_claim_id)?.is_none(),
        "fail-closed: no provenance Claim staged on body-corruption reject"
    );

    // Conflict gate: a caller-set body actor_class that disagrees with the
    // actor_class parameter is ambiguous → typed reject; an AGREEING body
    // class is accepted (idempotent injection).
    let mut conflicted = EdgeProvenanceClaimBody::new(fx.person, 0.5, SupersessionStatus::Proposed);
    conflicted.actor_class = Some(EdgeActorClass::Human);
    let err = vault
        .put_edge_provenance(
            &EntityId::now(),
            &fx.subject,
            &conflicted,
            EdgeActorClass::Agent,
            3_000,
        )
        .expect_err("conflicting body actor_class must be rejected");
    assert_eq!(err.kind(), ErrorKind::InvalidProvenanceBody);
    let mut agreeing = EdgeProvenanceClaimBody::new(fx.person, 0.5, SupersessionStatus::Proposed);
    agreeing.actor_class = Some(EdgeActorClass::Human);
    vault.put_edge_provenance(
        &EntityId::now(),
        &fx.subject,
        &agreeing,
        EdgeActorClass::Human,
        3_000,
    )?;
    Ok(())
}

/// ONE-1138 transition semantics, LEGACY side: a pre-bump claim — 7-key
/// value record (no `actor_class` body key) + the engine-owned
/// `{"actor_class": u8}` map on the wrapper's `evid` — still decodes and
/// participates in lifecycle operations; old claims are NEVER invalidated.
#[test]
fn legacy_evid_actor_class_claim_decodes_and_lifecycle_restamps() -> Result<()> {
    let fx = lifecycle_fixture()?;
    let vault = &fx.vault;

    // Fabricate the pre-bump shape byte-exactly through the reserved door
    // (the encoder elides the absent actor_class key, so this is the exact
    // legacy 7-key wire shape).
    let claim_id = EntityId::now();
    let record = EdgeProvenanceClaimBody::new(fx.person, 0.75, SupersessionStatus::Confirmed);
    let mut wrapper = ClaimBody::new(
        PREDICATE_EDGE_PROVENANCE,
        ClaimSubject::from(fx.subject),
        crate::provenance::encode_edge_provenance_value(&record),
        0.75,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    );
    wrapper.evidence = Some(crate::provenance::encode_actor_class_evidence(
        EdgeActorClass::Human,
    ));
    let bytes = crate::claim::encode_claim_body(&wrapper)?;
    vault.with_write_txn(|wtxn| {
        vault
            .batch_in()
            .put_reserved_claim(&claim_id, test_time_range(1_000, u64::MAX), 1_000, &bytes)
            .edge(&claim_id, EdgeKind::ClaimOf, &fx.subject.source, 1.0)
            .apply(wtxn)
    })?;

    // The legacy claim drives the lifecycle: retraction resolves the class
    // from the LEGACY evid map and restamps retracted (3) + human (0).
    vault.retract_edge_provenance(&claim_id, 2_000)?;
    let (out, inn) = raw_edge_values(vault, &fx.subject)?;
    let out = out.expect("edges_out row survives");
    assert_eq!(inn.as_deref(), Some(out.as_slice()));
    assert_eq!(out.len(), EDGE_VALUE_SEMANTIC_PROVENANCED_LEN);
    assert_eq!(out[24], 3, "retracted = 3");
    assert_eq!(out[25], 0, "human = 0 resolved from the LEGACY evid map");
    Ok(())
}

/// ONE-1138 transition semantics, ambiguity side: a claim carrying
/// `actor_class` in BOTH the value-record body AND the wrapper's legacy
/// `evid` map fails closed on every lifecycle read — typed
/// `InvalidProvenanceBody`, never silently reconciled, and the stored claim
/// is left untouched.
#[test]
fn provenance_actor_class_in_both_body_and_evid_fails_closed() -> Result<()> {
    let fx = lifecycle_fixture()?;
    let vault = &fx.vault;

    let claim_id = EntityId::now();
    let mut record = EdgeProvenanceClaimBody::new(fx.person, 0.75, SupersessionStatus::Confirmed);
    record.actor_class = Some(EdgeActorClass::Human);
    let mut wrapper = ClaimBody::new(
        PREDICATE_EDGE_PROVENANCE,
        ClaimSubject::from(fx.subject),
        crate::provenance::encode_edge_provenance_value(&record),
        0.75,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    );
    // Even an AGREEING duplicate is ambiguous — fail closed.
    wrapper.evidence = Some(crate::provenance::encode_actor_class_evidence(
        EdgeActorClass::Human,
    ));
    let bytes = crate::claim::encode_claim_body(&wrapper)?;
    // The structural write-door (ONE-1159) rejects the ambiguous body at WRITE
    // time — the claim never reaches the store, so the whole batch is rejected
    // atomically. The resolve-time check in `resolve_persisted_actor_class` is
    // the defence-in-depth backstop, pinned separately by
    // `resolve_persisted_actor_class_pins_transition_matrix`.
    let err = vault
        .with_write_txn(|wtxn| {
            vault
                .batch_in()
                .put_reserved_claim(&claim_id, test_time_range(1_000, u64::MAX), 1_000, &bytes)
                .edge(&claim_id, EdgeKind::ClaimOf, &fx.subject.source, 1.0)
                .apply(wtxn)
        })
        .expect_err("both-places actor_class must fail closed at write");
    assert_eq!(err.kind(), ErrorKind::InvalidProvenanceBody);

    // Fail-closed wrote nothing: the ambiguous claim was never stored and the
    // subject edge still carries no provenance stamp (24 B bare).
    assert!(
        vault.get_claim(&claim_id)?.is_none(),
        "rejected ambiguous claim must not be stored"
    );
    let (out, _) = raw_edge_values(vault, &fx.subject)?;
    assert_eq!(out.expect("edge row").len(), EDGE_VALUE_SEMANTIC_LEN);
    Ok(())
}

fn text_forward_row(vault: &Vault, id: &EntityId) -> Result<Vec<u8>> {
    let rtxn = vault.store.env.read_txn()?;
    vault
        .store
        .text_forward
        .get(&rtxn, id.as_bytes())?
        .map(<[u8]>::to_vec)
        .ok_or(Error::CorruptedIndex("missing text_forward row"))
}

fn assert_text_rows_deindexed(vault: &Vault, id: &EntityId) -> Result<()> {
    let rtxn = vault.store.env.read_txn()?;
    assert!(
        vault
            .store
            .text_forward
            .get(&rtxn, id.as_bytes())?
            .is_none(),
        "text_forward row (key = literal id bytes) must be deleted"
    );
    assert!(
        vault.store.text_meta.get(&rtxn, id.as_bytes())?.is_none(),
        "text_meta doc row (key = literal id bytes) must be deleted"
    );
    assert!(
        vault
            .store
            .text_doc_field_lengths
            .get(&rtxn, id.as_bytes())?
            .is_none(),
        "text_doc_field_lengths row (key = literal id bytes) must be deleted"
    );
    for item in vault.store.text_postings.iter(&rtxn)? {
        let (_term, posting) = item?;
        assert!(
            !posting.starts_with(id.as_bytes()),
            "no posting row may survive for the deindexed entity"
        );
    }
    Ok(())
}

fn assert_empty_text_corpus_after_deindex(vault: &Vault) -> Result<()> {
    let rtxn = vault.store.env.read_txn()?;
    assert!(
        vault.store.text_postings.iter(&rtxn)?.next().is_none(),
        "no posting row may survive the stale deindex"
    );
    assert!(
        vault
            .store
            .text_bm25_field_stats
            .iter(&rtxn)?
            .next()
            .is_none(),
        "the zeroed per-field stats row must be deleted, not kept at 0/0"
    );
    assert_eq!(
        vault.store.text_meta.get(&rtxn, &[0u8; 16])?,
        Some(&0u32.to_le_bytes()[..]),
        "TOTAL_DOCS must be decremented in the same txn as the overwrite"
    );
    Ok(())
}

/// ONE-1168: a local body-changing re-put without a covering `BatchOp::Text`
/// must drop the old full-text projection in the same transaction as the
/// entity overwrite.
#[test]
fn local_overwrite_changed_body_without_text_drops_stale_text_postings_same_txn() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let id = EntityId::now();
    vault.put_entity(&id, 1, test_time_range(1, 1), 1, b"payload-from-old-local")?;
    vault
        .batch()
        .text(&id, &[("body", "alpha_stale_xyz")])
        .commit()?;
    assert_eq!(
        vault.search_text("alpha_stale_xyz", 10)?.len(),
        1,
        "precondition: the old term must be indexed and searchable"
    );

    vault.put_entity(&id, 1, test_time_range(2, 2), 2, b"payload-from-new-local")?;

    let raw = vault.get_raw(&id)?.expect("entity stored");
    assert_eq!(
        &raw[ENTITY_METADATA_HEADER_LEN..],
        b"payload-from-new-local"
    );
    assert!(
        vault.search_text("alpha_stale_xyz", 10)?.is_empty(),
        "old body's postings must not match searches after a local overwrite"
    );
    assert_text_rows_deindexed(&vault, &id)?;
    assert_empty_text_corpus_after_deindex(&vault)
}

#[test]
fn retract_claim_lifecycle_reput_drops_stale_text_postings() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let subject = EntityId::now();
    vault.put_entity(&subject, 4, test_time_range(1, 1), 1, b"person")?;
    let id = put_active_claim(&vault, &subject, "profile.status", "active", 1)?;
    vault
        .batch()
        .text(&id, &[("body", "retract_lifecycle_stale_xyz")])
        .commit()?;
    assert_eq!(
        vault.search_text("retract_lifecycle_stale_xyz", 10)?.len(),
        1,
        "precondition: the active claim's term must be indexed and searchable"
    );

    vault.retract_claim(&id, 2_000)?;

    assert_eq!(
        vault
            .get_claim(&id)?
            .expect("retracted claim must stay readable")
            .lifecycle,
        ClaimLifecycleStatus::Retracted
    );
    assert!(
        vault
            .search_text("retract_lifecycle_stale_xyz", 10)?
            .is_empty(),
        "Vault::retract_claim must deindex stale postings from its lifecycle re-put"
    );
    assert_text_rows_deindexed(&vault, &id)?;
    assert_empty_text_corpus_after_deindex(&vault)
}

#[test]
fn local_overwrite_same_body_replay_without_text_keeps_text_postings() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let id = EntityId::now();
    vault.put_entity(&id, 1, test_time_range(1, 1), 1, b"stable-local-payload")?;
    vault
        .batch()
        .text(&id, &[("body", "stable_replay_xyz")])
        .commit()?;
    let forward_before = text_forward_row(&vault, &id)?;

    vault.put_entity(&id, 1, test_time_range(1, 1), 1, b"stable-local-payload")?;

    assert_eq!(
        vault.search_text("stable_replay_xyz", 10)?.len(),
        1,
        "same-bytes local replay must leave postings serving"
    );
    assert_eq!(
        text_forward_row(&vault, &id)?,
        forward_before,
        "same-bytes local replay must not rewrite the forward row"
    );
    Ok(())
}

#[test]
fn local_metadata_only_reput_without_text_keeps_text_postings() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let id = EntityId::now();
    vault.put_entity(&id, 1, test_time_range(1, 1), 1, b"metadata-stable-payload")?;
    vault
        .batch()
        .text(&id, &[("body", "metadata_only_xyz")])
        .commit()?;
    let forward_before = text_forward_row(&vault, &id)?;

    vault.put_entity(&id, 1, test_time_range(5, 7), 9, b"metadata-stable-payload")?;

    assert_eq!(
        vault.search_text("metadata_only_xyz", 10)?.len(),
        1,
        "metadata-only local re-put must leave postings serving"
    );
    assert_eq!(
        text_forward_row(&vault, &id)?,
        forward_before,
        "metadata-only local re-put must not rewrite the forward row"
    );

    let err = vault
        .put_entity(
            &id,
            1,
            test_time_range(9, 8),
            10,
            b"metadata-stable-payload",
        )
        .expect_err("reversed time range must still fail before mutation");
    assert_matches!(err, Error::InvalidTimeRange { start: 9, end: 8 });
    assert_eq!(
        vault.search_text("metadata_only_xyz", 10)?.len(),
        1,
        "failed metadata write must leave postings serving"
    );
    Ok(())
}

#[test]
fn local_changed_body_with_text_op_reindexes_new_terms() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let id = EntityId::now();
    vault.put_entity(&id, 1, test_time_range(1, 1), 1, b"body-before-text")?;
    vault
        .batch()
        .text(&id, &[("body", "old_term_xyz")])
        .commit()?;

    vault
        .batch()
        .put(&id, 1, test_time_range(2, 2), 2, b"body-after-text")
        .text(&id, &[("body", "new_term_xyz")])
        .commit()?;

    assert!(
        vault.search_text("old_term_xyz", 10)?.is_empty(),
        "Text op self-deindex must remove the old term"
    );
    assert_eq!(
        vault.search_text("new_term_xyz", 10)?.len(),
        1,
        "Text op must leave the new term indexed"
    );
    Ok(())
}

#[test]
fn batch_put_text_put_deindexes_text_from_non_final_body() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let id = EntityId::now();
    let other = EntityId::now();
    vault.put_entity(&id, 1, test_time_range(0, 0), 0, b"payload-body-v0")?;
    vault
        .batch()
        .text(&id, &[("body", "body_v0_unique_xyz")])
        .commit()?;
    vault
        .batch()
        .put(&other, 1, test_time_range(1, 1), 1, b"unrelated-payload")
        .text(&other, &[("body", "unrelated_survives_xyz")])
        .commit()?;

    vault
        .batch()
        .put(&id, 1, test_time_range(1, 1), 1, b"payload-body-v1")
        .text(&id, &[("body", "body_v1_unique_xyz")])
        .put(&id, 1, test_time_range(2, 2), 2, b"payload-body-v2")
        .commit()?;

    let raw = vault.get_raw(&id)?.expect("entity stored");
    assert_eq!(&raw[ENTITY_METADATA_HEADER_LEN..], b"payload-body-v2");
    assert!(
        vault
            .search_text("body_v0_unique_xyz", 10)?
            .iter()
            .all(|hit| hit.id != id),
        "Text rows from the pre-existing body must not retrieve the entity"
    );
    assert!(
        vault
            .search_text("body_v1_unique_xyz", 10)?
            .iter()
            .all(|hit| hit.id != id),
        "Text rows for the non-final body must not retrieve the entity"
    );
    assert_eq!(
        vault.search_text("unrelated_survives_xyz", 10)?.len(),
        1,
        "per-entity stale deindex must leave unrelated postings intact"
    );
    assert_text_rows_deindexed(&vault, &id)?;

    vault
        .batch()
        .text(&id, &[("body", "body_v2_unique_xyz")])
        .commit()?;
    assert!(
        vault
            .search_text("body_v2_unique_xyz", 10)?
            .iter()
            .any(|hit| hit.id == id),
        "final-body text remains indexable after the stale projection is removed"
    );
    assert!(
        vault
            .search_text("body_v1_unique_xyz", 10)?
            .iter()
            .all(|hit| hit.id != id),
        "reindexing final-body text must not resurrect non-final terms"
    );
    Ok(())
}

/// ONE-1141 (ARCH-0031 amendment, ratified 2026-06-13): "When an LWW
/// replicated overwrite replaces a document, the loser document's postings
/// must be removed in the same transaction as the overwrite — no replicated
/// overwrite ever leaves loser postings live."
///
/// Directed batch-level unit for the sync replay doors (`put_replicated` →
/// `apply_put`, replicated arm): text-index term A, replicated-overwrite the
/// entity with body B inside ONE write txn, then assert the loser's text
/// rows are gone at the DB level — mirroring exactly what SoftErase's
/// `deindex_text` leaves behind (`text_forward` / `text_meta` /
/// `text_doc_field_lengths` rows deleted under the literal id-bytes key, the
/// posting row dropped with its last duplicate, the per-field stats row
/// deleted at zero, and the TOTAL_DOCS sentinel row decremented back to 0).
#[cfg(feature = "sync")]
#[test]
fn replicated_overwrite_changed_body_drops_loser_text_postings_same_txn() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let id = EntityId::now();
    vault.put_entity(&id, 1, test_time_range(1, 1), 1, b"payload-from-loser")?;
    vault
        .batch()
        .text(&id, &[("body", "loseronlyterm")])
        .commit()?;
    assert_eq!(
        vault.search_text("loseronlyterm", 10)?.len(),
        1,
        "precondition: the loser term must be indexed and searchable"
    );

    // Replicated overwrite with a CHANGED body through the Observer-B replay
    // door (`TxnBatchBuilder::put_replicated`) — overwrite + deindex must
    // land in the SAME externally-owned wtxn.
    vault.with_write_txn(|wtxn| {
        vault
            .batch_in()
            .put_replicated(&id, 1, test_time_range(2, 2), 2, b"payload-from-winner")
            .apply(wtxn)
    })?;

    // The winner body is stored (header + body layout, body at offset 25)…
    let raw = vault.get_raw(&id)?.expect("entity stored");
    assert_eq!(&raw[ENTITY_METADATA_HEADER_LEN..], b"payload-from-winner");
    // …and the loser term no longer serves.
    assert!(
        vault.search_text("loseronlyterm", 10)?.is_empty(),
        "loser postings must not match searches after a replicated overwrite"
    );

    // DB-level: identical end-state to SoftErase's deindex.
    let rtxn = vault.store.env.read_txn()?;
    assert!(
        vault
            .store
            .text_forward
            .get(&rtxn, id.as_bytes())?
            .is_none(),
        "text_forward row (key = literal id bytes) must be deleted"
    );
    assert!(
        vault.store.text_meta.get(&rtxn, id.as_bytes())?.is_none(),
        "text_meta doc row (key = literal id bytes) must be deleted"
    );
    assert!(
        vault
            .store
            .text_doc_field_lengths
            .get(&rtxn, id.as_bytes())?
            .is_none(),
        "text_doc_field_lengths row (key = literal id bytes) must be deleted"
    );
    // This doc was the only indexed document: dropping its last duplicate
    // removes the posting term key entirely, and the zeroed per-field stats
    // row is deleted rather than kept at 0/0.
    assert!(
        vault.store.text_postings.iter(&rtxn)?.next().is_none(),
        "no posting row may survive the loser's deindex"
    );
    assert!(
        vault
            .store
            .text_bm25_field_stats
            .iter(&rtxn)?
            .next()
            .is_none(),
        "the zeroed per-field stats row must be deleted, not kept at 0/0"
    );
    // TOTAL_DOCS sentinel ([0x00; 16] key in text_meta, u32 LE value): the
    // corpus count is decremented back to 0, never left dangling at 1.
    assert_eq!(
        vault.store.text_meta.get(&rtxn, &[0u8; 16])?,
        Some(&0u32.to_le_bytes()[..]),
        "TOTAL_DOCS must be decremented in the same txn as the overwrite"
    );
    Ok(())
}

/// ONE-1141 byte-compare guard + scope pin. Two non-deindexing overwrites:
///
/// * SAME-BYTES replicated overwrite (idempotent re-import / reconnect echo,
///   or the winner node re-receiving its own winning value during a
///   convergence exchange) must NOT touch the text index — postings keep
///   serving and the `text_forward` row stays byte-identical. Metadata-only
///   changes (occurred/learned) are NOT body changes.
/// * ONE-1168 widens stale-posting cleanup to LOCAL body-changing overwrites
///   that have no covering same-batch `BatchOp::Text`; same-bytes replay and
///   metadata-only changes remain guarded by the body byte compare.
#[cfg(feature = "sync")]
#[test]
fn replicated_overwrite_same_body_bytes_keeps_text_postings() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let id = EntityId::now();
    vault.put_entity(&id, 1, test_time_range(1, 1), 1, b"stable-payload")?;
    vault
        .batch()
        .text(&id, &[("body", "winneronlyterm")])
        .commit()?;

    let forward_before = {
        let rtxn = vault.store.env.read_txn()?;
        vault
            .store
            .text_forward
            .get(&rtxn, id.as_bytes())?
            .map(<[u8]>::to_vec)
            .expect("precondition: forward row exists for the indexed doc")
    };

    // Same body bytes, different temporal metadata, through the
    // forward_rematerialize replay door (`BatchBuilder::put_replicated`).
    vault
        .batch()
        .put_replicated(&id, 1, test_time_range(5, 7), 9, b"stable-payload")
        .commit()?;

    assert_eq!(
        vault.search_text("winneronlyterm", 10)?.len(),
        1,
        "a same-bytes replicated replay must leave postings serving"
    );
    {
        let rtxn = vault.store.env.read_txn()?;
        assert_eq!(
            vault
                .store
                .text_forward
                .get(&rtxn, id.as_bytes())?
                .map(<[u8]>::to_vec),
            Some(forward_before),
            "the forward row must be byte-identical after a same-bytes replay"
        );
    }

    // ONE-1168: a LOCAL body-changing overwrite with no Text op now deindexes
    // stale postings while preserving the same-bytes replicated replay guard
    // above.
    vault.put_entity(&id, 1, test_time_range(8, 8), 11, b"locally-edited-payload")?;
    assert!(
        vault.search_text("winneronlyterm", 10)?.is_empty(),
        "local body-changing overwrite without Text must deindex stale postings"
    );
    Ok(())
}
