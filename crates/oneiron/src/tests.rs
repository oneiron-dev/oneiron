use std::collections::HashSet;
use std::path::Path;
use std::str;
use std::time::Instant;

use crate::limits::{MAX_ANCESTOR_DEPTH, MAX_CHILD_OF_CYCLE_TRAVERSAL_STEPS};
use crate::types::{
    EDGE_VALUE_SEMANTIC_LEN, EDGE_VALUE_SEMANTIC_PROVENANCED_LEN, EDGE_VALUE_STRUCTURAL_LEN,
    ENTITY_ID_LEN, ENTITY_TYPE_MACHINE, ENTITY_TYPE_REDACTION_AUDIT, ENTITY_TYPE_TASK,
    ENTITY_TYPE_TASK_LIST, EdgeActorClass, EdgeConfirmationStatus, EdgeProvenanceFlags,
    decode_edge_value, decode_edge_value_for_kind, encode_edge_value,
};
use heed::EnvOpenOptions;
use heed::types::{Bytes, Str};
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use sha2::{Digest, Sha256};
use xxhash_rust::xxh32::xxh32;

use super::*;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, LONG_INTERVAL_THRESHOLD_SECS};
use crate::deletion::{
    DeleteReason, LAST_HARD_ERASE_SWEEP_SEQ_KEY, RedactionScope, encode_hard_erase_sweep_job,
    encode_hard_erase_sweep_key,
};
use crate::hnsw::COUNT_KEY;
use crate::store::{
    DB_MANIFEST, GRAPH_VERSION_KEY, HNSW_CONFIG_KEY, MAX_DBS, MODEL_ID_KEY, STORAGE_ABI_VERSION,
    STORAGE_ABI_VERSION_KEY, STORAGE_SCHEMA_VERSION, STORAGE_SCHEMA_VERSION_KEY, Store,
    TEMPORAL_LONG_INTERVALS_SCHEMA_VERSION_KEY, VECTOR_VERSION_KEY, lmdb_database_open_guard,
};

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

fn seeded_entity_id(counter: u128) -> EntityId {
    let mut bytes = counter.to_be_bytes();
    bytes[0] = 0x7e;
    EntityId::from_bytes(bytes).expect("seeded test id should be valid")
}

fn valid_edge_value() -> Vec<u8> {
    encode_edge_value(EdgeKind::BelongsTo, 0.0, 0, Vad::NEUTRAL, None)
        .expect("valid structural edge value")
}

fn read_meta_u16(vault: &Vault, key: &[u8]) -> Result<Option<u16>> {
    let rtxn = vault.store.env.read_txn()?;
    let Some(raw) = vault.store.vault_meta.get(&rtxn, key)? else {
        return Ok(None);
    };
    let bytes: [u8; 2] = raw.try_into().map_err(|_| Error::InvalidKey)?;
    Ok(Some(u16::from_le_bytes(bytes)))
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

fn read_short_id_value(vault: &Vault, id: &EntityId) -> Result<Vec<u8>> {
    let rtxn = vault.store.env.read_txn()?;
    vault
        .store
        .short_ids
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

    vault.put_entity(&id, 0, test_time_range(10, 20), 30, data)?;
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
        .put(&id, 0, test_time_range(10, 10), 20, secret)
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
    assert!(vault.entities_by_type(0)?.contains(&id));
    assert!(redaction_audit_receipts(&vault)?.is_empty());
    assert!(hard_erase_sweep_rows(&vault)?.is_empty());
    Ok(())
}

#[test]
fn user_hard_delete_writes_opaque_redaction_audit_receipt() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let id = EntityId::now();
    let payload = b"Alice secret body predicate should never enter receipt";

    vault.put_entity(&id, 0, test_time_range(100, 100), 101, payload)?;

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
    assert!(receipt["verification"].as_object().unwrap().is_empty());
    Ok(())
}

#[test]
fn hard_delete_enqueues_bounded_historical_carrier_sweep() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let id = EntityId::now();

    vault.put_entity(&id, 0, test_time_range(200, 200), 201, b"sweep-me")?;

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
        0,
        test_time_range(250, 250),
        251,
        b"repair-sweep-cursor",
    )?;

    let stale_seq = 6_u64;
    let existing_seq = 7_u64;
    let repaired_seq = 8_u64;
    let existing_key = encode_hard_erase_sweep_key(existing_seq);
    let existing_value =
        encode_hard_erase_sweep_job(RedactionScope::entity(&EntityId::now()), 1_772_000_000)?;

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
            .put(&id, 0, test_time_range(300, 300), 301, b"regulated secret")
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

#[cfg(feature = "sync")]
#[test]
fn user_delete_soft_shell_survives_sync_rematerialization() -> Result<()> {
    use crate::sync::bridge::Materializer;
    use crate::sync::loro_support::map_contains_binary;
    use crate::sync::schema::create_window_doc;
    use crate::sync::types::WindowKey;
    use crate::sync::window;

    let (_dir, vault) = open_test_vault();
    let id = EntityId::now();
    let learned_at = 1_772_000_000;

    vault
        .batch()
        .put(
            &id,
            0,
            test_time_range(learned_at, learned_at),
            learned_at,
            b"soft-delete-sync-body",
        )
        .commit()?;

    let outcome = vault.delete_entity_with_reason(&id, DeleteReason::UserDelete)?;
    assert!(outcome.existed);
    assert_eq!(vault.get(&id)?.as_deref(), Some([].as_slice()));

    let window_key = WindowKey::from_timestamp(learned_at);
    let doc = match window::load_window_from_state(&vault, "local", &window_key) {
        Ok(doc) => doc,
        Err(Error::WindowNotFound { .. }) => create_window_doc("local", &window_key),
        Err(err) => return Err(err),
    };

    let materializer = Materializer::new();
    let _ = window::forward_rematerialize(&vault, &doc, &materializer)?;

    let tombstones = doc.get_map("tombstones");
    assert!(
        !map_contains_binary(&tombstones, id.to_hex().as_str()),
        "user_delete must not write the hard-purge CRDT tombstone; synced soft-delete propagation is deferred to ONE-1090"
    );
    assert_eq!(
        vault.get(&id)?.as_deref(),
        Some([].as_slice()),
        "sync rematerialization must preserve the SoftErase shell"
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
            0,
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
    assert!(matches!(err, Error::CorruptedIndex("edge record")));
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
            0,
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
    assert!(matches!(
        err,
        Error::DimensionMismatch {
            expected: 4,
            got: 3
        }
    ));

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
    assert!(matches!(
        err,
        Error::DimensionMismatch {
            expected: 4,
            got: 3
        }
    ));
    Ok(())
}

#[test]
fn search_vector_skips_deleted_nodes() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let entry = EntityId::now();
    let deleted = EntityId::now();
    let live = EntityId::now();

    for id in [entry, deleted, live] {
        vault.put_entity(&id, 0, test_time_range(1, 1), 1, b"vector-node")?;
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

    vault.put_entity(&entry, 0, test_time_range(1, 1), 1, b"entry")?;
    vault.put_entity(&live, 0, test_time_range(1, 1), 1, b"live")?;
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

    vault.put_entity(&entry, 0, test_time_range(1, 1), 1, b"entry")?;
    vault.put_entity(&survivor, 0, test_time_range(1, 1), 1, b"survivor")?;
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
    match vector_err {
        Error::InvalidVector { index, value } => {
            assert_eq!(index, 1);
            assert!(value.is_nan());
        }
        other => panic!("expected invalid vector, got {other:?}"),
    }
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
    match edge_err {
        Error::InvalidEdgeWeight { value } => assert!(value.is_infinite()),
        other => panic!("expected invalid edge weight, got {other:?}"),
    }
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

        vault.put_entity(&id, 0, test_time_range(1, 1), 1, b"recall-node")?;
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
        .put(&id_a, 0, test_time_range(100, 100), 101, b"a")
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
    let entity_type = 0_u8;

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

    let reopened = Vault::open(path, test_config());
    assert!(matches!(reopened, Err(Error::InvalidKey)));
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
    assert!(matches!(
        Vault::open(path, mismatch_cfg),
        Err(Error::EmbeddingModelChanged { .. })
    ));

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
        .put(&id1, 0, test_time_range(1, 1), 2, data1)
        .put(&id2, 0, test_time_range(3, 3), 4, data2)
        .commit()?;

    let (short_id1, hash1) = decode_short_id_value(&read_short_id_value(&vault, &id1)?)?;
    let (short_id2, hash2) = decode_short_id_value(&read_short_id_value(&vault, &id2)?)?;
    assert_eq!(short_id1, "cl1");
    assert_eq!(short_id2, "cl2");
    assert_eq!(hash1, content_hash(data1));
    assert_eq!(hash2, content_hash(data2));
    Ok(())
}

#[test]
fn batch_put_short_id_reverse_lookup() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let id = EntityId::now();
    let data = b"reverse";

    vault
        .batch()
        .put(&id, 0, test_time_range(100, 100), 101, data)
        .commit()?;

    let short_id_value = read_short_id_value(&vault, &id)?;
    let (short_id, _) = decode_short_id_value(&short_id_value)?;

    let rtxn = vault.store.env.read_txn()?;
    let reverse = vault
        .store
        .short_ids_reverse
        .get(&rtxn, short_id.as_bytes())?
        .ok_or(Error::EntityNotFound)?;
    assert_eq!(reverse, id.as_bytes());
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
        .put(&id, 0, test_time_range(10, 10), 11, data1)
        .commit()?;
    let (short_id1, hash1) = decode_short_id_value(&read_short_id_value(&vault, &id)?)?;

    vault
        .batch()
        .put(&id, 0, test_time_range(10, 10), 11, &data2)
        .commit()?;
    let (short_id2, hash2) = decode_short_id_value(&read_short_id_value(&vault, &id)?)?;

    assert_eq!(short_id1, short_id2);
    assert_eq!(hash1, content_hash(data1));
    assert_eq!(hash2, content_hash(&data2));
    assert_ne!(hash1, hash2);
    Ok(())
}

#[test]
fn reput_deindexes_stale_secondary_indexes() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let id = EntityId::now();
    // The type byte is immutable on re-put (D2, Error::EntityTypeImmutable);
    // re-typing coverage lives in the EntityTypeImmutable tests. This test
    // pins that a same-type re-put re-homes the temporal indexes while the
    // short id stays stable and the content hash refreshes.
    let entity_type = 0_u8;
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
        .put(&id, 0, test_time_range(100, 200), 300, b"range")
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
        .put(&id, 0, test_time_range(200, 200), 300, b"point")
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
        .put(&id, 0, test_time_range(1_000, old_end), 300, b"long-old")
        .commit()?;

    let old_key = Store::encode_temporal_key(old_end, &id);
    let new_key = Store::encode_temporal_key(new_end, &id);

    vault
        .batch()
        .put(&id, 0, test_time_range(5_000, new_end), 300, b"long-new")
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
        .put(&id, 0, test_time_range(10_000, 10_001), 300, b"short")
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
        .put(&id, 0, test_time_range(1, 1), 2, b"phonetic")
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
        .put(&id, 0, test_time_range(1, 2), 3, b"dedup")
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
        .put(&id, 0, test_time_range(1, 2), 3, b"dedup-in-batch")
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
        .put(&id, 0, test_time_range(1, 2), 3, b"union")
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
        .put(&id, 0, test_time_range(1, 2), 3, b"migrated")
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
            .put(&id, 0, test_time_range(1, 1), 2, payload)
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
        .put(&id, 0, occurred, learned_at, b"delete-me")
        .put(&out_target, 4, test_time_range(1, 1), 2, b"target")
        .put(&in_source, 4, test_time_range(3, 3), 4, b"source")
        .vector(&id, &[0.1, 0.2, 0.3, 0.4])
        .edge(&id, EdgeKind::Supports, &out_target, 0.9)
        .edge(&in_source, EdgeKind::Mentions, &id, 0.7)
        .phonetic(&id, &["SMTH", "SMT"])
        .commit()?;

    let short_id_before_delete = {
        let value = read_short_id_value(&vault, &id)?;
        let (short_id, _) = decode_short_id_value(&value)?;
        short_id
    };

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

    assert!(vault.store.short_ids.get(&rtxn, id.as_bytes())?.is_none());
    assert!(
        vault
            .store
            .short_ids_reverse
            .get(&rtxn, short_id_before_delete.as_bytes())?
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
            .put(&id, 0, test_time_range(1, 1), 2, payload)
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
        .put(&id, 0, test_time_range(1, 2), 3, b"exists")
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
    assert!(matches!(err, Error::CorruptedIndex("edge record")));
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

    vault.put_entity(&id, 0, occurred, learned_at, data)?;
    assert_eq!(vault.get(&id)?.ok_or(Error::EntityNotFound)?, data);

    let rtxn = vault.store.env.read_txn()?;
    let raw = vault
        .store
        .entities
        .get(&rtxn, id.as_bytes())?
        .ok_or(Error::EntityNotFound)?;
    assert_eq!(raw.len(), ENTITY_METADATA_HEADER_LEN + data.len());
    assert_eq!(&raw[ENTITY_METADATA_HEADER_LEN..], data);

    let type_key = Store::encode_type_key(0, &id);
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
    assert!(vault.store.short_ids.get(&rtxn, id.as_bytes())?.is_some());

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
    assert!(matches!(err, Error::CorruptedIndex("entity header")));

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
    assert!(matches!(err, Error::InvalidConfig(_)));

    let mut invalid_hnsw = test_config();
    invalid_hnsw.hnsw.m_max_0 = 0;
    let err = match Vault::open(temp_dir.path(), invalid_hnsw) {
        Ok(_) => panic!("expected invalid config"),
        Err(err) => err,
    };
    assert!(matches!(
        err,
        Error::InvalidConfig(ref message) if message == "hnsw m_max_0 must be greater than zero"
    ));

    let mut invalid_map = test_config();
    invalid_map.map_size = 0;
    let err = match Vault::open(temp_dir.path(), invalid_map) {
        Ok(_) => panic!("expected invalid config"),
        Err(err) => err,
    };
    assert!(matches!(err, Error::InvalidConfig(_)));
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
    assert!(matches!(err, Error::InvalidConfig(ref message) if message.contains("already open")));

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
    assert!(matches!(err, Error::InvalidConfig(ref message) if message.contains("already open")));

    drop(first_vault);
    let reopened = Vault::open(&link_path, test_config())?;
    drop(reopened);
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
        .put(&src, 0, test_time_range(1, 2), 3, b"src")
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
    vault.put_entity(&id, 0, test_time_range(1, 1), 1, b"node")?;
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
    vault.put_entity(&id, 0, test_time_range(1, 1), 1, b"node")?;
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
    assert!(matches!(
        err,
        Error::InvalidConfig(ref message)
            if message.contains("missing embedding model identity")
    ));

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
    assert!(matches!(
        err,
        Error::InvalidConfig(ref message)
            if message.contains("missing embedding model identity")
    ));

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
    vault.put_entity(&id, 0, test_time_range(1, 1), 1, b"node")?;
    vault.put_vector(&id, &[0.1, 0.2, 0.3, 0.4])?;
    drop(vault);

    let mut cfg = test_config();
    cfg.embedding_model = None;
    let Err(err) = Vault::open(path, cfg) else {
        panic!("expected missing requested embedding model rejection");
    };
    assert!(matches!(
        err,
        Error::InvalidConfig(ref message)
            if message.contains("embedding model is required to open")
    ));

    Ok(())
}

#[test]
fn detects_embedding_model_mismatch_on_populated_open() -> Result<()> {
    let temp_dir = tempfile::tempdir()?;
    let mut cfg = test_config();
    cfg.embedding_model = Some("model-a".to_owned());
    let vault = Vault::open(temp_dir.path(), cfg)?;
    let id = EntityId::now();
    vault.put_entity(&id, 0, test_time_range(1, 1), 1, b"node")?;
    vault.put_vector(&id, &[0.1, 0.2, 0.3, 0.4])?;
    drop(vault);

    let mut cfg = test_config();
    cfg.embedding_model = Some("model-b".to_owned());
    let Err(err) = Vault::open(temp_dir.path(), cfg) else {
        panic!("expected mismatch");
    };
    assert!(matches!(
        err,
        Error::EmbeddingModelChanged {
            ref stored,
            ref requested
        } if stored == "model-a" && requested == "model-b"
    ));

    Ok(())
}

#[test]
fn rejects_vector_write_without_embedding_model_identity() -> Result<()> {
    let temp_dir = tempfile::tempdir()?;
    let mut cfg = test_config();
    cfg.embedding_model = None;
    let vault = Vault::open(temp_dir.path(), cfg)?;
    let id = EntityId::now();
    vault.put_entity(&id, 0, test_time_range(1, 1), 1, b"node")?;

    let Err(err) = vault.put_vector(&id, &[0.1, 0.2, 0.3, 0.4]) else {
        panic!("expected missing embedding model rejection");
    };
    assert!(matches!(
        err,
        Error::InvalidConfig(ref message)
            if message.contains("embedding model is required before writing vectors")
    ));
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
    vault.put_entity(&id, 0, test_time_range(1, 1), 1, b"node")?;
    vault.put_vector(&id, &[0.1, 0.2, 0.3, 0.4])?;
    let legacy = legacy_hnsw_compatibility_record(&cfg);
    write_hnsw_config_record(&vault, &legacy)?;
    drop(vault);

    let Err(err) = Vault::open(path, cfg) else {
        panic!("expected legacy hnsw compatibility rejection");
    };
    assert!(matches!(
        err,
        Error::HnswConfigChanged {
            ref stored,
            ref requested
        } if stored == "dimensions=4,m_max_0=64,ef_construction=200,distance_metric=missing,index_structure=missing"
            && requested == "dimensions=4,m_max_0=64,ef_construction=200,distance_metric=cosine,index_structure=flat_nsw"
    ));
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
    assert!(matches!(
        err,
        Error::HnswConfigChanged {
            ref stored,
            ref requested
        } if stored == "dimensions=4,m_max_0=64,ef_construction=200,distance_metric=unknown(2),index_structure=unknown(2)"
            && requested == "dimensions=4,m_max_0=64,ef_construction=200,distance_metric=cosine,index_structure=flat_nsw"
    ));
    Ok(())
}

#[test]
fn detects_hnsw_config_mismatch_on_open() {
    let (temp_dir, vault) = open_test_vault();
    drop(vault);

    let mut cfg = test_config();
    cfg.hnsw.ef_construction += 1;
    let Err(err) = Vault::open(temp_dir.path(), cfg) else {
        panic!("expected hnsw config mismatch");
    };
    assert!(matches!(
        err,
        Error::HnswConfigChanged {
            ref stored,
            ref requested
        } if stored == "dimensions=4,m_max_0=64,ef_construction=200,distance_metric=cosine,index_structure=flat_nsw"
            && requested == "dimensions=4,m_max_0=64,ef_construction=201,distance_metric=cosine,index_structure=flat_nsw"
    ));
}

#[test]
fn detects_dimension_mismatch_on_open() {
    let (temp_dir, vault) = open_test_vault();
    drop(vault);

    let mut cfg = test_config();
    cfg.dimensions = 8;
    let Err(err) = Vault::open(temp_dir.path(), cfg) else {
        panic!("expected hnsw config mismatch");
    };
    assert!(matches!(
        err,
        Error::HnswConfigChanged {
            ref stored,
            ref requested
        } if stored == "dimensions=4,m_max_0=64,ef_construction=200,distance_metric=cosine,index_structure=flat_nsw"
            && requested == "dimensions=8,m_max_0=64,ef_construction=200,distance_metric=cosine,index_structure=flat_nsw"
    ));
}

#[test]
fn allows_ef_search_retuning_on_open() -> Result<()> {
    let (temp_dir, vault) = open_test_vault();
    let id = EntityId::now();
    vault.put_entity(&id, 0, test_time_range(1, 1), 1, b"node")?;
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
    vault.put_entity(&id, 0, test_time_range(1, 1), 1, b"node")?;
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
    assert!(matches!(
        err,
        Error::InvalidConfig(ref message)
            if message.contains("missing complete vector/hnsw compatibility metadata")
    ));
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
    assert!(matches!(
        Vault::open(temp_dir.path(), cfg2),
        Err(Error::EmbeddingModelChanged { .. })
    ));

    Ok(())
}

#[test]
fn creates_contract_manifest_databases() -> Result<()> {
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

#[test]
fn open_rejects_missing_required_manifest_database_name() -> Result<()> {
    let temp_dir = tempfile::tempdir()?;
    create_raw_vault_missing_manifest_name(temp_dir.path(), "hnsw_meta")?;

    let err = match Vault::open(temp_dir.path(), test_config()) {
        Ok(_) => panic!("expected Vault::open to fail closed on missing manifest DB"),
        Err(err) => err,
    };
    assert!(
        matches!(
            err,
            Error::DbManifestMismatch {
                ref missing,
                ref unexpected
            } if missing == &vec!["hnsw_meta".to_owned()] && unexpected.is_empty()
        ),
        "expected DB manifest mismatch for missing hnsw_meta, got {err:?}"
    );
    Ok(())
}

#[test]
fn materialized_manifest_set_is_feature_independent_all_25() -> Result<()> {
    let temp_dir = tempfile::tempdir()?;
    let vault = Vault::open(temp_dir.path(), test_config())?;
    let expected: Vec<String> = expected_manifest_names()
        .iter()
        .map(|name| (*name).to_owned())
        .collect();

    assert_eq!(materialized_database_names(&vault)?, expected);
    Ok(())
}

#[test]
fn open_rejects_missing_sync_state_manifest_database_name() -> Result<()> {
    let temp_dir = tempfile::tempdir()?;
    create_raw_vault_missing_manifest_name(temp_dir.path(), "sync_state")?;

    let err = match Vault::open(temp_dir.path(), test_config()) {
        Ok(_) => panic!("expected Vault::open to fail closed on missing sync_state DB"),
        Err(err) => err,
    };
    assert!(
        matches!(
            err,
            Error::DbManifestMismatch {
                ref missing,
                ref unexpected
            } if missing == &vec!["sync_state".to_owned()] && unexpected.is_empty()
        ),
        "expected DB manifest mismatch for missing sync_state, got {err:?}"
    );
    Ok(())
}

#[test]
fn open_rejects_missing_sync_queue_manifest_database_name() -> Result<()> {
    let temp_dir = tempfile::tempdir()?;
    create_raw_vault_missing_manifest_name(temp_dir.path(), "sync_queue")?;

    let err = match Vault::open(temp_dir.path(), test_config()) {
        Ok(_) => panic!("expected Vault::open to fail closed on missing sync_queue DB"),
        Err(err) => err,
    };
    assert!(
        matches!(
            err,
            Error::DbManifestMismatch {
                ref missing,
                ref unexpected
            } if missing == &vec!["sync_queue".to_owned()] && unexpected.is_empty()
        ),
        "expected DB manifest mismatch for missing sync_queue, got {err:?}"
    );
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

    assert_eq!(report.storage_abi_version, Some(2));
    assert_eq!(report.storage_schema_version, Some(1));
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
    assert_eq!(
        report.analyzer_manifest_hash.as_deref(),
        Some("acc359f173a6fcf5a7c4dc1ffcbbfe63d0c41878733fb4d20d033dea03640ce1")
    );
    assert_eq!(
        report.bm25_field_schema_hash.as_deref(),
        Some("2d59ed83e21963518570270aa88dd8dc8aac8c8308e092eb70654767fa3aef7d")
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
///    `InvalidConfig("vault path is already open in this process: …")`, and
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
        vault.put_entity(&id, 0, test_time_range(1, 1), 1, b"gate-node")?;
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
            .put(&id, 0, test_time_range(1, 1), 1, b"gate-text")
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
            .put(&id, 0, test_time_range(1, 1), 1, b"gate-both")
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
        // registration would yield InvalidConfig("vault path is already
        // open in this process: …") instead; partially-initialized vault
        // state would change which gate fires.
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
        // For cases whose expected kind is InvalidConfig, a leaked path
        // registration would ALSO surface as InvalidConfig("vault path is
        // already open …") and pass the kind check above — defeating the
        // no-partial-handle guarantee. Assert the re-open re-hit the GATE,
        // not a leaked registration.
        assert!(
            !second.to_string().contains("vault path is already open"),
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

    let payload_a = rmp_serde::to_vec_named(&serde_json::json!({
        "pred": "goal.learning",
        "val": "Learn Japanese by June"
    }))
    .map_err(|_| Error::InvalidKey)?;
    let payload_b = rmp_serde::to_vec_named(&serde_json::json!({ "name": "Alice" }))
        .map_err(|_| Error::InvalidKey)?;

    vault
        .batch()
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
    use crate::types::{ENTITY_TYPE_REGISTRY, short_id_prefix};

    // ARCH-0002 / oneiron-contracts.ts pinned storage ABI.
    let expected: &[(&str, u8, Option<&str>)] = &[
        ("CLAIM", 0, Some("cl")),
        ("TURN", 1, Some("tn")),
        ("SESSION", 2, Some("ss")),
        ("MESSAGE", 3, Some("ms")),
        ("PERSON", 4, Some("pr")),
        ("RELATIONSHIP", 5, Some("rl")),
        ("EVENT", 6, Some("ev")),
        ("SKILL", 7, Some("sk")),
        ("SUMMARY", 8, Some("sm")),
        ("PLACE", 9, Some("pl")),
        ("ASSET_TEXT", 10, Some("tx")),
        ("CONVERSATION", 11, Some("cv")),
        ("ORG", 12, Some("og")),
        ("FACET", 13, Some("fc")),
        ("WORLD", 14, Some("wd")),
        ("ASSET", 15, Some("as")),
        ("NOTIFICATION", 16, Some("nt")),
        ("TASK_LIST", 80, Some("tl")),
        ("TASK", 81, Some("tk")),
        ("MACHINE", 82, Some("mc")),
        ("REDACTION_AUDIT", 120, None),
    ];

    let actual: Vec<_> = ENTITY_TYPE_REGISTRY
        .iter()
        .map(|entry| (entry.kind, entry.type_byte, entry.short_id_prefix))
        .collect();
    assert_eq!(actual.as_slice(), expected);

    for (name, byte, prefix) in expected {
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
    }

    assert!(short_id_prefix(99).is_err());
    assert!(short_id_prefix(255).is_err());
}

#[test]
fn entity_value_envelope_matches_arch_0002_layout() -> Result<()> {
    use crate::batch::{
        ENTITY_BODY_OFFSET, ENTITY_LEARNED_AT_OFFSET, ENTITY_OCCURRED_END_OFFSET,
        ENTITY_OCCURRED_START_OFFSET, ENTITY_TYPE_OFFSET, EntityMetadataHeader,
    };

    let (_dir, vault) = open_test_vault();
    let id = EntityId::now();
    let entity_type = 0_u8;
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
        .put(&src, 0, test_time_range(1, 2), 3, b"src")
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
    match err {
        Error::InvalidVad { component, value } => {
            assert_eq!(component, expected_component);
            if expected_value.is_nan() {
                assert!(value.is_nan());
            } else {
                assert_eq!(value, expected_value);
            }
        }
        other => panic!("expected invalid vad, got {other:?}"),
    }

    assert!(message.contains(&format!("{expected_component:?}")));
    assert!(message.contains(&expected_value.to_string()));
}

#[test]
fn batch_edge_with_vad_api() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let src = EntityId::now();
    let tgt = EntityId::now();

    vault
        .batch()
        .put(&src, 0, test_time_range(1, 2), 3, b"src")
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

#[test]
fn reput_with_different_type_byte_is_rejected_with_no_index_residue() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let id = EntityId::now();

    vault
        .batch()
        .put(&id, 0, test_time_range(100, 200), 300, b"old-data")
        .commit()?;
    let record_before = read_raw_entity(&vault, &id)?;
    let short_id_before = read_short_id_value(&vault, &id)?;

    // D2: the type byte is immutable once a record exists. The pre-D2 engine
    // silently re-homed the type_index row and kept the old short id, leaving
    // a TURN entity addressed as "cl1".
    let err = vault
        .batch()
        .put(&id, 1, test_time_range(400, 500), 600, b"new-data")
        .commit()
        .expect_err("re-put with a different type byte must be rejected");
    assert!(
        matches!(
            err,
            Error::EntityTypeImmutable {
                id: err_id,
                existing: 0,
                attempted: 1,
            } if err_id == id
        ),
        "expected EntityTypeImmutable {{ existing: 0, attempted: 1 }}, got {err:?}"
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
            .get(&rtxn, &Store::encode_type_key(0, &id))?
            .is_some()
    );
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

    vault.put_entity(&id, 0, test_time_range(100, 200), 300, b"old-data")?;
    let record_before = read_raw_entity(&vault, &id)?;
    let short_id_before = read_short_id_value(&vault, &id)?;

    // Commit the externally-owned transaction DESPITE the error: the
    // apply-time gate must reject before staging any write, so an
    // implementation that re-homes index rows before checking the type byte
    // leaves residue these assertions catch.
    let mut wtxn = vault.store.env.write_txn()?;
    let err = vault
        .batch_in()
        .put(&id, 1, test_time_range(400, 500), 600, b"new-data")
        .apply(&mut wtxn)
        .expect_err("re-put with a different type byte must be rejected");
    assert!(
        matches!(
            err,
            Error::EntityTypeImmutable {
                id: err_id,
                existing: 0,
                attempted: 1,
            } if err_id == id
        ),
        "expected EntityTypeImmutable {{ existing: 0, attempted: 1 }}, got {err:?}"
    );
    wtxn.commit()?;

    assert_eq!(read_raw_entity(&vault, &id)?, record_before);
    assert_eq!(read_short_id_value(&vault, &id)?, short_id_before);

    let rtxn = vault.store.env.read_txn()?;
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
fn put_with_reversed_occurred_range_is_rejected_and_nothing_is_written() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let id = EntityId::now();

    // D3: occurred_start > occurred_end is rejected with a typed error. The
    // pre-D3 engine silently swapped the bounds and stored (100, 300).
    let err = vault
        .batch()
        .put(&id, 0, test_time_range(300, 100), 400, b"payload")
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
                .get(&rtxn, &Store::encode_type_key(0, &id))?
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
            0,
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
        .put(&id, 0, test_time_range(300, 100), 400, b"payload")
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
        .put(&id, 0, test_time_range(777, 777), 800, b"point")
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

    assert_eq!(EdgeKind::ChildOf.default_weight(), 1.0);
    assert_eq!(EdgeKind::AssignedTo.default_weight(), 0.8);
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
        assert!(matches!(err, Error::CorruptedIndex("type index key")));
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
        assert!(matches!(err, Error::CorruptedIndex("type index key")));
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
    assert!(matches!(err, Error::IndexOverflow("entities_by_type")));
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
    assert!(matches!(targets_err, Error::IndexOverflow("targets")));

    let sources_err = vault
        .sources(&tgt, EdgeKind::BelongsTo, None)
        .expect_err("sources should fail loud once cap is exceeded");
    assert!(matches!(sources_err, Error::IndexOverflow("sources")));
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
    assert!(matches!(targets_err, Error::IndexOverflow("targets")));

    let sources_err = vault
        .sources(&tgt, EdgeKind::BelongsTo, Some(ENTITY_TYPE_TASK_LIST))
        .expect_err("type-filtered sources should fail loud once scan cap is exceeded");
    assert!(matches!(sources_err, Error::IndexOverflow("sources")));
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
    assert!(matches!(err, Error::IndexOverflow("subtree")));
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
        for i in 0..DEPTH {
            batch = batch.edge(&nodes[i + 1], EdgeKind::ChildOf, &nodes[i], 1.0);
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
        for i in 0..ANCESTOR_CAP {
            let key =
                Store::encode_edge_key(&exact_nodes[i + 1], EdgeKind::ChildOf, &exact_nodes[i]);
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
    assert!(matches!(anc_err, Error::IndexOverflow("ancestors")));

    let unrelated = seeded_entity_id(3_000_000);
    let cycle_err = vault
        .would_create_cycle(&unrelated, &exact_nodes[ANCESTOR_CAP])
        .expect_err("public cycle check should fail loud once depth cap is exceeded");
    assert!(matches!(
        cycle_err,
        Error::IndexOverflow("child_of_cycle_check")
    ));

    let batch_err = vault
        .batch()
        .edge_checked(&unrelated, &exact_nodes[ANCESTOR_CAP], 1.0)
        .commit()
        .expect_err("batch cycle check should fail loud once depth cap is exceeded");
    assert!(matches!(
        batch_err,
        Error::IndexOverflow("child_of_cycle_check")
    ));
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
        for i in 0..=TRAVERSAL_CAP {
            let key = Store::encode_edge_key(&nodes[i + 1], EdgeKind::ChildOf, &nodes[i]);
            vault.store.edges_out.put(wtxn, &key, &value)?;
        }
        Ok(())
    })?;

    let public_err = vault
        .would_create_cycle(&nodes[0], &nodes[TRAVERSAL_CAP + 1])
        .expect_err("public cycle check should overflow before reporting a deep positive match");
    assert!(matches!(
        public_err,
        Error::IndexOverflow("child_of_cycle_check")
    ));

    let batch_err = vault
        .batch()
        .edge_checked(&nodes[0], &nodes[TRAVERSAL_CAP + 1], 1.0)
        .commit()
        .expect_err("batch cycle check should overflow before reporting a deep positive match");
    assert!(matches!(
        batch_err,
        Error::IndexOverflow("child_of_cycle_check")
    ));
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

#[test]
fn child_of_has_no_ppr_hop_limit() -> Result<()> {
    let (_dir, vault) = open_test_vault();

    // Build a 5-level deep ChildOf chain: a → b → c → d → e
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

    // PPR from e should reach a (5 hops via ChildOf, no limit)
    {
        let rtxn = vault.store.env.read_txn()?;
        let scores = ppr::ppr_compute(&vault.store, &rtxn, &[e], 6, 0.15)?;
        let a_score = scores
            .iter()
            .find(|s| s.id == a)
            .map(|s| s.score)
            .unwrap_or(0.0);
        assert!(
            a_score > 0.0,
            "ChildOf should propagate beyond 2 hops, got score={a_score}"
        );
    }

    // Compare with PartOf chain of same depth — d should be blocked at 3rd hop
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

#[test]
fn child_of_survives_mixed_part_of_path() -> Result<()> {
    let (_dir, vault) = open_test_vault();

    // Build a mixed path: place1 --PartOf--> place2 --PartOf--> place3 --ChildOf--> task
    // After 2 PartOf hops (place1→place3), the next edge is ChildOf.
    // Without the ChildOf exemption in PPR, this would be blocked at hop 3.
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

    // place1 is reachable via: task --ChildOf--> place3 --PartOf--> place2 --PartOf--> place1
    // The ChildOf hop doesn't count, so only 2 PartOf hops (within limit).
    // Without the ChildOf exemption, hops would be 3 and place1 would be blocked.
    let place1_score = scores
        .iter()
        .find(|s| s.id == place1)
        .map(|s| s.score)
        .unwrap_or(0.0);
    assert!(
        place1_score > 0.0,
        "ChildOf should not count toward PartOf hop limit in mixed paths, got score={place1_score}"
    );

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
    assert!(matches!(err, Error::CycleDetected));
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
    assert!(matches!(
        err,
        Error::InvariantViolation("childof requires a single parent")
    ));
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
            0,
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
        .put_entity(&id, 0, TimeRange { start: 1, end: 1 }, 1, b"exists")
        .unwrap();
    vault
        .put_entity(&other, 0, TimeRange { start: 1, end: 1 }, 1, b"other")
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
            0,
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
            0,
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
            0,
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
                .put(&id, 0, TimeRange { start: 1, end: 1 }, 1, b"atomic")
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
        .put(&src, 0, TimeRange { start: 1, end: 1 }, 1, b"src")
        .put(&tgt, 0, TimeRange { start: 1, end: 1 }, 1, b"tgt")
        .edge_with_created_at(&src, EdgeKind::Mentions, &tgt, 0.8, 99999)
        .commit()
        .unwrap();

    let edges = vault.edges_out(&src).unwrap();
    assert_eq!(edges.len(), 1);
    assert_eq!(edges[0].created_at, 99999);
    assert!((edges[0].weight - 0.8).abs() < f32::EPSILON);
}
