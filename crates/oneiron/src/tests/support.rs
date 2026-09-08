//! Shared fixtures, oracles and low-level read helpers for the vault tests.

use super::*;

/// Stamps `sensitivity: public` (band 0) on a claim body.
///
/// The ONE-1645 provenance floor makes an UNSTAMPED claim read band 2, which
/// exceeds the `max_auto_sensitivity: 0` row
/// `seed_generated_auto_source_trust_manifest` installs — the write itself
/// would be refused at the gate. The fixtures that pair these two helpers test
/// the CONSOLIDATION rule (Auto/Generated claims are not consolidatable until
/// vetted), which can only be observed once the claim actually lands, so they
/// stamp public to get past the write door. The floor is pinned directly by
/// `gate_source_trust_unstamped_claim_hits_floor_band`.
pub(super) fn public_stamped(mut body: ClaimBody) -> ClaimBody {
    body.scope = Some(rmpv::Value::Map(vec![(
        rmpv::Value::from("sensitivity"),
        rmpv::Value::from("public"),
    )]));
    body
}

pub(super) fn seed_generated_auto_source_trust_manifest(vault: &Vault) -> Result<()> {
    let manifest = rmpv::Value::Map(vec![
        (
            rmpv::Value::from("schema_version"),
            rmpv::Value::from("1.1"),
        ),
        (
            rmpv::Value::from("pack_id"),
            rmpv::Value::from("generated-auto-test"),
        ),
        (rmpv::Value::from("pack_version"), rmpv::Value::from("v1")),
        (
            rmpv::Value::from("min_engine_version"),
            rmpv::Value::from(env!("CARGO_PKG_VERSION")),
        ),
        (
            rmpv::Value::from("defaults"),
            rmpv::Value::Map(vec![
                (
                    rmpv::Value::from("criticality"),
                    rmpv::Value::from("normal"),
                ),
                (
                    rmpv::Value::from("sensitivity"),
                    rmpv::Value::from("normal"),
                ),
            ]),
        ),
        (rmpv::Value::from("rules"), rmpv::Value::Array(Vec::new())),
        (
            rmpv::Value::from("actor_ceilings"),
            rmpv::Value::Array(vec![rmpv::Value::Map(vec![
                (
                    rmpv::Value::from("actor_class"),
                    rmpv::Value::from("first_party"),
                ),
                (rmpv::Value::from("ceiling"), rmpv::Value::from("auto")),
            ])]),
        ),
        (
            rmpv::Value::from("source_trust"),
            rmpv::Value::Map(vec![(
                rmpv::Value::from("generated"),
                rmpv::Value::Map(vec![
                    (
                        rmpv::Value::from("max_auto_sensitivity"),
                        rmpv::Value::from(0_u64),
                    ),
                    (rmpv::Value::from("receipted"), rmpv::Value::Boolean(true)),
                    (rmpv::Value::from("warned"), rmpv::Value::Boolean(true)),
                ]),
            )]),
        ),
    ]);
    let mut data = Vec::new();
    rmpv::encode::write_value(&mut data, &manifest)
        .map_err(|_| Error::InvariantViolation("failed to encode policy manifest fixture"))?;

    let id = EntityId::from_bytes([0x6D; ENTITY_ID_LEN])
        .map_err(|_| Error::InvariantViolation("invalid policy fixture id"))?;
    let learned_at = 2_u64;
    let mut payload = Vec::with_capacity(ENTITY_METADATA_HEADER_LEN + data.len());
    payload.push(ENTITY_TYPE_POLICY_MANIFEST);
    payload.extend_from_slice(&learned_at.to_be_bytes());
    payload.extend_from_slice(&learned_at.to_be_bytes());
    payload.extend_from_slice(&learned_at.to_be_bytes());
    payload.extend_from_slice(&data);

    let mut wtxn = vault.store.env.write_txn()?;
    vault
        .store
        .entities
        .put(&mut wtxn, id.as_bytes(), &payload)?;
    let type_key = Store::encode_type_key(ENTITY_TYPE_POLICY_MANIFEST, &id);
    vault.store.type_index.put(&mut wtxn, &type_key, &[])?;
    let temporal_key = Store::encode_temporal_key(learned_at, &id);
    vault
        .store
        .temporal_occurred_start
        .put(&mut wtxn, &temporal_key, &[])?;
    vault
        .store
        .temporal_learned
        .put(&mut wtxn, &temporal_key, &[])?;
    wtxn.commit()?;
    Ok(())
}

pub(super) fn valid_edge_value() -> Vec<u8> {
    encode_edge_value(EdgeKind::BelongsTo, 0.0, 0, Vad::NEUTRAL, None)
        .expect("valid structural edge value")
}

/// Builds a structurally valid CLAIM body (D11 pinned keys) for raw type-0
/// writes. The subject is an arbitrary valid entity id — the raw write path
/// validates structure only; subject existence is `put_claim`'s concern.
pub(super) fn valid_claim_body_bytes(pred: &str, val: &str) -> Vec<u8> {
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

pub(super) fn read_meta_u16(vault: &Vault, key: &[u8]) -> Result<Option<u16>> {
    let rtxn = vault.store.env.read_txn()?;
    let Some(raw) = vault.store.vault_meta.get(&rtxn, key)? else {
        return Ok(None);
    };
    let bytes: [u8; 2] = raw.as_ref().try_into().map_err(|_| Error::InvalidKey)?;
    Ok(Some(u16::from_le_bytes(bytes)))
}

pub(super) fn vault_meta_rows_with_prefix(
    vault: &Vault,
    prefix: &[u8],
) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
    let rtxn = vault.store.env.read_txn()?;
    let mut rows = Vec::new();
    for row in vault.store.vault_meta.prefix_iter(&rtxn, prefix)? {
        let (key, value) = row?;
        rows.push((key.to_vec(), value.to_vec()));
    }
    Ok(rows)
}

pub(super) fn legacy_hnsw_compatibility_record(
    config: &VaultConfig,
) -> [u8; LEGACY_HNSW_COMPATIBILITY_LEN] {
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

pub(super) fn read_hnsw_config_record(vault: &Vault) -> Result<Vec<u8>> {
    let rtxn = vault.store.env.read_txn()?;
    let Some(raw) = vault.store.hnsw_meta.get(&rtxn, HNSW_CONFIG_KEY)? else {
        return Err(Error::InvalidKey);
    };
    Ok(raw.to_vec())
}

pub(super) fn write_hnsw_config_record(vault: &Vault, raw: &[u8]) -> Result<()> {
    let mut wtxn = vault.store.env.write_txn()?;
    vault.store.hnsw_meta.put(&mut wtxn, HNSW_CONFIG_KEY, raw)?;
    wtxn.commit()?;
    Ok(())
}

pub(super) fn redaction_audit_receipts(vault: &Vault) -> Result<Vec<EntityId>> {
    vault.entities_by_type(ENTITY_TYPE_REDACTION_AUDIT)
}

pub(super) fn hard_erase_sweep_rows(vault: &Vault) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
    let rtxn = vault.store.env.read_txn()?;
    let mut rows = Vec::new();
    for row in vault.store.sync_queue.prefix_iter(&rtxn, b"h:")? {
        let (key, value) = row?;
        rows.push((key.to_vec(), value.to_vec()));
    }
    Ok(rows)
}

pub(super) fn receipt_body(raw: &[u8]) -> serde_json::Value {
    rmp_serde::from_slice(&raw[ENTITY_METADATA_HEADER_LEN..]).expect("decode receipt body")
}

pub(super) fn assert_receipt_fields(receipt: &serde_json::Value) {
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

pub(super) fn assert_no_receipt_payload_leak(raw: &[u8], needles: &[&[u8]]) {
    for needle in needles {
        assert!(
            !raw.windows(needle.len()).any(|window| window == *needle),
            "receipt leaked forbidden content bytes: {:?}",
            String::from_utf8_lossy(needle)
        );
    }
}

pub(super) fn materialized_database_names(vault: &Vault) -> Result<Vec<String>> {
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

pub(super) fn expected_manifest_names() -> Vec<&'static str> {
    let mut names: Vec<&'static str> = DB_MANIFEST.iter().map(|entry| entry.name).collect();
    names.sort_unstable();
    names
}

pub(super) fn create_raw_vault_missing_manifest_name(path: &Path, missing: &str) -> Result<()> {
    let mut names = expected_manifest_names();
    names.retain(|name| *name != missing);
    create_raw_vault_with_manifest_names(path, &names)
}

pub(super) fn set_raw_storage_abi_version(
    path: &std::path::Path,
    value: Option<u16>,
) -> Result<()> {
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

pub(super) fn create_raw_vault_with_manifest_names(path: &Path, names: &[&str]) -> Result<()> {
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

pub(super) fn create_raw_named_database(path: &Path, name: &str) -> Result<()> {
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
pub(super) enum ContractEdgeLayout {
    Structural,
    SemanticBare,
}

impl ContractEdgeLayout {
    pub(super) fn bytes(self) -> usize {
        match self {
            Self::Structural => EDGE_VALUE_STRUCTURAL_LEN,
            Self::SemanticBare => EDGE_VALUE_SEMANTIC_LEN,
        }
    }
}

pub(super) const CONTRACT_EDGE_VALUE_LAYOUTS: [(EdgeKind, ContractEdgeLayout); 24] = [
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
    // ONE-1924: u8 23 `blocked_by`, structural 12 B (contracts.ts edgeKinds).
    (EdgeKind::BlockedBy, ContractEdgeLayout::Structural),
    // ONE-1608: u8 24 `blocks`, structural 12 B (contracts.ts edgeKinds).
    (EdgeKind::Blocks, ContractEdgeLayout::Structural),
    // ONE-1541: u8 25/26 `fulfills` / `discharged_by`, structural 12 B.
    (EdgeKind::Fulfills, ContractEdgeLayout::Structural),
    (EdgeKind::DischargedBy, ContractEdgeLayout::Structural),
];

pub(super) fn assert_f32_exact(actual: f32, expected: f32) {
    assert_eq!(actual.to_bits(), expected.to_bits());
}

pub(super) fn assert_vad_exact(actual: Vad, expected: Vad) {
    assert_f32_exact(actual.valence, expected.valence);
    assert_f32_exact(actual.arousal, expected.arousal);
    assert_f32_exact(actual.dominance, expected.dominance);
}

pub(super) fn contract_vad(i: usize) -> Vad {
    Vad {
        valence: -0.75 + (i as f32 * 0.05),
        arousal: 0.10 + (i as f32 * 0.02),
        dominance: 0.20 + (i as f32 * 0.03),
    }
}

pub(super) fn assert_common_edge_value_fields(value: &[u8], weight: f32, created_at: u64) {
    assert_eq!(&value[0..4], &weight.to_le_bytes());
    assert_eq!(&value[4..12], &created_at.to_le_bytes());
}

pub(super) fn assert_vad_bytes(value: &[u8], vad: Vad) {
    assert_eq!(&value[12..16], &vad.valence.to_le_bytes());
    assert_eq!(&value[16..20], &vad.arousal.to_le_bytes());
    assert_eq!(&value[20..24], &vad.dominance.to_le_bytes());
}

pub(super) fn contract_structural_value(weight: f32, created_at: u64) -> Vec<u8> {
    let mut value = Vec::with_capacity(EDGE_VALUE_STRUCTURAL_LEN);
    value.extend_from_slice(&weight.to_le_bytes());
    value.extend_from_slice(&created_at.to_le_bytes());
    assert_eq!(value.len(), EDGE_VALUE_STRUCTURAL_LEN);
    value
}

pub(super) fn contract_semantic_bare_value(weight: f32, created_at: u64, vad: Vad) -> Vec<u8> {
    let mut value = contract_structural_value(weight, created_at);
    value.extend_from_slice(&vad.valence.to_le_bytes());
    value.extend_from_slice(&vad.arousal.to_le_bytes());
    value.extend_from_slice(&vad.dominance.to_le_bytes());
    assert_eq!(value.len(), EDGE_VALUE_SEMANTIC_LEN);
    value
}

pub(super) fn contract_semantic_provenanced_value(
    weight: f32,
    created_at: u64,
    vad: Vad,
) -> Vec<u8> {
    let mut value = contract_semantic_bare_value(weight, created_at, vad);
    value.push(1); // confirmation_status = confirmed
    value.push(1); // actor_class = agent
    assert_eq!(value.len(), EDGE_VALUE_SEMANTIC_PROVENANCED_LEN);
    value
}

pub(super) fn encoded_entity_record(entity_type: u8, payload: &[u8]) -> Vec<u8> {
    let mut row = Vec::with_capacity(ENTITY_METADATA_HEADER_LEN + payload.len());
    row.push(entity_type);
    row.extend_from_slice(&0_u64.to_be_bytes());
    row.extend_from_slice(&0_u64.to_be_bytes());
    row.extend_from_slice(&0_u64.to_be_bytes());
    row.extend_from_slice(payload);
    row
}

pub(super) fn content_hash(data: &[u8]) -> u8 {
    (xxh32(data, 0) % 256) as u8
}

pub(super) fn decode_short_id_value(value: &[u8]) -> Result<(String, u8)> {
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
pub(super) fn read_short_id_value(vault: &Vault, id: &EntityId) -> Result<Vec<u8>> {
    let rtxn = vault.store.env.read_txn()?;
    vault
        .store
        .short_ids_reverse
        .get(&rtxn, id.as_bytes())?
        .map(|bytes| bytes.to_vec())
        .ok_or(Error::EntityNotFound)
}

pub(super) fn read_raw_entity(vault: &Vault, id: &EntityId) -> Result<Vec<u8>> {
    let rtxn = vault.store.env.read_txn()?;
    vault
        .store
        .entities
        .get(&rtxn, id.as_bytes())?
        .map(|bytes| bytes.to_vec())
        .ok_or(Error::EntityNotFound)
}

pub(super) fn read_hnsw_meta_u64(vault: &Vault, key: &[u8]) -> Result<u64> {
    let rtxn = vault.store.env.read_txn()?;
    let Some(raw) = vault.store.hnsw_meta.get(&rtxn, key)? else {
        return Ok(0);
    };
    Ok(u64::from_le_bytes(
        raw.as_ref().try_into().map_err(|_| Error::InvalidKey)?,
    ))
}

pub(super) fn read_model_id(vault: &Vault) -> Result<Option<String>> {
    let rtxn = vault.store.env.read_txn()?;
    let Some(raw) = vault.store.hnsw_meta.get(&rtxn, MODEL_ID_KEY)? else {
        return Ok(None);
    };
    String::from_utf8(raw.to_vec())
        .map(Some)
        .map_err(|_| Error::InvalidKey)
}

pub(super) fn decode_forward_codes(raw: &[u8]) -> Result<Vec<String>> {
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

pub(super) fn sync_state_value(vault: &Vault, key: &str) -> Result<Option<Vec<u8>>> {
    let rtxn = vault.store.env.read_txn()?;
    Ok(vault
        .store
        .sync_state
        .get(&rtxn, key)?
        .map(|value| value.to_vec()))
}

pub(super) fn sync_state_keys_with_prefix_raw(vault: &Vault, prefix: &str) -> Result<Vec<String>> {
    let rtxn = vault.store.env.read_txn()?;
    let mut keys = Vec::new();
    for row in vault.store.sync_state.prefix_iter(&rtxn, prefix)? {
        let (key, _) = row?;
        keys.push(key.to_string());
    }
    Ok(keys)
}

pub(super) fn sync_queue_row_count_with_prefix(vault: &Vault, prefix: &[u8]) -> Result<usize> {
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
pub(super) fn assert_no_erasure_audit_artifacts(vault: &Vault) -> Result<()> {
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
pub(super) fn run_raced_delete<F>(
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
pub(super) fn run_raced_delete_rendezvous<F>(
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

pub(super) fn run_raced_delete_inner<F>(
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
        crate::deletion::install_after_header_read_signal(tx);
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
pub(super) fn assert_raced_delete_artifacts(
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

/// Builds a v2 tombstone wire value from LITERAL parts (never via the
/// engine's encoder — these bytes are the test INPUT, and the layout under
/// test is the pinned `[reason:1][deleted_at:8 LE][request_id:16]`).
pub(super) fn wire_tombstone(reason_byte: u8, deleted_at: u64, request_byte: u8) -> Vec<u8> {
    let mut value = vec![reason_byte];
    value.extend_from_slice(&deleted_at.to_le_bytes());
    value.extend_from_slice(&[request_byte; 16]);
    value
}

/// Reads the raw `pt:{window}:{hex}` pending-tombstone marker (ONE-1132).
#[cfg(not(feature = "sync"))]
pub(super) fn pending_tombstone_row(
    vault: &Vault,
    window: &str,
    id: &EntityId,
) -> Result<Option<Vec<u8>>> {
    let rtxn = vault.store.env.read_txn()?;
    let key = format!("pt:{window}:{}", id.to_hex());
    Ok(vault
        .store
        .sync_state
        .get(&rtxn, &key)?
        .map(|value| value.to_vec()))
}

#[cfg(feature = "sync")]
pub(super) struct MigrationEmbedder {
    pub(super) model_id: String,
}

#[cfg(feature = "sync")]
impl Embedder for MigrationEmbedder {
    fn model_id(&self) -> &str {
        &self.model_id
    }
    fn dimensions(&self) -> usize {
        4
    }
    fn locality(&self) -> EmbedderLocality {
        EmbedderLocality::OnDevice
    }
    fn embed(&self, inputs: &[PendingEmbeddingInput]) -> Result<Vec<Vec<f32>>> {
        Ok(inputs.iter().map(|_| vec![0.0, 1.0, 0.0, 0.0]).collect())
    }
}

pub(super) fn assert_invalid_vad(
    err: Error,
    expected_component: VadComponent,
    expected_value: f32,
) {
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

pub(super) fn assert_vad_annotation_claim_present(
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

pub(super) fn assert_vad_annotation_claim_removed(
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

pub(super) fn put_claim_vad_turn(
    vault: &Vault,
    id: &EntityId,
    learned_at: u64,
    vad: Vad,
) -> Result<()> {
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

pub(super) fn claim_vad_fixture_body(subject: EntityId, turns: &[EntityId]) -> ClaimBody {
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

pub(super) fn assert_vad_close(actual: Vad, expected: Vad) {
    const EPSILON: f32 = 0.000_001;
    assert!((actual.valence - expected.valence).abs() < EPSILON);
    assert!((actual.arousal - expected.arousal).abs() < EPSILON);
    assert!((actual.dominance - expected.dominance).abs() < EPSILON);
}

pub(super) fn entity_header(vault: &Vault, id: &EntityId) -> Result<EntityMetadataHeader> {
    let rtxn = vault.store.env.read_txn()?;
    let raw = vault
        .store
        .entities
        .get(&rtxn, id.as_bytes())?
        .ok_or(Error::EntityNotFound)?;
    EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))
}

pub(super) fn coping_outcome_fixture_body(
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

pub(super) fn assert_f32_close(actual: f32, expected: f32) {
    const EPSILON: f32 = 0.000_001;
    assert!(
        (actual - expected).abs() < EPSILON,
        "expected {expected}, got {actual}"
    );
}

pub(super) fn assert_reparent_order_independent<F>(apply_reparent: F) -> Result<()>
where
    F: FnOnce(&Vault, EntityId, EntityId, EntityId) -> Result<()>,
{
    let (_dir, vault) = open_test_vault();

    let child = EntityId::now();
    let parent_a = EntityId::now();
    let parent_b = EntityId::now();

    put_tree_nodes(vault.batch(), &[child, parent_a, parent_b])
        .edge(&child, EdgeKind::ChildOf, &parent_a, 1.0)
        .commit()?;

    apply_reparent(&vault, child, parent_a, parent_b)?;

    let parents = vault.targets(&child, EdgeKind::ChildOf, None)?;
    assert_eq!(parents, vec![parent_b]);
    Ok(())
}

/// Asserts that no entity-record or index row anywhere references `id`.
/// Used by every negative claim test to prove a rejected write left nothing.
pub(super) fn assert_no_entity_state(vault: &Vault, id: &EntityId) -> Result<()> {
    let rtxn = vault.store.env.read_txn()?;
    assert!(
        vault.store.entities.get(&rtxn, id.as_bytes())?.is_none(),
        "entities row leaked for rejected write"
    );
    // Entity-keyed direct probe (ONE-1152): `short_ids_reverse` is the
    // entity-keyed table per the pinned DB manifest (key entity_id ->
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
                !slice_contains(&key, id.as_bytes()) && !slice_contains(&value, id.as_bytes()),
                "{name} row references rejected entity"
            );
        }
    }
    Ok(())
}

pub(super) fn slice_contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

/// Schema-agnostic short-id lookup: scans BOTH short-id DBs raw and accepts
/// whichever row links `id` to an ASCII `<prefix><counter>` short id.
///
/// WHY (cross-branch schema compat, ONE-1102): the parallel ONE-1102 branch
/// swaps the short-id table direction per the pinned DB manifest
/// (`short_ids`: key short_id bytes + content_hash u8 -> entity_id;
/// `short_ids_reverse`: key entity_id -> short_id + hash), while this branch
/// still carries the pre-1102 orientation (`short_ids`: entity_id ->
/// short_id + hash; `short_ids_reverse`: short_id -> entity_id). Reading one
/// fixed layout here would break this test on whichever side merges second,
/// so callers' prefix assertions stay green on this branch standalone AND
/// after ONE-1102 lands.
pub(super) fn find_short_id_any_schema(vault: &Vault, id: &EntityId) -> Result<Option<String>> {
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
            if *key == *id.as_bytes()
                && let Some(short_id) = parse_with_optional_hash(&value)
            {
                return Ok(Some(short_id));
            }
            // Orientation 2: short_id (+ hash) -> entity_id.
            if *value == *id.as_bytes()
                && let Some(short_id) = parse_with_optional_hash(&key)
            {
                return Ok(Some(short_id));
            }
        }
    }
    Ok(None)
}

pub(super) fn rmpv_map_bytes(entries: &[(rmpv::Value, rmpv::Value)]) -> Vec<u8> {
    let mut out = Vec::new();
    rmpv::encode::write_value(&mut out, &rmpv::Value::Map(entries.to_vec()))
        .expect("encode msgpack map");
    out
}

pub(super) fn task_body(role: TaskRole) -> Vec<u8> {
    rmpv_map_bytes(&[("role".into(), role.role_byte().into())])
}

/// Stages generic (NON-TASK) nodes for the `ChildOf` topology tests.
///
/// Single-parent cardinality, cycle rejection, dangling-parent rejection, and
/// the `subtree`/`ancestors` walks are domain-agnostic — STO-04's
/// productivity role matrix engages only when the edge SOURCE is a TASK. So
/// these tests hold a deliberately non-TASK pair, proving that a `ChildOf`
/// user outside the productivity pack keeps every tree guarantee without
/// being forced through `TaskRole` decoding. The matrix itself is covered
/// over TASK pairs in `batch/tests.rs` (ONE-1376).
///
/// Existence matters now: every node a `ChildOf` edge names as a parent must
/// be a real row, so these tests stage the whole node set up front.
pub(super) fn put_tree_nodes<'a>(
    mut batch: BatchBuilder<'a>,
    nodes: &[EntityId],
) -> BatchBuilder<'a> {
    for (index, node) in nodes.iter().enumerate() {
        let stamp = index as u64 + 1;
        batch = batch.put(
            node,
            ENTITY_TYPE_PERSON,
            test_time_range(stamp, stamp),
            stamp,
            b"tree node",
        );
    }
    batch
}

/// Structurally-VALID `edge.provenance` ClaimBody for door tests: a real
/// value record + the engine-owned actor-class evidence map. Since ONE-1159
/// the write chokepoint validates provenance STRUCTURE (value record +
/// persisted actor_class), so reserved-door tests can no longer carry an
/// opaque junk `val`.
pub(super) fn valid_provenance_claim_body(
    actor: EntityId,
    source: EntityId,
    target: EntityId,
) -> ClaimBody {
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
pub(super) fn base_claim_entries(pred: &str, subj: Vec<u8>) -> Vec<(rmpv::Value, rmpv::Value)> {
    vec![
        ("pred".into(), pred.into()),
        ("val".into(), "x".into()),
        ("conf".into(), rmpv::Value::F32(0.5)),
        ("subj".into(), rmpv::Value::Binary(subj)),
        ("appr".into(), "auto".into()),
        ("life".into(), "active".into()),
    ]
}

pub(super) fn entries_without(
    base: &[(rmpv::Value, rmpv::Value)],
    key: &str,
) -> Vec<(rmpv::Value, rmpv::Value)> {
    base.iter()
        .filter(|(k, _)| k.as_str() != Some(key))
        .cloned()
        .collect()
}

pub(super) fn entries_replacing(
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

/// FED-001: `put_replicated` admits the registered maintenance type byte for
/// FEDERATION_GRANT, but the body still has to fail closed before storage or
/// indexes are written.
#[cfg(feature = "sync")]
pub(super) fn federation_grant_body_with_role_and_preset(role: &str, preset: &str) -> Vec<u8> {
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

/// Raw `(edges_out, edges_in)` value bytes for one edge.
pub(super) type RawEdgeValuePair = (Option<Vec<u8>>, Option<Vec<u8>>);

/// Reads the raw `edges_out` / `edges_in` values for `edge` (both directions)
/// without any decoding — byte-level test oracle.
pub(super) fn raw_edge_values(vault: &Vault, edge: &EdgeRef) -> Result<RawEdgeValuePair> {
    let rtxn = vault.store.env.read_txn()?;
    let key_out = Store::encode_edge_key(&edge.source, edge.kind, &edge.target);
    let key_in = Store::encode_edge_key(&edge.target, edge.kind, &edge.source);
    let out = vault
        .store
        .edges_out
        .get(&rtxn, &key_out)?
        .map(|value| value.to_vec());
    let inn = vault
        .store
        .edges_in
        .get(&rtxn, &key_in)?
        .map(|value| value.to_vec());
    Ok((out, inn))
}

/// Stores a minimal ACTIVE claim about `subject` (point occurred + learned
/// at `learned_at`) and returns its id.
pub(super) fn put_active_claim(
    vault: &Vault,
    subject: &EntityId,
    pred: &str,
    val: &str,
    learned_at: u64,
) -> Result<EntityId> {
    put_active_claim_with_source(vault, subject, pred, val, None, learned_at)
}

pub(super) fn put_active_claim_with_source(
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

pub(super) fn put_active_claim_with_source_and_approval(
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
pub(super) fn raw_edge_key(src: &EntityId, kind_u8: u8, tgt: &EntityId) -> Vec<u8> {
    let mut key = Vec::with_capacity(33);
    key.extend_from_slice(src.as_bytes());
    key.push(kind_u8);
    key.extend_from_slice(tgt.as_bytes());
    key
}

/// Stores a minimal ACTIVE claim about `subject` with an INTERVAL
/// `occurred` window and returns its id. The interval (start != end)
/// matters: only interval entities own a `temporal_occurred_end` row, so
/// these fixtures create the PRE-EXISTING end row that a lifecycle
/// refresh must MOVE (delete stale, write refreshed) — an
/// add-without-delete implementation cannot pass against them.
pub(super) fn put_active_interval_claim(
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

/// Lifecycle fixture: PERSON + MACHINE actors and one semantic
/// `a -mentions-> b` subject edge carrying VAD.
pub(super) struct LifecycleFixture {
    pub(super) _dir: tempfile::TempDir,
    pub(super) vault: Vault,
    pub(super) person: EntityId,
    pub(super) machine: EntityId,
    pub(super) subject: EdgeRef,
}

pub(super) fn lifecycle_fixture() -> Result<LifecycleFixture> {
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

/// Asserts one rejected plain-put attempt pinned the ONE-1113 contract: the
/// typed [`Error::EdgeIsProvenanced`] variant carrying the subject kind
/// byte, with a message that ROUTES the caller to the provenance path and
/// the operational setters ("reject-and-route" — a bare reject without the
/// route is half the ruling).
pub(super) fn assert_edge_is_provenanced_reject(
    err: &Error,
    expected_kind: EdgeKind,
    context: &str,
) {
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

pub(super) fn text_forward_row(vault: &Vault, id: &EntityId) -> Result<Vec<u8>> {
    let rtxn = vault.store.env.read_txn()?;
    vault
        .store
        .text_forward
        .get(&rtxn, id.as_bytes())?
        .map(|value| value.to_vec())
        .ok_or(Error::CorruptedIndex("missing text_forward row"))
}

pub(super) fn assert_text_rows_deindexed(vault: &Vault, id: &EntityId) -> Result<()> {
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

pub(super) fn assert_empty_text_corpus_after_deindex(vault: &Vault) -> Result<()> {
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
        vault.store.text_meta.get(&rtxn, &[0u8; 16])?.as_deref(),
        Some(&0u32.to_le_bytes()[..]),
        "TOTAL_DOCS must be decremented in the same txn as the overwrite"
    );
    Ok(())
}
