use std::collections::{BTreeMap, HashSet};

use crate::Vault;
use crate::batch::ENTITY_METADATA_HEADER_LEN;
use crate::claim::ClaimSubject;
use crate::context_board::{MemoriesBudget, project_memories_section};
use crate::disclosure::DisclosureContext;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::registry::{ENTITY_TYPE_CLAIM, ENTITY_TYPE_TURN};
use crate::store::Store;
use crate::temporal::TimeRange;
use crate::test_util::embedding_test_config;

use super::builder::HydrateOptions;
use super::edge_walk::scan_edges_for_entity;
use super::empty_pack::context_pack_empty_reason;
use super::hydration::{hydrate_entity, read_vector};
use super::quarantine::{
    PACK_QUARANTINE_ROW, PackQuarantineContainer, PackQuarantineRecord,
    pack_entity_crdt_key_metadata,
};
use super::telemetry::finalize_context_pack_telemetry;
use super::validation::{
    PACK_VALIDATION_DELETED_PAYLOAD, PACK_VALIDATION_IMPOSSIBLE_TIME,
    PACK_VALIDATION_MISSING_EVIDENCE, PACK_VALIDATION_QUARANTINED_PAYLOAD,
    validate_pack_disclosure,
};
use super::*;

fn open_test_vault() -> (tempfile::TempDir, Vault) {
    let mut config = embedding_test_config();
    config.retrieval_telemetry_capture = true;
    crate::test_util::open_test_vault_with(config)
}

fn msgpack_entity(fields: serde_json::Value) -> Vec<u8> {
    rmp_serde::to_vec_named(&fields).expect("msgpack encode")
}

fn put_text_entity(
    vault: &Vault,
    id: &EntityId,
    entity_type: u8,
    text: &str,
    fields: serde_json::Value,
) -> Result<()> {
    let payload = msgpack_entity(fields);
    vault
        .batch()
        .put(id, entity_type, TimeRange { start: 1, end: 1 }, 1, &payload)
        .text(id, &[("body", text)])
        .commit()
}

/// Writes a structurally valid CLAIM (type 0, D11 pinned body keys) plus
/// a text row so it is retrievable through `search_text`.
fn put_claim_text_entity(
    vault: &Vault,
    id: &EntityId,
    text: &str,
    pred: &str,
    val: &str,
) -> Result<()> {
    put_claim_text_entity_with_lifecycle(
        vault,
        id,
        text,
        pred,
        val,
        crate::claim::ClaimLifecycleStatus::Active,
    )
}

fn put_claim_text_entity_with_lifecycle(
    vault: &Vault,
    id: &EntityId,
    text: &str,
    pred: &str,
    val: &str,
    life: crate::claim::ClaimLifecycleStatus,
) -> Result<()> {
    put_claim_text_entity_with_status(
        vault,
        id,
        text,
        pred,
        val,
        crate::claim::ClaimApprovalStatus::Auto,
        life,
    )
}

fn put_claim_text_entity_with_status(
    vault: &Vault,
    id: &EntityId,
    text: &str,
    pred: &str,
    val: &str,
    appr: crate::claim::ClaimApprovalStatus,
    life: crate::claim::ClaimLifecycleStatus,
) -> Result<()> {
    let subject = default_claim_subject_id()?;
    ensure_claim_subject_payload(vault, &subject)?;
    let body = crate::claim::ClaimBody::new(
        pred,
        crate::claim::ClaimSubject::Entity(subject),
        rmpv::Value::from(val),
        0.9,
        appr,
        life,
    )?;
    let payload = crate::claim::encode_claim_body(&body)?;
    vault
        .batch()
        .put(id, 0, TimeRange { start: 1, end: 1 }, 1, &payload)
        .text(id, &[("body", text)])
        .commit()
}

/// A vector-ranked CLAIM whose body carries an optional `world` scope
/// (`None` = base reality). Built through the pinned claim encoder so the
/// `world` key is the real 16-byte binary the partitioner groups by.
fn put_world_claim(
    vault: &Vault,
    id: EntityId,
    vector: [f32; 4],
    world: Option<EntityId>,
) -> Result<()> {
    let subject = default_claim_subject_id()?;
    ensure_claim_subject_payload(vault, &subject)?;
    let mut body = crate::claim::ClaimBody::new(
        "facet.scope_test",
        crate::claim::ClaimSubject::Entity(subject),
        rmpv::Value::from("v"),
        0.9,
        crate::claim::ClaimApprovalStatus::Auto,
        crate::claim::ClaimLifecycleStatus::Active,
    )?;
    body.world = world;
    let payload = crate::claim::encode_claim_body(&body)?;
    vault
        .batch()
        .put(
            &id,
            ENTITY_TYPE_CLAIM,
            TimeRange { start: 1, end: 1 },
            1,
            &payload,
        )
        .vector(&id, &vector)
        .commit()
}

fn raw_entity_record(
    entity_type: u8,
    occurred_start: u64,
    occurred_end: u64,
    learned_at: u64,
    payload: &[u8],
) -> Vec<u8> {
    crate::test_util::entity_record(
        entity_type,
        TimeRange {
            start: occurred_start,
            end: occurred_end,
        },
        learned_at,
        payload,
    )
}

fn overwrite_raw_entity(vault: &Vault, id: &EntityId, raw: &[u8]) -> Result<()> {
    vault.with_write_txn(|wtxn| {
        // These fixtures exercise live-row validation, not a torn revision ledger.
        // Keep the forged row unversioned so indexed pin capture reaches the same bytes.
        crate::vault::entity_revision::remove_entity_revisions(&vault.store, wtxn, id)?;
        vault.store.entities.put(wtxn, id.as_bytes(), raw)?;
        Ok(())
    })
}

fn default_claim_subject_id() -> Result<EntityId> {
    EntityId::from_bytes([0x7C; 16])
}

fn ensure_claim_subject_payload(vault: &Vault, id: &EntityId) -> Result<()> {
    if vault.get_raw(id)?.is_some() {
        return Ok(());
    }
    let raw = raw_entity_record(4, 1, 1, 1, &[]);
    overwrite_raw_entity(vault, id, &raw)
}

fn put_claim_text_entity_with_subject(
    vault: &Vault,
    id: &EntityId,
    subject: crate::claim::ClaimSubject,
    text: &str,
    pred: &str,
    val: &str,
) -> Result<()> {
    let body = crate::claim::ClaimBody::new(
        pred,
        subject,
        rmpv::Value::from(val),
        0.9,
        crate::claim::ClaimApprovalStatus::Auto,
        crate::claim::ClaimLifecycleStatus::Active,
    )?;
    let payload = crate::claim::encode_claim_body(&body)?;
    vault
        .batch()
        .put(
            id,
            ENTITY_TYPE_CLAIM,
            TimeRange { start: 1, end: 1 },
            1,
            &payload,
        )
        .text(id, &[("body", text)])
        .commit()
}

fn assert_context_pack_validation(
    err: Error,
    expected_id: EntityId,
    expected_reason: &'static str,
) {
    match err {
        Error::Record(RecordError::ContextPackValidation { id, reason }) => {
            assert_eq!(id, expected_id);
            assert_eq!(reason, expected_reason);
        }
        other => panic!(
            "expected ContextPackValidation({expected_reason:?}) for {}, got {other:?}",
            expected_id.to_hex()
        ),
    }
}

fn pack_quarantine_record_for_entity(window_key: &str, id: &EntityId) -> PackQuarantineRecord {
    let (crdt_key_hash, crdt_key_len) = pack_entity_crdt_key_metadata(id);
    PackQuarantineRecord {
        window_key: window_key.to_string(),
        container: PackQuarantineContainer::Entities,
        crdt_key_hash,
        crdt_key_len,
    }
}

fn pack_remat_marker_key(window_key: &str, id: &EntityId) -> String {
    format!("rm:w:{window_key}:{}", id.to_hex())
}

#[test]
fn hydrate_entity_rejects_present_corrupt_header() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let id = EntityId::now();

    vault.with_write_txn(|wtxn| {
        vault.store.entities.put(wtxn, id.as_bytes(), b"short")?;
        Ok(())
    })?;

    let rtxn = vault.store.env.read_txn()?;
    let mut claims_suppressed = 0;
    let err = match hydrate_entity(
        &vault,
        &rtxn,
        id,
        0.0,
        HydrateOptions {
            read_mode: crate::vault::ReadMode::Indexed,
            policy: &crate::gate::resolve_policy_manifest(&vault.store, &rtxn).unwrap(),
            criticality: None,
            hydrate_fields: true,
            include_edges: false,
            include_vectors: false,
            edge_cache: None,
            claim_bodies: None,
            clamp: None,
        },
        &mut claims_suppressed,
    ) {
        Ok(_) => panic!("present corrupt entity header must fail closed"),
        Err(err) => err,
    };

    assert!(
        matches!(err, Error::CorruptedIndex("entity metadata header")),
        "expected CorruptedIndex(\"entity metadata header\"), got {err:?}"
    );
    assert_eq!(claims_suppressed, 0);
    Ok(())
}

#[test]
fn read_vector_splits_absent_from_corrupt_rows() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let id = EntityId::now();

    {
        let rtxn = vault.store.env.read_txn()?;
        assert!(
            read_vector(&vault, &rtxn, &id)?.is_none(),
            "absent vector rows must remain Ok(None)"
        );
    }

    vault.with_write_txn(|wtxn| {
        vault.store.vectors.put(wtxn, id.as_bytes(), &[1, 2, 3])?;
        Ok(())
    })?;
    {
        let rtxn = vault.store.env.read_txn()?;
        let err = read_vector(&vault, &rtxn, &id)
            .expect_err("present undecodable vector row must fail closed");
        assert!(
            matches!(err, Error::CorruptedIndex("entity vector")),
            "expected CorruptedIndex(\"entity vector\"), got {err:?}"
        );
    }

    let wrong_dimension = [1.0_f32, 2.0, 3.0]
        .into_iter()
        .flat_map(f32::to_le_bytes)
        .collect::<Vec<_>>();
    vault.with_write_txn(|wtxn| {
        vault
            .store
            .vectors
            .put(wtxn, id.as_bytes(), &wrong_dimension)?;
        Ok(())
    })?;
    let rtxn = vault.store.env.read_txn()?;
    let err = read_vector(&vault, &rtxn, &id)
        .expect_err("present wrong-dimension vector row must fail closed");
    assert!(
        matches!(err, Error::CorruptedIndex("entity vector")),
        "expected CorruptedIndex(\"entity vector\"), got {err:?}"
    );
    Ok(())
}

#[test]
fn include_edges_rejects_malformed_edge_rows() -> Result<()> {
    let (_dir, vault) = open_test_vault();

    let src = EntityId::now();
    let healthy = EntityId::now();
    let tgt = EntityId::now();
    // Non-claim type byte (TURN = 1): this test is about EDGE rows, so the
    // seeded source must stay clear of the type-0 CLAIM body validation
    // (D17/D18) — its body is opaque at the storage layer.
    put_text_entity(
        &vault,
        &src,
        1,
        "alpha",
        serde_json::json!({"text": "alpha"}),
    )?;
    put_text_entity(
        &vault,
        &healthy,
        4,
        "beta",
        serde_json::json!({"name": "Alice"}),
    )?;
    vault.put_edge(&src, crate::edge::EdgeKind::Supports, &healthy, 0.7)?;

    // Plant a 13-byte edge value via a raw write: the contract pins the
    // edge value as a fixed-width LE buffer of exactly 12/24/26 bytes
    // (dbManifest n14), so 13 bytes is on-disk corruption.
    let key = Store::encode_edge_key(&src, crate::edge::EdgeKind::Mentions, &tgt);
    let value = [0_u8; 13];
    vault.with_write_txn(|wtxn| {
        vault.store.edges_out.put(wtxn, &key, &value)?;
        Ok(())
    })?;

    // The healthy edge must not rescue the pack: hydration fails closed
    // on the corrupt row instead of returning partial edges (D9).
    let err = vault
        .context_pack()
        .search_text("alpha", 10)
        .include_edges(true)
        .run()
        .expect_err("malformed edge row must fail context-pack hydration closed");
    assert!(
        matches!(err, Error::CorruptedIndex("edge record")),
        "expected CorruptedIndex(\"edge record\"), got {err:?}"
    );
    Ok(())
}

#[test]
fn edge_walk_rejects_malformed_edge_rows() -> Result<()> {
    let (_dir, vault) = open_test_vault();

    let root = EntityId::now();
    let neighbor = EntityId::now();
    let tgt = EntityId::now();
    // Non-claim type byte (TURN = 1): keeps this edge-row fixture clear of
    // the type-0 CLAIM body validation (D17/D18).
    put_text_entity(
        &vault,
        &root,
        1,
        "root",
        serde_json::json!({"text": "root"}),
    )?;
    put_text_entity(
        &vault,
        &neighbor,
        4,
        "friend",
        serde_json::json!({"name": "B"}),
    )?;
    vault.put_edge(&root, crate::edge::EdgeKind::Supports, &neighbor, 1.0)?;

    let key = Store::encode_edge_key(&root, crate::edge::EdgeKind::Mentions, &tgt);
    let value = [0_u8; 13];
    vault.with_write_txn(|wtxn| {
        vault.store.edges_out.put(wtxn, &key, &value)?;
        Ok(())
    })?;

    // include_edges stays off, so result hydration never scans edges —
    // the only edge reader on this path is the walk_edges neighbor
    // expansion, which must fail closed too (ONE-1101 AC 1).
    let err = vault
        .context_pack()
        .search_text("root", 10)
        .edge_hop(1)
        .run()
        .expect_err("malformed edge row must fail the neighbor walk closed");
    assert!(
        matches!(err, Error::CorruptedIndex("edge record")),
        "expected CorruptedIndex(\"edge record\"), got {err:?}"
    );
    Ok(())
}

#[test]
fn scan_rejects_each_malformed_edge_row_shape_like_vault_readers() -> Result<()> {
    let (_dir, vault) = open_test_vault();

    let src = EntityId::now();
    let tgt = EntityId::now();
    // Non-claim type byte (TURN = 1): keeps this edge-row fixture clear of
    // the type-0 CLAIM body validation (D17/D18).
    put_text_entity(
        &vault,
        &src,
        1,
        "alpha",
        serde_json::json!({"text": "alpha"}),
    )?;

    let supports_key = Store::encode_edge_key(&src, crate::edge::EdgeKind::Supports, &tgt).to_vec();
    let child_of_key = Store::encode_edge_key(&src, crate::edge::EdgeKind::ChildOf, &tgt).to_vec();

    // 33-byte key whose kind byte (20) is outside the pinned 0-19 range.
    let mut unknown_kind_key = src.as_bytes().to_vec();
    unknown_kind_key.push(20);
    unknown_kind_key.extend_from_slice(tgt.as_bytes());

    // 17-byte key: source id + kind byte, target id missing entirely.
    let mut truncated_key = src.as_bytes().to_vec();
    truncated_key.push(crate::edge::EdgeKind::Supports as u8);

    // 33-byte key whose target is the reserved all-0xFF sentinel id.
    let mut reserved_target_key = src.as_bytes().to_vec();
    reserved_target_key.push(crate::edge::EdgeKind::Supports as u8);
    reserved_target_key.extend_from_slice(&[0xFF; 16]);

    // 26-byte value with confirmation_status byte 4 (valid enums are 0-3).
    let mut bad_flag_value = vec![0_u8; 26];
    bad_flag_value[24] = 4;

    // Value lengths outside {12, 24, 26} and kind/layout-class mismatches
    // must all classify as CorruptedIndex("edge record") — exactly like
    // vault::parse_edge_record (ONE-1101 AC 3).
    let cases: Vec<(&str, &[u8], Vec<u8>)> = vec![
        ("empty value", &supports_key, vec![0_u8; 0]),
        ("13-byte value", &supports_key, vec![0_u8; 13]),
        ("25-byte value", &supports_key, vec![0_u8; 25]),
        ("27-byte value", &supports_key, vec![0_u8; 27]),
        (
            "12B structural value under a semantic kind",
            &supports_key,
            vec![0_u8; 12],
        ),
        (
            "24B semantic value under a structural kind",
            &child_of_key,
            vec![0_u8; 24],
        ),
        (
            "26B value with confirmation_status byte 4",
            &supports_key,
            bad_flag_value,
        ),
        ("unknown kind byte 20", &unknown_kind_key, vec![0_u8; 24]),
        ("truncated 17-byte key", &truncated_key, vec![0_u8; 24]),
        (
            "reserved sentinel target id",
            &reserved_target_key,
            vec![0_u8; 24],
        ),
    ];

    for (name, key, value) in &cases {
        vault.with_write_txn(|wtxn| {
            vault.store.edges_out.put(wtxn, key, value)?;
            Ok(())
        })?;

        {
            let rtxn = vault.store.env.read_txn()?;
            let err = scan_edges_for_entity(&vault.store, &rtxn, &src)
                .expect_err("context-pack scan must fail closed");
            assert!(
                matches!(err, Error::CorruptedIndex("edge record")),
                "case `{name}`: context-pack scan returned {err:?}"
            );
        }

        // Classification parity with the canonical vault reader on the
        // same planted bytes.
        let vault_err = vault
            .edges_out(&src)
            .expect_err("vault reader must fail closed");
        assert!(
            matches!(vault_err, Error::CorruptedIndex("edge record")),
            "case `{name}`: vault.edges_out returned {vault_err:?}"
        );

        vault.with_write_txn(|wtxn| {
            vault.store.edges_out.delete(wtxn, key)?;
            Ok(())
        })?;
        let rtxn = vault.store.env.read_txn()?;
        assert!(
            scan_edges_for_entity(&vault.store, &rtxn, &src)?.is_empty(),
            "case `{name}`: scan should be clean after removing the planted row"
        );
    }

    Ok(())
}

#[test]
fn retrieval_budget_zero_caps_remain_excluded_after_surplus_redistribution() -> Result<()> {
    let (_dir, vault) = open_test_vault();

    let claim = EntityId::from_bytes_unchecked([0x5E; 16]);
    let summary_a = EntityId::from_bytes_unchecked([0xE2; 16]);
    let summary_b = EntityId::from_bytes_unchecked([0xE3; 16]);

    put_claim_text_entity(&vault, &claim, "zerocapbudget", "test.zero.cap", "claim")?;
    put_text_entity(
        &vault,
        &summary_a,
        crate::registry::ENTITY_TYPE_SUMMARY,
        "zerocapbudget",
        serde_json::json!({"text": "summary a"}),
    )?;
    put_text_entity(
        &vault,
        &summary_b,
        crate::registry::ENTITY_TYPE_SUMMARY,
        "zerocapbudget",
        serde_json::json!({"text": "summary b"}),
    )?;

    let pack = vault
        .context_pack()
        .search_text("zerocapbudget", 10)
        .limit(3)
        .retrieval_budget(ContextPackRetrievalBudget::new(2, 0, 0, 0, 0, 0))
        .run()?;

    let ids: Vec<EntityId> = pack.results.iter().map(|entity| entity.id).collect();
    assert_eq!(
        ids,
        vec![claim],
        "explicit zero caps must not become eligible during surplus redistribution"
    );
    Ok(())
}

#[test]
fn default_retrieval_budget_keeps_small_limit_turn_results_eligible() -> Result<()> {
    let (_dir, vault) = open_test_vault();

    let turn = EntityId::from_bytes_unchecked([0xE4; 16]);
    put_text_entity(
        &vault,
        &turn,
        crate::registry::ENTITY_TYPE_TURN,
        "smalllimitturn",
        serde_json::json!({"text": "turn"}),
    )?;

    let pack = vault
        .context_pack()
        .search_text("smalllimitturn", 10)
        .limit(3)
        .run()?;

    let ids: Vec<EntityId> = pack.results.iter().map(|entity| entity.id).collect();
    assert_eq!(ids, vec![turn]);
    Ok(())
}

#[test]
fn retract_claim_end_to_end_removes_stale_text_from_context_pack() -> Result<()> {
    struct NoWithdrawnEmbedding;
    impl crate::memory::IndexedRevisionEmbedder for NoWithdrawnEmbedding {
        fn embed_revision(&self, _: &crate::memory::IndexedRevisionInput) -> Result<Vec<f32>> {
            panic!("withdrawn claims must not be reindexed at idle");
        }
    }

    let (_dir, vault) = open_test_vault();
    // Vault::open seeds the bootstrap skills, whose activation edits wait for
    // idle publication with a millisecond open stamp. The wall clock below is
    // second-truncated, so publish them first: otherwise a second boundary
    // between open and refresh hands them to the panicking embedder.
    crate::test_util::publish_seeded_revisions(&vault);
    let id = EntityId::from_bytes([0x43; 16])?;
    put_claim_text_entity(
        &vault,
        &id,
        "retractpackneedle",
        "test.retract_pack",
        "active",
    )?;

    let before = vault
        .context_pack()
        .search_text("retractpackneedle", 10)
        .run()?;
    assert_eq!(before.results.len(), 1);
    assert_eq!(before.results[0].id, id);

    vault.retract_claim(&id, 2_000)?;

    vault.set_indexed_idle_delay_ms(0)?;
    let idle = vault.refresh_indexed_at_idle(
        crate::unix_seconds_now().saturating_mul(1000),
        &NoWithdrawnEmbedding,
    )?;
    assert!(idle.refreshed.is_empty());

    let after = vault
        .context_pack()
        .search_text("retractpackneedle", 10)
        .run()?;
    assert!(after.results.is_empty());
    assert!(after.neighbors.is_empty());
    assert_eq!(
        after.stats.candidates_considered, 0,
        "retraction must deindex stale BM25F rows, not only filter them later"
    );
    assert_eq!(after.stats.claims_suppressed, 0);
    let empty = after.empty.as_ref().expect("empty context");
    assert_eq!(empty.reason, EmptyReason::NoData);
    assert_eq!(empty.total_in_scope, 0);
    Ok(())
}

// ── D19 read-path claim status gate (ONE-1111) ─────────────────

/// Writes a CLAIM with an explicit status triple and no text row —
/// reachable only through the edge walk.
fn put_claim_with_status(
    vault: &Vault,
    id: &EntityId,
    appr: crate::claim::ClaimApprovalStatus,
    life: crate::claim::ClaimLifecycleStatus,
    stale: bool,
) -> Result<()> {
    let subject = default_claim_subject_id()?;
    ensure_claim_subject_payload(vault, &subject)?;
    let mut body = crate::claim::ClaimBody::new(
        "test.status",
        crate::claim::ClaimSubject::Entity(subject),
        rmpv::Value::from("v"),
        0.9,
        appr,
        life,
    )?;
    body.stale = stale;
    let payload = crate::claim::encode_claim_body(&body)?;
    vault
        .batch()
        .put(id, 0, TimeRange { start: 1, end: 1 }, 1, &payload)
        .commit()
}

#[test]
fn pack_validation_skips_world_partition_dropped_results() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let world_w = EntityId::from_bytes([0x5E; 16])?;

    let base = EntityId::from_bytes([0x63; 16])?;
    let kept_fiction = EntityId::from_bytes([0x75; 16])?;
    let dropped_fiction = EntityId::from_bytes([0x76; 16])?;
    put_world_claim(&vault, base, [1.0, 0.0, 0.0, 0.0], None)?;
    put_world_claim(&vault, kept_fiction, [0.9, 0.1, 0.0, 0.0], Some(world_w))?;
    put_world_claim(&vault, dropped_fiction, [0.0, 1.0, 0.0, 0.0], Some(world_w))?;

    let raw = vault
        .get_raw(&dropped_fiction)?
        .expect("dropped fiction claim exists");
    let payload = raw[ENTITY_METADATA_HEADER_LEN..].to_vec();
    let reversed = raw_entity_record(ENTITY_TYPE_CLAIM, 20, 10, 1, &payload);
    overwrite_raw_entity(&vault, &dropped_fiction, &reversed)?;

    let pack = vault
        .context_pack()
        .read_mode(crate::vault::ReadMode::Live)
        .search_vector(&[1.0, 0.0, 0.0, 0.0], 10)
        .run()?;

    let ids: HashSet<EntityId> = pack.results.iter().map(|entity| entity.id).collect();
    assert!(ids.contains(&base), "base claim must survive");
    assert!(
        ids.contains(&kept_fiction),
        "top fiction claim must survive the cap"
    );
    assert!(
        !ids.contains(&dropped_fiction),
        "invalid fiction claim dropped by the cap must not abort the pack"
    );
    Ok(())
}

// ── RET-005 pre-assembly pack validation ───────────────────────

#[test]
fn pack_validation_rejects_missing_required_evidence() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let id = EntityId::from_bytes([0x92; 16])?;

    put_text_entity(
        &vault,
        &id,
        1,
        "missingevidenceneedle",
        serde_json::json!({"body": "placeholder"}),
    )?;

    let source = EntityId::from_bytes([0x21; 16])?;
    let target = EntityId::from_bytes([0x22; 16])?;
    let actor = EntityId::from_bytes([0x23; 16])?;
    ensure_claim_subject_payload(&vault, &source)?;
    ensure_claim_subject_payload(&vault, &target)?;
    let value = crate::provenance::encode_edge_provenance_value(
        &crate::provenance::EdgeProvenanceClaimBody::new(
            actor,
            0.75,
            crate::provenance::SupersessionStatus::Confirmed,
        ),
    );
    let body = crate::claim::ClaimBody::new(
        crate::provenance::PREDICATE_EDGE_PROVENANCE,
        crate::claim::ClaimSubject::Edge {
            source,
            kind: crate::edge::EdgeKind::Supports,
            target,
        },
        value,
        0.75,
        crate::claim::ClaimApprovalStatus::Auto,
        crate::claim::ClaimLifecycleStatus::Active,
    )?;
    let payload = crate::claim::encode_claim_body(&body)?;
    let raw = raw_entity_record(ENTITY_TYPE_CLAIM, 1, 1, 1, &payload);
    overwrite_raw_entity(&vault, &id, &raw)?;

    let err = vault
        .context_pack()
        .read_mode(crate::vault::ReadMode::Live)
        .search_text("missingevidenceneedle", 10)
        .run()
        .expect_err("provenance claim without actor-class evidence must fail pack validation");

    assert_context_pack_validation(err, id, PACK_VALIDATION_MISSING_EVIDENCE);
    Ok(())
}

#[test]
fn pack_validation_rejects_deleted_claim_entity_subject() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let id = EntityId::from_bytes([0x99; 16])?;
    let subject = EntityId::from_bytes([0x5B; 16])?;
    ensure_claim_subject_payload(&vault, &subject)?;
    put_claim_text_entity_with_subject(
        &vault,
        &id,
        crate::claim::ClaimSubject::Entity(subject),
        "deletedclaimsubjectneedle",
        "test.deleted_subject",
        "payload",
    )?;
    vault.with_write_txn(|wtxn| {
        vault.store.sync_state.put(
            wtxn,
            &crate::deletion::local_hard_delete_key(&subject),
            b"present",
        )?;
        Ok(())
    })?;

    let err = vault
        .context_pack()
        .search_text("deletedclaimsubjectneedle", 10)
        .run()
        .expect_err("deleted claim subject payload must fail pack validation");

    assert_context_pack_validation(err, subject, PACK_VALIDATION_DELETED_PAYLOAD);
    Ok(())
}

#[test]
fn pack_validation_rejects_impossible_time_ordering() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let id = EntityId::from_bytes([0x93; 16])?;
    put_claim_text_entity(&vault, &id, "reversedtimeneedle", "test.time", "payload")?;

    let raw = vault.get_raw(&id)?.expect("claim exists");
    let payload = raw[ENTITY_METADATA_HEADER_LEN..].to_vec();
    let reversed = raw_entity_record(ENTITY_TYPE_CLAIM, 20, 10, 1, &payload);
    overwrite_raw_entity(&vault, &id, &reversed)?;

    let err = vault
        .context_pack()
        .read_mode(crate::vault::ReadMode::Live)
        .search_text("reversedtimeneedle", 10)
        .run()
        .expect_err("reversed entity envelope must fail pack validation");

    assert_context_pack_validation(err, id, PACK_VALIDATION_IMPOSSIBLE_TIME);
    Ok(())
}

#[test]
fn deleted_payload_is_excluded_before_pack_assembly() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let id = EntityId::from_bytes([0x94; 16])?;
    put_claim_text_entity(
        &vault,
        &id,
        "deletedreferenceneedle",
        "test.deleted",
        "payload",
    )?;

    vault.with_write_txn(|wtxn| {
        vault.store.sync_state.put(
            wtxn,
            &crate::deletion::local_hard_delete_key(&id),
            b"present",
        )?;
        Ok(())
    })?;

    let pack = vault
        .context_pack()
        .search_text("deletedreferenceneedle", 10)
        .run()?;
    assert!(pack.results.is_empty());
    assert!(pack.neighbors.is_empty());
    Ok(())
}

#[test]
fn pack_validation_rejects_active_remat_marker_without_quarantine_row() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let id = EntityId::from_bytes([0x5E; 16])?;
    let window_key = "2026-03";
    put_claim_text_entity(
        &vault,
        &id,
        "rematmarkerwithoutquarantineneedle",
        "test.marker_only",
        "payload",
    )?;

    vault.with_write_txn(|wtxn| {
        vault
            .store
            .sync_state
            .put(wtxn, &pack_remat_marker_key(window_key, &id), &[1u8])?;
        Ok(())
    })?;

    let err = vault
        .context_pack()
        .search_text("rematmarkerwithoutquarantineneedle", 10)
        .run()
        .expect_err("active remat marker alone must fail pack validation");

    assert_context_pack_validation(err, id, PACK_VALIDATION_QUARANTINED_PAYLOAD);
    Ok(())
}

#[test]
fn pack_validation_ignores_stale_quarantine_row_after_reference_heals() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let id = EntityId::from_bytes([0x96; 16])?;
    let window_key = "2026-03";
    put_claim_text_entity(
        &vault,
        &id,
        "stalequarantinereferenceneedle",
        "test.stale_quarantine",
        "payload",
    )?;

    let record = pack_quarantine_record_for_entity(window_key, &id);
    let encoded = rmp_serde::to_vec_named(&record).expect("quarantine record encode");
    vault.with_write_txn(|wtxn| {
        vault
            .store
            .sync_queue
            .put(wtxn, b"x:\x00\x00\x00\x00\x00\x00\x00\x02", &encoded)?;
        Ok(())
    })?;

    let pack = vault
        .context_pack()
        .search_text("stalequarantinereferenceneedle", 10)
        .run()?;

    assert!(pack.results.iter().any(|entity| entity.id == id));
    Ok(())
}

#[test]
fn pack_validation_fails_closed_on_corrupt_quarantine_row() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let id = EntityId::from_bytes([0x97; 16])?;
    put_claim_text_entity(
        &vault,
        &id,
        "corruptquarantinerowneedle",
        "test.corrupt_quarantine",
        "payload",
    )?;

    vault.with_write_txn(|wtxn| {
        vault
            .store
            .sync_queue
            .put(wtxn, b"x:\x00\x00\x00\x00\x00\x00\x00\x03", &[0xc1])?;
        Ok(())
    })?;

    let err = vault
        .context_pack()
        .search_text("corruptquarantinerowneedle", 10)
        .run()
        .expect_err("corrupt quarantine row must fail closed");

    match err {
        Error::CorruptedIndex(row) => assert_eq!(row, PACK_QUARANTINE_ROW),
        other => panic!("expected CorruptedIndex({PACK_QUARANTINE_ROW:?}), got {other:?}"),
    }
    Ok(())
}

/// AC 7 — fail-closed hydration: a raw-written type-0 neighbor whose
/// body is not the pinned CLAIM ABI is EXCLUDED (and counted), never
/// surfaced with empty fields. Exclusion, not error.
#[test]
fn pack_hydration_fails_closed_on_undecodable_claim_neighbor() -> Result<()> {
    let (_dir, vault) = open_test_vault();

    let a = EntityId::from_bytes_unchecked([0x41; 16]);
    let bad = EntityId::from_bytes_unchecked([0x62; 16]);
    put_claim_text_entity(&vault, &a, "badneighbor", "test.root", "root")?;

    // Raw 25-byte envelope (type 0) + a non-map MessagePack body.
    let mut junk_body = Vec::new();
    rmpv::encode::write_value(&mut junk_body, &rmpv::Value::from("junk")).expect("msgpack encode");
    let raw = raw_entity_record(0, 1, 1, 1, &junk_body);
    vault.with_write_txn(|wtxn| {
        vault.store.entities.put(wtxn, bad.as_bytes(), &raw)?;
        Ok(())
    })?;
    vault.put_edge(&a, crate::edge::EdgeKind::Supports, &bad, 0.9)?;

    let pack = vault
        .context_pack()
        .search_text("badneighbor", 10)
        .edge_hop(1)
        .run()?;

    assert_eq!(pack.results.len(), 1);
    assert!(
        pack.neighbors.iter().all(|e| e.id != bad),
        "undecodable type-0 neighbor must be excluded, not surfaced with empty fields"
    );
    assert_eq!(pack.stats.claims_suppressed, 1);
    Ok(())
}

#[test]
fn context_pack_telemetry_records_final_hydration_suppressions() -> Result<()> {
    let (_dir, vault) = open_test_vault();

    let live = EntityId::from_bytes_unchecked([0x73; 16]);
    let dead_neighbor = EntityId::from_bytes_unchecked([0x74; 16]);
    put_claim_text_entity(&vault, &live, "telemetryhydrate", "test.live", "v")?;
    put_claim_with_status(
        &vault,
        &dead_neighbor,
        crate::claim::ClaimApprovalStatus::Auto,
        crate::claim::ClaimLifecycleStatus::Retracted,
        false,
    )?;
    vault.put_edge(&live, crate::edge::EdgeKind::Supports, &dead_neighbor, 0.9)?;

    let pack_with_telemetry = vault
        .context_pack()
        .search_text("telemetryhydrate", 10)
        .edge_hop(1)
        .run_with_telemetry()?;
    let run_id = pack_with_telemetry
        .run_id
        .expect("context-pack telemetry run id");
    let pack = pack_with_telemetry.value;
    assert_eq!(pack.results.len(), 1);
    assert_eq!(pack.results[0].id, live);
    assert!(pack.neighbors.is_empty());
    assert_eq!(pack.stats.claims_suppressed, 1);

    let runs = vault.retrieval_runs(1)?;
    assert_eq!(runs.len(), 1);
    assert_eq!(runs[0].action, crate::store::RetrievalAction::ContextPack);
    assert_eq!(runs[0].run_id, run_id);
    assert_eq!(runs[0].claims_suppressed, pack.stats.claims_suppressed);
    assert_eq!(runs[0].result_ids, vec![*live.as_bytes()]);
    assert_eq!(runs[0].score_breakdown.len(), 1);
    assert_eq!(runs[0].score_breakdown[0].result_id, *live.as_bytes());
    Ok(())
}

#[test]
fn context_pack_provisional_telemetry_hidden_until_finalization() -> Result<()> {
    let (_dir, vault) = open_test_vault();

    let id = EntityId::from_bytes_unchecked([0x7E; 16]);
    put_text_entity(
        &vault,
        &id,
        crate::registry::ENTITY_TYPE_PERSON,
        "telemetry unpublished finalization",
        serde_json::json!({"name": "Unpublished"}),
    )?;

    let run = vault
        .context_pack()
        .search_text("telemetry unpublished finalization", 10)
        .run_unfinalized()?;
    let run_id = run
        .telemetry_run_id
        .expect("unfinalized context-pack telemetry run id");
    assert!(
        vault.retrieval_runs(10)?.is_empty(),
        "unfinalized context-pack telemetry must not be publicly listed"
    );
    let outcome_error = vault
        .store
        .record_retrieval_outcome(crate::store::RetrievalOutcome {
            run_id,
            key: "click".to_owned(),
            reward: Some(1.0),
            accepted: Some(true),
            metadata: BTreeMap::new(),
        })
        .expect_err("unfinalized context-pack telemetry must reject outcomes");
    assert!(matches!(outcome_error, Error::InvalidConfig(_)));

    let surfaced_result_ids: Vec<[u8; 16]> = run
        .pack
        .results
        .iter()
        .map(|entity| *entity.id.as_bytes())
        .collect();
    let finalized_run_id = finalize_context_pack_telemetry(
        run.telemetry,
        run.telemetry_run_id,
        run.pack.stats.query_time_us,
        run.total_in_scope,
        run.pack.stats.claims_suppressed,
        &surfaced_result_ids,
        context_pack_empty_reason(&run.pack, &surfaced_result_ids),
        None,
        None,
    )?;
    assert_eq!(finalized_run_id, Some(run_id));

    let runs = vault.retrieval_runs(1)?;
    assert_eq!(runs.len(), 1);
    assert_eq!(runs[0].run_id, run_id);
    assert_eq!(runs[0].result_ids, vec![*id.as_bytes()]);
    vault
        .store
        .record_retrieval_outcome(crate::store::RetrievalOutcome {
            run_id,
            key: "click".to_owned(),
            reward: Some(1.0),
            accepted: Some(true),
            metadata: BTreeMap::new(),
        })?;
    assert_eq!(vault.store.retrieval_outcomes(run_id)?.len(), 1);
    Ok(())
}

#[test]
fn context_pack_telemetry_discards_run_on_assembly_error() -> Result<()> {
    let (_dir, vault) = open_test_vault();

    let id = EntityId::from_bytes_unchecked([0x7B; 16]);
    vault
        .batch()
        .put(
            &id,
            crate::registry::ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            &msgpack_entity(serde_json::json!({"name": "Corrupt"})),
        )
        .text(&id, &[("body", "telemetry corrupt vector")])
        .vector(&id, &[1.0, 0.0, 0.0, 0.0])
        .commit()?;
    vault.with_write_txn(|wtxn| {
        vault.store.vectors.put(wtxn, id.as_bytes(), &[1, 2, 3])?;
        Ok(())
    })?;

    let error = vault
        .context_pack()
        .search_text("telemetry corrupt vector", 10)
        .include_vectors(true)
        .run_with_telemetry()
        .expect_err("corrupt post-pipeline vector hydration should fail the context pack");
    assert!(
        matches!(error, Error::CorruptedIndex("entity vector")),
        "expected CorruptedIndex(\"entity vector\"), got {error:?}"
    );
    assert!(
        vault.retrieval_runs(10)?.is_empty(),
        "failed context-pack assembly must not leave a completed telemetry row"
    );
    Ok(())
}

#[test]
fn context_pack_telemetry_finalization_failure_returns_no_run_id() -> Result<()> {
    let (_dir, vault) = open_test_vault();

    let id = EntityId::from_bytes_unchecked([0x7D; 16]);
    put_text_entity(
        &vault,
        &id,
        crate::registry::ENTITY_TYPE_PERSON,
        "telemetry corrupt finalization",
        serde_json::json!({"name": "Corrupt Finalization"}),
    )?;

    let run = vault
        .context_pack()
        .search_text("telemetry corrupt finalization", 10)
        .run_unfinalized()?;
    let run_id = run
        .telemetry_run_id
        .expect("unfinalized context-pack telemetry run id");
    let outcome_error = vault
        .store
        .record_retrieval_outcome(crate::store::RetrievalOutcome {
            run_id,
            key: "click".to_owned(),
            reward: Some(1.0),
            accepted: Some(true),
            metadata: BTreeMap::new(),
        })
        .expect_err("unfinalized context-pack telemetry must reject outcomes");
    assert!(matches!(outcome_error, Error::InvalidConfig(_)));

    let mut run_key = Vec::from(&b"retr_run:v0:"[..]);
    run_key.extend_from_slice(&run_id.as_bytes());
    vault.with_write_txn(|wtxn| {
        vault
            .store
            .vault_meta
            .put(wtxn, &run_key, b"not a retrieval run")?;
        Ok(())
    })?;

    let surfaced_result_ids: Vec<[u8; 16]> = run
        .pack
        .results
        .iter()
        .map(|entity| *entity.id.as_bytes())
        .collect();
    let returned_run_id = finalize_context_pack_telemetry(
        run.telemetry,
        run.telemetry_run_id,
        run.pack.stats.query_time_us,
        run.total_in_scope,
        run.pack.stats.claims_suppressed,
        &surfaced_result_ids,
        context_pack_empty_reason(&run.pack, &surfaced_result_ids),
        None,
        None,
    )?;

    assert_eq!(
        returned_run_id, None,
        "a BASE assembly keeps its best-effort posture: the finalize failure is warned \
         past and the provisional row discarded"
    );
    assert!(
        !vault
            .store
            .retrieval_runs(10)?
            .iter()
            .any(|record| record.run_id == run_id),
        "failed finalization should discard the provisional telemetry row"
    );
    assert!(
        vault.store.retrieval_outcomes(run_id)?.is_empty(),
        "failed finalization should discard provisional outcomes"
    );
    Ok(())
}

/// A ROOM's assembly does NOT get the base arm's best-effort posture
/// (ONE-1570 Arm B).
///
/// The provisional row registers into the room, then a flip to on record SEALS
/// the overlay, so both the finalize and the discard that follows it refuse.
/// Warning past that would return a successful off-record retrieval with a
/// provisional row and ZERO final registrations — log-and-continue over both
/// the exactly-once clause and the close-set one. The retrieval fails instead.
#[test]
fn a_rooms_context_pack_fails_when_its_finalize_cannot_land() -> Result<()> {
    let (_dir, vault) = open_test_vault();

    let id = EntityId::from_bytes_unchecked([0x7C; 16]);
    put_text_entity(
        &vault,
        &id,
        crate::registry::ENTITY_TYPE_PERSON,
        "roomfinalizeneedle",
        serde_json::json!({"name": "Roomfinalize"}),
    )?;

    let session = vault.off_record_session_vault().enter(
        "sess-cp-armb",
        crate::off_record::OffRecordBackendClass::Local,
    )?;
    let route = session.write_route()?;
    let door = session.retrieval_telemetry(&route)?;

    let run = vault
        .context_pack()
        .search_text("roomfinalizeneedle", 10)
        .in_session(&door)
        .run_unfinalized()?;
    let run_id = run
        .telemetry_run_id
        .expect("the room's provisional registration landed");

    session.flip_on_record()?;

    let surfaced_result_ids: Vec<[u8; 16]> = run
        .pack
        .results
        .iter()
        .map(|entity| *entity.id.as_bytes())
        .collect();
    let error = finalize_context_pack_telemetry(
        run.telemetry,
        run.telemetry_run_id,
        run.pack.stats.query_time_us,
        run.total_in_scope,
        run.pack.stats.claims_suppressed,
        &surfaced_result_ids,
        context_pack_empty_reason(&run.pack, &surfaced_result_ids),
        None,
        None,
    )
    .expect_err("a room's failed finalize fails the retrieval");
    assert_eq!(
        error.kind(),
        crate::error::ErrorKind::OffRecordOverlayLeaseClosed
    );

    assert!(
        !vault
            .store
            .retrieval_runs(10)?
            .iter()
            .any(|record| record.run_id == run_id),
        "and the room's run never appears in the durable base ledger"
    );
    Ok(())
}

/// The deferred door is closed to rooms: `finish_projected_json` returns no
/// `Result`, so a room's failed finalize would have nowhere to go but a
/// warning. The refusal is what keeps [`finalize_context_pack_telemetry`]'s
/// `Err` arm unreachable from that path.
#[test]
fn a_room_may_not_defer_its_context_pack_finalization() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let session = vault.off_record_session_vault().enter(
        "sess-cp-armb-defer",
        crate::off_record::OffRecordBackendClass::Local,
    )?;
    let route = session.write_route()?;
    let door = session.retrieval_telemetry(&route)?;

    let deferred = vault
        .context_pack()
        .search_text("deferredroomneedle", 10)
        .in_session(&door)
        .run_unfinalized_with_telemetry();
    let Err(error) = deferred else {
        panic!("a room's assembly must take a finalizing door");
    };
    assert!(matches!(error, Error::InvalidConfig(_)));
    Ok(())
}

#[test]
fn context_pack_serialized_telemetry_reflects_budget_surviving_results() -> Result<()> {
    let (_dir, vault) = open_test_vault();

    let survivor = EntityId::from_bytes_unchecked([0x75; 16]);
    let dropped = EntityId::from_bytes_unchecked([0x76; 16]);
    let put_turn = |id: EntityId, vector: [f32; 4], text: &str| -> Result<()> {
        let payload = msgpack_entity(serde_json::json!({
            "txt": text,
            "spkr": "user",
            "at": 1_u64,
        }));
        vault
            .batch()
            .put(
                &id,
                crate::registry::ENTITY_TYPE_TURN,
                TimeRange { start: 1, end: 1 },
                1,
                &payload,
            )
            .vector(&id, &vector)
            .commit()
    };
    put_turn(survivor, [1.0, 0.0, 0.0, 0.0], "budget survivor")?;
    put_turn(dropped, [0.0, 1.0, 0.0, 0.0], "budget dropped")?;

    let serialized = vault
        .context_pack()
        .search_vector(&[1.0, 0.0, 0.0, 0.0], 10)
        .format(PackFormat::Plaintext)
        // Revision-qualified citations are longer; still admit exactly one row.
        .token_budget(48)
        .run_serialized_with_telemetry()?;
    assert!(!serialized.value.is_empty());
    let run_id = serialized.run_id.expect("serialized telemetry run id");

    let runs = vault.retrieval_runs(1)?;
    assert_eq!(runs.len(), 1);
    assert_eq!(runs[0].run_id, run_id);
    assert_eq!(runs[0].action, crate::store::RetrievalAction::ContextPack);
    assert!(
        runs[0].total_in_scope >= 2,
        "test setup should hydrate at least two pre-budget primary results"
    );
    assert_eq!(runs[0].result_ids, vec![*survivor.as_bytes()]);
    assert!(!runs[0].result_ids.contains(dropped.as_bytes()));
    assert_eq!(runs[0].score_breakdown.len(), 1);
    assert_eq!(runs[0].score_breakdown[0].result_id, *survivor.as_bytes());
    assert_eq!(runs[0].score_breakdown[0].final_rank, 1);
    assert_eq!(runs[0].empty_reason, None);
    Ok(())
}

#[test]
fn context_pack_serialized_telemetry_reports_item_budget_empty() -> Result<()> {
    let (_dir, vault) = open_test_vault();

    let first = EntityId::from_bytes_unchecked([0x77; 16]);
    let second = EntityId::from_bytes_unchecked([0x78; 16]);
    let put_turn = |id: EntityId, vector: [f32; 4], text: &str| -> Result<()> {
        let payload = msgpack_entity(serde_json::json!({
            "txt": text,
            "spkr": "user",
            "at": 1_u64,
        }));
        vault
            .batch()
            .put(
                &id,
                crate::registry::ENTITY_TYPE_TURN,
                TimeRange { start: 1, end: 1 },
                1,
                &payload,
            )
            .vector(&id, &vector)
            .commit()
    };
    put_turn(first, [1.0, 0.0, 0.0, 0.0], "budget empty first")?;
    put_turn(second, [0.0, 1.0, 0.0, 0.0], "budget empty second")?;

    let serialized = vault
        .context_pack()
        .search_vector(&[1.0, 0.0, 0.0, 0.0], 10)
        .format(PackFormat::Plaintext)
        .max_item_tokens(1)
        .run_serialized_with_telemetry()?;
    let run_id = serialized.run_id.expect("serialized telemetry run id");

    let runs = vault.retrieval_runs(1)?;
    assert_eq!(runs.len(), 1);
    assert_eq!(runs[0].run_id, run_id);
    assert!(
        runs[0].total_in_scope >= 2,
        "test setup should hydrate at least two pre-budget primary results"
    );
    assert!(runs[0].result_ids.is_empty());
    assert!(runs[0].score_breakdown.is_empty());
    assert_eq!(runs[0].empty_reason.as_deref(), Some("ItemBudget"));
    Ok(())
}

#[test]
fn context_pack_serialized_telemetry_excludes_merged_neighbors() -> Result<()> {
    let (_dir, vault) = open_test_vault();

    let result = EntityId::from_bytes_unchecked([0x7A; 16]);
    let neighbor = EntityId::from_bytes_unchecked([0x7B; 16]);
    put_claim_text_entity(
        &vault,
        &result,
        "serializedneighborroot",
        "test.result",
        "root",
    )?;
    put_text_entity(
        &vault,
        &neighbor,
        crate::registry::ENTITY_TYPE_PERSON,
        "serialized neighbor",
        serde_json::json!({"name": "Neighbor"}),
    )?;
    vault.put_edge(&result, crate::edge::EdgeKind::Supports, &neighbor, 1.0)?;

    let serialized = vault
        .context_pack()
        .search_text("serializedneighborroot", 10)
        .edge_hop(1)
        .format(PackFormat::Plaintext)
        .run_serialized_with_telemetry()?;
    assert!(!serialized.value.is_empty());
    let text = std::str::from_utf8(&serialized.value).expect("plaintext context pack");
    assert!(
        text.contains("Neighbor"),
        "test setup should serialize the merged neighbor"
    );
    let run_id = serialized.run_id.expect("serialized telemetry run id");

    let runs = vault.retrieval_runs(1)?;
    assert_eq!(runs.len(), 1);
    assert_eq!(runs[0].run_id, run_id);
    assert_eq!(runs[0].action, crate::store::RetrievalAction::ContextPack);
    assert_eq!(runs[0].result_ids, vec![*result.as_bytes()]);
    assert!(!runs[0].result_ids.contains(neighbor.as_bytes()));
    assert_eq!(runs[0].score_breakdown.len(), 1);
    assert_eq!(runs[0].score_breakdown[0].result_id, *result.as_bytes());
    Ok(())
}

// ─── OF-365 disclosure clamp red-team suite (ONE-1517, design §14.4) ────────
//
// Every assertion is on the ASSEMBLED CONTEXT (pack/board contents), never on
// model output. Absence is the boundary: a clamped id must appear NOWHERE as
// a tracked reference.

use crate::test_util::entity as disclosure_id;

fn seed_disclosure_contact(vault: &Vault, contact_id: EntityId, counterparty: &str) {
    let record = crate::counterparty_contact::CounterpartyContactRecord::user_introduction(
        disclosure_id(0xA0),
        counterparty,
        10,
    )
    .expect("contact record");
    vault
        .create_counterparty_contact(&contact_id, &record)
        .expect("create counterparty contact");
}

fn known_contact_entry(contact_id: EntityId, label: &str) -> crate::interlocutor::Interlocutor {
    crate::interlocutor::Interlocutor::known_contact(
        contact_id,
        label,
        crate::counterparty_contact::CounterpartyFirstTouch::UserIntroduction,
    )
}

fn absence_ctx_for_contact(vault: &Vault, contact_id: EntityId) -> DisclosureContext {
    DisclosureContext::resolve(
        vault,
        crate::interlocutor::InterlocutorSet::without_owner(vec![known_contact_entry(
            contact_id,
            "kenji@example.com",
        )]),
    )
    .expect("resolve disclosure context")
}

fn supervised_ctx_for_contact(vault: &Vault, contact_id: EntityId) -> DisclosureContext {
    DisclosureContext::resolve(
        vault,
        crate::interlocutor::InterlocutorSet::with_session_owner(vec![known_contact_entry(
            contact_id,
            "kenji@example.com",
        )]),
    )
    .expect("resolve disclosure context")
}

fn put_disclosure_turn(vault: &Vault, id: &EntityId, text: &str) {
    put_text_entity(
        vault,
        id,
        ENTITY_TYPE_TURN,
        text,
        serde_json::json!({ "txt": text }),
    )
    .expect("put turn");
}

fn put_disclosure_claim(
    vault: &Vault,
    id: &EntityId,
    subject: EntityId,
    predicate: &str,
    text: &str,
    band: Option<&str>,
) {
    put_disclosure_claim_in_world(vault, id, subject, predicate, text, band, None);
}

fn put_disclosure_claim_in_world(
    vault: &Vault,
    id: &EntityId,
    subject: EntityId,
    predicate: &str,
    text: &str,
    band: Option<&str>,
    world: Option<EntityId>,
) {
    let mut body = crate::claim::ClaimBody::new(
        predicate,
        ClaimSubject::Entity(subject),
        rmpv::Value::from(text),
        1.0,
        crate::claim::ClaimApprovalStatus::Auto,
        crate::claim::ClaimLifecycleStatus::Active,
    )
    .unwrap();
    body.world = world;
    if let Some(band) = band {
        body.scope = Some(rmpv::Value::Map(vec![(
            rmpv::Value::from("sensitivity"),
            rmpv::Value::from(band),
        )]));
    }
    let data = crate::claim::encode_claim_body(&body).expect("encode claim");
    vault
        .batch()
        .put(
            id,
            ENTITY_TYPE_CLAIM,
            TimeRange { start: 1, end: 1 },
            1,
            &data,
        )
        .text(id, &[("body", text)])
        .commit()
        .expect("put claim");
}

// Clearance for the base world (or an explicit set of record worlds).
fn disclosure_world_clearance(
    worlds: impl IntoIterator<Item = EntityId>,
) -> crate::federation::Scope {
    use crate::federation::{Scope, ScopeAxis, ScopeId};
    let mut scope = Scope::top();
    scope.worlds = ScopeAxis::Some(worlds.into_iter().map(ScopeId).collect());
    scope
}

fn pack_ids(pack: &ContextPack) -> Vec<EntityId> {
    pack.results
        .iter()
        .chain(pack.neighbors.iter())
        .map(|entity| entity.id)
        .collect()
}

fn assert_id_absent_everywhere(pack: &ContextPack, id: &EntityId, label: &str) {
    assert!(
        !pack_ids(pack).contains(id),
        "{label}: clamped id must not appear in results/neighbors"
    );
    for entity in pack.results.iter().chain(pack.neighbors.iter()) {
        if let Some(edges) = &entity.edges {
            assert!(
                edges.iter().all(|edge| edge.target != *id),
                "{label}: clamped id must not appear in any serialized edge list"
            );
        }
    }
}

#[test]
fn n1_owner_absent_tier_a_and_out_of_scope_ids_appear_nowhere() -> Result<()> {
    let (_tmp, vault) = open_test_vault();
    let contact_id = disclosure_id(0xC1);
    seed_disclosure_contact(&vault, contact_id, "kenji@example.com");

    let party = disclosure_id(0xD1);
    let party_fact = disclosure_id(0xD2);
    let off_record = disclosure_id(0xD3);
    let band2 = disclosure_id(0xD4);
    let marked = disclosure_id(0xD5);
    let diary = disclosure_id(0xD6);
    put_disclosure_turn(&vault, &party, "hanami party planning needle");
    put_disclosure_claim(
        &vault,
        &party_fact,
        party,
        "event.headcount",
        "party guest count needle",
        Some("public"),
    );
    put_disclosure_turn(&vault, &off_record, "off record confession needle");
    let room = vault
        .off_record_session_vault()
        .enter("room-n1", crate::off_record::OffRecordBackendClass::Local)?;
    {
        // Disclosure tier rule 1 is LIVE overlay membership. Staged straight
        // into the overlay because the K4 taint guard refuses a base write at a
        // live overlay id.
        let overlay = room.overlay();
        let segment = overlay.install_txn_segment()?;
        overlay.put(
            crate::session_overlay::OverlayKeyspace::Entities,
            off_record.as_bytes(),
            b"live session overlay entity",
        )?;
        segment.commit()?;
    }
    put_disclosure_claim(
        &vault,
        &band2,
        party,
        "profile.health_note",
        "clinic visit needle",
        Some("sensitive"),
    );
    put_disclosure_turn(&vault, &marked, "owner marked private needle");
    vault.set_disclosure_tier_a(&marked, 100)?;
    put_disclosure_claim_in_world(
        &vault,
        &diary,
        party,
        "event.diary",
        "private diary entry needle",
        Some("private"),
        Some(disclosure_id(0xF1)),
    );

    let scope = crate::disclosure::DisclosureScope::new(
        disclosure_world_clearance([crate::claim::base_world_id()]),
        "party planning",
        100,
    )?;
    vault.set_counterparty_disclosure_scope(&contact_id, &scope)?;
    let ctx = absence_ctx_for_contact(&vault, contact_id);

    let run = vault
        .context_pack()
        .search_text("needle", 10)
        .disclosure_context(ctx.clone())
        .run_unfinalized_with_telemetry()?;
    let clamped_out = run.clamped_out();
    let pack = run.value;

    let surfaced = pack_ids(&pack);
    assert!(surfaced.contains(&party), "in-scope party event surfaces");
    assert!(
        surfaced.contains(&party_fact),
        "claims within the shared base world are the payload"
    );
    for (id, label) in [
        (off_record, "off-record turn"),
        (band2, "band-2 claim"),
        (marked, "owner-marked turn"),
        (diary, "tier-B out-of-world claim"),
    ] {
        assert_id_absent_everywhere(&pack, &id, label);
    }
    assert!(clamped_out > 0, "candidate sweep counts its removals");
    assert_eq!(
        ctx.receipt_stamp(),
        "mode=absence_clamp;interlocutors=known_contact:kenji@example.com"
    );

    // Board rows agree with the pack (AC 5) and carry the disclosure block.
    let board = project_memories_section(
        &pack,
        MemoriesBudget::new(8, 8, 8, 8, 8, 8),
        None,
        Some(ctx.assembly(clamped_out)),
    );
    let board_ids: Vec<String> = board.rows.iter().map(|row| row.id.clone()).collect();
    assert!(board_ids.contains(&party.to_hex()));
    for id in [off_record, band2, marked, diary] {
        assert!(
            !board_ids.contains(&id.to_hex()),
            "clamped id must not appear in board rows"
        );
    }
    let disclosure = board.disclosure.expect("board disclosure block");
    assert_eq!(disclosure.mode, "absence_clamp");
    assert_eq!(disclosure.clamped_out, clamped_out);
    Ok(())
}

#[test]
fn n2_out_of_scope_neighbor_absent_from_neighbors_and_edge_lists() -> Result<()> {
    let (_tmp, vault) = open_test_vault();
    let contact_id = disclosure_id(0xC2);
    seed_disclosure_contact(&vault, contact_id, "kenji@example.com");

    let party = disclosure_id(0x57);
    let diary = disclosure_id(0xD8);
    put_disclosure_turn(&vault, &party, "party summary needle2");
    put_disclosure_claim_in_world(
        &vault,
        &diary,
        party,
        "event.diary",
        "private diary tangent",
        Some("private"),
        Some(disclosure_id(0xF2)),
    );
    vault.put_edge(&party, crate::edge::EdgeKind::Mentions, &diary, 0.9)?;

    let scope = crate::disclosure::DisclosureScope::new(
        disclosure_world_clearance([crate::claim::base_world_id()]),
        "party",
        100,
    )?;
    vault.set_counterparty_disclosure_scope(&contact_id, &scope)?;
    let ctx = absence_ctx_for_contact(&vault, contact_id);

    let pack = vault
        .context_pack()
        .search_text("needle2", 10)
        .include_edges(true)
        .edge_hop(1)
        .disclosure_context(ctx)
        .run()?;

    assert!(pack_ids(&pack).contains(&party));
    assert!(
        pack.neighbors.is_empty(),
        "tier-B out-of-world 1-hop neighbor must be absent"
    );
    assert_id_absent_everywhere(&pack, &diary, "out-of-scope edge neighbor");

    // Control: the same assembly without the clamp DOES hydrate the neighbor
    // (proves the absence above is the clamp, not missing data).
    let unclamped = vault
        .context_pack()
        .search_text("needle2", 10)
        .include_edges(true)
        .edge_hop(1)
        .run()?;
    assert!(pack_ids(&unclamped).contains(&diary));
    Ok(())
}

#[test]
fn n3_unknown_counterparty_yields_empty_pack_not_error() -> Result<()> {
    let (_tmp, vault) = open_test_vault();
    let turn = disclosure_id(0xD9);
    put_disclosure_turn(&vault, &turn, "anything at all needle3");

    let ctx = DisclosureContext::resolve(
        &vault,
        crate::interlocutor::InterlocutorSet::without_owner(vec![
            crate::interlocutor::Interlocutor::unknown("stranger", false),
        ]),
    )?;
    let pack = vault
        .context_pack()
        .search_text("needle3", 10)
        .disclosure_context(ctx)
        .run()?;

    assert!(pack.results.is_empty() && pack.neighbors.is_empty());
    assert!(
        pack.empty.is_some(),
        "empty-context envelope, not an error: {:?}",
        pack.empty
    );
    Ok(())
}

#[test]
fn n7_owner_drop_flips_on_next_assembly_with_no_sticky_state() -> Result<()> {
    let (_tmp, vault) = open_test_vault();
    let contact_id = disclosure_id(0xC3);
    seed_disclosure_contact(&vault, contact_id, "kenji@example.com");
    let diary = disclosure_id(0xDA);
    put_disclosure_turn(&vault, &diary, "tier b private memory needle7");
    let scope =
        crate::disclosure::DisclosureScope::new(crate::federation::Scope::default(), "party", 100)?;
    vault.set_counterparty_disclosure_scope(&contact_id, &scope)?;

    // Assembly 1 — supervised: Tier B present.
    let supervised = supervised_ctx_for_contact(&vault, contact_id);
    let pack = vault
        .context_pack()
        .search_text("needle7", 10)
        .disclosure_context(supervised)
        .run()?;
    assert!(pack_ids(&pack).contains(&diary), "supervised admits Tier B");

    // Assembly 2 — owner dropped: same query, id absent.
    let clamped = absence_ctx_for_contact(&vault, contact_id);
    let pack = vault
        .context_pack()
        .search_text("needle7", 10)
        .disclosure_context(clamped)
        .run()?;
    assert_id_absent_everywhere(&pack, &diary, "owner-drop flip");

    // Assembly 3 — owner back: present again (mode is request-keyed, no
    // cache to poison).
    let supervised = supervised_ctx_for_contact(&vault, contact_id);
    let pack = vault
        .context_pack()
        .search_text("needle7", 10)
        .disclosure_context(supervised)
        .run()?;
    assert!(pack_ids(&pack).contains(&diary), "flip back is stateless");
    Ok(())
}

#[test]
fn n8_disjoint_scopes_intersect_most_restrictive_wins() -> Result<()> {
    let (_tmp, vault) = open_test_vault();
    let contact_a = disclosure_id(0xC4);
    let contact_b = disclosure_id(0xC5);
    seed_disclosure_contact(&vault, contact_a, "a@example.com");
    seed_disclosure_contact(&vault, contact_b, "b@example.com");

    let event_a = disclosure_id(0xDB);
    let event_b = disclosure_id(0xDC);
    let event_c = disclosure_id(0xDD);
    let base = crate::claim::base_world_id();
    let world_a = disclosure_id(0xF3);
    let world_c = disclosure_id(0xF4);
    put_disclosure_claim_in_world(
        &vault,
        &event_a,
        event_a,
        "event.alpha",
        "event alpha needle8",
        Some("public"),
        Some(world_a),
    );
    put_disclosure_claim_in_world(
        &vault,
        &event_b,
        event_b,
        "event.beta",
        "event beta needle8",
        Some("public"),
        None,
    );
    put_disclosure_claim_in_world(
        &vault,
        &event_c,
        event_c,
        "event.gamma",
        "event gamma needle8",
        Some("public"),
        Some(world_c),
    );

    vault.set_counterparty_disclosure_scope(
        &contact_a,
        &crate::disclosure::DisclosureScope::new(
            disclosure_world_clearance([world_a, base]),
            "ab",
            100,
        )?,
    )?;
    vault.set_counterparty_disclosure_scope(
        &contact_b,
        &crate::disclosure::DisclosureScope::new(
            disclosure_world_clearance([base, world_c]),
            "bc",
            100,
        )?,
    )?;

    let ctx = DisclosureContext::resolve(
        &vault,
        crate::interlocutor::InterlocutorSet::without_owner(vec![
            known_contact_entry(contact_a, "a@example.com"),
            known_contact_entry(contact_b, "b@example.com"),
        ]),
    )?;
    let pack = vault
        .context_pack()
        .search_text("needle8", 10)
        .disclosure_context(ctx)
        .run()?;

    let surfaced = pack_ids(&pack);
    assert!(surfaced.contains(&event_b), "shared scope member admitted");
    assert_id_absent_everywhere(&pack, &event_a, "A-only scope member");
    assert_id_absent_everywhere(&pack, &event_c, "B-only scope member");
    Ok(())
}

#[test]
fn n10_tier_a_never_traversed_into_even_from_in_scope_seed() -> Result<()> {
    let (_tmp, vault) = open_test_vault();
    let contact_id = disclosure_id(0xC6);
    seed_disclosure_contact(&vault, contact_id, "kenji@example.com");

    let party = disclosure_id(0xDE);
    let vaulted = disclosure_id(0xDF);
    put_disclosure_turn(&vault, &party, "party seed needle10");
    put_disclosure_turn(&vault, &vaulted, "reachable only by edge");
    vault.put_edge(&party, crate::edge::EdgeKind::Mentions, &vaulted, 0.9)?;
    // The target is IN scope but owner-marked Tier A: tier supremacy blocks
    // the walk regardless of the Scope (I2).
    vault.set_disclosure_tier_a(&vaulted, 100)?;
    let scope =
        crate::disclosure::DisclosureScope::new(crate::federation::Scope::top(), "party", 100)?;
    vault.set_counterparty_disclosure_scope(&contact_id, &scope)?;

    let ctx = absence_ctx_for_contact(&vault, contact_id);
    let pack = vault
        .context_pack()
        .search_text("needle10", 10)
        .include_edges(true)
        .edge_hop(2)
        .disclosure_context(ctx)
        .run()?;

    assert!(pack_ids(&pack).contains(&party));
    assert_id_absent_everywhere(&pack, &vaulted, "edge-reachable Tier-A entity");
    Ok(())
}

#[test]
fn n11_tier_a_carve_out_is_mode_keyed_not_data_loss() -> Result<()> {
    let (_tmp, vault) = open_test_vault();
    let contact_id = disclosure_id(0xC7);
    seed_disclosure_contact(&vault, contact_id, "kenji@example.com");
    let subject = disclosure_id(0xE0);
    put_disclosure_turn(&vault, &subject, "subject turn");
    let band2 = disclosure_id(0x5E);
    put_disclosure_claim(
        &vault,
        &band2,
        subject,
        "profile.health_note",
        "clinic details needle11",
        Some("sensitive"),
    );

    // OwnerAlone (no context attached) returns the Tier-A claim.
    let pack = vault.context_pack().search_text("needle11", 10).run()?;
    assert!(pack_ids(&pack).contains(&band2));

    // An explicit OwnerAlone context is byte-identical in effect.
    let owner_ctx =
        DisclosureContext::resolve(&vault, crate::interlocutor::InterlocutorSet::owner_alone())?;
    let run = vault
        .context_pack()
        .search_text("needle11", 10)
        .disclosure_context(owner_ctx)
        .run_unfinalized_with_telemetry()?;
    assert!(pack_ids(&run.value).contains(&band2));
    assert_eq!(run.clamped_out(), 0, "OwnerAlone clamps nothing");

    // The same query under Supervised does not return it.
    let supervised = supervised_ctx_for_contact(&vault, contact_id);
    let pack = vault
        .context_pack()
        .search_text("needle11", 10)
        .disclosure_context(supervised)
        .run()?;
    assert_id_absent_everywhere(&pack, &band2, "mode-keyed Tier-A carve-out");
    Ok(())
}

#[test]
fn n12_validate_pack_disclosure_fails_a_tampered_pack() -> Result<()> {
    let (_tmp, vault) = open_test_vault();
    let contact_id = disclosure_id(0xC8);
    seed_disclosure_contact(&vault, contact_id, "kenji@example.com");
    let marked = disclosure_id(0xE2);
    put_disclosure_turn(&vault, &marked, "smuggled row");
    vault.set_disclosure_tier_a(&marked, 100)?;
    let ctx = absence_ctx_for_contact(&vault, contact_id);

    let smuggled = ContextEntity {
        critical: false,
        id: marked,
        short_id: "tn_smuggled".to_owned(),
        content_hash: 0,
        source_revision_ref: None,
        entity_type: ENTITY_TYPE_TURN,
        score: 1.0,
        fields: None,
        edges: None,
        vector: None,
    };
    let rtxn = vault.store.env.read_txn()?;
    let err = validate_pack_disclosure(&vault.store, &rtxn, &ctx, &[smuggled], &[])
        .expect_err("THE PACK BUILD FAILS RATHER THAN LEAKS");
    assert_eq!(
        err.kind(),
        crate::error::ErrorKind::DisclosureClampViolation
    );
    Ok(())
}

#[test]
fn clamped_assemblies_persist_no_retrieval_stage_trace() -> Result<()> {
    let (_tmp, vault) = open_test_vault();
    let contact_id = disclosure_id(0xC9);
    seed_disclosure_contact(&vault, contact_id, "kenji@example.com");
    let party = disclosure_id(0xE4);
    let diary = disclosure_id(0xE5);
    put_disclosure_turn(&vault, &party, "party trace needle25");
    put_disclosure_claim_in_world(
        &vault,
        &diary,
        party,
        "event.diary",
        "private trace needle25",
        Some("private"),
        Some(disclosure_id(0xF5)),
    );
    let scope = crate::disclosure::DisclosureScope::new(
        disclosure_world_clearance([crate::claim::base_world_id()]),
        "party",
        100,
    )?;
    vault.set_counterparty_disclosure_scope(&contact_id, &scope)?;

    // Control: an owner-alone assembly with capture on records a stage trace.
    let run = vault
        .context_pack()
        .search_text("needle25", 10)
        .capture_retrieval_trace(true)
        .run_with_telemetry()?;
    let run_id = run.run_id.expect("telemetry run id");
    let record = vault.retrieval_run(run_id)?.expect("run record");
    assert!(
        record.trace.is_some(),
        "owner-alone trace capture stays unchanged"
    );
    assert!(record.replay_inputs.is_some());
    assert!(record.pack_output.is_some());

    // Clamped assembly: NO stage trace exists at all, so per_channel, fused,
    // blended, and reranked can never retain ids the clamp removed.
    let ctx = absence_ctx_for_contact(&vault, contact_id);
    let run = vault
        .context_pack()
        .search_text("needle25", 10)
        .capture_retrieval_trace(true)
        .disclosure_context(ctx)
        .run_with_telemetry()?;
    let run_id = run.run_id.expect("telemetry run id");
    let record = vault.retrieval_run(run_id)?.expect("run record");
    assert!(
        record.trace.is_none(),
        "a clamped assembly persists no retrieval stage trace"
    );
    assert!(record.replay_inputs.is_none());
    assert!(record.pack_output.is_none());
    // The finalized telemetry record itself carries only post-clamp ids.
    assert!(record.result_ids.contains(party.as_bytes()));
    assert!(
        !record.result_ids.contains(diary.as_bytes()),
        "clamped id absent from finalized telemetry result ids"
    );
    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════
// RT-05 (ONE-1687) — the window budget lifts from constant to profile
// ═══════════════════════════════════════════════════════════════════════

use crate::error::RecordError;

#[test]
fn pack_vectors_follow_the_selected_indexed_frontier() -> Result<()> {
    use crate::vault::ReadMode;
    let (_dir, vault) = open_test_vault();
    crate::test_util::publish_seeded_revisions(&vault);
    let id = EntityId::now();
    let old_vector = vec![1.0, 0.0, 0.0, 0.0];
    let new_vector = vec![0.0, 1.0, 0.0, 0.0];
    put_claim_text_entity(&vault, &id, "vectorfrontier", "test.vector", "old")?;
    vault.put_vector(&id, &old_vector)?;
    let old_pin = vault.pin_entity_revision(&id)?;
    let read = |mode| {
        vault
            .context_pack()
            .search_text("vectorfrontier", 10)
            .read_mode(mode)
            .include_vectors(true)
            .run()
    };
    let original = read(ReadMode::Pinned(old_pin))?;
    assert_eq!(original.results.len(), 1);
    assert_eq!(original.results[0].vector.as_ref(), Some(&old_vector));

    put_claim_text_entity(&vault, &id, "vectorfrontier", "test.vector", "new")?;
    vault.put_vector(&id, &new_vector)?;
    let new_pin = vault.pin_entity_revision(&id)?;
    assert_ne!(old_pin, new_pin);
    // Caller-staged input has not replaced the indexed vector yet. Historical
    // content can still use that row; live/new-pinned content cannot.
    assert_eq!(
        read(ReadMode::Pinned(old_pin))?.results[0].vector.as_ref(),
        Some(&old_vector)
    );
    assert!(read(ReadMode::Pinned(new_pin))?.results[0].vector.is_none());
    assert!(read(ReadMode::Live)?.results[0].vector.is_none());
    vault.set_indexed_idle_delay_ms(0)?;
    assert_eq!(
        vault.refresh_staged_indexed_at_idle(u64::MAX)?.refreshed,
        vec![(id, new_pin)]
    );
    let historical = read(ReadMode::Pinned(old_pin))?;
    assert_eq!(historical.results.len(), 1);
    assert_eq!(historical.results[0].source_revision_ref, Some(old_pin.0));
    assert_eq!(
        historical.results[0].fields.as_ref().unwrap().get("val"),
        Some(&serde_json::json!("old"))
    );
    assert!(historical.results[0].vector.is_none());
    let current = read(ReadMode::Pinned(new_pin))?;
    assert_eq!(current.results[0].source_revision_ref, Some(new_pin.0));
    assert_eq!(current.results[0].vector.as_ref(), Some(&new_vector));
    assert_eq!(
        read(ReadMode::Indexed)?.results[0].vector.as_ref(),
        Some(&new_vector)
    );
    assert_eq!(
        read(ReadMode::Live)?.results[0].vector.as_ref(),
        Some(&new_vector)
    );
    Ok(())
}
