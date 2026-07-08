use std::collections::{BTreeMap, HashSet};

use crate::error::Error;
use crate::types::{HnswConfig, TimeRange, VaultConfig};

use super::*;

fn reset_edge_scan_count() {
    EDGE_SCAN_COUNT.with(|count| count.set(0));
}

fn edge_scan_count() -> usize {
    EDGE_SCAN_COUNT.with(Cell::get)
}

#[test]
fn mcp_context_pack_ref_requires_supported_version_and_handle() {
    let mut context_pack = McpContextPackRef {
        schema_version: MCP_CONTEXT_PACK_REF_SCHEMA_VERSION.to_owned(),
        context_version: Some(EIRI_CONTEXT_VERSION_V4.to_owned()),
        pack_ref: Some("context-pack:test".to_owned()),
        retrieval_run_id: None,
        result_ids: Vec::new(),
        budget_ref: None,
    };
    assert_eq!(context_pack.validate(), Ok(()));

    context_pack.schema_version = "context_pack_ref.v2".to_owned();
    assert_eq!(
        context_pack.validate(),
        Err(McpContextPackRefError::UnsupportedSchemaVersion)
    );

    context_pack.schema_version = MCP_CONTEXT_PACK_REF_SCHEMA_VERSION.to_owned();
    context_pack.pack_ref = None;
    assert_eq!(
        context_pack.validate(),
        Err(McpContextPackRefError::MissingHandle)
    );
}

#[test]
fn mcp_context_pack_ref_rejects_blank_fields_and_noncanonical_results() {
    let mut context_pack = McpContextPackRef {
        schema_version: MCP_CONTEXT_PACK_REF_SCHEMA_VERSION.to_owned(),
        context_version: Some("  ".to_owned()),
        pack_ref: Some("context-pack:test".to_owned()),
        retrieval_run_id: None,
        result_ids: Vec::new(),
        budget_ref: None,
    };
    assert_eq!(
        context_pack.validate(),
        Err(McpContextPackRefError::BlankField("context_version"))
    );

    context_pack.context_version = Some(EIRI_CONTEXT_VERSION_V4.to_owned());
    context_pack.result_ids = vec!["7777777777777777777777777777777X".to_owned()];
    assert_eq!(
        context_pack.validate(),
        Err(McpContextPackRefError::InvalidResultId)
    );
}

fn test_config() -> VaultConfig {
    VaultConfig {
        map_size: 16 * 1024 * 1024,
        dimensions: 4,
        embedding_model: Some("test-model-v1".to_owned()),
        max_readers: 16,
        hnsw: HnswConfig {
            m_max_0: 64,
            ef_construction: 200,
            ef_search: 128,
        },
        text_analyzer: crate::types::TextAnalyzerConfig::default(),
        dict_search_paths: Vec::new(),
        skip_text_index_manifest_check: false,
    }
}

fn open_test_vault() -> (tempfile::TempDir, Vault) {
    crate::test_util::open_test_vault_with(test_config())
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

fn empty_pack_stats() -> PackStats {
    PackStats {
        candidates_considered: 0,
        signals_used: Vec::new(),
        query_time_us: 0,
        entities_hydrated: 0,
        neighbors_hydrated: 0,
        cosine_ghosts_dampened: 0,
        claims_suppressed: 0,
        tokens: crate::types::PackTokenStats::default(),
        items_truncated: crate::types::PackItemAccounting::item_budget(),
        items_dropped: crate::types::PackItemAccounting::token_budget(),
    }
}

fn board_entity(seed: u8, entity_type: u8, score: f32, short_id: &str) -> ContextEntity {
    ContextEntity {
        id: EntityId::from_bytes_unchecked([seed; 16]),
        short_id: short_id.to_owned(),
        content_hash: seed,
        entity_type,
        score,
        fields: None,
        edges: None,
        vector: None,
    }
}

#[test]
fn eiri_memory_board_serializes_rows_in_stable_slot_order() {
    let pack = ContextPack {
        results: vec![
            board_entity(0x41, ENTITY_TYPE_TURN, 0.25, "tn41"),
            board_entity(0x21, ENTITY_TYPE_CLAIM, 0.50, "cl21"),
            board_entity(0x22, ENTITY_TYPE_CLAIM, 1.0, "cl22"),
            board_entity(0x51, 42, 0.75, "zz51"),
            board_entity(0x61, ENTITY_TYPE_COMPANION_REGISTER, 0.125, "cp61"),
        ],
        neighbors: vec![board_entity(0x42, ENTITY_TYPE_TURN, 0.875, "tn42")],
        stats: empty_pack_stats(),
        empty: None,
    };

    let board = assemble_eiri_memory_board(
        &pack,
        EiriMemoryBoardBudget::new(2, 1, 0, 0, 1, 0),
        Some(EiriCompanionAssembly {
            caller: Some("default".to_owned()),
            scope: Some("neutral".to_owned()),
            scope_source: Some("neutral_default".to_owned()),
            person_ref: None,
            persona_ref: Some("persona-alpha".to_owned()),
            expression: Some("professional".to_owned()),
        }),
    );

    let value = serde_json::to_value(&board).expect("memory board serializes");
    assert_eq!(
        value,
        serde_json::json!({
            "version": "v4",
            "budget": {
                "claims": 2,
                "turns": 1,
                "summaries": 0,
                "facets": 0,
                "companions": 1,
                "other": 0
            },
            "rows": [
                {
                    "row_index": 0,
                    "slot": "claims",
                    "source": "result",
                    "id": "22222222222222222222222222222222",
                    "short_id": "cl22",
                    "content_hash": "22",
                    "entity_type": ENTITY_TYPE_CLAIM,
                    "score": 1.0
                },
                {
                    "row_index": 1,
                    "slot": "claims",
                    "source": "result",
                    "id": "21212121212121212121212121212121",
                    "short_id": "cl21",
                    "content_hash": "21",
                    "entity_type": ENTITY_TYPE_CLAIM,
                    "score": 0.50
                },
                {
                    "row_index": 2,
                    "slot": "turns",
                    "source": "result",
                    "id": "41414141414141414141414141414141",
                    "short_id": "tn41",
                    "content_hash": "41",
                    "entity_type": ENTITY_TYPE_TURN,
                    "score": 0.25
                },
                {
                    "row_index": 3,
                    "slot": "companions",
                    "source": "result",
                    "id": "61616161616161616161616161616161",
                    "short_id": "cp61",
                    "content_hash": "61",
                    "entity_type": ENTITY_TYPE_COMPANION_REGISTER,
                    "score": 0.125
                }
            ],
            "companion": {
                "caller": "default",
                "scope": "neutral",
                "scope_source": "neutral_default",
                "person_ref": null,
                "persona_ref": "persona-alpha",
                "expression": "professional"
            }
        })
    );
}

#[test]
fn eiri_memory_board_routes_asset_rows_by_ref_without_local_downgrade() {
    let pack = ContextPack {
        results: vec![
            board_entity(0xA1, ENTITY_TYPE_ASSET, 0.9, "as15"),
            board_entity(0xA2, ENTITY_TYPE_ASSET_TEXT, 0.8, "tx10"),
        ],
        neighbors: Vec::new(),
        stats: empty_pack_stats(),
        empty: None,
    };

    let board =
        assemble_eiri_memory_board(&pack, EiriMemoryBoardBudget::new(0, 0, 0, 0, 0, 2), None);
    let asset_row = board
        .rows
        .iter()
        .find(|row| row.entity_type == ENTITY_TYPE_ASSET)
        .expect("ASSET row remains present");
    let asset_text_row = board
        .rows
        .iter()
        .find(|row| row.entity_type == ENTITY_TYPE_ASSET_TEXT)
        .expect("ASSET_TEXT row remains present");

    assert_eq!(asset_row.asset_ref.as_deref(), Some("as15:a1"));
    assert_eq!(asset_text_row.asset_ref.as_deref(), Some("tx10:a2"));
    assert_eq!(asset_row.entity_type, ENTITY_TYPE_ASSET);
}

#[test]
fn companion_register_api_context_pack_retrieves_affect_without_private_note_leak() -> Result<()> {
    let (_tmp, vault) = open_test_vault();
    let private_note = "private-companion-note-one1219";
    let private_provenance = "private-provenance-one1219";
    let companion_id = EntityId::from_bytes_unchecked([0x71; 16]);
    let turn_id = EntityId::from_bytes_unchecked([0x72; 16]);

    let provenance = crate::CompanionProvenance::new(
        EntityId::from_bytes_unchecked([0x73; 16]),
        crate::EdgeActorClass::Agent,
        crate::ClaimSource::UserStated,
        crate::ClaimApprovalStatus::Approved,
        crate::companion_value_from_json(
            &serde_json::json!({ "source": "fixture", "note": private_provenance }),
        )?,
    );
    let record = crate::CompanionRecord::persona(
        crate::CompanionScope::personal(EntityId::from_bytes_unchecked([0x74; 16])),
        EntityId::from_bytes_unchecked([0x75; 16]),
        crate::companion_value_from_json(&serde_json::json!({ "note": private_note }))?,
        provenance,
        crate::CompanionExportClassification::LocalOnly,
    );
    vault.create_companion_record(&companion_id, &record, 20)?;
    vault
        .batch()
        .text(&companion_id, &[("body", private_note)])
        .commit()?;

    put_text_entity(
        &vault,
        &turn_id,
        crate::types::ENTITY_TYPE_TURN,
        "turn affect retrieval needle",
        serde_json::json!({
            "txt": "turn affect retrieval needle",
            "spkr": "user",
            "at": 21_u64
        }),
    )?;
    vault.annotate_turn_vad(
        &turn_id,
        crate::VadAnnotation::new(
            crate::Vad {
                valence: 0.2,
                arousal: 0.3,
                dominance: 0.4,
            },
            crate::VadAnnotationSource::ModelInference,
            22,
        )?,
    )?;

    let private_pack = vault.context_pack().search_text(private_note, 10).run()?;
    let companion = private_pack
        .results
        .iter()
        .find(|entity| entity.id == companion_id)
        .expect("indexed companion record should hydrate");
    let fields = companion.fields.as_ref().expect("companion fields");
    assert!(
        !fields.contains_key("value"),
        "context-pack must not expose opaque private companion value"
    );
    assert_eq!(
        fields.get("lifecycle_events"),
        Some(&serde_json::json!([{ "kind": "created", "at": 20_u64 }]))
    );
    assert!(
        fields
            .get("provenance")
            .and_then(|value| value.get("value"))
            .is_none(),
        "context-pack must not expose opaque provenance payloads"
    );
    assert!(
        !serde_json::to_string(fields)
            .expect("fields serialize")
            .contains(private_note),
        "context-pack metadata must not leak private note text"
    );
    assert!(
        !serde_json::to_string(fields)
            .expect("fields serialize")
            .contains(private_provenance),
        "context-pack metadata must not leak private provenance text"
    );

    let affect_pack = vault
        .context_pack()
        .search_text("turn affect retrieval needle", 10)
        .run()?;
    assert!(
        affect_pack
            .results
            .iter()
            .any(|entity| entity.id == turn_id),
        "companion register tuning must not block affect-bearing turn retrieval"
    );
    Ok(())
}

#[test]
fn affect_trigger_context_pack_projects_typed_value_refs() -> Result<()> {
    let (_tmp, vault) = open_test_vault();
    let occurred = TimeRange { start: 1, end: 1 };
    let actor = EntityId::from_bytes_unchecked([0x81; 16]);
    let person = EntityId::from_bytes_unchecked([0x82; 16]);
    let trigger = EntityId::from_bytes_unchecked([0x83; 16]);
    let claim = EntityId::from_bytes_unchecked([0x84; 16]);
    vault.put_entity(
        &actor,
        crate::types::ENTITY_TYPE_PERSON,
        occurred,
        1,
        b"actor",
    )?;
    vault.put_entity(
        &person,
        crate::types::ENTITY_TYPE_PERSON,
        occurred,
        1,
        b"person",
    )?;
    put_text_entity(
        &vault,
        &trigger,
        crate::types::ENTITY_TYPE_TURN,
        "affect trigger source turn",
        serde_json::json!({
            "txt": "affect trigger source turn",
            "spkr": "user",
            "at": 2_u64
        }),
    )?;

    let envelope = crate::WriteEnvelope::new(
        crate::WriteActor::new(actor, crate::EdgeActorClass::Human),
        crate::ClaimSource::Observed,
        crate::WriteProvenance::new(rmpv::Value::from("dreamer"))?,
        crate::ClaimApprovalStatus::Approved,
    );
    let trigger_value = crate::AffectTriggerValue::new(
        person,
        trigger,
        crate::VadDelta::new(-0.1, 0.25, -0.2)?,
        0.67,
        4,
        16,
    )?;
    vault
        .batch()
        .affect_trigger_claim(
            &claim,
            trigger_value,
            &envelope,
            TimeRange { start: 3, end: 3 },
            4,
        )
        .text(&claim, &[("body", "affect trigger retrieval needle")])
        .commit()?;

    let pack = vault
        .context_pack()
        .search_text("affect trigger retrieval needle", 10)
        .run()?;
    let fields = pack
        .results
        .iter()
        .find(|entity| entity.id == claim)
        .and_then(|entity| entity.fields.as_ref())
        .expect("affect trigger claim fields");
    assert_eq!(
        fields.get("pred"),
        Some(&serde_json::Value::String(
            crate::AFFECT_TRIGGER_PREDICATE.to_owned()
        ))
    );
    let val = fields
        .get("val")
        .and_then(serde_json::Value::as_object)
        .expect("affect trigger value map");
    let person_hex = person.to_hex();
    let trigger_hex = trigger.to_hex();
    assert_eq!(
        val.get("affectedPerson")
            .and_then(serde_json::Value::as_str),
        Some(person_hex.as_str())
    );
    assert_eq!(
        val.get("triggerRef").and_then(serde_json::Value::as_str),
        Some(trigger_hex.as_str())
    );
    assert_eq!(
        val.get("observedN").and_then(serde_json::Value::as_u64),
        Some(16)
    );
    assert_eq!(val.get("k").and_then(serde_json::Value::as_u64), Some(4));
    let confidence = val
        .get("confidence")
        .and_then(serde_json::Value::as_f64)
        .expect("affect trigger confidence");
    assert!((confidence - 0.67).abs() < 1e-6);
    let vad_delta = val
        .get("vadDelta")
        .and_then(serde_json::Value::as_object)
        .expect("affect trigger vadDelta");
    for (key, expected) in [("valence", -0.1), ("arousal", 0.25), ("dominance", -0.2)] {
        let actual = vad_delta
            .get(key)
            .and_then(serde_json::Value::as_f64)
            .expect("vadDelta component");
        assert!((actual - expected).abs() < 1e-6, "{key}");
    }
    Ok(())
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
    );
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
    );
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
    let mut raw = Vec::with_capacity(ENTITY_METADATA_HEADER_LEN + payload.len());
    raw.push(entity_type);
    raw.extend_from_slice(&occurred_start.to_be_bytes());
    raw.extend_from_slice(&occurred_end.to_be_bytes());
    raw.extend_from_slice(&learned_at.to_be_bytes());
    raw.extend_from_slice(payload);
    raw
}

fn overwrite_raw_entity(vault: &Vault, id: &EntityId, raw: &[u8]) -> Result<()> {
    vault.with_write_txn(|wtxn| {
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
    );
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
        Error::ContextPackValidation { id, reason } => {
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
fn dedupe_signals_preserves_first_occurrence_order() {
    let signals = vec![
        Signal::Text,
        Signal::Vector,
        Signal::Text,
        Signal::Temporal,
        Signal::Vector,
    ];

    assert_eq!(
        dedupe_signals(signals),
        vec![Signal::Text, Signal::Vector, Signal::Temporal]
    );
}

#[test]
fn basic_hydration_populates_fields() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let id = EntityId::now();

    put_claim_text_entity(
        &vault,
        &id,
        "learn japanese",
        "goal.learning",
        "Learn Japanese by June",
    )?;

    let pack = vault.context_pack().search_text("japanese", 10).run()?;
    assert_eq!(pack.results.len(), 1);
    let entity = &pack.results[0];
    assert_eq!(entity.id, id);
    assert_eq!(entity.entity_type, 0);
    assert!(!entity.short_id.is_empty());

    let fields = entity.fields.as_ref().expect("fields missing");
    assert_eq!(
        fields.get("pred").and_then(|v| v.as_str()),
        Some("goal.learning")
    );
    let conf = fields
        .get("conf")
        .and_then(serde_json::Value::as_f64)
        .expect("conf field missing");
    assert!((conf - 0.9).abs() < 1e-6, "conf drifted: {conf}");
    Ok(())
}

#[test]
fn builder_clamps_edge_expansion_settings() {
    let (_dir, vault) = open_test_vault();

    let builder = vault.context_pack().edge_hop(99).max_neighbors(10_000);
    assert_eq!(builder.edge_hop, MAX_EDGE_HOP);
    assert_eq!(builder.selected_edge_budget, MAX_CONTEXT_NEIGHBORS);
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
            hydrate_fields: true,
            include_edges: false,
            include_vectors: false,
            edge_cache: None,
            claim_bodies: None,
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
fn include_edges_returns_edge_info() -> Result<()> {
    let (_dir, vault) = open_test_vault();

    let src = EntityId::now();
    let tgt = EntityId::now();
    put_claim_text_entity(&vault, &src, "alpha", "test.x", "y")?;
    put_text_entity(
        &vault,
        &tgt,
        4,
        "beta",
        serde_json::json!({"name": "Alice"}),
    )?;

    vault.put_edge(&src, crate::types::EdgeKind::Supports, &tgt, 0.7)?;

    let pack = vault
        .context_pack()
        .search_text("alpha", 10)
        .include_edges(true)
        .run()?;

    let edges = pack.results[0].edges.as_ref().expect("expected edges");
    assert_eq!(edges.len(), 1);
    assert_eq!(edges[0].target, tgt);
    assert_eq!(edges[0].kind, crate::types::EdgeKind::Supports);
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
    vault.put_edge(&src, crate::types::EdgeKind::Supports, &healthy, 0.7)?;

    // Plant a 13-byte edge value via a raw write: the contract pins the
    // edge value as a fixed-width LE buffer of exactly 12/24/26 bytes
    // (dbManifest n14), so 13 bytes is on-disk corruption.
    let key = Store::encode_edge_key(&src, crate::types::EdgeKind::Mentions, &tgt);
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
fn scan_edges_for_entity_enforces_result_bound() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let small_src = EntityId::from_bytes_unchecked([0x01; 16]);
    let bounded_src = EntityId::from_bytes_unchecked([0x02; 16]);
    let value = crate::types::encode_edge_value(
        crate::types::EdgeKind::Mentions,
        0.5,
        0,
        crate::types::Vad::NEUTRAL,
        None,
    )?;

    vault.with_write_txn(|wtxn| {
        let target = EntityId::from_bytes_unchecked([0x03; 16]);
        let key = Store::encode_edge_key(&small_src, crate::types::EdgeKind::Mentions, &target);
        vault.store.edges_out.put(wtxn, &key, &value)?;
        Ok(())
    })?;
    {
        let rtxn = vault.store.env.read_txn()?;
        assert_eq!(
            scan_edges_for_entity(&vault.store, &rtxn, &small_src)?.len(),
            1
        );
    }

    vault.with_write_txn(|wtxn| {
        for i in 0..MAX_EDGE_SCAN_RESULTS {
            let target_byte = u8::try_from(i + 4).expect("test cap fits in u8");
            let target = EntityId::from_bytes_unchecked([target_byte; 16]);
            let key =
                Store::encode_edge_key(&bounded_src, crate::types::EdgeKind::Mentions, &target);
            vault.store.edges_out.put(wtxn, &key, &value)?;
        }
        Ok(())
    })?;
    {
        let rtxn = vault.store.env.read_txn()?;
        assert_eq!(
            scan_edges_for_entity(&vault.store, &rtxn, &bounded_src)?.len(),
            MAX_EDGE_SCAN_RESULTS
        );
    }

    vault.with_write_txn(|wtxn| {
        let overflow_target = EntityId::from_bytes_unchecked([0xFE; 16]);
        let key = Store::encode_edge_key(
            &bounded_src,
            crate::types::EdgeKind::Mentions,
            &overflow_target,
        );
        vault.store.edges_out.put(wtxn, &key, &value)?;
        Ok(())
    })?;

    let rtxn = vault.store.env.read_txn()?;
    let err = scan_edges_for_entity(&vault.store, &rtxn, &bounded_src)
        .expect_err("edge scan must fail closed once the result bound is exceeded");
    assert!(
        matches!(err, Error::CorruptedIndex("edge scan exceeded bound")),
        "expected CorruptedIndex(\"edge scan exceeded bound\"), got {err:?}"
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
    vault.put_edge(&root, crate::types::EdgeKind::Supports, &neighbor, 1.0)?;

    let key = Store::encode_edge_key(&root, crate::types::EdgeKind::Mentions, &tgt);
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

    let supports_key =
        Store::encode_edge_key(&src, crate::types::EdgeKind::Supports, &tgt).to_vec();
    let child_of_key = Store::encode_edge_key(&src, crate::types::EdgeKind::ChildOf, &tgt).to_vec();

    // 33-byte key whose kind byte (20) is outside the pinned 0-19 range.
    let mut unknown_kind_key = src.as_bytes().to_vec();
    unknown_kind_key.push(20);
    unknown_kind_key.extend_from_slice(tgt.as_bytes());

    // 17-byte key: source id + kind byte, target id missing entirely.
    let mut truncated_key = src.as_bytes().to_vec();
    truncated_key.push(crate::types::EdgeKind::Supports as u8);

    // 33-byte key whose target is the reserved all-0xFF sentinel id.
    let mut reserved_target_key = src.as_bytes().to_vec();
    reserved_target_key.push(crate::types::EdgeKind::Supports as u8);
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
fn vad_round_trip_through_hydration() -> Result<()> {
    let (_dir, vault) = open_test_vault();

    let src = EntityId::now();
    let tgt = EntityId::now();
    put_claim_text_entity(&vault, &src, "gamma", "test.x", "y")?;
    put_text_entity(&vault, &tgt, 4, "delta", serde_json::json!({"name": "Bob"}))?;

    vault.put_edge_with_vad(
        &src,
        crate::types::EdgeKind::HasFacet,
        &tgt,
        0.8,
        crate::types::Vad {
            valence: 0.6,
            arousal: 0.3,
            dominance: 0.9,
        },
    )?;

    let pack = vault
        .context_pack()
        .search_text("gamma", 10)
        .include_edges(true)
        .run()?;

    let edges = pack.results[0].edges.as_ref().expect("expected edges");
    assert_eq!(edges.len(), 1);
    assert_eq!(edges[0].kind, crate::types::EdgeKind::HasFacet);
    assert!((edges[0].weight - 0.8).abs() < f32::EPSILON);
    let vad = edges[0].vad.expect("semantic edge should hydrate VAD");
    assert!((vad.valence - 0.6).abs() < f32::EPSILON);
    assert!((vad.arousal - 0.3).abs() < f32::EPSILON);
    assert!((vad.dominance - 0.9).abs() < f32::EPSILON);
    Ok(())
}

#[test]
fn edge_hops_collect_neighbors() -> Result<()> {
    let (_dir, vault) = open_test_vault();

    let a = EntityId::now();
    let b = EntityId::now();
    let c = EntityId::now();

    put_claim_text_entity(&vault, &a, "root", "test.root", "root")?;
    put_text_entity(&vault, &b, 4, "child", serde_json::json!({"name": "B"}))?;
    put_text_entity(&vault, &c, 4, "leaf", serde_json::json!({"name": "C"}))?;

    vault.put_edge(&a, crate::types::EdgeKind::Supports, &b, 1.0)?;
    vault.put_edge(&b, crate::types::EdgeKind::Supports, &c, 1.0)?;

    let hop1 = vault
        .context_pack()
        .search_text("root", 10)
        .edge_hop(1)
        .run()?;
    let hop1_ids: HashSet<EntityId> = hop1.neighbors.iter().map(|e| e.id).collect();
    assert!(hop1_ids.contains(&b));
    assert!(!hop1_ids.contains(&c));

    let hop2 = vault
        .context_pack()
        .search_text("root", 10)
        .edge_hop(2)
        .run()?;
    let hop2_ids: HashSet<EntityId> = hop2.neighbors.iter().map(|e| e.id).collect();
    assert!(hop2_ids.contains(&b));
    assert!(hop2_ids.contains(&c));
    Ok(())
}

#[test]
fn max_neighbors_caps_neighbor_count() -> Result<()> {
    let (_dir, vault) = open_test_vault();

    let root = EntityId::now();
    put_claim_text_entity(&vault, &root, "root", "test.root", "root")?;

    for i in 0..20_u8 {
        let id = EntityId::from_bytes_unchecked([i + 1; 16]);
        put_text_entity(
            &vault,
            &id,
            4,
            "neighbor",
            serde_json::json!({"name": format!("P{i}")}),
        )?;
        vault.put_edge(&root, crate::types::EdgeKind::Mentions, &id, 1.0)?;
    }

    let pack = vault
        .context_pack()
        .search_text("root", 10)
        .edge_hop(1)
        .max_neighbors(5)
        .run()?;

    assert!(pack.neighbors.len() <= 5);
    Ok(())
}

#[test]
fn retrieval_budget_balances_claim_turn_and_facet_before_global_truncation() -> Result<()> {
    let (_dir, vault) = open_test_vault();

    let claim_top = EntityId::from_bytes_unchecked([0xA1; 16]);
    let claim_crowder_a = EntityId::from_bytes_unchecked([0xA2; 16]);
    let claim_crowder_b = EntityId::from_bytes_unchecked([0xA3; 16]);
    let turn = EntityId::from_bytes_unchecked([0xB1; 16]);
    let facet = EntityId::from_bytes_unchecked([0xC1; 16]);

    put_claim_text_entity(
        &vault,
        &claim_top,
        "budgetbalance",
        "test.budget.top",
        "top",
    )?;
    put_claim_text_entity(
        &vault,
        &claim_crowder_a,
        "budgetbalance",
        "test.budget.crowder_a",
        "crowder a",
    )?;
    put_claim_text_entity(
        &vault,
        &claim_crowder_b,
        "budgetbalance",
        "test.budget.crowder_b",
        "crowder b",
    )?;
    put_text_entity(
        &vault,
        &turn,
        crate::types::ENTITY_TYPE_TURN,
        "budgetbalance",
        serde_json::json!({"text": "turn"}),
    )?;
    put_text_entity(
        &vault,
        &facet,
        crate::types::ENTITY_TYPE_FACET,
        "budgetbalance",
        serde_json::json!({"name": "active facet"}),
    )?;

    vault.put_vector(&claim_top, &[1.0, 0.0, 0.0, 0.0])?;
    vault.put_vector(&claim_crowder_a, &[0.9, 0.1, 0.0, 0.0])?;
    vault.put_vector(&claim_crowder_b, &[0.8, 0.2, 0.0, 0.0])?;
    vault.put_vector(&turn, &[0.7, 0.3, 0.0, 0.0])?;
    vault.put_vector(&facet, &[0.6, 0.4, 0.0, 0.0])?;

    let pack = vault
        .context_pack()
        .search_vector(&[1.0, 0.0, 0.0, 0.0], 10)
        .limit(3)
        .retrieval_budget(ContextPackRetrievalBudget::new(1, 1, 0, 1, 0, 0))
        .run()?;

    let ids: Vec<EntityId> = pack.results.iter().map(|entity| entity.id).collect();
    assert_eq!(
        ids,
        vec![claim_top, turn, facet],
        "CLAIM/TURN/FACET budgets must apply before global truncation"
    );
    assert!(
        !ids.contains(&claim_crowder_a) && !ids.contains(&claim_crowder_b),
        "lower-ranked claims must not consume the TURN/FACET budget"
    );
    Ok(())
}

#[test]
fn retrieval_budget_zero_caps_remain_excluded_after_surplus_redistribution() -> Result<()> {
    let (_dir, vault) = open_test_vault();

    let claim = EntityId::from_bytes_unchecked([0xE1; 16]);
    let summary_a = EntityId::from_bytes_unchecked([0xE2; 16]);
    let summary_b = EntityId::from_bytes_unchecked([0xE3; 16]);

    put_claim_text_entity(&vault, &claim, "zerocapbudget", "test.zero.cap", "claim")?;
    put_text_entity(
        &vault,
        &summary_a,
        crate::types::ENTITY_TYPE_SUMMARY,
        "zerocapbudget",
        serde_json::json!({"text": "summary a"}),
    )?;
    put_text_entity(
        &vault,
        &summary_b,
        crate::types::ENTITY_TYPE_SUMMARY,
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
        crate::types::ENTITY_TYPE_TURN,
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
fn selected_edge_budget_caps_edge_walk() -> Result<()> {
    let (_dir, vault) = open_test_vault();

    let root = EntityId::from_bytes_unchecked([0xD1; 16]);
    let strongest = EntityId::from_bytes_unchecked([0xD2; 16]);
    let weaker = EntityId::from_bytes_unchecked([0xD3; 16]);
    put_claim_text_entity(&vault, &root, "edgebudget", "test.edge.root", "root")?;
    put_text_entity(
        &vault,
        &strongest,
        4,
        "edge neighbor strongest",
        serde_json::json!({"name": "strongest"}),
    )?;
    put_text_entity(
        &vault,
        &weaker,
        4,
        "edge neighbor weaker",
        serde_json::json!({"name": "weaker"}),
    )?;
    vault.put_edge(&root, crate::types::EdgeKind::Mentions, &strongest, 0.9)?;
    vault.put_edge(&root, crate::types::EdgeKind::Mentions, &weaker, 0.8)?;

    let pack = vault
        .context_pack()
        .search_text("edgebudget", 10)
        .edge_hop(1)
        .selected_edge_budget(1)
        .run()?;

    let neighbor_ids: Vec<EntityId> = pack.neighbors.iter().map(|entity| entity.id).collect();
    assert_eq!(neighbor_ids, vec![strongest]);
    Ok(())
}

#[test]
fn neighbor_selection_prefers_highest_weight_edges() -> Result<()> {
    let (_dir, vault) = open_test_vault();

    let root = EntityId::from_bytes_unchecked([1; 16]);
    put_claim_text_entity(&vault, &root, "root", "test.root", "root")?;

    let weighted = [
        (EntityId::from_bytes_unchecked([2; 16]), 0.4_f32),
        (EntityId::from_bytes_unchecked([3; 16]), 0.9_f32),
        (EntityId::from_bytes_unchecked([4; 16]), 0.7_f32),
        (EntityId::from_bytes_unchecked([5; 16]), 0.2_f32),
    ];

    for (id, weight) in weighted {
        put_text_entity(
            &vault,
            &id,
            4,
            "neighbor",
            serde_json::json!({"name": format!("P{:?}", id.as_bytes()[0])}),
        )?;
        vault.put_edge(&root, crate::types::EdgeKind::Mentions, &id, weight)?;
    }

    let pack = vault
        .context_pack()
        .search_text("root", 10)
        .edge_hop(1)
        .max_neighbors(2)
        .run()?;

    let neighbor_ids: Vec<EntityId> = pack.neighbors.iter().map(|entity| entity.id).collect();
    assert_eq!(
        neighbor_ids,
        vec![
            EntityId::from_bytes_unchecked([3; 16]),
            EntityId::from_bytes_unchecked([4; 16])
        ]
    );
    Ok(())
}

#[test]
fn include_edges_reuses_walk_scans_for_results() -> Result<()> {
    let (_dir, vault) = open_test_vault();

    let root = EntityId::from_bytes_unchecked([7; 16]);
    let child = EntityId::from_bytes_unchecked([8; 16]);
    put_claim_text_entity(&vault, &root, "root", "test.root", "root")?;
    put_text_entity(
        &vault,
        &child,
        4,
        "child",
        serde_json::json!({"name": "Child"}),
    )?;
    vault.put_edge(&root, crate::types::EdgeKind::Supports, &child, 1.0)?;

    reset_edge_scan_count();
    let rtxn = vault.store.env.read_txn()?;
    let walked = walk_edges(&vault.store, &rtxn, &[root], 1, 10, &HashSet::from([root]))?;
    assert_eq!(edge_scan_count(), 1, "walk should scan the root once");

    let cached_edges = load_entity_edges(&vault.store, &rtxn, &root, Some(&walked.scanned_edges))?;
    assert_eq!(cached_edges.len(), 1);
    assert_eq!(
        edge_scan_count(),
        1,
        "loading root edges from the walk cache should not rescan"
    );

    let uncached_edges =
        load_entity_edges(&vault.store, &rtxn, &child, Some(&walked.scanned_edges))?;
    assert!(uncached_edges.is_empty());
    assert_eq!(
        edge_scan_count(),
        2,
        "loading uncached neighbor edges should perform one scan"
    );
    Ok(())
}

#[test]
fn include_vectors_controls_vector_hydration() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let id = EntityId::now();

    put_claim_text_entity(&vault, &id, "vec", "test.a", "b")?;

    vault.put_vector(&id, &[0.1, 0.2, 0.3, 0.4])?;

    let with_vectors = vault
        .context_pack()
        .search_text("vec", 10)
        .include_vectors(true)
        .run()?;
    assert_eq!(
        with_vectors.results[0].vector.as_ref().map(Vec::len),
        Some(4)
    );

    let without_vectors = vault.context_pack().search_text("vec", 10).run()?;
    assert!(without_vectors.results[0].vector.is_none());
    Ok(())
}

#[test]
fn empty_results_return_empty_pack() -> Result<()> {
    let (_dir, vault) = open_test_vault();

    let pack = vault.context_pack().search_text("nothing", 10).run()?;
    assert!(pack.results.is_empty());
    assert!(pack.neighbors.is_empty());
    assert_eq!(pack.stats.candidates_considered, 0);
    let empty = pack.empty.as_ref().expect("empty context");
    assert_eq!(empty.reason, EmptyReason::NoData);
    assert_eq!(empty.total_in_scope, 0);
    Ok(())
}

#[test]
fn non_empty_results_omit_empty_context() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let id = EntityId::now();
    put_claim_text_entity(&vault, &id, "alpha", "test.alpha", "a")?;

    let pack = vault.context_pack().search_text("alpha", 10).run()?;
    assert_eq!(pack.results.len(), 1);
    assert!(pack.neighbors.is_empty());
    assert!(pack.empty.is_none());
    Ok(())
}

#[test]
fn filtered_empty_reports_pre_filter_scope_count() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    for i in 0..3_u8 {
        let id = EntityId::from_bytes([0x30 + i; 16])?;
        put_claim_text_entity(&vault, &id, "sharedneedle", "test.filter", "v")?;
    }

    let pack = vault
        .context_pack()
        .search_text("sharedneedle", 10)
        .filter_types(&[1])
        .run()?;

    assert!(pack.results.is_empty());
    assert!(pack.neighbors.is_empty());
    assert_eq!(pack.stats.candidates_considered, 3);
    let empty = pack.empty.as_ref().expect("empty context");
    assert_eq!(empty.reason, EmptyReason::FilterMatchedNone);
    assert_eq!(empty.total_in_scope, 3);
    Ok(())
}

#[test]
fn status_suppressed_empty_reports_all_activated() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let superseded = EntityId::from_bytes([0x41; 16])?;
    let retracted = EntityId::from_bytes([0x42; 16])?;
    put_claim_text_entity_with_status(
        &vault,
        &superseded,
        "deadneedle",
        "test.status",
        "superseded",
        crate::claim::ClaimApprovalStatus::Auto,
        crate::claim::ClaimLifecycleStatus::Superseded,
    )?;
    put_claim_text_entity_with_status(
        &vault,
        &retracted,
        "deadneedle",
        "test.status",
        "retracted",
        crate::claim::ClaimApprovalStatus::Approved,
        crate::claim::ClaimLifecycleStatus::Retracted,
    )?;

    let pack = vault.context_pack().search_text("deadneedle", 10).run()?;

    assert!(pack.results.is_empty());
    assert!(pack.neighbors.is_empty());
    assert_eq!(pack.stats.candidates_considered, 2);
    assert_eq!(pack.stats.claims_suppressed, 2);
    let empty = pack.empty.as_ref().expect("empty context");
    assert_eq!(empty.reason, EmptyReason::AllActivated);
    assert_eq!(empty.total_in_scope, 2);
    Ok(())
}

#[test]
fn retract_claim_end_to_end_removes_stale_text_from_context_pack() -> Result<()> {
    let (_dir, vault) = open_test_vault();
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

#[test]
fn empty_after_result_cap_reports_below_threshold() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let id = EntityId::now();
    put_claim_text_entity(&vault, &id, "capneedle", "test.cap", "v")?;

    let pack = vault
        .context_pack()
        .search_text("capneedle", 10)
        .limit(0)
        .run()?;

    assert!(pack.results.is_empty());
    assert!(pack.neighbors.is_empty());
    assert_eq!(pack.stats.candidates_considered, 1);
    let empty = pack.empty.as_ref().expect("empty context");
    assert_eq!(empty.reason, EmptyReason::BelowThreshold);
    assert_eq!(empty.total_in_scope, pack.stats.candidates_considered);
    Ok(())
}

#[test]
fn scores_match_pipeline_scores() -> Result<()> {
    let (_dir, vault) = open_test_vault();

    let a = EntityId::now();
    let b = EntityId::now();
    put_claim_text_entity(&vault, &a, "alpha alpha", "test.a", "a")?;
    put_claim_text_entity(&vault, &b, "alpha", "test.b", "b")?;

    let expected = vault.query().search_text("alpha", 10).run()?;
    let pack = vault.context_pack().search_text("alpha", 10).run()?;

    assert_eq!(expected.len(), pack.results.len());
    for (left, right) in expected.iter().zip(pack.results.iter()) {
        assert_eq!(left.id, right.id);
        assert!((left.score - right.score).abs() < 1e-6);
    }
    Ok(())
}

#[test]
fn short_id_falls_back_to_hex_on_corruption() -> Result<()> {
    // (case_name, ingest_text, search_query, corrupt_fn)
    // After each corruption, `context_pack().search_text(query).run()` must
    // still return the entity with a 32-char (hex) short_id fallback.
    type CorruptFn = fn(&Vault, &EntityId) -> Result<()>;
    let cases: &[(&str, &str, &str, CorruptFn)] = &[
        ("missing", "fallback", "fallback", |vault, id| {
            let mut wtxn = vault.store.env.write_txn()?;
            vault
                .store
                .short_ids_reverse
                .delete(&mut wtxn, id.as_bytes())?;
            wtxn.commit()?;
            Ok(())
        }),
        ("corrupt", "corrupt fallback", "corrupt", |vault, id| {
            let mut wtxn = vault.store.env.write_txn()?;
            vault
                .store
                .short_ids_reverse
                .put(&mut wtxn, id.as_bytes(), &[0xff, 0xfe, 7])?;
            wtxn.commit()?;
            Ok(())
        }),
    ];

    for (name, ingest_text, search_query, corrupt) in cases {
        let (_dir, vault) = open_test_vault();
        let id = EntityId::now();

        put_claim_text_entity(&vault, &id, ingest_text, "test.a", "b")?;

        corrupt(&vault, &id)?;

        let pack = vault.context_pack().search_text(search_query, 10).run()?;
        assert_eq!(pack.results.len(), 1, "case {name}");
        assert_eq!(pack.results[0].id, id, "case {name}");
        assert_eq!(
            pack.results[0].short_id.len(),
            32,
            "case {name}: short_id should fall back to 32-char hex"
        );
    }

    Ok(())
}

/// Blocker 2 partitioning: under the default `All` scope the pack is
/// ordered base section first, then one section per non-base world —
/// EVEN when fictional claims outrank the base claim. Pins base-first
/// ordering + adjacency grouping; `fraction(1.0)` disables the cap so
/// every claim survives.
#[test]
fn world_all_scope_partitions_base_first() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let world_w = EntityId::from_bytes([0xE1; 16])?;
    let world_v = EntityId::from_bytes([0xE2; 16])?;

    let w1 = EntityId::from_bytes([0x71; 16])?; // rank 0 — world W
    let w2 = EntityId::from_bytes([0x72; 16])?; // rank 1 — world W
    let claim_base = EntityId::from_bytes([0x61; 16])?; // rank 2 — base
    let v1 = EntityId::from_bytes([0x81; 16])?; // rank 3 — world V
    put_world_claim(&vault, w1, [1.0, 0.0, 0.0, 0.0], Some(world_w))?;
    put_world_claim(&vault, w2, [0.9, 0.1, 0.0, 0.0], Some(world_w))?;
    put_world_claim(&vault, claim_base, [0.8, 0.2, 0.0, 0.0], None)?;
    put_world_claim(&vault, v1, [0.7, 0.3, 0.0, 0.0], Some(world_v))?;

    let pack = vault
        .context_pack()
        .search_vector(&[1.0, 0.0, 0.0, 0.0], 10)
        .non_base_world_claim_fraction(1.0) // disable the cap
        .run()?;

    let order: Vec<EntityId> = pack.results.iter().map(|entity| entity.id).collect();
    assert_eq!(
        order,
        vec![claim_base, w1, w2, v1],
        "All-scope pack must be base section first, then world W (adjacent), then world V"
    );
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
    );
    body.stale = stale;
    let payload = crate::claim::encode_claim_body(&body)?;
    vault
        .batch()
        .put(id, 0, TimeRange { start: 1, end: 1 }, 1, &payload)
        .commit()
}

/// AC 6 — results AND neighbors apply the same gate: dead claims
/// reached through `supports` / `claim_of` edges never enter
/// `pack.neighbors`, while a non-claim neighbor on the same seed does.
#[test]
fn pack_neighbors_apply_the_status_gate() -> Result<()> {
    let (_dir, vault) = open_test_vault();

    let a = EntityId::from_bytes_unchecked([0x31; 16]);
    let retracted = EntityId::from_bytes_unchecked([0x32; 16]);
    let proposed = EntityId::from_bytes_unchecked([0x33; 16]);
    let person = EntityId::from_bytes_unchecked([0x34; 16]);

    put_claim_text_entity(&vault, &a, "rootclaim", "test.root", "root")?;
    put_claim_with_status(
        &vault,
        &retracted,
        crate::claim::ClaimApprovalStatus::Auto,
        crate::claim::ClaimLifecycleStatus::Retracted,
        false,
    )?;
    put_claim_with_status(
        &vault,
        &proposed,
        crate::claim::ClaimApprovalStatus::Proposed,
        crate::claim::ClaimLifecycleStatus::Active,
        false,
    )?;
    put_text_entity(
        &vault,
        &person,
        4,
        "friendly",
        serde_json::json!({"name": "N"}),
    )?;

    vault.put_edge(&a, crate::types::EdgeKind::Supports, &retracted, 0.9)?;
    vault.put_edge(&a, crate::types::EdgeKind::ClaimOf, &proposed, 1.0)?;
    vault.put_edge(&a, crate::types::EdgeKind::Supports, &person, 0.8)?;

    let pack = vault
        .context_pack()
        .search_text("rootclaim", 10)
        .edge_hop(1)
        .max_neighbors(10)
        .run()?;

    assert_eq!(pack.results.len(), 1);
    assert_eq!(pack.results[0].id, a);

    let neighbor_ids: HashSet<EntityId> = pack.neighbors.iter().map(|e| e.id).collect();
    assert!(
        !neighbor_ids.contains(&retracted),
        "retracted claim via supports edge must not enter pack.neighbors"
    );
    assert!(
        !neighbor_ids.contains(&proposed),
        "proposed claim via claim_of edge must not enter pack.neighbors"
    );
    assert!(
        neighbor_ids.contains(&person),
        "non-claim neighbor must still hydrate"
    );
    assert_eq!(
        pack.stats.claims_suppressed, 2,
        "both dead claim neighbors counted"
    );
    Ok(())
}

/// Blocker 2 cap: with the default 0.5 fraction, 2 base + 4 fictional
/// claims give a claim budget of 6 and a non-base cap of 3 — the three
/// highest-scoring fiction claims survive, the lowest is dropped, and both
/// base claims are always kept (fiction can never crowd base out).
#[test]
fn world_all_scope_cap_drops_excess_fiction() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let world_w = EntityId::from_bytes([0xE1; 16])?;

    let base1 = EntityId::from_bytes([0x61; 16])?; // rank 0 — base
    let f1 = EntityId::from_bytes([0x71; 16])?; // rank 1 — world W
    let f2 = EntityId::from_bytes([0x72; 16])?; // rank 2 — world W
    let base2 = EntityId::from_bytes([0x62; 16])?; // rank 3 — base
    let f3 = EntityId::from_bytes([0x73; 16])?; // rank 4 — world W
    let f4 = EntityId::from_bytes([0x74; 16])?; // rank 5 — world W (dropped)
    put_world_claim(&vault, base1, [1.0, 0.0, 0.0, 0.0], None)?;
    put_world_claim(&vault, f1, [0.9, 0.1, 0.0, 0.0], Some(world_w))?;
    put_world_claim(&vault, f2, [0.8, 0.2, 0.0, 0.0], Some(world_w))?;
    put_world_claim(&vault, base2, [0.7, 0.3, 0.0, 0.0], None)?;
    put_world_claim(&vault, f3, [0.6, 0.4, 0.0, 0.0], Some(world_w))?;
    put_world_claim(&vault, f4, [0.0, 1.0, 0.0, 0.0], Some(world_w))?;

    let pack = vault
        .context_pack()
        .search_vector(&[1.0, 0.0, 0.0, 0.0], 10)
        .run()?; // default fraction = 0.5

    let ids: HashSet<EntityId> = pack.results.iter().map(|entity| entity.id).collect();
    assert!(
        ids.contains(&base1) && ids.contains(&base2),
        "both base claims must always be kept, got {ids:?}"
    );
    assert!(
        ids.contains(&f1) && ids.contains(&f2) && ids.contains(&f3),
        "the top-3 fiction claims must survive the cap, got {ids:?}"
    );
    assert!(
        !ids.contains(&f4),
        "the lowest-scoring fiction claim must be dropped by the cap"
    );
    assert_eq!(
        pack.results.len(),
        5,
        "2 base + capped 3 fiction = 5 surviving claims"
    );
    Ok(())
}

#[test]
fn pack_validation_skips_world_partition_dropped_results() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let world_w = EntityId::from_bytes([0xE1; 16])?;

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
fn pack_validation_rejects_conflicting_duplicate_ids() -> Result<()> {
    let id = EntityId::from_bytes([0x91; 16])?;
    let err = validate_scored_candidates(&[
        ScoredEntity { id, score: 1.0 },
        ScoredEntity { id, score: 0.5 },
    ])
    .expect_err("duplicate retrieval candidate id must fail before pack assembly");

    assert_context_pack_validation(err, id, PACK_VALIDATION_DUPLICATE_ID);
    Ok(())
}

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
            kind: crate::types::EdgeKind::Supports,
            target,
        },
        value,
        0.75,
        crate::claim::ClaimApprovalStatus::Auto,
        crate::claim::ClaimLifecycleStatus::Active,
    );
    let payload = crate::claim::encode_claim_body(&body)?;
    let raw = raw_entity_record(ENTITY_TYPE_CLAIM, 1, 1, 1, &payload);
    overwrite_raw_entity(&vault, &id, &raw)?;

    let err = vault
        .context_pack()
        .search_text("missingevidenceneedle", 10)
        .run()
        .expect_err("provenance claim without actor-class evidence must fail pack validation");

    assert_context_pack_validation(err, id, PACK_VALIDATION_MISSING_EVIDENCE);
    Ok(())
}

#[test]
fn pack_validation_rejects_missing_claim_entity_subject() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let id = EntityId::from_bytes([0x98; 16])?;
    let subject = EntityId::from_bytes([0x5A; 16])?;
    put_claim_text_entity_with_subject(
        &vault,
        &id,
        crate::claim::ClaimSubject::Entity(subject),
        "missingclaimsubjectneedle",
        "test.missing_subject",
        "payload",
    )?;

    let err = vault
        .context_pack()
        .search_text("missingclaimsubjectneedle", 10)
        .run()
        .expect_err("missing claim subject payload must fail pack validation");

    assert_context_pack_validation(err, subject, PACK_VALIDATION_MISSING_PAYLOAD);
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
fn pack_validation_rejects_quarantined_claim_edge_subject_endpoint() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let id = EntityId::from_bytes([0x9A; 16])?;
    let source = EntityId::from_bytes([0x5C; 16])?;
    let target = EntityId::from_bytes([0x5D; 16])?;
    let window_key = "2026-03";
    ensure_claim_subject_payload(&vault, &source)?;
    ensure_claim_subject_payload(&vault, &target)?;
    put_claim_text_entity_with_subject(
        &vault,
        &id,
        crate::claim::ClaimSubject::Edge {
            source,
            kind: crate::types::EdgeKind::Supports,
            target,
        },
        "quarantinededgeclaimsubjectneedle",
        "test.quarantined_edge_subject",
        "payload",
    )?;

    let record = pack_quarantine_record_for_entity(window_key, &target);
    let encoded = rmp_serde::to_vec_named(&record).expect("quarantine record encode");
    vault.with_write_txn(|wtxn| {
        vault
            .store
            .sync_queue
            .put(wtxn, b"x:\x00\x00\x00\x00\x00\x00\x00\x04", &encoded)?;
        vault
            .store
            .sync_state
            .put(wtxn, &pack_remat_marker_key(window_key, &target), &[1u8])?;
        Ok(())
    })?;

    let err = vault
        .context_pack()
        .search_text("quarantinededgeclaimsubjectneedle", 10)
        .run()
        .expect_err("quarantined claim edge subject endpoint must fail pack validation");

    assert_context_pack_validation(err, target, PACK_VALIDATION_QUARANTINED_PAYLOAD);
    Ok(())
}

#[test]
fn pack_validation_rejects_missing_affect_trigger_ref() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let claim = EntityId::from_bytes([0x9B; 16])?;
    let person = EntityId::from_bytes([0x5E; 16])?;
    let missing_trigger = EntityId::from_bytes([0x5F; 16])?;
    ensure_claim_subject_payload(&vault, &person)?;

    let trigger_value = crate::AffectTriggerValue::new(
        person,
        missing_trigger,
        crate::VadDelta::new(-0.1, 0.2, -0.3)?,
        0.66,
        2,
        5,
    )?;
    let body = crate::claim::ClaimBody::new(
        crate::AFFECT_TRIGGER_PREDICATE,
        crate::claim::ClaimSubject::Entity(person),
        crate::affect::affect_trigger_value(&trigger_value),
        trigger_value.confidence(),
        crate::claim::ClaimApprovalStatus::Auto,
        crate::claim::ClaimLifecycleStatus::Active,
    );
    let payload = crate::claim::encode_claim_body(&body)?;
    vault
        .batch()
        .put(
            &claim,
            ENTITY_TYPE_CLAIM,
            TimeRange { start: 1, end: 1 },
            1,
            &payload,
        )
        .text(&claim, &[("body", "missingaffecttriggerrefneedle")])
        .commit()?;

    let err = vault
        .context_pack()
        .search_text("missingaffecttriggerrefneedle", 10)
        .run()
        .expect_err("missing affect.trigger triggerRef must fail pack validation");

    assert_context_pack_validation(err, missing_trigger, PACK_VALIDATION_MISSING_PAYLOAD);
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
        .search_text("reversedtimeneedle", 10)
        .run()
        .expect_err("reversed entity envelope must fail pack validation");

    assert_context_pack_validation(err, id, PACK_VALIDATION_IMPOSSIBLE_TIME);
    Ok(())
}

#[test]
fn pack_validation_rejects_deleted_payload_reference() -> Result<()> {
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

    let err = vault
        .context_pack()
        .search_text("deletedreferenceneedle", 10)
        .run()
        .expect_err("deleted payload reference must fail pack validation");

    assert_context_pack_validation(err, id, PACK_VALIDATION_DELETED_PAYLOAD);
    Ok(())
}

#[test]
fn pack_validation_rejects_deleted_edge_target_reference() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let source = EntityId::from_bytes([0x54; 16])?;
    let target = EntityId::from_bytes([0x55; 16])?;
    put_claim_text_entity(
        &vault,
        &source,
        "deletededgetargetneedle",
        "test.edge_source",
        "payload",
    )?;
    put_text_entity(
        &vault,
        &target,
        4,
        "edge target",
        serde_json::json!({"body": "target"}),
    )?;
    vault.put_edge(&source, crate::types::EdgeKind::Supports, &target, 0.7)?;
    vault.with_write_txn(|wtxn| {
        vault.store.sync_state.put(
            wtxn,
            &crate::deletion::local_hard_delete_key(&target),
            b"present",
        )?;
        Ok(())
    })?;

    let err = vault
        .context_pack()
        .search_text("deletededgetargetneedle", 10)
        .include_edges(true)
        .run()
        .expect_err("deleted edge target reference must fail pack validation");

    assert_context_pack_validation(err, target, PACK_VALIDATION_DELETED_PAYLOAD);
    Ok(())
}

#[test]
fn pack_validation_rejects_quarantined_payload_reference() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let id = EntityId::from_bytes([0x95; 16])?;
    let window_key = "2026-03";
    put_claim_text_entity(
        &vault,
        &id,
        "quarantinedreferenceneedle",
        "test.quarantined",
        "payload",
    )?;

    let record = pack_quarantine_record_for_entity(window_key, &id);
    let encoded = rmp_serde::to_vec_named(&record).expect("quarantine record encode");
    vault.with_write_txn(|wtxn| {
        vault
            .store
            .sync_queue
            .put(wtxn, b"x:\x00\x00\x00\x00\x00\x00\x00\x01", &encoded)?;
        vault
            .store
            .sync_state
            .put(wtxn, &pack_remat_marker_key(window_key, &id), &[1u8])?;
        Ok(())
    })?;

    let err = vault
        .context_pack()
        .search_text("quarantinedreferenceneedle", 10)
        .run()
        .expect_err("quarantined payload reference must fail pack validation");

    assert_context_pack_validation(err, id, PACK_VALIDATION_QUARANTINED_PAYLOAD);
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
fn pack_validation_rejects_active_edge_source_remat_marker() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let source = EntityId::from_bytes([0x5F; 16])?;
    let target = EntityId::from_bytes([0x60; 16])?;
    let window_key = "2026-03";
    put_claim_text_entity(
        &vault,
        &source,
        "edgesourcerematmarkerneedle",
        "test.edge_marker",
        "payload",
    )?;
    put_text_entity(
        &vault,
        &target,
        4,
        "edge target",
        serde_json::json!({"body": "target"}),
    )?;
    vault.put_edge(&source, crate::types::EdgeKind::Supports, &target, 0.7)?;
    vault.with_write_txn(|wtxn| {
        vault
            .store
            .sync_state
            .put(wtxn, &pack_remat_marker_key(window_key, &source), &[1u8])?;
        Ok(())
    })?;

    let err = vault
        .context_pack()
        .search_text("edgesourcerematmarkerneedle", 10)
        .include_edges(true)
        .run()
        .expect_err("active edge-source remat marker must fail pack validation");

    assert_context_pack_validation(err, source, PACK_VALIDATION_QUARANTINED_PAYLOAD);
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
    let bad = EntityId::from_bytes_unchecked([0x42; 16]);
    put_claim_text_entity(&vault, &a, "badneighbor", "test.root", "root")?;

    // Raw 25-byte envelope (type 0) + a non-map MessagePack body.
    let mut junk_body = Vec::new();
    rmpv::encode::write_value(&mut junk_body, &rmpv::Value::from("junk")).expect("msgpack encode");
    let mut raw = Vec::with_capacity(ENTITY_METADATA_HEADER_LEN + junk_body.len());
    raw.push(0);
    raw.extend_from_slice(&1_u64.to_be_bytes());
    raw.extend_from_slice(&1_u64.to_be_bytes());
    raw.extend_from_slice(&1_u64.to_be_bytes());
    raw.extend_from_slice(&junk_body);
    vault.with_write_txn(|wtxn| {
        vault.store.entities.put(wtxn, bad.as_bytes(), &raw)?;
        Ok(())
    })?;
    vault.put_edge(&a, crate::types::EdgeKind::Supports, &bad, 0.9)?;

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

/// AC 9 — a claim body is MessagePack-decoded exactly ONCE per entity
/// for gate + projection: results reuse the pipeline gate's decode,
/// neighbors reuse the pre-assembly validation decode. Counted via the
/// claim-module decode counter, not by round-tripping output.
#[test]
fn claim_body_is_decoded_once_per_result_for_gate_and_projection() -> Result<()> {
    let (_dir, vault) = open_test_vault();

    let a = EntityId::from_bytes_unchecked([0x51; 16]);
    let b = EntityId::from_bytes_unchecked([0x52; 16]);
    put_claim_text_entity(&vault, &a, "decodeonce", "test.root", "root")?;
    put_claim_with_status(
        &vault,
        &b,
        crate::claim::ClaimApprovalStatus::Auto,
        crate::claim::ClaimLifecycleStatus::Active,
        false,
    )?;
    vault.put_edge(&a, crate::types::EdgeKind::Supports, &b, 0.9)?;

    crate::claim::reset_claim_body_decode_count();
    let pack = vault
        .context_pack()
        .search_text("decodeonce", 10)
        .edge_hop(1)
        .run()?;
    assert_eq!(
        crate::claim::claim_body_decode_count(),
        2,
        "one decode for the result claim (pipeline gate, reused by projection) \
             + one for the neighbor claim (validation, reused by projection)"
    );

    // The single decode still projects full fields on both.
    assert_eq!(pack.results.len(), 1);
    let result_fields = pack.results[0].fields.as_ref().expect("result fields");
    assert_eq!(
        result_fields.get("pred").and_then(|v| v.as_str()),
        Some("test.root")
    );
    assert_eq!(
        result_fields.get("appr").and_then(|v| v.as_str()),
        Some("auto")
    );
    assert_eq!(
        result_fields.get("life").and_then(|v| v.as_str()),
        Some("active")
    );
    assert!(
        result_fields.contains_key("subj"),
        "subj key projects (as null) like the generic decoder"
    );

    let neighbor = pack
        .neighbors
        .iter()
        .find(|e| e.id == b)
        .expect("active claim neighbor hydrates");
    let neighbor_fields = neighbor.fields.as_ref().expect("neighbor fields");
    assert_eq!(
        neighbor_fields.get("pred").and_then(|v| v.as_str()),
        Some("test.status")
    );
    Ok(())
}

/// AC 10 — walk_edges kind/provenance gating: `child_of` and
/// `assigned_to` (structural, not retrieval-scored) contribute no
/// neighbor even at weight 1.0; retracted-provenanced edges are skipped
/// (D8-consistent); `opposes` and non-retracted provenanced edges ARE
/// followed.
#[test]
fn walk_edges_gates_structural_kinds_and_retracted_provenance() -> Result<()> {
    let (_dir, vault) = open_test_vault();

    let root = EntityId::from_bytes_unchecked([0x61; 16]);
    put_claim_text_entity(&vault, &root, "walkroot", "test.root", "root")?;

    let child_of_tgt = EntityId::from_bytes_unchecked([0x62; 16]);
    let assigned_tgt = EntityId::from_bytes_unchecked([0x63; 16]);
    let opposes_tgt = EntityId::from_bytes_unchecked([0x64; 16]);
    let retracted_tgt = EntityId::from_bytes_unchecked([0x65; 16]);
    let confirmed_tgt = EntityId::from_bytes_unchecked([0x66; 16]);
    for (i, id) in [
        child_of_tgt,
        assigned_tgt,
        opposes_tgt,
        retracted_tgt,
        confirmed_tgt,
    ]
    .iter()
    .enumerate()
    {
        put_text_entity(
            &vault,
            id,
            4,
            "target",
            serde_json::json!({"name": format!("T{i}")}),
        )?;
    }

    // Structural plumbing at FULL weight — must contribute no neighbor.
    vault.put_edge(&root, crate::types::EdgeKind::ChildOf, &child_of_tgt, 1.0)?;
    vault.put_edge(
        &root,
        crate::types::EdgeKind::AssignedTo,
        &assigned_tgt,
        1.0,
    )?;
    // Contradiction IS context — opposes is followed (unlike PPR λ=0).
    vault.put_edge(&root, crate::types::EdgeKind::Opposes, &opposes_tgt, 0.5)?;

    // Two provenanced (26 B) edges planted raw: confirmation_status
    // byte 24 = retracted (3) must be skipped, confirmed (1) followed.
    let plant = |tgt: &EntityId, status: crate::types::EdgeConfirmationStatus| -> Result<()> {
        let key = Store::encode_edge_key(&root, crate::types::EdgeKind::Supports, tgt);
        let value = crate::types::encode_edge_value(
            crate::types::EdgeKind::Supports,
            0.9,
            1,
            crate::types::Vad::NEUTRAL,
            Some(crate::types::EdgeProvenanceFlags {
                confirmation_status: status,
                actor_class: crate::types::EdgeActorClass::Human,
            }),
        )?;
        vault.with_write_txn(|wtxn| {
            vault.store.edges_out.put(wtxn, &key, &value)?;
            Ok(())
        })
    };
    plant(
        &retracted_tgt,
        crate::types::EdgeConfirmationStatus::Retracted,
    )?;
    plant(
        &confirmed_tgt,
        crate::types::EdgeConfirmationStatus::Confirmed,
    )?;

    let pack = vault
        .context_pack()
        .search_text("walkroot", 10)
        .edge_hop(1)
        .max_neighbors(10)
        .run()?;

    let neighbor_ids: HashSet<EntityId> = pack.neighbors.iter().map(|e| e.id).collect();
    assert!(
        !neighbor_ids.contains(&child_of_tgt),
        "child_of (weight 1.0) must contribute no neighbor"
    );
    assert!(
        !neighbor_ids.contains(&assigned_tgt),
        "assigned_to must contribute no neighbor"
    );
    assert!(
        !neighbor_ids.contains(&retracted_tgt),
        "retracted-provenanced edge must be skipped"
    );
    assert!(
        neighbor_ids.contains(&opposes_tgt),
        "opposes must still be followed"
    );
    assert!(
        neighbor_ids.contains(&confirmed_tgt),
        "confirmed-provenanced edge must still be followed"
    );
    Ok(())
}

/// Pipeline-suppressed claims are reported through
/// `PackStats::claims_suppressed` (exclusion is silent — the count is
/// the only signal).
#[test]
fn pack_stats_count_pipeline_suppressed_claims() -> Result<()> {
    let (_dir, vault) = open_test_vault();

    let live = EntityId::from_bytes_unchecked([0x71; 16]);
    let dead = EntityId::from_bytes_unchecked([0x72; 16]);
    put_claim_text_entity(&vault, &live, "statneedle", "test.live", "v")?;
    put_claim_text_entity_with_lifecycle(
        &vault,
        &dead,
        "statneedle",
        "test.dead",
        "v",
        crate::claim::ClaimLifecycleStatus::Retracted,
    )?;

    let pack = vault.context_pack().search_text("statneedle", 10).run()?;
    assert_eq!(pack.results.len(), 1);
    assert_eq!(pack.results[0].id, live);
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
    vault.put_edge(&live, crate::types::EdgeKind::Supports, &dead_neighbor, 0.9)?;

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
fn context_pack_trace_finalization_updates_final_stage() -> Result<()> {
    let (_dir, vault) = open_test_vault();

    let kept = EntityId::from_bytes_unchecked([0x75; 16]);
    let dropped = EntityId::from_bytes_unchecked([0x76; 16]);
    put_claim_text_entity(&vault, &kept, "tracebudget", "test.kept", "kept")?;
    put_claim_text_entity(&vault, &dropped, "tracebudget", "test.dropped", "dropped")?;

    let pack_with_telemetry = vault
        .context_pack()
        .search_text("tracebudget", 10)
        .limit(2)
        .retrieval_budget(ContextPackRetrievalBudget::new(1, 0, 0, 0, 0, 0))
        .capture_retrieval_trace(true)
        .run_with_telemetry()?;
    let run_id = pack_with_telemetry
        .run_id
        .expect("context-pack trace telemetry run id");
    assert_eq!(pack_with_telemetry.value.results.len(), 1);
    assert_eq!(pack_with_telemetry.value.results[0].id, kept);

    let run = vault
        .retrieval_run(run_id)?
        .expect("context-pack trace telemetry record");
    let trace = run.trace.expect("context-pack trace");
    assert_eq!(
        trace.reranked.stage,
        crate::store::RetrievalTraceStage::Reranked
    );
    assert_eq!(
        trace.final_stage.stage,
        crate::store::RetrievalTraceStage::Final
    );
    assert_eq!(trace.final_stage.candidates.len(), 1);
    assert_eq!(trace.final_stage.candidates[0].result_id, *kept.as_bytes());
    assert!(!run.result_ids.contains(dropped.as_bytes()));
    Ok(())
}

#[test]
fn context_pack_stats_include_parsed_temporal_hint_signal() -> Result<()> {
    let (_dir, vault) = open_test_vault();

    let pack = vault
        .context_pack()
        .search_text("recent stattemporal", 10)
        .run()?;

    assert!(pack.stats.signals_used.contains(&Signal::Text));
    assert!(pack.stats.signals_used.contains(&Signal::Temporal));
    Ok(())
}

#[test]
fn context_pack_provisional_telemetry_hidden_until_finalization() -> Result<()> {
    let (_dir, vault) = open_test_vault();

    let id = EntityId::from_bytes_unchecked([0x7E; 16]);
    put_text_entity(
        &vault,
        &id,
        crate::types::ENTITY_TYPE_PERSON,
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
    let outcome_error = run
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
        run.store,
        run.telemetry_run_id,
        run.pack.stats.query_time_us,
        run.pack.stats.claims_suppressed,
        &surfaced_result_ids,
        context_pack_empty_reason(&run.pack, &surfaced_result_ids),
    );
    assert_eq!(finalized_run_id, Some(run_id));

    let runs = vault.retrieval_runs(1)?;
    assert_eq!(runs.len(), 1);
    assert_eq!(runs[0].run_id, run_id);
    assert_eq!(runs[0].result_ids, vec![*id.as_bytes()]);
    run.store
        .record_retrieval_outcome(crate::store::RetrievalOutcome {
            run_id,
            key: "click".to_owned(),
            reward: Some(1.0),
            accepted: Some(true),
            metadata: BTreeMap::new(),
        })?;
    assert_eq!(run.store.retrieval_outcomes(run_id)?.len(), 1);
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
            crate::types::ENTITY_TYPE_PERSON,
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
fn context_pack_telemetry_discard_removes_provisional_outcomes() -> Result<()> {
    let (_dir, vault) = open_test_vault();

    let id = EntityId::from_bytes_unchecked([0x7C; 16]);
    put_text_entity(
        &vault,
        &id,
        crate::types::ENTITY_TYPE_PERSON,
        "telemetry provisional outcome",
        serde_json::json!({"name": "Provisional"}),
    )?;

    let run = vault
        .context_pack()
        .search_text("telemetry provisional outcome", 10)
        .run_unfinalized()?;
    let run_id = run
        .telemetry_run_id
        .expect("unfinalized context-pack telemetry run id");
    let outcome_error = run
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
    assert!(run.store.retrieval_outcomes(run_id)?.is_empty());

    discard_failed_context_pack_telemetry(run.store, run.telemetry_run_id);

    assert!(
        !run.store
            .retrieval_runs(10)?
            .iter()
            .any(|record| record.run_id == run_id),
        "discarded context-pack telemetry run should not remain readable"
    );
    assert!(
        run.store.retrieval_outcomes(run_id)?.is_empty(),
        "discarded context-pack telemetry run should not leave readable outcomes"
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
        crate::types::ENTITY_TYPE_PERSON,
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
    let outcome_error = run
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
        run.store,
        run.telemetry_run_id,
        run.pack.stats.query_time_us,
        run.pack.stats.claims_suppressed,
        &surfaced_result_ids,
        context_pack_empty_reason(&run.pack, &surfaced_result_ids),
    );

    assert_eq!(returned_run_id, None);
    assert!(
        !run.store
            .retrieval_runs(10)?
            .iter()
            .any(|record| record.run_id == run_id),
        "failed finalization should discard the provisional telemetry row"
    );
    assert!(
        run.store.retrieval_outcomes(run_id)?.is_empty(),
        "failed finalization should discard provisional outcomes"
    );
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
                crate::types::ENTITY_TYPE_TURN,
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
        .token_budget(24)
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
                crate::types::ENTITY_TYPE_TURN,
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
        crate::types::ENTITY_TYPE_PERSON,
        "serialized neighbor",
        serde_json::json!({"name": "Neighbor"}),
    )?;
    vault.put_edge(&result, crate::types::EdgeKind::Supports, &neighbor, 1.0)?;

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

#[test]
fn context_pack_serialized_stats_populate_token_accounting() -> Result<()> {
    let (_dir, vault) = open_test_vault();

    let first = EntityId::from_bytes_unchecked([0x7C; 16]);
    let second = EntityId::from_bytes_unchecked([0x7D; 16]);
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
                crate::types::ENTITY_TYPE_TURN,
                TimeRange { start: 1, end: 1 },
                1,
                &payload,
            )
            .vector(&id, &vector)
            .commit()
    };
    put_turn(first, [1.0, 0.0, 0.0, 0.0], "token stats first")?;
    put_turn(second, [0.0, 1.0, 0.0, 0.0], "token stats second")?;

    let serialized = vault
        .context_pack()
        .search_vector(&[1.0, 0.0, 0.0, 0.0], 10)
        .format(PackFormat::Plaintext)
        .token_budget(512)
        .run_serialized_with_stats()?;
    let text = std::str::from_utf8(&serialized.value.bytes).expect("plaintext context pack");

    assert_eq!(
        serialized.value.stats.tokens.tokenizer_id,
        crate::tokenizer::DEFAULT_CONTEXT_PACK_TOKENIZER_ID
    );
    assert_eq!(
        serialized.value.stats.tokens.total_tokens,
        crate::tokenizer::count_context_pack_tokens(text)
    );
    assert!(serialized.value.stats.tokens.total_tokens <= 512);
    assert!(!serialized.value.stats.tokens.sections.is_empty());
    assert!(!serialized.value.stats.tokens.items.is_empty());
    assert!(serialized.run_id.is_some());
    Ok(())
}
