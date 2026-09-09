//! VAD edge values and turn/message VAD annotation claims incl. delete interplay.

use super::*;

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
    let header_fixture: [u8; 25] = [
        0x01, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16,
        0x17, 0x18, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
    ];

    vault.put_entity(&id, entity_type, occurred, learned_at, &body)?;

    let rtxn = vault.store.env.read_txn()?;
    let raw = vault
        .store
        .entities
        .get(&rtxn, id.as_bytes())?
        .ok_or(Error::EntityNotFound)?;

    assert_eq!(ENTITY_METADATA_HEADER_LEN, 25);
    assert_eq!(ENTITY_TYPE_OFFSET, 0);
    assert_eq!(ENTITY_OCCURRED_START_OFFSET, 1);
    assert_eq!(ENTITY_OCCURRED_END_OFFSET, 9);
    assert_eq!(ENTITY_LEARNED_AT_OFFSET, 17);
    assert_eq!(ENTITY_BODY_OFFSET, 25);
    assert_eq!(raw.len(), 25 + body.len());
    assert_eq!(&raw[..25], header_fixture.as_slice());
    assert_eq!(raw[0], entity_type);
    assert_eq!(&raw[1..9], occurred.start.to_be_bytes().as_slice());
    assert_eq!(&raw[9..17], occurred.end.to_be_bytes().as_slice());
    assert_eq!(&raw[17..25], learned_at.to_be_bytes().as_slice());
    assert_eq!(&raw[25..], body.as_slice());

    let header = EntityMetadataHeader::parse(&raw).expect("parse entity header");
    assert_eq!(header.entity_type, entity_type);
    assert_eq!(header.occurred_start, occurred.start);
    assert_eq!(header.occurred_end, occurred.end);
    assert_eq!(header.learned_at, learned_at);

    let decoded: serde_json::Value =
        rmp_serde::from_slice(&raw[25..]).expect("decode MessagePack body");
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
    assert_eq!(vault.get_learned_at(&turn)?, 100);
    let results = vault.search_text("turnlevel_affect_unique", 10)?;
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].id, turn);

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
    let results = vault.search_text("turnlevel_affect_unique", 10)?;
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].id, turn);

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
    let results = vault.search_text("turnlevel_affect_unique", 10)?;
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].id, turn);
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
    seed_message_fixture(&vault, &message, "message-level affect", 110)?;
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

#[test]
fn fresh_default_policy_allows_internal_vad_annotations() -> Result<()> {
    let tmp = tempfile::tempdir()?;
    let vault = Vault::open(tmp.path(), test_config())?;
    let turn = EntityId::now();
    let message = EntityId::now();

    vault.put_entity(
        &turn,
        ENTITY_TYPE_TURN,
        test_time_range(120, 120),
        120,
        b"turn",
    )?;
    seed_message_fixture(&vault, &message, "message", 121)?;

    let turn_annotation = VadAnnotation::new(
        Vad {
            valence: 0.2,
            arousal: 0.4,
            dominance: 0.6,
        },
        VadAnnotationSource::ModelInference,
        220,
    )?;
    assert_eq!(
        vault.annotate_turn_vad(&turn, turn_annotation)?,
        turn_annotation
    );

    let message_annotation = VadAnnotation::new(
        Vad {
            valence: -0.2,
            arousal: 0.3,
            dominance: 0.5,
        },
        VadAnnotationSource::UserSelfReport,
        221,
    )?;
    assert_eq!(
        vault.annotate_message_vad(&message, message_annotation)?,
        message_annotation
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
    seed_message_fixture(&vault, &message, "message soft delete affect", 131)?;
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
    assert_eq!(delete_vault.get_turn_vad_annotation(&turn)?, None);
    let turn_delete =
        delete_vault.delete_entity_with_reason(&turn, DeleteReason::UserHardDelete)?;
    assert!(turn_delete.existed);
    assert_eq!(delete_vault.get_turn_vad_annotation(&turn)?, None);

    let (_annotate_dir, annotate_vault) = open_test_vault();
    let message = EntityId::now();
    seed_message_fixture(&annotate_vault, &message, "message claim shell", 134)?;
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
    seed_message_fixture(&claim_vault, &message, "message claim residue", 132)?;
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
