use std::collections::HashMap;

use rmpv::Value;

use super::*;
use crate::claim::{ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject};
use crate::config::VaultConfig;
use crate::context_pack::ContextEntity;
use crate::context_pack::{
    psych_mirror_source_candidate_from_claim, psych_mirror_source_candidate_from_context_entity,
};
use crate::registry::ENTITY_TYPE_PERSON;
use crate::{ErrorKind, Vault};

use crate::test_util::entity;

fn test_profile() -> PsychProfile {
    PsychProfile::new(
        entity(0x51),
        "fast compact profile",
        "retrieval-friendly profile text",
        "A warm narrative profile.",
        vec![entity(0xC3), entity(0xC1), entity(0xC3), entity(0xC2)],
        PsychProfileConfidence::new(0.8, 0.7, 0.6).expect("valid confidence"),
    )
    .expect("valid profile")
}

fn test_vault() -> (tempfile::TempDir, Vault) {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Vault::open(dir.path(), VaultConfig::default()).expect("open vault");
    (dir, vault)
}

fn msgpack_map(entries: Vec<(&'static str, Value)>) -> Vec<u8> {
    let mut out = Vec::new();
    rmpv::encode::write_value(
        &mut out,
        &Value::Map(
            entries
                .into_iter()
                .map(|(key, value)| (Value::from(key), value))
                .collect(),
        ),
    )
    .expect("encode msgpack");
    out
}

fn fixture_claim(text: &'static str, salience: f32) -> ClaimBody {
    let mut body = ClaimBody::new(
        "profile.preference",
        ClaimSubject::Entity(entity(0x51)),
        Value::from(text),
        0.8,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    );
    body.salience = Some(salience);
    body
}

#[test]
fn psych_mirror_selection_ranks_fixture_memories_deterministically() -> Result<()> {
    let now = 20_000_000_u64;
    let candidates = vec![
        psych_mirror_source_candidate_from_claim(
            entity(0x60),
            entity(0xB1),
            0.98,
            now - 90 * 86_400,
            &fixture_claim("long-term preference for direct concise answers", 0.10),
        )?,
        psych_mirror_source_candidate_from_claim(
            entity(0x12),
            entity(0xB2),
            0.72,
            now - 2 * 86_400,
            &fixture_claim("high salience self story about anxious onboarding", 0.95),
        )?,
        psych_mirror_source_candidate_from_claim(
            entity(0x13),
            entity(0xB3),
            0.50,
            now,
            &fixture_claim("fresh mixed topic with several distinct cues", 0.55),
        )?,
        psych_mirror_source_candidate_from_claim(
            entity(0x14),
            entity(0xB4),
            0.40,
            now - 30 * 86_400,
            &fixture_claim("abcdefghi jklmnop qrstuv wxyz", 0.20),
        )?,
    ];

    let ranked = rank_psych_mirror_sources(&candidates, now, candidates.len())?;

    assert_eq!(
        ranked
            .iter()
            .map(|source| source.source_revision_ref)
            .collect::<Vec<_>>(),
        vec![entity(0xB2), entity(0xB3), entity(0xB1), entity(0xB4)]
    );
    assert_eq!(
        ranked.iter().map(|source| source.rank).collect::<Vec<_>>(),
        vec![1, 2, 3, 4]
    );
    assert!(ranked[0].score.affect_salience > ranked[0].score.connectivity * 0.5);
    assert!(ranked[1].score.recency > ranked[2].score.recency);
    assert!(ranked[3].score.entropy > 0.0);
    Ok(())
}

#[test]
fn psych_mirror_selection_context_entity_adapter_reads_projected_fields() -> Result<()> {
    let mut fields = HashMap::new();
    fields.insert("sal".to_owned(), serde_json::json!(0.7));
    fields.insert("txt".to_owned(), serde_json::json!("distinct context text"));
    let context_entity = ContextEntity {
        id: entity(0x21),
        short_id: "ctx".to_owned(),
        content_hash: 7,
        entity_type: ENTITY_TYPE_PERSON,
        score: 2.0,
        fields: Some(fields),
        edges: None,
        vector: None,
    };

    let candidate =
        psych_mirror_source_candidate_from_context_entity(&context_entity, entity(0xC1), 42)?;

    assert_eq!(candidate.source_revision_ref, entity(0xC1));
    assert_eq!(candidate.connectivity, 1.0);
    assert!((candidate.affect_salience - 0.7).abs() < 1e-6);
    assert!(candidate.entropy > 0.0);

    let mut invalid_salience_fields = HashMap::new();
    invalid_salience_fields.insert("sal".to_owned(), serde_json::json!(1.7));
    invalid_salience_fields.insert("txt".to_owned(), serde_json::json!("distinct context text"));
    let invalid_salience_entity = ContextEntity {
        id: entity(0x22),
        short_id: "ctx2".to_owned(),
        content_hash: 8,
        entity_type: ENTITY_TYPE_PERSON,
        score: 0.5,
        fields: Some(invalid_salience_fields),
        edges: None,
        vector: None,
    };
    let invalid_salience_candidate = psych_mirror_source_candidate_from_context_entity(
        &invalid_salience_entity,
        entity(0xC2),
        42,
    )?;

    assert_eq!(invalid_salience_candidate.affect_salience, 0.0);
    Ok(())
}

#[test]
fn psych_mirror_selection_structured_claim_value_contributes_entropy() -> Result<()> {
    let body = ClaimBody::new(
        "profile.preference",
        ClaimSubject::Entity(entity(0x51)),
        Value::Map(vec![
            (
                Value::from("summary"),
                Value::from("prefers direct repair notes"),
            ),
            (
                Value::from("details"),
                Value::Array(vec![
                    Value::from("tracks source changes carefully"),
                    Value::from(3),
                    Value::Map(vec![(
                        Value::from("nested"),
                        Value::from("asks for concise review replies"),
                    )]),
                ]),
            ),
        ]),
        0.8,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    );

    let candidate =
        psych_mirror_source_candidate_from_claim(entity(0x23), entity(0xC3), 0.5, 42, &body)?;

    assert!(candidate.entropy > 0.0);
    Ok(())
}

#[test]
fn psych_mirror_selection_emits_drift_anchor_events_with_revision_refs() {
    let events = psych_mirror_drift_anchor_events(
        &[entity(0xC3), entity(0xC1), entity(0xC2), entity(0xC2)],
        &[entity(0xC4), entity(0xC1), entity(0xC3), entity(0xC4)],
    );

    assert_eq!(
        events,
        vec![
            PsychMirrorDriftAnchorEvent {
                state: PsychMirrorDriftAnchorState::Keep,
                source_revision_ref: entity(0xC1),
            },
            PsychMirrorDriftAnchorEvent {
                state: PsychMirrorDriftAnchorState::Revert,
                source_revision_ref: entity(0xC2),
            },
            PsychMirrorDriftAnchorEvent {
                state: PsychMirrorDriftAnchorState::Keep,
                source_revision_ref: entity(0xC3),
            },
            PsychMirrorDriftAnchorEvent {
                state: PsychMirrorDriftAnchorState::Tune,
                source_revision_ref: entity(0xC4),
            },
            PsychMirrorDriftAnchorEvent {
                state: PsychMirrorDriftAnchorState::Tune,
                source_revision_ref: entity(0xC4),
            },
        ]
    );
    assert_eq!(events[0].state.as_str(), "keep");
    assert_eq!(events[1].state.as_str(), "revert");
    assert_eq!(events[3].state.as_str(), "tune");
}

#[test]
fn psych_profile_roundtrip_canonicalizes_source_revisions() -> Result<()> {
    let profile = test_profile();
    assert_eq!(
        profile.source_revision_ids,
        vec![entity(0xC1), entity(0xC2), entity(0xC3)]
    );

    let encoded = encode_psych_profile_body(&profile)?;
    let decoded = decode_psych_profile_body(&encoded)?;

    assert_eq!(decoded, profile);
    Ok(())
}

#[test]
fn psych_profile_rejects_invalid_confidence_and_missing_sources() {
    assert_eq!(
        PsychProfileConfidence::new(1.1, 0.5, 0.5)
            .expect_err("confidence outside unit interval")
            .kind(),
        ErrorKind::InvalidPsychProfileBody
    );
    assert_eq!(
        PsychProfile::new(
            entity(0x51),
            "compact",
            "text",
            "narrative",
            vec![],
            PsychProfileConfidence::new(0.5, 0.5, 0.5).expect("valid confidence"),
        )
        .expect_err("missing source revisions")
        .kind(),
        ErrorKind::InvalidPsychProfileBody
    );
}

#[test]
fn psych_profile_decoder_rejects_unknown_keys() {
    let profile = test_profile();
    let mut entries = vec![
        (
            KEY_SCHEMA_VERSION,
            Value::from(PSYCH_PROFILE_SCHEMA_VERSION),
        ),
        (KEY_SUBJECT_REF, Value::from(profile.subject_ref.to_hex())),
        (KEY_COMPACT, Value::from(profile.compact.as_str())),
        (KEY_TEXT, Value::from(profile.text.as_str())),
        (KEY_NARRATIVE, Value::from(profile.narrative.as_str())),
        (
            KEY_SOURCE_REVISION_IDS,
            encode_source_revision_ids(&profile.source_revision_ids),
        ),
        (KEY_CONFIDENCE, encode_confidence(profile.confidence)),
        (KEY_STATUS, Value::from(profile.status.as_code())),
    ];
    entries.push(("unexpected", Value::from(true)));

    let err = decode_psych_profile_body(&msgpack_map(entries))
        .expect_err("unknown psych profile keys fail closed");
    assert_eq!(err.kind(), ErrorKind::InvalidPsychProfileBody);
}

#[test]
fn psych_profile_decoder_rejects_noncanonical_source_revisions() {
    let profile = test_profile();
    let entries = vec![
        (
            KEY_SCHEMA_VERSION,
            Value::from(PSYCH_PROFILE_SCHEMA_VERSION),
        ),
        (KEY_SUBJECT_REF, Value::from(profile.subject_ref.to_hex())),
        (KEY_COMPACT, Value::from(profile.compact.as_str())),
        (KEY_TEXT, Value::from(profile.text.as_str())),
        (KEY_NARRATIVE, Value::from(profile.narrative.as_str())),
        (
            KEY_SOURCE_REVISION_IDS,
            Value::Array(vec![
                Value::from(entity(0xC2).to_hex()),
                Value::from(entity(0xC1).to_hex()),
            ]),
        ),
        (KEY_CONFIDENCE, encode_confidence(profile.confidence)),
        (KEY_STATUS, Value::from(profile.status.as_code())),
    ];

    let err = decode_psych_profile_body(&msgpack_map(entries))
        .expect_err("stored source revisions must be canonical");
    assert_eq!(err.kind(), ErrorKind::InvalidPsychProfileBody);
}

#[test]
fn psych_profile_status_persists_as_typed_code_and_rejects_strings() -> Result<()> {
    let profile = test_profile();
    let encoded = encode_psych_profile_body(&profile)?;
    let Value::Map(entries) = rmpv::decode::read_value(&mut Cursor::new(&encoded))
        .expect("encoded profile is MessagePack")
    else {
        panic!("encoded profile must be a MessagePack map");
    };
    assert_eq!(
        required_value(&entries, KEY_STATUS)?.as_u64(),
        Some(profile.status.as_code())
    );

    let string_status_body = msgpack_map(vec![
        (
            KEY_SCHEMA_VERSION,
            Value::from(PSYCH_PROFILE_SCHEMA_VERSION),
        ),
        (KEY_SUBJECT_REF, Value::from(profile.subject_ref.to_hex())),
        (KEY_COMPACT, Value::from(profile.compact.as_str())),
        (KEY_TEXT, Value::from(profile.text.as_str())),
        (KEY_NARRATIVE, Value::from(profile.narrative.as_str())),
        (
            KEY_SOURCE_REVISION_IDS,
            encode_source_revision_ids(&profile.source_revision_ids),
        ),
        (KEY_CONFIDENCE, encode_confidence(profile.confidence)),
        (KEY_STATUS, Value::from("fresh")),
    ]);

    let err = decode_psych_profile_body(&string_status_body)
        .expect_err("string status must fail closed under v6 schema");
    assert_eq!(err.kind(), ErrorKind::InvalidPsychProfileBody);
    Ok(())
}

#[test]
fn psych_profile_vault_helpers_persist_and_type_lookup_state() -> Result<()> {
    let (_dir, vault) = test_vault();
    let id = entity(0xD1);
    let profile = test_profile();

    assert_eq!(
        vault.psych_profile_state(&id, None)?,
        PsychProfileState::Missing
    );
    vault.put_psych_profile(&id, &profile)?;

    assert_eq!(vault.get_entity_type(&id)?, Some(ENTITY_TYPE_PSYCH_PROFILE));
    assert_eq!(vault.get_psych_profile(&id)?, Some(profile.clone()));
    assert_eq!(
        vault.psych_profile_state(&id, Some(&profile.source_revision_ids))?,
        PsychProfileState::Fresh(profile.clone())
    );

    let stale = vault.psych_profile_state(&id, Some(&[entity(0xC1)]))?;
    assert!(matches!(
        stale,
        PsychProfileState::Stale {
            reason: PsychProfileStaleReason::SourceRevisionMismatch { .. },
            ..
        }
    ));

    let empty_expected = vault.psych_profile_state(&id, Some(&[]))?;
    match empty_expected {
        PsychProfileState::Stale {
            reason: PsychProfileStaleReason::SourceRevisionMismatch { expected, actual },
            ..
        } => {
            assert!(expected.is_empty());
            assert_eq!(actual, profile.source_revision_ids);
        }
        other => {
            panic!("empty expected source set should produce typed stale state: {other:?}")
        }
    }
    Ok(())
}

#[test]
fn psych_profile_public_put_rejects_maintenance_type() -> Result<()> {
    let (_dir, vault) = test_vault();
    let id = entity(0xD1);
    let profile = test_profile();
    let data = encode_psych_profile_body(&profile)?;
    let err = vault
        .put_entity(
            &id,
            ENTITY_TYPE_PSYCH_PROFILE,
            TimeRange { start: 1, end: 1 },
            2,
            &data,
        )
        .expect_err("public generic puts cannot write PsychProfile records");
    assert_eq!(err.kind(), ErrorKind::MaintenanceKindNotWritable);
    assert!(vault.get_raw(&id)?.is_none());
    Ok(())
}

#[test]
fn psych_profile_read_rejects_wrong_entity_type() -> Result<()> {
    let (_dir, vault) = test_vault();
    let id = entity(0xD1);
    vault.put_entity(
        &id,
        ENTITY_TYPE_PERSON,
        TimeRange { start: 1, end: 1 },
        2,
        b"person",
    )?;
    assert_eq!(
        vault
            .get_psych_profile(&id)
            .expect_err("wrong entity type")
            .kind(),
        ErrorKind::InvalidEntityType
    );
    Ok(())
}
