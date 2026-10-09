use super::*;
use crate::config::VaultConfig;
use crate::edge::EdgeActorClass;
use crate::error::Error;
use crate::registry::ENTITY_TYPE_PERSON;

/// A minimal valid artifact, so a test can mutate exactly the field it probes.
fn meeting_transcript_json(overrides: &[(&str, &str)]) -> String {
    let mut document = format!(
        r#"{{
          "schema": "{MEETING_TRANSCRIPT_SCHEMA_V1}",
          "recording": {{
            "recording_id": "sha256:rec",
            "source_name": "m.mp4",
            "source_sha256": "aa",
            "canonical_pcm_sha256": "bb",
            "capture_started_at": 1000,
            "duration_ms": 60000,
            "language_hint": null
          }},
          "producer": {{
            "asr_model": "m",
            "aligner_model": "a",
            "vad_model": "v",
            "glossary_sha256": "cc"
          }},
          "packs": [],
          "words": [{{"word_id": "word-000001", "pack_id": "pack-0001",
            "start_ms": 0, "end_ms": 500, "text": "hi", "confidence": null,
            "speaker_cluster": null, "speaker_ref": null}}],
          "turns": [{{"turn_id": "turn-0001", "start_ms": 2000, "end_ms": 5000,
            "text": "Hello there.", "source_word_ids": ["word-000001"],
            "speaker_cluster": "spk-1", "speaker_ref": null}}],
          "cleanup": {{"status": "skipped"}},
          "note_fallback": {{"title": "Meeting transcript", "body": "Hello there."}},
          "diarization": null,
          "identity": null
        }}"#
    );
    for (from, to) in overrides {
        assert!(document.contains(from), "override target not found: {from}");
        document = document.replace(from, to);
    }
    document
}

use crate::error::GateError;
use crate::test_util::{entity as test_id, put_policy_manifest_bytes};

fn test_time(ts: u64) -> TimeRange {
    TimeRange { start: ts, end: ts }
}

fn temp_vault() -> (tempfile::TempDir, crate::Vault) {
    let tmp = tempfile::tempdir().expect("temp dir");
    let vault = crate::Vault::open(tmp.path(), VaultConfig::default()).expect("open vault");
    (tmp, vault)
}

fn normalized_imported_claim() -> NormalizedIngestClaim {
    NormalizedIngestClaim {
        source_record_id: "turn-001".to_owned(),
        predicate: "profile.name".to_owned(),
        value: Value::String("Ada".to_owned()),
    }
}

fn proposed_admission(
    claim_id: EntityId,
    subject: EntityId,
    actor: EntityId,
) -> ImportedEvidenceAdmission {
    ImportedEvidenceAdmission::proposed(
        JSONL_TRANSCRIPT_SOURCE_ID,
        claim_id,
        ImportedEvidenceEntityResolution::subject(subject),
        WriteActor::new(actor, EdgeActorClass::Human),
        test_time(10),
        10,
    )
}

fn put_actor_and_subject(vault: &crate::Vault, actor: &EntityId, subject: &EntityId) {
    vault
        .put_entity(actor, ENTITY_TYPE_PERSON, test_time(1), 1, b"import actor")
        .expect("put actor");
    vault
        .put_entity(
            subject,
            ENTITY_TYPE_PERSON,
            test_time(1),
            1,
            b"resolved subject",
        )
        .expect("put subject");
}

fn evidence_field<'a>(value: &'a MsgpackValue, field: &str) -> Option<&'a MsgpackValue> {
    let MsgpackValue::Map(entries) = value else {
        return None;
    };
    entries
        .iter()
        .find_map(|(key, value)| (key.as_str() == Some(field)).then_some(value))
}

#[test]
fn imported_evidence_admission_defaults_to_proposed_claim() -> crate::Result<()> {
    let (_tmp, vault) = temp_vault();
    let actor = test_id(0x60);
    let subject = test_id(0x12);
    let claim_id = test_id(0x13);
    put_actor_and_subject(&vault, &actor, &subject);

    admit_imported_evidence_claim(
        &vault,
        &normalized_imported_claim(),
        proposed_admission(claim_id, subject, actor),
    )?;

    let body = vault
        .get_claim(&claim_id)?
        .expect("imported evidence claim stored for review");
    assert_eq!(body.approval, ClaimApprovalStatus::Proposed);
    assert_eq!(body.source, Some(ClaimSource::Imported));
    assert_eq!(body.subject, ClaimSubject::Entity(subject));
    assert_eq!(body.value, MsgpackValue::from("Ada"));
    let evidence = body.evidence.expect("write envelope evidence");
    let candidate_evidence = evidence_field(
        &evidence,
        crate::write_envelope::WRITE_ENVELOPE_EVIDENCE_CANDIDATE_KEY,
    )
    .expect("candidate evidence");
    assert_eq!(
        evidence_field(candidate_evidence, "source_record_id").and_then(MsgpackValue::as_str),
        Some("turn-001")
    );
    Ok(())
}

#[test]
fn imported_evidence_rejects_blank_source_id_before_persistence() -> crate::Result<()> {
    let (_tmp, vault) = temp_vault();
    let actor = test_id(0x51);
    let subject = test_id(0x52);
    let claim_id = test_id(0x53);
    put_actor_and_subject(&vault, &actor, &subject);
    let mut admission = proposed_admission(claim_id, subject, actor);
    admission.source_id = " \t\n".to_owned();

    let err = admit_imported_evidence_claim(&vault, &normalized_imported_claim(), admission)
        .expect_err("blank source_id must fail before persistence");

    assert!(
        matches!(err, Error::InvalidClaimBody(_)),
        "expected InvalidClaimBody for blank source_id, got {err:?}"
    );
    assert!(vault.get_raw(&claim_id)?.is_none());
    Ok(())
}

#[test]
fn imported_evidence_rejects_blank_source_record_id_before_persistence() -> crate::Result<()> {
    let (_tmp, vault) = temp_vault();
    let actor = test_id(0x61);
    let subject = test_id(0x62);
    let claim_id = test_id(0x63);
    put_actor_and_subject(&vault, &actor, &subject);
    let mut claim = normalized_imported_claim();
    claim.source_record_id = " \t\n".to_owned();

    let err =
        admit_imported_evidence_claim(&vault, &claim, proposed_admission(claim_id, subject, actor))
            .expect_err("blank source_record_id must fail before persistence");

    assert!(
        matches!(err, Error::InvalidClaimBody(_)),
        "expected InvalidClaimBody for blank source_record_id, got {err:?}"
    );
    assert!(vault.get_raw(&claim_id)?.is_none());
    Ok(())
}

#[test]
fn imported_evidence_auto_denial_leaves_no_candidate_claim() -> crate::Result<()> {
    let (_tmp, vault) = temp_vault();
    let actor = test_id(0x21);
    let subject = test_id(0x22);
    let claim_id = test_id(0x23);
    put_actor_and_subject(&vault, &actor, &subject);
    let admission =
        proposed_admission(claim_id, subject, actor).with_approval(ClaimApprovalStatus::Auto);

    let err = admit_imported_evidence_claim(&vault, &normalized_imported_claim(), admission)
        .expect_err("imported auto claim must be denied by default");

    assert!(
        matches!(
            err,
            Error::Gate(GateError::GateWriteRejected {
                outcome: "pending",
                ref reason_codes,
            }) if reason_codes == &["gate.pending.source_trust"]
        ),
        "expected imported write-gate source-trust pending, got {err:?}"
    );
    assert!(vault.get_raw(&claim_id)?.is_none());
    Ok(())
}

#[test]
fn imported_evidence_requires_explicit_resolved_entity_before_persistence() -> crate::Result<()> {
    let (_tmp, vault) = temp_vault();
    let actor = test_id(0x31);
    let missing_subject = test_id(0x32);
    let claim_id = test_id(0x33);
    vault.put_entity(&actor, ENTITY_TYPE_PERSON, test_time(1), 1, b"import actor")?;

    let err = admit_imported_evidence_claim(
        &vault,
        &normalized_imported_claim(),
        proposed_admission(claim_id, missing_subject, actor),
    )
    .expect_err("missing resolved subject entity must abort admission");

    assert!(matches!(err, Error::EntityNotFound), "got {err:?}");
    assert!(vault.get_raw(&claim_id)?.is_none());
    Ok(())
}

#[test]
fn imported_evidence_gate_denial_leaves_no_candidate_claim() -> crate::Result<()> {
    let (_tmp, vault) = temp_vault();
    let actor = test_id(0x41);
    let subject = test_id(0x54);
    let claim_id = test_id(0x43);
    put_actor_and_subject(&vault, &actor, &subject);
    put_policy_manifest_bytes(&vault, test_id(0x44), b"not a messagepack manifest")?;

    let err = admit_imported_evidence_claim(
        &vault,
        &normalized_imported_claim(),
        proposed_admission(claim_id, subject, actor),
    )
    .expect_err("Gate fail-closed denial must abort admission");

    assert!(
        matches!(
            err,
            Error::Gate(GateError::GateWriteRejected {
                outcome: "deny",
                ref reason_codes
            }) if reason_codes.as_slice() == ["gate.deny.policy_fail_closed"]
        ),
        "expected Gate deny, got {err:?}"
    );
    assert!(vault.get_raw(&claim_id)?.is_none());
    Ok(())
}

// -- meeting-transcript ----------------------------------------------------

#[test]
fn meeting_transcript_rejects_an_unsupported_schema_version() {
    let err = INGEST_SOURCE_REGISTRY
        .normalize(
            MEETING_TRANSCRIPT_SOURCE_ID,
            &meeting_transcript_json(&[(
                "\"oneiron.meeting_transcript.v1\"",
                "\"oneiron.meeting_transcript.v2\"",
            )]),
        )
        .expect_err("unknown schema version must fail");

    assert_eq!(
        err,
        IngestError::UnsupportedSchema {
            source_id: MEETING_TRANSCRIPT_SOURCE_ID,
            expected: MEETING_TRANSCRIPT_SCHEMA_V1,
            found: "oneiron.meeting_transcript.v2".to_owned(),
        }
    );
}

#[test]
fn meeting_transcript_rejects_a_turn_citing_an_unknown_word() {
    let err = INGEST_SOURCE_REGISTRY
        .normalize(
            MEETING_TRANSCRIPT_SOURCE_ID,
            &meeting_transcript_json(&[(
                r#""source_word_ids": ["word-000001"]"#,
                r#""source_word_ids": ["word-999999"]"#,
            )]),
        )
        .expect_err("dangling word reference must fail");

    assert_eq!(
        err,
        IngestError::UnknownWordReference {
            source_id: MEETING_TRANSCRIPT_SOURCE_ID,
            turn_id: "turn-0001".to_owned(),
            word_id: "word-999999".to_owned(),
        }
    );
}

#[test]
fn meeting_transcript_rejects_duplicate_turn_ids() {
    let duplicated = meeting_transcript_json(&[(
        r#""turns": [{"turn_id": "turn-0001", "start_ms": 2000, "end_ms": 5000,"#,
        r#""turns": [{"turn_id": "turn-0001", "start_ms": 0, "end_ms": 1000,
            "text": "First.", "source_word_ids": [], "speaker_cluster": null,
            "speaker_ref": null},
          {"turn_id": "turn-0001", "start_ms": 2000, "end_ms": 5000,"#,
    )]);

    let err = INGEST_SOURCE_REGISTRY
        .normalize(MEETING_TRANSCRIPT_SOURCE_ID, &duplicated)
        .expect_err("duplicate turn ids must fail");

    assert_eq!(
        err,
        IngestError::DuplicateId {
            source_id: MEETING_TRANSCRIPT_SOURCE_ID,
            kind: "turn",
            id: "turn-0001".to_owned(),
        }
    );
}

#[test]
fn meeting_transcript_rejects_a_capture_time_that_overflows_occurred_at() {
    let err = INGEST_SOURCE_REGISTRY
        .normalize(
            MEETING_TRANSCRIPT_SOURCE_ID,
            &meeting_transcript_json(&[(
                "\"capture_started_at\": 1000",
                &format!("\"capture_started_at\": {}", u64::MAX),
            )]),
        )
        .expect_err("u64::MAX-adjacent capture time must reject, not wrap");

    assert!(
        matches!(
            err,
            IngestError::TimestampOverflow {
                source_id: MEETING_TRANSCRIPT_SOURCE_ID,
                ..
            }
        ),
        "got {err:?}"
    );
}

#[test]
fn imported_asset_text_admission_persists_locality_provenance() -> crate::Result<()> {
    let (_tmp, vault) = temp_vault();
    let id = test_id(0x71);
    let asset = NormalizedIngestEntity {
        entity_type: crate::registry::ENTITY_TYPE_ASSET_TEXT,
        body: "[PROVENANCE recognizer_locality=1]\n[OCR]\nlocal text\n".to_owned(),
        recognizer_locality: Some(LocalityRung::HostLocal),
    };
    admit_imported_entity(&vault, &id, &asset, test_time(2), 2)?;
    assert_eq!(vault.get(&id)?, Some(asset.body.into_bytes()));
    let wrong = NormalizedIngestEntity {
        entity_type: ENTITY_TYPE_PERSON,
        body: "wrong".to_owned(),
        recognizer_locality: None,
    };
    assert!(matches!(
        admit_imported_entity(&vault, &test_id(0x72), &wrong, test_time(2), 2),
        Err(Error::InvalidClaimBody(_))
    ));
    Ok(())
}

// ── CAL-08 (ONE-1790) G2: imported turn bodies decode as GATE-10 ROLES ──────

/// The import path's own persisted turn body, read through the SHARED
/// dirty-scan decoder rather than a bespoke re-parse: `decode_turn_body` is
/// first-wins across the `speaker|spkr` alias set, so this is exactly the
/// speaker string GATE-10 classifies when the scan admits (or drops) the turn.
fn persisted_turn_role(
    vault: &crate::Vault,
    turn: &EntityId,
) -> crate::dreamer_runner::DreamerTurnRole {
    let raw = vault
        .get_raw(turn)
        .expect("raw turn row")
        .expect("persisted turn exists");
    let facts = crate::dreamer_consolidation::decode_turn_body(
        &raw[crate::batch::ENTITY_METADATA_HEADER_LEN..],
    );
    crate::dreamer_runner::dreamer_turn_role(facts.speaker.as_deref(), &[])
}

/// A NAMED-speaker file drop ("Ada:", "Bob:") must persist turns the production
/// decoder classifies as admissible. Parking the display label in `speaker`
/// made it win the alias set and decode as `Unknown`, which GATE-10 never
/// admits — the import was then permanently invisible to every dirty scan.
#[test]
fn named_speaker_file_drop_turns_decode_to_gate_10_admissible_roles() {
    let tmp = tempfile::tempdir().expect("temp dir");
    let vault = crate::Vault::open_unseeded_for_test(tmp.path(), VaultConfig::default())
        .expect("open unseeded vault");
    let crate::calendar::transcript::TranscriptIngestOutcome::Session { turn_refs, .. } =
        crate::calendar::transcript::ingest_file_drop_transcript(
            &vault,
            crate::calendar::transcript::TranscriptFileDropRequest {
                source_blob_ref: EntityId::now(),
                decoded_text: "Ada: hello\nBob: hi",
                arrived_at_ms: 200_000,
            },
        )
        .expect("named-speaker import")
    else {
        panic!("a turn-bearing transcript mints a session")
    };

    assert_eq!(turn_refs.len(), 2, "both named turns persisted");
    for turn in &turn_refs {
        let role = persisted_turn_role(&vault, turn);
        assert_eq!(
            role,
            crate::dreamer_runner::DreamerTurnRole::User,
            "the GATE-10 keys carry the role, never the display label"
        );
        assert!(
            crate::dreamer_runner::dreamer_extraction_role_admissible(role),
            "a named-speaker import must never be invisible to the dirty scan"
        );
    }
}
