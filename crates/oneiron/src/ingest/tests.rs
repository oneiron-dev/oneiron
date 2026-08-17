use super::*;
use crate::config::VaultConfig;
use crate::edge::EdgeActorClass;
use crate::error::Error;
use crate::registry::ENTITY_TYPE_PERSON;

const MINIMAL_TRANSCRIPT_FIXTURE: &str =
    include_str!("../../tests/fixtures/ingest/minimal_transcript.jsonl");
const NULL_OPTIONAL_METADATA_FIXTURE: &str =
    include_str!("../../tests/fixtures/ingest/null_optional_metadata.jsonl");
/// Seam fixture: CAL-08/ONE-1790's SESSION-first + NOTE-fallback consumer test
/// reads this same artifact, so both sides are pinned to one wire example.
const MEETING_TRANSCRIPT_FIXTURE: &str =
    include_str!("../../tests/fixtures/ingest/meeting_transcript_v1.json");

fn expected_jsonl_transcript_config() -> IngestSourceConfig {
    IngestSourceConfig {
        source_id: JSONL_TRANSCRIPT_SOURCE_ID,
        label: "JSONL transcript",
        format: IngestSourceFormat::JsonlTranscript,
        adapter_skill: None,
        writes_claims: false,
        trust_ceiling: IngestTrustCeiling {
            claim_source: ClaimSource::Imported,
            max_auto_sensitivity: None,
            receipted: false,
            warned: false,
        },
        default_admission: ClaimApprovalStatus::Proposed,
    }
}

fn expected_meeting_transcript_config() -> IngestSourceConfig {
    IngestSourceConfig {
        source_id: MEETING_TRANSCRIPT_SOURCE_ID,
        label: "Meeting transcript",
        format: IngestSourceFormat::MeetingTranscriptV1,
        adapter_skill: Some(IngestAdapterSkillRef {
            skill_id: "builtin.ingest.meeting-transcript",
            version: "1",
        }),
        writes_claims: false,
        trust_ceiling: IngestTrustCeiling {
            claim_source: ClaimSource::Imported,
            max_auto_sensitivity: None,
            receipted: false,
            warned: false,
        },
        default_admission: ClaimApprovalStatus::Proposed,
    }
}

/// CAL-02's ICS feed entry (ONE-1784). PACKET_AMEND candidate: this file is
/// ONE-1790's claim, but the registry parity assertion lives here and must
/// name entry #3 the moment `ingest.rs` registers it.
fn expected_ics_feed_config() -> IngestSourceConfig {
    IngestSourceConfig {
        source_id: ICS_FEED_SOURCE_ID,
        label: "ICS feed",
        format: IngestSourceFormat::IcsFeed,
        adapter_skill: Some(IngestAdapterSkillRef {
            skill_id: "builtin.ingest.ics-feed",
            version: "1",
        }),
        writes_claims: false,
        trust_ceiling: IngestTrustCeiling {
            claim_source: ClaimSource::Imported,
            max_auto_sensitivity: None,
            receipted: false,
            warned: false,
        },
        default_admission: ClaimApprovalStatus::Proposed,
    }
}

fn expected_image_asset_config() -> IngestSourceConfig {
    IngestSourceConfig {
        source_id: IMAGE_SOURCE_ID,
        label: "Image asset",
        format: IngestSourceFormat::ImageAsset,
        adapter_skill: Some(IngestAdapterSkillRef {
            skill_id: "builtin.ingest.image-asset",
            version: "1",
        }),
        writes_claims: false,
        trust_ceiling: IngestTrustCeiling {
            claim_source: ClaimSource::Imported,
            max_auto_sensitivity: None,
            receipted: false,
            warned: false,
        },
        default_admission: ClaimApprovalStatus::Proposed,
    }
}

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

fn expected_file_drop_transcript_config() -> IngestSourceConfig {
    IngestSourceConfig {
        source_id: FILE_DROP_TRANSCRIPT_SOURCE_ID,
        label: "File-drop transcript",
        format: IngestSourceFormat::FileDropTranscript,
        adapter_skill: None,
        writes_claims: false,
        trust_ceiling: IngestTrustCeiling {
            claim_source: ClaimSource::Imported,
            max_auto_sensitivity: None,
            receipted: false,
            warned: false,
        },
        default_admission: ClaimApprovalStatus::Proposed,
    }
}

#[test]
fn ingest_registry_set_compare_exact_sources() {
    let actual: std::collections::HashSet<_> = INGEST_SOURCE_REGISTRY
        .source_configs()
        .map(|c| (c.source_id, c.format))
        .collect();
    let expected: std::collections::HashSet<_> = [
        expected_image_asset_config(),
        expected_jsonl_transcript_config(),
        expected_file_drop_transcript_config(),
        expected_meeting_transcript_config(),
        expected_ics_feed_config(),
    ]
    .into_iter()
    .map(|c| (c.source_id, c.format))
    .collect();
    assert_eq!(actual, expected);
}
#[test]
fn file_drop_registration_parity() {
    let c = INGEST_SOURCE_REGISTRY
        .get_config(FILE_DROP_TRANSCRIPT_SOURCE_ID)
        .unwrap();
    assert_eq!(c, expected_file_drop_transcript_config());
}
#[test]
fn file_drop_trust_ceiling_is_fail_closed() {
    let c = INGEST_SOURCE_REGISTRY
        .get_config(FILE_DROP_TRANSCRIPT_SOURCE_ID)
        .unwrap();
    assert!(!c.trust_ceiling.permits_auto(Some(0)));
}

#[test]
fn ingest_registry_equals_known_harness_config() {
    let registry_configs = INGEST_SOURCE_REGISTRY.source_configs().collect::<Vec<_>>();
    let harness_configs = KNOWN_INGEST_HARNESS_CONFIG
        .source_configs()
        .collect::<Vec<_>>();

    assert!(std::ptr::eq(
        KNOWN_INGEST_HARNESS_CONFIG.registry(),
        &INGEST_SOURCE_REGISTRY
    ));
    assert_eq!(registry_configs, harness_configs);
}

#[test]
fn ingest_source_ids_are_unique_and_adapter_skills_are_named_when_present() {
    let configs = INGEST_SOURCE_REGISTRY.source_configs().collect::<Vec<_>>();

    let mut ids = configs.iter().map(|c| c.source_id).collect::<Vec<_>>();
    ids.sort_unstable();
    ids.dedup();
    assert_eq!(ids.len(), configs.len(), "source ids must be unique");

    for config in &configs {
        let Some(skill) = config.adapter_skill else {
            continue;
        };
        assert!(!skill.skill_id.trim().is_empty(), "{:?}", config.source_id);
        assert!(!skill.version.trim().is_empty(), "{:?}", config.source_id);
    }
}

#[test]
fn meeting_transcript_policy_matches_imported_proposed_fail_closed_defaults() {
    let config = INGEST_SOURCE_REGISTRY
        .get_config(MEETING_TRANSCRIPT_SOURCE_ID)
        .expect("meeting transcript source config");

    assert_eq!(config, expected_meeting_transcript_config());
    assert_eq!(config.trust_ceiling.claim_source, ClaimSource::Imported);
    assert_eq!(config.trust_ceiling.max_auto_sensitivity, None);
    assert!(!config.trust_ceiling.receipted);
    assert!(!config.trust_ceiling.warned);
    assert_eq!(config.default_admission, ClaimApprovalStatus::Proposed);
    assert!(!config.trust_ceiling.permits_auto(Some(0)));
    assert!(!config.trust_ceiling.permits_auto(None));
    assert!(!config.writes_claims);
}

#[test]
fn jsonl_transcript_policy_defaults_to_proposed_and_fails_closed_for_auto() {
    let config = INGEST_SOURCE_REGISTRY
        .get_config(JSONL_TRANSCRIPT_SOURCE_ID)
        .expect("jsonl source config");

    assert_eq!(config, expected_jsonl_transcript_config());
    assert_eq!(config.trust_ceiling.claim_source, ClaimSource::Imported);
    assert_eq!(config.trust_ceiling.max_auto_sensitivity, None);
    assert_eq!(config.default_admission, ClaimApprovalStatus::Proposed);
    assert!(!config.trust_ceiling.permits_auto(Some(0)));
    assert!(!config.trust_ceiling.permits_auto(None));
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
        matches!(
            err,
            Error::InvalidClaimBody("imported evidence missing source_id")
        ),
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
        matches!(
            err,
            Error::InvalidClaimBody("imported evidence missing source_record_id")
        ),
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
            Error::GateWriteRejected {
                outcome: "pending",
                ref reason_codes,
            } if reason_codes == &["gate.pending.source_trust"]
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
            Error::GateWriteRejected {
                outcome: "deny",
                ref reason_codes
            } if reason_codes.as_slice() == ["gate.deny.policy_fail_closed"]
        ),
        "expected Gate deny, got {err:?}"
    );
    assert!(vault.get_raw(&claim_id)?.is_none());
    Ok(())
}

#[test]
fn ingest_jsonl_transcript_fixture_normalizes_records_without_claims() {
    let batch = INGEST_SOURCE_REGISTRY
        .normalize(JSONL_TRANSCRIPT_SOURCE_ID, MINIMAL_TRANSCRIPT_FIXTURE)
        .expect("fixture normalizes");

    assert_eq!(batch.source_id, JSONL_TRANSCRIPT_SOURCE_ID);
    assert_eq!(batch.records.len(), 2);
    assert!(
        batch.claims.is_empty(),
        "source normalization must not write claims"
    );

    assert_eq!(
        batch.records[0],
        NormalizedIngestRecord {
            source_record_id: "turn-001".to_owned(),
            thread_id: Some("dream-session-001".to_owned()),
            speaker: Some("dreamer".to_owned()),
            occurred_at: Some(1_773_532_800),
            text: "I saw a blue door at the end of a long hallway.".to_owned(),
        }
    );
    assert_eq!(
        batch.records[1],
        NormalizedIngestRecord {
            source_record_id: "turn-002".to_owned(),
            thread_id: Some("dream-session-001".to_owned()),
            speaker: Some("assistant".to_owned()),
            occurred_at: Some(1_773_532_806),
            text: "What did the door feel like?".to_owned(),
        }
    );
}

#[test]
fn ingest_jsonl_transcript_optional_null_metadata_is_absent() {
    let batch = INGEST_SOURCE_REGISTRY
        .normalize(JSONL_TRANSCRIPT_SOURCE_ID, NULL_OPTIONAL_METADATA_FIXTURE)
        .expect("fixture normalizes");

    assert_eq!(
        batch.records.as_slice(),
        [NormalizedIngestRecord {
            source_record_id: "turn-null".to_owned(),
            thread_id: None,
            speaker: None,
            occurred_at: None,
            text: "Null optional metadata is omitted.".to_owned(),
        }]
    );
}

#[test]
fn ingest_jsonl_transcript_required_null_field_is_invalid() {
    let err = INGEST_SOURCE_REGISTRY
        .normalize(
            JSONL_TRANSCRIPT_SOURCE_ID,
            r#"{"id":null,"text":"required id is null"}"#,
        )
        .expect_err("required null field must fail");

    assert_eq!(
        err,
        IngestError::InvalidStringField {
            source_id: JSONL_TRANSCRIPT_SOURCE_ID,
            line: 1,
            field: "id",
        }
    );
}

#[test]
fn ingest_jsonl_transcript_batches_carry_no_note_fallback() {
    let batch = INGEST_SOURCE_REGISTRY
        .normalize(JSONL_TRANSCRIPT_SOURCE_ID, MINIMAL_TRANSCRIPT_FIXTURE)
        .expect("fixture normalizes");

    assert_eq!(batch.note_fallback, None);
}

// -- meeting-transcript ----------------------------------------------------

#[test]
fn meeting_transcript_fixture_normalizes_ordered_records_without_claims() {
    let batch = INGEST_SOURCE_REGISTRY
        .normalize(MEETING_TRANSCRIPT_SOURCE_ID, MEETING_TRANSCRIPT_FIXTURE)
        .expect("fixture normalizes");

    assert_eq!(batch.source_id, MEETING_TRANSCRIPT_SOURCE_ID);
    assert!(
        batch.claims.is_empty(),
        "source normalization must not write claims"
    );
    assert_eq!(
        batch.records,
        [
            NormalizedIngestRecord {
                source_record_id: "turn-0001".to_owned(),
                thread_id: Some(
                    "sha256:9f2c4a1e7b3d5086c1f4a9e2b7d0c3f6a8e1b4d7c0f3a6e9b2d5c8f1a4e7b0d3"
                        .to_owned()
                ),
                // Resolved identity wins over the anonymous cluster.
                speaker: Some("person:ada".to_owned()),
                occurred_at: Some(1_773_532_802),
                text: "Morning everyone.".to_owned(),
            },
            NormalizedIngestRecord {
                source_record_id: "turn-0002".to_owned(),
                thread_id: Some(
                    "sha256:9f2c4a1e7b3d5086c1f4a9e2b7d0c3f6a8e1b4d7c0f3a6e9b2d5c8f1a4e7b0d3"
                        .to_owned()
                ),
                // No resolved ref yet: the provisional cluster label stands.
                speaker: Some("spk-2".to_owned()),
                occurred_at: Some(1_773_532_821),
                text: "Numbers are up.".to_owned(),
            },
            NormalizedIngestRecord {
                source_record_id: "turn-0003".to_owned(),
                thread_id: Some(
                    "sha256:9f2c4a1e7b3d5086c1f4a9e2b7d0c3f6a8e1b4d7c0f3a6e9b2d5c8f1a4e7b0d3"
                        .to_owned()
                ),
                speaker: Some("person:ada".to_owned()),
                occurred_at: Some(1_773_532_917),
                text: "Agreed, let's ship it.".to_owned(),
            },
        ]
    );
}

#[test]
fn meeting_transcript_preserves_the_producer_note_fallback() {
    let batch = INGEST_SOURCE_REGISTRY
        .normalize(MEETING_TRANSCRIPT_SOURCE_ID, MEETING_TRANSCRIPT_FIXTURE)
        .expect("fixture normalizes");

    assert_eq!(
        batch.note_fallback,
        Some(NormalizedIngestNote {
            source_record_id:
                "sha256:9f2c4a1e7b3d5086c1f4a9e2b7d0c3f6a8e1b4d7c0f3a6e9b2d5c8f1a4e7b0d3".to_owned(),
            occurred_at: Some(1_773_532_800),
            title: "Meeting transcript".to_owned(),
            text: "The team reviewed quarterly numbers and agreed to ship.".to_owned(),
        }),
        "CAL-08 needs the fallback present even when records land as turns"
    );
}

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
fn meeting_transcript_rejects_a_turn_reaching_past_the_recording() {
    let err = INGEST_SOURCE_REGISTRY
        .normalize(
            MEETING_TRANSCRIPT_SOURCE_ID,
            &meeting_transcript_json(&[("\"end_ms\": 5000", "\"end_ms\": 90000")]),
        )
        .expect_err("out-of-bounds turn must fail");

    assert_eq!(
        err,
        IngestError::InvalidTurnTimestamps {
            source_id: MEETING_TRANSCRIPT_SOURCE_ID,
            turn_id: "turn-0001".to_owned(),
        }
    );
}

#[test]
fn meeting_transcript_rejects_non_monotone_turns() {
    let two_turns = meeting_transcript_json(&[(
        r#""turns": [{"turn_id": "turn-0001", "start_ms": 2000, "end_ms": 5000,"#,
        r#""turns": [{"turn_id": "turn-0002", "start_ms": 20000, "end_ms": 25000,
            "text": "Later.", "source_word_ids": [], "speaker_cluster": null,
            "speaker_ref": null},
          {"turn_id": "turn-0001", "start_ms": 2000, "end_ms": 5000,"#,
    )]);

    let err = INGEST_SOURCE_REGISTRY
        .normalize(MEETING_TRANSCRIPT_SOURCE_ID, &two_turns)
        .expect_err("turns going backwards in time must fail");

    assert_eq!(
        err,
        IngestError::InvalidTurnTimestamps {
            source_id: MEETING_TRANSCRIPT_SOURCE_ID,
            turn_id: "turn-0001".to_owned(),
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
fn meeting_transcript_rejects_an_empty_recording_id() {
    let err = INGEST_SOURCE_REGISTRY
        .normalize(
            MEETING_TRANSCRIPT_SOURCE_ID,
            &meeting_transcript_json(&[(
                "\"recording_id\": \"sha256:rec\"",
                "\"recording_id\": \" \"",
            )]),
        )
        .expect_err("blank recording id must fail");

    assert_eq!(
        err,
        IngestError::InvalidDocumentField {
            source_id: MEETING_TRANSCRIPT_SOURCE_ID,
            path: "recording.recording_id".to_owned(),
        }
    );
}

#[test]
fn meeting_transcript_rejects_empty_turn_text() {
    let err = INGEST_SOURCE_REGISTRY
        .normalize(
            MEETING_TRANSCRIPT_SOURCE_ID,
            &meeting_transcript_json(&[("\"text\": \"Hello there.\"", "\"text\": \"   \"")]),
        )
        .expect_err("blank turn text must fail");

    assert_eq!(
        err,
        IngestError::InvalidDocumentField {
            source_id: MEETING_TRANSCRIPT_SOURCE_ID,
            path: "turns[0].text".to_owned(),
        }
    );
}

#[test]
fn meeting_transcript_without_capture_time_normalizes_without_occurred_at() {
    let batch = INGEST_SOURCE_REGISTRY
        .normalize(
            MEETING_TRANSCRIPT_SOURCE_ID,
            &meeting_transcript_json(&[(
                "\"capture_started_at\": 1000",
                "\"capture_started_at\": null",
            )]),
        )
        .expect("missing capture time is not a failure");

    assert_eq!(batch.records[0].occurred_at, None);
    assert_eq!(
        batch.note_fallback.expect("note fallback").occurred_at,
        None
    );
}

#[test]
fn meeting_transcript_rejects_malformed_json() {
    let err = INGEST_SOURCE_REGISTRY
        .normalize(MEETING_TRANSCRIPT_SOURCE_ID, "{ not json")
        .expect_err("malformed document must fail");

    assert!(
        matches!(
            err,
            IngestError::InvalidDocument {
                source_id: MEETING_TRANSCRIPT_SOURCE_ID,
                ..
            }
        ),
        "got {err:?}"
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
    crate::dreamer_runner::dreamer_turn_role(facts.speaker.as_deref())
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
