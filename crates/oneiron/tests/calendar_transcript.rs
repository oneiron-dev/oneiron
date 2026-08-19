// Integration-test helpers (non-#[test] fns) are not covered by allow-unwrap-in-tests.
#![allow(clippy::unwrap_used)]

use oneiron::attempt_queue::AttemptQueue;
use oneiron::blob_artifact::{BlobArtifactBody, BlobVersionProvenance};
use oneiron::calendar::transcript::{
    TranscriptFileDropRequest, TranscriptIngestOutcome, ingest_file_drop_transcript,
    ingest_file_drop_transcript_fail_after_turns_for_test, parse_file_drop_transcript,
    seed_file_drop_machine_fixture,
};
use oneiron::claim::ClaimApprovalStatus;
use oneiron::dreamer_runner::decode_dreamer_attempt_payload;
use oneiron::edge::{EdgeActorClass, EdgeKind};
use oneiron::ingest::{self, IngestSourceFormat};
use oneiron::write_envelope::WriteActor;
use oneiron::{EntityId, Vault, VaultConfig};
use sha2::Digest;
use std::collections::HashSet;

fn vault() -> (tempfile::TempDir, Vault) {
    let dir = tempfile::tempdir().unwrap();
    let vault = Vault::open_unseeded_for_test(dir.path(), VaultConfig::default()).unwrap();
    (dir, vault)
}

fn file_drop_actor(vault: &Vault, at: u64) -> EntityId {
    seed_file_drop_machine_fixture(vault, at).unwrap()
}

fn uploaded_blob(vault: &Vault, at: u64) -> EntityId {
    let blob = EntityId::now();
    vault
        .put_blob_artifact(
            &blob,
            &BlobArtifactBody::new("transcript.txt", "text/plain"),
            oneiron::TimeRange { start: at, end: at },
            at,
        )
        .unwrap();
    let uploader = EntityId::now();
    vault
        .put_entity(
            &uploader,
            oneiron::registry::ENTITY_TYPE_PERSON,
            oneiron::TimeRange { start: at, end: at },
            at,
            b"blob uploader",
        )
        .unwrap();
    vault
        .append_blob_artifact_version(
            &blob,
            b"blob",
            &BlobVersionProvenance::UserUpload,
            WriteActor::new(uploader, EdgeActorClass::Human),
            oneiron::TimeRange { start: at, end: at },
            at,
        )
        .unwrap();
    blob
}

/// A CONVERSATION for pre-existing (non-imported) dirty turns to hang from.
fn seed_conversation(vault: &Vault, at: u64) -> EntityId {
    let id = EntityId::now();
    vault
        .put_entity(
            &id,
            oneiron::registry::ENTITY_TYPE_CONVERSATION,
            oneiron::TimeRange { start: at, end: at },
            at,
            b"conversation",
        )
        .unwrap();
    id
}

/// One pre-existing admissible dirty TURN in the shape the production scan
/// admits: a GATE-10 role key plus the structural ChildOf conversation edge.
fn seed_dirty_turn(vault: &Vault, conversation: &EntityId, learned_at: u64) -> EntityId {
    let turn = EntityId::now();
    let mut body = Vec::new();
    rmpv::encode::write_value(
        &mut body,
        &rmpv::Value::Map(vec![
            (rmpv::Value::from("spkr"), rmpv::Value::from("user")),
            (
                rmpv::Value::from("txt"),
                rmpv::Value::from("pre-existing turn"),
            ),
        ]),
    )
    .unwrap();
    vault
        .batch()
        .put(
            &turn,
            oneiron::registry::ENTITY_TYPE_TURN,
            oneiron::TimeRange {
                start: learned_at,
                end: learned_at,
            },
            learned_at,
            &body,
        )
        .edge(&turn, EdgeKind::ChildOf, conversation, 1.0)
        .commit()
        .unwrap();
    turn
}

fn meso_partition_attempt_count(vault: &Vault) -> usize {
    AttemptQueue::new(vault)
        .list()
        .unwrap()
        .into_iter()
        .filter(|attempt| attempt.kind == oneiron::DREAMER_CONSOLIDATION_MESO_ATTEMPT_KIND)
        .map(|attempt| decode_dreamer_attempt_payload(&attempt.payload).unwrap())
        .filter(|payload| payload.attempt_type == "meso")
        .count()
}
#[test]
fn speaker_transcript_mints_one_session_and_ordered_turns() {
    let (_dir, vault) = vault();
    let outcome = ingest_file_drop_transcript(
        &vault,
        TranscriptFileDropRequest {
            source_blob_ref: EntityId::now(),
            decoded_text: "Alice: hello\nBob: hi",
            arrived_at_ms: 1_000,
        },
    )
    .unwrap();
    let TranscriptIngestOutcome::Session {
        session_ref,
        turn_refs,
        ..
    } = outcome
    else {
        panic!("must mint a session")
    };
    assert_eq!(turn_refs.len(), 2);
    assert_eq!(
        vault
            .entities_by_type(oneiron::registry::ENTITY_TYPE_SESSION)
            .unwrap(),
        vec![session_ref]
    );
    assert_eq!(
        vault
            .entities_by_type(oneiron::registry::ENTITY_TYPE_TURN)
            .unwrap()
            .len(),
        2
    );
}
#[test]
fn empty_input_is_rejected_not_minted_as_empty_session_or_note() {
    let (_dir, vault) = vault();
    let before = (
        vault
            .entities_by_type(oneiron::registry::ENTITY_TYPE_SESSION)
            .unwrap()
            .len(),
        vault
            .entities_by_type(oneiron::registry::ENTITY_TYPE_TURN)
            .unwrap()
            .len(),
        vault
            .entities_by_type(oneiron::registry::ENTITY_TYPE_NOTE)
            .unwrap()
            .len(),
        AttemptQueue::new(&vault).list().unwrap().len(),
    );
    assert!(parse_file_drop_transcript(" ").is_err());
    assert!(
        ingest_file_drop_transcript(
            &vault,
            TranscriptFileDropRequest {
                source_blob_ref: EntityId::now(),
                decoded_text: " ",
                arrived_at_ms: 1
            }
        )
        .is_err()
    );
    assert_eq!(
        before,
        (
            vault
                .entities_by_type(oneiron::registry::ENTITY_TYPE_SESSION)
                .unwrap()
                .len(),
            vault
                .entities_by_type(oneiron::registry::ENTITY_TYPE_TURN)
                .unwrap()
                .len(),
            vault
                .entities_by_type(oneiron::registry::ENTITY_TYPE_NOTE)
                .unwrap()
                .len(),
            AttemptQueue::new(&vault).list().unwrap().len()
        )
    );
}

#[test]
fn ingest_registry_set_matches_jsonl_file_drop_and_ics() {
    let ids: HashSet<_> = ingest::INGEST_SOURCE_REGISTRY.source_ids().collect();
    assert!(ids.contains(ingest::JSONL_TRANSCRIPT_SOURCE_ID));
    assert!(ids.contains(ingest::FILE_DROP_TRANSCRIPT_SOURCE_ID));
    assert!(ids.contains(ingest::ICS_FEED_SOURCE_ID));
    let actual: HashSet<_> = ingest::INGEST_SOURCE_REGISTRY
        .source_configs()
        .map(|c| (c.source_id, c.format))
        .collect();
    let expected: HashSet<_> = [
        ("image-asset", IngestSourceFormat::ImageAsset),
        ("jsonl-transcript", IngestSourceFormat::JsonlTranscript),
        (
            "file-drop-transcript",
            IngestSourceFormat::FileDropTranscript,
        ),
        (
            "meeting-transcript",
            IngestSourceFormat::MeetingTranscriptV1,
        ),
        ("ics-feed", IngestSourceFormat::IcsFeed),
    ]
    .into_iter()
    .collect();
    assert_eq!(actual, expected);
}

#[test]
fn file_drop_registration_has_exact_source_id_and_format() {
    let cfg = ingest::INGEST_SOURCE_REGISTRY
        .get_config(ingest::FILE_DROP_TRANSCRIPT_SOURCE_ID)
        .unwrap();
    assert_eq!(cfg.source_id, "file-drop-transcript");
    assert_eq!(cfg.format, IngestSourceFormat::FileDropTranscript);
}

#[test]
fn file_drop_source_obeys_ingest_registry_parity() {
    let source = ingest::INGEST_SOURCE_REGISTRY
        .get(ingest::FILE_DROP_TRANSCRIPT_SOURCE_ID)
        .unwrap();
    let batch = source.normalize("Ada: hello").unwrap();
    assert_eq!(batch.source_id, ingest::FILE_DROP_TRANSCRIPT_SOURCE_ID);
    assert_eq!(batch.records[0].speaker.as_deref(), Some("Ada"));
}

#[test]
fn turns_preserve_source_labels_timestamps_order_and_blob_provenance() {
    let (_dir, vault) = vault();
    let blob = EntityId::now();
    let TranscriptIngestOutcome::Session { turn_refs, .. } = ingest_file_drop_transcript(
        &vault,
        TranscriptFileDropRequest {
            source_blob_ref: blob,
            decoded_text: "[123400] Ada: first\n[123500] Bob: second",
            arrived_at_ms: 200_000,
        },
    )
    .unwrap() else {
        panic!()
    };
    let first: serde_json::Value =
        rmp_serde::from_slice(&vault.get(&turn_refs[0]).unwrap().unwrap()).unwrap();
    let second: serde_json::Value =
        rmp_serde::from_slice(&vault.get(&turn_refs[1]).unwrap().unwrap()).unwrap();
    // The source display name is PROVENANCE, and lives under a key outside the
    // dirty scan's `speaker|spkr` alias set. The GATE-10 keys carry the role, so
    // a named import decodes as an admissible User turn instead of `Unknown`.
    assert_eq!(first["speaker_label"], "Ada");
    assert_eq!(first["speaker"], "user");
    assert_eq!(first["spkr"], "user");
    assert_eq!(first["role"], "user");
    assert_eq!(first["ordinal"], 0);
    assert_eq!(second["speaker_label"], "Bob");
    assert_eq!(second["speaker"], "user");
    assert_eq!(second["ordinal"], 1);
    assert_eq!(first["source_blob_ref"], blob.to_hex());
    assert_eq!(first["claimed_start_ms"], 123400);
    assert_eq!(first["claimed_end_ms"], 123400);
    assert_eq!(first["arrived_at_ms"], 200000);
    assert_eq!(
        vault.get_entity_type(&turn_refs[0]).unwrap(),
        Some(oneiron::registry::ENTITY_TYPE_TURN)
    );
}
#[test]
fn session_first_path_uses_in_txn_mint_plan_and_end_lifecycle() {
    let (_dir, vault) = vault();
    let outcome = ingest_file_drop_transcript(
        &vault,
        TranscriptFileDropRequest {
            source_blob_ref: EntityId::now(),
            decoded_text: "Alice: hello",
            arrived_at_ms: 2_000,
        },
    )
    .unwrap();
    assert!(matches!(outcome, TranscriptIngestOutcome::Session { .. }));
    assert!(vault.open_session().unwrap().is_none());
}

#[test]
fn public_lifecycle_wrappers_delegate_to_in_txn_entrypoints() {
    let (_dir, vault) = vault();
    let oneiron::session_lifecycle::SessionMintOutcome::Minted(id) = vault.mint_session(4).unwrap()
    else {
        panic!()
    };
    let wake = vault.plan_session_end_wake().unwrap();
    assert!(
        vault
            .end_session_with_wake(
                &id,
                oneiron::session_lifecycle::SessionClosePredicate::Explicit,
                4,
                &wake
            )
            .unwrap()
            .is_some()
    );
    assert!(vault.open_session().unwrap().is_none());
}
#[test]
fn timestamp_preserving_end_wrapper_forwards_exact_end_hint() {
    let (_dir, vault) = vault();
    let hint = oneiron::session_lifecycle::SessionHintTimestamp {
        claimed_ms: Some(5_001),
        arrival_ms: 5_000,
        effective_ms: 5_000,
    };
    let oneiron::session_lifecycle::SessionMintOutcome::Minted(id) =
        vault.mint_session_from_hint(hint).unwrap()
    else {
        panic!()
    };
    let wake = vault.plan_session_end_wake().unwrap();
    vault
        .end_session_with_wake_and_hint(
            &id,
            oneiron::session_lifecycle::SessionClosePredicate::Explicit,
            5,
            &wake,
            Some(hint),
        )
        .unwrap();
    assert_eq!(
        vault
            .session_lifecycle_record(&id)
            .unwrap()
            .unwrap()
            .explicit_end_hint,
        Some(hint)
    );
}
#[test]
fn in_txn_wake_planner_includes_newly_persisted_turn_ids() {
    let (_dir, vault) = vault();
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    let TranscriptIngestOutcome::Session {
        turn_refs,
        wake_turn_refs,
        ..
    } = ingest_file_drop_transcript(
        &vault,
        TranscriptFileDropRequest {
            source_blob_ref: EntityId::now(),
            decoded_text: "user: wake",
            arrived_at_ms: now_ms,
        },
    )
    .unwrap()
    else {
        panic!()
    };
    assert_eq!(wake_turn_refs, turn_refs);
}

/// NAMED speakers plan exactly like role-named ones: the label never reaches a
/// GATE-10 key, so every imported turn stays admissible to the dirty scan the
/// close's planner runs — with no empty-only fallback left to rescue them.
#[test]
fn in_txn_wake_planner_includes_named_speaker_turn_ids() {
    let (_dir, vault) = vault();
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    let TranscriptIngestOutcome::Session {
        turn_refs,
        wake_turn_refs,
        extraction_enqueued,
        ..
    } = ingest_file_drop_transcript(
        &vault,
        TranscriptFileDropRequest {
            source_blob_ref: EntityId::now(),
            decoded_text: "Ada: wake\nBob: hi",
            arrived_at_ms: now_ms,
        },
    )
    .unwrap()
    else {
        panic!()
    };
    assert_eq!(turn_refs.len(), 2, "both named turns persisted");
    assert_eq!(
        wake_turn_refs, turn_refs,
        "named-speaker turns are planned by the same in-txn round"
    );
    assert!(extraction_enqueued, "a planned round mints its attempt");
}

/// MIXED state (the case the deleted empty-only fallback could never serve): a
/// pre-existing admissible dirty turn AND a named-speaker import in one ingest
/// land in the SAME round — both planned, one attempt per partition, watermark
/// settled at the max `learned_at` of the planned prefix.
#[test]
fn mixed_state_ingest_plans_pre_existing_and_imported_turns_in_one_round() {
    let (_dir, vault) = vault();
    let conversation = seed_conversation(&vault, 100);
    let pre_existing = seed_dirty_turn(&vault, &conversation, 100);
    let before = meso_partition_attempt_count(&vault);

    let TranscriptIngestOutcome::Session {
        turn_refs,
        wake_turn_refs,
        extraction_enqueued,
        ..
    } = ingest_file_drop_transcript(
        &vault,
        TranscriptFileDropRequest {
            source_blob_ref: EntityId::now(),
            decoded_text: "Ada: imported\nBob: reply",
            arrived_at_ms: 200_000,
        },
    )
    .unwrap()
    else {
        panic!()
    };

    let mut expected = vec![pre_existing];
    expected.extend(turn_refs.iter().copied());
    assert_eq!(
        wake_turn_refs, expected,
        "the round plans the pre-existing dirty turn AND the import, in temporal order"
    );
    assert!(extraction_enqueued);
    assert_eq!(
        meso_partition_attempt_count(&vault),
        before + 2,
        "one attempt per partition: the pre-existing conversation and the import's own"
    );
    assert!(
        vault.open_session().unwrap().is_none(),
        "the import closes its own sitting exactly once"
    );
    assert_eq!(
        oneiron::dreamer_consolidation::read_watermark(
            &vault,
            oneiron::dreamer_runner::DreamerConsolidationScope::Meso
        )
        .unwrap()
        .last_learned_at,
        200,
        "the watermark settles at the max learned_at of the planned prefix"
    );
}
#[test]
fn session_end_enqueues_existing_extraction_path_once() {
    let (_dir, vault) = vault();
    let before = meso_partition_attempt_count(&vault);
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    let TranscriptIngestOutcome::Session { session_ref, .. } = ingest_file_drop_transcript(
        &vault,
        TranscriptFileDropRequest {
            source_blob_ref: EntityId::now(),
            decoded_text: "Ada: wake",
            arrived_at_ms: now_ms,
        },
    )
    .unwrap() else {
        panic!()
    };
    let after_first = meso_partition_attempt_count(&vault);
    assert_eq!(
        after_first,
        before + 1,
        "first close must enqueue exactly one Meso partition attempt"
    );
    let wake = vault.plan_session_end_wake().unwrap();
    assert!(
        vault
            .end_session_with_wake(
                &session_ref,
                oneiron::session_lifecycle::SessionClosePredicate::Explicit,
                7,
                &wake
            )
            .unwrap()
            .is_none()
    );
    assert_eq!(
        meso_partition_attempt_count(&vault),
        after_first,
        "duplicate close creates no Meso partition attempt"
    );
}
#[test]
fn open_interactive_session_causes_retry_without_partial_turn_writes() {
    let (_dir, vault) = vault();
    vault.mint_session(8).unwrap();
    let outcome = ingest_file_drop_transcript(
        &vault,
        TranscriptFileDropRequest {
            source_blob_ref: EntityId::now(),
            decoded_text: "Ada: blocked",
            arrived_at_ms: 8_001,
        },
    )
    .unwrap();
    assert!(matches!(
        outcome,
        TranscriptIngestOutcome::RetryOpenSession { .. }
    ));
    assert!(
        vault
            .entities_by_type(oneiron::registry::ENTITY_TYPE_TURN)
            .unwrap()
            .is_empty()
    );
}

#[test]
fn unparseable_nonempty_summary_uses_note_fallback_after_one_1377() {
    let (_dir, vault) = vault();
    let actor = file_drop_actor(&vault, 9);
    let blob = uploaded_blob(&vault, 9);
    let out = ingest_file_drop_transcript(
        &vault,
        TranscriptFileDropRequest {
            source_blob_ref: blob,
            decoded_text: "Ada:",
            arrived_at_ms: 9_000,
        },
    )
    .unwrap();
    assert!(matches!(out, TranscriptIngestOutcome::NoteFallback { .. }));
    assert_eq!(
        vault.get_entity_type(&actor).unwrap(),
        Some(oneiron::registry::ENTITY_TYPE_MACHINE)
    );
}

#[test]
fn note_fallback_uses_l1_note_identifier_without_registry_edit() {
    let (_dir, vault) = vault();
    let actor = file_drop_actor(&vault, 9);
    let blob = uploaded_blob(&vault, 9);
    let TranscriptIngestOutcome::NoteFallback { note_ref } = ingest_file_drop_transcript(
        &vault,
        TranscriptFileDropRequest {
            source_blob_ref: blob,
            decoded_text: "Ada:",
            arrived_at_ms: 9_001,
        },
    )
    .unwrap() else {
        panic!()
    };
    assert_eq!(
        vault.get_entity_type(&note_ref).unwrap(),
        Some(oneiron::registry::ENTITY_TYPE_NOTE)
    );
    let edges = vault.edges_out(&note_ref).unwrap();
    assert!(
        edges
            .iter()
            .any(|e| e.kind == EdgeKind::About && e.target == blob)
    );
    assert!(
        edges
            .iter()
            .any(|e| e.kind == EdgeKind::AuthoredBy && e.target == actor)
    );
    assert!(vault.get_blob_artifact(&blob).unwrap().is_some());
}

#[test]
fn extracted_follow_ups_are_write_envelope_proposals_never_sends() {
    let (_dir, vault) = vault();
    let actor = EntityId::from_bytes(
        sha2::Sha256::digest(b"oneiron:calendar:file-drop-import-machine:v1")[..16]
            .try_into()
            .unwrap(),
    )
    .unwrap();
    let at = 30_000_u64;
    vault
        .put_entity(
            &actor,
            oneiron::registry::ENTITY_TYPE_MACHINE,
            oneiron::TimeRange { start: at, end: at },
            at,
            b"file-drop import machine",
        )
        .unwrap();
    let subject = EntityId::now();
    vault
        .put_entity(
            &subject,
            oneiron::registry::ENTITY_TYPE_PERSON,
            oneiron::TimeRange { start: at, end: at },
            at,
            b"resolved subject",
        )
        .unwrap();
    let claim_id = EntityId::now();
    let admission = oneiron::ingest::ImportedEvidenceAdmission::proposed(
        ingest::FILE_DROP_TRANSCRIPT_SOURCE_ID,
        claim_id,
        oneiron::ingest::ImportedEvidenceEntityResolution::subject(subject),
        oneiron::write_envelope::WriteActor::new(actor, EdgeActorClass::System),
        oneiron::TimeRange { start: at, end: at },
        at,
    );
    let claim = oneiron::ingest::NormalizedIngestClaim {
        source_record_id: "r1".to_owned(),
        predicate: "calendar.follow_up".to_owned(),
        value: serde_json::json!("Ada: follow up"),
    };
    let before_outbound = vault.standalone_outbound_intent_count().unwrap();
    let before_dispatches = AttemptQueue::new(&vault).list().unwrap().len();
    oneiron::ingest::admit_imported_evidence_claim(&vault, &claim, admission).unwrap();
    let body = vault
        .get_claim(&claim_id)
        .unwrap()
        .expect("claim persisted");
    assert_eq!(body.approval, ClaimApprovalStatus::Proposed);
    assert_eq!(body.source, Some(oneiron::claim::ClaimSource::Imported));
    let rmpv::Value::Map(evidence) = body.evidence.expect("persisted evidence") else {
        panic!("imported evidence must be a MessagePack map")
    };
    let rmpv::Value::Map(ref candidate_evidence) = evidence
        .iter()
        .find(|(key, _)| key.as_str() == Some("candidate_evidence"))
        .expect("candidate evidence")
        .1
    else {
        panic!("candidate evidence must be map")
    };
    assert!(
        candidate_evidence
            .iter()
            .any(|(key, value)| key.as_str() == Some("source_id")
                && value.as_str() == Some(ingest::FILE_DROP_TRANSCRIPT_SOURCE_ID))
    );
    assert!(candidate_evidence.iter().any(
        |(key, value)| key.as_str() == Some("source_record_id") && value.as_str() == Some("r1")
    ));
    // Admission is a durable proposal, not an outbound-send or task dispatch path.
    assert_eq!(
        vault.standalone_outbound_intent_count().unwrap(),
        before_outbound
    );
    assert_eq!(
        AttemptQueue::new(&vault).list().unwrap().len(),
        before_dispatches
    );
}
#[test]
fn injected_failure_rolls_back_session_turns_close_and_wake() {
    let (_dir, vault) = vault();
    let before_turns = vault
        .entities_by_type(oneiron::registry::ENTITY_TYPE_TURN)
        .unwrap()
        .len();
    let before_sessions = vault
        .entities_by_type(oneiron::registry::ENTITY_TYPE_SESSION)
        .unwrap()
        .len();
    let before_queue = AttemptQueue::new(&vault).list().unwrap().len();
    let err = ingest_file_drop_transcript_fail_after_turns_for_test(
        &vault,
        TranscriptFileDropRequest {
            source_blob_ref: EntityId::now(),
            decoded_text: "Ada: first\nBob: second",
            arrived_at_ms: 42_000,
        },
    )
    .expect_err("injected failure must abort the outer transaction");
    assert!(matches!(err, oneiron::Error::InvariantViolation(_)));
    assert!(vault.open_session().unwrap().is_none());
    assert_eq!(
        vault
            .entities_by_type(oneiron::registry::ENTITY_TYPE_SESSION)
            .unwrap()
            .len(),
        before_sessions
    );
    assert_eq!(
        vault
            .entities_by_type(oneiron::registry::ENTITY_TYPE_TURN)
            .unwrap()
            .len(),
        before_turns
    );
    assert_eq!(
        AttemptQueue::new(&vault).list().unwrap().len(),
        before_queue,
        "close+wake queue writes roll back"
    );
    assert!(
        vault.open_session().unwrap().is_none(),
        "lifecycle open-session state rolls back"
    );
}

#[test]
fn raw_blob_is_retained_and_calendar_adapter_does_not_rewrite_blob_storage() {
    let (_dir, vault) = vault();
    let blob = uploaded_blob(&vault, 10);
    let before_body = vault.get_blob_artifact(&blob).unwrap();
    let before_head = vault.blob_artifact_head(&blob).unwrap();
    let before_versions = vault.blob_artifact_versions(&blob).unwrap();
    let before_bytes = vault.read_blob_artifact_version(&blob, 1).unwrap();
    let TranscriptIngestOutcome::Session { turn_refs, .. } = ingest_file_drop_transcript(
        &vault,
        TranscriptFileDropRequest {
            source_blob_ref: blob,
            decoded_text: "Ada: source",
            arrived_at_ms: 10_000,
        },
    )
    .unwrap() else {
        panic!()
    };
    let body: serde_json::Value =
        rmp_serde::from_slice(&vault.get(&turn_refs[0]).unwrap().unwrap()).unwrap();
    assert_eq!(body["source_blob_ref"], blob.to_hex());
    assert!(!body.as_object().unwrap().contains_key("blob_storage"));
    assert_eq!(vault.get_blob_artifact(&blob).unwrap(), before_body);
    assert_eq!(vault.blob_artifact_head(&blob).unwrap(), before_head);
    assert_eq!(
        vault.blob_artifact_versions(&blob).unwrap(),
        before_versions
    );
    assert_eq!(
        vault.read_blob_artifact_version(&blob, 1).unwrap(),
        before_bytes
    );
}

#[test]
fn transcript_lifecycle_hints_preserve_claimed_and_arrival_effective_timestamps() {
    let (_dir, vault) = vault();
    let start = oneiron::session_lifecycle::SessionHintTimestamp {
        claimed_ms: Some(1_001),
        arrival_ms: 2_003,
        effective_ms: 3_005,
    };
    let end = oneiron::session_lifecycle::SessionHintTimestamp {
        claimed_ms: Some(4_007),
        arrival_ms: 5_009,
        effective_ms: 6_011,
    };
    let oneiron::session_lifecycle::SessionMintOutcome::Minted(id) =
        vault.mint_session_from_hint(start).unwrap()
    else {
        panic!()
    };
    let wake = vault.plan_session_end_wake().unwrap();
    vault
        .end_session_with_wake_and_hint(
            &id,
            oneiron::session_lifecycle::SessionClosePredicate::Explicit,
            7,
            &wake,
            Some(end),
        )
        .unwrap();
    let record = vault.session_lifecycle_record(&id).unwrap().unwrap();
    assert_eq!(record.app_open_hints.first(), Some(&start));
    assert_eq!(record.explicit_end_hint, Some(end));
}
