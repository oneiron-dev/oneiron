// Integration-test helpers (non-#[test] fns) are not covered by allow-unwrap-in-tests.
#![allow(clippy::unwrap_used)]

use oneiron::attempt_queue::AttemptQueue;
use oneiron::blob_artifact::{BlobArtifactBody, BlobVersionProvenance};
use oneiron::calendar::transcript::{
    TranscriptFileDropRequest, TranscriptIngestOutcome, ingest_file_drop_transcript,
    ingest_file_drop_transcript_fail_after_turns_for_test, seed_file_drop_machine_fixture,
};
use oneiron::claim::ClaimApprovalStatus;
use oneiron::dreamer_runner::decode_dreamer_attempt_payload;
use oneiron::edge::{EdgeActorClass, EdgeKind};
use oneiron::ingest::{self};
use oneiron::write_envelope::WriteActor;
use oneiron::{EntityId, Vault, VaultConfig};
use sha2::Digest;

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
            b"\x80",
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
    // The transcript importer is an engine MACHINE: it signs with a host-held key.
    crate::common::provision_engine_machines(&vault);
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

