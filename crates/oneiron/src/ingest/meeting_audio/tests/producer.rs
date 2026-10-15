use serde_json::Value;

use crate::claim::ClaimSource;
use crate::ingest::{INGEST_SOURCE_REGISTRY, MEETING_TRANSCRIPT_SOURCE_ID};

use super::super::provenance::sha256;
use super::super::*;
use super::support::*;

#[test]
fn saved_artifact_reloads_exact_bytes_and_waits_for_bulk_owner_consent() {
    let mut host = FixtureHost::small(Fault::None);
    let artifact = produce_meeting_transcript(&file(), &options(), &mut host).unwrap();
    let serialized = format!("{}\n", artifact.json());
    let restored = ProducedMeetingTranscript::from_json(serialized.clone()).unwrap();
    assert_eq!(restored.json(), serialized);
    assert_eq!(restored.recording_id(), artifact.recording_id());
    let mut pending = Authorizer {
        response: ConsentResponse::Missing,
        requests: Vec::new(),
    };
    assert_eq!(
        restored.authorize_import(&mut pending).unwrap_err(),
        AudioError::BulkConsentRequired
    );
    let mut rebound = Authorizer {
        response: ConsentResponse::WrongHash,
        requests: Vec::new(),
    };
    assert_eq!(
        restored.authorize_import(&mut rebound).unwrap_err(),
        AudioError::BulkConsentMismatch
    );
    let mut allowed = Authorizer {
        response: ConsentResponse::Allow,
        requests: Vec::new(),
    };
    let imported = restored.authorize_import(&mut allowed).unwrap();
    assert_eq!(
        imported.receipt().binding.artifact_sha256,
        sha256(serialized.as_bytes())
    );
    assert_eq!(
        imported.receipt().binding.source_record_ids,
        ["turn-0001", "turn-0002"]
    );
    assert!(imported.normalized().claims.is_empty());
    assert_eq!(imported.claim_source(), ClaimSource::Imported);
    // No producer call was made after serialization; every consent retry used
    // the same saved bytes and exact turn IDs.
    assert_eq!(
        pending.requests[0].artifact_sha256,
        allowed.requests[0].artifact_sha256
    );
    assert_eq!(
        rebound.requests[0].artifact_sha256,
        allowed.requests[0].artifact_sha256
    );
    let mut invalid: Value = serde_json::from_str(&serialized).unwrap();
    invalid["schema"] = "oneiron.meeting_transcript.v99".into();
    assert!(ProducedMeetingTranscript::from_json(invalid.to_string()).is_err());
}

#[test]
fn acoustic_word_correction_keeps_raw_word_clock_and_rejects_unbacked_cleanup() {
    let mut host = FixtureHost::small(Fault::AcousticCorrection);
    let mut input = file();
    input.language_hint = Some("English");
    let artifact = produce_meeting_transcript(&input, &options(), &mut host).unwrap();
    let document: Value = serde_json::from_str(artifact.json()).unwrap();
    assert_eq!(document["words"][0]["text"], "allice");
    assert_eq!(document["turns"][0]["text"], "Alice.");
    assert_eq!(
        document["turns"][0]["source_word_ids"][0],
        document["words"][0]["word_id"]
    );
    assert_eq!(
        document["turns"][0]["speaker_cluster"],
        document["words"][0]["speaker_cluster"]
    );
    assert_eq!(
        document["turns"][0]["start_ms"],
        document["words"][0]["start_ms"]
    );
    assert_eq!(
        document["cleanup"]["policy"],
        "acoustic_word_corrections_v1"
    );
    assert_eq!(
        document["cleanup"]["accepted_corrections"][0]["from"],
        "allice"
    );
    assert_eq!(
        document["cleanup"]["accepted_corrections"][0]["word_id"],
        document["words"][0]["word_id"]
    );
    INGEST_SOURCE_REGISTRY
        .normalize(MEETING_TRANSCRIPT_SOURCE_ID, artifact.json())
        .unwrap();

    let mut unsupported = FixtureHost::small(Fault::InventedCleanup);
    assert_eq!(
        produce_meeting_transcript(&file(), &options(), &mut unsupported).unwrap_err(),
        AudioError::CleanupInventedContent
    );
}

#[test]
fn host_contract_faults_fail_closed_with_typed_errors() {
    for (fault, expected) in [
        (Fault::EmptyDecode, AudioError::InvalidAudio),
        (Fault::NoSpeech, AudioError::NoSpeech),
        (Fault::EmptyAsr, AudioError::EmptyAsr),
        (Fault::WrongRoute, AudioError::InvalidRoute),
        (Fault::WrongAsrHash, AudioError::InvalidProvenance),
        (Fault::WrongAsrModel, AudioError::InvalidProvenance),
        (Fault::InvalidConfidence, AudioError::InvalidWords),
        (Fault::WordCrossesSeam, AudioError::WordCrossesPackSeam),
        (Fault::WrongGlobalHash, AudioError::InvalidProvenance),
        (Fault::WrongGlobalModel, AudioError::InvalidProvenance),
        (Fault::ReusedInvocation, AudioError::InvalidProvenance),
        (Fault::OverlappingTracks, AudioError::NonExclusiveTracks),
        (
            Fault::MissingTrack,
            AudioError::UnlabelledWord {
                word_id: "word-000002".into(),
            },
        ),
        (Fault::InventedCleanup, AudioError::CleanupInventedContent),
    ] {
        let mut host = FixtureHost::small(fault);
        let error = produce_meeting_transcript(&file(), &options(), &mut host).unwrap_err();
        assert_eq!(error, expected, "{fault:?}");
    }
}

#[test]
fn local_only_is_passed_to_the_router_and_remote_fallback_is_refused() {
    let options = ProducerOptions {
        local_only: true,
        ..options()
    };
    let mut host = FixtureHost::small(Fault::RemoteRoute);
    assert_eq!(
        produce_meeting_transcript(&file(), &options, &mut host).unwrap_err(),
        AudioError::InvalidRoute
    );
    assert_eq!(
        host.requests.last().unwrap(),
        &HostRequest::Route {
            role: AsrRole::Asr,
            preferred: ProcessingTier::Local,
            local_only: true,
            model: "fixture-asr".into(),
        }
    );
}

#[test]
fn a_supplied_e1_reference_cannot_promote_fixture_execution_to_measured() {
    let options = ProducerOptions {
        batch_default: BatchDefault::MeasuredE1 {
            model_id: "fixture-asr".into(),
            evidence_ref: "unverified-host-reference".into(),
        },
        ..options()
    };
    let mut host = FixtureHost::small(Fault::None);
    let artifact = produce_meeting_transcript(&file(), &options, &mut host).unwrap();
    let document: Value = serde_json::from_str(artifact.json()).unwrap();
    assert_eq!(document["producer"]["execution"], "fixture");
    assert_eq!(
        document["producer"]["batch_default"]["evidence_ref"],
        "unverified-host-reference"
    );
}

#[test]
fn bulk_consent_cannot_be_missing_or_rebound_to_other_artifacts_turns_or_vaults() {
    for response in [
        ConsentResponse::Missing,
        ConsentResponse::WrongScope,
        ConsentResponse::WrongHash,
        ConsentResponse::WrongTurns,
        ConsentResponse::BlankReceipt,
    ] {
        let mut host = FixtureHost::small(Fault::None);
        let artifact = produce_meeting_transcript(&file(), &options(), &mut host).unwrap();
        let mut authorizer = Authorizer {
            response,
            requests: Vec::new(),
        };
        let error = artifact.authorize_import(&mut authorizer).unwrap_err();
        let expected = if matches!(response, ConsentResponse::Missing) {
            AudioError::BulkConsentRequired
        } else {
            AudioError::BulkConsentMismatch
        };
        assert_eq!(error, expected);
        assert_eq!(authorizer.requests.len(), 1);
    }
}
