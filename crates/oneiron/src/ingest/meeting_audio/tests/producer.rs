use serde_json::Value;

use crate::claim::{ClaimApprovalStatus, ClaimSource};
use crate::ingest::{
    INGEST_SOURCE_REGISTRY, IngestError, IngestSourceFormat, KNOWN_INGEST_HARNESS_CONFIG,
    MEETING_TRANSCRIPT_SCHEMA_V1, MEETING_TRANSCRIPT_SOURCE_ID,
};

use super::super::provenance::sha256;
use super::super::*;
use super::support::*;

#[test]
fn two_pack_fixture_labels_every_word_from_one_full_file_call_then_normalizes_after_one_consent() {
    let mut host = FixtureHost::two_packs();
    let options = options();
    let artifact = produce_meeting_transcript(&file(), &options, &mut host).unwrap();
    let document: Value = serde_json::from_str(artifact.json()).unwrap();
    assert_eq!(document["schema"], MEETING_TRANSCRIPT_SCHEMA_V1);
    assert_eq!(document["producer"]["execution"], "fixture");
    assert_eq!(
        document["producer"]["batch_default"]["basis"],
        "provisional"
    );
    assert_eq!(document["diarization"]["scope"], "full_file");
    assert_eq!(document["diarization"]["track_kind"], "exclusive");
    assert_eq!(
        document["diarization"]["provenance"]["invocation_id"],
        "global-call"
    );
    assert_eq!(document["cleanup"]["status"], "turns_only");
    let labels: Vec<_> = document["words"]
        .as_array()
        .unwrap()
        .iter()
        .map(|word| word["speaker_cluster"].as_str().unwrap())
        .collect();
    assert_eq!(labels, ["global-a", "global-b", "global-a", "global-b"]);
    let starts: Vec<_> = document["words"]
        .as_array()
        .unwrap()
        .iter()
        .map(|word| word["start_ms"].as_u64().unwrap())
        .collect();
    assert_eq!(starts, [1_000, 48_000, 95_000, 142_000]);
    let words = document["words"].as_array().unwrap();
    let turns = document["turns"].as_array().unwrap();
    for (word, turn) in words.iter().zip(turns) {
        assert_eq!(word["speaker_cluster"], turn["speaker_cluster"]);
        assert_eq!(turn["source_word_ids"][0], word["word_id"]);
    }
    assert_ne!(words[0]["pack_id"], words[2]["pack_id"]);
    assert_eq!(words[0]["speaker_cluster"], words[2]["speaker_cluster"]);

    // These are observations at the injected host boundary, not private engine
    // counters. The exact call sequence falsifies per-chunk diarization.
    assert_eq!(host.requests.len(), 7);
    assert_eq!(host.requests[0], HostRequest::Decode);
    let full_hash = document["recording"]["canonical_pcm_sha256"]
        .as_str()
        .unwrap();
    assert_eq!(
        host.requests[1],
        HostRequest::Vad {
            samples: 3_040_000,
            hash: full_hash.into()
        }
    );
    assert_eq!(
        host.requests[2],
        HostRequest::Route {
            role: AsrRole::Asr,
            preferred: ProcessingTier::HomeFleet,
            local_only: false,
            model: "fixture-asr".into(),
        }
    );
    for (index, request) in host.requests[3..5].iter().enumerate() {
        let HostRequest::Pack {
            id,
            samples,
            hash,
            glossary,
        } = request
        else {
            panic!("expected pack call")
        };
        assert_eq!(id, &format!("pack-{:04}", index + 1));
        assert_eq!(*samples, 91_000 * 16);
        assert_ne!(hash, full_hash);
        assert_eq!(glossary, &options.glossary);
        assert_eq!(
            document["producer"]["asr_packs"][index]["provenance"]["input_sha256"],
            hash.as_str()
        );
    }
    assert_eq!(
        host.requests[5],
        HostRequest::Global {
            samples: 3_040_000,
            hash: full_hash.into()
        }
    );
    assert_eq!(host.requests[6], HostRequest::Cleanup);

    let json_hash = sha256(artifact.json().as_bytes());
    let direct = INGEST_SOURCE_REGISTRY
        .normalize(MEETING_TRANSCRIPT_SOURCE_ID, artifact.json())
        .unwrap();
    let mut authorizer = Authorizer {
        response: ConsentResponse::Allow,
        requests: Vec::new(),
    };
    let imported = artifact.authorize_import(&mut authorizer).unwrap();
    assert_eq!(authorizer.requests.len(), 1);
    assert_eq!(authorizer.requests[0].artifact_sha256, json_hash);
    assert_eq!(
        authorizer.requests[0].source_record_ids,
        ["turn-0001", "turn-0002", "turn-0003", "turn-0004"]
    );
    assert_eq!(authorizer.requests[0].vault_scope, "fixture-vault-owner");
    assert_eq!(imported.receipt().binding, authorizer.requests[0]);
    assert_eq!(imported.normalized(), &direct);
    assert!(direct.claims.is_empty());
    assert_eq!(
        direct
            .records
            .iter()
            .map(|record| record.occurred_at)
            .collect::<Vec<_>>(),
        [Some(1_001), Some(1_048), Some(1_095), Some(1_142)]
    );
    assert_eq!(
        direct
            .records
            .iter()
            .map(|record| record.text.as_str())
            .collect::<Vec<_>>(),
        ["hello.", "world.", "hello.", "world."]
    );
    assert_eq!(imported.claim_source(), ClaimSource::Imported);
    assert_eq!(imported.default_admission(), ClaimApprovalStatus::Proposed);

    let config = INGEST_SOURCE_REGISTRY
        .get_config(MEETING_TRANSCRIPT_SOURCE_ID)
        .unwrap();
    assert_eq!(
        KNOWN_INGEST_HARNESS_CONFIG.get_config(MEETING_TRANSCRIPT_SOURCE_ID),
        Some(config)
    );
    assert_eq!(config.format, IngestSourceFormat::MeetingTranscriptV1);
    let skill = config.adapter_skill.unwrap();
    assert_eq!(
        (skill.skill_id, skill.version),
        ("builtin.ingest.meeting-transcript", "1")
    );
    assert_eq!(config.trust_ceiling.claim_source, ClaimSource::Imported);
    assert!(!config.trust_ceiling.permits_auto(Some(0)));
    assert_eq!(config.default_admission, ClaimApprovalStatus::Proposed);
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

#[test]
fn native_normalizer_rejects_mutated_schema_word_reference_and_clock() {
    let mut host = FixtureHost::small(Fault::None);
    let artifact = produce_meeting_transcript(&file(), &options(), &mut host).unwrap();
    let mut value: Value = serde_json::from_str(artifact.json()).unwrap();
    value["schema"] = "meeting_transcript_v1".into();
    assert!(matches!(
        INGEST_SOURCE_REGISTRY.normalize(MEETING_TRANSCRIPT_SOURCE_ID, &value.to_string()),
        Err(IngestError::UnsupportedSchema { .. })
    ));
    value["schema"] = MEETING_TRANSCRIPT_SCHEMA_V1.into();
    value["turns"][0]["source_word_ids"][0] = "unknown-word".into();
    assert!(matches!(
        INGEST_SOURCE_REGISTRY.normalize(MEETING_TRANSCRIPT_SOURCE_ID, &value.to_string()),
        Err(IngestError::UnknownWordReference { .. })
    ));
    let mut input = file();
    input.capture_started_at = Some(u64::MAX);
    let mut host = FixtureHost::small(Fault::None);
    assert!(matches!(
        produce_meeting_transcript(&input, &options(), &mut host),
        Err(AudioError::Ingest(IngestError::TimestampOverflow { .. }))
    ));
}

#[test]
fn pending_import_can_retry_the_same_artifact_without_another_inference_run() {
    let mut host = FixtureHost::small(Fault::None);
    let artifact = produce_meeting_transcript(&file(), &options(), &mut host).unwrap();
    let calls = host.requests.clone();
    let mut authorizer = Authorizer {
        response: ConsentResponse::Missing,
        requests: Vec::new(),
    };
    assert_eq!(
        artifact.authorize_import(&mut authorizer).unwrap_err(),
        AudioError::BulkConsentRequired
    );
    authorizer.response = ConsentResponse::Allow;
    let imported = artifact.authorize_import(&mut authorizer).unwrap();
    assert_eq!(imported.artifact().json(), artifact.json());
    assert_eq!(authorizer.requests[0], authorizer.requests[1]);
    assert_eq!(host.requests, calls);
}

#[test]
fn incomplete_native_backend_refuses_before_the_decode_port() {
    let mut host = FixtureHost::small(Fault::BackendUnavailable);
    host.duration_ms = 0; // Decode would produce InvalidAudio if reached first.
    assert!(
        matches!(produce_meeting_transcript(&file(),&options(),&mut host),Err(AudioError::Host {stage,code}) if stage=="capabilities" && code=="ArtifactBackendUnavailable")
    );
}
