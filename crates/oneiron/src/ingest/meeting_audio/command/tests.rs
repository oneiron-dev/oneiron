//! Framing/refusal tests only. Real native evidence is recorded separately.

use super::*;

use std::process::Command;
use std::sync::Arc;

use crate::EntityId;
use crate::llm::media::{AiOperation, MediaCaps};
use crate::llm::run_admission::{
    BudgetLine, KeyCustody, LeaseUnit, MemoryReceipts, OfferBinding, OfferRoute, Payer,
    RunAdmission, RunDeclaration, WireSeat, offer_id, offer_place,
};
use crate::llm::{
    CallClass, CallEnvelope, CallPurpose, ModelId, ModelLocality, ModelTierRef, ResponseFormat,
    TierPrecedence,
};

/// The host's on-device rungs for the fixture route: one [`WireSeat`] per
/// physical model, built as production builds them in `meeting_transcript`.
/// The ASR rung serves the routed model; no unit ever runs in these tests.
fn fixture_seats(asr_model_id: &str) -> MeetingAudioSeats {
    let run = RunAdmission::new(
        format!("meeting-audio-test:{}", EntityId::now().to_hex()),
        RunDeclaration::undeclared(BudgetLine {
            limit_units: 1_000_000,
            reserve_units: 10_000,
            unit: LeaseUnit::tokens(),
        }),
        None,
        Arc::new(MemoryReceipts::default()),
    );
    let seat = |model_id: &str, operation: AiOperation| {
        let model = ModelId::new(model_id).expect("fixture model id");
        let route = OfferRoute::new("meeting-audio-fixture", "loopback").expect("fixture route");
        let offer = OfferBinding {
            offer: offer_id(
                &model,
                &offer_place(ModelLocality::OnDevice, route.origin()),
            ),
            model,
            route,
            locality: ModelLocality::OnDevice,
            payer: Payer::Local,
            credential_binding: None,
            catalog_revision: None,
            custody: KeyCustody::Keyless,
            rates: vec![],
            payer_person: None,
        };
        let envelope = CallEnvelope {
            scope: Default::default(),
            purpose: CallPurpose::Voice,
            class: CallClass::BestEffort,
            tier: TierPrecedence::for_purpose(&CallPurpose::Voice, ModelTierRef("global".into())),
            response_format: ResponseFormat::Text,
            locality: ModelLocality::OnDevice,
            host_keyless: false,
            host_paid: false,
            seat_effort: None,
        };
        WireSeat::new(
            run.clone(),
            offer,
            envelope,
            MediaCaps::for_operation(operation),
        )
    };
    MeetingAudioSeats {
        vad: seat("local/silero-vad@fixture-revision", AiOperation::Transcribe),
        diarization: seat(
            "pyannote/speaker-diarization-community-1@fixture-revision",
            AiOperation::Transcribe,
        ),
        asr: seat(
            &format!("{asr_model_id}@fixture-revision"),
            AiOperation::Transcribe,
        ),
        alignment: vec![seat(
            "Qwen/Qwen3-ForcedAligner-0.6B@fixture-revision",
            AiOperation::Transcribe,
        )],
        cleanup: seat("local/cleanup@fixture-revision", AiOperation::Text),
    }
}

fn frame(ok: bool, request_id: &str, body: &[u8]) -> Vec<u8> {
    let mut data = serde_json::to_vec(&json!({
        "protocol": PROTOCOL, "request_id": request_id, "body_bytes": body.len(),
        "ok": ok, "result": {},
        "error": {"code": "ForcedAlignmentUnavailable"},
    }))
    .expect("fixture header");
    data.push(b'\n');
    data.extend_from_slice(body);
    data
}

#[test]
fn mismatched_and_trailing_response_data_fail_closed() {
    for (stage, success, response) in [
        ("decode", true, frame(true, "other-request", b"")),
        ("decode", false, frame(true, "request", b"")),
        (
            "silero_vad",
            true,
            frame(true, "request", b"unexpected-pcm"),
        ),
        ("decode", true, {
            let mut response = frame(true, "request", b"pcm");
            response.push(1);
            response
        }),
    ] {
        assert!(matches!(parse_reply(stage, "request", success, response),
            Err(AudioError::Host { code, .. }) if code == "InvalidResponse"));
    }
}

#[test]
fn runtime_profile_reaches_the_real_bridge_without_loading_models() {
    let python = Command::new("python3")
        .args(["-c", "import sys; print(sys.executable)"])
        .output()
        .unwrap();
    assert!(python.status.success());
    let python = PathBuf::from(String::from_utf8(python.stdout).unwrap().trim());
    let directory = tempfile::tempdir().unwrap();
    let workspace = directory.path().canonicalize().unwrap();
    let profile = workspace.join("runtime.json");
    let data=br#"{"version":1,"packages":{},"asr":null,"alignment":null,"diarization":null,"cleanup":null}"#;
    std::fs::write(&profile, data).unwrap();
    let digest = sha256(data);
    let bridge = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../scripts/meeting-audio-native.py")
        .canonicalize()
        .unwrap();
    let config = CommandAudioConfig {
        python: python.clone(),
        bridge,
        ffmpeg: python,
        workspace: workspace.clone(),
        model_snapshot: workspace,
    };
    let route = AsrRoute {
        role: super::super::AsrRole::Asr,
        model_id: "mlx-community/Qwen3-ASR-1.7B-8bit".into(),
        tier: ProcessingTier::Local,
        route_receipt_ref: "fixture:configuration-not-authorization".into(),
    };
    let seats = fixture_seats(&route.model_id);
    let mut host = CommandMeetingAudioHost::new(config, route, seats)
        .unwrap()
        .with_runtime_profile(profile.clone(), digest.clone())
        .unwrap();
    let capabilities = host.inspect_capabilities().unwrap();
    assert_eq!(capabilities.runtime_profile_sha256, Some(digest));
    assert!(capabilities.runtime_helper_sha256.is_some());
    assert!(
        capabilities
            .runtime_components_sha256
            .contains_key("meeting_audio_process.py")
    );
    assert!(
        capabilities
            .runtime_components_sha256
            .contains_key("meeting_audio_ctc.py")
    );
    assert!(capabilities.alignment_languages.is_empty());
    assert!(capabilities.transcribe_pack_languages.is_empty());
    assert!(!capabilities.artifact_capable);
    assert!(!capabilities.e1_e3_evidence);
    assert!(
        matches!(host.preflight_artifact(),Err(AudioError::Host{code,..}) if code=="ArtifactBackendUnavailable")
    );
    std::fs::write(profile, b"changed").unwrap();
    assert!(
        matches!(host.inspect_capabilities(),Err(AudioError::Host{code,..}) if code=="ProfileDigestMismatch")
    );
}
