//! Framing/refusal tests only. Real native evidence is recorded separately.

use super::*;

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
        stage_timeout: std::time::Duration::from_secs(30),
    };
    let route = AsrRoute {
        role: super::super::AsrRole::Asr,
        model_id: "mlx-community/Qwen3-ASR-1.7B-8bit".into(),
        tier: ProcessingTier::Local,
        route_receipt_ref: "fixture:configuration-not-authorization".into(),
    };
    let mut host = CommandMeetingAudioHost::new(config, route)
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
