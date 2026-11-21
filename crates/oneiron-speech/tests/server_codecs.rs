//! The server speech rungs' codecs on oneiron-speech's public paths (L9-25
//! PR 3b): the VoxCPM2 render framing, the hosted clone wires and Soniox's
//! retriable errors. Each case pins what the server's own copy did before
//! the move.
use oneiron::llm::media::wav::pcm16_wav;
use oneiron::voice_cascade::our_voice::VoiceClientFrame;
use oneiron::voice_cascade::voxcpm2::VoiceServingLimits;
use oneiron::voice_identity::ref_bank::VoiceRegisterClip;
use oneiron::{FatalLlmError, LlmError};
use oneiron_speech::asr::soniox::retriable_error;
use oneiron_speech::design::elevenlabs::is_verified;
use oneiron_speech::design::hosted::{
    CloneFile, VendorVoice, clone_form, cloned_voice, voice_path,
};
use oneiron_speech::tts::hosted::HostedWire;
use oneiron_speech::tts::voxcpm2::{
    VOICE_GENERATION, start_frame, started_matches, text_pieces, worker_error,
};
use serde_json::{Value as JsonValue, json};

const RATE: u32 = 24_000;

fn clip(media_type: &str, audio: &[u8]) -> VoiceRegisterClip {
    VoiceRegisterClip {
        register: "neutral".to_owned(),
        media_type: media_type.to_owned(),
        audio: audio.to_vec(),
        transcript: String::new(),
    }
}

fn is_fatal(error: &LlmError, want: &FatalLlmError) -> bool {
    matches!(error, LlmError::Fatal(fatal) if fatal == want)
}

#[test]
fn text_pieces_fit_the_text_frame_bound_and_keep_the_order() {
    let text = "The harbour at dawn is quiet and bright, and the boats are still.";
    let limits = VoiceServingLimits {
        max_text_bytes: 16,
        max_ref_bytes: 1_000_000,
        max_queued_renders: 4,
        max_inflight_uploads: 1,
        upload_read_deadline_ms: 1_000,
        http_deadline_ms: 1_000,
        max_header_bytes: 1_024,
    };
    let pieces = text_pieces(text, limits).expect("pieces");
    let renders = pieces.len();
    assert!(renders >= 2, "two renders, got {renders}");
    assert_eq!(pieces.concat(), text, "the order keeps");
    for piece in &pieces {
        let frame = VoiceClientFrame::Text {
            generation: VOICE_GENERATION,
            text: (*piece).to_owned(),
        }
        .to_json();
        assert!(
            frame.len() as u64 <= limits.max_header_bytes,
            "a frame fits: {frame:?}"
        );
    }
    let overhead = VoiceClientFrame::Text {
        generation: VOICE_GENERATION,
        text: String::new(),
    }
    .to_json()
    .len() as u64;
    let tight = VoiceServingLimits {
        max_header_bytes: overhead + 4,
        ..limits
    };
    let fitted = text_pieces(text, tight).expect("tight pieces");
    assert_eq!(fitted.concat(), text, "the tight order keeps");
    for piece in &fitted {
        let frame = VoiceClientFrame::Text {
            generation: VOICE_GENERATION,
            text: (*piece).to_owned(),
        }
        .to_json();
        assert!(
            frame.len() as u64 <= tight.max_header_bytes,
            "a tight frame fits: {frame:?}"
        );
    }
    let impossible = VoiceServingLimits {
        max_header_bytes: overhead,
        ..limits
    };
    let error = text_pieces("hi", impossible).expect_err("no character fits");
    assert!(
        is_fatal(&error, &FatalLlmError::InvalidRequest),
        "one character refused: {error:?}"
    );
}

#[test]
fn start_frame_refuses_metadata_past_the_bound() {
    let target = json!({"voice_id": "voice-1"});
    let audio = b"RIFF0000WAVEfmt ";
    let start = start_frame(&target, "hello", audio, 1_024).expect("a start fits");
    let frame: JsonValue = serde_json::from_str(&start).expect("start JSON");
    assert_eq!(frame["type"].as_str(), Some("start"));
    assert_eq!(frame["transcript_bytes"].as_u64(), Some(5));
    assert_eq!(frame["reference_bytes"].as_u64(), Some(audio.len() as u64));
    let error = start_frame(&target, "hello", audio, 8).expect_err("a header past 8");
    assert!(
        is_fatal(&error, &FatalLlmError::InvalidRequest),
        "a long frame refuses: {error:?}"
    );
    let long = "a".repeat(200);
    let error = start_frame(&target, &long, audio, 120).expect_err("a long transcript");
    assert!(
        is_fatal(&error, &FatalLlmError::InvalidRequest),
        "a long transcript refuses: {error:?}"
    );
}

#[test]
fn started_matches_needs_the_same_target_rate_and_mono() {
    let target = json!({"voice_id": "voice-1"});
    let same = json!({
        "generation": 1,
        "target": target,
        "sample_rate": RATE,
        "channels": 1
    });
    assert!(started_matches(&same, &target, RATE), "the same pins match");
    for meta in [
        json!({"generation": 2, "target": target, "sample_rate": RATE, "channels": 1}),
        json!({"generation": 1, "target": {"voice_id": "voice-2"}, "sample_rate": RATE, "channels": 1}),
        json!({"generation": 1, "target": target, "sample_rate": 16_000, "channels": 1}),
        json!({"generation": 1, "target": target, "sample_rate": RATE, "channels": 2}),
    ] {
        assert!(
            !started_matches(&meta, &target, RATE),
            "another pins refuse: {meta}"
        );
    }
}

#[test]
fn a_render_failure_is_retryable_and_others_fatal() {
    let retry = worker_error("render_failed");
    assert!(
        matches!(
            retry,
            LlmError::Retryable(oneiron::RetryableLlmError::ServerError)
        ),
        "a failed render retries: {retry:?}"
    );
    for code in [
        "invalid_request",
        "stale_target",
        "not_started",
        "anything-else",
    ] {
        let fatal = worker_error(code);
        assert!(
            is_fatal(&fatal, &FatalLlmError::InvalidRequest),
            "{code} refuses: {fatal:?}"
        );
    }
}

#[test]
fn each_hosted_wire_builds_its_clone_form_and_reads_its_reply() {
    let invalid = FatalLlmError::InvalidRequest;
    let clips = [clip("audio/mpeg", b"one"), clip("audio/ogg", b"two")];
    // ElevenLabs takes every clip, each a file named by its place.
    let form = clone_form(HostedWire::ElevenLabs, "owen", &clips, None).unwrap();
    assert_eq!(form.path, "/v1/voices/add");
    assert_eq!(form.texts, [("name", "owen".to_owned())]);
    let names: Vec<_> = form
        .files
        .iter()
        .map(|file| {
            (
                file.field,
                file.file_name.as_str(),
                file.media_type.as_str(),
            )
        })
        .collect();
    assert_eq!(
        names,
        [
            ("files", "clip-0.mp3", "audio/mpeg"),
            ("files", "clip-1.ogg", "audio/ogg"),
        ]
    );
    // Cartesia takes one clip and its language; clips that are no PCM16 WAV
    // do not join, so the first goes alone.
    let form = clone_form(HostedWire::Cartesia, "owen", &clips, Some("en")).unwrap();
    assert_eq!(form.path, "/voices/clone");
    assert_eq!(
        form.texts,
        [("name", "owen".to_owned()), ("language", "en".to_owned())]
    );
    assert_eq!(
        form.files,
        [CloneFile {
            field: "clip",
            file_name: "clip-0.mp3".to_owned(),
            media_type: "audio/mpeg".to_owned(),
            bytes: b"one".to_vec(),
        }]
    );
    // PCM16 WAVs at one rate join into one clip.
    let wavs = [
        clip("audio/x-wav", &pcm16_wav(RATE, 1, &[1, 2, 3, 4]).unwrap()),
        clip("audio/x-wav", &pcm16_wav(RATE, 1, &[5, 6]).unwrap()),
    ];
    let form = clone_form(HostedWire::Cartesia, "owen", &wavs, Some("en")).unwrap();
    assert_eq!(
        form.files,
        [CloneFile {
            field: "clip",
            file_name: "clip-0.wav".to_owned(),
            media_type: "audio/wav".to_owned(),
            bytes: pcm16_wav(RATE, 1, &[1, 2, 3, 4, 5, 6]).unwrap(),
        }]
    );
    // No clip, or no language for Cartesia, sends nothing.
    for (wire, clips, language) in [
        (HostedWire::Cartesia, &clips[..], Some("  ")),
        (HostedWire::Cartesia, &clips[..], None),
        (HostedWire::Cartesia, &[][..], Some("en")),
        (HostedWire::ElevenLabs, &[][..], None),
    ] {
        let error = clone_form(wire, "owen", clips, language).unwrap_err();
        assert!(is_fatal(&error, &invalid), "{wire:?} {language:?}");
    }
    // Each wire's reply names the voice in its own field; only ElevenLabs
    // holds one for verification.
    assert_eq!(
        cloned_voice(
            HostedWire::ElevenLabs,
            &json!({"voice_id": "voice_1", "requires_verification": true}),
        )
        .unwrap(),
        VendorVoice {
            id: "voice_1".to_owned(),
            awaiting_verification: true,
        }
    );
    assert_eq!(
        cloned_voice(
            HostedWire::Cartesia,
            &json!({"id": "voice-2", "requires_verification": true}),
        )
        .unwrap(),
        VendorVoice {
            id: "voice-2".to_owned(),
            awaiting_verification: false,
        }
    );
    for (wire, body) in [
        (HostedWire::Cartesia, json!({"id": "a/b"})),
        (HostedWire::Cartesia, json!({"voice_id": "voice-2"})),
        (HostedWire::ElevenLabs, json!({"voice_id": ""})),
    ] {
        let error = cloned_voice(wire, &body).unwrap_err();
        assert!(is_fatal(&error, &FatalLlmError::EmptyResponse), "{body}");
    }
    // A voice's path, only for an id safe in it.
    assert_eq!(
        voice_path(HostedWire::Cartesia, "voice-2").unwrap(),
        "/voices/voice-2"
    );
    assert_eq!(
        voice_path(HostedWire::ElevenLabs, "voice_1").unwrap(),
        "/v1/voices/voice_1"
    );
    for id in ["", "a b", "a/b", "a?b"] {
        let error = voice_path(HostedWire::ElevenLabs, id).unwrap_err();
        assert!(is_fatal(&error, &invalid), "{id:?}");
    }
    assert!(is_verified(
        &json!({"voice_verification": {"is_verified": true}})
    ));
    assert!(is_verified(
        &json!({"voice_verification": {"requires_verification": false}})
    ));
    assert!(!is_verified(&json!({
        "voice_verification": {"requires_verification": true, "is_verified": false}
    })));
    assert!(!is_verified(&json!({})));
}

#[test]
fn soniox_retries_only_a_request_timeout_or_its_own_failure() {
    let worded = |frame: JsonValue| -> Option<String> {
        retriable_error(&frame).map(|error| match error {
            oneiron::Error::InvalidConfig(message) => message,
            other => panic!("not a config refusal: {other}"),
        })
    };
    assert_eq!(
        worded(json!({"error_code": 503, "error_message": "busy"})).as_deref(),
        Some("soniox: provider error: 503: busy")
    );
    assert_eq!(
        worded(json!({"error_code": 408})).as_deref(),
        Some("soniox: provider error: 408: unnamed")
    );
    for frame in [
        json!({"error_code": 400, "error_message": "bad audio"}),
        json!({"error_code": 401}),
        json!({"error_message": "no code"}),
        json!({"tokens": []}),
    ] {
        assert_eq!(worded(frame.clone()), None, "{frame}");
    }
}
