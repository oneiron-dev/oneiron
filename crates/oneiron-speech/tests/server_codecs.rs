//! The server speech rungs' codecs on oneiron-speech's public paths (L9-25
//! PR 3b): the VoxCPM2 render framing, the hosted clone wires and Soniox's
//! retriable errors. Each case pins what the server's own copy did before
//! the move.
use oneiron::llm::media::wav::pcm16_wav;
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
    RenderReply, Transcript, TranscriptPlacement, header_pieces, render_body,
};
use serde_json::{Value as JsonValue, json};

const RATE: u32 = 24_000;

/// A worker's reply: the header's length, the header, then `audio`.
fn framed_reply(header: &JsonValue, audio: &[u8]) -> Vec<u8> {
    let header = serde_json::to_vec(header).expect("a JSON value serializes");
    let length = u32::try_from(header.len()).expect("a short header");
    let mut reply = length.to_be_bytes().to_vec();
    reply.extend_from_slice(&header);
    reply.extend_from_slice(audio);
    reply
}

fn limits(max_header_bytes: u64) -> VoiceServingLimits {
    VoiceServingLimits {
        max_text_bytes: 1_000,
        max_ref_bytes: 1_000_000,
        max_queued_renders: 4,
        max_inflight_uploads: 1,
        upload_read_deadline_ms: 1_000,
        http_deadline_ms: 1_000,
        max_header_bytes,
    }
}

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
fn a_render_reply_hands_back_the_same_audio_however_it_is_chunked() {
    let target = json!({"voice_id": "voice-1", "owner": "owen"});
    let header = json!({"target": target, "sample_rate": RATE, "channels": 1});
    let audio = [1_u8, 2, 3, 4, 5, 6];
    let bytes = framed_reply(&header, &audio);
    for size in [1, 3, 7, bytes.len()] {
        let mut reply = RenderReply::new(&target, RATE, 1_024);
        let mut kept = Vec::new();
        for chunk in bytes.chunks(size) {
            kept.extend_from_slice(reply.push(chunk).unwrap());
        }
        assert!(reply.header_whole(), "chunks of {size}");
        assert_eq!(kept, audio, "chunks of {size}");
    }
}

#[test]
fn a_render_reply_refuses_a_bad_length_or_a_header_for_another_target() {
    let target = json!({"voice_id": "voice-1"});
    let empty = FatalLlmError::EmptyResponse;
    // A zero length, and one past the effective bound, before any header byte.
    let mut reply = RenderReply::new(&target, RATE, 1_024);
    assert!(is_fatal(&reply.push(&[0, 0, 0, 0]).unwrap_err(), &empty));
    let mut reply = RenderReply::new(&target, RATE, 8);
    assert!(is_fatal(
        &reply.push(&9_u32.to_be_bytes()).unwrap_err(),
        &empty
    ));
    // A header for another target, or at another rate, keeps no audio.
    for header in [
        json!({"target": {"voice_id": "voice-2"}, "sample_rate": RATE, "channels": 1}),
        json!({"target": target, "sample_rate": 16_000, "channels": 1}),
        json!({"target": target, "sample_rate": RATE, "channels": 2}),
    ] {
        let mut reply = RenderReply::new(&target, RATE, 1_024);
        let error = reply.push(&framed_reply(&header, &[1, 2])).unwrap_err();
        assert!(is_fatal(&error, &empty), "{header}");
    }
    // A reply that ends inside its header holds no render.
    let whole = framed_reply(
        &json!({"target": target, "sample_rate": RATE, "channels": 1}),
        &[],
    );
    let mut reply = RenderReply::new(&target, RATE, 1_024);
    assert!(reply.push(&whole[..whole.len() - 1]).unwrap().is_empty());
    assert!(!reply.header_whole());
}

#[test]
fn a_render_body_frames_the_header_then_the_transcript_then_the_clip() {
    let target = json!({"voice_id": "voice-1"});
    let clip = b"RIFF";
    let header_of = |body: &[u8]| -> (JsonValue, Vec<u8>) {
        let length = u32::from_be_bytes(body[..4].try_into().unwrap()) as usize;
        let header = serde_json::from_slice(&body[4..4 + length]).unwrap();
        (header, body[4 + length..].to_vec())
    };
    let framed = Transcript {
        text: "hello there",
        placement: TranscriptPlacement::Frame,
    };
    let body = render_body(&target, "speak this", framed, 1_024, clip).unwrap();
    let (header, rest) = header_of(&body);
    assert_eq!(
        header,
        json!({"target": target, "text": "speak this", "transcript_bytes": 11})
    );
    assert_eq!(rest, b"hello thereRIFF");
    let inline = Transcript {
        text: "hello there",
        placement: TranscriptPlacement::Header,
    };
    let body = render_body(&target, "speak this", inline, 1_024, clip).unwrap();
    let (header, rest) = header_of(&body);
    assert_eq!(
        header,
        json!({"target": target, "text": "speak this", "transcript": "hello there"})
    );
    assert_eq!(rest, clip);
    // A header past the effective decoder bound does not go.
    let error = render_body(&target, "speak this", inline, 8, clip).unwrap_err();
    assert!(is_fatal(&error, &FatalLlmError::InvalidRequest));
}

#[test]
fn a_transcript_too_long_for_the_header_rides_as_its_own_frame() {
    let target = json!({"voice_id": "voice-1"});
    let long = "a".repeat(200);
    let (transcript, pieces) =
        header_pieces(&target, "Short text.", "brief", limits(120), true).unwrap();
    assert_eq!(transcript.placement, TranscriptPlacement::Header);
    assert_eq!(pieces.concat(), "Short text.");
    let (transcript, pieces) =
        header_pieces(&target, "Short text.", &long, limits(120), true).unwrap();
    assert_eq!(transcript.placement, TranscriptPlacement::Frame);
    assert_eq!(pieces.concat(), "Short text.");
    // A worker that takes no frame: not one character fits beside it.
    let error = header_pieces(&target, "Short text.", &long, limits(120), false).unwrap_err();
    assert!(is_fatal(&error, &FatalLlmError::InvalidRequest));
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
