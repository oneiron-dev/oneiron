//! The hosted TTS request wire (Cartesia, ElevenLabs): the path, body,
//! version and voice rules `tts::hosted::build` shares, and the WAV reply
//! `tts::hosted::parse` reads. Each case pins what the two wires send.
use std::collections::BTreeMap;

use oneiron::llm::media::{AiOperation, MediaPart, MediaRequest, MediaVoice};
use oneiron::llm::{
    CallClass, CallEnvelope, CallPurpose, ModelTierRef, ResponseFormat, TierPrecedence,
};
use oneiron::{FatalLlmError, LlmError, ModelId, ModelLocality};
use oneiron_speech::tts::cartesia::CARTESIA_VERSION;
use oneiron_speech::tts::hosted::{HostedWire, PCM_RATE, build, parse};
use serde_json::json;

const MODEL: &str = "fake/media@v1";
const TEXT: &str = "Hello there.";
const VOICE: &str = "voice-123";

fn models(wire_model: &str) -> BTreeMap<ModelId, String> {
    BTreeMap::from([(ModelId::new(MODEL).expect("model"), wire_model.to_owned())])
}

fn call() -> MediaRequest {
    let purpose = CallPurpose::Other {
        name: "hosted-speech-wire".to_owned(),
    };
    MediaRequest {
        model: ModelId::new(MODEL).expect("model"),
        envelope: CallEnvelope {
            seat_effort: None,
            scope: Default::default(),
            tier: TierPrecedence::for_purpose(&purpose, ModelTierRef("media".into())),
            purpose,
            class: CallClass::BestEffort,
            response_format: ResponseFormat::Text,
            locality: ModelLocality::ThirdParty,
            host_keyless: false,
            host_paid: false,
        },
        operation: AiOperation::Speech,
        parts: vec![MediaPart::Text {
            text: TEXT.to_owned(),
        }],
        references: Vec::new(),
        mask: None,
        params: BTreeMap::from([("voice".to_owned(), json!(VOICE))]),
        voice: None,
    }
}

fn is_fatal(error: &LlmError, want: &FatalLlmError) -> bool {
    matches!(error, LlmError::Fatal(fatal) if fatal == want)
}

#[test]
fn cartesia_build_pins_path_body_and_version() {
    assert_eq!(CARTESIA_VERSION, "2026-08-14");
    assert_eq!(PCM_RATE, 24_000);
    let models = models("sonic-2");
    let mut request = call();
    let (text, path, body) = build(HostedWire::Cartesia, &models, &mut request).expect("build");
    assert_eq!(text, TEXT);
    assert_eq!(path, "/tts/bytes");
    assert_eq!(
        body,
        json!({
            "model_id": "sonic-2",
            "transcript": TEXT,
            "voice": {"mode": "id", "id": VOICE},
            "output_format": {
                "container": "raw",
                "encoding": "pcm_s16le",
                "sample_rate": 24_000,
            },
        })
    );
}

#[test]
fn elevenlabs_build_pins_path_and_body() {
    let models = models("eleven_flash_v2_5");
    let mut request = call();
    let (text, path, body) = build(HostedWire::ElevenLabs, &models, &mut request).expect("build");
    assert_eq!(text, TEXT);
    assert_eq!(path, "/v1/text-to-speech/voice-123?output_format=pcm_24000");
    assert_eq!(body, json!({"model_id": "eleven_flash_v2_5", "text": TEXT}));
}

#[test]
fn typed_voice_builds_the_same_cartesia_call() {
    let models = models("sonic-2");
    let want = json!({
        "model_id": "sonic-2",
        "transcript": TEXT,
        "voice": {"mode": "id", "id": VOICE},
        "output_format": {
            "container": "raw",
            "encoding": "pcm_s16le",
            "sample_rate": 24_000,
        },
    });
    for voice in [
        MediaVoice::Stock {
            name: VOICE.to_owned(),
        },
        MediaVoice::Clone {
            id: VOICE.to_owned(),
        },
    ] {
        assert_eq!(voice.wire_id(), Some(VOICE));
        let mut request = call();
        request.params.clear();
        request.voice = Some(voice);
        let (text, path, body) = build(HostedWire::Cartesia, &models, &mut request).expect("typed");
        assert_eq!(text, TEXT);
        assert_eq!(path, "/tts/bytes");
        assert_eq!(body, want);
    }
}

#[test]
fn extra_params_ride_beside_the_fixed_fields() {
    for (wire, wire_model) in [
        (HostedWire::Cartesia, "sonic-2"),
        (HostedWire::ElevenLabs, "eleven_flash_v2_5"),
    ] {
        let models = models(wire_model);
        let mut request = call();
        request.params.insert("speed".to_owned(), json!(1.1));
        let (_, _, body) = build(wire, &models, &mut request).expect("build");
        assert_eq!(body["speed"], json!(1.1), "{wire:?}");
        assert_eq!(body["model_id"], json!(wire_model), "{wire:?}");
    }
}

#[test]
fn params_naming_fixed_fields_are_refused() {
    for (wire, wire_model, field) in [
        (HostedWire::Cartesia, "sonic-2", "model_id"),
        (HostedWire::Cartesia, "sonic-2", "transcript"),
        (HostedWire::ElevenLabs, "eleven_flash_v2_5", "model_id"),
        (HostedWire::ElevenLabs, "eleven_flash_v2_5", "text"),
    ] {
        let models = models(wire_model);
        let mut request = call();
        request.params.insert(field.to_owned(), json!("other"));
        let error = build(wire, &models, &mut request).expect_err("fixed field");
        assert!(
            is_fatal(&error, &FatalLlmError::InvalidRequest),
            "{wire:?} {field}"
        );
    }
}

#[test]
fn unsafe_or_missing_voice_is_refused() {
    let invalid = FatalLlmError::InvalidRequest;
    for (wire, wire_model) in [
        (HostedWire::Cartesia, "sonic-2"),
        (HostedWire::ElevenLabs, "eleven_flash_v2_5"),
    ] {
        let models = models(wire_model);
        for voice in ["", "a/b", "a?b", "a b", "../x"] {
            let mut request = call();
            request.params.insert("voice".to_owned(), json!(voice));
            let error = build(wire, &models, &mut request).expect_err("voice");
            assert!(is_fatal(&error, &invalid), "{wire:?} {voice:?}");
        }
        let mut request = call();
        request.params.clear();
        let error = build(wire, &models, &mut request).expect_err("no voice");
        assert!(is_fatal(&error, &invalid), "{wire:?} no voice");
        let mut request = call();
        request.voice = Some(MediaVoice::Stock {
            name: VOICE.to_owned(),
        });
        let error = build(wire, &models, &mut request).expect_err("both");
        assert!(is_fatal(&error, &invalid), "{wire:?} both");
    }
}

#[test]
fn unknown_model_is_refused() {
    for wire in [HostedWire::Cartesia, HostedWire::ElevenLabs] {
        let models = BTreeMap::from([(
            ModelId::new("fake/other@v1").expect("model"),
            "sonic-2".to_owned(),
        )]);
        let mut request = call();
        let error = build(wire, &models, &mut request).expect_err("unknown");
        assert!(is_fatal(&error, &FatalLlmError::InvalidRequest), "{wire:?}");
    }
}

#[test]
fn parse_wraps_pcm_in_a_wav_and_counts_characters() {
    let headers = BTreeMap::new();
    let model = ModelId::new(MODEL).expect("model");
    let response = parse(200, &headers, &[1, 2, 3, 4, 5, 6], model.clone(), TEXT).expect("parse");
    let [MediaPart::Audio { media_type, bytes }] = &response.parts[..] else {
        panic!("an audio part");
    };
    assert_eq!(media_type, "audio/wav");
    assert_eq!(bytes.len(), 44 + 6);
    let rate = u32::from_le_bytes(bytes[24..28].try_into().expect("rate"));
    assert_eq!(rate, 24_000);
    assert_eq!(&bytes[44..], &[1, 2, 3, 4, 5, 6]);
    let want = u64::try_from(TEXT.chars().count()).expect("chars");
    assert_eq!(response.usage.characters, want);
    let odd = parse(200, &headers, &[1, 2, 3, 4, 5, 6, 7], model.clone(), TEXT).expect("odd");
    let [MediaPart::Audio { bytes, .. }] = &odd.parts[..] else {
        panic!("an audio part");
    };
    assert_eq!(bytes.len(), 44 + 6);
    assert_eq!(&bytes[44..], &[1, 2, 3, 4, 5, 6]);
    let error = parse(200, &headers, &[], model, TEXT).expect_err("empty");
    assert!(is_fatal(&error, &FatalLlmError::EmptyResponse));
}

#[test]
fn parse_refuses_a_non_2xx_status() {
    let headers = BTreeMap::new();
    let model = ModelId::new(MODEL).expect("model");
    let body = json!({"error": {"message": "bad key"}});
    let bytes = serde_json::to_vec(&body).expect("json");
    let error = parse(401, &headers, &bytes, model, TEXT).expect_err("401");
    assert!(is_fatal(&error, &FatalLlmError::Auth), "{error:?}");
}
