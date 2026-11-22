//! The hosted TTS wires on the loopback wire: the exact request line,
//! headers and JSON body each backend sends, and the version header the
//! Cartesia leg adds. Each case pins what `media.rs` builds.
use std::collections::BTreeMap;

use oneiron::llm::media::{AiOperation, MediaBackend, MediaPart, MediaRequest};
use oneiron::llm::{
    CallClass, CallEnvelope, CallPurpose, ModelTierRef, ResponseFormat, TierPrecedence,
};
use oneiron::{BudgetExhaustionPolicy, BudgetGuard, BudgetLease, ModelId, ModelLocality};
use oneiron_speech::tts::cartesia::CARTESIA_VERSION;
use oneiron_speech::tts::hosted::HostedWire;
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::hosted_speech::HostedSpeech;
use super::http::{KeyStyle, ProviderHttp};
use super::media::cartesia;
use crate::config::models::{ModelsConfig, ProviderConfig};

const MODEL: &str = "fake/media@v1";
const TEXT: &str = "Hello there.";
const VOICE: &str = "voice-123";

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

fn lease() -> BudgetLease {
    BudgetGuard::with_reserve_units(
        "hosted-speech-wire",
        1_000_000,
        1,
        BudgetExhaustionPolicy::Suspend,
    )
    .admit()
    .expect("admit")
    .lease
}

fn provider_for(kind: &str, base_url: &str) -> ProviderConfig {
    let text = format!(
        "[providers.probe]\nkind = \"{kind}\"\nbase_url = \"{base_url}\"\nkey_env = \"HOME\"\n"
    );
    ModelsConfig::from_toml(&text, None)
        .expect("config")
        .providers
        .get("probe")
        .expect("provider")
        .clone()
}

struct Captured {
    line: String,
    headers: BTreeMap<String, String>,
    body: Vec<u8>,
}

async fn loopback(reply: Vec<u8>) -> (String, tokio::sync::oneshot::Receiver<Captured>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let base_url = format!("http://{}", listener.local_addr().expect("addr"));
    let (sender, receiver) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.expect("accept");
        let mut head = Vec::new();
        let mut chunk = [0; 4096];
        while !head.windows(4).any(|window| window == b"\r\n\r\n") {
            let read = socket.read(&mut chunk).await.expect("read");
            if read == 0 {
                break;
            }
            head.extend_from_slice(&chunk[..read]);
        }
        let end = head
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .expect("head");
        let header = String::from_utf8_lossy(&head[..end]).into_owned();
        let mut lines = header.split("\r\n");
        let line = lines.next().expect("line").to_owned();
        let mut headers = BTreeMap::new();
        for text in lines {
            if text.is_empty() {
                continue;
            }
            let (name, value) = text.split_once(':').expect("header");
            headers.insert(name.trim().to_ascii_lowercase(), value.trim().to_owned());
        }
        let length = headers
            .get("content-length")
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or(0);
        let mut body = head[end + 4..].to_vec();
        while body.len() < length {
            let read = socket.read(&mut chunk).await.expect("body");
            if read == 0 {
                break;
            }
            body.extend_from_slice(&chunk[..read]);
        }
        body.truncate(length);
        let status = format!("HTTP/1.1 200 OK\r\ncontent-length: {}\r\n\r\n", reply.len());
        socket.write_all(status.as_bytes()).await.expect("status");
        socket.write_all(&reply).await.expect("reply");
        let _ = sender.send(Captured {
            line,
            headers,
            body,
        });
    });
    (base_url, receiver)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cartesia_sends_its_path_version_key_and_body() {
    let (base_url, seen) = loopback(vec![1, 2, 3, 4]).await;
    let provider = provider_for("cartesia", &base_url);
    let models = BTreeMap::from([(ModelId::new(MODEL).expect("model"), "sonic-2".to_owned())]);
    let http = ProviderHttp::new(&cartesia(&provider), KeyStyle::ApiKeyHeader).expect("client");
    let backend = HostedSpeech {
        http,
        wire: HostedWire::Cartesia,
        models,
    };
    let lease = lease();
    let response = backend.run(call(), &lease).await.expect("speech");
    let captured = seen.await.expect("request");
    assert_eq!(captured.line, "POST /tts/bytes HTTP/1.1");
    assert_eq!(
        captured.headers.get("cartesia-version").map(String::as_str),
        Some(CARTESIA_VERSION)
    );
    assert_eq!(
        captured.headers.get("cartesia-version").map(String::as_str),
        Some("2026-08-14")
    );
    let home = std::env::var("HOME").expect("HOME");
    assert_eq!(captured.headers.get("x-api-key"), Some(&home));
    assert!(!captured.headers.contains_key("authorization"));
    assert!(!captured.headers.contains_key("xi-api-key"));
    let content_type = captured.headers.get("content-type").expect("content-type");
    assert!(
        content_type.starts_with("application/json"),
        "{content_type}"
    );
    let body: serde_json::Value = serde_json::from_slice(&captured.body).expect("json");
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
    assert!(
        matches!(
            &response.parts[..],
            [MediaPart::Audio { media_type, .. }] if media_type == "audio/wav"
        ),
        "{:?}",
        response.parts
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn elevenlabs_sends_its_path_named_key_and_body() {
    let (base_url, seen) = loopback(vec![1, 2, 3, 4]).await;
    let provider = provider_for("elevenlabs", &base_url);
    let models = BTreeMap::from([(
        ModelId::new(MODEL).expect("model"),
        "eleven_flash_v2_5".to_owned(),
    )]);
    let http = ProviderHttp::new(&provider, KeyStyle::Named("xi-api-key")).expect("client");
    let backend = HostedSpeech {
        http,
        wire: HostedWire::ElevenLabs,
        models,
    };
    let lease = lease();
    let response = backend.run(call(), &lease).await.expect("speech");
    let captured = seen.await.expect("request");
    assert_eq!(
        captured.line,
        "POST /v1/text-to-speech/voice-123?output_format=pcm_24000 HTTP/1.1"
    );
    let home = std::env::var("HOME").expect("HOME");
    assert_eq!(captured.headers.get("xi-api-key"), Some(&home));
    assert!(!captured.headers.contains_key("cartesia-version"));
    assert!(!captured.headers.contains_key("x-api-key"));
    assert!(!captured.headers.contains_key("authorization"));
    let content_type = captured.headers.get("content-type").expect("content-type");
    assert!(
        content_type.starts_with("application/json"),
        "{content_type}"
    );
    let body: serde_json::Value = serde_json::from_slice(&captured.body).expect("json");
    assert_eq!(body, json!({"model_id": "eleven_flash_v2_5", "text": TEXT}));
    assert!(
        matches!(
            &response.parts[..],
            [MediaPart::Audio { media_type, .. }] if media_type == "audio/wav"
        ),
        "{:?}",
        response.parts
    );
}

#[test]
fn owner_set_cartesia_version_is_kept() {
    let base = provider_for("cartesia", "http://127.0.0.1:9");
    let mut owned = base.clone();
    owned
        .headers
        .insert("cartesia-version".to_owned(), "2025-01-01".to_owned());
    let kept = cartesia(&owned);
    let versions: Vec<_> = kept
        .headers
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case("cartesia-version"))
        .collect();
    assert_eq!(versions.len(), 1);
    assert_eq!(versions[0].1, "2025-01-01");
    let added = cartesia(&base);
    let versions: Vec<_> = added
        .headers
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case("cartesia-version"))
        .collect();
    assert_eq!(versions.len(), 1);
    assert_eq!(
        added.headers.get("Cartesia-Version").map(String::as_str),
        Some(CARTESIA_VERSION)
    );
    assert_eq!(
        added.headers.get("Cartesia-Version").map(String::as_str),
        Some("2026-08-14")
    );
}
