#![cfg(oneiron_test_support)]

use std::sync::{Arc, Mutex};

use futures_util::{SinkExt, StreamExt};
use oneiron::llm::media::{AiOperation, MediaPart, MediaRequest, MediaVoice};
use oneiron::voice_cascade::media::BankVoiceBinding;
use oneiron::voice_identity::ref_bank::{
    VoiceRefOrigin, VoiceRefPack, VoiceRefSubjectKind, VoiceRegisterClip, VoiceRenderDecision,
};
use oneiron::voice_identity::{VoiceConsentBasis, VoiceConsentState};
use oneiron::{
    CallClass, CallEnvelope, CallPurpose, EntityId, FatalLlmError, LlmError, ModelId,
    ModelLocality, ModelTierRef, ResponseFormat, TierPrecedence, Vault, VaultConfig,
};
use oneiron_server::config::models::ModelsConfig;
use oneiron_server::models::ModelRuntime;
use serde_json::{Value, json};
use tokio::io::AsyncWriteExt;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::handshake::server::{Request, Response};
use tokio_tungstenite::tungstenite::http::StatusCode;

const SAMPLE_RATE: u32 = 48_000;
const VOICE_ID: &str = "owner-voice";
const PROVIDER: &str = "voxcpm2";
const TRANSCRIPT: &str = "banked sample";
const CLIP: &[u8] = b"RIFF0000WAVEfmt ";
const TEXT: &str = "The harbour at dawn is quiet and bright, and the boats are still.";

type Connections = Arc<Mutex<Vec<(String, bool)>>>;
type SeenFrames = Arc<Mutex<Vec<StubSeen>>>;
type SentPcm = Arc<Mutex<Vec<Vec<u8>>>>;
type HandshakeFailures = Arc<Mutex<Vec<String>>>;
type ServerWs = tokio_tungstenite::WebSocketStream<tokio::net::TcpStream>;

/// What the stub worker does besides answering every frame.
#[derive(Clone)]
enum StubPlan {
    /// Answers every frame.
    Answer,
    /// Withdraws the owner's consent when the first text arrives.
    WithdrawAtFirstText(Arc<Vault>, EntityId),
    /// Withdraws the owner's consent before it answers `start`.
    WithdrawAtStart(Arc<Vault>, EntityId),
    /// Answers `start` with a frame whose reserved bit is set.
    ReservedBitAtStart,
    /// Answers `start` with a `started` past the call's metadata ceiling
    /// (the stub's `max_header_bytes`, 32768), under the audio frame bound.
    OversizedStarted,
}

#[derive(Debug, Clone)]
enum StubSeen {
    Start {
        generation: u64,
        target: Value,
        transcript: Vec<u8>,
        reference: Vec<u8>,
    },
    Text {
        generation: u64,
        text: String,
    },
    End {
        generation: u64,
    },
}

fn banked_vault() -> (tempfile::TempDir, Arc<Vault>, EntityId) {
    let dir = tempfile::tempdir().expect("fixture dir");
    let vault = Arc::new(Vault::open(dir.path(), VaultConfig::device()).expect("vault"));
    let owner = EntityId::now();
    vault
        .record_voice_render_consent(&VoiceRenderDecision {
            event_id: "owner-grant".into(),
            voice_id: VOICE_ID.into(),
            subject: owner,
            subject_kind: VoiceRefSubjectKind::Person,
            recorded_by: owner,
            occurred_at: 1,
            reach: ModelLocality::OwnServer,
            basis: Some(VoiceConsentBasis::ConversationalNotice {
                notice: "render".into(),
            }),
            state: VoiceConsentState::Granted,
        })
        .expect("grant");
    vault
        .store_voice_ref_pack(&VoiceRefPack {
            version: 1,
            id: "owner-ref".into(),
            voice_id: VOICE_ID.into(),
            owner,
            origin: VoiceRefOrigin::Captured {
                consent_event_ref: "owner-grant".into(),
            },
            clips: vec![VoiceRegisterClip {
                register: "neutral".into(),
                media_type: "audio/wav".into(),
                audio: CLIP.to_vec(),
                transcript: TRANSCRIPT.into(),
            }],
        })
        .expect("pack");
    (dir, vault, owner)
}

fn reference_voice(vault: &Vault) -> MediaVoice {
    let (clip, fence) = vault
        .fenced_voice_reference(VOICE_ID, PROVIDER, None, ModelLocality::OwnServer)
        .expect("fenced");
    let revision = BankVoiceBinding::reference_revision(&fence);
    MediaVoice::Reference {
        voice_id: VOICE_ID.into(),
        owner: fence.owner.to_hex(),
        register: clip.register.clone(),
        revision,
        media_type: clip.media_type.clone(),
        audio: clip.audio.clone(),
        transcript: clip.transcript.clone(),
    }
}

fn speech_request(voice: MediaVoice) -> MediaRequest {
    let purpose = CallPurpose::Other {
        name: "voxcpm2-speech-test".into(),
    };
    let tier = TierPrecedence::for_purpose(&purpose, ModelTierRef("speech".into()));
    MediaRequest {
        model: ModelId::new("voxcpm2/voxcpm2@v1").expect("model id"),
        envelope: CallEnvelope {
            seat_effort: None,
            scope: Default::default(),
            tier,
            purpose,
            class: CallClass::BestEffort,
            response_format: ResponseFormat::Text,
            locality: ModelLocality::OwnServer,
            host_keyless: false,
            host_paid: false,
        },
        operation: AiOperation::Speech,
        parts: vec![MediaPart::Text { text: TEXT.into() }],
        references: Vec::new(),
        mask: None,
        params: [("response_format".to_owned(), json!("wav"))]
            .into_iter()
            .collect(),
        voice: Some(voice),
    }
}

fn stub_limits() -> Value {
    json!({
        "max_text_bytes": 16,
        "max_ref_bytes": 16777216,
        "max_queued_renders": 16,
        "max_inflight_uploads": 2,
        "upload_read_deadline_ms": 5000,
        "http_deadline_ms": 45000,
        "max_header_bytes": 32768
    })
}

fn ready_text() -> String {
    let limits = stub_limits();
    let target = json!({
        "model": "VoxCPM2",
        "checkpoint": "pinned-revision",
        "boot_id": "warm-worker",
        "sample_rate": SAMPLE_RATE,
        "limits": limits.clone(),
        "transcript_frame": true
    });
    json!({
        "type": "ready",
        "version": 1,
        "target": target,
        "capabilities": {
            "input": "full",
            "streaming": false,
            "alignment": "none",
            "remote_cancel": "before_start",
            "max_text_bytes": limits["max_text_bytes"].clone()
        }
    })
    .to_string()
}

fn stripped(text: &str) -> String {
    text.chars().filter(|c| !c.is_whitespace()).collect()
}

async fn read_binary(ws: &mut ServerWs) -> Option<Vec<u8>> {
    loop {
        let message = ws.next().await?;
        match message {
            Ok(Message::Binary(bytes)) => return Some(bytes.to_vec()),
            Ok(Message::Ping(_) | Message::Pong(_) | Message::Frame(_)) => continue,
            _ => return None,
        }
    }
}

fn withdraw_consent(vault: &Vault, owner: EntityId) {
    let _ = vault.record_voice_render_consent(&VoiceRenderDecision {
        event_id: "owner-withdrawn".into(),
        voice_id: VOICE_ID.into(),
        subject: owner,
        subject_kind: VoiceRefSubjectKind::Person,
        recorded_by: owner,
        occurred_at: 2,
        reach: ModelLocality::OwnServer,
        basis: Some(VoiceConsentBasis::ConversationalNotice {
            notice: "render".into(),
        }),
        state: VoiceConsentState::Withdrawn,
    });
}

async fn handle_start(
    ws: &mut ServerWs,
    frame: &Value,
    seen: &SeenFrames,
    plan: &StubPlan,
) -> bool {
    let generation = frame.get("generation").and_then(Value::as_u64).unwrap_or(0);
    let target = frame.get("target").cloned().unwrap_or(Value::Null);
    let Some(transcript) = read_binary(ws).await else {
        return false;
    };
    let Some(reference) = read_binary(ws).await else {
        return false;
    };
    if let Ok(mut guard) = seen.lock() {
        guard.push(StubSeen::Start {
            generation,
            target: target.clone(),
            transcript,
            reference,
        });
    }
    match plan {
        StubPlan::WithdrawAtStart(vault, owner) => withdraw_consent(vault, *owner),
        StubPlan::ReservedBitAtStart => {
            // FIN, RSV1 and the text opcode, an empty payload, unmasked: no
            // extension was negotiated, so the reserved bit is a protocol
            // error at the client.
            let raw = ws.get_mut();
            return raw.write_all(&[0xC1, 0x00]).await.is_ok() && raw.flush().await.is_ok();
        }
        _ => {}
    }
    let mut started = json!({
        "type": "started",
        "generation": generation,
        "target": target,
        "sample_rate": SAMPLE_RATE,
        "channels": 1
    });
    if matches!(plan, StubPlan::OversizedStarted) {
        started["pad"] = Value::String("x".repeat(40_000));
    }
    ws.send(Message::text(started.to_string())).await.is_ok()
}

async fn handle_text(
    ws: &mut ServerWs,
    frame: &Value,
    seen: &SeenFrames,
    sent: &SentPcm,
    text_index: usize,
    plan: &StubPlan,
) -> bool {
    let generation = frame.get("generation").and_then(Value::as_u64).unwrap_or(0);
    let text_body = frame
        .get("text")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_owned();
    if let Ok(mut guard) = seen.lock() {
        guard.push(StubSeen::Text {
            generation,
            text: text_body.clone(),
        });
    }
    if text_index == 0 {
        if let StubPlan::WithdrawAtFirstText(vault, owner) = plan {
            withdraw_consent(vault, *owner);
        }
    }
    let pcm_a = vec![text_index as u8, 0xAA];
    let pcm_b = vec![text_index as u8, 0xBB];
    let audio0 = json!({
        "type": "audio",
        "generation": generation,
        "chunk_index": 0,
        "bytes": pcm_a.len()
    })
    .to_string();
    if ws.send(Message::text(audio0)).await.is_err() {
        return false;
    }
    if ws.send(Message::binary(pcm_a.clone())).await.is_err() {
        return false;
    }
    if let Ok(mut guard) = sent.lock() {
        guard.push(pcm_a);
    }
    let audio1 = json!({
        "type": "audio",
        "generation": generation,
        "chunk_index": 1,
        "bytes": pcm_b.len()
    })
    .to_string();
    if ws.send(Message::text(audio1)).await.is_err() {
        return false;
    }
    if ws.send(Message::binary(pcm_b.clone())).await.is_err() {
        return false;
    }
    if let Ok(mut guard) = sent.lock() {
        guard.push(pcm_b);
    }
    let audio_ms = (4_u64 / 2 * 1000) / u64::from(SAMPLE_RATE);
    let usage = json!({
        "type": "usage",
        "generation": generation,
        "characters": text_body.chars().count() as u64,
        "audio_ms": audio_ms
    })
    .to_string();
    ws.send(Message::text(usage)).await.is_ok()
}

async fn handle_end(ws: &mut ServerWs, frame: &Value, seen: &SeenFrames) {
    let generation = frame.get("generation").and_then(Value::as_u64).unwrap_or(0);
    if let Ok(mut guard) = seen.lock() {
        guard.push(StubSeen::End { generation });
    }
    let done = json!({"type": "done", "generation": generation}).to_string();
    let _ = ws.send(Message::text(done)).await;
}

async fn handle_one(
    mut ws: ServerWs,
    ready: &str,
    seen: &SeenFrames,
    sent: &SentPcm,
    plan: &StubPlan,
) {
    if ws.send(Message::text(ready.to_owned())).await.is_err() {
        return;
    }
    let mut text_index = 0_usize;
    loop {
        let next = ws.next().await;
        let message = match next {
            Some(Ok(message)) => message,
            _ => break,
        };
        match message {
            Message::Text(text) => {
                let frame: Value = match serde_json::from_str(text.as_str()) {
                    Ok(frame) => frame,
                    Err(_) => break,
                };
                let kind = frame.get("type").and_then(Value::as_str).unwrap_or("");
                if kind == "start" {
                    if !handle_start(&mut ws, &frame, seen, plan).await {
                        break;
                    }
                } else if kind == "text" {
                    let ok = handle_text(&mut ws, &frame, seen, sent, text_index, plan).await;
                    text_index += 1;
                    if !ok {
                        break;
                    }
                } else if kind == "end" {
                    handle_end(&mut ws, &frame, seen).await;
                } else if kind == "flush" || kind == "cancel" {
                    continue;
                } else {
                    break;
                }
            }
            Message::Binary(_) => break,
            Message::Ping(_) | Message::Pong(_) | Message::Frame(_) => continue,
            Message::Close(_) => break,
        }
    }
}

async fn start_stub(
    expected_bearer: String,
    plan: StubPlan,
) -> (
    u16,
    Connections,
    SeenFrames,
    SentPcm,
    HandshakeFailures,
    tokio::task::JoinHandle<()>,
) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("stub bind");
    let port = listener.local_addr().expect("stub addr").port();
    let connections: Connections = Arc::new(Mutex::new(Vec::new()));
    let seen: SeenFrames = Arc::new(Mutex::new(Vec::new()));
    let sent: SentPcm = Arc::new(Mutex::new(Vec::new()));
    let failures: HandshakeFailures = Arc::new(Mutex::new(Vec::new()));
    let connections_task = Arc::clone(&connections);
    let seen_task = Arc::clone(&seen);
    let sent_task = Arc::clone(&sent);
    let failures_task = Arc::clone(&failures);
    let ready = ready_text();
    let handle = tokio::spawn(async move {
        loop {
            let (stream, _) = match listener.accept().await {
                Ok(pair) => pair,
                Err(_) => break,
            };
            let expected_header = format!("Bearer {expected_bearer}");
            let connections_cb = Arc::clone(&connections_task);
            let upgraded = tokio_tungstenite::accept_hdr_async(
                stream,
                move |request: &Request, response: Response| {
                    let path = request.uri().path().to_owned();
                    let bearer_ok = request
                        .headers()
                        .get("Authorization")
                        .and_then(|value| value.to_str().ok())
                        == Some(expected_header.as_str());
                    if let Ok(mut guard) = connections_cb.lock() {
                        guard.push((path.clone(), bearer_ok));
                    }
                    if path != "/v1/voice" {
                        let denied = Response::builder()
                            .status(StatusCode::NOT_FOUND)
                            .body(Some("not found".into()))
                            .expect("404 response");
                        return Err(denied);
                    }
                    if !bearer_ok {
                        let denied = Response::builder()
                            .status(StatusCode::UNAUTHORIZED)
                            .body(Some("unauthorized".into()))
                            .expect("401 response");
                        return Err(denied);
                    }
                    Ok(response)
                },
            )
            .await;
            let ws = match upgraded {
                Ok(ws) => ws,
                Err(error) => {
                    if let Ok(mut guard) = failures_task.lock() {
                        guard.push(format!("{error:?}"));
                    }
                    continue;
                }
            };
            handle_one(ws, &ready, &seen_task, &sent_task, &plan).await;
        }
    });
    (port, connections, seen, sent, failures, handle)
}

fn speech_runtime(port: u16, key_env: &str, vault: Arc<Vault>) -> ModelRuntime {
    // SAFETY: the test binary sets its own unique variable before any other
    // thread reads it, and no other test uses this name.
    unsafe {
        std::env::set_var(key_env, "t".repeat(32));
    }
    let config = ModelsConfig::from_toml(
        &format!(
            r#"
[providers.voxcpm2]
kind = "voxcpm2"
base_url = "http://127.0.0.1:{port}"
key_env = "{key_env}"
revision = "v1"
timeout_secs = 10

[media.speech]
rungs = ["voxcpm2:voxcpm2"]
"#
        ),
        None,
    )
    .expect("models config");
    ModelRuntime::build_with_keys(
        Some(&config),
        None,
        oneiron::HostingPrivacyPosture::SelfHostLocal,
    )
    .with_media_vault(vault)
}

async fn wait_for_end(seen: &SeenFrames) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
    loop {
        let done = seen.lock().is_ok_and(|guard| {
            guard
                .iter()
                .any(|frame| matches!(frame, StubSeen::End { .. }))
        });
        if done {
            break;
        }
        if std::time::Instant::now() >= deadline {
            panic!("the stub never saw end");
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn the_speech_rung_renders_through_the_voice_socket() {
    let (_dir, vault, _owner) = banked_vault();
    let key_env = "VOXCPM2_OUR_VOICE_TEST_A";
    let bearer = "t".repeat(32);
    let (port, connections, seen, sent, _failures, handle) =
        start_stub(bearer, StubPlan::Answer).await;
    let runtime = speech_runtime(port, key_env, Arc::clone(&vault));
    let request = speech_request(reference_voice(&vault));
    let result = runtime.media().run(request, None, None).await;
    let response = result.expect("speech renders");
    assert_eq!(response.parts.len(), 1, "one audio part");
    let part = response.parts.into_iter().next().expect("one part");
    let (media_type, bytes) = match part {
        MediaPart::Audio { media_type, bytes } => (media_type, bytes),
        other => panic!("an audio part, got {other:?}"),
    };
    assert_eq!(media_type, "audio/wav");
    assert!(bytes.len() >= 44, "a wav header");
    assert_eq!(&bytes[0..4], b"RIFF");
    assert_eq!(&bytes[8..12], b"WAVE");
    let rate = u32::from_le_bytes([bytes[24], bytes[25], bytes[26], bytes[27]]);
    assert_eq!(rate, SAMPLE_RATE);
    let pcm = sent.lock().expect("pcm").concat();
    assert_eq!(&bytes[44..], pcm.as_slice(), "the joined pcm");
    assert_eq!(response.usage.characters, TEXT.chars().count() as u64);
    let conns = connections.lock().expect("conns");
    assert_eq!(conns.len(), 1, "one connection");
    assert_eq!(conns[0].0, "/v1/voice");
    assert!(conns[0].1, "the right bearer");
    drop(conns);
    // The stub reads `end` after the call returns: it runs until it has.
    wait_for_end(&seen).await;
    handle.abort();
    let guard = seen.lock().expect("frames");
    assert!(!guard.is_empty(), "the stub saw frames");
    match &guard[0] {
        StubSeen::Start {
            target,
            transcript,
            reference,
            ..
        } => {
            assert_eq!(target["voice_id"], VOICE_ID, "the start names the voice");
            assert_eq!(transcript.as_slice(), TRANSCRIPT.as_bytes());
            assert_eq!(reference.as_slice(), CLIP);
        }
        other => panic!("first is start, got {other:?}"),
    }
    let texts: Vec<String> = guard
        .iter()
        .filter_map(|frame| match frame {
            StubSeen::Text { text, .. } => Some(stripped(text)),
            _ => None,
        })
        .collect();
    let renders = texts.len();
    assert!(renders >= 2, "two renders, got {renders}");
    let joined: String = texts.concat();
    assert_eq!(joined, stripped(TEXT), "the texts join to the request");
    match guard.last().expect("last") {
        StubSeen::End { .. } => {}
        other => panic!("last is end, got {other:?}"),
    }
    let starts = guard
        .iter()
        .filter(|frame| matches!(frame, StubSeen::Start { .. }))
        .count();
    let ends = guard
        .iter()
        .filter(|frame| matches!(frame, StubSeen::End { .. }))
        .count();
    assert_eq!(starts, 1, "one start");
    assert_eq!(ends, 1, "one end");
    let generations: Vec<u64> = guard
        .iter()
        .map(|frame| match frame {
            StubSeen::Start { generation, .. }
            | StubSeen::Text { generation, .. }
            | StubSeen::End { generation } => *generation,
        })
        .collect();
    assert!(
        generations.iter().all(|generation| *generation == 1),
        "one generation for the whole call: {generations:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_withdrawn_reference_stops_the_renders_still_to_come() {
    let (_dir, vault, owner) = banked_vault();
    let key_env = "VOXCPM2_OUR_VOICE_TEST_B";
    let bearer = "t".repeat(32);
    let (port, _connections, seen, _sent, _failures, handle) = start_stub(
        bearer,
        StubPlan::WithdrawAtFirstText(Arc::clone(&vault), owner),
    )
    .await;
    let runtime = speech_runtime(port, key_env, Arc::clone(&vault));
    let request = speech_request(reference_voice(&vault));
    let result = runtime.media().run(request, None, None).await;
    handle.abort();
    assert!(result.is_err(), "the withdrawn call errs");
    let guard = seen.lock().expect("frames");
    let texts = guard
        .iter()
        .filter(|frame| matches!(frame, StubSeen::Text { .. }))
        .count();
    assert_eq!(texts, 1, "exactly one text");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_wrong_bearer_is_refused_at_the_upgrade() {
    let (_dir, vault, _owner) = banked_vault();
    let key_env = "VOXCPM2_OUR_VOICE_TEST_C";
    let expected = "u".repeat(32);
    let (port, _connections, seen, _sent, _failures, handle) =
        start_stub(expected, StubPlan::Answer).await;
    let runtime = speech_runtime(port, key_env, Arc::clone(&vault));
    let request = speech_request(reference_voice(&vault));
    let result = runtime.media().run(request, None, None).await;
    handle.abort();
    let error = match result {
        Ok(_) => panic!("a wrong bearer must err"),
        Err(error) => error,
    };
    assert!(
        matches!(error, LlmError::Fatal(FatalLlmError::Auth)),
        "a 401 is auth, got {error:?}"
    );
    let guard = seen.lock().expect("frames");
    assert!(
        !guard
            .iter()
            .any(|frame| matches!(frame, StubSeen::Start { .. })),
        "no start"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_reference_withdrawn_during_the_start_exchange_sends_no_text() {
    let (_dir, vault, owner) = banked_vault();
    let key_env = "VOXCPM2_OUR_VOICE_TEST_D";
    let bearer = "t".repeat(32);
    let (port, _connections, seen, _sent, _failures, handle) =
        start_stub(bearer, StubPlan::WithdrawAtStart(Arc::clone(&vault), owner)).await;
    let runtime = speech_runtime(port, key_env, Arc::clone(&vault));
    let request = speech_request(reference_voice(&vault));
    let result = runtime.media().run(request, None, None).await;
    handle.abort();
    assert!(result.is_err(), "the withdrawn call errs");
    let guard = seen.lock().expect("frames");
    let starts = guard
        .iter()
        .filter(|frame| matches!(frame, StubSeen::Start { .. }))
        .count();
    let texts = guard
        .iter()
        .filter(|frame| matches!(frame, StubSeen::Text { .. }))
        .count();
    assert_eq!(starts, 1, "the start went before the withdrawal");
    assert_eq!(texts, 0, "no text after the withdrawal");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_frame_the_protocol_forbids_is_a_malformed_reply() {
    let (_dir, vault, _owner) = banked_vault();
    let key_env = "VOXCPM2_OUR_VOICE_TEST_E";
    let bearer = "t".repeat(32);
    let (port, _connections, seen, _sent, _failures, handle) =
        start_stub(bearer, StubPlan::ReservedBitAtStart).await;
    let runtime = speech_runtime(port, key_env, Arc::clone(&vault));
    let request = speech_request(reference_voice(&vault));
    let result = runtime.media().run(request, None, None).await;
    handle.abort();
    let error = match result {
        Ok(_) => panic!("a forbidden frame must err"),
        Err(error) => error,
    };
    assert!(
        matches!(error, LlmError::Fatal(FatalLlmError::EmptyResponse)),
        "a reserved bit is a malformed reply, got {error:?}"
    );
    let guard = seen.lock().expect("frames");
    assert!(
        guard
            .iter()
            .any(|frame| matches!(frame, StubSeen::Start { .. })),
        "the stub saw the start"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_started_past_the_metadata_ceiling_is_a_malformed_reply() {
    let (_dir, vault, _owner) = banked_vault();
    let key_env = "VOXCPM2_OUR_VOICE_TEST_F";
    let bearer = "t".repeat(32);
    let (port, _connections, seen, _sent, _failures, handle) =
        start_stub(bearer, StubPlan::OversizedStarted).await;
    let runtime = speech_runtime(port, key_env, Arc::clone(&vault));
    let request = speech_request(reference_voice(&vault));
    let result = runtime.media().run(request, None, None).await;
    handle.abort();
    let error = match result {
        Ok(_) => panic!("a started past max_header_bytes must err"),
        Err(error) => error,
    };
    assert!(
        matches!(error, LlmError::Fatal(FatalLlmError::EmptyResponse)),
        "a started past the ceiling is a malformed reply, got {error:?}"
    );
    let guard = seen.lock().expect("frames");
    assert!(
        !guard
            .iter()
            .any(|frame| matches!(frame, StubSeen::Text { .. })),
        "no text after a malformed started"
    );
}
