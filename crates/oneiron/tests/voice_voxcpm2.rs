//! Host-visible banked-ref → TTS seam → PCM harness (CPU fixture, not GPU proof).
#![allow(
    clippy::disallowed_methods,
    reason = "a test process starts its own subprocesses; the rule covers the server's crates"
)]
use oneiron::error::Result;
use oneiron::interlocutor::InterlocutorResolutionInput;
use oneiron::llm::ModelLocality;
#[cfg(feature = "sync")]
use oneiron::llm::media::{AiOperation, MediaCaps};
#[cfg(feature = "sync")]
use oneiron::llm::run_admission::{
    BudgetLine, KeyCustody, LeaseUnit, MemoryReceipts, OfferBinding, OfferRoute, Payer,
    RunAdmission, RunDeclaration, WireSeat, offer_id, offer_place,
};
#[cfg(feature = "sync")]
use oneiron::llm::{
    CallClass, CallEnvelope, CallPurpose, ModelId, ModelTierRef, ResponseFormat, TierPrecedence,
};
use oneiron::speculative::SpeculativeSessionConfig;
#[cfg(feature = "sync")]
use oneiron::voice_cascade::GenerationEpoch;
#[cfg(feature = "sync")]
use oneiron::voice_cascade::our_voice::{OurVoiceQueue, VoxCpm2Event};
use oneiron::voice_identity::ref_bank::{VoiceRefSubjectKind, VoiceRenderDecision};
use oneiron::voice_identity::{VoiceConsentBasis, VoiceConsentState};
use oneiron::{
    EntityId, Vault, VaultConfig,
    voice_cascade::{
        AsrEvent, AsrEventKind, AsrUpdate, PartialEnricher, PartialEnrichment, TtsCommand,
        TtsSeamClient, VoiceCascadeSession, VoiceSessionConfig,
        voxcpm2::{
            MODEL, RenderTarget, VoiceServingLimits, VoxCpm2Adapter, VoxCpm2Audio, VoxCpm2PcmBody,
            VoxCpm2Queue, VoxCpm2Work, WarmTarget,
        },
    },
    voice_identity::ref_bank::{VoiceRefFence, VoiceRefOrigin, VoiceRefPack, VoiceRegisterClip},
};
#[cfg(feature = "sync")]
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
#[cfg(feature = "sync")]
use std::sync::mpsc;
#[cfg(feature = "sync")]
use std::thread;
#[cfg(feature = "sync")]
use std::time::{Duration, Instant};
#[cfg(feature = "sync")]
use tokio_tungstenite::tungstenite::handshake::server::{Request, Response};
#[cfg(feature = "sync")]
use tokio_tungstenite::tungstenite::http::StatusCode;
#[cfg(feature = "sync")]
use tokio_tungstenite::tungstenite::{Message, WebSocket, accept_hdr};

struct EmptyEnricher;
impl PartialEnricher for EmptyEnricher {
    fn enrich_speculative_partial(&mut self, _text: &str) -> Result<PartialEnrichment> {
        Ok(PartialEnrichment::default())
    }
}
#[derive(Default)]
struct Capture {
    work: Vec<VoxCpm2Work>,
    limits: Option<VoiceServingLimits>,
}
impl VoxCpm2Queue for Capture {
    fn warm_target(&self) -> Result<WarmTarget> {
        Ok(WarmTarget {
            limits: self.limits.expect("test serving policy"),
            model: MODEL.into(),
            checkpoint: "pinned-revision".into(),
            boot_id: "warm-worker".into(),
            sample_rate: 48_000,
        })
    }
    fn try_submit(&mut self, work: VoxCpm2Work) -> Result<()> {
        self.work.push(work);
        Ok(())
    }
}
#[test]
fn one_banked_ref_renders_pcm_with_target_metadata() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let vault = Arc::new(Vault::open(dir.path(), VaultConfig::device())?);
    let owner = EntityId::now();
    grant_render(&vault, "owner-voice", owner, "owner-grant")?;
    vault.store_voice_ref_pack(&VoiceRefPack {
        version: 1,
        id: "owner-ref".into(),
        voice_id: "owner-voice".into(),
        owner,
        origin: VoiceRefOrigin::Captured {
            consent_event_ref: "owner-grant".into(),
        },
        clips: vec![VoiceRegisterClip {
            register: "neutral".into(),
            media_type: "audio/wav".into(),
            audio: b"RIFF0000WAVEfmt ".to_vec(),
            transcript: "banked sample".into(),
        }],
    })?;
    let mut cascade = VoiceCascadeSession::new(
        Arc::clone(&vault),
        VoiceSessionConfig::new(
            "test-session",
            InterlocutorResolutionInput {
                owner_session: true,
                parties: vec![],
                voice_session_ref: None,
            },
        ),
    )?;
    let utterance = cascade.open_utterance("turn", SpeculativeSessionConfig::default())?;
    let AsrUpdate::Final(brain) = cascade.handle_asr(
        &utterance,
        1,
        AsrEvent {
            kind: AsrEventKind::Final,
            text: "hello".into(),
            tokens: vec![],
            provider_latency_ms: None,
            endpoint_delay_ms: None,
            error: None,
        },
        false,
        &mut EmptyEnricher,
    )?
    else {
        panic!("final ASR")
    };
    let mut tts = VoxCpm2Adapter::new(
        Arc::clone(&vault),
        "owner-voice",
        "neutral",
        WORKER_LOCALITY,
        Capture {
            limits: Some(vault.voice_serving_limits(None)?),
            ..Capture::default()
        },
    )?;
    let generation = brain.generation;
    tts.submit(TtsCommand::Start { generation })?;
    tts.submit(TtsCommand::Text {
        generation,
        text: "render this".into(),
    })?;
    tts.submit(TtsCommand::End { generation })?;
    let target = tts.target().expect("target").clone();
    let selected = vault.prepare_voice_clone("owner-voice", "voxcpm2", false, WORKER_LOCALITY)?;
    assert_eq!(
        target,
        RenderTarget {
            voice_id: "owner-voice".into(),
            register: "neutral".into(),
            fence: VoiceRefFence {
                owner,
                // Minted by the bank at identity birth; the digest binds the refs.
                incarnation: target.fence.incarnation,
                ref_digest: selected.ref_digest,
                include_generated: false,
                // The render consent the refs reach the worker under.
                grant: selected.grant,
            },
            limits: vault.voice_serving_limits(None)?,
            warm: WarmTarget {
                limits: vault.voice_serving_limits(None)?,
                model: MODEL.into(),
                checkpoint: "pinned-revision".into(),
                boot_id: "warm-worker".into(),
                sample_rate: 48_000
            }
        }
    );
    let mut pcm = tts.handle_pcm(VoxCpm2Audio {
        generation,
        submission: 1,
        chunk_index: 0,
        target: target.clone(),
        channels: 1,
        body: &Arc::new(VoxCpm2PcmBody::from(vec![1, 0, 255, 255])),
    })?;
    let (frame, origin) = pcm.next_window(&cascade)?.expect("active cascade PCM");
    assert_eq!(frame.samples, [1, -1]);
    assert_eq!(frame.sample_rate, 48_000);
    assert_eq!(origin, target);
    // Bank identity is pinned by the revision, not a vendor voice ID.
    assert_eq!(MODEL, "VoxCPM2");
    // A callback accepted before withdrawal cannot be played afterwards.
    let mut second = VoxCpm2Adapter::new(
        Arc::clone(&vault),
        "owner-voice",
        "neutral",
        WORKER_LOCALITY,
        Capture {
            limits: Some(vault.voice_serving_limits(None)?),
            ..Capture::default()
        },
    )?;
    second.submit(TtsCommand::Start { generation })?;
    second.submit(TtsCommand::Text {
        generation,
        text: "later".into(),
    })?;
    second.submit(TtsCommand::End { generation })?;
    let second_target = second.target().unwrap().clone();
    let mut pending = second.handle_pcm(VoxCpm2Audio {
        generation,
        submission: 1,
        chunk_index: 0,
        target: second_target,
        channels: 1,
        body: &Arc::new(VoxCpm2PcmBody::from(vec![1, 0])),
    })?;
    vault.withdraw_voice_consent(&oneiron::voice_identity::VoiceWithdrawalRequest {
        event_id: "withdraw-before-playback".into(),
        subject_ref: owner,
        recorded_by_ref: owner,
        occurred_at: 10,
        purposes: vec![oneiron::voice_identity::VoicePrintPurpose::LiveInterlocutor],
        basis: oneiron::voice_identity::VoiceConsentBasis::ConversationalNotice {
            notice: "withdraw".into(),
        },
    })?;
    assert!(pending.next_window(&cascade)?.is_none());
    Ok(())
}

/// Where the host's worker runs in these tests: its own server, never a
/// third party, as the reference clip is the person's raw voice.
const WORKER_LOCALITY: ModelLocality = ModelLocality::OwnServer;

/// The subject's render grant for `voice_id`, reaching the host's worker:
/// a captured pack is banked under it and cites its event.
fn grant_render(vault: &Vault, voice_id: &str, owner: EntityId, event_id: &str) -> Result<()> {
    vault.record_voice_render_consent(&VoiceRenderDecision {
        event_id: event_id.into(),
        voice_id: voice_id.into(),
        subject: owner,
        subject_kind: VoiceRefSubjectKind::Person,
        recorded_by: owner,
        occurred_at: 1,
        reach: WORKER_LOCALITY,
        basis: Some(VoiceConsentBasis::ConversationalNotice {
            notice: "render".into(),
        }),
        state: VoiceConsentState::Granted,
    })?;
    Ok(())
}

/// The host's rung for the worker: each render is one `ai.speech` call on
/// it (FIX 8314), admitted under one run with room for every render here.
/// Only the socket tests seat a run, so the helper is sync-gated with them.
#[cfg(feature = "sync")]
fn worker_seat() -> WireSeat {
    let model = ModelId::new(format!("local/{MODEL}@pinned-revision")).expect("worker model id");
    let route = OfferRoute::new("voxcpm2-worker", "loopback").expect("worker route");
    let offer = OfferBinding {
        offer: offer_id(&model, &offer_place(WORKER_LOCALITY, route.origin())),
        model,
        route,
        locality: WORKER_LOCALITY,
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
        locality: WORKER_LOCALITY,
        host_keyless: false,
        host_paid: false,
        seat_effort: None,
    };
    let run = RunAdmission::new(
        format!("voxcpm2-test:{}", EntityId::now().to_hex()),
        RunDeclaration::undeclared(BudgetLine {
            limit_units: 1_000_000,
            reserve_units: 10_000,
            unit: LeaseUnit::tokens(),
        }),
        None,
        Arc::new(MemoryReceipts::default()),
    );
    WireSeat::new(
        run,
        offer,
        envelope,
        MediaCaps::for_operation(AiOperation::Speech),
    )
}

/// One banked owner voice plus its cascade and ASR generation: every
/// socket test's setup.
#[cfg(feature = "sync")]
struct VoiceFixture {
    _dir: tempfile::TempDir,
    vault: Arc<Vault>,
    cascade: VoiceCascadeSession,
    generation: GenerationEpoch,
    owner: EntityId,
    limits: VoiceServingLimits,
}

#[cfg(feature = "sync")]
impl VoiceFixture {
    fn banked() -> Result<Self> {
        let dir = tempfile::tempdir()?;
        let vault = Arc::new(Vault::open(dir.path(), VaultConfig::device())?);
        let owner = EntityId::now();
        grant_render(&vault, "owner-voice", owner, "owner-grant")?;
        vault.store_voice_ref_pack(&VoiceRefPack {
            version: 1,
            id: "owner-ref".into(),
            voice_id: "owner-voice".into(),
            owner,
            origin: VoiceRefOrigin::Captured {
                consent_event_ref: "owner-grant".into(),
            },
            clips: vec![VoiceRegisterClip {
                register: "neutral".into(),
                media_type: "audio/wav".into(),
                audio: b"RIFF0000WAVEfmt ".to_vec(),
                transcript: "banked sample".into(),
            }],
        })?;
        let mut cascade = VoiceCascadeSession::new(
            Arc::clone(&vault),
            VoiceSessionConfig::new(
                "test-session",
                InterlocutorResolutionInput {
                    owner_session: true,
                    parties: vec![],
                    voice_session_ref: None,
                },
            ),
        )?;
        let utterance = cascade.open_utterance("turn", SpeculativeSessionConfig::default())?;
        let AsrUpdate::Final(brain) = cascade.handle_asr(
            &utterance,
            1,
            AsrEvent {
                kind: AsrEventKind::Final,
                text: "hello".into(),
                tokens: vec![],
                provider_latency_ms: None,
                endpoint_delay_ms: None,
                error: None,
            },
            false,
            &mut EmptyEnricher,
        )?
        else {
            panic!("final ASR")
        };
        let limits = vault.voice_serving_limits(None)?;
        Ok(Self {
            _dir: dir,
            vault,
            cascade,
            generation: brain.generation,
            owner,
            limits,
        })
    }
}

/// A loopback listener plus the base URL that dials it.
#[cfg(feature = "sync")]
fn loopback_listener() -> Result<(TcpListener, String)> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let endpoint = format!("http://{}/", listener.local_addr()?);
    Ok((listener, endpoint))
}

/// The adapter on a fresh queue to `endpoint`, under the test bearer.
#[cfg(feature = "sync")]
fn connect_adapter(vault: &Arc<Vault>, endpoint: &str) -> Result<VoxCpm2Adapter<OurVoiceQueue>> {
    let queue =
        OurVoiceQueue::connect(Arc::clone(vault), endpoint, &"t".repeat(32), worker_seat())?;
    VoxCpm2Adapter::new(
        Arc::clone(vault),
        "owner-voice",
        "neutral",
        WORKER_LOCALITY,
        queue,
    )
}

/// Accepts one loopback connection and upgrades it, answering 401 to any
/// path but `/v1/voice` and any bearer but `expected_bearer`.
#[cfg(feature = "sync")]
fn accept_stub(listener: &TcpListener, expected_bearer: &str) -> WebSocket<TcpStream> {
    let (stream, _) = listener.accept().expect("worker accept");
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .expect("stub timeouts");
    stream
        .set_write_timeout(Some(Duration::from_secs(3)))
        .expect("stub timeouts");
    accept_hdr(stream, |request: &Request, response: Response| {
        assert_eq!(request.uri().path(), "/v1/voice");
        let bearer = request
            .headers()
            .get("Authorization")
            .and_then(|value| value.to_str().ok());
        if bearer != Some(expected_bearer) {
            let denied = Response::builder()
                .status(StatusCode::UNAUTHORIZED)
                .body(Some("unauthorized".into()))
                .expect("401 response");
            return Err(denied);
        }
        Ok(response)
    })
    .expect("voice upgrade")
}

/// The worker's `ready`: today's `/ready` body plus `transcript_frame`.
#[cfg(feature = "sync")]
fn send_ready(ws: &mut WebSocket<TcpStream>, limits: &VoiceServingLimits) {
    let ready = serde_json::json!({"type": "ready", "version": 1,
        "target": {"model": MODEL, "checkpoint": "pinned-revision", "boot_id": "warm-worker",
            "sample_rate": 48000, "limits": limits, "transcript_frame": true},
        "capabilities": {"input": "full", "streaming": false, "alignment": "none",
            "remote_cancel": "before_start", "max_text_bytes": limits.max_text_bytes}});
    ws.send(Message::text(ready.to_string()))
        .expect("ready frame");
}

/// One text frame's JSON.
#[cfg(feature = "sync")]
fn read_text_frame(ws: &mut WebSocket<TcpStream>) -> serde_json::Value {
    match ws.read().expect("wire frame") {
        Message::Text(text) => serde_json::from_str(text.as_str()).expect("frame JSON"),
        other => panic!("expected a text frame, got {other:?}"),
    }
}

/// One binary frame's bytes.
#[cfg(feature = "sync")]
fn read_binary_frame(ws: &mut WebSocket<TcpStream>) -> Vec<u8> {
    match ws.read().expect("wire frame") {
        Message::Binary(bytes) => bytes.to_vec(),
        other => panic!("expected a binary frame, got {other:?}"),
    }
}

/// Reads `start` plus its transcript and reference binaries, checking the
/// banked identity; returns the generation and the received target.
#[cfg(feature = "sync")]
fn read_start(ws: &mut WebSocket<TcpStream>, owner_hex: &str) -> (u64, serde_json::Value) {
    let mut start = read_text_frame(ws);
    assert_eq!(start["type"], "start");
    let generation = start["generation"].as_u64().expect("start generation");
    assert_eq!(start["target"]["voice_id"], "owner-voice");
    assert_eq!(start["target"]["owner"], owner_hex);
    assert_eq!(
        start["transcript_bytes"].as_u64(),
        Some("banked sample".len() as u64)
    );
    assert_eq!(
        start["reference_bytes"].as_u64(),
        Some("RIFF0000WAVEfmt ".len() as u64)
    );
    let transcript = read_binary_frame(ws);
    assert_eq!(transcript.as_slice(), b"banked sample");
    let reference = read_binary_frame(ws);
    assert_eq!(reference.as_slice(), b"RIFF0000WAVEfmt ");
    let target = std::mem::take(&mut start["target"]);
    (generation, target)
}

/// Answers `started`, echoing the received target.
#[cfg(feature = "sync")]
fn answer_started(ws: &mut WebSocket<TcpStream>, generation: u64, target: &serde_json::Value) {
    let started = serde_json::json!({"type": "started", "generation": generation,
        "target": target, "sample_rate": 48000, "channels": 1});
    ws.send(Message::text(started.to_string()))
        .expect("started frame");
}

/// Reads one `text` frame of `generation`; returns its text.
#[cfg(feature = "sync")]
fn read_text_command(ws: &mut WebSocket<TcpStream>, generation: u64) -> String {
    let command = read_text_frame(ws);
    assert_eq!(command["type"], "text");
    assert_eq!(command["generation"].as_u64(), Some(generation));
    command["text"].as_str().expect("text body").to_owned()
}

/// Answers one render: an `audio` header plus its bytes, then its `usage`.
#[cfg(feature = "sync")]
fn answer_audio_usage(
    ws: &mut WebSocket<TcpStream>,
    generation: u64,
    chunk_index: u64,
    pcm: &[u8],
    text: &str,
) {
    let audio = serde_json::json!({"type": "audio", "generation": generation,
        "chunk_index": chunk_index, "bytes": pcm.len() as u64});
    ws.send(Message::text(audio.to_string()))
        .expect("audio header");
    ws.send(Message::from(pcm.to_vec())).expect("audio bytes");
    let usage = serde_json::json!({"type": "usage", "generation": generation,
        "characters": text.chars().count() as u64,
        "audio_ms": pcm.len() as u64 / 2 * 1000 / 48000});
    ws.send(Message::text(usage.to_string()))
        .expect("usage frame");
}

/// Reads until the peer's close, EOF or the socket timeout; returns the
/// text frames seen on the idle wire.
#[cfg(feature = "sync")]
fn drain_stub(ws: &mut WebSocket<TcpStream>) -> Vec<String> {
    let mut seen = Vec::new();
    loop {
        match ws.read() {
            Ok(Message::Text(text)) => seen.push(text.to_string()),
            Ok(Message::Close(_)) => break,
            Ok(_) => continue,
            Err(_) => break,
        }
    }
    seen
}

/// The queue's next event, waiting up to 3 s.
#[cfg(feature = "sync")]
fn next_event(queue: &OurVoiceQueue) -> VoxCpm2Event {
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        if let Some(event) = queue.try_recv().expect("worker queue") {
            return event;
        }
        assert!(Instant::now() < deadline, "worker reply timed out");
        thread::yield_now();
    }
}

/// Tiny wire peer: proves the production queue really sends the banked
/// reference over the socket to an already-ready process and plays its PCM.
#[cfg(feature = "sync")]
#[test]
fn loopback_worker_queue_roundtrips_a_banked_ref_and_pcm() -> Result<()> {
    let fixture = VoiceFixture::banked()?;
    let (listener, endpoint) = loopback_listener()?;
    let token = "t".repeat(32);
    let bearer = format!("Bearer {token}");
    let (done, rendered) = mpsc::channel();
    let owner_hex = fixture.owner.to_hex();
    let limits = fixture.limits;
    let server = thread::spawn(move || {
        let mut ws = accept_stub(&listener, &bearer);
        send_ready(&mut ws, &limits);
        let (generation, target) = read_start(&mut ws, &owner_hex);
        answer_started(&mut ws, generation, &target);
        let text = read_text_command(&mut ws, generation);
        assert_eq!(text, "render this");
        answer_audio_usage(&mut ws, generation, 0, &[1, 0, 255, 255], &text);
        done.send(()).expect("render signal");
        let idle = drain_stub(&mut ws);
        assert!(idle.is_empty(), "quiet wire after the reply: {idle:?}");
    });
    let mut tts = connect_adapter(&fixture.vault, &endpoint)?;
    let generation = fixture.generation;
    tts.submit(TtsCommand::Start { generation })?;
    tts.submit(TtsCommand::Text {
        generation,
        text: "render this".into(),
    })?;
    tts.submit(TtsCommand::End { generation })?;
    rendered
        .recv_timeout(Duration::from_secs(3))
        .expect("wire render");
    server.join().expect("wire peer");
    let event = next_event(tts.queue());
    let mut pcm = tts.handle_pcm(event.audio().expect("valid worker audio"))?;
    let (frame, target) = pcm.next_window(&fixture.cascade)?.expect("active PCM");
    assert_eq!(frame.samples, [1, -1]);
    assert_eq!(target.fence.owner, fixture.owner);
    assert_eq!(target.warm.model, MODEL);
    Ok(())
}

/// The generation fence: a stray generation's audio, bytes and done never
/// reach the render's spool.
#[cfg(feature = "sync")]
#[test]
fn our_voice_skips_frames_of_another_generation() -> Result<()> {
    let fixture = VoiceFixture::banked()?;
    let (listener, endpoint) = loopback_listener()?;
    let token = "t".repeat(32);
    let bearer = format!("Bearer {token}");
    let (done, rendered) = mpsc::channel();
    let owner_hex = fixture.owner.to_hex();
    let limits = fixture.limits;
    let server = thread::spawn(move || {
        let mut ws = accept_stub(&listener, &bearer);
        send_ready(&mut ws, &limits);
        let (generation, target) = read_start(&mut ws, &owner_hex);
        answer_started(&mut ws, generation, &target);
        let text = read_text_command(&mut ws, generation);
        assert_eq!(text, "render this");
        let stray = serde_json::json!({"type": "audio", "generation": generation + 1,
            "chunk_index": 0, "bytes": 4});
        ws.send(Message::text(stray.to_string()))
            .expect("stray audio");
        ws.send(Message::from(vec![9, 9, 9, 9]))
            .expect("stray bytes");
        let stray_done = serde_json::json!({"type": "done", "generation": generation + 1});
        ws.send(Message::text(stray_done.to_string()))
            .expect("stray done");
        answer_audio_usage(&mut ws, generation, 0, &[1, 0, 255, 255], &text);
        done.send(()).expect("render signal");
        let idle = drain_stub(&mut ws);
        assert!(idle.is_empty(), "quiet wire after the reply: {idle:?}");
    });
    let mut tts = connect_adapter(&fixture.vault, &endpoint)?;
    let generation = fixture.generation;
    tts.submit(TtsCommand::Start { generation })?;
    tts.submit(TtsCommand::Text {
        generation,
        text: "render this".into(),
    })?;
    tts.submit(TtsCommand::End { generation })?;
    rendered
        .recv_timeout(Duration::from_secs(3))
        .expect("wire render");
    server.join().expect("wire peer");
    let event = next_event(tts.queue());
    let mut pcm = tts.handle_pcm(event.audio().expect("valid worker audio"))?;
    let (frame, _) = pcm.next_window(&fixture.cascade)?.expect("active PCM");
    assert_eq!(frame.samples, [1, -1]);
    Ok(())
}

/// One generation's two renders upload its reference once: one `start` with
/// one transcript and one reference frame, then two `text` frames in order.
#[cfg(feature = "sync")]
#[test]
fn our_voice_uploads_the_reference_once_for_two_renders() -> Result<()> {
    let fixture = VoiceFixture::banked()?;
    let (listener, endpoint) = loopback_listener()?;
    let token = "t".repeat(32);
    let bearer = format!("Bearer {token}");
    let (done, rendered) = mpsc::channel();
    let owner_hex = fixture.owner.to_hex();
    let limits = fixture.limits;
    let server = thread::spawn(move || {
        let mut ws = accept_stub(&listener, &bearer);
        send_ready(&mut ws, &limits);
        let (generation, target) = read_start(&mut ws, &owner_hex);
        answer_started(&mut ws, generation, &target);
        let first = read_text_command(&mut ws, generation);
        assert_eq!(first, "first sentence");
        answer_audio_usage(&mut ws, generation, 0, &[1, 0, 255, 255], &first);
        let second = read_text_command(&mut ws, generation);
        assert_eq!(second, "second sentence");
        answer_audio_usage(&mut ws, generation, 0, &[1, 0, 255, 255], &second);
        done.send(()).expect("render signal");
        let idle = drain_stub(&mut ws);
        assert!(idle.is_empty(), "quiet wire after the reply: {idle:?}");
    });
    let mut tts = connect_adapter(&fixture.vault, &endpoint)?;
    let generation = fixture.generation;
    tts.submit(TtsCommand::Start { generation })?;
    tts.submit(TtsCommand::Text {
        generation,
        text: "first sentence".into(),
    })?;
    tts.submit(TtsCommand::Flush { generation })?;
    tts.submit(TtsCommand::Text {
        generation,
        text: "second sentence".into(),
    })?;
    tts.submit(TtsCommand::End { generation })?;
    rendered
        .recv_timeout(Duration::from_secs(3))
        .expect("wire renders");
    server.join().expect("wire peer");
    let first_event = next_event(tts.queue());
    let second_event = next_event(tts.queue());
    match (&first_event, &second_event) {
        (
            VoxCpm2Event::Audio { chunk_index: 0, .. },
            VoxCpm2Event::Audio { chunk_index: 1, .. },
        ) => {}
        _ => panic!("two audio events with chunk indexes 0 and 1"),
    }
    let mut first_pcm = tts.handle_pcm(first_event.audio().expect("first audio"))?;
    let (first_frame, _) = first_pcm.next_window(&fixture.cascade)?.expect("first PCM");
    assert_eq!(first_frame.samples, [1, -1]);
    let mut second_pcm = tts.handle_pcm(second_event.audio().expect("second audio"))?;
    let (second_frame, _) = second_pcm
        .next_window(&fixture.cascade)?
        .expect("second PCM");
    assert_eq!(second_frame.samples, [1, -1]);
    Ok(())
}

/// Cancelling after the first render's audio sends `cancel` for the started
/// generation, and the queue yields no further event.
#[cfg(feature = "sync")]
#[test]
fn our_voice_sends_cancel_to_the_worker() -> Result<()> {
    let fixture = VoiceFixture::banked()?;
    let (listener, endpoint) = loopback_listener()?;
    let token = "t".repeat(32);
    let bearer = format!("Bearer {token}");
    let (done, rendered) = mpsc::channel();
    let (cancelled, cancel_seen) = mpsc::channel();
    let owner_hex = fixture.owner.to_hex();
    let limits = fixture.limits;
    let server = thread::spawn(move || {
        let mut ws = accept_stub(&listener, &bearer);
        send_ready(&mut ws, &limits);
        let (generation, target) = read_start(&mut ws, &owner_hex);
        answer_started(&mut ws, generation, &target);
        let text = read_text_command(&mut ws, generation);
        assert_eq!(text, "render this");
        answer_audio_usage(&mut ws, generation, 0, &[1, 0, 255, 255], &text);
        done.send(()).expect("render signal");
        let cancel = read_text_frame(&mut ws);
        assert_eq!(cancel["type"], "cancel");
        assert_eq!(cancel["generation"].as_u64(), Some(generation));
        cancelled.send(generation).expect("cancel signal");
    });
    let mut tts = connect_adapter(&fixture.vault, &endpoint)?;
    let generation = fixture.generation;
    tts.submit(TtsCommand::Start { generation })?;
    tts.submit(TtsCommand::Text {
        generation,
        text: "render this".into(),
    })?;
    tts.submit(TtsCommand::End { generation })?;
    rendered
        .recv_timeout(Duration::from_secs(3))
        .expect("wire render");
    let event = next_event(tts.queue());
    let mut pcm = tts.handle_pcm(event.audio().expect("valid worker audio"))?;
    let (frame, _) = pcm.next_window(&fixture.cascade)?.expect("active PCM");
    assert_eq!(frame.samples, [1, -1]);
    tts.submit(TtsCommand::Cancel { generation })?;
    let wire_generation = cancel_seen
        .recv_timeout(Duration::from_secs(3))
        .expect("wire cancel");
    assert_eq!(wire_generation, generation.value());
    server.join().expect("wire peer");
    assert!(tts.queue().try_recv()?.is_none(), "no event after cancel");
    Ok(())
}

/// A wrong bearer is refused at the upgrade: `connect` fails and the stub
/// reads no frame.
#[cfg(feature = "sync")]
#[test]
fn our_voice_refuses_a_wrong_bearer_at_the_upgrade() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let vault = Arc::new(Vault::open(dir.path(), VaultConfig::device())?);
    let (listener, endpoint) = loopback_listener()?;
    let (rejected, refused) = mpsc::channel();
    let server = thread::spawn(move || {
        let (stream, _) = listener.accept().expect("worker accept");
        stream
            .set_read_timeout(Some(Duration::from_secs(3)))
            .expect("stub timeouts");
        let wrong = format!("Bearer {}", "u".repeat(32));
        let upgrade = accept_hdr(stream, |request: &Request, response: Response| {
            assert_eq!(request.uri().path(), "/v1/voice");
            let bearer = request
                .headers()
                .get("Authorization")
                .and_then(|value| value.to_str().ok());
            assert_eq!(bearer, Some(wrong.as_str()));
            let denied = Response::builder()
                .status(StatusCode::UNAUTHORIZED)
                .body(Some("unauthorized".into()))
                .expect("401 response");
            Err(denied)
        });
        assert!(upgrade.is_err(), "the upgrade is refused");
        // No socket came out of the refused upgrade, so no frame was read.
        rejected.send(()).expect("refusal signal");
    });
    let connect = OurVoiceQueue::connect(
        Arc::clone(&vault),
        &endpoint,
        &"u".repeat(32),
        worker_seat(),
    );
    assert!(connect.is_err(), "a wrong bearer refuses");
    refused
        .recv_timeout(Duration::from_secs(3))
        .expect("wire refusal");
    server.join().expect("wire peer");
    Ok(())
}

#[cfg(feature = "sync")]
#[test]
fn loopback_worker_ignores_environment_proxies() -> Result<()> {
    // Run the real ready+render wire case in a child process: environment
    // mutation in this parallel test binary would race sibling tests. The
    // named case is sync-gated, so this proxy rerun is too.
    let exe = std::env::current_exe()?;
    let mut child = std::process::Command::new(exe)
        .args([
            "--exact",
            "loopback_worker_queue_roundtrips_a_banked_ref_and_pcm",
        ])
        .env("HTTP_PROXY", "http://127.0.0.1:1")
        .env("http_proxy", "http://127.0.0.1:1")
        .env("ALL_PROXY", "http://127.0.0.1:1")
        .env("all_proxy", "http://127.0.0.1:1")
        .env("NO_PROXY", "")
        .env("no_proxy", "")
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()?;
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if child.try_wait()?.is_some() {
            break;
        }
        if Instant::now() >= deadline {
            child.kill()?;
            let _ = child.wait();
            panic!("proxy-negative loopback wire test did not finish");
        }
        thread::yield_now();
    }
    let result = child.wait_with_output()?;
    assert!(
        result.status.success(),
        "loopback request took the proxy path: {} {}",
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
    Ok(())
}
