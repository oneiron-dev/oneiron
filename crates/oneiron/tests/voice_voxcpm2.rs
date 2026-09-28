//! Host-visible banked-ref → TTS seam → PCM harness (CPU fixture, not GPU proof).
use oneiron::error::Result;
use oneiron::interlocutor::InterlocutorResolutionInput;
use oneiron::speculative::SpeculativeSessionConfig;
use oneiron::{
    EntityId, Vault, VaultConfig,
    voice_cascade::{
        AsrEvent, AsrEventKind, AsrUpdate, PartialEnricher, PartialEnrichment, TtsCommand,
        TtsSeamClient, VoiceCascadeSession, VoiceSessionConfig,
        voxcpm2::{
            MODEL, RenderTarget, VoiceServingLimits, VoxCpm2Adapter, VoxCpm2Audio, VoxCpm2Queue,
            VoxCpm2Work, WarmTarget, http::VoxCpm2HttpQueue,
        },
    },
    voice_identity::ref_bank::{VoiceRefFence, VoiceRefOrigin, VoiceRefPack, VoiceRegisterClip},
};
use std::{
    io::{BufRead, BufReader, Read, Write},
    net::TcpListener,
    sync::{Arc, mpsc},
    thread,
    time::{Duration, Instant},
};

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
    vault.store_voice_ref_pack(&VoiceRefPack {
        version: 1,
        id: "owner-ref".into(),
        voice_id: "owner-voice".into(),
        owner,
        origin: VoiceRefOrigin::Captured,
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
    assert_eq!(
        target,
        RenderTarget {
            voice_id: "owner-voice".into(),
            register: "neutral".into(),
            fence: VoiceRefFence {
                owner,
                // Minted by the bank at identity birth; the digest binds the refs.
                incarnation: target.fence.incarnation,
                ref_digest: vault
                    .prepare_voice_clone("owner-voice", "voxcpm2", false)?
                    .ref_digest,
                include_generated: false,
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
    let pcm = tts.handle_pcm(VoxCpm2Audio {
        generation,
        submission: 1,
        chunk_index: 0,
        target: target.clone(),
        channels: 1,
        bytes: &[1, 0, 255, 255],
    })?;
    let (frame, origin) = pcm.filter_pcm(&cascade).expect("active cascade PCM");
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
    let pending = second.handle_pcm(VoxCpm2Audio {
        generation,
        submission: 1,
        chunk_index: 0,
        target: second_target,
        channels: 1,
        bytes: &[1, 0],
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
    assert!(pending.filter_pcm(&cascade).is_none());
    Ok(())
}

/// Tiny wire peer: proves the production queue really posts banked bytes to
/// an already-ready process and rejects a different target in its response.
#[test]
fn loopback_worker_queue_roundtrips_a_banked_ref_and_pcm() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let vault = Arc::new(Vault::open(dir.path(), VaultConfig::device())?);
    let owner = EntityId::now();
    vault.store_voice_ref_pack(&VoiceRefPack {
        version: 1,
        id: "owner-ref".into(),
        voice_id: "owner-voice".into(),
        owner,
        origin: VoiceRefOrigin::Captured,
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
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let endpoint = format!("http://{}/", listener.local_addr()?);
    let (done, ready) = mpsc::channel();
    let server = thread::spawn(move || {
        for index in 0..2 {
            let (stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            let mut reader = BufReader::new(stream);
            let mut request_line = String::new();
            reader.read_line(&mut request_line).unwrap();
            let mut length = 0;
            loop {
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                if line == "\r\n" {
                    break;
                }
                if let Some(value) = line.to_ascii_lowercase().strip_prefix("content-length: ") {
                    length = value.trim().parse::<usize>().unwrap();
                }
            }
            let response = if index == 0 {
                assert!(request_line.starts_with("GET /ready "));
                serde_json::to_vec(&serde_json::json!({"model": MODEL,
                    "checkpoint": "pinned-revision", "boot_id": "warm-worker", "sample_rate": 48000,
                    "limits": limits}))
                .unwrap()
            } else {
                assert!(request_line.starts_with("POST /render "));
                let mut body = vec![0; length];
                reader.read_exact(&mut body).unwrap();
                let n = u32::from_be_bytes(body[..4].try_into().unwrap()) as usize;
                let meta: serde_json::Value = serde_json::from_slice(&body[4..4 + n]).unwrap();
                assert_eq!(meta["text"], "render this");
                assert_eq!(meta["transcript"], "banked sample");
                assert_eq!(meta["target"]["voice_id"], "owner-voice");
                assert_eq!(meta["target"]["owner"], owner.to_hex());
                assert_eq!(&body[4 + n..], b"RIFF0000WAVEfmt ");
                let header = serde_json::to_vec(&serde_json::json!({
                    "target": meta["target"], "sample_rate": 48000, "channels": 1}))
                .unwrap();
                let mut output = (header.len() as u32).to_be_bytes().to_vec();
                output.extend_from_slice(&header);
                output.extend_from_slice(&[1, 0, 255, 255]);
                done.send(()).unwrap();
                output
            };
            let stream = reader.get_mut();
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                response.len()
            )
            .unwrap();
            stream.write_all(&response).unwrap();
        }
    });
    let queue = VoxCpm2HttpQueue::connect(Arc::clone(&vault), &endpoint, &"t".repeat(32))?;
    let mut tts = VoxCpm2Adapter::new(Arc::clone(&vault), "owner-voice", "neutral", queue)?;
    let generation = brain.generation;
    tts.submit(TtsCommand::Start { generation })?;
    tts.submit(TtsCommand::Text {
        generation,
        text: "render this".into(),
    })?;
    tts.submit(TtsCommand::End { generation })?;
    ready
        .recv_timeout(Duration::from_secs(3))
        .expect("wire render");
    server.join().expect("wire peer");
    let deadline = Instant::now() + Duration::from_secs(3);
    let event = loop {
        if let Some(event) = tts.queue().try_recv()? {
            break event;
        }
        assert!(Instant::now() < deadline, "worker reply timed out");
        thread::yield_now();
    };
    let pcm = tts.handle_pcm(event.audio().expect("valid worker audio"))?;
    let (frame, target) = pcm.filter_pcm(&cascade).expect("active PCM");
    assert_eq!(frame.samples, [1, -1]);
    assert_eq!(target.fence.owner, owner);
    assert_eq!(target.warm.model, MODEL);
    Ok(())
}

#[test]
fn loopback_worker_ignores_environment_proxies() -> Result<()> {
    // Run the real ready+render wire case in a child process: environment
    // mutation in this parallel test binary would race sibling tests.
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
