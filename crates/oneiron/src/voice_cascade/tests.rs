//! Authored source-only in the bounded phase. These are not live transport proofs.

use std::collections::VecDeque;
use std::sync::Arc;
use std::time::Duration;

use serde_json::json;

use super::*;
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::interlocutor::InterlocutorResolutionInput;
use crate::speculative::SpeculativeSessionConfig;
use crate::temporal::TimeRange;

mod preparation;
mod retrieval;
mod safeguard;
mod session;
mod stream;

fn vault() -> (tempfile::TempDir, Arc<Vault>) {
    let dir = tempfile::tempdir().expect("temporary vault");
    let mut config = crate::test_util::embedding_test_config();
    config.retrieval_telemetry_capture = true;
    let vault = Vault::open(dir.path(), config).expect("open vault");
    (dir, Arc::new(vault))
}

fn entity(byte: u8) -> EntityId {
    let mut bytes = [byte; 16];
    bytes[0] = 0x5e;
    EntityId::from_bytes(bytes).expect("entity id")
}

fn put_text(vault: &Vault, byte: u8, text: &str) -> Result<String> {
    let id = entity(byte);
    vault
        .batch()
        .put(
            &id,
            1,
            TimeRange { start: 1, end: 1 },
            1,
            b"private entity body",
        )
        .text(&id, &[("body", text)])
        .commit()?;
    Ok(id.to_hex())
}

struct Enricher {
    value: PartialEnrichment,
    texts: Vec<String>,
}

impl Default for Enricher {
    fn default() -> Self {
        Self {
            value: PartialEnrichment {
                entity_labels: vec!["person:mika".to_owned()],
                salient_terms: vec!["Tokyo launch".to_owned()],
                query_vector: None,
            },
            texts: Vec::new(),
        }
    }
}

impl PartialEnricher for Enricher {
    fn enrich_speculative_partial(&mut self, text: &str) -> Result<PartialEnrichment> {
        self.texts.push(text.to_owned());
        Ok(self.value.clone())
    }
}

fn event(kind: AsrEventKind, text: &str) -> AsrEvent {
    AsrEvent {
        kind,
        text: text.to_owned(),
        tokens: Vec::new(),
        provider_latency_ms: None,
        endpoint_delay_ms: None,
        error: None,
    }
}

#[test]
fn blank_finals_have_no_effects_and_the_same_revision_is_retryable() -> Result<()> {
    for blank in ["", " \t\r\n", "\u{2003}\u{a0}"] {
        for warm in [false, true] {
            let (_dir, vault) = vault();
            let mut session = VoiceCascadeSession::new(Arc::clone(&vault), config())?;
            let handle =
                session.open_utterance("blank-final", SpeculativeSessionConfig::default())?;
            let mut enricher = Enricher::default();
            let warm_context = if warm {
                let update = session.handle_asr(
                    &handle,
                    1,
                    event(AsrEventKind::Partial, "Tokyo launch"),
                    false,
                    &mut enricher,
                )?;
                let AsrUpdate::Partial(partial) = update else {
                    panic!("warm partial")
                };
                Some(partial.context.expect("warm retrieval"))
            } else {
                None
            };
            let texts_before = enricher.texts.clone();
            let runs_before = vault.retrieval_runs(200)?.len();
            assert!(matches!(
                session.handle_asr(
                    &handle,
                    2,
                    event(AsrEventKind::Final, blank),
                    true,
                    &mut enricher,
                ),
                Err(Error::InvalidConfig(_))
            ));
            assert_eq!(enricher.texts, texts_before);
            assert_eq!(vault.retrieval_runs(200)?.len(), runs_before);
            assert!(!session.is_ended());
            let transcript = "  Tokyo launch\n";
            let update = session.handle_asr(
                &handle,
                2,
                event(AsrEventKind::Final, transcript),
                false,
                &mut enricher,
            )?;
            let AsrUpdate::Final(request) = update else {
                panic!("same handle and revision must remain retryable")
            };
            assert_eq!(request.generation.value(), 1);
            assert_eq!(request.transcript, transcript, "valid text is not trimmed");
            assert!(!request.externally_tainted);
            assert!(session.accepts_pcm(request.generation));
            assert_eq!(enricher.texts.len(), texts_before.len() + 1);
            if let Some(warm_context) = warm_context {
                assert!(request.retrieval.promoted);
                assert_eq!(request.retrieval.run_id, warm_context.run_id);
                assert_eq!(request.retrieval.result_refs, warm_context.result_refs);
                assert_eq!(vault.retrieval_runs(200)?.len(), runs_before);
            } else {
                assert_eq!(vault.retrieval_runs(200)?.len(), runs_before + 1);
            }
            assert!(!session.close_utterance(&handle));
        }
    }
    Ok(())
}

#[test]
fn invalid_asr_metadata_has_no_effects_and_leaves_the_revision_retryable() -> Result<()> {
    let token = AsrToken {
        text: "Tokyo".to_owned(),
        is_final: true,
        start_ms: None,
        end_ms: None,
        confidence: None,
    };
    let valid = AsrEvent {
        tokens: vec![token.clone()],
        ..event(AsrEventKind::Final, "Tokyo launch")
    };
    let mut invalid_events = Vec::new();
    for value in [-1.0, f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
        invalid_events.extend([
            AsrEvent {
                provider_latency_ms: Some(value),
                ..valid.clone()
            },
            AsrEvent {
                endpoint_delay_ms: Some(value),
                ..valid.clone()
            },
        ]);
        for bad_token in [
            AsrToken {
                start_ms: Some(value),
                ..token.clone()
            },
            AsrToken {
                end_ms: Some(value),
                ..token.clone()
            },
        ] {
            invalid_events.push(AsrEvent {
                tokens: vec![token.clone(), bad_token],
                ..valid.clone()
            });
        }
    }
    for value in [-0.01, 1.01, f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
        invalid_events.push(AsrEvent {
            tokens: vec![
                token.clone(),
                AsrToken {
                    confidence: Some(value),
                    ..token.clone()
                },
            ],
            ..valid.clone()
        });
    }
    invalid_events.push(AsrEvent {
        tokens: vec![
            token.clone(),
            AsrToken {
                start_ms: Some(2.0),
                end_ms: Some(1.0),
                ..token
            },
        ],
        ..valid.clone()
    });
    let (_dir, vault) = vault();
    for invalid in invalid_events {
        for kind in [
            AsrEventKind::Partial,
            AsrEventKind::Final,
            AsrEventKind::Endpoint,
            AsrEventKind::Error,
            AsrEventKind::Closed,
        ] {
            let mut session = VoiceCascadeSession::new(Arc::clone(&vault), config())?;
            let handle =
                session.open_utterance("bad-metadata", SpeculativeSessionConfig::default())?;
            let mut enricher = Enricher::default();
            let input = AsrEvent {
                kind,
                ..invalid.clone()
            };
            let runs_before = vault.retrieval_runs(200)?.len();
            assert!(
                matches!(
                    session.handle_asr(&handle, 7, input.clone(), true, &mut enricher),
                    Err(Error::InvalidConfig(_))
                ),
                "invalid input was not rejected: {input:?}"
            );
            assert!(enricher.texts.is_empty());
            assert_eq!(vault.retrieval_runs(200)?.len(), runs_before);
            assert!(!session.is_ended());
            let revision = if kind == AsrEventKind::Partial {
                let retry = AsrEvent {
                    kind,
                    ..valid.clone()
                };
                let update = session.handle_asr(&handle, 7, retry, false, &mut enricher)?;
                assert!(matches!(update, AsrUpdate::Partial(_)));
                8
            } else {
                7
            };
            let update =
                session.handle_asr(&handle, revision, valid.clone(), false, &mut enricher)?;
            let AsrUpdate::Final(request) = update else {
                panic!("invalid metadata must not consume the handle or revision")
            };
            assert_eq!(request.generation.value(), 1);
            assert_eq!(request.transcript, valid.text);
            assert!(!request.externally_tainted);
            assert_eq!(session.brain_context(request.generation), Some(&request));
            assert!(session.accepts_pcm(request.generation));
            let partial_retry = kind == AsrEventKind::Partial;
            assert_eq!(request.retrieval.promoted, partial_retry);
            assert_eq!(
                enricher.texts,
                vec![valid.text.clone(); if partial_retry { 2 } else { 1 }]
            );
            assert_eq!(vault.retrieval_runs(200)?.len(), runs_before + 1);
        }
    }
    Ok(())
}

#[test]
fn invalid_asr_metadata_preserves_live_output_and_stale_callbacks_stay_ignored() -> Result<()> {
    let (_dir, vault) = vault();
    let mut session = VoiceCascadeSession::new(Arc::clone(&vault), config())?;
    let request = start(&mut session, false)?;
    let stale = session.open_utterance("incoming", SpeculativeSessionConfig::default())?;
    assert!(session.close_utterance(&stale));
    let handle = session.open_utterance("incoming", SpeculativeSessionConfig::default())?;
    let mut enricher = Enricher::default();
    let runs_before = vault.retrieval_runs(200)?.len();
    for kind in [
        AsrEventKind::Partial,
        AsrEventKind::Final,
        AsrEventKind::Endpoint,
        AsrEventKind::Error,
        AsrEventKind::Closed,
    ] {
        let input = AsrEvent {
            provider_latency_ms: Some(f64::NAN),
            ..event(kind, "Tokyo launch")
        };
        assert!(matches!(
            session.handle_asr(&stale, 9, input.clone(), true, &mut enricher)?,
            AsrUpdate::Ignored
        ));
        assert!(matches!(
            session.handle_asr(&handle, 9, input, true, &mut enricher),
            Err(Error::InvalidConfig(_))
        ));
        assert_eq!(session.brain_context(request.generation), Some(&request));
        assert!(session.accepts_pcm(request.generation));
        assert!(!session.is_ended());
        assert!(enricher.texts.is_empty());
        assert_eq!(vault.retrieval_runs(200)?.len(), runs_before);
    }
    assert_eq!(
        session.handle_brain(request.generation, BrainEvent::Done, false)?,
        Some(BrainEvent::Done)
    );
    assert!(session.finish_playout(request.generation)?);
    let update = session.handle_asr(
        &handle,
        9,
        event(AsrEventKind::Final, "Tokyo launch"),
        false,
        &mut enricher,
    )?;
    let AsrUpdate::Final(next) = update else {
        panic!("incoming handle and revision remain retryable")
    };
    assert_eq!(next.generation.value(), request.generation.value() + 1);
    assert!(!next.externally_tainted);
    Ok(())
}

fn config() -> VoiceSessionConfig {
    let mut config = VoiceSessionConfig::new(
        "session:test",
        InterlocutorResolutionInput {
            owner_session: true,
            parties: Vec::new(),
            voice_session_ref: None,
        },
    );
    config.tools_enabled = true;
    config
}

fn start(session: &mut VoiceCascadeSession, tainted: bool) -> Result<BrainRequest> {
    let handle = session.open_utterance("turn", SpeculativeSessionConfig::default())?;
    let mut enricher = Enricher::default();
    let update = session.handle_asr(
        &handle,
        1,
        event(AsrEventKind::Final, "Tokyo launch"),
        tainted,
        &mut enricher,
    )?;
    let AsrUpdate::Final(request) = update else {
        panic!("final request")
    };
    Ok(request)
}

fn pcm(generation: GenerationEpoch) -> PcmFrame {
    PcmFrame {
        generation,
        sample_rate: 24_000,
        samples: vec![1, 2, 3],
    }
}

fn call(id: &str) -> BrainEvent {
    BrainEvent::Tool(ToolEvent::Call {
        call_id: id.to_owned(),
        name: "lookup".to_owned(),
        input: json!({"query": "launch"}),
    })
}

fn result(id: &str) -> BrainEvent {
    BrainEvent::Tool(ToolEvent::Result {
        call_id: id.to_owned(),
        output: json!({"refs": ["tool:result"]}),
        is_error: false,
    })
}

#[derive(Default)]
struct TestBrain {
    requests: Vec<BrainRequest>,
    contexts: Vec<BrainRequest>,
    cancelled: Vec<GenerationEpoch>,
    fail_cancel: bool,
}

impl Brain for TestBrain {
    fn start(&mut self, request: &BrainRequest) -> Result<()> {
        self.requests.push(request.clone());
        Ok(())
    }

    fn update_context(&mut self, request: &BrainRequest) -> Result<()> {
        self.contexts.push(request.clone());
        Ok(())
    }

    fn cancel(&mut self, generation: GenerationEpoch) -> Result<()> {
        self.cancelled.push(generation);
        if self.fail_cancel {
            Err(Error::InvalidConfig("test brain failure".to_owned()))
        } else {
            Ok(())
        }
    }
}

#[derive(Default)]
struct TestTts {
    commands: Vec<TtsCommand>,
    fail_cancel: bool,
}

impl TtsSeamClient for TestTts {
    fn submit(&mut self, command: TtsCommand) -> Result<()> {
        let fail = self.fail_cancel && matches!(&command, TtsCommand::Cancel { .. });
        self.commands.push(command);
        if fail {
            Err(Error::InvalidConfig("test TTS failure".to_owned()))
        } else {
            Ok(())
        }
    }
}

#[derive(Default)]
struct TestSafeguard {
    pending: Vec<SafeguardRequest>,
}

impl Safeguard for TestSafeguard {
    fn submit(&mut self, request: SafeguardRequest) -> Result<()> {
        // Deliberately no verdict yet. TTS must be able to produce audio now.
        self.pending.push(request);
        Ok(())
    }
}

#[derive(Default)]
struct TestControl {
    queued: VecDeque<PcmFrame>,
    client_queued: Vec<PcmFrame>,
    flushed: Vec<GenerationEpoch>,
    events: Vec<ControlEvent>,
}

impl CascadeControl for TestControl {
    fn flush_queued_pcm(&mut self, generation: GenerationEpoch) -> Result<()> {
        self.queued.retain(|frame| frame.generation != generation);
        self.flushed.push(generation);
        Ok(())
    }

    fn submit(&mut self, event: ControlEvent) -> Result<()> {
        match &event {
            ControlEvent::PlayoutStop { generation, .. } => {
                self.client_queued
                    .retain(|frame| frame.generation != *generation);
            }
            ControlEvent::SessionEnded => self.client_queued.clear(),
            ControlEvent::Safeguard { .. } => {}
        }
        self.events.push(event);
        Ok(())
    }
}

#[test]
fn hosted_eviction_repoints_banked_identity_to_self_hosted_spine() -> Result<()> {
    use crate::voice_cascade::hosted_tts::{
        HostedProvider, HostedTransport, HostedTtsAdapter, HostedWork,
    };
    use crate::voice_identity::ref_bank::{VoiceRefOrigin, VoiceRefPack, VoiceRegisterClip};
    #[derive(Default)]
    struct Queue(Vec<HostedWork>);
    impl HostedTransport for Queue {
        fn try_submit(&mut self, work: HostedWork) -> Result<()> {
            self.0.push(work);
            Ok(())
        }
    }
    let (_dir, vault) = vault();
    let pack = VoiceRefPack {
        version: 1,
        id: "owner-voice-refs".into(),
        voice_id: "owner-voice".into(),
        owner: entity(6),
        origin: VoiceRefOrigin::Captured,
        clips: vec![VoiceRegisterClip {
            register: "neutral".into(),
            media_type: "audio/wav".into(),
            audio: vec![4, 5, 6],
            transcript: "reference".into(),
        }],
    };
    vault.store_voice_ref_pack(&pack)?;
    for provider in [HostedProvider::Cartesia, HostedProvider::ElevenLabsFlash] {
        let request = vault.prepare_voice_clone(&pack.voice_id, provider.target(), false)?;
        vault.record_voice_target_clone(&request, "ephemeral-voice", 1)?;
        let mut session = VoiceCascadeSession::new(Arc::clone(&vault), config())?;
        let old = start(&mut session, false)?.generation;
        let mut hosted =
            HostedTtsAdapter::bind(&vault, &pack.voice_id, provider, false, Queue::default())?;
        hosted.submit(TtsCommand::Start { generation: old })?;
        hosted.submit(TtsCommand::Text {
            generation: old,
            text: "hello".into(),
        })?;
        hosted.submit(TtsCommand::End { generation: old })?;
        let frame = hosted.receive_pcm(old, 0, 0, &[1, 0])?;
        assert!(hosted.filter_pcm(&session, frame.clone()).is_some());
        // The vendor and its voice ID disappear; the bank identity remains.
        vault.evict_voice_target(&pack.voice_id, provider.target())?;
        assert!(hosted.receive_pcm(old, 0, 1, &[1, 0]).is_err());
        assert!(
            HostedTtsAdapter::bind(&vault, &pack.voice_id, provider, false, Queue::default())
                .is_err()
        );
        let stop = session.end();
        assert_eq!(stop.generation, Some(old));
        hosted.submit(TtsCommand::Cancel { generation: old })?;
        assert!(hosted.receive_pcm(old, 0, 1, &[1, 0]).is_err());
        assert!(hosted.filter_pcm(&session, frame).is_none());
        drop(hosted);
        let spine = vault.prepare_voice_clone(&pack.voice_id, "voxcpm2", false)?;
        assert_eq!(
            vault
                .voice_identity(&spine.voice_id)?
                .map(|voice| voice.owner),
            Some(pack.owner)
        );
        assert_eq!(spine.source_packs, std::slice::from_ref(&pack.id));
        assert_eq!(spine.clips, pack.clips);
        let mut new_session = VoiceCascadeSession::new(Arc::clone(&vault), config())?;
        let current = start(&mut new_session, false)?.generation;
        assert!(
            new_session
                .filter_pcm(PcmFrame {
                    generation: current,
                    sample_rate: 24_000,
                    samples: vec![1]
                })
                .is_some()
        );
        assert!(
            new_session
                .filter_pcm(PcmFrame {
                    generation: old,
                    sample_rate: 24_000,
                    samples: vec![1]
                })
                .is_none()
        );
    }
    Ok(())
}
