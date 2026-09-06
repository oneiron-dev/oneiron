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

mod retrieval;
mod safeguard;
mod session;

fn vault() -> (tempfile::TempDir, Arc<Vault>) {
    let dir = tempfile::tempdir().expect("temporary vault");
    let vault =
        Vault::open(dir.path(), crate::test_util::embedding_test_config()).expect("open vault");
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
