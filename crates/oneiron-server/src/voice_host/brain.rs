//! The voice call's brain (OF-410): the chat role, as `/ai/chat` runs it.
//! Each final starts one turn on the vault's chat seat with the answering
//! agent's instructions, this call's prior turns and the transcript, and
//! tools off. The turn is a run on the vault's budget policy for the payer,
//! one line per turn, admitted through its role before any model is
//! called. Its stream's text comes back to the host as [`VoiceBrainOut`],
//! and the host speaks it past the session's safeguards. A cancel drops the
//! turn's stream, and its run settles what it spent.

use std::sync::{Arc, Mutex};

use futures_util::StreamExt;
use oneiron::llm::{DEFAULT_BUDGET_RESERVE_UNITS, FinishReason};
use oneiron::voice_cascade::{Brain, BrainEvent, BrainRequest, GenerationEpoch};
use oneiron::{
    BudgetExhaustionPolicy, LlmMessage, LlmMessageRole, LlmStream, LlmStreamEvent, Vault,
    WriteActor,
};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use super::{HostError, VoiceBrainOut};
use crate::ai_host::{AiHandle, CHAT_ROLE};
use crate::api::ai::chat::{chat_request, text_message};
use crate::models::Seat;

fn refused(message: impl std::fmt::Display) -> oneiron::Error {
    oneiron::Error::InvalidConfig(format!("voice brain: {message}"))
}

/// What the call's chat brain answers with and on whose line.
pub struct ChatBrainBindings {
    pub ai: AiHandle,
    pub vault: Arc<Vault>,
    /// The answering agent's instructions, read under the call owner's
    /// credential; `None` answers with none.
    pub instructions: Option<String>,
    /// The actor whose budget line each turn runs on.
    pub payer: WriteActor,
    /// Where the turns' events go: the host's `brain_out`.
    pub out: mpsc::Sender<VoiceBrainOut>,
}

/// The chat role as a voice call's [`Brain`].
pub struct ChatBrain {
    bindings: ChatBrainBindings,
    seat: Seat,
    /// This call's turns so far, the person's and the brain's.
    history: Arc<Mutex<Vec<LlmMessage>>>,
    turn: Option<(GenerationEpoch, JoinHandle<()>)>,
}

impl ChatBrain {
    /// A server with no chat seat refuses.
    pub fn new(bindings: ChatBrainBindings) -> Result<Self, HostError> {
        let seat = bindings
            .ai
            .chat_seat()
            .cloned()
            .ok_or_else(|| refused("no [models] rung serves generative_reasoner"))?;
        Ok(Self {
            bindings,
            seat,
            history: Arc::new(Mutex::new(Vec::new())),
            turn: None,
        })
    }

    /// The turn's admitted stream, opened before anything is spoken.
    fn open(&self, request: &BrainRequest) -> oneiron::Result<LlmStream<'static>> {
        let ChatBrainBindings {
            ai,
            vault,
            instructions,
            payer,
            ..
        } = &self.bindings;
        let settings = ai.chat_settings();
        let mut messages: Vec<LlmMessage> = instructions
            .iter()
            .map(|text| text_message(LlmMessageRole::System, text.clone()))
            .collect();
        {
            let history = self
                .history
                .lock()
                .map_err(|_| refused("history poisoned"))?;
            let skip = history.len().saturating_sub(settings.history_turns);
            messages.extend(history.iter().skip(skip).cloned());
        }
        messages.push(text_message(
            LlmMessageRole::User,
            request.transcript.clone(),
        ));
        let admitted = ai
            .admit_role(vault, CHAT_ROLE, chat_request(&self.seat, messages))
            .map_err(refused)?;
        let line = format!(
            "voice:{}:{}",
            request.session_ref,
            request.generation.value()
        );
        let units = settings.turn_budget_units;
        let meter = vault.policy_budget_guard(
            line.clone(),
            units,
            DEFAULT_BUDGET_RESERVE_UNITS.min(units),
            BudgetExhaustionPolicy::Suspend,
            payer.clone(),
        )?;
        let run = ai.undeclared_run(line, meter);
        admitted
            .ladder
            .stream(&run, admitted.request, None)
            .map_err(|error| refused(format!("{error:?}")))
    }

    fn abort(&mut self) {
        if let Some((_, turn)) = self.turn.take() {
            turn.abort();
        }
    }
}

impl Brain for ChatBrain {
    fn start(&mut self, request: &BrainRequest) -> oneiron::Result<()> {
        self.abort();
        let stream = self.open(request)?;
        let generation = request.generation;
        self.history
            .lock()
            .map_err(|_| refused("history poisoned"))?
            .push(text_message(
                LlmMessageRole::User,
                request.transcript.clone(),
            ));
        let turn = Turn {
            generation,
            out: self.bindings.out.clone(),
            history: Arc::clone(&self.history),
        };
        let entered = self.bindings.ai.enter_turn();
        let handle = tokio::spawn(async move {
            let _entered = entered;
            turn.run(stream).await;
        });
        self.turn = Some((generation, handle));
        Ok(())
    }

    /// Tools are off: no tool event is ever accepted, so nothing resumes.
    fn update_context(&mut self, _request: &BrainRequest) -> oneiron::Result<()> {
        Ok(())
    }

    fn cancel(&mut self, generation: GenerationEpoch) -> oneiron::Result<()> {
        if self
            .turn
            .as_ref()
            .is_some_and(|(current, _)| *current == generation)
        {
            self.abort();
        }
        Ok(())
    }
}

impl Drop for ChatBrain {
    fn drop(&mut self) {
        self.abort();
    }
}

/// One turn's stream, handed back event by event.
struct Turn {
    generation: GenerationEpoch,
    out: mpsc::Sender<VoiceBrainOut>,
    history: Arc<Mutex<Vec<LlmMessage>>>,
}

impl Turn {
    async fn run(self, mut stream: LlmStream<'static>) {
        let mut said = String::new();
        let event = loop {
            match stream.next().await {
                Some(Ok(LlmStreamEvent::TextDelta { text, .. })) => {
                    said.push_str(&text);
                    if !self.send(BrainEvent::TextDelta(text)).await {
                        return;
                    }
                }
                // A cancelled terminal is no answer: nothing more is said.
                Some(Ok(LlmStreamEvent::Done {
                    finish_reason: FinishReason::Cancelled,
                    ..
                })) => return,
                Some(Ok(LlmStreamEvent::Done { .. })) => break BrainEvent::Done,
                Some(Ok(_)) => {}
                Some(Err(error)) => break BrainEvent::Error(error.to_string()),
                None => break BrainEvent::Error("stream ended without a terminal".into()),
            }
        };
        if matches!(event, BrainEvent::Done)
            && let Ok(mut history) = self.history.lock()
        {
            history.push(text_message(LlmMessageRole::Assistant, said));
        }
        self.send(event).await;
    }

    /// `false` once the host stopped listening.
    async fn send(&self, event: BrainEvent) -> bool {
        self.out
            .send(VoiceBrainOut {
                generation: self.generation,
                event,
                externally_tainted: false,
            })
            .await
            .is_ok()
    }
}
