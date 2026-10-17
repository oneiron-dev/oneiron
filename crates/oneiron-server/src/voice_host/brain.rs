//! The voice call's brain (OF-410): the chat role, as `/ai/chat` runs it.
//! Each final starts one turn on the vault's chat seat with the answering
//! agent's instructions, this call's prior turns, the memories its retrieval
//! found and the transcript, and tools off. The memories are read under the
//! call's credential and clamped to its audience, and go in as fenced data,
//! never instructions. The turn is a run on the vault's budget policy for
//! the payer, one line per turn, admitted through its role before any model
//! is called. Its stream's text comes back to the host as [`VoiceBrainOut`],
//! and the host speaks it past the session's safeguards. A cancel drops the
//! turn's stream, and its run settles what it spent; what it had already
//! said stays in the history, marked interrupted. Each safeguard notice said
//! to the person enters the history too, and the next turn hears it.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};

use futures_util::StreamExt;
use oneiron::context_board::{BoardBlockHeader, BoardBudgetRequest};
use oneiron::llm::{DEFAULT_BUDGET_RESERVE_UNITS, FinishReason};
use oneiron::store::GateSystemNoticeRecord;
use oneiron::voice_cascade::{Brain, BrainEvent, BrainRequest, GenerationEpoch};
use oneiron::{
    BudgetExhaustionPolicy, DisclosureContext, EntityId, LlmMessage, LlmMessageRole, LlmStream,
    LlmStreamEvent, MemoriesSection, Vault, WriteActor,
};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use super::{HostError, VoiceBrainOut};
use crate::ai_host::{AiHandle, CHAT_ROLE};
use crate::api::ai::chat::{chat_request, text_message};
use crate::auth::CoreAuth;
use crate::models::Seat;

/// A turn that hears retrieved memories carries context from outside it,
/// so its speech passes the outbound safeguard as a tool result's would.
const MEMORIES_TAINT_TURN: bool = true;
/// How an interrupted answer's history entry ends: the person cut in after
/// the brain had said this much.
const INTERRUPTED_MARK: &str = " [interrupted: the person cut in here]";

fn refused(message: impl std::fmt::Display) -> oneiron::Error {
    oneiron::Error::InvalidConfig(format!("voice brain: {message}"))
}

/// What the call's chat brain answers with and on whose line.
pub struct ChatBrainBindings {
    pub ai: AiHandle,
    pub vault: Arc<Vault>,
    /// The call's credential, as the owner door admitted it at hello. Each
    /// turn's memories are read under it; it is never bound again.
    pub(crate) auth: CoreAuth,
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
    turn: Option<Running>,
}

/// The turn answering now.
struct Running {
    generation: GenerationEpoch,
    handle: JoinHandle<()>,
    /// What it has handed the speech host so far; whichever ends it, the
    /// turn's terminal or a cancel, takes it.
    said: Arc<Mutex<Option<String>>>,
}

/// The turn's retrieved memories, as the brain hears them.
struct Memories {
    /// The fenced MEMORIES board.
    board: String,
    /// The rows it carries, for the audience's disclosure receipts.
    ids: Vec<EntityId>,
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

    /// The turn's admitted stream, opened before anything is spoken, and
    /// whether the turn heard context from outside it.
    fn open(&self, request: &BrainRequest) -> oneiron::Result<(LlmStream<'static>, bool)> {
        let ChatBrainBindings {
            ai,
            vault,
            instructions,
            payer,
            ..
        } = &self.bindings;
        let settings = ai.chat_settings();
        let memories = self.memories(request)?;
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
        if let Some(memories) = &memories {
            messages.push(text_message(LlmMessageRole::User, memories.board.clone()));
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
        let stream = admitted
            .ladder
            .stream(&run, admitted.request, None)
            .map_err(|error| refused(format!("{error:?}")))?;
        let Some(memories) = memories else {
            return Ok((stream, false));
        };
        // The rows are going out: a contact who heard one under standing
        // clearance gets its quiet receipt. The owner alone gets none.
        vault.record_standing_disclosure_uses(
            &memories.ids,
            Some(&request.interlocutors),
            &BTreeMap::new(),
            &BTreeSet::from([oneiron::consent::contact_disclosure_voice_channel(
                &request.session_ref,
            )]),
        )?;
        Ok((stream, MEMORIES_TAINT_TURN))
    }

    /// The rows the turn's retrieval found, read under the call's credential,
    /// narrowed to its audience and clamped to what that audience may hear.
    /// Only a row with text to say is kept: the brain has no tools to open a
    /// bare reference. `None` when none is left.
    fn memories(&self, request: &BrainRequest) -> oneiron::Result<Option<Memories>> {
        let refs = &request.retrieval.result_refs;
        if refs.is_empty() {
            return Ok(None);
        }
        let ChatBrainBindings { vault, auth, .. } = &self.bindings;
        let ids = refs
            .iter()
            .map(|reference| EntityId::from_hex(reference))
            .collect::<oneiron::Result<Vec<_>>>()?;
        let set = &request.interlocutors;
        let read = crate::api::scoped_read_for_core_auth(vault, auth)
            .and_then(|read| {
                crate::api::narrow_to_core_audience(vault, auth, read, None, None, Some(set))
            })
            .map_err(|error| refused(format!("{error:?}")))?;
        let disclosure = DisclosureContext::resolve(vault, set.clone())?;
        let mut section = MemoriesSection::pins_only(Some(disclosure.assembly(0)));
        let receipts =
            section.include_pinned_ids_with_disclosure(&read, &ids, Some(&disclosure))?;
        section.rows.retain(|row| row.snippet.is_some());
        let withheld: usize = receipts
            .iter()
            .map(|receipt| receipt.suppressed_count)
            .sum();
        tracing::debug!(
            found = ids.len(),
            heard = section.rows.len(),
            withheld,
            "voice: the turn's memories"
        );
        if section.rows.is_empty() {
            return Ok(None);
        }
        let ids = section
            .rows
            .iter()
            .map(|row| EntityId::from_hex(&row.id))
            .collect::<oneiron::Result<Vec<_>>>()?;
        let render = section
            .render_board(
                &BoardBlockHeader {
                    epoch: request.generation.value(),
                    scope: request.session_ref.clone(),
                },
                BoardBudgetRequest {
                    harness_default_tok: crate::mcp::MCP_BOARD_BUDGET_TOK,
                    caller_limit_tok: None,
                    explicit_override_tok: None,
                },
            )
            .map_err(refused)?;
        Ok(Some(Memories {
            board: render.text,
            ids,
        }))
    }

    /// Stops the turn answering. What it had handed the speech host enters
    /// the history, marked interrupted; the rest was never said.
    fn abort(&mut self) {
        let Some(running) = self.turn.take() else {
            return;
        };
        running.handle.abort();
        let said = running.said.lock().ok().and_then(|mut said| said.take());
        if let Some(said) = said.filter(|said| !said.is_empty())
            && let Ok(mut history) = self.history.lock()
        {
            history.push(text_message(
                LlmMessageRole::Assistant,
                format!("{said}{INTERRUPTED_MARK}"),
            ));
        }
    }
}

impl Brain for ChatBrain {
    fn start(&mut self, request: &BrainRequest) -> oneiron::Result<()> {
        self.abort();
        let (stream, tainted) = self.open(request)?;
        let generation = request.generation;
        self.history
            .lock()
            .map_err(|_| refused("history poisoned"))?
            .push(text_message(
                LlmMessageRole::User,
                request.transcript.clone(),
            ));
        let said = Arc::new(Mutex::new(Some(String::new())));
        let turn = Turn {
            generation,
            tainted,
            out: self.bindings.out.clone(),
            history: Arc::clone(&self.history),
            said: Arc::clone(&said),
        };
        let entered = self.bindings.ai.enter_turn();
        let handle = tokio::spawn(async move {
            let _entered = entered;
            turn.run(stream).await;
        });
        self.turn = Some(Running {
            generation,
            handle,
            said,
        });
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
            .is_some_and(|running| running.generation == generation)
        {
            self.abort();
        }
        Ok(())
    }

    /// The notice enters the call's history as System context, so the next
    /// turn hears it; a turn already answering is not interrupted.
    fn notice(&mut self, notice: &GateSystemNoticeRecord) -> oneiron::Result<()> {
        self.history
            .lock()
            .map_err(|_| refused("history poisoned"))?
            .push(text_message(
                LlmMessageRole::System,
                format!(
                    "Safeguard notice said to the person ({}): {}",
                    notice.notice_type, notice.body
                ),
            ));
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
    /// The turn heard context from outside it: every event says so, from
    /// the first delta, so its first sentence already passes the safeguard.
    tainted: bool,
    out: mpsc::Sender<VoiceBrainOut>,
    history: Arc<Mutex<Vec<LlmMessage>>>,
    /// What the turn has handed the speech host, shared with its cancel.
    said: Arc<Mutex<Option<String>>>,
}

impl Turn {
    async fn run(self, mut stream: LlmStream<'static>) {
        let event = loop {
            match stream.next().await {
                Some(Ok(LlmStreamEvent::TextDelta { text, .. })) => {
                    if !self.send(BrainEvent::TextDelta(text.clone())).await {
                        return;
                    }
                    if let Ok(mut draft) = self.said.lock()
                        && let Some(said) = draft.as_mut()
                    {
                        said.push_str(&text);
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
        let said = self.said.lock().ok().and_then(|mut said| said.take());
        if matches!(event, BrainEvent::Done)
            && let Some(said) = said
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
                externally_tainted: self.tainted,
            })
            .await
            .is_ok()
    }
}
