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
//! to the person enters the history too, and the next turn hears it. A turn
//! assembled for a new audience revision, as after an attendee entered the
//! call's room, starts from that audience's own history (OF-365 P5), and so
//! does one after another call went live in the room or ended. A call heard
//! in a room reads it again each turn, with every speaker a call live there
//! must place; a room a missing entry holds starts no turn (FIX 3342). What
//! a turn's memories read found, heard and withheld goes to the owner's
//! client with the turn's first event, its narrowing receipts whole; a turn
//! cancelled or ended before any event sends it then.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};

use futures_util::StreamExt;
use oneiron::claim::ScopedRead;
use oneiron::context_board::{BoardBlockHeader, BoardBudgetRequest};
use oneiron::conversation::RoomLiveSpeakerEntries;
use oneiron::llm::run_admission::PayerPerson;
use oneiron::llm::{DEFAULT_BUDGET_RESERVE_UNITS, FinishReason};
use oneiron::store::GateSystemNoticeRecord;
use oneiron::voice_cascade::{Brain, BrainEvent, BrainRequest, GenerationEpoch, TurnMemories};
use oneiron::{
    BudgetExhaustionPolicy, DisclosureContext, EntityId, LlmMessage, LlmMessageRole, LlmStream,
    LlmStreamEvent, MemoriesSection, Vault, WriteActor,
};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use super::speech::{TurnSources, add_rows, notice_rows};
use super::{HostError, VoiceBrainOut};
use crate::ai_host::{AiHandle, CHAT_ROLE};
use crate::api::RoomAudience;
use crate::api::ai::chat::{chat_request, text_message};
use crate::auth::CoreAuth;
use crate::models::Seat;

// Vault memory/diary material is exempt from the external/tool sentence
// safeguard. Live connector results enter separately and always add taint.
/// How an interrupted answer's history entry ends: the person cut in after
/// the brain had said this much.
const INTERRUPTED_MARK: &str = " [interrupted: the person cut in here]";
/// What the call's earlier turns become for a turn assembled for a new
/// audience (CALLS.md: FIX 1389 history).
const PRIOR_TURNS_ON_NEW_AUDIENCE: PriorTurns = PriorTurns::Dropped;

/// The policies the call's earlier turns may follow when its audience moves.
enum PriorTurns {
    /// They leave the model's context. They carry no source or cut that a
    /// new audience could be read under, so none is kept; the vault keeps
    /// whatever was recorded.
    Dropped,
}

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
    /// The room the call is heard in, as the host proved the caller reads
    /// it at hello: the host's own binding, never a claim a request makes.
    /// Each turn proves it again under `auth`. `None` for no room.
    pub(crate) room: Option<EntityId>,
    /// The answering agent's instructions, read under the call owner's
    /// credential; `None` answers with none.
    pub instructions: Option<String>,
    /// The AGENT_DEF `instructions` were read from, which each turn lists
    /// among the rows it was made from (FIX 4778).
    pub agent: EntityId,
    /// The actor whose budget line each turn runs on.
    pub payer: WriteActor,
    /// Who each turn bills when a room pays for the call (FIX 805), which
    /// the host resolved at hello; `None` is the vault owner.
    pub funding: Option<PayerPerson>,
    /// Where the turns' events go: the host's `brain_out`.
    pub out: mpsc::Sender<VoiceBrainOut>,
}

/// The chat role as a voice call's [`Brain`].
pub struct ChatBrain {
    bindings: ChatBrainBindings,
    seat: Seat,
    /// This call's turns so far, the person's and the brain's.
    history: Arc<Mutex<Vec<HistoryEntry>>>,
    /// The audience revision `history` was heard under.
    history_revision: Option<u64>,
    /// The room's live speakers `history` was heard under, for a call heard
    /// in a room.
    history_live: Option<RoomLiveSpeakerEntries>,
    turn: Option<Running>,
    retiring: Vec<JoinHandle<()>>,
    /// Each tool context, beside the rows the connector call listed.
    foreign: Vec<(oneiron::task_verb::sdk::ConnectorToolResult, Vec<EntityId>)>,
    /// Every row this call's turns were made from so far: a safeguard
    /// notice is not told which turn's sentence it judged.
    said_ever: Option<Vec<EntityId>>,
}

/// One history message, beside the rows it was made from (FIX 4778);
/// `None` when they are unknown.
type HistoryEntry = (LlmMessage, Option<Vec<EntityId>>);

/// The turn answering now.
struct Running {
    generation: GenerationEpoch,
    handle: JoinHandle<()>,
    /// What it has handed the speech host so far; whichever ends it, the
    /// turn's terminal or a cancel, takes it.
    said: Arc<Mutex<Option<String>>>,
    /// Its memories receipt until an event carries it, shared the same way.
    memories: Arc<Mutex<Option<TurnMemories>>>,
    /// The rows it was made from until an event carries them.
    sources: Arc<Mutex<Option<TurnSources>>>,
    /// The rows what it says is made from, for its history entry.
    said_from: Option<Vec<EntityId>>,
}

/// The turn's retrieved memories, as the brain hears them.
struct Memories {
    /// The fenced MEMORIES board.
    board: String,
    /// The rows it carries, for the audience's disclosure receipts.
    ids: Vec<EntityId>,
}

/// What a turn's memories read gives: the memories heard, what the read
/// found, heard and withheld, and the live speakers of the call's room.
type TurnRead = (
    Option<Memories>,
    Option<TurnMemories>,
    Option<RoomLiveSpeakerEntries>,
);

/// What opening a turn gives: its stream, whether it heard outside context,
/// its memories receipt and the rows its model input was read from.
type OpenedTurn = (
    LlmStream<'static>,
    bool,
    Option<TurnMemories>,
    Option<Vec<EntityId>>,
);

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
            history_revision: None,
            history_live: None,
            turn: None,
            retiring: Vec::new(),
            foreign: Vec::new(),
            said_ever: Some(Vec::new()),
        })
    }

    /// The newcomer barrier's history half: a turn for a new audience
    /// revision starts from that audience's history, never the old one's.
    /// So does a turn whose room's live speakers moved, as when another call
    /// went live there or ended, though this call's audience looks the same.
    fn rebuild_history(
        &mut self,
        audience_revision: u64,
        live: Option<RoomLiveSpeakerEntries>,
    ) -> oneiron::Result<()> {
        if self.history_revision == Some(audience_revision) && self.history_live == live {
            return Ok(());
        }
        if self.history_revision.is_some() {
            self.foreign.clear();
        }
        match PRIOR_TURNS_ON_NEW_AUDIENCE {
            PriorTurns::Dropped => self
                .history
                .lock()
                .map_err(|_| refused("history poisoned"))?
                .clear(),
        }
        self.history_revision = Some(audience_revision);
        self.history_live = live;
        Ok(())
    }

    /// The turn's admitted stream over its `memories`, opened before
    /// anything is spoken, whether the turn heard context from outside it,
    /// what its memories read found and withheld, and the rows its model
    /// input was read from (FIX 4778): the answering agent's definition,
    /// each history message it hears, the memories and each tool context's
    /// rows. The person's transcript is no stored row.
    fn open(
        &self,
        request: &BrainRequest,
        memories: Option<Memories>,
        heard: Option<TurnMemories>,
    ) -> oneiron::Result<OpenedTurn> {
        let ChatBrainBindings {
            ai,
            vault,
            instructions,
            agent,
            payer,
            funding,
            ..
        } = &self.bindings;
        let settings = ai.chat_settings();
        let mut messages: Vec<LlmMessage> = instructions
            .iter()
            .map(|text| text_message(LlmMessageRole::System, text.clone()))
            .collect();
        let mut said_from = Some(vec![*agent]);
        {
            let history = self
                .history
                .lock()
                .map_err(|_| refused("history poisoned"))?;
            let skip = history.len().saturating_sub(settings.history_turns);
            for (message, rows) in history.iter().skip(skip) {
                messages.push(message.clone());
                add_rows(&mut said_from, rows.as_deref());
            }
        }
        if let Some(memories) = &memories {
            messages.push(text_message(LlmMessageRole::User, memories.board.clone()));
            add_rows(&mut said_from, Some(&memories.ids));
        }
        for (context, rows) in &self.foreign {
            // The connector's own source and foreign marker stay with every
            // field. They are task data, never a System instruction.
            let data = serde_json::to_string(context).map_err(refused)?;
            messages.push(text_message(LlmMessageRole::User, data));
            add_rows(&mut said_from, Some(rows));
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
        let run = ai.model_runtime().funded_run(line, meter, funding.clone());
        let stream = admitted
            .ladder
            .stream(&run, admitted.request, None)
            .map_err(|error| refused(format!("{error:?}")))?;
        let Some(memories) = memories else {
            return Ok((stream, !self.foreign.is_empty(), heard, said_from));
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
        Ok((stream, !self.foreign.is_empty(), heard, said_from))
    }

    /// The rows the turn's retrieval found, read under the call's credential,
    /// narrowed to its audience and clamped to what that audience may hear.
    /// Only a row with text to say is kept: the brain has no tools to open a
    /// bare reference. `None` when none is left. Beside it, what the read
    /// found, heard and withheld, whenever the retrieval found a row, and
    /// the live speakers of the call's room.
    ///
    /// A call heard in a room proves the room on every turn, retrieval or
    /// none, so a room whose live calls' speakers are not all entered holds
    /// the turn with the engine's typed error, and no turn starts as if the
    /// room were complete. Its audience is the room's members and every
    /// speaker a call live there must place, named or not (FIX 3342).
    fn memories(&self, request: &BrainRequest) -> oneiron::Result<TurnRead> {
        let ChatBrainBindings { vault, auth, .. } = &self.bindings;
        let in_room = match self.bindings.room {
            Some(room) => Some(room_audience(vault, auth, room)?),
            None => None,
        };
        let live = in_room
            .as_ref()
            .map(|(_, _, audience)| audience.live.clone());
        let refs = &request.retrieval.result_refs;
        if refs.is_empty() {
            return Ok((None, None, live));
        }
        let ids = refs
            .iter()
            .map(|reference| EntityId::from_hex(reference))
            .collect::<oneiron::Result<Vec<_>>>()?;
        let (read, members, room) = match in_room {
            Some((read, members, room)) => (read, Some(members), Some(room)),
            None => {
                let read = crate::api::scoped_read_for_core_auth(vault, auth)
                    .map_err(|error| refused(format!("{error:?}")))?;
                (read, None, None)
            }
        };
        let set = match &room {
            Some(room) => room.live.merged_into(request.interlocutors.clone()),
            None => request.interlocutors.clone(),
        };
        let read = crate::api::narrow_to_core_audience(
            vault,
            auth,
            read,
            members.as_deref(),
            room.as_ref(),
            Some(&set),
        )
        .map_err(|error| refused(format!("{error:?}")))?;
        // With no room (or no proven reader) this is `resolve`'s context.
        let reader = room.as_ref().is_some_and(|room| room.reader.is_some());
        let disclosure = DisclosureContext::resolve_room(vault, set, reader)?;
        let mut section = MemoriesSection::pins_only(Some(disclosure.assembly(0)));
        let receipts =
            section.include_pinned_ids_with_disclosure(&read, &ids, Some(&disclosure))?;
        section.rows.retain(|row| row.snippet.is_some());
        let heard = TurnMemories {
            found: ids.len(),
            heard: section.rows.len(),
            receipts,
        };
        if section.rows.is_empty() {
            return Ok((None, Some(heard), live));
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
        Ok((
            Some(Memories {
                board: render.text,
                ids,
            }),
            Some(heard),
            live,
        ))
    }

    /// Only a host that actually delivered a connector reply supplies this.
    /// Context stays foreign for every later turn that can still hear it.
    /// `rows` are the ones the connector call that delivered it listed.
    pub(super) fn add_foreign(
        &mut self,
        result: oneiron::task_verb::sdk::ConnectorToolResult,
        rows: Vec<EntityId>,
    ) {
        self.foreign.push((result, rows));
    }

    pub(super) fn producer_pending(&self, generation: GenerationEpoch) -> bool {
        self.turn
            .as_ref()
            .is_some_and(|turn| turn.generation == generation && !turn.handle.is_finished())
    }

    /// Whether no turn of this brain is answering or still winding down, so
    /// nothing it started can write any more.
    pub(super) fn at_rest(&self) -> bool {
        self.turn
            .as_ref()
            .is_none_or(|turn| turn.handle.is_finished())
            && self.retiring.iter().all(JoinHandle::is_finished)
    }

    /// An abort only requests cancellation. Joining observes the stream drop,
    /// including the existing exactly-once partial-usage settlement.
    pub(super) async fn settle_retired(&mut self) {
        for task in self.retiring.drain(..) {
            let _ = task.await;
        }
    }

    /// Stops the turn answering. What it had handed the speech host enters
    /// the history, marked interrupted; the rest was never said.
    fn abort(&mut self) {
        let Some(running) = self.turn.take() else {
            return;
        };
        running.handle.abort();
        self.retiring.push(running.handle);
        // A turn cancelled before its first event still owes the owner's
        // client its memories receipt. An empty delta carries it: the host
        // hands the receipt on first and says nothing for a cancelled turn.
        if let Some(memories) = running
            .memories
            .lock()
            .ok()
            .and_then(|mut memories| memories.take())
            && self
                .bindings
                .out
                .try_send(VoiceBrainOut {
                    generation: running.generation,
                    event: BrainEvent::TextDelta(String::new()),
                    externally_tainted: false,
                    memories: Some(memories),
                    sources: running
                        .sources
                        .lock()
                        .ok()
                        .and_then(|mut sources| sources.take()),
                })
                .is_err()
        {
            tracing::warn!("voice brain: a cancelled turn's memories receipt was not delivered");
        }
        let said = running.said.lock().ok().and_then(|mut said| said.take());
        if let Some(said) = said.filter(|said| !said.is_empty())
            && let Ok(mut history) = self.history.lock()
        {
            history.push((
                text_message(
                    LlmMessageRole::Assistant,
                    format!("{said}{INTERRUPTED_MARK}"),
                ),
                running.said_from,
            ));
        }
    }
}

/// `room`'s audience as the call's credential reads it now, with the read
/// that proved it: its members and live speakers, in one snapshot. The
/// engine reads them, so a hold stays its typed error.
fn room_audience<'a>(
    vault: &'a Vault,
    auth: &CoreAuth,
    room: EntityId,
) -> oneiron::Result<(ScopedRead<'a>, Vec<EntityId>, RoomAudience)> {
    let read = crate::api::scoped_read_for_core_auth(vault, auth)
        .map_err(|error| refused(format!("{error:?}")))?;
    let principal = auth
        .principal_ref()
        .and_then(|id| EntityId::from_hex(id).ok());
    let (members, live) = vault.room_audience_with_live_under(&read, room, principal)?;
    let audience = RoomAudience::resolve(vault, auth, &members, live)
        .map_err(|error| refused(format!("{error:?}")))?;
    Ok((read, members, audience))
}

impl Brain for ChatBrain {
    fn start(&mut self, request: &BrainRequest) -> oneiron::Result<()> {
        self.abort();
        let (memories, heard, live) = self.memories(request)?;
        self.rebuild_history(request.audience_revision, live)?;
        let (stream, tainted, memories, said_from) = self.open(request, memories, heard)?;
        let generation = request.generation;
        // The person's words: no stored row.
        self.history
            .lock()
            .map_err(|_| refused("history poisoned"))?
            .push((
                text_message(LlmMessageRole::User, request.transcript.clone()),
                Some(Vec::new()),
            ));
        add_rows(&mut self.said_ever, said_from.as_deref());
        let sources = Arc::new(Mutex::new(Some(TurnSources {
            said: said_from.clone(),
            found: request
                .retrieval
                .result_refs
                .iter()
                .filter_map(|reference| EntityId::from_hex(reference).ok())
                .collect(),
        })));
        let said = Arc::new(Mutex::new(Some(String::new())));
        let memories = Arc::new(Mutex::new(memories));
        let turn = Turn {
            generation,
            tainted,
            memories: Arc::clone(&memories),
            sources: Arc::clone(&sources),
            said_from: said_from.clone(),
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
            memories,
            sources,
            said_from,
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
    /// It is heard as made from every turn so far, whose sentence it may
    /// have judged, and the policy row it names.
    fn notice(&mut self, notice: &GateSystemNoticeRecord) -> oneiron::Result<()> {
        let mut rows = self.said_ever.clone();
        add_rows(&mut rows, Some(&notice_rows(notice)));
        self.history
            .lock()
            .map_err(|_| refused("history poisoned"))?
            .push((
                text_message(
                    LlmMessageRole::System,
                    format!(
                        "Safeguard notice said to the person ({}): {}",
                        notice.notice_type, notice.body
                    ),
                ),
                rows,
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
    /// What its memories read found and withheld, sent with its first event;
    /// shared with its cancel, which sends it when no event did.
    memories: Arc<Mutex<Option<TurnMemories>>>,
    /// The rows it was made from, sent with its first event, shared the
    /// same way (FIX 4778).
    sources: Arc<Mutex<Option<TurnSources>>>,
    /// The rows what it says is made from, for its history entry.
    said_from: Option<Vec<EntityId>>,
    out: mpsc::Sender<VoiceBrainOut>,
    history: Arc<Mutex<Vec<HistoryEntry>>>,
    /// What the turn has handed the speech host, shared with its cancel.
    said: Arc<Mutex<Option<String>>>,
}

impl Turn {
    async fn run(mut self, mut stream: LlmStream<'static>) {
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
                // A cancelled terminal is no answer: nothing more is said,
                // but a memories receipt no event carried still goes.
                Some(Ok(LlmStreamEvent::Done {
                    finish_reason: FinishReason::Cancelled,
                    ..
                })) => {
                    let owed = self
                        .memories
                        .lock()
                        .is_ok_and(|memories| memories.is_some());
                    if owed {
                        self.send(BrainEvent::TextDelta(String::new())).await;
                    }
                    return;
                }
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
            history.push((
                text_message(LlmMessageRole::Assistant, said),
                self.said_from.clone(),
            ));
        }
        self.send(event).await;
    }

    /// `false` once the host stopped listening.
    async fn send(&mut self, event: BrainEvent) -> bool {
        // Taken before the await, so no lock is held across it.
        let memories = self
            .memories
            .lock()
            .ok()
            .and_then(|mut memories| memories.take());
        let sources = self
            .sources
            .lock()
            .ok()
            .and_then(|mut sources| sources.take());
        self.out
            .send(VoiceBrainOut {
                generation: self.generation,
                event,
                externally_tainted: self.tainted,
                memories,
                sources,
            })
            .await
            .is_ok()
    }
}
