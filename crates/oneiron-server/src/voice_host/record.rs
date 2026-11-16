//! What an owner's own voice call keeps (UNBUILT-02 PR 2), and what a room
//! call keeps (PR 4). The owner ruled voice turns ordinary conversation
//! turns (VOICE-EPOCH-SOURCE = B: "i think we just treat them as normal
//! convos"): each answered turn of the call is kept as two TURN rows, the
//! person's final transcript and the agent's answer, text only, in the
//! call's conversation, and that conversation then compacts exactly as a
//! chat does, in the agent's own voice past its threshold.
//!
//! - Which calls (Engine ruling VOICE-CALL-SCOPE, corrected 22:53): a
//!   standalone companion call, which is the owner's own, a phone call the
//!   line agent answers (PR 3: [`phone_call_record`]), and a room call (PR 4:
//!   [`room_call_record`]). An owner-only room call is the owner's own; a
//!   room call with other people keeps between its two divider rows.
//! - Where (VOICE-HOME-THREAD = A): a standalone call's home, a conversation
//!   derived from the person and the agent, one per pair, created at the
//!   first such call by its first witness. A resident agent's own home
//!   conversation wins when it has one. No verb and no stored pointer. A room
//!   call's conversation is the room.
//! - As whom and when: the call's payer writes both rows, as a chat turn's
//!   requester does, once the answer's stream stopped, off the media loop.
//!   An owner's own call joins the owner's sitting on the call's machine, as
//!   a chat turn does, so the sitting's close learns from them as from chat.
//!   A call with other people writes with no sitting, so no sitting's close
//!   learns from another person's words. A cancelled or broken turn, an
//!   answer that never stopped, and a turn in a stretch its room keeps no
//!   record of keep nothing. Each turn is kept once, from its own stop; its
//!   rows' ids are minted in time order, as chat's are.
//! - A phone call (UNBUILT-02 PR 3) is a call with another person, kept as
//!   its own thread: one conversation per line agent and caller number, its
//!   turns held in that conversation's own SESSION (PHONE-CALL-SESSION = A),
//!   as a mail or LINE thread's are. The caller's words are theirs
//!   (Counterparty, labelled with the call's speaker key), the answer the
//!   agent's own, and the call opens and closes with a divider row. With the
//!   owner's `voice.call_transcripts.keep` off, only the dividers are kept.
//!   The line agent reads its caller's thread back under its per-caller
//!   witness-read grant (owner ruling 16 Nov 00:44 replaces
//!   PHONE-CALL-READ-GRANT = B for this). Past the line agent's threshold the
//!   thread's earlier turns compact in its own voice, as a connector thread's
//!   do, under every reach the owner picks for the line ("Compaction works
//!   under every preset", owner 16 Nov 00:44).
//! - A room call with other people (UNBUILT-02 PR 4) is kept in the room:
//!   each speaker's words are theirs (Counterparty, labelled with the call's
//!   speaker key), the answer the agent's own, and the call opens and closes
//!   with a divider row. With the owner's `voice.call_transcripts.keep` off,
//!   only the dividers are kept. In a stretch its room keeps no record of,
//!   not even the dividers are kept.
//! - With the owner's `voice.call_transcripts.announce` on (PR 3B), the agent
//!   opens a phone call by saying it is transcribed ([`phone_call_opening`]).
//!   With keep on, that line is the call's first answer, kept after the
//!   start row and before the caller's first words. A room call with other
//!   people writes its own line after its start row, not spoken.
//! - Stored change: keep. TURN and MESSAGE rows of chat's own shape; the
//!   speaker and divider marks ride in MESSAGE metadata.

use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};

use oneiron::authority::PeerMachine;
use oneiron::claim::CallerLocality;
use oneiron::compaction::{ConversationCompactionUnavailable, read_chat_log};
use oneiron::dreamer_wake::{AgentWakeSignals, WakeTurnSubject};
use oneiron::interlocutor::CallSpeaker;
use oneiron::llm::run_admission::PayerPerson;
use oneiron::memory::{MemoryResult, WitnessAuthor, WitnessReceipt, WitnessTurn};
use oneiron::session_lifecycle::SessionKey;
use oneiron::voice_call::{caller_number, voice_phone_conversation_id};
use oneiron::{EdgeActorClass, EntityId, Vault, WriteActor};
use oneiron_driver::SessionHint;
use serde_json::json;

use super::call_wording::{self, ANOTHER_SPEAKER};
use crate::ai_host::{AiHandle, ChatBreakpointCall};
use crate::api::ai::chat::witness_turn;
use crate::models::{AnsweringRung, RoleCall};
use crate::server::SyncServer;

/// A standalone call's home conversation. Parts: the person, then the agent.
const VOICE_HOME_DOMAIN: &[u8] = b"oneiron.conversation.voice_home.v1";
/// The speaker key a phone call's caller speaks under on its turns.
const PHONE_CALLER_SPEAKER: &str = "caller";

/// The home conversation of `person`'s standalone calls with `agent`: one
/// per pair, the same id on every host of the vault.
///
/// # Errors
///
/// The id does not derive.
pub fn voice_home_conversation_id(person: EntityId, agent: EntityId) -> oneiron::Result<EntityId> {
    Ok(EntityId::derive(
        VOICE_HOME_DOMAIN,
        &[person.as_bytes(), agent.as_bytes()],
    )?)
}

/// Where a call keeps its turns, and as whom.
#[derive(Clone)]
pub(crate) struct CallRecord {
    /// The conversation the call's turns land in.
    pub(crate) conversation: EntityId,
    /// Who writes them: the call's payer, as a chat turn's requester.
    pub(crate) writer: WriteActor,
    /// Who the call is with, which decides how its turns are kept.
    pub(crate) party: CallParty,
}

/// Who a recorded call is with.
#[derive(Clone)]
pub(crate) enum CallParty {
    /// The owner's own call, standalone or in a room alone: the person
    /// speaks as the user, and each turn joins the owner's sitting on the
    /// call's machine, as a chat turn does, then compacts as chat.
    Owner {
        /// The owner's sitting on the call's machine, which they join.
        sitting: SessionKey,
        /// Where the call's caller sits: its compaction's home-read ceiling.
        locality: CallerLocality,
    },
    /// A phone call the line agent answered (UNBUILT-02 PR 3).
    Phone(PhoneCall),
    /// A room call with other people (UNBUILT-02 PR 4): the words are not
    /// all the owner's, so each turn is kept with no sitting.
    Room(RoomCall),
}

/// What a phone call keeps beside its conversation.
#[derive(Clone)]
pub(crate) struct PhoneCall {
    /// The call, which each of its rows names.
    call_ref: String,
    /// The caller's number as kept; `None` when withheld.
    number: Option<String>,
    /// When the call started, Unix seconds.
    started_at: u64,
}

/// What a room call with other people keeps beside its conversation: the
/// call's dividers name the room's other members, and each kept turn labels
/// its speaker key from the call's roster.
#[derive(Clone)]
pub(crate) struct RoomCall {
    /// The call, which each of its rows names.
    call_ref: String,
    /// When the call started, Unix seconds.
    started_at: u64,
    /// Where the call's caller sits: its compaction's home-read ceiling.
    locality: CallerLocality,
    /// The room's other members by name, for the dividers.
    names: Vec<String>,
    /// The call's speaker roster, read for each kept turn's label.
    roster_ref: Option<String>,
    /// Whether the start divider was written: the end divider follows only it.
    opened: Arc<AtomicBool>,
    /// Unplaced speaker keys, in first-heard order: "Another speaker",
    /// "Another speaker 2", ...
    unplaced: Arc<Mutex<Vec<String>>>,
}

impl RoomCall {
    /// Labels `speaker`'s words for display only (UNBUILT-02 PR 4): the
    /// roster's contact name, or the owner's name for an owner-print match,
    /// else the key's number by first-heard order. A key only labels; the
    /// kept turn stays another person's in every case.
    fn label(&self, vault: &Vault, speaker: Option<&str>) -> String {
        let Some(key) = speaker else {
            return call_wording::another_speaker(1);
        };
        let Some(roster_ref) = self.roster_ref.as_deref() else {
            return self.numbered(key);
        };
        match vault.call_speaker(roster_ref, key) {
            Ok(CallSpeaker::OwnerPrint) => match vault.call_owner_display_name() {
                Ok(Some(name)) => name,
                Ok(None) => self.numbered(key),
                Err(error) => {
                    tracing::warn!(
                        %error,
                        "voice: the owner's name did not read; the turn is numbered"
                    );
                    self.numbered(key)
                }
            },
            Ok(CallSpeaker::Contact { name, .. }) => name,
            Ok(CallSpeaker::Unplaced) => self.numbered(key),
            Err(error) => {
                tracing::warn!(
                    %error,
                    "voice: the call's speaker did not read; the turn is numbered"
                );
                self.numbered(key)
            }
        }
    }

    /// Numbers `key` by first-heard order in the call: the first unplaced
    /// key is "Another speaker", the next "Another speaker 2", and so on.
    fn numbered(&self, key: &str) -> String {
        let mut unplaced = match self.unplaced.lock() {
            Ok(guard) => guard,
            Err(error) => {
                tracing::warn!(
                    %error,
                    "voice: the call's speakers did not lock; the turn is first"
                );
                return call_wording::another_speaker(1);
            }
        };
        let position = match unplaced.iter().position(|known| known == key) {
            Some(index) => index + 1,
            None => {
                unplaced.push(key.to_owned());
                unplaced.len()
            }
        };
        call_wording::another_speaker(position)
    }
}

impl CallRecord {
    /// Whether the call keeps its answered turns now, not only its dividers:
    /// a call with other people reads the owner's `voice.call_transcripts.keep`
    /// again at each turn, so turning it off during a call stops the call's
    /// keeping from its next turn. A choice that does not read keeps the
    /// dividers only.
    pub(crate) fn keeps_turns(&self, vault: &Vault) -> bool {
        match &self.party {
            CallParty::Owner { .. } => true,
            CallParty::Phone(_) | CallParty::Room(_) => {
                vault.keeps_call_transcripts().unwrap_or_else(|error| {
                    tracing::warn!(
                        %error,
                        "voice: the call-transcript choice did not read; only the dividers are kept"
                    );
                    false
                })
            }
        }
    }

    /// Writes the row where a call with other people starts. An owner's own
    /// call has no divider. A room call in a stretch its room keeps no record
    /// of writes none. A row that does not land is logged.
    pub(crate) fn open(&self, vault: &Vault) {
        match &self.party {
            CallParty::Owner { .. } => {}
            CallParty::Phone(call) => {
                let text = call_wording::call_started(call.number.as_deref(), call.started_at);
                self.witness_divider(vault, &call.call_ref, "started", text, call.started_at);
            }
            CallParty::Room(call) => {
                if vault.room_has_unrecorded_stretch(self.conversation) {
                    tracing::info!(
                        "voice: the room keeps no record of the call's start; it keeps nothing"
                    );
                    return;
                }
                let text = call_wording::room_call_started(&call.names, call.started_at);
                self.witness_divider(vault, &call.call_ref, "started", text, call.started_at);
                call.opened.store(true, Ordering::SeqCst);
                let announces = vault.announces_call_transcripts().unwrap_or_else(|error| {
                    tracing::warn!(
                        %error,
                        "voice: the call-announcement choice did not read; the call announces"
                    );
                    true
                });
                if announces && self.keeps_turns(vault) {
                    self.keep_announcement(vault, &call_wording::room_announcement());
                }
            }
        }
    }

    /// Writes the row where a call with other people ends, with its length. A
    /// room call writes none unless its start row was written and the room
    /// keeps a record now.
    pub(crate) fn close(&self, vault: &Vault) {
        match &self.party {
            CallParty::Owner { .. } => {}
            CallParty::Phone(call) => {
                let now = vault.now_recorded_at();
                let text = call_wording::call_ended(now.saturating_sub(call.started_at));
                self.witness_divider(vault, &call.call_ref, "ended", text, now);
            }
            CallParty::Room(call) => {
                if !call.opened.load(Ordering::SeqCst) {
                    return;
                }
                if vault.room_has_unrecorded_stretch(self.conversation) {
                    return;
                }
                let now = vault.now_recorded_at();
                let text = call_wording::call_ended(now.saturating_sub(call.started_at));
                self.witness_divider(vault, &call.call_ref, "ended", text, now);
            }
        }
    }

    /// Keeps the line a call with other people opened with as the agent's own
    /// first answer, marked as the call's announcement, when the call keeps
    /// its turns. An owner's own call opens with none. A row that does not
    /// land is logged.
    pub(crate) fn keep_announcement(&self, vault: &Vault, line: &str) {
        let call_ref = match &self.party {
            CallParty::Phone(call) => &call.call_ref,
            CallParty::Room(call) => &call.call_ref,
            CallParty::Owner { .. } => return,
        };
        if !self.keeps_turns(vault) {
            return;
        }
        let mut turn = witness_turn(
            &self.conversation.to_hex(),
            None,
            WitnessAuthor::Companion,
            line.to_owned(),
            vault.now_recorded_at(),
        );
        set_metadata(
            &mut turn,
            json!({ "voice": { "call": call_ref, "call_announcement": true } }),
        );
        if let Err(error) = self.witness_party_row(vault, &turn) {
            tracing::warn!(%error, "voice: the call's announcement was not kept");
        }
    }

    /// A divider: the writer's own row, marked as the call's start or end
    /// in its metadata, since a System row needs an auto actor ceiling the
    /// line agent may not hold (ONE-1686).
    fn witness_divider(&self, vault: &Vault, call_ref: &str, mark: &str, text: String, at: u64) {
        let mut turn = witness_turn(
            &self.conversation.to_hex(),
            None,
            WitnessAuthor::Companion,
            text,
            at,
        );
        set_metadata(
            &mut turn,
            json!({ "voice": { "call": call_ref, "call_divider": mark } }),
        );
        if let Err(error) = self.witness_party_row(vault, &turn) {
            tracing::warn!(%error, mark, "voice: the call's divider row was not kept");
        }
    }

    /// Writes `turn` for the record's party: a phone call through its
    /// thread's witness, a room call through the plain memory witness with no
    /// sitting, since the words are not all the owner's. An owner's own call
    /// writes no divider or line, so it never calls here.
    fn witness_party_row(&self, vault: &Vault, turn: &WitnessTurn) -> MemoryResult<WitnessReceipt> {
        match &self.party {
            CallParty::Phone(_) => vault.witness_call_turn(self.writer.entity_ref(), turn),
            CallParty::Room(_) | CallParty::Owner { .. } => vault
                .memory(self.writer.entity_ref(), self.writer.actor_class())
                .witness(turn),
        }
    }
}

/// Sets the metadata of `turn`'s one message.
fn set_metadata(turn: &mut WitnessTurn, metadata: serde_json::Value) {
    for message in &mut turn.messages {
        message.metadata = Some(metadata.clone());
    }
}

/// The record of a phone call the line agent `agent` answered, under
/// `call_ref`, from the arrival's untrusted `caller` text: the agent's thread
/// with that number, written by the agent. The owner's keep choice is read at
/// each turn ([`CallRecord::keeps_turns`]). `None`, logged, when the thread's
/// id does not derive: the call then keeps nothing.
pub(crate) fn phone_call_record(
    vault: &Vault,
    agent: EntityId,
    caller: Option<&str>,
    call_ref: &str,
) -> Option<CallRecord> {
    let number = caller_number(caller);
    let conversation = match voice_phone_conversation_id(agent, number.as_deref(), call_ref) {
        Ok(conversation) => conversation,
        Err(error) => {
            tracing::warn!(%error, "voice: the phone call's thread does not derive; it keeps nothing");
            return None;
        }
    };
    Some(CallRecord {
        conversation,
        writer: WriteActor::new(agent, EdgeActorClass::Agent),
        party: CallParty::Phone(PhoneCall {
            call_ref: call_ref.to_owned(),
            number,
            started_at: vault.now_recorded_at(),
        }),
    })
}

/// The line a phone call answered by the line agent `definition` opens
/// with, read now: the call's announcement while the owner's
/// `voice.call_transcripts.announce` is on, naming the agent and the vault's
/// owner. A choice that does not read speaks it, as the key's strictest
/// value does. `None` when the owner turned it off.
pub(crate) fn phone_call_opening(
    vault: &Vault,
    definition: &oneiron::agent_def::AgentDefinition,
) -> Option<String> {
    let announces = vault.announces_call_transcripts().unwrap_or_else(|error| {
        tracing::warn!(%error, "voice: the call-announcement choice did not read; the call announces");
        true
    });
    if !announces {
        return None;
    }
    let agent = definition
        .display_name
        .as_deref()
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .unwrap_or(&definition.agent_id);
    let owner = vault.call_owner_display_name().unwrap_or_else(|error| {
        tracing::warn!(%error, "voice: the owner's name did not read; the announcement names none");
        None
    });
    Some(call_wording::answered_announcement(agent, owner.as_deref()))
}

/// The record of `person`'s standalone call with `agent`, paid and written
/// by `writer` from the machine `peer` at `locality`: its home conversation
/// and the sitting it joins. `None`, logged, when the call keeps no turn: a
/// remote caller whose machine is not proven has no sitting to join, as a
/// chat turn from it is refused one, or its home does not resolve.
pub(crate) fn standalone_call_record(
    server: &SyncServer,
    person: EntityId,
    agent: EntityId,
    writer: WriteActor,
    peer: PeerMachine,
    locality: CallerLocality,
) -> Option<CallRecord> {
    let conversation = match home_conversation(server.vault(), person, agent) {
        Ok(conversation) => conversation,
        Err(error) => {
            tracing::warn!(%error, "voice: the call's home does not resolve; it keeps no turn");
            return None;
        }
    };
    let Ok(sitting) =
        crate::api::ai::bound_session_key(server, writer.entity_ref(), peer, locality)
    else {
        tracing::info!("voice: the call's machine holds no sitting here; it keeps no turn");
        return None;
    };
    Some(CallRecord {
        conversation,
        writer,
        party: CallParty::Owner { sitting, locality },
    })
}

/// The record of a room call heard in `room`, paid and written by `writer`
/// from the machine `peer` at `locality` (UNBUILT-02 PR 4): an owner-only
/// room call keeps as a standalone call does, in the room; a call with other
/// people keeps between its dividers. `None`, logged, when the call keeps no
/// turn yet: in a thread, in a project room, or with no sitting for an
/// owner-only call.
pub(crate) fn room_call_record(
    server: &SyncServer,
    writer: WriteActor,
    peer: PeerMachine,
    locality: CallerLocality,
    room: EntityId,
    branch: Option<EntityId>,
    members: &[EntityId],
    roster_ref: Option<String>,
    call_ref: &str,
) -> Option<CallRecord> {
    if branch.is_some() {
        tracing::info!(
            "voice: a call in a thread keeps no turn yet ([VOICE-ROOM-THREAD-CALL-KEEP])"
        );
        return None;
    }
    let vault = server.vault();
    match vault.room_is_project_room(room) {
        Ok(true) => {
            tracing::info!(
                "voice: a project room call keeps no turn yet ([VOICE-PROJECT-ROOM-CALL-KEEP])"
            );
            return None;
        }
        Ok(false) => {}
        Err(error) => {
            tracing::warn!(
                %error,
                "voice: room kind unread; keeps nothing ([VOICE-PROJECT-ROOM-CALL-KEEP])"
            );
            return None;
        }
    }
    let parties = match vault.call_room_parties(writer.entity_ref(), members) {
        Ok(parties) => parties,
        Err(error) => {
            tracing::warn!(%error, "voice: the room's parties did not read; it keeps nothing");
            return None;
        }
    };
    if !parties.with_others && roster_ref.is_none() {
        let Ok(sitting) =
            crate::api::ai::bound_session_key(server, writer.entity_ref(), peer, locality)
        else {
            tracing::info!("voice: the call's machine holds no sitting here; it keeps no turn");
            return None;
        };
        return Some(CallRecord {
            conversation: room,
            writer,
            party: CallParty::Owner { sitting, locality },
        });
    }
    Some(CallRecord {
        conversation: room,
        writer,
        party: CallParty::Room(RoomCall {
            call_ref: call_ref.to_owned(),
            started_at: vault.now_recorded_at(),
            locality,
            names: parties.names,
            roster_ref,
            opened: Arc::new(AtomicBool::new(false)),
            unplaced: Arc::new(Mutex::new(Vec::new())),
        }),
    })
}

/// A standalone call's home: the resident agent's own home conversation when
/// `agent` is a settled resident, else the pair's derived one.
fn home_conversation(
    vault: &Vault,
    person: EntityId,
    agent: EntityId,
) -> oneiron::Result<EntityId> {
    if let Some(resident) = vault.settled_resident_agent(agent)? {
        return Ok(resident.home_conversation_ref);
    }
    voice_home_conversation_id(person, agent)
}

/// One answered turn of a recorded call, as its stop keeps it.
pub(crate) struct KeptTurn {
    pub(crate) ai: AiHandle,
    pub(crate) vault: Arc<Vault>,
    pub(crate) record: CallRecord,
    /// The answering agent, whose own voice compacts the conversation.
    pub(crate) agent: EntityId,
    /// The person's final transcript, and when it was heard (Unix seconds).
    pub(crate) transcript: String,
    pub(crate) heard_at: u64,
    /// The final's speaker key, when the host route's final named one.
    pub(crate) speaker: Option<String>,
    /// Who the turn bills when a room pays for it.
    pub(crate) funding: Option<PayerPerson>,
    pub(crate) budget_units: u64,
}

impl KeptTurn {
    /// Keeps the turn whose answer said `answer`, on a blocking thread. A
    /// phone call's turn is kept as [`Self::keep_phone`] keeps it, a room call
    /// with other people's as [`Self::keep_room`] keeps it. An owner's own
    /// call keeps the person's words, then the answer, each a TURN of the
    /// call's conversation in the owner's sitting. Then, for a self agent past its
    /// threshold, the conversation's earlier turns compact in its own voice
    /// on chat's flight path, under the answer's own `admitted` call and the
    /// `answering` rung. A witness that fails is logged and keeps what landed
    /// before it; a flight that does not run leaves the log raw.
    pub(crate) fn keep(
        self,
        answer: String,
        admitted: &RoleCall,
        answering: Option<AnsweringRung>,
    ) {
        match self.record.party.clone() {
            CallParty::Owner { sitting, locality } => {
                self.keep_owner(sitting, locality, answer, admitted, answering)
            }
            CallParty::Phone(call) => self.keep_phone(&call, answer, admitted, answering),
            CallParty::Room(call) => self.keep_room(&call, answer, admitted, answering),
        }
    }

    /// Keeps an owner's own turn: the person's words, then the answer, each a
    /// TURN of the call's conversation in the owner's sitting, as a chat turn
    /// does, then the conversation compacts as a chat does.
    fn keep_owner(
        self,
        sitting: SessionKey,
        locality: CallerLocality,
        answer: String,
        admitted: &RoleCall,
        answering: Option<AnsweringRung>,
    ) {
        let KeptTurn {
            ai,
            vault,
            record,
            agent,
            transcript,
            heard_at,
            funding,
            budget_units,
            ..
        } = self;
        // The call is a visit, as a chat turn's request is: it opens the
        // sitting, or keeps it open, before the turn joins it.
        let _applied = ai.session_app_open_applied(sitting, None);
        let memory = vault
            .memory(record.writer.entity_ref(), record.writer.actor_class())
            .with_session(sitting);
        let conversation = record.conversation.to_hex();
        let person = witness_turn(
            &conversation,
            None,
            WitnessAuthor::User,
            transcript,
            heard_at,
        );
        if let Err(error) = memory.witness(&person) {
            tracing::warn!(%error, "voice: the person's words were not kept; the turn keeps nothing");
            return;
        }
        // The person's turn landed, as a chat request's does.
        ai.turn_landed(&vault, WakeTurnSubject::Vault);
        let reply = witness_turn(
            &conversation,
            None,
            WitnessAuthor::Companion,
            answer,
            vault.now_recorded_at(),
        );
        let message = match memory
            .witness(&reply)
            .map(|receipt| answer_message(&receipt))
        {
            Ok(Some(message)) => message,
            Ok(None) => {
                tracing::warn!(
                    "voice: the kept answer names no message; its conversation stays raw"
                );
                return;
            }
            Err(error) => {
                tracing::warn!(%error, "voice: the answer was not kept");
                return;
            }
        };
        // The answer is the agent's turn and activity in the sitting, as a
        // chat answer's is: its own cadence dial counts it.
        ai.session_hint(sitting, SessionHint::Activity, None);
        ai.turn_landed(
            &vault,
            WakeTurnSubject::Agent {
                id: agent,
                signals: AgentWakeSignals::default(),
            },
        );
        let Some(mode) = ai.chat_self_mode(&vault, agent) else {
            return;
        };
        let log = match read_chat_log(&memory, record.conversation, mode.hot_turns(), usize::MAX) {
            Ok(log) => log,
            Err(error) => {
                tracing::warn!(%error, "voice: the call's conversation log did not read; it stays raw");
                return;
            }
        };
        let call = ChatBreakpointCall {
            vault: Arc::clone(&vault),
            mode,
            log,
            locality,
            payer: record.writer,
            funding,
            budget_units,
            message,
            // The call's request carries its instructions, the call's own
            // history and the person's transcript, none a witnessed row as it
            // was sent, so no live fork is captured (FIX 9463): the flight
            // writes on the cheap writer, as the agent.
            sources: None,
        };
        match ai.enter_chat_breakpoint(call, admitted, answering) {
            Ok(()) | Err(ConversationCompactionUnavailable::Quiet) => {}
            Err(why) => tracing::info!(
                reason = why.as_str(),
                "voice: the call's compaction is unavailable; its conversation stays raw"
            ),
        }
    }

    /// Keeps a phone call's turn: the caller's words as theirs, labelled
    /// with the call's speaker key, then the answer as the agent's own, each
    /// a TURN of the call's thread held in the thread's own SESSION. No
    /// sitting opens or hears of it. Then, for a self line agent past its
    /// threshold, the thread's earlier turns compact in its own voice, as
    /// [`Self::compact_phone_thread`] enters it. A witness that fails is
    /// logged and keeps what landed before it.
    fn keep_phone(
        mut self,
        call: &PhoneCall,
        answer: String,
        admitted: &RoleCall,
        answering: Option<AnsweringRung>,
    ) {
        // The owner may have turned keep off while the turn answered.
        if !self.record.keeps_turns(&self.vault) {
            return;
        }
        let conversation = self.record.conversation.to_hex();
        let writer = self.record.writer.entity_ref();
        let mut caller = witness_turn(
            &conversation,
            None,
            WitnessAuthor::Counterparty,
            std::mem::take(&mut self.transcript),
            self.heard_at,
        );
        set_metadata(
            &mut caller,
            json!({ "voice": {
                "call": call.call_ref,
                "speaker": PHONE_CALLER_SPEAKER,
                "speaker_label": ANOTHER_SPEAKER,
            } }),
        );
        if let Err(error) = self.vault.witness_call_turn(writer, &caller) {
            tracing::warn!(%error, "voice: the caller's words were not kept; the turn keeps nothing");
            return;
        }
        let mut reply = witness_turn(
            &conversation,
            None,
            WitnessAuthor::Companion,
            answer,
            self.vault.now_recorded_at(),
        );
        set_metadata(&mut reply, json!({ "voice": { "call": call.call_ref } }));
        let message = match self
            .vault
            .witness_call_turn(writer, &reply)
            .map(|receipt| answer_message(&receipt))
        {
            Ok(Some(message)) => message,
            Ok(None) => {
                tracing::warn!("voice: the kept answer names no message; its thread stays raw");
                return;
            }
            Err(error) => {
                tracing::warn!(%error, "voice: the answer was not kept");
                return;
            }
        };
        self.compact_phone_thread(message, admitted, answering);
    }

    /// Keeps a room call with other people's turn: the speaker's words as
    /// theirs, labelled with the final's speaker key, then the answer as the
    /// agent's own, each a TURN of the room with no sitting. Then, for a self
    /// agent past its threshold, the room's earlier turns compact in its own
    /// voice, as [`Self::keep_owner`] enters it, with the call's locality. A
    /// witness that fails is logged and keeps what landed before it.
    fn keep_room(
        mut self,
        call: &RoomCall,
        answer: String,
        admitted: &RoleCall,
        answering: Option<AnsweringRung>,
    ) {
        // The owner may have turned keep off while the turn answered.
        if !self.record.keeps_turns(&self.vault) {
            return;
        }
        if self
            .vault
            .room_has_unrecorded_stretch(self.record.conversation)
        {
            return;
        }
        let conversation = self.record.conversation.to_hex();
        let label = call.label(&self.vault, self.speaker.as_deref());
        let mut voice = serde_json::Map::new();
        voice.insert("call".to_owned(), json!(call.call_ref));
        if let Some(speaker) = self.speaker.as_deref() {
            voice.insert("speaker".to_owned(), json!(speaker));
        }
        voice.insert("speaker_label".to_owned(), json!(label));
        let mut person = witness_turn(
            &conversation,
            None,
            WitnessAuthor::Counterparty,
            std::mem::take(&mut self.transcript),
            self.heard_at,
        );
        set_metadata(&mut person, json!({ "voice": voice }));
        if let Err(error) = self
            .vault
            .memory(
                self.record.writer.entity_ref(),
                self.record.writer.actor_class(),
            )
            .witness(&person)
        {
            tracing::warn!(
                %error,
                "voice: the person's words were not kept; the turn keeps nothing"
            );
            return;
        }
        // The person's turn landed, as a chat request's does.
        self.ai.turn_landed(&self.vault, WakeTurnSubject::Vault);
        let mut reply = witness_turn(
            &conversation,
            None,
            WitnessAuthor::Companion,
            answer,
            self.vault.now_recorded_at(),
        );
        set_metadata(&mut reply, json!({ "voice": { "call": call.call_ref } }));
        let message = match self
            .vault
            .memory(
                self.record.writer.entity_ref(),
                self.record.writer.actor_class(),
            )
            .witness(&reply)
            .map(|receipt| answer_message(&receipt))
        {
            Ok(Some(message)) => message,
            Ok(None) => {
                tracing::warn!(
                    "voice: the kept answer names no message; its conversation stays raw"
                );
                return;
            }
            Err(error) => {
                tracing::warn!(%error, "voice: the answer was not kept");
                return;
            }
        };
        self.ai.turn_landed(
            &self.vault,
            WakeTurnSubject::Agent {
                id: self.agent,
                signals: AgentWakeSignals::default(),
            },
        );
        let KeptTurn {
            ai,
            vault,
            record,
            agent,
            funding,
            budget_units,
            ..
        } = self;
        let Some(mode) = ai.chat_self_mode(&vault, agent) else {
            return;
        };
        let memory = vault.memory(record.writer.entity_ref(), record.writer.actor_class());
        let log = match read_chat_log(&memory, record.conversation, mode.hot_turns(), usize::MAX) {
            Ok(log) => log,
            Err(error) => {
                tracing::warn!(
                    %error,
                    "voice: the call's conversation log did not read; it stays raw"
                );
                return;
            }
        };
        let breakpoint = ChatBreakpointCall {
            vault: Arc::clone(&vault),
            mode,
            log,
            locality: call.locality,
            payer: record.writer,
            funding,
            budget_units,
            message,
            // The call's request carries its instructions, the call's own
            // history and the person's transcript, none a witnessed row as it
            // was sent, so no live fork is captured (FIX 9463): the flight
            // writes on the cheap writer, as the agent.
            sources: None,
        };
        match ai.enter_chat_breakpoint(breakpoint, admitted, answering) {
            Ok(()) | Err(ConversationCompactionUnavailable::Quiet) => {}
            Err(why) => tracing::info!(
                reason = why.as_str(),
                "voice: the call's compaction is unavailable; its conversation stays raw"
            ),
        }
    }

    /// Enters the line agent's breakpoint for its caller's thread once the
    /// answer `message` is kept, on chat's flight path and claim, as a
    /// connector thread's reply enters it. The agent reads the thread
    /// through its own lane, under the per-caller witness-read grant its
    /// first kept turn issued, never through the call's key: the line's reach
    /// narrows only the call's key, and that key ends with the call, so the
    /// thread compacts under every reach the owner picks, while the epoch
    /// reads only where the thread's own words read. The call's request
    /// carries its instructions and the caller's transcript, none a witnessed
    /// row as it was sent, so no live fork is captured (FIX 9463): the flight
    /// writes on the cheap writer, as the agent, which pays as for its answer.
    /// A flight that does not run leaves the thread raw.
    fn compact_phone_thread(
        self,
        message: EntityId,
        admitted: &RoleCall,
        answering: Option<AnsweringRung>,
    ) {
        let KeptTurn {
            ai,
            vault,
            record,
            agent,
            funding,
            budget_units,
            ..
        } = self;
        let Some(mode) = ai.chat_self_mode(&vault, agent) else {
            return;
        };
        let memory = vault.memory(record.writer.entity_ref(), EdgeActorClass::Agent);
        let log = match read_chat_log(&memory, record.conversation, mode.hot_turns(), usize::MAX) {
            Ok(log) => log,
            Err(error) => {
                tracing::warn!(%error, "voice: the phone thread's log did not read; it stays raw");
                return;
            }
        };
        let call = ChatBreakpointCall {
            vault: Arc::clone(&vault),
            mode,
            log,
            // A caller reaches the line agent from off this device.
            locality: CallerLocality::OffDevice,
            payer: record.writer,
            funding,
            budget_units,
            message,
            sources: None,
        };
        match ai.enter_chat_breakpoint(call, admitted, answering) {
            Ok(()) | Err(ConversationCompactionUnavailable::Quiet) => {}
            Err(why) => tracing::info!(
                reason = why.as_str(),
                "voice: the phone thread's compaction is unavailable; it stays raw"
            ),
        }
    }
}

/// The answer's MESSAGE, which files its compaction's paid calls.
fn answer_message(receipt: &WitnessReceipt) -> Option<EntityId> {
    receipt
        .messages
        .first()
        .and_then(|message| EntityId::from_hex(&message.id).ok())
}
