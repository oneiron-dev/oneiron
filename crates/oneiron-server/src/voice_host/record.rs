//! What an owner's own voice call keeps (UNBUILT-02 PR 2). The owner ruled
//! voice turns ordinary conversation turns (VOICE-EPOCH-SOURCE = B: "i think
//! we just treat them as normal convos"): each answered turn of the call is
//! kept as two TURN rows, the person's final transcript and the agent's
//! answer, text only, in the call's conversation, and that conversation then
//! compacts exactly as a chat does, in the agent's own voice past its
//! threshold.
//!
//! - Which calls (Engine ruling VOICE-CALL-SCOPE, corrected 22:53): a
//!   standalone companion call, which is the owner's own, and a phone call
//!   the line agent answers (PR 3: [`phone_call_record`]). A call heard in a
//!   room keeps no turn here yet (PR 4).
//! - Where (VOICE-HOME-THREAD = A): a standalone call's home, a conversation
//!   derived from the person and the agent, one per pair, created at the
//!   first such call by its first witness. A resident agent's own home
//!   conversation wins when it has one. No verb and no stored pointer.
//! - As whom and when: the call's payer writes both rows, as a chat turn's
//!   requester does, once the answer's stream stopped, off the media loop.
//!   They join the owner's sitting on the call's machine, as a chat turn
//!   does, so the sitting's close learns from them as from chat. A cancelled
//!   or broken turn, an answer that never stopped, and a turn in a stretch
//!   its room keeps no record of keep nothing. Each turn is kept once, from
//!   its own stop; its rows' ids are minted in time order, as chat's are.
//! - A phone call (UNBUILT-02 PR 3) is a call with another person, kept as
//!   its own thread: one conversation per line agent and caller number, its
//!   turns held in that conversation's own SESSION (PHONE-CALL-SESSION = A),
//!   as a mail or LINE thread's are. The caller's words are theirs
//!   (Counterparty, labelled with the call's speaker key), the answer the
//!   agent's own, and the call opens and closes with a divider row. With the
//!   owner's `voice.call_transcripts.keep` off, only the dividers are kept.
//!   The line agent reads no stranger's words back, so a phone thread stays
//!   raw: it does not compact (PHONE-CALL-READ-GRANT, recommendation B).
//! - With the owner's `voice.call_transcripts.announce` on (PR 3B), the agent
//!   opens a phone call by saying it is transcribed ([`phone_call_opening`]).
//!   With keep on, that line is the call's first answer, kept after the
//!   start row and before the caller's first words.
//! - Stored change: keep. TURN and MESSAGE rows of chat's own shape; the
//!   speaker and divider marks ride in MESSAGE metadata.

use std::sync::Arc;

use oneiron::authority::PeerMachine;
use oneiron::claim::CallerLocality;
use oneiron::compaction::{ConversationCompactionUnavailable, read_chat_log};
use oneiron::dreamer_wake::{AgentWakeSignals, WakeTurnSubject};
use oneiron::llm::run_admission::PayerPerson;
use oneiron::memory::{WitnessAuthor, WitnessReceipt, WitnessTurn};
use oneiron::session_lifecycle::SessionKey;
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
/// A phone thread. Parts: the line agent, then the caller's number as kept.
const VOICE_PHONE_DOMAIN: &[u8] = b"oneiron.conversation.voice_phone.v1";
/// The thread of a call whose number is withheld. Parts: the line agent,
/// then the call.
const VOICE_PHONE_CALL_DOMAIN: &[u8] = b"oneiron.conversation.voice_phone_call.v1";
/// The most characters a kept caller number holds, its `+` included.
const CALLER_NUMBER_MAX: usize = 20;
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

/// The number a phone thread keeps for `caller`, the line provider's
/// untrusted text: a leading `+` and its digits, at most
/// [`CALLER_NUMBER_MAX`] characters, nothing else. `None` when it holds no
/// digit, as a withheld number does.
#[must_use]
pub fn caller_number(caller: Option<&str>) -> Option<String> {
    let text = caller?.trim();
    let plus = text.starts_with('+');
    let digits: String = text
        .chars()
        .filter(char::is_ascii_digit)
        .take(CALLER_NUMBER_MAX - usize::from(plus))
        .collect();
    (!digits.is_empty()).then(|| if plus { format!("+{digits}") } else { digits })
}

/// The thread the line agent `agent`'s calls from `number` (as
/// [`caller_number`] keeps it) land in: one per agent and number, the same
/// id on every host of the vault. A call whose number is withheld (`None`)
/// gets a thread of its own, derived from `call_ref`.
///
/// # Errors
///
/// The id does not derive.
pub fn voice_phone_conversation_id(
    agent: EntityId,
    number: Option<&str>,
    call_ref: &str,
) -> oneiron::Result<EntityId> {
    Ok(match number {
        Some(number) => {
            EntityId::derive(VOICE_PHONE_DOMAIN, &[agent.as_bytes(), number.as_bytes()])?
        }
        None => EntityId::derive(
            VOICE_PHONE_CALL_DOMAIN,
            &[agent.as_bytes(), call_ref.as_bytes()],
        )?,
    })
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
    /// The owner's own standalone call: the person speaks as the user, and
    /// each turn joins the owner's sitting on the call's machine, as a chat
    /// turn does, then compacts as chat.
    Owner {
        /// The owner's sitting on the call's machine, which they join.
        sitting: SessionKey,
        /// Where the call's caller sits: its compaction's home-read ceiling.
        locality: CallerLocality,
    },
    /// A phone call the line agent answered (UNBUILT-02 PR 3).
    Phone(PhoneCall),
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

impl CallRecord {
    /// Whether the call keeps its answered turns now, not only its dividers:
    /// a phone call reads the owner's `voice.call_transcripts.keep` again at
    /// each turn, so turning it off during a call stops the call's keeping
    /// from its next turn. A choice that does not read keeps the dividers
    /// only.
    pub(crate) fn keeps_turns(&self, vault: &Vault) -> bool {
        match &self.party {
            CallParty::Owner { .. } => true,
            CallParty::Phone(_) => vault.keeps_call_transcripts().unwrap_or_else(|error| {
                tracing::warn!(%error, "voice: the call-transcript choice did not read; only the dividers are kept");
                false
            }),
        }
    }

    /// Writes the row where a phone call starts. An owner's own call has no
    /// divider. A row that does not land is logged.
    pub(crate) fn open(&self, vault: &Vault) {
        if let CallParty::Phone(call) = &self.party {
            let text = call_wording::call_started(call.number.as_deref(), call.started_at);
            self.witness_divider(vault, call, "started", text, call.started_at);
        }
    }

    /// Writes the row where a phone call ends, with its length.
    pub(crate) fn close(&self, vault: &Vault) {
        if let CallParty::Phone(call) = &self.party {
            let now = vault.now_recorded_at();
            let text = call_wording::call_ended(now.saturating_sub(call.started_at));
            self.witness_divider(vault, call, "ended", text, now);
        }
    }

    /// Keeps the line a phone call opened with as the agent's own first
    /// answer, marked as the call's announcement, when the call keeps its
    /// turns. An owner's own call opens with none. A row that does not land
    /// is logged.
    pub(crate) fn keep_announcement(&self, vault: &Vault, line: &str) {
        let CallParty::Phone(call) = &self.party else {
            return;
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
            json!({ "voice": { "call": call.call_ref, "call_announcement": true } }),
        );
        if let Err(error) = vault.witness_call_turn(self.writer.entity_ref(), &turn) {
            tracing::warn!(%error, "voice: the call's announcement was not kept");
        }
    }

    /// A divider: the writer's own row, marked as the call's start or end
    /// in its metadata, since a System row needs an auto actor ceiling the
    /// line agent may not hold (ONE-1686).
    fn witness_divider(&self, vault: &Vault, call: &PhoneCall, mark: &str, text: String, at: u64) {
        let mut turn = witness_turn(
            &self.conversation.to_hex(),
            None,
            WitnessAuthor::Companion,
            text,
            at,
        );
        set_metadata(
            &mut turn,
            json!({ "voice": { "call": call.call_ref, "call_divider": mark } }),
        );
        if let Err(error) = vault.witness_call_turn(self.writer.entity_ref(), &turn) {
            tracing::warn!(%error, mark, "voice: the call's divider row was not kept");
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
    /// Who the turn bills when a room pays for it.
    pub(crate) funding: Option<PayerPerson>,
    pub(crate) budget_units: u64,
}

impl KeptTurn {
    /// Keeps the turn whose answer said `answer`, on a blocking thread. A
    /// phone call's turn is kept as [`Self::keep_phone`] keeps it. An owner's
    /// own call keeps the person's words, then the answer, each a TURN of the
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
        let (sitting, locality) = match self.record.party.clone() {
            CallParty::Owner { sitting, locality } => (sitting, locality),
            CallParty::Phone(call) => return self.keep_phone(&call, answer),
        };
        let KeptTurn {
            ai,
            vault,
            record,
            agent,
            transcript,
            heard_at,
            funding,
            budget_units,
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
    /// sitting opens or hears of it, and the thread does not compact: the
    /// line agent reads no stranger's words back (PHONE-CALL-READ-GRANT, B).
    /// A witness that fails is logged and keeps what landed before it.
    fn keep_phone(self, call: &PhoneCall, answer: String) {
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
            self.transcript,
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
        if let Err(error) = self.vault.witness_call_turn(writer, &reply) {
            tracing::warn!(%error, "voice: the answer was not kept");
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
