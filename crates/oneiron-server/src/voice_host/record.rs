//! What an owner's own voice call keeps (UNBUILT-02 PR 2). The owner ruled
//! voice turns ordinary conversation turns (VOICE-EPOCH-SOURCE = B: "i think
//! we just treat them as normal convos"): each answered turn of the call is
//! kept as two TURN rows, the person's final transcript and the agent's
//! answer, text only, in the call's conversation, and that conversation then
//! compacts exactly as a chat does, in the agent's own voice past its
//! threshold.
//!
//! - Which calls (Engine ruling VOICE-CALL-SCOPE = A): a standalone
//!   companion call, which is the owner's own. A phone call and a call heard
//!   in a room keep no turn here; their own row follows.
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
//! - Stored change: keep. TURN and MESSAGE rows of chat's own shape.

use std::sync::Arc;

use oneiron::authority::PeerMachine;
use oneiron::claim::CallerLocality;
use oneiron::compaction::{ConversationCompactionUnavailable, read_chat_log};
use oneiron::llm::run_admission::PayerPerson;
use oneiron::memory::{WitnessAuthor, WitnessReceipt};
use oneiron::session_lifecycle::SessionKey;
use oneiron::{EntityId, Vault, WriteActor};

use crate::ai_host::{AiHandle, ChatBreakpointCall};
use crate::api::ai::chat::witness_turn;
use crate::models::{AnsweringRung, RoleCall};
use crate::server::SyncServer;

/// A standalone call's home conversation. Parts: the person, then the agent.
const VOICE_HOME_DOMAIN: &[u8] = b"oneiron.conversation.voice_home.v1";

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

/// Where an owner's call keeps its turns, and as whom.
#[derive(Clone, Copy)]
pub(crate) struct CallRecord {
    /// The conversation the call's turns land in.
    pub(crate) conversation: EntityId,
    /// Who writes them: the call's payer, as a chat turn's requester.
    pub(crate) writer: WriteActor,
    /// The owner's sitting on the call's machine, which they join.
    pub(crate) sitting: SessionKey,
    /// Where the call's caller sits: its compaction's home-read ceiling.
    pub(crate) locality: CallerLocality,
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
        sitting,
        locality,
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
    /// Keeps the turn whose answer said `answer`, on a blocking thread: the
    /// person's words, then the answer, each a TURN of the call's
    /// conversation in the owner's sitting. Then, for a self agent past its
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
        let _applied = ai.session_app_open_applied(record.sitting, None);
        let memory = vault
            .memory(record.writer.entity_ref(), record.writer.actor_class())
            .with_session(record.sitting);
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
            locality: record.locality,
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
}

/// The answer's MESSAGE, which files its compaction's paid calls.
fn answer_message(receipt: &WitnessReceipt) -> Option<EntityId> {
    receipt
        .messages
        .first()
        .and_then(|message| EntityId::from_hex(&message.id).ok())
}
