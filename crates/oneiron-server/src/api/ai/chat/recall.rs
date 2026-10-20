//! The vault's memory a live chat turn reads (FIX 6794): the context board
//! `ai.reply` assembles (ARCH-0067: the board owns assembly), hydrated for
//! the turn's own text and placed after the stable history, right before the
//! newest User (the board rides the dynamic tail; FIX 6676's layout).
//! Reading it never fails the turn: a refusal, a hold, or a role that does
//! not admit the call with it leaves the turn as it was, logged. The witness
//! and the conversation log never hold it.
use std::sync::Arc;

use oneiron::claim::CallerLocality;
use oneiron::memory::resolve_entity_ref;
use oneiron::{LlmMessage, LlmMessageRole, ModelLocality, Vault};

use super::{ChatTurnRequest, assistant, chat_request, text_message};
use crate::ai_host::{AiHandle, CHAT_ROLE};
use crate::auth::{CoreAuth, CoreScope};
use crate::models::{RoleCall, RoleRefusal, Seat};
use crate::server::SyncServer;

/// The board `request`'s turn reads as `auth` reads, read before anything is
/// written; `None` when the turn reads none: a caller or request the turn
/// refuses, no chat seat, a refused assembly, an empty frame, or rows a world
/// keeps from where the call goes. The seat's ladder may fall back to a rung
/// off this device, so the board is read as an off-device read is, and its
/// rows meet the hold of a prompt that leaves the device.
pub(super) async fn turn_board(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    request: &ChatTurnRequest,
) -> Option<String> {
    if auth.require(CoreScope::Read).is_err()
        || auth.require(CoreScope::Write).is_err()
        || request.text.trim().is_empty()
        || server.ai.chat_seat().is_none()
    {
        return None;
    }
    let vault = server.vault();
    let (agent, _) = assistant(auth, vault, request.agent_ref.as_deref()).ok()?;
    // A new conversation has no room yet; one that resolves narrows the read
    // to its audience.
    let conversation = resolve_entity_ref(vault, &request.conversation_ref).ok();
    let board = match crate::api::context_board::chat_board(
        server,
        auth.clone().at(CallerLocality::OffDevice),
        conversation,
        agent,
        &request.text,
    )
    .await
    {
        Ok(board) if !board.block.trim().is_empty() => board,
        Ok(_) => return None,
        Err(status) => {
            tracing::info!(
                %status,
                "a chat turn's context board was refused; the turn runs without it"
            );
            return None;
        }
    };
    let prompt_for =
        crate::device_local::prompt_destination(auth.destination(), ModelLocality::ThirdParty);
    match crate::device_local::retained_hold(vault, &prompt_for, &board.rows, board.block.as_bytes())
    {
        Ok(None) => Some(board.block),
        Ok(Some(hold)) => {
            tracing::info!(
                reason = hold.reason(),
                "a chat turn's context board is kept on this device; the turn runs without it"
            );
            None
        }
        Err(error) => {
            tracing::warn!(
                kind = ?error.kind(),
                "a chat turn's context board hold was not read; the turn runs without it"
            );
            None
        }
    }
}

/// The turn's call admitted through its role, with `board` as one User
/// message right before the newest User, or last when there is none. A role
/// that does not admit the call with the board admits it as it was; the flag
/// says whether the board rides.
pub(super) fn admit(
    ai: &AiHandle,
    vault: &Vault,
    seat: &Seat,
    mut messages: Vec<LlmMessage>,
    board: Option<String>,
) -> (Result<RoleCall, RoleRefusal>, bool) {
    let Some(board) = board else {
        return (
            ai.admit_role(vault, CHAT_ROLE, chat_request(seat, messages)),
            false,
        );
    };
    let baseline = messages.clone();
    let at = messages
        .iter()
        .rposition(|message| message.role == LlmMessageRole::User)
        .unwrap_or(messages.len());
    messages.insert(at, text_message(LlmMessageRole::User, board));
    match ai.admit_role(vault, CHAT_ROLE, chat_request(seat, messages)) {
        Ok(admitted) => (Ok(admitted), true),
        Err(refusal) => {
            tracing::info!(
                %refusal,
                "a chat turn's call was not admitted with its context board; it goes without it"
            );
            (
                ai.admit_role(vault, CHAT_ROLE, chat_request(seat, baseline)),
                false,
            )
        }
    }
}
