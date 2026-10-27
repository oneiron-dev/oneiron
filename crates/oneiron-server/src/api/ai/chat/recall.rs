//! The vault's memory a live chat turn reads (FIX 6794): the context board
//! `ai.reply` assembles (ARCH-0067: the board owns assembly), hydrated for
//! the turn's own text and placed after the stable history, right before the
//! newest User (the board rides the dynamic tail; FIX 6676's layout).
//! Reading it never fails the turn: a refusal, a hold, or a role that does
//! not admit the call with it leaves the turn as it was, and the turn's
//! caller and its model are told why, typed (FIX 8136). The witness and the
//! conversation log never hold it.
use std::sync::Arc;

use oneiron::claim::CallerLocality;
use oneiron::conversation::OutputMark;
use oneiron::memory::resolve_entity_ref;
use oneiron::{LlmMessage, LlmMessageRole, ModelLocality, Vault};
use serde::Serialize;

use super::{ChatTurnRequest, assistant, chat_request, text_message};
use crate::ai_host::{AiHandle, CHAT_ROLE};
use crate::api::context_board::{ChatBoard, ChatContextCapture, PromptBoard};
use crate::auth::{CoreAuth, CoreScope};
use crate::models::{RoleCall, RoleRefusal, Seat};
use crate::server::SyncServer;

/// Why a turn's call goes without the context board it read (FIX 8136):
/// what its caller and its model are told, naming no row and no count.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum BoardOmission {
    /// The board's assembly was refused for this caller.
    Refused,
    /// The rows it showed may not go as far as the call's route may take
    /// them (FIX 7257).
    RouteHeld,
    /// The chat role did not admit the call with it.
    NotAdmitted,
}

impl BoardOmission {
    /// The host's note in the call's tail, at the board's place.
    pub(super) fn note(self) -> String {
        let why = match self {
            Self::Refused => "the vault refused to assemble it for this caller",
            Self::RouteHeld => "its rows may not go where this call's model may run",
            Self::NotAdmitted => "the model's route did not admit the call with it",
        };
        format!("The vault's context board is not part of this turn: {why}.")
    }
}

/// What a turn read before anything was written: the reply's newcomer mark,
/// taken first (FIX 8133), and the board read after it.
pub(super) struct TurnRead {
    pub(super) mark: OutputMark,
    pub(super) board: Result<Option<ChatBoard>, BoardOmission>,
}

/// The board `request`'s turn reads as `auth` reads, read before anything is
/// written, beside every row it served (FIX 6935); `Ok(None)` when the turn
/// reads none: a caller or request the turn refuses, no chat seat, or an
/// empty frame. A board the turn read and goes without is the omission's
/// reason (FIX 8136): a refused assembly, or rows a world keeps from where
/// the call goes.
/// The board reads as an on-device read does only when the caller sits on
/// this device and the chat role's live route never leaves it: where it is
/// admitted and every rung or fallback it may reach (FIX 6922). Any other
/// caller or route, or one that is not read, reads it as an off-device read
/// does. Its rows then meet the hold of a prompt that goes back to the caller
/// and as far as that route may take the call (FIX 7257), judged again here
/// and on the admitted call, so a route that moved since never carries them
/// off the device.
pub(super) async fn turn_board(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    request: &ChatTurnRequest,
) -> Result<Option<ChatBoard>, BoardOmission> {
    if auth.require(CoreScope::Read).is_err()
        || auth.require(CoreScope::Write).is_err()
        || request.text.trim().is_empty()
    {
        return Ok(None);
    }
    let Some(seat) = server.ai.chat_seat() else {
        return Ok(None);
    };
    let vault = server.vault();
    let Ok((agent, _)) = assistant(auth, vault, request.agent_ref.as_deref()) else {
        return Ok(None);
    };
    // A new conversation has no room yet; one that resolves narrows the read
    // to its audience.
    let conversation = resolve_entity_ref(vault, &request.conversation_ref).ok();
    let reads_at = if auth.locality() == CallerLocality::OnDevice
        && PromptBoard::route_locality(&server.ai, vault, seat) == ModelLocality::OnDevice
    {
        CallerLocality::OnDevice
    } else {
        CallerLocality::OffDevice
    };
    let board = match crate::api::context_board::chat_board(
        server,
        auth.clone().at(reads_at),
        conversation,
        agent,
        &request.text,
    )
    .await
    {
        Ok(board) if !board.block.trim().is_empty() => board,
        Ok(_) => return Ok(None),
        Err(status) => {
            tracing::info!(
                %status,
                "a chat turn's context board was refused; the turn runs without it"
            );
            return Err(BoardOmission::Refused);
        }
    };
    let board = PromptBoard::new(board, auth.destination());
    if board.rides_route(&server.ai, vault, seat) {
        Ok(Some(board.board))
    } else {
        Err(BoardOmission::RouteHeld)
    }
}

/// A turn's call as its role admitted it.
pub(super) struct AdmittedTurn {
    pub(super) call: Result<RoleCall, RoleRefusal>,
    /// Whether the board rides the call.
    pub(super) recalled: bool,
    /// The board's context capture (FIX 6921), only when it rides.
    pub(super) context: Option<ChatContextCapture>,
    /// Why a board the turn read does not ride (FIX 8136).
    pub(super) omitted: Option<BoardOmission>,
    /// Whether the omission's note rides the call, at the board's place.
    pub(super) noted: bool,
}

/// The turn's call admitted through its role, with `board` as one User
/// message right before the newest User, or last when there is none. A role
/// that does not admit the call with the board admits it without, and so
/// does a call admitted where the board may not go for `auth`, the caller
/// (FIX 7257), never sent with it; a board the turn read and goes without
/// leaves its omission's note in its place instead (FIX 8136).
pub(super) fn admit(
    ai: &AiHandle,
    vault: &Vault,
    seat: &Seat,
    auth: &CoreAuth,
    mut messages: Vec<LlmMessage>,
    board: Result<Option<ChatBoard>, BoardOmission>,
) -> AdmittedTurn {
    let at = messages
        .iter()
        .rposition(|message| message.role == LlmMessageRole::User)
        .unwrap_or(messages.len());
    let board = match board {
        Ok(Some(board)) => board,
        Ok(None) => {
            return AdmittedTurn {
                call: ai.admit_role(vault, CHAT_ROLE, chat_request(seat, messages)),
                recalled: false,
                context: None,
                omitted: None,
                noted: false,
            };
        }
        Err(omission) => return admit_omitted(ai, vault, seat, messages, at, omission),
    };
    let baseline = messages.clone();
    messages.insert(at, text_message(LlmMessageRole::User, board.block.clone()));
    let board = PromptBoard::new(board, auth.destination());
    match ai.admit_role(vault, CHAT_ROLE, chat_request(seat, messages)) {
        Ok(admitted) if board.rides(vault, &admitted) => AdmittedTurn {
            call: Ok(admitted),
            recalled: true,
            context: board.board.context,
            omitted: None,
            noted: false,
        },
        Ok(_) => admit_omitted(ai, vault, seat, baseline, at, BoardOmission::RouteHeld),
        Err(refusal) => {
            tracing::info!(
                %refusal,
                "a chat turn's call was not admitted with its context board; it goes without it"
            );
            admit_omitted(ai, vault, seat, baseline, at, BoardOmission::NotAdmitted)
        }
    }
}

/// The call admitted without the board, `omission`'s note at the board's
/// place `at`; a role that does not admit it with the note admits it as it
/// was, and the caller is still told.
fn admit_omitted(
    ai: &AiHandle,
    vault: &Vault,
    seat: &Seat,
    mut messages: Vec<LlmMessage>,
    at: usize,
    omission: BoardOmission,
) -> AdmittedTurn {
    let baseline = messages.clone();
    messages.insert(at, text_message(LlmMessageRole::User, omission.note()));
    let (call, noted) = match ai.admit_role(vault, CHAT_ROLE, chat_request(seat, messages)) {
        Ok(admitted) => (Ok(admitted), true),
        Err(_) => (
            ai.admit_role(vault, CHAT_ROLE, chat_request(seat, baseline)),
            false,
        ),
    };
    AdmittedTurn {
        call,
        recalled: false,
        context: None,
        omitted: Some(omission),
        noted,
    }
}
