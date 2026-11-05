//! Two phases of one turn action's run (`act`): admitting its call, with
//! its context board where the board may ride, and opening its answer on
//! the MESSAGE or new TURN it lands in. `act` calls them in order.
use std::sync::Arc;

use oneiron::conversation::{TurnAction, TurnActionAttempt};
use oneiron::memory::WitnessAuthor;
use oneiron::{EntityId, LlmCapability, LlmMessage, LlmMessageRole, Vault};

use crate::ai_host::{AiHandle, CHAT_ROLE};
use crate::api::ai::chat::{
    AnswerOpen, CONTINUE_INSTRUCTION, chat_request, text_message, turn_tail, witness_turn,
};
use crate::api::{ChatContextCapture, PromptBoard};
use crate::models::{RoleCall, Seat};

/// What admission reads of the action's context: the saved reply a
/// Continue extends, the index of the user turn the board rides before, and
/// the opener that closes the turn (I1 = C).
pub(super) struct ActionText {
    pub(super) saved: String,
    pub(super) answers: usize,
    pub(super) opener: Option<String>,
}

/// `messages` with the turn's close right after the user turn at `answers`:
/// the board's query part when `board` rides, then the opener (I1 = C turn
/// order, FIX 14677); the opener alone otherwise (FIX 14676).
fn closed(
    mut messages: Vec<LlmMessage>,
    answers: usize,
    board: Option<&PromptBoard>,
    opener: Option<&str>,
) -> Vec<LlmMessage> {
    let query = board.and_then(|board| board.board.query.as_ref());
    if let Some(tail) = turn_tail(query, opener) {
        let after = (answers + 1).min(messages.len());
        messages.insert(after, text_message(LlmMessageRole::User, tail));
    }
    messages
}

/// Admits the action's call, with `board` in two parts where the board may
/// ride (its state part before the user turn, its query part and the
/// opener right after it), else as the call always was, closed by the
/// opener; the board's capture and rows when it rode (independent of
/// whether a capture was available). The reason it was not admitted
/// otherwise.
pub(super) fn admit_action(
    vault: &Arc<Vault>,
    ai: &AiHandle,
    seat: &Seat,
    action: &TurnActionAttempt,
    text: ActionText,
    messages: Vec<LlmMessage>,
    board: Option<PromptBoard>,
) -> Result<(RoleCall, Option<ChatContextCapture>, Option<Vec<EntityId>>), String> {
    let admit = |messages| {
        ai.admit_role(vault, CHAT_ROLE, chat_request(seat, messages))
            .map_err(|refusal| refusal.to_string())
    };
    // An empty saved reply is an honest empty prefix: the reply is generated
    // afresh on the same MESSAGE.
    let continues = action.action == TurnAction::Continue && !text.saved.is_empty();
    let request = |mut messages: Vec<LlmMessage>| {
        let mut admitted = admit(messages.clone())?;
        if continues {
            let prefill = admitted
                .ladder
                .supports(&admitted.request.model, &LlmCapability::AssistantPrefill);
            messages.push(text_message(LlmMessageRole::Assistant, text.saved.clone()));
            if !prefill {
                messages.push(text_message(
                    LlmMessageRole::User,
                    CONTINUE_INSTRUCTION.to_owned(),
                ));
            }
            admitted = admit(messages)?;
        }
        Ok::<_, String>(admitted)
    };
    // A call its role does not admit with the board, first or with its
    // suffix, is admitted exactly as it always was, and so is the final call
    // admitted where the board may not go (FIX 7257), never sent with it.
    let opener = text.opener.as_deref();
    // Without the board, the call closes with the opener alone; a role that
    // does not admit it so admits it as it always was.
    let bare = |messages: Vec<LlmMessage>| {
        if opener.is_some()
            && let Ok(admitted) = request(closed(messages.clone(), text.answers, None, opener))
        {
            return Ok(admitted);
        }
        request(messages)
    };
    let (admitted, board_context, board_rows) = match board {
        Some(board) => {
            let mut framed = messages.clone();
            framed.insert(
                text.answers,
                text_message(LlmMessageRole::User, board.board.block.clone()),
            );
            let framed = closed(framed, text.answers + 1, Some(&board), opener);
            match request(framed) {
                Ok(admitted) if board.rides(vault, &admitted) => {
                    (admitted, board.board.context, Some(board.board.rows))
                }
                Ok(_) => (bare(messages)?, None, None),
                Err(_) => {
                    tracing::info!(
                        "a turn action's call was not admitted with its context board; it goes without it"
                    );
                    (bare(messages)?, None, None)
                }
            }
        }
        None => (bare(messages)?, None, None),
    };
    Ok((admitted, board_context, board_rows))
}

/// Where the action's answer opens: more of its MESSAGE for a Continue, a
/// new TURN for a Retry.
pub(super) fn answer_open(vault: &Vault, action: &TurnActionAttempt) -> AnswerOpen {
    match action.action {
        TurnAction::Continue => AnswerOpen::Continue(action.message),
        // The reply's TURN lands with its MESSAGE, in the reply's terminal
        // write (FIX 3152): on a DAG conversation a sibling of the old one
        // that leaves HEAD where it is, in a project room an answer to the
        // same claimed turn (FIX 3149), elsewhere the TURN the stream mints.
        // A Retry never admitted leaves neither.
        TurnAction::Retry => AnswerOpen::Retry {
            turn: witness_turn(
                &action.conversation.to_hex(),
                None,
                WitnessAuthor::Companion,
                String::new(),
                vault.now_recorded_at(),
            ),
            action: Box::new(action.clone()),
        },
    }
}
