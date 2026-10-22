//! Two phases of one turn action's run (`act`): admitting its call, with
//! its context board where the board may ride, and opening its answer on
//! the MESSAGE or new TURN it lands in. `act` calls them in order.
use std::sync::Arc;

use oneiron::conversation::{TurnAction, TurnActionAttempt};
use oneiron::memory::WitnessAuthor;
use oneiron::{LlmCapability, LlmMessage, LlmMessageRole, Vault};

use crate::ai_host::{AiHandle, CHAT_ROLE};
use crate::api::ai::chat::{
    AnswerOpen, CONTINUE_INSTRUCTION, chat_request, text_message, witness_turn,
};
use crate::api::{ChatContextCapture, PromptBoard};
use crate::models::{RoleCall, Seat};

/// What admission reads of the action's context: the saved reply a
/// Continue extends, and the index of the user turn the board rides before.
pub(super) struct ActionText {
    pub(super) saved: String,
    pub(super) answers: usize,
}

/// Admits the action's call, with `board` before its user turn where the
/// board may ride, else as the call always was; the board's capture when
/// it rode. The reason it was not admitted otherwise.
pub(super) fn admit_action(
    vault: &Arc<Vault>,
    ai: &AiHandle,
    seat: &Seat,
    action: &TurnActionAttempt,
    text: ActionText,
    messages: Vec<LlmMessage>,
    board: Option<PromptBoard>,
) -> Result<(RoleCall, Option<ChatContextCapture>), String> {
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
    let (admitted, board_context) = match board {
        Some(board) => {
            let mut framed = messages.clone();
            framed.insert(
                text.answers,
                text_message(LlmMessageRole::User, board.board.block.clone()),
            );
            match request(framed) {
                Ok(admitted) if board.rides(vault, &admitted) => (admitted, board.board.context),
                Ok(_) => (request(messages)?, None),
                Err(_) => {
                    tracing::info!(
                        "a turn action's call was not admitted with its context board; it goes without it"
                    );
                    (request(messages)?, None)
                }
            }
        }
        None => (request(messages)?, None),
    };
    Ok((admitted, board_context))
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
