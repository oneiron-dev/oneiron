//! Where a chat call's context board may go (FIX 7257), for a live turn and
//! a queued Continue or Retry alike: its rows meet the hold of a prompt that
//! goes to the caller who reads the answer and as far as the call may reach,
//! judged by the shared [`crate::device_local::prompt_destination`] as
//! `ai.reply` judges its own. The reach is the widest route the call may
//! take: where it is admitted, every rung of the ladder that sends it, and
//! every model the owner may name as that ladder's fallback for a parked
//! offer. It is judged on the role's live route before the call is admitted,
//! and again on the call that carries the board. A route that is not read
//! is a third party's. A board that may not go leaves the call as it always
//! ran, logged without content; judging it never fails the call.
use oneiron::settings::ReadDestination;
use oneiron::{ModelLocality, Vault};

use super::ChatBoard;
use crate::ai_host::{AiHandle, CHAT_ROLE};
use crate::models::{RoleCall, Seat};

/// A board read for one chat call, beside the caller its answer goes back
/// to.
pub(crate) struct PromptBoard {
    pub(crate) board: ChatBoard,
    /// Where the caller who reads the answer sits.
    caller: ReadDestination,
}

impl PromptBoard {
    pub(crate) fn new(board: ChatBoard, caller: ReadDestination) -> Self {
        Self { board, caller }
    }

    /// Whether the board may ride a call of the chat role, judged before
    /// the call is admitted: as far as the role's live route from `seat`
    /// may take it, or a third party's when that route is not read.
    pub(crate) fn rides_route(&self, ai: &AiHandle, vault: &Vault, seat: &Seat) -> bool {
        let reach = match ai.models().route_role(vault, CHAT_ROLE, seat) {
            Ok(route) => route.locality.max(route.ladder.prompt_locality_bound()),
            Err(_) => ModelLocality::ThirdParty,
        };
        self.may_go(vault, reach, "route")
    }

    /// Whether the board may ride `call`, the admitted call that carries it:
    /// as far as its admission and the ladder that sends it may take it.
    pub(crate) fn rides(&self, vault: &Vault, call: &RoleCall) -> bool {
        let reach = call
            .request
            .envelope
            .locality
            .max(call.ladder.prompt_locality_bound());
        self.may_go(vault, reach, "admitted")
    }

    /// Whether no row of the board is one a world keeps from a prompt that
    /// goes to the caller and to a model at `reach`; a hold, or a hold that
    /// is not read, keeps the board here.
    fn may_go(&self, vault: &Vault, reach: ModelLocality, stage: &'static str) -> bool {
        let destination = crate::device_local::prompt_destination(self.caller.clone(), reach);
        match crate::device_local::retained_hold(
            vault,
            &destination,
            &self.board.rows,
            self.board.block.as_bytes(),
        ) {
            Ok(None) => true,
            Ok(Some(hold)) => {
                tracing::info!(
                    reason = hold.reason(),
                    stage,
                    "a chat call's context board is kept on this device; the call runs without it"
                );
                false
            }
            Err(error) => {
                tracing::warn!(
                    kind = ?error.kind(),
                    stage,
                    "a chat call's context board hold was not read; the call runs without it"
                );
                false
            }
        }
    }
}
