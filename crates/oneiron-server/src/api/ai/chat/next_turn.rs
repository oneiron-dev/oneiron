//! What a live chat conversation's next turn is known to start with past its
//! committed history (I1 = C, ARCH-0067 turn order): the state-only part of
//! its board, which reads no new message. Once a reply's canonical successor
//! is published on a native session, the session coordinator asks this for
//! that part, rendered now for the turn's reader as the turn's own board
//! renders it, and prepares it beside the published checkpoint. The next
//! turn renders its own board and runs its own recall; the worker reuses the
//! prepared tokens only where the turn's tokens equal them.
//!
//! The tail is the state part's one User message, the message the turn puts
//! right after its history: so a turn whose resident craft rides there (the
//! stable layout) prepares nothing.
use std::sync::Arc;

use oneiron::claim::CallerLocality;
use oneiron::{EntityId, ModelLocality};
use serde_json::json;

use super::TurnCredential;
use crate::api::context_board::PromptBoard;
use crate::auth::CoreAuth;
use crate::models::{NextTail, NextTurnSource};
use crate::server::SyncServer;

/// One conversation's next turn, as the turn just answered saw it: its
/// caller's credential and the conversation it was asked in.
pub(super) struct ChatNextTurn {
    pub(super) server: Arc<SyncServer>,
    pub(super) auth: CoreAuth,
    pub(super) credential: TurnCredential,
    pub(super) conversation: Option<EntityId>,
}

impl NextTurnSource for ChatNextTurn {
    /// The state part, rendered now, read on the device as the turn's own
    /// board is only when the caller sits here and the chat role's route
    /// stays here; nothing once the credential lapsed or the read fails.
    fn next_tail(&self) -> NextTail<'_> {
        Box::pin(async move {
            if !crate::server::blocking(|| self.credential.live()) {
                return None;
            }
            let seat = self.server.ai.chat_seat()?;
            let vault = self.server.vault();
            let reads_at = if self.auth.locality() == CallerLocality::OnDevice
                && PromptBoard::route_locality(&self.server.ai, vault, seat)
                    == ModelLocality::OnDevice
            {
                CallerLocality::OnDevice
            } else {
                CallerLocality::OffDevice
            };
            let state = crate::api::context_board::next_state_part(
                &self.server,
                &self.auth.clone().at(reads_at),
                self.conversation,
            )
            .await?;
            Some(vec![json!({ "role": "user", "content": state })])
        })
    }
}
