//! What a conversation's next chat turn is known to start with past its
//! committed history (I1 = C, ARCH-0067 turn order): the answering agent's
//! resident craft, where the layout puts it right after the history, then
//! the state-only part of its board, which reads no new message. Once a
//! reply's canonical successor is published on a native session, the
//! session coordinator asks this for those messages, rendered now for the
//! turn's reader as the turn's own call renders them, and prepares them
//! beside the published checkpoint. The next turn reads its own craft,
//! renders its own board and runs its own recall; the worker reuses the
//! prepared tokens only where the turn's tokens equal them.
//!
//! A live chat turn hands this over, and so does a queued Continue or Retry
//! that published a successor (FIX 14677): the conversation's next turn is
//! then its requester's, read under what the action's kept slip verifies to
//! again.
use std::sync::Arc;

use oneiron::claim::CallerLocality;
use oneiron::prompt::PromptLayout;
use oneiron::{EntityId, ModelLocality};
use serde_json::{Value as JsonValue, json};

use super::TurnCredential;
use super::segments::Reader;
use crate::api::context_board::PromptBoard;
use crate::auth::CoreAuth;
use crate::models::{NextTail, NextTurnSource};
use crate::server::SyncServer;

/// One conversation's next turn, as the turn just answered saw it: its
/// reader (the credential it was asked on, where it was asked from), the
/// agent that answers it and the conversation it was asked in.
pub(super) struct ChatNextTurn {
    pub(super) server: Arc<SyncServer>,
    pub(super) reader: Reader,
    pub(super) agent: EntityId,
    pub(super) conversation: Option<EntityId>,
}

impl NextTurnSource for ChatNextTurn {
    /// The craft carrier when the layout puts it after the history, then
    /// the state part, rendered now; the state part is read on the device,
    /// as the turn's own board is, only when the caller sits here and the
    /// chat role's route stays here. Nothing once the credential lapsed or
    /// the board read fails.
    fn next_tail(&self) -> NextTail<'_> {
        Box::pin(async move {
            let auth = crate::server::blocking(|| self.auth())?;
            let seat = self.server.ai.chat_seat()?;
            let vault = self.server.vault();
            let reads_at = if auth.locality() == CallerLocality::OnDevice
                && PromptBoard::route_locality(&self.server.ai, vault, seat)
                    == ModelLocality::OnDevice
            {
                CallerLocality::OnDevice
            } else {
                CallerLocality::OffDevice
            };
            let state = crate::api::context_board::next_state_part(
                &self.server,
                &auth.clone().at(reads_at),
                self.conversation,
                Some(self.agent),
            )
            .await?;
            let craft = crate::server::blocking(|| self.craft(&auth));
            Some(
                craft
                    .into_iter()
                    .chain([json!({ "role": "user", "content": state })])
                    .collect(),
            )
        })
    }
}

impl ChatNextTurn {
    /// The credential the next turn's reads stand on, live now: a request's
    /// own, or what a queued action's kept slip verifies to again, placed
    /// where its requester asked from ([`crate::api::context_board::requester_auth`]).
    fn auth(&self) -> Option<CoreAuth> {
        if !self.reader.credential.live() {
            return None;
        }
        match &self.reader.credential {
            TurnCredential::Request { auth, .. } => Some(auth.clone()),
            TurnCredential::Action { action, .. } => Some(
                crate::api::context_board::requester_auth(&self.server, action)?
                    .at(self.reader.locality),
            ),
        }
    }

    /// The answering agent's craft as the next turn shows it, when the
    /// layout puts it right after the history, before the state part (FIX
    /// 6676, FIX 14888): read now, on one snapshot, through the handle a
    /// live turn of `auth` reads it through, in the carrier the turn sends.
    /// `None` in the early-system layout, where the craft rides the
    /// published path, and when no craft reads.
    fn craft(&self, auth: &CoreAuth) -> Option<JsonValue> {
        let layout = self.server.ai.prompt_layout();
        if layout != PromptLayout::StableHistoryThenTurnContext {
            return None;
        }
        let vault = self.server.vault();
        let Reader {
            actor,
            class,
            locality,
            ..
        } = &self.reader;
        let reader = match auth.principal_ref() {
            Some(_) => {
                crate::api::credential_memory(vault, Some(auth), *actor, *class).at(*locality)
            }
            None => vault.memory(*actor, *class),
        };
        let craft = crate::ai_host::resident_craft::snapshot_craft_scoped(
            vault,
            &reader,
            &self.agent,
            vault.now_recorded_at(),
            layout,
        )?;
        let mut placed = Vec::new();
        crate::ai_host::resident_craft::place_craft(&mut placed, 0, craft.message, layout)?;
        let [message] = placed.as_slice() else {
            return None;
        };
        Some(json!({
            "role": "user",
            "content": super::compaction::message_text(message),
        }))
    }
}
