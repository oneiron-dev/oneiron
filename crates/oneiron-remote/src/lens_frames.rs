//! A host-rendered lens card's events and its close (OF-181), over the
//! server routes `POST /v1/core/lens-frames/{card_id}/events` and `DELETE
//! /v1/core/lens-frames/{card_id}`.
//!
//! These are transport helpers, not verbs: the routes sit outside the facade
//! nest and have no verb-table row. A card's frame lives only on the server
//! that rendered it (`vault.lenses.default`), found there by the card id. The
//! handle that sends an event authors its action (FIX 3267): a person
//! pressing an agent-rendered card sends its own events, proved under its own
//! credential, and the card id lends it none of the renderer's authority.
//! Closing a card stays with the handle that rendered it. A handle served in
//! process (`connect_in_process`, OF-237) crosses its transport to the server
//! this process runs, with the same headers and the same replies, a queued
//! callback included. That served client is the path for interactive frames
//! in an app that runs its engine in process (`EmbeddedEngine.client` in the
//! UniFFI binding). An embedded handle holds no frame and refuses both calls;
//! this crate keeps no second frame store and no bare renderer.
//!
//! An event's reply states its dispatched verb's call receipt, so
//! `last_receipt_ref` reads it after a deterministic tool (FIX 2887); a local
//! patch, a queued callback and a close dispatch no verb and leave it empty.
//!
//! The bodies are the server's wire shapes, camelCase as it spells them.

use oneiron::claim::ScopedReadReceipt;
use oneiron::lens::{GeneratedUiActionEvent, GeneratedUiStateSnapshot};
use oneiron::memory::MemoryError;
use serde::{Deserialize, Serialize};

use crate::{Backend, OneironClient};

/// One event's body: the client's event, the key a deterministic action's
/// dispatch replays under, and the selections this handle made on the card.
/// The key is required in the body.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LensFrameEventRequest {
    /// What was touched: the card, the element, the action, an optional
    /// `$state` patch and when. It names no command and no authority.
    pub event: GeneratedUiActionEvent,
    /// The idempotency key a deterministic action's dispatch replays under.
    pub idempotency_key: String,
    /// Selections this handle made on this card, each the `selectionRef`
    /// `vault.lenses.select` answered (FIX 3268): read reach the server
    /// holds, proved again under the held render before a model round trip
    /// carries it to the agent as context. Context, never approval or
    /// action authority; any other action ignores it. Empty by default.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub selected_context: Vec<String>,
}

/// What an event answers. The wire has no discriminator: a local action
/// answers the card's new `$state`, a deterministic tool its outcome and the
/// scoped read of its entity arguments, and a model round trip the callback
/// queued for the agent that emitted the card.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum LensFrameEventReply {
    /// A local patch moved the card's held `$state`; nothing was dispatched.
    Local {
        /// The card's `$state` after the patch.
        #[serde(rename = "$state")]
        state: GeneratedUiStateSnapshot,
    },
    /// A deterministic tool ran as the credential's action.
    Tool {
        /// The outcome as the run's replay record spells it.
        outcome: serde_json::Value,
        /// The principal's scoped read of the action's entity arguments.
        #[serde(rename = "readReceipt")]
        read_receipt: ScopedReadReceipt,
    },
    /// A model round trip went back to the agent that emitted the card, as
    /// its next turn (`202`). A replay answers the same callback.
    Callback {
        /// False once the agent's run that carried it has finished.
        queued: bool,
        /// The agent run that carries the callback.
        #[serde(rename = "callbackId")]
        callback_id: String,
    },
}

/// What a close answers: whether this server held the card's frame. A card it
/// does not hold, or an id that is no card, answers `false`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloseLensFrameReply {
    /// Whether a held frame was freed.
    pub closed: bool,
}

/// What an embedded handle answers both calls with (G47): a card's frame
/// lives only on the served host that rendered it, and an embedded handle
/// renders with no host to keep one. The served client is the path; there is
/// no bare renderer. One constant, so a later ruling changes one line.
const EMBEDDED_LENS_FRAME_REFUSAL: &str = "lens frames live on the served host that rendered the card, and an embedded handle keeps none; render the lens and send its events through a served client";

/// The paths [`EMBEDDED_LENS_FRAME_REFUSAL`] names, in order.
const EMBEDDED_LENS_FRAME_SUGGESTIONS: &[&str] = &[
    "In this process, render the lens through the in-process served client (OneironClient::connect_in_process; EmbeddedEngine.client in an app) and send its events and close on that same handle.",
    "Or connect to the oneiron-server that rendered the card and send its events through that handle.",
    "A card an embedded handle rendered has no frame to drive: render it again through the served client.",
];

/// An embedded handle's answer to both calls: it holds no frame.
fn embedded_refusal() -> MemoryError {
    crate::error::bad_request(EMBEDDED_LENS_FRAME_REFUSAL, EMBEDDED_LENS_FRAME_SUGGESTIONS)
}

impl OneironClient {
    /// Sends one event on the lens card `card_id` to the server that
    /// rendered it, under this handle's credential, which authors the
    /// card's action whoever rendered it. `request.event.cardId` must name
    /// the same card. A card the server holds no frame for (closed, evicted,
    /// or held before a restart) refuses `NOT_FOUND`: render the lens again.
    /// A model round-trip action queues its callback for the agent that
    /// rendered the card; a card no agent rendered refuses `INVALID_STATE`. A handle served in process sends it to the server
    /// this process runs; an embedded handle refuses `BAD_REQUEST`, naming
    /// the served client to render through.
    pub fn lens_frame_event(
        &self,
        card_id: &str,
        request: &LensFrameEventRequest,
    ) -> Result<LensFrameEventReply, MemoryError> {
        match &self.backend {
            Backend::Remote(remote) => remote.lens_frame_event(card_id, request),
            Backend::Embedded(_) => Err(embedded_refusal()),
        }
    }

    /// Closes the lens card `card_id` on the server that rendered it and
    /// frees its frame, when this handle rendered it. An embedded handle
    /// refuses `BAD_REQUEST`.
    pub fn close_lens_frame(&self, card_id: &str) -> Result<CloseLensFrameReply, MemoryError> {
        match &self.backend {
            Backend::Remote(remote) => remote.close_lens_frame(card_id),
            Backend::Embedded(_) => Err(embedded_refusal()),
        }
    }
}
