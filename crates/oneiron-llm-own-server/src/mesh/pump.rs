//! The asking side's stream pump (FIX 8619): a mesh stream's events go to
//! its caller one handoff at a time. The pump asks the serving node for its
//! next batch only once the caller has taken every event handed so far, and
//! awaits each handoff, its error and end too. A batch's bytes stay booked
//! on the transport's [`StagingBudget`](super::StagingBudget) until the
//! caller takes its last event. A caller that stops reading pauses the
//! node's stream; nothing is dropped and no timeout is added. A caller that
//! lets the stream go ends the pump ([`AbortOnDrop`]) and every wait in it.

use std::pin::Pin;
use std::task::{Context, Poll};

use oneiron::{LlmResult, LlmStreamEvent};
use tokio::sync::mpsc;
use tokio::task::AbortHandle;

use super::staging::Booking;

/// Stops the spawned call when the caller lets it go.
pub(super) struct AbortOnDrop(pub(super) AbortHandle);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// One event handed to the caller, with the batch booking it closes, if it
/// is its batch's last.
struct Handed {
    event: LlmResult<LlmStreamEvent>,
    _booking: Option<Booking>,
}

/// The pump's end: it hands events over one at a time.
pub(super) struct Demand {
    send: mpsc::Sender<Handed>,
}

/// Room for one handoff, held while the pump asks for more.
pub(super) struct Room<'a> {
    permit: mpsc::Permit<'a, Handed>,
}

/// The caller's end before the pump's task runs: guarded, it is the
/// stream ([`Unguarded::guarded`]).
pub(super) struct Unguarded {
    receive: mpsc::Receiver<Handed>,
}

/// The caller's end: the stream's events, as the pump hands them.
pub(super) struct DemandStream {
    receive: mpsc::Receiver<Handed>,
    _guard: AbortOnDrop,
}

/// A pump and the end it feeds: one handoff of room between them.
pub(super) fn demand() -> (Demand, Unguarded) {
    let (send, receive) = mpsc::channel(1);
    (Demand { send }, Unguarded { receive })
}

impl Unguarded {
    /// The stream, ending the pump's task, `guard`'s, when it is let go.
    pub(super) fn guarded(self, guard: AbortOnDrop) -> DemandStream {
        DemandStream {
            receive: self.receive,
            _guard: guard,
        }
    }
}

impl Demand {
    /// Room for the next handoff, once the caller has taken every event
    /// handed so far: what the pump waits for before it asks the node for
    /// more. `None` when the caller let the stream go.
    pub(super) async fn room(&self) -> Option<Room<'_>> {
        self.send.reserve().await.ok().map(|permit| Room { permit })
    }

    /// Hands `event` over, waiting for the caller to take the one before.
    /// `false` when the caller let the stream go.
    pub(super) async fn hand(
        &self,
        event: LlmResult<LlmStreamEvent>,
        booking: Option<Booking>,
    ) -> bool {
        self.send
            .send(Handed {
                event,
                _booking: booking,
            })
            .await
            .is_ok()
    }

    /// Whether the caller let the stream go.
    pub(super) fn is_closed(&self) -> bool {
        self.send.is_closed()
    }
}

impl Room<'_> {
    /// Hands `event` over in the room already held.
    pub(super) fn hand(self, event: LlmResult<LlmStreamEvent>, booking: Option<Booking>) {
        self.permit.send(Handed {
            event,
            _booking: booking,
        });
    }
}

impl futures_core::Stream for DemandStream {
    type Item = LlmResult<LlmStreamEvent>;
    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        // Taking an event frees its handoff's room, and the batch booking
        // its last event closes.
        self.receive
            .poll_recv(cx)
            .map(|handed| handed.map(|handed| handed.event))
    }
}
