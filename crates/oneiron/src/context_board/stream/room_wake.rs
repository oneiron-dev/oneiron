//! The room wake producer's STREAM half (FIX 15647): a room turn that
//! addresses an agent an external harness runs, or whose thread's open TASK
//! that agent holds, wakes the agent's STREAM connections.
//!
//! The witness that minted the turn staged the wake in its own write
//! ([`crate::workspace_roster::ROOM_WAKE_ATTEMPT_KIND`]). After each commit,
//! and when a connection attaches, the host reads the staged wakes again with
//! [`PendingRoomWake::read_all`], outside any lock, and hands the live ones
//! to [`BoardStreamRegistry::publish_room_wakes`]. That queues one WAKE per
//! wake on each connection of its agent that subscribes to
//! [`SubscriptionScope::RoomTurns`](super::SubscriptionScope::RoomTurns)
//! and has not had it yet, as review wakes are offered. Queuing settles
//! nothing: a queue may never be drained (a credential's own connection
//! beside the bridge instance that polls), so the staged row stays while
//! the wake is live and each connection that attaches later is offered it
//! too. The host settles a staged row only once the wake is no longer live:
//! its turn claimed or answered, or its agent gone from the room. A settled
//! resident's wakes are its inbox pass's, never this half's.
//!
//! The wake names the room, the turn and the agent, and nothing else: no
//! speaker, no words, and it grants no read. The harness reads the room
//! through its own bound room and takes the claim before it speaks. The
//! adapter that delivers the wake asks [`PendingRoomWake::is_pending`] again
//! and drops a wake that is no longer live. Nothing here runs inside the
//! write that minted the turn, so a wake that does not go out never fails it.

use std::collections::{BTreeMap, BTreeSet};

use super::events::{BoardEvent, RouteObservation, SubscriptionScope};
use super::frames::StreamConnectionId;
use super::provenance::VerifiedRoomWakeEvent;
use super::registry::BoardStreamRegistry;
use crate::attempt_queue::AttemptId;
use crate::workspace_roster::RoomWake;
use crate::{EntityId, Result, Vault};

/// The one line every room wake carries. It names no speaker and holds none
/// of the turn: the room holds those, behind the agent's own reads.
const ROOM_WAKE_LINE: &str =
    "a room turn addresses you; read the room, and take its claim before you answer";

/// One live room wake of an agent the engine does not run, as the board
/// STREAM sees it: its staged row and its wake.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PendingRoomWake {
    attempt: AttemptId,
    wake: RoomWake,
}

/// What one read of the staged room wakes found for the STREAM: the live
/// wakes to hand over, and the staged rows no longer live, which the host
/// settles unsent.
#[derive(Debug, Default)]
pub struct RoomWakeRead {
    pub pending: Vec<PendingRoomWake>,
    pub spent: Vec<AttemptId>,
}

impl PendingRoomWake {
    /// Every staged room wake of an agent that is no settled resident, read
    /// live ([`Vault::room_wake_turn`]). A wake whose agent's binding or turn
    /// does not read is logged and left staged for the next pass.
    pub fn read_all(vault: &Vault) -> Result<RoomWakeRead> {
        let mut read = RoomWakeRead::default();
        for staged in vault.staged_room_wakes()? {
            match vault.settled_resident_agent(staged.wake.agent) {
                Ok(None) => {}
                Ok(Some(_)) => continue,
                Err(error) => {
                    tracing::warn!(
                        agent = %staged.wake.agent.to_hex(),
                        %error,
                        "room wake: the agent's resident binding did not read; left staged"
                    );
                    continue;
                }
            }
            match vault.room_wake_turn(&staged.wake) {
                Ok(Some(_)) => read.pending.push(Self {
                    attempt: staged.attempt,
                    wake: staged.wake,
                }),
                Ok(None) => read.spent.push(staged.attempt),
                Err(error) => tracing::warn!(
                    turn = %staged.wake.turn.to_hex(),
                    agent = %staged.wake.agent.to_hex(),
                    %error,
                    "room wake: the turn did not read; left staged"
                ),
            }
        }
        Ok(read)
    }

    /// Whether `agent`'s wake for `turn` in `room` is still live: the agent
    /// still stands there and nobody holds the turn's claim. The answer is
    /// yes or no and nothing of the turn, so it grants no read.
    pub fn is_pending(
        vault: &Vault,
        agent: EntityId,
        room: EntityId,
        turn: EntityId,
    ) -> Result<bool> {
        Ok(vault
            .room_wake_turn(&RoomWake { room, turn, agent })?
            .is_some())
    }

    /// The wake id of `agent`'s wake for `turn`: `room-wake:<turn>:<agent>`.
    /// A turn is staged once per agent, so the id names one occurrence.
    #[must_use]
    pub fn wake_ref(agent: EntityId, turn: EntityId) -> String {
        format!("room-wake:{}:{}", turn.to_hex(), agent.to_hex())
    }
}

/// Which connections each live room wake was queued on, so a pass offers
/// it once per connection and a connection that attaches later still hears
/// it.
#[derive(Debug, Default)]
pub(super) struct PublishedRoomWakes {
    offered: BTreeMap<String, BTreeSet<StreamConnectionId>>,
}

impl PublishedRoomWakes {
    /// Forgets what was queued for `connection` once its queue is gone, so
    /// a connection attached again under the same id hears each wake anew.
    pub(super) fn forget(&mut self, connection: &StreamConnectionId) {
        self.offered.retain(|_, offered| {
            offered.remove(connection);
            !offered.is_empty()
        });
    }
}

impl BoardStreamRegistry {
    /// Queues a WAKE for each pending room wake on every connection of its
    /// agent that subscribes to room turns and has not had it yet. `pending`
    /// is the whole live set, read after a commit or an attach: a wake it no
    /// longer holds is forgotten here. Queuing settles no staged row.
    pub fn publish_room_wakes(&mut self, pending: Vec<PendingRoomWake>) -> RouteObservation {
        let mut observed = RouteObservation::default();
        let live: BTreeSet<String> = pending
            .iter()
            .map(|pending| PendingRoomWake::wake_ref(pending.wake.agent, pending.wake.turn))
            .collect();
        self.published_room_wakes
            .offered
            .retain(|event_ref, _| live.contains(event_ref));
        for pending in pending {
            let wake = pending.wake;
            let event_ref = PendingRoomWake::wake_ref(wake.agent, wake.turn);
            let agent_ref = wake.agent.to_hex();
            let fresh: BTreeSet<StreamConnectionId> = {
                let offered = self.published_room_wakes.offered.get(&event_ref);
                self.connections
                    .iter()
                    .filter(|(connection, state)| {
                        state.actor_ref == agent_ref
                            && state.subscribed.contains(&SubscriptionScope::RoomTurns)
                            && !offered.is_some_and(|offered| offered.contains(*connection))
                    })
                    .map(|(connection, _)| connection.clone())
                    .collect()
            };
            if fresh.is_empty() {
                continue;
            }
            let routed = self.route_event_where(
                BoardEvent::RoomTurnAddressed {
                    event: VerifiedRoomWakeEvent {
                        agent_ref,
                        room_ref: wake.room.to_hex(),
                        turn_ref: wake.turn.to_hex(),
                        event_ref: event_ref.clone(),
                    },
                    line: ROOM_WAKE_LINE.to_owned(),
                },
                |connection, _| fresh.contains(connection),
            );
            observed.wake_enqueued += routed.wake_enqueued;
            self.published_room_wakes
                .offered
                .entry(event_ref)
                .or_default()
                .extend(fresh);
        }
        observed
    }
}
