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
//! [`SubscriptionScope::RoomTurns`](super::SubscriptionScope::RoomTurns).
//! A wake queued on a connection is handed over, and the host settles its
//! staged row; a wake no longer live is settled unsent; one whose agent has
//! no such connection yet waits for one to attach. A settled resident's
//! wakes are its inbox pass's, never this half's.
//!
//! The wake names the room, the turn and the agent, and nothing else: no
//! speaker, no words, and it grants no read. The harness reads the room
//! through its own bound room and takes the claim before it speaks. The
//! adapter that delivers the wake asks [`PendingRoomWake::is_pending`] again
//! and drops a wake that is no longer live. Nothing here runs inside the
//! write that minted the turn, so a wake that does not go out never fails it.

use super::events::BoardEvent;
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

impl BoardStreamRegistry {
    /// Queues a WAKE for each pending room wake on every connection of its
    /// agent that subscribes to room turns, and answers the staged rows it
    /// queued on at least one connection: those are handed over, and the host
    /// settles them. A wake whose agent has no such connection stays staged
    /// until one attaches.
    pub fn publish_room_wakes(&mut self, pending: Vec<PendingRoomWake>) -> Vec<AttemptId> {
        let mut handed = Vec::new();
        for pending in pending {
            let wake = pending.wake;
            let routed = self.route_event(BoardEvent::RoomTurnAddressed {
                event: VerifiedRoomWakeEvent {
                    agent_ref: wake.agent.to_hex(),
                    room_ref: wake.room.to_hex(),
                    turn_ref: wake.turn.to_hex(),
                    event_ref: PendingRoomWake::wake_ref(wake.agent, wake.turn),
                },
                line: ROOM_WAKE_LINE.to_owned(),
            });
            if routed.wake_enqueued > 0 {
                handed.push(pending.attempt);
            }
        }
        handed
    }
}
