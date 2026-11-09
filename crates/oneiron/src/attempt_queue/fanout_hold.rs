//! OF-393: the fan-out launch hold. A cut that waits on its launch approval
//! parks its planning attempt here; it is never a budget hold.
//!
//! When a gated wave apply holds its cut for the owner's ruling, the worker
//! holding the planning attempt parks it here, in the transaction that
//! records the held launch: the lease-fenced door moves the leased row to
//! `Paused` with the checkpoint naming that launch, under the reserved
//! [`FANOUT_HOLD_ACTOR`]. Nothing is cancelled or completed. The approval
//! resumes the same row through the ordinary `Resume` intervention, re-leases
//! it and completes it as the cut lands, all in one transaction; a denial
//! leaves it parked and visible.

use super::AttemptQueue;
use super::AttemptResumePoint;
use super::lifecycle::{EngineHold, HoldWrite};
use super::types::{AttemptId, AttemptPause, AttemptRecord, AttemptState};
use crate::entity_id::EntityId;
use crate::error::Result;

/// The intervention actor of a fan-out launch hold. Reserved: only the
/// lease-fenced hold door writes it, so a person's pause never reads as a
/// hold and an approval never releases a person's pause.
pub const FANOUT_HOLD_ACTOR: &str = "engine:fanout_hold";

/// Refusal for an intervention that names [`FANOUT_HOLD_ACTOR`].
pub(in crate::attempt_queue) const ERR_FANOUT_HOLD_ACTOR_RESERVED: &str =
    "intervention actor is reserved for the fan-out launch hold";

/// The prefix of a fan-out hold's event note; the launch ref follows.
const HOLD_NOTE_PREFIX: &str = "fanout launch ";

/// The lease holder's request to hold its attempt for a launch approval.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HoldAttemptForFanout {
    pub id: AttemptId,
    pub lease_owner: String,
    pub attempt_count: u32,
    /// The held launch the owner rules on.
    pub launch_ref: EntityId,
    /// Where the same work picks up on resume.
    pub resume_point: AttemptResumePoint,
    pub now: u64,
}

impl AttemptRecord {
    /// Whether this row is paused by the fan-out hold of `launch_ref`:
    /// paused, and held under the engine's hold for that launch. A row a
    /// person paused or resumed afterwards reads `false`. Read from the row's
    /// held pause, never from its pruned event history (FIX 9579).
    #[must_use]
    pub fn fanout_hold_for(&self, launch_ref: EntityId) -> bool {
        self.state == AttemptState::Paused
            && self.active_pause == Some(AttemptPause::Fanout { launch_ref })
    }
}

impl AttemptQueue<'_> {
    /// Holds a leased attempt for a launch approval: lease-fenced like
    /// complete/fail, it parks the row `Paused` with its checkpoint and
    /// releases the lease. Idempotent for a row already held for the same
    /// launch.
    ///
    /// # Errors
    ///
    /// A missing row, a row that is not leased, a stale lease or an invalid
    /// resume point; storage errors.
    pub(crate) fn hold_for_fanout_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        input: HoldAttemptForFanout,
    ) -> Result<AttemptRecord> {
        self.hold_in_txn(
            wtxn,
            HoldWrite {
                id: input.id,
                lease_owner: input.lease_owner,
                attempt_count: input.attempt_count,
                resume_point: input.resume_point,
                hold: EngineHold::Fanout {
                    launch_ref: input.launch_ref,
                },
                actor: FANOUT_HOLD_ACTOR,
                note: format!("{HOLD_NOTE_PREFIX}{}", input.launch_ref.to_hex()),
                now: input.now,
            },
        )
    }
}
