//! The erase of a turn action's requester takes the signed instrument its
//! request was admitted on out of each kept copy of the action (FIX 10668):
//! the queued attempt's payload and a Retry stream's recovery seed. Every
//! other member stays, its authority reads as an erased slip, never native,
//! and so it no longer stands and nothing runs on it.

use super::{TurnActionAttempt, TurnActionAuthority};
use crate::EntityId;

impl TurnActionAttempt {
    /// Leaves this action without the slip its request was admitted on when
    /// `actor` asked it. Whether it changed.
    pub(crate) fn scrub_actor_instrument(&mut self, actor: &EntityId) -> bool {
        if self.actor != *actor || !self.holds_slip() {
            return false;
        }
        self.authority = TurnActionAuthority::SlipErased;
        true
    }

    /// Whether this action still keeps the slip its request was admitted on.
    pub(crate) fn holds_slip(&self) -> bool {
        matches!(self.authority, TurnActionAuthority::Slip { .. })
    }
}
