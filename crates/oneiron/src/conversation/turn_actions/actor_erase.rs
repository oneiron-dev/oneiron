//! The erase of a turn action's requester takes the signed instrument its
//! request was admitted on out of each kept copy of the action (FIX 10668):
//! the queued attempt's payload and a Retry stream's recovery seed. Every
//! other member stays, `native` stays false, and an action with no slip no
//! longer stands, so nothing runs on it.

use super::TurnActionAttempt;
use crate::EntityId;

impl TurnActionAttempt {
    /// Leaves this action without the slip its request was admitted on when
    /// `actor` asked it. Whether it changed.
    pub(crate) fn scrub_actor_instrument(&mut self, actor: &EntityId) -> bool {
        self.actor == *actor && self.invocation_slip.take().is_some()
    }
}
