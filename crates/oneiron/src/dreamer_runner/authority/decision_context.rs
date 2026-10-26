//! The loop link an attempt's action carries on its Gate decision (FIX 7500),
//! from the attempt's own authority stamp: the agent it runs as and the
//! receipt that admitted it. Read only; nothing here refuses.

use super::{ATTEMPT, RESIDENT_ATTEMPT};
use crate::Vault;
use crate::attempt_queue::{AttemptId, AttemptQueue};
use crate::store::{GateDecisionId, GateLoopLink, GateLoopOrigin, GateLoopSource};

impl Vault {
    /// The link of an action attempt `attempt` took: the base agent or the
    /// resident its stamp names, the receipt that admitted it, and the run
    /// its queue row names. A stamp or row that does not read leaves that
    /// part unresolved; the action's own record never waits on it.
    pub(crate) fn attempt_action_link_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        attempt: AttemptId,
    ) -> GateLoopLink {
        let run = AttemptQueue::new(self)
            .get_in_txn(txn, attempt)
            .ok()
            .flatten()
            .and_then(|record| record.run_id);
        let stamped = match ATTEMPT.get(&self.store, txn, &attempt) {
            Ok(Some(stamp)) => Some((
                match super::base_agent_for_facet(&stamp.facet) {
                    super::BaseAgent::Dreamer => GateLoopSource::Dreamer,
                    super::BaseAgent::Coach => GateLoopSource::Coach,
                },
                stamp.receipt_id,
            )),
            _ => match RESIDENT_ATTEMPT.get(&self.store, txn, &attempt) {
                Ok(Some(stamp)) => Some((GateLoopSource::Resident, stamp.receipt_id)),
                _ => None,
            },
        };
        let (source, origin) = match stamped {
            Some((source, receipt)) => (
                source,
                GateLoopOrigin::Decision(GateDecisionId::from_bytes(receipt)),
            ),
            None => (GateLoopSource::Runner, GateLoopOrigin::Unresolved),
        };
        GateLoopLink::action(source, run, Some(*attempt.as_bytes()), origin)
    }
}
