//! The authored carriers whose writers already mask a new write: an
//! owner-policy ruling or proposal, an eval case, and a stream's seed. An old
//! row gets what a new write of it gets today (Engine ruling D = (a)): its
//! writer's own door admits it again at its own key, each secret a rule
//! places goes to custody and leaves its handle, and the row keeps its ids,
//! links and times. Nothing is applied again, appended or notified. A hit the
//! door does not place, and a row no door reads, files a proposal.

use heed::RwTxn;

use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;

/// The writer door that admits a carrier's rows again.
#[derive(Clone, Copy)]
pub enum Door {
    /// `Vault::lift_policy_change_row_in_txn`, by whole key.
    PolicyRow,
    /// `Vault::lift_eval_case_in_txn`, by case id.
    EvalCase,
    /// `Vault::lift_stream_seed_in_txn`, by message id.
    StreamSeed,
}
