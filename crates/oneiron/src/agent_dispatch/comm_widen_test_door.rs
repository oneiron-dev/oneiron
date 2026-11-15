//! Door for `tests/vault_tasks_doors.rs` (compiled only under
//! `--cfg oneiron_test_support`): stores the approval an owner's settled
//! answer to one run's comm-widen ask leaves on that run's row, as
//! [`super::comm_widen::CommWidenRecord::settle`] leaves it, so the owner's
//! `vault.tasks.comm_widen.revoke` has a recorded choice to end. No public
//! door writes one: only a host-bound run's refused send raises the ask.

use crate::Vault;
use crate::attempt_queue::AttemptId;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::genui::ConsentConfirmOutcome;

use super::comm::CommReach;
use super::comm_widen::{
    CommApproval, CommWidenDecision, CommWidenRecipient, CommWidenRecord, put_comm_widen_in,
};

/// Stores, on the run `attempt`'s row, the owner `owner`'s approval of
/// `reach` answered with `choice` at `at`, and answers the id of the ask
/// that answer settled.
///
/// # Errors
///
/// Storage errors.
pub fn record_owner_comm_choice(
    vault: &Vault,
    attempt: AttemptId,
    owner: EntityId,
    reach: CommReach,
    choice: ConsentConfirmOutcome,
    at: u64,
) -> Result<EntityId> {
    let ask = EntityId::now();
    let record = CommWidenRecord {
        approved: Some(CommApproval {
            reach,
            decision: CommWidenDecision {
                by: CommWidenRecipient::Owner(owner),
                at,
                ask,
                choice,
            },
            standing_revoked_at: None,
        }),
        requests: Vec::new(),
    };
    vault.with_write_txn(|txn| put_comm_widen_in(vault, txn, attempt, &record))?;
    Ok(ask)
}
