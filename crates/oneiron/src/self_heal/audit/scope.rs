//! The scope a seal's audit rate is read at (FIX 2957, OF-542): the project
//! its attempt ran in, frozen at seal time, and its confession's task type.

use crate::attempt_queue::AttemptRecord;
use crate::learning_setting::{AUDIT_RATE, setting_value_in_scope_in_txn};
use crate::{EntityId, Result, Vault};

use super::{SealedAttemptReceipt, invalid};

/// The project `attempt`'s stored dispatch names. `None` for an attempt that
/// is no agent dispatch or names no project: unknown, never read off its
/// actor or session.
pub(super) fn attempt_project(attempt: &AttemptRecord) -> Option<EntityId> {
    crate::agent_dispatch::record_dispatch_input(attempt).and_then(|input| input.project_ref)
}

/// The `audit_rate` in force for `receipt`, where its project and type apply.
pub(super) fn audit_rate_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    receipt: &SealedAttemptReceipt,
) -> Result<f64> {
    let rate = setting_value_in_scope_in_txn(
        vault,
        txn,
        &AUDIT_RATE,
        receipt.project,
        Some(&receipt.confession.type_ref),
    )?;
    if !rate.is_finite() || !(AUDIT_RATE.min..=AUDIT_RATE.max).contains(&rate) {
        return Err(invalid(
            "the seal audit rate is bounded and strictly positive",
        ));
    }
    Ok(rate)
}
