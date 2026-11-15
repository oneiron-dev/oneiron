//! The reviewed outbound send a channel identity's graduation evidence names
//! (ARCH-0063 [INB-04]), for the test of the owner's ramp offer pile
//! (`tests/identity_ramp_offer_pile.rs`).
use crate::receipt::{ReceiptRecord, SendReceiptOutcome};
use crate::{EntityId, Result, Vault};

/// Persists `receipt` as task `task_ref`'s durable failed-send audit row,
/// as the send path leaves a reviewed draft; true when it was written.
///
/// # Errors
///
/// The receipt substrate's.
pub fn persist_reviewed_send(
    vault: &Vault,
    task_ref: EntityId,
    receipt: ReceiptRecord,
) -> Result<bool> {
    crate::receipt::persist_send_receipt(
        vault,
        task_ref,
        receipt,
        SendReceiptOutcome::Failed,
        false,
        None,
    )
}
