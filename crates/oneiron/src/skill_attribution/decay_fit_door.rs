//! The `credit_decay` fit's door for the integration tests (FIX-LIST
//! CREDIT-DECAY-FIT-DROPS-OWNER-AND-WORLD-ANCHORS). Compiled only under
//! `--cfg oneiron_test_support`; [`crate::test_doors::credit_decay_fit`]
//! opens it.

use super::contribution::ContributionCheckRecord;
use super::late_credit::{CREDIT_RECEIPT, LateCreditReceipt, receipt_id};
use crate::{Result, Vault};

/// Seals `credit` under its outcome's key, as the outcome's projection
/// does, then records `record`, a matched check on a used edge of its run,
/// into the `credit_decay` fit as the contribution admission does once the
/// run's kept forks prove the pair. One write.
///
/// # Errors
///
/// Storage errors. The fit itself is capture-only: a refused observation is
/// dropped with a WARN, and the write goes on.
pub(crate) fn credit_and_record_ancestor_check(
    vault: &Vault,
    credit: &LateCreditReceipt,
    record: &ContributionCheckRecord,
    now: u64,
) -> Result<()> {
    vault.with_write_txn_grouped(|txn| {
        let key = receipt_id(
            &credit.attempt_receipt,
            &credit.outcome_receipt,
            &credit.axis,
        );
        let mut sealed = credit.clone();
        sealed.receipt_id.clone_from(&key);
        CREDIT_RECEIPT.put(&vault.store, txn, &key, &sealed)?;
        super::decay_fit::record_ancestor_decay_check_in_txn(vault, txn, record, now);
        Ok(())
    })
}
