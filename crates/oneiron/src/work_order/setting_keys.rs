//! The work orders' Setting keys (pass 34, 4.7 and 6.3; the lead's POLICY AS SETTINGS, 25 Nov
//! 00:04): how many times each class of attempt end is retried, and the wait first, whose
//! default is pass 34's table 4.7 as a value, not as code; and each named running cap (row Q5),
//! whose default is no cap.

use crate::Vault;
use crate::error::Result;
use crate::setting::{AbsentEnd, ItemDomain, Kind};

use super::after::RetryPolicy;
use super::caps::is_cap_name;

/// Pass 34's table 4.7.
fn table_4_7() -> RetryPolicy {
    RetryPolicy::default()
}

/// The default bound on the warm keys one order lists.
pub(crate) const ORDER_WARM_KEYS_MAX_DEFAULT: u32 = 16;

fn order_warm_keys_max() -> u32 {
    ORDER_WARM_KEYS_MAX_DEFAULT
}

crate::setting::setting_keys! {
    /// How the AFTER rule typed_retry@1 retries a work order's attempt, per class of end: a
    /// zero-second end that never started (3 retries, 30 s then doubling), an expired start
    /// window (1 retry), a lost machine (no retry: the lead or the owner decides), and a failure
    /// the order's own retry_on lists (1 retry). A success is done, a cancel or a revoke gives
    /// up, a write-off never starts anything again, and any other failure is not retried.
    pub(crate) JOBS_RETRY: RetryPolicy = "jobs.retry" {
        kind: Kind::new(table_4_7),
    };
    /// The most warm keys one work order lists (pass 34, 4.1; row P2), the keys of what its
    /// work reads that placement prefers a machine for and a node keeps in its cache. Default
    /// 16; an attempt carries at most 32 whatever this says. Fewer is tighter.
    pub(crate) ORDER_WARM_KEYS_MAX: u32 = "jobs.orders.warm_keys_max" {
        kind: Kind::new(order_warm_keys_max).lower(),
    };
    /// A named running cap (item: the cap's name, as orders list it in limits.caps): the most
    /// orders that name it and hold a live attempt at once, a seat count, a family's share or a
    /// tool's slots. None is no cap. A lower cap is the tighter; no cap is the loosest.
    pub(crate) JOBS_CAPS: Option<u32> = "jobs.caps" {
        kind: Kind::new(no_cap).lower_or_absent(AbsentEnd::Loosest),
        item: Some(ItemDomain { name: "running cap names", admits: is_cap_name }),
    };
}

/// A cap's default: none.
const fn no_cap() -> Option<u32> {
    None
}

/// The cap named `name` in force, read in `txn` at the vault scope; `None` is no cap.
///
/// # Errors
///
/// Storage errors.
pub(super) fn running_cap_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    name: &str,
) -> Result<Option<u32>> {
    Ok(JOBS_CAPS.read_in_txn(vault, txn, &[], Some(name))?.value)
}

/// The retry policy in force, read in `txn` at the vault scope.
///
/// # Errors
///
/// Storage errors.
pub(super) fn retry_policy_in_txn(vault: &Vault, txn: &heed::RoTxn<'_>) -> Result<RetryPolicy> {
    Ok(JOBS_RETRY.read_in_txn(vault, txn, &[], None)?.value)
}

/// The most warm keys one order may list now, read in `txn` at the vault scope, within the
/// attempt's own bound.
///
/// # Errors
///
/// Storage errors.
pub(super) fn order_warm_keys_max_in_txn(vault: &Vault, txn: &heed::RoTxn<'_>) -> Result<usize> {
    let max = ORDER_WARM_KEYS_MAX
        .read_in_txn(vault, txn, &[], None)?
        .value;
    Ok(usize::try_from(max)
        .unwrap_or(usize::MAX)
        .min(crate::warm_key::ATTEMPT_WARM_KEYS_MAX))
}
