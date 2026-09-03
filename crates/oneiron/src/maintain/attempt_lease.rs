//! ONE-1896 §3: the attempt-queue LEASE lane of one maintenance pass.
//!
//! Its own file because it is its own concern — the maintenance builder in
//! [`super`] orchestrates unrelated sweeps and must not grow past the
//! repository's module-size bar to hold two rungs of a cancel protocol.

use crate::Vault;
use crate::attempt_queue::{
    AttemptLeaseWarningReport, AttemptQueue, AttemptQueueCleanupReport, CleanupAttemptLeases,
    WarnExpiringAttemptLeases,
};
use crate::error::Result;

/// Runs the WARNING rung and then the reclaim rung over live attempt leases,
/// against ONE clock and ONE timeout.
///
/// Ordering is the invariant, not a preference: a worker warned only after
/// cleanup already reclaimed its lease has been asked to land work it no
/// longer holds. The warning never terminalizes anything — a row already past
/// expiry is left untouched for the reclaim pass, which is the only hard rung
/// in this lane — so the two counter sets stay disjoint and honest: warned
/// leases are live work that was asked to stop, reclaimed leases are work that
/// was taken away.
pub(super) fn sweep_attempt_leases(
    vault: &Vault,
    now: u64,
    lease_timeout_secs: u64,
) -> Result<(AttemptLeaseWarningReport, AttemptQueueCleanupReport)> {
    let queue = AttemptQueue::new(vault);
    let warnings = queue.warn_expiring_leases(WarnExpiringAttemptLeases {
        now,
        lease_timeout_secs,
    })?;
    let cleanup = queue.cleanup_leases(CleanupAttemptLeases {
        now,
        lease_timeout_secs,
    })?;
    Ok((warnings, cleanup))
}
