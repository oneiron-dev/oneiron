//! Door for `oneiron-server/tests/own_rate_health_ask.rs`: an own actor's
//! acts counted on an advisory rate window through the production counter
//! (`own_rate::count_in_txn`), each act in its own write, as the doors that
//! count them do.

use crate::own_rate::{OwnRate, OwnRateKind};
use crate::{EntityId, Result, Vault};

/// Counts `acts` acts of `kind` by `actor` at the vault's clock on a window
/// of `window_seconds` with an advisory `threshold`. Returns the window's
/// count after the last act.
///
/// # Errors
///
/// Storage errors.
pub fn count_own_acts(
    vault: &Vault,
    kind: OwnRateKind,
    actor: EntityId,
    acts: u64,
    threshold: u64,
    window_seconds: u64,
) -> Result<u64> {
    let rate = OwnRate {
        threshold,
        window_seconds,
    };
    let mut count = 0;
    for _ in 0..acts {
        let now = vault.now_recorded_at();
        count = vault.with_write_txn_grouped(|txn| {
            crate::own_rate::count_in_txn(&vault.store, txn, kind, actor, now, rate)
        })?;
    }
    Ok(count)
}
