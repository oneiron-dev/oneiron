//! Wake deadlines: when a vault that is not running must next run a pass.
//!
//! A door that starts a retirement deadline notes it here in its own write
//! transaction: a secret lease's expiry, a voice print's retention deadline, a
//! critical confirm's window. Rows are keyed by sweep and deadline, so a
//! sweep's earliest deadline is the first row under its tag, read without a
//! scan. A run that succeeds removes the rows that were due when it started;
//! rows noted while it ran stay for the next run. A deadline that moved or was
//! settled early leaves a row that costs one wake that finds nothing.

use heed::{RoTxn, RwTxn};

use super::HousekeepingSweep;
use crate::Vault;
use crate::error::Result;
use crate::side_table::{self, Raw, SideTable};
use crate::store::Store;

const WAKE: SideTable<([u8; 1], u64), (), Raw> = SideTable::new(&side_table::HOUSEKEEPING_WAKE);

/// Rows one successful run removes at most; the rest go with the next run.
const CLEAR_LIMIT: usize = 4096;

/// The sweeps whose deadlines wake a vault, with their tags. The erasure
/// sweep needs no rows: an obligation waiting is the first `h:` row.
pub(super) const WAKE_SWEEPS: [HousekeepingSweep; 3] = [
    HousekeepingSweep::SecretLeaseExpiry,
    HousekeepingSweep::CriticalConfirmExpiry,
    HousekeepingSweep::VoicePrintRetention,
];

fn tag(sweep: HousekeepingSweep) -> Option<[u8; 1]> {
    match sweep {
        HousekeepingSweep::SecretLeaseExpiry => Some([1]),
        HousekeepingSweep::CriticalConfirmExpiry => Some([2]),
        HousekeepingSweep::VoicePrintRetention => Some([3]),
        _ => None,
    }
}

/// Notes that `sweep` has work due at `at`, in the caller's transaction, so
/// the note commits with the deadline it records. A sweep that wakes no vault
/// notes nothing.
pub(crate) fn note_wake_in_txn(
    store: &Store,
    txn: &mut RwTxn<'_>,
    sweep: HousekeepingSweep,
    at: u64,
) -> Result<()> {
    match tag(sweep) {
        Some(tag) => WAKE.put(store, txn, &(tag, at), &()),
        None => Ok(()),
    }
}

/// The earliest deadline noted for `sweep`.
pub(super) fn earliest_in_txn(
    store: &Store,
    txn: &RoTxn<'_>,
    sweep: HousekeepingSweep,
) -> Result<Option<u64>> {
    let Some(tag) = tag(sweep) else {
        return Ok(None);
    };
    let mut rows = WAKE.iter_from(store, txn, &tag)?;
    Ok(rows.next().transpose()?.map(|((_, at), ())| at))
}

/// The rows of `sweep` due by `now`: what a run starting now covers.
pub(super) fn due_by(vault: &Vault, sweep: HousekeepingSweep, now: u64) -> Result<Vec<u64>> {
    let Some(tag) = tag(sweep) else {
        return Ok(Vec::new());
    };
    let txn = vault.store.env.read_txn()?;
    let mut due = Vec::new();
    for row in WAKE.iter_from(&vault.store, &txn, &tag)? {
        let ((_, at), ()) = row?;
        if at > now || due.len() == CLEAR_LIMIT {
            break;
        }
        due.push(at);
    }
    Ok(due)
}

/// Removes the rows a successful run covered.
pub(super) fn clear(vault: &Vault, sweep: HousekeepingSweep, covered: &[u64]) -> Result<()> {
    let Some(tag) = tag(sweep) else {
        return Ok(());
    };
    if covered.is_empty() {
        return Ok(());
    }
    let mut txn = vault.store.env.write_txn()?;
    for &at in covered {
        WAKE.delete(&vault.store, &mut txn, &(tag, at))?;
    }
    txn.commit()?;
    Ok(())
}
