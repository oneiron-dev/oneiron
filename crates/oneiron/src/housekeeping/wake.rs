//! Wake deadlines: when a retirement sweep next has work, read without a scan.
//!
//! A door that starts a retirement deadline notes it here in its own write
//! transaction: a secret lease's expiry, a voice print's retention deadline, a
//! critical confirm's window. Rows are keyed by sweep, deadline and a fresh id
//! per note, so a sweep's earliest deadline is the first row under its tag and
//! two notes of the same deadline are two rows. The schedule makes the sweep
//! due at its earliest row, and a vault that is not running wakes for it. A
//! run that covered its rows removes exactly the rows it read before it
//! started; a row noted since stays for the next run. A deadline that moved or
//! was settled early leaves a row that costs one run that finds nothing.

use heed::{RoTxn, RwTxn};

use super::HousekeepingSweep;
use crate::error::Result;
use crate::side_table::{self, Raw, SideTable};
use crate::store::Store;
use crate::{EntityId, Vault};

type WakeKey = ([u8; 1], u64, EntityId);

const WAKE: SideTable<WakeKey, (), Raw> = SideTable::new(&side_table::HOUSEKEEPING_WAKE);

/// Rows one covering run removes at most; the rest go with the next run.
const CLEAR_LIMIT: usize = 4096;

/// The sweeps whose deadlines are noted. The erasure sweep needs no rows: an
/// obligation waiting is the first `h:` row.
pub(super) const WAKE_SWEEPS: [HousekeepingSweep; 4] = [
    HousekeepingSweep::SecretLeaseExpiry,
    HousekeepingSweep::CriticalConfirmExpiry,
    HousekeepingSweep::VoicePrintRetention,
    HousekeepingSweep::SharedActMaturity,
];

fn tag(sweep: HousekeepingSweep) -> Option<[u8; 1]> {
    match sweep {
        HousekeepingSweep::SecretLeaseExpiry => Some([1]),
        HousekeepingSweep::CriticalConfirmExpiry => Some([2]),
        HousekeepingSweep::VoicePrintRetention => Some([3]),
        HousekeepingSweep::SharedActMaturity => Some([4]),
        _ => None,
    }
}

/// Notes that `sweep` has work due at `at`, in the caller's transaction, so
/// the note commits with the deadline it records. A sweep without notes
/// notes nothing.
pub(crate) fn note_wake_in_txn(
    store: &Store,
    txn: &mut RwTxn<'_>,
    sweep: HousekeepingSweep,
    at: u64,
) -> Result<()> {
    match tag(sweep) {
        Some(tag) => WAKE.put(store, txn, &(tag, at, store.clock.entity_id()?), &()),
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
    Ok(rows.next().transpose()?.map(|((_, at, _), ())| at))
}

/// The rows of `sweep` due by `now`, as they stand before a run starting now.
pub(super) fn due_by(vault: &Vault, sweep: HousekeepingSweep, now: u64) -> Result<Vec<WakeKey>> {
    let Some(tag) = tag(sweep) else {
        return Ok(Vec::new());
    };
    let txn = vault.store.env.read_txn()?;
    let mut due = Vec::new();
    for row in WAKE.iter_from(&vault.store, &txn, &tag)? {
        let (key, ()) = row?;
        if key.1 > now || due.len() == CLEAR_LIMIT {
            break;
        }
        due.push(key);
    }
    Ok(due)
}

/// Removes the rows a covering run read before it started.
pub(super) fn clear(vault: &Vault, covered: &[WakeKey]) -> Result<()> {
    if covered.is_empty() {
        return Ok(());
    }
    let mut txn = vault.store.env.write_txn()?;
    for key in covered {
        WAKE.delete(&vault.store, &mut txn, key)?;
    }
    txn.commit()?;
    Ok(())
}
