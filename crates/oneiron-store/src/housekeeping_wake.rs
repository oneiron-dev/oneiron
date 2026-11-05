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

use crate::housekeeping_schedule::HousekeepingSweep;
use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;

pub type WakeKey = ([u8; 1], u64, EntityId);

/// Rows one covering run removes at most; the rest go with the next run.
pub const CLEAR_LIMIT: usize = 4096;

/// The sweeps whose deadlines are noted. The erasure sweep needs no rows: an
/// obligation waiting is the first `h:` row.
pub const WAKE_SWEEPS: [HousekeepingSweep; 4] = [
    HousekeepingSweep::SecretLeaseExpiry,
    HousekeepingSweep::CriticalConfirmExpiry,
    HousekeepingSweep::VoicePrintRetention,
    HousekeepingSweep::SharedActMaturity,
];

pub fn tag(sweep: HousekeepingSweep) -> Option<[u8; 1]> {
    match sweep {
        HousekeepingSweep::SecretLeaseExpiry => Some([1]),
        HousekeepingSweep::CriticalConfirmExpiry => Some([2]),
        HousekeepingSweep::VoicePrintRetention => Some([3]),
        HousekeepingSweep::SharedActMaturity => Some([4]),
        _ => None,
    }
}
