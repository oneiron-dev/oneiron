//! Bounded, expirable base-ledger retrieval runs and crash-orphan reconciliation.

use heed::RwTxn;

use crate::error::{Error, Result, SideTableRowProblem, StoreError};
use crate::side_table::{self, CodecError, Raw, RawValue, SideTable};
use crate::store::{ManifestDbs, Store};

use super::RetrievalRunId;
#[cfg(target_os = "linux")]
use super::run_store::RETRIEVAL_RUN_PROVISIONAL;
use super::run_store::stage_retrieval_run_delete;

// Base-ledger retention only. Session overlay rows evaporate on close and
// cannot be evicted while an in-flight room assembly still owns them.
/// A published run's capture time, ordered for expiry and cap pruning; empty
/// value. Production run ids come from the store-local monotonic id source,
/// so the id breaks ties between captures in the same clock second. Key:
/// u64be (captured at) + run id.
const RETRIEVAL_AGE: SideTable<(u64, RetrievalRunId), (), Raw> =
    SideTable::new(&side_table::RETRIEVAL_AGE);
/// A run's capture time, locating its [`RETRIEVAL_AGE`] row. Key: run id.
const RETRIEVAL_AGE_BY_RUN: SideTable<RetrievalRunId, CapturedAt, Raw> =
    SideTable::new(&side_table::RETRIEVAL_AGE_BY_RUN);

/// [`RETRIEVAL_AGE_BY_RUN`]'s value: the capture time, u64 big-endian.
struct CapturedAt(u64);

impl RawValue for CapturedAt {
    fn to_raw(&self) -> std::result::Result<Vec<u8>, CodecError> {
        Ok(self.0.to_be_bytes().to_vec())
    }

    fn from_raw(bytes: &[u8]) -> std::result::Result<Self, CodecError> {
        let bytes = bytes
            .try_into()
            .map_err(|_| Error::CorruptedIndex("retrieval run retention"))?;
        Ok(Self(u64::from_be_bytes(bytes)))
    }
}

/// A key that does not spell its table's shape stays a corrupt-index error.
fn corrupt_key(context: &'static str) -> impl FnOnce(Error) -> Error {
    move |error| match error {
        Error::Store(StoreError::SideTableRow {
            problem: SideTableRowProblem::KeyShape,
            ..
        }) => Error::CorruptedIndex(context),
        other => other,
    }
}

/// On Linux every live Store holds a shared lock for its lifetime. The sole opener may
/// take an exclusive lock, sweep crashed provisional rows, then downgrade.
/// A second process with an active run keeps its shared lock, so an opener
/// cannot mistake that run for an orphan. The file is one stable inode per
/// vault, not one file per retrieval.
#[cfg(target_os = "linux")]
pub(super) const RETRIEVAL_TELEMETRY_LOCK_FILE: &str = "oneiron.retrieval-telemetry.lock";

#[cfg(target_os = "linux")]
pub(in crate::store) struct RetrievalTelemetryLease {
    file: std::fs::File,
    pid: u32,
}

#[cfg(target_os = "linux")]
impl RetrievalTelemetryLease {
    fn acquire(dir: &std::fs::File) -> Result<(Self, bool)> {
        use std::os::fd::AsRawFd;
        let lock_name = std::ffi::CString::new(RETRIEVAL_TELEMETRY_LOCK_FILE)
            .expect("static lock filename contains no NUL");
        // SAFETY: dir is a live directory fd; lock_name is NUL-terminated,
        // and openat returns a new fd adopted exactly once below. O_NOFOLLOW
        // refuses a hostile link at the lock filename.
        let fd = unsafe {
            libc::openat(
                dir.as_raw_fd(),
                lock_name.as_ptr(),
                libc::O_RDWR | libc::O_CREAT | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o600,
            )
        };
        let file = crate::store::root_directory::adopt_descriptor(fd)?;
        // SAFETY: the descriptor remains owned by `file` for the whole call.
        let exclusive = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        if exclusive == 0 {
            return Ok((
                Self {
                    file,
                    pid: std::process::id(),
                },
                true,
            ));
        }
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::EWOULDBLOCK) {
            return Err(error.into());
        }
        // Another live Store holds SH. Join it without sweeping. An EX sweep
        // in progress refuses this opener rather than blocking on an unknown
        // amount of legacy data.
        // SAFETY: the same live file descriptor is still owned by `file`.
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_SH | libc::LOCK_NB) } != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        Ok((
            Self {
                file,
                pid: std::process::id(),
            },
            false,
        ))
    }

    fn downgrade(&self) -> Result<()> {
        use std::os::fd::AsRawFd;
        // SAFETY: `file` remains open through the returned Store lifetime.
        if unsafe { libc::flock(self.file.as_raw_fd(), libc::LOCK_SH) } != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        Ok(())
    }
}

#[cfg(target_os = "linux")]
impl Drop for RetrievalTelemetryLease {
    fn drop(&mut self) {
        if self.pid == std::process::id() {
            use std::os::fd::AsRawFd;
            // SAFETY: this process owns the live descriptor. Explicit unlock
            // prevents a forked child inheriting it from extending our hold.
            unsafe { libc::flock(self.file.as_raw_fd(), libc::LOCK_UN) };
        }
    }
}

/// Recover interrupted context-pack registrations and expire indexed runs.
/// Runs after the open gates, before handing the vault to a caller.
impl Store {
    pub(in crate::store) fn reconcile_retrieval_telemetry_on_open(&self) -> Result<()> {
        #[cfg(target_os = "linux")]
        {
            let (lease, sole_opener) =
                RetrievalTelemetryLease::acquire(self.owner.env.bound_root_dir()?)?;
            // Published age/cap entries are safe to prune under LMDB's
            // writer lock even if another process owns a shared lease.
            let mut wtxn = self.env.write_txn()?;
            if sole_opener {
                let orphans = RETRIEVAL_RUN_PROVISIONAL
                    .scan_keys(self, &wtxn, &[])
                    .map_err(corrupt_key("retrieval run telemetry"))?;
                for id in orphans {
                    stage_retrieval_run_delete(self, &mut wtxn, id)?;
                }
            }
            let _ = prune_retrieval_runs(self, &mut wtxn, 0)?;
            wtxn.commit()?;
            if sole_opener {
                lease.downgrade()?;
            }
            let mut guard = self.core.retrieval_telemetry_lease.lock().map_err(|_| {
                Error::InvariantViolation("retrieval telemetry lease lock poisoned")
            })?;
            *guard = Some(lease);
            Ok(())
        }
        #[cfg(not(target_os = "linux"))]
        {
            // A pathname-opened LMDB cannot use the retained directory as
            // proof of orphanhood. Published rows have their own age index,
            // however, and can be pruned under LMDB's writer transaction.
            let mut wtxn = self.env.write_txn()?;
            let _ = prune_retrieval_runs(self, &mut wtxn, 0)?;
            wtxn.commit()?;
            Ok(())
        }
    }
}

pub(super) fn delete_retrieval_age(
    target: &impl ManifestDbs,
    txn: &mut RwTxn<'_>,
    id: RetrievalRunId,
) -> Result<()> {
    if let Some(CapturedAt(at)) = RETRIEVAL_AGE_BY_RUN.get(target, &*txn, &id)? {
        RETRIEVAL_AGE.delete(target, txn, &(at, id))?;
        RETRIEVAL_AGE_BY_RUN.delete(target, txn, &id)?;
    }
    Ok(())
}

pub(super) fn put_retrieval_age(
    target: &impl ManifestDbs,
    txn: &mut RwTxn<'_>,
    id: RetrievalRunId,
    at: u64,
) -> Result<()> {
    delete_retrieval_age(target, txn, id)?;
    RETRIEVAL_AGE.put(target, txn, &(at, id), &())?;
    RETRIEVAL_AGE_BY_RUN.put(target, txn, &id, &CapturedAt(at))?;
    Ok(())
}

pub(super) fn prune_retrieval_runs(
    store: &Store,
    txn: &mut RwTxn<'_>,
    reserve: usize,
) -> Result<bool> {
    let resolved = crate::gate::resolve_policy_manifest(store, txn)?;
    let Some(policy) = resolved.retrieval_retention_policy() else {
        // Opening a degraded vault stays possible, but no rejected policy
        // is permission to erase published runs.
        return Ok(false);
    };
    let (max_age_secs, max_runs) = policy.effective();
    let now = store.clock.now_recorded_at();
    let cutoff = now.saturating_sub(max_age_secs);
    // Collect keys before any delete; heed forbids mutating under an active cursor.
    let age_rows = RETRIEVAL_AGE
        .scan_keys(store, txn, &[])
        .map_err(corrupt_key("retrieval run retention"))?;
    let over = age_rows
        .len()
        .saturating_sub(max_runs.saturating_sub(reserve));
    for (index, (at, id)) in age_rows.into_iter().enumerate() {
        if index >= over && at >= cutoff {
            break;
        }
        stage_retrieval_run_delete(store, txn, id)?;
    }
    Ok(true)
}

/// Publication and finalization must refuse when the manifest is rejected;
/// unlike a healthy open they cannot use an invalid policy to admit a row.
pub(super) fn require_prune_retrieval_runs(
    store: &Store,
    txn: &mut RwTxn<'_>,
    reserve: usize,
) -> Result<()> {
    if prune_retrieval_runs(store, txn, reserve)? {
        Ok(())
    } else {
        Err(Error::InvalidConfig(
            "retrieval retention policy unavailable".to_owned(),
        ))
    }
}
