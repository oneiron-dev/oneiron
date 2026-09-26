//! Bounded, expirable base-ledger retrieval runs and crash-orphan reconciliation.

use heed::RwTxn;

use crate::error::{Error, Result};
use crate::store::{ManifestDbs, Store};

use super::RetrievalRunId;
#[cfg(unix)]
use super::run_store::{
    RETRIEVAL_RUN_KEY_PREFIX, RETRIEVAL_RUN_PROVISIONAL_KEY_PREFIX, decode_retrieval_run,
    retrieval_run_id_from_key, retrieval_run_id_from_value, stage_retrieval_run_delete,
};

// Base-ledger retention only. Session overlay rows evaporate on close and
// cannot be evicted while an in-flight room assembly still owns them.
const RETRIEVAL_AGE_KEY_PREFIX: &[u8] = b"retr_age:v0:";
const RETRIEVAL_AGE_BY_RUN_KEY_PREFIX: &[u8] = b"retr_age_run:v0:";
pub(super) const RETRIEVAL_RUN_TTL_SECONDS: u64 = 7 * 24 * 60 * 60;
#[cfg(not(test))]
pub(super) const RETRIEVAL_RUN_MAX_ROWS: usize = 1024;
#[cfg(test)]
pub(super) const RETRIEVAL_RUN_MAX_ROWS: usize = 128;

/// Every live Store holds a shared lock for its lifetime. The sole opener may
/// take an exclusive lock, sweep crashed provisional rows, then downgrade.
/// A second process with an active run keeps its shared lock, so an opener
/// cannot mistake that run for an orphan. The file is one stable inode per
/// vault, not one file per retrieval.
#[cfg(unix)]
pub(super) const RETRIEVAL_TELEMETRY_LOCK_FILE: &str = "oneiron.retrieval-telemetry.lock";

#[cfg(unix)]
pub(in crate::store) struct RetrievalTelemetryLease {
    file: std::fs::File,
    pid: u32,
}

#[cfg(unix)]
impl RetrievalTelemetryLease {
    fn acquire(root: &std::path::Path) -> Result<(Self, bool)> {
        use std::os::fd::AsRawFd;
        let dir = crate::store::root_directory::open_root_directory(root)?;
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

#[cfg(unix)]
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

/// Recover an interrupted context-pack registration and reconcile pre-retention
/// published rows. Runs after the open gates, before handing the vault to a caller.
impl Store {
    pub(in crate::store) fn reconcile_retrieval_telemetry_on_open(&self) -> Result<()> {
        #[cfg(unix)]
        {
            let (lease, sole_opener) =
                RetrievalTelemetryLease::acquire(&self.owner._registered_path.path)?;
            if sole_opener {
                let mut wtxn = self.env.write_txn()?;
                let mut orphans = Vec::new();
                for row in self
                    .vault_meta
                    .prefix_iter(&wtxn, RETRIEVAL_RUN_PROVISIONAL_KEY_PREFIX)?
                {
                    let (key, _) = row?;
                    let id = retrieval_run_id_from_value(
                        &key[RETRIEVAL_RUN_PROVISIONAL_KEY_PREFIX.len()..],
                    )?;
                    orphans.push(id);
                }
                for id in orphans {
                    stage_retrieval_run_delete(self, &mut wtxn, id)?;
                }
                let mut unindexed = Vec::new();
                for row in self
                    .vault_meta
                    .prefix_iter(&wtxn, RETRIEVAL_RUN_KEY_PREFIX)?
                {
                    let (key, value) = row?;
                    let id = retrieval_run_id_from_key(&key)?;
                    if self.vault_meta.get(&wtxn, &age_by_run_key(id))?.is_none() {
                        let record = decode_retrieval_run(&value)?;
                        if record.run_id != id {
                            return Err(Error::CorruptedIndex("retrieval run telemetry"));
                        }
                        unindexed.push((id, record.started_at));
                    }
                }
                // Delete old/excess legacy rows BEFORE allocating any new sidecars.
                // A full old ledger must be able to reopen without doubling its map
                // footprint just to discover which rows retention will discard.
                unindexed.sort_unstable_by_key(|(id, at)| (*at, id.as_bytes()));
                let cutoff = self
                    .clock
                    .now_recorded_at()
                    .saturating_sub(RETRIEVAL_RUN_TTL_SECONDS);
                let excess = unindexed.len().saturating_sub(RETRIEVAL_RUN_MAX_ROWS);
                let mut survivors = Vec::new();
                for (index, (id, at)) in unindexed.into_iter().enumerate() {
                    if index < excess || at < cutoff {
                        stage_retrieval_run_delete(self, &mut wtxn, id)?;
                    } else {
                        survivors.push((id, at));
                    }
                }
                prune_retrieval_runs(self, &mut wtxn, survivors.len())?;
                for (id, started_at) in survivors {
                    put_retrieval_age(self, &mut wtxn, id, started_at)?;
                }
                wtxn.commit()?;
                lease.downgrade()?;
            }
            let mut guard = self.core.retrieval_telemetry_lease.lock().map_err(|_| {
                Error::InvariantViolation("retrieval telemetry lease lock poisoned")
            })?;
            *guard = Some(lease);
            Ok(())
        }
        #[cfg(not(unix))]
        {
            // No cross-process ownership proof: do not delete provisional rows.
            Ok(())
        }
    }
}

fn age_by_run_key(id: RetrievalRunId) -> Vec<u8> {
    [RETRIEVAL_AGE_BY_RUN_KEY_PREFIX, &id.as_bytes()].concat()
}

// Production run ids come from the store-local monotonic id source, so the
// id breaks ties between captures in the same clock second.
fn age_key(at: u64, id: RetrievalRunId) -> Vec<u8> {
    [RETRIEVAL_AGE_KEY_PREFIX, &at.to_be_bytes(), &id.as_bytes()].concat()
}

pub(super) fn delete_retrieval_age(
    target: &impl ManifestDbs,
    txn: &mut RwTxn<'_>,
    id: RetrievalRunId,
) -> Result<()> {
    let by_run = age_by_run_key(id);
    if let Some(raw) = target.vault_meta().get(txn, &by_run)? {
        let at = u64::from_be_bytes(
            raw.as_ref()
                .try_into()
                .map_err(|_| Error::CorruptedIndex("retrieval run retention"))?,
        );
        target.vault_meta().delete(txn, &age_key(at, id))?;
        target.vault_meta().delete(txn, &by_run)?;
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
    target.vault_meta().put(txn, &age_key(at, id), b"")?;
    target
        .vault_meta()
        .put(txn, &age_by_run_key(id), &at.to_be_bytes())?;
    Ok(())
}

pub(super) fn prune_retrieval_runs(
    store: &Store,
    txn: &mut RwTxn<'_>,
    reserve: usize,
) -> Result<()> {
    let now = store.clock.now_recorded_at();
    let cutoff = now.saturating_sub(RETRIEVAL_RUN_TTL_SECONDS);
    // Collect keys before any delete; heed forbids mutating under an active cursor.
    let mut age_rows = Vec::new();
    for row in store
        .vault_meta
        .prefix_iter(txn, RETRIEVAL_AGE_KEY_PREFIX)?
    {
        let (key, _) = row?;
        let suffix: [u8; 24] = key[RETRIEVAL_AGE_KEY_PREFIX.len()..]
            .try_into()
            .map_err(|_| Error::CorruptedIndex("retrieval run retention"))?;
        let at = u64::from_be_bytes(suffix[..8].try_into().expect("eight bytes"));
        let id = RetrievalRunId::from_bytes(suffix[8..].try_into().expect("sixteen bytes"));
        age_rows.push((at, id));
    }
    let over = age_rows
        .len()
        .saturating_sub(RETRIEVAL_RUN_MAX_ROWS.saturating_sub(reserve));
    for (index, (at, id)) in age_rows.into_iter().enumerate() {
        if index >= over && at >= cutoff {
            break;
        }
        stage_retrieval_run_delete(store, txn, id)?;
    }
    Ok(())
}
