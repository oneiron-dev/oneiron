//! A Dreamer pass's read phase and its short write (FIX 11568). Scans and
//! history reads run in a read snapshot, so they hold no LMDB writer; the
//! writer opens after them for the writes they decided, and only when no
//! commit landed in between.

use crate::Vault;
use crate::error::{Error, Result};

use super::deadline::WakeCancellation;

/// How many read phases a pass makes before it reads in its writer.
const READ_PHASE_TRIES: usize = 2;

/// What stops a read phase before its write: the host's pause or a stop
/// raised on the pass's cancellation. A read phase holds no writer, so the
/// pass deadline does not stop it.
#[derive(Clone, Copy, Default)]
pub(crate) struct WakeStop<'a> {
    cancel: Option<&'a WakeCancellation>,
}

impl<'a> WakeStop<'a> {
    /// A read phase nothing stops.
    pub(crate) const NEVER: Self = Self { cancel: None };

    pub(crate) const fn new(cancel: Option<&'a WakeCancellation>) -> Self {
        Self { cancel }
    }

    /// Whether the pass was cancelled or paused.
    pub(crate) fn stopped(&self) -> bool {
        self.cancel.is_some_and(WakeCancellation::is_cancelled)
    }
}

/// Why a short write wrote nothing.
enum WriteError {
    /// A commit landed after the read phase pinned the generation.
    Stale,
    Failed(Error),
}

impl From<Error> for WriteError {
    fn from(error: Error) -> Self {
        Self::Failed(error)
    }
}

/// Runs `read` in a read snapshot, then `write` with what it read in a
/// short writer. The read phase pins the vault's commit generation (LMDB's
/// last committed txn id, which every commit moves) before its snapshot
/// opens, and the writer checks it before any write: when it still matches,
/// no commit landed in between and the writer starts from exactly the state
/// `read` saw. When it moved, the writer writes nothing and the pair runs
/// again; after [`READ_PHASE_TRIES`] tries both run in one writer, as before
/// the split, so the work is never lost. `None`: `read` stopped, and
/// nothing was written.
pub(crate) fn read_then_write<R, T>(
    vault: &Vault,
    read: impl Fn(&heed::RoTxn<'_>) -> Result<Option<R>>,
    write: impl Fn(&mut heed::RwTxn<'_>, R) -> Result<T>,
) -> Result<Option<T>> {
    for _ in 0..READ_PHASE_TRIES {
        let generation = vault.store.env.info().last_txn_id;
        let Some(reads) = read(&vault.store.env.read_txn()?)? else {
            return Ok(None);
        };
        let written = vault.try_with_write_txn(|txn| {
            if vault.store.env.info().last_txn_id != generation {
                return Err(WriteError::Stale);
            }
            Ok(write(txn, reads)?)
        });
        match written {
            Ok(value) => return Ok(Some(value)),
            Err(WriteError::Stale) => {}
            Err(WriteError::Failed(error)) => return Err(error),
        }
    }
    vault.with_write_txn(|txn| match read(txn)? {
        Some(reads) => write(txn, reads).map(Some),
        None => Ok(None),
    })
}
