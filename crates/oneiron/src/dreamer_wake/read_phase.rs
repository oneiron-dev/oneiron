//! A Dreamer pass's read phase and its short write (FIX 11568). Scans and
//! history reads run in a read snapshot, so they hold no LMDB writer; the
//! writer opens after them for the writes they decided, and only when no
//! commit landed in between.

use std::time::{Duration, Instant, SystemTime};

use crate::Vault;
use crate::error::{Error, Result};

use super::deadline::WakeCancellation;

/// How many guarded tries a pass makes before it defers.
const READ_PHASE_TRIES: u32 = 3;

/// The shortest pause between two guarded tries; a jitter of up to
/// [`READ_PHASE_BACKOFF_JITTER_MS`] more keeps two passes apart.
const READ_PHASE_BACKOFF_MS: u64 = 50;
const READ_PHASE_BACKOFF_JITTER_MS: u32 = 150;

/// How long a trigger waits deferred before its pass reads in its writer.
pub(crate) const READ_PHASE_STARVATION_SECS: u64 = 60;

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

/// What a pass does when a commit landed between its read and its write on
/// every guarded try.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum OnStale {
    /// Write nothing; the caller wakes again later.
    Defer,
    /// Read and write in one writer, as before the split: the starvation
    /// stop for a trigger deferred [`READ_PHASE_STARVATION_SECS`] or more.
    OneWriter,
}

/// How a read phase and its write ended.
#[derive(Debug)]
pub(crate) enum ReadWrite<T> {
    /// The write landed.
    Written(T),
    /// The read phase stopped on a pause or a stop; nothing was written.
    Stopped,
    /// A commit landed between the read and the write on every guarded
    /// try; nothing was written.
    Deferred,
}

/// Why a guarded write wrote nothing.
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
/// again after a short jittered pause. After [`READ_PHASE_TRIES`] stale
/// tries the pass defers, or with [`OnStale::OneWriter`] reads and writes
/// in one writer, as before the split. `pass` names the pass in the log
/// line each run leaves: its read time and its stale tries.
pub(crate) fn read_then_write<R, T>(
    vault: &Vault,
    pass: &'static str,
    on_stale: OnStale,
    read: impl Fn(&heed::RoTxn<'_>) -> Result<Option<R>>,
    write: impl Fn(&mut heed::RwTxn<'_>, R) -> Result<T>,
) -> Result<ReadWrite<T>> {
    let mut read_time = Duration::ZERO;
    let mut stale = 0;
    let outcome = loop {
        if stale == READ_PHASE_TRIES {
            if on_stale == OnStale::Defer {
                break ReadWrite::Deferred;
            }
            tracing::warn!(
                pass,
                stale,
                "a Dreamer pass read in its writer after stale reads"
            );
            break vault.with_write_txn(|txn| match read(txn)? {
                Some(reads) => write(txn, reads).map(ReadWrite::Written),
                None => Ok(ReadWrite::Stopped),
            })?;
        }
        if stale > 0 {
            std::thread::sleep(backoff());
        }
        let generation = vault.store.env.info().last_txn_id;
        let started = Instant::now();
        let reads = read(&vault.store.env.read_txn()?)?;
        read_time += started.elapsed();
        let Some(reads) = reads else {
            break ReadWrite::Stopped;
        };
        let written = vault.try_with_write_txn(|txn| {
            if vault.store.env.info().last_txn_id != generation {
                return Err(WriteError::Stale);
            }
            Ok(write(txn, reads)?)
        });
        match written {
            Ok(value) => break ReadWrite::Written(value),
            Err(WriteError::Stale) => stale += 1,
            Err(WriteError::Failed(error)) => return Err(error),
        }
    };
    tracing::info!(
        pass,
        read_ms = u64::try_from(read_time.as_millis()).unwrap_or(u64::MAX),
        stale,
        outcome = outcome.label(),
        "Dreamer read phase"
    );
    Ok(outcome)
}

impl<T> ReadWrite<T> {
    const fn label(&self) -> &'static str {
        match self {
            Self::Written(_) => "written",
            Self::Stopped => "stopped",
            Self::Deferred => "deferred",
        }
    }
}

/// The pause before a guarded try runs again.
fn backoff() -> Duration {
    let nanos = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |since| since.subsec_nanos());
    Duration::from_millis(
        READ_PHASE_BACKOFF_MS + u64::from(nanos % (READ_PHASE_BACKOFF_JITTER_MS + 1)),
    )
}
