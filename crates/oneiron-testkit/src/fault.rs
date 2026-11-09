//! Fault injection through doors the engine already has.
//!
//! | Fault | How |
//! |---|---|
//! | Crash (power cut, OOM kill) | [`crash_and_restart`]: SIGKILL the server, start it again on the same port |
//! | Crash at a chosen point | hold the step's model call ([`crate::provider::Step::held`]), wait for it with [`crate::provider::ScriptedProvider::await_reached`], then [`crash_and_restart`] |
//! | Lost lease | [`expire_leases`]: move the fake clock past the lease and run the queue's own lease cleanup |
//! | Dead or failing provider | [`crate::provider::Reply::Status`], [`crate::provider::Reply::CutStream`], [`crate::provider::Reply::Body`] |
//! | Damaged vault on disk | [`truncate`], [`overwrite`], [`remove`] on a closed [`TestVault`] |
//!
//! A crash at a chosen fsync inside the store needs a fault door in the
//! store's commit path (`test_doors`, under `--cfg oneiron_test_support`);
//! none exists yet, and this kit adds no door into the engine. Until one
//! lands, crash tests crash the process at a barrier.

use std::fs::OpenOptions;
use std::io::{self, Seek, SeekFrom, Write};
use std::path::{Component, Path, PathBuf};
use std::process::ExitStatus;

use oneiron::attempt_queue::{AttemptQueue, AttemptQueueCleanupReport, CleanupAttemptLeases};

use crate::clock::FakeClock;
use crate::fixture::TestVault;
#[cfg(unix)]
use crate::server::ServerProcess;

/// Kills the server with SIGKILL and starts it again on the same port with
/// the same vault, returning once it is ready. Returns the killed process's
/// exit status.
///
/// # Errors
/// The server was not running or does not come back.
#[cfg(unix)]
pub fn crash_and_restart(server: &mut ServerProcess) -> io::Result<ExitStatus> {
    let status = server.kill()?;
    server.restart()?;
    Ok(status)
}

/// Moves `clock` `lease_timeout_secs` past `leased_at` (a leased row's
/// `updated_at`) and runs the queue's lease cleanup at that time: every lease
/// that old is lost, and its row goes back to the queue for another worker.
/// Returns the cleanup's report.
///
/// # Errors
/// The cleanup fails.
pub fn expire_leases(
    queue: &AttemptQueue<'_>,
    clock: &FakeClock,
    leased_at: u64,
    lease_timeout_secs: u64,
) -> oneiron::Result<AttemptQueueCleanupReport> {
    let expired = leased_at.saturating_add(lease_timeout_secs);
    if clock.now() < expired {
        clock.set(expired);
    }
    queue.cleanup_leases(CleanupAttemptLeases {
        now: clock.now(),
        lease_timeout_secs,
    })
}

/// `relative` inside the copy's vault directory, refusing a path that
/// leaves it.
fn inside(copy: &TestVault, relative: &str) -> io::Result<PathBuf> {
    let relative = Path::new(relative);
    if relative
        .components()
        .any(|part| !matches!(part, Component::Normal(_)))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{}: not a plain path inside the vault", relative.display()),
        ));
    }
    Ok(copy.path().join(relative))
}

/// Cuts the file `relative` (inside the copy's closed vault) to `length`
/// bytes: a write the disk lost.
///
/// # Errors
/// The path leaves the vault or the file cannot be written.
pub fn truncate(copy: &TestVault, relative: &str, length: u64) -> io::Result<()> {
    OpenOptions::new()
        .write(true)
        .open(inside(copy, relative)?)?
        .set_len(length)
}

/// Writes `bytes` at `offset` into the file `relative` (inside the copy's
/// closed vault): a torn or corrupted page.
///
/// # Errors
/// The path leaves the vault or the file cannot be written.
pub fn overwrite(copy: &TestVault, relative: &str, offset: u64, bytes: &[u8]) -> io::Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .open(inside(copy, relative)?)?;
    file.seek(SeekFrom::Start(offset))?;
    file.write_all(bytes)?;
    file.sync_all()
}

/// Deletes the file `relative` from the copy's closed vault.
///
/// # Errors
/// The path leaves the vault or the file cannot be removed.
pub fn remove(copy: &TestVault, relative: &str) -> io::Result<()> {
    std::fs::remove_file(inside(copy, relative)?)
}
