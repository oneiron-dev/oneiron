//! Linux microVM guest agent and an unprivileged protocol conformance adapter.
//!
//! The production executable runs only as Linux PID 1. [`serve_localtest`] is
//! explicitly a local test adapter: it proves neither boot nor JavaScript.
//! [`serve_batch`] runs one exchange as a transcript on a vendor's sandbox,
//! which has no live channel to the host (L8-43).
//! Components use the canonical typed WIT; no WASI or first-party writes link.

/// The transcript channel of a run on a vendor's sandbox (L8-43).
mod batch;
mod filesystem;
mod protocol;
mod runtime;

#[cfg(target_os = "linux")]
mod boot;
mod conformance;
#[cfg(target_os = "linux")]
mod egress;
#[cfg(target_os = "linux")]
mod native;
#[cfg(target_os = "linux")]
mod native_mounts;

#[cfg(target_os = "linux")]
pub use boot::run as run_production;
pub use conformance::component as conformance_component;

use std::{
    io::{Read, Write},
    path::Path,
};

/// A fail-closed guest boundary error. Details never contain credential bodies.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("guest protocol refused: {0}")]
    Protocol(&'static str),
    #[error("guest filesystem refused: {0}")]
    Filesystem(&'static str),
    #[error("guest runtime refused: {0}")]
    Runtime(&'static str),
    #[error("guest transport does not support claim-candidate proposals")]
    UnsupportedClaimCandidate,
    #[error("guest system I/O failed")]
    Io(#[from] std::io::Error),
}

/// Result returned by the guest agent's bounded interfaces.
pub type Result<T> = std::result::Result<T, Error>;

/// Runs one host-protocol exchange over an injected duplex channel.
///
/// LOCALTEST ONLY. The caller supplies a private, empty directory with no
/// symlink ancestors. Files received from the host are copied there, never
/// mounted. The adapter does not fork, drop privileges, or emulate OverlayFS.
/// Production PID 1 uses `run_production` instead (Linux only).
/// All errors attempt a nonzero finish; partial writes are scratch state only.
pub fn serve_localtest<T: Read + Write + 'static>(channel: T, workspace: &Path) -> Result<()> {
    let mut session = protocol::Session::new(channel);
    let setup = (|| {
        let workspace = filesystem::Workspace::open(workspace)?;
        if !workspace.snapshot()?.is_empty() {
            return Err(Error::Filesystem("localtest workspace must be empty"));
        }
        let input = session.receive(&workspace)?;
        Ok((input, workspace))
    })();
    let outcome = match setup {
        Ok((input, workspace)) => {
            let (returned, result) = runtime::execute(session, input, workspace);
            session = returned;
            result
        }
        Err(error) => Err(error),
    };
    let finish = session.finish(if outcome.is_ok() { 0 } else { 1 });
    outcome.and(finish)
}

/// Runs one host-protocol exchange as a transcript, on a vendor's sandbox
/// (L8-43, VENDOR-BOUNDARY = A).
///
/// The host's opening frames are read from `input`, and every frame this
/// guest sends is appended to `output`, a file this call creates (it never
/// replaces one). Each receipt the guest waits for is answered as the host
/// answers it when nothing is wrong, and every credential read is refused:
/// no broker is reachable from a vendor's machine. The host replays the
/// transcript through its own checks, so nothing here is trusted. `workspace`
/// is a private, empty directory with no symlink ancestors; the staged files
/// are copied there, never mounted. The vendor's sandbox is the isolation:
/// this adapter installs no fence of ours, and the host records the run as
/// unproven.
pub fn serve_batch(input: &Path, output: &Path, workspace: &Path) -> Result<()> {
    let input = std::io::BufReader::new(std::fs::File::open(input)?);
    let output = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(output)?;
    let channel = batch::TranscriptChannel::new(input, output);
    let mut session = protocol::Session::new(channel);
    let setup = (|| {
        let workspace = filesystem::Workspace::open(workspace)?;
        if !workspace.snapshot()?.is_empty() {
            return Err(Error::Filesystem("batch workspace must be empty"));
        }
        let input = session.receive(&workspace)?;
        Ok((input, workspace))
    })();
    let outcome = match setup {
        Ok((input, workspace)) => {
            let (returned, result) = runtime::execute(session, input, workspace);
            session = returned;
            result
        }
        Err(error) => Err(error),
    };
    let finish = session.finish(i32::from(outcome.is_err()));
    outcome.and(finish)
}

/// Production OCI guest entry. The engine's parent launcher has already
/// installed Landlock/seccomp; this agent cannot be an in-process fallback.
#[cfg(target_os = "linux")]
pub fn serve_fenced_container() -> Result<()> {
    // SAFETY: identity queries have no preconditions.
    if unsafe { libc::geteuid() } == 0 || unsafe { libc::getpid() } == 1 {
        return Err(Error::Runtime(
            "container agent requires the non-root fence child",
        ));
    }
    let status = std::fs::read_to_string("/proc/self/status")?;
    if !status.lines().any(|l| l == "NoNewPrivs:\t1") || !status.lines().any(|l| l == "Seccomp:\t2")
    {
        return Err(Error::Runtime(
            "container agent requires the installed fence",
        ));
    }
    struct Channel;
    impl Read for Channel {
        fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
            std::io::stdin().read(bytes)
        }
    }
    impl Write for Channel {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            std::io::stdout().write(bytes)
        }
        fn flush(&mut self) -> std::io::Result<()> {
            std::io::stdout().flush()
        }
    }
    let root = Path::new("/tmp/oneiron-workspace");
    std::fs::create_dir(root)?;
    let mut session = protocol::Session::new(Channel);
    let preparation = (|| {
        let workspace = filesystem::Workspace::open(root)?;
        let input = session.receive(&workspace)?;
        Ok((input, workspace))
    })();
    let outcome = match preparation {
        Ok((input, workspace)) => {
            let (returned, result) = runtime::execute(session, input, workspace);
            session = returned;
            result
        }
        Err(error) => Err(error),
    };
    let finish = session.finish(i32::from(outcome.is_err()));
    outcome.and(finish)
}

#[cfg(test)]
mod tests;
