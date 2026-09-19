//! Linux microVM guest agent and an unprivileged protocol conformance adapter.
//!
//! The production executable runs only as Linux PID 1. [`serve_localtest`] is
//! explicitly a local test adapter: it proves neither boot nor JavaScript.
//! Components use the canonical typed WIT; no WASI or first-party writes link.

mod filesystem;
mod protocol;
mod runtime;

#[cfg(target_os = "linux")]
pub mod boot;
pub mod conformance;

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
/// Production PID 1 uses `boot::run` instead (Linux only).
/// All errors attempt a nonzero finish; partial writes are scratch state only.
pub fn serve_localtest<T: Read + Write + 'static>(channel: T, workspace: &Path) -> Result<()> {
    let mut session = protocol::Session::new(channel);
    let setup = (|| {
        let input = session.receive()?;
        let workspace = filesystem::Workspace::open(workspace)?;
        if !workspace.snapshot()?.is_empty() {
            return Err(Error::Filesystem("localtest workspace must be empty"));
        }
        workspace.seed(&input.files)?;
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

#[cfg(test)]
mod tests;
