//! The same-user broker (ARCH-0069 `#broker-same-user-open`). Where no
//! separate OS user exists, as on macOS, the daemon starts the broker as its
//! own child, under its own uid. Receipts say `same_user`, and the run shows
//! the unproven badge.
//!
//! The child confines itself as an organ is confined, and closes its memory
//! as its first act ([`crate::peer::confine_child`]). It listens on a socket
//! in a directory only the daemon's uid may enter, and serves only the
//! daemon's pid. It says it listens on its stdout, a pipe only the daemon
//! holds, so a socket another process put at the path never passes for it.
//! The daemon checks the other way too: the peer on the socket must be the
//! child it started. Another process of the same uid can reach the socket,
//! but it can neither pose as the broker nor be served by it. The child exits
//! when its stdin, which the daemon holds, closes. That happens when the
//! daemon drops it or dies.
//!
//! What this mode cannot close: a process of the same uid that opens the
//! child's memory in the moment between its start and its first act keeps
//! that handle. The child starts once and is kept warm, so that moment comes
//! once per start, not once per call.

use std::ffi::OsString;
use std::hash::{BuildHasher, Hasher};
use std::os::unix::fs::DirBuilderExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::io::{BufRead as _, Read as _};
use std::sync::mpsc::RecvTimeoutError;
use std::sync::{Mutex, PoisonError};
use std::time::Duration;

/// How long a starting child has to listen.
const START_DEADLINE: Duration = Duration::from_secs(10);

/// The broker as a child of this process, started when first needed and
/// again after it exits.
#[derive(Debug)]
pub struct ChildBroker {
    program: PathBuf,
    args: Vec<OsString>,
    dir: PathBuf,
    socket: PathBuf,
    running: Mutex<Option<Running>>,
}

#[derive(Debug)]
struct Running {
    process: Child,
    /// Held open: the child exits when it closes.
    lifeline: ChildStdin,
}

impl Running {
    fn stop(mut self) {
        drop(self.lifeline);
        let _ = self.process.kill();
        let _ = self.process.wait();
    }
}

impl ChildBroker {
    /// A child broker run from `program`, trusting the PEM roots in
    /// `extra_roots` beside the system's, and giving each send `timeout`.
    /// Its socket's directory is made now, for this uid only; the child
    /// starts at the first [`Self::ensure`].
    pub fn new(
        program: PathBuf,
        extra_roots: &[PathBuf],
        timeout: Duration,
    ) -> std::io::Result<Self> {
        let dir = private_dir()?;
        let secs = timeout.as_secs().max(1).to_string();
        let mut args: Vec<OsString> = vec!["--timeout-secs".into(), secs.into()];
        for roots in extra_roots {
            args.push("--extra-roots".into());
            args.push(roots.into());
        }
        Ok(Self {
            program,
            args,
            socket: dir.join("broker.sock"),
            dir,
            running: Mutex::new(None),
        })
    }

    /// The child's socket.
    #[must_use]
    pub fn socket(&self) -> &Path {
        &self.socket
    }

    /// The running child's pid, starting it first if it is not running. A
    /// start blocks until the child listens, at most [`START_DEADLINE`].
    pub fn ensure(&self) -> std::io::Result<u32> {
        let mut running = self.running.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(child) = running.as_mut() {
            if matches!(child.process.try_wait(), Ok(None)) {
                return Ok(child.process.id());
            }
            // It exited, and is reaped, or its state is unknown: a second
            // child would find the first one's socket lock.
            if let Some(child) = running.take() {
                child.stop();
            }
        }
        let child = self.start()?;
        let pid = child.process.id();
        *running = Some(child);
        Ok(pid)
    }

    fn start(&self) -> std::io::Result<Running> {
        let mut process = Command::new(&self.program)
            .arg("child")
            .arg("--socket")
            .arg(&self.socket)
            .args(&self.args)
            .env_clear()
            .current_dir("/")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            // Its own group, so a terminal's signal to the daemon's group
            // leaves it to end at its stdin's close.
            .process_group(0)
            .spawn()?;
        match listening(&mut process) {
            Ok(lifeline) => Ok(Running { process, lifeline }),
            Err(error) => {
                let _ = process.kill();
                let _ = process.wait();
                Err(error)
            }
        }
    }
}

impl Drop for ChildBroker {
    fn drop(&mut self) {
        let running = self
            .running
            .get_mut()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        if let Some(child) = running {
            child.stop();
        }
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// The started child's lifeline, once the child has said on its stdout that
/// it listens, which it does after it has closed its memory: at most
/// [`START_DEADLINE`]. A child that exits first, or says anything else, never
/// listened.
fn listening(process: &mut Child) -> std::io::Result<ChildStdin> {
    let lifeline = process.stdin.take();
    let said = process.stdout.take();
    let (Some(lifeline), Some(said)) = (lifeline, said) else {
        return Err(std::io::ErrorKind::BrokenPipe.into());
    };
    let (tell, heard) = std::sync::mpsc::channel();
    // Reads until the line or the pipe's end; a child killed for the deadline
    // ends it.
    std::thread::Builder::new()
        .name("broker-start".to_owned())
        .spawn(move || {
            let mut line = Vec::new();
            let read = std::io::BufReader::new(said)
                .take(crate::LISTENING.len() as u64)
                .read_until(b'\n', &mut line);
            let _ = tell.send(read.is_ok() && line == crate::LISTENING);
        })?;
    match heard.recv_timeout(START_DEADLINE) {
        Ok(true) => Ok(lifeline),
        Ok(false) | Err(RecvTimeoutError::Disconnected) => match process.try_wait()? {
            Some(status) => Err(std::io::Error::other(format!(
                "the broker exited before it listened ({status})"
            ))),
            None => Err(std::io::Error::other("the broker did not say it listens")),
        },
        Err(RecvTimeoutError::Timeout) => Err(std::io::ErrorKind::TimedOut.into()),
    }
}

/// A new directory under the temporary directory that only this uid may
/// enter.
fn private_dir() -> std::io::Result<PathBuf> {
    let base = std::env::temp_dir();
    loop {
        let mut nonce = std::hash::RandomState::new().build_hasher();
        nonce.write_u32(std::process::id());
        let dir = base.join(format!("oneiron-broker-{:016x}", nonce.finish()));
        match std::fs::DirBuilder::new().mode(0o700).create(&dir) {
            Ok(()) => return Ok(dir),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error),
        }
    }
}
