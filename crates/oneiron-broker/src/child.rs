//! The same-user broker (ARCH-0069 `#broker-same-user-open`). Where no
//! separate OS user exists, as on macOS, the daemon starts the broker as its
//! own child, under its own uid. Receipts say `same_user`, and the run shows
//! the unproven badge.
//!
//! The child confines itself as an organ is confined, and closes its memory
//! as its first act ([`crate::peer::confine_child`]). The daemon and the
//! child talk only over a channel the daemon makes at the start: one end of
//! a socket pair, which the child inherits on descriptor 3 and nothing else
//! holds. For each call the daemon makes a fresh socket pair, passes one end
//! to the child over the channel, and writes the call's frame on the other.
//! The child binds no path and listens on nothing, so no other process can
//! reach it, and no path or pid number names it to the daemon. It says it
//! serves on its stdout, a pipe only the daemon holds. The child exits when
//! its stdin, which the daemon holds, closes, or the channel does. That
//! happens when the daemon drops it or dies.
//!
//! What this mode cannot close: a process of the same uid that opens the
//! child's memory in the moment between its start and its first act keeps
//! that handle. The child starts once and is kept warm, so that moment comes
//! once per start, not once per call. Such a process can also stop or kill
//! the child, or reach the daemon's own descriptors (its ends of the channel
//! and of the start pipes among them), and so make a call fail after its
//! permit started, which is charged as a started call. None of that hands it
//! the key.

use std::ffi::OsString;
use std::io::{BufRead as _, IoSlice, Read as _};
use std::mem::MaybeUninit;
use std::os::fd::{AsFd as _, AsRawFd as _, BorrowedFd, RawFd};
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::RecvTimeoutError;
use std::sync::{Mutex, PoisonError};
use std::time::Duration;

use rustix::io::Errno;
use rustix::net::{SendAncillaryBuffer, SendAncillaryMessage, SendFlags, sendmsg};

use crate::peer::CHANNEL_FD;

/// How long a starting child has to say it serves.
const START_DEADLINE: Duration = Duration::from_secs(10);

/// How long a call's socket may wait for room on the channel. The child
/// takes each one at once, so only a child that has stopped leaves none.
const HANDOVER_DEADLINE: Duration = Duration::from_secs(5);

#[cfg(target_os = "linux")]
const SEND_FLAGS: SendFlags = SendFlags::NOSIGNAL;
#[cfg(not(target_os = "linux"))]
const SEND_FLAGS: SendFlags = SendFlags::empty();

/// The broker as a child of this process, started when first needed and
/// again after it exits.
#[derive(Debug)]
pub struct ChildBroker {
    program: PathBuf,
    args: Vec<OsString>,
    running: Mutex<Option<Running>>,
}

#[derive(Debug)]
struct Running {
    process: Child,
    /// Held open: the child exits when it closes.
    lifeline: ChildStdin,
    /// This process's end of the channel; the child holds the other.
    channel: UnixStream,
}

impl Running {
    fn stop(mut self) {
        drop(self.lifeline);
        drop(self.channel);
        let _ = self.process.kill();
        let _ = self.process.wait();
    }
}

impl ChildBroker {
    /// A child broker run from `program`, trusting the PEM roots in
    /// `extra_roots` beside the system's, and giving each send `timeout`.
    /// The child starts at the first [`Self::ensure`] or [`Self::connect`].
    #[must_use]
    pub fn new(program: PathBuf, extra_roots: &[PathBuf], timeout: Duration) -> Self {
        let secs = timeout.as_secs().max(1).to_string();
        let mut args: Vec<OsString> = vec!["--timeout-secs".into(), secs.into()];
        for roots in extra_roots {
            args.push("--extra-roots".into());
            args.push(roots.into());
        }
        Self {
            program,
            args,
            running: Mutex::new(None),
        }
    }

    /// Starts the child if it is not running. A start blocks until the child
    /// says it serves, at most `START_DEADLINE` (10 s).
    pub fn ensure(&self) -> std::io::Result<()> {
        let mut running = self.running.lock().unwrap_or_else(PoisonError::into_inner);
        live(&mut running, || self.start()).map(drop)
    }

    /// A socket to the child for one call, starting the child first if it is
    /// not running. Its other end goes to the child over the channel. A child
    /// that does not take it is stopped, so the next call starts a new one.
    pub fn connect(&self) -> std::io::Result<UnixStream> {
        let mut running = self.running.lock().unwrap_or_else(PoisonError::into_inner);
        let child = live(&mut running, || self.start())?;
        let (ours, theirs) = UnixStream::pair()?;
        let handed = hand_over(&child.channel, theirs.as_fd());
        drop(theirs);
        if let Err(error) = handed {
            if let Some(child) = running.take() {
                child.stop();
            }
            return Err(error);
        }
        Ok(ours)
    }

    fn start(&self) -> std::io::Result<Running> {
        let (channel, theirs) = UnixStream::pair()?;
        channel.set_write_timeout(Some(HANDOVER_DEADLINE))?;
        let end = theirs.as_raw_fd();
        let mut command = Command::new(&self.program);
        command
            .arg("child")
            .args(&self.args)
            .env_clear()
            .current_dir("/")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            // Its own group, so a terminal's signal to the daemon's group
            // leaves it to end at its stdin's close.
            .process_group(0);
        // SAFETY: the closure runs in the child between fork and exec. It only
        // makes async-signal-safe calls (dup2, fcntl) on a descriptor number
        // taken before the fork, and allocates nothing.
        unsafe {
            command.pre_exec(move || on_channel_fd(end));
        }
        let spawned = command.spawn();
        drop(theirs);
        let mut process = spawned?;
        match listening(&mut process) {
            Ok(lifeline) => Ok(Running {
                process,
                lifeline,
                channel,
            }),
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
    }
}

/// The running child in `running`, after `start` replaced one that exited,
/// or whose state is unknown, or put one where there was none.
fn live(
    running: &mut Option<Running>,
    start: impl FnOnce() -> std::io::Result<Running>,
) -> std::io::Result<&mut Running> {
    let alive = running
        .as_mut()
        .is_some_and(|child| matches!(child.process.try_wait(), Ok(None)));
    if !alive {
        if let Some(child) = running.take() {
            child.stop();
        }
        *running = Some(start()?);
    }
    running
        .as_mut()
        .ok_or_else(|| std::io::ErrorKind::NotConnected.into())
}

/// Puts the child's end of the channel on [`CHANNEL_FD`], open across exec.
/// Runs in the child between fork and exec.
fn on_channel_fd(end: RawFd) -> std::io::Result<()> {
    let placed = if end == CHANNEL_FD {
        // SAFETY: `end` is the channel's end, inherited open; clearing its
        // close-on-exec flag only keeps it across exec.
        unsafe { libc::fcntl(end, libc::F_SETFD, 0) == 0 }
    } else {
        // SAFETY: both descriptors are valid in the child; dup2 leaves the
        // copy on CHANNEL_FD without close-on-exec.
        unsafe { libc::dup2(end, CHANNEL_FD) == CHANNEL_FD }
    };
    if placed {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

/// Passes `end` to the child over `channel`, on one byte, waiting at most
/// [`HANDOVER_DEADLINE`] for room.
fn hand_over(channel: &UnixStream, end: BorrowedFd<'_>) -> std::io::Result<()> {
    let fds = [end];
    let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
    let mut control = SendAncillaryBuffer::new(&mut space);
    if !control.push(SendAncillaryMessage::ScmRights(&fds)) {
        return Err(std::io::ErrorKind::InvalidInput.into());
    }
    loop {
        match sendmsg(channel, &[IoSlice::new(&[0])], &mut control, SEND_FLAGS) {
            Ok(1) => return Ok(()),
            Ok(_) => return Err(std::io::ErrorKind::WriteZero.into()),
            Err(Errno::INTR) => {}
            Err(errno) => return Err(errno.into()),
        }
    }
}

/// The started child's lifeline, once the child has said on its stdout that
/// it serves, which it does after it has closed its memory: at most
/// [`START_DEADLINE`]. A child that exits first, or says anything else, never
/// served.
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
                "the broker exited before it served ({status})"
            ))),
            None => Err(std::io::Error::other("the broker did not say it serves")),
        },
        Err(RecvTimeoutError::Timeout) => Err(std::io::ErrorKind::TimedOut.into()),
    }
}
