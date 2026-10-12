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
//! happens when the daemon drops it or dies. A child that let its channel go
//! is replaced before the next call's permit starts.
//!
//! Every other subprocess of the daemon starts through `oneiron_spawn`, with
//! only the descriptors it is named. So none keeps a copy of a socket pair's
//! end in the moment, on macOS, between the pair's making and its
//! close-on-exec.
//!
//! What this mode cannot close, against a process of the same uid: it can
//! open the child's memory in the moment between its start and its first
//! act, and keep that handle (the child starts once and is kept warm, so that
//! moment comes once per start, not once per call); it can reach the daemon's
//! own descriptors, its ends of the channel, of the start pipes and of each
//! call's socket pair among them; and it can stop or kill the child. The
//! first two lie outside what this mode protects. Stopping or killing the
//! child hands it no key: it makes a call fail after its permit started,
//! which is charged as a started call.

use std::ffi::OsString;
use std::io::{BufRead as _, IoSlice, Read as _};
use std::mem::MaybeUninit;
use std::os::fd::{AsFd as _, AsRawFd as _, BorrowedFd};
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::{Child, ChildStdin, Stdio};
use std::sync::mpsc::RecvTimeoutError;
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};

use rustix::event::{PollFd, PollFlags, Timespec, poll};
use rustix::io::Errno;
use rustix::net::{SendAncillaryBuffer, SendAncillaryMessage, SendFlags, sendmsg};

use crate::peer::CHANNEL_FD;

/// How long a starting child has to say it serves.
const START_DEADLINE: Duration = Duration::from_secs(10);

/// How long a call's socket may wait for room on the channel. The child
/// takes each one at once, so only a child that has stopped leaves none.
const HANDOVER_DEADLINE: Duration = Duration::from_secs(5);

/// A child gone mid-handover is an error, never a SIGPIPE: per send on Linux,
/// and through `SO_NOSIGPIPE` on each socket on macOS.
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

    /// Starts the child if it is not running, or if it let its channel go. A
    /// start blocks until the child says it serves, at most `START_DEADLINE`
    /// (10 s).
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
        // The frame and the reply go on these: a peer gone is an error to
        // either side, whatever its SIGPIPE disposition.
        #[cfg(target_os = "macos")]
        for end in [&ours, &theirs] {
            rustix::net::sockopt::set_socket_nosigpipe(end, true)?;
        }
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
        #[cfg(target_os = "macos")]
        rustix::net::sockopt::set_socket_nosigpipe(&channel, true)?;
        let mut command =
            oneiron_spawn::command_with_fds(&self.program, &[(theirs.as_raw_fd(), CHANNEL_FD)]);
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
        let spawned = command.spawn();
        drop(theirs);
        let mut process = spawned?;
        // A child that let its channel go before it said it serves never
        // served.
        let served = listening(&mut process).and_then(|lifeline| {
            if channel_open(&channel) {
                Ok(lifeline)
            } else {
                Err(std::io::Error::other("the broker let its channel go"))
            }
        });
        match served {
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
/// whose state is unknown or that let its channel go, or put one where there
/// was none.
fn live(
    running: &mut Option<Running>,
    start: impl FnOnce() -> std::io::Result<Running>,
) -> std::io::Result<&mut Running> {
    let alive = running.as_mut().is_some_and(|child| {
        matches!(child.process.try_wait(), Ok(None)) && channel_open(&child.channel)
    });
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

/// Whether the child still holds its end of `channel`. It never writes
/// there, so anything to read, a hang-up or an error means it let it go.
fn channel_open(channel: &UnixStream) -> bool {
    let now = Timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    loop {
        let mut fds = [PollFd::new(channel, PollFlags::IN)];
        match poll(&mut fds, Some(&now)) {
            Ok(ready) => return ready == 0,
            Err(Errno::INTR) => {}
            Err(_) => return false,
        }
    }
}

/// Passes `end` to the child over `channel`, on one byte, waiting at most
/// [`HANDOVER_DEADLINE`] in all for room.
fn hand_over(channel: &UnixStream, end: BorrowedFd<'_>) -> std::io::Result<()> {
    let fds = [end];
    let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
    let mut control = SendAncillaryBuffer::new(&mut space);
    if !control.push(SendAncillaryMessage::ScmRights(&fds)) {
        return Err(std::io::ErrorKind::InvalidInput.into());
    }
    let deadline = Instant::now() + HANDOVER_DEADLINE;
    let mut left = HANDOVER_DEADLINE;
    loop {
        // The send timeout bounds one send: one a signal cut short is sent
        // again with what is left.
        channel.set_write_timeout(Some(left))?;
        match sendmsg(channel, &[IoSlice::new(&[0])], &mut control, SEND_FLAGS) {
            Ok(1) => return Ok(()),
            Ok(_) => return Err(std::io::ErrorKind::WriteZero.into()),
            Err(Errno::INTR) => {}
            Err(errno) => return Err(errno.into()),
        }
        left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(std::io::ErrorKind::TimedOut.into());
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

#[cfg(test)]
mod tests;
