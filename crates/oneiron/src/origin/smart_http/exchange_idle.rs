//! An exchange's idle limit: a clock of the last byte it moved in either
//! direction, the request body and response sink that wind it, and the
//! watchdog that kills the backend when it runs down.

use std::io::{self, Read};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, RecvTimeoutError};
use std::time::{Duration, Instant};

use super::paths::serve_idle;
use super::serve::ServeSink;
use super::serve_cmd::ServeChild;
use crate::error::Error;

/// When the exchange last moved a byte, in either direction.
pub(super) struct Progress {
    started: Instant,
    /// Milliseconds after `started`.
    last: AtomicU64,
}

impl Progress {
    pub(super) fn new() -> Self {
        Self {
            started: Instant::now(),
            last: AtomicU64::new(0),
        }
    }

    fn touch(&self) {
        let now = u64::try_from(self.started.elapsed().as_millis()).unwrap_or(u64::MAX);
        self.last.store(now, Ordering::Relaxed);
    }

    fn quiet_for(&self) -> Duration {
        let last = Duration::from_millis(self.last.load(Ordering::Relaxed));
        self.started.elapsed().saturating_sub(last)
    }
}

/// The request body, winding the clock on every byte it yields.
pub(super) struct ProgressRead<'a> {
    pub(super) body: &'a mut (dyn Read + Send),
    pub(super) progress: &'a Progress,
}

impl Read for ProgressRead<'_> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        let read = self.body.read(out)?;
        if read > 0 {
            self.progress.touch();
        }
        Ok(read)
    }
}

/// The response sink, winding the clock on everything it accepts.
pub(super) struct ProgressSink<'a> {
    pub(super) sink: &'a mut dyn ServeSink,
    pub(super) progress: &'a Progress,
}

impl ServeSink for ProgressSink<'_> {
    fn begin(&mut self, status: u16, headers: &[(String, String)]) -> io::Result<()> {
        self.sink.begin(status, headers)?;
        self.progress.touch();
        Ok(())
    }

    fn write_chunk(&mut self, bytes: &[u8]) -> io::Result<()> {
        self.sink.write_chunk(bytes)?;
        self.progress.touch();
        Ok(())
    }
}

/// Kills the backend once the exchange has moved no byte for `idle`, and
/// says whether it did. A message on `watched` kills it at once and is no
/// idling: the exchange already failed, and nothing more is wanted from the
/// backend. The watch ends when `watched` closes, which the exchange does
/// only once every thread that reads the backend's pipes or answers its hook
/// has been joined, so none of them waits on a backend nobody watches.
///
/// The kill is what unblocks the exchange: the backend's pipes close with it,
/// so the response reader sees its end, the body pump its broken pipe, the
/// stderr drain its end, and a hook waiting on a verdict dies with the rest.
pub(super) fn watch(
    progress: &Progress,
    idle: Duration,
    watched: &Receiver<()>,
    child: &mut ServeChild,
) -> bool {
    loop {
        let quiet = progress.quiet_for();
        if quiet >= idle {
            child.end();
            return true;
        }
        match watched.recv_timeout(idle - quiet) {
            Err(RecvTimeoutError::Timeout) => {}
            Ok(()) => {
                child.end();
                return false;
            }
            Err(RecvTimeoutError::Disconnected) => return false,
        }
    }
}

/// A body or sink that bounds its own waits reports a stall as `TimedOut`:
/// the same idle limit, reached on the other side of the seam.
pub(super) fn stall_as_idle(error: Error) -> Error {
    match &error {
        Error::Io(io) if io.kind() == io::ErrorKind::TimedOut => serve_idle(),
        _ => error,
    }
}
