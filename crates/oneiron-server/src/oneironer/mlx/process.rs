//! The MLX worker's process (FIX 6755 slice 3, contract rev 3 A1, A3b): one
//! child and the threads that own its pipes, from spawn to reaping.
//!
//! The child starts through `oneiron_spawn`, with the standard descriptors
//! alone, a cleared environment, `/` as its cwd and three pipes. Its stderr
//! is drained from the start, line by line into the log, so a full pipe
//! never stalls it. Its stdout is read on a thread of its own, frame by
//! frame, into one event queue, which every wait reads with a deadline: the
//! 120 s handshake and each call's timeout really interrupt a worker that
//! hangs. Its stdin is written by a third thread, so a write to a worker
//! that has stopped reading never blocks a call past its deadline.
//!
//! One request is in flight at a time, under an id that only grows. The
//! session ends as the contract asks: stdin closes, the worker has 2 s to
//! exit, at 5 s it is killed, and it is reaped and its threads joined, so
//! none outlives the session.

use std::ffi::OsString;
use std::io::{BufRead, BufReader, ErrorKind};
use std::path::Path;
use std::process::{Child, ChildStderr, ChildStdin, ChildStdout, Stdio};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use super::super::dispatcher::Fault;
use super::frame::{self, FrameError};

/// How long a worker has to exit once its stdin closes (A3b).
const EXIT_WITHIN: Duration = Duration::from_secs(2);
/// When a worker that has not exited is killed (A3b).
const KILL_AFTER: Duration = Duration::from_secs(5);
/// How often a closing worker is checked for its exit.
const REAP_POLL: Duration = Duration::from_millis(20);
/// The longest stderr line logged whole; a longer one is logged in pieces,
/// every byte of it, so the drain holds no growing buffer.
const LOG_LINE_BYTES: usize = 8 * 1024;
/// The environment the worker keeps when this process has it (A1).
const INHERITED: [&str; 2] = ["HOME", "TMPDIR"];

/// What a session's wait can hear.
enum Event {
    /// One frame's payload from stdout.
    Frame(Vec<u8>),
    /// The stream ended or broke: why, by name.
    Closed(&'static str),
    /// The dispatcher closed.
    Stop,
}

/// One running worker and its pipes' threads.
pub(super) struct Session {
    child: Child,
    /// To the stdin writer. Dropped, it ends the writer, which closes the
    /// worker's stdin: the EOF the worker exits at.
    frames: Option<Sender<Vec<u8>>>,
    events: Receiver<Event>,
    /// A sender onto `events`, for a stop from another thread.
    stop: Sender<Event>,
    threads: Vec<JoinHandle<()>>,
    next_id: u64,
}

impl Session {
    /// Starts `program` with `args`. `on_exit` runs on the stdout thread
    /// once the worker's stdout ends or breaks, whether or not a call waits:
    /// how a crash while idle is seen.
    pub(super) fn spawn(
        program: &Path,
        args: &[OsString],
        on_exit: Box<dyn Fn() + Send>,
    ) -> Result<Self, Fault> {
        let mut command = oneiron_spawn::command(program);
        command
            .args(args)
            .env_clear()
            .env("PYTHONDONTWRITEBYTECODE", "1")
            .current_dir("/")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        for key in INHERITED {
            if let Some(value) = std::env::var_os(key) {
                command.env(key, value);
            }
        }
        let mut child = command.spawn().map_err(|error| {
            tracing::warn!(program = %program.display(), %error, "oneironer mlx spawn failed");
            Fault::Crash("spawn_failed")
        })?;
        let pipes = (child.stdin.take(), child.stdout.take(), child.stderr.take());
        let (events_in, events) = mpsc::channel();
        let (frames, queue) = mpsc::channel();
        let mut session = Self {
            child,
            frames: Some(frames),
            events,
            stop: events_in.clone(),
            threads: Vec::with_capacity(3),
            next_id: 0,
        };
        // A session dropped from here on closes, kills and reaps its child.
        let (Some(stdin), Some(stdout), Some(stderr)) = pipes else {
            return Err(Fault::Crash("spawn_failed"));
        };
        session.start("oneironer mlx stderr", move || drain_stderr(stderr))?;
        let replies = events_in.clone();
        session.start("oneironer mlx stdout", move || {
            read_frames(stdout, &replies, on_exit.as_ref());
        })?;
        session.start("oneironer mlx stdin", move || {
            write_frames(stdin, &queue, &events_in);
        })?;
        Ok(session)
    }

    fn start(&mut self, name: &str, body: impl FnOnce() + Send + 'static) -> Result<(), Fault> {
        let thread = std::thread::Builder::new()
            .name(name.to_owned())
            .spawn(body)
            .map_err(|_| Fault::Crash("spawn_failed"))?;
        self.threads.push(thread);
        Ok(())
    }

    /// The worker's first frame, waited for at most `deadline`: its
    /// handshake, or its refused load.
    pub(super) fn first_frame(&self, deadline: Duration) -> Result<Vec<u8>, Fault> {
        self.next_frame(deadline, "handshake_timeout")
    }

    /// Sends one request's payload as a frame and waits at most `timeout`
    /// for the next frame, its reply. The payload must fit one frame.
    pub(super) fn exchange(&self, payload: Vec<u8>, timeout: Duration) -> Result<Vec<u8>, Fault> {
        let sent = self
            .frames
            .as_ref()
            .is_some_and(|frames| frames.send(payload).is_ok());
        if !sent {
            return Err(Fault::Crash("broken_pipe"));
        }
        self.next_frame(timeout, "call_timeout")
    }

    fn next_frame(&self, wait: Duration, late: &'static str) -> Result<Vec<u8>, Fault> {
        match self.events.recv_timeout(wait) {
            Ok(Event::Frame(payload)) => Ok(payload),
            Ok(Event::Closed(why)) => Err(Fault::Crash(why)),
            Ok(Event::Stop) => Err(Fault::Stopped),
            Err(RecvTimeoutError::Timeout) => Err(Fault::Crash(late)),
            Err(RecvTimeoutError::Disconnected) => Err(Fault::Crash("worker_exited")),
        }
    }

    /// The next request id, monotonic for the session's life.
    pub(super) fn next_id(&mut self) -> u64 {
        self.next_id += 1;
        self.next_id
    }

    /// What ends this session's current or next wait from another thread:
    /// the stop its dispatcher's close sends.
    pub(super) fn stopper(&self) -> Box<dyn Fn() + Send> {
        let stop = self.stop.clone();
        Box::new(move || {
            let _ = stop.send(Event::Stop);
        })
    }
}

impl Drop for Session {
    /// Ends the worker as the contract asks: stdin closes, it has 2 s to
    /// exit, at 5 s it is killed; then it is reaped and every thread of the
    /// session joined. A child's own drop would neither kill nor reap it.
    fn drop(&mut self) {
        self.frames = None;
        let closing = Instant::now();
        let status = loop {
            match self.child.try_wait() {
                Ok(Some(status)) => break Some(status),
                Ok(None) if closing.elapsed() < KILL_AFTER => std::thread::sleep(REAP_POLL),
                Ok(None) | Err(_) => break None,
            }
        };
        match status {
            Some(status) if closing.elapsed() <= EXIT_WITHIN => {
                tracing::info!(%status, "oneironer mlx worker exited");
            }
            Some(status) => {
                tracing::warn!(%status, "oneironer mlx worker exited after the contract's 2 s");
            }
            None => {
                let _ = self.child.kill();
                let _ = self.child.wait();
                tracing::warn!("oneironer mlx worker killed: no exit after its stdin closed");
            }
        }
        for thread in self.threads.drain(..) {
            let _ = thread.join();
        }
    }
}

/// The stdout thread: every frame into `events` until the stream ends or
/// breaks, then why, then `on_exit`. A frame no wait reads is dropped with
/// its session; the stream is read on, so the worker never blocks on it.
fn read_frames(stdout: ChildStdout, events: &Sender<Event>, on_exit: &(dyn Fn() + Send)) {
    let mut stdout = BufReader::new(stdout);
    let why = loop {
        match frame::read_frame(&mut stdout) {
            Ok(Some(payload)) => {
                let _ = events.send(Event::Frame(payload));
            }
            Ok(None) | Err(FrameError::Io { .. }) => break "worker_exited",
            Err(FrameError::TooLarge { .. } | FrameError::Truncated) => break "malformed_frame",
        }
    };
    let _ = events.send(Event::Closed(why));
    on_exit();
}

/// The stdin thread: each queued payload as one frame, until the queue's
/// sender drops; then stdin closes with this thread. A failed write ends it
/// as a broken pipe.
fn write_frames(mut stdin: ChildStdin, queue: &Receiver<Vec<u8>>, events: &Sender<Event>) {
    for payload in queue {
        if frame::write_frame(&mut stdin, &payload).is_err() {
            let _ = events.send(Event::Closed("broken_pipe"));
            return;
        }
    }
}

/// The stderr thread: every line into the log as a worker diagnostic, never
/// read as protocol, until the pipe ends.
fn drain_stderr(stderr: ChildStderr) {
    let mut reader = BufReader::with_capacity(LOG_LINE_BYTES, stderr);
    let mut line = Vec::with_capacity(LOG_LINE_BYTES);
    loop {
        let used = match reader.fill_buf() {
            Ok([]) => break,
            Ok(available) => {
                for &byte in available {
                    if byte == b'\n' {
                        log_line(&line);
                        line.clear();
                    } else {
                        line.push(byte);
                        if line.len() == LOG_LINE_BYTES {
                            log_line(&line);
                            line.clear();
                        }
                    }
                }
                available.len()
            }
            Err(error) if error.kind() == ErrorKind::Interrupted => continue,
            Err(_) => break,
        };
        reader.consume(used);
    }
    log_line(&line);
}

fn log_line(line: &[u8]) {
    let text = String::from_utf8_lossy(line);
    let text = text.trim_end();
    if !text.is_empty() {
        tracing::info!(worker = "mlx/metal", line = text, "oneironer worker stderr");
    }
}
