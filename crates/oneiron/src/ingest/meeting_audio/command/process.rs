//! One native-host process, run while it makes progress (FIX 3765): every
//! line it writes before its reply is progress, and a process that writes
//! none for the idle time faults; however long a recording runs, it runs
//! while its units progress. Its reply is read whole (Rule 5). Admission
//! answers go back on its stdin, one line each. No shell or global state.
use std::io::{BufRead, BufReader, Read, Write};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{Receiver, RecvTimeoutError, sync_channel};
use std::time::{Duration, Instant};

use serde_json::Value;

/// One thing the process wrote.
pub(super) enum Frame {
    /// An event line before its reply: a unit about to run, its progress,
    /// or its end.
    Event(Value),
    /// Its reply: the header line and everything after it.
    Reply(Vec<u8>),
}

/// A running native host process.
pub(super) struct Session {
    child: Child,
    stdin: Option<ChildStdin>,
    frames: Receiver<Result<Frame, &'static str>>,
    idle: Duration,
    reaped: bool,
}

impl Session {
    /// Spawns `command` in a process group of its own, which every native
    /// worker it starts stays in, so stopping the group stops them all;
    /// `idle` is how long it may go without writing a line.
    pub(super) fn spawn(command: &mut Command, idle: Duration) -> Result<Self, &'static str> {
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;
            command.process_group(0);
        }
        let mut child = command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|_| "SpawnFailed")?;
        let (Some(stdout), Some(stdin)) = (child.stdout.take(), child.stdin.take()) else {
            stop(&mut child);
            return Err("MissingStdio");
        };
        // Rendezvous: the reader hands over one frame at a time, and the
        // process blocks on its pipe while a frame waits.
        let (sender, frames) = sync_channel(0);
        let reader = std::thread::Builder::new()
            .name("oneiron-audio-output".into())
            .spawn(move || read_frames(BufReader::new(stdout), |frame| sender.send(frame).is_ok()));
        if reader.is_err() {
            stop(&mut child);
            return Err("OutputWorkerUnavailable");
        }
        Ok(Self {
            child,
            stdin: Some(stdin),
            frames,
            idle,
            reaped: false,
        })
    }

    /// The process's next frame, within the idle time.
    pub(super) fn next(&mut self) -> Result<Frame, &'static str> {
        match self.frames.recv_timeout(self.idle) {
            Ok(frame) => frame,
            Err(RecvTimeoutError::Timeout) => Err("HostProgressStalled"),
            Err(RecvTimeoutError::Disconnected) => Err("OutputWorkerFailed"),
        }
    }

    /// Answers the unit the process asked to run: admitted or not.
    pub(super) fn answer(&mut self, admitted: bool) -> Result<(), &'static str> {
        let stdin = self.stdin.as_mut().ok_or("AdmissionClosed")?;
        let mut line = serde_json::to_vec(&serde_json::json!({ "admitted": admitted }))
            .map_err(|_| "AdmissionIo")?;
        line.push(b'\n');
        stdin
            .write_all(&line)
            .and_then(|()| stdin.flush())
            .map_err(|_| "AdmissionIo")
    }

    /// Whether the process, its reply read, exits successfully within the
    /// idle time. Past it, its whole process group is killed and the process
    /// reaped before `HostDeadlineExceeded` returns.
    pub(super) fn finish(mut self) -> Result<bool, &'static str> {
        // No more answers: a process still waiting on one ends.
        self.stdin = None;
        let started = Instant::now();
        loop {
            match self.child.try_wait() {
                Ok(Some(status)) => {
                    self.reaped = true;
                    return Ok(status.success());
                }
                Ok(None) if started.elapsed() >= self.idle => {
                    stop(&mut self.child);
                    self.reaped = true;
                    return Err("HostDeadlineExceeded");
                }
                Ok(None) => std::thread::sleep(Duration::from_millis(1)),
                Err(_) => return Err("WaitFailed"),
            }
        }
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        // A live leader retains its process-group id. Do not signal a
        // potentially recycled id after observing/reaping its exit.
        if !self.reaped {
            stop(&mut self.child);
        }
    }
}

/// Reads `stdout`'s event lines, each a JSON object with an `event`, then
/// its reply: the first other line and everything after it, read whole.
fn read_frames(
    mut stdout: impl BufRead,
    mut send: impl FnMut(Result<Frame, &'static str>) -> bool,
) {
    loop {
        let mut line = Vec::new();
        match stdout.read_until(b'\n', &mut line) {
            Ok(0) => {
                send(Err("InvalidResponse"));
                return;
            }
            Ok(_) => {}
            Err(_) => {
                send(Err("ResponseIo"));
                return;
            }
        }
        let event = serde_json::from_slice::<Value>(&line)
            .ok()
            .filter(|value| value.get("event").is_some());
        if let Some(event) = event {
            if !send(Ok(Frame::Event(event))) {
                return;
            }
            continue;
        }
        let reply = stdout.read_to_end(&mut line).map(|_| Frame::Reply(line));
        send(reply.map_err(|_| "ResponseIo"));
        return;
    }
}

fn stop(child: &mut Child) {
    #[cfg(unix)]
    if let Ok(pid) = i32::try_from(child.id()) {
        // SAFETY: this live child was spawned into its own process group above.
        unsafe {
            libc::kill(-pid, libc::SIGKILL);
        }
    }
    let _ = child.kill();
    let _ = child.wait();
}
