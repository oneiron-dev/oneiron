//! logind's sleep signals: a delay lock the thread holds while awake and a
//! signal monitor it reads line by line.
//!
//! The delay lock is a `systemd-inhibit` child in delay mode: while it runs,
//! logind delays a sleep until it exits, up to its delay maximum. The monitor
//! is `gdbus monitor` on logind's object: `gdbus` subscribes with plain match
//! rules, so it needs no privilege. `busctl monitor` and `dbus-monitor` need
//! the monitor or eavesdrop right on the system bus, which an unprivileged
//! service lacks, so they are not used here.

use super::SleepHooks;
use std::io::{BufRead, BufReader};
use std::process::{Child, ChildStdout, Command, Stdio};
use std::sync::Arc;
use std::thread::JoinHandle;

/// The member text a logind sleep signal line carries.
const PREPARE_FOR_SLEEP_MEMBER: &str = "org.freedesktop.login1.Manager.PrepareForSleep (";

/// Reads a `gdbus monitor` line as a logind sleep signal: `Some(true)` for a
/// sleep announcement, `Some(false)` for the wake after it, `None` for every
/// other line.
pub fn prepare_for_sleep_line(line: &str) -> Option<bool> {
    let rest = line.split_once(PREPARE_FOR_SLEEP_MEMBER)?.1;
    if rest.starts_with("true") {
        Some(true)
    } else if rest.starts_with("false") {
        Some(false)
    } else {
        None
    }
}

/// Spawns the delay lock: `systemd-inhibit` in delay mode over `sleep
/// infinity`, so logind delays a sleep until the child exits.
fn spawn_delay_lock() -> Option<Child> {
    Command::new("/usr/bin/systemd-inhibit")
        .args([
            "--what=sleep",
            "--mode=delay",
            "--who=oneiron",
            "--why=agent run and send leases are released before sleep",
            "/usr/bin/sleep",
            "infinity",
        ])
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .ok()
}

/// The delay lock the watch thread owns: killed and reaped when released and
/// when the thread ends.
struct DelayLock(Option<Child>);

impl DelayLock {
    /// Takes the delay lock; empty when it did not spawn, so the release
    /// races the sleep.
    fn take() -> Self {
        Self(spawn_delay_lock())
    }

    /// Releases the lock so the sleep goes on.
    fn release(&mut self) {
        release(self.0.take());
    }

    /// Takes the lock again after a wake, when none is held.
    fn retake(&mut self) {
        if self.0.is_none() {
            self.0 = spawn_delay_lock();
        }
    }
}

impl Drop for DelayLock {
    fn drop(&mut self) {
        self.release();
    }
}

/// Ends a child: killed, then reaped.
fn release(child: Option<Child>) {
    if let Some(mut child) = child {
        let _ = child.kill();
        let _ = child.wait();
    }
}

/// The logind sleep watch: its monitor child and its thread. Dropping it
/// kills and reaps the monitor, whose ended stdout ends the thread, then
/// joins the thread.
pub(super) struct LogindWatch {
    child: Option<Child>,
    thread: Option<JoinHandle<()>>,
}

impl LogindWatch {
    /// Starts the logind watch: the monitor child and its thread, which owns
    /// the delay lock. `None` when the monitor did not start, which
    /// `unobserved` hears once with its reason.
    pub(super) fn start(
        hooks: Arc<dyn SleepHooks>,
        unobserved: impl FnOnce(&'static str),
    ) -> Option<Self> {
        let mut monitor = match Command::new("/usr/bin/gdbus")
            .args([
                "monitor",
                "--system",
                "--dest",
                "org.freedesktop.login1",
                "--object-path",
                "/org/freedesktop/login1",
            ])
            .env_clear()
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
        {
            Ok(monitor) => monitor,
            Err(error) => {
                let reason = match error.kind() {
                    std::io::ErrorKind::NotFound => "gdbus is not on this host",
                    std::io::ErrorKind::PermissionDenied => "gdbus permission denied",
                    _ => "gdbus did not start",
                };
                unobserved(reason);
                return None;
            }
        };
        let Some(events) = monitor.stdout.take() else {
            release(Some(monitor));
            unobserved("gdbus did not start");
            return None;
        };
        let lock = DelayLock::take();
        let locked = lock.0.is_some();
        let thread = std::thread::Builder::new()
            .name("oneiron-sleep".to_owned())
            .spawn(move || follow(hooks, events, lock));
        let Ok(thread) = thread else {
            release(Some(monitor));
            unobserved("sleep watch thread did not start");
            return None;
        };
        if !locked {
            unobserved("no logind delay lock: the release may not finish before sleep");
        }
        Some(Self {
            child: Some(monitor),
            thread: Some(thread),
        })
    }
}

impl Drop for LogindWatch {
    fn drop(&mut self) {
        release(self.child.take());
        if let Some(thread) = self.thread.take()
            && thread.thread().id() != std::thread::current().id()
        {
            let _ = thread.join();
        }
    }
}

/// The watch thread: for each sleep announcement it releases first, then lets
/// the sleep go on; for each wake it announces the wake, then locks again.
/// When the monitor's stdout ends it ends, releasing the lock.
fn follow(hooks: Arc<dyn SleepHooks>, events: ChildStdout, mut lock: DelayLock) {
    for line in BufReader::new(events).lines() {
        let Ok(line) = line else {
            break;
        };
        match prepare_for_sleep_line(&line) {
            Some(true) => {
                hooks.will_sleep();
                lock.release();
            }
            Some(false) => {
                hooks.woke();
                lock.retake();
            }
            None => {}
        }
    }
}
