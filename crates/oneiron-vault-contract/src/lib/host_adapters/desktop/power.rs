//! The power source a PluggedIn wake assertion follows (FIX 9547). While a
//! holder set is held, one observer runs: a child that prints a line on each
//! power-source change (`pmset -g pslog` on macOS, the kernel's power-supply
//! events through `udevadm monitor` on Linux), read on a thread of its own.
//! The thread samples the source once the child runs, so no change between
//! the two is missed, and again on each line, and settles the one shared
//! assertion on it: taken on mains power, released on battery. Sampling,
//! spawning and reaping run outside the holders' lock, and a result is kept
//! only while its holder set is the current one. The last holder out kills
//! and reaps the child and joins the thread. Nothing polls on an interval.

use super::{AwakeState, Held, release};
use std::io::{BufRead, BufReader};
use std::process::{Child, ChildStdout, Command, Stdio};
use std::sync::{Arc, Weak};
use std::thread::JoinHandle;

/// A command that prints a line on each power-source change.
pub(super) type Watch = (&'static str, &'static [&'static str]);

/// macOS: each power-source notification, the current source first.
pub(super) const PMSET_WATCH: Watch = ("/usr/bin/pmset", &["-g", "pslog"]);

/// Linux: the kernel's power-supply uevents.
pub(super) const UDEV_WATCH: Watch = (
    "/usr/bin/udevadm",
    &["monitor", "--kernel", "--subsystem-match=power_supply"],
);

/// One holder set's observer: its child, when one started, and its thread.
/// Dropping it kills and reaps the child, then joins the thread.
pub(super) struct PowerObserver {
    child: Option<Child>,
    thread: Option<JoinHandle<()>>,
}

impl PowerObserver {
    /// Starts the observer of holder set `generation` and hands it to
    /// `state`, or stops it at once when that set has already ended. A host
    /// whose changes cannot be observed samples once, as before, and says so
    /// through the host's notice.
    pub(super) fn start(state: &Arc<AwakeState>, generation: u64) {
        let (program, args) = state.watch;
        let mut child = Command::new(program)
            .args(args)
            .env_clear()
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .ok();
        let events = child.as_mut().and_then(|child| child.stdout.take());
        if events.is_none() {
            state.unobserved();
        }
        let weak = Arc::downgrade(state);
        let thread = std::thread::Builder::new()
            .name("oneiron-power".to_owned())
            .spawn({
                let weak = weak.clone();
                move || follow(&weak, generation, events)
            });
        let thread = match thread {
            Ok(thread) => Some(thread),
            Err(_) => {
                state.unobserved();
                settle(&weak, generation);
                None
            }
        };
        let observer = Self { child, thread };
        let stale = match state.held.lock() {
            Ok(mut held) if is_current(&held, generation) => {
                held.observer = Some(observer);
                None
            }
            _ => Some(observer),
        };
        // Stopped outside the lock, which its thread takes.
        drop(stale);
    }
}

impl Drop for PowerObserver {
    fn drop(&mut self) {
        release(self.child.take());
        if let Some(thread) = self.thread.take()
            && thread.thread().id() != std::thread::current().id()
        {
            let _ = thread.join();
        }
    }
}

/// The observer's thread: one sample now, the child already running, then
/// one on each line it prints, until the child ends or the set does.
fn follow(state: &Weak<AwakeState>, generation: u64, events: Option<ChildStdout>) {
    if !settle(state, generation) {
        return;
    }
    let Some(events) = events else {
        return;
    };
    let mut events = BufReader::new(events);
    let mut line = Vec::new();
    while events
        .read_until(b'\n', &mut line)
        .is_ok_and(|read| read > 0)
    {
        line.clear();
        if !settle(state, generation) {
            return;
        }
    }
    // The child ended while its set still holds: changes from here on are
    // not observed.
    if let Some(state) = state.upgrade()
        && state
            .held
            .lock()
            .is_ok_and(|held| is_current(&held, generation))
    {
        state.unobserved();
    }
}

/// Samples the power source and settles holder set `generation`'s one
/// assertion on it. False once that set has ended.
fn settle(state: &Weak<AwakeState>, generation: u64) -> bool {
    let Some(state) = state.upgrade() else {
        return false;
    };
    let mains = on_mains_power();
    let holds = match state.held.lock() {
        Ok(held) if is_current(&held, generation) => held.assertion.is_some(),
        _ => return false,
    };
    if holds == mains {
        return true;
    }
    let mut taken = if mains { state.assertion() } else { None };
    let mut released = None;
    let current = match state.held.lock() {
        Ok(mut held) if is_current(&held, generation) => {
            if mains {
                if held.assertion.is_none() {
                    held.assertion = taken.take();
                }
            } else {
                released = held.assertion.take();
            }
            true
        }
        _ => false,
    };
    release(taken);
    release(released);
    current
}

/// Whether `generation` is the holder set `held` holds now.
fn is_current(held: &Held, generation: u64) -> bool {
    held.holders > 0 && held.generation == generation
}

/// A machine with no battery counts as plugged in.
fn on_mains_power() -> bool {
    if cfg!(target_os = "macos") {
        return Command::new("/usr/bin/pmset")
            .args(["-g", "batt"])
            .env_clear()
            .stderr(Stdio::null())
            .output()
            .is_ok_and(|output| String::from_utf8_lossy(&output.stdout).contains("'AC Power'"));
    }
    let Ok(supplies) = std::fs::read_dir("/sys/class/power_supply") else {
        return true;
    };
    let mut battery = false;
    for supply in supplies.flatten() {
        let read =
            |file: &str| std::fs::read_to_string(supply.path().join(file)).unwrap_or_default();
        match read("type").trim() {
            "Mains" if read("online").trim() == "1" => return true,
            "Battery" => battery = true,
            _ => {}
        }
    }
    !battery
}
