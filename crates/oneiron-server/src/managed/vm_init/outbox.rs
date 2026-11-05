//! The outbox companion beside the engine (FIX 5235, FIX 5467): the
//! bootstrap starts `oneiron-vm-outbox` before the engine, restarts it if
//! it exits while the engine serves (FIX 11072), and reaps it before the
//! encrypted storage's key is removed.
//!
//! The companion's `ready` line means its outbox is laid out and its
//! endpoint bound; only then does the engine get its outbox flags. A
//! companion that does not come up leaves the engine to start without them,
//! as before the carrier: no outbox is ever a reason not to serve.
//! A replacement's readiness is read without blocking engine supervision.

use oneiron_vault_contract::vm_outbox::VM_GUEST_OUTBOX_DIR;
use rustix::fs::{OFlags, fcntl_getfl, fcntl_setfl};
use std::ffi::OsString;
use std::io::{self, BufRead, BufReader};
use std::path::Path;
use std::process::{Child, ChildStdout, Stdio};

/// The companion, beside the bootstrap in the image.
const COMPANION: &str = "/usr/bin/oneiron-vm-outbox";

/// The initially admitted companion and any replacement, owned until reaped.
pub(super) struct Companion(Option<Process>);

struct Process {
    child: Child,
    starting: Option<Starting>,
}

struct Starting {
    output: BufReader<ChildStdout>,
    line: String,
}

fn spawn(vault: &str, uid: u32, path: &str, resuming: bool) -> io::Result<Child> {
    let mut command = oneiron_spawn::command(COMPANION);
    if resuming {
        command.arg("--resume-state");
    }
    command
        .arg("--vault-name")
        .arg(vault)
        .arg("--uid")
        .arg(uid.to_string())
        .env_clear()
        .env("PATH", path)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .spawn()
}

/// Starts the companion for `vault`, writing as `uid`, and waits for its
/// `ready` line. `None` when it does not start or ends first.
pub(super) fn start(vault: &str, uid: u32, path: &str) -> Option<Companion> {
    let mut child = match spawn(vault, uid, path, false) {
        Ok(child) => child,
        Err(error) => {
            eprintln!(
                "oneiron-vm-init: the outbox companion did not start ({error}); the engine runs \
                 without its outboxes"
            );
            return None;
        }
    };
    let mut line = String::new();
    let ready = child
        .stdout
        .take()
        .is_some_and(|out| BufReader::new(out).read_line(&mut line).is_ok())
        && line.trim_end() == "ready";
    if ready {
        return Some(Companion(Some(Process {
            child,
            starting: None,
        })));
    }
    eprintln!(
        "oneiron-vm-init: the outbox companion did not come up; the engine runs without its \
         outboxes"
    );
    kill_and_wait(child);
    None
}

/// Starts a replacement without waiting for its readiness line.
fn restart(vault: &str, uid: u32, path: &str) -> Option<Process> {
    let mut child = match spawn(vault, uid, path, true) {
        Ok(child) => child,
        Err(error) => {
            eprintln!("oneiron-vm-init: restarting the outbox companion failed: {error}");
            return None;
        }
    };
    if let Some(output) = child.stdout.take() {
        match fcntl_getfl(&output).and_then(|flags| fcntl_setfl(&output, flags | OFlags::NONBLOCK))
        {
            Ok(()) => {
                return Some(Process {
                    child,
                    starting: Some(Starting {
                        output: BufReader::new(output),
                        line: String::new(),
                    }),
                });
            }
            Err(error) => {
                eprintln!(
                    "oneiron-vm-init: preparing the companion's readiness pipe failed: {error}"
                );
            }
        }
    }
    kill_and_wait(child);
    None
}

fn kill_and_wait(mut child: Child) {
    let _ = child.kill();
    if let Err(error) = child.wait() {
        eprintln!("oneiron-vm-init: waiting for the outbox companion failed: {error}");
    }
}

/// The engine's outbox flags: the companion's admission itself, then its
/// flags at the guest paths it laid out, with each escrow recipient the
/// host has already sent.
pub(super) fn engine_flags() -> Vec<OsString> {
    let outbox = Path::new(VM_GUEST_OUTBOX_DIR);
    let mut flags: Vec<OsString> = Vec::new();
    // The admission, not a path: only this constructor runs with a companion
    // beside the engine, so presence records that initial admission.
    flags.push("--vm-outbox-companion-admitted".into());
    for (flag, dir) in [
        ("--escrow-outbox-dir", "escrow"),
        ("--esign-delivery-outbox-dir", "esign"),
        ("--publisher-training-outbox-dir", "training"),
    ] {
        flags.push(flag.into());
        flags.push(outbox.join(dir).into());
    }
    for (flag, file) in [
        ("--escrow-recipient-file", "managed.pub"),
        ("--break-glass-recipient-file", "break-glass.pub"),
    ] {
        let path = outbox.join("recipients").join(file);
        if path.is_file() {
            flags.push(flag.into());
            flags.push(path.into());
        }
    }
    flags
}

impl Companion {
    /// Runs once per existing engine-supervision tick. A failed attempt is
    /// retried on a later tick, never in a loop inside engine supervision.
    pub(super) fn refresh(&mut self, vault: &str, uid: u32, path: &str) {
        let Some(process) = self.0.as_mut() else {
            self.0 = restart(vault, uid, path);
            return;
        };
        match process.child.try_wait() {
            Ok(Some(status)) => {
                eprintln!("oneiron-vm-init: the outbox companion exited ({status}); restarting");
                // try_wait reaped it; never signal this PID through a stale handle.
                self.0 = None;
                return;
            }
            Ok(None) => {}
            Err(error) => {
                eprintln!("oneiron-vm-init: polling the outbox companion failed: {error}");
                return;
            }
        }
        let Some(starting) = process.starting.as_mut() else {
            return;
        };
        match starting.output.read_line(&mut starting.line) {
            Ok(_) if starting.line.trim_end() == "ready" => {
                process.starting = None;
                eprintln!("oneiron-vm-init: the replacement outbox companion is ready");
            }
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                ) => {}
            _ => {
                eprintln!("oneiron-vm-init: the replacement outbox companion did not come up");
                if let Some(process) = self.0.take() {
                    kill_and_wait(process.child);
                }
            }
        }
    }

    /// Stops and reaps the owned child. An observed-ready companion drains
    /// as before; an unconfirmed start is killed rather than waiting for a
    /// readiness line or for a stop handler it may not have armed yet.
    pub(super) fn stop(self) {
        let Some(mut process) = self.0 else {
            return;
        };
        if process.starting.is_some() {
            kill_and_wait(process.child);
            return;
        }
        if matches!(process.child.try_wait(), Ok(Some(_))) {
            return;
        }
        if let Ok(pid) = libc::pid_t::try_from(process.child.id()) {
            // SAFETY: kill takes no pointers; `pid` is this process's own
            // child, not yet reaped, so the number is still its.
            unsafe { libc::kill(pid, libc::SIGTERM) };
        }
        if let Err(error) = process.child.wait() {
            eprintln!("oneiron-vm-init: waiting for the outbox companion failed: {error}");
        }
    }
}
