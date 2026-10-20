//! The outbox companion beside the engine (FIX 5235, FIX 5467): the
//! bootstrap starts `oneiron-vm-outbox` as its own child once the guest is
//! provisioned, before the engine, and stops it once the engine exited,
//! before anything else is ended and before the key is removed, since the
//! companion writes into the encrypted storage.
//!
//! The companion's `ready` line means its outbox is laid out and its
//! endpoint bound; only then does the engine get its outbox flags. A
//! companion that does not come up leaves the engine to start without them,
//! as before the carrier: no outbox is ever a reason not to serve.

use oneiron_vault_contract::vm_outbox::VM_GUEST_OUTBOX_DIR;
use std::ffi::OsString;
use std::io::{BufRead, BufReader};
use std::path::Path;
use std::process::{Child, Stdio};

/// The companion, beside the bootstrap in the image.
const COMPANION: &str = "/usr/bin/oneiron-vm-outbox";

/// A running companion.
pub(super) struct Companion(Child);

/// Starts the companion for `vault`, writing as `uid`, and waits for its
/// `ready` line. `None` when it does not start or ends first.
pub(super) fn start(vault: &str, uid: u32, path: &str) -> Option<Companion> {
    let mut command = oneiron_spawn::command(COMPANION);
    command
        .arg("--vault-name")
        .arg(vault)
        .arg("--uid")
        .arg(uid.to_string())
        .env_clear()
        .env("PATH", path)
        .stdin(Stdio::null())
        .stdout(Stdio::piped());
    let mut child = match command.spawn() {
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
        return Some(Companion(child));
    }
    eprintln!(
        "oneiron-vm-init: the outbox companion did not come up; the engine runs without its \
         outboxes"
    );
    let _ = child.kill();
    let _ = child.wait();
    None
}

/// The engine's outbox flags, at the guest paths the companion laid out,
/// with each escrow recipient the host has already sent.
pub(super) fn engine_flags() -> Vec<OsString> {
    let outbox = Path::new(VM_GUEST_OUTBOX_DIR);
    let mut flags: Vec<OsString> = Vec::new();
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
    /// Stops the companion and waits for it, with no deadline: it finishes
    /// a local commit in flight, parks a network transfer for its next boot
    /// and exits.
    pub(super) fn stop(mut self) {
        if let Ok(pid) = libc::pid_t::try_from(self.0.id()) {
            // SAFETY: kill takes no pointers; `pid` is this process's own
            // child, not yet waited for, so the number is still its.
            unsafe { libc::kill(pid, libc::SIGTERM) };
        }
        if let Err(error) = self.0.wait() {
            eprintln!("oneiron-vm-init: waiting for the outbox companion failed: {error}");
        }
    }
}
