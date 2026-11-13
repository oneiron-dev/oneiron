//! Core-dump suppression for a process that holds off-record room bytes
//! (ARCH-0052 threat-model note: "zeroize/dump-suppression is a follow-up
//! hardening ticket, not a launch gate").
//!
//! The overlay already scrubs its rows when they drop (`keyspace.rs`). This
//! keeps a live overlay out of a core file and away from a same-user
//! debugger. The first [`SessionOverlay`](super::SessionOverlay) a process
//! makes turns its core dumps off for the rest of the process's life:
//! freed pages may still hold a room's bytes after the room closes.
//!
//! - Linux and Android: `prctl(PR_SET_DUMPABLE, 0)`, so the kernel writes no
//!   core file and a debugger needs `CAP_SYS_PTRACE` to attach, plus
//!   `RLIMIT_CORE` set to zero.
//! - Other unix (macOS, iOS): `RLIMIT_CORE` set to zero.
//! - Windows: nothing yet.
//!
//! A failed call logs a warning and the room still opens, since the canon
//! makes this hardening, not a gate. The process keeps its own `/proc/self`
//! and `/proc/self/fd` paths (the kernel allows a task its own thread
//! group's), so `Store::open_existing`'s `/proc/self/fd/<dirfd>` door still
//! works. A child started with `execve` is dumpable again.

use std::sync::Once;

static SUPPRESSED: Once = Once::new();

/// Turns this process's core dumps off, once per process.
pub(crate) fn suppress_process_dumps() {
    SUPPRESSED.call_once(|| {
        clear_dumpable();
        zero_core_limit();
    });
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn clear_dumpable() {
    use rustix::process::{DumpableBehavior, set_dumpable_behavior};

    if let Err(error) = set_dumpable_behavior(DumpableBehavior::NotDumpable) {
        tracing::warn!(
            %error,
            "off-record overlay: PR_SET_DUMPABLE 0 failed; this process stays dumpable"
        );
    }
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn clear_dumpable() {}

#[cfg(unix)]
fn zero_core_limit() {
    use rustix::process::{Resource, Rlimit, setrlimit};

    let none = Rlimit {
        current: Some(0),
        maximum: Some(0),
    };
    if let Err(error) = setrlimit(Resource::Core, none) {
        tracing::warn!(
            %error,
            "off-record overlay: RLIMIT_CORE 0 failed; this process may still write a core file"
        );
    }
}

#[cfg(not(unix))]
fn zero_core_limit() {}
