//! An organ starts whole while another thread frees and reuses fd 3, the
//! number the organ's socket takes in the child (FIX
//! [MESH-ASK-CARRIED-HANDSHAKE-CUT-SHORT]). The host makes the descriptors
//! the child uses before exec (its status pipe's writer, its Landlock
//! ruleset) while the engine's other threads open and close files, so any
//! of them can be numbered 3; the child's socket then took that number
//! first. A status writer there sent the child's eight status bytes down
//! the organ socket and the handshake failed ("no hello_ack: frame decode:
//! the encoding is cut short"); a ruleset there was the socket when the
//! child restricted itself, and the start failed. Alone in its own test
//! binary, so no other test holds fd 3.
#![cfg(target_os = "linux")]

use std::os::fd::AsRawFd;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::thread;

use oneiron_organ_host::{HostConfig, OrganHost, OrganSpec};

const PROBE: &str = env!("CARGO_BIN_EXE_oneiron-organ-probe");

/// Organ starts, each in a host of its own.
const STARTS: usize = 400;

/// Moves an fd 3 this binary inherited (a runner's descriptor) to a higher
/// number, so that 3 is free for the starts and the reusing thread.
fn free_fd_3() {
    if std::fs::read_link("/proc/self/fd/3").is_err() {
        return;
    }
    // SAFETY: fcntl on fd 3, which this process holds; the copy it makes
    // stays open, close-on-exec, and keeps what fd 3 named.
    let moved = unsafe { libc::fcntl(3, libc::F_DUPFD_CLOEXEC, 64) };
    assert!(moved > 3, "the inherited fd 3 could not be moved");
    // SAFETY: close of fd 3, whose open file `moved` still holds; nothing in
    // this binary refers to fd 3 by number.
    let closed = unsafe { libc::close(3) };
    assert_eq!(closed, 0, "the inherited fd 3 closes");
}

#[test]
fn organs_start_whole_while_fd_3_is_freed_and_reused() {
    free_fd_3();
    let stop = Arc::new(AtomicBool::new(false));
    let held_3 = Arc::new(AtomicUsize::new(0));
    let reusing = {
        let stop = Arc::clone(&stop);
        let held_3 = Arc::clone(&held_3);
        thread::spawn(move || {
            while !stop.load(Ordering::Relaxed) {
                // The lowest free number: 3 whenever no start holds it.
                let file = std::fs::File::open("/dev/null").expect("/dev/null opens");
                if file.as_raw_fd() == 3 {
                    held_3.fetch_add(1, Ordering::Relaxed);
                }
            }
        })
    };
    let mut failed = Vec::new();
    for n in 0..STARTS {
        let host = OrganHost::new(HostConfig::default());
        host.install(OrganSpec::first_party("probe", PROBE));
        if let Err(err) = host.warm("probe") {
            failed.push(format!("start {n}: {err}"));
        }
    }
    stop.store(true, Ordering::Relaxed);
    reusing.join().expect("the reusing thread ends");
    assert!(
        held_3.load(Ordering::Relaxed) > 0,
        "the reusing thread never held fd 3, so nothing was tested"
    );
    assert!(
        failed.is_empty(),
        "{} of {STARTS} starts failed while fd 3 was freed and reused: {failed:?}",
        failed.len()
    );
}
