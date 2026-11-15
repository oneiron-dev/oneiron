//! Census row L6-18 (ARCH-0052 threat-model note): a process that holds an
//! off-record overlay writes no core file, by default. Linux only: the
//! dumpable flag is a Linux prctl. This file is its own test binary, so the
//! process-wide change reaches no other test; the operator's off switch is
//! `session_overlay_dump_suppression_off.rs`, in a process of its own. It
//! names only main's paths, so it runs red on main.
#![cfg(any(target_os = "linux", target_os = "android"))]

use std::fs::File;
use std::io::Write as _;
use std::os::fd::AsRawFd as _;

use oneiron_store::session_overlay::SessionOverlay;
use rustix::process::{
    DumpableBehavior, Resource, Rlimit, dumpable_behavior, getrlimit, setrlimit,
};

#[test]
fn an_off_record_overlay_turns_the_process_core_dumps_off() {
    assert_eq!(
        dumpable_behavior().expect("PR_GET_DUMPABLE"),
        DumpableBehavior::Dumpable,
        "a test process starts dumpable"
    );
    // Give the soft core limit room to fall where the host allows a core file.
    let before = getrlimit(Resource::Core);
    if before.maximum != Some(0) {
        setrlimit(
            Resource::Core,
            Rlimit {
                current: before.maximum,
                maximum: before.maximum,
            },
        )
        .expect("raise the soft core limit to the hard one");
    }

    let _overlay = SessionOverlay::new(4096);

    assert_eq!(
        dumpable_behavior().expect("PR_GET_DUMPABLE"),
        DumpableBehavior::NotDumpable,
        "an off-record overlay leaves the process dumpable"
    );
    assert_eq!(
        getrlimit(Resource::Core),
        Rlimit {
            current: Some(0),
            maximum: Some(0),
        },
        "an off-record overlay leaves the core limit up"
    );

    // The store opens a vault root through `/proc/self/fd/<dirfd>`
    // (`Store::open_existing`); a non-dumpable process still reaches its own.
    let root = tempfile::tempdir().expect("temp dir");
    File::create(root.path().join("probe"))
        .and_then(|mut file| file.write_all(b"probe"))
        .expect("write the probe");
    let dir = File::open(root.path()).expect("open the root as a descriptor");
    let fd = dir.as_raw_fd();
    let through_fd = std::fs::read(format!("/proc/self/fd/{fd}/probe"))
        .expect("read through /proc/self/fd after dumps are off");
    assert_eq!(through_fd, b"probe");
}
