//! A guest's pids-limit hits read through its session lease (FIX 8013
//! follow-ups [GUEST-PIDS-PRESSURE-MERGE-QUEUE-CHECKER] and
//! [GUEST-PIDS-PRESSURE-BROWSER-DESKTOP]): a backend's `start_session`
//! hands its caller a `Box<dyn SessionLease>`, and the merge-queue checker,
//! the browser and the desktop read the guest's `pids.events` through it.
//! The runtime is inspected once per session to find that file, so a read
//! at every browser verb costs one file read.
#![cfg(target_os = "linux")]

use oneiron_container::{
    ContainerRuntime, GuestLimits, GuestPressure, GuestSeccomp, GuestSpec, ImageRef,
};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

const IMAGE: &str = concat!(
    "example.invalid/guest@sha256:",
    "0000000000000000000000000000000000000000000000000000000000000000",
);

/// A fake container CLI. `run` stays up as the guest until the session's
/// drop kills it; `inspect` notes each call in `inspects` and names `cgroup`
/// as the container's cgroup; anything else (the drop's `rm --force`) exits
/// quietly.
fn fake_runtime(dir: &Path, cgroup: &Path) -> PathBuf {
    let program = dir.join("container-runtime");
    let inspects = dir.join("inspects").display().to_string();
    let script = [
        "#!/bin/sh".to_owned(),
        "case \"$1\" in".to_owned(),
        "  run) exec sleep 300 ;;".to_owned(),
        "  inspect)".to_owned(),
        format!("    echo inspect >> \"{inspects}\""),
        format!(
            "    printf '%s' '[{{\"State\":{{\"CgroupPath\":\"{}\"}}}}]'",
            cgroup.display()
        ),
        "    ;;".to_owned(),
        "esac".to_owned(),
        "exit 0".to_owned(),
    ]
    .join("\n");
    std::fs::write(&program, script).expect("fake runtime script");
    std::fs::set_permissions(&program, std::fs::Permissions::from_mode(0o755))
        .expect("fake runtime is executable");
    program
}

fn spec() -> GuestSpec {
    GuestSpec {
        image: ImageRef::pinned(IMAGE).expect("pinned image"),
        user: (10001, 10001),
        limits: GuestLimits {
            memory_mib: 256,
            cpu_millis: 1000,
            pids: 64,
            tmpfs_mib: 64,
        },
        seccomp: GuestSeccomp::RuntimeDefault,
        read_only_mounts: Vec::new(),
    }
}

/// A scratch cgroup directory whose `pids.events` reads `max <hits>`.
fn cgroup_with_hits(dir: &Path, hits: u64) -> PathBuf {
    let cgroup = dir.join("cgroup");
    std::fs::create_dir_all(&cgroup).expect("scratch cgroup dir");
    set_hits(&cgroup, hits);
    cgroup
}

fn set_hits(cgroup: &Path, hits: u64) {
    std::fs::write(cgroup.join("pids.events"), format!("max {hits}\n")).expect("pids.events");
}

fn inspect_count(dir: &Path) -> usize {
    std::fs::read_to_string(dir.join("inspects"))
        .map(|text| text.lines().count())
        .unwrap_or(0)
}

#[test]
fn session_lease_reads_the_guest_pids_pressure() {
    let dir = tempfile::tempdir().expect("temp dir");
    let cgroup = cgroup_with_hits(dir.path(), 5);
    let runtime = ContainerRuntime::new(fake_runtime(dir.path(), &cgroup)).expect("runtime");
    let session = runtime.start(&spec()).expect("guest starts");
    // What a backend's start_session hands the checker, browser and desktop.
    let transport = session.into_transport().expect("transport");
    assert_eq!(
        transport.lease.observe_pressure(),
        Some(GuestPressure::Processes { hits: 5 }),
        "the lease reads the guest's pids.events"
    );
    set_hits(&cgroup, 9);
    assert_eq!(
        transport.lease.observe_pressure(),
        Some(GuestPressure::Processes { hits: 9 }),
        "a later read sees the count as it stands"
    );
    drop(transport);
}

#[test]
fn pressure_reads_inspect_the_runtime_once_per_session() {
    let dir = tempfile::tempdir().expect("temp dir");
    let cgroup = cgroup_with_hits(dir.path(), 3);
    let runtime = ContainerRuntime::new(fake_runtime(dir.path(), &cgroup)).expect("runtime");
    let session = runtime.start(&spec()).expect("guest starts");
    assert_eq!(
        session.observe_pressure(),
        Some(GuestPressure::Processes { hits: 3 })
    );
    set_hits(&cgroup, 4);
    assert_eq!(
        session.observe_pressure(),
        Some(GuestPressure::Processes { hits: 4 })
    );
    assert_eq!(
        inspect_count(dir.path()),
        1,
        "the second read reads the file it found, with no inspect of its own"
    );
    drop(session);
}
