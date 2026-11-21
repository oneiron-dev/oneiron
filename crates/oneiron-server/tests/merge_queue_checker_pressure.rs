//! A merge-queue checker guest's pids-limit hits reach the completed run's
//! session manifest ([GUEST-PIDS-PRESSURE-MERGE-QUEUE-CHECKER], FIX 8013
//! follow-up). The isolated executor reads the guest's cgroup `pids.events`
//! through the session's lease after the helper's terminal frame, while its
//! container still runs (a held session: it ends when the helper's input
//! closes), and the run's receipt carries what it read. The door hands its
//! session only to a held start. The session here is a container session on
//! a fake runtime whose `inspect` names a scratch cgroup directory; the real
//! launcher's hold is proven by `oneiron-container`'s
//! `fence_launcher_stdin_hold` test.
#![cfg(all(oneiron_test_support, target_os = "linux"))]

use oneiron::merge_queue::QueueCheckExecution;
use oneiron_container::{
    ContainerRuntime, GuestLimits, GuestPressure, GuestSeccomp, GuestSpec, ImageRef,
};
use oneiron_server::test_doors::merge_queue_checker_pressure::run_empty_isolated_check;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

const IMAGE: &str = concat!(
    "example.invalid/checker@sha256:",
    "0000000000000000000000000000000000000000000000000000000000000000",
);
const HITS: u64 = 7;

/// A fake container CLI: `run` stays up as the guest until the session's
/// drop kills it, `inspect` names `cgroup` as the container's cgroup, and
/// anything else (the drop's `rm --force`) exits quietly.
fn fake_runtime(dir: &Path, cgroup: &Path) -> PathBuf {
    let program = dir.join("container-runtime");
    let script = [
        "#!/bin/sh".to_owned(),
        "case \"$1\" in".to_owned(),
        "  run) exec sleep 300 ;;".to_owned(),
        format!(
            "  inspect) printf '%s' '[{{\"State\":{{\"CgroupPath\":\"{}\"}}}}]' ;;",
            cgroup.display()
        ),
        "esac".to_owned(),
        "exit 0".to_owned(),
    ]
    .join("\n");
    std::fs::write(&program, script).expect("fake runtime script");
    std::fs::set_permissions(&program, std::fs::Permissions::from_mode(0o755))
        .expect("fake runtime is executable");
    program
}

#[test]
fn completed_check_session_names_guest_pids_pressure() {
    let dir = tempfile::tempdir().expect("temp dir");
    let cgroup = dir.path().join("cgroup");
    std::fs::create_dir_all(&cgroup).expect("scratch cgroup dir");
    std::fs::write(cgroup.join("pids.events"), format!("max {HITS}\n")).expect("pids.events");
    let runtime =
        ContainerRuntime::new(fake_runtime(dir.path(), &cgroup)).expect("fake runtime binds");
    let spec = GuestSpec {
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
    };
    let session = runtime.start(&spec).expect("guest starts");
    let manifest = session.manifest().clone();
    assert_eq!(manifest.guest_pressure, None, "nothing read at start");
    let ran = run_empty_isolated_check(Box::new(session), manifest).expect("the check runs");
    let run = match ran {
        QueueCheckExecution::Completed(run) => run,
        other => panic!("the empty check completes: {other:?}"),
    };
    let session = run.session.expect("an isolated run names its session");
    assert_eq!(
        session.guest_pressure,
        Some(GuestPressure::Processes { hits: HITS }),
        "the run's session manifest names the guest's pids-limit hits"
    );
}
