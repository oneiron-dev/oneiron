//! The pids limit a container launch passes: physical, not the manifest count.
#![cfg(unix)]

use oneiron_container::{ContainerRuntime, GuestLimits, GuestSeccomp, GuestSpec, ImageRef};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

const IMAGE: &str = concat!(
    "example.invalid/guest@sha256:",
    "0000000000000000000000000000000000000000000000000000000000000000",
);

/// A fake container CLI: on `run` it records its arguments and exits, on
/// anything else (the session drop's `rm --force`) it exits quietly.
fn fake_runtime(dir: &Path) -> PathBuf {
    let program = dir.join("container-runtime");
    let out = dir.join("run-args").display().to_string();
    let script = [
        "#!/bin/sh".to_owned(),
        "if [ \"$1\" = \"run\" ]; then".to_owned(),
        format!("  : > \"{out}\""),
        "  for arg in \"$@\"; do".to_owned(),
        format!("    printf '%s\\n' \"$arg\" >> \"{out}\""),
        "  done".to_owned(),
        "fi".to_owned(),
        "exit 0".to_owned(),
    ]
    .join("\n");
    std::fs::write(&program, script).expect("fake runtime script");
    std::fs::set_permissions(&program, std::fs::Permissions::from_mode(0o755))
        .expect("fake runtime is executable");
    program
}

fn spec(memory_mib: u32, pids: u32) -> GuestSpec {
    GuestSpec {
        image: ImageRef::pinned(IMAGE).expect("pinned image"),
        user: (10001, 10001),
        limits: GuestLimits {
            memory_mib,
            cpu_millis: 1000,
            pids,
            tmpfs_mib: 64,
        },
        seccomp: GuestSeccomp::RuntimeDefault,
        read_only_mounts: Vec::new(),
    }
}

/// The fake runtime's recorded `run` arguments, once it wrote them all: the
/// image goes last, so its line marks a complete write.
fn read_run_args(dir: &Path) -> Vec<String> {
    let path = dir.join("run-args");
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Ok(text) = std::fs::read_to_string(&path) {
            let args: Vec<String> = text.lines().map(str::to_owned).collect();
            if args.last().is_some_and(|last| last == IMAGE) {
                return args;
            }
        }
        assert!(
            Instant::now() < deadline,
            "the fake runtime never recorded its run"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn pids_limit(args: &[String]) -> Option<u32> {
    args.iter()
        .find_map(|arg| arg.strip_prefix("--pids-limit=")?.parse().ok())
}

#[test]
fn launch_scales_a_small_pids_count_to_guest_memory() {
    let dir = tempfile::tempdir().expect("temp dir");
    let runtime = ContainerRuntime::new(fake_runtime(dir.path())).expect("runtime");
    let session = runtime.start(&spec(512, 16)).expect("guest starts");
    let args = read_run_args(dir.path());
    let limit = pids_limit(&args).expect("a --pids-limit flag");
    assert!(
        limit > 16,
        "a 512 MiB guest holds more tasks than its manifest 16: {limit}"
    );
    drop(session);
}

#[test]
fn launch_keeps_a_large_pids_count_on_small_memory() {
    let dir = tempfile::tempdir().expect("temp dir");
    let runtime = ContainerRuntime::new(fake_runtime(dir.path())).expect("runtime");
    let session = runtime.start(&spec(1, 4096)).expect("guest starts");
    let args = read_run_args(dir.path());
    let limit = pids_limit(&args).expect("a --pids-limit flag");
    assert!(
        (32..=4096).contains(&limit),
        "a 4096 manifest on 1 MiB stays within [32, 4096]: {limit}"
    );
    drop(session);
}
