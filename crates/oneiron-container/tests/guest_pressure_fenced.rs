//! A fenced guest's pids-pressure reads (FIX
//! [GUEST-PRESSURE-FENCED-ZERO-INSPECT-UNTESTED]): `observe_pressure` says
//! a fenced session never inspects its runtime, because the fence proof's
//! own inspect already named the guest's cgroup. The fake container CLI here
//! runs the real fence launcher in place of a container, so `start_fenced`
//! makes a real fence proof, and the test counts the CLI's `inspect` calls
//! around the session's pressure reads.
//!
//! The launcher refuses root and any capability, and its proof needs
//! Landlock ABI 3 and no seccomp listener above it; on a host that cannot
//! run it the test prints a SKIPPED line and returns.
#![cfg(target_os = "linux")]

use oneiron_container::{
    ContainerRuntime, EgressRelay, GuestLimits, GuestPressure, GuestSeccomp, GuestSpec,
    HostNetFloor, HttpRequest, HttpResponse, ImageRef, SessionManifest, UnmeteredFloor,
    landlock_abi,
};
use std::ffi::OsString;
use std::io;
use std::net::{SocketAddr, TcpStream};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

const IMAGE: &str = concat!(
    "example.invalid/guest@sha256:",
    "0000000000000000000000000000000000000000000000000000000000000000",
);
const LAUNCHER_ENV: &str = "ONEIRON_FENCE_LAUNCHER";

/// The guest reaches nothing; its command makes no network call.
struct NoEgress;

fn refused() -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, "this test has no egress")
}

impl EgressRelay for NoEgress {
    fn connect(&self, _target: SocketAddr) -> io::Result<TcpStream> {
        Err(refused())
    }

    fn authorize_datagram(&self, _target: SocketAddr) -> io::Result<()> {
        Err(refused())
    }

    fn record_session(&self, _manifest: &SessionManifest) -> io::Result<()> {
        Ok(())
    }

    fn record_abandoned(&self, _manifest: &SessionManifest) -> io::Result<()> {
        Ok(())
    }

    fn datagram(&self, _target: SocketAddr, _bytes: &[u8]) -> io::Result<Vec<u8>> {
        Err(refused())
    }

    fn fetch(&self, _request: HttpRequest) -> io::Result<HttpResponse> {
        Err(refused())
    }

    fn transferred(&self, _target: SocketAddr, _content_hash: [u8; 32], _bytes: u64) {}

    fn host_net_floor(&self) -> &dyn HostNetFloor {
        &UnmeteredFloor
    }
}

/// Why this host cannot run the launcher, if it cannot: the launcher
/// refuses root and any capability, and its proof needs Landlock ABI 3.
fn fence_unavailable() -> Option<String> {
    let status = match std::fs::read_to_string("/proc/self/status") {
        Ok(status) => status,
        Err(error) => return Some(format!("no /proc/self/status: {error}")),
    };
    let field = |name: &str| {
        status
            .lines()
            .find_map(|line| line.strip_prefix(name))
            .map(str::trim)
            .unwrap_or("")
            .to_owned()
    };
    if field("Uid:").split_whitespace().nth(1) == Some("0") {
        return Some("runs as root".to_owned());
    }
    let capabilities = field("CapEff:");
    if capabilities.is_empty() || capabilities.bytes().any(|b| b != b'0') {
        return Some(format!("effective capabilities {capabilities:?}"));
    }
    let abi = landlock_abi();
    if abi < 3 {
        return Some(format!("Landlock ABI {abi}"));
    }
    None
}

/// A fake container CLI. `run` reads the fence directory from the mount the
/// engine passes for `/run/oneiron-fence`, writes its own pid to
/// `container.pid`, and becomes the fence launcher on that directory's
/// bridge socket, so the launcher is the container's process. `inspect`
/// notes each call in `inspects` and answers the evidence a fence proof
/// checks, with `cgroup` as the container's cgroup. Anything else (the
/// drop's `rm --force`) exits quietly.
fn fake_runtime(dir: &Path, cgroup: &Path) -> PathBuf {
    let program = dir.join("container-runtime");
    let pid_file = dir.join("container.pid").display().to_string();
    let inspects = dir.join("inspects").display().to_string();
    let launcher = env!("CARGO_BIN_EXE_oneiron-fence");
    let evidence = format!(
        concat!(
            "[{{\"State\":{{\"Pid\":%s,\"CgroupPath\":\"{cgroup}\"}},",
            "\"HostConfig\":{{\"NetworkMode\":\"none\",\"Privileged\":false,",
            "\"ReadonlyRootfs\":true,\"CapDrop\":[\"ALL\"],",
            "\"SecurityOpt\":[\"no-new-privileges\"]}},",
            "\"Config\":{{\"User\":\"10001:10001\"}}}}]"
        ),
        cgroup = cgroup.display(),
    );
    let script = [
        "#!/bin/sh".to_owned(),
        "case \"$1\" in".to_owned(),
        "  run)".to_owned(),
        "    shift".to_owned(),
        "    fence_dir=".to_owned(),
        "    while [ $# -gt 0 ]; do".to_owned(),
        "      case \"$1\" in".to_owned(),
        "        --mount=type=bind,readonly,src=*,dst=/run/oneiron-fence)".to_owned(),
        "          fence_dir=${1#--mount=type=bind,readonly,src=}".to_owned(),
        "          fence_dir=${fence_dir%,dst=/run/oneiron-fence}".to_owned(),
        "          ;;".to_owned(),
        "        /run/oneiron-fence/bridge.sock)".to_owned(),
        "          shift".to_owned(),
        "          break".to_owned(),
        "          ;;".to_owned(),
        "      esac".to_owned(),
        "      shift".to_owned(),
        "    done".to_owned(),
        format!("    echo $$ > \"{pid_file}\""),
        format!("    exec \"{launcher}\" \"$fence_dir/bridge.sock\" \"$@\""),
        "    ;;".to_owned(),
        "  inspect)".to_owned(),
        format!("    echo inspect >> \"{inspects}\""),
        format!("    printf '{evidence}' \"$(cat \"{pid_file}\")\""),
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

// One test in this file: it sets the launcher's environment variable, which
// no other thread of this test binary reads or writes.
#[test]
fn a_fenced_session_reads_its_pressure_with_no_inspect_of_its_own() {
    if let Some(reason) = fence_unavailable() {
        eprintln!("guest_pressure_fenced: SKIPPED: {reason}");
        return;
    }
    let dir = tempfile::tempdir().expect("temp dir");
    let cgroup = cgroup_with_hits(dir.path(), 5);
    let runtime = ContainerRuntime::new(fake_runtime(dir.path(), &cgroup)).expect("runtime");
    // SAFETY: this file holds one test, and its harness starts no other
    // thread that reads or writes the environment while this one sets it.
    unsafe { std::env::set_var(LAUNCHER_ENV, env!("CARGO_BIN_EXE_oneiron-fence")) };
    let command = [OsString::from("/bin/sleep"), OsString::from("60")];
    let session = match runtime.start_fenced(&spec(), &command, Arc::new(NoEgress)) {
        Ok(session) => session,
        Err(error) => {
            // A seccomp listener above this process (a sandboxed CI box)
            // makes the launcher's own listener fail with EBUSY: the host
            // cannot run the fence. Every other failure is this test's.
            let text = error.to_string();
            if text.contains("Device or resource busy") {
                eprintln!("guest_pressure_fenced: SKIPPED: {text}");
                return;
            }
            panic!("the fenced start failed: {text}");
        }
    };
    assert!(
        session.manifest().fence_proof.is_some() && !session.manifest().fence_unproven,
        "the session is fenced and its manifest carries the fence proof"
    );
    let at_start = inspect_count(dir.path());
    assert!(
        at_start >= 1,
        "the fence proof inspected the container ({at_start} inspects)"
    );
    assert_eq!(
        session.observe_pressure(),
        Some(GuestPressure::Processes { hits: 5 }),
        "the fenced session reads the cgroup its proof named"
    );
    set_hits(&cgroup, 8);
    assert_eq!(
        session.observe_pressure(),
        Some(GuestPressure::Processes { hits: 8 }),
        "a later read sees the count as it stands"
    );
    assert_eq!(
        inspect_count(dir.path()),
        at_start,
        "a fenced session's pressure reads read the file its proof found, with no inspect of their own"
    );
    drop(session);
}
