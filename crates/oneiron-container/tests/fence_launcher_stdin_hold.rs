//! The fence launcher's stdin hold (FIX 8013): a launcher started with
//! `ONEIRON_FENCE_HOLD_UNTIL_STDIN_CLOSES` outlives its fenced command until
//! its stdin closes, so the host still reads the container's cgroup after the
//! guest's last frame, and the guest's stdout still ends with the guest. A
//! launcher started without it exits with its command, as before.
#![cfg(target_os = "linux")]

use oneiron_container::{
    EgressRelay, HostNetFloor, HttpRequest, HttpResponse, NativeFenceGuard, SessionManifest,
    UnmeteredFloor, landlock_abi, serve_native_fence,
};
use std::io::{self, Read};
use std::net::{SocketAddr, TcpStream};
use std::os::unix::net::UnixListener;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::{Arc, mpsc};
use std::time::{Duration, Instant};

const HOLD_ENV: &str = "ONEIRON_FENCE_HOLD_UNTIL_STDIN_CLOSES";
const GENERATION: &str = "fence-launcher-stdin-hold";
/// The fenced command's exit code, which the launcher passes on.
const GUEST_EXIT: i32 = 3;

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

struct Launched {
    child: Child,
    _fence: NativeFenceGuard,
    _dir: tempfile::TempDir,
}

/// The built launcher over `sh -c 'exit 3'`, proven to a native fence
/// supervisor; `None`, with the reason printed, on a host that cannot run it.
fn launch(hold: bool) -> Option<Launched> {
    if let Some(reason) = fence_unavailable() {
        eprintln!("fence_launcher_stdin_hold: SKIPPED: {reason}");
        return None;
    }
    let dir = tempfile::tempdir().expect("temp dir");
    let socket = dir.path().join("bridge.sock");
    let listener = UnixListener::bind(&socket).expect("bridge socket");
    let mut command = Command::new(env!("CARGO_BIN_EXE_oneiron-fence"));
    command
        .arg(&socket)
        .arg(GENERATION)
        .arg("1000")
        .arg("--")
        .arg("/bin/sh")
        .arg("-c")
        .arg(format!("exit {GUEST_EXIT}"))
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if hold {
        command.env(HOLD_ENV, "1");
    }
    let mut child = command.spawn().expect("the launcher starts");
    let pid = i32::try_from(child.id()).expect("a pid fits i32");
    match serve_native_fence(listener, pid, GENERATION, Arc::new(NoEgress)) {
        Ok(fence) => Some(Launched {
            child,
            _fence: fence,
            _dir: dir,
        }),
        Err(error) => {
            if let Ok(Some(status)) = child.try_wait() {
                let mut stderr = String::new();
                if let Some(mut pipe) = child.stderr.take() {
                    let _ = pipe.read_to_string(&mut stderr);
                }
                eprintln!(
                    "fence_launcher_stdin_hold: SKIPPED: the launcher ended ({status}) before its proof ({error}): {stderr}"
                );
                return None;
            }
            let _ = child.kill();
            let _ = child.wait();
            panic!("the launcher runs, but its fence proof failed: {error}");
        }
    }
}

/// The child's exit status once it exits within `limit`; killed otherwise.
fn wait_within(child: &mut Child, limit: Duration) -> Option<ExitStatus> {
    let deadline = Instant::now() + limit;
    loop {
        if let Some(status) = child.try_wait().expect("launcher status") {
            return Some(status);
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return None;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn a_held_launcher_outlives_its_guest_until_stdin_closes() {
    let Some(mut launched) = launch(true) else {
        return;
    };
    let mut stdout = launched.child.stdout.take().expect("launcher stdout");
    let (sender, ended) = mpsc::channel();
    std::thread::spawn(move || {
        let mut bytes = Vec::new();
        let _ = sender.send(stdout.read_to_end(&mut bytes));
    });
    ended
        .recv_timeout(Duration::from_secs(30))
        .expect("the guest's stdout ends with the guest")
        .expect("the guest's stdout reads to its end");
    std::thread::sleep(Duration::from_millis(500));
    let early = launched.child.try_wait().expect("launcher status");
    assert!(
        early.is_none(),
        "the launcher exited ({early:?}) before the host closed its stdin"
    );
    drop(launched.child.stdin.take());
    let status = wait_within(&mut launched.child, Duration::from_secs(30))
        .expect("the launcher exits once its stdin closes");
    assert_eq!(
        status.code(),
        Some(GUEST_EXIT),
        "the launcher passes on its guest's exit code"
    );
}

#[test]
fn an_unheld_launcher_exits_with_its_guest() {
    let Some(mut launched) = launch(false) else {
        return;
    };
    let status = wait_within(&mut launched.child, Duration::from_secs(30))
        .expect("the launcher exits with its guest while its stdin stays open");
    assert_eq!(
        status.code(),
        Some(GUEST_EXIT),
        "the launcher passes on its guest's exit code"
    );
    drop(launched.child.stdin.take());
}
