//! A browser or desktop guest's pids-limit hits reach its session's manifest
//! (FIX 8013 follow-up [GUEST-PIDS-PRESSURE-BROWSER-DESKTOP]): each verb's
//! entry reads the guest's cgroup `pids.events` through the session's lease,
//! so the `session_manifest` the run's door adds to every answer, and the
//! run's receipt, name what the guest showed. The guest here is a scripted
//! pipe (Chromium's NUL-framed CDP for the browser, newline JSON-RPC for the
//! desktop's MCP) beside a container session on a fake runtime whose
//! `inspect` names a scratch cgroup directory.
#![cfg(all(target_os = "linux", feature = "driver"))]

use oneiron_browser::{
    BrowserEngine, BrowserGuest, BrowserSession, DesktopGuest, DesktopSession, GuestLimits,
    HandleRetention, SendPolicy,
};
use oneiron_container::{
    ContainerRuntime, EgressRelay, FenceProof, GuestPressure, GuestSeccomp, GuestSpec,
    HostNetFloor, HttpRequest, HttpResponse, ImageRef, SessionManifest, SessionTransport,
    UnmeteredFloor,
};
use serde_json::{Value, json};
use std::io::{self, BufRead, BufReader, Write};
use std::net::{SocketAddr, TcpStream};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const IMAGE: &str = concat!(
    "example.invalid/guest@sha256:",
    "0000000000000000000000000000000000000000000000000000000000000000",
);
const HITS: u64 = 5;

/// A scratch directory under the system temp dir, removed on drop.
struct Scratch(PathBuf);

impl Scratch {
    fn new(label: &str) -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |since| since.as_nanos());
        let dir = std::env::temp_dir().join(format!(
            "guest-pressure-{label}-{}-{nanos}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).expect("scratch dir");
        Self(dir)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

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

fn limits() -> GuestLimits {
    GuestLimits {
        memory_mib: 256,
        cpu_millis: 1000,
        pids: 64,
        tmpfs_mib: 64,
    }
}

/// A transport whose bytes go to `guest_end` and whose lease is a container
/// session on the fake runtime, its cgroup's `pids.events` reading
/// `max HITS`. The manifest claims a proved fence, as an attach requires.
fn transport(scratch: &Scratch, host_end: UnixStream) -> SessionTransport {
    let cgroup = scratch.0.join("cgroup");
    std::fs::create_dir_all(&cgroup).expect("scratch cgroup dir");
    std::fs::write(cgroup.join("pids.events"), format!("max {HITS}\n")).expect("pids.events");
    let runtime =
        ContainerRuntime::new(fake_runtime(&scratch.0, &cgroup)).expect("fake runtime binds");
    let spec = GuestSpec {
        image: ImageRef::pinned(IMAGE).expect("pinned image"),
        user: (10001, 10001),
        limits: limits(),
        seccomp: GuestSeccomp::RuntimeDefault,
        read_only_mounts: Vec::new(),
    };
    let session = runtime.start(&spec).expect("guest starts");
    let mut manifest: SessionManifest = session.manifest().clone();
    manifest.fence_unproven = false;
    manifest.fence_proof = Some(FenceProof {
        ruleset_hash: "ruleset".to_owned(),
        seccomp_hash: "seccomp".to_owned(),
        network_routes: Vec::new(),
        network_evidence_digest: "evidence".to_owned(),
        sandbox_generation: manifest.generation.clone(),
        launcher_digest: "launcher".to_owned(),
    });
    assert_eq!(manifest.guest_pressure, None, "nothing read before attach");
    SessionTransport {
        reader: Box::new(host_end.try_clone().expect("reader end")),
        writer: Box::new(host_end),
        manifest,
        lease: Box::new(session),
    }
}

/// Answers every CDP call on Chromium's NUL-framed pipe: the target list
/// empty, a created target and an attached session named, every other
/// call an empty result.
fn scripted_cdp(stream: UnixStream) {
    let mut reader = BufReader::new(stream.try_clone().expect("cdp reader"));
    let mut writer = stream;
    let mut buf = Vec::new();
    loop {
        buf.clear();
        match reader.read_until(0, &mut buf) {
            Ok(0) | Err(_) => return,
            Ok(_) => {}
        }
        if buf.last() == Some(&0) {
            buf.pop();
        }
        let Ok(message) = serde_json::from_slice::<Value>(&buf) else {
            continue;
        };
        let Some(id) = message.get("id").cloned() else {
            continue;
        };
        let result = match message.get("method").and_then(Value::as_str) {
            Some("Target.getTargets") => json!({"targetInfos": []}),
            Some("Target.createTarget") => json!({"targetId": "page-1"}),
            Some("Target.attachToTarget") => json!({"sessionId": "session-1"}),
            _ => json!({}),
        };
        let mut reply = json!({"id": id, "result": result});
        if let Some(session) = message.get("sessionId") {
            reply["sessionId"] = session.clone();
        }
        let mut bytes = serde_json::to_vec(&reply).expect("cdp reply");
        bytes.push(0);
        if writer
            .write_all(&bytes)
            .and_then(|()| writer.flush())
            .is_err()
        {
            return;
        }
    }
}

/// Answers every MCP request on newline JSON-RPC with an empty result.
fn scripted_mcp(stream: UnixStream) {
    let mut reader = BufReader::new(stream.try_clone().expect("mcp reader"));
    let mut writer = stream;
    let mut line = String::new();
    loop {
        line.clear();
        match reader.read_line(&mut line) {
            Ok(0) | Err(_) => return,
            Ok(_) => {}
        }
        let Ok(message) = serde_json::from_str::<Value>(&line) else {
            continue;
        };
        let (Some(id), Some(_)) = (message.get("id").cloned(), message.get("method")) else {
            continue;
        };
        let mut bytes = serde_json::to_vec(&json!({"jsonrpc": "2.0", "id": id, "result": {}}))
            .expect("mcp reply");
        bytes.push(b'\n');
        if writer
            .write_all(&bytes)
            .and_then(|()| writer.flush())
            .is_err()
        {
            return;
        }
    }
}

/// Holds nothing against any floor.
struct Unmetered;

impl HandleRetention for Unmetered {
    fn resize(&mut self, _bytes: usize) -> bool {
        true
    }
}

/// The session reaches nothing.
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

#[test]
fn browser_verb_entry_records_guest_pids_pressure() {
    let scratch = Scratch::new("browser");
    let (host_end, guest_end) = UnixStream::pair().expect("cdp pipe");
    std::thread::spawn(move || scripted_cdp(guest_end));
    let config = BrowserGuest {
        runtime: scratch.0.join("container-runtime"),
        image: IMAGE.to_owned(),
        limits: limits(),
        wait_cap: Duration::from_secs(5),
        policy: SendPolicy::default(),
        fixture: None,
        fixture_forward: None,
        engine: BrowserEngine::Chromium,
    };
    let transport = transport(&scratch, host_end);
    let mut session = BrowserSession::attach(
        &config,
        transport,
        Arc::new(NoEgress),
        Box::new(Unmetered),
        None,
        None,
    )
    .expect("the scripted browser attaches");
    session
        .take_over("person-1")
        .expect("a verb entry with the guest up");
    assert_eq!(
        session.manifest().guest_pressure,
        Some(GuestPressure::Processes { hits: HITS }),
        "the browser's manifest names the guest's pids-limit hits"
    );
}

#[test]
fn desktop_verb_entry_records_guest_pids_pressure() {
    let scratch = Scratch::new("desktop");
    let (host_end, guest_end) = UnixStream::pair().expect("mcp pipe");
    std::thread::spawn(move || scripted_mcp(guest_end));
    let config = DesktopGuest {
        runtime: scratch.0.join("container-runtime"),
        image: IMAGE.to_owned(),
        limits: limits(),
        wait_cap: Duration::from_secs(5),
        policy: SendPolicy::default(),
    };
    let transport = transport(&scratch, host_end);
    let mut session = DesktopSession::attach(&config, transport, Box::new(Unmetered))
        .expect("the scripted desktop attaches");
    session
        .take_over("person-1")
        .expect("a verb entry with the guest up");
    assert_eq!(
        session.manifest().guest_pressure,
        Some(GuestPressure::Processes { hits: HITS }),
        "the desktop's manifest names the guest's pids-limit hits"
    );
}
