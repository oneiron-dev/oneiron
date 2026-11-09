//! The shipped server's default features carry `mesh`, and its paired-machine
//! mesh listener still starts only when the host names a bind address
//! (`ONEIRON_MESH_BIND`, or `--mesh-bind` in managed mode). Without one,
//! `handler::mesh::start` starts nothing.
//!
//! The check runs the shipped binary's `serve` on a fresh install with no bind
//! address. A fresh install is not enrolled as a machine, and the listener
//! refuses to start on such an install, so a serve that started it would fail
//! its startup. Two things are asserted: serve finishes its startup (the mesh
//! start is part of it) and answers on its API listener, and its log names no
//! mesh listener.
#![allow(
    clippy::disallowed_methods,
    reason = "a test process starts its own subprocesses; the rule covers the server's crates"
)]

use std::fs::File;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, TcpListener, TcpStream};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const SECRET: &str = "mesh-listener-bind-gate-host-secret";
/// What serve logs once its startup, the mesh start included, has finished.
const STARTUP_FINISHED: &str = "startup finished";
/// What the mesh listener logs once it is bound (`handler::mesh`).
const MESH_LISTENING: &str = "mesh listening";
/// How long a fresh install's serve may take to answer.
const STARTUP_DEADLINE: Duration = Duration::from_secs(180);

/// A running `oneiron serve`, killed on drop so a failed assertion never
/// leaves a server holding the vault.
struct Server(Child);

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// The shipped `oneiron` binary with no mesh address in its environment.
fn oneiron(args: &[&str], config: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_oneiron"));
    command
        .args(args)
        .arg("--config")
        .arg(config)
        .env("ONEIRON_AUTH_SECRET", SECRET)
        .env_remove("ONEIRON_MESH_BIND")
        .env_remove("ONEIRON_MESH_RELAYS")
        .env_remove("ONEIRON_VAULT_PATH")
        .env_remove("ONEIRON_URL");
    command
}

/// The status code an unauthenticated request gets, or `None` while the
/// server does not answer it yet.
fn status(port: u16) -> Option<u16> {
    let mut stream = TcpStream::connect((Ipv4Addr::LOCALHOST, port)).ok()?;
    stream.set_read_timeout(Some(Duration::from_secs(5))).ok()?;
    stream
        .write_all(
            b"POST /v1/core/facade/receipts HTTP/1.1\r\nHost: 127.0.0.1\r\n\
              Content-Type: application/json\r\nContent-Length: 2\r\n\
              Connection: close\r\n\r\n{}",
        )
        .ok()?;
    // "HTTP/1.1 401": the code is bytes 9 to 12.
    let mut head = [0_u8; 12];
    stream.read_exact(&mut head).ok()?;
    std::str::from_utf8(&head[9..]).ok()?.parse().ok()
}

fn log_text(log: &Path) -> String {
    std::fs::read_to_string(log).unwrap_or_default()
}

#[test]
fn serve_without_a_mesh_bind_address_starts_no_mesh_listener() {
    let dir = tempfile::tempdir().expect("install dir");
    let vault = dir.path().join("vault");
    let config = dir.path().join("oneiron.toml");
    let init = oneiron(
        &[
            "init",
            vault.to_str().expect("UTF-8 path"),
            "--embedder",
            "none",
        ],
        &config,
    )
    .output()
    .expect("run oneiron init");
    assert!(
        init.status.success(),
        "oneiron init: {}",
        String::from_utf8_lossy(&init.stderr)
    );

    let port = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .expect("a free port")
        .local_addr()
        .expect("its address")
        .port();
    let log = dir.path().join("serve.log");
    let out = File::create(&log).expect("serve log file");
    let err = out.try_clone().expect("serve log file");
    let mut command = oneiron(
        &["serve", "--host", "127.0.0.1", "--port", &port.to_string()],
        &config,
    );
    command
        .env("RUST_LOG", "info")
        .stdin(Stdio::null())
        .stdout(out)
        .stderr(err);
    let mut server = Server(command.spawn().expect("spawn oneiron serve"));

    // Every request but health waits for the router the startup installs, so
    // a 401 or 403 means the startup, the mesh start among it, succeeded.
    let deadline = Instant::now() + STARTUP_DEADLINE;
    loop {
        if let Some(exit) = server.0.try_wait().expect("poll oneiron serve") {
            panic!(
                "oneiron serve exited during startup ({exit}): {}",
                log_text(&log)
            );
        }
        if matches!(status(port), Some(401 | 403)) {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "oneiron serve never answered: {}",
            log_text(&log)
        );
        std::thread::sleep(Duration::from_millis(200));
    }
    // The line follows the router's handover by a moment.
    let logged = Instant::now() + Duration::from_secs(30);
    while !log_text(&log).contains(STARTUP_FINISHED) {
        assert!(
            Instant::now() < logged,
            "serve answered but never logged its finished startup: {}",
            log_text(&log)
        );
        std::thread::sleep(Duration::from_millis(100));
    }
    let text = log_text(&log);
    assert!(
        !text.contains(MESH_LISTENING),
        "a serve with no mesh bind address started the mesh listener: {text}"
    );
    assert!(
        server.0.try_wait().expect("poll oneiron serve").is_none(),
        "oneiron serve exited after its startup: {text}"
    );
}
