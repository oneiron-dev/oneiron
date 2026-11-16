//! The shipped server's default features carry `mesh`, and its paired-machine
//! mesh listener still starts only when the host names a bind address
//! (`ONEIRON_MESH_BIND`, or `--mesh-bind` in managed mode). Without one,
//! `handler::mesh::start` starts nothing.
//!
//! The check runs the shipped binary's `serve` on a fresh install with no bind
//! address. `oneiron init` gives the install a machine identity, so a serve
//! that ignored the missing address would bind the listener and log
//! `mesh listening`. Serve logs its finished startup after the mesh start, so
//! once that line is written the log is complete for the mesh: it must name no
//! listener, and serve must still be running.
#![allow(
    clippy::disallowed_methods,
    reason = "a test process starts its own subprocesses; the rule covers the server's crates"
)]

use std::fs::File;
use std::net::{Ipv4Addr, TcpListener};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const SECRET: &str = "mesh-listener-bind-gate-host-secret";
/// What serve logs once its startup, the mesh start included, has finished.
const STARTUP_FINISHED: &str = "startup finished";
/// What the mesh listener logs once it is bound (`handler::mesh`).
const MESH_LISTENING: &str = "mesh listening";
/// How long a fresh install's serve may take to finish its startup.
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
        .env("RUST_LOG", "info,loro_internal=warn")
        .stdin(Stdio::null())
        .stdout(out)
        .stderr(err);
    let mut server = Server(command.spawn().expect("spawn oneiron serve"));

    let deadline = Instant::now() + STARTUP_DEADLINE;
    while !log_text(&log).contains(STARTUP_FINISHED) {
        if let Some(exit) = server.0.try_wait().expect("poll oneiron serve") {
            panic!(
                "oneiron serve exited during startup ({exit}): {}",
                log_text(&log)
            );
        }
        assert!(
            Instant::now() < deadline,
            "oneiron serve never finished its startup: {}",
            log_text(&log)
        );
        std::thread::sleep(Duration::from_millis(200));
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
