//! The server's `[runtime] clock`, checked through public paths only: the
//! shipped binaries, `build_app`, and the vault's public `store_clock`.
//! The clock file is written by hand, so this file names no clock type.
#![cfg(unix)]
#![allow(clippy::unwrap_used)]

use std::fs::File;
use std::path::Path;
use std::process::{Child, Command};
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode};
use ed25519_dalek::SigningKey;
use oneiron::authority::{CapabilitySlip, holder_proof};
use oneiron::store::ports::ManualClock;
use oneiron_remote::unix_seconds_now;
use oneiron_server::build_app;
use oneiron_server::config::SyncServerConfig;
use oneiron_server::server::SyncServer;
use serde_json::{Value, json};
use tower::ServiceExt;

const SECRET: &str = "restart-check-issuer-key-not-a-bearer";

#[test]
fn the_shipped_server_accepts_an_agents_proof_after_a_stop_longer_than_the_window() {
    let dir = tempfile::tempdir().unwrap();
    let vault = dir.path().join("vault");
    let config = dir.path().join("oneiron.toml");
    let clock = dir.path().join("clock");
    stdout(oneiron(
        &["init", vault.to_str().unwrap(), "--embedder", "none"],
        &config,
    ));
    let start = unix_seconds_now();
    set_clock_file(&clock, start * 1000);
    let mut text = std::fs::read_to_string(&config).unwrap();
    text.push_str(&format!(
        "\n[runtime]\nclock = \"manual\"\nclock_file = {:?}\n",
        clock.to_str().unwrap()
    ));
    std::fs::write(&config, text).unwrap();
    let minted: Value = serde_json::from_str(&stdout(oneiron(
        &["token", "agent", "--name", "clock-check"],
        &config,
    )))
    .expect("token agent prints its credential as JSON");
    let token = minted["token"].as_str().expect("token").to_owned();
    let slip = CapabilitySlip::from_token(&token).expect("v2 slip");
    let key = signing_key(minted["binding_key"].as_str().expect("binding key"));
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let client = reqwest::blocking::Client::builder()
        .no_proxy()
        .build()
        .unwrap();
    let read = |proof: &Value| {
        client
            .get(format!("http://127.0.0.1:{port}/v1/core/conversations"))
            .bearer_auth(&token)
            .header("x-oneiron-binding", proof.to_string())
            .send()
            .expect("read conversations")
            .status()
            .as_u16()
    };

    let first = serve(&config, port, &dir.path().join("serve-1.log"));
    let proof = holder_proof(&slip, &key, start).unwrap();
    assert_eq!(read(&proof), 200, "a fresh proof");
    assert_eq!(read(&proof), 401, "the same proof replayed");
    sigterm(first);

    let now = start + 70;
    set_clock_file(&clock, now * 1000);
    let _second = serve(&config, port, &dir.path().join("serve-2.log"));
    let at = |timestamp: u64| holder_proof(&slip, &key, timestamp).unwrap();
    assert_eq!(read(&at(now)), 200, "a fresh proof after the stop");
    assert_eq!(read(&at(now - 120)), 401, "a proof older than the window");
    assert_eq!(read(&at(now + 120)), 401, "a proof dated past the window");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_keyed_response_expires_a_day_later_on_the_vaults_clock() {
    const START: u64 = 1_800_000_000;
    // Private server constant: src/idempotency.rs:23, in seconds.
    const IDEMPOTENCY_TTL_SECS: u64 = 86_400;
    let dir = tempfile::tempdir().unwrap();
    let clock = ManualClock::new(START);
    let mut config = oneiron::VaultConfig::device();
    config.store_clock = clock.bundle();
    let vault = Arc::new(oneiron::Vault::open(dir.path(), config).unwrap());
    // The target must be a live PERSON; the dev hatch's replay also checks
    // that this unrooted self-hosted vault has a live embedded owner.
    let owner = vault.ensure_embedded_owner_actor().unwrap().to_hex();
    let server = Arc::new(
        SyncServer::new(
            vault,
            SyncServerConfig {
                allow_unauthenticated: true,
                ..Default::default()
            },
        )
        .unwrap(),
    );
    let app = build_app(server);
    let body = json!({
        "principal_ref": owner,
        "scope": {
            "kind": "companion_profile",
            "person_ref": owner
        },
        "created_at": START
    })
    .to_string();
    let request = || {
        Request::builder()
            .method("POST")
            .uri("/v1/companion/access-grants")
            .header("content-type", "application/json")
            .header("Idempotency-Key", "runtime-clock-day")
            .body(Body::from(body.clone()))
            .unwrap()
    };

    let first = response_json(app.clone().oneshot(request()).await.unwrap()).await;
    let first_id = first["id"].as_str().expect("first grant id");
    assert_eq!(first["status"], "active", "a live grant was created");

    clock.set(START + IDEMPOTENCY_TTL_SECS - 1);
    let within = response_json(app.clone().oneshot(request()).await.unwrap()).await;
    assert_eq!(within, first, "replayed within the day");

    clock.set(START + IDEMPOTENCY_TTL_SECS);
    let after = response_json(app.oneshot(request()).await.unwrap()).await;
    let after_id = after["id"].as_str().expect("new grant id");
    assert_ne!(after_id, first_id, "a day on, the key runs again");
    assert_eq!(after["status"], "active");
}

#[test]
fn a_managed_settings_file_that_sets_the_vaults_clock_is_refused() {
    for (text, leaf) in [
        ("[runtime]\nclock = \"manual\"\n", "runtime.clock"),
        ("[runtime]\nclock = \"system\"\n", "runtime.clock"),
        (
            "[runtime]\nclock_file = \"/nonexistent/clock\"\n",
            "runtime.clock_file",
        ),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let settings = dir.path().join("settings.toml");
        std::fs::write(&settings, text).unwrap();
        let output = Command::new(env!("CARGO_BIN_EXE_oneiron-server"))
            .arg("serve")
            .arg("--managed-by-hypnos")
            .arg("--contract-version")
            .arg(oneiron_vault_contract::CONTRACT_VERSION.to_string())
            .arg("--vault-name")
            .arg("runtime-clock")
            .arg("--derivation-owner")
            .arg("09".repeat(32))
            .arg("--data-dir")
            .arg(dir.path().join("data"))
            .arg("--http-socket")
            .arg(dir.path().join("http.sock"))
            .arg("--ctl-socket")
            .arg(dir.path().join("ctl.sock"))
            .arg("--hypnos-socket")
            .arg(dir.path().join("supervisor.sock"))
            .args(["--ready-fd", "1", "--credentials-fd", "0"])
            .arg("--settings-file")
            .arg(&settings)
            .env_clear()
            // Settings are refused before credentials or sockets are read.
            .stdin(std::process::Stdio::null())
            .output()
            .expect("run managed oneiron-server");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(!output.status.success(), "managed start accepted {text}");
        assert!(
            stderr.contains(&format!("--settings-file sets `{leaf}`")),
            "the refusal names the leaf: {stderr}"
        );
        // A server whose schema lacks these leaves refuses them too, as
        // UnknownField; the reason is what this checks, not the exit code.
        assert!(
            stderr.contains("the supervisor owns this binding"),
            "the refusal must be SupervisorOwned for {text}: {stderr}"
        );
        assert!(output.stdout.is_empty(), "no ready byte before refusal");
        for name in ["data", "http.sock", "ctl.sock", "supervisor.sock"] {
            assert!(
                !dir.path().join(name).exists(),
                "refused boot created {name}"
            );
        }
    }
}

/// A doctor run with no `--config` reads the default config path. When that
/// path's existence cannot be checked, its file may set the manual clock, so
/// doctor must not open the vault on the host's clock: an open runs the
/// vault's recovery, which may record the time it reads for good.
#[test]
fn doctor_does_not_open_a_vault_whose_default_config_it_cannot_check() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    let vault = dir.path().join("vault");
    stdout(oneiron(
        &["init", vault.to_str().unwrap(), "--embedder", "none"],
        &dir.path().join("init.toml"),
    ));
    // Two default config paths whose existence cannot be checked: a symlink
    // loop (ELOOP, for every user), and a file under a parent this process
    // may not search (EACCES, which binds every user but root).
    let looped = dir.path().join("looped");
    std::fs::create_dir_all(looped.join("oneiron")).unwrap();
    std::os::unix::fs::symlink("oneiron.toml", looped.join("oneiron").join("oneiron.toml"))
        .unwrap();
    let locked = dir.path().join("locked");
    let unsearchable = locked.join("xdg");
    std::fs::create_dir_all(unsearchable.join("oneiron")).unwrap();
    std::fs::write(
        unsearchable.join("oneiron").join("oneiron.toml"),
        "[runtime]\nclock = \"manual\"\n",
    )
    .unwrap();
    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000)).unwrap();
    let mut cases = vec![("a symlink loop", looped)];
    if unsearchable.join("oneiron").try_exists().is_err() {
        cases.push(("an unsearchable parent", unsearchable));
    } else {
        eprintln!("this user searches a mode-000 directory (root): only the symlink loop runs");
    }
    let outputs: Vec<_> = cases
        .into_iter()
        .map(|(case, xdg)| {
            let mut command = Command::new(env!("CARGO_BIN_EXE_oneiron"));
            for (name, _) in std::env::vars_os() {
                if name.to_string_lossy().starts_with("ONEIRON_") {
                    command.env_remove(name);
                }
            }
            command.arg("doctor").arg(&vault).env("XDG_CONFIG_HOME", &xdg);
            (case, command.output().expect("run oneiron doctor"))
        })
        .collect();
    // Searchable again, so the temporary directory is removed.
    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o755)).unwrap();
    for (case, output) in outputs {
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            output.status.success(),
            "doctor failed under {case}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let report: Value = serde_json::from_str(&stdout).unwrap_or_else(|error| {
            panic!("doctor printed no JSON under {case} ({error}): {stdout}")
        });
        let note = report["location"]["note"].as_str().unwrap_or_default();
        assert!(
            note.contains("doctor did not open the vault"),
            "doctor opened the vault under {case}: {stdout}"
        );
        let errors = report["config_errors"].as_array().cloned().unwrap_or_default();
        let named = errors
            .iter()
            .filter_map(Value::as_str)
            .any(|text| text.contains("cannot be checked"));
        assert!(named, "the config error names the unchecked path under {case}: {stdout}");
    }
}

async fn response_json(response: axum::response::Response) -> Value {
    let status = response.status();
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    assert_eq!(
        status,
        StatusCode::OK,
        "response body: {}",
        String::from_utf8_lossy(&bytes)
    );
    serde_json::from_slice(&bytes).expect("JSON response")
}

// The manual clock file: decimal Unix milliseconds and a newline, replaced
// by a rename from a sibling ending in `.next`.
fn set_clock_file(path: &Path, unix_ms: u64) {
    let mut staged = path.as_os_str().to_owned();
    staged.push(".next");
    let staged = std::path::PathBuf::from(staged);
    std::fs::write(&staged, format!("{unix_ms}\n")).unwrap();
    std::fs::rename(&staged, path).unwrap();
}

fn signing_key(seed: &str) -> SigningKey {
    let seed: Vec<u8> = (0..seed.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&seed[at..at + 2], 16).expect("hex seed"))
        .collect();
    SigningKey::from_bytes(&seed.try_into().expect("32-byte seed"))
}

struct Server(Child);

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn oneiron(args: &[&str], config: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_oneiron"));
    // Do not inherit vault/model/URL overrides from the build host.
    for (name, _) in std::env::vars_os() {
        if name.to_string_lossy().starts_with("ONEIRON_") {
            command.env_remove(name);
        }
    }
    command
        .args(args)
        .arg("--config")
        .arg(config)
        .env("ONEIRON_AUTH_SECRET", SECRET);
    command
}

fn stdout(mut command: Command) -> String {
    let output = command.output().expect("run oneiron");
    assert!(
        output.status.success(),
        "oneiron exited with {}: {}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).expect("UTF-8 stdout")
}

fn serve(config: &Path, port: u16, log: &Path) -> Server {
    let port = port.to_string();
    let mut command = oneiron(&["serve", "--host", "127.0.0.1", "--port", &port], config);
    let file = File::create(log).expect("server log file");
    command
        .stdout(file.try_clone().expect("server log file"))
        .stderr(file);
    let mut server = Server(command.spawn().expect("spawn oneiron serve"));
    let probe = reqwest::blocking::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();
    // A registered verb, so a missing credential is answered 401. A path
    // that names no verb (the unrooted `receipts`) gets the facade's
    // unknown-verb 400 or 404 on every poll and never reads as ready.
    let url = format!("http://127.0.0.1:{port}/v1/core/facade/vault.receipts");
    let deadline = Instant::now() + Duration::from_secs(120);
    let mut last = String::from("no answer yet");
    loop {
        if let Some(status) = server.0.try_wait().expect("poll oneiron serve") {
            panic!(
                "oneiron serve exited during startup ({status}); last probe: {last}; log tail:\n{}",
                log_tail(log)
            );
        }
        match probe
            .post(&url)
            .header("content-type", "application/json")
            .body("{}")
            .send()
        {
            Ok(response) if matches!(response.status().as_u16(), 401 | 403) => return server,
            Ok(response) => {
                let status = response.status().as_u16();
                let body: String = response
                    .text()
                    .unwrap_or_default()
                    .chars()
                    .take(400)
                    .collect();
                last = format!("HTTP {status}: {body}");
            }
            Err(error) => last = format!("no answer: {error}"),
        }
        assert!(
            Instant::now() < deadline,
            "oneiron serve never became ready; last probe: {last}; log tail:\n{}",
            log_tail(log)
        );
        std::thread::sleep(Duration::from_millis(200));
    }
}

/// The last 60 lines of a server log, so a startup failure keeps its cause
/// inside the panic message.
fn log_tail(log: &Path) -> String {
    let text = std::fs::read_to_string(log).unwrap_or_default();
    let lines: Vec<&str> = text.lines().collect();
    lines[lines.len().saturating_sub(60)..].join("\n")
}

fn sigterm(mut server: Server) {
    let pid = libc::pid_t::try_from(server.0.id()).expect("pid fits pid_t");
    // SAFETY: pid identifies this test's unreaped child process.
    let sent = unsafe { libc::kill(pid, libc::SIGTERM) };
    assert_eq!(sent, 0, "SIGTERM could not be sent");
    let deadline = Instant::now() + Duration::from_secs(30);
    while server.0.try_wait().expect("poll oneiron serve").is_none() {
        assert!(Instant::now() < deadline, "oneiron serve ignored SIGTERM");
        std::thread::sleep(Duration::from_millis(100));
    }
}
