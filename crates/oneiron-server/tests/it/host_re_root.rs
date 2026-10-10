//! A self-host owner moves the vault's root off a leaked host secret
//! (OF-455; ARCH-0028 #host-key-warning). Before `oneiron host re-root`, the
//! first host command bound the vault to its secret for good: a leaked or
//! lost `ONEIRON_AUTH_SECRET` stranded the vault.
//!
//! The check: a served vault re-roots to a new secret read from an
//! owner-only file. The old secret is refused, the new one serves, the vault
//! id is unchanged, what was saved is still found, the old credentials stop
//! working, and doctor passes.
use std::fs::File;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

use oneiron::memory::{Effort, RecallScope, WitnessAuthor, WitnessMessage, WitnessTurn};
use oneiron_remote::{OneironClient, unix_seconds_now};
use serde_json::Value;

const OLD: &str = "re-root-check-leaked-host-secret";
const NEW: &str = "re-root-check-fresh-host-secret";
const TEXT: &str = "The Varnholt orchard ladder is stored under the north eaves.";

/// A running `oneiron serve`, killed on drop so a failed assertion never
/// leaves a server holding the vault.
struct Server(Child);

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn oneiron(args: &[&str], config: &Path, secret: &str) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_oneiron"));
    command
        .args(args)
        .arg("--config")
        .arg(config)
        .env("ONEIRON_AUTH_SECRET", secret)
        .env_remove("ONEIRON_NEW_AUTH_SECRET")
        .env_remove("ONEIRON_VAULT_PATH")
        .env_remove("ONEIRON_URL");
    command
}

fn run(mut command: Command) -> Output {
    command.output().expect("run oneiron")
}

fn json(command: Command) -> Value {
    let output = run(command);
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("UTF-8 stdout");
    serde_json::from_str(stdout.trim()).unwrap_or_else(|_| Value::String(stdout.trim().into()))
}

fn refused(command: Command) -> String {
    let output = run(command);
    assert!(!output.status.success(), "expected a refusal");
    String::from_utf8_lossy(&output.stderr).into_owned()
}

/// Starts `oneiron serve` and waits until an unauthenticated call is refused.
fn serve(config: &Path, secret: &str, port: u16, log: &Path) -> Server {
    let port = port.to_string();
    let mut command = oneiron(
        &["serve", "--host", "127.0.0.1", "--port", &port],
        config,
        secret,
    );
    command
        .stdout(Stdio::null())
        .stderr(File::create(log).expect("server log file"));
    let mut server = Server(command.spawn().expect("spawn oneiron serve"));
    let probe = reqwest::blocking::Client::new();
    let url = format!("http://127.0.0.1:{port}/v1/core/facade/receipts");
    let deadline = Instant::now() + Duration::from_secs(120);
    loop {
        if let Some(status) = server.0.try_wait().expect("poll oneiron serve") {
            panic!(
                "oneiron serve exited during startup ({status}): {}",
                std::fs::read_to_string(log).unwrap_or_default()
            );
        }
        let answered = probe
            .post(&url)
            .header("content-type", "application/json")
            .body("{}")
            .send()
            .map(|response| response.status().as_u16());
        if matches!(answered, Ok(401 | 403)) {
            return server;
        }
        assert!(
            Instant::now() < deadline,
            "oneiron serve never became ready: {}",
            std::fs::read_to_string(log).unwrap_or_default()
        );
        std::thread::sleep(Duration::from_millis(200));
    }
}

fn sigterm(mut server: Server) {
    let pid = libc::pid_t::try_from(server.0.id()).expect("pid fits pid_t");
    // SAFETY: `kill` takes plain integers and touches no memory; `pid` is a
    // child this test spawned and has not yet reaped.
    let sent = unsafe { libc::kill(pid, libc::SIGTERM) };
    assert_eq!(sent, 0, "SIGTERM could not be sent");
    let deadline = Instant::now() + Duration::from_secs(30);
    while server.0.try_wait().expect("poll oneiron serve").is_none() {
        assert!(Instant::now() < deadline, "oneiron serve ignored SIGTERM");
        std::thread::sleep(Duration::from_millis(100));
    }
}

fn recall(client: &OneironClient) -> Result<bool, String> {
    client
        .recall(
            "Varnholt orchard ladder",
            Effort::Medium,
            &RecallScope::default(),
            10,
            None,
            None,
        )
        .map(|pack| pack.items.iter().any(|item| item.value_text.contains(TEXT)))
        .map_err(|error| error.to_string())
}

fn secret_file(path: &Path, secret: &str, mode: u32) {
    std::fs::write(path, format!("{secret}\n")).expect("write the secret file");
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
        .expect("set the secret file's mode");
}

#[test]
fn a_leaked_host_secret_moves_to_a_new_one_and_the_vault_keeps_its_id() {
    let dir = tempfile::tempdir().unwrap();
    let vault = dir.path().join("vault");
    let vault_arg = vault.to_str().unwrap();
    let config = dir.path().join("oneiron.toml");
    json(oneiron(
        &["init", vault_arg, "--embedder", "none"],
        &config,
        OLD,
    ));
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let origin = format!("http://127.0.0.1:{port}");

    // The vault binds to the old secret at its first host command, then serves.
    let agent = json(oneiron(
        &["token", "agent", "--name", "claude-code"],
        &config,
        OLD,
    ));
    let link = json(oneiron(
        &["token", "bootstrap", "--url", &origin],
        &config,
        OLD,
    ));
    let vault_id = json(oneiron(&["whoami", vault_arg], &config, OLD))["vault_id"].clone();
    assert!(vault_id.is_string(), "rooted: {vault_id}");
    let first = serve(&config, OLD, port, &dir.path().join("serve-1.log"));
    let (url, owner_credential) = OneironClient::pair(link.as_str().unwrap()).unwrap();
    let owner = OneironClient::connect(&url, &owner_credential).unwrap();
    owner
        .witness(&WitnessTurn {
            conversation_ref: "55555555555555555555555555555555".into(),
            turn_ref: None,
            messages: vec![WitnessMessage {
                id: None,
                author: WitnessAuthor::User,
                message_type: "dialogue".into(),
                content: TEXT.into(),
                metadata: None,
                is_visible: true,
                order: 0,
            }],
            occurred_at: unix_seconds_now(),
        })
        .unwrap();
    assert_eq!(recall(&owner), Ok(true));
    let old_agent = OneironClient::connect(&origin, agent["credential"].as_str().unwrap()).unwrap();
    assert!(recall(&old_agent).is_ok());
    sigterm(first);

    // A new secret others can read is refused before anything moves.
    let new_secret = dir.path().join("new-host-secret");
    secret_file(&new_secret, NEW, 0o644);
    let file_arg = new_secret.to_str().unwrap();
    let error = refused(oneiron(
        &["host", "re-root", "--new-secret-file", file_arg],
        &config,
        OLD,
    ));
    assert!(error.contains("chmod 600"), "{error}");
    assert!(!error.contains(NEW) && !error.contains(OLD), "{error}");
    // A config line the parser cannot read is named by its file alone: the
    // TOML error would print the line, and the line holds the secret.
    let broken = dir.path().join("broken.toml");
    std::fs::write(&broken, format!("auth_secret = \"{OLD}\" trailing\n")).unwrap();
    let error = refused(oneiron(
        &["host", "re-root", "--new-secret-file", file_arg],
        &broken,
        OLD,
    ));
    assert!(error.contains("broken.toml"), "{error}");
    assert!(!error.contains(OLD), "{error}");

    secret_file(&new_secret, NEW, 0o600);
    let output = run(oneiron(
        &["host", "re-root", "--new-secret-file", file_arg],
        &config,
        OLD,
    ));
    let printed = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.status.success(), "{printed}");
    assert!(
        !printed.contains(NEW) && !printed.contains(OLD),
        "{printed}"
    );
    let moved: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(moved["vault_id"], vault_id, "{moved:#}");
    assert_eq!(moved["engine_writers_enrolled"], 6, "{moved:#}");
    let agent_slip = agent["slip_id"].as_str().unwrap();
    assert!(
        moved["retired_credentials"]
            .as_array()
            .unwrap()
            .iter()
            .any(|slip| slip["slip_id"].as_str() == Some(agent_slip)),
        "the agent's slip is listed: {moved:#}"
    );
    assert!(
        moved["next"].to_string().contains("token agent"),
        "{moved:#}"
    );

    // The old secret is refused everywhere: a host command, a second
    // re-root, and the server itself.
    refused(oneiron(
        &["token", "agent", "--name", "claude-code"],
        &config,
        OLD,
    ));
    let error = refused(oneiron(
        &["host", "re-root", "--new-secret-file", file_arg],
        &config,
        OLD,
    ));
    assert!(error.contains("retired"), "{error}");
    let port_arg = port.to_string();
    let error = refused(oneiron(
        &["serve", "--host", "127.0.0.1", "--port", &port_arg],
        &config,
        OLD,
    ));
    assert!(!error.is_empty());

    // The new secret is the host: same vault, doctor passes, new credentials.
    assert_eq!(
        json(oneiron(&["whoami", vault_arg], &config, NEW))["vault_id"],
        vault_id
    );
    let doctor = json(oneiron(&["doctor", vault_arg], &config, NEW));
    assert_eq!(
        doctor["unreadable_fields"],
        serde_json::json!([]),
        "{doctor:#}"
    );
    assert!(
        doctor["config_errors"]
            .as_array()
            .is_none_or(Vec::is_empty),
        "{doctor:#}"
    );
    let agent = json(oneiron(
        &["token", "agent", "--name", "claude-code"],
        &config,
        NEW,
    ));
    let link = json(oneiron(
        &["token", "bootstrap", "--url", &origin],
        &config,
        NEW,
    ));
    let _second = serve(&config, NEW, port, &dir.path().join("serve-2.log"));
    let (url, owner_credential) = OneironClient::pair(link.as_str().unwrap()).unwrap();
    let owner = OneironClient::connect(&url, &owner_credential).unwrap();
    assert_eq!(recall(&owner), Ok(true), "what was saved is still found");
    let new_agent = OneironClient::connect(&origin, agent["credential"].as_str().unwrap()).unwrap();
    assert!(recall(&new_agent).is_ok());
    assert!(
        recall(&old_agent).is_err(),
        "the old agent slip stopped working"
    );
}
