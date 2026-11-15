//! `oneiron token revoke` (and `oneiron revoke`) print their JSON answer on
//! stdout, with the log lines on stderr (FIX-LIST 23427). `token revoke`
//! used to install the tracing subscriber on stdout, so the keystore line it
//! logs on a fresh process landed before its `{"revoked": ...}` answer and a
//! caller parsing stdout got no JSON. These tests run the shipped binary and
//! parse what it printed.
#![allow(
    clippy::disallowed_methods,
    reason = "a test process starts its own subprocesses; the rule covers the server's crates"
)]

use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::{Value, json};

const SECRET: &str = "token-revoke-stdout-key-not-a-bearer";

fn oneiron(args: &[&str], config: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_oneiron"));
    command
        .args(args)
        .arg("--config")
        .arg(config)
        .env("ONEIRON_AUTH_SECRET", SECRET)
        .env_remove("ONEIRON_VAULT_PATH")
        .env_remove("ONEIRON_URL")
        .env_remove("RUST_LOG");
    command
}

fn run(mut command: Command) -> std::process::Output {
    command.output().expect("run oneiron")
}

/// A vault made by `oneiron init`, and its config file.
struct Install {
    dir: tempfile::TempDir,
    config: PathBuf,
}

fn init() -> Install {
    let dir = tempfile::tempdir().expect("install dir");
    let vault = dir.path().join("vault");
    let config = dir.path().join("oneiron.toml");
    let output = run(oneiron(
        &[
            "init",
            vault.to_str().expect("UTF-8 path"),
            "--embedder",
            "none",
        ],
        &config,
    ));
    assert!(
        output.status.success(),
        "init stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    Install { dir, config }
}

/// The minted agent slip's id, from `token agent`'s printed answer.
fn mint_slip_id(install: &Install) -> String {
    let credential = install.dir.path().join("agent.cred");
    let output = run(oneiron(
        &[
            "token",
            "agent",
            "--name",
            "revokee",
            "--tier",
            "full-access",
            "--out",
            credential.to_str().expect("UTF-8 path"),
        ],
        &install.config,
    ));
    assert!(
        output.status.success(),
        "token agent stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let minted: Value = serde_json::from_str(
        &String::from_utf8(output.stdout).expect("UTF-8 stdout"),
    )
    .expect("token agent prints its answer as JSON");
    minted["slip_id"].as_str().expect("slip id").to_owned()
}

#[test]
fn token_revoke_prints_json_alone_on_stdout() {
    let install = init();
    let slip_id = mint_slip_id(&install);
    let output = run(oneiron(
        &[
            "token",
            "revoke",
            "--jti",
            slip_id.as_str(),
            "--log-level",
            "info",
        ],
        &install.config,
    ));
    assert!(
        output.status.success(),
        "token revoke stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let revoked: Value = serde_json::from_str(
        &String::from_utf8(output.stdout).expect("UTF-8 stdout"),
    )
    .expect("token revoke prints its JSON answer on stdout alone");
    assert_eq!(revoked, json!({ "revoked": true }));
}

#[test]
fn lease_revoke_prints_json_alone_on_stdout() {
    let install = init();
    // No lease holder exists, so the answer is `false`; the empty dict root
    // forces the CJK warning, which used to land on stdout before the answer.
    let dicts = install.dir.path().join("dicts");
    std::fs::create_dir(&dicts).expect("dict dir");
    let mut command = oneiron(
        &[
            "revoke",
            "--client",
            "0000000000000001",
            "--dict-search-paths",
            dicts.to_str().expect("UTF-8 path"),
            "--log-level",
            "info",
        ],
        &install.config,
    );
    command.env_remove("ONEIRON_AUTH_SECRET");
    let output = run(command);
    assert!(
        output.status.success(),
        "revoke stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let revoked: Value = serde_json::from_str(
        &String::from_utf8(output.stdout).expect("UTF-8 stdout"),
    )
    .expect("revoke prints its JSON answer on stdout alone");
    assert_eq!(revoked, json!({ "revoked": false }));
}
