//! AGENT-CREDENTIAL-VERB-ALLOWLIST: `oneiron token agent` signs the agent's
//! verb list into its slip. Omitted, the list is empty: the read verbs
//! alone (the good default). `--verbs <names>` lists those verbs;
//! `--all-verbs` leaves the credential no list (every verb its tier admits;
//! Engine CREDENTIAL-VERBS-UNRESTRICTED = A); a name the verb table does not
//! hold is refused before anything is minted.
//! These tests run the shipped binary on a stopped vault.
//!
//! Run with: `cargo test --locked -p oneiron-server --all-features --test
//! token_agent_verb_allowlist`.
#![allow(
    clippy::disallowed_methods,
    reason = "a test process starts its own subprocesses; the rule covers the server's crates"
)]

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use oneiron::authority::CapabilitySlip;
use serde_json::Value;

const SECRET: &str = "token-agent-verbs-issuer-key-not-a-bearer";

fn oneiron(args: &[&str], config: &Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_oneiron"))
        .args(args)
        .arg("--config")
        .arg(config)
        .env("ONEIRON_AUTH_SECRET", SECRET)
        .env_remove("ONEIRON_VAULT_PATH")
        .env_remove("ONEIRON_URL")
        .output()
        .expect("run oneiron")
}

/// A vault made by `oneiron init`, and its config file.
struct Install {
    _dir: tempfile::TempDir,
    config: PathBuf,
}

fn init() -> Install {
    let dir = tempfile::tempdir().expect("install dir");
    let vault = dir.path().join("vault");
    let config = dir.path().join("oneiron.toml");
    let output = oneiron(
        &[
            "init",
            vault.to_str().expect("UTF-8 path"),
            "--embedder",
            "none",
        ],
        &config,
    );
    assert!(
        output.status.success(),
        "init: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    Install { _dir: dir, config }
}

/// One `token agent` run with `verbs` (`None`: no `--verbs`): what it
/// printed and the verb list its slip carries.
fn token_agent(install: &Install, name: &str, extra: &[&str]) -> (Value, Option<BTreeSet<String>>) {
    let mut args = vec!["token", "agent", "--name", name, "--tier", "full-access"];
    args.extend(extra);
    let output = oneiron(&args, &install.config);
    assert!(
        output.status.success(),
        "token agent {extra:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let printed: Value =
        serde_json::from_slice(&output.stdout).expect("token agent prints its credential as JSON");
    let slip = CapabilitySlip::from_token(printed["token"].as_str().expect("the slip token"))
        .expect("a slip token");
    (printed, slip.claims.verb_allowlist)
}

#[test]
fn token_agent_signs_the_read_verbs_alone_by_default() {
    let install = init();
    let (printed, list) = token_agent(&install, "default-reader", &[]);
    assert_eq!(list, Some(BTreeSet::new()), "the read verbs alone");
    assert_eq!(printed["verb_allowlist"], serde_json::json!([]));
}

#[test]
fn token_agent_signs_the_verbs_named_at_mint() {
    let install = init();
    let (printed, list) = token_agent(
        &install,
        "note-writer",
        &["--verbs", "vault.notes.create,vault.notes.lifecycle"],
    );
    assert_eq!(
        list,
        Some(BTreeSet::from([
            "vault.notes.create".to_owned(),
            "vault.notes.lifecycle".to_owned(),
        ]))
    );
    assert_eq!(
        printed["verb_allowlist"],
        serde_json::json!(["vault.notes.create", "vault.notes.lifecycle"])
    );
}

#[test]
fn token_agent_all_verbs_leaves_no_list() {
    let install = init();
    let (printed, list) = token_agent(&install, "every-verb", &["--all-verbs"]);
    assert_eq!(list, None, "no list: every verb its tier admits");
    assert_eq!(printed["verb_allowlist"], Value::Null);
}

#[test]
fn token_agent_refuses_a_name_the_verb_table_does_not_hold() {
    let install = init();
    let output = oneiron(
        &[
            "token",
            "agent",
            "--name",
            "typo",
            "--verbs",
            "vault.notes.create,vault.notes.creat",
        ],
        &install.config,
    );
    assert!(!output.status.success(), "an unknown verb name is refused");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("vault.notes.creat"),
        "names the unknown verb: {stderr}"
    );
    let output = oneiron(
        &[
            "token",
            "agent",
            "--name",
            "mixed",
            "--verbs",
            "all,vault.batch",
        ],
        &install.config,
    );
    assert!(!output.status.success(), "`all` stands alone");
}
