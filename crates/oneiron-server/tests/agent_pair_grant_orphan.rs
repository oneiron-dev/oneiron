#![cfg(oneiron_test_support)]
//! A `token agent` mint that fails after its link keeps no default Grant
//! (AGENT-PAIR-GRANT-ORPHAN). The link issue mints the agent's default read
//! Grant in its writer; when a later step fails, the error arm used to take
//! the new slip back but keep the Grant. These tests run the shipped binary,
//! then read the stopped vault.
#![allow(
    clippy::disallowed_methods,
    reason = "a test process starts its own subprocesses; the rule covers the server's crates"
)]

use std::path::{Path, PathBuf};
use std::process::Command;

use oneiron::counterparty_contact::CounterpartyContactRecord;
use oneiron::test_doors::agent_pair_grant_orphan::live_agent_grants_for_holder;
use oneiron::{EntityId, Vault, VaultConfig};

const SECRET: &str = "token-agent-orphan-grant-key-not-a-bearer";

fn oneiron(args: &[&str], config: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_oneiron"));
    command
        .args(args)
        .arg("--config")
        .arg(config)
        .env("ONEIRON_AUTH_SECRET", SECRET)
        .env_remove("ONEIRON_VAULT_PATH")
        .env_remove("ONEIRON_URL");
    command
}

/// A vault made by `oneiron init`, and its config file.
struct Install {
    _dir: tempfile::TempDir,
    vault: PathBuf,
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
    )
    .output()
    .expect("run oneiron");
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    Install {
        _dir: dir,
        vault,
        config,
    }
}

/// The PERSON `name` acts as, named by a counterparty contact: `token
/// agent` mints its link, its default Grant and its slip for it, then the
/// binding step refuses a PERSON a contact names, so the mint fails after
/// the link. The vault is closed before the caller runs the CLI.
fn contact_named_agent(install: &Install, name: &str) -> EntityId {
    let vault = Vault::open_owned(&install.vault, VaultConfig::server()).expect("open vault");
    let agent = vault.ensure_agent_principal(name).expect("agent principal");
    let now = vault.now_recorded_at();
    vault
        .create_counterparty_contact(
            &EntityId::now(),
            &CounterpartyContactRecord::public(agent, "agent@example.com", now).expect("contact"),
        )
        .expect("name the agent in a contact");
    drop(vault);
    agent
}

/// 64 hex chars to the 32 bytes they name.
fn hex32(text: &str) -> [u8; 32] {
    let bytes: Vec<u8> = (0..text.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&text[at..at + 2], 16).expect("hex pair"))
        .collect();
    bytes.try_into().expect("32 bytes")
}

#[test]
fn a_token_agent_mint_that_fails_after_its_link_keeps_no_default_grant() {
    let install = init();
    let agent = contact_named_agent(&install, "orphan-grant");

    let output = oneiron(
        &[
            "token",
            "agent",
            "--name",
            "orphan-grant",
            "--tier",
            "full-access",
        ],
        &install.config,
    )
    .output()
    .expect("run oneiron");
    assert!(
        !output.status.success(),
        "the binding refuses a PERSON a contact names"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("actor lacks authority over this claim"),
        "the mint fails at the binding step: {stderr}"
    );

    // The credential reached stdout, so the link, its default Grant and the
    // slip all landed before the binding refused.
    let credential: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("the failed mint delivered its credential");
    assert_eq!(
        credential["principal_ref"].as_str().expect("principal_ref"),
        agent.to_hex().as_str()
    );
    let slip_id = hex32(credential["slip_id"].as_str().expect("slip id"));

    let vault = Vault::open_owned(&install.vault, VaultConfig::server()).expect("open vault");
    let fold = vault.authority_fold().expect("authority fold");
    assert!(
        fold.slips.explicit_revoked.contains(&slip_id),
        "the error arm revokes the new slip"
    );
    assert!(
        !fold.slip_is_live(&slip_id),
        "the revoked slip authorizes nothing"
    );
    let grants = live_agent_grants_for_holder(&vault, agent).expect("read agent grants");
    assert!(
        grants.is_empty(),
        "a failed mint keeps no default Grant: {grants:?}"
    );
}

#[test]
fn a_successful_mint_keeps_the_agents_default_grant() {
    let install = init();

    let output = oneiron(
        &[
            "token",
            "agent",
            "--name",
            "fine-grant",
            "--tier",
            "full-access",
        ],
        &install.config,
    )
    .output()
    .expect("run oneiron");
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let credential: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("the mint prints its credential");
    let agent = EntityId::from_hex(credential["principal_ref"].as_str().expect("principal_ref"))
        .expect("principal id");

    let vault = Vault::open_owned(&install.vault, VaultConfig::server()).expect("open vault");
    let grants = live_agent_grants_for_holder(&vault, agent).expect("read agent grants");
    assert_eq!(
        grants.len(),
        1,
        "the mint leaves the agent's one default Grant"
    );
}
