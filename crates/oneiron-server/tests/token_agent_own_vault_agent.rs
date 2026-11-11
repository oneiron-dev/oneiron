//! `oneiron token agent` leaves its agent one of this vault's own agents
//! (PRIVACY-07). ARCH-0028: one name is one agent principal, of class
//! `agent`. ARCH-0052 d5: the off-record save grant's agent holders are the
//! bound agents and the live AGENT_DEFs. The mint used to leave a PERSON with
//! no `agent` binding, so the save grant refused a full-access agent's save
//! with 403. These tests run the shipped binary, then read the vault's
//! authority fold.
#![allow(
    clippy::disallowed_methods,
    reason = "a test process starts its own subprocesses; the rule covers the server's crates"
)]

use std::path::{Path, PathBuf};
use std::process::Command;

use ed25519_dalek::SigningKey;
use oneiron::authority::{
    ActorBindingStatus, AuthorityFold, AuthorityKey, ROLE_AGENT, actor_binding_is_active,
};
use oneiron::{EntityId, Vault, VaultConfig};
use serde_json::Value;

const SECRET: &str = "token-agent-issuer-key-not-a-bearer";

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

fn stdout(mut command: Command) -> String {
    let output = command.output().expect("run oneiron");
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).expect("UTF-8 stdout")
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
    stdout(oneiron(
        &[
            "init",
            vault.to_str().expect("UTF-8 path"),
            "--embedder",
            "none",
        ],
        &config,
    ));
    Install {
        _dir: dir,
        vault,
        config,
    }
}

/// What one `token agent` run left: the principal and the key the
/// credential connects with.
struct Minted {
    principal: EntityId,
    connection_key: AuthorityKey,
}

fn token_agent(install: &Install, name: &str, tier: &str) -> Minted {
    let minted: Value = serde_json::from_str(&stdout(oneiron(
        &["token", "agent", "--name", name, "--tier", tier],
        &install.config,
    )))
    .expect("token agent prints its credential as JSON");
    assert_eq!(minted["actor_class"], "agent");
    let principal = EntityId::from_hex(minted["principal_ref"].as_str().expect("principal_ref"))
        .expect("principal id");
    let seed = minted["binding_key"].as_str().expect("binding key");
    let seed: Vec<u8> = (0..seed.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&seed[at..at + 2], 16).expect("hex seed"))
        .collect();
    let key = SigningKey::from_bytes(&seed.try_into().expect("32-byte seed"));
    Minted {
        principal,
        connection_key: AuthorityKey::Ed25519(key.verifying_key().to_bytes()),
    }
}

/// The vault's authority fold, read on the stopped vault.
fn authority_fold(install: &Install) -> AuthorityFold {
    let vault = Vault::open_owned(&install.vault, VaultConfig::server()).expect("open vault");
    vault.authority_fold().expect("authority fold")
}

/// The keys bound to `principal` as an active `agent`.
fn agent_keys(fold: &AuthorityFold, principal: EntityId) -> Vec<AuthorityKey> {
    fold.actor_bindings
        .iter()
        .filter(|(_, binding)| {
            binding.status == ActorBindingStatus::Active
                && binding.actor_ref == principal
                && binding.actor_class == "agent"
        })
        .map(|(key, _)| key.clone())
        .collect()
}

#[test]
fn token_agent_binds_its_principal_as_one_of_the_vaults_own_agents() {
    let install = init();
    let agent = token_agent(&install, "save-holder", "full-access");

    let fold = authority_fold(&install);
    assert!(fold.vault_id.is_some(), "the vault is rooted");
    assert!(
        actor_binding_is_active(&fold, &agent.principal, "agent"),
        "the save grant's own-agent reader needs an active `agent` binding"
    );
    let keys = agent_keys(&fold, agent.principal);
    assert_eq!(keys.len(), 1, "one binding for one name");
    let device = fold
        .roster
        .get(&keys[0])
        .expect("the bound key is enrolled");
    assert!(!device.revoked);
    assert_eq!(device.roles, ROLE_AGENT, "an agent key, with no owner role");
    assert_ne!(
        keys[0], agent.connection_key,
        "the binding key is not the credential's"
    );
    assert!(
        !fold.roster.contains_key(&agent.connection_key),
        "the credential's connection key never enters the roster"
    );
}

#[test]
fn a_second_mint_for_the_same_name_keeps_its_one_binding() {
    let install = init();
    let first = token_agent(&install, "save-holder", "full-access");
    let before = agent_keys(&authority_fold(&install), first.principal);

    let second = token_agent(&install, "save-holder", "full-access");

    assert_eq!(second.principal, first.principal, "one name, one principal");
    assert_ne!(
        second.connection_key, first.connection_key,
        "a new credential"
    );
    let fold = authority_fold(&install);
    assert_eq!(agent_keys(&fold, second.principal), before);
    assert_eq!(before.len(), 1);
    assert!(!fold.roster.contains_key(&second.connection_key));
}

#[test]
fn each_named_agent_has_its_own_binding() {
    let install = init();
    let north = token_agent(&install, "north", "propose-only");
    let south = token_agent(&install, "south", "full-access");

    let fold = authority_fold(&install);
    let north_keys = agent_keys(&fold, north.principal);
    let south_keys = agent_keys(&fold, south.principal);
    assert_eq!(north_keys.len(), 1);
    assert_eq!(south_keys.len(), 1);
    assert_ne!(north_keys, south_keys, "one key per agent principal");
}
