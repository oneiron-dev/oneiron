//! `[keystore] backend = "file"` (MACOS-UNSIGNED-FILE-KEYSTORE): the owner's
//! explicit file tier lets a build the platform keychain will not serve, such
//! as an unsigned macOS source build, mint its agent credential. Its slots are
//! 0600 files in the 0700 key directory the config names, which must lie
//! outside the vault. These tests run the shipped binary: `init`, then
//! `token agent --out`, as the agent quickstart does, and `token revoke`. On
//! Apple each open warns that file modes alone guard the slots, and nothing
//! a command's log or stderr does stops the open.
#![cfg(unix)]
#![allow(
    clippy::disallowed_methods,
    reason = "a test process starts its own subprocesses; the rule covers the server's crates"
)]

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use serde_json::Value;

const SECRET: &str = "file-keystore-issuer-key-not-a-bearer";

/// One install's paths: a vault, its config and the credential file
/// `token agent --out` writes. A test's key directory sits beside the vault.
struct Install {
    _dir: tempfile::TempDir,
    vault: PathBuf,
    config: PathBuf,
    credential: PathBuf,
}

impl Install {
    /// A fresh install whose config holds `config` and nothing else.
    fn with_config(config: impl FnOnce(&Path) -> String) -> Self {
        let dir = tempfile::tempdir().expect("install dir");
        let root = dir.path().to_path_buf();
        let install = Self {
            vault: root.join("vault"),
            config: root.join("oneiron.toml"),
            credential: root.join("agent.cred"),
            _dir: dir,
        };
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&install.config)
            .expect("config file");
        file.write_all(config(&root).as_bytes())
            .expect("write config");
        install
    }

    /// `oneiron <args> --config <config>`, with no keystore, vault, URL or
    /// log setting of the caller's environment.
    fn command(&self, args: &[&str], env: &[(&str, &str)]) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_oneiron"));
        command
            .args(args)
            .arg("--config")
            .arg(&self.config)
            .env("ONEIRON_AUTH_SECRET", SECRET)
            .env_remove("ONEIRON_VAULT_PATH")
            .env_remove("ONEIRON_URL")
            .env_remove("ONEIRON_KEYSTORE_BACKEND")
            .env_remove("ONEIRON_KEYSTORE_DIR")
            .env_remove("ONEIRON_KEYSTORE_SERVICE")
            .env_remove("RUST_LOG")
            .envs(env.iter().copied());
        command
    }

    /// [`Self::command`], run to its end.
    fn oneiron(&self, args: &[&str], env: &[(&str, &str)]) -> Output {
        self.command(args, env).output().expect("run oneiron")
    }

    /// `init` with no models, with `env`. A fresh vault is not rooted yet, so
    /// init opens no keystore: the mint below is the first to.
    fn init(&self, env: &[(&str, &str)]) {
        succeeded(
            &self.oneiron(
                &[
                    "init",
                    path_str(&self.vault),
                    "--embedder",
                    "none",
                    "--oneironer",
                    "none",
                ],
                env,
            ),
            "init",
        );
    }

    /// `token agent --out` for one full-access agent, with `env`.
    fn mint_command(&self, env: &[(&str, &str)]) -> Command {
        self.command(
            &[
                "token",
                "agent",
                "--name",
                "file-tier",
                "--tier",
                "full-access",
                "--out",
                path_str(&self.credential),
            ],
            env,
        )
    }

    /// [`Self::mint_command`], run to its end.
    fn mint(&self, env: &[(&str, &str)]) -> Output {
        self.mint_command(env).output().expect("run token agent")
    }
}

/// An install whose config names the file tier, with its key directory
/// `keys` beside the vault.
fn file_tier_install() -> Install {
    Install::with_config(|root| {
        format!(
            "[keystore]\nbackend = \"file\"\ndir = {:?}\n",
            path_str(&root.join("keys"))
        )
    })
}

/// Whether `output`'s stderr carries the file tier's warning.
fn warned(output: &Output) -> bool {
    String::from_utf8_lossy(&output.stderr).contains("keystore.backend = \"file\"")
}

fn path_str(path: &Path) -> &str {
    path.to_str().expect("UTF-8 path")
}

fn succeeded(output: &Output, step: &str) {
    assert!(
        output.status.success(),
        "{step} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// The JSON a successful `token agent --out` prints: its slip id and
/// principal, never the credential.
fn minted(output: &Output) -> Value {
    succeeded(output, "token agent");
    serde_json::from_slice(&output.stdout).expect("token agent prints JSON")
}

fn mode(path: &Path) -> u32 {
    fs::metadata(path).expect("metadata").permissions().mode() & 0o777
}

/// The slot files in `keys`.
fn slot_files(keys: &Path) -> Vec<PathBuf> {
    let Ok(entries) = fs::read_dir(keys) else {
        return Vec::new();
    };
    entries
        .map(|entry| entry.expect("key directory entry").path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "key"))
        .collect()
}

/// The mint left a paired credential readable by its owner only, and this
/// install's slots as 0600 files in the 0700 key directory `keys`.
fn assert_minted_on_the_file_tier(install: &Install, minted: &Value, keys: &Path) {
    assert_eq!(minted["actor_class"], "agent");
    let principal = minted["principal_ref"].as_str().expect("principal_ref");
    assert_eq!(principal.len(), 32, "a 32-hex principal id");
    // Never print the credential: only whether it has the paired shape.
    let paired = fs::read_to_string(&install.credential).expect("credential file");
    assert!(
        paired.trim().starts_with("v2.cred."),
        "the credential file holds a paired credential"
    );
    assert_eq!(
        mode(&install.credential) & 0o077,
        0,
        "the credential file is its owner's only"
    );
    assert_eq!(mode(keys), 0o700, "the key directory is 0700");
    let slots = slot_files(keys);
    assert!(
        !slots.is_empty(),
        "the mint keeps this install's slots in the key directory"
    );
    for slot in &slots {
        assert_eq!(mode(slot), 0o600, "{} is 0600", slot.display());
    }
}

#[test]
fn the_config_file_tier_mints_an_agent_credential_with_its_slots_in_the_key_directory() {
    let install = file_tier_install();
    let keys = install.vault.with_file_name("keys");
    install.init(&[]);
    let output = install.mint(&[]);
    // `token agent` installs no log: on Apple the file tier's warning reaches
    // stderr, and stdout keeps only the JSON. Elsewhere on Unix it is the
    // platform tier, and nothing is said.
    assert_eq!(
        warned(&output),
        cfg!(target_vendor = "apple"),
        "token agent's stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let minted = minted(&output);
    assert_minted_on_the_file_tier(&install, &minted, &keys);
}

/// `token revoke` logs to stderr through a filter, and `RUST_LOG=error`
/// drops every warning: on Apple the file tier's warning reaches stderr all
/// the same, and the revoke goes on.
#[test]
fn the_file_tier_warning_reaches_stderr_when_the_log_filter_drops_warnings() {
    let install = file_tier_install();
    install.init(&[]);
    let minted = minted(&install.mint(&[]));
    let slip_id = minted["slip_id"].as_str().expect("slip_id");
    let output = install.oneiron(
        &["token", "revoke", "--jti", slip_id],
        &[("RUST_LOG", "error")],
    );
    succeeded(&output, "token revoke");
    assert_eq!(
        warned(&output),
        cfg!(target_vendor = "apple"),
        "token revoke's stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let answer: Value = serde_json::from_slice(&output.stdout).expect("token revoke prints JSON");
    assert_eq!(answer["revoked"], true, "the agent's slip is revoked");
}

/// A stderr whose reader is gone loses only the file tier's warning on
/// Apple: `token agent --out` still mints, and its credential file holds the
/// credential.
#[test]
fn token_agent_mints_on_the_file_tier_with_a_closed_stderr() {
    let install = file_tier_install();
    let keys = install.vault.with_file_name("keys");
    install.init(&[]);
    let mut child = install
        .mint_command(&[])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start token agent");
    // The pipe's only reader closes before the child writes, so each write
    // to stderr fails with a broken pipe.
    drop(child.stderr.take());
    let output = child.wait_with_output().expect("token agent ends");
    let minted = minted(&output);
    assert_minted_on_the_file_tier(&install, &minted, &keys);
}

#[test]
fn the_environment_file_tier_mints_an_agent_credential_with_its_slots_in_the_key_directory() {
    let install = Install::with_config(|_| String::new());
    let keys = install.vault.with_file_name("env-keys");
    let env = [
        ("ONEIRON_KEYSTORE_BACKEND", "file"),
        ("ONEIRON_KEYSTORE_DIR", path_str(&keys)),
    ];
    install.init(&env);
    let minted = minted(&install.mint(&env));
    assert_minted_on_the_file_tier(&install, &minted, &keys);
}

#[test]
fn the_file_tier_refuses_a_key_directory_inside_the_vault() {
    let install = Install::with_config(|root| {
        format!(
            "[keystore]\nbackend = \"file\"\ndir = {:?}\n",
            path_str(&root.join("vault").join("keys"))
        )
    });
    let inside = install.vault.join("keys");
    install.init(&[]);
    assert!(
        !install.mint(&[]).status.success(),
        "no keystore opens inside the vault, so no agent credential is minted"
    );
    assert!(
        slot_files(&inside).is_empty(),
        "no slot is written inside the vault"
    );
    assert!(
        !install.credential.exists(),
        "no credential file is written"
    );
}
