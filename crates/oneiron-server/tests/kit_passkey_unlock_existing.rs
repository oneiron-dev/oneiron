//! The synced passkey counts as one of the data-key kit's two pieces on a
//! vault already on this host, as it does at a fresh restore (census L10-18;
//! FIX [KIT-PASSKEY-UNLOCK-ON-EXISTING-VAULT-CLI]). The shared unlock flags
//! (`--unlock kit --unlock-credential NAME --unlock-kit-passkey-prf-file
//! FILE`) and `vault-key add-device`'s own (`--credential NAME
//! --kit-passkey-prf-file FILE`) take the passkey's PRF output, and the piece
//! the vault keeps sealed under it (its `kit_point` wrap) joins the pieces
//! given: one piece file and the passkey open the key, and so do the passkey
//! and the kit passphrase with no piece file. Another passkey's output opens
//! nothing, the passkey alone opens nothing, and a world kit's piece with the
//! passkey is refused: a passkey is a piece of the data-key kit only.
//!
//! Every step runs the shipped `oneiron` binary on a plain vault `init` made,
//! its keystore in the test's own directory.
//! `cargo test --locked -p oneiron-server --all-features --test
//! kit_passkey_unlock_existing`.
#![cfg(unix)]
#![allow(clippy::unwrap_used)]

use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use oneiron::recovery::{
    CodeKeeping, KitIssue, PassphraseCost, PieceHome, issue_recovery_root_kit,
};
use serde_json::Value;

/// The synced passkey's credential name the kit seals its piece under.
const PASSKEY: &str = "phone";
/// That passkey's PRF output, 64 hex digits.
const PRF: &str = "0404040404040404040404040404040404040404040404040404040404040404";
/// Another passkey's output under the same name.
const WRONG_PRF: &str = "0303030303030303030303030303030303030303030303030303030303030303";
const KIT_PASSPHRASE: &str = "correct horse battery staple";

/// One host: the config `init` wrote for its vault, and the state directory
/// its keystore keeps its slots under.
struct Host {
    dir: tempfile::TempDir,
    config: PathBuf,
    state: PathBuf,
}

impl Host {
    /// A plain vault `init` made, its data key minted on this install's
    /// keystore with a password wrap beside it.
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("oneiron.toml");
        let state = dir.path().join("state");
        let host = Self { dir, config, state };
        let vault = host.path("vault");
        host.ok(&["init", vault.to_str().unwrap(), "--embedder", "none"]);
        let password = host.owner_file("password", b"a long vault password");
        host.ok(&[
            "vault-key",
            "set-password",
            "--secret-file",
            password.to_str().unwrap(),
        ]);
        host
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    /// `bytes` in a new file only its owner may read.
    fn owner_file(&self, name: &str, bytes: &[u8]) -> PathBuf {
        let path = self.path(name);
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .unwrap();
        file.write_all(bytes).unwrap();
        path
    }

    /// The binary with `args` and this host's config, stdin closed: a
    /// secret it would read from stdin reads nothing.
    fn run(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_oneiron"))
            .args(args)
            .arg("--config")
            .arg(&self.config)
            .env("XDG_STATE_HOME", &self.state)
            .env_remove("ONEIRON_VAULT_PATH")
            .env_remove("ONEIRON_BACKUP_DIR")
            .stdin(Stdio::null())
            .output()
            .unwrap()
    }

    /// `args` run and succeeded; their JSON answer.
    fn ok(&self, args: &[&str]) -> Value {
        let output = self.run(args);
        assert!(
            output.status.success(),
            "oneiron {args:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        serde_json::from_slice(&output.stdout).unwrap_or(Value::Null)
    }

    /// `args` run and failed; their stderr.
    fn refused(&self, args: &[&str], what: &str) -> String {
        let output = self.run(args);
        assert!(
            !output.status.success(),
            "{what}: oneiron {args:?} succeeded"
        );
        String::from_utf8_lossy(&output.stderr).into_owned()
    }

    /// A data-key kit over `homes`, the passkey's piece sealed into the
    /// vault's `kit_point` wrap: its vault id, and each stored piece's file.
    fn issue_kit(&self, homes: [&str; 3], passphrase: Option<&Path>) -> (String, Vec<String>) {
        let prf = self.owner_file("issue-prf", PRF.as_bytes());
        let out = self.path("kit");
        let mut args = vec!["recovery-kit", "issue-vault-key"];
        for home in homes {
            args.extend(["--home", home]);
        }
        args.extend([
            "--passkey-credential",
            PASSKEY,
            "--passkey-prf-file",
            prf.to_str().unwrap(),
            "--out",
            out.to_str().unwrap(),
        ]);
        if let Some(passphrase) = passphrase {
            args.extend(["--secret-file", passphrase.to_str().unwrap()]);
        }
        let issued = self.ok(&args);
        let vault_id = issued["vault_id"].as_str().unwrap().to_owned();
        let pieces = issued["pieces"]
            .as_array()
            .unwrap()
            .iter()
            .map(|piece| piece["file"].as_str().unwrap().to_owned())
            .collect();
        (vault_id, pieces)
    }
}

/// The shared flags that unlock with the kit: `pieces`, and with `prf`, the
/// synced passkey's PRF output file.
fn kit_unlock<'a>(vault_id: &'a str, pieces: &[&'a str], prf: Option<&'a str>) -> Vec<&'a str> {
    let mut args = vec!["--unlock", "kit", "--unlock-vault-id", vault_id];
    for piece in pieces {
        args.extend(["--unlock-piece", piece]);
    }
    if let Some(prf) = prf {
        args.extend([
            "--unlock-credential",
            PASSKEY,
            "--unlock-kit-passkey-prf-file",
            prf,
        ]);
    }
    args
}

fn with<'a>(command: &[&'a str], unlock: &[&'a str]) -> Vec<&'a str> {
    let mut args = command.to_vec();
    args.extend_from_slice(unlock);
    args
}

#[test]
fn one_piece_and_the_synced_passkey_unlock_a_vault_on_this_host() {
    let host = Host::new();
    let (vault_id, pieces) = host.issue_kit(["paper", "passkey", "trusted-person"], None);
    assert_eq!(pieces.len(), 2, "the passkey's piece is in no file");
    let (paper, trusted) = (pieces[0].as_str(), pieces[1].as_str());
    let prf = host.owner_file("prf", PRF.as_bytes());
    let prf = prf.to_str().unwrap();
    let wrong = host.owner_file("wrong-prf", WRONG_PRF.as_bytes());
    let wrong = wrong.to_str().unwrap();
    let status = ["vault-key", "status"];

    host.ok(&with(&status, &kit_unlock(&vault_id, &[paper], Some(prf))));
    let stderr = host.refused(
        &with(&status, &kit_unlock(&vault_id, &[paper], Some(wrong))),
        "another passkey's output opens no piece",
    );
    assert!(stderr.contains("did not unlock with kit"), "{stderr}");
    let guess = host.owner_file("guess", b"a passphrase this kit never had");
    let mut alone = kit_unlock(&vault_id, &[paper], None);
    alone.extend(["--unlock-secret-file", guess.to_str().unwrap()]);
    host.refused(
        &with(&status, &alone),
        "one piece and no passkey is one piece",
    );

    // The key the trusted person's piece and the passkey rebuild is held:
    // a new passkey wrap seals it, and that passkey alone then opens it.
    let laptop = host.owner_file(
        "laptop-prf",
        b"0505050505050505050505050505050505050505050505050505050505050505",
    );
    let laptop = laptop.to_str().unwrap();
    host.ok(&with(
        &[
            "vault-key",
            "add-passkey",
            "laptop",
            "--secret-file",
            laptop,
        ],
        &kit_unlock(&vault_id, &[trusted], Some(prf)),
    ));
    host.ok(&[
        "vault-key",
        "status",
        "--unlock",
        "passkey",
        "--unlock-credential",
        "laptop",
        "--unlock-secret-file",
        laptop,
    ]);

    // `vault-key add-device` reads the same passkey through its own flags.
    host.ok(&[
        "vault-key",
        "add-device",
        "--unlock",
        "kit",
        "--vault-id",
        &vault_id,
        "--piece",
        paper,
        "--credential",
        PASSKEY,
        "--kit-passkey-prf-file",
        prf,
    ]);
}

#[test]
fn the_synced_passkey_and_the_kit_passphrase_unlock_with_no_piece_file() {
    let host = Host::new();
    let phrase = host.owner_file("kit-passphrase", KIT_PASSPHRASE.as_bytes());
    let (vault_id, pieces) = host.issue_kit(["paper", "passkey", "passphrase"], Some(&phrase));
    assert_eq!(pieces.len(), 1, "only the paper piece is in a file");
    let prf = host.owner_file("prf", PRF.as_bytes());
    let status = ["vault-key", "status"];

    let mut both = kit_unlock(&vault_id, &[], Some(prf.to_str().unwrap()));
    both.extend(["--unlock-secret-file", phrase.to_str().unwrap()]);
    host.ok(&with(&status, &both));
    host.refused(
        &with(
            &status,
            &kit_unlock(&vault_id, &[], Some(prf.to_str().unwrap())),
        ),
        "the passkey alone opens nothing",
    );
}

#[test]
fn a_world_kit_piece_with_the_passkey_is_refused() {
    let host = Host::new();
    let world_vault = [7u8; 32];
    let issued = issue_recovery_root_kit(
        &KitIssue {
            vault_id: world_vault,
            homes: [
                PieceHome::RecoveryCode(CodeKeeping::Paper),
                PieceHome::TrustedPerson,
                PieceHome::RecoveryCode(CodeKeeping::OwnEmail),
            ],
            passphrase: None,
            cost: PassphraseCost::DEFAULT,
            only_machine: false,
        },
        &[9u8; 32],
    )
    .unwrap();
    let piece = host.owner_file(
        "world-piece",
        issued.pieces[0].recovery_code().reveal().as_bytes(),
    );
    let world_id: String = world_vault
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    let prf = host.owner_file("prf", PRF.as_bytes());
    let prf = prf.to_str().unwrap();

    let stderr = host.refused(
        &with(
            &["vault-key", "status"],
            &kit_unlock(&world_id, &[piece.to_str().unwrap()], Some(prf)),
        ),
        "a passkey is no piece of a world kit",
    );
    assert!(stderr.contains("never of the world kit"), "{stderr}");

    let stderr = host.refused(
        &[
            "vault-key",
            "status",
            "--unlock",
            "password",
            "--unlock-kit-passkey-prf-file",
            prf,
            "--unlock-credential",
            PASSKEY,
        ],
        "the passkey's PRF file is read only with the kit",
    );
    assert!(
        stderr.contains("--unlock-kit-passkey-prf-file is read only with --unlock kit"),
        "{stderr}"
    );
}
