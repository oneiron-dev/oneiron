//! FIX 2230 (OF-067): a snapshot restore and the withheld files it names.
//! The vault keeps no byte of a withheld file, so a restore on unix that
//! finds one gone writes it anew from the bytes the snapshot head commits
//! there, owner only, and the checkout then recaptures as the snapshot
//! itself; elsewhere it stays gone. A withheld file the head does not track
//! stays gone, and so does one a custody record declares, however the record
//! spells its path: a declared or T2 file re-materializes from the vault
//! alone (ARCH-0069 S4). A withheld file the checkout still holds keeps its
//! bytes and its permissions.
//!
//! `cargo test --locked -p oneiron --all-features --test repo_snapshot_withheld_restore`.
#![allow(
    clippy::disallowed_methods,
    reason = "a test process starts its own git subprocesses; the rule covers the engine's crates"
)]

use std::fs;
use std::path::Path;
use std::process::Command;

use oneiron::codebase::RepoRef;
use oneiron::repo_mutation::{RepoMutationOperation, RepoMutationRequest};
use oneiron::secret_custody::{
    CustodyClass, SECRET_CUSTODY_BODY_KEYS, SECRET_CUSTODY_SCHEMA_VERSION, SecretCustodyStatus,
    decode_secret_custody_body,
};
use oneiron::{Vault, VaultConfig};
use rmpv::Value;
use tempfile::TempDir;

/// A token the release scan detects, so snapshot custody withholds the file.
const SECRET_FILE: &[u8] = b"TOKEN=ghp_0123456789abcdefghijklmnopqrstuvwxyz\n";

fn git(dir: &Path, args: &[&str]) -> String {
    let output = Command::new("git")
        .args(args)
        .current_dir(dir)
        .output()
        .expect("git runs");
    assert!(
        output.status.success(),
        "git {args:?} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout)
        .expect("git output is UTF-8")
        .trim()
        .to_owned()
}

/// A repository whose one commit holds a README and each of `committed`.
fn repo_with(committed: &[(&str, &[u8])]) -> TempDir {
    let dir = tempfile::tempdir().expect("repo tempdir");
    git(dir.path(), &["init", "--quiet"]);
    fs::write(dir.path().join("README.md"), "base\n").expect("write readme");
    git(dir.path(), &["add", "--", "README.md"]);
    for (path, content) in committed {
        fs::write(dir.path().join(path), content).expect("write committed file");
        git(dir.path(), &["add", "--", path]);
    }
    git(
        dir.path(),
        &[
            "-c",
            "user.name=Oneiron",
            "-c",
            "user.email=oneiron@example.invalid",
            "-c",
            "commit.gpgsign=false",
            "commit",
            "--quiet",
            "-m",
            "initial",
        ],
    );
    dir
}

fn repo_ref(repo: &TempDir) -> RepoRef {
    RepoRef::LocalFolder {
        path: repo.path().to_string_lossy().into_owned(),
        commit: git(repo.path(), &["rev-parse", "HEAD"]),
    }
}

fn open_vault() -> (TempDir, Vault) {
    let dir = tempfile::tempdir().expect("vault tempdir");
    let vault = Vault::open(dir.path(), VaultConfig::default()).expect("open vault");
    (dir, vault)
}

/// Writes the README through the trusted queue and returns the forkHash of
/// the checkout as it stood before the write.
fn write_readme(vault: &Vault, repo: &TempDir, content: &str) -> [u8; 32] {
    vault
        .apply_repo_mutation(RepoMutationRequest::new(
            repo_ref(repo),
            RepoMutationOperation::CommitFile {
                path: "README.md".to_owned(),
                content: content.as_bytes().to_vec(),
                message: "write readme".to_owned(),
            },
        ))
        .expect("the README write applies")
        .entry
        .pre_action_fork_hash
}

/// Registers a custody record whose manifest entry declares each of
/// `declared`: a vault-resident path, whose bytes only the vault writes. The
/// record is built through the public codec, as a manifest flow builds it,
/// with a synthetic value and no binding.
fn declare_custody_paths(vault: &Vault, declared: &[String]) {
    let band = |min: u64, max: u64| {
        Value::Map(vec![
            (Value::from("min"), Value::from(min)),
            (Value::from("max"), Value::from(max)),
        ])
    };
    let floor = Value::Map(vec![
        (Value::from("portable"), band(0, 2)),
        (Value::from("device_bound"), band(0, 2)),
        (Value::from("cross_vault"), band(0, 0)),
        (Value::from("rotation_max_age_secs"), Value::Nil),
        (Value::from("env_bindings"), Value::Map(vec![])),
    ]);
    let key = |i: usize| Value::from(SECRET_CUSTODY_BODY_KEYS[i]);
    let body = Value::Map(vec![
        (
            key(0),
            Value::from(u64::from(SECRET_CUSTODY_SCHEMA_VERSION)),
        ),
        (key(1), Value::from("restore-declared-file")),
        (key(2), Value::from(CustodyClass::CustodyPortable.as_str())),
        (key(3), Value::from(false)),
        (key(4), Value::Binary(b"synthetic-declared-value".to_vec())),
        (key(5), Value::from(SecretCustodyStatus::Active.as_str())),
        (key(6), Value::from(1_767_225_600_u64)),
        (key(7), Value::Nil),
        (key(8), Value::from(0_u64)),
        (key(9), Value::Array(vec![])),
        (key(10), Value::from("")),
        (
            key(11),
            Value::Array(
                declared
                    .iter()
                    .map(|path| Value::from(path.as_str()))
                    .collect(),
            ),
        ),
        (key(12), floor),
        (key(13), Value::from(true)),
    ]);
    let mut bytes = Vec::new();
    rmpv::encode::write_value(&mut bytes, &body).expect("encode custody body");
    vault
        .register_secret(decode_secret_custody_body(&bytes).expect("decode custody body"))
        .expect("register the declaring custody record");
}

#[cfg(unix)]
fn mode_of(path: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    fs::metadata(path)
        .expect("file metadata")
        .permissions()
        .mode()
        & 0o777
}

#[cfg(unix)]
#[test]
fn a_restore_recreates_a_committed_withheld_file_the_checkout_lost() {
    let (_vault_dir, vault) = open_vault();
    let repo = repo_with(&[("secrets.env", SECRET_FILE)]);
    let snapshot = write_readme(&vault, &repo, "mutated\n");
    let secret = repo.path().join("secrets.env");
    fs::remove_file(&secret).expect("the withheld file is removed");

    vault
        .recover_repo_snapshot(&repo_ref(&repo), snapshot)
        .expect("the restore applies");

    assert_eq!(
        fs::read(&secret).ok().as_deref(),
        Some(SECRET_FILE),
        "the restore writes the committed withheld file anew"
    );
    assert_eq!(
        mode_of(&secret) & 0o077,
        0,
        "only its owner may read the rewritten withheld file"
    );
    assert_eq!(
        fs::read_to_string(repo.path().join("README.md")).expect("read README"),
        "base\n"
    );
    assert_eq!(
        write_readme(&vault, &repo, "again\n"),
        snapshot,
        "the restored checkout recaptures as the snapshot itself"
    );
}

/// The T2 writer walks a declared path by its components, so a `.`
/// component or a doubled `/` in a declaration names the file it writes
/// there (review 8290 round 2). The restore reads the declaration the same
/// way: a declared file the commit tracks is never written anew from it.
#[test]
fn a_restore_leaves_a_gone_declared_file_gone_however_its_declaration_is_spelled() {
    let (_vault_dir, vault) = open_vault();
    let names = ["plain.env", "dot.env", "doubled.env"];
    let repo = repo_with(&names.map(|name| (name, SECRET_FILE)));
    let root = fs::canonicalize(repo.path()).expect("canonical repo root");
    let root = root.to_str().expect("a UTF-8 repo root");
    declare_custody_paths(
        &vault,
        &[
            format!("{root}/plain.env"),
            format!("{root}/./dot.env"),
            format!("{root}//doubled.env"),
        ],
    );
    let snapshot = write_readme(&vault, &repo, "mutated\n");
    for name in names {
        fs::remove_file(repo.path().join(name)).expect("the declared file is removed");
    }

    vault
        .recover_repo_snapshot(&repo_ref(&repo), snapshot)
        .expect("the restore applies");

    for name in names {
        assert!(
            fs::symlink_metadata(repo.path().join(name)).is_err(),
            "{name} is declared, so only the vault writes it again"
        );
    }
    assert_eq!(
        fs::read_to_string(repo.path().join("README.md")).expect("read README"),
        "base\n"
    );
}

#[test]
fn a_restore_leaves_a_gone_untracked_withheld_file_gone() {
    let (_vault_dir, vault) = open_vault();
    let repo = repo_with(&[]);
    let local = repo.path().join("local.env");
    fs::write(&local, SECRET_FILE).expect("write the untracked withheld file");
    let snapshot = write_readme(&vault, &repo, "mutated\n");
    fs::remove_file(&local).expect("the withheld file is removed");

    vault
        .recover_repo_snapshot(&repo_ref(&repo), snapshot)
        .expect("the restore applies");

    assert!(
        fs::symlink_metadata(&local).is_err(),
        "no snapshot and no commit holds the file's bytes, so it stays gone"
    );
    assert_eq!(
        fs::read_to_string(repo.path().join("README.md")).expect("read README"),
        "base\n"
    );
}

#[cfg(unix)]
#[test]
fn a_restore_keeps_a_held_withheld_file_and_its_owner_only_mode() {
    use std::os::unix::fs::PermissionsExt;

    let (_vault_dir, vault) = open_vault();
    let repo = repo_with(&[("secrets.env", SECRET_FILE)]);
    let secret = repo.path().join("secrets.env");
    fs::set_permissions(&secret, fs::Permissions::from_mode(0o600)).expect("owner-only mode");
    let snapshot = write_readme(&vault, &repo, "mutated\n");

    vault
        .recover_repo_snapshot(&repo_ref(&repo), snapshot)
        .expect("the restore applies");

    assert_eq!(
        fs::read(&secret).expect("read the withheld file"),
        SECRET_FILE
    );
    assert_eq!(
        mode_of(&secret),
        0o600,
        "the restore never widens a withheld file"
    );
}
