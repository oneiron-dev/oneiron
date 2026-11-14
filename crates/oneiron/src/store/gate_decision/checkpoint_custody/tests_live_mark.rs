//! Every write reads the archive mark (ARCH-0038, restore path).
//!
//! A handle opened before a restore's swap keeps the vault moved aside. Its
//! next write refuses when the mark archives it, and writes while the mark
//! still names the directory it opened.

use std::path::Path;

use crate::Vault;
use crate::VaultConfig;
use crate::error::{Error, StoreError};

fn open_vault(path: &Path) -> Vault {
    let vault = Vault::open(path, VaultConfig::device()).expect("open vault");
    vault.install_device_keystore(std::sync::Arc::new(
        oneiron_keystore::MemoryKeystore::default(),
    ));
    vault
}

fn mark_live_only_at(vault: &Vault, home: &Path) {
    let mut wtxn = vault.store.env.write_txn().expect("open mark txn");
    vault
        .store
        .mark_live_only_at_in_txn(&mut wtxn, home)
        .expect("write live-only mark");
    wtxn.commit().expect("commit live-only mark");
}

#[test]
fn a_mark_archiving_the_vault_written_after_open_refuses_the_next_write() {
    let base = tempfile::tempdir().expect("tempdir");
    let vault = open_vault(&base.path().join("vault"));
    let elsewhere = base.path().join("elsewhere");
    std::fs::create_dir_all(&elsewhere).expect("make elsewhere");
    let elsewhere = elsewhere.canonicalize().expect("canonicalize elsewhere");
    mark_live_only_at(&vault, &elsewhere);
    let next = vault.store.env.write_txn();
    assert!(
        matches!(next, Err(Error::Store(StoreError::ArchivedVault))),
        "a vault marked live only elsewhere must refuse its next write"
    );
}

#[test]
fn a_live_only_vault_moved_from_its_path_refuses_the_next_write() {
    let base = tempfile::tempdir().expect("tempdir");
    let vault = open_vault(&base.path().join("vault"));
    let home = vault.store.env.path().to_path_buf();
    mark_live_only_at(&vault, &home);
    let aside = home.parent().expect("vault parent").join("vault-aside");
    std::fs::rename(&home, &aside).expect("move vault aside");
    std::fs::create_dir(&home).expect("make fresh dir at vault path");
    let next = vault.store.env.write_txn();
    assert!(
        matches!(next, Err(Error::Store(StoreError::ArchivedVault))),
        "a live-only vault moved from its path must refuse its next write"
    );
}

#[test]
fn a_live_only_vault_at_its_path_writes() {
    let base = tempfile::tempdir().expect("tempdir");
    let vault = open_vault(&base.path().join("vault"));
    let home = vault.store.env.path().to_path_buf();
    mark_live_only_at(&vault, &home);
    let wtxn = vault
        .store
        .env
        .write_txn()
        .expect("a live-only vault at its path must still write");
    wtxn.commit()
        .expect("a live-only vault at its path must commit");
}

#[test]
fn an_unmarked_vault_writes() {
    let base = tempfile::tempdir().expect("tempdir");
    let vault = open_vault(&base.path().join("vault"));
    let first = vault
        .store
        .env
        .write_txn()
        .expect("an unmarked vault must write");
    first
        .commit()
        .expect("an unmarked vault must commit its first write");
    let second = vault
        .store
        .env
        .write_txn()
        .expect("an unmarked vault must write again");
    second
        .commit()
        .expect("an unmarked vault must commit its second write");
}
