//! The restore swap exchanges inside held parents (ARCH-0038, restore path).
//!
//! A parent moved before the exchange leaves the name at the vault path
//! alone, and a quiet swap exchanges the vault with its replacement.

use std::path::{Path, PathBuf};

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

fn open_pair(base: &Path) -> (Vault, Vault, PathBuf) {
    let live = open_vault(&base.join("home").join("vault"));
    let replacement = open_vault(&base.join("staging").join("vault"));
    let home = live.store.env.path().to_path_buf();
    let mut wtxn = replacement
        .store
        .env
        .write_txn()
        .expect("open replacement mark txn");
    replacement
        .store
        .mark_live_only_at_in_txn(&mut wtxn, &home)
        .expect("mark replacement live only at home");
    wtxn.commit().expect("commit replacement mark");
    (live, replacement, home)
}

#[test]
fn a_parent_moved_before_the_exchange_leaves_the_name_at_the_vault_path_alone() {
    let base = tempfile::tempdir().expect("tempdir");
    let (live, replacement, home) = open_pair(base.path());
    let home_parent = home.parent().expect("home parent").to_path_buf();
    let home_moved = home_parent
        .parent()
        .expect("base parent")
        .join("home-moved");
    let outcome = live.store.swap_out(
        &replacement.store,
        |_| Ok(()),
        |live_entry, replacement_entry| {
            std::fs::rename(&home_parent, &home_moved).expect("move home aside");
            std::fs::create_dir_all(&home).expect("make decoy vault dir");
            std::fs::write(home.join("decoy.txt"), b"decoy").expect("write decoy");
            crate::store::exchange_held(live_entry, replacement_entry)
        },
    );
    assert!(
        outcome.is_err(),
        "a swap whose parent moved before the exchange must refuse"
    );
    assert!(
        home.join("decoy.txt").exists(),
        "the name at the vault path must stay alone when its parent moved"
    );
}

#[test]
fn a_swap_exchanges_the_vault_and_its_replacement() {
    let base = tempfile::tempdir().expect("tempdir");
    let (live, replacement, home) = open_pair(base.path());
    let replacement_opened =
        super::opened_directory(&replacement.store).expect("replacement identity");
    let outcome = live
        .store
        .swap_out(&replacement.store, |_| Ok(()), crate::store::exchange_held);
    assert!(
        outcome.is_ok(),
        "a quiet swap must exchange the vault and its replacement"
    );
    let now =
        crate::store::root_directory::named_directory_identity(&home).expect("read vault identity");
    assert_eq!(
        now,
        Some(replacement_opened),
        "the vault path must now hold the replacement"
    );
    let next = live.store.env.write_txn();
    assert!(
        matches!(next, Err(Error::Store(StoreError::ArchivedVault))),
        "the swapped-out vault must refuse its next write"
    );
}
