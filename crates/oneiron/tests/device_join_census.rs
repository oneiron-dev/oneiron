//! A fresh vault that `device enrol` opens holds only its own seeds
//! (FIX-LIST [DEVICE-JOIN-CENSUS-MISSES-CARRIERS-AND-HOME-ROOM]). The
//! empty-vault join guard asks `first_non_bootstrap_row`. A seeded open
//! also writes the root project's home CONVERSATION and a source-carrier
//! ASSET for each clean seeded skill tree; the census did not know those,
//! so the guard refused a vault that held nothing of its own.

use oneiron::{Vault, VaultConfig};

#[test]
fn fresh_stopped_vault_holds_no_non_bootstrap_row() {
    let temp = tempfile::tempdir().expect("temporary directory");
    let vault_path = temp.path().join("vault");

    // Initialize, stop, and reopen through the CLI's owned-vault door, as
    // `device enrol` does before its join guard.
    drop(Vault::open_owned(&vault_path, VaultConfig::device()).expect("initialize vault"));
    let vault = Vault::open_owned(&vault_path, VaultConfig::device()).expect("reopen vault");
    vault.root_project().expect("a seeded open roots the vault");

    assert_eq!(
        vault.first_non_bootstrap_row().expect("seed census scan"),
        None,
        "a fresh seeded vault holds no row of its own"
    );
}
