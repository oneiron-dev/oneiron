//! Row OWNER-CONFIRM-SHEET, PR 4b-5: a command a person runs at this device
//! installs the process's presence gate beside its keystore
//! (`KeystoreConfig::install_for_command`), so an important owner act of the
//! command asks through the device's own unlock prompt. The installs a
//! serving process makes (`install_on_boot`, `install`, `install_on`) leave
//! the handle without a gate: the server's screen is not its caller's. A
//! keystore that is off installs no gate.

use std::sync::Arc;

use oneiron::{Vault, VaultConfig};
use oneiron_keystore::PresenceGate;
use oneiron_server::config::{KeystoreBackend, KeystoreConfig, KeystoreInstall};
use tempfile::TempDir;

/// A stopped vault, and a keystore config whose key directory is outside
/// the vault's and does not exist yet: the file keystore makes it, open to
/// its owner alone, and refuses a directory that others can read.
fn stopped_vault() -> (Vault, TempDir, KeystoreConfig, TempDir) {
    let vault_dir = tempfile::tempdir().expect("vault directory");
    let key_home = tempfile::tempdir().expect("the key directory's parent");
    let vault = Vault::open(vault_dir.path(), VaultConfig::device()).expect("vault");
    let keystore = KeystoreConfig {
        dir: Some(key_home.path().join("keys")),
        ..KeystoreConfig::default()
    };
    (vault, vault_dir, keystore, key_home)
}

#[test]
fn a_command_install_leaves_the_process_gate_beside_the_keystore() {
    let (vault, vault_dir, keystore, _key_home) = stopped_vault();
    assert!(vault.presence_gate().is_none());
    assert!(keystore.install_for_command(&vault, vault_dir.path()));
    let gate = vault
        .presence_gate()
        .expect("the command's handle holds a gate");
    assert!(Arc::ptr_eq(&gate, &PresenceGate::process_wide()));
}

#[test]
fn the_plain_install_leaves_no_gate() {
    let (vault, vault_dir, keystore, _key_home) = stopped_vault();
    assert!(keystore.install_on(&vault, vault_dir.path()));
    assert!(vault.presence_gate().is_none());
}

#[test]
fn the_install_of_a_serving_start_leaves_no_gate() {
    let (vault, vault_dir, keystore, _key_home) = stopped_vault();
    let installed = keystore
        .install_on_boot(&vault, vault_dir.path())
        .expect("a plain vault needs no wrap");
    assert!(installed);
    assert!(vault.presence_gate().is_none());
}

#[test]
fn the_install_of_a_managed_start_leaves_no_gate() {
    let (vault, vault_dir, keystore, _key_home) = stopped_vault();
    assert!(matches!(
        keystore.install(&vault, vault_dir.path()),
        KeystoreInstall::Installed { .. }
    ));
    assert!(vault.presence_gate().is_none());
}

#[test]
fn a_keystore_that_is_off_installs_no_gate() {
    let (vault, vault_dir, mut keystore, _key_home) = stopped_vault();
    keystore.backend = KeystoreBackend::Off;
    assert!(!keystore.install_for_command(&vault, vault_dir.path()));
    assert!(vault.device_keystore_assurance().is_none());
    assert!(vault.presence_gate().is_none());
}
