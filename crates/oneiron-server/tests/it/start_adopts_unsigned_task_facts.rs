//! A start that loads this install's signer adopts the TASK authority facts a door wrote
//! unsigned while none was loaded ([TASK-FACT-ADOPTION-ROOT-WINDOW-ONLY]). Without a loaded
//! signer a door writes its fact unsigned, and it then counts on this install only (Engine
//! RULING 16 Nov 03:18, TASK-FACT-RULING-CROSSED-OPTION-D = B); the keystore install at the
//! next start twins such facts under this install's signature, so they count on the vault's
//! other devices too.
//!
//! Red on the base (bf2b69c428be): `KeystoreConfig::install` loads the signer and adopts
//! nothing, so the explicit adoption pass below finds the unsigned fact. Green with the fix:
//! the start's install adopts it, so the pass finds none.

use std::path::Path;

use oneiron::task_verb::TaskCreateSpec;
use oneiron::{EdgeActorClass, EntityId, Vault, VaultConfig};
use oneiron_server::config::{KeystoreConfig, KeystoreInstall};

/// A TASK `owner` creates through the task door, which writes its Owner fact.
fn owner_task(vault: &Vault, owner: EntityId) -> EntityId {
    vault
        .memory(owner, EdgeActorClass::Human)
        .tasks_create(&TaskCreateSpec::new(
            rmpv::Value::Nil,
            Some("adopted at the next start that loads a signer".into()),
            Some(owner),
            Some(vault.now_recorded_at()),
        ))
        .expect("the task door")
        .task_ref
        .expect("the TASK creation took effect")
}

/// Installs this install's keystore on `vault` as `oneiron serve` does, and asserts that this
/// install's signer loaded from it: with none loaded no start adopts, so the red below would
/// prove nothing.
fn install_signing_keystore(keystore: &KeystoreConfig, vault: &Vault, vault_path: &Path) {
    assert_eq!(
        keystore.install(vault, vault_path),
        KeystoreInstall::Installed { signing: true },
        "this install's keystore, as `oneiron serve` installs it, loads this install's signer"
    );
}

#[test]
fn a_start_that_loads_the_signer_adopts_the_facts_written_while_none_was_loaded() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault_path = dir.path().join("vault");
    let keystore = KeystoreConfig::default();
    // A rooted vault whose signer loads, as `oneiron serve` opens it.
    let owner = {
        let vault = Vault::open_owned(&vault_path, VaultConfig::server()).expect("a new vault");
        install_signing_keystore(&keystore, &vault, &vault_path);
        let issuer = vault
            .bootstrap_host_slip_issuer()
            .expect("this install's host issuer seed");
        vault
            .ensure_host_root_slip(&issuer)
            .expect("the vault's host root slip, as `oneiron serve` ensures it");
        assert!(
            vault
                .authority_fold()
                .expect("the vault's fold")
                .vault_id
                .is_some(),
            "a rooted vault, whose facts a loaded signer signs"
        );
        vault.ensure_embedded_owner_actor().expect("the owner")
    };
    // The same vault reopened with no keystore installed, as a start whose keystore did
    // not open: the task door writes its Owner fact unsigned.
    let task = {
        let vault =
            Vault::open_owned(&vault_path, VaultConfig::server()).expect("the stopped vault");
        let task = owner_task(&vault, owner);
        let written = vault
            .task_authority_state(task)
            .expect("the task's authority reads")
            .expect("the Owner fact this install's door wrote counts here");
        assert_eq!(written.owner_ref, owner);
        task
    };
    // The same vault reopened with the keystore installed, as the next start.
    let vault = Vault::open_owned(&vault_path, VaultConfig::server()).expect("the next start");
    install_signing_keystore(&keystore, &vault, &vault_path);
    assert_eq!(
        vault.adopt_unsigned_task_facts().expect("an adoption pass"),
        0,
        "the start that loaded this install's signer adopted the task facts written while \
         none was loaded"
    );
    let state = vault
        .task_authority_state(task)
        .expect("the task's authority reads after the adoption")
        .expect("the task still reads its owner");
    assert_eq!(state.owner_ref, owner);
}
