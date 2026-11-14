//! FIX 23943 [HOME-HANDOFF-RETIRE-TAKES-ANY-PURPOSE]: the holder's retire
//! half of the home handoff (`home_handoff_retire` -> `retire_held` ->
//! `home_handoff_custody::retire`) retires only home handoff keys. A
//! request that names the ref of a key custody holds for another purpose,
//! here a federation grant's scope opening, is refused with the typed
//! `StoreError::ErasableKeyPurposeMismatch`, and every key it names stays
//! live.
//!
//! The fixture is one device vault: a home handoff key minted as an export
//! mints it, and a scope opening key installed as an accepted Connect
//! installs it. The peer proof the public door runs first is not under
//! test; the doors call the retire half it reaches.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test home_handoff_retire_purpose`.
#![cfg(all(oneiron_test_support, feature = "sync"))]

use std::sync::Arc;

use oneiron::error::StoreError;
use oneiron::test_doors::home_handoff_retire::{
    ErasableKeyState, erasable_key_state, install_grant_scope_key, mint_home_handoff_key,
    retire_held,
};
use oneiron::{EntityId, Error, Vault, VaultConfig};

/// A fresh device vault with a process-memory keystore.
fn vault() -> (Vault, tempfile::TempDir) {
    let dir = tempfile::tempdir().expect("vault directory");
    let vault = Vault::open(dir.path().join("vault"), VaultConfig::device()).expect("fresh vault");
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    (vault, dir)
}

fn state(vault: &Vault, key: &str) -> ErasableKeyState {
    erasable_key_state(vault, key).expect("the key's state")
}

#[test]
fn a_grant_scope_ref_passed_to_retire_is_refused_and_its_entry_stays_live() {
    let (vault, _dir) = vault();
    let grant_key =
        install_grant_scope_key(&vault, EntityId::now()).expect("a grant's scope opening key");
    assert_eq!(state(&vault, &grant_key), ErasableKeyState::Live);

    let answer = retire_held(&vault, EntityId::now(), std::slice::from_ref(&grant_key));

    assert_eq!(
        state(&vault, &grant_key),
        ErasableKeyState::Live,
        "a peer's home handoff retire request retired a grant's scope opening key",
    );
    assert!(
        matches!(
            answer,
            Err(Error::Store(StoreError::ErasableKeyPurposeMismatch))
        ),
        "the request is refused with the typed purpose error, got {answer:?}",
    );
}

#[test]
fn a_request_naming_a_grant_scope_ref_stages_none_of_its_keys() {
    let (vault, _dir) = vault();
    let handoff_key = mint_home_handoff_key(&vault, EntityId::now()).expect("a home handoff key");
    let grant_key =
        install_grant_scope_key(&vault, EntityId::now()).expect("a grant's scope opening key");

    let answer = retire_held(
        &vault,
        EntityId::now(),
        &[handoff_key.clone(), grant_key.clone()],
    );

    assert_eq!(
        (state(&vault, &handoff_key), state(&vault, &grant_key)),
        (ErasableKeyState::Live, ErasableKeyState::Live),
        "a refused request retired a key it named",
    );
    assert!(
        matches!(
            answer,
            Err(Error::Store(StoreError::ErasableKeyPurposeMismatch))
        ),
        "the request is refused with the typed purpose error, got {answer:?}",
    );
}

#[test]
fn a_home_handoff_ref_passed_to_retire_is_retired() {
    let (vault, _dir) = vault();
    let handoff_key = mint_home_handoff_key(&vault, EntityId::now()).expect("a home handoff key");
    assert_eq!(state(&vault, &handoff_key), ErasableKeyState::Live);

    let named = retire_held(&vault, EntityId::now(), std::slice::from_ref(&handoff_key))
        .expect("the holder retires its copy of a home handoff key");

    assert_eq!(named, 1);
    assert_eq!(state(&vault, &handoff_key), ErasableKeyState::Retired);
}
