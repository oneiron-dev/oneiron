//! A shared vault never takes the own-device residence's id (FIX
//! [SHARED-VAULT-ID-7-OWN-DEVICE-ALIAS]).
//!
//! An owner's own-device Grant is an Owner row under the residence scope
//! (`federation::own_device_residence_scope`, vault 7). A shared vault's id is its creator's
//! pick, so a vault shared under 7 would give its Owner a member row with exactly an own-device
//! Grant's terms, and every reader that tells the two apart by scope would read one as the
//! other. Both doors that take a shared vault's id refuse it: the creation writer, before it
//! writes anything, and the preset pick's compile. Zero stays refused, and any other id still
//! shares.
//!
//! Runs on public paths:
//! `cargo test --locked -p oneiron --all-features --test shared_vault_residence_id`.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use oneiron::consent::AuthenticatedOwner;
use oneiron::federation::{FederationGrantScope, own_device_residence_scope};
use oneiron::registry::ENTITY_TYPE_FEDERATION_GRANT;
use oneiron::store::GateDecisionId;
use oneiron::test_support::provision_act_carrier;
use oneiron::vault_shape::{ShapePreset, ShapePresetPick, ShapeSeed};
use oneiron::{EntityId, Error, Vault, VaultConfig};

/// The own-device residence's vault id.
const RESIDENCE: u64 = 7;
/// An id a shared vault may take.
const SHARED: u64 = 41;
/// The phrase each refusal of the residence's id names.
const RESIDENCE_REFUSAL: &str = "own-device residence";

/// A vault whose install carries acts, so a creation can sign its creator's giving; its
/// embedded owner's proof.
fn carrier_vault() -> (tempfile::TempDir, Vault, AuthenticatedOwner) {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut config = VaultConfig::device();
    config.map_size = 16 * 1024 * 1024;
    config.dimensions = 4;
    config.embedding_model = None;
    let vault = Vault::open_owned(dir.path(), config).expect("vault");
    provision_act_carrier(&vault);
    let owner = vault.ensure_embedded_owner_actor().expect("owner");
    let proof = vault
        .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
        .expect("owner proof");
    (dir, vault, proof)
}

/// How many FEDERATION_GRANT rows the vault holds.
fn grant_rows(vault: &Vault) -> usize {
    vault
        .entity_ids_by_type_newest_first(ENTITY_TYPE_FEDERATION_GRANT)
        .expect("grant rows")
        .len()
}

/// A preset pick sharing under `vault_id`, with no founding member besides the creator.
fn pick(vault_id: u64) -> ShapePresetPick {
    ShapePresetPick {
        preset: ShapePreset::Family,
        vault_id,
        members: Vec::new(),
    }
}

#[test]
fn a_shared_vault_never_takes_the_residence_id() {
    assert_eq!(
        FederationGrantScope::vault(RESIDENCE),
        own_device_residence_scope(),
        "FIXTURE: the own-device residence is vault {RESIDENCE}"
    );
    let (_dir, vault, proof) = carrier_vault();
    let before = grant_rows(&vault);

    let created = vault.initialize_shared_vault(&proof, RESIDENCE, None, &[], 1);

    let Err(Error::InvalidConfig(reason)) = &created else {
        panic!(
            "vault_id={RESIDENCE}; expected the creation under the own-device residence's id \
             to be refused; seen {created:?}"
        );
    };
    assert!(
        reason.contains(RESIDENCE_REFUSAL),
        "vault_id={RESIDENCE}; expected the refusal to name the {RESIDENCE_REFUSAL}; seen \
         {reason:?}"
    );
    assert_eq!(
        vault.shared_vault_creation().expect("the creation read"),
        None,
        "vault_id={RESIDENCE}; expected a refused creation to leave the vault unshared"
    );
    assert_eq!(
        grant_rows(&vault),
        before,
        "vault_id={RESIDENCE}; expected a refused creation to write no grant row"
    );
}

#[test]
fn a_preset_pick_never_names_the_residence_id() {
    let compiled = ShapeSeed::for_preset(&pick(RESIDENCE), EntityId::now());

    let Err(Error::InvalidConfig(reason)) = &compiled else {
        panic!(
            "vault_id={RESIDENCE}; expected a preset pick under the own-device residence's id \
             to be refused before it plans; seen {compiled:?}"
        );
    };
    assert!(
        reason.contains(RESIDENCE_REFUSAL),
        "vault_id={RESIDENCE}; expected the refusal to name the {RESIDENCE_REFUSAL}; seen \
         {reason:?}"
    );
}

#[test]
fn any_other_id_still_shares() {
    let (_dir, vault, proof) = carrier_vault();

    let created = vault
        .initialize_shared_vault(&proof, SHARED, None, &[], 1)
        .expect("a shared vault under another id");

    assert_eq!(created.vault_id, SHARED, "the creation names its id");
    ShapeSeed::for_preset(&pick(SHARED), EntityId::now())
        .expect("a preset pick under another id compiles");
}

#[test]
fn zero_is_still_refused() {
    let (_dir, vault, proof) = carrier_vault();

    let created = vault.initialize_shared_vault(&proof, 0, None, &[], 1);
    let compiled = ShapeSeed::for_preset(&pick(0), EntityId::now());

    assert!(
        matches!(created, Err(Error::InvalidConfig(_))),
        "vault_id=0; expected the creation refused; seen {created:?}"
    );
    assert!(
        matches!(compiled, Err(Error::InvalidConfig(_))),
        "vault_id=0; expected the preset pick refused; seen {compiled:?}"
    );
}
