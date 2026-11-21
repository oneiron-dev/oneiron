//! Setting stage 7c-4 (DESIGN 15-setting-primitive 1.6, "Restore"): a copy restored into an empty
//! place on a vault a root roots is no machine of the vault until it joins (row
//! RESTORED-COPIES-ENROL-EACH-OTHER). Until then every stored row of the image is a bound on the
//! default the vault accepted and nothing more: a loosening waits and a tightening holds, a pin's
//! included; a `custom` key reads the image's value only when its comparator says it is no wider
//! than the default; a key with no order reads the image's value. The copy changes no `sync:
//! vault` setting, and a direct restore leaves the image's `sync: install` rows and residence
//! choice behind, as an activated archive leaves its install's with its replacement and a vault
//! that forgets its machine (a raw copy on another host) leaves them with it. Once the owner
//! joins it, every row reads current: nothing was deleted.
//!
//! On main (6ee3f3aafc0) the copy reads the image's rows as the source did, the engine's change
//! of a vault key commits on it, and the image's `sync: install` row comes back with the copy.
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test setting_restore_not_joined`.

#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::Path;
use std::sync::Arc;

use oneiron::authority::{HostSlipIssuer, MachineRole};
use oneiron::consent::AuthenticatedOwner;
use oneiron::setting::{SetSetting, SetSettingOutcome, SettingCaller, SettingMode, SettingSource};
use oneiron::store::GateDecisionId;
use oneiron::sync::SyncResidenceMode;
use oneiron::sync::residence::{load_device_sync_preference, set_device_sync_preference};
use oneiron::task_verb::sdk::invoke;
use oneiron::test_doors::setting::{
    ordered_cap_read, owner_number_read_both_ways, set_setting_as_engine,
};
use oneiron::test_support::test_host_issuer;
use oneiron::{EdgeActorClass, EntityId, Vault, VaultConfig};
use serde_json::{Value, json};

/// Lower is stricter; the default is 10.
const CAP: &str = "test.ordered_cap";
/// Lower is stricter; the default is 10.
const BUDGET: &str = "test.work_budget";
/// `custom`: a window no longer than another is no wider; the default is 10.
const WINDOW: &str = "test.custom_window";
/// No order; the default is 7.
const NUMBER: &str = "test.owner_number";
/// `sync: install`, no order; the default is 0.
const INSTALL: &str = "test.install_mode";
const GET: &str = "vault.settings.get";
/// The refusal's words that name the copy's state.
const NOT_JOINED: &str = "has not joined the vault";

/// The vault's first install: rooted, with its owner bound, its own unanswered serving profile,
/// and the vault's root held as its owner key, so the owner's acts are proved. It never
/// restored, so it is joined.
struct Host {
    _dir: tempfile::TempDir,
    vault: Vault,
    issuer: HostSlipIssuer,
    owner: EntityId,
    proof: AuthenticatedOwner,
    vault_id: [u8; 32],
}

fn rooted_host() -> Host {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("the host install");
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    let issuer = oneiron::test_support::provision_engine_machines(&vault);
    vault
        .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
        .expect("the host install profile");
    let owner = vault.ensure_embedded_owner_actor().expect("the owner");
    oneiron::test_support::bind_host_owner(&vault, &issuer, owner).expect("the owner binding");
    vault.hold_checkpoint_root_signer(Arc::new(test_host_issuer()));
    let proof = vault
        .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
        .expect("an owner proof");
    let vault_id = vault
        .authority_vault_id()
        .expect("the fold")
        .expect("a rooted vault");
    Host {
        _dir: dir,
        vault,
        issuer,
        owner,
        proof,
        vault_id,
    }
}

/// A copy restored beside a host from its checkpoint image, with its own keystore, owner proof
/// and enrolment request: born of a restore, and no machine of the vault yet.
struct Copy {
    vault: Vault,
    owner: EntityId,
    proof: AuthenticatedOwner,
}

/// The copy of `host` restored from an image taken now into an empty place under `backups`.
fn restored_copy(host: &Host, backups: &Path) -> Copy {
    let image = backups.join("image");
    host.vault
        .snapshot_checkpoint(&image, 100)
        .expect("FIXTURE: the image");
    let key = host.vault.checkpoint_key().expect("FIXTURE: its key");
    let origin = host
        .vault
        .side_restore_source()
        .expect("FIXTURE: the beside restore source");
    let (vault, _) = Vault::restore_checkpoint_beside(
        &image,
        &key,
        &backups.join("copy"),
        VaultConfig::device(),
        &origin,
        200,
    )
    .expect("FIXTURE: a copy of the image");
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    let owner = vault
        .ensure_embedded_owner_actor()
        .expect("FIXTURE: the owner on the copy");
    let proof = vault
        .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
        .expect("FIXTURE: an owner proof on the copy");
    let encryption = vault
        .machine_encryption_key(host.vault_id)
        .expect("FIXTURE: the copy's encryption key");
    let request = vault
        .machine_enrolment_request(host.vault_id, encryption)
        .expect("FIXTURE: the copy's enrolment request");
    assert!(
        vault
            .authority_fold()
            .expect("FIXTURE: the copy's fold")
            .machine(request.machine)
            .is_none(),
        "FIXTURE: the copy is no machine of the vault yet"
    );
    Copy {
        vault,
        owner,
        proof,
    }
}

/// The engine's change of `key`'s vault value row on `vault` to `value`, which must apply.
fn engine_sets(vault: &Vault, key: &str, value: Value) {
    let outcome = set_setting_as_engine(vault, None, SetSetting::vault_value(key, value))
        .unwrap_or_else(|error| panic!("FIXTURE: the engine's change of {key}: {error:?}"));
    assert!(
        matches!(outcome, SetSettingOutcome::Applied { .. }),
        "FIXTURE: the engine's change of {key} applied: {outcome:?}"
    );
}

/// The owner's pin of `key` at the vault on `vault`, which must apply.
fn owner_pins(vault: &Vault, proof: &AuthenticatedOwner, key: &str, value: Value) {
    let outcome = vault
        .set_setting(
            SettingCaller::Owner(proof),
            SetSetting {
                mode: SettingMode::Pin,
                ..SetSetting::vault_value(key, value)
            },
        )
        .unwrap_or_else(|error| panic!("FIXTURE: the owner's pin of {key}: {error:?}"));
    assert!(
        matches!(outcome, SetSettingOutcome::Applied { .. }),
        "FIXTURE: the owner's pin of {key} applied: {outcome:?}"
    );
}

/// `key`'s value in force on `vault`, through `vault.settings.get` as `owner`.
fn value_of(vault: &Vault, owner: EntityId, key: &str) -> Value {
    invoke(
        &vault.memory(owner, EdgeActorClass::Human),
        GET,
        json!({ "key": key }),
    )
    .unwrap_or_else(|error| panic!("{GET} answers for {key}: {error:?}"))["value"]
        .clone()
}

/// The owner's word that no other machine is left joins `copy` (`Vault::join_restored_install`),
/// with the vault's root held on it as the owner's key; the host is gone.
fn owner_joins(host: Host, copy: &Copy) {
    let Host {
        vault: source,
        issuer,
        ..
    } = host;
    drop(source);
    copy.vault
        .hold_checkpoint_root_signer(Arc::new(test_host_issuer()));
    copy.vault
        .join_restored_install(&issuer, &copy.proof, MachineRole::Unanswered)
        .expect("the owner's word joins the copy");
}

#[test]
fn an_unjoined_copy_reads_each_image_row_as_a_bound_on_the_default() {
    let host = rooted_host();
    engine_sets(&host.vault, CAP, json!(30));
    engine_sets(&host.vault, BUDGET, json!(4));
    engine_sets(&host.vault, WINDOW, json!(20));
    engine_sets(&host.vault, NUMBER, json!(3));
    assert_eq!(
        ordered_cap_read(&host.vault, &[]).expect("the read").value,
        30,
        "FIXTURE: the host reads its own loosening"
    );
    let backups = oneiron::test_support::restore_tempdir();
    let copy = restored_copy(&host, backups.path());

    let cap = ordered_cap_read(&copy.vault, &[]).expect("the copy's read");
    assert_eq!(
        (cap.value, cap.source),
        (10, SettingSource::Default),
        "the image's loosening waits: the copy reads the accepted default"
    );
    assert_eq!(
        value_of(&copy.vault, copy.owner, CAP),
        json!(10),
        "the verb's read holds the loosening back too"
    );
    assert_eq!(
        value_of(&copy.vault, copy.owner, BUDGET),
        json!(4),
        "the image's tightening holds"
    );
    assert_eq!(
        value_of(&copy.vault, copy.owner, WINDOW),
        json!(10),
        "a custom key's wider value waits: the copy reads the default"
    );
    let (typed, below) = owner_number_read_both_ways(&copy.vault, &[]).expect("the copy's read");
    assert_eq!(
        (typed.value, below.value),
        (3, 3),
        "a key with no order reads the image's value, through the vault and below it"
    );
}

#[test]
fn an_unjoined_copy_reads_a_pin_as_a_value_row_that_releases_nothing() {
    let host = rooted_host();
    owner_pins(&host.vault, &host.proof, CAP, json!(30));
    owner_pins(&host.vault, &host.proof, BUDGET, json!(2));
    assert_eq!(
        value_of(&host.vault, host.owner, CAP),
        json!(30),
        "FIXTURE: the host reads its owner's loose pin"
    );
    let backups = oneiron::test_support::restore_tempdir();
    let copy = restored_copy(&host, backups.path());

    assert_eq!(
        ordered_cap_read(&copy.vault, &[])
            .expect("the copy's read")
            .value,
        10,
        "a pin that loosens waits on the copy"
    );
    assert_eq!(
        value_of(&copy.vault, copy.owner, BUDGET),
        json!(2),
        "a pin that tightens holds on the copy"
    );
}

#[test]
fn an_unjoined_copy_changes_no_vault_setting_and_keeps_its_own_install_rows() {
    let host = rooted_host();
    engine_sets(&host.vault, BUDGET, json!(4));
    let backups = oneiron::test_support::restore_tempdir();
    let copy = restored_copy(&host, backups.path());

    match set_setting_as_engine(&copy.vault, None, SetSetting::vault_value(BUDGET, json!(3))) {
        Err(error) => assert!(
            format!("{error:?}").contains(NOT_JOINED),
            "the refusal names the copy's state: {error:?}"
        ),
        Ok(outcome) => panic!("an unjoined copy changed a vault setting: {outcome:?}"),
    }
    assert_eq!(
        value_of(&copy.vault, copy.owner, BUDGET),
        json!(4),
        "the refused change left the row as the image had it"
    );
    let unchanged =
        set_setting_as_engine(&copy.vault, None, SetSetting::vault_value(BUDGET, json!(4)))
            .expect("a change that leaves the row as it is still answers");
    assert!(
        matches!(unchanged, SetSettingOutcome::Applied { sequence: None, .. }),
        "an equal value writes nothing: {unchanged:?}"
    );
    engine_sets(&copy.vault, INSTALL, json!(4));
    assert_eq!(
        value_of(&copy.vault, copy.owner, INSTALL),
        json!(4),
        "the copy sets a choice about itself"
    );
}

#[test]
fn a_direct_restore_leaves_the_images_install_rows_behind() {
    let host = rooted_host();
    engine_sets(&host.vault, INSTALL, json!(5));
    assert_eq!(
        value_of(&host.vault, host.owner, INSTALL),
        json!(5),
        "FIXTURE: the host reads its own install choice"
    );
    let backups = oneiron::test_support::restore_tempdir();
    let copy = restored_copy(&host, backups.path());

    assert_eq!(
        value_of(&copy.vault, copy.owner, INSTALL),
        json!(0),
        "the new machine starts at the default: the host's choice about itself stayed behind"
    );
}

/// The vault a restore replaced, once the owner activates it beside its replacement
/// (`Vault::activate_archived`), joins as a new machine: the install's choice about itself stays
/// with the replacement, which is the machine the vault was, as a direct restore leaves the
/// image's behind (row SETTING-ACTIVATE-ARCHIVED-INSTALL-ROWS). On #10155's head (ab7ec09adcf)
/// the activated vault reads the install's choice.
#[cfg(unix)]
#[test]
fn an_activated_archive_leaves_its_install_rows_with_its_replacement() {
    let root = oneiron::test_support::restore_tempdir();
    let (home, image, staged) = (
        root.path().join("vault"),
        root.path().join("image"),
        root.path().join("staged"),
    );
    let keys = Arc::new(oneiron_keystore::MemoryKeystore::default());
    let vault = Vault::open(&home, VaultConfig::device()).expect("FIXTURE: the vault");
    vault.install_device_keystore(keys.clone());
    let owner = vault
        .ensure_embedded_owner_actor()
        .expect("FIXTURE: the owner");
    engine_sets(&vault, INSTALL, json!(5));
    assert_eq!(
        value_of(&vault, owner, INSTALL),
        json!(5),
        "FIXTURE: the vault reads its install's choice"
    );
    set_device_sync_preference(&vault, SyncResidenceMode::Opened)
        .expect("FIXTURE: the install's residence choice");
    vault
        .ensure_vault_key()
        .expect("FIXTURE: the vault data key");
    vault
        .snapshot_checkpoint(&image, 100)
        .expect("FIXTURE: the image");
    let key = vault.checkpoint_key().expect("FIXTURE: its key");
    let (replacement, _) = Vault::restore_checkpoint_replacing(
        &image,
        &key,
        &staged,
        VaultConfig::device(),
        &vault,
        200,
    )
    .expect("FIXTURE: the replacement");
    replacement.install_device_keystore(keys.clone());
    // As `oneiron restore` exchanges the two directories.
    vault
        .swap_in_replacement(&replacement, oneiron::store::exchange_held)
        .expect("FIXTURE: the swap");
    drop((vault, replacement));
    let replacement =
        Vault::open(&home, VaultConfig::device()).expect("FIXTURE: the replacement in its place");
    replacement.install_device_keystore(keys.clone());
    Vault::activate_archived(
        &staged,
        VaultConfig::device(),
        &replacement
            .side_restore_source()
            .expect("FIXTURE: the replacement as the source"),
    )
    .expect("the owner activates the archive");
    let side = Vault::open(&staged, VaultConfig::device()).expect("the activated vault opens");
    side.install_device_keystore(keys);

    assert_eq!(
        value_of(&side, owner, INSTALL),
        json!(0),
        "the activated vault joins as a new machine and starts at the default: the install's \
         choice about itself stayed with the replacement"
    );
    assert_eq!(
        value_of(&replacement, owner, INSTALL),
        json!(5),
        "the replacement is the machine the vault was, and keeps its choice"
    );
    assert_eq!(
        load_device_sync_preference(&side).expect("the activated vault's residence read"),
        None,
        "the activated vault starts at the default residence: the install's choice stayed with \
         the replacement"
    );
    assert_eq!(
        load_device_sync_preference(&replacement)
            .expect("the replacement's residence read")
            .map(|preference| preference.mode),
        Some(SyncResidenceMode::Opened),
        "the replacement keeps its residence choice"
    );
}

/// A direct restore leaves the image's residence choice behind with its machine identity, as it
/// leaves its `sync: install` setting rows: the new machine starts at the default (DESIGN
/// 15-setting-primitive 1.6, "Restore"; row SETTING-RESIDENCE-DEVICE-MODE-RIDES-IMAGE). On #10155's
/// head (ab7ec09adcf) the copy holds the host's choice.
#[test]
fn a_direct_restore_leaves_the_images_residence_choice_behind() {
    let host = rooted_host();
    set_device_sync_preference(&host.vault, SyncResidenceMode::Opened)
        .expect("FIXTURE: the host's residence choice");
    assert!(
        load_device_sync_preference(&host.vault)
            .expect("FIXTURE: the host's residence read")
            .is_some(),
        "FIXTURE: the host holds its residence choice"
    );
    let backups = oneiron::test_support::restore_tempdir();
    let copy = restored_copy(&host, backups.path());

    assert_eq!(
        load_device_sync_preference(&copy.vault).expect("the copy's residence read"),
        None,
        "the new machine starts at the default residence: the host's choice about itself stayed \
         behind"
    );
}

/// A vault whose install holds no seed for the machine it names (a raw copy on another host, a
/// lost keychain) forgets that machine and joins as a new one (`Vault::prepare_install_signing`):
/// the choices about the install it was go with it, its `sync: install` setting and its residence
/// choice, so the new machine starts at the defaults (DESIGN 15-setting-primitive 1.6,
/// "Restore"). On #10247's head 9ad1f63f2db the new machine reads the old install's choices.
#[test]
fn a_vault_that_forgets_its_machine_forgets_its_install_choices() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("FIXTURE: the vault");
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    let owner = vault
        .ensure_embedded_owner_actor()
        .expect("FIXTURE: the owner");
    let machine = vault
        .prepare_install_signing()
        .expect("FIXTURE: this install's machine and its signing keys");
    engine_sets(&vault, INSTALL, json!(5));
    set_device_sync_preference(&vault, SyncResidenceMode::Opened)
        .expect("FIXTURE: the install's residence choice");
    assert_eq!(
        value_of(&vault, owner, INSTALL),
        json!(5),
        "FIXTURE: the vault reads its install's choice"
    );

    // As on a raw copy on another host: no slot holds the seed of the machine the vault names.
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    let new_machine = vault
        .prepare_install_signing()
        .expect("the signing keys ready under an empty keystore");
    assert_ne!(
        new_machine, machine,
        "FIXTURE: the vault forgot its machine and joined as a new one"
    );

    assert_eq!(
        value_of(&vault, owner, INSTALL),
        json!(0),
        "the new machine starts at the default: the install's choice about itself went with the \
         machine it forgot"
    );
    assert_eq!(
        load_device_sync_preference(&vault).expect("the new machine's residence read"),
        None,
        "the new machine starts at the default residence: the install's choice went with the \
         machine it forgot"
    );
}

#[test]
fn a_joined_copy_reads_every_image_row_current() {
    let host = rooted_host();
    engine_sets(&host.vault, CAP, json!(30));
    engine_sets(&host.vault, WINDOW, json!(20));
    let backups = oneiron::test_support::restore_tempdir();
    let copy = restored_copy(&host, backups.path());
    owner_joins(host, &copy);

    assert_eq!(
        ordered_cap_read(&copy.vault, &[])
            .expect("the joined copy's read")
            .value,
        30,
        "joined, the copy reads the image's loosening: nothing was deleted"
    );
    assert_eq!(
        value_of(&copy.vault, copy.owner, WINDOW),
        json!(20),
        "joined, the copy reads the custom key's image value"
    );
    engine_sets(&copy.vault, CAP, json!(25));
    assert_eq!(
        ordered_cap_read(&copy.vault, &[])
            .expect("the joined copy's read")
            .value,
        25,
        "joined, the copy changes a vault setting"
    );
}
