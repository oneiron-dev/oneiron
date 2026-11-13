//! An opened device admits its owner's paired slip once its authority
//! catch-up also brings the own-device grant the slip names, and refuses it
//! once that grant's withdrawal crosses (FIX 23747, Engine RULING
//! OPENED-DEVICE-GRANT-CATCHUP = A, 13 Nov). The home here is a vault whose
//! owner paired a device; the opened device is a second vault that took the
//! home's signed authority history only, as an opened device's authority
//! catch-up brings it, and no window. The grant catch-up runs its two halves
//! in process: the home's answer (`own_device_grant_states`, which
//! `residence.authority.grants` serves a proven linked machine through
//! `own_device_grants_for`) and the device's admission
//! (`admit_own_device_grants`). Built only under `--cfg oneiron_test_support`.
#![cfg(oneiron_test_support)]

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use ed25519_dalek::{Signer, SigningKey};
use oneiron::authority::{MachineRole, PairingPrincipal, PeerMachine};
use oneiron::federation::Scope;
use oneiron::sync::residence::{
    OwnDeviceGrantState, admit_own_device_grants, own_device_grant_refs, own_device_grant_states,
    own_device_grants_for,
};
use oneiron::test_doors::label_writers::embedded_owner;
use oneiron::test_doors::own_device_grant::retire_own_device_grants;
use oneiron::{EntityId, Vault, VaultConfig};

/// The binding key seed of the owner's paired device.
const DEVICE_BINDING_SEED: u8 = 0x5A;

/// A home whose owner paired a device: the paired slip and the own-device
/// grant it names.
struct Home {
    vault: Vault,
    _dir: tempfile::TempDir,
    owner: EntityId,
    slip_id: [u8; 32],
    grant: EntityId,
}

fn home() -> Home {
    let dir = tempfile::tempdir().expect("home vault directory");
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("home vault");
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    let issuer = oneiron::test_support::provision_engine_machines(&vault);
    // The owner's pairing link is an owner act this install's live machine
    // profile carries, as a serving start or `init` enrols it (FIX 4648).
    vault
        .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
        .expect("this install's live machine profile");
    let (owner, owner_proof) = embedded_owner(&vault).expect("authenticated embedded owner");
    let holder = owner.to_hex();
    let link = vault
        .issue_owner_pairing_link(
            &issuer,
            &owner_proof,
            Scope::top(),
            3_600,
            PairingPrincipal {
                holder_ref: Some(holder.clone()),
                ..PairingPrincipal::default()
            },
        )
        .expect("the owner issues a pairing link for their own device");
    let signing_key = SigningKey::from_bytes(&[DEVICE_BINDING_SEED; 32]);
    let binding_key = signing_key.verifying_key().to_bytes();
    let transcript = oneiron::authority::pairing_binding_transcript_pinned(
        &link.code,
        &binding_key,
        &holder,
        link.pin.as_ref(),
    )
    .expect("the device's pairing transcript");
    let slip = vault
        .redeem_pairing_link(
            &issuer,
            &link.code,
            &holder,
            binding_key,
            &signing_key.sign(&transcript).to_bytes(),
        )
        .expect("the owner's device redeems the link");
    let grant = slip
        .claims
        .grant_ref
        .as_deref()
        .map(EntityId::from_hex)
        .expect("the owner's paired slip names their own-device grant (FIX 3134)")
        .expect("the named grant is an entity id");
    Home {
        vault,
        _dir: dir,
        owner,
        slip_id: slip.claims.slip_id,
        grant,
    }
}

/// An opened device of `home`'s vault: a fresh vault that took the home's
/// signed authority history and no window, so it holds the slip's mint and
/// not the grant row.
fn opened_device(home: &Home) -> (Vault, tempfile::TempDir) {
    let dir = tempfile::tempdir().expect("device vault directory");
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("device vault");
    // A replayed withdrawal that erases a row signs its receipt here.
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    let history = home
        .vault
        .export_signed_authority_history()
        .expect("the home exports its signed authority history");
    vault
        .import_signed_authority_history(&history)
        .expect("the device takes the home's authority history");
    (vault, dir)
}

/// Whether `vault` admits slip `id` now: its mint is live and the grant it
/// names stands. A refusal that errs counts as a refusal.
fn admits(vault: &Vault, id: &[u8; 32]) -> bool {
    matches!(vault.capability_slip_id_is_live(id), Ok(true))
}

/// One grant catch-up round: the device asks about the grants its live
/// slips name and the own-device grants it holds, the home answers, and the
/// device admits the answer.
fn catch_up(
    home: &Home,
    device: &Vault,
) -> (
    BTreeMap<EntityId, BTreeSet<String>>,
    Vec<(EntityId, OwnDeviceGrantState)>,
    oneiron::sync::residence::OwnDeviceGrantAdmission,
) {
    let asked = own_device_grant_refs(device).expect("the device reads the grants it asks about");
    let ids: BTreeSet<EntityId> = asked.keys().copied().collect();
    let served =
        own_device_grant_states(&home.vault, &ids).expect("the home answers the device's ask");
    let admission = admit_own_device_grants(device, &asked, served.clone())
        .expect("the device admits the home's answer");
    (asked, served, admission)
}

#[test]
fn opened_device_admits_existing_owner_slip_after_authority_catchup_and_reopen() {
    let home = home();
    assert!(
        admits(&home.vault, &home.slip_id),
        "control: the home admits the owner's paired slip"
    );
    let (device, dir) = opened_device(&home);
    assert!(
        !admits(&device, &home.slip_id),
        "an opened device with the authority history alone refuses the slip: the grant row it names is not here"
    );

    let (asked, served, admission) = catch_up(&home, &device);
    assert!(
        asked
            .get(&home.grant)
            .is_some_and(|holders| holders.contains(&home.owner.to_hex())),
        "the device asks about the owner's own-device grant its live slip names: {asked:?}"
    );
    assert!(
        matches!(served.as_slice(), [(id, OwnDeviceGrantState::Live(_))] if *id == home.grant),
        "the home serves the grant's stored row: {served:?}"
    );
    assert_eq!(
        admission.landed,
        BTreeSet::from([home.grant]),
        "the row lands through the entity ingest: {admission:?}"
    );
    assert!(admission.refused.is_empty() && admission.withdrawn.is_empty());
    assert!(
        admits(&device, &home.slip_id),
        "after the grant catch-up the opened device admits the owner's slip"
    );

    let (_, _, again) = catch_up(&home, &device);
    assert_eq!(
        again.landed,
        BTreeSet::from([home.grant]),
        "a second round finds the row already here: {again:?}"
    );

    drop(device);
    let device = Vault::open(dir.path(), VaultConfig::device()).expect("the device reopens");
    assert!(
        admits(&device, &home.slip_id),
        "after a reopen the opened device still admits the owner's slip"
    );
}

#[test]
fn withdrawn_own_device_grant_crosses_and_refuses_the_owner_slip() {
    let home = home();
    let (device, _dir) = opened_device(&home);
    let (asked, live, _) = catch_up(&home, &device);
    assert!(
        admits(&device, &home.slip_id),
        "precondition: the device admits the owner's slip once the grant row landed"
    );

    let retired =
        retire_own_device_grants(&home.vault, home.owner).expect("the home retires the grant");
    assert_eq!(
        retired,
        vec![home.grant],
        "the home retires the owner's grant"
    );
    assert!(
        !admits(&home.vault, &home.slip_id),
        "control: the home refuses the slip once its grant is withdrawn"
    );

    let (_, served, admission) = catch_up(&home, &device);
    assert!(
        matches!(served.as_slice(), [(id, OwnDeviceGrantState::Withdrawn(_))] if *id == home.grant),
        "the home serves the grant's withdrawal: {served:?}"
    );
    assert_eq!(
        admission.withdrawn,
        BTreeSet::from([home.grant]),
        "the withdrawal replays on the device: {admission:?}"
    );
    assert!(
        !admits(&device, &home.slip_id),
        "the withdrawal crossed: the opened device refuses the owner's slip"
    );

    let stale =
        admit_own_device_grants(&device, &asked, live).expect("the device judges a stale live row");
    assert!(
        stale.landed.is_empty(),
        "a stale live row of the withdrawn grant does not land again: {stale:?}"
    );
    assert!(
        !admits(&device, &home.slip_id),
        "the withdrawn grant does not stand again"
    );
}

#[test]
fn grant_catchup_serves_only_a_proven_machine_and_lands_only_asked_grants() {
    let home = home();
    let (device, _dir) = opened_device(&home);
    let asked = own_device_grant_refs(&device).expect("the device reads the grants it asks about");
    let ids: BTreeSet<EntityId> = asked.keys().copied().collect();
    assert!(
        own_device_grants_for(&home.vault, PeerMachine::Unknown, &ids).is_err(),
        "the home refuses a peer that proved no linked machine"
    );

    let served =
        own_device_grant_states(&home.vault, &ids).expect("the home answers the device's ask");
    let admission = admit_own_device_grants(&device, &BTreeMap::new(), served)
        .expect("the device judges an answer it did not ask for");
    assert!(
        admission.landed.is_empty() && admission.refused.contains(&home.grant),
        "a grant the device did not ask about is refused: {admission:?}"
    );
    assert!(
        !admits(&device, &home.slip_id),
        "nothing landed: the device still refuses the slip"
    );
}

/// Review round 1 of #7485, at the reviewed head: the admission takes no
/// answerer, so an endpoint that proved no machine of the vault answers as
/// the home does. It serves an empty tombstone for the live grant; the
/// device must take nothing from it.
#[test]
fn grant_catchup_takes_no_withdrawal_from_a_home_that_proved_no_machine_of_the_vault() {
    let home = home();
    let (device, _dir) = opened_device(&home);
    let (asked, _, admission) = catch_up(&home, &device);
    assert_eq!(admission.landed, BTreeSet::from([home.grant]));
    assert!(
        admits(&device, &home.slip_id),
        "precondition: the device admits the owner's slip once the grant row landed"
    );

    let forged = vec![(home.grant, OwnDeviceGrantState::Withdrawn(Vec::new()))];
    let admission = admit_own_device_grants(&device, &asked, forged)
        .expect("the device judges the unproven answer");
    assert!(
        admission.withdrawn.is_empty()
            && admission.landed.is_empty()
            && admission.refused == BTreeSet::from([home.grant]),
        "an answer from an endpoint that proved nothing is refused whole: {admission:?}"
    );
    assert!(
        admits(&device, &home.slip_id),
        "the grant still stands: the owner's slip is admitted"
    );
}
