//! ROLES-CHECKIN P2.5, row 2k3a (ARCH-0082 #act-table "Key recovery (C)"
//! and #owner-own-acts; Engine ruling P25-SHAPE Q1 = A, 14 Nov 13:39): the
//! step-up resets and the root request, in the 2j apply shape.
//!
//! - `vault.step_up.passkeys.reset`, `vault.step_up.totp.reset` and
//!   `vault.roots.requests.create` take `check_in_ref`. An Owner's own act
//!   is never gated: its answer records the Owner's own-proof decision.
//! - With `check_in_ref` the Owner applies another asker's approved
//!   check-in for that exact effect on their own proof: it is spent in the
//!   act's writer, the answer names the asker as requester, and it applies
//!   once. A check-in for another person, another factor or another change
//!   does nothing and stays unspent.
//! - A root request for an install this one cannot name records nothing: it
//!   answers no decision and leaves the check-in unspent.
//!
//! The ask is opened here through the check-in test doors on a chain whose
//! Owner rung is the vault owner, as in `check_in_erase_effects`. The root
//! request's target is a second install the owner enrolled as theirs.
//!
//! On the base (1daae67dc2a) this file does not build: the three requests
//! have no `check_in_ref`, their answers no `check_in`, and the two effect
//! digests do not exist.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test check_in_key_recovery_effects`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

#[path = "check_in/owner_apply_fixture.rs"]
mod owner_apply_fixture;

use std::sync::Arc;

use oneiron::authority::{
    ActSurface, MachineOwnership, MachineRole, RootChange, StepUpFactor,
    StepUpPasskeysResetRequest, StepUpTotpResetRequest,
};
use oneiron::check_in::{ActClass, root_request_effect_digest, step_up_reset_effect_digest};
use oneiron::consent::AuthenticatedOwner;
use oneiron::verbs::{
    RootRequestCreateRequest, create_root_request_as, reset_step_up_passkeys_as,
    reset_step_up_totp_as,
};
use oneiron::{EntityId, Vault, VaultConfig};
use oneiron_keystore::MemoryKeystore;
use owner_apply_fixture::{approved, owner_decision, rooted, spent};

const PASSKEYS_RESET: &str = "vault.step_up.passkeys.reset";
const TOTP_RESET: &str = "vault.step_up.totp.reset";
const ROOT_REQUEST: &str = "vault.roots.requests.create";

/// A second install that asked to join `vault` and that its owner enrolled
/// as theirs: an install this one can name. Its directory, held so its
/// files outlive the test, and its machine id.
fn linked_install(
    vault: &Vault,
    owner_proof: &AuthenticatedOwner,
) -> (tempfile::TempDir, EntityId) {
    let dir = tempfile::tempdir().expect("tempdir");
    let install = Vault::open(dir.path(), VaultConfig::device()).expect("open the joining install");
    install.install_device_keystore(Arc::new(MemoryKeystore::default()));
    let vault_id = vault
        .authority_vault_id()
        .expect("read the vault id")
        .expect("a rooted vault");
    let key = install
        .machine_encryption_key(vault_id)
        .expect("its encryption key");
    let request = install
        .machine_enrolment_request(vault_id, key)
        .expect("its enrolment request");
    vault
        .enroll_machine(
            owner_proof,
            ActSurface::ThisInstall,
            &request,
            MachineRole::Owned(MachineOwnership::Yours),
            None,
        )
        .expect("the owner enrols it");
    (dir, request.machine)
}

#[test]
fn the_owner_applies_an_approved_passkey_reset_once() {
    let (_dir, vault, owner, owner_proof) = rooted();
    let person = EntityId::now();
    let reset = |person: EntityId, check_in_ref: Option<EntityId>| {
        reset_step_up_passkeys_as(
            &vault,
            &owner_proof,
            StepUpPasskeysResetRequest {
                person: person.to_hex(),
                check_in_ref: check_in_ref.map(|id| id.to_hex()),
            },
        )
    };

    let own = reset(person, None).expect("the owner resets on their own proof");
    assert_eq!(own.removed, 0, "no passkey here: nothing to remove");
    assert_eq!(
        own.check_in,
        Some(owner_decision(ActClass::KeyRecovery, None, None)),
        "the Owner's own reset records their own proof"
    );

    let digest = step_up_reset_effect_digest(&person, StepUpFactor::Passkey);
    let (asked, asker) = approved(
        &vault,
        owner,
        &owner_proof,
        PASSKEYS_RESET,
        ActClass::KeyRecovery,
        &digest,
    );
    let other_person = reset(EntityId::now(), Some(asked));
    assert!(
        other_person.is_err(),
        "an ask for another person resets nothing: {other_person:?}"
    );
    assert!(!spent(&vault, &asked), "a refused apply spends nothing");

    let applied = reset(person, Some(asked)).expect("the owner applies the approved reset");
    assert_eq!(
        applied.check_in,
        Some(owner_decision(
            ActClass::KeyRecovery,
            Some(asked),
            Some(asker)
        )),
        "the answer names the check-in it applied and its asker"
    );
    assert!(
        spent(&vault, &asked),
        "the reset's writer spent the check-in"
    );
    let again = reset(person, Some(asked));
    assert!(again.is_err(), "a spent check-in applies once: {again:?}");
}

#[test]
fn a_passkey_reset_ask_does_not_apply_to_the_authenticator_app_reset() {
    let (_dir, vault, owner, owner_proof) = rooted();
    let person = EntityId::now();
    let reset = |check_in_ref: Option<EntityId>| {
        reset_step_up_totp_as(
            &vault,
            &owner_proof,
            StepUpTotpResetRequest {
                person: person.to_hex(),
                check_in_ref: check_in_ref.map(|id| id.to_hex()),
            },
        )
    };

    let own = reset(None).expect("the owner resets on their own proof");
    assert_eq!(own.removed, 0, "no authenticator app here");
    assert_eq!(
        own.check_in,
        Some(owner_decision(ActClass::KeyRecovery, None, None)),
        "the Owner's own reset records their own proof"
    );

    let passkeys = step_up_reset_effect_digest(&person, StepUpFactor::Passkey);
    let (passkey_ask, _) = approved(
        &vault,
        owner,
        &owner_proof,
        PASSKEYS_RESET,
        ActClass::KeyRecovery,
        &passkeys,
    );
    let crossed = reset(Some(passkey_ask));
    assert!(
        crossed.is_err(),
        "a passkey reset's ask resets no authenticator app: {crossed:?}"
    );
    assert!(
        !spent(&vault, &passkey_ask),
        "a refused apply spends nothing"
    );

    let digest = step_up_reset_effect_digest(&person, StepUpFactor::Totp);
    let (asked, asker) = approved(
        &vault,
        owner,
        &owner_proof,
        TOTP_RESET,
        ActClass::KeyRecovery,
        &digest,
    );
    let applied = reset(Some(asked)).expect("the owner applies the approved reset");
    assert_eq!(
        applied.check_in,
        Some(owner_decision(
            ActClass::KeyRecovery,
            Some(asked),
            Some(asker)
        )),
        "the answer names the check-in it applied and its asker"
    );
    assert!(
        spent(&vault, &asked),
        "the reset's writer spent the check-in"
    );
}

#[test]
fn the_owner_applies_an_approved_root_request_once_on_an_install_they_can_name() {
    let (_dir, vault, owner, owner_proof) = rooted();
    let (_target_dir, target) = linked_install(&vault, &owner_proof);
    let (_other_dir, other) = linked_install(&vault, &owner_proof);
    let activate = |target: EntityId, check_in_ref: Option<EntityId>| {
        create_root_request_as(
            &vault,
            &owner_proof,
            ActSurface::ThisInstall,
            RootRequestCreateRequest {
                target: target.to_hex(),
                change: "activate".to_owned(),
                root: None,
                machine: None,
                check_in_ref: check_in_ref.map(|id| id.to_hex()),
            },
        )
    };

    let own = activate(target, None).expect("the owner requests on their own proof");
    assert!(
        own.receipt.request.is_some(),
        "a linked install's request is recorded: {own:?}"
    );
    assert_eq!(
        own.check_in,
        Some(owner_decision(ActClass::KeyRecovery, None, None)),
        "the Owner's own request records their own proof"
    );

    let digest = root_request_effect_digest(&target, RootChange::Activate);
    let (asked, asker) = approved(
        &vault,
        owner,
        &owner_proof,
        ROOT_REQUEST,
        ActClass::KeyRecovery,
        &digest,
    );
    let unnamed = activate(EntityId::now(), Some(asked)).expect("an unnamed install answers");
    assert!(
        unnamed.receipt.request.is_none() && unnamed.check_in.is_none(),
        "an install this one cannot name records nothing: {unnamed:?}"
    );
    assert!(
        !spent(&vault, &asked),
        "a request that records nothing spends nothing"
    );
    let crossed = activate(other, Some(asked));
    assert!(
        crossed.is_err(),
        "an ask for another install's change records nothing: {crossed:?}"
    );
    assert!(!spent(&vault, &asked), "a refused apply spends nothing");

    let applied = activate(target, Some(asked)).expect("the owner applies the approved request");
    assert!(
        applied.receipt.request.is_some(),
        "it is recorded: {applied:?}"
    );
    assert_eq!(
        applied.check_in,
        Some(owner_decision(
            ActClass::KeyRecovery,
            Some(asked),
            Some(asker)
        )),
        "the answer names the check-in it applied and its asker"
    );
    assert!(
        spent(&vault, &asked),
        "the request's writer spent the check-in"
    );
    let again = activate(target, Some(asked));
    assert!(again.is_err(), "a spent check-in applies once: {again:?}");
}
