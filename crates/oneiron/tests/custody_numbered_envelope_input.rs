#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]
//! FIX 5624: the numbered-envelope custody input (FIX 5521) is covered.
//!
//! A register's record framed with its manifest's text, past one envelope's
//! 16 MiB bound, seals as numbered envelopes in one frame, relays in parts,
//! and opens for a holder that is not the recorder. A frame with an
//! envelope dropped, two swapped, or its count rewritten does not open,
//! which the executor refuses as `invalid_input`. One missing part keeps
//! the request pending.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test fix_l5624_numbered_envelope_input`.

use oneiron::authority::{ActSurface, CustodyChange, MachineOwnership, MachineRole};
use oneiron::consent::AuthenticatedOwner;
use oneiron::secret_custody::{
    CustodyClass, CustodyInputBinding, CustodyTier, OwnerSecretRegistration, RequestedBinding,
    SealedCustodyChange, SealedInput, seal_custody_input,
};
use oneiron::test_doors::{custody_numbered_input as numbered, steward};
use oneiron::world_keys::OwnerWorkStatus;
use oneiron::{EntityId, Vault};

/// One envelope's plaintext bound: a body past it seals as numbered
/// envelopes (`oneiron_crypto::MAX_PLAINTEXT_LEN`).
const SIXTEEN_MIB: usize = 16 * 1024 * 1024;

/// The holder key the door tests seal to and open with.
const HOLDER_SEED: u8 = 0x66;

/// When the custody acts below happen.
const CUSTODY_AT: u64 = 1_780_000_000;

/// A record value plus framed manifest text that passes one envelope's
/// bound: 15 MiB of value and 2 MiB of manifest text.
fn large_register_body() -> (Vec<u8>, String) {
    (vec![0xA5; 15 * 1024 * 1024], "m".repeat(2 * 1024 * 1024))
}

/// A vault whose install can carry the owner's acts, its owner proof, and
/// this install's machine id, answered as the owner's (as in
/// `gate_pins_authority_custody_grants`).
fn enrolled_carrier() -> (tempfile::TempDir, Vault, AuthenticatedOwner, EntityId) {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = steward::open_owner_carrier_vault(dir.path()).expect("carrier vault");
    let owner = steward::owner(&vault).expect("owner proof");
    let machine = vault
        .local_machine()
        .expect("read this install")
        .expect("this install has a machine id")
        .id;
    vault
        .set_machine_role(
            &owner,
            ActSurface::ThisInstall,
            machine,
            MachineRole::Owned(MachineOwnership::Yours),
            None,
        )
        .expect("the owner answers this install is his");
    (dir, vault, owner, machine)
}

#[test]
fn door_sealed_register_opens_for_a_holder_that_is_not_the_recorder() {
    let (_dir, _vault, _, recorder) = enrolled_carrier();
    let holder = EntityId::now();
    assert_ne!(holder, recorder, "the holder is not the recorder");
    let (value, manifest) = large_register_body();
    let (frame, body_len, envelopes) = numbered::seal_numbered_register(
        holder,
        HOLDER_SEED,
        "numbered-input-test",
        &value,
        Some(&manifest),
    )
    .expect("seal the register");
    assert!(
        body_len > SIXTEEN_MIB,
        "the record plus framed manifest text passes one envelope's bound: {body_len}"
    );
    assert!(
        envelopes >= 2,
        "the body seals as numbered envelopes: {envelopes}"
    );
    assert_eq!(
        numbered::frame_envelope_count(&frame),
        Some(envelopes),
        "the frame counts its envelopes"
    );
    let (opened_value, opened_manifest, opened_name) =
        numbered::open_numbered_as_holder(&frame, holder, HOLDER_SEED)
            .expect("the holder opens its input");
    assert_eq!(opened_value, value, "the holder opens the whole value");
    assert_eq!(
        opened_manifest.as_deref(),
        Some(manifest.as_str()),
        "the holder opens the framed manifest text"
    );
    assert_eq!(opened_name, "numbered-input-test");
    assert!(
        numbered::open_numbered_as_holder(&frame, holder, HOLDER_SEED ^ 0x01).is_none(),
        "another key does not open the holder's input"
    );
    assert!(
        numbered::open_numbered_as_holder(&frame, EntityId::now(), HOLDER_SEED).is_none(),
        "another machine does not open the holder's input"
    );
}

#[test]
#[cfg(feature = "sync")]
fn numbered_input_relays_in_parts_and_opens_from_kept_rows() {
    let (_dir, vault, _, _) = enrolled_carrier();
    let holder = EntityId::now();
    let (value, manifest) = large_register_body();
    let (frame, _, _) = numbered::seal_numbered_register(
        holder,
        HOLDER_SEED,
        "numbered-input-test",
        &value,
        Some(&manifest),
    )
    .expect("seal the register");
    let (digest, parts) = numbered::keep_numbered(&vault, &frame).expect("keep the input");
    assert!(parts >= 2, "the input relays in parts: {parts}");
    match numbered::open_kept_numbered(&vault, &digest, holder, HOLDER_SEED)
        .expect("open the kept input")
    {
        numbered::KeptOpen::Opened {
            value: opened_value,
            manifest: opened_manifest,
            name: opened_name,
        } => {
            assert_eq!(opened_value, value, "the kept rows open to the whole value");
            assert_eq!(
                opened_manifest.as_deref(),
                Some(manifest.as_str()),
                "the kept rows open to the framed manifest text"
            );
            assert_eq!(opened_name, "numbered-input-test");
        }
        other => panic!("the kept input opens: {other:?}"),
    }
}

#[test]
fn tampered_numbered_frame_does_not_open() {
    let holder = EntityId::now();
    let (value, manifest) = large_register_body();
    let (frame, _, envelopes) = numbered::seal_numbered_register(
        holder,
        HOLDER_SEED,
        "numbered-input-test",
        &value,
        Some(&manifest),
    )
    .expect("seal the register");
    let dropped = numbered::drop_first_envelope(&frame).expect("drop the frame's first envelope");
    assert!(
        numbered::open_numbered_as_holder(&dropped, holder, HOLDER_SEED).is_none(),
        "a frame with an envelope dropped does not open"
    );
    let swapped =
        numbered::swap_first_two_envelopes(&frame).expect("swap the frame's first envelopes");
    assert!(
        numbered::open_numbered_as_holder(&swapped, holder, HOLDER_SEED).is_none(),
        "a frame with two envelopes swapped does not open"
    );
    let recounted =
        numbered::rewrite_envelope_count(&frame, envelopes + 1).expect("rewrite the frame's count");
    assert!(
        numbered::open_numbered_as_holder(&recounted, holder, HOLDER_SEED).is_none(),
        "a frame with its count rewritten does not open"
    );
    let singular =
        numbered::rewrite_envelope_count(&frame, 1).expect("rewrite the frame's count to one");
    assert!(
        numbered::open_numbered_as_holder(&singular, holder, HOLDER_SEED).is_none(),
        "a frame recounting one envelope does not open"
    );
    assert!(
        numbered::open_numbered_as_holder(&frame, holder, HOLDER_SEED).is_some(),
        "the untampered frame still opens"
    );
}

#[test]
#[cfg(feature = "sync")]
fn one_missing_part_keeps_the_request_pending() {
    let (_dir, vault, _, _) = enrolled_carrier();
    let holder = EntityId::now();
    let (value, manifest) = large_register_body();
    let (frame, _, _) = numbered::seal_numbered_register(
        holder,
        HOLDER_SEED,
        "numbered-input-test",
        &value,
        Some(&manifest),
    )
    .expect("seal the register");
    let (digest, parts) = numbered::keep_numbered(&vault, &frame).expect("keep the input");
    assert!(parts >= 2, "the input relays in parts: {parts}");
    assert!(
        numbered::drop_kept_part(&vault, &digest, 1).expect("drop one part"),
        "a part row was kept at index 1"
    );
    assert!(
        matches!(
            numbered::open_kept_numbered(&vault, &digest, holder, HOLDER_SEED)
                .expect("open the kept input"),
            numbered::KeptOpen::Missing
        ),
        "one missing part keeps the request pending"
    );
}

/// Registers a small portable secret this install holds, and seals a rotate
/// past one envelope's bound to this install's key through the public
/// surface seal. Returns the custody view and the sealed frame.
fn sealed_large_rotate(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    machine: EntityId,
    name: &str,
) -> (oneiron::secret_custody::SecretCustodyView, Vec<u8>) {
    vault
        .register_secret_as_owner(
            owner,
            &OwnerSecretRegistration {
                name,
                class: CustodyClass::CustodyPortable,
                device_only: false,
                rung: CustodyTier::T1Leased,
                bindings: vec![RequestedBinding {
                    effector: "deploy".to_owned(),
                    tier_ceiling: None,
                    scopes: vec!["read".to_owned()],
                }],
                manifest: None,
                value: b"small",
            },
            CUSTODY_AT,
        )
        .expect("register the portable secret");
    let view = vault
        .secret_custody_view(owner, name)
        .expect("read the custody view");
    let candidate = view
        .candidates
        .iter()
        .find(|candidate| candidate.this_install)
        .expect("this install is a custody candidate");
    let value = vec![0xA5; SIXTEEN_MIB + 1024];
    let frame = seal_custody_input(
        &CustodyInputBinding {
            vault_id: view.vault_id,
            secret_id: view.secret_id,
            change: CustodyChange::Rotate,
            generation: view.generation + 1,
            seen: view.seen,
            holder: machine,
            permits: &[candidate.permit],
        },
        &candidate.encryption_key,
        &value,
    )
    .expect("seal the rotate");
    assert!(
        numbered::frame_envelope_count(&frame).is_some_and(|count| count >= 2),
        "the rotate seals as numbered envelopes"
    );
    (view, frame)
}

#[test]
fn large_sealed_rotate_enacts_through_numbered_parts() {
    let (_dir, vault, owner, machine) = enrolled_carrier();
    let (view, frame) = sealed_large_rotate(&vault, &owner, machine, "numbered-rotate");
    let candidate = view
        .candidates
        .iter()
        .find(|candidate| candidate.this_install)
        .expect("this install is a custody candidate");
    let work = vault
        .seal_custody_change_as_owner(
            &owner,
            ActSurface::ThisInstall,
            &SealedCustodyChange {
                manifest_ref: None,
                change: CustodyChange::Rotate,
                secret_id: view.secret_id,
                generation: view.generation + 1,
                seen: view.seen,
                holder: machine,
                recipients: &[candidate.permit],
                input: SealedInput::Slice(&frame),
            },
            CUSTODY_AT + 1,
        )
        .expect("the holder enacts the numbered rotate");
    let receipt = work.work.expect("a recorded request");
    assert!(
        matches!(receipt.status, OwnerWorkStatus::Enacted),
        "the rotate is enacted: {:?}",
        receipt.status
    );
    assert_eq!(receipt.executor, Some(machine));
    let after = vault
        .secret_custody_view(&owner, "numbered-rotate")
        .expect("read the custody view again");
    assert_eq!(after.generation, view.generation + 1, "the rotation landed");
}

#[test]
fn tampered_sealed_rotate_is_refused_as_invalid_input() {
    let (_dir, vault, owner, machine) = enrolled_carrier();
    let (view, frame) = sealed_large_rotate(&vault, &owner, machine, "numbered-rotate-tampered");
    let candidate = view
        .candidates
        .iter()
        .find(|candidate| candidate.this_install)
        .expect("this install is a custody candidate");
    let mut tampered = frame;
    tampered[tampered.len() / 2] ^= 0x01;
    let err = vault
        .seal_custody_change_as_owner(
            &owner,
            ActSurface::ThisInstall,
            &SealedCustodyChange {
                manifest_ref: None,
                change: CustodyChange::Rotate,
                secret_id: view.secret_id,
                generation: view.generation + 1,
                seen: view.seen,
                holder: machine,
                recipients: &[candidate.permit],
                input: SealedInput::Slice(&tampered),
            },
            CUSTODY_AT + 1,
        )
        .expect_err("a tampered numbered input is refused");
    let msg = err.to_string();
    assert!(
        msg.contains("invalid_input"),
        "the refusal names invalid_input: {msg}"
    );
    assert!(
        msg.contains("nothing was written"),
        "the refusal wrote nothing: {msg}"
    );
    let after = vault
        .secret_custody_view(&owner, "numbered-rotate-tampered")
        .expect("read the custody view again");
    assert_eq!(after.live.len(), view.live.len(), "no request was recorded");
    assert_eq!(after.generation, view.generation, "no rotation landed");
}
