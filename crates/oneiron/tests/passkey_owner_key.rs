//! A browser passkey is an owner key of a hosted vault (row
//! WEB-PASSKEY-OWNER-KEY; lead ruling CARRIER-HOSTED-WEB-ACTS = C, Engine
//! ruling WAYBACK-E4 shape (b): the passkey's own WebAuthn signature, so the
//! key never leaves the authenticator).
//!
//! The owner enrols his passkey through the owner key enrollment act, its
//! assertion over the enrollment challenge as its proof of possession; the
//! fold puts its P-256 key on the roster as an owner root of its own,
//! outside the host's custody. Then the passkey vouches for a new device's
//! key: its assertion over the entry's transcript is the predecessor's
//! signature, which the fold verifies. An assertion over another challenge,
//! one the authenticator made without verifying the person, or one made at
//! another origin than the passkey's enrollment (a sibling under the same RP
//! id), enrols nothing.
//!
//! A key only the passkey vouched for acts in part (lead ruling
//! WEBPASSKEY-BLIND-SIGNATURE = B): it cannot fence the owner's device key
//! and vouches for no further key until a non-passkey key, here a device
//! key, vouches for it too; the passkey itself cannot confirm it. After
//! that confirmation it acts as any owner root.
//!
//! The passkey is a software P-256 key here; each assertion is built as a
//! browser's `navigator.credentials.get` returns it (authenticator data,
//! client data JSON, DER signature).
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test passkey_owner_key`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use base64::Engine as _;
use ed25519_dalek::Signer as _;
use oneiron::authority::{
    ActAuthority, ActSurface, AuthorityKey, HostSlipIssuer, MachineRole, OwnerKeyEnrollment,
    OwnerPasskeyEnrollment, ROLE_OWNER, webauthn_assertion_envelope, webauthn_challenge,
};
use oneiron::consent::AuthenticatedOwner;
use oneiron::test_doors::label_writers::embedded_owner;
use oneiron::test_doors::passkey_vouch_limits::revoke_owner_key_signed_by;
use oneiron::{HostingPrivacyPosture, Vault, VaultConfig};
use p256::ecdsa::signature::Signer as _;
use p256::ecdsa::{Signature as P256Signature, SigningKey as P256SigningKey};
use sha2::{Digest as _, Sha256};

/// User present and user verified.
const FLAGS_PRESENT_VERIFIED: u8 = 0x05;
/// User present alone.
const FLAGS_PRESENT_ONLY: u8 = 0x01;

/// One vault under the Hosted posture, rooted under the test host, with this
/// install's machine profile enrolled and the embedded owner authenticated.
/// The vault drops first.
struct HostedVault {
    vault: Vault,
    issuer: HostSlipIssuer,
    proof: AuthenticatedOwner,
    _dir: tempfile::TempDir,
}

impl HostedVault {
    fn open() -> Self {
        let dir = tempfile::tempdir().expect("vault directory");
        let mut config = VaultConfig::device();
        config.privacy.posture = HostingPrivacyPosture::Hosted;
        let vault = Vault::open(dir.path(), config).expect("hosted vault");
        vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
        let issuer = oneiron::test_support::provision_engine_machines(&vault);
        vault
            .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
            .expect("this install's machine profile under the host root");
        let (_, proof) = embedded_owner(&vault).expect("authenticated embedded owner");
        Self {
            vault,
            issuer,
            proof,
            _dir: dir,
        }
    }

    fn owner(&self) -> ActAuthority {
        ActAuthority::Owner(self.proof.clone(), ActSurface::ThisInstall)
    }

    fn live_owner_key(&self, key: &AuthorityKey) -> bool {
        let fold = self.vault.authority_fold().expect("authority fold");
        fold.roster
            .get(key)
            .is_some_and(|device| !device.revoked && device.roles & ROLE_OWNER != 0)
    }
}

/// The passkey's credential id (`rawId`).
const CREDENTIAL_ID: &[u8] = b"passkey-credential-0001";

/// The passkey a platform authenticator holds, as a software key.
fn passkey() -> P256SigningKey {
    P256SigningKey::from_slice(&[0x5A; 32]).expect("a P-256 scalar")
}

/// The credential's public key as `getPublicKey()` hands its point:
/// uncompressed SEC1.
fn passkey_public_key() -> Vec<u8> {
    passkey()
        .verifying_key()
        .to_encoded_point(false)
        .as_bytes()
        .to_vec()
}

/// The passkey's key as the roster names it: compressed SEC1.
fn passkey_roster_key() -> AuthorityKey {
    AuthorityKey::P256(
        passkey()
            .verifying_key()
            .to_encoded_point(true)
            .as_bytes()
            .to_vec(),
    )
}

/// What `navigator.credentials.get` returns for `challenge`: authenticator
/// data (RP id hash, `flags`, a zero sign count), the client data JSON, and
/// the DER signature over the one and SHA-256 of the other.
struct Assertion {
    authenticator_data: Vec<u8>,
    client_data_json: Vec<u8>,
    signature: Vec<u8>,
}

/// The origin the passkey enrols at.
const ORIGIN: &str = "https://oneiron.test";
/// Another page under the same RP id.
const SIBLING_ORIGIN: &str = "https://docs.oneiron.test";

fn assert_over(challenge: &[u8], flags: u8) -> Assertion {
    assert_over_at(challenge, flags, ORIGIN)
}

fn assert_over_at(challenge: &[u8], flags: u8, origin: &str) -> Assertion {
    let mut authenticator_data = Sha256::digest(b"oneiron.test").to_vec();
    authenticator_data.push(flags);
    authenticator_data.extend_from_slice(&[0; 4]);
    let client_data_json = format!(
        r#"{{"type":"webauthn.get","challenge":"{}","origin":"{origin}","crossOrigin":false}}"#,
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(challenge)
    )
    .into_bytes();
    let mut signed = authenticator_data.clone();
    signed.extend_from_slice(&Sha256::digest(&client_data_json));
    let signature: P256Signature = passkey().sign(&signed);
    Assertion {
        authenticator_data,
        client_data_json,
        signature: signature.to_der().as_bytes().to_vec(),
    }
}

fn passkey_enrollment(assertion: Assertion) -> OwnerPasskeyEnrollment {
    OwnerPasskeyEnrollment {
        credential_id: CREDENTIAL_ID.to_vec(),
        public_key: passkey_public_key(),
        authenticator_data: assertion.authenticator_data,
        client_data_json: assertion.client_data_json,
        signature: assertion.signature,
    }
}

/// The passkey signs an authority transcript as the browser would: an
/// assertion over its challenge, in its envelope.
fn passkey_signs(transcript: &[u8], flags: u8) -> Vec<u8> {
    passkey_signs_at(transcript, flags, ORIGIN)
}

fn passkey_signs_at(transcript: &[u8], flags: u8, origin: &str) -> Vec<u8> {
    let assertion = assert_over_at(&webauthn_challenge(transcript), flags, origin);
    webauthn_assertion_envelope(
        &assertion.authenticator_data,
        &assertion.client_data_json,
        &assertion.signature,
    )
    .expect("an envelope")
}

/// Enrols the passkey with the host root as predecessor, as a hosted vault
/// with no owner key enrols its first one today.
fn enrol_passkey(hosted: &HostedVault) -> oneiron::authority::OwnerPasskeyEnrollmentReceipt {
    let challenge = hosted
        .vault
        .owner_passkey_enrollment_challenge_as(&hosted.owner(), &passkey_public_key())
        .expect("the passkey's enrollment challenge");
    hosted
        .vault
        .enrol_owner_passkey_as_host(
            &hosted.owner(),
            &passkey_enrollment(assert_over(&challenge, FLAGS_PRESENT_VERIFIED)),
            &hosted.issuer,
        )
        .expect("the owner enrols his passkey")
}

/// A fresh device key and its proof for `machine`, as a new device's
/// keystore makes them.
fn device_enrollment(hosted: &HostedVault, machine: oneiron::EntityId) -> OwnerKeyEnrollment {
    keyed_enrollment(
        hosted,
        machine,
        &ed25519_dalek::SigningKey::from_bytes(&[0x6B; 32]),
    )
}

/// `device`'s enrollment input for `machine`: its key and its proof.
fn keyed_enrollment(
    hosted: &HostedVault,
    machine: oneiron::EntityId,
    device: &ed25519_dalek::SigningKey,
) -> OwnerKeyEnrollment {
    let public_key = device.verifying_key().to_bytes();
    let challenge = hosted
        .vault
        .owner_key_enrollment_challenge_as(&hosted.owner(), machine, &public_key)
        .expect("the device key's challenge");
    OwnerKeyEnrollment {
        machine,
        public_key,
        proof: device.sign(&challenge).to_bytes().to_vec(),
    }
}

#[test]
fn a_passkey_enrols_as_an_owner_key_of_a_hosted_vault() {
    let hosted = HostedVault::open();
    let receipt = enrol_passkey(&hosted);
    let key = passkey_roster_key();
    assert_eq!(
        AuthorityKey::P256(receipt.public_key.clone()),
        key,
        "the receipt names the passkey's key"
    );
    assert_eq!(
        receipt.credential_id, CREDENTIAL_ID,
        "the enrollment records the passkey's credential id"
    );
    assert!(
        hosted.live_owner_key(&key),
        "the passkey's key is a live owner root on the roster"
    );
    assert!(
        !hosted
            .vault
            .authority_key_in_host_custody(&key)
            .expect("custody read"),
        "the passkey starts its own custody line: the host does not hold it"
    );
}

#[test]
fn the_enrolled_passkey_vouches_for_a_new_device_key() {
    let hosted = HostedVault::open();
    let receipt = enrol_passkey(&hosted);
    let input = device_enrollment(&hosted, receipt.machine);
    let device_key = AuthorityKey::Ed25519(input.public_key);
    hosted
        .vault
        .enrol_owner_signing_key_as(&hosted.owner(), input, passkey_roster_key(), |transcript| {
            Ok(passkey_signs(transcript, FLAGS_PRESENT_VERIFIED))
        })
        .expect("the passkey signs the new device's key in");
    assert!(
        hosted.live_owner_key(&device_key),
        "the device key the passkey vouched for is a live owner root"
    );
}

#[test]
fn a_passkey_assertion_over_another_challenge_enrols_nothing() {
    let hosted = HostedVault::open();
    let mut wrong = hosted
        .vault
        .owner_passkey_enrollment_challenge_as(&hosted.owner(), &passkey_public_key())
        .expect("the passkey's enrollment challenge");
    wrong[0] ^= 1;
    let refused = hosted.vault.enrol_owner_passkey_as_host(
        &hosted.owner(),
        &passkey_enrollment(assert_over(&wrong, FLAGS_PRESENT_VERIFIED)),
        &hosted.issuer,
    );
    assert!(
        refused.is_err(),
        "a proof over another challenge is no proof"
    );
    assert!(
        !hosted.live_owner_key(&passkey_roster_key()),
        "nothing was enrolled"
    );
}

#[test]
fn a_passkey_that_did_not_verify_the_person_vouches_for_nothing() {
    let hosted = HostedVault::open();
    let receipt = enrol_passkey(&hosted);
    let input = device_enrollment(&hosted, receipt.machine);
    let device_key = AuthorityKey::Ed25519(input.public_key);
    let refused = hosted.vault.enrol_owner_signing_key_as(
        &hosted.owner(),
        input,
        passkey_roster_key(),
        |transcript| Ok(passkey_signs(transcript, FLAGS_PRESENT_ONLY)),
    );
    assert!(
        refused.is_err(),
        "an assertion without user verification signs no owner act"
    );
    assert!(!hosted.live_owner_key(&device_key), "nothing was enrolled");
}

#[test]
fn a_passkey_assertion_from_a_sibling_origin_vouches_for_nothing() {
    let hosted = HostedVault::open();
    let receipt = enrol_passkey(&hosted);
    let input = device_enrollment(&hosted, receipt.machine);
    let device_key = AuthorityKey::Ed25519(input.public_key);
    let refused = hosted.vault.enrol_owner_signing_key_as(
        &hosted.owner(),
        input,
        passkey_roster_key(),
        |transcript| {
            Ok(passkey_signs_at(
                transcript,
                FLAGS_PRESENT_VERIFIED,
                SIBLING_ORIGIN,
            ))
        },
    );
    assert!(
        refused.is_err(),
        "the passkey enrolled at its own origin signs nothing made at a sibling's"
    );
    assert!(!hosted.live_owner_key(&device_key), "nothing was enrolled");
}

/// The owner's device key, held here: enrolled by the host root.
fn owner_device() -> ed25519_dalek::SigningKey {
    ed25519_dalek::SigningKey::from_bytes(&[0x71; 32])
}

/// A key the host holds, which a mislabelled prompt had the passkey vouch for.
fn host_held() -> ed25519_dalek::SigningKey {
    ed25519_dalek::SigningKey::from_bytes(&[0x6B; 32])
}

fn ed_key(key: &ed25519_dalek::SigningKey) -> AuthorityKey {
    AuthorityKey::Ed25519(key.verifying_key().to_bytes())
}

/// A hosted vault with the owner's passkey and device key, and a host-held
/// key that only the passkey vouched for. Answers the carrier.
fn passkey_vouched_host_key(hosted: &HostedVault) -> oneiron::EntityId {
    let machine = enrol_passkey(hosted).machine;
    hosted
        .vault
        .enrol_owner_signing_key_as_host(
            &hosted.owner(),
            keyed_enrollment(hosted, machine, &owner_device()),
            &hosted.issuer,
        )
        .expect("the owner's device key");
    hosted
        .vault
        .enrol_owner_signing_key_as(
            &hosted.owner(),
            keyed_enrollment(hosted, machine, &host_held()),
            passkey_roster_key(),
            |transcript| Ok(passkey_signs(transcript, FLAGS_PRESENT_VERIFIED)),
        )
        .expect("the passkey vouches for the host-held key");
    assert!(
        hosted.live_owner_key(&ed_key(&host_held())),
        "guard: the passkey-vouched key is a live owner key"
    );
    machine
}

/// The host-held key signs a revoke of the owner's device key; true when
/// it counted.
fn host_key_revokes_device_key(hosted: &HostedVault) -> bool {
    revoke_owner_key_signed_by(
        &hosted.vault,
        ed_key(&host_held()),
        ed_key(&owner_device()),
        |transcript| host_held().sign(transcript).to_bytes().to_vec(),
    )
    .unwrap_or(false)
}

#[test]
fn a_key_only_a_passkey_vouched_for_cannot_fence_the_owners_device_key() {
    let hosted = HostedVault::open();
    passkey_vouched_host_key(&hosted);
    assert!(
        !host_key_revokes_device_key(&hosted),
        "a key only the passkey vouched for revokes no other owner key"
    );
    assert!(
        hosted.live_owner_key(&ed_key(&owner_device())),
        "the owner's device key stands"
    );
}

#[test]
fn once_a_device_key_confirms_it_the_passkey_vouched_key_acts() {
    let hosted = HostedVault::open();
    let machine = passkey_vouched_host_key(&hosted);
    hosted
        .vault
        .confirm_owner_key_as(
            &hosted.owner(),
            keyed_enrollment(&hosted, machine, &host_held()),
            ed_key(&owner_device()),
            |transcript| Ok(owner_device().sign(transcript).to_bytes().to_vec()),
        )
        .expect("the owner's device key confirms the passkey-vouched key");
    assert!(
        host_key_revokes_device_key(&hosted),
        "after the confirmation the key acts as any owner root"
    );
    assert!(
        !hosted.live_owner_key(&ed_key(&owner_device())),
        "its revoke of the device key counted"
    );
}

#[test]
fn a_key_only_a_passkey_vouched_for_vouches_for_no_further_key() {
    let hosted = HostedVault::open();
    let machine = passkey_vouched_host_key(&hosted);
    let further = ed25519_dalek::SigningKey::from_bytes(&[0x5C; 32]);
    let refused = hosted.vault.enrol_owner_signing_key_as(
        &hosted.owner(),
        keyed_enrollment(&hosted, machine, &further),
        ed_key(&host_held()),
        |transcript| Ok(host_held().sign(transcript).to_bytes().to_vec()),
    );
    assert!(refused.is_err(), "an unconfirmed key vouches for nothing");
    assert!(
        !hosted.live_owner_key(&ed_key(&further)),
        "nothing was enrolled"
    );
}

#[test]
fn a_passkey_does_not_confirm_the_key_it_vouched_for() {
    let hosted = HostedVault::open();
    let machine = passkey_vouched_host_key(&hosted);
    let refused = hosted.vault.confirm_owner_key_as(
        &hosted.owner(),
        keyed_enrollment(&hosted, machine, &host_held()),
        passkey_roster_key(),
        |transcript| Ok(passkey_signs(transcript, FLAGS_PRESENT_VERIFIED)),
    );
    assert!(
        refused.is_err(),
        "only a non-passkey key confirms a passkey's vouch"
    );
    assert!(
        !host_key_revokes_device_key(&hosted),
        "the key is still unconfirmed"
    );
}
