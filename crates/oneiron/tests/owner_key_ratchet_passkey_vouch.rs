//! The owner-key ratchet beside a passkey's vouch (AUTH-5 PR a, row
//! AUTHORITY-ONE-RULE, met with the limits of row WEB-PASSKEY-OWNER-KEY:
//! lead ruling WEBPASSKEY-BLIND-SIGNATURE = B, Engine ANSWER
//! WEBPASSKEY-LIMITED-KEY-OWNER-PROOF = A). The vault remembers an owner key
//! for good once the key can give the owner's proof. A key only a passkey
//! vouched for gives none until a key that is no passkey confirms it, so the
//! vault does not remember it at its enrolment, and does at its
//! confirmation: a hosted vault whose only Ed25519 owner key a passkey
//! vouched for asks for no owner key, and once the key is confirmed the
//! value a switch back to web sign-in carries covers it.
//!
//! The passkey is a software P-256 key; each assertion is built as a
//! browser's `navigator.credentials.get` returns it, as in
//! `passkey_owner_key.rs`.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test owner_key_ratchet_passkey_vouch`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeSet;
use std::sync::Arc;

use base64::Engine as _;
use ed25519_dalek::Signer as _;
use oneiron::authority::{
    ActAuthority, ActSurface, AuthorityKey, HostSlipIssuer, MachineRole, OwnerKeyEnrollment,
    OwnerKeyRequirement, OwnerPasskeyEnrollment, webauthn_assertion_envelope, webauthn_challenge,
};
use oneiron::consent::AuthenticatedOwner;
use oneiron::test_doors::label_writers::embedded_owner;
use oneiron::{HostingPrivacyPosture, Vault, VaultConfig};
use oneiron_authority::authority::web_sign_in_value;
use p256::ecdsa::signature::Signer as _;
use p256::ecdsa::{Signature as P256Signature, SigningKey as P256SigningKey};
use sha2::{Digest as _, Sha256};

/// User present and user verified.
const FLAGS_PRESENT_VERIFIED: u8 = 0x05;
/// The passkey's credential id (`rawId`).
const CREDENTIAL_ID: &[u8] = b"passkey-credential-0001";
/// The origin the passkey enrols and signs at.
const ORIGIN: &str = "https://oneiron.test";

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

    /// What the vault asks of its owner, read off its fold.
    fn requirement(&self) -> OwnerKeyRequirement {
        self.vault
            .authority_fold()
            .expect("authority fold")
            .owner_key_requirement()
    }
}

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

/// What `navigator.credentials.get` returns for `challenge`, the person
/// verified: authenticator data (RP id hash, flags, a zero sign count), the
/// client data JSON, and the DER signature over the one and SHA-256 of the
/// other.
fn assert_over(challenge: &[u8]) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let mut authenticator_data = Sha256::digest(b"oneiron.test").to_vec();
    authenticator_data.push(FLAGS_PRESENT_VERIFIED);
    authenticator_data.extend_from_slice(&[0; 4]);
    let client_data_json = format!(
        r#"{{"type":"webauthn.get","challenge":"{}","origin":"{ORIGIN}","crossOrigin":false}}"#,
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(challenge)
    )
    .into_bytes();
    let mut signed = authenticator_data.clone();
    signed.extend_from_slice(&Sha256::digest(&client_data_json));
    let signature: P256Signature = passkey().sign(&signed);
    (
        authenticator_data,
        client_data_json,
        signature.to_der().as_bytes().to_vec(),
    )
}

/// The passkey signs an authority transcript as the browser would: an
/// assertion over its challenge, in its envelope.
fn passkey_signs(transcript: &[u8]) -> Vec<u8> {
    let (authenticator_data, client_data_json, signature) =
        assert_over(&webauthn_challenge(transcript));
    webauthn_assertion_envelope(&authenticator_data, &client_data_json, &signature)
        .expect("an envelope")
}

/// Enrols the passkey with the host root as predecessor, as a hosted vault
/// with no owner key enrols its first one today. Answers its machine.
fn enrol_passkey(hosted: &HostedVault) -> oneiron::EntityId {
    let challenge = hosted
        .vault
        .owner_passkey_enrollment_challenge_as(&hosted.owner(), &passkey_public_key())
        .expect("the passkey's enrollment challenge");
    let (authenticator_data, client_data_json, signature) = assert_over(&challenge);
    hosted
        .vault
        .enrol_owner_passkey_as_host(
            &hosted.owner(),
            &OwnerPasskeyEnrollment {
                credential_id: CREDENTIAL_ID.to_vec(),
                public_key: passkey_public_key(),
                authenticator_data,
                client_data_json,
                signature,
            },
            &hosted.issuer,
        )
        .expect("the owner enrols his passkey")
        .machine
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

/// The owner's device key, which the host root vouches for.
fn owner_device() -> ed25519_dalek::SigningKey {
    ed25519_dalek::SigningKey::from_bytes(&[0x71; 32])
}

/// A device key only the passkey vouches for.
fn passkey_vouched_device() -> ed25519_dalek::SigningKey {
    ed25519_dalek::SigningKey::from_bytes(&[0x6C; 32])
}

/// The value a switch back to web sign-in carries over `keys`.
fn speaks_for(keys: &[&ed25519_dalek::SigningKey]) -> [u8; 32] {
    web_sign_in_value(
        &keys
            .iter()
            .map(|key| AuthorityKey::Ed25519(key.verifying_key().to_bytes()))
            .collect::<BTreeSet<_>>(),
    )
}

/// A hosted vault whose only Ed25519 owner key a passkey vouched for asks
/// for no owner key: neither the custodial root, nor the passkey, nor that
/// key gives the owner's proof, so no key could answer the ask. Once the
/// owner's device key confirms the vouched key, the vault asks under the
/// value over both keys: the confirmed key gives the proof from then on,
/// with no roster row of its own, and a switch back over the device key
/// alone would no longer speak for every key the vault has held.
#[test]
fn a_key_only_a_passkey_vouched_for_is_remembered_at_its_confirmation() {
    let hosted = HostedVault::open();
    let machine = enrol_passkey(&hosted);
    assert_eq!(
        hosted.requirement(),
        OwnerKeyRequirement::NeverHeld,
        "guard: a passkey gives no owner proof"
    );
    hosted
        .vault
        .enrol_owner_signing_key_as(
            &hosted.owner(),
            keyed_enrollment(&hosted, machine, &passkey_vouched_device()),
            passkey_roster_key(),
            |transcript| Ok(passkey_signs(transcript)),
        )
        .expect("the passkey vouches for a device key");
    assert_eq!(
        hosted.requirement(),
        OwnerKeyRequirement::NeverHeld,
        "a key only a passkey vouched for gives no owner proof, so the vault holds no key that does"
    );
    hosted
        .vault
        .enrol_owner_signing_key_as_host(
            &hosted.owner(),
            keyed_enrollment(&hosted, machine, &owner_device()),
            &hosted.issuer,
        )
        .expect("the owner's device key");
    assert_eq!(
        hosted.requirement(),
        OwnerKeyRequirement::Required {
            web_sign_in_switch: Some(speaks_for(&[&owner_device()])),
        },
        "guard: the owner's device key gives the proof, and the vouched key is not yet held"
    );
    hosted
        .vault
        .confirm_owner_key_as(
            &hosted.owner(),
            keyed_enrollment(&hosted, machine, &passkey_vouched_device()),
            AuthorityKey::Ed25519(owner_device().verifying_key().to_bytes()),
            |transcript| Ok(owner_device().sign(transcript).to_bytes().to_vec()),
        )
        .expect("the owner's device key confirms the passkey-vouched key");
    assert_eq!(
        hosted.requirement(),
        OwnerKeyRequirement::Required {
            web_sign_in_switch: Some(speaks_for(&[&owner_device(), &passkey_vouched_device()])),
        },
        "the confirmed key gives the owner's proof from its confirmation on"
    );
}
