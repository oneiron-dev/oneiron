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
//! that confirmation it acts as any owner root. The passkey's own signature
//! revokes no other owner key either (Engine ruling
//! WEBPASSKEY-PASSKEY-OWN-REVOKE = B). Nor does the limited key shed its
//! limits through a row no door writes: it rotates to no successor and
//! enrols no device that could re-root, and its cosign lends no consent to
//! an agent's revoke of another owner key (Sol xhigh stack review F1, F2),
//! nor revokes, on a sibling branch, an owner key its own parents do not
//! hold yet (Astra stack review finding 1), nor answers a machine as the
//! owner's or removes one by a roster-signed profile (OPUS-SECREAD-A N1),
//! nor unbinds or rebinds another owner key's actor (Astra delta review
//! finding 1), nor binds itself to any actor, whose row would then be an
//! actor's for good (Astra delta 2 review finding 1). A device key's
//! enrolment of a key confirms it, so a passkey's vouch for the same key on
//! a sibling branch limits nothing once the fold merges the two (Astra
//! delta review finding 2).
//! A passkey that only another passkey vouched for has its own confirmation
//! door (F5).
//!
//! The owner's choice "Let my passkey remove devices and keys" (choice id
//! `passkey.full_owner`; Engine ruling WEBPASSKEY-OPTIN-HOME = A) lifts
//! every one of these limits while it is on, for the passkey and for every
//! key only a passkey vouched for. Only an owner key's proof by a key the
//! limits do not reach turns it on, and turning it off brings the limits
//! back, also for each key a limited key vouched for or rotated to while it
//! was on, and for each device whose enrolment rested on a limited key's
//! cosign. It reads at each row's parents: a row on a sibling branch of the
//! choice keeps the limits, and an off beside an on that did not see it
//! reads off. A vault whose only owner key is a passkey asks for no proof
//! (Engine ruling CARRIER-ASKS-ON-PASSKEY-ONLY-VAULT = A), so its web
//! session turns the choice off, never on.
//!
//! The passkey is a software P-256 key here; each assertion is built as a
//! browser's `navigator.credentials.get` returns it (authenticator data,
//! client data JSON, DER signature).
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test passkey_owner_key`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeSet;
use std::sync::Arc;

use base64::Engine as _;
use ed25519_dalek::Signer as _;
use oneiron::authority::{
    ActAuthority, ActSurface, AuthorityAttestation, AuthorityKey, AuthorityOp, AuthorityTier,
    DeviceAuthority, HostSlipIssuer, MACHINE_ENCRYPTION_KEY_LEN,
    MACHINE_ENCRYPTION_SUITE_HYBRID_V1, MachineDeviceClass, MachineEncryptionKey, MachineOwnership,
    MachineProfile, MachineRole, OwnerKeyEnrollment, OwnerPasskeyEnrollment, ROLE_AGENT,
    ROLE_OWNER, machine_profile_proof_transcript, webauthn_assertion_envelope, webauthn_challenge,
};
use oneiron::consent::AuthenticatedOwner;
use oneiron::test_doors::label_writers::embedded_owner;
use oneiron::test_doors::passkey_vouch_limits::{
    SignedRow, append_signed_rows, append_signed_rows_on, enrol_owner_key_on, main_log_heads,
    revoke_owner_key_signed_by, set_passkey_full_owner,
};
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
    assert_by(&passkey(), challenge, flags, origin)
}

/// What `navigator.credentials.get` returns for `challenge` when the
/// passkey `key` answers it at `origin`.
fn assert_by(key: &P256SigningKey, challenge: &[u8], flags: u8, origin: &str) -> Assertion {
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
    let signature: P256Signature = key.sign(&signed);
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

/// Astra delta review finding 1: the owner's device key binds a fresh owner
/// key as the owner; a key only the passkey vouched for then revokes that
/// binding on a sibling branch at the highest epoch (which no later bind
/// could clear once the branches merge), and rebinds the key to another
/// actor at the heads. Neither counts.
#[test]
fn a_key_only_a_passkey_vouched_for_unbinds_no_other_owner_key() {
    let hosted = HostedVault::open();
    let machine = passkey_vouched_host_key(&hosted);
    let fork = main_log_heads(&hosted.vault).expect("the heads before the fork");
    let fresh = ed_key(&fresh_owner_key());
    hosted
        .vault
        .enrol_owner_signing_key_as(
            &hosted.owner(),
            keyed_enrollment(&hosted, machine, &fresh_owner_key()),
            ed_key(&owner_device()),
            |transcript| Ok(owner_device().sign(transcript).to_bytes().to_vec()),
        )
        .expect("the owner's device key enrols a fresh key");
    let owner = hosted
        .proof
        .actor_for_read(&hosted.vault)
        .expect("the vault's owner");
    let bound = append_signed_rows(
        &hosted.vault,
        vec![SignedRow {
            op: AuthorityOp::BindActor {
                authority_key: fresh.clone(),
                actor_ref: owner,
                actor_class: "human".to_owned(),
                epoch: 1,
            },
            signer: ed_key(&owner_device()),
            cosigners: Vec::new(),
        }],
        signs_as,
    )
    .expect("the bind is stored");
    assert_eq!(
        bound,
        vec![true],
        "guard: the owner's device key binds the fresh key as the owner"
    );
    let revoked = append_signed_rows_on(
        &hosted.vault,
        fork,
        vec![SignedRow {
            op: AuthorityOp::RevokeActor {
                authority_key: fresh.clone(),
                epoch: u64::MAX,
            },
            signer: ed_key(&host_held()),
            cosigners: Vec::new(),
        }],
        signs_as,
    )
    .unwrap_or_default();
    assert!(
        !revoked.first().copied().unwrap_or(false),
        "the limited key's sibling revoke of the fresh key's binding counts for nothing"
    );
    let rebound = append_signed_rows(
        &hosted.vault,
        vec![SignedRow {
            op: AuthorityOp::RebindActor {
                authority_key: fresh,
                actor_ref: oneiron::EntityId::now(),
                actor_class: "human".to_owned(),
                epoch: 2,
            },
            signer: ed_key(&host_held()),
            cosigners: Vec::new(),
        }],
        signs_as,
    )
    .unwrap_or_default();
    assert!(
        !rebound.first().copied().unwrap_or(false),
        "the limited key rebinds no other owner key to another actor"
    );
}

/// The host-held key's binding of itself to `actor_ref`, signed by itself.
fn host_key_binds_itself_to(actor_ref: oneiron::EntityId) -> SignedRow {
    SignedRow {
        op: AuthorityOp::BindActor {
            authority_key: ed_key(&host_held()),
            actor_ref,
            actor_class: "human".to_owned(),
            epoch: 1,
        },
        signer: ed_key(&host_held()),
        cosigners: Vec::new(),
    }
}

/// Astra delta 2 review finding 1: an accepted binding makes its actor row
/// an actor's on every branch for good, and a machine whose row is an
/// actor's loses its standing on each of its chains. So a key only the
/// passkey vouched for binds itself to no actor (here the row of a machine
/// the owner may answer for on another branch). Once a device key confirms
/// the key, the same binding counts.
#[test]
fn a_key_only_a_passkey_vouched_for_binds_itself_to_no_actor() {
    let machine_row = oneiron::EntityId::now();
    let limited = HostedVault::open();
    passkey_vouched_host_key(&limited);
    let bound = append_signed_rows(
        &limited.vault,
        vec![host_key_binds_itself_to(machine_row)],
        signs_as,
    )
    .unwrap_or_default();
    assert!(
        !bound.first().copied().unwrap_or(false),
        "the limited key's binding of itself to a machine's row counts for nothing"
    );

    let confirmed = HostedVault::open();
    let machine = passkey_vouched_host_key(&confirmed);
    confirmed
        .vault
        .confirm_owner_key_as(
            &confirmed.owner(),
            keyed_enrollment(&confirmed, machine, &host_held()),
            ed_key(&owner_device()),
            |transcript| Ok(owner_device().sign(transcript).to_bytes().to_vec()),
        )
        .expect("the owner's device key confirms the passkey-vouched key");
    assert_eq!(
        append_signed_rows(
            &confirmed.vault,
            vec![host_key_binds_itself_to(machine_row)],
            signs_as,
        )
        .expect("the binding is stored"),
        vec![true],
        "guard: once confirmed, the same binding counts"
    );
}

/// Astra delta review finding 2: the owner's device key enrols a fresh key
/// at the heads, and the passkey vouches for the same key on a sibling
/// branch (a blind signature the page's host obtained). Once the fold merges
/// the two, the key acts in full: the device key's enrolment confirms it, so
/// it revokes the passkey-vouched key.
#[test]
fn a_device_keys_enrolment_confirms_against_a_sibling_passkey_vouch() {
    let hosted = HostedVault::open();
    let machine = passkey_vouched_host_key(&hosted);
    let fork = main_log_heads(&hosted.vault).expect("the heads before the fork");
    hosted
        .vault
        .enrol_owner_signing_key_as(
            &hosted.owner(),
            keyed_enrollment(&hosted, machine, &fresh_owner_key()),
            ed_key(&owner_device()),
            |transcript| Ok(owner_device().sign(transcript).to_bytes().to_vec()),
        )
        .expect("the owner's device key enrols a fresh key");
    let vouched = enrol_owner_key_on(
        &hosted.vault,
        &hosted.owner(),
        keyed_enrollment(&hosted, machine, &fresh_owner_key()),
        fork,
        passkey_roster_key(),
        |transcript| passkey_signs(transcript, FLAGS_PRESENT_VERIFIED),
    )
    .expect("the sibling vouch is stored");
    assert!(
        vouched,
        "guard: the passkey's sibling vouch for the same fresh key counts"
    );
    assert!(
        revoke_owner_key_signed_by(
            &hosted.vault,
            ed_key(&fresh_owner_key()),
            ed_key(&host_held()),
            |transcript| fresh_owner_key().sign(transcript).to_bytes().to_vec(),
        )
        .unwrap_or(false),
        "the key the device key enrolled acts in full after the merge"
    );
}

/// The install key of a machine a roster-signed profile answers for.
fn machine_install() -> ed25519_dalek::SigningKey {
    ed25519_dalek::SigningKey::from_bytes(&[0x4C; 32])
}

/// `signer`'s roster-signed profile of a fresh machine in `role`, with the
/// machine's own proof, stored for the fold to judge; true when it counted.
fn answers_fresh_machine(
    hosted: &HostedVault,
    signer: &ed25519_dalek::SigningKey,
    role: MachineRole,
) -> bool {
    let vault_id = hosted
        .vault
        .authority_vault_id()
        .expect("the vault id read")
        .expect("a rooted vault");
    let machine = oneiron::EntityId::now();
    let install = machine_install();
    let machine_key = install.verifying_key().to_bytes();
    let encryption_key = || MachineEncryptionKey {
        suite: MACHINE_ENCRYPTION_SUITE_HYBRID_V1,
        key: vec![7; MACHINE_ENCRYPTION_KEY_LEN],
    };
    let machine_proof = install
        .sign(&machine_profile_proof_transcript(
            &vault_id,
            machine,
            &machine_key,
            MachineDeviceClass::Computer,
            &encryption_key(),
        ))
        .to_bytes();
    let owner = hosted
        .proof
        .actor_for_read(&hosted.vault)
        .expect("the vault's owner");
    let op = AuthorityOp::MachineProfile(MachineProfile {
        machine,
        owner,
        machine_key,
        device_class: MachineDeviceClass::Computer,
        encryption_key: encryption_key(),
        role,
        revision: 1,
        machine_proof,
        seen_world_edits: BTreeSet::new(),
        carrier: None,
        act: None,
    });
    append_signed_rows(
        &hosted.vault,
        vec![SignedRow {
            op,
            signer: ed_key(signer),
            cosigners: Vec::new(),
        }],
        signs_as,
    )
    .unwrap_or_default()
    .first()
    .copied()
    .unwrap_or(false)
}

/// OPUS-SECREAD-A N1: a roster-signed machine profile is the owner's
/// answer for a machine, so a key only the passkey vouched for answers no
/// machine as the owner's (a node the page's operator runs would then merge
/// as his) and removes none (lead ruling WEBPASSKEY-BLIND-SIGNATURE = B:
/// the vouch and revoke class). Judged by role, not by the machine's
/// presence, so no sibling branch reopens it.
#[test]
fn a_key_only_a_passkey_vouched_for_answers_no_machine_as_the_owners() {
    let hosted = HostedVault::open();
    passkey_vouched_host_key(&hosted);
    assert!(
        !answers_fresh_machine(
            &hosted,
            &host_held(),
            MachineRole::Owned(MachineOwnership::Yours)
        ),
        "the limited key answers no machine as the owner's"
    );
    assert!(
        !answers_fresh_machine(&hosted, &host_held(), MachineRole::Removed),
        "the limited key removes no machine"
    );
}

/// Once a device key confirms it, the passkey-vouched key answers a
/// machine as the owner's as any owner-held root does.
#[test]
fn once_confirmed_the_passkey_vouched_key_answers_a_machine_as_the_owners() {
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
        answers_fresh_machine(
            &hosted,
            &host_held(),
            MachineRole::Owned(MachineOwnership::Yours)
        ),
        "the confirmed key's machine answer counts"
    );
}

/// A fresh key the owner's device key enrols on one branch.
fn fresh_owner_key() -> ed25519_dalek::SigningKey {
    ed25519_dalek::SigningKey::from_bytes(&[0x55; 32])
}

/// Astra stack review finding 1: a key only the passkey vouched for signs a
/// revoke of a key its parents do not hold, on a sibling branch of the
/// owner's enrolment of that key. The revoke counts for nothing; else its
/// tombstone revokes the owner key once the fold merges the two branches.
#[test]
fn a_key_only_a_passkey_vouched_for_revokes_no_owner_key_on_a_sibling_branch() {
    let hosted = HostedVault::open();
    let machine = passkey_vouched_host_key(&hosted);
    let fork = main_log_heads(&hosted.vault).expect("the heads before the fork");
    let fresh = ed_key(&fresh_owner_key());
    hosted
        .vault
        .enrol_owner_signing_key_as(
            &hosted.owner(),
            keyed_enrollment(&hosted, machine, &fresh_owner_key()),
            ed_key(&owner_device()),
            |transcript| Ok(owner_device().sign(transcript).to_bytes().to_vec()),
        )
        .expect("the owner's device key enrols a fresh key");
    assert!(
        hosted.live_owner_key(&fresh),
        "guard: the fresh key is a live owner key"
    );
    let counted = append_signed_rows_on(
        &hosted.vault,
        fork,
        vec![SignedRow {
            op: AuthorityOp::RevokeDevice {
                revoked_key: fresh.clone(),
            },
            signer: ed_key(&host_held()),
            cosigners: Vec::new(),
        }],
        signs_as,
    )
    .unwrap_or_default();
    assert!(
        !counted.first().copied().unwrap_or(false),
        "the limited key's revoke of a key its parents do not hold counts for nothing"
    );
    assert!(
        hosted.live_owner_key(&fresh),
        "the owner's fresh key stands once the branches merge"
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

#[test]
fn the_passkey_itself_cannot_revoke_the_owners_device_key() {
    let hosted = HostedVault::open();
    passkey_vouched_host_key(&hosted);
    let counted = revoke_owner_key_signed_by(
        &hosted.vault,
        passkey_roster_key(),
        ed_key(&owner_device()),
        |transcript| passkey_signs(transcript, FLAGS_PRESENT_VERIFIED),
    )
    .unwrap_or(false);
    assert!(
        !counted,
        "a mislabelled passkey prompt cancels no other owner key"
    );
    assert!(
        hosted.live_owner_key(&ed_key(&owner_device())),
        "the owner's device key stands"
    );
}

/// A key the host holds, which a key only the passkey vouched for hands its
/// standing to, by a row no door writes.
fn successor() -> ed25519_dalek::SigningKey {
    ed25519_dalek::SigningKey::from_bytes(&[0x3E; 32])
}

/// The key the host would re-root the vault to.
fn new_root() -> ed25519_dalek::SigningKey {
    ed25519_dalek::SigningKey::from_bytes(&[0x2F; 32])
}

/// An agent key, which holds no consent.
fn agent() -> ed25519_dalek::SigningKey {
    ed25519_dalek::SigningKey::from_bytes(&[0x1D; 32])
}

/// `key` as a Software device of `roles`, the shape a hand-written
/// enrolment or rotation names.
fn software_device(key: &ed25519_dalek::SigningKey, roles: u16) -> DeviceAuthority {
    DeviceAuthority {
        key: ed_key(key),
        transport_key_binding: [0; 32],
        attestation: AuthorityAttestation {
            kind: "software".to_owned(),
            evidence: Vec::new(),
        },
        tier: AuthorityTier::Software,
        roles,
    }
}

/// Signs `transcript` as `key`, one of the keys this file holds.
fn signs_as(key: &AuthorityKey, transcript: &[u8]) -> Vec<u8> {
    [
        host_held(),
        owner_device(),
        successor(),
        new_root(),
        agent(),
    ]
    .into_iter()
    .find(|held| ed_key(held) == *key)
    .map(|held| held.sign(transcript).to_bytes().to_vec())
    .expect("a key this file holds")
}

/// `rows`, signed and stored in one put.
fn append(hosted: &HostedVault, rows: Vec<SignedRow>) {
    let _ = append_signed_rows(&hosted.vault, rows, signs_as);
}

/// The host's re-root to [`new_root`], signed by [`successor`].
fn successor_re_roots() -> SignedRow {
    SignedRow {
        op: AuthorityOp::ReRoot {
            new_device: software_device(&new_root(), ROLE_OWNER),
        },
        signer: ed_key(&successor()),
        cosigners: Vec::new(),
    }
}

/// The host keeps none of the vault: the owner's device key stands and the
/// host's new root is no owner key.
fn assert_vault_stays_the_owners(hosted: &HostedVault) {
    assert!(
        hosted.live_owner_key(&ed_key(&owner_device())),
        "the owner's device key stands"
    );
    assert!(
        !hosted.live_owner_key(&ed_key(&new_root())),
        "the host re-rooted nothing"
    );
}

/// Sol xhigh stack review F1: a rotation is a re-root of one key, so a key
/// only the passkey vouched for rotates to no successor; else the successor,
/// unlimited, re-roots the vault in the same history (the handoff probe
/// admits a rotation before the first handoff).
#[test]
fn a_key_only_a_passkey_vouched_for_rotates_to_no_successor() {
    let hosted = HostedVault::open();
    passkey_vouched_host_key(&hosted);
    append(
        &hosted,
        vec![
            SignedRow {
                op: AuthorityOp::RotateKey {
                    old_key: ed_key(&host_held()),
                    new_device: software_device(&successor(), ROLE_OWNER),
                },
                signer: ed_key(&host_held()),
                cosigners: Vec::new(),
            },
            successor_re_roots(),
        ],
    );
    assert!(
        !hosted.live_owner_key(&ed_key(&successor())),
        "the rotation counted nothing"
    );
    assert_vault_stays_the_owners(&hosted);
}

/// Sol xhigh stack review F1: an enrolment of a device is a vouch, so a key
/// only the passkey vouched for enrols no owner device that then re-roots.
#[test]
fn a_key_only_a_passkey_vouched_for_enrols_no_device_that_re_roots() {
    let hosted = HostedVault::open();
    passkey_vouched_host_key(&hosted);
    append(
        &hosted,
        vec![
            SignedRow {
                op: AuthorityOp::EnrollDevice {
                    device: software_device(&successor(), ROLE_OWNER),
                },
                signer: ed_key(&host_held()),
                cosigners: Vec::new(),
            },
            successor_re_roots(),
        ],
    );
    assert!(
        !hosted.live_owner_key(&ed_key(&successor())),
        "the enrolment counted nothing"
    );
    assert_vault_stays_the_owners(&hosted);
}

/// Sol xhigh stack review F2: a key only the passkey vouched for lends no
/// consent to a revoke of another owner key from a cosign either. An agent
/// primary (the owner's device key enrolled it), which holds no consent, and
/// that key's cosign revoke nothing.
#[test]
fn a_key_only_a_passkey_vouched_for_lends_no_consent_to_a_revoke() {
    let hosted = HostedVault::open();
    passkey_vouched_host_key(&hosted);
    let counted = append_signed_rows(
        &hosted.vault,
        vec![
            SignedRow {
                op: AuthorityOp::EnrollDevice {
                    device: software_device(&agent(), ROLE_AGENT),
                },
                signer: ed_key(&owner_device()),
                cosigners: Vec::new(),
            },
            SignedRow {
                op: AuthorityOp::RevokeDevice {
                    revoked_key: ed_key(&owner_device()),
                },
                signer: ed_key(&agent()),
                cosigners: vec![ed_key(&host_held())],
            },
        ],
        signs_as,
    )
    .expect("the rows are stored");
    assert_eq!(
        counted,
        vec![true, false],
        "the agent enrols; its revoke with the limited key's cosign counts nothing"
    );
    assert!(
        hosted.live_owner_key(&ed_key(&owner_device())),
        "the owner's device key stands"
    );
}

/// A second passkey of the owner's, which the first one vouches for.
fn second_passkey() -> P256SigningKey {
    P256SigningKey::from_slice(&[0x4B; 32]).expect("a P-256 scalar")
}

fn second_passkey_roster_key() -> AuthorityKey {
    AuthorityKey::P256(
        second_passkey()
            .verifying_key()
            .to_encoded_point(true)
            .as_bytes()
            .to_vec(),
    )
}

/// The second passkey's enrollment input: its assertion over its
/// enrollment challenge.
fn second_passkey_enrollment(hosted: &HostedVault) -> OwnerPasskeyEnrollment {
    let public_key = second_passkey()
        .verifying_key()
        .to_encoded_point(false)
        .as_bytes()
        .to_vec();
    let challenge = hosted
        .vault
        .owner_passkey_enrollment_challenge_as(&hosted.owner(), &public_key)
        .expect("the second passkey's enrollment challenge");
    let assertion = assert_by(
        &second_passkey(),
        &challenge,
        FLAGS_PRESENT_VERIFIED,
        ORIGIN,
    );
    OwnerPasskeyEnrollment {
        credential_id: b"passkey-credential-0002".to_vec(),
        public_key,
        authenticator_data: assertion.authenticator_data,
        client_data_json: assertion.client_data_json,
        signature: assertion.signature,
    }
}

/// The second passkey signs an authority transcript as the browser would.
fn second_passkey_signs(transcript: &[u8]) -> Vec<u8> {
    let assertion = assert_by(
        &second_passkey(),
        &webauthn_challenge(transcript),
        FLAGS_PRESENT_VERIFIED,
        ORIGIN,
    );
    webauthn_assertion_envelope(
        &assertion.authenticator_data,
        &assertion.client_data_json,
        &assertion.signature,
    )
    .expect("an envelope")
}

/// Sol xhigh stack review F5: a passkey that only another passkey vouched
/// for is confirmed through its own door, as a device's key is: the owner's
/// device key vouches for it again, and from then on it vouches for further
/// keys.
#[test]
fn a_device_key_confirms_a_passkey_another_passkey_vouched_for() {
    let hosted = HostedVault::open();
    let machine = passkey_vouched_host_key(&hosted);
    hosted
        .vault
        .enrol_owner_passkey_as(
            &hosted.owner(),
            &second_passkey_enrollment(&hosted),
            passkey_roster_key(),
            |transcript| Ok(passkey_signs(transcript, FLAGS_PRESENT_VERIFIED)),
        )
        .expect("the first passkey vouches for the second");
    let further = ed25519_dalek::SigningKey::from_bytes(&[0x4C; 32]);
    let vouch_for_further = || {
        hosted.vault.enrol_owner_signing_key_as(
            &hosted.owner(),
            keyed_enrollment(&hosted, machine, &further),
            second_passkey_roster_key(),
            |transcript| Ok(second_passkey_signs(transcript)),
        )
    };
    assert!(
        vouch_for_further().is_err(),
        "guard: the unconfirmed second passkey vouches for nothing"
    );
    hosted
        .vault
        .confirm_owner_passkey_as(
            &hosted.owner(),
            &second_passkey_enrollment(&hosted),
            ed_key(&owner_device()),
            |transcript| Ok(owner_device().sign(transcript).to_bytes().to_vec()),
        )
        .expect("the owner's device key confirms the second passkey");
    vouch_for_further().expect("the confirmed passkey vouches for a further key");
    assert!(
        hosted.live_owner_key(&ed_key(&further)),
        "the further key is enrolled"
    );
}

// The owner's choice "Let my passkey remove devices and keys" (choice id
// `passkey.full_owner`; Engine ruling WEBPASSKEY-OPTIN-HOME = A).

/// A further key, which a key only the passkey vouched for vouches for while
/// the choice is on.
fn further() -> ed25519_dalek::SigningKey {
    ed25519_dalek::SigningKey::from_bytes(&[0x5D; 32])
}

/// Signs `transcript` as `key`: the passkey's assertion, or one of the
/// Ed25519 keys this file holds.
fn proves_as(key: &AuthorityKey, transcript: &[u8]) -> Vec<u8> {
    if *key == passkey_roster_key() {
        passkey_signs(transcript, FLAGS_PRESENT_VERIFIED)
    } else {
        signs_as(key, transcript)
    }
}

/// The choice turned `on` or off at the main-log heads, carried by this
/// install and proved by `key`; true when the fold counted it.
fn full_owner_proved_by(hosted: &HostedVault, on: bool, key: &AuthorityKey) -> bool {
    let signer = key.clone();
    set_passkey_full_owner(
        &hosted.vault,
        &hosted.owner(),
        on,
        Some((key.clone(), move |transcript: &[u8]| {
            proves_as(&signer, transcript)
        })),
        None,
    )
    .unwrap_or(false)
}

/// Whether the fold reads the choice on.
fn full_owner_reads_on(hosted: &HostedVault) -> bool {
    hosted
        .vault
        .authority_fold()
        .expect("authority fold")
        .passkey_full_owner()
}

/// `predecessor` vouches for [`further`] through the owner key enrollment
/// door; true when the fold counted it.
fn vouches_for_further(
    hosted: &HostedVault,
    machine: oneiron::EntityId,
    predecessor: &ed25519_dalek::SigningKey,
) -> bool {
    hosted
        .vault
        .enrol_owner_signing_key_as(
            &hosted.owner(),
            keyed_enrollment(hosted, machine, &further()),
            ed_key(predecessor),
            |transcript| Ok(predecessor.sign(transcript).to_bytes().to_vec()),
        )
        .is_ok()
}

#[test]
fn with_full_owner_on_a_key_only_a_passkey_vouched_for_fences_a_device_key() {
    let hosted = HostedVault::open();
    passkey_vouched_host_key(&hosted);
    assert!(
        full_owner_proved_by(&hosted, true, &ed_key(&owner_device())),
        "guard: the owner's device key turns the choice on"
    );
    assert!(full_owner_reads_on(&hosted), "guard: the fold reads it on");
    assert!(
        host_key_revokes_device_key(&hosted),
        "with the choice on, the passkey-vouched key revokes another owner key"
    );
    assert!(
        !hosted.live_owner_key(&ed_key(&owner_device())),
        "its revoke counted"
    );
}

#[test]
fn with_full_owner_on_the_passkey_revokes_another_owner_key() {
    let hosted = HostedVault::open();
    passkey_vouched_host_key(&hosted);
    assert!(
        full_owner_proved_by(&hosted, true, &ed_key(&owner_device())),
        "guard: the owner's device key turns the choice on"
    );
    assert!(
        revoke_owner_key_signed_by(
            &hosted.vault,
            passkey_roster_key(),
            ed_key(&owner_device()),
            |transcript| passkey_signs(transcript, FLAGS_PRESENT_VERIFIED),
        )
        .unwrap_or(false),
        "with the choice on, the passkey's own revoke of another owner key counts"
    );
    assert!(
        !hosted.live_owner_key(&ed_key(&owner_device())),
        "the device key is revoked"
    );
}

/// OPUS-SECREAD-A N1's bar is lifted with the others (the ruling's
/// sub-point).
#[test]
fn with_full_owner_on_a_key_only_a_passkey_vouched_for_answers_a_machine_as_the_owners() {
    let hosted = HostedVault::open();
    passkey_vouched_host_key(&hosted);
    assert!(
        full_owner_proved_by(&hosted, true, &ed_key(&owner_device())),
        "guard: the owner's device key turns the choice on"
    );
    assert!(
        answers_fresh_machine(
            &hosted,
            &host_held(),
            MachineRole::Owned(MachineOwnership::Yours)
        ),
        "with the choice on, the passkey-vouched key's machine answer counts"
    );
}

/// The passkey's own assertion is no owner key's proof, and a key only the
/// passkey vouched for is one the limits reach: neither turns the choice
/// on, so a mislabelled prompt cannot lift the limits it set.
#[test]
fn full_owner_proved_by_the_passkey_or_a_key_only_it_vouched_for_turns_nothing_on() {
    let hosted = HostedVault::open();
    passkey_vouched_host_key(&hosted);
    assert!(
        !full_owner_proved_by(&hosted, true, &passkey_roster_key()),
        "the passkey alone turns nothing on"
    );
    assert!(
        !full_owner_proved_by(&hosted, true, &ed_key(&host_held())),
        "a key only the passkey vouched for turns nothing on"
    );
    assert!(!full_owner_reads_on(&hosted), "the choice stays off");
    assert!(!host_key_revokes_device_key(&hosted), "the limits stand");
    assert!(
        full_owner_proved_by(&hosted, true, &ed_key(&owner_device())),
        "the owner's device key still turns it on"
    );
}

/// Turning the choice off is any owner act, a limited key's included, and
/// it brings back the limits of the passkey-vouched key and of the key that
/// key vouched for while the choice was on.
#[test]
fn full_owner_off_brings_back_the_limits_of_every_key_a_passkey_vouched_for() {
    let hosted = HostedVault::open();
    let machine = passkey_vouched_host_key(&hosted);
    assert!(
        full_owner_proved_by(&hosted, true, &ed_key(&owner_device())),
        "guard: the owner's device key turns the choice on"
    );
    assert!(
        vouches_for_further(&hosted, machine, &host_held()),
        "with the choice on, the passkey-vouched key vouches for a further key"
    );
    assert!(
        full_owner_proved_by(&hosted, false, &ed_key(&host_held())),
        "turning the choice off counts with any owner key's proof"
    );
    assert!(!full_owner_reads_on(&hosted), "the choice reads off");
    assert!(
        !host_key_revokes_device_key(&hosted),
        "the passkey-vouched key's limits are back"
    );
    assert!(
        !revoke_owner_key_signed_by(
            &hosted.vault,
            ed_key(&further()),
            ed_key(&owner_device()),
            |transcript| further().sign(transcript).to_bytes().to_vec(),
        )
        .unwrap_or(false),
        "so are the limits of the key it vouched for while the choice was on"
    );
    assert!(
        hosted.live_owner_key(&ed_key(&owner_device())),
        "the owner's device key stands"
    );
}

/// The choice reads at each row's parents: a row on a sibling branch of the
/// choice's act did not see it and keeps the limits; a row that saw it acts
/// in full.
#[test]
fn full_owner_on_lifts_nothing_for_a_row_on_a_sibling_branch() {
    let hosted = HostedVault::open();
    let machine = passkey_vouched_host_key(&hosted);
    let fork = main_log_heads(&hosted.vault).expect("the heads before the fork");
    assert!(
        full_owner_proved_by(&hosted, true, &ed_key(&owner_device())),
        "guard: the owner's device key turns the choice on"
    );
    let counted = append_signed_rows_on(
        &hosted.vault,
        fork,
        vec![SignedRow {
            op: AuthorityOp::RevokeDevice {
                revoked_key: ed_key(&owner_device()),
            },
            signer: ed_key(&host_held()),
            cosigners: Vec::new(),
        }],
        signs_as,
    )
    .unwrap_or_default();
    assert!(
        !counted.first().copied().unwrap_or(false),
        "a row that did not see the choice keeps the limits"
    );
    assert!(
        hosted.live_owner_key(&ed_key(&owner_device())),
        "the owner's device key stands"
    );
    assert!(
        vouches_for_further(&hosted, machine, &host_held()),
        "a row that saw the choice is not limited"
    );
}

/// Two acts of the choice that did not see each other, on and off, read
/// off where the fold merges them.
#[test]
fn a_sibling_off_beside_an_on_reads_off() {
    let hosted = HostedVault::open();
    let machine = passkey_vouched_host_key(&hosted);
    let fork = main_log_heads(&hosted.vault).expect("the heads before the fork");
    assert!(
        full_owner_proved_by(&hosted, true, &ed_key(&owner_device())),
        "guard: the owner's device key turns the choice on"
    );
    assert!(
        vouches_for_further(&hosted, machine, &host_held()),
        "with the choice on alone, the passkey-vouched key vouches for a further key"
    );
    assert!(
        set_passkey_full_owner(
            &hosted.vault,
            &hosted.owner(),
            false,
            Some((ed_key(&owner_device()), |transcript: &[u8]| {
                owner_device().sign(transcript).to_bytes().to_vec()
            })),
            Some(fork),
        )
        .expect("the sibling act is stored"),
        "guard: the off on the sibling branch counts"
    );
    assert!(!full_owner_reads_on(&hosted), "the merged fold reads off");
    assert!(
        !host_key_revokes_device_key(&hosted),
        "the limits are back where the two acts meet"
    );
}

/// A rotation a limited key makes while the choice is on hands its limits
/// to its successor: once the choice is off, the successor revokes no other
/// owner key until a non-passkey key confirms it.
#[test]
fn a_successor_a_limited_key_rotated_to_under_full_owner_is_limited_once_it_is_off() {
    let hosted = HostedVault::open();
    passkey_vouched_host_key(&hosted);
    assert!(
        full_owner_proved_by(&hosted, true, &ed_key(&owner_device())),
        "guard: the owner's device key turns the choice on"
    );
    let rotated = append_signed_rows(
        &hosted.vault,
        vec![SignedRow {
            op: AuthorityOp::RotateKey {
                old_key: ed_key(&host_held()),
                new_device: software_device(&successor(), ROLE_OWNER),
            },
            signer: ed_key(&host_held()),
            cosigners: Vec::new(),
        }],
        signs_as,
    )
    .unwrap_or_default();
    assert!(
        rotated.first().copied().unwrap_or(false),
        "with the choice on, the passkey-vouched key rotates"
    );
    assert!(
        full_owner_proved_by(&hosted, false, &ed_key(&owner_device())),
        "guard: the owner's device key turns the choice off"
    );
    assert!(
        !revoke_owner_key_signed_by(
            &hosted.vault,
            ed_key(&successor()),
            ed_key(&owner_device()),
            |transcript| successor().sign(transcript).to_bytes().to_vec(),
        )
        .unwrap_or(false),
        "the successor keeps the limits of the key it succeeded"
    );
    assert!(
        hosted.live_owner_key(&ed_key(&owner_device())),
        "the owner's device key stands"
    );
}

/// Sol xhigh review of PR 1c, finding 1: the successor rule reads whose
/// consent the entry rests on, not its primary alone. An agent primary,
/// which holds no consent, enrols an owner device with the passkey-vouched
/// key's cosign while the choice is on; once it is off, that device revokes
/// no other owner key until a non-passkey key confirms it.
#[test]
fn a_device_enrolled_on_a_limited_keys_cosign_under_full_owner_is_limited_once_it_is_off() {
    let hosted = HostedVault::open();
    passkey_vouched_host_key(&hosted);
    assert!(
        full_owner_proved_by(&hosted, true, &ed_key(&owner_device())),
        "guard: the owner's device key turns the choice on"
    );
    let counted = append_signed_rows(
        &hosted.vault,
        vec![
            SignedRow {
                op: AuthorityOp::EnrollDevice {
                    device: software_device(&agent(), ROLE_AGENT),
                },
                signer: ed_key(&owner_device()),
                cosigners: Vec::new(),
            },
            SignedRow {
                op: AuthorityOp::EnrollDevice {
                    device: software_device(&successor(), ROLE_OWNER),
                },
                signer: ed_key(&agent()),
                cosigners: vec![ed_key(&host_held())],
            },
        ],
        signs_as,
    )
    .unwrap_or_default();
    assert_eq!(
        counted,
        vec![true, true],
        "guard: with the choice on, the agent enrols the device on the passkey-vouched key's cosign"
    );
    assert!(
        full_owner_proved_by(&hosted, false, &ed_key(&owner_device())),
        "guard: the owner's device key turns the choice off"
    );
    assert!(
        !revoke_owner_key_signed_by(
            &hosted.vault,
            ed_key(&successor()),
            ed_key(&owner_device()),
            |transcript| successor().sign(transcript).to_bytes().to_vec(),
        )
        .unwrap_or(false),
        "the device keeps the limits of the key whose cosign enrolled it"
    );
    assert!(
        hosted.live_owner_key(&ed_key(&owner_device())),
        "the owner's device key stands"
    );
}

/// The owner's door proves the act with an owner key this install holds; a
/// hosted install holds none, so turning the choice on waits for the
/// owner's device and the door refuses, storing nothing.
#[test]
fn the_door_turns_full_owner_on_only_with_an_owner_key_this_install_holds() {
    let hosted = HostedVault::open();
    passkey_vouched_host_key(&hosted);
    let refused = hosted.vault.set_passkey_full_owner(&hosted.owner(), true);
    assert!(
        matches!(
            refused,
            Err(oneiron::Error::Record(
                oneiron::error::RecordError::OwnerKeyRequired
            ))
        ),
        "the door asks for an owner key: {refused:?}"
    );
    assert!(!full_owner_reads_on(&hosted), "the choice stays off");
}

/// No owner key's proof: an act the carrier alone signs.
fn no_proof() -> Option<(AuthorityKey, fn(&[u8]) -> Vec<u8>)> {
    None
}

/// Engine ruling CARRIER-ASKS-ON-PASSKEY-ONLY-VAULT = A: a hosted vault whose
/// only owner key is a passkey asks for no owner key's proof, since no proof
/// the fold takes could answer it. So the owner's web session, which this
/// install carries with no proof, turns the choice off; turning it on still
/// waits for an owner key's proof.
#[test]
fn a_passkey_only_vault_turns_full_owner_off_with_no_proof_and_not_on() {
    let hosted = HostedVault::open();
    enrol_passkey(&hosted);
    assert!(
        set_passkey_full_owner(&hosted.vault, &hosted.owner(), false, no_proof(), None)
            .expect("the act is stored"),
        "a passkey-only vault takes the web session's off with no proof"
    );
    assert!(
        !set_passkey_full_owner(&hosted.vault, &hosted.owner(), true, no_proof(), None)
            .expect("the act is stored"),
        "turning it on waits for an owner key's proof"
    );
    assert!(!full_owner_reads_on(&hosted), "the choice reads off");
}
