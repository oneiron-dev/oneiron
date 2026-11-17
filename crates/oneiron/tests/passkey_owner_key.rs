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
    OwnerPasskeyEnrollment, ROLE_OWNER, encode_authority_log_entry_body, sign_owner_key_move,
    webauthn_assertion_envelope, webauthn_challenge,
};
use oneiron::consent::AuthenticatedOwner;
use oneiron::federation::{FederationGrantRole, InitialSharedMember};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::store::GateDecisionId;
use oneiron::temporal::TimeRange;
use oneiron::test_doors::label_writers::embedded_owner;
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
    let device = ed25519_dalek::SigningKey::from_bytes(&[0x6B; 32]);
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

/// The shared vault [`SharedVault`] runs its membership moves in.
const SHARED: u64 = 44;

/// A person's proof of their own standing.
fn person_proof(vault: &Vault, person: oneiron::EntityId) -> AuthenticatedOwner {
    vault
        .authenticate_owner(person, &person.to_hex(), true, GateDecisionId::now())
        .expect("a person proof")
}

/// Whether `key` is a live owner root on `vault`'s roster.
fn live_owner_key_on(vault: &Vault, key: &AuthorityKey) -> bool {
    let fold = vault.authority_fold().expect("authority fold");
    fold.roster
        .get(key)
        .is_some_and(|device| !device.revoked && device.roles & ROLE_OWNER != 0)
}

/// A self-hosted shared vault whose embedded owner the host root binds,
/// with a co-Owner the owner added (the fixture of tests/owner_enrol.rs).
/// The vault drops first.
struct SharedVault {
    vault: Vault,
    issuer: HostSlipIssuer,
    owner: oneiron::EntityId,
    co_owner: oneiron::EntityId,
    _dir: tempfile::TempDir,
}

impl SharedVault {
    fn open() -> Self {
        Self::open_with(VaultConfig::device())
    }

    /// [`Self::open`] under the Hosted posture, as a managed host serves it:
    /// its custodial root proves for no owner (the fixture of
    /// tests/owner_key_move_two_phase.rs).
    fn open_hosted() -> Self {
        let mut config = VaultConfig::device();
        config.privacy.posture = HostingPrivacyPosture::Hosted;
        Self::open_with(config)
    }

    fn open_with(config: VaultConfig) -> Self {
        let dir = tempfile::tempdir().expect("vault directory");
        let vault = Vault::open(dir.path(), config).expect("vault");
        vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
        let issuer = oneiron::test_support::provision_engine_machines(&vault);
        vault
            .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
            .expect("this install's live machine profile");
        let owner = vault.ensure_embedded_owner_actor().expect("owner");
        oneiron::test_support::bind_host_owner(&vault, &issuer, owner)
            .expect("the owner's binding");
        vault
            .initialize_shared_vault(
                &person_proof(&vault, owner),
                SHARED,
                None,
                &[InitialSharedMember {
                    member_ref: owner,
                    role: Some(FederationGrantRole::Owner),
                }],
                1,
            )
            .expect("a shared vault");
        let co_owner = oneiron::EntityId::now();
        vault
            .put_entity(
                &co_owner,
                ENTITY_TYPE_PERSON,
                TimeRange { start: 1, end: 1 },
                1,
                b"human",
            )
            .expect("a live person");
        let owner_proof = person_proof(&vault, owner);
        let act = vault
            .propose_add_owner(&owner_proof, SHARED, co_owner)
            .expect("the owner starts add_owner");
        vault
            .execute_completed_shared_act(&owner_proof, &act.id, Some(&issuer))
            .expect("add_owner runs at once");
        Self {
            vault,
            issuer,
            owner,
            co_owner,
            _dir: dir,
        }
    }
}

/// A membership move that ends an Owner's standing revokes their passkey
/// too (REVIEW-8437 P1, REVIEW-8451 P1): the revoke of a removed Owner's
/// owner authority (REVIEW-7931) lists their passkeys beside their device
/// keys. The co-Owner's first owner key is a passkey, with the host root as
/// predecessor, which binds them (OWNER-ENROL); the owner removes them, and
/// the passkey is no live owner root after.
#[test]
fn a_removed_owner_keeps_no_passkey() {
    let shared = SharedVault::open();
    let authority = ActAuthority::Owner(
        person_proof(&shared.vault, shared.co_owner),
        ActSurface::ThisInstall,
    );
    let challenge = shared
        .vault
        .owner_passkey_enrollment_challenge_as(&authority, &passkey_public_key())
        .expect("the passkey's enrollment challenge");
    shared
        .vault
        .enrol_owner_passkey_as_host(
            &authority,
            &passkey_enrollment(assert_over(&challenge, FLAGS_PRESENT_VERIFIED)),
            &shared.issuer,
        )
        .expect("the co-Owner enrols a passkey");
    assert!(
        live_owner_key_on(&shared.vault, &passkey_roster_key()),
        "guard: the co-Owner's passkey is a live owner root"
    );
    let owner_proof = person_proof(&shared.vault, shared.owner);
    let act = shared
        .vault
        .propose_remove_owner(&owner_proof, SHARED, shared.co_owner, None, None, false)
        .expect("the owner starts remove_owner");
    shared
        .vault
        .execute_completed_shared_act(&owner_proof, &act.id, Some(&shared.issuer))
        .expect("remove_owner runs at once");
    assert!(
        !live_owner_key_on(&shared.vault, &passkey_roster_key()),
        "the removed Owner's passkey is revoked with the removal"
    );
}

impl SharedVault {
    /// `person` enrols an owner signing key of a device of theirs, made from
    /// `seed`, with the host root as its predecessor; this install never
    /// holds it. Answers the key.
    fn enrol_device_key(&self, person: oneiron::EntityId, seed: u8) -> ed25519_dalek::SigningKey {
        let key = ed25519_dalek::SigningKey::from_bytes(&[seed; 32]);
        let public_key = key.verifying_key().to_bytes();
        let machine = self
            .vault
            .prepare_install_signing()
            .expect("this install's machine");
        let authority =
            ActAuthority::Owner(person_proof(&self.vault, person), ActSurface::ThisInstall);
        let challenge = self
            .vault
            .owner_key_enrollment_challenge_as(&authority, machine, &public_key)
            .expect("the enrolment challenge");
        let input = OwnerKeyEnrollment {
            machine,
            public_key,
            proof: key.sign(&challenge).to_bytes().to_vec(),
        };
        self.vault
            .enrol_owner_signing_key_as_host(&authority, input, &self.issuer)
            .expect("an Owner enrols an owner key of their own");
        key
    }

    /// `person` enrols the passkey, with the host root as its predecessor.
    fn enrol_passkey_of(&self, person: oneiron::EntityId) {
        let authority =
            ActAuthority::Owner(person_proof(&self.vault, person), ActSurface::ThisInstall);
        let challenge = self
            .vault
            .owner_passkey_enrollment_challenge_as(&authority, &passkey_public_key())
            .expect("the passkey's enrollment challenge");
        self.vault
            .enrol_owner_passkey_as_host(
                &authority,
                &passkey_enrollment(assert_over(&challenge, FLAGS_PRESENT_VERIFIED)),
                &self.issuer,
            )
            .expect("an Owner enrols a passkey");
    }
}

/// A hosted removal of an Owner who holds a device key and a passkey lands
/// with both revoked (REVIEW2 #8539 P2-1, the second lander of #9093): the
/// move's plan names every live owner key of the member, the passkey among
/// them, the executor's device signs a revoke of each, and the confirmed run
/// lands them with the removal. Before, the plan named the device key alone,
/// and the run then found the passkey live with no owner proof to end it, so
/// the removal could never run.
#[test]
fn a_hosted_removal_revokes_the_members_passkey_on_the_executors_confirm() {
    let shared = SharedVault::open_hosted();
    let owner_key = shared.enrol_device_key(shared.owner, 0x71);
    shared.enrol_passkey_of(shared.co_owner);
    let co_key = shared.enrol_device_key(shared.co_owner, 0x73);
    let co_device_key = AuthorityKey::Ed25519(co_key.verifying_key().to_bytes());
    assert!(
        live_owner_key_on(&shared.vault, &passkey_roster_key())
            && live_owner_key_on(&shared.vault, &co_device_key),
        "guard: the co-Owner holds a live passkey and a live device key"
    );
    let owner_proof = person_proof(&shared.vault, shared.owner);
    let act = shared
        .vault
        .propose_remove_owner(&owner_proof, SHARED, shared.co_owner, None, None, false)
        .expect("the owner starts remove_owner")
        .id;
    let plan = shared
        .vault
        .owner_key_move_plan(&owner_proof, &act, Some(&shared.issuer))
        .expect("the act's plan");
    let rows: Vec<Vec<u8>> =
        sign_owner_key_move(&plan, owner_key.verifying_key().to_bytes(), |transcript| {
            Ok(owner_key.sign(transcript).to_bytes().to_vec())
        })
        .expect("the owner's device signs the plan")
        .iter()
        .map(|row| encode_authority_log_entry_body(row).expect("a row body"))
        .collect();
    shared
        .vault
        .execute_completed_shared_act_with_owner_key_revokes(
            &owner_proof,
            &act,
            Some(&shared.issuer),
            &rows,
        )
        .expect("the confirmed removal runs");
    assert!(
        !live_owner_key_on(&shared.vault, &passkey_roster_key()),
        "the removal revokes the co-Owner's passkey"
    );
    assert!(
        !live_owner_key_on(&shared.vault, &co_device_key),
        "the removal revokes the co-Owner's device key"
    );
    assert!(
        live_owner_key_on(
            &shared.vault,
            &AuthorityKey::Ed25519(owner_key.verifying_key().to_bytes())
        ),
        "the confirming key stays live"
    );
}

/// The move plan's wire names a passkey by its compressed P-256 key, 66
/// hex digits, beside a device key's 64 (`vault.shared.owner_key_move_plan`).
#[test]
fn the_move_plan_verb_names_the_members_passkey_in_hex() {
    use oneiron::task_verb::sdk::{self, SharedActRequest};
    let shared = SharedVault::open_hosted();
    shared.enrol_device_key(shared.owner, 0x71);
    shared.enrol_passkey_of(shared.co_owner);
    let owner_proof = person_proof(&shared.vault, shared.owner);
    let act_id = shared
        .vault
        .propose_remove_owner(&owner_proof, SHARED, shared.co_owner, None, None, false)
        .expect("the owner starts remove_owner")
        .id;
    let plan = sdk::plan_shared_owner_key_move(
        &shared.vault,
        &owner_proof,
        Some(&shared.issuer),
        SharedActRequest { act_id },
    )
    .expect("the plan verb answers the plan");
    let passkey_hex =
        oneiron_hex::encode(passkey().verifying_key().to_encoded_point(true).as_bytes());
    assert_eq!(passkey_hex.len(), 66, "guard: a compressed P-256 key");
    assert_eq!(plan.revoked, vec![passkey_hex], "{plan:?}");
}
