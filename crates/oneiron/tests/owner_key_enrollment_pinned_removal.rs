//! Red/green tests for #8722 review round 2, P1 1 (FIX
//! [DOOR-HEADS-REVIEW2-P1-TESTS]): an owner key enrollment for a holding
//! machine M that the install's pinned anchor has removed, while M's roster
//! head stays live, lands nothing.
//!
//! #8712 makes the fold's `machine_is_live` read the roster's head alone, so
//! the fold counts such an entry. A door also believes its pinned anchor's
//! chain (`FoldedMachine::standing_heads`): the prepared path's stale check
//! refuses with PREPARED_ENTRY_STALE, and the one-step path (another holding
//! machine than the carrier) refuses with NOT_COUNTED before the commit
//! (`machine_is_live_here`, crates/oneiron/src/authority/owner_key_enrollment.rs).
//!
//! Each test serves a self-host vault, enrols M as the owner's, enrols the
//! owner's passkey (the predecessor that signs elsewhere), publishes a root
//! whose anchor the test holds, marks this install Yours in that anchor's
//! chain and pins the root. Under the pin the passkey first vouches for one
//! device key of M (the fixture's control: it lands). Then the pinned anchor
//! removes M in its own chain, and a second device key of M is enrolled.
//!
//! Red at f47c3aac19b (#8722 before its review round 2 fix): both tests fail
//! at their final `expect_err`, as each test's doc states. Green at #8722's
//! head and later.
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test owner_key_enrollment_pinned_removal`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use base64::Engine as _;
use ed25519_dalek::{Signer as _, SigningKey};
use oneiron::authority::{
    AUTHORITY_LOG_SCHEMA_VERSION, ActAuthority, ActSurface, AuthorityEntryHash, AuthorityKey,
    AuthorityLogEntry, AuthorityOp, AuthoritySignature, AuthorityVaultId, HostSlipIssuer,
    MACHINE_ENCRYPTION_KEY_LEN, MACHINE_ENCRYPTION_SUITE_HYBRID_V1, MachineDeviceClass,
    MachineEncryptionKey, MachineEnrolmentRequest, MachineOwnership, MachineProfile, MachineRole,
    OwnerKeyEnrollment, OwnerPasskeyEnrollment, OwnerRootRecord, PinnedRoot,
    PreparedOwnerKeyEnrollment, ROLE_OWNER, authority_entry_hash, authority_transcript,
    machine_profile_proof_transcript, webauthn_assertion_envelope, webauthn_challenge,
};
use oneiron::consent::AuthenticatedOwner;
use oneiron::error::RecordError;
use oneiron::store::GateDecisionId;
use oneiron::world_keys::RecoveryRootSeed;
use oneiron::{EntityId, Error, TimeRange, Vault, VaultConfig};
use p256::ecdsa::signature::Signer as _;
use p256::ecdsa::{Signature as P256Signature, SigningKey as P256SigningKey};
use sha2::{Digest as _, Sha256};

/// The stored rows' occurred range and learned-at, as the store-door tests use.
const AT: TimeRange = TimeRange { start: 2, end: 2 };
/// The seed of M's machine key.
const M_SEED: u8 = 0x31;
/// User present and user verified.
const FLAGS_PRESENT_VERIFIED: u8 = 0x05;
/// The passkey's credential id (`rawId`).
const CREDENTIAL_ID: &[u8] = b"passkey-credential-0001";
/// The origin the passkey enrols at.
const ORIGIN: &str = "https://oneiron.test";

fn signing(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn key_of(signing: &SigningKey) -> AuthorityKey {
    AuthorityKey::Ed25519(signing.verifying_key().to_bytes())
}

/// `signer` alone signs `op` on `parent_hashes`.
fn signed(
    vault_id: AuthorityVaultId,
    seq: u64,
    parent_hashes: Vec<AuthorityEntryHash>,
    op: AuthorityOp,
    signer: &SigningKey,
) -> AuthorityLogEntry {
    let key = key_of(signer);
    let mut row = AuthorityLogEntry {
        schema_version: AUTHORITY_LOG_SCHEMA_VERSION,
        vault_id: Some(vault_id),
        seq,
        parent_hashes,
        op,
        signer: AuthoritySignature {
            suite: key.suite(),
            public_key: key,
            signature: vec![0; 64],
        },
        cosigns: Vec::new(),
        ts: 1,
    };
    let transcript = authority_transcript(&row).expect("the transcript");
    row.signer.signature = signer.sign(&transcript).to_bytes().to_vec();
    row
}

fn hash(row: &AuthorityLogEntry) -> AuthorityEntryHash {
    authority_entry_hash(row).expect("a hash")
}

/// The held root's owner person, distinct from the vault's owner.
fn root_owner() -> EntityId {
    EntityId::from_bytes([0xA1; 16]).expect("an id")
}

/// A self-host vault as its own server starts one: this install serving and
/// profiled under the host root, and the owner bound and authenticated.
struct ServedVault {
    vault: Vault,
    owner: AuthenticatedOwner,
    /// This install, the carrier of every owner act its doors sign.
    carrier: EntityId,
    issuer: HostSlipIssuer,
    _dir: tempfile::TempDir,
}

impl ServedVault {
    fn self_host() -> Self {
        let dir = tempfile::tempdir().expect("vault directory");
        let vault = Vault::open(dir.path(), VaultConfig::device()).expect("self-host vault");
        vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
        let issuer = oneiron::test_support::provision_engine_machines(&vault);
        let carrier = vault
            .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
            .expect("this install's machine profile under the host root")
            .roster
            .expect("guard: this install has a roster chain")
            .profile
            .machine;
        let person = vault.ensure_embedded_owner_actor().expect("the owner");
        oneiron::test_support::bind_host_owner(&vault, &issuer, person)
            .expect("the owner's binding");
        let owner = vault
            .authenticate_owner(person, &person.to_hex(), true, GateDecisionId::now())
            .expect("the owner's proof");
        Self {
            vault,
            owner,
            carrier,
            issuer,
            _dir: dir,
        }
    }

    fn act(&self) -> ActAuthority {
        ActAuthority::Owner(self.owner.clone(), ActSurface::ThisInstall)
    }

    fn vault_id(&self) -> AuthorityVaultId {
        self.vault
            .authority_fold()
            .expect("authority fold")
            .vault_id
            .expect("the vault is rooted")
    }

    /// The roster's head of `machine`.
    fn roster_profile(&self, machine: EntityId) -> MachineProfile {
        self.vault
            .authority_fold()
            .expect("authority fold")
            .machine(machine)
            .and_then(|folded| folded.roster.clone())
            .expect("guard: the roster holds a head of the machine")
            .profile
    }

    fn live_owner_key(&self, key: &AuthorityKey) -> bool {
        let fold = self.vault.authority_fold().expect("authority fold");
        fold.roster
            .get(key)
            .is_some_and(|device| !device.revoked && device.roles & ROLE_OWNER != 0)
    }

    fn rows(&self) -> usize {
        self.vault
            .export_signed_authority_history()
            .expect("the authority history")
            .len()
    }

    /// M, another machine, enrolled as the owner's ("yours") by this install.
    fn enrol_m(&self) -> EntityId {
        let vault_id = self.vault_id();
        let node = signing(M_SEED);
        let machine = EntityId::from_bytes([0x76; 16]).expect("an id");
        let machine_key = node.verifying_key().to_bytes();
        let device_class = MachineDeviceClass::Computer;
        let encryption_key = MachineEncryptionKey {
            suite: MACHINE_ENCRYPTION_SUITE_HYBRID_V1,
            key: vec![7; MACHINE_ENCRYPTION_KEY_LEN],
        };
        let machine_proof = node
            .sign(&machine_profile_proof_transcript(
                &vault_id,
                machine,
                &machine_key,
                device_class,
                &encryption_key,
            ))
            .to_bytes();
        let request = MachineEnrolmentRequest {
            vault_id,
            machine,
            machine_key,
            device_class,
            encryption_key,
            machine_proof,
            restored_from: None,
        };
        self.vault
            .enroll_machine(
                &self.owner,
                ActSurface::ThisInstall,
                &request,
                MachineRole::Owned(MachineOwnership::Yours),
                None,
            )
            .expect("guard: the owner enrols M");
        machine
    }
}

/// The passkey a platform authenticator holds, as a software key.
fn passkey() -> P256SigningKey {
    P256SigningKey::from_slice(&[0x5A; 32]).expect("a P-256 scalar")
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

/// What `navigator.credentials.get` returns for `challenge`, as
/// tests/passkey_owner_key.rs builds it: authenticator data (RP id hash,
/// user present and verified, a zero sign count), the client data JSON, and
/// the DER signature.
fn assertion_over(challenge: &[u8]) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let mut authenticator_data = Sha256::digest(b"oneiron.test").to_vec();
    authenticator_data.push(FLAGS_PRESENT_VERIFIED);
    authenticator_data.extend_from_slice(&[0; 4]);
    let client_data_json = format!(
        r#"{{"type":"webauthn.get","challenge":"{}","origin":"{ORIGIN}","crossOrigin":false}}"#,
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(challenge)
    )
    .into_bytes();
    let mut message = authenticator_data.clone();
    message.extend_from_slice(&Sha256::digest(&client_data_json));
    let signature: P256Signature = passkey().sign(&message);
    (
        authenticator_data,
        client_data_json,
        signature.to_der().as_bytes().to_vec(),
    )
}

/// The passkey's assertion over `challenge` in its envelope, as a browser
/// hands a predecessor signature to the engine.
fn passkey_envelope(challenge: &[u8]) -> Vec<u8> {
    let (authenticator_data, client_data_json, signature) = assertion_over(challenge);
    webauthn_assertion_envelope(&authenticator_data, &client_data_json, &signature)
        .expect("an envelope")
}

/// The owner enrols the passkey with the host root as predecessor.
fn enrol_passkey(served: &ServedVault) {
    let public_key = passkey()
        .verifying_key()
        .to_encoded_point(false)
        .as_bytes()
        .to_vec();
    let challenge = served
        .vault
        .owner_passkey_enrollment_challenge_as(&served.act(), &public_key)
        .expect("the passkey's enrollment challenge");
    let (authenticator_data, client_data_json, signature) = assertion_over(&challenge);
    served
        .vault
        .enrol_owner_passkey_as_host(
            &served.act(),
            &OwnerPasskeyEnrollment {
                credential_id: CREDENTIAL_ID.to_vec(),
                public_key,
                authenticator_data,
                client_data_json,
                signature,
            },
            &served.issuer,
        )
        .expect("the owner enrols his passkey");
    assert!(
        served.live_owner_key(&passkey_roster_key()),
        "guard: the passkey is a live owner root"
    );
}

/// `device`'s enrollment input for `machine`: its key and its proof.
fn enrollment_for(
    served: &ServedVault,
    machine: EntityId,
    device: &SigningKey,
) -> OwnerKeyEnrollment {
    let public_key = device.verifying_key().to_bytes();
    let challenge = served
        .vault
        .owner_key_enrollment_challenge_as(&served.act(), machine, &public_key)
        .expect("the device key's challenge");
    OwnerKeyEnrollment {
        machine,
        public_key,
        proof: device.sign(&challenge).to_bytes().to_vec(),
    }
}

/// The two-step vouch's second step for `prepared`.
fn land(
    served: &ServedVault,
    prepared: &PreparedOwnerKeyEnrollment,
) -> oneiron::Result<oneiron::authority::OwnerKeyEnrollmentReceipt> {
    served.vault.land_owner_key_enrollment_as(
        &served.act(),
        &prepared.entry,
        passkey_envelope(&prepared.challenge),
    )
}

/// The pin the tests set: a root whose anchor the test holds, published on
/// the vault, whose anchor marks this install Yours in its own chain, pinned
/// by the owner.
struct HeldPin {
    anchor: SigningKey,
    /// The anchor's mark of this install, the parent of its next row.
    carrier_mark: AuthorityEntryHash,
    pin: PinnedRoot,
}

fn pin_held_root(served: &ServedVault) -> HeldPin {
    let vault_id = served.vault_id();
    let seed = RecoveryRootSeed::generate().expect("a fresh root seed");
    let root = seed.public(&vault_id).expect("the root's public half");
    let anchor = seed.anchor();
    let anchor_key = anchor.verifying_key().to_bytes();
    let parent = served
        .vault
        .authority_fold()
        .expect("authority fold for a parent")
        .valid_entries
        .iter()
        .next()
        .copied()
        .expect("guard: the vault holds a valid row for the root's parent");
    let record = OwnerRootRecord {
        owner: root_owner(),
        root: root.id,
        recovery_key: MachineEncryptionKey {
            suite: MACHINE_ENCRYPTION_SUITE_HYBRID_V1,
            key: root.recovery_key.to_bytes(),
        },
        anchor_key: root.anchor_key,
    };
    let root_row = signed(
        vault_id,
        1,
        vec![parent],
        AuthorityOp::OwnerRoot(record),
        &anchor,
    );
    served
        .vault
        .put_authority_log_entry(&root_row, AT, 2)
        .expect("the held root's row is stored");
    let mark = signed(
        vault_id,
        2,
        vec![hash(&root_row)],
        AuthorityOp::MachineProfile(MachineProfile {
            owner: root_owner(),
            role: MachineRole::Owned(MachineOwnership::Yours),
            revision: 1,
            carrier: None,
            act: None,
            ..served.roster_profile(served.carrier)
        }),
        &anchor,
    );
    let carrier_mark = hash(&mark);
    served
        .vault
        .put_authority_log_entry(&mark, AT, 2)
        .expect("the anchor's mark of this install is stored");
    let fold = served.vault.authority_fold().expect("authority fold");
    assert!(
        fold.valid_entries.contains(&hash(&root_row)) && fold.valid_entries.contains(&carrier_mark),
        "guard: the held root and its mark of this install are valid"
    );
    let root_id = fold
        .root_anchors()
        .get(&anchor_key)
        .and_then(|ids| ids.iter().next())
        .copied()
        .expect("guard: the fold holds the root signed by the held anchor");
    let report = served
        .vault
        .pin_owner_root(&served.owner, root_id)
        .expect("the owner pins the held root");
    assert_eq!(report.awaiting, None, "guard: the pin is not awaiting");
    let pin = PinnedRoot {
        id: root_id,
        anchor_key,
    };
    assert_eq!(
        served
            .vault
            .authority_fold()
            .expect("authority fold")
            .pinned_root,
        Some(pin),
        "guard: the pin is effective"
    );
    HeldPin {
        anchor,
        carrier_mark,
        pin,
    }
}

/// The pinned anchor's next row removes `machine` in its own chain; the
/// roster's head of it stays live.
fn remove_under_pin(served: &ServedVault, held: &HeldPin, machine: EntityId) {
    let template = served.roster_profile(machine);
    let removal = signed(
        served.vault_id(),
        3,
        vec![held.carrier_mark],
        AuthorityOp::MachineProfile(MachineProfile {
            owner: root_owner(),
            role: MachineRole::Removed,
            revision: template.revision + 1,
            carrier: None,
            act: None,
            ..template
        }),
        &held.anchor,
    );
    let mark = hash(&removal);
    served
        .vault
        .put_authority_log_entry(&removal, AT, 2)
        .expect("the pinned anchor's removal of the machine is stored");
    let fold = served.vault.authority_fold().expect("authority fold");
    assert_eq!(fold.pinned_root, Some(held.pin), "guard: the pin stands");
    assert!(
        fold.valid_entries.contains(&mark),
        "guard: the pinned anchor's removal is valid"
    );
    let folded = fold.machine(machine).expect("guard: the fold holds M");
    let anchored = folded
        .anchored
        .get(&held.pin.anchor_key)
        .expect("guard: the pinned anchor's chain holds M");
    assert_eq!(anchored.entry, mark, "guard: the removal heads that chain");
    assert!(anchored.removed, "guard: the pinned chain removes M");
    assert!(
        folded.roster.as_ref().is_some_and(|head| head.is_live()),
        "guard: M's roster head stays live"
    );
}

/// The passkey's vouch for a device key of M, prepared while M stands live
/// under the pin and landed after the pinned anchor removed M, lands
/// nothing: land judges the holding machine again at the heads it reads,
/// with the pinned anchor's chain (review round 2 P1 1, prepared path).
///
/// RED at f47c3aac19b: the final `expect_err` fails: land's stale check reads
/// M's roster head alone, and the fold counts the entry, so the key lands.
/// GREEN: PREPARED_ENTRY_STALE, and the key is not enrolled.
#[test]
fn a_prepared_vouch_for_a_machine_the_pinned_anchor_removed_since_lands_nothing() {
    let served = ServedVault::self_host();
    let m = served.enrol_m();
    enrol_passkey(&served);
    let held = pin_held_root(&served);

    let control = signing(0x6A);
    let prepared = served
        .vault
        .prepare_owner_key_enrollment_as(
            &served.act(),
            enrollment_for(&served, m, &control),
            passkey_roster_key(),
        )
        .expect("guard: the engine prepares the control key's enrollment");
    land(&served, &prepared).expect("guard: under the pin, a vouch for M's key lands");
    assert!(
        served.live_owner_key(&key_of(&control)),
        "guard: the control key is a live owner root"
    );

    let device = signing(0x6B);
    let prepared = served
        .vault
        .prepare_owner_key_enrollment_as(
            &served.act(),
            enrollment_for(&served, m, &device),
            passkey_roster_key(),
        )
        .expect("the engine prepares the enrollment while M stands live");
    remove_under_pin(&served, &held, m);
    let rows = served.rows();

    let refused = land(&served, &prepared)
        .expect_err("a vouch for a machine the pinned anchor removed since prepare lands nothing");
    assert!(
        matches!(
            &refused,
            Error::Record(RecordError::InvalidAuthorityLogBody(reason))
                if reason.contains("the machine that holds the key was removed")
        ),
        "refused as stale since prepare: {refused:?}"
    );
    assert!(
        !served.live_owner_key(&key_of(&device)),
        "the key is not enrolled"
    );
    assert_eq!(served.rows(), rows, "nothing was written");
}

/// The passkey's one-step vouch for a device key of M, after the pinned
/// anchor removed M, lands nothing: the writer judges the holding machine at
/// the heads this install stands under before the commit, while the fold
/// counts the entry on M's live roster head (review round 2 P1 1, the
/// one-step path for another holding machine than the carrier).
///
/// RED at f47c3aac19b: the final `expect_err` fails: the writer asks the fold
/// alone, which counts the entry, so the key lands.
/// GREEN: NOT_COUNTED (`AuthorityRefused`), and the key is not enrolled.
#[test]
fn a_one_step_vouch_for_a_machine_the_pinned_anchor_removed_lands_nothing() {
    let served = ServedVault::self_host();
    let m = served.enrol_m();
    enrol_passkey(&served);
    let held = pin_held_root(&served);
    let vouch = |device: &SigningKey| {
        served.vault.enrol_owner_signing_key_as(
            &served.act(),
            enrollment_for(&served, m, device),
            passkey_roster_key(),
            |transcript| Ok(passkey_envelope(&webauthn_challenge(transcript))),
        )
    };

    let control = signing(0x6A);
    vouch(&control).expect("guard: under the pin, a one-step vouch for M's key lands");
    assert!(
        served.live_owner_key(&key_of(&control)),
        "guard: the control key is a live owner root"
    );

    remove_under_pin(&served, &held, m);
    let rows = served.rows();
    let device = signing(0x6B);
    let refused =
        vouch(&device).expect_err("a vouch for a machine the pinned anchor removed lands nothing");
    assert!(
        matches!(
            &refused,
            Error::Record(RecordError::AuthorityRefused(reason))
                if reason.contains("does not count the key enrollment")
        ),
        "refused as not counted on this install: {refused:?}"
    );
    assert!(
        !served.live_owner_key(&key_of(&device)),
        "the key is not enrolled"
    );
    assert_eq!(served.rows(), rows, "nothing was written");
}
