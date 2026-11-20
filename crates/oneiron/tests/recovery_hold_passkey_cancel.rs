//! An owner's passkey cancels a box recovery's wait (row
//! RECOVERY-HOLD-PASSKEY-ANSWER).
//!
//! An owner whose only live owner key is a browser passkey stops a recovery
//! hold with a `Cancel` its passkey signs. The passkey signs in the browser,
//! so the Cancel is two steps, as the passkey's vouch for a device key is:
//! `prepare_recovery_hold_cancel_as` builds the unsigned answer entry and
//! hands out its challenge, and `land_recovery_hold_cancel_as` lands it with
//! the assertion as its one signature. The fold counts it as any owner
//! key's Cancel: the hold is Cancelled, names the owner, and never lands.
//!
//! Cancel only: an `ItIsMe` lands the hold's revocations of the owner's
//! other keys at once, and a passkey revokes no other owner key (Engine
//! ruling WEBPASSKEY-PASSKEY-OWN-REVOKE = B), so the wire refuses a passkey's
//! `ItIsMe` while it takes the same entry as a `Cancel`. An assertion over
//! another challenge, made at another origin than the passkey's enrollment,
//! or made without verifying the person, cancels nothing. A key that is not
//! a live passkey of the acting owner's prepares no Cancel, and a Cancel
//! prepared for a hold that has ended since lands nothing.
//!
//! The fixture is `owner_root_recovery_wait.rs`'s (a self-host vault rooted
//! under its host, with a confirmed kit, on a clock the test moves); the
//! passkey is `passkey_owner_key.rs`'s software P-256 key, each assertion
//! built as a browser's `navigator.credentials.get` returns it.
//!
//! Red: the head with the wire's answer rule back at Ed25519 alone
//! (`RecoveryHoldAnswer::validate_entry`), where the passkey's Cancel never
//! lands: `a_passkey_cancels_a_live_hold_and_it_never_lands`,
//! `the_wire_takes_a_passkeys_cancel_and_refuses_its_it_is_me` and
//! `only_the_passkeys_verified_assertion_over_the_challenge_cancels` fail.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test recovery_hold_passkey_cancel`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use ed25519_dalek::{Signer as _, SigningKey};
use oneiron::authority::{
    AUTHORITY_LOG_SCHEMA_VERSION, ActAuthority, ActSurface, AuthorityEntryHash, AuthorityKey,
    AuthorityLogEntry, AuthorityOp, AuthoritySignature, HostSlipIssuer, MachineRole,
    OwnerKeyEnrollment, OwnerPasskeyEnrollment, RecoveryHoldAnswer, RecoveryHoldAnswerKind,
    RecoveryHoldState, RecoveryHoldView, RootMaterial, RootRecovery, RootSuccessor,
    authority_entry_hash, authority_transcript, decode_authority_log_entry_body,
    encode_authority_log_entry_body, webauthn_assertion_envelope, webauthn_challenge,
};
use oneiron::consent::AuthenticatedOwner;
use oneiron::recovery::{
    CodeKeeping, KitIssue, KitSecretKind, PassphraseCost, PieceHome, restore_kit,
};
use oneiron::store::GateDecisionId;
use oneiron::store::recovery_kit::KitPiece;
use oneiron::test_doors::root_recovery::{recover_owner_root_waiting, released_authority_seed};
use oneiron::test_support::bind_host_owner;
use oneiron::world_keys::{RecoveryAuthoritySigner, RecoveryRootSeed};
use oneiron::{EntityId, ErrorKind, Vault, VaultConfig};
use oneiron_keystore::MemoryKeystore;
use oneiron_store::ports::manual_clock::ManualClock;
use p256::ecdsa::signature::Signer as _;
use p256::ecdsa::{Signature as P256Signature, SigningKey as P256SigningKey};
use sha2::{Digest as _, Sha256};

/// The instant every fixture opens at.
const T0: u64 = 1_790_000_000;
/// The wait the tests hold with: one hour.
const WAIT: Duration = Duration::from_secs(60 * 60);
/// The seed of the owner's device key that is lost.
const LOST_KEY_SEED: u8 = 21;
/// The seed of the successor key the box recovery would enrol.
const NEW_KEY_SEED: u8 = 41;

/// The doors' refusal words, asserted with `contains`.
const HOLD_NOT_LIVE: &str = "the recovery hold is not live";
const PASSKEY_NOT_ACTORS: &str = "the key is not a live passkey of the acting owner's";

/// User present and user verified.
const FLAGS_PRESENT_VERIFIED: u8 = 0x05;
/// User present alone.
const FLAGS_PRESENT_ONLY: u8 = 0x01;
/// The passkey's credential id (`rawId`).
const CREDENTIAL_ID: &[u8] = b"passkey-credential-0001";
/// The origin the passkey enrols at.
const ORIGIN: &str = "https://oneiron.test";
/// Another page under the same RP id.
const SIBLING_ORIGIN: &str = "https://docs.oneiron.test";

fn proof(vault: &Vault, person: EntityId) -> AuthenticatedOwner {
    vault
        .authenticate_owner(person, &person.to_hex(), true, GateDecisionId::now())
        .expect("an owner proof")
}

fn key_of(signing: &SigningKey) -> AuthorityKey {
    AuthorityKey::Ed25519(signing.verifying_key().to_bytes())
}

/// Asserts `error` is an authority refusal with `words`.
fn assert_refused(error: &oneiron::Error, words: &str) {
    assert_eq!(error.kind(), ErrorKind::AuthorityRefused, "{error}");
    assert!(
        error.to_string().contains(words),
        "the exact words {words:?}: {error}"
    );
}

/// The passkey a platform authenticator holds, as a software key.
fn passkey() -> P256SigningKey {
    P256SigningKey::from_slice(&[0x5A; 32]).expect("a P-256 scalar")
}

/// The passkey's key as the roster names it: compressed SEC1.
fn passkey_key() -> AuthorityKey {
    AuthorityKey::P256(
        passkey()
            .verifying_key()
            .to_encoded_point(true)
            .as_bytes()
            .to_vec(),
    )
}

/// What `navigator.credentials.get` returns for `challenge` when `key`
/// answers it at `origin` with `flags`: authenticator data (RP id hash,
/// flags, a zero sign count), client data JSON and the DER signature, in
/// their envelope.
fn assertion_by(key: &P256SigningKey, challenge: &[u8], flags: u8, origin: &str) -> Vec<u8> {
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
    webauthn_assertion_envelope(
        &authenticator_data,
        &client_data_json,
        signature.to_der().as_bytes(),
    )
    .expect("an envelope")
}

/// The passkey's verified assertion over `challenge` at its own origin.
fn passkey_assertion(challenge: &[u8]) -> Vec<u8> {
    assertion_by(&passkey(), challenge, FLAGS_PRESENT_VERIFIED, ORIGIN)
}

/// A vault with a confirmed world kit (generation 0 live) on a clock the
/// test moves: `owner_root_recovery_wait.rs`'s fixture.
struct Fixture {
    _dir: tempfile::TempDir,
    vault: Vault,
    clock: Arc<ManualClock>,
    issuer: HostSlipIssuer,
    person: EntityId,
    machine: EntityId,
    vault_id: [u8; 32],
    pieces: Vec<KitPiece>,
}

fn fixture() -> Fixture {
    let clock = ManualClock::new(T0);
    let dir = tempfile::tempdir().expect("tempdir");
    let mut config = VaultConfig::device();
    config.store_clock = clock.bundle();
    let vault = Vault::open(dir.path(), config).expect("the vault");
    vault.install_device_keystore(Arc::new(MemoryKeystore::default()));
    vault.prepare_install_signing().expect("install signing");
    let issuer = vault.bootstrap_host_slip_issuer().expect("the host seed");
    vault.ensure_host_root_slip(&issuer).expect("the host root");
    vault
        .provision_engine_machine_identities(&issuer)
        .expect("engine machines");
    vault
        .ensure_serving_install_profile(&issuer, MachineRole::HostedNode)
        .expect("this install's live machine profile");
    let person = vault.ensure_embedded_owner_actor().expect("the owner");
    bind_host_owner(&vault, &issuer, person).expect("the owner's binding");
    vault.ensure_vault_key().expect("the data key");
    let machine = vault
        .prepare_install_signing()
        .expect("this install's machine");
    let vault_id = vault
        .authority_fold()
        .expect("the fold")
        .vault_id
        .expect("a rooted vault");
    let issued = vault
        .issue_world_kit(
            &proof(&vault, person),
            &KitIssue {
                vault_id,
                homes: [
                    PieceHome::RecoveryCode(CodeKeeping::Paper),
                    PieceHome::TrustedPerson,
                    PieceHome::SecurityKey,
                ],
                passphrase: None,
                cost: PassphraseCost::FLOOR,
                only_machine: false,
            },
        )
        .expect("a kit");
    let fixture = Fixture {
        _dir: dir,
        vault,
        clock,
        issuer,
        person,
        machine,
        vault_id,
        pieces: issued.pieces,
    };
    fixture
        .vault
        .confirm_world_kit(
            &fixture.owner(),
            &fixture.kit_refs(),
            None,
            &BTreeSet::new(),
        )
        .expect("the kit confirms");
    fixture
}

impl Fixture {
    fn owner(&self) -> AuthenticatedOwner {
        proof(&self.vault, self.person)
    }

    fn authority(&self) -> ActAuthority {
        ActAuthority::Owner(self.owner(), ActSurface::ThisInstall)
    }

    /// Moves both clocks to `now`: the store's and the authority
    /// observation's floor.
    fn at(&self, now: u64) {
        self.clock.set(now);
        self.vault
            .advance_authority_clock_for_test(now)
            .expect("authority time moves");
    }

    fn kit_refs(&self) -> Vec<&KitPiece> {
        self.pieces.iter().take(2).collect()
    }

    /// `key`'s enrolment input for this vault and owner.
    fn enrollment(&self, key: &SigningKey) -> OwnerKeyEnrollment {
        let public_key = key.verifying_key().to_bytes();
        let challenge = self
            .vault
            .owner_key_enrollment_challenge_as(&self.authority(), self.machine, &public_key)
            .expect("the challenge");
        OwnerKeyEnrollment {
            machine: self.machine,
            public_key,
            proof: key.sign(&challenge).to_bytes().to_vec(),
        }
    }

    /// Enrols a device key (not this install's) under the host root.
    fn enrol_device_key(&self, seed: u8) -> SigningKey {
        let key = SigningKey::from_bytes(&[seed; 32]);
        self.vault
            .enrol_owner_signing_key_as_host(&self.authority(), self.enrollment(&key), &self.issuer)
            .expect("the owner enrols a device key");
        key
    }

    /// Enrols the passkey under the host root, its assertion over the
    /// enrollment challenge at its own origin.
    fn enrol_passkey(&self) -> AuthorityKey {
        let public_key = passkey()
            .verifying_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec();
        let challenge = self
            .vault
            .owner_passkey_enrollment_challenge_as(&self.authority(), &public_key)
            .expect("the passkey's enrollment challenge");
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
        let input = OwnerPasskeyEnrollment {
            credential_id: CREDENTIAL_ID.to_vec(),
            public_key,
            authenticator_data,
            client_data_json,
            signature: signature.to_der().as_bytes().to_vec(),
        };
        self.vault
            .enrol_owner_passkey_as_host(&self.authority(), &input, &self.issuer)
            .expect("the owner enrols his passkey");
        let key = passkey_key();
        assert!(self.live(&key), "the passkey is a live owner key");
        key
    }

    /// The kit's seed, restored from its two pieces.
    fn seed(&self) -> RecoveryRootSeed {
        let secret = restore_kit(
            self.vault_id,
            KitSecretKind::RecoveryRoot,
            &self.kit_refs(),
            None,
        )
        .expect("two pieces restore the seed");
        RecoveryRootSeed::from_restored_kit(secret).expect("the seed")
    }

    /// Generation 0's key as the box releases it: a box recovery.
    fn released_material(&self) -> RootMaterial {
        let seed = self.seed();
        let root = seed.public(&self.vault_id).expect("the root").id;
        RootMaterial::Released(
            RecoveryAuthoritySigner::from_released_seed(
                released_authority_seed(&seed, &self.vault_id, 0),
                &self.vault_id,
                root,
            )
            .expect("the released key"),
        )
    }

    /// A box recovery that waits: its hold (the attempt id) and its landing
    /// second, enrolling `successor` and revoking `lost`.
    fn hold(&self, successor: &SigningKey, lost: &AuthorityKey) -> (AuthorityEntryHash, u64) {
        let answer = recover_owner_root_waiting(
            &self.vault,
            &self.owner(),
            ActSurface::ThisInstall,
            self.released_material(),
            RootSuccessor::Device(self.enrollment(successor)),
            std::slice::from_ref(lost),
            WAIT,
        )
        .expect("the box recovery holds");
        let RootRecovery::Held { hold, lands_at } = answer else {
            panic!("the box recovery holds with a nonzero wait");
        };
        (hold, lands_at)
    }

    fn hold_view(&self, hold: &AuthorityEntryHash) -> RecoveryHoldView {
        self.vault
            .recovery_holds()
            .expect("the holds")
            .into_iter()
            .find(|view| view.hold == *hold)
            .expect("the hold is read")
    }

    fn live(&self, key: &AuthorityKey) -> bool {
        self.vault
            .authority_fold()
            .expect("the fold")
            .roster
            .get(key)
            .is_some_and(|device| !device.revoked)
    }

    fn history(&self) -> Vec<AuthorityLogEntry> {
        self.vault
            .export_signed_authority_history()
            .expect("the signed history")
            .iter()
            .map(|row| decode_authority_log_entry_body(row).expect("a row"))
            .collect()
    }
}

/// A fixture with the passkey enrolled, the lost device key enrolled, and a
/// live hold: the passkey, the lost key, the successor key, the hold and
/// its landing second.
struct HeldFixture {
    fixture: Fixture,
    passkey: AuthorityKey,
    lost: AuthorityKey,
    successor: AuthorityKey,
    hold: AuthorityEntryHash,
    lands_at: u64,
}

fn held_fixture() -> HeldFixture {
    let fixture = fixture();
    let passkey = fixture.enrol_passkey();
    let lost = key_of(&fixture.enrol_device_key(LOST_KEY_SEED));
    let successor_key = SigningKey::from_bytes(&[NEW_KEY_SEED; 32]);
    let (hold, lands_at) = fixture.hold(&successor_key, &lost);
    assert_eq!(fixture.hold_view(&hold).state, RecoveryHoldState::Waiting);
    HeldFixture {
        fixture,
        passkey,
        lost,
        successor: key_of(&successor_key),
        hold,
        lands_at,
    }
}

#[test]
fn a_passkey_cancels_a_live_hold_and_it_never_lands() {
    let held = held_fixture();
    let fixture = &held.fixture;
    let prepared = fixture
        .vault
        .prepare_recovery_hold_cancel_as(&fixture.authority(), held.hold, &held.passkey)
        .expect("the Cancel is prepared for the passkey");
    let cancel = fixture
        .vault
        .land_recovery_hold_cancel_as(
            &fixture.authority(),
            &prepared.entry,
            passkey_assertion(&prepared.challenge),
        )
        .expect("the passkey's Cancel lands");

    let row = fixture
        .history()
        .into_iter()
        .find(|row| authority_entry_hash(row).expect("a hash") == cancel)
        .expect("the Cancel is stored");
    assert_eq!(row.signer_key(), &held.passkey, "the passkey signs it");
    assert!(row.cosigns.is_empty(), "the passkey signs it alone");
    assert!(
        matches!(
            &row.op,
            AuthorityOp::RecoveryHoldAnswer(RecoveryHoldAnswer {
                hold,
                answer: RecoveryHoldAnswerKind::Cancel,
            }) if *hold == held.hold
        ),
        "the row is a Cancel of the hold"
    );
    let view = fixture.hold_view(&held.hold);
    assert_eq!(view.state, RecoveryHoldState::Cancelled);
    assert_eq!(view.answered_by, vec![held.passkey.clone()]);
    assert_eq!(
        view.cancelled_by,
        vec![fixture.person],
        "the hold names the owner whose passkey cancelled"
    );

    fixture.at(held.lands_at + 60);
    let landings = fixture
        .vault
        .land_due_recovery_holds()
        .expect("the landing runs");
    assert_eq!(landings.len(), 1, "the cancelled hold is cleaned");
    assert_eq!(landings[0].state, RecoveryHoldState::Cancelled);
    assert!(landings[0].enrollment.is_none(), "a Cancel writes nothing");
    assert!(landings[0].revoked.is_empty());
    assert!(!fixture.live(&held.successor), "the successor never enrols");
    assert!(fixture.live(&held.lost), "the lost key stays live");
    assert!(fixture.live(&held.passkey), "the passkey stays live");
}

#[test]
fn the_wire_takes_a_passkeys_cancel_and_refuses_its_it_is_me() {
    let held = held_fixture();
    let fixture = &held.fixture;
    let history = fixture.history();
    let parents: BTreeSet<AuthorityEntryHash> = history
        .iter()
        .flat_map(|row| row.parent_hashes.iter().copied())
        .collect();
    let heads: Vec<AuthorityEntryHash> = history
        .iter()
        .map(|row| authority_entry_hash(row).expect("a hash"))
        .filter(|row| !parents.contains(row))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let signed = |answer: RecoveryHoldAnswerKind| {
        let mut entry = AuthorityLogEntry {
            schema_version: AUTHORITY_LOG_SCHEMA_VERSION,
            vault_id: Some(fixture.vault_id),
            seq: 1,
            parent_hashes: heads.clone(),
            op: AuthorityOp::RecoveryHoldAnswer(RecoveryHoldAnswer {
                hold: held.hold,
                answer,
            }),
            signer: AuthoritySignature {
                suite: held.passkey.suite(),
                public_key: held.passkey.clone(),
                signature: Vec::new(),
            },
            cosigns: Vec::new(),
            ts: T0,
        };
        let transcript = authority_transcript(&entry).expect("a transcript");
        entry.signer.signature = passkey_assertion(&webauthn_challenge(&transcript));
        entry
    };
    encode_authority_log_entry_body(&signed(RecoveryHoldAnswerKind::Cancel))
        .expect("the wire takes a passkey's Cancel");
    encode_authority_log_entry_body(&signed(RecoveryHoldAnswerKind::ItIsMe))
        .expect_err("the wire refuses a passkey's ItIsMe");
    assert_eq!(
        fixture.hold_view(&held.hold).state,
        RecoveryHoldState::Waiting,
        "nothing answered the hold"
    );
}

#[test]
fn only_the_passkeys_verified_assertion_over_the_challenge_cancels() {
    let held = held_fixture();
    let fixture = &held.fixture;
    let prepared = fixture
        .vault
        .prepare_recovery_hold_cancel_as(&fixture.authority(), held.hold, &held.passkey)
        .expect("the Cancel is prepared for the passkey");
    let before = fixture.history().len();
    let wrong = [
        (
            "an assertion over another challenge",
            passkey_assertion(&[0x11; 32]),
        ),
        (
            "an assertion from a sibling origin",
            assertion_by(
                &passkey(),
                &prepared.challenge,
                FLAGS_PRESENT_VERIFIED,
                SIBLING_ORIGIN,
            ),
        ),
        (
            "an assertion that did not verify the person",
            assertion_by(&passkey(), &prepared.challenge, FLAGS_PRESENT_ONLY, ORIGIN),
        ),
        (
            "another key's assertion",
            assertion_by(
                &P256SigningKey::from_slice(&[0x6C; 32]).expect("a P-256 scalar"),
                &prepared.challenge,
                FLAGS_PRESENT_VERIFIED,
                ORIGIN,
            ),
        ),
    ];
    for (what, assertion) in wrong {
        fixture
            .vault
            .land_recovery_hold_cancel_as(&fixture.authority(), &prepared.entry, assertion)
            .expect_err(what);
        assert_eq!(
            fixture.hold_view(&held.hold).state,
            RecoveryHoldState::Waiting,
            "{what} cancels nothing"
        );
        assert_eq!(fixture.history().len(), before, "{what} writes nothing");
    }
    fixture
        .vault
        .land_recovery_hold_cancel_as(
            &fixture.authority(),
            &prepared.entry,
            passkey_assertion(&prepared.challenge),
        )
        .expect("the passkey's own assertion over the challenge lands");
    assert_eq!(
        fixture.hold_view(&held.hold).state,
        RecoveryHoldState::Cancelled
    );
}

#[test]
fn a_key_that_is_no_passkey_of_the_actor_prepares_no_cancel() {
    let held = held_fixture();
    let fixture = &held.fixture;
    let stranger = AuthorityKey::P256(
        P256SigningKey::from_slice(&[0x6C; 32])
            .expect("a P-256 scalar")
            .verifying_key()
            .to_encoded_point(true)
            .as_bytes()
            .to_vec(),
    );
    for (what, key) in [
        ("a P-256 key no enrollment names", stranger),
        ("the owner's device key, which is no passkey", held.lost),
    ] {
        let refused = fixture
            .vault
            .prepare_recovery_hold_cancel_as(&fixture.authority(), held.hold, &key)
            .expect_err(what);
        assert_refused(&refused, PASSKEY_NOT_ACTORS);
    }
    assert_eq!(
        fixture.hold_view(&held.hold).state,
        RecoveryHoldState::Waiting
    );
}

#[test]
fn a_cancel_prepared_before_the_hold_ended_lands_nothing() {
    let held = held_fixture();
    let fixture = &held.fixture;
    let prepared = fixture
        .vault
        .prepare_recovery_hold_cancel_as(&fixture.authority(), held.hold, &held.passkey)
        .expect("the Cancel is prepared for the passkey");
    fixture
        .vault
        .cancel_recovery_holds_with_kit_as(
            &fixture.authority(),
            &fixture.kit_refs(),
            None,
            Some(held.hold),
        )
        .expect("the kit cancels the hold first");
    let before = fixture.history().len();
    let refused = fixture
        .vault
        .land_recovery_hold_cancel_as(
            &fixture.authority(),
            &prepared.entry,
            passkey_assertion(&prepared.challenge),
        )
        .expect_err("the hold is no longer live");
    assert_refused(&refused, HOLD_NOT_LIVE);
    assert_eq!(
        fixture.history().len(),
        before,
        "the refusal writes nothing"
    );
    let refused = fixture
        .vault
        .prepare_recovery_hold_cancel_as(&fixture.authority(), held.hold, &held.passkey)
        .expect_err("an ended hold takes no new Cancel");
    assert_refused(&refused, HOLD_NOT_LIVE);
}
