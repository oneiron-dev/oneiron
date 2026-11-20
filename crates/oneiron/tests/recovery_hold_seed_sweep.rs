//! OPUS-WAYBACK recovery wait: the orphan sweep reaps a hold seed a crash
//! left behind (Sol F4).
//!
//! The door commits a pending slot record before R's seed enters the slot,
//! and drops the record once the slot is deleted. `land_due_recovery_holds`
//! sweeps first: a record whose slot holds no seed is dropped, and a seed
//! no hold names is deleted with its record. A hold's own seed stays until
//! its landing.
//!
//! Red on the recovery-wait head `86b9c4cd3b07`: the file does not compile
//! there (no `stage_orphan_recovery_hold_seed`, `recovery_hold_seed_present`
//! or `recovery_hold_slots_pending`).
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test recovery_hold_seed_sweep`.
#![cfg(oneiron_test_support)]

use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Duration;

use ed25519_dalek::{Signer, SigningKey};
use oneiron::authority::{
    AUTHORITY_TRANSCRIPT_DOMAIN, ActAuthority, ActSurface, AuthorityEntryHash, AuthorityKey,
    CheckpointRootSigner, HostSlipIssuer, MachineRole, OwnerKeyEnrollment, RecoveryHoldAnswerKind,
    RecoveryHoldLanding, RecoveryHoldState, RecoveryHoldView, RootMaterial, RootRecovery,
    RootSuccessor,
};
use oneiron::consent::AuthenticatedOwner;
use oneiron::recovery::{
    CodeKeeping, KitIssue, KitSecretKind, PassphraseCost, PieceHome, restore_kit,
};
use oneiron::store::GateDecisionId;
use oneiron::store::recovery_kit::KitPiece;
use oneiron::test_doors::owner_key_release::release_owner_keys;
use oneiron::test_doors::root_recovery::{
    recover_owner_root_waiting, recovery_hold_seed_present, recovery_hold_slots_pending,
    released_authority_seed, stage_orphan_recovery_hold_seed,
};
use oneiron::test_support::bind_host_owner;
use oneiron::world_keys::{RecoveryAuthoritySigner, RecoveryRootSeed};
use oneiron::{EntityId, Vault, VaultConfig};
use oneiron_keystore::MemoryKeystore;
use oneiron_store::ports::manual_clock::ManualClock;

/// The instant every fixture opens at.
const T0: u64 = 1_790_000_000;
/// The wait the tests hold with: one hour.
const WAIT: Duration = Duration::from_secs(60 * 60);
/// The seed of the owner's device key that is lost.
const LOST_KEY_SEED: u8 = 21;
/// The seed of the keeper device key that answers.
const KEEPER_KEY_SEED: u8 = 22;
/// The seed of the successor key.
const NEW_KEY_SEED: u8 = 41;

fn proof(vault: &Vault, person: EntityId) -> AuthenticatedOwner {
    vault
        .authenticate_owner(person, &person.to_hex(), true, GateDecisionId::now())
        .expect("an owner proof")
}

fn key_of(signing: &SigningKey) -> AuthorityKey {
    AuthorityKey::Ed25519(signing.verifying_key().to_bytes())
}

/// Another owner device's key, held on this handle: what the answer doors
/// sign with. A test double for a device install of its own.
struct KeySigner(SigningKey);

impl CheckpointRootSigner for KeySigner {
    fn root(&self) -> AuthorityKey {
        key_of(&self.0)
    }

    fn sign_checkpoint_statement(&self, statement: &[u8]) -> oneiron::Result<Vec<u8>> {
        Ok(self.0.sign(statement).to_bytes().to_vec())
    }

    fn sign_owner_proof(&self, transcript: &[u8]) -> oneiron::Result<Vec<u8>> {
        assert!(transcript.starts_with(AUTHORITY_TRANSCRIPT_DOMAIN));
        Ok(self.0.sign(transcript).to_bytes().to_vec())
    }
}

/// A vault with a confirmed world kit (generation 0 live), on a clock the
/// test moves. Based on `kit_only_authority_rotation.rs`, plus the
/// `ManualClock` open of `check_in/fixture.rs`.
struct Fixture {
    _dir: tempfile::TempDir,
    vault: Vault,
    clock: Arc<ManualClock>,
    issuer: HostSlipIssuer,
    person: EntityId,
    machine: EntityId,
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
    let owner = proof(&vault, person);
    let issued = vault
        .issue_world_kit(
            &owner,
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
        pieces: issued.pieces,
    };
    let refs = fixture.kit_refs();
    fixture
        .vault
        .confirm_world_kit(&fixture.owner(), &refs, None, &BTreeSet::new())
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

    /// Holds `key` on this handle, as another owner device's install holds
    /// its own key. The caller releases what the handle holds first, so the
    /// held set is exactly what the test names.
    fn hold_signer(&self, key: &SigningKey) {
        self.vault
            .hold_checkpoint_root_signer(Arc::new(KeySigner(key.clone())));
    }

    /// The kit's seed, restored from its two pieces.
    fn seed(&self) -> (RecoveryRootSeed, [u8; 32]) {
        let vault_id = self
            .vault
            .authority_fold()
            .expect("the fold")
            .vault_id
            .expect("a rooted vault");
        let secret = restore_kit(
            vault_id,
            KitSecretKind::RecoveryRoot,
            &self.kit_refs(),
            None,
        )
        .expect("two pieces restore the seed");
        (
            RecoveryRootSeed::from_restored_kit(secret).expect("the seed"),
            vault_id,
        )
    }

    fn released_material(&self) -> RootMaterial {
        let (seed, vault_id) = self.seed();
        let root = seed.public(&vault_id).expect("the root").id;
        RootMaterial::Released(
            RecoveryAuthoritySigner::from_released_seed(
                released_authority_seed(&seed, &vault_id, 0),
                &vault_id,
                root,
            )
            .expect("the released key"),
        )
    }

    fn recover_wait(
        &self,
        wait: Duration,
        material: RootMaterial,
        successor: RootSuccessor,
        lost: &[AuthorityKey],
    ) -> oneiron::Result<RootRecovery> {
        recover_owner_root_waiting(
            &self.vault,
            &self.owner(),
            ActSurface::ThisInstall,
            material,
            successor,
            lost,
            wait,
        )
    }

    fn hold_view(&self, hold: &AuthorityEntryHash) -> RecoveryHoldView {
        self.vault
            .recovery_holds()
            .expect("the holds")
            .into_iter()
            .find(|view| view.hold == *hold)
            .expect("the hold is read")
    }

    fn land(&self) -> Vec<RecoveryHoldLanding> {
        self.vault
            .land_due_recovery_holds()
            .expect("the landing runs")
    }
}

/// The attempt id and landing second of a `Held` answer.
fn held(answer: RootRecovery) -> (AuthorityEntryHash, u64) {
    let RootRecovery::Held { hold, lands_at } = answer else {
        panic!("the box recovery holds with a nonzero wait");
    };
    (hold, lands_at)
}

#[test]
fn an_orphaned_hold_seed_is_swept() {
    let fixture = fixture();
    let successor = [7u8; 32];
    stage_orphan_recovery_hold_seed(&fixture.vault, successor, &[9u8; 32])
        .expect("the crash state stages");
    assert!(
        recovery_hold_seed_present(&fixture.vault, successor).expect("the slot reads"),
        "the orphaned seed is staged"
    );
    assert_eq!(
        recovery_hold_slots_pending(&fixture.vault).expect("the records read"),
        vec![successor],
        "the orphaned slot is recorded"
    );

    let landings = fixture.land();
    assert!(landings.is_empty(), "no hold lands");
    assert!(
        !recovery_hold_seed_present(&fixture.vault, successor).expect("the slot reads"),
        "the sweep deleted the orphaned seed"
    );
    assert!(
        recovery_hold_slots_pending(&fixture.vault)
            .expect("the records read")
            .is_empty(),
        "the sweep dropped its record"
    );
}

#[test]
fn a_held_seed_stays_until_its_landing() {
    let fixture = fixture();
    let lost = fixture.enrol_device_key(LOST_KEY_SEED);
    let lost_key = key_of(&lost);
    let new_key = SigningKey::from_bytes(&[NEW_KEY_SEED; 32]);
    let successor = new_key.verifying_key().to_bytes();

    let (hold, lands_at) = held(
        fixture
            .recover_wait(
                WAIT,
                fixture.released_material(),
                RootSuccessor::Device(fixture.enrollment(&new_key)),
                std::slice::from_ref(&lost_key),
            )
            .expect("the box recovery holds"),
    );
    assert_eq!(fixture.hold_view(&hold).state, RecoveryHoldState::Waiting);
    assert!(
        recovery_hold_seed_present(&fixture.vault, successor).expect("the slot reads"),
        "the held seed is kept"
    );
    assert_eq!(
        recovery_hold_slots_pending(&fixture.vault).expect("the records read"),
        vec![successor],
        "the held slot is recorded"
    );

    fixture.at(lands_at + 60);
    let landings = fixture.land();
    assert_eq!(landings.len(), 1, "the due hold lands");
    assert_eq!(landings[0].hold, hold);
    assert_eq!(landings[0].state, RecoveryHoldState::Landed);
    assert!(
        !recovery_hold_seed_present(&fixture.vault, successor).expect("the slot reads"),
        "the landing deleted the seed"
    );
    assert!(
        recovery_hold_slots_pending(&fixture.vault)
            .expect("the records read")
            .is_empty(),
        "the landing dropped its record"
    );
}

#[test]
fn a_cancelled_holds_seed_is_swept_with_its_record() {
    let fixture = fixture();
    let lost = fixture.enrol_device_key(LOST_KEY_SEED);
    let lost_key = key_of(&lost);
    let keeper = fixture.enrol_device_key(KEEPER_KEY_SEED);
    let new_key = SigningKey::from_bytes(&[NEW_KEY_SEED; 32]);
    let successor = new_key.verifying_key().to_bytes();

    let (hold, _) = held(
        fixture
            .recover_wait(
                WAIT,
                fixture.released_material(),
                RootSuccessor::Device(fixture.enrollment(&new_key)),
                std::slice::from_ref(&lost_key),
            )
            .expect("the box recovery holds"),
    );
    release_owner_keys(&fixture.vault);
    fixture.hold_signer(&keeper);
    fixture
        .vault
        .answer_recovery_hold_as(&fixture.authority(), hold, RecoveryHoldAnswerKind::Cancel)
        .expect("the keeper device cancels");
    assert_eq!(fixture.hold_view(&hold).state, RecoveryHoldState::Cancelled);

    let landings = fixture.land();
    assert_eq!(landings.len(), 1, "the cancelled hold is cleaned");
    assert_eq!(landings[0].state, RecoveryHoldState::Cancelled);
    assert!(
        !recovery_hold_seed_present(&fixture.vault, successor).expect("the slot reads"),
        "the cleanup deleted the seed"
    );
    assert!(
        recovery_hold_slots_pending(&fixture.vault)
            .expect("the records read")
            .is_empty(),
        "the cleanup dropped its record"
    );
}
