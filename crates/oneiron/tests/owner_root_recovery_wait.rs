//! OPUS-WAYBACK recovery wait: a box recovery holds before owner-grade acts
//! land (Engine RULING WAYBACK-RECOVERY-HOLD-WIRE = A).
//!
//! After a box recovery (sign-in + recovery PIN, `RootMaterial::Released`)
//! the recovered root's authority key R does not vouch at once: the root's
//! door writes one `RecoveryHold` (the successor's enrolment input, the lost
//! keys, `lands_at`), keeps R's seed in this install's keystore slot, and
//! answers `RootRecovery::Held`. Another owner device ends the wait early
//! (`ItIsMe`) or stops the attempt (`Cancel`) with a `RecoveryHoldAnswer`
//! signed by its own live owner key, and the kit stops it with an
//! anchor-signed `Cancel`. At the wait's end the seed holder lands the
//! ordinary enrolment + revocations. A zero wait vouches as today; the kit
//! arm never waits.
//!
//! Time: the fixture opens on a `ManualClock` (as
//! `tests/check_in/fixture.rs` does) and moves authority time with
//! `advance_authority_clock_for_test` beside it, since the anchored
//! authority observation clock ignores wall candidates after seeding
//! (precedent: `tests/turn_program_triggers.rs`). The `lands_at - 1` probe
//! of the door-clock test runs at `lands_at - 60`: the anchor measures
//! real elapsed seconds, so a literal one-second margin would be flaky.
//!
//! The 21 tests: the 13 build-leg tests (`a_released_recovery_waits_then_lands`,
//! `zero_wait_lands_at_once`, `a_sheet_cancel_stops_the_attempt_and_a_retry_lands`,
//! `a_cancel_without_an_owner_key_is_refused`,
//! `a_device_the_recovery_removes_still_cancels`,
//! `the_kit_recovery_cancels_a_live_hold`, `an_owner_key_approval_ends_the_wait_early`,
//! `a_cancel_leaves_the_recovering_device_without_owner_key_or_seed`,
//! `a_hold_voids_when_its_root_key_is_revoked`,
//! `every_owner_device_reads_the_hold_after_an_export_import`,
//! `the_root_key_cannot_answer_its_own_hold`,
//! `a_landing_follows_the_door_installs_clock`, `a_cancelled_hold_never_lands`),
//! the five review-fix pins (`an_admin_or_host_key_never_answers_a_hold`,
//! `a_landing_binds_a_co_owner_whose_lost_key_held_their_binding`,
//! `the_waits_rows_are_marked_for_the_live_mirror`,
//! `a_box_call_after_the_wait_lands_and_answers_vouched`,
//! `a_kit_recovery_cancels_a_due_hold_on_the_door_install`), and the three
//! Sol-fix pins (`a_foreign_anchors_cancel_never_stops_a_hold`,
//! `a_kit_cancel_reaches_a_hold_only_an_adopted_checkpoint_carries`
//! (ignored: needs an adopted image), `a_retry_after_a_cancelled_hold_keeps_its_seed_and_lands`).
//!
//! Red on the kit-only rotation head `5adc0295753f`: the file does not
//! compile there (no `RecoveryHold` ops, no hold view, no answer doors, no
//! landing, no `RootRecovery::Held`, no `recover_owner_root_waiting`).
//! The five review-fix pins fail at `699bba4fa53` (the review fixes'
//! parent); the Sol-fix pins fail at `86b9c4cd3b07`.
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test owner_root_recovery_wait`.
#![cfg(oneiron_test_support)]

use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Duration;

use ed25519_dalek::{Signer, SigningKey};
use oneiron::authority::{
    AUTHORITY_LOG_SCHEMA_VERSION, AUTHORITY_TRANSCRIPT_DOMAIN, ActAuthority, ActSurface,
    ActorBindingStatus, AuthorityAttestation, AuthorityEntryHash, AuthorityKey, AuthorityLogEntry,
    AuthorityOp, AuthoritySignature, AuthorityTier, CheckpointRootSigner, DeviceAuthority,
    HostSlipIssuer, MACHINE_ENCRYPTION_SUITE_HYBRID_V1, MachineEncryptionKey, MachineRole,
    OwnerKeyEnrollment, OwnerRootRecord, ROLE_ADMIN, RecoveryHoldAnswer, RecoveryHoldAnswerKind,
    RecoveryHoldLanding, RecoveryHoldState, RecoveryHoldView, RootMaterial, RootRecovery,
    RootSuccessor, authority_entry_hash, authority_log_entity_id_from_hash, authority_transcript,
    decode_authority_log_entry_body, encode_authority_log_entry_body,
};
use oneiron::consent::AuthenticatedOwner;
use oneiron::federation::{FederationGrantRole, InitialSharedMember};
use oneiron::memory::MEMORY_CODE_OWNER_BINDING_REQUIRED;
use oneiron::recovery::{
    CodeKeeping, KitIssue, KitSecretKind, PassphraseCost, PieceHome, issue_recovery_root_kit,
    restore_kit,
};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::store::GateDecisionId;
use oneiron::store::recovery_kit::KitPiece;
use oneiron::test_doors::owner_key_release::release_owner_keys;
use oneiron::test_doors::root_recovery::{recover_owner_root_waiting, released_authority_seed};
use oneiron::test_support::bind_host_owner;
use oneiron::world_keys::{
    NoRecoveryBox, RecoveryAuthoritySigner, RecoveryPreset, RecoveryRootSeed,
};
use oneiron::{
    EdgeActorClass, EntityId, ErrorKind, HostingPrivacyPosture, TimeRange, Vault, VaultConfig,
};
use oneiron_keystore::{DeviceKeystore, KeystoreSlot, MemoryKeystore, SlotKind};
use oneiron_store::ports::manual_clock::ManualClock;

/// The instant every fixture opens at.
const T0: u64 = 1_790_000_000;
/// The wait the tests hold with: one hour.
const WAIT: Duration = Duration::from_secs(60 * 60);
/// No wait: today's vouch path.
const NO_WAIT: Duration = Duration::from_secs(0);
/// The seed of the owner's device key that is lost.
const LOST_KEY_SEED: u8 = 21;
/// The seed of the keeper device key that answers.
const KEEPER_KEY_SEED: u8 = 22;
/// The seed of an admin-only device key, which never answers a hold.
const ADMIN_KEY_SEED: u8 = 23;
/// The seed of a key that is not the vault's recovery root key, which a
/// foreign anchor's Cancel names as its cosign.
const STRANGER_KEY_SEED: u8 = 61;
/// The co-Owner fixture's shared vault id.
const SHARED: u64 = 44;
/// The seed of the co-Owner's first owner key, which binds them and is lost.
const CO_OWNER_LOST_SEED: u8 = 51;
/// The seeds of successor keys.
const NEW_KEY_SEED: u8 = 41;
const NEW2_KEY_SEED: u8 = 42;
const NEW3_KEY_SEED: u8 = 43;

/// The answer doors' refusal words, asserted with `contains`.
const HOLD_NOT_LIVE: &str = "the recovery hold is not live";
const ANSWER_KEY_IS_SUCCESSOR: &str = "the hold's successor key never answers its own hold";
const ANSWER_KEY_IS_ROOT: &str = "the root's authority key never answers a recovery hold";
const NO_OWNER_KEY: &str = "this install holds no live owner key to answer the recovery hold";

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
    keystore: Arc<MemoryKeystore>,
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
    let keystore = Arc::new(MemoryKeystore::default());
    vault.install_device_keystore(keystore.clone());
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
        keystore,
        issuer,
        person,
        machine,
        vault_id,
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

    /// Generation `generation`'s public key, via the box's bytes.
    fn generation_key(&self, generation: u32) -> [u8; 32] {
        let seed = self.seed();
        SigningKey::from_bytes(&released_authority_seed(&seed, &self.vault_id, generation))
            .verifying_key()
            .to_bytes()
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

    fn kit_material(&self) -> RootMaterial {
        RootMaterial::Kit {
            seed: self.seed(),
            confirm: None,
        }
    }

    fn released_material(&self, generation: u32) -> RootMaterial {
        let seed = self.seed();
        let root = seed.public(&self.vault_id).expect("the root").id;
        RootMaterial::Released(
            RecoveryAuthoritySigner::from_released_seed(
                released_authority_seed(&seed, &self.vault_id, generation),
                &self.vault_id,
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

    fn holds(&self) -> Vec<RecoveryHoldView> {
        self.vault.recovery_holds().expect("the holds")
    }

    fn hold_view(&self, hold: &AuthorityEntryHash) -> RecoveryHoldView {
        self.holds()
            .into_iter()
            .find(|view| view.hold == *hold)
            .expect("the hold is read")
    }

    fn land(&self) -> Vec<RecoveryHoldLanding> {
        self.vault
            .land_due_recovery_holds()
            .expect("the landing runs")
    }

    /// Whether this install's keystore still keeps R's seed for
    /// `successor`'s hold.
    fn slot_present(&self, successor: &[u8; 32]) -> bool {
        let slot = KeystoreSlot {
            vault_id: self.vault_id,
            install: *self.machine.as_bytes(),
            kind: SlotKind::RecoveryHold(*successor),
        };
        self.keystore
            .get(&slot)
            .expect("the keystore reads")
            .is_some()
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

    fn row(&self, entry: &AuthorityEntryHash) -> AuthorityLogEntry {
        self.history()
            .into_iter()
            .find(|row| authority_entry_hash(row).expect("a hash") == *entry)
            .expect("the row is stored")
    }

    /// The stored history's heads, which a new main-log entry names.
    fn heads(&self) -> Vec<AuthorityEntryHash> {
        let rows = self.history();
        let parents: BTreeSet<AuthorityEntryHash> = rows
            .iter()
            .flat_map(|row| row.parent_hashes.iter().copied())
            .collect();
        let mut heads: Vec<AuthorityEntryHash> = rows
            .iter()
            .map(|row| authority_entry_hash(row).expect("a hash"))
            .filter(|row| !parents.contains(row))
            .collect();
        heads.sort_unstable();
        heads.dedup();
        heads
    }

    /// `signer`'s next sequence in the stored history.
    fn next_seq(&self, signer: &AuthorityKey) -> u64 {
        self.history()
            .iter()
            .filter(|row| row.signer_key() == signer)
            .map(|row| row.seq + 1)
            .max()
            .unwrap_or(1)
    }

    /// Switches to `NobodyButMe` with the kit (the CLI's kept-sheet shape):
    /// rotates R.
    fn switch_with_kit(&self) {
        self.vault
            .set_recovery_preset_with_kit_as(
                &self.authority(),
                RecoveryPreset::NobodyButMe,
                &self.kit_refs(),
                None,
                |_| Ok(()),
                &NoRecoveryBox,
            )
            .expect("the switch with the kit");
    }

    fn switch_back_to_standard(&self) {
        self.vault
            .set_recovery_preset_as(
                &self.owner(),
                RecoveryPreset::Standard,
                |_| Ok(()),
                &NoRecoveryBox,
            )
            .expect("the switch back");
    }
}

/// A second install of the vault: its own directory, clock and keystore,
/// the history imported as sync carries it. It holds no seed slot of any
/// hold: slots never sync.
struct Replica {
    _dir: tempfile::TempDir,
    vault: Vault,
}

fn replica(history: &[Vec<u8>], at: u64) -> Replica {
    let clock = ManualClock::new(at);
    let dir = tempfile::tempdir().expect("tempdir");
    let mut config = VaultConfig::device();
    config.store_clock = clock.bundle();
    let vault = Vault::open(dir.path(), config).expect("the replica");
    vault.install_device_keystore(Arc::new(MemoryKeystore::default()));
    vault
        .import_signed_authority_history(history)
        .expect("the replica takes the rows");
    Replica { _dir: dir, vault }
}

/// `seed` rebuilt from two stored pieces of a kit issued for it: the owner's
/// restore (as `tests/owner_root_recovery.rs`).
fn restored(vault_id: [u8; 32], seed: &RecoveryRootSeed) -> RecoveryRootSeed {
    let issue = KitIssue {
        vault_id,
        homes: [
            PieceHome::ThisMachine,
            PieceHome::OtherMachine(EntityId::now()),
            PieceHome::OtherMachine(EntityId::now()),
        ],
        passphrase: None,
        cost: PassphraseCost::FLOOR,
        only_machine: false,
    };
    let pieces = issue_recovery_root_kit(&issue, &seed.kit_bytes())
        .expect("the kit")
        .into_pieces();
    let secret = restore_kit(
        vault_id,
        KitSecretKind::RecoveryRoot,
        &[&pieces[0], &pieces[1]],
        None,
    )
    .expect("two stored pieces restore the seed");
    RecoveryRootSeed::from_restored_kit(secret).expect("the restored seed")
}

/// A self-hosted shared vault whose embedded owner the host root binds, with
/// a co-Owner the owner added as the fixture's `person`, on a clock the test
/// moves (as `tests/owner_root_recovery.rs`' `co_owner_fixture`, plus the
/// `ManualClock` open). The co-Owner's first owner key (`lost_key`, the key
/// that is lost) binds them as `human`, as an added Owner's first key does
/// on a self-hosted vault. The root's authority key is enrolled, never
/// confirmed through a world kit: the box recovery needs no kit.
struct CoOwner {
    _dir: tempfile::TempDir,
    vault: Vault,
    clock: Arc<ManualClock>,
    issuer: HostSlipIssuer,
    person: EntityId,
    vault_id: [u8; 32],
    machine: EntityId,
    lost_key: SigningKey,
    seed: RecoveryRootSeed,
}

fn co_owner_wait_fixture() -> CoOwner {
    let clock = ManualClock::new(T0);
    let dir = tempfile::tempdir().expect("tempdir");
    let mut config = VaultConfig::device();
    config.privacy.posture = HostingPrivacyPosture::SelfHostLocal;
    config.store_clock = clock.bundle();
    let vault = Vault::open(dir.path(), config).expect("the vault");
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    let issuer = oneiron::test_support::provision_engine_machines(&vault);
    vault
        .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
        .expect("this install's live machine profile");
    let owner = vault.ensure_embedded_owner_actor().expect("the owner");
    bind_host_owner(&vault, &issuer, owner).expect("the owner's binding");
    vault
        .initialize_shared_vault(
            &proof(&vault, owner),
            SHARED,
            None,
            &[InitialSharedMember {
                member_ref: owner,
                role: Some(FederationGrantRole::Owner),
            }],
            1,
        )
        .expect("a shared vault");
    let co_owner = EntityId::now();
    vault
        .put_entity(
            &co_owner,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"human",
        )
        .expect("a live person");
    let owner_proof = proof(&vault, owner);
    let act = vault
        .propose_add_owner(&owner_proof, SHARED, co_owner)
        .expect("the owner starts add_owner");
    vault
        .execute_completed_shared_act(&owner_proof, &act.id, Some(&issuer))
        .expect("add_owner runs at once");
    let vault_id = vault
        .authority_fold()
        .expect("the fold")
        .vault_id
        .expect("a rooted vault");
    let machine = vault
        .prepare_install_signing()
        .expect("this install's machine");
    let fixture = CoOwner {
        _dir: dir,
        vault,
        clock,
        issuer,
        person: co_owner,
        vault_id,
        machine,
        lost_key: SigningKey::from_bytes(&[CO_OWNER_LOST_SEED; 32]),
        seed: restored(
            vault_id,
            &RecoveryRootSeed::generate().expect("a root seed"),
        ),
    };
    let input = fixture.enrollment(&fixture.lost_key);
    fixture
        .vault
        .enrol_owner_signing_key_as_host(&fixture.authority(), input, &fixture.issuer)
        .expect("the co-Owner enrols their first owner key");
    fixture
}

/// Whether `person` passes the owner verbs: a live `human` binding names
/// them (as `tests/owner_root_recovery.rs`).
fn passes_owner_verbs(vault: &Vault, person: EntityId) -> bool {
    match vault.memory(person, EdgeActorClass::Human).verify_owner() {
        Ok(()) => true,
        Err(error) => {
            assert_eq!(error.code, MEMORY_CODE_OWNER_BINDING_REQUIRED, "{error:?}");
            false
        }
    }
}

impl CoOwner {
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

    /// `key`'s enrolment input for this vault and owner, with its proof of
    /// possession.
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

    /// The owner enrols the kit root's authority key before the loss.
    fn enrol_root_key(&self) -> AuthorityKey {
        let receipt = self
            .vault
            .enrol_recovery_authority_key_as_host(
                &self.authority(),
                self.machine,
                &self.seed,
                &self.issuer,
            )
            .expect("the owner enrols the root's authority key");
        AuthorityKey::Ed25519(receipt.public_key)
    }

    fn released(&self) -> RootMaterial {
        let root = self.seed.public(&self.vault_id).expect("the root").id;
        RootMaterial::Released(
            RecoveryAuthoritySigner::from_released_seed(
                released_authority_seed(&self.seed, &self.vault_id, 0),
                &self.vault_id,
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

    fn holds(&self) -> Vec<RecoveryHoldView> {
        self.vault.recovery_holds().expect("the holds")
    }

    fn hold_view(&self, hold: &AuthorityEntryHash) -> RecoveryHoldView {
        self.holds()
            .into_iter()
            .find(|view| view.hold == *hold)
            .expect("the hold is read")
    }

    fn land(&self) -> Vec<RecoveryHoldLanding> {
        self.vault
            .land_due_recovery_holds()
            .expect("the landing runs")
    }

    fn live(&self, key: &AuthorityKey) -> bool {
        self.vault
            .authority_fold()
            .expect("the fold")
            .roster
            .get(key)
            .is_some_and(|device| !device.revoked)
    }
}

impl Replica {
    fn holds(&self) -> Vec<RecoveryHoldView> {
        self.vault.recovery_holds().expect("the replica's holds")
    }

    fn owner(&self) -> AuthenticatedOwner {
        let person = self
            .vault
            .ensure_embedded_owner_actor()
            .expect("the owner on the replica");
        proof(&self.vault, person)
    }

    fn authority(&self) -> ActAuthority {
        ActAuthority::Owner(self.owner(), ActSurface::ThisInstall)
    }
}

/// Asserts the door's answer is a vouch that enrolled `new` and revoked
/// exactly `lost`, each signed by `root_key`, and that the custodial root
/// and the root's key stay live (as `tests/owner_root_recovery.rs`).
fn assert_vouched(
    fixture: &Fixture,
    answer: RootRecovery,
    root_key: &AuthorityKey,
    new: &AuthorityKey,
    lost: &AuthorityKey,
) {
    let RootRecovery::Vouched {
        enrollment,
        revoked,
    } = answer
    else {
        panic!("the root's live authority key vouches; the anchor appoints nothing here");
    };
    assert_eq!(AuthorityKey::Ed25519(enrollment.public_key), *new);
    let enrolment = fixture.row(&enrollment.entry);
    assert!(matches!(enrolment.op, AuthorityOp::OwnerKeyEnroll(_)));
    assert_eq!(
        enrolment.signer_key(),
        root_key,
        "the root's key is the predecessor"
    );
    assert_eq!(revoked.len(), 1, "one lost key, one revocation");
    let revocation = fixture.row(&revoked[0]);
    assert!(
        matches!(&revocation.op, AuthorityOp::RevokeDevice { revoked_key } if revoked_key == lost),
        "the revocation names the lost key"
    );
    assert_eq!(revocation.signer_key(), root_key, "the root's key signs it");
    assert!(fixture.live(new), "the new key is live");
    assert!(!fixture.live(lost), "the lost key is revoked");
    assert!(fixture.live(root_key), "the root's key stays live");
    assert!(
        fixture.live(&fixture.issuer.public_key()),
        "the custodial root stays live: no ReRoot ran"
    );
    fixture
        .vault
        .ensure_host_root_slip(&fixture.issuer)
        .expect("the host root still signs");
}

/// The attempt id and landing second of a `Held` answer.
fn held(answer: RootRecovery) -> (AuthorityEntryHash, u64) {
    let RootRecovery::Held { hold, lands_at } = answer else {
        panic!("the box recovery holds with a nonzero wait");
    };
    (hold, lands_at)
}

/// An admin-only device of `seed`'s key (as `tests/owner_root_recovery.rs`'
/// `owner_device`, but with the admin role alone): the generic consent rule
/// admits it, but it never answers a recovery hold.
fn admin_device(seed: u8) -> DeviceAuthority {
    DeviceAuthority {
        key: key_of(&SigningKey::from_bytes(&[seed; 32])),
        transport_key_binding: [7; 32],
        attestation: AuthorityAttestation {
            kind: "SoftwareArgon2id".to_owned(),
            evidence: vec![1, 2, 3],
        },
        tier: AuthorityTier::Software,
        roles: ROLE_ADMIN,
    }
}

/// Every pending-mirror marker (`lm:w:`) the vault holds, paged as
/// `the_doors_rows_are_marked_for_the_live_mirror` reads them
/// (`tests/owner_root_recovery.rs`).
fn markers(vault: &Vault) -> Vec<String> {
    let mut markers = Vec::new();
    let mut after: Option<String> = None;
    loop {
        after = vault
            .sync_state_prefix_page("lm:w:", after.as_deref(), 256, |key, _| {
                markers.push(key.to_owned());
                Ok(())
            })
            .expect("a page of the pending-mirror markers");
        if after.is_none() {
            break;
        }
    }
    markers
}

/// Asserts every entry of `entries` carries a pending-mirror marker for its
/// window among `markers`.
fn assert_marked(markers: &[String], entries: &[AuthorityEntryHash]) {
    for entry in entries {
        let id = authority_log_entity_id_from_hash(entry)
            .expect("the row's id")
            .to_hex();
        assert!(
            markers
                .iter()
                .any(|marker| marker.ends_with(&format!(":{id}"))),
            "the row {id} carries a marker for its window: {markers:?}"
        );
    }
}

#[test]
fn a_released_recovery_waits_then_lands() {
    let fixture = fixture();
    let root_key = AuthorityKey::Ed25519(fixture.generation_key(0));
    assert!(fixture.live(&root_key), "generation 0 is live");
    let lost = fixture.enrol_device_key(LOST_KEY_SEED);
    let lost_key = key_of(&lost);
    let new_key = SigningKey::from_bytes(&[NEW_KEY_SEED; 32]);
    let new = key_of(&new_key);
    let before_roster = fixture.vault.authority_fold().expect("the fold").roster;
    let before_history = fixture.history().len();

    let (hold, lands_at) = held(
        fixture
            .recover_wait(
                WAIT,
                fixture.released_material(0),
                RootSuccessor::Device(fixture.enrollment(&new_key)),
                std::slice::from_ref(&lost_key),
            )
            .expect("the box recovery holds"),
    );
    assert!(
        lands_at >= T0 + WAIT.as_secs(),
        "the wait lands on this install's clock: {lands_at}"
    );
    assert!(
        lands_at < T0 + WAIT.as_secs() + 300,
        "the wait is one hour, not wall time: {lands_at}"
    );
    // A second call while the hold waits answers the same Held, and writes
    // no second hold.
    let again = fixture
        .recover_wait(
            WAIT,
            fixture.released_material(0),
            RootSuccessor::Device(fixture.enrollment(&new_key)),
            std::slice::from_ref(&lost_key),
        )
        .expect("the same Held again");
    assert_eq!(again, RootRecovery::Held { hold, lands_at });
    assert_eq!(
        fixture.history().len(),
        before_history + 1,
        "one hold row, no enrolment and no revocation"
    );
    assert_eq!(
        fixture.vault.authority_fold().expect("the fold").roster,
        before_roster,
        "the roster is unchanged while the hold waits"
    );
    assert!(!fixture.live(&new), "the successor is not enrolled yet");
    assert!(fixture.live(&lost_key), "the lost key is still live");
    assert!(
        fixture.slot_present(&new_key.verifying_key().to_bytes()),
        "this install keeps R's seed for the hold"
    );
    let view = fixture.hold_view(&hold);
    assert_eq!(view.state, RecoveryHoldState::Waiting);
    assert_eq!(view.lands_at, lands_at);
    assert_eq!(view.successor_key, new);
    assert_eq!(view.lost, vec![lost_key.clone()]);
    assert!(view.answered_by.is_empty());

    fixture.at(lands_at + 60);
    let landings = fixture.land();
    assert_eq!(landings.len(), 1, "the due hold lands");
    assert_eq!(landings[0].hold, hold);
    assert_eq!(landings[0].state, RecoveryHoldState::Landed);
    assert_vouched(
        &fixture,
        RootRecovery::Vouched {
            enrollment: landings[0].enrollment.expect("the enrolment"),
            revoked: landings[0].revoked.clone(),
        },
        &root_key,
        &new,
        &lost_key,
    );
    assert!(
        !fixture.slot_present(&new_key.verifying_key().to_bytes()),
        "the landing deletes R's seed"
    );
    assert_eq!(
        fixture.hold_view(&hold).state,
        RecoveryHoldState::Landed,
        "the hold reads Landed after"
    );
}

#[test]
fn zero_wait_lands_at_once() {
    let fixture = fixture();
    let root_key = AuthorityKey::Ed25519(fixture.generation_key(0));
    let lost = fixture.enrol_device_key(LOST_KEY_SEED);
    let lost_key = key_of(&lost);
    let new_key = SigningKey::from_bytes(&[NEW_KEY_SEED; 32]);
    let new = key_of(&new_key);
    let before_history = fixture.history().len();

    let answer = fixture
        .recover_wait(
            NO_WAIT,
            fixture.released_material(0),
            RootSuccessor::Device(fixture.enrollment(&new_key)),
            std::slice::from_ref(&lost_key),
        )
        .expect("a zero wait vouches at once");

    assert_vouched(&fixture, answer, &root_key, &new, &lost_key);
    assert_eq!(
        fixture.history().len(),
        before_history + 2,
        "the enrolment and the revocation, and no hold row"
    );
    assert!(fixture.holds().is_empty(), "no hold was written");
    assert!(
        !fixture.slot_present(&new_key.verifying_key().to_bytes()),
        "no seed is kept without a hold"
    );
}

#[test]
fn a_sheet_cancel_stops_the_attempt_and_a_retry_lands() {
    let fixture = fixture();
    let root_key = AuthorityKey::Ed25519(fixture.generation_key(0));
    let lost = fixture.enrol_device_key(LOST_KEY_SEED);
    let lost_key = key_of(&lost);
    let keeper = fixture.enrol_device_key(KEEPER_KEY_SEED);
    let keeper_key = key_of(&keeper);
    let new_key = SigningKey::from_bytes(&[NEW_KEY_SEED; 32]);
    let new = key_of(&new_key);

    let (hold, _) = held(
        fixture
            .recover_wait(
                WAIT,
                fixture.released_material(0),
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
    assert_eq!(
        fixture.hold_view(&hold).state,
        RecoveryHoldState::Cancelled,
        "the Cancel lands on the hold"
    );
    assert_eq!(fixture.hold_view(&hold).answered_by, vec![keeper_key]);
    let landings = fixture.land();
    assert_eq!(landings.len(), 1, "the cancelled hold is cleaned");
    assert_eq!(landings[0].state, RecoveryHoldState::Cancelled);
    assert!(landings[0].enrollment.is_none(), "a cancel writes nothing");
    assert!(landings[0].revoked.is_empty());
    assert!(
        !fixture.slot_present(&new_key.verifying_key().to_bytes()),
        "the cancel deletes R's seed"
    );
    assert!(!fixture.live(&new), "the successor was never enrolled");

    // A retry after the cancel is a new attempt, and lands.
    let (retry, retry_lands_at) = held(
        fixture
            .recover_wait(
                WAIT,
                fixture.released_material(0),
                RootSuccessor::Device(fixture.enrollment(&new_key)),
                std::slice::from_ref(&lost_key),
            )
            .expect("the retry holds"),
    );
    assert_ne!(retry, hold, "the retry is a new attempt");
    fixture.at(retry_lands_at + 60);
    let landings = fixture.land();
    assert_eq!(landings.len(), 1);
    assert_eq!(landings[0].hold, retry);
    assert_vouched(
        &fixture,
        RootRecovery::Vouched {
            enrollment: landings[0].enrollment.expect("the enrolment"),
            revoked: landings[0].revoked.clone(),
        },
        &root_key,
        &new,
        &lost_key,
    );
    assert_eq!(
        fixture.hold_view(&hold).state,
        RecoveryHoldState::Cancelled,
        "the first hold stays cancelled"
    );
}

#[test]
fn a_cancel_without_an_owner_key_is_refused() {
    let fixture = fixture();
    let lost = fixture.enrol_device_key(LOST_KEY_SEED);
    let lost_key = key_of(&lost);
    let new_key = SigningKey::from_bytes(&[NEW_KEY_SEED; 32]);
    let (hold, _) = held(
        fixture
            .recover_wait(
                WAIT,
                fixture.released_material(0),
                RootSuccessor::Device(fixture.enrollment(&new_key)),
                std::slice::from_ref(&lost_key),
            )
            .expect("the box recovery holds"),
    );
    // Sign-in alone, on an install that holds no owner key and no seed of
    // the hold: the replica.
    let history = fixture
        .vault
        .export_signed_authority_history()
        .expect("the history");
    let replica = replica(&history, T0);
    assert_eq!(
        replica
            .holds()
            .into_iter()
            .find(|view| view.hold == hold)
            .expect("the replica reads the hold")
            .state,
        RecoveryHoldState::Waiting
    );
    let before_roster = replica.vault.authority_fold().expect("the fold").roster;
    let before_history = replica
        .vault
        .export_signed_authority_history()
        .expect("the history")
        .len();

    let refused = replica
        .vault
        .answer_recovery_hold_as(&replica.authority(), hold, RecoveryHoldAnswerKind::Cancel)
        .expect_err("sign-in alone cannot answer");
    assert_refused(&refused, NO_OWNER_KEY);
    assert_eq!(
        replica.vault.authority_fold().expect("the fold").roster,
        before_roster,
        "the roster is unchanged"
    );
    assert_eq!(
        replica
            .vault
            .export_signed_authority_history()
            .expect("the history")
            .len(),
        before_history,
        "the refusal writes nothing"
    );
}

#[test]
fn a_device_the_recovery_removes_still_cancels() {
    let fixture = fixture();
    let lost = fixture.enrol_device_key(LOST_KEY_SEED);
    let lost_key = key_of(&lost);
    let new_key = SigningKey::from_bytes(&[NEW_KEY_SEED; 32]);
    let (hold, _) = held(
        fixture
            .recover_wait(
                WAIT,
                fixture.released_material(0),
                RootSuccessor::Device(fixture.enrollment(&new_key)),
                std::slice::from_ref(&lost_key),
            )
            .expect("the box recovery holds"),
    );
    release_owner_keys(&fixture.vault);
    fixture.hold_signer(&lost);
    fixture
        .vault
        .answer_recovery_hold_as(&fixture.authority(), hold, RecoveryHoldAnswerKind::Cancel)
        .expect("a key the hold lists as lost still cancels");
    assert_eq!(fixture.hold_view(&hold).state, RecoveryHoldState::Cancelled);
    assert!(fixture.live(&lost_key), "the lost key stays live");
}

#[test]
fn the_kit_recovery_cancels_a_live_hold() {
    let fixture = fixture();
    let root_key = AuthorityKey::Ed25519(fixture.generation_key(0));
    let lost = fixture.enrol_device_key(LOST_KEY_SEED);
    let lost_key = key_of(&lost);
    let new_key = SigningKey::from_bytes(&[NEW_KEY_SEED; 32]);
    let new2_key = SigningKey::from_bytes(&[NEW2_KEY_SEED; 32]);
    let new2 = key_of(&new2_key);
    let new3_key = SigningKey::from_bytes(&[NEW3_KEY_SEED; 32]);

    // The kit's cancel door stops a live hold by name.
    let (hold, _) = held(
        fixture
            .recover_wait(
                WAIT,
                fixture.released_material(0),
                RootSuccessor::Device(fixture.enrollment(&new_key)),
                std::slice::from_ref(&lost_key),
            )
            .expect("the box recovery holds"),
    );
    fixture
        .vault
        .cancel_recovery_holds_with_kit_as(
            &fixture.authority(),
            &fixture.kit_refs(),
            None,
            Some(hold),
        )
        .expect("the kit cancels the live hold");
    assert_eq!(fixture.hold_view(&hold).state, RecoveryHoldState::Cancelled);

    // A kit recovery cancels the live hold in its own write, before its
    // vouch rows: the kit lands over the attempt.
    let (retry, _) = held(
        fixture
            .recover_wait(
                WAIT,
                fixture.released_material(0),
                RootSuccessor::Device(fixture.enrollment(&new2_key)),
                std::slice::from_ref(&lost_key),
            )
            .expect("the retry holds"),
    );
    let answer = fixture
        .vault
        .recover_owner_root(
            &fixture.owner(),
            ActSurface::ThisInstall,
            fixture.kit_material(),
            RootSuccessor::Device(fixture.enrollment(&new2_key)),
            std::slice::from_ref(&lost_key),
        )
        .expect("the kit recovers");
    assert_vouched(&fixture, answer, &root_key, &new2, &lost_key);
    assert_eq!(
        fixture.hold_view(&retry).state,
        RecoveryHoldState::Cancelled,
        "the kit's write cancelled the live hold"
    );

    // Cancelling every live hold, unnamed, stops the next attempt too.
    let (third, _) = held(
        fixture
            .recover_wait(
                WAIT,
                fixture.released_material(0),
                RootSuccessor::Device(fixture.enrollment(&new3_key)),
                &[],
            )
            .expect("the third attempt holds"),
    );
    fixture
        .vault
        .cancel_recovery_holds_with_kit_as(&fixture.authority(), &fixture.kit_refs(), None, None)
        .expect("the kit cancels every live hold");
    assert_eq!(
        fixture.hold_view(&third).state,
        RecoveryHoldState::Cancelled
    );
    assert_eq!(
        fixture.hold_view(&hold).state,
        RecoveryHoldState::Cancelled,
        "the first hold stays cancelled"
    );
}

#[test]
fn an_owner_key_approval_ends_the_wait_early() {
    let fixture = fixture();
    let root_key = AuthorityKey::Ed25519(fixture.generation_key(0));
    let lost = fixture.enrol_device_key(LOST_KEY_SEED);
    let lost_key = key_of(&lost);
    let keeper = fixture.enrol_device_key(KEEPER_KEY_SEED);
    let new_key = SigningKey::from_bytes(&[NEW_KEY_SEED; 32]);
    let new = key_of(&new_key);

    let (hold, _) = held(
        fixture
            .recover_wait(
                WAIT,
                fixture.released_material(0),
                RootSuccessor::Device(fixture.enrollment(&new_key)),
                std::slice::from_ref(&lost_key),
            )
            .expect("the box recovery holds"),
    );
    release_owner_keys(&fixture.vault);
    fixture.hold_signer(&keeper);
    fixture
        .vault
        .answer_recovery_hold_as(&fixture.authority(), hold, RecoveryHoldAnswerKind::ItIsMe)
        .expect("the keeper device approves");
    assert_eq!(
        fixture.hold_view(&hold).state,
        RecoveryHoldState::Due,
        "ItIsMe is Due at once, before lands_at"
    );
    // The wait ends early: the landing runs before lands_at.
    let landings = fixture.land();
    assert_eq!(landings.len(), 1);
    assert_vouched(
        &fixture,
        RootRecovery::Vouched {
            enrollment: landings[0].enrollment.expect("the enrolment"),
            revoked: landings[0].revoked.clone(),
        },
        &root_key,
        &new,
        &lost_key,
    );
}

#[test]
fn a_cancel_leaves_the_recovering_device_without_owner_key_or_seed() {
    let fixture = fixture();
    let lost = fixture.enrol_device_key(LOST_KEY_SEED);
    let lost_key = key_of(&lost);
    let keeper = fixture.enrol_device_key(KEEPER_KEY_SEED);
    let new_key = SigningKey::from_bytes(&[NEW_KEY_SEED; 32]);
    let new = key_of(&new_key);
    let new_pub = new_key.verifying_key().to_bytes();
    let before_history = fixture.history().len();

    let (hold, _) = held(
        fixture
            .recover_wait(
                WAIT,
                fixture.released_material(0),
                RootSuccessor::Device(fixture.enrollment(&new_key)),
                std::slice::from_ref(&lost_key),
            )
            .expect("the box recovery holds"),
    );
    assert!(fixture.slot_present(&new_pub));
    release_owner_keys(&fixture.vault);
    fixture.hold_signer(&keeper);
    fixture
        .vault
        .answer_recovery_hold_as(&fixture.authority(), hold, RecoveryHoldAnswerKind::Cancel)
        .expect("the keeper device cancels");
    let landings = fixture.land();
    assert_eq!(landings.len(), 1);
    assert_eq!(landings[0].state, RecoveryHoldState::Cancelled);

    assert!(!fixture.live(&new), "no owner key was enrolled");
    assert!(
        !fixture.slot_present(&new_pub),
        "no seed is kept after the cancel"
    );
    assert_eq!(
        fixture.history().len(),
        before_history + 2,
        "the hold and the answer, and nothing else"
    );
}

#[test]
fn a_hold_voids_when_its_root_key_is_revoked() {
    let fixture = fixture();
    let gen0 = AuthorityKey::Ed25519(fixture.generation_key(0));
    let gen1 = AuthorityKey::Ed25519(fixture.generation_key(1));
    let lost = fixture.enrol_device_key(LOST_KEY_SEED);
    let lost_key = key_of(&lost);
    let new_key = SigningKey::from_bytes(&[NEW_KEY_SEED; 32]);
    let new = key_of(&new_key);
    let new_pub = new_key.verifying_key().to_bytes();

    let (hold, lands_at) = held(
        fixture
            .recover_wait(
                WAIT,
                fixture.released_material(0),
                RootSuccessor::Device(fixture.enrollment(&new_key)),
                std::slice::from_ref(&lost_key),
            )
            .expect("the box recovery holds"),
    );
    let before_history = fixture.history().len();
    // The kit-only switch rotates R: generation 0 is revoked.
    fixture.switch_with_kit();
    assert!(!fixture.live(&gen0), "generation 0 is revoked");
    assert!(fixture.live(&gen1), "generation 1 is live");
    assert_eq!(
        fixture.hold_view(&hold).state,
        RecoveryHoldState::Void,
        "the hold voids with its root key"
    );

    fixture.at(lands_at + 60);
    let landings = fixture.land();
    assert_eq!(landings.len(), 1);
    assert_eq!(landings[0].state, RecoveryHoldState::Void);
    assert!(
        landings[0].enrollment.is_none(),
        "a void hold writes nothing"
    );
    assert!(landings[0].revoked.is_empty());
    assert!(!fixture.slot_present(&new_pub), "the void deletes R's seed");
    assert!(!fixture.live(&new), "the successor was never enrolled");
    assert_eq!(
        fixture.history().len(),
        before_history + 2,
        "the rotation's enrolment and revocation only"
    );

    // The new generation serves back on Standard, with a wait.
    fixture.switch_back_to_standard();
    let (retry, _) = held(
        fixture
            .recover_wait(
                WAIT,
                fixture.released_material(1),
                RootSuccessor::Device(fixture.enrollment(&new_key)),
                std::slice::from_ref(&lost_key),
            )
            .expect("released generation 1 holds"),
    );
    assert_ne!(retry, hold);
}

#[test]
fn every_owner_device_reads_the_hold_after_an_export_import() {
    let fixture = fixture();
    let lost = fixture.enrol_device_key(LOST_KEY_SEED);
    let lost_key = key_of(&lost);
    let new_key = SigningKey::from_bytes(&[NEW_KEY_SEED; 32]);
    let new = key_of(&new_key);

    let (hold, lands_at) = held(
        fixture
            .recover_wait(
                WAIT,
                fixture.released_material(0),
                RootSuccessor::Device(fixture.enrollment(&new_key)),
                std::slice::from_ref(&lost_key),
            )
            .expect("the box recovery holds"),
    );
    let history = fixture
        .vault
        .export_signed_authority_history()
        .expect("the history");
    let replica = replica(&history, T0);
    let view = replica
        .holds()
        .into_iter()
        .find(|view| view.hold == hold)
        .expect("every owner device reads the hold");
    assert_eq!(view.successor_key, new);
    assert_eq!(view.lands_at, lands_at);
    assert_eq!(view.lost, vec![lost_key]);
    assert_eq!(view.state, RecoveryHoldState::Waiting);
    assert!(view.answered_by.is_empty());
}

#[test]
fn the_root_key_cannot_answer_its_own_hold() {
    let fixture = fixture();
    let root_key = AuthorityKey::Ed25519(fixture.generation_key(0));
    let lost = fixture.enrol_device_key(LOST_KEY_SEED);
    let lost_key = key_of(&lost);
    let new_key = SigningKey::from_bytes(&[NEW_KEY_SEED; 32]);

    let (hold, _) = held(
        fixture
            .recover_wait(
                WAIT,
                fixture.released_material(0),
                RootSuccessor::Device(fixture.enrollment(&new_key)),
                std::slice::from_ref(&lost_key),
            )
            .expect("the box recovery holds"),
    );
    // The door: this install holds R's seed for the hold, and no owner
    // key beside it, so the answer is the root's.
    release_owner_keys(&fixture.vault);
    let refused = fixture
        .vault
        .answer_recovery_hold_as(&fixture.authority(), hold, RecoveryHoldAnswerKind::ItIsMe)
        .expect_err("the root key cannot answer its own hold");
    assert_refused(&refused, ANSWER_KEY_IS_ROOT);

    // The fold: an R-signed answer is stored and refused, and the hold is
    // unaffected.
    let before_roster = fixture.vault.authority_fold().expect("the fold").roster;
    let before_history = fixture.history().len();
    let r_signing = SigningKey::from_bytes(&released_authority_seed(
        &fixture.seed(),
        &fixture.vault_id,
        0,
    ));
    assert_eq!(key_of(&r_signing), root_key);
    let mut row = AuthorityLogEntry {
        schema_version: AUTHORITY_LOG_SCHEMA_VERSION,
        vault_id: Some(fixture.vault_id),
        seq: fixture.next_seq(&root_key),
        parent_hashes: fixture.heads(),
        op: AuthorityOp::RecoveryHoldAnswer(RecoveryHoldAnswer {
            hold,
            answer: RecoveryHoldAnswerKind::ItIsMe,
        }),
        signer: AuthoritySignature {
            suite: root_key.suite(),
            public_key: root_key.clone(),
            signature: vec![0; 64],
        },
        cosigns: Vec::new(),
        ts: T0,
    };
    let transcript = authority_transcript(&row).expect("the transcript");
    row.signer.signature = r_signing.sign(&transcript).to_bytes().to_vec();
    let hash = authority_entry_hash(&row).expect("a hash");
    let bytes = encode_authority_log_entry_body(&row).expect("the bytes");
    fixture
        .vault
        .import_signed_authority_history(&[bytes])
        .expect("the import stores the row");
    assert!(
        !fixture
            .vault
            .authority_fold()
            .expect("the fold")
            .valid_entries
            .contains(&hash),
        "the fold refuses the R-signed answer"
    );
    assert_eq!(
        fixture.vault.authority_fold().expect("the fold").roster,
        before_roster,
        "the roster is unchanged"
    );
    assert_eq!(
        fixture.history().len(),
        before_history + 1,
        "the refused row is stored, and nothing else is written"
    );
    let view = fixture.hold_view(&hold);
    assert_eq!(view.state, RecoveryHoldState::Waiting);
    assert!(view.answered_by.is_empty());

    // The successor key cannot answer its own hold either: a hold for a
    // fresh key of this install, answered here.
    let (own, _) = held(
        fixture
            .recover_wait(
                WAIT,
                fixture.released_material(0),
                RootSuccessor::ThisInstall,
                &[],
            )
            .expect("this install's recovery holds"),
    );
    let refused = fixture
        .vault
        .answer_recovery_hold_as(&fixture.authority(), own, RecoveryHoldAnswerKind::ItIsMe)
        .expect_err("the successor key cannot answer its own hold");
    assert_refused(&refused, ANSWER_KEY_IS_SUCCESSOR);
    assert_eq!(
        fixture.hold_view(&own).state,
        RecoveryHoldState::Waiting,
        "the refused answer changes nothing"
    );
}

#[test]
fn a_landing_follows_the_door_installs_clock() {
    let fixture = fixture();
    let root_key = AuthorityKey::Ed25519(fixture.generation_key(0));
    let lost = fixture.enrol_device_key(LOST_KEY_SEED);
    let lost_key = key_of(&lost);
    let new_key = SigningKey::from_bytes(&[NEW_KEY_SEED; 32]);
    let new = key_of(&new_key);
    let new_pub = new_key.verifying_key().to_bytes();

    let (hold, lands_at) = held(
        fixture
            .recover_wait(
                WAIT,
                fixture.released_material(0),
                RootSuccessor::Device(fixture.enrollment(&new_key)),
                std::slice::from_ref(&lost_key),
            )
            .expect("the box recovery holds"),
    );
    // Before the wait ends the hold waits, on this install's clock.
    fixture.at(lands_at - 60);
    assert!(fixture.land().is_empty(), "nothing lands before lands_at");
    assert!(fixture.slot_present(&new_pub), "the seed is kept");
    assert_eq!(fixture.hold_view(&hold).state, RecoveryHoldState::Waiting);

    // Past it the next door call lands it, then holds the new attempt.
    fixture.at(lands_at);
    let new2_key = SigningKey::from_bytes(&[NEW2_KEY_SEED; 32]);
    let (retry, _) = held(
        fixture
            .recover_wait(
                WAIT,
                fixture.released_material(0),
                RootSuccessor::Device(fixture.enrollment(&new2_key)),
                &[],
            )
            .expect("the next call lands, then holds"),
    );
    assert_ne!(retry, hold);
    let view = fixture.hold_view(&hold);
    assert_eq!(view.state, RecoveryHoldState::Landed);
    assert!(fixture.live(&new), "the successor landed");
    assert!(!fixture.live(&lost_key), "the lost key was revoked");
    assert!(
        !fixture.slot_present(&new_pub),
        "the landing deletes R's seed"
    );
    let enrolment = fixture
        .history()
        .into_iter()
        .find(|row| {
            matches!(&row.op, AuthorityOp::OwnerKeyEnroll(enroll)
                if enroll.device.key == new)
        })
        .expect("the landing enrolled the successor");
    assert_eq!(enrolment.signer_key(), &root_key);

    // A replica whose clock is behind imports the landing and folds
    // Landed: the landed rows are ordinary R-signed rows.
    let history = fixture
        .vault
        .export_signed_authority_history()
        .expect("the history");
    let replica = replica(&history, T0);
    assert_eq!(
        replica
            .holds()
            .into_iter()
            .find(|view| view.hold == hold)
            .expect("the replica reads the hold")
            .state,
        RecoveryHoldState::Landed
    );
}

#[test]
fn a_cancelled_hold_never_lands() {
    let fixture = fixture();
    let lost = fixture.enrol_device_key(LOST_KEY_SEED);
    let lost_key = key_of(&lost);
    let keeper = fixture.enrol_device_key(KEEPER_KEY_SEED);
    let keeper_key = key_of(&keeper);
    let new_key = SigningKey::from_bytes(&[NEW_KEY_SEED; 32]);
    let new = key_of(&new_key);

    let (hold, lands_at) = held(
        fixture
            .recover_wait(
                WAIT,
                fixture.released_material(0),
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

    fixture.at(lands_at + WAIT.as_secs());
    // A later ItIsMe is refused: Cancel wins in either order.
    let before_roster = fixture.vault.authority_fold().expect("the fold").roster;
    let before_history = fixture.history().len();
    let refused = fixture
        .vault
        .answer_recovery_hold_as(&fixture.authority(), hold, RecoveryHoldAnswerKind::ItIsMe)
        .expect_err("no answer revives a cancelled hold");
    assert_refused(&refused, HOLD_NOT_LIVE);
    let unknown = [9u8; 32];
    let refused = fixture
        .vault
        .answer_recovery_hold_as(
            &fixture.authority(),
            unknown,
            RecoveryHoldAnswerKind::ItIsMe,
        )
        .expect_err("an unknown hold is not live");
    assert_refused(&refused, HOLD_NOT_LIVE);
    assert_eq!(
        fixture.vault.authority_fold().expect("the fold").roster,
        before_roster,
        "the roster is unchanged"
    );
    assert_eq!(
        fixture.history().len(),
        before_history,
        "the refusals write nothing"
    );

    // And the wait's end lands nothing.
    let landings = fixture.land();
    assert_eq!(landings.len(), 1);
    assert_eq!(landings[0].state, RecoveryHoldState::Cancelled);
    assert!(fixture.land().is_empty(), "the hold never lands");
    assert!(!fixture.live(&new));
    let view = fixture.hold_view(&hold);
    assert_eq!(view.state, RecoveryHoldState::Cancelled);
    assert_eq!(view.answered_by, vec![keeper_key]);
}

#[test]
fn an_admin_or_host_key_never_answers_a_hold() {
    let fixture = fixture();
    let lost = fixture.enrol_device_key(LOST_KEY_SEED);
    let lost_key = key_of(&lost);
    let keeper = fixture.enrol_device_key(KEEPER_KEY_SEED);
    let keeper_key = key_of(&keeper);
    let new_key = SigningKey::from_bytes(&[NEW_KEY_SEED; 32]);

    let (hold, _) = held(
        fixture
            .recover_wait(
                WAIT,
                fixture.released_material(0),
                RootSuccessor::Device(fixture.enrollment(&new_key)),
                std::slice::from_ref(&lost_key),
            )
            .expect("the box recovery holds"),
    );
    // An admin-only device, enrolled by a crafted row a held owner key
    // signs: the generic consent rule admits it.
    let admin = SigningKey::from_bytes(&[ADMIN_KEY_SEED; 32]);
    let admin_key = key_of(&admin);
    let mut enroll = AuthorityLogEntry {
        schema_version: AUTHORITY_LOG_SCHEMA_VERSION,
        vault_id: Some(fixture.vault_id),
        seq: fixture.next_seq(&keeper_key),
        parent_hashes: fixture.heads(),
        op: AuthorityOp::EnrollDevice {
            device: admin_device(ADMIN_KEY_SEED),
        },
        signer: AuthoritySignature {
            suite: keeper_key.suite(),
            public_key: keeper_key.clone(),
            signature: vec![0; 64],
        },
        cosigns: Vec::new(),
        ts: T0,
    };
    let transcript = authority_transcript(&enroll).expect("the transcript");
    enroll.signer.signature = keeper.sign(&transcript).to_bytes().to_vec();
    fixture
        .vault
        .import_signed_authority_history(&[
            encode_authority_log_entry_body(&enroll).expect("the bytes")
        ])
        .expect("the import stores the enrolment");
    assert!(fixture.live(&admin_key), "the admin key is enrolled");

    // The admin key's ItIsMe: stored, but not counted, and the hold still
    // waits.
    let before_history = fixture.history().len();
    let mut row = AuthorityLogEntry {
        schema_version: AUTHORITY_LOG_SCHEMA_VERSION,
        vault_id: Some(fixture.vault_id),
        seq: fixture.next_seq(&admin_key),
        parent_hashes: fixture.heads(),
        op: AuthorityOp::RecoveryHoldAnswer(RecoveryHoldAnswer {
            hold,
            answer: RecoveryHoldAnswerKind::ItIsMe,
        }),
        signer: AuthoritySignature {
            suite: admin_key.suite(),
            public_key: admin_key.clone(),
            signature: vec![0; 64],
        },
        cosigns: Vec::new(),
        ts: T0,
    };
    let transcript = authority_transcript(&row).expect("the transcript");
    row.signer.signature = admin.sign(&transcript).to_bytes().to_vec();
    let hash = authority_entry_hash(&row).expect("a hash");
    let bytes = encode_authority_log_entry_body(&row).expect("the bytes");
    fixture
        .vault
        .import_signed_authority_history(&[bytes])
        .expect("the import stores the row");
    assert!(
        !fixture
            .vault
            .authority_fold()
            .expect("the fold")
            .valid_entries
            .contains(&hash),
        "the fold refuses the admin-signed answer"
    );
    assert_eq!(
        fixture.history().len(),
        before_history + 1,
        "the refused row is stored, and nothing else is written"
    );
    let view = fixture.hold_view(&hold);
    assert_eq!(view.state, RecoveryHoldState::Waiting);
    assert!(view.answered_by.is_empty());
}

#[test]
fn a_landing_binds_a_co_owner_whose_lost_key_held_their_binding() {
    let fixture = co_owner_wait_fixture();
    assert!(
        passes_owner_verbs(&fixture.vault, fixture.person),
        "the co-Owner's first owner key binds them"
    );
    let root_key = fixture.enrol_root_key();
    let new_key = SigningKey::from_bytes(&[NEW_KEY_SEED; 32]);
    let lost = key_of(&fixture.lost_key);

    let (hold, lands_at) = held(
        fixture
            .recover_wait(
                WAIT,
                fixture.released(),
                RootSuccessor::Device(fixture.enrollment(&new_key)),
                std::slice::from_ref(&lost),
            )
            .expect("the box recovery holds"),
    );
    assert_eq!(fixture.hold_view(&hold).state, RecoveryHoldState::Waiting);
    fixture.at(lands_at + 60);
    let landings = fixture.land();
    assert_eq!(landings.len(), 1, "the due hold lands");
    assert_eq!(landings[0].hold, hold);
    assert_eq!(landings[0].state, RecoveryHoldState::Landed);
    assert_eq!(fixture.hold_view(&hold).state, RecoveryHoldState::Landed);
    let enrollment = landings[0].enrollment.expect("the enrolment");
    assert_eq!(
        AuthorityKey::Ed25519(enrollment.public_key),
        key_of(&new_key)
    );
    assert!(!fixture.live(&lost), "the lost key is revoked");
    assert!(fixture.live(&root_key), "the root's key stays live");
    let bound = fixture
        .vault
        .authority_fold()
        .expect("the fold")
        .actor_bindings
        .get(&key_of(&new_key))
        .filter(|binding| {
            binding.status == ActorBindingStatus::Active && binding.actor_class == "human"
        })
        .map(|binding| binding.actor_ref);
    assert_eq!(
        bound,
        Some(fixture.person),
        "the new key binds the co-Owner"
    );
    assert!(
        passes_owner_verbs(&fixture.vault, fixture.person),
        "the co-Owner keeps owner control"
    );
}

#[test]
fn the_waits_rows_are_marked_for_the_live_mirror() {
    let fixture = fixture();
    let lost = fixture.enrol_device_key(LOST_KEY_SEED);
    let lost_key = key_of(&lost);
    let keeper = fixture.enrol_device_key(KEEPER_KEY_SEED);
    let new_key = SigningKey::from_bytes(&[NEW_KEY_SEED; 32]);

    let (hold, _) = held(
        fixture
            .recover_wait(
                WAIT,
                fixture.released_material(0),
                RootSuccessor::Device(fixture.enrollment(&new_key)),
                std::slice::from_ref(&lost_key),
            )
            .expect("the box recovery holds"),
    );
    assert_marked(&markers(&fixture.vault), std::slice::from_ref(&hold));

    release_owner_keys(&fixture.vault);
    fixture.hold_signer(&keeper);
    fixture
        .vault
        .answer_recovery_hold_as(&fixture.authority(), hold, RecoveryHoldAnswerKind::Cancel)
        .expect("the keeper device cancels");
    let answer = fixture
        .history()
        .into_iter()
        .find(
            |row| matches!(&row.op, AuthorityOp::RecoveryHoldAnswer(answer) if answer.hold == hold),
        )
        .expect("the answer row");
    let answer_hash = authority_entry_hash(&answer).expect("a hash");
    assert_marked(&markers(&fixture.vault), std::slice::from_ref(&answer_hash));

    // A second hold for a fresh successor lands, and its rows are marked.
    let new3_key = SigningKey::from_bytes(&[NEW3_KEY_SEED; 32]);
    let (second, second_lands_at) = held(
        fixture
            .recover_wait(
                WAIT,
                fixture.released_material(0),
                RootSuccessor::Device(fixture.enrollment(&new3_key)),
                &[],
            )
            .expect("the second attempt holds"),
    );
    fixture.at(second_lands_at + 60);
    let landings = fixture.land();
    assert_eq!(landings.len(), 2, "the cancel cleans and the second lands");
    let landed = landings
        .iter()
        .find(|landing| landing.hold == second)
        .expect("the second hold's landing");
    assert_eq!(landed.state, RecoveryHoldState::Landed);
    let mut entries: Vec<AuthorityEntryHash> = landed.revoked.clone();
    entries.push(landed.enrollment.expect("the enrolment").entry);
    assert_marked(&markers(&fixture.vault), &entries);
}

#[test]
fn a_box_call_after_the_wait_lands_and_answers_vouched() {
    let fixture = fixture();
    let root_key = AuthorityKey::Ed25519(fixture.generation_key(0));
    let (hold, lands_at) = held(
        fixture
            .recover_wait(
                WAIT,
                fixture.released_material(0),
                RootSuccessor::ThisInstall,
                &[],
            )
            .expect("the box recovery holds"),
    );
    let successor = fixture.hold_view(&hold).successor_key;

    fixture.at(lands_at + 60);
    let answer = fixture
        .recover_wait(
            WAIT,
            fixture.released_material(0),
            RootSuccessor::ThisInstall,
            &[],
        )
        .expect("the same box call lands and answers Vouched");
    let RootRecovery::Vouched {
        enrollment,
        revoked,
    } = answer
    else {
        panic!("the call completes the attempt it held");
    };
    assert_eq!(
        AuthorityKey::Ed25519(enrollment.public_key),
        successor,
        "the landing enrolled this call's successor"
    );
    assert!(revoked.is_empty(), "no lost key, no revocation");
    let enrolment = fixture.row(&enrollment.entry);
    assert!(matches!(enrolment.op, AuthorityOp::OwnerKeyEnroll(_)));
    assert_eq!(enrolment.signer_key(), &root_key);
    assert_eq!(fixture.hold_view(&hold).state, RecoveryHoldState::Landed);
}

#[test]
fn a_kit_recovery_cancels_a_due_hold_on_the_door_install() {
    let fixture = fixture();
    let lost = fixture.enrol_device_key(LOST_KEY_SEED);
    let lost_key = key_of(&lost);
    let new_key = SigningKey::from_bytes(&[NEW_KEY_SEED; 32]);
    let successor = key_of(&new_key);
    let new2_key = SigningKey::from_bytes(&[NEW2_KEY_SEED; 32]);
    let other = key_of(&new2_key);

    let (hold, lands_at) = held(
        fixture
            .recover_wait(
                WAIT,
                fixture.released_material(0),
                RootSuccessor::Device(fixture.enrollment(&new_key)),
                std::slice::from_ref(&lost_key),
            )
            .expect("the box recovery holds"),
    );
    // Due, on this install's clock, and not landed: no landing call.
    fixture.at(lands_at + 60);
    assert_eq!(fixture.hold_view(&hold).state, RecoveryHoldState::Due);

    let answer = fixture
        .vault
        .recover_owner_root(
            &fixture.owner(),
            ActSurface::ThisInstall,
            fixture.kit_material(),
            RootSuccessor::Device(fixture.enrollment(&new2_key)),
            std::slice::from_ref(&lost_key),
        )
        .expect("the kit recovers");
    assert!(
        matches!(answer, RootRecovery::Vouched { .. }),
        "the kit vouches over the hold"
    );
    assert_eq!(
        fixture.hold_view(&hold).state,
        RecoveryHoldState::Cancelled,
        "the kit's write cancelled the due hold"
    );
    assert!(!fixture.live(&successor), "the hold never landed");
    assert!(fixture.live(&other), "the kit enrolled its own successor");
}

#[test]
fn a_foreign_anchors_cancel_never_stops_a_hold() {
    let fixture = fixture();
    let lost = fixture.enrol_device_key(LOST_KEY_SEED);
    let lost_key = key_of(&lost);
    let new_key = SigningKey::from_bytes(&[NEW_KEY_SEED; 32]);

    let (hold, _) = held(
        fixture
            .recover_wait(
                WAIT,
                fixture.released_material(0),
                RootSuccessor::Device(fixture.enrollment(&new_key)),
                std::slice::from_ref(&lost_key),
            )
            .expect("the box recovery holds"),
    );
    // A fresh root seed that is NOT the vault's kit, and its self-signed
    // root record for this vault, imported as a crafted row.
    let foreign = RecoveryRootSeed::generate().expect("a foreign root seed");
    let root = foreign.public(&fixture.vault_id).expect("the foreign root");
    let anchor = foreign.anchor();
    let anchor_key = AuthorityKey::Ed25519(anchor.verifying_key().to_bytes());
    let record = OwnerRootRecord {
        owner: fixture.person,
        root: root.id,
        recovery_key: MachineEncryptionKey {
            suite: MACHINE_ENCRYPTION_SUITE_HYBRID_V1,
            key: root.recovery_key.to_bytes(),
        },
        anchor_key: root.anchor_key,
    };
    // The anchor's chain starts at sequence 0, as `anchor_signed_entry`
    // builds it.
    let mut published = AuthorityLogEntry {
        schema_version: AUTHORITY_LOG_SCHEMA_VERSION,
        vault_id: Some(fixture.vault_id),
        seq: 0,
        parent_hashes: fixture.heads(),
        op: AuthorityOp::OwnerRoot(record),
        signer: AuthoritySignature {
            suite: anchor_key.suite(),
            public_key: anchor_key.clone(),
            signature: vec![0; 64],
        },
        cosigns: Vec::new(),
        ts: T0,
    };
    let transcript = authority_transcript(&published).expect("the transcript");
    published.signer.signature = anchor.sign(&transcript).to_bytes().to_vec();
    let before_history = fixture.history().len();
    fixture
        .vault
        .import_signed_authority_history(&[
            encode_authority_log_entry_body(&published).expect("the bytes")
        ])
        .expect("the foreign root stores");

    // That anchor's Cancel naming the hold, with no cosign: the attack
    // shape. The import leaves it out: no key vouches for it.
    let mut row = AuthorityLogEntry {
        schema_version: AUTHORITY_LOG_SCHEMA_VERSION,
        vault_id: Some(fixture.vault_id),
        seq: 1,
        parent_hashes: fixture.heads(),
        op: AuthorityOp::RecoveryHoldAnswer(RecoveryHoldAnswer {
            hold,
            answer: RecoveryHoldAnswerKind::Cancel,
        }),
        signer: AuthoritySignature {
            suite: anchor_key.suite(),
            public_key: anchor_key.clone(),
            signature: vec![0; 64],
        },
        cosigns: Vec::new(),
        ts: T0,
    };
    let transcript = authority_transcript(&row).expect("the transcript");
    row.signer.signature = anchor.sign(&transcript).to_bytes().to_vec();
    fixture
        .vault
        .import_signed_authority_history(&[
            encode_authority_log_entry_body(&row).expect("the bytes")
        ])
        .expect("the import answers");
    assert_eq!(
        fixture.history().len(),
        before_history + 1,
        "the root stores, and the foreign Cancel is left out"
    );
    let view = fixture.hold_view(&hold);
    assert_eq!(view.state, RecoveryHoldState::Waiting);
    assert!(view.answered_by.is_empty());

    // The same anchor's Cancel beside one cosign by a key that is not the
    // vault's recovery root key R: the structure vouches the shape (an
    // anchor and one cosign), and the fold refuses it, since the cosign is
    // no live recovery root key. Stored or left out, it never counts.
    let stranger = SigningKey::from_bytes(&[STRANGER_KEY_SEED; 32]);
    let stranger_key = key_of(&stranger);
    let mut cosigned = AuthorityLogEntry {
        schema_version: AUTHORITY_LOG_SCHEMA_VERSION,
        vault_id: Some(fixture.vault_id),
        seq: 1,
        parent_hashes: fixture.heads(),
        op: AuthorityOp::RecoveryHoldAnswer(RecoveryHoldAnswer {
            hold,
            answer: RecoveryHoldAnswerKind::Cancel,
        }),
        signer: AuthoritySignature {
            suite: anchor_key.suite(),
            public_key: anchor_key.clone(),
            signature: vec![0; 64],
        },
        cosigns: vec![AuthoritySignature {
            suite: stranger_key.suite(),
            public_key: stranger_key.clone(),
            signature: vec![0; 64],
        }],
        ts: T0,
    };
    let transcript = authority_transcript(&cosigned).expect("the transcript");
    cosigned.cosigns[0].signature = stranger.sign(&transcript).to_bytes().to_vec();
    cosigned.signer.signature = anchor.sign(&transcript).to_bytes().to_vec();
    let cosigned_hash = authority_entry_hash(&cosigned).expect("a hash");
    let _ = fixture
        .vault
        .import_signed_authority_history(&[
            encode_authority_log_entry_body(&cosigned).expect("the bytes")
        ]);
    assert!(
        !fixture
            .vault
            .authority_fold()
            .expect("the fold")
            .valid_entries
            .contains(&cosigned_hash),
        "the fold refuses a Cancel beside a key that is not R"
    );
    let view = fixture.hold_view(&hold);
    assert_eq!(view.state, RecoveryHoldState::Waiting);
    assert!(view.answered_by.is_empty());
}

#[test]
#[ignore = "needs an adopted checkpoint image carrying the hold: adopt_authority_checkpoint needs an owner-pairing pin, certified root key bindings and attestations, which no integration-test path builds (no adopting test in tests/)"]
fn a_kit_cancel_reaches_a_hold_only_an_adopted_checkpoint_carries() {
    // Vault A holds a live attempt.
    let fixture = fixture();
    let lost = fixture.enrol_device_key(LOST_KEY_SEED);
    let lost_key = key_of(&lost);
    let new_key = SigningKey::from_bytes(&[NEW_KEY_SEED; 32]);
    let (hold, _) = held(
        fixture
            .recover_wait(
                WAIT,
                fixture.released_material(0),
                RootSuccessor::Device(fixture.enrollment(&new_key)),
                std::slice::from_ref(&lost_key),
            )
            .expect("the box recovery holds"),
    );
    assert_eq!(fixture.hold_view(&hold).state, RecoveryHoldState::Waiting);
    // Not reachable from here: write A's checkpoint image, adopt it on a
    // replica that stores no raw hold row, and run the kit cancel-all
    // there. `Vault::adopt_authority_checkpoint` verifies the image
    // against an owner-pairing pin and per-root certified key bindings
    // plus attestations (`attest_authority_checkpoint`); building those
    // needs the pairing-link and checkpoint-key stack, which no
    // integration test reaches. The full test would then assert the
    // replica's kit cancel-all writes a Cancel for the carried hold.
}

#[test]
fn a_retry_after_a_cancelled_hold_keeps_its_seed_and_lands() {
    let fixture = fixture();
    let keeper = fixture.enrol_device_key(KEEPER_KEY_SEED);

    let (first, _) = held(
        fixture
            .recover_wait(
                WAIT,
                fixture.released_material(0),
                RootSuccessor::ThisInstall,
                &[],
            )
            .expect("the box recovery holds"),
    );
    let successor = fixture.hold_view(&first).successor_key;
    release_owner_keys(&fixture.vault);
    fixture.hold_signer(&keeper);
    fixture
        .vault
        .answer_recovery_hold_as(&fixture.authority(), first, RecoveryHoldAnswerKind::Cancel)
        .expect("another owner device cancels the hold");
    assert_eq!(
        fixture.hold_view(&first).state,
        RecoveryHoldState::Cancelled
    );

    // The same box call again: a retry for the same successor. The slot
    // key is still unenrolled (the cancel landed nothing), so no fresh
    // key is minted.
    let (retry, retry_lands_at) = held(
        fixture
            .recover_wait(
                WAIT,
                fixture.released_material(0),
                RootSuccessor::ThisInstall,
                &[],
            )
            .expect("the retry holds"),
    );
    assert_ne!(retry, first, "the retry is a new attempt");
    assert_eq!(
        fixture.hold_view(&retry).successor_key,
        successor,
        "the retry names the same successor"
    );
    fixture.at(retry_lands_at + 60);
    let landings = fixture.land();
    let landed = landings
        .iter()
        .find(|landing| landing.hold == retry)
        .expect("the retry lands");
    assert_eq!(landed.state, RecoveryHoldState::Landed);
    assert!(
        landed.enrollment.is_some(),
        "the retry's landing enrolled its successor"
    );
    assert!(fixture.live(&successor), "the successor is enrolled");
    assert_eq!(fixture.hold_view(&retry).state, RecoveryHoldState::Landed);
    assert_eq!(
        fixture.hold_view(&first).state,
        RecoveryHoldState::Cancelled,
        "the first hold stays cancelled"
    );
}
