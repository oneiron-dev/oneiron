//! OPUS-WAYBACK recovery wait: a box recovery holds before owner-grade acts
//! land (Engine RULING WAYBACK-RECOVERY-HOLD-WIRE = A).
//!
//! After a box recovery (sign-in + recovery PIN, `RootMaterial::Released`)
//! the recovered root's authority key R does not vouch at once: the root's
//! door writes one `RecoveryHold` (the successor's enrolment input, the lost
//! keys, `lands_at`), keeps R's seed in this install's keystore slot, and
//! answers `RootRecovery::Held`. Another owner device ends the wait early
//! (`ItIsMe`) or stops the attempt (`Cancel`) with a `RecoveryHoldAnswer`
//! signed by its own live owner key, and the kit stops it with a `Cancel`
//! its live root key R signs alone (lead ANCHORS-3 = A: the kit acts
//! through R like any owner key). At the wait's end the seed holder lands the
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
//! The 22 tests: the 13 build-leg tests (`a_released_recovery_waits_then_lands`,
//! `zero_wait_lands_at_once`, `a_sheet_cancel_stops_the_attempt_and_a_retry_lands`,
//! `a_cancel_without_an_owner_key_is_refused`,
//! `a_device_the_recovery_removes_still_cancels`,
//! `the_kit_recovery_cancels_a_live_hold`, `an_owner_key_approval_ends_the_wait_early`,
//! `a_cancel_leaves_the_recovering_device_without_owner_key_or_seed`,
//! `a_hold_voids_when_its_root_key_is_revoked`,
//! `every_owner_device_reads_the_hold_after_an_export_import`,
//! `the_root_key_cannot_answer_its_own_hold`,
//! `a_landing_follows_the_door_installs_clock`, `a_cancelled_hold_never_lands`),
//! the five review-fix pins (`an_agent_key_never_answers_a_hold`,
//! `a_landing_binds_a_co_owner_whose_lost_key_held_their_binding`,
//! `the_waits_rows_are_marked_for_the_live_mirror`,
//! `a_box_call_after_the_wait_lands_and_answers_vouched`,
//! `a_kit_recovery_cancels_a_due_hold_on_the_door_install`), and two of the
//! three Sol-fix pins (`a_foreign_anchors_cancel_never_stops_a_hold`,
//! `a_retry_after_a_cancelled_hold_keeps_its_seed_and_lands`; the third,
//! `a_kit_cancel_reaches_a_hold_only_an_adopted_checkpoint_carries`, is in
//! `recovery_hold_adopted_image.rs`, whose replica adopts an image),
//! and the two ANCHORS-E6 pins (Fable pass 29: an anchor is no voice in a
//! shared judge): `a_fresh_roots_anchor_beside_the_root_key_never_stops_a_hold`
//! and `the_kits_cancel_is_the_root_keys_own_row`.
//!
//! One wait on a hosted vault (WAYBACK-BOX-WAIT-ENGINE-HOLD-ONE-WAIT = A):
//! the box's wait is the recovery wait, so after it the door's hold lands at
//! the box's release second (`RootMaterial::ReleasedAfterBoxWait`):
//! `a_hosted_recovery_waits_once_at_the_box_and_lands_at_its_release`,
//! `a_box_release_never_waits_past_its_release_or_this_installs_wait` and
//! `a_wait_report_the_box_refuses_answers_its_error`. Without a box (self-host,
//! `RootMaterial::Released`) the engine's own wait is unchanged:
//! `a_released_recovery_waits_then_lands`. The three fail at the mutation
//! that drops the box's release second and the report (the red branch
//! `opus-wayback/recovery-box-one-wait-on-main-red`).
//!
//! The enrolment preflight pin (row RECOVERY-HOLD-ENROLMENT-PREFLIGHT):
//! `a_hold_whose_enrolment_never_lands_is_refused_before_its_wait`. It fails
//! on main `54f7ce11c55b`, where the door held a successor whose holding
//! machine the vault never held, and that hold never landed.
//!
//! The seed-slot pins (row RECOVERY-HOLD-SEED-SLOT-PER-ATTEMPT):
//! `a_retry_puts_back_its_holds_seed_and_the_hold_lands_at_its_second` and
//! `a_device_successor_on_this_machine_never_answers_this_installs_box_call`.
//! Both fail on main `42d134bab7a5`.
//!
//! The judged-before-writes pins (row
//! RECOVERY-HOLD-BOX-PATH-WRITES-BEFORE-CHECKS):
//! `a_refused_box_call_lands_no_due_hold`,
//! `a_refused_hold_attempt_leaves_this_installs_slot_as_it_was` and
//! `another_owners_hold_for_the_successor_key_is_never_the_owners`. All
//! three fail on main `2c56ee802949`. Beside them,
//! `a_vouch_for_this_install_with_a_revoked_key_enrols_the_slots_fresh_key`
//! covers the vouch arm's fresh key, made in memory and taken by the slot
//! just before the commit (it passes on main too). The review's round 2
//! pins: `a_hold_the_log_refuses_leaves_this_installs_slot_as_it_was` and
//! `a_removed_owners_hold_never_holds_the_successor_key_against_another_owner`,
//! both failing on `a7a9486fe5f7`.
//!
//! The lost-key pins (row RECOVERY-HOLD-LOST-KEY-RULE-AT-FOLD), each over a
//! hold R signs by hand, since the door never writes one:
//! `a_hold_that_names_its_root_key_lost_lands_with_the_root_key_live` and
//! `a_hold_never_revokes_a_lost_key_that_is_no_owner_key_of_its_owner`.
//! Both fail on main `8418b839a4ad`, where the landing revoked every live
//! key a hold named.
//!
//! Red on the kit-only rotation head `5adc0295753f`: the file does not
//! compile there (no `RecoveryHold` ops, no hold view, no answer doors, no
//! landing, no `RootRecovery::Held`, no `recover_owner_root_waiting`).
//! The five review-fix pins fail at `699bba4fa53` (the review fixes'
//! parent); the Sol-fix pins fail at `86b9c4cd3b07`; the ANCHORS-E6 pins
//! fail at `14e0d18770df`, where the kit's Cancel was the anchor's beside
//! R's cosign and any valid root's anchor passed.
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test owner_root_recovery_wait`.
#![cfg(oneiron_test_support)]

use std::cell::RefCell;
use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Duration;

use ed25519_dalek::{Signer, SigningKey};
use oneiron::authority::{
    AUTHORITY_LOG_SCHEMA_VERSION, AUTHORITY_TRANSCRIPT_DOMAIN, ActAuthority, ActSurface,
    ActorBindingStatus, AuthorityAttestation, AuthorityEntryHash, AuthorityFold, AuthorityKey,
    AuthorityLogEntry, AuthorityOp, AuthoritySignature, AuthorityTier, CheckpointRootSigner,
    DeviceAuthority, HostSlipIssuer, MACHINE_ENCRYPTION_SUITE_HYBRID_V1, MachineEncryptionKey,
    MachineRole, OwnerKeyEnrollment, OwnerRootRecord, RECOVERY_WAIT_DEFAULT, ROLE_AGENT,
    RecoveryBoxCancelProof, RecoveryHold, RecoveryHoldAnswer, RecoveryHoldAnswerKind,
    RecoveryHoldEnrolment, RecoveryHoldLanding, RecoveryHoldState, RecoveryHoldView, RootMaterial,
    RootRecovery, RootSuccessor, authority_entry_hash, authority_log_entity_id_from_hash,
    authority_transcript, decode_authority_log_entry_body, encode_authority_log_entry_body,
};
use oneiron::consent::AuthenticatedOwner;
use oneiron::error::{OwnerPresenceRefusal, RecordError};
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
use oneiron::test_doors::root_recovery::{
    recover_owner_root_waiting, released_authority_seed, stage_orphan_recovery_hold_seed,
};
use oneiron::test_support::bind_host_owner;
use oneiron::world_keys::{
    NoRecoveryBox, RecoveryAuthoritySigner, RecoveryBoxCanceller, RecoveryBoxHold,
    RecoveryBoxRelease, RecoveryPreset, RecoveryRootSeed,
};
use oneiron::{
    EdgeActorClass, EntityId, ErrorKind, HostingPrivacyPosture, TimeRange, Vault, VaultConfig,
};
use oneiron_keystore::{
    DeviceKeystore, KeystoreSlot, ManualPresenceClock, MemoryKeystore, PresenceError, PresenceGate,
    PresenceWindow, ScriptedPresence, SlotKind,
};
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
/// The seed of an agent-only device key, which never answers a hold.
const AGENT_KEY_SEED: u8 = 23;
/// The seed of a key that is not the vault's recovery root key, which a
/// foreign anchor's Cancel names as its cosign.
const STRANGER_KEY_SEED: u8 = 61;
/// The co-Owner fixture's shared vault id.
const SHARED: u64 = 44;
/// The seed of the co-Owner's first owner key, which binds them and is lost.
const CO_OWNER_LOST_SEED: u8 = 51;
/// The first owner's own device key on the shared vault.
const FIRST_OWNER_KEY_SEED: u8 = 52;
/// The seeds of successor keys.
const NEW_KEY_SEED: u8 = 41;
const NEW2_KEY_SEED: u8 = 42;
const NEW3_KEY_SEED: u8 = 43;

/// The answer doors' refusal words, asserted with `contains`.
const HOLD_NOT_LIVE: &str = "the recovery hold is not live";
const ANSWER_KEY_IS_SUCCESSOR: &str = "the hold's successor key never answers its own hold";
const ANSWER_KEY_IS_ROOT: &str = "the root's authority key never answers a recovery hold";
const NO_OWNER_KEY: &str = "this install holds no live owner key to answer the recovery hold";
const ANSWER_NOT_HOLD_OWNER: &str = "only the owner whose recovery this is says it is them";

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

/// Imports `row` when the wire encodes it; a row the wire refuses (an
/// answer with a cosign) is never stored. Either way the caller asserts
/// that the fold does not count it.
fn import_if_encodable(vault: &Vault, row: &AuthorityLogEntry) {
    if let Ok(bytes) = encode_authority_log_entry_body(row) {
        let _ = vault.import_signed_authority_history(&[bytes]);
    }
}

/// Another owner device's key, held on this handle: what the answer doors
/// sign with. A test double for a device install of its own.
struct KeySigner(SigningKey);

impl CheckpointRootSigner for KeySigner {
    fn root(&self) -> AuthorityKey {
        key_of(&self.0)
    }

    fn sign_checkpoint_statement(
        &self,
        _vault: &Vault,
        statement: &[u8],
    ) -> oneiron::Result<Vec<u8>> {
        Ok(self.0.sign(statement).to_bytes().to_vec())
    }

    fn sign_owner_proof(
        &self,
        _vault: &Vault,
        _fold: &AuthorityFold,
        _ground: &oneiron::authority::OwnerProofGround,
        transcript: &[u8],
    ) -> oneiron::Result<Vec<u8>> {
        assert!(transcript.starts_with(AUTHORITY_TRANSCRIPT_DOMAIN));
        Ok(self.0.sign(transcript).to_bytes().to_vec())
    }

    fn sign_ask_word_proof(
        &self,
        _vault: &Vault,
        _fold: &AuthorityFold,
        _ground: &oneiron::authority::OwnerProofGround,
        transcript: &[u8],
    ) -> oneiron::Result<Vec<u8>> {
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

    /// The public key of the seed this install's keystore keeps for
    /// `successor`'s hold, if any.
    fn slot_seed_key(&self, successor: &[u8; 32]) -> Option<[u8; 32]> {
        let slot = KeystoreSlot {
            vault_id: self.vault_id,
            install: *self.machine.as_bytes(),
            kind: SlotKind::RecoveryHold(*successor),
        };
        self.keystore
            .get(&slot)
            .expect("the keystore reads")
            .map(|seed| SigningKey::from_bytes(&seed).verifying_key().to_bytes())
    }

    /// Puts `seed` in `successor`'s hold slot in place of what it keeps.
    fn replace_slot_seed(&self, successor: &[u8; 32], seed: &[u8; 32]) {
        let slot = KeystoreSlot {
            vault_id: self.vault_id,
            install: *self.machine.as_bytes(),
            kind: SlotKind::RecoveryHold(*successor),
        };
        self.keystore.delete(&slot).expect("the slot empties");
        self.keystore
            .create(&slot, seed)
            .expect("the slot takes the seed");
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
    /// The first owner: the embedded owner the host root binds.
    first_owner: EntityId,
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
        first_owner: owner,
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

    /// The first owner's act authority on this install.
    fn first_owner_authority(&self) -> ActAuthority {
        ActAuthority::Owner(
            proof(&self.vault, self.first_owner),
            ActSurface::ThisInstall,
        )
    }

    /// The first owner enrols a device key of their own under the host
    /// root, and this handle holds it alone, as the first owner's device
    /// install holds its own key.
    fn hold_first_owners_key(&self, seed: u8) -> SigningKey {
        let key = SigningKey::from_bytes(&[seed; 32]);
        let public_key = key.verifying_key().to_bytes();
        let authority = self.first_owner_authority();
        let challenge = self
            .vault
            .owner_key_enrollment_challenge_as(&authority, self.machine, &public_key)
            .expect("the first owner's challenge");
        let input = OwnerKeyEnrollment {
            machine: self.machine,
            public_key,
            proof: key.sign(&challenge).to_bytes().to_vec(),
        };
        self.vault
            .enrol_owner_signing_key_as_host(&authority, input, &self.issuer)
            .expect("the first owner enrols a device key");
        release_owner_keys(&self.vault);
        self.vault
            .hold_checkpoint_root_signer(Arc::new(KeySigner(key.clone())));
        key
    }

    fn history(&self) -> Vec<AuthorityLogEntry> {
        self.vault
            .export_signed_authority_history()
            .expect("the signed history")
            .iter()
            .map(|row| decode_authority_log_entry_body(row).expect("a row"))
            .collect()
    }

    /// `key`'s answer row to `hold`, signed by `key` on the stored heads.
    fn signed_answer(
        &self,
        key: &SigningKey,
        hold: AuthorityEntryHash,
        answer: RecoveryHoldAnswerKind,
    ) -> AuthorityLogEntry {
        let public = key_of(key);
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
        let seq = rows
            .iter()
            .filter(|row| row.signer_key() == &public)
            .map(|row| row.seq + 1)
            .max()
            .unwrap_or(1);
        let mut row = AuthorityLogEntry {
            schema_version: AUTHORITY_LOG_SCHEMA_VERSION,
            vault_id: Some(self.vault_id),
            seq,
            parent_hashes: heads,
            op: AuthorityOp::RecoveryHoldAnswer(RecoveryHoldAnswer { hold, answer }),
            signer: AuthoritySignature {
                suite: public.suite(),
                public_key: public,
                signature: vec![0; 64],
            },
            cosigns: Vec::new(),
            ts: T0,
            overlay_seed: None,
        };
        let transcript = authority_transcript(&row).expect("the transcript");
        row.signer.signature = key.sign(&transcript).to_bytes().to_vec();
        row
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

/// An agent-only device of `seed`'s key (as `tests/owner_root_recovery.rs`'
/// `owner_device`, but with the agent role alone): the one device
/// enrolment a vault's fold still counts after the host-rooted redesign (an
/// owner or admin `EnrollDevice` is a retired device op there), so it is
/// the live roster key with no owner role that a vault can hold. It never
/// answers a recovery hold.
fn agent_device(seed: u8) -> DeviceAuthority {
    DeviceAuthority {
        key: key_of(&SigningKey::from_bytes(&[seed; 32])),
        transport_key_binding: [7; 32],
        attestation: AuthorityAttestation {
            kind: "SoftwareArgon2id".to_owned(),
            evidence: vec![1, 2, 3],
        },
        tier: AuthorityTier::Software,
        roles: ROLE_AGENT,
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
    assert_eq!(
        fixture.hold_view(&hold).cancelled_by,
        vec![fixture.person],
        "the hold names the owner whose device cancelled"
    );
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
        overlay_seed: None,
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

/// A live roster key with no owner role never answers a hold: the judge
/// counts an answer only from a live owner key (`answers_recovery_holds`).
/// An admin-only key never reaches a vault's roster on this line (its
/// `EnrollDevice` is retired), so the key here is an agent's.
#[test]
fn an_agent_key_never_answers_a_hold() {
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
    // An agent-only device, enrolled by a crafted row an owner key signs:
    // the fold admits an agent's enrolment.
    let agent = SigningKey::from_bytes(&[AGENT_KEY_SEED; 32]);
    let agent_key = key_of(&agent);
    let mut enroll = AuthorityLogEntry {
        schema_version: AUTHORITY_LOG_SCHEMA_VERSION,
        vault_id: Some(fixture.vault_id),
        seq: fixture.next_seq(&keeper_key),
        parent_hashes: fixture.heads(),
        op: AuthorityOp::EnrollDevice {
            device: agent_device(AGENT_KEY_SEED),
        },
        signer: AuthoritySignature {
            suite: keeper_key.suite(),
            public_key: keeper_key.clone(),
            signature: vec![0; 64],
        },
        cosigns: Vec::new(),
        ts: T0,
        overlay_seed: None,
    };
    enroll.overlay_seed = oneiron_authority::authority::authority_overlay_seed_for(&enroll.op)
        .expect("authority overlay seed");
    let transcript = authority_transcript(&enroll).expect("the transcript");
    enroll.signer.signature = keeper.sign(&transcript).to_bytes().to_vec();
    fixture
        .vault
        .import_signed_authority_history(&[
            encode_authority_log_entry_body(&enroll).expect("the bytes")
        ])
        .expect("the import stores the enrolment");
    assert!(fixture.live(&agent_key), "the agent key is enrolled");

    // The agent key's ItIsMe is never counted, and the hold still waits.
    let before_history = fixture.history().len();
    let mut row = AuthorityLogEntry {
        schema_version: AUTHORITY_LOG_SCHEMA_VERSION,
        vault_id: Some(fixture.vault_id),
        seq: fixture.next_seq(&agent_key),
        parent_hashes: fixture.heads(),
        op: AuthorityOp::RecoveryHoldAnswer(RecoveryHoldAnswer {
            hold,
            answer: RecoveryHoldAnswerKind::ItIsMe,
        }),
        signer: AuthoritySignature {
            suite: agent_key.suite(),
            public_key: agent_key.clone(),
            signature: vec![0; 64],
        },
        cosigns: Vec::new(),
        ts: T0,
        overlay_seed: None,
    };
    let transcript = authority_transcript(&row).expect("the transcript");
    row.signer.signature = agent.sign(&transcript).to_bytes().to_vec();
    let hash = authority_entry_hash(&row).expect("a hash");
    let bytes = encode_authority_log_entry_body(&row).expect("the bytes");
    let _ = fixture.vault.import_signed_authority_history(&[bytes]);
    assert!(
        !fixture
            .vault
            .authority_fold()
            .expect("the fold")
            .valid_entries
            .contains(&hash),
        "the fold refuses the agent-signed answer"
    );
    assert!(
        fixture.history().len() <= before_history + 1,
        "stored or left out, the refused row writes nothing else"
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

/// A co-Owner's "it is me" never ends another owner's wait (REVIEW2 #8800
/// P2-1; WAYBACK-COOWNER-CANCEL-OTHER-OWNERS-RECOVERY = B): the first
/// owner's install answers `ItIsMe` on the co-Owner's hold and is refused
/// before any key signs, and an `ItIsMe` row the first owner's own key
/// signs, imported, counts in the fold yet leaves the hold Waiting until
/// its own `lands_at`.
#[test]
fn a_co_owners_it_is_me_never_ends_another_owners_wait() {
    let fixture = co_owner_wait_fixture();
    fixture.enrol_root_key();
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
            .expect("the co-Owner's box recovery holds"),
    );
    let first_key = fixture.hold_first_owners_key(FIRST_OWNER_KEY_SEED);

    // At the door: refused, and nothing is written.
    let before = fixture.history().len();
    let refused = fixture
        .vault
        .answer_recovery_hold_as(
            &fixture.first_owner_authority(),
            hold,
            RecoveryHoldAnswerKind::ItIsMe,
        )
        .expect_err("another owner's ItIsMe is refused at the door");
    assert_refused(&refused, ANSWER_NOT_HOLD_OWNER);
    assert_eq!(fixture.history().len(), before, "nothing was written");
    assert_eq!(fixture.hold_view(&hold).state, RecoveryHoldState::Waiting);

    // Imported: the fold counts the first owner's signed ItIsMe row, and
    // the hold still waits.
    let row = fixture.signed_answer(&first_key, hold, RecoveryHoldAnswerKind::ItIsMe);
    let hash = authority_entry_hash(&row).expect("a hash");
    fixture
        .vault
        .import_signed_authority_history(&[
            encode_authority_log_entry_body(&row).expect("the bytes")
        ])
        .expect("the import stores the row");
    assert!(
        fixture
            .vault
            .authority_fold()
            .expect("the fold")
            .valid_entries
            .contains(&hash),
        "the fold counts the first owner's answer row"
    );
    let view = fixture.hold_view(&hold);
    assert_eq!(
        view.state,
        RecoveryHoldState::Waiting,
        "a co-Owner's ItIsMe never ends another owner's wait"
    );
    assert!(view.answered_by.is_empty(), "it counts for nothing");
    fixture.at(lands_at + 60);
    assert_eq!(
        fixture.hold_view(&hold).state,
        RecoveryHoldState::Due,
        "the wait runs to its own end"
    );
}

/// A co-Owner's Cancel stops another owner's wait, and the hold names who
/// cancelled (WAYBACK-COOWNER-CANCEL-OTHER-OWNERS-RECOVERY = B: a Cancel
/// only denies, so any live owner key of an owner of this vault counts):
/// the first owner's install cancels the co-Owner's hold with the first
/// owner's own key; the hold is Cancelled, names the first owner, and
/// never lands, and the co-Owner's lost key stays live.
#[test]
fn a_co_owners_cancel_stops_another_owners_wait_and_names_them() {
    let fixture = co_owner_wait_fixture();
    fixture.enrol_root_key();
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
            .expect("the co-Owner's box recovery holds"),
    );
    let view = fixture.hold_view(&hold);
    assert_eq!(view.owner, fixture.person, "the hold is the co-Owner's");
    assert!(view.cancelled_by.is_empty(), "nobody cancelled yet");
    let first_key = fixture.hold_first_owners_key(FIRST_OWNER_KEY_SEED);

    fixture
        .vault
        .answer_recovery_hold_as(
            &fixture.first_owner_authority(),
            hold,
            RecoveryHoldAnswerKind::Cancel,
        )
        .expect("another owner of this vault cancels");
    let view = fixture.hold_view(&hold);
    assert_eq!(view.state, RecoveryHoldState::Cancelled);
    assert_eq!(view.owner, fixture.person);
    assert_eq!(view.answered_by, vec![key_of(&first_key)]);
    assert_eq!(
        view.cancelled_by,
        vec![fixture.first_owner],
        "the hold names the first owner as who cancelled"
    );
    fixture.at(lands_at + 60);
    fixture.land();
    assert_eq!(
        fixture.hold_view(&hold).state,
        RecoveryHoldState::Cancelled,
        "a cancelled hold never lands"
    );
    assert!(
        !fixture.live(&key_of(&new_key)),
        "the successor was never enrolled"
    );
    assert!(fixture.live(&lost), "the co-Owner's lost key stays live");
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
    // The cancel is cleaned here: a later box call lands this install's due
    // holds first, so its own pass would clean it unseen.
    let cleaned = fixture.land();
    assert_eq!(cleaned.len(), 1, "the cancel cleans");
    assert_eq!(cleaned[0].hold, hold);
    assert_eq!(cleaned[0].state, RecoveryHoldState::Cancelled);

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
    assert_eq!(landings.len(), 1, "the second lands");
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
        overlay_seed: None,
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
        overlay_seed: None,
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
    // vault's recovery root key R: the wire refuses an answer with any
    // cosign, so it never encodes. Stored or left out, it never counts.
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
        overlay_seed: None,
    };
    let transcript = authority_transcript(&cosigned).expect("the transcript");
    cosigned.cosigns[0].signature = stranger.sign(&transcript).to_bytes().to_vec();
    cosigned.signer.signature = anchor.sign(&transcript).to_bytes().to_vec();
    assert!(
        encode_authority_log_entry_body(&cosigned).is_err(),
        "the wire refuses an answer with a cosign"
    );
    assert!(
        authority_entry_hash(&cosigned).is_err(),
        "the row has no hash"
    );
    let before_cosigned = fixture.history().len();
    import_if_encodable(&fixture.vault, &cosigned);
    assert_eq!(
        fixture.history().len(),
        before_cosigned,
        "a Cancel beside a key that is not R is never stored"
    );
    let view = fixture.hold_view(&hold);
    assert_eq!(view.state, RecoveryHoldState::Waiting);
    assert!(view.answered_by.is_empty());
}

/// ANCHORS-E6 (Fable pass 29; lead ANCHORS-3 = A): whoever holds R alone
/// (the box's release) mints a fresh root, valid by its own anchor, and
/// signs a Cancel with that anchor beside R's cosign. An anchor is no voice
/// in a shared judge: the row never counts, and the hold waits on. Red at
/// `14e0d18770df`, where any valid root's anchor beside R cancelled.
#[test]
fn a_fresh_roots_anchor_beside_the_root_key_never_stops_a_hold() {
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
    // R's seed as the box releases it, and a fresh root that is not the
    // vault's kit, published by its own anchor.
    let r_signing = SigningKey::from_bytes(&released_authority_seed(
        &fixture.seed(),
        &fixture.vault_id,
        0,
    ));
    assert_eq!(key_of(&r_signing), root_key);
    let fresh = RecoveryRootSeed::generate().expect("a fresh root seed");
    let root = fresh.public(&fixture.vault_id).expect("the fresh root");
    let anchor = fresh.anchor();
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
        overlay_seed: None,
    };
    let transcript = authority_transcript(&published).expect("the transcript");
    published.signer.signature = anchor.sign(&transcript).to_bytes().to_vec();
    let published_hash = authority_entry_hash(&published).expect("a hash");
    fixture
        .vault
        .import_signed_authority_history(&[
            encode_authority_log_entry_body(&published).expect("the bytes")
        ])
        .expect("the fresh root stores");
    assert!(
        fixture
            .vault
            .authority_fold()
            .expect("the fold")
            .valid_entries
            .contains(&published_hash),
        "a fresh root is valid by its own anchor alone"
    );

    // That anchor's Cancel naming the hold, beside R's one cosign.
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
        cosigns: vec![AuthoritySignature {
            suite: root_key.suite(),
            public_key: root_key.clone(),
            signature: vec![0; 64],
        }],
        ts: T0,
        overlay_seed: None,
    };
    let transcript = authority_transcript(&row).expect("the transcript");
    row.cosigns[0].signature = r_signing.sign(&transcript).to_bytes().to_vec();
    row.signer.signature = anchor.sign(&transcript).to_bytes().to_vec();
    // The wire refuses an answer with any cosign: the row has no canonical
    // bytes, so it has no hash, and no import can store it.
    assert!(
        encode_authority_log_entry_body(&row).is_err(),
        "the wire refuses an answer with a cosign"
    );
    assert!(authority_entry_hash(&row).is_err(), "the row has no hash");
    let before_history = fixture.history().len();
    import_if_encodable(&fixture.vault, &row);
    assert_eq!(
        fixture.history().len(),
        before_history,
        "an anchor's Cancel beside R is never stored"
    );
    let view = fixture.hold_view(&hold);
    assert_eq!(view.state, RecoveryHoldState::Waiting, "the hold waits on");
    assert!(view.answered_by.is_empty());
}

/// The kit cancels through R like any owner key (lead ANCHORS-3 = A): its
/// Cancel is a roster row the kit's live root key R signs alone, with no
/// anchor and no cosign, and R is the hold's one answerer. Red at
/// `14e0d18770df`, where the anchor signed it beside R's cosign.
#[test]
fn the_kits_cancel_is_the_root_keys_own_row() {
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
    fixture
        .vault
        .cancel_recovery_holds_with_kit_as(
            &fixture.authority(),
            &fixture.kit_refs(),
            None,
            Some(hold),
        )
        .expect("the kit cancels the live hold");
    let cancels: Vec<AuthorityLogEntry> = fixture
        .history()
        .into_iter()
        .filter(|row| {
            matches!(&row.op, AuthorityOp::RecoveryHoldAnswer(answer)
                if answer.hold == hold && answer.answer == RecoveryHoldAnswerKind::Cancel)
        })
        .collect();
    assert_eq!(cancels.len(), 1, "one Cancel names the hold");
    assert_eq!(
        cancels[0].signer_key(),
        &root_key,
        "the kit's live root key R signs the Cancel"
    );
    assert!(cancels[0].cosigns.is_empty(), "no anchor, no cosign");
    let view = fixture.hold_view(&hold);
    assert_eq!(view.state, RecoveryHoldState::Cancelled);
    assert_eq!(view.answered_by, vec![root_key]);
    assert_eq!(
        view.cancelled_by,
        vec![fixture.person],
        "the kit's Cancel names the owner its R was enrolled for"
    );
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

/// A recovery box as the cloud keeps it (WAYBACK-BOX-WAIT-ENGINE-HOLD-ONE-WAIT
/// = A): it records each wait the vault reports, and a release it opens at
/// `opened` gives the root's authority key out at `opened` plus the last
/// reported wait, or 24 hours before any report. With `fail_report`, a
/// report answers `Err`. It records each Cancel with who cancelled and the
/// release it names; the first Cancel voids the pending release, so a later
/// one finds nothing pending.
#[derive(Default)]
struct WaitingBox {
    reports: RefCell<Vec<Duration>>,
    fail_report: bool,
    cancels: RefCell<Vec<(RecoveryBoxCanceller, Option<RecoveryBoxRelease>)>>,
}

impl RecoveryBoxHold for WaitingBox {
    fn hold_kit_only(&self, _kit_only: bool) -> oneiron::Result<()> {
        Ok(())
    }

    fn report_recovery_wait(&self, wait: Duration) -> oneiron::Result<()> {
        self.reports.borrow_mut().push(wait);
        if self.fail_report {
            return Err(oneiron::Error::Io(std::io::Error::other(
                "the recovery box did not answer",
            )));
        }
        Ok(())
    }

    fn cancel_pending_box_release(
        &self,
        cancelled_by: &RecoveryBoxCanceller,
        release: Option<RecoveryBoxRelease>,
    ) -> oneiron::Result<bool> {
        let mut cancels = self.cancels.borrow_mut();
        cancels.push((*cancelled_by, release));
        Ok(cancels.len() == 1)
    }
}

impl WaitingBox {
    /// The second a release opened at `opened` gives the root's authority
    /// key out.
    fn release_at(&self, opened: u64) -> u64 {
        let wait = self
            .reports
            .borrow()
            .last()
            .copied()
            .unwrap_or(Duration::from_secs(24 * 60 * 60));
        opened + wait.as_secs()
    }
}

impl Fixture {
    /// Generation `generation`'s authority key as the box gives it out at
    /// `release_at`, at the end of the box's own wait.
    fn released_after_box_wait(&self, generation: u32, release_at: u64) -> RootMaterial {
        let RootMaterial::Released(signer) = self.released_material(generation) else {
            panic!("the box's bytes are a released authority key");
        };
        RootMaterial::ReleasedAfterBoxWait { signer, release_at }
    }
}

/// One wait end to end: the vault reports its recovery wait to the box, the
/// box waits it out before it gives R out, and the door then lands at once
/// with the hold row as the receipt, with no second wait of its own.
#[test]
fn a_hosted_recovery_waits_once_at_the_box_and_lands_at_its_release() {
    let fixture = fixture();
    let root_key = AuthorityKey::Ed25519(fixture.generation_key(0));
    let lost = fixture.enrol_device_key(LOST_KEY_SEED);
    let lost_key = key_of(&lost);
    let new_key = SigningKey::from_bytes(&[NEW_KEY_SEED; 32]);
    let new = key_of(&new_key);
    let recovery_box = WaitingBox::default();
    fixture
        .vault
        .report_recovery_wait_to_box(&recovery_box)
        .expect("the vault reports its wait");
    assert_eq!(
        *recovery_box.reports.borrow(),
        vec![RECOVERY_WAIT_DEFAULT],
        "the box is told the vault's recovery wait"
    );
    // Sign-in and the recovery PIN open the release at T0; the box gives R
    // out once its wait ends, and the door is called then.
    let release_at = recovery_box.release_at(T0);
    assert_eq!(release_at, T0 + RECOVERY_WAIT_DEFAULT.as_secs());
    fixture.at(release_at + 5);
    let before_history = fixture.history().len();

    let answer = fixture
        .vault
        .recover_owner_root(
            &fixture.owner(),
            ActSurface::ThisInstall,
            fixture.released_after_box_wait(0, release_at),
            RootSuccessor::Device(fixture.enrollment(&new_key)),
            std::slice::from_ref(&lost_key),
        )
        .expect("the box's wait was the recovery wait");

    assert_vouched(&fixture, answer, &root_key, &new, &lost_key);
    assert_eq!(
        fixture.history().len(),
        before_history + 3,
        "the hold, its revocation and its enrolment, in one call"
    );
    let holds = fixture.holds();
    assert_eq!(holds.len(), 1, "one hold row: the recovery's receipt");
    assert_eq!(holds[0].state, RecoveryHoldState::Landed);
    assert_eq!(
        holds[0].lands_at, release_at,
        "the hold lands at the box's release second"
    );
    assert_eq!(
        fixture.row(&holds[0].hold).signer_key(),
        &root_key,
        "R signed the hold"
    );
    assert!(
        !fixture.slot_present(&new_key.verifying_key().to_bytes()),
        "the landing deletes R's seed"
    );
}

/// The box's clock may run ahead of this install's: the hold then waits
/// until the box's release second, and a release second past this
/// install's own wait is cut to that wait.
#[test]
fn a_box_release_never_waits_past_its_release_or_this_installs_wait() {
    let fixture = fixture();
    let lost = fixture.enrol_device_key(LOST_KEY_SEED);
    let lost_key = key_of(&lost);
    let new_key = SigningKey::from_bytes(&[NEW_KEY_SEED; 32]);
    let new = key_of(&new_key);

    let (hold, lands_at) = held(
        fixture
            .recover_wait(
                WAIT,
                fixture.released_after_box_wait(0, T0 + 120),
                RootSuccessor::Device(fixture.enrollment(&new_key)),
                std::slice::from_ref(&lost_key),
            )
            .expect("a release ahead of this clock holds"),
    );
    assert_eq!(
        lands_at,
        T0 + 120,
        "the hold lands at the box's release second"
    );
    assert!(!fixture.live(&new), "nothing lands before it");
    fixture.at(T0 + 180);
    let landings = fixture.land();
    assert_eq!(
        landings.len(),
        1,
        "the hold is due at the box's release second"
    );
    assert_eq!(landings[0].hold, hold);
    assert!(fixture.live(&new), "the successor landed");
    assert!(!fixture.live(&lost_key), "the lost key was revoked");

    let new2_key = SigningKey::from_bytes(&[NEW2_KEY_SEED; 32]);
    let far = T0 + 180 + 10 * WAIT.as_secs();
    let (_, capped) = held(
        fixture
            .recover_wait(
                WAIT,
                fixture.released_after_box_wait(0, far),
                RootSuccessor::Device(fixture.enrollment(&new2_key)),
                &[],
            )
            .expect("a release far ahead of this clock holds"),
    );
    assert!(
        capped >= T0 + 180 + WAIT.as_secs() && capped < T0 + 180 + WAIT.as_secs() + 300,
        "never later than this install's own wait: {capped}"
    );
}

/// A report the box refuses is the caller's error to log: the box keeps its
/// last value, and the next managed boot reports again.
#[test]
fn a_wait_report_the_box_refuses_answers_its_error() {
    let fixture = fixture();
    let recovery_box = WaitingBox {
        fail_report: true,
        ..WaitingBox::default()
    };
    fixture
        .vault
        .report_recovery_wait_to_box(&recovery_box)
        .expect_err("the box's error is the answer");
    assert_eq!(
        *recovery_box.reports.borrow(),
        vec![RECOVERY_WAIT_DEFAULT],
        "the report was sent once"
    );
    fixture
        .vault
        .report_recovery_wait_to_box(&NoRecoveryBox)
        .expect("no box: nothing to report");
}

/// The box cancel doors' refusal words, asserted with `contains`.
const NO_OWNER_KEY_TO_CANCEL: &str =
    "this install holds no live owner key of yours to cancel the box's recovery";
const CANCEL_PROOF_NOT_ACTORS: &str = "the cancel's proof names another person";
const CANCEL_KEY_NOT_OWNERS: &str =
    "the cancel is not signed by a live owner key of yours on this vault";
const CANCEL_KEY_IS_ROOT: &str = "the root's authority key never cancels the box's recovery";
const CANCEL_PROOF_NOT_VALID: &str = "the cancel's signature does not verify for this vault";
const CANCEL_PROOF_STALE: &str =
    "the cancel was signed more than five minutes from this node's clock";

/// The pending release named by its receipt alone, as a device that read no
/// start names it.
fn receipt_only(receipt: u64) -> Option<RecoveryBoxRelease> {
    Some(RecoveryBoxRelease {
        receipt,
        started_at_ms: None,
    })
}

/// The start of the box's pending release in unix milliseconds, as its
/// recovery-started act gives it: one second after T0.
const RELEASE_STARTED_AT_MS: u64 = (T0 + 1) * 1000;

/// `key`'s Cancel of the box's pending release for `person`, signed by hand
/// over the door's transcript for `vault_id`: an owner device install of its
/// own.
fn signed_cancel(
    vault_id: &[u8; 32],
    key: &SigningKey,
    person: EntityId,
    issued_at: u64,
    release: Option<RecoveryBoxRelease>,
) -> RecoveryBoxCancelProof {
    let mut proof = RecoveryBoxCancelProof {
        person,
        key: key.verifying_key().to_bytes(),
        issued_at,
        release,
        signature: Vec::new(),
    };
    proof.signature = key.sign(&proof.transcript(vault_id)).to_bytes().to_vec();
    proof
}

/// An owner device's Cancel during the box wait (ONE-WAIT = A: no recovery
/// hold exists yet) reaches the box once, naming the owner and the key that
/// signed it, and voids the pending release: a second Cancel finds nothing
/// pending. The Cancel writes no authority row.
#[test]
fn an_owner_devices_cancel_during_the_box_wait_voids_the_release_and_names_them() {
    let fixture = fixture();
    let enrolled = fixture
        .vault
        .enrol_device_owner_signing_key(&fixture.authority(), &fixture.issuer)
        .expect("this device's owner key enrols");
    let recovery_box = WaitingBox::default();
    let before_history = fixture.history().len();

    let proof = fixture
        .vault
        .sign_recovery_box_cancel_as(&fixture.authority(), receipt_only(7))
        .expect("the device signs its cancel");
    assert_eq!(proof.person, fixture.person, "the cancel names the owner");
    assert_eq!(
        proof.key, enrolled.public_key,
        "this device's owner key signs"
    );
    assert!(
        (T0..T0 + 60).contains(&proof.issued_at),
        "signed on this clock: {}",
        proof.issued_at
    );
    assert_eq!(proof.release, receipt_only(7));

    fixture.at(T0 + 60);
    let cancelled = fixture
        .vault
        .cancel_box_recovery_as(&fixture.authority(), &proof, &recovery_box)
        .expect("the node takes the cancel");
    assert!(cancelled, "the box cancelled the pending release");
    assert_eq!(
        *recovery_box.cancels.borrow(),
        vec![(
            RecoveryBoxCanceller {
                owner: fixture.person,
                key: enrolled.public_key,
            },
            receipt_only(7),
        )],
        "the box is asked once, naming who cancelled and the release"
    );
    let again = fixture
        .vault
        .cancel_box_recovery_as(&fixture.authority(), &proof, &recovery_box)
        .expect("a second cancel reaches the box");
    assert!(!again, "nothing is pending after the cancel");
    assert_eq!(
        fixture.history().len(),
        before_history,
        "a box cancel writes no authority row"
    );
}

/// Any owner of the vault cancels the box's recovery, each with their own
/// key (WAYBACK-COOWNER-CANCEL-OTHER-OWNERS-RECOVERY = B): the co-Owner's
/// Cancel and the first owner's each reach the box naming who cancelled.
#[test]
fn every_owner_of_the_vault_cancels_the_box_wait_with_their_own_key() {
    let co = co_owner_wait_fixture();
    let first_key = co.hold_first_owners_key(FIRST_OWNER_KEY_SEED);
    let recovery_box = WaitingBox::default();

    let co_owners = signed_cancel(&co.vault_id, &co.lost_key, co.person, T0, None);
    assert!(
        co.vault
            .cancel_box_recovery_as(&co.authority(), &co_owners, &recovery_box)
            .expect("the co-Owner cancels"),
        "the co-Owner's cancel voids the pending release"
    );
    let first_owners = signed_cancel(
        &co.vault_id,
        &first_key,
        co.first_owner,
        T0,
        receipt_only(3),
    );
    co.vault
        .cancel_box_recovery_as(&co.first_owner_authority(), &first_owners, &recovery_box)
        .expect("the first owner cancels");
    assert_eq!(
        *recovery_box.cancels.borrow(),
        vec![
            (
                RecoveryBoxCanceller {
                    owner: co.person,
                    key: co.lost_key.verifying_key().to_bytes(),
                },
                None,
            ),
            (
                RecoveryBoxCanceller {
                    owner: co.first_owner,
                    key: first_key.verifying_key().to_bytes(),
                },
                receipt_only(3),
            ),
        ],
        "each cancel names its owner and key"
    );
}

/// Sign-in alone never cancels the box's recovery: an install that holds no
/// live owner key of the owner's signs no Cancel, and the node refuses a
/// Cancel whose key is no live owner key on its fold. Neither reaches the
/// box.
#[test]
fn sign_in_alone_never_cancels_the_box_wait() {
    let fixture = fixture();
    let error = fixture
        .vault
        .sign_recovery_box_cancel_as(&fixture.authority(), None)
        .expect_err("no owner key on this install, no cancel");
    assert_refused(&error, NO_OWNER_KEY_TO_CANCEL);

    let recovery_box = WaitingBox::default();
    let stranger = SigningKey::from_bytes(&[STRANGER_KEY_SEED; 32]);
    let proof = signed_cancel(&fixture.vault_id, &stranger, fixture.person, T0, None);
    let error = fixture
        .vault
        .cancel_box_recovery_as(&fixture.authority(), &proof, &recovery_box)
        .expect_err("a key off the roster never cancels");
    assert_refused(&error, CANCEL_KEY_NOT_OWNERS);
    assert!(
        recovery_box.cancels.borrow().is_empty(),
        "nothing reached the box"
    );
}

/// The root's authority key never cancels the box's recovery: the box holds
/// its seed. Its Cancel never reaches the box.
#[test]
fn the_roots_authority_key_never_cancels_the_box_wait() {
    let fixture = fixture();
    let root = SigningKey::from_bytes(&released_authority_seed(
        &fixture.seed(),
        &fixture.vault_id,
        0,
    ));
    assert!(fixture.live(&key_of(&root)), "the kit's R is on the roster");
    let recovery_box = WaitingBox::default();
    let proof = signed_cancel(&fixture.vault_id, &root, fixture.person, T0, None);
    let error = fixture
        .vault
        .cancel_box_recovery_as(&fixture.authority(), &proof, &recovery_box)
        .expect_err("R never cancels at this door");
    assert_refused(&error, CANCEL_KEY_IS_ROOT);
    assert!(
        recovery_box.cancels.borrow().is_empty(),
        "nothing reached the box"
    );
}

/// A Cancel the node cannot trust never reaches the box: one signed more
/// than five minutes from the node's clock, ahead or behind; one whose
/// receipt changed after signing; one signed for another vault.
#[test]
fn a_stale_or_altered_cancel_never_reaches_the_box() {
    let fixture = fixture();
    let keeper = fixture.enrol_device_key(KEEPER_KEY_SEED);
    let recovery_box = WaitingBox::default();
    let node = |proof: &RecoveryBoxCancelProof| {
        fixture
            .vault
            .cancel_box_recovery_as(&fixture.authority(), proof, &recovery_box)
            .expect_err("the node refuses the cancel")
    };

    let ahead = signed_cancel(
        &fixture.vault_id,
        &keeper,
        fixture.person,
        T0 + 400,
        receipt_only(7),
    );
    assert_refused(&node(&ahead), CANCEL_PROOF_STALE);
    let mut altered = signed_cancel(
        &fixture.vault_id,
        &keeper,
        fixture.person,
        T0,
        receipt_only(7),
    );
    altered.release = receipt_only(8);
    assert_refused(&node(&altered), CANCEL_PROOF_NOT_VALID);
    let other_vault = signed_cancel(&[9; 32], &keeper, fixture.person, T0, receipt_only(7));
    assert_refused(&node(&other_vault), CANCEL_PROOF_NOT_VALID);
    let behind = signed_cancel(
        &fixture.vault_id,
        &keeper,
        fixture.person,
        T0,
        receipt_only(7),
    );
    fixture.at(T0 + 400);
    assert_refused(&node(&behind), CANCEL_PROOF_STALE);
    assert!(
        recovery_box.cancels.borrow().is_empty(),
        "nothing reached the box"
    );
}

/// A Cancel names the release it stops by its receipt and its start
/// ([RECOVERY-BOX-CANCEL-RELEASE-STARTED-AT]): a control-plane snapshot
/// restore gives receipts out again, so the box needs both to void only that
/// release. The device signs both, the node hands both to the box as signed,
/// and a start changed or dropped after signing never reaches the box.
#[test]
fn a_cancel_names_its_release_by_receipt_and_start_and_the_box_gets_both() {
    let fixture = fixture();
    let enrolled = fixture
        .vault
        .enrol_device_owner_signing_key(&fixture.authority(), &fixture.issuer)
        .expect("this device's owner key enrols");
    let recovery_box = WaitingBox::default();
    let release = RecoveryBoxRelease {
        receipt: 7,
        started_at_ms: Some(RELEASE_STARTED_AT_MS),
    };

    let proof = fixture
        .vault
        .sign_recovery_box_cancel_as(&fixture.authority(), Some(release))
        .expect("the device signs its cancel");
    assert_eq!(
        proof.release,
        Some(release),
        "the cancel names the receipt and the start"
    );

    let mut later_start = proof.clone();
    later_start.release = Some(RecoveryBoxRelease {
        started_at_ms: Some(RELEASE_STARTED_AT_MS + 1),
        ..release
    });
    let mut start_dropped = proof.clone();
    start_dropped.release = receipt_only(7);
    for altered in [&later_start, &start_dropped] {
        let error = fixture
            .vault
            .cancel_box_recovery_as(&fixture.authority(), altered, &recovery_box)
            .expect_err("a start changed after signing never verifies");
        assert_refused(&error, CANCEL_PROOF_NOT_VALID);
    }
    assert!(
        recovery_box.cancels.borrow().is_empty(),
        "nothing reached the box"
    );

    assert!(
        fixture
            .vault
            .cancel_box_recovery_as(&fixture.authority(), &proof, &recovery_box)
            .expect("the node takes the cancel"),
        "the box cancelled the release"
    );
    assert_eq!(
        *recovery_box.cancels.borrow(),
        vec![(
            RecoveryBoxCanceller {
                owner: fixture.person,
                key: enrolled.public_key,
            },
            Some(release),
        )],
        "the box is asked once, with the receipt and the start as signed"
    );
}

/// A Cancel that names no start signs the bytes a box Cancel signed before
/// starts were named, so an owner device that reads no start still cancels
/// at a node that knows them; a start adds its own tag and eight bytes.
/// Each layout, built by hand.
#[test]
fn a_cancel_without_a_start_signs_the_bytes_it_signed_before() {
    let fixture = fixture();
    let key = [6_u8; 32];
    let issued_at = T0 + 2;
    let proof = |release: Option<RecoveryBoxRelease>| RecoveryBoxCancelProof {
        person: fixture.person,
        key,
        issued_at,
        release,
        signature: Vec::new(),
    };
    let head = |tag: u8| {
        let mut bytes = b"oneiron/recovery-box-cancel/v1".to_vec();
        bytes.extend_from_slice(&fixture.vault_id);
        bytes.extend_from_slice(fixture.person.as_bytes());
        bytes.extend_from_slice(&key);
        bytes.extend_from_slice(&issued_at.to_be_bytes());
        bytes.push(tag);
        bytes
    };

    let mut none = head(0);
    none.extend_from_slice(&[0; 8]);
    assert_eq!(
        proof(None).transcript(&fixture.vault_id),
        none,
        "no release: tag 0 and eight zero bytes"
    );
    let mut receipt = head(1);
    receipt.extend_from_slice(&7_u64.to_be_bytes());
    assert_eq!(
        proof(receipt_only(7)).transcript(&fixture.vault_id),
        receipt,
        "a receipt alone: tag 1 and the receipt, the bytes signed before starts"
    );
    let mut both = head(2);
    both.extend_from_slice(&7_u64.to_be_bytes());
    both.extend_from_slice(&RELEASE_STARTED_AT_MS.to_be_bytes());
    assert_eq!(
        proof(Some(RecoveryBoxRelease {
            receipt: 7,
            started_at_ms: Some(RELEASE_STARTED_AT_MS),
        }))
        .transcript(&fixture.vault_id),
        both,
        "a receipt with its start: tag 2, the receipt, then the start"
    );
}

/// Each owner cancels with their own key: a Cancel that names another
/// person than the actor, or that another owner's key signed for the
/// actor, never reaches the box.
#[test]
fn another_owners_name_or_key_never_cancels_for_the_actor() {
    let co = co_owner_wait_fixture();
    let first_key = co.hold_first_owners_key(FIRST_OWNER_KEY_SEED);
    let recovery_box = WaitingBox::default();

    let names_another = signed_cancel(&co.vault_id, &first_key, co.first_owner, T0, None);
    let error = co
        .vault
        .cancel_box_recovery_as(&co.authority(), &names_another, &recovery_box)
        .expect_err("the co-Owner never sends the first owner's cancel");
    assert_refused(&error, CANCEL_PROOF_NOT_ACTORS);
    let another_key = signed_cancel(&co.vault_id, &first_key, co.person, T0, None);
    let error = co
        .vault
        .cancel_box_recovery_as(&co.authority(), &another_key, &recovery_box)
        .expect_err("the first owner's key never cancels for the co-Owner");
    assert_refused(&error, CANCEL_KEY_NOT_OWNERS);
    assert!(
        recovery_box.cancels.borrow().is_empty(),
        "nothing reached the box"
    );
}

/// A declined confirm at a box recovery that would wait holds nothing: the
/// hold arm asks for the person at this device before it readies anything,
/// as the vouch arm does (OWNER-KEY-PRESENCE = B), so the refusal writes no
/// row and leaves no seed of R in a slot. With the confirm given, the same
/// call holds.
#[test]
fn a_declined_confirm_holds_nothing_and_a_given_one_holds() {
    let fixture = fixture();
    let lost_key = key_of(&fixture.enrol_device_key(LOST_KEY_SEED));
    let new_key = SigningKey::from_bytes(&[NEW_KEY_SEED; 32]);
    let presence = Arc::new(ScriptedPresence::new([
        Err(PresenceError::Declined),
        Ok(()),
    ]));
    let window = PresenceWindow::new(ManualPresenceClock::new(1_000_000, 1_000_000));
    fixture
        .vault
        .install_presence_gate(Arc::new(PresenceGate::new(presence.clone(), window)));
    let rows = fixture.history().len();
    let recover = || {
        fixture.recover_wait(
            WAIT,
            fixture.released_material(0),
            RootSuccessor::Device(fixture.enrollment(&new_key)),
            std::slice::from_ref(&lost_key),
        )
    };

    let refused = recover();
    assert!(
        matches!(
            refused,
            Err(oneiron::Error::Record(RecordError::OwnerPresenceRequired {
                here: OwnerPresenceRefusal::Declined
            }))
        ),
        "a declined confirm refuses the box recovery's hold: {refused:?}"
    );
    assert_eq!(presence.prompts(), 1, "the hold arm showed one prompt");
    assert_eq!(fixture.history().len(), rows, "the refusal writes no row");
    assert!(fixture.holds().is_empty(), "no hold was written");
    assert!(
        !fixture.slot_present(&new_key.verifying_key().to_bytes()),
        "no seed of R went to a slot"
    );

    let (hold, lands_at) = held(recover().expect("with the confirm given, the box recovery holds"));
    assert_eq!(presence.prompts(), 2, "the second call asked again");
    assert_eq!(fixture.history().len(), rows + 1, "one hold row");
    assert_eq!(fixture.hold_view(&hold).lands_at, lands_at);
    assert!(
        fixture.slot_present(&new_key.verifying_key().to_bytes()),
        "this install keeps R's seed for the hold"
    );
}

/// Row RECOVERY-HOLD-ENROLMENT-PREFLIGHT: a box recovery whose held
/// enrolment the fold would never count is refused at the hold, with the
/// landing's own refusal, and writes nothing. Before the fix the door held
/// it, and every landing pass after its wait failed. Here the successor's
/// holding machine is one this vault never held: a live holding machine is
/// the enrolment's rule, not the hold judge's. The same owner's hold for a
/// successor on this install's machine then holds and lands as before.
#[test]
fn a_hold_whose_enrolment_never_lands_is_refused_before_its_wait() {
    let fixture = fixture();
    let lost = fixture.enrol_device_key(LOST_KEY_SEED);
    let lost_key = key_of(&lost);
    let new_key = SigningKey::from_bytes(&[NEW_KEY_SEED; 32]);
    let new = key_of(&new_key);
    let public_key = new_key.verifying_key().to_bytes();
    let stranger = EntityId::from_bytes([0x7C; 16]).expect("a machine id this vault never held");
    let challenge = fixture
        .vault
        .owner_key_enrollment_challenge_as(&fixture.authority(), stranger, &public_key)
        .expect("the challenge");
    let on_stranger = OwnerKeyEnrollment {
        machine: stranger,
        public_key,
        proof: new_key.sign(&challenge).to_bytes().to_vec(),
    };
    let rows = fixture.history().len();

    let refused = fixture
        .recover_wait(
            WAIT,
            fixture.released_material(0),
            RootSuccessor::Device(on_stranger),
            std::slice::from_ref(&lost_key),
        )
        .expect_err("a hold whose enrolment the fold refuses is never written");
    assert_refused(&refused, "the holding machine is not live");
    assert_eq!(fixture.history().len(), rows, "the refusal writes no row");
    assert!(fixture.holds().is_empty(), "no hold was written");
    assert!(
        !fixture.slot_present(&public_key),
        "no seed of R stays in a slot"
    );
    assert!(fixture.live(&lost_key), "the lost key is still live");
    assert!(!fixture.live(&new), "the successor is not enrolled");
    assert!(fixture.land().is_empty(), "nothing waits to land");

    let (hold, lands_at) = held(
        fixture
            .recover_wait(
                WAIT,
                fixture.released_material(0),
                RootSuccessor::Device(fixture.enrollment(&new_key)),
                std::slice::from_ref(&lost_key),
            )
            .expect("a successor on this install's machine holds"),
    );
    assert_eq!(fixture.history().len(), rows + 1, "one hold row");
    fixture.at(lands_at + 60);
    let landings = fixture.land();
    assert_eq!(landings.len(), 1, "the due hold lands");
    assert_eq!(landings[0].hold, hold);
    assert_eq!(landings[0].state, RecoveryHoldState::Landed);
    assert!(fixture.live(&new), "the successor is enrolled");
    assert!(!fixture.live(&lost_key), "the lost key is revoked");
}

/// The seed-slot pin (row RECOVERY-HOLD-SEED-SLOT-PER-ATTEMPT): a hold's
/// slot is keyed by its successor alone, so an attempt racing it could
/// leave another key's seed there, and the landing signs only with the
/// hold's own R. The door answered such a hold again on every retry, and it
/// never landed. Now a retry by the hold's R puts R's seed back and answers
/// the same hold, which lands at its own second; no second hold is written.
/// It fails on main `42d134bab7a5`, where the retry left the other seed in
/// the slot.
#[test]
fn a_retry_puts_back_its_holds_seed_and_the_hold_lands_at_its_second() {
    let fixture = fixture();
    let new_key = SigningKey::from_bytes(&[NEW_KEY_SEED; 32]);
    let successor = new_key.verifying_key().to_bytes();
    let (hold, lands_at) = held(
        fixture
            .recover_wait(
                WAIT,
                fixture.released_material(0),
                RootSuccessor::Device(fixture.enrollment(&new_key)),
                &[],
            )
            .expect("the box recovery holds"),
    );
    assert_eq!(
        fixture.slot_seed_key(&successor),
        Some(fixture.generation_key(0)),
        "the slot keeps R's seed"
    );
    fixture.replace_slot_seed(&successor, &[STRANGER_KEY_SEED; 32]);
    let rows = fixture.history().len();

    let (again, again_lands_at) = held(
        fixture
            .recover_wait(
                WAIT,
                fixture.released_material(0),
                RootSuccessor::Device(fixture.enrollment(&new_key)),
                &[],
            )
            .expect("the retry holds"),
    );
    assert_eq!(again, hold, "the retry answers the same hold");
    assert_eq!(again_lands_at, lands_at, "at the hold's own second");
    assert_eq!(fixture.history().len(), rows, "no second hold is written");
    assert_eq!(
        fixture.slot_seed_key(&successor),
        Some(fixture.generation_key(0)),
        "R's seed is back in the slot"
    );

    fixture.at(lands_at + 60);
    let landings = fixture.land();
    assert_eq!(landings.len(), 1, "the due hold lands");
    assert_eq!(landings[0].hold, hold);
    assert_eq!(landings[0].state, RecoveryHoldState::Landed);
    assert!(
        fixture.live(&AuthorityKey::Ed25519(successor)),
        "the successor is enrolled"
    );
    assert_eq!(fixture.slot_seed_key(&successor), None, "the slot is empty");
}

/// A box call for this install's own key takes a landing only when it
/// enrolled this install's owner signing key (row
/// RECOVERY-HOLD-SEED-SLOT-PER-ATTEMPT): a device successor on the same
/// machine is another attempt's. The call holds for its own key instead. It
/// fails on main `42d134bab7a5`, where the call matched the landing by its
/// machine and answered the device key's enrolment as its own.
#[test]
fn a_device_successor_on_this_machine_never_answers_this_installs_box_call() {
    let fixture = fixture();
    let new_key = SigningKey::from_bytes(&[NEW_KEY_SEED; 32]);
    let device = AuthorityKey::Ed25519(new_key.verifying_key().to_bytes());
    let (hold, lands_at) = held(
        fixture
            .recover_wait(
                WAIT,
                fixture.released_material(0),
                RootSuccessor::Device(fixture.enrollment(&new_key)),
                &[],
            )
            .expect("the device's hold"),
    );

    fixture.at(lands_at + 60);
    let answer = fixture
        .recover_wait(
            WAIT,
            fixture.released_material(0),
            RootSuccessor::ThisInstall,
            &[],
        )
        .expect("this install's box call");
    assert_eq!(
        fixture.hold_view(&hold).state,
        RecoveryHoldState::Landed,
        "the device's hold landed first"
    );
    assert!(fixture.live(&device), "the device key is enrolled");
    let RootRecovery::Held {
        hold: own,
        lands_at: own_lands_at,
    } = answer
    else {
        panic!("the device key's enrolment is not this install's");
    };
    let own_view = fixture.hold_view(&own);
    assert_ne!(own, hold, "a new attempt");
    assert_ne!(
        own_view.successor_key, device,
        "this install holds for its own key"
    );
    assert_eq!(own_view.state, RecoveryHoldState::Waiting);
    assert!(own_lands_at > lands_at, "its own wait");
}

/// Revokes this install's owner signing key on the fixture's roster: a zero
/// wait recovery enrols it, then a zero wait recovery onto a device key
/// names it lost. Answers that key; the slot still holds its seed.
fn revoke_this_installs_key(fixture: &Fixture) -> AuthorityKey {
    let RootRecovery::Vouched { enrollment, .. } = fixture
        .recover_wait(
            NO_WAIT,
            fixture.released_material(0),
            RootSuccessor::ThisInstall,
            &[],
        )
        .expect("the root's key vouches for this install's key")
    else {
        panic!("a zero wait vouches");
    };
    let install_key = AuthorityKey::Ed25519(enrollment.public_key);
    let device = SigningKey::from_bytes(&[NEW3_KEY_SEED; 32]);
    fixture
        .recover_wait(
            NO_WAIT,
            fixture.released_material(0),
            RootSuccessor::Device(fixture.enrollment(&device)),
            std::slice::from_ref(&install_key),
        )
        .expect("a recovery onto a device key revokes this install's key");
    assert!(!fixture.live(&install_key), "this install's key is revoked");
    install_key
}

/// This install's owner signing key, as its slot holds it.
fn slot_key(fixture: &Fixture) -> AuthorityKey {
    AuthorityKey::Ed25519(
        fixture
            .vault
            .device_owner_signing_key()
            .expect("this install's owner signing key")
            .public_key(),
    )
}

/// A box call is judged before it lands anything (row
/// RECOVERY-HOLD-BOX-PATH-WRITES-BEFORE-CHECKS): a call that names a lost
/// key the owner never enrolled is refused, and the due hold it would
/// complete stays due, with nothing landed. The same call with no lost key
/// then lands it and answers `Vouched`. It fails on main `2c56ee802949`,
/// where the call landed the due hold first and answered `Vouched`.
#[test]
fn a_refused_box_call_lands_no_due_hold() {
    let fixture = fixture();
    let new_key = SigningKey::from_bytes(&[NEW_KEY_SEED; 32]);
    let new = key_of(&new_key);
    let (hold, lands_at) = held(
        fixture
            .recover_wait(
                WAIT,
                fixture.released_material(0),
                RootSuccessor::Device(fixture.enrollment(&new_key)),
                &[],
            )
            .expect("the box recovery holds"),
    );
    fixture.at(lands_at + 60);
    let stranger = key_of(&SigningKey::from_bytes(&[STRANGER_KEY_SEED; 32]));
    let rows = fixture.history().len();

    let refused = fixture
        .recover_wait(
            WAIT,
            fixture.released_material(0),
            RootSuccessor::Device(fixture.enrollment(&new_key)),
            std::slice::from_ref(&stranger),
        )
        .expect_err("a key the owner never enrolled is no lost key");
    assert_refused(&refused, "is not a live owner key the owner enrolled");
    assert_eq!(fixture.history().len(), rows, "the refusal writes no row");
    assert_eq!(
        fixture.hold_view(&hold).state,
        RecoveryHoldState::Due,
        "the hold still waits to land"
    );
    assert!(!fixture.live(&new), "the successor is not enrolled");

    let answer = fixture
        .recover_wait(
            WAIT,
            fixture.released_material(0),
            RootSuccessor::Device(fixture.enrollment(&new_key)),
            &[],
        )
        .expect("the lawful call lands the hold");
    assert!(
        matches!(answer, RootRecovery::Vouched { .. }),
        "the call completes its own hold: {answer:?}"
    );
    assert_eq!(fixture.hold_view(&hold).state, RecoveryHoldState::Landed);
    assert!(fixture.live(&new), "the successor is enrolled");
}

/// A refused hold attempt for this install's key leaves this install's
/// owner signing slot as it was (row
/// RECOVERY-HOLD-BOX-PATH-WRITES-BEFORE-CHECKS): the door judges the request
/// before the slot takes a fresh key. The slot's key is revoked, so a new
/// attempt makes a fresh key; a call that names a lost key the owner never
/// enrolled is refused, and the slot keeps its old key. A lawful attempt
/// then holds for a fresh key, the slot takes it, and the box call after
/// the wait lands it and answers `Vouched`. It fails on main
/// `2c56ee802949`, where the door renewed the slot before it judged the
/// lost keys.
#[test]
fn a_refused_hold_attempt_leaves_this_installs_slot_as_it_was() {
    let fixture = fixture();
    let install_key = revoke_this_installs_key(&fixture);
    let stranger = key_of(&SigningKey::from_bytes(&[STRANGER_KEY_SEED; 32]));
    let rows = fixture.history().len();

    let refused = fixture
        .recover_wait(
            WAIT,
            fixture.released_material(0),
            RootSuccessor::ThisInstall,
            std::slice::from_ref(&stranger),
        )
        .expect_err("a key the owner never enrolled is no lost key");
    assert_refused(&refused, "is not a live owner key the owner enrolled");
    assert_eq!(fixture.history().len(), rows, "the refusal writes no row");
    assert!(fixture.holds().is_empty(), "no hold was written");
    assert_eq!(
        slot_key(&fixture),
        install_key,
        "the slot keeps its old key"
    );

    let (hold, lands_at) = held(
        fixture
            .recover_wait(
                WAIT,
                fixture.released_material(0),
                RootSuccessor::ThisInstall,
                &[],
            )
            .expect("the lawful attempt holds"),
    );
    let successor = fixture.hold_view(&hold).successor_key;
    assert_ne!(successor, install_key, "the hold names a fresh key");
    assert_eq!(slot_key(&fixture), successor, "the slot took the fresh key");

    fixture.at(lands_at + 60);
    let RootRecovery::Vouched { enrollment, .. } = fixture
        .recover_wait(
            WAIT,
            fixture.released_material(0),
            RootSuccessor::ThisInstall,
            &[],
        )
        .expect("the box call after the wait")
    else {
        panic!("the call lands this install's hold and answers Vouched");
    };
    assert_eq!(AuthorityKey::Ed25519(enrollment.public_key), successor);
    assert!(fixture.live(&successor), "this install's fresh key is live");
}

/// The vouch arm makes this install's fresh key in memory and the slot
/// takes it as the last step before the commit (row
/// RECOVERY-HOLD-BOX-PATH-WRITES-BEFORE-CHECKS): a zero wait recovery for
/// this install while its slot's key is revoked enrols a fresh key, which
/// the slot then holds and this install signs with.
#[test]
fn a_vouch_for_this_install_with_a_revoked_key_enrols_the_slots_fresh_key() {
    let fixture = fixture();
    let install_key = revoke_this_installs_key(&fixture);

    let RootRecovery::Vouched { enrollment, .. } = fixture
        .recover_wait(
            NO_WAIT,
            fixture.released_material(0),
            RootSuccessor::ThisInstall,
            &[],
        )
        .expect("the root's key vouches for a fresh key of this install")
    else {
        panic!("a zero wait vouches");
    };
    let fresh = AuthorityKey::Ed25519(enrollment.public_key);
    assert_ne!(fresh, install_key, "a fresh key");
    assert_eq!(slot_key(&fixture), fresh, "the slot holds the fresh key");
    assert!(fixture.live(&fresh), "the fresh key is live");
}

/// A successor key is held for one owner at a time (row
/// RECOVERY-HOLD-BOX-PATH-WRITES-BEFORE-CHECKS): while the co-Owner's hold
/// for a device key waits, the first owner's box call with the same root
/// key and the same device key is refused and writes nothing, and after the
/// wait the first owner's call lands the co-Owner's due hold but never
/// answers its enrolment as the first owner's. It fails on main
/// `2c56ee802949`, where the first owner's call answered the co-Owner's
/// hold as `Held`.
#[test]
fn another_owners_hold_for_the_successor_key_is_never_the_owners() {
    let fixture = co_owner_wait_fixture();
    fixture.enrol_root_key();
    let new_key = SigningKey::from_bytes(&[NEW_KEY_SEED; 32]);
    let new = key_of(&new_key);
    let (hold, lands_at) = held(
        fixture
            .recover_wait(
                WAIT,
                fixture.released(),
                RootSuccessor::Device(fixture.enrollment(&new_key)),
                &[],
            )
            .expect("the co-Owner's box recovery holds"),
    );
    let first_owner = proof(&fixture.vault, fixture.first_owner);
    let first_owners_input = || {
        let public_key = new_key.verifying_key().to_bytes();
        let challenge = fixture
            .vault
            .owner_key_enrollment_challenge_as(
                &fixture.first_owner_authority(),
                fixture.machine,
                &public_key,
            )
            .expect("the first owner's challenge");
        OwnerKeyEnrollment {
            machine: fixture.machine,
            public_key,
            proof: new_key.sign(&challenge).to_bytes().to_vec(),
        }
    };
    let first_owners_call = || {
        recover_owner_root_waiting(
            &fixture.vault,
            &first_owner,
            ActSurface::ThisInstall,
            fixture.released(),
            RootSuccessor::Device(first_owners_input()),
            &[],
            WAIT,
        )
    };
    let rows = fixture.history().len();

    let refused = first_owners_call().expect_err("the co-Owner's hold is not the first owner's");
    assert_refused(
        &refused,
        "another owner's recovery waits for this successor key",
    );
    assert_eq!(fixture.history().len(), rows, "the refusal writes no row");
    assert_eq!(
        fixture.hold_view(&hold).state,
        RecoveryHoldState::Waiting,
        "the co-Owner's hold waits on"
    );

    fixture.at(lands_at + 60);
    let answer = first_owners_call();
    assert!(
        !matches!(answer, Ok(RootRecovery::Vouched { .. })),
        "the co-Owner's enrolment is never the first owner's: {answer:?}"
    );
    let view = fixture.hold_view(&hold);
    assert_eq!(view.owner, fixture.person, "the hold is the co-Owner's");
    assert_eq!(view.state, RecoveryHoldState::Landed, "the due hold landed");
    assert!(fixture.live(&new), "the successor is enrolled");
}

/// A hold the log would refuse leaves this install's owner signing slot as
/// it was (REVIEW-10327 round 2 P1 1): a box that gives R out at second 0
/// makes a hold that lands at 0, which no hold row carries. The slot's key
/// is revoked, so the attempt would make a fresh key; the call is refused
/// before the slot takes it, writes no row and no hold, and the slot keeps
/// its old key. It fails on `a7a9486fe5f7`, where the first write renewed
/// the slot and only the hold row's own check refused the zero second.
#[test]
fn a_hold_the_log_refuses_leaves_this_installs_slot_as_it_was() {
    let fixture = fixture();
    let install_key = revoke_this_installs_key(&fixture);
    let rows = fixture.history().len();

    fixture
        .recover_wait(
            WAIT,
            fixture.released_after_box_wait(0, 0),
            RootSuccessor::ThisInstall,
            &[],
        )
        .expect_err("a hold that lands at second 0 is no hold row");
    assert_eq!(fixture.history().len(), rows, "the refusal writes no row");
    assert!(fixture.holds().is_empty(), "no hold was written");
    assert_eq!(
        slot_key(&fixture),
        install_key,
        "the slot keeps its old key"
    );
}

impl CoOwner {
    /// The first owner enrols the kit root's authority key, so the
    /// co-Owner's removal, which ends the co-Owner's owner keys, leaves it
    /// live.
    fn enrol_root_key_as_first_owner(&self) -> AuthorityKey {
        let receipt = self
            .vault
            .enrol_recovery_authority_key_as_host(
                &self.first_owner_authority(),
                self.machine,
                &self.seed,
                &self.issuer,
            )
            .expect("the first owner enrols the root's authority key");
        AuthorityKey::Ed25519(receipt.public_key)
    }

    /// The first owner removes the co-Owner, at once.
    fn remove_co_owner(&self) {
        let first_owner = proof(&self.vault, self.first_owner);
        let act = self
            .vault
            .propose_remove_owner(&first_owner, SHARED, self.person, None, None, false)
            .expect("the first owner starts remove_owner");
        self.vault
            .execute_completed_shared_act(&first_owner, &act.id, Some(&self.issuer))
            .expect("remove_owner runs at once");
    }

    /// `key`'s enrolment input for this vault and the first owner, with its
    /// proof of possession.
    fn first_owners_enrollment(&self, key: &SigningKey) -> OwnerKeyEnrollment {
        let public_key = key.verifying_key().to_bytes();
        let challenge = self
            .vault
            .owner_key_enrollment_challenge_as(
                &self.first_owner_authority(),
                self.machine,
                &public_key,
            )
            .expect("the first owner's challenge");
        OwnerKeyEnrollment {
            machine: self.machine,
            public_key,
            proof: key.sign(&challenge).to_bytes().to_vec(),
        }
    }
}

/// A hold whose owner is no Owner now holds no successor key against
/// another owner (REVIEW-10327 round 2 P1 2): the co-Owner's hold for a
/// device key waits under the root's key, which the first owner enrolled,
/// and the first owner then removes the co-Owner. The root's key stays
/// live; at the end of the wait the landing voids the hold and enrols
/// nothing. The first owner's box call for the same device key then holds
/// for the first owner. It fails on `a7a9486fe5f7`, where the voided hold
/// still read as due and refused the first owner's call as another
/// owner's.
#[test]
fn a_removed_owners_hold_never_holds_the_successor_key_against_another_owner() {
    let fixture = co_owner_wait_fixture();
    let root_key = fixture.enrol_root_key_as_first_owner();
    let new_key = SigningKey::from_bytes(&[NEW_KEY_SEED; 32]);
    let new = key_of(&new_key);
    let (hold, lands_at) = held(
        fixture
            .recover_wait(
                WAIT,
                fixture.released(),
                RootSuccessor::Device(fixture.enrollment(&new_key)),
                &[],
            )
            .expect("the co-Owner's box recovery holds"),
    );
    fixture.remove_co_owner();
    assert!(fixture.live(&root_key), "the root's key stays live");

    fixture.at(lands_at + 60);
    let voided = fixture
        .land()
        .into_iter()
        .find(|landing| landing.hold == hold)
        .expect("the landing reads the co-Owner's hold");
    assert_eq!(
        voided.state,
        RecoveryHoldState::Void,
        "its owner is no Owner now"
    );
    assert!(voided.enrollment.is_none(), "a void hold enrols nothing");
    assert!(!fixture.live(&new), "the successor is not enrolled");

    let first_owner = proof(&fixture.vault, fixture.first_owner);
    let (own, _) = held(
        recover_owner_root_waiting(
            &fixture.vault,
            &first_owner,
            ActSurface::ThisInstall,
            fixture.released(),
            RootSuccessor::Device(fixture.first_owners_enrollment(&new_key)),
            &[],
            WAIT,
        )
        .expect("the removed co-Owner's hold is no live hold"),
    );
    assert_ne!(own, hold, "a new hold");
    let view = fixture.hold_view(&own);
    assert_eq!(
        view.owner, fixture.first_owner,
        "the hold is the first owner's"
    );
    assert_eq!(view.state, RecoveryHoldState::Waiting);
}

/// Writes a hold that R signs by hand, a shape no door writes: the owner's
/// recovery to `successor` with `lost` as its lost keys and its wait over
/// at `lands_at`. Then puts R's seed in this install's hold slot for
/// `successor`, as the door's hold attempt does. Answers the hold's entry
/// hash, which the fold counts.
fn hold_signed_by_hand(
    fixture: &Fixture,
    successor: &SigningKey,
    lost: Vec<AuthorityKey>,
    lands_at: u64,
) -> AuthorityEntryHash {
    let root_seed = released_authority_seed(&fixture.seed(), &fixture.vault_id, 0);
    let r_signing = SigningKey::from_bytes(&root_seed);
    let root_key = key_of(&r_signing);
    let input = fixture.enrollment(successor);
    let mut row = AuthorityLogEntry {
        schema_version: AUTHORITY_LOG_SCHEMA_VERSION,
        vault_id: Some(fixture.vault_id),
        seq: fixture.next_seq(&root_key),
        parent_hashes: fixture.heads(),
        op: AuthorityOp::RecoveryHold(RecoveryHold {
            owner: fixture.person,
            enrolment: RecoveryHoldEnrolment {
                machine: input.machine,
                public_key: input.public_key,
                proof: input.proof,
            },
            lost,
            lands_at,
        }),
        signer: AuthoritySignature {
            suite: root_key.suite(),
            public_key: root_key.clone(),
            signature: vec![0; 64],
        },
        cosigns: Vec::new(),
        ts: T0,
        overlay_seed: None,
    };
    let transcript = authority_transcript(&row).expect("the transcript");
    row.signer.signature = r_signing.sign(&transcript).to_bytes().to_vec();
    let hash = authority_entry_hash(&row).expect("a hash");
    fixture
        .vault
        .import_signed_authority_history(&[
            encode_authority_log_entry_body(&row).expect("the bytes")
        ])
        .expect("the import stores the hold");
    assert!(
        fixture
            .vault
            .authority_fold()
            .expect("the fold")
            .valid_entries
            .contains(&hash),
        "the fold counts the hold R signed by hand"
    );
    stage_orphan_recovery_hold_seed(&fixture.vault, input.public_key, &root_seed)
        .expect("R's seed goes in the hold's slot");
    hash
}

/// A hold that names R itself among its lost keys lands as the door's
/// rule reads it (row RECOVERY-HOLD-LOST-KEY-RULE-AT-FOLD): the owner's own
/// lost key is revoked, the successor is enrolled under R, and R stays
/// live, since the door never names R lost.
#[test]
fn a_hold_that_names_its_root_key_lost_lands_with_the_root_key_live() {
    let fixture = fixture();
    let root_key = AuthorityKey::Ed25519(fixture.generation_key(0));
    let lost_key = key_of(&fixture.enrol_device_key(LOST_KEY_SEED));
    let new_key = SigningKey::from_bytes(&[NEW_KEY_SEED; 32]);
    let new = key_of(&new_key);
    let lands_at = T0 + WAIT.as_secs();
    let hold = hold_signed_by_hand(
        &fixture,
        &new_key,
        vec![lost_key.clone(), root_key.clone()],
        lands_at,
    );
    assert_eq!(
        fixture.hold_view(&hold).state,
        RecoveryHoldState::Waiting,
        "the hold waits"
    );

    fixture.at(lands_at + 60);
    let landings = fixture.land();
    assert_eq!(landings.len(), 1, "the due hold lands");
    assert_eq!(landings[0].hold, hold);
    assert_eq!(landings[0].state, RecoveryHoldState::Landed);
    assert_eq!(
        landings[0].revoked.len(),
        1,
        "one revocation: the owner's lost key alone"
    );
    assert!(fixture.live(&root_key), "R stays live");
    assert!(!fixture.live(&lost_key), "the owner's lost key is revoked");
    assert!(fixture.live(&new), "the successor is enrolled");
    assert_eq!(fixture.hold_view(&hold).state, RecoveryHoldState::Landed);
}

/// A hold whose lost keys name a live key that is no owner key of its
/// owner, here an agent-only device, never revokes that key at its landing
/// (row RECOVERY-HOLD-LOST-KEY-RULE-AT-FOLD): the door refuses such a key
/// as lost ("is not a live owner key the owner enrolled"), and the landing
/// reads the same rule.
#[test]
fn a_hold_never_revokes_a_lost_key_that_is_no_owner_key_of_its_owner() {
    let fixture = fixture();
    let lost_key = key_of(&fixture.enrol_device_key(LOST_KEY_SEED));
    let keeper = fixture.enrol_device_key(KEEPER_KEY_SEED);
    let keeper_key = key_of(&keeper);
    let new_key = SigningKey::from_bytes(&[NEW_KEY_SEED; 32]);
    let new = key_of(&new_key);
    // An agent-only device, enrolled by a crafted row an owner key signs,
    // as `an_agent_key_never_answers_a_hold` enrols it.
    let agent_key = key_of(&SigningKey::from_bytes(&[AGENT_KEY_SEED; 32]));
    let mut enroll = AuthorityLogEntry {
        schema_version: AUTHORITY_LOG_SCHEMA_VERSION,
        vault_id: Some(fixture.vault_id),
        seq: fixture.next_seq(&keeper_key),
        parent_hashes: fixture.heads(),
        op: AuthorityOp::EnrollDevice {
            device: agent_device(AGENT_KEY_SEED),
        },
        signer: AuthoritySignature {
            suite: keeper_key.suite(),
            public_key: keeper_key.clone(),
            signature: vec![0; 64],
        },
        cosigns: Vec::new(),
        ts: T0,
        overlay_seed: None,
    };
    enroll.overlay_seed = oneiron_authority::authority::authority_overlay_seed_for(&enroll.op)
        .expect("authority overlay seed");
    let transcript = authority_transcript(&enroll).expect("the transcript");
    enroll.signer.signature = keeper.sign(&transcript).to_bytes().to_vec();
    fixture
        .vault
        .import_signed_authority_history(&[
            encode_authority_log_entry_body(&enroll).expect("the bytes")
        ])
        .expect("the import stores the enrolment");
    assert!(fixture.live(&agent_key), "the agent key is enrolled");

    let refused = fixture
        .recover_wait(
            WAIT,
            fixture.released_material(0),
            RootSuccessor::Device(fixture.enrollment(&new_key)),
            &[lost_key.clone(), agent_key.clone()],
        )
        .expect_err("the door never names an agent key lost");
    assert_refused(&refused, "is not a live owner key the owner enrolled");

    let lands_at = T0 + WAIT.as_secs();
    let hold = hold_signed_by_hand(
        &fixture,
        &new_key,
        vec![lost_key.clone(), agent_key.clone()],
        lands_at,
    );
    fixture.at(lands_at + 60);
    let landings = fixture.land();
    assert_eq!(landings.len(), 1, "the due hold lands");
    assert_eq!(landings[0].hold, hold);
    assert_eq!(landings[0].state, RecoveryHoldState::Landed);
    assert_eq!(
        landings[0].revoked.len(),
        1,
        "one revocation: the owner's lost key alone"
    );
    assert!(fixture.live(&agent_key), "the agent key stays live");
    assert!(!fixture.live(&lost_key), "the owner's lost key is revoked");
    assert!(fixture.live(&keeper_key), "the keeper is untouched");
    assert!(fixture.live(&new), "the successor is enrolled");
}
