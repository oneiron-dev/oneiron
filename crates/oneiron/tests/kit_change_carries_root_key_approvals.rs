//! A kit change carries the old R's live approvals (OPUS-WAYBACK, Engine RULING
//! 16 Nov 07:13): the act that revokes an R (a new kit's activation; the
//! kit-only rotation) carries R's live approvals in the same write, as a host
//! re-root carries its standings (`carry_machine_standing_in_txn`): the new R
//! signs the next revision of each live act-free roster standing the old R
//! signed, and signs each live binding the old R signed again.
//!
//! Tests with the clock 24 h past each event (restore with kit A, confirm kit
//! B / switch to kit-only: the machine still carries, its wrap counts, the
//! root door's binding stands). Also one guard: a standing the old R signed
//! that was already revoked or stale is NOT carried.
//!
//! Red before the carry (R4 PR 2 at ceeb4058e14a; the kit-only rotation PR
//! at 824e4bda79a9): each kit-change test fails at its post-24 h assertion,
//! because every approval the revoked R signed goes stale 24 h + 1 s after
//! the revocation is first seen (`stale_roster.rs`, window
//! `DEFAULT_STALE_ROSTER_WINDOW_SECS`): the restored machine's roster head
//! turns `stale` (not live), and the root door's binding turns `Revoked`. The
//! guard passes there, since no carry exists yet, and must still pass after.
//!
//! Green with the carry: each kit-change test passes (the new R carried the
//! standing / the binding in the same write as the revocation, so 24 h later
//! it is still live and still counts), and the guard still passes (a removed
//! standing is not carried).
//!
//! Time: each vault opens on a `ManualClock` (`config.store_clock =
//! clock.bundle()`), all setup runs at `T0`, and authority time moves with
//! `clock.set(now)` plus `vault.advance_authority_clock_for_test(now)` and a
//! fresh `authority_fold()`. The margin is 60 s, not 1 s: the stale deadline
//! is `min(approval_seen, revoked_seen) + window + 1`, so `T0 + window + 60`
//! is safely past it despite floor/anchor rounding.
//!
//! Data key: a checkpoint-restored copy holds the vault's data key locked,
//! and both kit changes need it held (a kit confirm writes the key's
//! `world-kit` escrow wrap; the switch to kit-only draws a sheet from it).
//! So the source sets a vault password before the checkpoint, and the fresh
//! machine unlocks with it after its kit restore.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test kit_change_carries_root_key_approvals`.
#![cfg(oneiron_test_support)]

use std::collections::BTreeSet;
use std::sync::Arc;

use ed25519_dalek::{Signer, SigningKey};
use oneiron::authority::{
    ActAuthority, ActSurface, ActorBindingStatus, AuthorityKey, AuthorityLogEntry, AuthorityOp,
    EnrolledOwnerKeyKind, HostSlipIssuer, MachineOwnership, MachineRole, OwnerKeyEnrollment,
    ReadLocation, RootMaterial, RootRecovery, RootSuccessor, WorldPrivacy,
    decode_authority_log_entry_body,
};
use oneiron::consent::AuthenticatedOwner;
use oneiron::federation::{FederationGrantRole, InitialSharedMember};
use oneiron::memory::MEMORY_CODE_OWNER_BINDING_REQUIRED;
use oneiron::recovery::checkpoint::RestoreReason;
use oneiron::recovery::{
    CodeKeeping, KitIssue, KitSecretKind, PassphraseCost, PieceHome, issue_recovery_root_kit,
    restore_kit,
};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::store::GateDecisionId;
use oneiron::store::ports::ManualClock;
use oneiron::store::recovery_kit::KitPiece;
use oneiron::test_support::{bind_host_owner, provision_engine_machines, restore_tempdir};
use oneiron::world_keys::{
    ConfirmedWorldKit, IssuedWorldKit, KitConfirmation, NoRecoveryBox, RecoveryPreset,
    RecoveryRootId, RecoveryRootSeed, WorldKitRestore,
};
use oneiron::{EdgeActorClass, EntityId, HostingPrivacyPosture, TimeRange, Vault, VaultConfig};

/// Authority wall time for all setup: every first-seen lands here.
const T0: u64 = 1_800_000_000;
/// The stale-roster window (`DEFAULT_STALE_ROSTER_WINDOW_SECS`): 24 h.
const WINDOW_SECS: u64 = 24 * 60 * 60;
/// Margin past the window: 60 s, not 1 s, so the `+ window + 1` deadline is
/// safely passed (see the module doc).
const MARGIN_SECS: u64 = 60;
/// The source's vault password, which the fresh machine unlocks the data
/// key with (see the module doc).
const PASSWORD: &[u8] = b"correct horse battery staple";

/// The co-Owner fixture's shared vault id.
const SHARED: u64 = 44;
/// The seed of the co-Owner's first owner key, which binds them and is lost.
const CO_OWNER_LOST_SEED: u8 = 51;
/// The seed of the root door's successor key.
const NEW_KEY_SEED: u8 = 41;

fn proof(vault: &Vault, person: EntityId) -> AuthenticatedOwner {
    vault
        .authenticate_owner(person, &person.to_hex(), true, GateDecisionId::now())
        .expect("an owner proof")
}

fn keep_on_my_machines() -> WorldPrivacy {
    WorldPrivacy {
        read: ReadLocation::MyMachines,
        ..WorldPrivacy::default()
    }
}

fn rows(vault: &Vault) -> Vec<AuthorityLogEntry> {
    vault
        .export_signed_authority_history()
        .expect("the history")
        .iter()
        .map(|bytes| decode_authority_log_entry_body(bytes).expect("a row"))
        .collect()
}

/// `seed` rebuilt from two stored pieces of a kit issued for it: the owner's
/// restore (copied from `owner_root_recovery.rs`).
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

/// Whether `person` passes the owner verbs: a live `human` binding names
/// them (copied from `owner_root_recovery.rs`).
fn passes_owner_verbs(vault: &Vault, person: EntityId) -> bool {
    match vault.memory(person, EdgeActorClass::Human).verify_owner() {
        Ok(()) => true,
        Err(error) => {
            assert_eq!(error.code, MEMORY_CODE_OWNER_BINDING_REQUIRED, "{error:?}");
            false
        }
    }
}

/// Moves authority time to `T0 + window + margin` on `vault`: the wall clock
/// plus the persisted floor, then a fresh fold observes it.
fn advance_past_window(vault: &Vault, clock: &Arc<ManualClock>) {
    let now = T0 + WINDOW_SECS + MARGIN_SECS;
    clock.set(now);
    vault
        .advance_authority_clock_for_test(now)
        .expect("the authority clock moves past the window");
    vault.authority_fold().expect("the fold at the new time");
}

/// Every `MachineProfile` row for `machine` on `vault`: roster rows and the
/// anchor's marks alike (both use the same op; the carry writes a roster
/// row, so any carry grows this list).
fn machine_rows_for(vault: &Vault, machine: EntityId) -> Vec<AuthorityLogEntry> {
    rows(vault)
        .into_iter()
        .filter(|row| {
            matches!(&row.op, AuthorityOp::MachineProfile(profile) if profile.machine == machine)
        })
        .collect()
}

/// A self-hosted source vault on a manual clock, whose host seed this install
/// holds, with its data key. `issuer` is kept so a fresh install (whose own
/// slot is empty) can enrol its device key under it.
struct Source {
    dir: tempfile::TempDir,
    vault: Vault,
    clock: Arc<ManualClock>,
    issuer: HostSlipIssuer,
    person: EntityId,
}

fn source() -> Source {
    let clock = ManualClock::new(T0);
    let dir = restore_tempdir();
    let mut config = VaultConfig::device();
    config.store_clock = clock.bundle();
    let vault = Vault::open(dir.path().join("source"), config).expect("the source vault");
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
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
    vault.ensure_vault_key().expect("the vault's data key");
    vault
        .set_vault_key_password(PASSWORD, None)
        .expect("a password wrap of the data key");
    Source {
        dir,
        vault,
        clock,
        issuer,
        person,
    }
}

impl Source {
    fn owner(&self) -> AuthenticatedOwner {
        proof(&self.vault, self.person)
    }

    fn issue(&self) -> IssuedWorldKit {
        let vault_id = self
            .vault
            .authority_fold()
            .expect("the fold")
            .vault_id
            .expect("a rooted vault");
        self.vault
            .issue_world_kit(
                &self.owner(),
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
            .expect("a kit")
    }

    fn confirm(&self, issued: &IssuedWorldKit) -> ConfirmedWorldKit {
        let pieces: Vec<&KitPiece> = issued.pieces.iter().take(2).collect();
        self.vault
            .confirm_world_kit(&self.owner(), &pieces, None, &BTreeSet::new())
            .expect("the kit confirms")
    }

    fn world(&self, name: &str) -> EntityId {
        self.vault
            .create_world(&self.owner(), name, self.vault.now_recorded_at())
            .expect("a world")
    }

    /// The one live R, kind `RecoveryAuthority`.
    fn live_r(&self) -> AuthorityKey {
        let live = self.live_rs();
        assert_eq!(live.len(), 1, "one live R");
        live.into_iter().next().expect("one live R")
    }

    /// Every live R, kind `RecoveryAuthority`.
    fn live_rs(&self) -> Vec<AuthorityKey> {
        self.vault
            .enrolled_owner_keys()
            .expect("the list")
            .into_iter()
            .filter(|key| key.kind == EnrolledOwnerKeyKind::RecoveryAuthority && key.live)
            .map(|key| AuthorityKey::Ed25519(key.public_key))
            .collect()
    }

    /// Whether `key` is on the roster and not revoked.
    fn is_live(&self, key: &AuthorityKey) -> bool {
        self.vault
            .authority_fold()
            .expect("the fold")
            .roster
            .get(key)
            .is_some_and(|device| !device.revoked)
    }

    /// A fresh machine of this vault on the same manual clock: a direct
    /// checkpoint restore, which joins as a new machine, unpinned, with an
    /// empty keystore of its own.
    fn fresh(&self) -> Fresh {
        let key = self.vault.checkpoint_key().expect("the checkpoint key");
        let image = self.dir.path().join("image");
        self.vault
            .snapshot_checkpoint(&image, 100)
            .expect("the checkpoint");
        let mut config = VaultConfig::device();
        config.store_clock = self.clock.bundle();
        let (vault, _) = Vault::restore_checkpoint(
            &image,
            &key,
            &self.dir.path().join("fresh"),
            config,
            RestoreReason::Restore,
            200,
        )
        .expect("the fresh machine's copy of the vault");
        vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
        Fresh {
            vault,
            person: self.person,
            clock: Arc::clone(&self.clock),
        }
    }
}

struct Fresh {
    vault: Vault,
    person: EntityId,
    clock: Arc<ManualClock>,
}

impl Fresh {
    fn owner(&self) -> AuthenticatedOwner {
        proof(&self.vault, self.person)
    }

    fn authority(&self) -> ActAuthority {
        ActAuthority::Owner(self.owner(), ActSurface::ThisInstall)
    }

    /// The kit restore from `issued`'s pieces, the owner carrying `root`'s
    /// fingerprint.
    fn restore(
        &self,
        issued: &IssuedWorldKit,
        root: RecoveryRootId,
    ) -> oneiron::Result<WorldKitRestore> {
        let pieces: Vec<&KitPiece> = issued.pieces.iter().take(2).collect();
        self.vault.restore_world_kit(
            &self.owner(),
            &pieces,
            None,
            Some(KitConfirmation::Fingerprint(root)),
        )
    }

    /// The data key held on this handle: the restored copy holds it locked,
    /// and a kit confirm or the switch to kit-only needs it held.
    fn unlock_data_key(&self) {
        self.vault
            .unlock_vault_key_with_password(PASSWORD)
            .expect("the source's password opens the data key here");
    }

    /// A world kit issued on this install (for kit B where the roster row
    /// lives).
    fn issue(&self) -> IssuedWorldKit {
        let vault_id = self
            .vault
            .authority_fold()
            .expect("the fold")
            .vault_id
            .expect("a rooted vault");
        self.vault
            .issue_world_kit(
                &self.owner(),
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
            .expect("a kit")
    }

    fn confirm(&self, issued: &IssuedWorldKit) -> oneiron::Result<ConfirmedWorldKit> {
        let pieces: Vec<&KitPiece> = issued.pieces.iter().take(2).collect();
        self.vault
            .confirm_world_kit(&self.owner(), &pieces, None, &BTreeSet::new())
    }

    /// Every live R, kind `RecoveryAuthority`.
    fn live_rs(&self) -> Vec<AuthorityKey> {
        self.vault
            .enrolled_owner_keys()
            .expect("the list")
            .into_iter()
            .filter(|key| key.kind == EnrolledOwnerKeyKind::RecoveryAuthority && key.live)
            .map(|key| AuthorityKey::Ed25519(key.public_key))
            .collect()
    }

    /// The one live R, kind `RecoveryAuthority`.
    fn live_r(&self) -> AuthorityKey {
        let live = self.live_rs();
        assert_eq!(live.len(), 1, "one live R");
        live.into_iter().next().expect("one live R")
    }

    /// Whether `key` is on the roster and not revoked.
    fn is_live(&self, key: &AuthorityKey) -> bool {
        self.vault
            .authority_fold()
            .expect("the fold")
            .roster
            .get(key)
            .is_some_and(|device| !device.revoked)
    }

    /// This install's machine and its install key.
    fn me(&self) -> (EntityId, [u8; 32]) {
        let vault_id = self
            .vault
            .authority_fold()
            .expect("the fold")
            .vault_id
            .expect("a rooted vault");
        let encryption = self
            .vault
            .machine_encryption_key(vault_id)
            .expect("this install's encryption key");
        let request = self
            .vault
            .machine_enrolment_request(vault_id, encryption)
            .expect("this install's request");
        (request.machine, request.machine_key)
    }

    /// The roster's chain names this install live, `Owned(Yours)`, with its
    /// install key, signed by `r`.
    fn assert_on_roster_by(&self, r: &AuthorityKey) {
        let (machine, key) = self.me();
        let fold = self.vault.authority_fold().expect("the fold");
        let roster = fold
            .machine(machine)
            .and_then(|folded| folded.roster.as_ref())
            .expect("the roster's chain names the restored machine");
        assert!(roster.is_live(), "the roster revision is live: {roster:?}");
        assert_eq!(roster.profile.machine_key, key, "with its install key");
        assert_eq!(
            roster.profile.role,
            MachineRole::Owned(MachineOwnership::Yours)
        );
        assert_eq!(&roster.signer, r, "the kit's R signs it");
    }

    /// One owner act this install carries: `world` kept on the owner's
    /// machines, its key minted and wrapped here.
    fn keep_on_my_machines(&self, world: EntityId) -> oneiron::Result<()> {
        self.vault
            .set_world_privacy_as(
                &self.owner(),
                ActSurface::ThisInstall,
                world,
                keep_on_my_machines(),
                None,
            )
            .map(drop)
    }
}

/// A self-hosted shared vault on a manual clock, whose embedded owner the
/// host root binds, with a co-Owner the owner added. The co-Owner's first
/// owner key (`lost_key`) binds them as `human`. The root's authority key R
/// is enrolled by the embedded owner (so a kit the embedded owner confirms
/// revokes it), and the co-Owner recovers through it.
struct CoOwner {
    _dir: tempfile::TempDir,
    vault: Vault,
    clock: Arc<ManualClock>,
    issuer: HostSlipIssuer,
    owner: EntityId,
    co_owner: EntityId,
    vault_id: [u8; 32],
    machine: EntityId,
    lost_key: SigningKey,
    seed: RecoveryRootSeed,
}

fn co_owner_fixture() -> CoOwner {
    let clock = ManualClock::new(T0);
    let dir = tempfile::tempdir().expect("tempdir");
    let mut config = VaultConfig::device();
    config.privacy.posture = HostingPrivacyPosture::SelfHostLocal;
    config.store_clock = clock.bundle();
    let vault = Vault::open(dir.path(), config).expect("the vault");
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    let issuer = provision_engine_machines(&vault);
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
    let lost_key = SigningKey::from_bytes(&[CO_OWNER_LOST_SEED; 32]);
    let seed = restored(
        vault_id,
        &RecoveryRootSeed::generate().expect("a root seed"),
    );
    let fixture = CoOwner {
        _dir: dir,
        vault,
        clock,
        issuer,
        owner,
        co_owner,
        vault_id,
        machine,
        lost_key,
        seed,
    };
    let input = fixture.enrollment_as(&fixture.co_owner_authority(), &fixture.lost_key);
    fixture
        .vault
        .enrol_owner_signing_key_as_host(&fixture.co_owner_authority(), input, &fixture.issuer)
        .expect("the co-Owner enrols their first owner key");
    fixture
}

impl CoOwner {
    fn owner_proof(&self) -> AuthenticatedOwner {
        proof(&self.vault, self.owner)
    }

    fn co_owner_proof(&self) -> AuthenticatedOwner {
        proof(&self.vault, self.co_owner)
    }

    fn owner_authority(&self) -> ActAuthority {
        ActAuthority::Owner(self.owner_proof(), ActSurface::ThisInstall)
    }

    fn co_owner_authority(&self) -> ActAuthority {
        ActAuthority::Owner(self.co_owner_proof(), ActSurface::ThisInstall)
    }

    /// `key`'s enrolment input for this vault under `authority`, with its
    /// proof of possession.
    fn enrollment_as(&self, authority: &ActAuthority, key: &SigningKey) -> OwnerKeyEnrollment {
        let public_key = key.verifying_key().to_bytes();
        let challenge = self
            .vault
            .owner_key_enrollment_challenge_as(authority, self.machine, &public_key)
            .expect("the challenge");
        OwnerKeyEnrollment {
            machine: self.machine,
            public_key,
            proof: key.sign(&challenge).to_bytes().to_vec(),
        }
    }

    /// The embedded owner enrols the kit root's authority key before the
    /// loss. Enrolled by the embedded owner so a kit the embedded owner
    /// confirms (host root predecessor) revokes it; the co-Owner recovers
    /// through it (the vouch checks the key is live, not whose it is).
    fn enrol_root_key_as_owner(&self) -> AuthorityKey {
        let receipt = self
            .vault
            .enrol_recovery_authority_key_as_host(
                &self.owner_authority(),
                self.machine,
                &self.seed,
                &self.issuer,
            )
            .expect("the owner enrols the root's authority key");
        AuthorityKey::Ed25519(receipt.public_key)
    }

    fn kit(&self) -> RootMaterial {
        RootMaterial::Kit {
            seed: restored(self.vault_id, &self.seed),
            confirm: None,
        }
    }

    /// A world kit issued by the embedded owner. This install holds no host
    /// seed (the fixture's host issuer lives in memory only), so its
    /// activation needs this install's device key as the predecessor.
    fn issue_world_kit(&self) -> IssuedWorldKit {
        self.vault
            .issue_world_kit(
                &self.owner_proof(),
                &KitIssue {
                    vault_id: self.vault_id,
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
            .expect("a kit")
    }

    fn confirm_world_kit(&self, issued: &IssuedWorldKit) -> oneiron::Result<ConfirmedWorldKit> {
        let pieces: Vec<&KitPiece> = issued.pieces.iter().take(2).collect();
        self.vault
            .confirm_world_kit(&self.owner_proof(), &pieces, None, &BTreeSet::new())
    }

    fn is_live(&self, key: &AuthorityKey) -> bool {
        self.vault
            .authority_fold()
            .expect("the fold")
            .roster
            .get(key)
            .is_some_and(|device| !device.revoked)
    }
}

/// Test 1: a new kit's activation keeps the kit-restored machine standing.
///
/// Fixture: kit A confirmed on the source; a fresh install restores with kit
/// A (`R_A` puts it on the roster); kit B is issued and confirmed on the
/// fresh install, where the roster row lives, under this install's device key
/// (enrolled under the source's host root, which the checkpoint carried live
/// onto the fresh fold). Then the clock moves 24 h + 60 s past the confirm.
///
/// Red before the carry: fails at `assert!(roster.is_live())`, because
/// `R_A` was revoked by kit B's activation, nothing carried its roster row,
/// and the row went stale 24 h + 1 s after the revocation was first seen; the
/// owner act then refuses too (no live carrier). Green after the build: kit
/// B's activation carries the standing in the same write (the new R signs the
/// next revision), so the standing is still live and the next owner act
/// stands.
#[test]
fn a_new_kits_activation_keeps_the_kit_restored_machine_standing() {
    let source = source();
    let issued_a = source.issue();
    let confirmed_a = source.confirm(&issued_a);
    let r_a = source.live_r();
    let world = source.world("Another world");
    let fresh = source.fresh();

    let restored = fresh
        .restore(&issued_a, confirmed_a.activated.root)
        .expect("the kit restores on the fresh machine");
    assert!(
        restored.keys.usable.is_empty(),
        "no private world: {:?}",
        restored.keys
    );
    fresh.assert_on_roster_by(&r_a);
    fresh.unlock_data_key();

    // Kit B needs a predecessor on the fresh install, whose own host slot is
    // empty: this install's device key, enrolled under the source's host
    // root, which the checkpoint holds live on the fresh fold.
    fresh
        .vault
        .enrol_device_owner_signing_key(&fresh.authority(), &source.issuer)
        .expect("the fresh install enrols its device key");
    let issued_b = fresh.issue();
    fresh
        .confirm(&issued_b)
        .expect("kit B confirms on the fresh install");
    assert!(!fresh.is_live(&r_a), "kit A's R is revoked");
    let live = fresh.live_rs();
    assert_eq!(live.len(), 1, "one live R: kit B's");
    assert_ne!(live[0], r_a);

    advance_past_window(&fresh.vault, &fresh.clock);

    let (machine, _) = fresh.me();
    let roster = fresh
        .vault
        .authority_fold()
        .expect("the fold")
        .machine(machine)
        .and_then(|folded| folded.roster.clone())
        .expect("the roster's chain names the restored machine");
    assert!(
        roster.is_live(),
        "the restored machine's standing is still live 24 h past kit B: {roster:?}"
    );
    fresh
        .keep_on_my_machines(world)
        .expect("the next owner act stands, carried by the restored machine");
    fresh
        .vault
        .world_key(world)
        .expect("the owner act's new key opens here");
}

/// Test 2: a new kit's activation keeps the binding the root door signed.
///
/// Fixture: the `co_owner_fixture` flow, with R enrolled by the embedded
/// owner: the co-Owner's lost key held their `human` binding, R's root door
/// revokes it and enrols the successor, whose enrolment binds the co-Owner
/// again through a `BindActor` signed by R. Then the embedded owner enrols
/// this install's device key and confirms a new kit on that self-hosted vault
/// (the device key is its predecessor), which revokes R. Then +24 h + 60 s.
///
/// Red before the carry: fails at the binding assertion
/// (`assert_eq!(bound, Some(co_owner))`), because the `BindActor` R signed
/// went stale 24 h + 1 s after R's revocation, so the successor's binding is
/// `Revoked` and the co-Owner fails the owner verbs. Green after the build:
/// the new R signs the live binding again in the same write (`RebindActor`
/// at epoch + 1), so the binding is still active and the co-Owner keeps owner
/// control.
#[test]
fn a_new_kits_activation_keeps_the_binding_the_root_door_signed() {
    let fixture = co_owner_fixture();
    assert!(
        passes_owner_verbs(&fixture.vault, fixture.co_owner),
        "the co-Owner's first owner key binds them"
    );
    let r = fixture.enrol_root_key_as_owner();
    let new_key = SigningKey::from_bytes(&[NEW_KEY_SEED; 32]);
    let new_public = AuthorityKey::Ed25519(new_key.verifying_key().to_bytes());
    let lost = AuthorityKey::Ed25519(fixture.lost_key.verifying_key().to_bytes());

    let answer = fixture
        .vault
        .recover_owner_root(
            &fixture.co_owner_proof(),
            ActSurface::ThisInstall,
            fixture.kit(),
            RootSuccessor::Device(fixture.enrollment_as(&fixture.co_owner_authority(), &new_key)),
            std::slice::from_ref(&lost),
        )
        .expect("the root's key vouches");
    let RootRecovery::Vouched { enrollment, .. } = answer else {
        panic!("the root's live authority key vouches");
    };
    assert_eq!(AuthorityKey::Ed25519(enrollment.public_key), new_public);
    assert!(!fixture.is_live(&lost), "the lost key is revoked");
    assert!(fixture.is_live(&r), "the root's key stays live");
    let bound = fixture
        .vault
        .authority_fold()
        .expect("the fold")
        .actor_bindings
        .get(&new_public)
        .filter(|binding| {
            binding.status == ActorBindingStatus::Active && binding.actor_class == "human"
        })
        .map(|binding| binding.actor_ref);
    assert_eq!(
        bound,
        Some(fixture.co_owner),
        "the new key binds the co-Owner"
    );
    assert!(
        passes_owner_verbs(&fixture.vault, fixture.co_owner),
        "the co-Owner keeps owner control"
    );

    // Kit B's activation needs a predecessor: the embedded owner enrols this
    // install's device key first (see `issue_world_kit`).
    fixture
        .vault
        .enrol_device_owner_signing_key(&fixture.owner_authority(), &fixture.issuer)
        .expect("the owner enrols this install's device key");
    let issued_b = fixture.issue_world_kit();
    fixture
        .confirm_world_kit(&issued_b)
        .expect("kit B confirms on the self-hosted vault");
    assert!(!fixture.is_live(&r), "kit B revokes the old R");

    advance_past_window(&fixture.vault, &fixture.clock);

    let still_bound = fixture
        .vault
        .authority_fold()
        .expect("the fold")
        .actor_bindings
        .get(&new_public)
        .filter(|binding| {
            binding.status == ActorBindingStatus::Active && binding.actor_class == "human"
        })
        .map(|binding| binding.actor_ref);
    assert_eq!(
        still_bound,
        Some(fixture.co_owner),
        "the successor's binding is still active 24 h past kit B"
    );
    assert!(
        passes_owner_verbs(&fixture.vault, fixture.co_owner),
        "the co-Owner keeps owner control 24 h past kit B"
    );
}

/// Test 3: switching to kit-only keeps the kit-restored machine standing.
///
/// Fixture: as test 1, but the kit change is the kit-only switch with the kit
/// present (rotation 0 -> 1) on the fresh install, instead of kit B. No device
/// key is needed: the live R itself signs the rotation.
///
/// Red before the carry: fails at `assert!(roster.is_live())`, because
/// generation 0 was revoked by the switch, nothing carried its roster row,
/// and the row went stale 24 h + 1 s after the revocation was first seen; the
/// owner act then refuses too. Green after the build: the switch carries the
/// standing in the same write (generation 1 signs the next revision), so the
/// standing is still live and the next owner act stands.
#[test]
fn switching_to_kit_only_keeps_the_kit_restored_machine_standing() {
    let source = source();
    let issued = source.issue();
    let confirmed = source.confirm(&issued);
    let gen0 = source.live_r();
    let world = source.world("Another world");
    let fresh = source.fresh();

    fresh
        .restore(&issued, confirmed.activated.root)
        .expect("the kit restores on the fresh machine");
    fresh.assert_on_roster_by(&gen0);
    fresh.unlock_data_key();

    let pieces: Vec<&KitPiece> = issued.pieces.iter().take(2).collect();
    fresh
        .vault
        .set_recovery_preset_with_kit_as(
            &fresh.authority(),
            RecoveryPreset::NobodyButMe,
            &pieces,
            None,
            |_| Ok(()),
            &NoRecoveryBox,
        )
        .expect("the switch to kit-only with the kit");
    let gen1 = fresh.live_r();
    assert_ne!(gen1, gen0, "the switch rotates R");
    assert!(!fresh.is_live(&gen0), "generation 0 is revoked");

    advance_past_window(&fresh.vault, &fresh.clock);

    let (machine, _) = fresh.me();
    let roster = fresh
        .vault
        .authority_fold()
        .expect("the fold")
        .machine(machine)
        .and_then(|folded| folded.roster.clone())
        .expect("the roster's chain names the restored machine");
    assert!(
        roster.is_live(),
        "the restored machine's standing is still live 24 h past the switch: {roster:?}"
    );
    fresh
        .keep_on_my_machines(world)
        .expect("the next owner act stands, carried by the restored machine");
    fresh
        .vault
        .world_key(world)
        .expect("the owner act's new key opens here");
}

/// Test 4 (the guard): a standing the old R signed but already removed is not
/// carried.
///
/// Fixture: kit A confirmed on the source; a fresh install restores with kit
/// A (`R_A` puts its machine `M1` on the roster); the source imports the
/// fresh rows, so it holds `M1` live (R-signed) beside its own machine (the
/// carrier); the owner removes `M1` on the source; kit B is confirmed on the
/// source (its device key, enrolled for the removal, is the predecessor; the
/// carrier stands because only the remote machine was removed). Then +24 h +
/// 60 s.
///
/// Green before the carry and green with it: a removed head is
/// never live, and no carry may write a new revision for it. It fails after
/// the build only if the build wrongly carries a removed standing (a third
/// `MachineProfile` row for `M1`, or a live head).
#[test]
fn a_standing_the_old_root_key_signed_but_already_removed_is_not_carried() {
    let source = source();
    let issued_a = source.issue();
    let confirmed_a = source.confirm(&issued_a);
    let r_a = source.live_r();
    let fresh = source.fresh();

    fresh
        .restore(&issued_a, confirmed_a.activated.root)
        .expect("the kit restores on the fresh machine");
    fresh.assert_on_roster_by(&r_a);
    let (removed_machine, _) = fresh.me();

    // The source takes the fresh rows it does not hold yet, so the kit change
    // below sees the R-signed standing. Only the remote machine is removed,
    // so this install (the source's own machine) still carries.
    let held: BTreeSet<Vec<u8>> = source
        .vault
        .export_signed_authority_history()
        .expect("the source history")
        .into_iter()
        .collect();
    let new: Vec<Vec<u8>> = fresh
        .vault
        .export_signed_authority_history()
        .expect("the fresh history")
        .into_iter()
        .filter(|row| !held.contains(row))
        .collect();
    assert!(
        !new.is_empty(),
        "the fresh install wrote rows the source does not hold"
    );
    source
        .vault
        .import_signed_authority_history(&new)
        .expect("the source takes the fresh rows");
    let live = source
        .vault
        .authority_fold()
        .expect("the fold")
        .machine(removed_machine)
        .and_then(|folded| folded.roster.clone())
        .expect("the source holds the restored machine");
    assert!(
        live.is_live(),
        "the restored machine is live here: {live:?}"
    );
    assert_eq!(&live.signer, &r_a, "the kit's R signs it");

    // The removal is an owner answer carried by this install (a HostedNode,
    // not mine), so it needs an owner key's proof to stand rather than wait:
    // this install enrols its device key first.
    source
        .vault
        .enrol_device_owner_signing_key(
            &ActAuthority::Owner(source.owner(), ActSurface::ThisInstall),
            &source.issuer,
        )
        .expect("the source enrols its device key");
    let landing = source
        .vault
        .set_machine_role(
            &source.owner(),
            ActSurface::ThisInstall,
            removed_machine,
            MachineRole::Removed,
            None,
        )
        .expect("the owner removes the restored machine");
    assert!(
        landing.held().is_none(),
        "the removal stands, it does not wait for a proof"
    );
    let removed = source
        .vault
        .authority_fold()
        .expect("the fold")
        .machine(removed_machine)
        .and_then(|folded| folded.roster.clone())
        .expect("the roster still names the removed machine");
    assert!(removed.removed, "the machine is removed: {removed:?}");
    assert!(!removed.is_live(), "a removed standing is not live");
    let rows_before = machine_rows_for(&source.vault, removed_machine);

    let issued_b = source.issue();
    source.confirm(&issued_b);
    assert!(!source.is_live(&r_a), "kit A's R is revoked");
    let live = source.live_rs();
    assert_eq!(live.len(), 1, "one live R: kit B's");
    let r_b = live.into_iter().next().expect("kit B's R");

    advance_past_window(&source.vault, &source.clock);

    let after = source
        .vault
        .authority_fold()
        .expect("the fold")
        .machine(removed_machine)
        .and_then(|folded| folded.roster.clone())
        .expect("the roster still names the removed machine");
    assert!(
        !after.is_live(),
        "a removed standing stays not live 24 h past kit B: {after:?}"
    );
    assert!(after.removed, "still removed: {after:?}");
    let rows_after = machine_rows_for(&source.vault, removed_machine);
    assert_eq!(
        rows_after.len(),
        rows_before.len(),
        "no new roster revision names the removed machine: {rows_after:?}"
    );
    assert!(
        rows_after.iter().all(|row| row.signer_key() != &r_b),
        "the new R signs no revision of the removed machine: {rows_after:?}"
    );
    let max_revision: u64 = rows_after
        .iter()
        .filter_map(|row| match &row.op {
            AuthorityOp::MachineProfile(profile) => Some(profile.revision),
            _ => None,
        })
        .max()
        .expect("the removed machine keeps its rows");
    assert!(
        max_revision <= removed.profile.revision,
        "no revision above the removal: {rows_after:?}"
    );
}
