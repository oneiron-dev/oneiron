//! A recovery hold and its answers past an adopted checkpoint image (row
//! RECOVERY-HOLD-ROWS-PAST-ADOPTED-IMAGE, OPUS-WAYBACK).
//!
//! A replica that adopted an image holds the covered rows only through it:
//! the image carries each hold's and each answer's body, and the hold view
//! reads them there. A hold or an answer signed past the image is a tail
//! row there, and the fold past the image took neither kind
//! (`fold_resume::admits_past`), so the replica's fold asked for the whole
//! history: a kit's Cancel of a hold only the image carries never counted
//! on the replica. Both kinds now fold past the image: each moves only its
//! signer's sequence, and its judge reads only its parents' roster and
//! recovery root keys.
//!
//! The fixture: the home vault of `owner_root_recovery_wait.rs` (a host
//! root, the owner bound, a confirmed world kit whose root key R is live).
//! Its two owner roots (the host root and R) need one attestation, the
//! host's, so the image the home writes is pinned at once. An empty replica
//! of the same vault adopts that image, as `authority_log_owner_reserve_adopted.rs`
//! adopts one, and stores one row the home signed past it, as sync carries a
//! row.
//!
//! Red on main `1b32efa6512f` (by reading): the replica's fold of the tail
//! row asks for the history (`AuthorityHistoryRequired`, reason
//! `OpNotFoldedPast`), so each test fails at its fold. Green on the head.
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test recovery_hold_adopted_image`.
#![cfg(oneiron_test_support)]

use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Duration;

use ed25519_dalek::{Signer, SigningKey};
use oneiron::authority::{
    ActAuthority, ActSurface, AuthorityCheckpointV2, AuthorityEntryHash, AuthorityEntryStatus,
    AuthorityFold, AuthorityKey, AuthorityLogEntry, AuthorityOp, HostSlipIssuer, MachineRole,
    OwnerKeyEnrollment, RecoveryHoldAnswerKind, RecoveryHoldState, RecoveryHoldView, RootMaterial,
    RootRecovery, RootSuccessor, authority_entry_hash, decode_authority_log_entry_body,
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
use oneiron::{EntityId, OpenOptions, TimeRange, Vault, VaultConfig, VaultStorageId};
use oneiron_keystore::MemoryKeystore;
use oneiron_store::ports::manual_clock::ManualClock;

/// The instant every vault opens at.
const T0: u64 = 1_790_000_000;
/// The wait the holds take: one hour.
const WAIT: Duration = Duration::from_secs(60 * 60);
/// The seed of the successor key a hold names.
const NEW_KEY_SEED: u8 = 41;
/// The challenge the home's pin answers.
const PIN_CHALLENGE: [u8; 32] = [7; 32];

fn proof(vault: &Vault, person: EntityId) -> AuthenticatedOwner {
    vault
        .authenticate_owner(person, &person.to_hex(), true, GateDecisionId::now())
        .expect("an owner proof")
}

fn key_of(signing: &SigningKey) -> AuthorityKey {
    AuthorityKey::Ed25519(signing.verifying_key().to_bytes())
}

fn held(answer: RootRecovery) -> (AuthorityEntryHash, u64) {
    let RootRecovery::Held { hold, lands_at } = answer else {
        panic!("the box recovery holds with a nonzero wait");
    };
    (hold, lands_at)
}

fn live(state: RecoveryHoldState) -> bool {
    matches!(state, RecoveryHoldState::Waiting | RecoveryHoldState::Due)
}

/// The home vault: a confirmed world kit (generation 0 live), on a clock
/// the test holds. As `owner_root_recovery_wait.rs`'s fixture.
struct Fixture {
    _dir: tempfile::TempDir,
    vault: Vault,
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

    /// The kit's live root key R (generation 0), via the box's bytes.
    fn root_key(&self) -> AuthorityKey {
        let seed = self.seed();
        AuthorityKey::Ed25519(
            SigningKey::from_bytes(&released_authority_seed(&seed, &self.vault_id, 0))
                .verifying_key()
                .to_bytes(),
        )
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

    /// The box's release of R: a box recovery holds with it.
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

    /// A box recovery that holds for `successor`, losing no key.
    fn hold(&self, successor: &SigningKey) -> (AuthorityEntryHash, u64) {
        held(
            recover_owner_root_waiting(
                &self.vault,
                &self.owner(),
                ActSurface::ThisInstall,
                self.released_material(),
                RootSuccessor::Device(self.enrollment(successor)),
                &[],
                WAIT,
            )
            .expect("the box recovery holds on the home vault"),
        )
    }

    fn hold_view(&self, hold: &AuthorityEntryHash) -> RecoveryHoldView {
        self.vault
            .recovery_holds()
            .expect("the holds")
            .into_iter()
            .find(|view| view.hold == *hold)
            .expect("the home reads the hold")
    }

    /// The one stored row of the home's history that `pick` takes, by its
    /// hash and its body.
    fn the_row(
        &self,
        pick: impl Fn(&AuthorityEntryHash, &AuthorityLogEntry) -> bool,
    ) -> AuthorityLogEntry {
        let mut rows: Vec<AuthorityLogEntry> = self
            .vault
            .export_signed_authority_history()
            .expect("the signed history")
            .iter()
            .map(|body| decode_authority_log_entry_body(body).expect("a row"))
            .filter(|row| pick(&authority_entry_hash(row).expect("a hash"), row))
            .collect();
        assert_eq!(rows.len(), 1, "FIXTURE: exactly one such row on the home");
        rows.remove(0)
    }

    /// The home's image of every row it holds now, written and attested by
    /// the host, adopted by an empty replica of the vault on its own clock
    /// and keystore.
    fn adopted_replica(&self) -> Replica {
        let image_id = self
            .vault
            .write_authority_checkpoint_v2(&self.issuer)
            .expect("the home writes and attests its image");
        let pin = self
            .vault
            .authority_checkpoint_pin(PIN_CHALLENGE)
            .expect("the pin")
            .expect(
                "FIXTURE: the host's attestation reaches the image's quorum (two owner roots, the \
                 host root and R)",
            );
        assert_eq!(pin.checkpoint, image_id, "FIXTURE: the pin names the image");
        let bundle = self
            .vault
            .authority_checkpoint_bundle(&image_id)
            .expect("the bundle")
            .expect("FIXTURE: the home keeps the image");
        let image = self
            .vault
            .authority_checkpoint_v2(&image_id)
            .expect("the image")
            .expect("FIXTURE: the home keeps the image");
        let clock = ManualClock::new(T0);
        let dir = tempfile::tempdir().expect("tempdir");
        let mut config = VaultConfig::device();
        config.store_clock = clock.bundle();
        let vault = Vault::open_owned_with(
            dir.path(),
            config,
            OpenOptions::default().adopt_storage_id(VaultStorageId::from_verified_pin(&pin)),
        )
        .expect("the replica opens");
        vault.install_device_keystore(Arc::new(MemoryKeystore::default()));
        let adopted = match image.building_pin {
            Some(root) => vault.adopt_recovered_authority_checkpoint(
                &pin,
                &bundle.image,
                &bundle.attestations,
                pin.digest().expect("the pin's digest"),
                root,
            ),
            None => vault.adopt_authority_checkpoint(&pin, &bundle.image, &bundle.attestations),
        };
        assert_eq!(
            adopted.expect("the replica adopts the home's image"),
            image_id
        );
        vault
            .authority_fold()
            .expect("FIXTURE: the replica's empty tail folds past its image");
        Replica {
            _dir: dir,
            vault,
            image,
        }
    }
}

/// A replica of the home vault that adopted the home's image and stores no
/// row of the history the image covers.
struct Replica {
    _dir: tempfile::TempDir,
    vault: Vault,
    image: AuthorityCheckpointV2,
}

impl Replica {
    /// Stores `row`, signed on the home past the image, as sync carries it:
    /// a tail row whose parents the image covers.
    fn carry(&self, row: &AuthorityLogEntry) {
        assert!(
            row.parent_hashes
                .iter()
                .all(|parent| self.image.rows.contains_key(parent)),
            "FIXTURE: the row stands on rows the image covers"
        );
        self.vault
            .put_authority_log_entry(row, TimeRange { start: T0, end: T0 }, T0)
            .expect("the replica stores the row");
    }

    /// The replica's fold: the image and the tail row, with no history of
    /// the covered rows.
    fn fold(&self) -> AuthorityFold {
        self.vault.authority_fold().unwrap_or_else(|error| {
            panic!(
                "the replica's fold past its adopted image asks for the history the image \
                 covers: {error}"
            )
        })
    }

    fn hold_view(&self, hold: &AuthorityEntryHash) -> RecoveryHoldView {
        self.vault
            .recovery_holds()
            .expect("the replica's holds")
            .into_iter()
            .find(|view| view.hold == *hold)
            .expect("the replica reads the hold")
    }
}

/// The hold row itself past the image: R signs it on the home after the
/// image, and the replica folds it there and reads the hold live, as the
/// home does.
#[test]
fn a_hold_signed_past_an_adopted_checkpoint_folds_there() {
    let fixture = fixture();
    let replica = fixture.adopted_replica();
    let new_key = SigningKey::from_bytes(&[NEW_KEY_SEED; 32]);
    let (hold, lands_at) = fixture.hold(&new_key);
    let row = fixture.the_row(|hash, _| *hash == hold);
    assert!(
        matches!(row.op, AuthorityOp::RecoveryHold(_)),
        "FIXTURE: the hold's row"
    );
    assert!(
        !replica.image.rows.contains_key(&hold),
        "FIXTURE: the image does not cover the hold"
    );

    replica.carry(&row);
    let fold = replica.fold();
    assert!(
        fold.valid_entries.contains(&hold),
        "the replica's fold counts the hold past its image"
    );
    let view = replica.hold_view(&hold);
    assert_eq!(view.root_key, fixture.root_key(), "R signed the hold");
    assert_eq!(view.successor_key, key_of(&new_key));
    assert_eq!(view.lands_at, lands_at);
    assert_eq!(view.owner, fixture.person);
    assert!(live(view.state), "the hold is live: {:?}", view.state);
    assert!(view.answered_by.is_empty(), "no answer yet");
}

/// The hold inside the image, its Cancel past it: the kit's live root key R
/// cancels the hold on the home, and the replica, which holds the hold only
/// through its adopted image, folds that Cancel and reads the hold
/// Cancelled by the owner the kit's R was enrolled for.
#[test]
fn a_kit_cancel_reaches_a_hold_only_an_adopted_checkpoint_carries() {
    let fixture = fixture();
    let root_key = fixture.root_key();
    let new_key = SigningKey::from_bytes(&[NEW_KEY_SEED; 32]);
    let (hold, _) = fixture.hold(&new_key);
    let replica = fixture.adopted_replica();
    assert!(
        replica
            .image
            .rows
            .get(&hold)
            .is_some_and(|row| row.body.is_some()),
        "FIXTURE: the image covers the hold and carries its body"
    );
    assert!(
        matches!(
            replica
                .vault
                .authority_log_entry_status(&hold)
                .expect("the hold's status"),
            AuthorityEntryStatus::CoveredAttested { .. }
        ),
        "FIXTURE: the replica holds the hold through the image alone, no raw row"
    );
    assert!(
        live(replica.hold_view(&hold).state),
        "FIXTURE: the replica reads the carried hold live"
    );

    fixture
        .vault
        .cancel_recovery_holds_with_kit_as(
            &fixture.authority(),
            &fixture.kit_refs(),
            None,
            Some(hold),
        )
        .expect("the kit cancels the live hold on the home");
    assert_eq!(
        fixture.hold_view(&hold).state,
        RecoveryHoldState::Cancelled,
        "FIXTURE: the home reads the hold cancelled"
    );
    let cancel = fixture.the_row(|_, row| {
        matches!(&row.op, AuthorityOp::RecoveryHoldAnswer(answer)
            if answer.hold == hold && answer.answer == RecoveryHoldAnswerKind::Cancel)
    });
    assert_eq!(
        cancel.signer_key(),
        &root_key,
        "FIXTURE: the kit's live root key R signs the Cancel"
    );
    let cancel_hash = authority_entry_hash(&cancel).expect("a hash");

    replica.carry(&cancel);
    let fold = replica.fold();
    assert!(
        fold.valid_entries.contains(&cancel_hash),
        "the replica's fold counts the kit's Cancel past its image"
    );
    let view = replica.hold_view(&hold);
    assert_eq!(
        view.state,
        RecoveryHoldState::Cancelled,
        "the kit's Cancel reaches the hold the replica holds only through its image"
    );
    assert_eq!(view.answered_by, vec![root_key]);
    assert_eq!(
        view.cancelled_by,
        vec![fixture.person],
        "the kit's Cancel names the owner its R was enrolled for"
    );
}
