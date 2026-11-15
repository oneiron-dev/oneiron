//! Kit-only rotation (WAYBACK-KIT-ONLY-AUTHORITY-KEY = B): switching to
//! "Nobody but me" with the kit rotates the root's authority key R (generation
//! k+1 enrolled, generation k revoked, in the same write as the preset
//! change); old kits read as generation 0; while kit-only holds the root door
//! refuses `RootMaterial::Released`.
//!
//! Red on R4 PR 2's head `d6e43e3ea7ea`: the file does not compile there (no
//! `set_recovery_preset_with_kit_as`, `set_recovery_preset_any_two_with_kit_as`
//! or `NoRecoveryBox`).
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test kit_only_authority_rotation`.
#![cfg(oneiron_test_support)]

use std::cell::RefCell;
use std::collections::BTreeSet;
use std::sync::Arc;

use ed25519_dalek::{Signer, SigningKey};
use oneiron::authority::{
    ActAuthority, ActSurface, AuthorityKey, AuthorityLogEntry, AuthorityOp, DeviceAuthority,
    EnrolledOwnerKeyKind, HostSlipIssuer, MachineRole, RootMaterial, RootRecovery, RootSuccessor,
    authority_entry_hash, decode_authority_log_entry_body,
};
use oneiron::authority::{AuthorityAttestation, AuthorityTier, ROLE_OWNER};
use oneiron::consent::AuthenticatedOwner;
use oneiron::recovery::{
    CodeKeeping, KitIssue, KitSecretKind, PassphraseCost, PieceHome, restore_kit,
};
use oneiron::store::GateDecisionId;
use oneiron::test_doors::root_recovery::released_authority_seed;
use oneiron::test_support::{bind_host_owner, provision_engine_machines};
use oneiron::world_keys::{NoRecoveryBox, RecoveryBoxHold, RecoveryPreset, RecoveryRootSeed};
use oneiron::{EntityId, ErrorKind, HostingPrivacyPosture, Vault, VaultConfig};

/// Decision 5 words, asserted with `contains`.
const KIT_ONLY_NEEDS_KIT: &str = "switching to Nobody but me needs your recovery kit, so the key the recovery box could release is replaced; bring the kit; nothing was written";
const RELEASED_UNDER_KIT_ONLY: &str = "under Nobody but me the recovery box holds nothing; bring your recovery kit; nothing was written";
const KIT_NOT_THIS_VAULTS: &str =
    "this recovery kit does not hold this vault's live way back; nothing was written";

/// Seeds for the lost device key and the root door's successor.
const LOST_KEY_SEED: u8 = 21;
const NEW_KEY_SEED: u8 = 41;
/// Seed for the ReRoot successor.
const REROOT_SEED: u8 = 42;

fn proof(vault: &Vault, person: EntityId) -> AuthenticatedOwner {
    vault
        .authenticate_owner(person, &person.to_hex(), true, GateDecisionId::now())
        .expect("an owner proof")
}

fn key_of(signing: &SigningKey) -> AuthorityKey {
    AuthorityKey::Ed25519(signing.verifying_key().to_bytes())
}

/// A software device with the owner role alone, keyed by `seed`'s key.
fn owner_device(seed: u8) -> DeviceAuthority {
    DeviceAuthority {
        key: key_of(&SigningKey::from_bytes(&[seed; 32])),
        transport_key_binding: [7; 32],
        attestation: AuthorityAttestation {
            kind: "SoftwareArgon2id".to_owned(),
            evidence: vec![1, 2, 3],
        },
        tier: AuthorityTier::Software,
        roles: ROLE_OWNER,
    }
}

/// A self-hosted vault with host seed, owner bound, data key held, and a
/// confirmed world kit (generation 0 live). Based on
/// `kit_activation_enrols_authority_key.rs` plus `ensure_vault_key`.
struct Fixture {
    _dir: tempfile::TempDir,
    vault: Vault,
    issuer: HostSlipIssuer,
    person: EntityId,
    machine: EntityId,
    vault_id: [u8; 32],
    pieces: Vec<oneiron::store::recovery_kit::KitPiece>,
}

fn fixture() -> Fixture {
    let fixture = issued_fixture();
    let refs = fixture.kit_refs();
    fixture
        .vault
        .confirm_world_kit(&fixture.owner(), &refs, None, &BTreeSet::new())
        .expect("the kit confirms");
    fixture
}

/// [`fixture`] with the world kit issued but not confirmed: no generation is
/// live yet.
fn issued_fixture() -> Fixture {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("the vault");
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
    Fixture {
        _dir: dir,
        vault,
        issuer,
        person,
        machine,
        vault_id,
        pieces: issued.pieces,
    }
}

impl Fixture {
    fn owner(&self) -> AuthenticatedOwner {
        proof(&self.vault, self.person)
    }

    fn authority(&self) -> ActAuthority {
        ActAuthority::Owner(self.owner(), ActSurface::ThisInstall)
    }

    fn kit_refs(&self) -> Vec<&oneiron::store::recovery_kit::KitPiece> {
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
    fn enrollment(&self, key: &SigningKey) -> oneiron::authority::OwnerKeyEnrollment {
        let public_key = key.verifying_key().to_bytes();
        let challenge = self
            .vault
            .owner_key_enrollment_challenge_as(&self.authority(), self.machine, &public_key)
            .expect("the challenge");
        oneiron::authority::OwnerKeyEnrollment {
            machine: self.machine,
            public_key,
            proof: key.sign(&challenge).to_bytes().to_vec(),
        }
    }

    /// Enrols a lost device key (not this install's) under the host root.
    fn enrol_lost_key(&self, seed: u8) -> SigningKey {
        let key = SigningKey::from_bytes(&[seed; 32]);
        self.vault
            .enrol_owner_signing_key_as_host(&self.authority(), self.enrollment(&key), &self.issuer)
            .expect("the owner enrols a device key");
        key
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

    fn row(&self, entry: &oneiron::authority::AuthorityEntryHash) -> AuthorityLogEntry {
        self.history()
            .into_iter()
            .find(|row| authority_entry_hash(row).expect("a hash") == *entry)
            .expect("the row is stored")
    }

    /// Switches to `NobodyButMe` with the kit (the CLI's kept-sheet shape).
    fn switch_with_kit(&self) -> oneiron::Result<oneiron::world_keys::RecoveryPresetChange> {
        self.vault.set_recovery_preset_with_kit_as(
            &self.authority(),
            RecoveryPreset::NobodyButMe,
            &self.kit_refs(),
            None,
            |_| Ok(()),
            &NoRecoveryBox,
        )
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
            oneiron::world_keys::RecoveryAuthoritySigner::from_released_seed(
                released_authority_seed(&seed, &self.vault_id, generation),
                &self.vault_id,
                root,
            )
            .expect("the released key"),
        )
    }
}

/// The enrolled rows of kind `RecoveryAuthority`, live and revoked.
fn authority_rows(fixture: &Fixture) -> Vec<oneiron::authority::EnrolledOwnerKey> {
    fixture
        .vault
        .enrolled_owner_keys()
        .expect("the list")
        .into_iter()
        .filter(|key| key.kind == EnrolledOwnerKeyKind::RecoveryAuthority)
        .collect()
}

#[test]
fn the_switch_with_the_kit_enrols_generation_1_and_revokes_generation_0_in_one_write() {
    let fixture = fixture();
    let gen0 = fixture.generation_key(0);
    assert!(
        authority_rows(&fixture)
            .iter()
            .any(|key| key.public_key == gen0 && key.live),
        "generation 0 is live before the switch"
    );
    let history = fixture.history().len();

    let change = fixture.switch_with_kit().expect("the switch with the kit");
    assert_eq!(change.previous, RecoveryPreset::Standard);
    assert_eq!(change.preset, RecoveryPreset::NobodyButMe);
    assert_eq!(
        fixture.vault.recovery_preset().expect("the preset"),
        RecoveryPreset::NobodyButMe,
        "the preset is NobodyButMe after"
    );

    let gen1 = fixture.generation_key(1);
    let rows = authority_rows(&fixture);
    assert!(
        rows.iter().any(|key| key.public_key == gen1 && key.live),
        "generation 1 is enrolled live, kind RecoveryAuthority"
    );
    assert!(
        rows.iter().any(|key| key.public_key == gen0 && !key.live),
        "generation 0 is revoked"
    );
    assert_eq!(
        fixture.history().len(),
        history + 2,
        "one OwnerKeyEnroll and one RevokeDevice in one write"
    );
}

#[test]
fn the_kitless_switch_while_generation_0_is_live_is_refused_and_writes_nothing() {
    let fixture = fixture();
    let before_roster = fixture.vault.authority_fold().expect("the fold").roster;
    let before_history = fixture.history().len();
    let hold = RecordingBoxHold::default();

    let refused = fixture
        .vault
        .set_recovery_preset_as(
            &fixture.owner(),
            RecoveryPreset::NobodyButMe,
            |_| Ok(()),
            &hold,
        )
        .expect_err("the kitless switch while live is refused");
    assert!(
        hold.calls.borrow().is_empty(),
        "a switch refused before the hold makes no hold call"
    );
    assert_eq!(refused.kind(), ErrorKind::AuthorityRefused, "{refused}");
    assert!(
        refused.to_string().contains(KIT_ONLY_NEEDS_KIT),
        "the exact words: {refused}"
    );
    assert_eq!(
        fixture.vault.recovery_preset().expect("the preset"),
        RecoveryPreset::Standard,
        "the preset is still Standard"
    );
    assert_eq!(
        fixture.vault.authority_fold().expect("the fold").roster,
        before_roster,
        "the roster is unchanged"
    );
    assert_eq!(
        fixture.history().len(),
        before_history,
        "the history is unchanged"
    );
}

#[test]
fn the_same_kit_recovers_ownership_after_the_rotation_through_the_kit_arm() {
    let fixture = fixture();
    let lost = fixture.enrol_lost_key(LOST_KEY_SEED);
    let lost_key = key_of(&lost);
    fixture.switch_with_kit().expect("the rotation");
    let gen1 = AuthorityKey::Ed25519(fixture.generation_key(1));

    let new_key = SigningKey::from_bytes(&[NEW_KEY_SEED; 32]);
    let answer = fixture
        .vault
        .recover_owner_root(
            &fixture.owner(),
            ActSurface::ThisInstall,
            fixture.kit_material(),
            RootSuccessor::Device(fixture.enrollment(&new_key)),
            std::slice::from_ref(&lost_key),
        )
        .expect("the same kit recovers after the rotation");
    let RootRecovery::Vouched {
        enrollment,
        revoked,
    } = answer
    else {
        panic!("the kit's live generation vouches");
    };
    assert_eq!(
        AuthorityKey::Ed25519(enrollment.public_key),
        key_of(&new_key)
    );
    let enrolment = fixture.row(&enrollment.entry);
    assert!(matches!(enrolment.op, AuthorityOp::OwnerKeyEnroll(_)));
    assert_eq!(
        enrolment.signer_key(),
        &gen1,
        "generation 1 vouches the enrolment"
    );
    assert_eq!(revoked.len(), 1);
    let revocation = fixture.row(&revoked[0]);
    assert!(
        matches!(&revocation.op, AuthorityOp::RevokeDevice { revoked_key } if revoked_key == &lost_key),
        "the revocation names the lost key"
    );
    assert_eq!(
        revocation.signer_key(),
        &gen1,
        "generation 1 signs the revocation"
    );
    assert!(fixture.live(&key_of(&new_key)));
    assert!(!fixture.live(&lost_key));
}

#[test]
fn box_material_is_refused_under_kit_only_and_writes_nothing() {
    let fixture = fixture();
    fixture.enrol_lost_key(LOST_KEY_SEED);
    fixture.switch_with_kit().expect("the rotation");
    let before_roster = fixture.vault.authority_fold().expect("the fold").roster;
    let before_history = fixture.history().len();
    let new_key = SigningKey::from_bytes(&[NEW_KEY_SEED; 32]);
    let lost = key_of(&SigningKey::from_bytes(&[LOST_KEY_SEED; 32]));

    for generation in [0, 1] {
        let refused = fixture
            .vault
            .recover_owner_root(
                &fixture.owner(),
                ActSurface::ThisInstall,
                fixture.released_material(generation),
                RootSuccessor::Device(fixture.enrollment(&new_key)),
                std::slice::from_ref(&lost),
            )
            .expect_err("released material is refused under kit-only");
        assert_eq!(refused.kind(), ErrorKind::AuthorityRefused, "{refused}");
        assert!(
            refused.to_string().contains(RELEASED_UNDER_KIT_ONLY),
            "generation {generation}: the exact words: {refused}"
        );
    }
    assert_eq!(
        fixture.vault.recovery_preset().expect("the preset"),
        RecoveryPreset::NobodyButMe,
        "the preset still holds"
    );
    assert_eq!(
        fixture.vault.authority_fold().expect("the fold").roster,
        before_roster,
        "the roster is unchanged"
    );
    assert_eq!(
        fixture.history().len(),
        before_history,
        "the history is unchanged"
    );
}

#[test]
fn switching_back_to_standard_changes_no_roster_and_released_1_serves() {
    let fixture = fixture();
    let lost = fixture.enrol_lost_key(LOST_KEY_SEED);
    let lost_key = key_of(&lost);
    fixture.switch_with_kit().expect("the rotation");
    let gen0 = AuthorityKey::Ed25519(fixture.generation_key(0));
    let gen1 = AuthorityKey::Ed25519(fixture.generation_key(1));

    let back = fixture
        .vault
        .set_recovery_preset_as(
            &fixture.owner(),
            RecoveryPreset::Standard,
            |_| Ok(()),
            &NoRecoveryBox,
        )
        .expect("the switch back");
    assert_eq!(back.previous, RecoveryPreset::NobodyButMe);
    assert_eq!(back.preset, RecoveryPreset::Standard);
    assert!(fixture.live(&gen1), "generation 1 stays live");
    assert!(!fixture.live(&gen0), "generation 0 stays revoked");

    let new_key = SigningKey::from_bytes(&[NEW_KEY_SEED; 32]);
    let refused = fixture
        .vault
        .recover_owner_root(
            &fixture.owner(),
            ActSurface::ThisInstall,
            fixture.released_material(0),
            RootSuccessor::Device(fixture.enrollment(&new_key)),
            std::slice::from_ref(&lost_key),
        )
        .expect_err("released generation 0 is not live");
    assert_eq!(refused.kind(), ErrorKind::AuthorityRefused, "{refused}");
    assert!(
        refused.to_string().contains("not a live owner key"),
        "released 0 is refused as not live: {refused}"
    );

    let answer = fixture
        .vault
        .recover_owner_root(
            &fixture.owner(),
            ActSurface::ThisInstall,
            fixture.released_material(1),
            RootSuccessor::Device(fixture.enrollment(&new_key)),
            std::slice::from_ref(&lost_key),
        )
        .expect("released generation 1 serves back on Standard");
    assert!(
        matches!(answer, RootRecovery::Vouched { .. }),
        "generation 1 vouches"
    );
}

#[test]
fn generation_0_bytes_are_todays_bytes_exactly() {
    let fixture = fixture();
    let seed = fixture.seed();
    let mut material = Vec::with_capacity(64);
    material.extend_from_slice(&seed.kit_bytes()[..]);
    material.extend_from_slice(&fixture.vault_id);
    let expected = blake3::derive_key("oneiron/owner-recovery-authority/v1", &material);
    assert_eq!(
        &*released_authority_seed(&seed, &fixture.vault_id, 0),
        &expected,
        "generation 0 derives today's bytes exactly"
    );
}

#[test]
fn re_activation_of_the_same_kit_after_the_rotation_skips_on_generation_1() {
    let fixture = fixture();
    fixture.switch_with_kit().expect("the rotation");
    let gen0 = fixture.generation_key(0);
    let gen1 = fixture.generation_key(1);
    let r_rows = authority_rows(&fixture).len();

    // A second confirm is still the spent-kit refusal path's guard: the kit is
    // already confirmed, so nothing is written and generation 1 stays live.
    let refused = fixture
        .vault
        .confirm_world_kit(
            &fixture.owner(),
            &fixture.kit_refs(),
            None,
            &BTreeSet::new(),
        )
        .expect_err("confirming an already-confirmed kit is refused");
    assert!(
        refused.to_string().contains("already confirmed"),
        "the confirm guard still holds: {refused}"
    );
    let rows = authority_rows(&fixture);
    assert_eq!(rows.len(), r_rows, "no new authority row");
    assert!(
        rows.iter().any(|key| key.public_key == gen1 && key.live),
        "generation 1 stays live"
    );
    assert!(
        rows.iter().any(|key| key.public_key == gen0 && !key.live),
        "generation 0 stays revoked"
    );

    // The activation itself skips the enrol when generation 1 is live and
    // hands generation 1's seed out: the same seed reaches the same live key.
    let seed = fixture.seed();
    let live = SigningKey::from_bytes(&released_authority_seed(&seed, &fixture.vault_id, 1))
        .verifying_key()
        .to_bytes();
    assert_eq!(live, gen1, "generation 1's seed rebuilds the live key");
}

#[test]
fn the_any_two_switch_with_the_kit_rotates_too() {
    let fixture = fixture();
    let gen0 = fixture.generation_key(0);
    let history = fixture.history().len();
    let issue = KitIssue {
        vault_id: fixture.vault.vault_key_vault_id(),
        homes: [
            PieceHome::RecoveryCode(CodeKeeping::Paper),
            PieceHome::TrustedPerson,
            PieceHome::SecurityKey,
        ],
        passphrase: None,
        cost: PassphraseCost::DEFAULT,
        only_machine: false,
    };
    let switched = fixture
        .vault
        .set_recovery_preset_any_two_with_kit_as(
            &fixture.authority(),
            &issue,
            None,
            &fixture.kit_refs(),
            None,
            |_| Ok(()),
            &NoRecoveryBox,
        )
        .expect("the any-two switch with the kit");
    assert_eq!(switched.change.previous, RecoveryPreset::Standard);
    assert_eq!(switched.change.preset, RecoveryPreset::NobodyButMeAnyTwo);
    assert_eq!(
        fixture.vault.recovery_preset().expect("the preset"),
        RecoveryPreset::NobodyButMeAnyTwo,
    );
    let gen1 = fixture.generation_key(1);
    let rows = authority_rows(&fixture);
    assert!(
        rows.iter().any(|key| key.public_key == gen1 && key.live),
        "generation 1 is enrolled live"
    );
    assert!(
        rows.iter().any(|key| key.public_key == gen0 && !key.live),
        "generation 0 is revoked"
    );
    assert_eq!(
        fixture.history().len(),
        history + 2,
        "one OwnerKeyEnroll and one RevokeDevice in one write"
    );
}

#[test]
fn the_kits_reroot_after_a_rotation_is_signed_by_generation_1_and_counts() {
    // Self-hosted, so the ReRoot path serves (on a hosted vault with a live
    // host root it is refused for the root's door instead). Under kit-only:
    // the kit serves there, only the box's released bytes are refused.
    let dir = tempfile::tempdir().expect("tempdir");
    let mut config = VaultConfig::device();
    config.privacy.posture = HostingPrivacyPosture::SelfHostLocal;
    let vault = Vault::open(dir.path(), config).expect("the vault");
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    let issuer = provision_engine_machines(&vault);
    vault
        .ensure_serving_install_profile(&issuer, MachineRole::HostedNode)
        .expect("this install's live machine profile");
    let person = vault.ensure_embedded_owner_actor().expect("the owner");
    bind_host_owner(&vault, &issuer, person).expect("the owner's binding");
    vault.ensure_vault_key().expect("the data key");
    let owner = proof(&vault, person);
    let authority = ActAuthority::Owner(owner.clone(), ActSurface::ThisInstall);
    let vault_id = vault
        .authority_fold()
        .expect("the fold")
        .vault_id
        .expect("a rooted vault");
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
    let refs: Vec<&oneiron::store::recovery_kit::KitPiece> = issued.pieces.iter().take(2).collect();
    vault
        .confirm_world_kit(&owner, &refs, None, &BTreeSet::new())
        .expect("the kit confirms");
    vault
        .set_recovery_preset_with_kit_as(
            &authority,
            RecoveryPreset::NobodyButMe,
            &refs,
            None,
            |_| Ok(()),
            &NoRecoveryBox,
        )
        .expect("the rotation");

    let secret = restore_kit(vault_id, KitSecretKind::RecoveryRoot, &refs, None)
        .expect("two pieces restore the kit");
    let entry = vault
        .recover_owner_authority_from_kit(secret, owner_device(REROOT_SEED))
        .expect("the kit's ReRoot after the rotation");
    assert!(
        matches!(entry.op, AuthorityOp::ReRoot { .. }),
        "a ReRoot entry counts"
    );
    let seed = {
        let secret = restore_kit(vault_id, KitSecretKind::RecoveryRoot, &refs, None)
            .expect("the seed again");
        RecoveryRootSeed::from_restored_kit(secret).expect("the seed")
    };
    let gen1 = AuthorityKey::Ed25519(
        SigningKey::from_bytes(&released_authority_seed(&seed, &vault_id, 1))
            .verifying_key()
            .to_bytes(),
    );
    assert_eq!(entry.signer_key(), &gen1, "generation 1 signs the ReRoot");
    assert!(
        vault
            .authority_fold()
            .expect("the fold")
            .roster
            .get(&key_of(&SigningKey::from_bytes(&[REROOT_SEED; 32])))
            .is_some_and(|device| !device.revoked),
        "the ReRoot counts: its successor is live"
    );
}

#[test]
fn switching_with_another_kit_while_live_is_refused_as_not_this_vaults() {
    // Extra coverage for decision 5's third words (no PLAN test names them):
    // a kit that holds none live while generation 0 does is the wrong kit.
    let fixture = fixture();
    let owner = fixture.owner();
    let other = fixture
        .vault
        .issue_world_kit(
            &owner,
            &KitIssue {
                vault_id: fixture.vault_id,
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
        .expect("another kit");
    let wrong: Vec<&oneiron::store::recovery_kit::KitPiece> = other.pieces.iter().take(2).collect();
    let before_roster = fixture.vault.authority_fold().expect("the fold").roster;
    let before_history = fixture.history().len();

    let refused = fixture
        .vault
        .set_recovery_preset_with_kit_as(
            &fixture.authority(),
            RecoveryPreset::NobodyButMe,
            &wrong,
            None,
            |_| Ok(()),
            &NoRecoveryBox,
        )
        .expect_err("the wrong kit is refused");
    assert_eq!(refused.kind(), ErrorKind::AuthorityRefused, "{refused}");
    assert!(
        refused.to_string().contains(KIT_NOT_THIS_VAULTS),
        "the exact words: {refused}"
    );
    assert_eq!(
        fixture.vault.recovery_preset().expect("the preset"),
        RecoveryPreset::Standard,
    );
    assert_eq!(
        fixture.vault.authority_fold().expect("the fold").roster,
        before_roster,
        "the roster is unchanged"
    );
    assert_eq!(
        fixture.history().len(),
        before_history,
        "the history is unchanged"
    );
}

/// Records each box hold call. On the first `hold_kit_only(true)` it runs
/// `race` once: an act that lands between the door's no-write checks and its
/// write.
#[derive(Default)]
struct RecordingBoxHold<'a> {
    calls: RefCell<Vec<bool>>,
    race: RefCell<Option<Box<dyn FnOnce() + 'a>>>,
}

impl RecoveryBoxHold for RecordingBoxHold<'_> {
    fn hold_kit_only(&self, kit_only: bool) -> oneiron::Result<()> {
        self.calls.borrow_mut().push(kit_only);
        let race = if kit_only {
            self.race.borrow_mut().take()
        } else {
            None
        };
        if let Some(race) = race {
            race();
        }
        Ok(())
    }
}

#[test]
fn a_switch_refused_in_its_write_after_the_box_hold_releases_the_box_again() {
    // [RECOVERY-BOX-HOLD-ORPHAN]: the kitless switch passes its no-write
    // checks with no generation live and holds the box; the kit's confirm
    // then lands generation 0 before the write, so the write refuses
    // KIT_ONLY_NEEDS_KIT. The box must follow the stored preset (Standard).
    let fixture = issued_fixture();
    let hold = RecordingBoxHold::default();
    *hold.race.borrow_mut() = Some(Box::new(|| {
        let refs = fixture.kit_refs();
        fixture
            .vault
            .confirm_world_kit(&fixture.owner(), &refs, None, &BTreeSet::new())
            .expect("the kit confirms between the checks and the write");
    }));

    let refused = fixture
        .vault
        .set_recovery_preset_as(
            &fixture.owner(),
            RecoveryPreset::NobodyButMe,
            |_| Ok(()),
            &hold,
        )
        .expect_err("the write refuses once generation 0 is live");
    assert_eq!(refused.kind(), ErrorKind::AuthorityRefused, "{refused}");
    assert!(
        refused.to_string().contains(KIT_ONLY_NEEDS_KIT),
        "the first error is the answer: {refused}"
    );
    assert_eq!(
        *hold.calls.borrow(),
        vec![true, false],
        "held for kit-only, then released once the write refused"
    );
    assert_eq!(
        fixture.vault.recovery_preset().expect("the preset"),
        RecoveryPreset::Standard,
        "the preset is still Standard"
    );
    assert!(
        authority_rows(&fixture)
            .iter()
            .any(|key| key.public_key == fixture.generation_key(0) && key.live),
        "the race's generation 0 stands, not rotated"
    );
}
