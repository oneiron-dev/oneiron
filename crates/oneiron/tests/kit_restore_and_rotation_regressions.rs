//! [KIT-ACTIVATION-REVIEW2-TESTS], REVIEW-9488 round 2: P1 1 checks that a
//! revoked kit's sealed restore creates no MachineEncryption slot; P1 2 checks
//! that a revocation during sealed restore leaves no pad, restore pin or roster
//! row; P1 5 checks that rotation carries a trusted machine profile despite a
//! custodial duplicate.
#![cfg(all(feature = "sync", oneiron_test_support))]

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex, mpsc};
use std::time::Duration;

use ed25519_dalek::{Signer, SigningKey};
use oneiron::authority::{
    AUTHORITY_LOG_SCHEMA_VERSION, ActAuthority, ActSurface, AuthorityEntryHash, AuthorityKey,
    AuthorityLogEntry, AuthorityOp, AuthoritySignature, Destination, EnrolledOwnerKeyKind,
    MACHINE_ENCRYPTION_KEY_LEN, MACHINE_ENCRYPTION_SUITE_HYBRID_V1, MachineDeviceClass,
    MachineEncryptionKey, MachineOwnership, MachineProfile, MachineRole, ReadLocation,
    SealedCopies, SignerClass, WorldPrivacy, authority_entry_hash, authority_transcript,
    decode_authority_log_entry_body, machine_profile_proof_transcript,
};
use oneiron::consent::AuthenticatedOwner;
use oneiron::recovery::{
    CodeKeeping, KitIssue, KitSecretKind, PassphraseCost, PieceHome, restore_kit,
};
use oneiron::store::GateDecisionId;
use oneiron::store::ports::ManualClock;
use oneiron::sync::bridge::Materializer;
use oneiron::sync::manager::WindowManager;
use oneiron::sync::residence::SealedKitRestore;
use oneiron::test_doors::host_root_row_signature::sign_authority_row_as_host_root;
use oneiron::test_support::{bind_host_owner, provision_engine_machines, restore_tempdir};
use oneiron::world_keys::{
    ConfirmedWorldKit, KitConfirmation, RecoveryRootSeed, SealedVaultUpload, WorldPadAvailability,
};
use oneiron::{EntityId, ErrorKind, HostingPrivacyPosture, TimeRange, Vault, VaultConfig};
use oneiron_keystore::{
    AuthBoundSecretStore, DeviceKeystore, KeystoreAssurance, KeystoreLocality, KeystoreSlot,
    MemoryKeystore, SealedBytesStore, SlotKind,
};
use zeroize::Zeroizing;

// The refusal's text up to where the pre-fix head (24c6aa90f805) adds
// "; nothing was written", which #9517 removed from main.
const KIT_NOT_CURRENT: &str = "this recovery kit is not the vault's current kit: a newer kit \
                               replaced it, or it was never confirmed; use your newest kit, or \
                               sign in from a device that is still yours";
const RENDEZVOUS_TIMEOUT: Duration = Duration::from_secs(60);

fn proof(vault: &Vault, person: EntityId) -> AuthenticatedOwner {
    vault
        .authenticate_owner(person, &person.to_hex(), true, GateDecisionId::now())
        .expect("an owner proof")
}

fn signed_history(vault: &Vault) -> Vec<Vec<u8>> {
    vault
        .export_signed_authority_history()
        .expect("signed authority history")
}

fn activate_kit(vault: &Vault, person: EntityId) -> (ConfirmedWorldKit, RecoveryRootSeed) {
    let owner = proof(vault, person);
    let vault_id = vault
        .authority_fold()
        .expect("the fold")
        .vault_id
        .expect("Genesis");
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
        .expect("issue a kit");
    let pieces = [&issued.pieces[0], &issued.pieces[1]];
    let confirmed = vault
        .confirm_world_kit(&owner, &pieces, None, &BTreeSet::new())
        .expect("confirm the kit");
    let secret = restore_kit(vault_id, KitSecretKind::RecoveryRoot, &pieces, None)
        .expect("two stored pieces reconstruct the kit");
    let seed = RecoveryRootSeed::from_restored_kit(secret).expect("the kit's seed");
    (confirmed, seed)
}

fn window_manager(vault: Arc<Vault>) -> Arc<WindowManager> {
    Arc::new(WindowManager::new(
        vault,
        Arc::new(Materializer::new()),
        "kit-restore-regression",
    ))
}

struct Source {
    manager: Arc<WindowManager>,
    dir: tempfile::TempDir,
    person: EntityId,
    world: EntityId,
    vault_id: [u8; 32],
}

impl Source {
    fn new() -> Self {
        let dir = restore_tempdir();
        let vault = Arc::new(
            Vault::open(dir.path().join("source"), VaultConfig::device())
                .expect("the source vault"),
        );
        vault.install_device_keystore(Arc::new(MemoryKeystore::default()));
        vault
            .prepare_install_signing()
            .expect("source install signing");
        let issuer = vault.bootstrap_host_slip_issuer().expect("the host seed");
        vault.ensure_host_root_slip(&issuer).expect("the host root");
        vault
            .provision_engine_machine_identities(&issuer)
            .expect("engine machines");
        vault
            .ensure_serving_install_profile(&issuer, MachineRole::Owned(MachineOwnership::Yours))
            .expect("an answered, trusted publisher");
        let person = vault.ensure_embedded_owner_actor().expect("the owner");
        bind_host_owner(&vault, &issuer, person).expect("the owner's binding");
        vault.ensure_vault_key().expect("the data key");
        let vault_id = vault
            .authority_fold()
            .expect("the fold")
            .vault_id
            .expect("Genesis");
        let owner = proof(&vault, person);
        let world = vault
            .create_world(&owner, "Private restore world", vault.now_recorded_at())
            .expect("the world");
        vault
            .set_world_privacy_as(
                &owner,
                ActSurface::ThisInstall,
                world,
                WorldPrivacy {
                    read: ReadLocation::MyMachines,
                    sealed: SealedCopies::CloudAndMyMachines,
                    ..WorldPrivacy::default()
                },
                None,
            )
            .expect("a private world that a sealed bundle may carry");
        vault.world_key(world).expect("a usable private-world key");
        Self {
            manager: window_manager(vault),
            dir,
            person,
            world,
            vault_id,
        }
    }

    fn fresh(&self, name: &str, keystore: Arc<dyn DeviceKeystore>) -> Arc<Vault> {
        // A direct checkpoint restore can share the source's pad custody.
        // Open independently and let the sealed restore bring the windows.
        let vault = Vault::open(self.dir.path().join(name), VaultConfig::device())
            .expect("a fresh vault with its own custody");
        vault.install_device_keystore(keystore);
        Arc::new(vault)
    }

    fn activate_and_seal(&self, slot: u64) -> SealedKit {
        let (kit, seed) = activate_kit(self.manager.vault(), self.person);
        let upload = self
            .manager
            .assemble_sealed_bundle(slot, Destination::Unknown, None, None, true)
            .expect("seal a generation with the answered publisher");
        assert_eq!(upload.kit_root, Some(kit.activated.root));
        SealedKit {
            seed,
            upload,
            confirm: KitConfirmation::Fingerprint(kit.activated.root),
        }
    }
}

struct SealedKit {
    seed: RecoveryRootSeed,
    upload: SealedVaultUpload,
    confirm: KitConfirmation,
}

impl SealedKit {
    fn restore(
        &self,
        manager: &Arc<WindowManager>,
        person: EntityId,
        vault_id: &[u8; 32],
    ) -> oneiron::Result<SealedKitRestore> {
        manager.restore_sealed_bundle_with_kit(
            &proof(manager.vault(), person),
            vault_id,
            &self.upload.bundle,
            &self.upload.pads,
            &self.seed,
            Some(self.confirm),
        )
    }
}

fn assert_kit_not_current(result: oneiron::Result<SealedKitRestore>) {
    let refused = result.expect_err("the revoked kit must be refused");
    assert_eq!(refused.kind(), ErrorKind::AuthorityRefused, "{refused}");
    assert!(refused.to_string().contains(KIT_NOT_CURRENT), "{refused}");
}

#[test]
fn a_sealed_restore_of_a_revoked_kit_creates_no_machine_encryption_slot() {
    let source = Source::new();
    let old = source.activate_and_seal(1);
    let new = source.activate_and_seal(2);
    let keystore = Arc::new(MemoryKeystore::default());
    let target = source.fresh("target", keystore.clone());
    target
        .import_signed_authority_history(&signed_history(source.manager.vault()))
        .expect("import Genesis and the old kit's revocation");
    let machine = target
        .prepare_install_signing()
        .expect("only install signing");
    assert!(
        target
            .authority_fold()
            .expect("the fold")
            .machine(machine)
            .is_none()
    );
    let slot = KeystoreSlot {
        vault_id: source.vault_id,
        install: *machine.as_bytes(),
        kind: SlotKind::MachineEncryption,
    };
    assert!(keystore.get(&slot).expect("look up the slot").is_none());
    let history = signed_history(&target);
    let manager = window_manager(target.clone());

    assert_kit_not_current(old.restore(&manager, source.person, &source.vault_id));

    assert!(
        keystore.get(&slot).expect("look up the slot").is_none(),
        "sealed restore of a revoked kit created a MachineEncryption slot"
    );
    assert_eq!(signed_history(&target), history, "authority rows changed");
    new.restore(&manager, source.person, &source.vault_id)
        .expect("the live kit restores on the same install");
}

struct SigningPause {
    memory: MemoryKeystore,
    hit: mpsc::Sender<KeystoreSlot>,
    resume: Mutex<Option<mpsc::Receiver<()>>>,
}

impl DeviceKeystore for SigningPause {
    fn get(&self, slot: &KeystoreSlot) -> oneiron_keystore::Result<Option<Zeroizing<[u8; 32]>>> {
        self.memory.get(slot)
    }

    fn create(&self, slot: &KeystoreSlot, secret: &[u8; 32]) -> oneiron_keystore::Result<()> {
        if slot.kind == SlotKind::DeviceSigning {
            let resume = self.resume.lock().expect("pause mutex").take();
            if let Some(resume) = resume {
                self.hit
                    .send(*slot)
                    .expect("test thread receives the signing pause");
                resume.recv_timeout(RENDEZVOUS_TIMEOUT)
                    .expect("test thread must commit the revocation and release the signing pause within 60 s");
            }
        }
        self.memory.create(slot, secret)
    }

    fn delete(&self, slot: &KeystoreSlot) -> oneiron_keystore::Result<()> {
        self.memory.delete(slot)
    }

    fn replace(&self, slot: &KeystoreSlot, secret: &[u8; 32]) -> oneiron_keystore::Result<bool> {
        self.memory.replace(slot, secret)
    }

    fn locality(&self) -> KeystoreLocality {
        self.memory.locality()
    }

    fn assurance(&self) -> KeystoreAssurance {
        self.memory.assurance()
    }

    fn sealed_bytes(&self) -> Option<&dyn SealedBytesStore> {
        self.memory.sealed_bytes()
    }

    fn auth_bound_secret(&self) -> Option<&dyn AuthBoundSecretStore> {
        self.memory.auth_bound_secret()
    }
}

#[test]
fn a_revocation_landing_during_a_sealed_restore_leaves_no_pad_or_roster_row() {
    let source = Source::new();
    let old = source.activate_and_seal(1);
    let initial = signed_history(source.manager.vault());
    let r1 = source
        .manager
        .vault()
        .enrolled_owner_keys()
        .expect("the owner keys")
        .into_iter()
        .find(|key| key.kind == EnrolledOwnerKeyKind::RecoveryAuthority && key.live)
        .map(|key| AuthorityKey::Ed25519(key.public_key))
        .expect("kit A's live R");

    let control = source.fresh("live-control", Arc::new(MemoryKeystore::default()));
    control
        .import_signed_authority_history(&initial)
        .expect("the live control's history");
    let live = old
        .restore(
            &window_manager(control.clone()),
            source.person,
            &source.vault_id,
        )
        .expect("the same signed generation restores while R1 is live");
    assert!(live.windows > 0, "the generation must carry a base window");
    assert!(live.pads > 0, "the generation must carry a pad");
    assert_eq!(
        control
            .world_pad_availability(source.world)
            .expect("the live control's pad"),
        WorldPadAvailability::Present
    );

    activate_kit(source.manager.vault(), source.person);
    let revoked = signed_history(source.manager.vault());
    let (hit, paused) = mpsc::channel();
    let (release, resume) = mpsc::channel();
    let target = source.fresh(
        "racing-target",
        Arc::new(SigningPause {
            memory: MemoryKeystore::default(),
            hit,
            resume: Mutex::new(Some(resume)),
        }),
    );
    target
        .import_signed_authority_history(&initial)
        .expect("start with R1 live");
    let before = target.authority_fold().expect("the starting fold");
    let generation_key = before
        .current_world_key(source.world)
        .expect("the generation's current private-world key")
        .id;
    assert!(!before.roster.get(&r1).expect("R1 on the roster").revoked);
    assert!(before.pinned_root.is_none(), "no pin on a fresh install");
    assert!(
        target
            .local_machine()
            .expect("read the local install")
            .is_none()
    );
    assert_eq!(
        target
            .world_pad_availability(source.world)
            .expect("the starting pad state"),
        WorldPadAvailability::Missing
    );

    let manager = window_manager(target.clone());
    let (person, vault_id) = (source.person, source.vault_id);
    let (finished, outcome) = mpsc::channel();
    let restore = std::thread::spawn(move || {
        let result = old.restore(&manager, person, &vault_id);
        finished
            .send(result)
            .expect("test thread collects the restore result");
    });
    let slot = paused
        .recv_timeout(RENDEZVOUS_TIMEOUT)
        .expect("sealed restore must reach its first DeviceSigning slot creation within 60 s");
    let machine = EntityId::from_bytes(slot.install).expect("the paused install id");
    target
        .import_signed_authority_history(&revoked)
        .expect("commit kit A's revocation while restore is paused");
    let imported = target.authority_fold().expect("fold after import");
    assert!(imported.roster.get(&r1).expect("R1 on the roster").revoked);
    assert_eq!(
        imported.current_world_key(source.world).map(|key| key.id),
        Some(generation_key),
        "the availability check must still read the old generation's pad"
    );
    release
        .send(())
        .expect("release the restore after the revocation commits");
    let result = outcome
        .recv_timeout(RENDEZVOUS_TIMEOUT)
        .expect("sealed restore must finish within 60 s of release");
    restore.join().expect("the restore thread did not panic");

    assert_kit_not_current(result);
    assert_eq!(
        target
            .world_pad_availability(source.world)
            .expect("the final pad state"),
        WorldPadAvailability::Missing,
        "a pad from the revoked generation was left behind"
    );
    let after = target.authority_fold().expect("the final fold");
    assert!(after.pinned_root.is_none(), "a restore pin was left behind");
    assert!(
        after
            .machine(machine)
            .and_then(|machine| machine.roster.as_ref())
            .is_none()
    );
    assert!(!signed_history(&target).iter().any(|bytes| {
        let row = decode_authority_log_entry_body(bytes).expect("a signed row");
        row.signer_key() == &r1
            && matches!(row.op, AuthorityOp::MachineProfile(profile) if profile.machine == machine)
    }), "R1 signed a profile for the racing install");
}

const T0: u64 = 1_800_000_000;
const ROSTER_WINDOW_SECS: u64 = 24 * 60 * 60;
const AGED: u64 = T0 + ROSTER_WINDOW_SECS + 60;

fn signing_key_id(signing: &SigningKey) -> AuthorityKey {
    AuthorityKey::Ed25519(signing.verifying_key().to_bytes())
}

fn unanswered_profile(vault_id: &[u8; 32], owner: EntityId) -> MachineProfile {
    let machine = EntityId::now();
    let signing = SigningKey::from_bytes(&[0x6e; 32]);
    let machine_key = signing.verifying_key().to_bytes();
    // This fixture never sends or wraps a key to this unanswered node.
    let encryption_key = MachineEncryptionKey {
        suite: MACHINE_ENCRYPTION_SUITE_HYBRID_V1,
        key: vec![7; MACHINE_ENCRYPTION_KEY_LEN],
    };
    let device_class = MachineDeviceClass::Computer;
    let machine_proof = signing
        .sign(&machine_profile_proof_transcript(
            vault_id,
            machine,
            &machine_key,
            device_class,
            &encryption_key,
        ))
        .to_bytes();
    MachineProfile {
        machine,
        owner,
        machine_key,
        device_class,
        encryption_key,
        role: MachineRole::Unanswered,
        revision: 1,
        machine_proof,
        seen_world_edits: BTreeSet::new(),
        carrier: None,
        act: None,
        restored_from: None,
    }
}

fn unsigned_profile_row(
    vault_id: [u8; 32],
    profile: MachineProfile,
    key: AuthorityKey,
    seq: u64,
    parent: AuthorityEntryHash,
) -> AuthorityLogEntry {
    AuthorityLogEntry {
        schema_version: AUTHORITY_LOG_SCHEMA_VERSION,
        vault_id: Some(vault_id),
        seq,
        parent_hashes: vec![parent],
        op: AuthorityOp::MachineProfile(profile),
        signer: AuthoritySignature {
            suite: key.suite(),
            public_key: key,
            signature: vec![0; 64],
        },
        cosigns: Vec::new(),
        ts: T0,
    }
}

#[test]
fn a_kit_rotation_carries_the_trusted_profile_a_custodial_duplicate_shadows() {
    let clock = ManualClock::new(T0);
    let dir = restore_tempdir();
    let mut config = VaultConfig::device();
    config.privacy.posture = HostingPrivacyPosture::Hosted;
    config.store_clock = clock.bundle();
    let vault = Vault::open(dir.path(), config).expect("a Hosted vault");
    vault.install_device_keystore(Arc::new(MemoryKeystore::default()));
    let issuer = provision_engine_machines(&vault);
    vault
        .ensure_serving_install_profile(&issuer, MachineRole::HostedNode)
        .expect("the serving install can carry the owner's acts");
    let person = vault.ensure_embedded_owner_actor().expect("the owner");
    bind_host_owner(&vault, &issuer, person).expect("the owner's binding");
    let vault_id = vault
        .authority_fold()
        .expect("the fold")
        .vault_id
        .expect("Genesis");
    let device = vault
        .enrol_device_owner_signing_key(
            &ActAuthority::Owner(proof(&vault, person), ActSurface::ThisInstall),
            &issuer,
        )
        .expect("hold the enrolled owner device predecessor on this install");
    let (old, _) = activate_kit(&vault, person);
    let r1_signing = SigningKey::from_bytes(old.activated.authority_seed.bytes());
    let r1 = signing_key_id(&r1_signing);
    let host = issuer.public_key();
    let history: Vec<_> = signed_history(&vault)
        .iter()
        .map(|bytes| decode_authority_log_entry_body(bytes).expect("a signed row"))
        .collect();
    let r1_enrollment = history
        .iter()
        .find(
            |row| matches!(&row.op, AuthorityOp::OwnerKeyEnroll(enroll) if enroll.device.key == r1),
        )
        .expect("kit A's R is enrolled");
    assert_eq!(
        r1_enrollment.signer_key(),
        &AuthorityKey::Ed25519(device.public_key)
    );
    let parent = authority_entry_hash(r1_enrollment).expect("the shared parent");
    let next_seq = |key: &AuthorityKey| {
        history
            .iter()
            .filter(|row| row.signer_key() == key)
            .map(|row| row.seq)
            .max()
            .unwrap_or(0)
            + 1
    };
    let put = |row: &AuthorityLogEntry| {
        vault
            .put_authority_log_entry(row, TimeRange { start: T0, end: T0 }, T0)
            .expect("store the signed machine profile");
        authority_entry_hash(row).expect("the profile's entry hash")
    };

    let profile = unanswered_profile(&vault_id, person);
    let mut accepted =
        unsigned_profile_row(vault_id, profile.clone(), r1.clone(), next_seq(&r1), parent);
    let transcript = authority_transcript(&accepted).expect("the profile transcript");
    accepted.signer.signature = r1_signing.sign(&transcript).to_bytes().to_vec();
    let accepted = put(&accepted);
    let mut duplicate = unsigned_profile_row(
        vault_id,
        profile.clone(),
        host.clone(),
        next_seq(&host),
        parent,
    );
    sign_authority_row_as_host_root(&issuer, &mut duplicate).expect("sign the custodial duplicate");
    let duplicate = put(&duplicate);
    let mut shadow = unsigned_profile_row(
        vault_id,
        MachineProfile {
            revision: 2,
            ..profile.clone()
        },
        host.clone(),
        next_seq(&host) + 1,
        duplicate,
    );
    sign_authority_row_as_host_root(&issuer, &mut shadow).expect("sign the custodial revision 2");
    let shadow = put(&shadow);

    clock.set(AGED);
    vault
        .advance_authority_clock_for_test(AGED)
        .expect("age both approvals past the stale-roster window");
    let before = vault
        .authority_fold()
        .expect("the aged fold before rotation");
    for (label, row) in [
        ("R1 revision 1", accepted),
        ("host revision 1", duplicate),
        ("host revision 2", shadow),
    ] {
        assert!(
            before.valid_entries.contains(&row),
            "fixture: {label} must be valid"
        );
    }
    let heads = before
        .machine(profile.machine)
        .expect("the fixture's machine");
    let raw = heads.roster.as_ref().expect("raw head");
    assert_eq!((raw.entry, raw.profile.revision), (shadow, 2));
    assert_eq!(raw.signer, host);
    assert_eq!(raw.signer_class, SignerClass::Custodial);
    assert!(raw.is_live());
    let trusted = heads.roster_trusted.as_ref().expect("trusted head");
    assert_eq!(trusted.entry, accepted);
    assert_eq!(trusted.profile, profile);
    assert_eq!(trusted.signer, r1);
    assert_eq!(trusted.signer_class, SignerClass::OwnerHeld);
    assert!(
        trusted.is_live(),
        "the old approval still stands while R1 is live"
    );

    let (new, _) = activate_kit(&vault, person);
    let r2 = signing_key_id(&SigningKey::from_bytes(
        new.activated.authority_seed.bytes(),
    ));
    assert_ne!(r1, r2);
    let after = vault.authority_fold().expect("the fold after rotation");
    assert!(after.roster.get(&r1).expect("R1 on the roster").revoked);
    assert!(!after.roster.get(&r2).expect("R2 on the roster").revoked);
    let carried: Vec<_> = signed_history(&vault).iter()
        .map(|bytes| decode_authority_log_entry_body(bytes).expect("a signed row"))
        .filter(|row| row.signer_key() == &r2
            && matches!(&row.op, AuthorityOp::MachineProfile(head) if head.machine == profile.machine))
        .collect();
    assert_eq!(
        carried.len(),
        1,
        "R2 must carry the trusted profile exactly once"
    );
    let machine = profile.machine;
    let expected = MachineProfile {
        revision: 3,
        ..profile
    };
    assert_eq!(carried[0].op, AuthorityOp::MachineProfile(expected));

    let carry = authority_entry_hash(&carried[0]).expect("the carry's entry hash");
    let heads = after.machine(machine).expect("the machine after rotation");
    let raw = heads.roster.as_ref().expect("raw head after rotation");
    let trusted = heads
        .roster_trusted
        .as_ref()
        .expect("trusted head after rotation");
    assert_eq!(raw.entry, carry);
    assert_eq!(trusted.entry, carry);
    assert!(
        trusted.is_live(),
        "R2's carry keeps the aged trusted profile live"
    );
}
