//! Red/green tests for the owner key vouch door's machine check
//! (`require_holding_machine`, crates/oneiron/src/authority/owner_key_vouch.rs)
//! under a stranger's root (FIX [FOREIGN-ANCHOR-MARK-BLOCKS-MACHINE-DOORS],
//! open half; [FOREIGN-ANCHOR-CHAIN-COUNTS-IN-EVERY-CHAIN-PREDICATES]).
//!
//! Any fresh key publishes an owner root, and that root's anchor marks any
//! machine in its own chain, removed or answered, under the machine's own
//! keys and proof. Main's door read every chain of the vouching machine: any
//! chain that said removed refused the vouch, and any live owned chain
//! admitted it. The door now reads the heads the machine stands under on
//! this install (the roster's head and the pinned anchor's chain), so a
//! stranger's chain neither blocks nor admits a vouch.
//!
//! Red on main d54d8768eef8 (this file added alone): both tests fail at
//! their first door assert, as each test's doc states. Green on #8722's head.
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test owner_key_vouch_standing_heads`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeSet;
use std::sync::Arc;

use ed25519_dalek::{Signer, SigningKey};
use oneiron::authority::{
    AUTHORITY_LOG_SCHEMA_VERSION, ActAuthority, ActSurface, AuthorityEntryHash, AuthorityKey,
    AuthorityLogEntry, AuthorityOp, AuthoritySignature, AuthorityVaultId, DeviceOwnerKeyVouch,
    MACHINE_ENCRYPTION_SUITE_HYBRID_V1, MachineAnswerLanding, MachineEncryptionKey,
    MachineOwnership, MachineProfile, MachineRole, OwnerKeyVouchRequest, OwnerRootRecord,
    authority_entry_hash, authority_transcript,
};
use oneiron::consent::AuthenticatedOwner;
use oneiron::error::RecordError;
use oneiron::store::GateDecisionId;
use oneiron::test_doors::label_writers::embedded_owner;
use oneiron::world_keys::RecoveryRootSeed;
use oneiron::{EntityId, Error, HostingPrivacyPosture, TimeRange, Vault, VaultConfig};

/// The stored rows' occurred range and learned-at, as the store-door tests use.
const AT: TimeRange = TimeRange { start: 2, end: 2 };

fn hosted_config() -> VaultConfig {
    let mut config = VaultConfig::device();
    config.privacy.posture = HostingPrivacyPosture::Hosted;
    config
}

fn owner_act(proof: &AuthenticatedOwner) -> ActAuthority {
    ActAuthority::Owner(proof.clone(), ActSurface::ThisInstall)
}

/// The request `vault`'s door makes for its own key as `authority`'s owner.
fn request_on(vault: &Vault, authority: &ActAuthority) -> OwnerKeyVouchRequest {
    match vault
        .device_owner_key_vouch_request(authority, "Laptop")
        .expect("the install makes its key's request")
    {
        DeviceOwnerKeyVouch::Request(request) => request,
        DeviceOwnerKeyVouch::Enrolled(receipt) => {
            panic!("the install's key is not enrolled yet: {receipt:?}")
        }
    }
}

/// The owner's device, as tests/owner_key_vouch.rs builds it: an install of a
/// hosted vault rooted under the test host, its own machine profile live and
/// unanswered, the owner bound and authenticated; with `with_key` it holds
/// its own enrolled owner key.
struct OwnerDevice {
    vault: Vault,
    proof: AuthenticatedOwner,
    vault_id: [u8; 32],
    _dir: tempfile::TempDir,
}

fn owner_device(with_key: bool) -> OwnerDevice {
    let dir = tempfile::tempdir().expect("vault directory");
    let vault = Vault::open(dir.path(), hosted_config()).expect("the owner device's install");
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    let issuer = Arc::new(oneiron::test_support::provision_engine_machines(&vault));
    vault
        .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
        .expect("this install's machine profile under the host root");
    let (_, proof) = embedded_owner(&vault).expect("the authenticated owner");
    if with_key {
        vault
            .enrol_device_owner_signing_key(&owner_act(&proof), &issuer)
            .expect("the owner enrols this device's own owner key");
    }
    let vault_id = vault
        .authority_vault_id()
        .expect("the vault's fold")
        .expect("a rooted vault");
    OwnerDevice {
        vault,
        proof,
        vault_id,
        _dir: dir,
    }
}

impl OwnerDevice {
    fn vouch(
        &self,
        request: &OwnerKeyVouchRequest,
    ) -> oneiron::Result<oneiron::authority::OwnerKeyEnrollmentReceipt> {
        self.vault
            .enrol_vouched_owner_signing_key(&owner_act(&self.proof), request)
    }

    fn history(&self) -> Vec<Vec<u8>> {
        self.vault
            .export_signed_authority_history()
            .expect("the owner device's history")
    }

    fn roster_lists(&self, key: [u8; 32]) -> bool {
        self.vault
            .authority_fold()
            .expect("the owner device's fold")
            .roster
            .contains_key(&AuthorityKey::Ed25519(key))
    }

    /// The roster's live head of `machine` on this install.
    fn roster_profile(&self, machine: EntityId) -> MachineProfile {
        let fold = self
            .vault
            .authority_fold()
            .expect("the owner device's fold");
        let roster = fold
            .machine(machine)
            .and_then(|folded| folded.roster.as_ref())
            .expect("guard: the roster holds a head of the machine");
        assert!(roster.is_live(), "guard: the roster's head is live");
        roster.profile.clone()
    }
}

/// The new device: its own install of the vault, enrolled as the owner's
/// machine ("yours") by the owner device, holding no owner key, with the
/// owner device's authority history imported.
struct NewDevice {
    vault: Vault,
    machine: EntityId,
    _dir: tempfile::TempDir,
}

fn new_device(owner: &OwnerDevice) -> NewDevice {
    let dir = tempfile::tempdir().expect("vault directory");
    let vault = Vault::open(dir.path(), hosted_config()).expect("the new device's install");
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    let key = vault
        .machine_encryption_key(owner.vault_id)
        .expect("the new device's encryption key");
    let request = vault
        .machine_enrolment_request(owner.vault_id, key)
        .expect("the new device's enrolment request");
    let landing = owner
        .vault
        .enroll_machine(
            &owner.proof,
            ActSurface::ThisInstall,
            &request,
            MachineRole::Owned(MachineOwnership::Yours),
            None,
        )
        .expect("the owner enrols the new device as his");
    assert!(
        matches!(landing, MachineAnswerLanding::Stands(_)),
        "guard: the new device is a live machine of the vault: {landing:?}"
    );
    vault
        .ensure_embedded_owner_actor()
        .expect("the owner on the new device");
    vault
        .import_signed_authority_history(&owner.history())
        .expect("the new device takes the rows");
    NewDevice {
        vault,
        machine: request.machine,
        _dir: dir,
    }
}

impl NewDevice {
    fn request(&self) -> OwnerKeyVouchRequest {
        let person = self
            .vault
            .ensure_embedded_owner_actor()
            .expect("the owner on the new device");
        let proof = self
            .vault
            .authenticate_owner(person, &person.to_hex(), true, GateDecisionId::now())
            .expect("an owner proof on the new device");
        request_on(&self.vault, &owner_act(&proof))
    }
}

fn key_of(signing: &SigningKey) -> AuthorityKey {
    AuthorityKey::Ed25519(signing.verifying_key().to_bytes())
}

fn signature_slot(key: AuthorityKey) -> AuthoritySignature {
    AuthoritySignature {
        suite: key.suite(),
        public_key: key,
        signature: vec![0; 64],
    }
}

/// `signer` alone signs `op` on `parent_hashes`.
fn signed(
    vault_id: AuthorityVaultId,
    seq: u64,
    parent_hashes: Vec<AuthorityEntryHash>,
    op: AuthorityOp,
    signer: &SigningKey,
) -> AuthorityLogEntry {
    let mut row = AuthorityLogEntry {
        schema_version: AUTHORITY_LOG_SCHEMA_VERSION,
        vault_id: Some(vault_id),
        seq,
        parent_hashes,
        op,
        signer: signature_slot(key_of(signer)),
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

/// The stranger root's owner person, distinct from the vault's owner.
fn stranger_owner() -> EntityId {
    EntityId::from_bytes([0xA1; 16]).expect("an id")
}

fn vault_id_of(vault: &Vault) -> AuthorityVaultId {
    vault
        .authority_fold()
        .expect("authority fold")
        .vault_id
        .expect("the vault is rooted")
}

/// A stranger publishes an owner root of its own on `vault`: a fresh seed,
/// nothing the vault holds or pins. Returns its anchor and the root's hash.
fn publish_stranger_root(vault: &Vault) -> (SigningKey, AuthorityEntryHash) {
    let vault_id = vault_id_of(vault);
    let seed = RecoveryRootSeed::generate().expect("a fresh stranger root seed");
    let root = seed
        .public(&vault_id)
        .expect("the stranger root's public half");
    let anchor = seed.anchor();
    let parent = vault
        .authority_fold()
        .expect("authority fold for a parent")
        .valid_entries
        .iter()
        .next()
        .copied()
        .expect("guard: the vault holds a valid row for the root's parent");
    let record = OwnerRootRecord {
        owner: stranger_owner(),
        root: root.id,
        recovery_key: MachineEncryptionKey {
            suite: MACHINE_ENCRYPTION_SUITE_HYBRID_V1,
            key: root.recovery_key.to_bytes(),
        },
        anchor_key: root.anchor_key,
    };
    let entry = signed(
        vault_id,
        1,
        vec![parent],
        AuthorityOp::OwnerRoot(record),
        &anchor,
    );
    let root_hash = hash(&entry);
    vault
        .put_authority_log_entry(&entry, AT, 2)
        .expect("the stranger's root row is stored");
    assert!(
        vault
            .authority_fold()
            .expect("authority fold")
            .valid_entries
            .contains(&root_hash),
        "guard: the stranger's root is in valid_entries"
    );
    (anchor, root_hash)
}

/// The stranger's anchor marks the machine of `template` (the roster's head
/// of it, whose proof verifies for its keys) as `role` one revision above
/// that head, in the stranger's own chain, and the mark is stored. Guards
/// that the mark is valid, that the stranger's chain holds it, and that the
/// roster's head stays live. Returns the stranger's head of the machine's
/// `is_live()` and `removed`.
fn stranger_mark(vault: &Vault, template: &MachineProfile, role: MachineRole) -> (bool, bool) {
    let vault_id = vault_id_of(vault);
    let (anchor, root) = publish_stranger_root(vault);
    let profile = MachineProfile {
        owner: stranger_owner(),
        role,
        revision: template.revision + 1,
        carrier: None,
        act: None,
        ..template.clone()
    };
    let entry = signed(
        vault_id,
        2,
        vec![root],
        AuthorityOp::MachineProfile(profile),
        &anchor,
    );
    let mark = hash(&entry);
    vault
        .put_authority_log_entry(&entry, AT, 2)
        .expect("the stranger's mark is stored");
    let fold = vault.authority_fold().expect("authority fold");
    assert!(
        fold.valid_entries.contains(&mark),
        "guard: the stranger's mark is in valid_entries"
    );
    let folded = fold
        .machine(template.machine)
        .expect("guard: the fold holds the machine");
    let stranger_head = folded
        .anchored
        .get(&anchor.verifying_key().to_bytes())
        .expect("guard: the stranger's chain holds the mark");
    assert!(
        folded
            .roster
            .as_ref()
            .is_some_and(|roster| roster.is_live()),
        "guard: the roster's head stays live"
    );
    (stranger_head.is_live(), stranger_head.removed)
}

/// A stranger's Removed mark of the new device, under the device's own keys
/// in the stranger's own chain, leaves the device's vouch standing: the
/// owner's device still enrols the device's new key.
///
/// RED on main: the vouch is refused with `InvalidAuthorityLogBody` ("the
/// machine proof is not valid"), as main's door refuses a machine any chain
/// of which says removed. GREEN: the key is enrolled.
#[test]
fn a_strangers_removal_mark_of_the_new_device_leaves_its_vouch_standing() {
    let owner = owner_device(true);
    let device = new_device(&owner);
    let request = device.request();
    assert_eq!(
        request.machine, device.machine,
        "guard: the device's request"
    );
    let template = owner.roster_profile(device.machine);
    let (_, removed) = stranger_mark(&owner.vault, &template, MachineRole::Removed);
    assert!(
        removed,
        "guard: the stranger's head of the device says removed"
    );

    let receipt = owner
        .vouch(&request)
        .expect("a stranger's removal mark blocks no vouch of the owner's device");
    assert_eq!(receipt.public_key, request.public_key);
    assert!(
        owner.roster_lists(request.public_key),
        "the device's new key is on the roster"
    );
}

/// A stranger's Owned mark of an install the owner never answered, under the
/// install's own keys in the stranger's own chain, makes it no machine the
/// owner holds: its vouch request is refused as not the owner's, and nothing
/// is written.
///
/// RED on main: the refusal is `OwnerKeyRequired`, not `AuthorityRefused`:
/// main's door admits the machine through the stranger's live owned chain,
/// and only the later owner-key lookup refuses. GREEN: `AuthorityRefused`.
#[test]
fn a_strangers_owned_mark_of_an_unanswered_install_admits_no_vouch() {
    let owner = owner_device(false);
    let request = request_on(&owner.vault, &owner_act(&owner.proof));
    let template = owner.roster_profile(request.machine);
    assert!(
        matches!(template.role, MachineRole::Unanswered),
        "guard: the owner never answered this install"
    );
    let (live, _) = stranger_mark(
        &owner.vault,
        &template,
        MachineRole::Owned(MachineOwnership::Yours),
    );
    assert!(
        live,
        "guard: the stranger's owned head of the install is live"
    );
    let rows = owner.history().len();

    let refused = owner
        .vouch(&request)
        .expect_err("a stranger's owned mark admits no vouch");
    assert!(
        matches!(refused, Error::Record(RecordError::AuthorityRefused(_))),
        "the install is not the owner's: {refused:?}"
    );
    assert!(
        !owner.roster_lists(request.public_key),
        "the key is not enrolled"
    );
    assert_eq!(owner.history().len(), rows, "nothing was written");
}
