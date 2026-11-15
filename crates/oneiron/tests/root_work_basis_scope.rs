//! The root-work basis is the target's two roster heads (K5-BASIS-SHAPE = A,
//! Engine RULING 07:03): the roster head and the accepted-roster head the
//! recorder folded, nothing else. A stranger root, or a stranger anchor's
//! mark of the target, that lands after the owner recorded an honest pin
//! never stales it; only a genuine target roster revision does.
//!
//! Red on main: `stranger_root_after_recording_does_not_stale_a_pin` and
//! `stranger_owned_mark_after_recording_does_not_stale_a_pin` (the old
//! checker folds every valid root and each anchor's chain head into the
//! revision, so the pickup refuses root_revision_mismatch). Guard, which
//! passes on main too: `target_roster_revision_after_recording_stales_the_request`.
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test root_work_basis_scope`.
#![cfg(oneiron_test_support)]

use std::collections::BTreeSet;
use std::sync::Arc;

use ed25519_dalek::{Signer, SigningKey};
use oneiron::authority::{
    AUTHORITY_LOG_SCHEMA_VERSION, ActSurface, AuthorityEntryHash, AuthorityKey, AuthorityLogEntry,
    AuthorityOp, AuthoritySignature, AuthorityVaultId, HostSlipIssuer,
    MACHINE_ENCRYPTION_SUITE_HYBRID_V1, MachineEncryptionKey, MachineEnrolmentRequest,
    MachineOwnership, MachineProfile, MachineRole, OwnerRootRecord, OwnerRootView,
    OwnerWorkRefusal, RecoveryRootId, RootChange, authority_entry_hash, authority_transcript,
};
use oneiron::consent::AuthenticatedOwner;
use oneiron::store::GateDecisionId;
use oneiron::test_support::bind_host_owner;
use oneiron::world_keys::{OwnerWorkDrain, OwnerWorkStatus, RecoveryRoot, RecoveryRootSeed};
use oneiron::{EntityId, TimeRange, Vault, VaultConfig};

fn proof(vault: &Vault, person: EntityId) -> AuthenticatedOwner {
    vault
        .authenticate_owner(person, &person.to_hex(), true, GateDecisionId::now())
        .expect("an owner proof")
}

/// The vault's host: a hosted node, rooted, whose install carries the
/// owner's acts, as every live machine profile of the vault does. The
/// recorder R of these tests.
struct Host {
    _dir: tempfile::TempDir,
    vault: Vault,
    _issuer: HostSlipIssuer,
    owner: AuthenticatedOwner,
    vault_id: [u8; 32],
}

fn host() -> Host {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("the host's install");
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    let issuer = oneiron::test_support::provision_engine_machines(&vault);
    vault
        .ensure_serving_install_profile(&issuer, MachineRole::HostedNode)
        .expect("the hosted node's live machine profile");
    let person = vault.ensure_embedded_owner_actor().expect("the owner");
    bind_host_owner(&vault, &issuer, person).expect("the owner's binding");
    let owner = proof(&vault, person);
    let vault_id = vault
        .authority_fold()
        .expect("the host's fold")
        .vault_id
        .expect("a rooted vault");
    Host {
        _dir: dir,
        vault,
        _issuer: issuer,
        owner,
        vault_id,
    }
}

impl Host {
    /// A recovery root the host mints with a seed of its own, on its own
    /// install: its record, its anchor's mark of the host's machine, and the
    /// host's own pin.
    fn mint_own_root(&self) -> RecoveryRootId {
        let prepared = self
            .vault
            .prepare_owner_root(&self.owner)
            .expect("the host prepares a root");
        self.vault
            .activate_owner_root(&self.owner, prepared, &BTreeSet::new())
            .expect("the host activates its root")
            .root
    }

    /// Records a pin of `root` on `target`, carried by the host's install
    /// as the hosted console's act.
    fn request_pin(&self, target: EntityId, root: RecoveryRootId) {
        let receipt = self
            .vault
            .request_root_change(
                &self.owner,
                ActSurface::HostedConsole,
                target,
                RootChange::Pin { root },
            )
            .expect("the host records the pin request");
        assert!(
            receipt.request.is_some(),
            "the pin request is recorded for the device: {receipt:?}"
        );
    }
}

/// The owner's device: its own install, enrolled as his, never pinned. It
/// takes the vault's authority history from the host, as sync does. The
/// target T of these tests.
struct Device {
    _dir: tempfile::TempDir,
    vault: Vault,
    machine: EntityId,
    enrolment: MachineEnrolmentRequest,
    held: BTreeSet<Vec<u8>>,
}

fn device(host: &Host) -> Device {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("the device's install");
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    let key = vault
        .machine_encryption_key(host.vault_id)
        .expect("the device's encryption key");
    let request = vault
        .machine_enrolment_request(host.vault_id, key)
        .expect("the device's enrolment request");
    host.vault
        .enroll_machine(
            &host.owner,
            ActSurface::HostedConsole,
            &request,
            MachineRole::Owned(MachineOwnership::Yours),
            None,
        )
        .expect("the owner enrols the device as his");
    vault
        .ensure_embedded_owner_actor()
        .expect("the owner on the device");
    let mut device = Device {
        _dir: dir,
        vault,
        machine: request.machine,
        enrolment: request,
        held: BTreeSet::new(),
    };
    device.take(host);
    device
}

impl Device {
    /// Imports the rows of the host's history this device does not hold yet.
    fn take(&mut self, host: &Host) {
        let new: Vec<Vec<u8>> = host
            .vault
            .export_signed_authority_history()
            .expect("the host's history")
            .into_iter()
            .filter(|row| !self.held.contains(row))
            .collect();
        self.vault
            .import_signed_authority_history(&new)
            .expect("the device takes the rows");
        self.held.extend(new);
    }

    fn owner(&self) -> AuthenticatedOwner {
        let person = self
            .vault
            .ensure_embedded_owner_actor()
            .expect("the owner on the device");
        proof(&self.vault, person)
    }

    /// Two syncs and pickups: the first may only commit the wait for a root
    /// whose record the device does not store yet, which lets the next sync
    /// store it.
    fn sync_and_pick_up(&mut self, host: &Host) -> Vec<OwnerWorkDrain> {
        let mut drains = Vec::new();
        for _ in 0..2 {
            self.take(host);
            drains.push(
                self.vault
                    .run_pending_owner_work(|| true)
                    .expect("the device's pickup"),
            );
        }
        self.take(host);
        drains
    }

    fn roots(&self) -> OwnerRootView {
        self.vault
            .owner_root_view(None, 16)
            .expect("the device's roots")
    }
}

/// The device's pending pin request: its entry hash.
fn pending_pin_hash(device: &Device) -> AuthorityEntryHash {
    device
        .vault
        .pending_root_requests(&device.owner())
        .expect("the device's pending root requests")
        .into_iter()
        .find_map(|(hash, change, _)| matches!(change, RootChange::Pin { .. }).then_some(hash))
        .expect("one pending pin request")
}

/// The device's roster head and accepted-roster head, each by its entry.
fn roster_heads(device: &Device) -> (Option<AuthorityEntryHash>, Option<AuthorityEntryHash>) {
    let fold = device.vault.authority_fold().expect("the device's fold");
    let machine = fold.machine(device.machine).expect("the device's machine");
    (
        machine.roster.as_ref().map(|head| head.entry),
        machine.roster_trusted.as_ref().map(|head| head.entry),
    )
}

/// The stored rows' occurred range and learned-at, as the store-door tests use.
const AT: TimeRange = TimeRange { start: 2, end: 2 };

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

/// `signer` signs `op` on `parent_hashes`, with one cosign by each of `cosigners`.
fn signed(
    vault_id: Option<AuthorityVaultId>,
    seq: u64,
    parent_hashes: Vec<AuthorityEntryHash>,
    op: AuthorityOp,
    signer: &SigningKey,
    cosigners: &[&SigningKey],
) -> AuthorityLogEntry {
    let mut cosigners = cosigners.to_vec();
    cosigners.sort_by_key(|cosigner| key_of(cosigner));
    let mut row = AuthorityLogEntry {
        schema_version: AUTHORITY_LOG_SCHEMA_VERSION,
        vault_id,
        seq,
        parent_hashes,
        op,
        signer: signature_slot(key_of(signer)),
        cosigns: cosigners
            .iter()
            .map(|cosigner| signature_slot(key_of(cosigner)))
            .collect(),
        ts: 1,
    };
    let transcript = authority_transcript(&row).expect("the transcript");
    row.signer.signature = signer.sign(&transcript).to_bytes().to_vec();
    for (slot, cosigner) in row.cosigns.iter_mut().zip(&cosigners) {
        slot.signature = cosigner.sign(&transcript).to_bytes().to_vec();
    }
    row
}

fn hash(row: &AuthorityLogEntry) -> AuthorityEntryHash {
    authority_entry_hash(row).expect("a hash")
}

/// The stranger root's owner person, distinct from the vault's owner.
fn stranger_owner() -> EntityId {
    EntityId::from_bytes([0xA1; 16]).expect("an id")
}

/// A stranger's root published on one held valid row and stored. Returns the
/// root, its anchor signing key, and the root row's hash.
fn publish_stranger_root(
    vault: &Vault,
    vault_id: AuthorityVaultId,
) -> (RecoveryRoot, SigningKey, AuthorityEntryHash) {
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
        Some(vault_id),
        1,
        vec![parent],
        AuthorityOp::OwnerRoot(record),
        &anchor,
        &[],
    );
    let root_hash = hash(&entry);
    vault
        .put_authority_log_entry(&entry, AT, 2)
        .expect("the stranger's root row is stored");
    let fold = vault.authority_fold().expect("authority fold");
    assert!(
        fold.valid_entries.contains(&root_hash),
        "guard: the stranger's root is in valid_entries"
    );
    (root, anchor, root_hash)
}

/// The stranger's anchor marks `request`'s machine under its own keys and
/// proof, and the mark is stored. Returns the mark's hash.
fn stranger_mark_with_m_keys(
    vault: &Vault,
    vault_id: AuthorityVaultId,
    root: AuthorityEntryHash,
    anchor: &SigningKey,
    request: &MachineEnrolmentRequest,
    role: MachineRole,
    revision: u64,
) -> AuthorityEntryHash {
    let profile = MachineProfile {
        machine: request.machine,
        owner: stranger_owner(),
        machine_key: request.machine_key,
        device_class: request.device_class,
        encryption_key: request.encryption_key.clone(),
        role,
        revision,
        machine_proof: request.machine_proof,
        seen_world_edits: BTreeSet::new(),
        carrier: None,
        act: None,
    };
    let entry = signed(
        Some(vault_id),
        2,
        vec![root],
        AuthorityOp::MachineProfile(profile),
        anchor,
        &[],
    );
    let mark = hash(&entry);
    vault
        .put_authority_log_entry(&entry, AT, 2)
        .expect("the stranger's mark is stored");
    mark
}

/// A stranger root that lands after recording never stales an honest pin:
/// the basis is the target's two roster heads, which did not move. Red on
/// main: the old basis folds every valid root, so it reads as Moved.
#[test]
fn stranger_root_after_recording_does_not_stale_a_pin() {
    let host = host();
    let mut device = device(&host);
    let honest = host.mint_own_root();
    device.take(&host);
    device
        .vault
        .pin_owner_root(&device.owner(), honest)
        .expect("the device pins the honest root first");
    assert_eq!(
        device.roots().pinned,
        Some(honest),
        "guard: the carried-pin trust policy is not the variable"
    );
    host.request_pin(device.machine, honest);

    let (_, _, stranger) = publish_stranger_root(&host.vault, host.vault_id);
    device.take(&host);
    let request = pending_pin_hash(&device);
    let drains = device.sync_and_pick_up(&host);

    let receipt = device
        .vault
        .owner_work_receipt(&device.owner(), request)
        .expect("the receipt read")
        .expect("the device folds the request");
    assert!(
        !matches!(
            receipt.status,
            OwnerWorkStatus::Refused {
                reason: OwnerWorkRefusal::RootRevisionMismatch,
            }
        ),
        "a stranger root after recording never stales the pin (drains {drains:?}, receipt {receipt:?})"
    );
    let fold = device.vault.authority_fold().expect("the device's fold");
    assert!(
        fold.valid_entries.contains(&stranger),
        "the stranger's row stays valid"
    );
    assert_eq!(
        device.roots().pinned,
        Some(honest),
        "the device's pin stays the honest root"
    );
}

/// A stranger anchor's mark of the target that lands after recording never
/// stales the pin either: no anchor chain is a head. Red on main: the old
/// basis folds each anchor's chain head, so it reads as Moved.
#[test]
fn stranger_owned_mark_after_recording_does_not_stale_a_pin() {
    let host = host();
    let mut device = device(&host);
    let honest = host.mint_own_root();
    let (_, anchor, stranger) = publish_stranger_root(&host.vault, host.vault_id);
    device.take(&host);
    let anchor_key = anchor.verifying_key().to_bytes();
    let fold = device.vault.authority_fold().expect("the device's fold");
    assert!(
        fold.valid_entries.contains(&stranger),
        "guard: the stranger's root is valid on the device before recording"
    );
    assert!(
        !fold
            .machine(device.machine)
            .expect("the device's machine")
            .anchored
            .contains_key(&anchor_key),
        "guard: no stranger mark of the device before recording"
    );
    device
        .vault
        .pin_owner_root(&device.owner(), honest)
        .expect("the device pins the honest root first");
    let before = roster_heads(&device);
    host.request_pin(device.machine, honest);

    let mark = stranger_mark_with_m_keys(
        &host.vault,
        host.vault_id,
        stranger,
        &anchor,
        &device.enrolment,
        MachineRole::Owned(MachineOwnership::Yours),
        1,
    );
    device.take(&host);
    let fold = device.vault.authority_fold().expect("the device's fold");
    assert!(
        fold.valid_entries.contains(&mark),
        "guard: the stranger's mark is valid on the device"
    );
    assert_eq!(
        roster_heads(&device),
        before,
        "guard: the honest roster heads did not move"
    );
    let request = pending_pin_hash(&device);
    let drains = device.sync_and_pick_up(&host);

    let receipt = device
        .vault
        .owner_work_receipt(&device.owner(), request)
        .expect("the receipt read")
        .expect("the device folds the request");
    assert!(
        !matches!(
            receipt.status,
            OwnerWorkStatus::Refused {
                reason: OwnerWorkRefusal::RootRevisionMismatch,
            }
        ),
        "a stranger mark after recording never stales the pin (drains {drains:?}, receipt {receipt:?})"
    );
    let fold = device.vault.authority_fold().expect("the device's fold");
    assert!(
        fold.valid_entries.contains(&stranger),
        "the stranger's root stays valid"
    );
    assert!(
        fold.valid_entries.contains(&mark),
        "the stranger's mark stays valid"
    );
    assert_eq!(
        roster_heads(&device),
        before,
        "the honest roster heads are unchanged"
    );
    assert_eq!(
        device.roots().pinned,
        Some(honest),
        "the device's pin stays the honest root"
    );
}

/// Only a genuine target roster revision stales the request: a live role
/// change of the target after recording still refuses root_revision_mismatch
/// with no pin effect. Guard: passes on main and on the head alike.
#[test]
fn target_roster_revision_after_recording_stales_the_request() {
    let host = host();
    let mut device = device(&host);
    let honest = host.mint_own_root();
    device.take(&host);
    device
        .vault
        .pin_owner_root(&device.owner(), honest)
        .expect("the device pins the honest root first");
    host.request_pin(device.machine, honest);

    host.vault
        .set_machine_role(
            &host.owner,
            ActSurface::HostedConsole,
            device.machine,
            MachineRole::Owned(MachineOwnership::WorkSchool),
            None,
        )
        .expect("the owner re-answers the device under a live role");
    device.take(&host);
    let request = pending_pin_hash(&device);
    let drains = device.sync_and_pick_up(&host);

    let receipt = device
        .vault
        .owner_work_receipt(&device.owner(), request)
        .expect("the receipt read")
        .expect("the device folds the request");
    assert!(
        matches!(
            receipt.status,
            OwnerWorkStatus::Refused {
                reason: OwnerWorkRefusal::RootRevisionMismatch,
            }
        ),
        "a genuine roster revision stales the request (drains {drains:?}, receipt {receipt:?})"
    );
    assert_eq!(
        device.roots().pinned,
        Some(honest),
        "the refusal moves no pin"
    );
}
