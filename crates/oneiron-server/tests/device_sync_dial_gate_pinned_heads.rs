//! Red/green test for #8722 review round 2, P1 2 (FIX
//! [DOOR-HEADS-REVIEW2-P1-TESTS]): device sync's dial gate
//! (`device_sync::standing`, crates/oneiron-server/src/device_sync/dial_gate.rs)
//! refuses a home whose roster head says removed, beside a live Owned head
//! in the chain of the anchor this install pins.
//!
//! The gate reads the heads a machine stands under on this install
//! (`FoldedMachine::standing_heads`: the roster's head, then the pinned
//! anchor's). One live head among them admitted the home; a head that says
//! removed now vetoes it first, as the carrier rule reads them.
//!
//! The test serves a self-host vault, enrols the home H as the owner's, and
//! asks the gate as a machine `oneiron device enrol` added (`enrolled`): it
//! admits H. The owner removes H, and the gate refuses it. Then a root whose
//! anchor the test holds marks this install Yours and H Owned in its own
//! chain, and the owner pins it.
//!
//! Red at f47c3aac19b (#8722 before its review round 2 fix; the door and the
//! gate's `pub(crate)` added, nothing else): the final `expect_err` fails, as
//! the test's doc states. Green at #8722's head and later.
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron-server
//! --features oneiron/test-support --test device_sync_dial_gate_pinned_heads`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use ed25519_dalek::{Signer as _, SigningKey};
use oneiron::authority::{
    AUTHORITY_LOG_SCHEMA_VERSION, ActSurface, AuthorityEntryHash, AuthorityKey, AuthorityLogEntry,
    AuthorityOp, AuthoritySignature, AuthorityVaultId, MACHINE_ENCRYPTION_KEY_LEN,
    MACHINE_ENCRYPTION_SUITE_HYBRID_V1, MachineDeviceClass, MachineEncryptionKey,
    MachineEnrolmentRequest, MachineOwnership, MachineProfile, MachineRole, OwnerRootRecord,
    PinnedRoot, authority_entry_hash, authority_transcript, machine_profile_proof_transcript,
};
use oneiron::consent::AuthenticatedOwner;
use oneiron::store::GateDecisionId;
use oneiron::world_keys::RecoveryRootSeed;
use oneiron::{EntityId, TimeRange, Vault, VaultConfig};
use oneiron_server::test_doors::device_sync_dial_gate::dial_standing;

/// The stored rows' occurred range and learned-at, as the store-door tests use.
const AT: TimeRange = TimeRange { start: 2, end: 2 };
/// The seed of the home's machine key.
const HOME_SEED: u8 = 0x31;
/// This machine was added by `oneiron device enrol`, as a dialling device is.
const ENROLLED: bool = true;

fn key_of(signing: &SigningKey) -> AuthorityKey {
    AuthorityKey::Ed25519(signing.verifying_key().to_bytes())
}

/// `signer` alone signs `op` on `parent_hashes`.
fn signed(
    vault_id: AuthorityVaultId,
    seq: u64,
    parent_hashes: Vec<AuthorityEntryHash>,
    op: AuthorityOp,
    signer: &SigningKey,
) -> AuthorityLogEntry {
    let key = key_of(signer);
    let mut row = AuthorityLogEntry {
        schema_version: AUTHORITY_LOG_SCHEMA_VERSION,
        vault_id: Some(vault_id),
        seq,
        parent_hashes,
        op,
        signer: AuthoritySignature {
            suite: key.suite(),
            public_key: key,
            signature: vec![0; 64],
        },
        cosigns: Vec::new(),
        ts: 1,
        overlay_seed: None,
    };
    let transcript = authority_transcript(&row).expect("the transcript");
    row.signer.signature = signer.sign(&transcript).to_bytes().to_vec();
    row
}

fn hash(row: &AuthorityLogEntry) -> AuthorityEntryHash {
    authority_entry_hash(row).expect("a hash")
}

/// The held root's owner person, distinct from the vault's owner.
fn root_owner() -> EntityId {
    EntityId::from_bytes([0xA1; 16]).expect("an id")
}

/// A self-host vault as its own server starts one: this install serving and
/// profiled under the host root, and the owner bound and authenticated.
struct ServedVault {
    vault: Vault,
    owner: AuthenticatedOwner,
    /// This install, the machine that dials.
    local: EntityId,
    _dir: tempfile::TempDir,
}

impl ServedVault {
    fn self_host() -> Self {
        let dir = tempfile::tempdir().expect("vault directory");
        let vault = Vault::open(dir.path(), VaultConfig::device()).expect("self-host vault");
        vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
        let issuer = oneiron::test_support::provision_engine_machines(&vault);
        let local = vault
            .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
            .expect("this install's machine profile under the host root")
            .roster
            .expect("guard: this install has a roster chain")
            .profile
            .machine;
        let person = vault.ensure_embedded_owner_actor().expect("the owner");
        oneiron::test_support::bind_host_owner(&vault, &issuer, person)
            .expect("the owner's binding");
        let owner = vault
            .authenticate_owner(person, &person.to_hex(), true, GateDecisionId::now())
            .expect("the owner's proof");
        Self {
            vault,
            owner,
            local,
            _dir: dir,
        }
    }

    fn vault_id(&self) -> AuthorityVaultId {
        self.vault
            .authority_fold()
            .expect("authority fold")
            .vault_id
            .expect("the vault is rooted")
    }

    /// The roster's head of `machine`.
    fn roster_profile(&self, machine: EntityId) -> MachineProfile {
        self.vault
            .authority_fold()
            .expect("authority fold")
            .machine(machine)
            .and_then(|folded| folded.roster.clone())
            .expect("guard: the roster holds a head of the machine")
            .profile
    }

    /// The home H, another machine, enrolled as the owner's ("yours").
    fn enrol_home(&self) -> EntityId {
        let vault_id = self.vault_id();
        let node = SigningKey::from_bytes(&[HOME_SEED; 32]);
        let machine = EntityId::from_bytes([0x76; 16]).expect("an id");
        let machine_key = node.verifying_key().to_bytes();
        let device_class = MachineDeviceClass::Computer;
        let encryption_key = MachineEncryptionKey {
            suite: MACHINE_ENCRYPTION_SUITE_HYBRID_V1,
            key: vec![7; MACHINE_ENCRYPTION_KEY_LEN],
        };
        let machine_proof = node
            .sign(&machine_profile_proof_transcript(
                &vault_id,
                machine,
                &machine_key,
                device_class,
                &encryption_key,
            ))
            .to_bytes();
        let request = MachineEnrolmentRequest {
            vault_id,
            machine,
            machine_key,
            device_class,
            encryption_key,
            machine_proof,
            restored_from: None,
        };
        self.vault
            .enroll_machine(
                &self.owner,
                ActSurface::ThisInstall,
                &request,
                MachineRole::Owned(MachineOwnership::Yours),
                None,
            )
            .expect("guard: the owner enrols the home");
        machine
    }

    /// A row the held anchor signs, stored; returns its hash.
    fn put(&self, row: &AuthorityLogEntry) -> AuthorityEntryHash {
        self.vault
            .put_authority_log_entry(row, AT, 2)
            .expect("the held anchor's row is stored");
        let mark = hash(row);
        assert!(
            self.vault
                .authority_fold()
                .expect("authority fold")
                .valid_entries
                .contains(&mark),
            "guard: the held anchor's row is valid"
        );
        mark
    }
}

/// The held anchor's mark of the machine of `template` (a profile whose
/// proof verifies for its keys) as Owned (Yours) at revision 1, in its own
/// chain.
fn owned_mark(
    vault_id: AuthorityVaultId,
    seq: u64,
    parent: AuthorityEntryHash,
    template: MachineProfile,
    anchor: &SigningKey,
) -> AuthorityLogEntry {
    signed(
        vault_id,
        seq,
        vec![parent],
        AuthorityOp::MachineProfile(MachineProfile {
            owner: root_owner(),
            role: MachineRole::Owned(MachineOwnership::Yours),
            revision: 1,
            carrier: None,
            act: None,
            ..template
        }),
        anchor,
    )
}

/// The home's roster head says removed, while the chain of the anchor this
/// install pins holds a live Owned head of it: the gate refuses the home.
///
/// RED at f47c3aac19b: the final `expect_err` fails: the gate admits the
/// home on its one live standing head, the pinned anchor's.
/// GREEN: "home_machine <id> is not a live machine".
#[test]
fn a_home_the_roster_removed_is_refused_beside_a_live_head_under_the_pin() {
    let served = ServedVault::self_host();
    let home = served.enrol_home();
    let template = served.roster_profile(home);

    let (machine, _) =
        dial_standing(&served.vault, home, ENROLLED).expect("guard: the gate admits the live home");
    assert_eq!(machine, served.local, "guard: this install dials");

    served
        .vault
        .set_machine_role(
            &served.owner,
            ActSurface::ThisInstall,
            home,
            MachineRole::Removed,
            None,
        )
        .expect("guard: the owner removes the home");
    let refused = dial_standing(&served.vault, home, ENROLLED)
        .expect_err("guard: the gate refuses the home the roster removed");
    assert!(
        refused.to_string().contains("is not a live machine"),
        "guard: refused as no live machine: {refused:#}"
    );

    let vault_id = served.vault_id();
    let seed = RecoveryRootSeed::generate().expect("a fresh root seed");
    let root = seed.public(&vault_id).expect("the root's public half");
    let anchor = seed.anchor();
    let anchor_key = anchor.verifying_key().to_bytes();
    let parent = served
        .vault
        .authority_fold()
        .expect("authority fold for a parent")
        .valid_entries
        .iter()
        .next()
        .copied()
        .expect("guard: the vault holds a valid row for the root's parent");
    let root_row = served.put(&signed(
        vault_id,
        1,
        vec![parent],
        AuthorityOp::OwnerRoot(OwnerRootRecord {
            owner: root_owner(),
            root: root.id,
            recovery_key: MachineEncryptionKey {
                suite: MACHINE_ENCRYPTION_SUITE_HYBRID_V1,
                key: root.recovery_key.to_bytes(),
            },
            anchor_key: root.anchor_key,
        }),
        &anchor,
    ));
    let local_mark = served.put(&owned_mark(
        vault_id,
        2,
        root_row,
        served.roster_profile(served.local),
        &anchor,
    ));
    let home_mark = served.put(&owned_mark(vault_id, 3, local_mark, template, &anchor));
    let root_id = served
        .vault
        .authority_fold()
        .expect("authority fold")
        .root_anchors()
        .get(&anchor_key)
        .and_then(|ids| ids.iter().next())
        .copied()
        .expect("guard: the fold holds the root signed by the held anchor");
    let report = served
        .vault
        .pin_owner_root(&served.owner, root_id)
        .expect("the owner pins the held root");
    assert_eq!(report.awaiting, None, "guard: the pin is not awaiting");

    let fold = served.vault.authority_fold().expect("authority fold");
    assert_eq!(
        fold.pinned_root,
        Some(PinnedRoot {
            id: root_id,
            anchor_key,
        }),
        "guard: the pin is effective"
    );
    let folded = fold.machine(home).expect("guard: the fold holds the home");
    let roster = folded.roster.as_ref().expect("guard: the roster's head");
    assert!(
        roster.removed && roster.profile.role == MachineRole::Removed,
        "guard: the roster's head of the home says removed"
    );
    let pinned = folded
        .anchored
        .get(&anchor_key)
        .expect("guard: the pinned anchor's chain holds the home");
    assert_eq!(
        pinned.entry, home_mark,
        "guard: the pinned head is the mark"
    );
    assert!(
        pinned.is_live() && pinned.profile.role == MachineRole::Owned(MachineOwnership::Yours),
        "guard: the pinned anchor's head of the home is live and Owned"
    );

    let refused = dial_standing(&served.vault, home, ENROLLED)
        .expect_err("a removed roster head vetoes the home beside a live pinned head");
    let message = refused.to_string();
    assert!(
        message.contains("home_machine") && message.contains("is not a live machine"),
        "refused as no live home: {refused:#}"
    );
}
