//! Review #9496 P1 (round 2): the settings this install reads judge an owner
//! act's carrier against the removal of the anchor this install pins.
//!
//! Stack #8714 made every shared judge read a machine's roster chain alone
//! (Fable pass 29 K3). The install view's carrier rule and removal race read
//! the roster alone too and passed no pin, so a world edit that a
//! roster-live machine M carried offline, concurrent with this install's
//! pinned anchor removing M without seeing the edit, counted at full
//! strength here: a widen to Everywhere made the world readable on an
//! unknown destination. The install view now passes the pin it counts to
//! the one carrier rule and reads the pinned anchor's mark in the race: an
//! edit that removal did not see only narrows here, and one it saw keeps
//! its strength. Validity, and the roster's read, stay the roster's.
//!
//! Each test serves a self-host vault, enrols M on the roster, publishes a
//! root under a held anchor key that marks this install and M "yours", pins
//! that root, has M carry world edits signed by M's held install key, and
//! has the pinned anchor remove M in its own chain only.

#![cfg(oneiron_test_support)]

use std::collections::BTreeSet;
use std::sync::Arc;

use ed25519_dalek::{Signer, SigningKey};
use oneiron::authority::{
    AUTHORITY_LOG_SCHEMA_VERSION, ActSurface, AuthorityEntryHash, AuthorityKey, AuthorityLogEntry,
    AuthorityOp, AuthoritySignature, AuthorityVaultId, Destination, EffectiveRead,
    MACHINE_ENCRYPTION_KEY_LEN, MACHINE_ENCRYPTION_SUITE_HYBRID_V1, MachineDeviceClass,
    MachineEncryptionKey, MachineEnrolmentRequest, MachineOwnership, MachineProfile, MachineRole,
    ModelOrder, OwnerAct, OwnerActKind, OwnerRootRecord, PinnedRoot, ReadLocation, SealedCopies,
    WorldPrivacy, WorldPrivacyEdit, authority_entry_hash, authority_transcript,
    machine_profile_proof_transcript,
};
use oneiron::consent::AuthenticatedOwner;
use oneiron::store::GateDecisionId;
use oneiron::world_keys::RecoveryRootSeed;
use oneiron::{EntityId, TimeRange, Vault, VaultConfig};

/// The seed of M's install key, which the test holds.
const JOINING_SEED: u8 = 68;
/// The stored rows' occurred range and learned-at, as the store-door tests use.
const AT: TimeRange = TimeRange { start: 2, end: 2 };

fn signing(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
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

/// The pinned root's owner person, as the doors' pinned-anchor test names it.
fn root_owner() -> EntityId {
    EntityId::from_bytes([0xA1; 16]).expect("an id")
}

/// A self-host vault as its own server starts one: this install serving and
/// profiled under the host root, and the owner bound and authenticated.
struct ServedVault {
    vault: Vault,
    owner: AuthenticatedOwner,
    /// The owner's PERSON, bound to a live human actor.
    person: EntityId,
    /// This install.
    carrier: EntityId,
    _dir: tempfile::TempDir,
}

impl ServedVault {
    fn self_host() -> Self {
        let dir = tempfile::tempdir().expect("vault directory");
        let vault = Vault::open(dir.path(), VaultConfig::device()).expect("self-host vault");
        vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
        let issuer = oneiron::test_support::provision_engine_machines(&vault);
        let carrier = vault
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
            person,
            carrier,
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

    /// `machine`'s roster head profile and entry.
    fn roster_head(&self, machine: EntityId) -> (MachineProfile, AuthorityEntryHash) {
        self.vault
            .authority_fold()
            .expect("authority fold")
            .machine(machine)
            .and_then(|folded| folded.roster.clone())
            .map(|chain| (chain.profile, chain.entry))
            .expect("guard: the machine has a roster chain")
    }

    /// M's request to join this vault under the held install key `node`,
    /// with its own proof.
    fn joining_machine(&self, node: &SigningKey) -> MachineEnrolmentRequest {
        let vault_id = self.vault_id();
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
        MachineEnrolmentRequest {
            vault_id,
            machine,
            machine_key,
            device_class,
            encryption_key,
            machine_proof,
            restored_from: None,
        }
    }

    /// `signer`'s row `op` at `seq` on `parents`, stored. Returns its hash.
    fn store(
        &self,
        signer: &SigningKey,
        seq: u64,
        parents: Vec<AuthorityEntryHash>,
        op: AuthorityOp,
    ) -> AuthorityEntryHash {
        let row = signed(self.vault_id(), seq, parents, op, signer);
        self.vault
            .put_authority_log_entry(&row, AT, 2)
            .expect("the row is stored");
        hash(&row)
    }

    /// The owner's edit of `world` to `settings`, carried by `machine` and
    /// signed by its install key `node` at `seq`, on `parents`. Stored;
    /// returns the edit's hash.
    fn store_world_edit(
        &self,
        node: &SigningKey,
        seq: u64,
        parents: Vec<AuthorityEntryHash>,
        machine: EntityId,
        world: EntityId,
        settings: WorldPrivacy,
    ) -> AuthorityEntryHash {
        let act = OwnerAct::by_owner(
            self.person,
            OwnerActKind::WorldPrivacy,
            world,
            ActSurface::ThisInstall,
            [0; 32],
        );
        self.store(
            node,
            seq,
            parents,
            AuthorityOp::WorldPrivacy(WorldPrivacyEdit {
                world,
                act,
                machine,
                settings,
            }),
        )
    }
}

/// The pinned anchor's mark of a machine: `template` (a roster profile whose
/// proof verifies for its keys) in `role` at `revision`, under the root's
/// owner, having seen `seen`.
fn anchor_mark(
    template: &MachineProfile,
    role: MachineRole,
    revision: u64,
    seen: BTreeSet<AuthorityEntryHash>,
) -> AuthorityOp {
    AuthorityOp::MachineProfile(MachineProfile {
        owner: root_owner(),
        role,
        revision,
        seen_world_edits: seen,
        carrier: None,
        act: None,
        ..template.clone()
    })
}

/// One served vault with M enrolled on the roster, and a root under a held
/// anchor key that marks this install and M "yours", pinned here.
struct Pinned {
    served: ServedVault,
    /// M's held install key.
    node: SigningKey,
    machine: EntityId,
    anchor: SigningKey,
    /// The pinned anchor's mark of M, revision 1, at the anchor's seq 3.
    m_mark: AuthorityEntryHash,
    /// M's roster head entry.
    m_roster: AuthorityEntryHash,
    m_profile: MachineProfile,
    pin: PinnedRoot,
}

impl Pinned {
    fn new() -> Self {
        let served = ServedVault::self_host();
        let node = signing(JOINING_SEED);
        let request = served.joining_machine(&node);
        served
            .vault
            .enroll_machine(
                &served.owner,
                ActSurface::ThisInstall,
                &request,
                MachineRole::Owned(MachineOwnership::Yours),
                None,
            )
            .expect("guard: the owner enrols M");
        let machine = request.machine;
        let (m_profile, m_roster) = served.roster_head(machine);
        let (carrier_profile, _) = served.roster_head(served.carrier);

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
        let root_row = served.store(
            &anchor,
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
        );
        let yours = MachineRole::Owned(MachineOwnership::Yours);
        let carrier_mark = served.store(
            &anchor,
            2,
            vec![root_row],
            anchor_mark(&carrier_profile, yours, 1, BTreeSet::new()),
        );
        let m_mark = served.store(
            &anchor,
            3,
            vec![carrier_mark],
            anchor_mark(&m_profile, yours, 1, BTreeSet::new()),
        );

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
            .expect("guard: the owner pins the held anchor's root");
        assert_eq!(report.awaiting, None, "guard: the pin is not awaiting");
        let pin = PinnedRoot {
            id: root_id,
            anchor_key,
        };
        let fold = served.vault.authority_fold().expect("authority fold");
        assert_eq!(fold.pinned_root, Some(pin), "guard: the pin is effective");
        assert!(
            fold.machine(machine)
                .and_then(|folded| folded.anchored.get(&anchor_key))
                .is_some_and(|chain| chain.entry == m_mark && chain.is_live()),
            "guard: the pinned anchor holds M live"
        );
        drop(fold);
        Self {
            served,
            node,
            machine,
            anchor,
            m_mark,
            m_roster,
            m_profile,
            pin,
        }
    }

    /// The pinned anchor removes M (revision 2, seq 4, on its mark of M
    /// alone), having seen `seen`. Returns the removal's hash, after guards:
    /// it is valid, it is the head of the pinned chain of M, the pin still
    /// stands, and M's roster head is live and unmoved.
    fn remove_m(&self, seen: BTreeSet<AuthorityEntryHash>) -> AuthorityEntryHash {
        let removal = self.served.store(
            &self.anchor,
            4,
            vec![self.m_mark],
            anchor_mark(&self.m_profile, MachineRole::Removed, 2, seen),
        );
        let fold = self.served.vault.authority_fold().expect("authority fold");
        assert!(
            fold.valid_entries.contains(&removal),
            "guard: the pinned anchor's removal of M is valid"
        );
        assert_eq!(fold.pinned_root, Some(self.pin), "guard: the pin stands");
        let folded = fold.machine(self.machine).expect("guard: M is folded");
        assert!(
            folded
                .anchored
                .get(&self.pin.anchor_key)
                .is_some_and(|chain| chain.entry == removal && chain.removed),
            "guard: the pinned anchor's chain holds M removed"
        );
        assert!(
            folded
                .roster
                .as_ref()
                .is_some_and(|chain| chain.entry == self.m_roster && chain.is_live()),
            "guard: M's roster head stays live and unmoved"
        );
        removal
    }

    /// Guard: `edit` is valid and has effect.
    fn guard_edit_stands(&self, edit: AuthorityEntryHash) {
        let fold = self.served.vault.authority_fold().expect("authority fold");
        assert!(
            fold.valid_entries.contains(&edit),
            "guard: M's world edit is valid"
        );
        assert!(
            !fold.refused_world_edits.contains(&edit),
            "guard: M's world edit has effect"
        );
    }
}

fn world() -> EntityId {
    EntityId::from_bytes([0xB0; 16]).expect("an id")
}

fn settings(read: ReadLocation) -> WorldPrivacy {
    WorldPrivacy {
        read,
        sealed: SealedCopies::CloudAndMyMachines,
        models: ModelOrder::Inherit,
    }
}

/// T1 (the review's case): M sets the world to MyMachines, then widens it to
/// Everywhere offline; the pinned anchor removes M having seen only the
/// first edit. This install reads the world as MyMachines.
///
/// RED (stack top bd41ee27): the final asserts fail: the install view passes
/// no pin, so M's roster head admits the widen at full strength here and
/// the world reads Everywhere, readable on an unknown destination.
/// GREEN: the pinned anchor's removal vetoes M here and never saw the widen,
/// so the widen only narrows: the meet of Everywhere with the first edit,
/// which that removal saw and which keeps its strength. The roster's read,
/// which every install shares, still holds the widen.
#[test]
fn a_widen_the_pinned_anchors_removal_never_saw_only_narrows_here() {
    let pinned = Pinned::new();
    let served = &pinned.served;
    let mut parents = vec![pinned.m_roster, pinned.m_mark];
    parents.sort_unstable();
    let first = served.store_world_edit(
        &pinned.node,
        1,
        parents,
        pinned.machine,
        world(),
        settings(ReadLocation::MyMachines),
    );
    let widen = served.store_world_edit(
        &pinned.node,
        2,
        vec![first],
        pinned.machine,
        world(),
        settings(ReadLocation::Everywhere),
    );
    pinned.remove_m(BTreeSet::from([first]));
    pinned.guard_edit_stands(first);
    pinned.guard_edit_stands(widen);

    let fold = served.vault.authority_fold().expect("authority fold");
    assert!(
        fold.worlds
            .get(&world())
            .is_some_and(|folded| folded.live.get(&widen) == Some(&pinned.machine)),
        "guard: the widen is the world's live edit, carried by M"
    );
    assert_eq!(
        fold.world_roster_read(world()),
        EffectiveRead::Everywhere,
        "guard: the roster's read, shared by every install, holds the widen"
    );
    assert!(
        !fold.world_readable_on(world(), Destination::Unknown),
        "this install read a widen its pinned anchor's removal never saw at full strength"
    );
    assert_eq!(
        fold.world_privacy(world()).read,
        EffectiveRead::MyMachines,
        "the widen only narrows here, down to the edit the removal saw"
    );
}

/// T2 (guard, green on both trees): a widen the pinned anchor's removal saw
/// keeps its strength here. M sets the world to MyMachines and widens it to
/// Everywhere; the pinned anchor then removes M, having seen both.
///
/// It proves the fix reads the pinned anchor's mark in the race and does
/// not only veto: with the veto alone, no chain this install reads would
/// give the race a reason, both edits would only narrow, and the world
/// would read MyMachines.
#[test]
fn a_widen_the_pinned_anchors_removal_saw_keeps_its_strength_here() {
    let pinned = Pinned::new();
    let served = &pinned.served;
    let mut parents = vec![pinned.m_roster, pinned.m_mark];
    parents.sort_unstable();
    let first = served.store_world_edit(
        &pinned.node,
        1,
        parents,
        pinned.machine,
        world(),
        settings(ReadLocation::MyMachines),
    );
    let widen = served.store_world_edit(
        &pinned.node,
        2,
        vec![first],
        pinned.machine,
        world(),
        settings(ReadLocation::Everywhere),
    );
    pinned.remove_m(BTreeSet::from([first, widen]));
    pinned.guard_edit_stands(first);
    pinned.guard_edit_stands(widen);

    let fold = served.vault.authority_fold().expect("authority fold");
    assert_eq!(
        fold.world_privacy(world()).read,
        EffectiveRead::Everywhere,
        "a widen the pinned anchor's removal saw lost its strength here"
    );
    assert!(
        fold.world_readable_on(world(), Destination::Unknown),
        "a widen the pinned anchor's removal saw is not readable on an unknown destination"
    );
}
