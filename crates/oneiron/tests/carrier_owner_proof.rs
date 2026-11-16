//! A carried answer that makes a machine mine stands only with an owner
//! key's proof (row CARRIER-OWNER-PROOF; the lead's ruling 15 Nov 12:1x,
//! item 1; FIX [CARRIER-SELF-ANSWER-MINE]).
//!
//! The carrier rule admits the install key of any live profiled machine, in
//! any role, a hosted node's included. So a hosted node may carry its own
//! answer `Owned(Yours)`, signed by its own key, and every replica then
//! counts it as the owner's machine: secrets seal to it and pads are granted
//! to it. Under the rule the answer stands only when one cosign by a live
//! owner key the host does not hold signs the same entry; without it the
//! answer is held, and the machine is not mine.
//!
//! Item 2 (the lead's ruling 15 Nov 13:2x, CARRIER-ITEM2-SCOPE = A): on a
//! self-host vault, an owner act a not-mine carrier delivers without that
//! proof waits for the owner's confirm. This file covers the shared
//! owner-choice gate (a home pick) and a machine removal.
//!
//! Strict (the lead's ruling 15 Nov 13:2x, CARRIER-GRANDFATHER = C): a
//! machine the owner's own laptop paired with no owner key's proof is held as
//! well, until the owner confirms it on an owner device.
//!
//! Pure folds over hand-signed rows: a genesis root key, the root's
//! registration of a hosted node, and the node's own answer, home pick or
//! removal of another machine; or the root's registration of the owner's
//! laptop and the laptop's pairing of a new machine.

#![cfg(oneiron_test_support)]

use std::collections::{BTreeMap, BTreeSet};

use ed25519_dalek::{Signer, SigningKey};
use oneiron::authority::{
    AUTHORITY_LOG_SCHEMA_VERSION, ActSurface, AuthorityAttestation, AuthorityEntryHash,
    AuthorityFold, AuthorityKey, AuthorityLogEntry, AuthorityOp, AuthoritySignature, AuthorityTier,
    AuthorityVaultId, DeviceAuthority, GenesisRecoveryStep, MACHINE_ENCRYPTION_KEY_LEN,
    MACHINE_ENCRYPTION_SUITE_HYBRID_V1, MachineDeviceClass, MachineEncryptionKey, MachineOwnership,
    MachineProfile, MachineRole, OwnerAct, OwnerActKind, ROLE_ADMIN, ROLE_CLOUD, ROLE_OWNER,
    authority_entry_hash, authority_transcript, fold_authority_log, fold_authority_log_for_posture,
    genesis_vault_id, machine_profile_proof_transcript,
};
use oneiron::test_doors::conversation_training_fold::leaves_out;
use oneiron::test_doors::home_pick_fold::home_pick_in_force;
use oneiron::{EntityId, HostingPrivacyPosture};
use oneiron_authority::authority::{
    ConversationTrainingSet, ConversationTrainingVaultSet, HomeNodePick,
    conversation_training_vault_target, home_pick_target, machine_answer_revision,
};

const ROOT_SEED: u8 = 61;
const NODE_SEED: u8 = 62;
const VICTIM_SEED: u8 = 63;
const LAPTOP_SEED: u8 = 64;
const PAIRED_SEED: u8 = 65;
const STRANGER_SEED: u8 = 66;

/// The node the owner's home pick names in test 3.
const PICKED_NODE: u64 = 7;

/// The node the owner's own laptop picks after a waiting pick.
const LAPTOPS_PICKED_NODE: u64 = 8;

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

/// `signer` signs `op` on `parent_hashes`, with one cosign by each of
/// `cosigners`. Every key is in the entry before any of them signs, so all
/// of them sign the same transcript.
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

/// The genesis row of a vault whose root key `root` holds `roles` at `tier`.
fn genesis_row(root: &SigningKey, roles: u16, tier: AuthorityTier) -> AuthorityLogEntry {
    signed(
        None,
        0,
        Vec::new(),
        AuthorityOp::Genesis {
            device: DeviceAuthority {
                key: key_of(root),
                transport_key_binding: [7; 32],
                attestation: AuthorityAttestation {
                    kind: "SoftwareArgon2id".to_owned(),
                    evidence: vec![1, 2, 3],
                },
                tier,
                roles,
            },
            genesis_nonce: [196; 32],
            recovery: GenesisRecoveryStep::Saved([1; 32]),
        },
        root,
        &[],
    )
}

/// A vault whose root registered one hosted node, and that node's own
/// answer, home pick or removal, cosigned by each of `cosigners`.
struct HostedNodeAnswer {
    root: SigningKey,
    node: SigningKey,
    machine: EntityId,
    rows: Vec<AuthorityLogEntry>,
    /// A managed host's vault: its root is the host's custodial key, and
    /// replicas fold under the hosted posture.
    hosted: bool,
}

impl HostedNodeAnswer {
    /// A self-host vault: its root is an owner-held key.
    fn new() -> Self {
        Self::with_root(ROLE_OWNER | ROLE_ADMIN, AuthorityTier::Software, false)
    }

    /// A managed host's vault whose only owner key is the host's custodial
    /// root, so no owner device key is enrolled.
    fn on_a_hosted_vault() -> Self {
        Self::with_root(
            ROLE_OWNER | ROLE_ADMIN | ROLE_CLOUD,
            AuthorityTier::CloudCustodial,
            true,
        )
    }

    fn with_root(roles: u16, tier: AuthorityTier, hosted: bool) -> Self {
        let root = signing(ROOT_SEED);
        let node = signing(NODE_SEED);
        let genesis = genesis_row(&root, roles, tier);
        let vault_id = genesis_vault_id(&genesis).expect("the vault id");
        let machine = EntityId::from_bytes([0x70; 16]).expect("an id");
        let registration = signed(
            Some(vault_id),
            1,
            vec![hash(&genesis)],
            AuthorityOp::MachineProfile(node_profile(
                vault_id,
                machine,
                &node,
                MachineRole::HostedNode,
                1,
                None,
            )),
            &root,
            &[],
        );
        Self {
            root,
            node,
            machine,
            rows: vec![genesis, registration],
            hosted,
        }
    }

    fn vault_id(&self) -> AuthorityVaultId {
        genesis_vault_id(&self.rows[0]).expect("the vault id")
    }

    /// The fold of the rows, under the hosted posture on a managed host's
    /// vault.
    fn fold(&self) -> AuthorityFold {
        if self.hosted {
            fold_authority_log_for_posture(
                &self.rows,
                &BTreeMap::new(),
                1,
                &BTreeMap::new(),
                HostingPrivacyPosture::Hosted,
            )
        } else {
            fold_authority_log(&self.rows)
        }
    }

    /// The node carries its own answer `Owned(Yours)` on the registration,
    /// signed by its own install key.
    fn answer_yours(mut self, cosigners: &[&SigningKey]) -> (AuthorityFold, EntityId, [u8; 32]) {
        let registration = hash(&self.rows[1]);
        let act = OwnerAct::by_owner(
            owner(),
            OwnerActKind::MachineAnswer,
            self.machine,
            ActSurface::ThisInstall,
            machine_answer_revision([registration]),
        );
        let answer = signed(
            Some(self.vault_id()),
            1,
            vec![registration],
            AuthorityOp::MachineProfile(node_profile(
                self.vault_id(),
                self.machine,
                &self.node,
                MachineRole::Owned(MachineOwnership::Yours),
                2,
                Some((self.machine, act)),
            )),
            &self.node,
            cosigners,
        );
        self.rows.push(answer);
        let node_key = self.node.verifying_key().to_bytes();
        (self.fold(), self.machine, node_key)
    }

    /// The node carries the owner's home pick of [`PICKED_NODE`] on the
    /// registration, signed by its own install key.
    fn pick_home(mut self, cosigners: &[&SigningKey]) -> AuthorityFold {
        let registration = hash(&self.rows[1]);
        let target = home_pick_target(&self.vault_id()).expect("the pick's target");
        // No pick is live yet, so the pick saw the zero revision.
        let act = OwnerAct::by_owner(
            owner(),
            OwnerActKind::HomeNodePick,
            target,
            ActSurface::ThisInstall,
            [0; 32],
        );
        let pick = signed(
            Some(self.vault_id()),
            1,
            vec![registration],
            AuthorityOp::HomeNodePick(HomeNodePick {
                act,
                machine: self.machine,
                node_id: Some(PICKED_NODE),
            }),
            &self.node,
            cosigners,
        );
        self.rows.push(pick);
        self.fold()
    }

    /// The node carries `op` on the registration, signed by its own install
    /// key with no cosign. Returns the fold and the entry.
    fn node_carries(mut self, op: AuthorityOp) -> (AuthorityFold, AuthorityEntryHash) {
        let carried = signed(
            Some(self.vault_id()),
            1,
            vec![hash(&self.rows[1])],
            op,
            &self.node,
            &[],
        );
        let entry = hash(&carried);
        self.rows.push(carried);
        (self.fold(), entry)
    }

    /// The root registers a second machine, an execution node, and the node
    /// carries the owner's removal of it, signed by its own install key.
    /// Returns the fold and the removed machine.
    fn remove_another_machine(mut self) -> (AuthorityFold, EntityId) {
        let vault_id = self.vault_id();
        let victim_key = signing(VICTIM_SEED);
        let victim = EntityId::from_bytes([0x72; 16]).expect("an id");
        let registration = signed(
            Some(vault_id),
            2,
            vec![hash(&self.rows[1])],
            AuthorityOp::MachineProfile(node_profile(
                vault_id,
                victim,
                &victim_key,
                MachineRole::ExecutionNode,
                1,
                None,
            )),
            &self.root,
            &[],
        );
        let victim_registration = hash(&registration);
        self.rows.push(registration);
        let act = OwnerAct::by_owner(
            owner(),
            OwnerActKind::MachineRemoval,
            victim,
            ActSurface::ThisInstall,
            machine_answer_revision([victim_registration]),
        );
        let removal = signed(
            Some(vault_id),
            1,
            vec![victim_registration],
            AuthorityOp::MachineProfile(node_profile(
                vault_id,
                victim,
                &victim_key,
                MachineRole::Removed,
                2,
                Some((self.machine, act)),
            )),
            &self.node,
            &[],
        );
        self.rows.push(removal);
        (self.fold(), victim)
    }
}

/// A self-host vault whose root registered the owner's laptop as the owner's
/// machine, and the laptop's pairing of a new machine, carried by the
/// laptop's own install key with no cosign: every paired machine today.
struct PairedMachine {
    root: SigningKey,
    laptop: SigningKey,
    laptop_machine: EntityId,
    paired: SigningKey,
    paired_machine: EntityId,
    rows: Vec<AuthorityLogEntry>,
}

impl PairedMachine {
    fn new() -> Self {
        let root = signing(ROOT_SEED);
        let laptop = signing(LAPTOP_SEED);
        let paired = signing(PAIRED_SEED);
        let genesis = genesis_row(&root, ROLE_OWNER | ROLE_ADMIN, AuthorityTier::Software);
        let vault_id = genesis_vault_id(&genesis).expect("the vault id");
        let laptop_machine = EntityId::from_bytes([0x73; 16]).expect("an id");
        let paired_machine = EntityId::from_bytes([0x74; 16]).expect("an id");
        let registration = signed(
            Some(vault_id),
            1,
            vec![hash(&genesis)],
            AuthorityOp::MachineProfile(node_profile(
                vault_id,
                laptop_machine,
                &laptop,
                MachineRole::Owned(MachineOwnership::Yours),
                1,
                None,
            )),
            &root,
            &[],
        );
        // The paired machine has no revision yet, so the pairing saw the
        // zero revision.
        let act = OwnerAct::by_owner(
            owner(),
            OwnerActKind::Pairing,
            paired_machine,
            ActSurface::ThisInstall,
            [0; 32],
        );
        let pairing = signed(
            Some(vault_id),
            1,
            vec![hash(&registration)],
            AuthorityOp::MachineProfile(node_profile(
                vault_id,
                paired_machine,
                &paired,
                MachineRole::Owned(MachineOwnership::Yours),
                1,
                Some((laptop_machine, act)),
            )),
            &laptop,
            &[],
        );
        Self {
            root,
            laptop,
            laptop_machine,
            paired,
            paired_machine,
            rows: vec![genesis, registration, pairing],
        }
    }

    /// The owner confirms the paired machine on an owner device: the laptop
    /// carries the owner's answer `Owned(Yours)` again at revision 2, over
    /// the pairing, cosigned by each of `cosigners`.
    fn confirm(mut self, cosigners: &[&SigningKey]) -> AuthorityFold {
        let vault_id = genesis_vault_id(&self.rows[0]).expect("the vault id");
        let pairing = hash(&self.rows[2]);
        let act = OwnerAct::by_owner(
            owner(),
            OwnerActKind::MachineAnswer,
            self.paired_machine,
            ActSurface::ThisInstall,
            machine_answer_revision([pairing]),
        );
        let confirm = signed(
            Some(vault_id),
            2,
            vec![pairing],
            AuthorityOp::MachineProfile(node_profile(
                vault_id,
                self.paired_machine,
                &self.paired,
                MachineRole::Owned(MachineOwnership::Yours),
                2,
                Some((self.laptop_machine, act)),
            )),
            &self.laptop,
            cosigners,
        );
        self.rows.push(confirm);
        fold_authority_log(&self.rows)
    }

    /// The laptop carries the owner's answer `Owned(Yours)` about the paired
    /// machine at `revision`, naming the key of `key_holder`, on `parents`,
    /// cosigned by each of `cosigners`. Returns the answer's entry.
    fn laptop_answers_yours(
        &mut self,
        seq: u64,
        parents: Vec<AuthorityEntryHash>,
        key_holder: &SigningKey,
        revision: u64,
        cosigners: &[&SigningKey],
    ) -> AuthorityEntryHash {
        let vault_id = genesis_vault_id(&self.rows[0]).expect("the vault id");
        let act = OwnerAct::by_owner(
            owner(),
            OwnerActKind::MachineAnswer,
            self.paired_machine,
            ActSurface::ThisInstall,
            machine_answer_revision(parents.iter().copied()),
        );
        let answer = signed(
            Some(vault_id),
            seq,
            parents,
            AuthorityOp::MachineProfile(node_profile(
                vault_id,
                self.paired_machine,
                key_holder,
                MachineRole::Owned(MachineOwnership::Yours),
                revision,
                Some((self.laptop_machine, act)),
            )),
            &self.laptop,
            cosigners,
        );
        let entry = hash(&answer);
        self.rows.push(answer);
        entry
    }
}

/// A self-host vault whose root registered a hosted node and then the
/// owner's laptop as the owner's machine (a root-signed roster revision, so
/// the laptop is mine with no carried act).
struct LaptopBesideNode {
    node: HostedNodeAnswer,
    laptop: SigningKey,
    laptop_machine: EntityId,
}

impl LaptopBesideNode {
    fn new() -> Self {
        let mut node = HostedNodeAnswer::new();
        let laptop = signing(LAPTOP_SEED);
        let laptop_machine = EntityId::from_bytes([0x73; 16]).expect("an id");
        let vault_id = node.vault_id();
        let registration = signed(
            Some(vault_id),
            2,
            vec![hash(&node.rows[1])],
            AuthorityOp::MachineProfile(node_profile(
                vault_id,
                laptop_machine,
                &laptop,
                MachineRole::Owned(MachineOwnership::Yours),
                1,
                None,
            )),
            &node.root,
            &[],
        );
        node.rows.push(registration);
        Self {
            node,
            laptop,
            laptop_machine,
        }
    }

    fn laptop_key(&self) -> [u8; 32] {
        self.laptop.verifying_key().to_bytes()
    }

    /// `carrier_key`, the install key of `carrier`, carries the owner's
    /// answer about the laptop: `role` at revision 2, naming the key of
    /// `key_holder`, on the laptop's registration.
    fn answer_for_the_laptop(
        mut self,
        carrier: EntityId,
        carrier_key: &SigningKey,
        role: MachineRole,
        key_holder: &SigningKey,
    ) -> AuthorityFold {
        let vault_id = self.node.vault_id();
        let registration = hash(&self.node.rows[2]);
        let act = OwnerAct::by_owner(
            owner(),
            OwnerActKind::MachineAnswer,
            self.laptop_machine,
            ActSurface::ThisInstall,
            machine_answer_revision([registration]),
        );
        let answer = signed(
            Some(vault_id),
            1,
            vec![registration],
            AuthorityOp::MachineProfile(node_profile(
                vault_id,
                self.laptop_machine,
                key_holder,
                role,
                2,
                Some((carrier, act)),
            )),
            carrier_key,
            &[],
        );
        self.node.rows.push(answer);
        self.node.fold()
    }

    /// The hosted node carries the owner's answer about the laptop.
    fn node_answers_for_the_laptop(
        self,
        role: MachineRole,
        key_holder: &SigningKey,
    ) -> AuthorityFold {
        let (machine, node) = (self.node.machine, self.node.node.clone());
        self.answer_for_the_laptop(machine, &node, role, key_holder)
    }

    /// The node's home pick of [`PICKED_NODE`] with no proof, and the laptop's
    /// pick of [`LAPTOPS_PICKED_NODE`] over it, having seen no live pick.
    fn node_and_laptop_picks(&self) -> [AuthorityLogEntry; 2] {
        let vault_id = self.node.vault_id();
        let target = home_pick_target(&vault_id).expect("the pick's target");
        let pick = |machine: EntityId, node_id: u64| {
            AuthorityOp::HomeNodePick(HomeNodePick {
                act: OwnerAct::by_owner(
                    owner(),
                    OwnerActKind::HomeNodePick,
                    target,
                    ActSurface::ThisInstall,
                    [0; 32],
                ),
                machine,
                node_id: Some(node_id),
            })
        };
        let nodes_pick = signed(
            Some(vault_id),
            1,
            vec![hash(&self.node.rows[2])],
            pick(self.node.machine, PICKED_NODE),
            &self.node.node,
            &[],
        );
        let laptops_pick = signed(
            Some(vault_id),
            1,
            vec![hash(&nodes_pick)],
            pick(self.laptop_machine, LAPTOPS_PICKED_NODE),
            &self.laptop,
            &[],
        );
        [nodes_pick, laptops_pick]
    }

    /// The node carries a home pick with no proof, then the laptop carries
    /// the owner's pick over it.
    fn node_then_laptop_pick(mut self) -> AuthorityFold {
        let picks = self.node_and_laptop_picks();
        self.node.rows.extend(picks);
        self.node.fold()
    }
}

fn owner() -> EntityId {
    EntityId::from_bytes([0x71; 16]).expect("an id")
}

/// A person of the vault who is not its owner.
fn member() -> EntityId {
    EntityId::from_bytes([0x75; 16]).expect("an id")
}

/// `node`'s profile of `machine` in `role` at `revision`, carried by
/// `carried` when it is an owner act.
fn node_profile(
    vault_id: AuthorityVaultId,
    machine: EntityId,
    node: &SigningKey,
    role: MachineRole,
    revision: u64,
    carried: Option<(EntityId, OwnerAct)>,
) -> MachineProfile {
    let machine_key = node.verifying_key().to_bytes();
    let encryption_key = MachineEncryptionKey {
        suite: MACHINE_ENCRYPTION_SUITE_HYBRID_V1,
        key: vec![7; MACHINE_ENCRYPTION_KEY_LEN],
    };
    let machine_proof = node
        .sign(&machine_profile_proof_transcript(
            &vault_id,
            machine,
            &machine_key,
            MachineDeviceClass::Computer,
            &encryption_key,
        ))
        .to_bytes();
    MachineProfile {
        machine,
        owner: owner(),
        machine_key,
        device_class: MachineDeviceClass::Computer,
        encryption_key,
        role,
        revision,
        machine_proof,
        seen_world_edits: BTreeSet::new(),
        carrier: carried.as_ref().map(|(carrier, _)| *carrier),
        act: carried.map(|(_, act)| act),
    }
}

/// Mine by every reader the fold offers: the machine's own standing, the
/// trusted identity, and the lookup by key.
fn mine(fold: &AuthorityFold, machine: EntityId, machine_key: &[u8; 32]) -> bool {
    let readers = [
        fold.machine(machine)
            .is_some_and(|folded| folded.is_mine(None)),
        fold.trusted_machine(machine).is_some(),
        fold.mine_machine_by_key(machine_key) == Some(machine),
    ];
    assert!(
        readers.iter().all(|reader| *reader == readers[0]),
        "the fold's mine readers disagree: {readers:?}"
    );
    readers[0]
}

/// The held answers about `machine` that still ask the owner, by entry.
fn asking(fold: &AuthorityFold, machine: EntityId) -> BTreeSet<AuthorityEntryHash> {
    fold.held_machine_answers()
        .get(&machine)
        .map(|held| held.keys().copied().collect())
        .unwrap_or_default()
}

/// Test 1 of the row. Main: the answer folds, and the node is mine.
#[test]
fn a_hosted_nodes_own_yours_answer_stays_held() {
    let (fold, machine, node_key) = HostedNodeAnswer::new().answer_yours(&[]);
    assert!(
        fold.machine(machine).is_some(),
        "the root's registration of the node folds"
    );
    assert!(
        !mine(&fold, machine, &node_key),
        "a hosted node's own answer, with no owner key's proof, never makes it mine"
    );
}

/// Test 2 of the row. Main: the fold refuses any cosign on an answer, so the
/// node is not mine.
#[test]
fn an_owner_key_cosigned_answer_carried_by_the_same_node_stands() {
    let answer = HostedNodeAnswer::new();
    let root = answer.root.clone();
    let (fold, machine, node_key) = answer.answer_yours(&[&root]);
    assert!(
        mine(&fold, machine, &node_key),
        "the same answer cosigned by the live owner-held root makes the node mine: {:?}",
        fold.issues
    );
}

/// Test 3 of the row (item 2, the shared owner-choice gate). Main: the pick
/// lands.
#[test]
fn a_hosted_nodes_unproven_home_pick_waits() {
    let fold = HostedNodeAnswer::new().pick_home(&[]);
    assert_eq!(
        home_pick_in_force(&fold),
        None,
        "a not-mine node's home pick with no owner key's proof waits for the owner: {:?}",
        fold.issues
    );
}

/// Test 3, proven. Main: the gate refuses any cosign, so no pick lands.
#[test]
fn an_owner_key_cosigned_home_pick_carried_by_a_hosted_node_lands() {
    let answer = HostedNodeAnswer::new();
    let root = answer.root.clone();
    let fold = answer.pick_home(&[&root]);
    assert_eq!(
        home_pick_in_force(&fold),
        Some(PICKED_NODE),
        "the same pick cosigned by the live owner-held root lands: {:?}",
        fold.issues
    );
}

/// Test 3b of the row (item 2, a machine removal). Main: the removal lands,
/// and no later revision brings the machine back.
#[test]
fn a_hosted_nodes_unproven_removal_of_another_machine_waits() {
    let (fold, victim) = HostedNodeAnswer::new().remove_another_machine();
    let head = fold
        .machine(victim)
        .and_then(|folded| folded.roster.as_ref())
        .expect("the root's registration of the victim folds");
    assert_ne!(
        head.profile.role,
        MachineRole::Removed,
        "a not-mine node's removal with no owner key's proof waits for the owner: {:?}",
        fold.issues
    );
    assert!(
        head.is_live(),
        "the victim's registration still stands: {:?}",
        fold.issues
    );
}

/// Test 3, hosted guard (the lead's ruling 15 Nov 13:2x,
/// CARRIER-HOSTED-WEB-ACTS = C): item 2 waits for an enrolled owner device
/// key on a managed host's vault. With none, the node's pick lands as today.
/// Main: the pick lands.
#[test]
fn a_hosted_nodes_unproven_home_pick_lands_on_a_hosted_vault_with_no_owner_device_key() {
    let fold = HostedNodeAnswer::on_a_hosted_vault().pick_home(&[]);
    assert_eq!(
        home_pick_in_force(&fold),
        Some(PICKED_NODE),
        "a hosted vault with no enrolled owner device key keeps today's pick: {:?}",
        fold.issues
    );
}

/// Item 1 on a managed host's vault (CARRIER-HOSTED-WEB-ACTS = C: item 1
/// applies everywhere). The host's custodial root is no owner key, so neither
/// the node's own answer nor the same answer cosigned by that root makes the
/// node mine. Main: the bare answer makes the node mine.
#[test]
fn a_custodial_roots_cosign_proves_nothing_on_a_hosted_vault() {
    let (fold, machine, node_key) = HostedNodeAnswer::on_a_hosted_vault().answer_yours(&[]);
    assert!(
        !mine(&fold, machine, &node_key),
        "a hosted node's own answer on a hosted vault, with no owner key's proof, never makes it mine"
    );
    let answer = HostedNodeAnswer::on_a_hosted_vault();
    let root = answer.root.clone();
    let (fold, machine, node_key) = answer.answer_yours(&[&root]);
    assert!(
        !mine(&fold, machine, &node_key),
        "the host's custodial root proves nothing for the owner: {:?}",
        fold.issues
    );
}

/// Test 4 of the row (strict, CARRIER-GRANDFATHER = C). Main: the pairing
/// makes the machine mine.
#[test]
fn a_machine_paired_without_an_owner_keys_proof_is_held() {
    let paired = PairedMachine::new();
    let fold = fold_authority_log(&paired.rows);
    let laptop_key = paired.laptop.verifying_key().to_bytes();
    assert!(
        mine(&fold, paired.laptop_machine, &laptop_key),
        "the root's registration of the laptop stands: {:?}",
        fold.issues
    );
    let paired_key = paired.paired.verifying_key().to_bytes();
    assert!(
        !mine(&fold, paired.paired_machine, &paired_key),
        "a pairing the owner's laptop carried with no owner key's proof is held, not mine"
    );
}

/// Test 4, the confirm. The owner's answer again, cosigned by the live
/// owner-held root, makes the held machine mine, and the fold trusts the
/// confirmed revision. Main: the fold refuses the cosigned confirm, so the
/// revision it trusts stays the unproven pairing.
#[test]
fn an_owner_key_cosigned_confirm_over_a_held_pairing_makes_the_machine_mine() {
    let paired = PairedMachine::new();
    let root = paired.root.clone();
    let paired_machine = paired.paired_machine;
    let paired_key = paired.paired.verifying_key().to_bytes();
    let fold = paired.confirm(&[&root]);
    assert!(
        mine(&fold, paired_machine, &paired_key),
        "the confirmed machine is mine: {:?}",
        fold.issues
    );
    assert_eq!(
        fold.trusted_machine(paired_machine)
            .map(|trusted| trusted.profile.revision),
        Some(2),
        "the fold trusts the owner key's confirm, not the held pairing: {:?}",
        fold.issues
    );
}

/// Guard: a cosign by a key the roster does not hold, or a second cosign
/// beside the owner key's, proves nothing (a forged proof is an invalid
/// entry, not a held one). Main: the fold refuses any cosign.
#[test]
fn a_strangers_cosign_or_a_second_cosign_proves_nothing() {
    let stranger = signing(STRANGER_SEED);
    let (fold, machine, node_key) = HostedNodeAnswer::new().answer_yours(&[&stranger]);
    assert!(
        !mine(&fold, machine, &node_key),
        "a stranger's cosign is no owner key's proof"
    );
    let answer = HostedNodeAnswer::new();
    let root = answer.root.clone();
    let (fold, machine, node_key) = answer.answer_yours(&[&root, &stranger]);
    assert!(
        !mine(&fold, machine, &node_key),
        "a proven answer carries exactly one cosign"
    );
}

/// Guard: a revision of a mine machine that keeps it the owner's, carried by
/// the machine itself under its own key, needs no proof (a class revision
/// makes nothing mine). Main: it lands.
#[test]
fn a_mine_machines_own_class_revision_needs_no_proof() {
    let beside = LaptopBesideNode::new();
    let (laptop_machine, laptop_key, laptop) = (
        beside.laptop_machine,
        beside.laptop_key(),
        beside.laptop.clone(),
    );
    let fold = beside.answer_for_the_laptop(
        laptop_machine,
        &laptop,
        MachineRole::Owned(MachineOwnership::Yours),
        &laptop,
    );
    assert!(
        mine(&fold, laptop_machine, &laptop_key),
        "the laptop stays mine: {:?}",
        fold.issues
    );
    assert_eq!(
        fold.trusted_machine(laptop_machine)
            .map(|trusted| trusted.profile.revision),
        Some(2),
        "the laptop's own class revision stands with no proof: {:?}",
        fold.issues
    );
}

/// Item 1: a not-mine carrier's answer that keeps a mine machine the
/// owner's under a NEW key makes that key mine, so it needs the proof too.
/// Unproven, it is held and the laptop keeps its key. Main: the node's answer
/// re-keys the laptop.
#[test]
fn a_hosted_nodes_unproven_rekey_of_a_mine_machine_is_held() {
    let beside = LaptopBesideNode::new();
    let (laptop_machine, laptop_key) = (beside.laptop_machine, beside.laptop_key());
    let stranger = signing(STRANGER_SEED);
    let fold =
        beside.node_answers_for_the_laptop(MachineRole::Owned(MachineOwnership::Yours), &stranger);
    assert_eq!(
        fold.trusted_machine(laptop_machine)
            .map(|trusted| trusted.profile.machine_key),
        Some(laptop_key),
        "the laptop keeps its own key: {:?}",
        fold.issues
    );
    assert!(
        mine(&fold, laptop_machine, &laptop_key),
        "the laptop stays mine: {:?}",
        fold.issues
    );
}

/// Item 2 on the MachineProfile op: a not-mine carrier's unproven demote of a
/// mine machine waits. Main: the laptop is no longer mine.
#[test]
fn a_hosted_nodes_unproven_demote_of_a_mine_machine_waits() {
    let beside = LaptopBesideNode::new();
    let (laptop_machine, laptop_key, laptop) = (
        beside.laptop_machine,
        beside.laptop_key(),
        beside.laptop.clone(),
    );
    let fold = beside
        .node_answers_for_the_laptop(MachineRole::Owned(MachineOwnership::WorkSchool), &laptop);
    assert!(
        mine(&fold, laptop_machine, &laptop_key),
        "a not-mine node's demote with no owner key's proof waits for the owner: {:?}",
        fold.issues
    );
}

/// Guard: a proof never lifts a refusal. The root removed the node, so its
/// later pick is refused even with the owner key's cosign. Main: the fold
/// refuses any cosign.
#[test]
fn an_owner_keys_cosign_never_lifts_a_removed_carriers_refusal() {
    let mut answer = HostedNodeAnswer::new();
    let vault_id = answer.vault_id();
    let removal = signed(
        Some(vault_id),
        2,
        vec![hash(&answer.rows[1])],
        AuthorityOp::MachineProfile(node_profile(
            vault_id,
            answer.machine,
            &answer.node,
            MachineRole::Removed,
            2,
            None,
        )),
        &answer.root,
        &[],
    );
    let target = home_pick_target(&vault_id).expect("the pick's target");
    let pick = signed(
        Some(vault_id),
        1,
        vec![hash(&removal)],
        AuthorityOp::HomeNodePick(HomeNodePick {
            act: OwnerAct::by_owner(
                owner(),
                OwnerActKind::HomeNodePick,
                target,
                ActSurface::ThisInstall,
                [0; 32],
            ),
            machine: answer.machine,
            node_id: Some(PICKED_NODE),
        }),
        &answer.node,
        &[&answer.root],
    );
    answer.rows.push(removal);
    answer.rows.push(pick);
    let fold = answer.fold();
    assert_eq!(
        home_pick_in_force(&fold),
        None,
        "a removed carrier's pick lands nowhere, proven or not: {:?}",
        fold.issues
    );
}

/// Item 2, the confirm: the owner's own laptop carries the pick again over a
/// waiting one (re-carry, no confirm op). The waiting pick never joined the
/// live choices, so the laptop's pick names the zero revision and lands.
/// Main: the node's pick landed, so the laptop's pick names a stale
/// revision and the node's pick stays in force.
#[test]
fn an_owner_laptops_pick_lands_over_a_waiting_pick() {
    let fold = LaptopBesideNode::new().node_then_laptop_pick();
    assert_eq!(
        home_pick_in_force(&fold),
        Some(LAPTOPS_PICKED_NODE),
        "the owner's own pick lands over the waiting one: {:?}",
        fold.issues
    );
}

/// Guard (plan read F2): revision numbers never decide what asks. A held
/// answer at the last revision a profile can name blocks nothing: the
/// owner's confirm lands under it, the machine is mine, and both held
/// answers the confirm saw ask no more.
#[test]
fn a_held_answer_at_the_last_revision_never_blocks_the_owners_confirm() {
    let mut paired = PairedMachine::new();
    let (root, key_holder) = (paired.root.clone(), paired.paired.clone());
    let paired_machine = paired.paired_machine;
    let paired_key = key_holder.verifying_key().to_bytes();
    let pairing = hash(&paired.rows[2]);
    let last = paired.laptop_answers_yours(2, vec![pairing], &key_holder, u64::MAX, &[]);
    let fold = fold_authority_log(&paired.rows);
    assert_eq!(
        asking(&fold, paired_machine),
        BTreeSet::from([pairing, last]),
        "both unproven answers are held and ask: {:?}",
        fold.issues
    );
    paired.laptop_answers_yours(3, vec![last], &key_holder, 2, &[&root]);
    let fold = fold_authority_log(&paired.rows);
    assert!(
        mine(&fold, paired_machine, &paired_key),
        "the owner key's confirm lands under the held answer: {:?}",
        fold.issues
    );
    assert_eq!(
        fold.trusted_machine(paired_machine)
            .map(|trusted| trusted.profile.revision),
        Some(2),
        "the fold trusts the confirm: {:?}",
        fold.issues
    );
    assert_eq!(
        asking(&fold, paired_machine),
        BTreeSet::new(),
        "the confirm ends the ask of every held answer it saw"
    );
}

/// Guard (plan read F2): an unproven answer after the owner's confirm is a
/// new ask. The laptop carries a new key for the confirmed machine with no
/// proof: it is held and asks alone, and the machine keeps its key.
#[test]
fn an_unproven_answer_after_the_owners_confirm_asks_again() {
    let mut paired = PairedMachine::new();
    let (root, key_holder) = (paired.root.clone(), paired.paired.clone());
    let paired_machine = paired.paired_machine;
    let paired_key = key_holder.verifying_key().to_bytes();
    let pairing = hash(&paired.rows[2]);
    let confirm = paired.laptop_answers_yours(2, vec![pairing], &key_holder, 2, &[&root]);
    let rekey = paired.laptop_answers_yours(3, vec![confirm], &signing(STRANGER_SEED), 3, &[]);
    let fold = fold_authority_log(&paired.rows);
    assert!(
        mine(&fold, paired_machine, &paired_key),
        "the confirmed machine keeps its key: {:?}",
        fold.issues
    );
    assert_eq!(
        asking(&fold, paired_machine),
        BTreeSet::from([rekey]),
        "the new unproven answer asks, and the answered pairing does not"
    );
}

/// Guard (plan read F1): mine is read with the removal race applied, never
/// off a raw chain head. A node paired a machine with the owner key's proof;
/// then the owner's laptop removed the node by a removal that never saw the
/// pairing, so the pairing stands on nothing and the machine is not mine. An
/// answer that keeps it `Owned(Yours)` under the same key would make it mine
/// again, so it needs the proof even from the owner's own laptop.
#[test]
fn a_machine_whose_carrier_lost_its_removal_race_is_not_mine_again_without_proof() {
    let mut beside = LaptopBesideNode::new();
    let vault_id = beside.node.vault_id();
    let paired = signing(PAIRED_SEED);
    let paired_key = paired.verifying_key().to_bytes();
    let paired_machine = EntityId::from_bytes([0x74; 16]).expect("an id");
    let yours = MachineRole::Owned(MachineOwnership::Yours);
    let pairing = signed(
        Some(vault_id),
        1,
        vec![hash(&beside.node.rows[2])],
        AuthorityOp::MachineProfile(node_profile(
            vault_id,
            paired_machine,
            &paired,
            yours,
            1,
            Some((
                beside.node.machine,
                OwnerAct::by_owner(
                    owner(),
                    OwnerActKind::Pairing,
                    paired_machine,
                    ActSurface::ThisInstall,
                    [0; 32],
                ),
            )),
        )),
        &beside.node.node,
        &[&beside.node.root],
    );
    let removal = signed(
        Some(vault_id),
        1,
        vec![hash(&pairing)],
        AuthorityOp::MachineProfile(node_profile(
            vault_id,
            beside.node.machine,
            &beside.node.node,
            MachineRole::Removed,
            2,
            Some((
                beside.laptop_machine,
                OwnerAct::by_owner(
                    owner(),
                    OwnerActKind::MachineRemoval,
                    beside.node.machine,
                    ActSurface::ThisInstall,
                    machine_answer_revision([hash(&beside.node.rows[1])]),
                ),
            )),
        )),
        &beside.laptop,
        &[],
    );
    let again = signed(
        Some(vault_id),
        2,
        vec![hash(&removal)],
        AuthorityOp::MachineProfile(node_profile(
            vault_id,
            paired_machine,
            &paired,
            yours,
            2,
            Some((
                beside.laptop_machine,
                OwnerAct::by_owner(
                    owner(),
                    OwnerActKind::MachineAnswer,
                    paired_machine,
                    ActSurface::ThisInstall,
                    machine_answer_revision([hash(&pairing)]),
                ),
            )),
        )),
        &beside.laptop,
        &[],
    );
    let again_entry = hash(&again);
    beside.node.rows.push(pairing);
    let fold = beside.node.fold();
    assert!(
        mine(&fold, paired_machine, &paired_key),
        "the proven pairing makes the machine mine: {:?}",
        fold.issues
    );
    beside.node.rows.push(removal);
    let fold = beside.node.fold();
    assert!(
        !mine(&fold, paired_machine, &paired_key),
        "the pairing's carrier lost its removal race, so the machine is not mine: {:?}",
        fold.issues
    );
    beside.node.rows.push(again);
    let fold = beside.node.fold();
    assert!(
        !mine(&fold, paired_machine, &paired_key),
        "an unproven answer never makes it mine again: {:?}",
        fold.issues
    );
    assert_eq!(
        asking(&fold, paired_machine),
        BTreeSet::from([again_entry]),
        "the unproven answer is held and asks: {:?}",
        fold.issues
    );
}

/// Guard (plan read F4, the strict cascade): a held machine carries nothing.
/// Its own later answer is an invalid entry, not a second held answer, so
/// the owner's confirm of the pairing is the only way in.
#[test]
fn a_held_machines_own_later_answer_is_refused_not_held() {
    let mut paired = PairedMachine::new();
    let vault_id = genesis_vault_id(&paired.rows[0]).expect("the vault id");
    let paired_machine = paired.paired_machine;
    let paired_key = paired.paired.verifying_key().to_bytes();
    let pairing = hash(&paired.rows[2]);
    let issues_before = fold_authority_log(&paired.rows).issues.len();
    let own_answer = signed(
        Some(vault_id),
        1,
        vec![pairing],
        AuthorityOp::MachineProfile(node_profile(
            vault_id,
            paired_machine,
            &paired.paired,
            MachineRole::Owned(MachineOwnership::Yours),
            2,
            Some((
                paired_machine,
                OwnerAct::by_owner(
                    owner(),
                    OwnerActKind::MachineAnswer,
                    paired_machine,
                    ActSurface::ThisInstall,
                    machine_answer_revision([pairing]),
                ),
            )),
        )),
        &paired.paired,
        &[],
    );
    paired.rows.push(own_answer);
    let fold = fold_authority_log(&paired.rows);
    assert!(
        !mine(&fold, paired_machine, &paired_key),
        "a held machine's own answer makes nothing mine"
    );
    assert_eq!(
        asking(&fold, paired_machine),
        BTreeSet::from([pairing]),
        "only the pairing asks: {:?}",
        fold.issues
    );
    assert!(
        fold.issues.len() > issues_before,
        "the held machine's own answer is an invalid entry: {:?}",
        fold.issues
    );
}

/// Item 2, what asks: a waiting pick asks the owner until the owner's own
/// pick, which saw it, lands; then nothing asks.
#[test]
fn a_waiting_pick_asks_until_the_owners_pick_lands() {
    let mut beside = LaptopBesideNode::new();
    let [nodes_pick, laptops_pick] = beside.node_and_laptop_picks();
    let waiting = hash(&nodes_pick);
    beside.node.rows.push(nodes_pick);
    let fold = beside.node.fold();
    assert_eq!(
        fold.waiting_owner_choices(),
        &BTreeSet::from([waiting]),
        "the node's unproven pick waits and asks: {:?}",
        fold.issues
    );
    beside.node.rows.push(laptops_pick);
    let fold = beside.node.fold();
    assert_eq!(
        home_pick_in_force(&fold),
        Some(LAPTOPS_PICKED_NODE),
        "the owner's own pick lands: {:?}",
        fold.issues
    );
    assert_eq!(
        fold.waiting_owner_choices(),
        &BTreeSet::new(),
        "the owner's pick ends the ask of the waiting pick it saw"
    );
}

/// `person`'s conversation-training choice for `target`, carried by
/// `machine`, having seen no live choice.
fn training_choice(person: EntityId, target: EntityId, machine: EntityId) -> AuthorityOp {
    AuthorityOp::ConversationTrainingSet(ConversationTrainingSet {
        act: OwnerAct::by_owner(
            person,
            OwnerActKind::ConversationTraining,
            target,
            ActSurface::ThisInstall,
            [0; 32],
        ),
        machine,
        leave_out: true,
    })
}

/// Ruling CARRIER-PERSON-OPT-OUT = A: a person's own opt-out of conversation
/// training is that person's act, not the vault owner's, so it lands through
/// a carrier that is not the owner's machine, as it does on main.
#[test]
fn a_members_own_opt_out_lands_through_a_not_mine_carrier() {
    let answer = HostedNodeAnswer::new();
    let node = answer.machine;
    let (fold, _) = answer.node_carries(training_choice(member(), member(), node));
    assert!(
        leaves_out(&fold, member()),
        "the member's own opt-out lands: {:?}",
        fold.issues
    );
    assert_eq!(
        fold.waiting_owner_choices(),
        &BTreeSet::new(),
        "a person's own choice never waits for the vault owner's proof"
    );
}

/// The same ruling's other side: the vault-wide training setting is the
/// vault owner's act, so a not-mine carrier's unproven set waits.
#[test]
fn an_admins_vault_wide_training_setting_waits_through_a_not_mine_carrier() {
    let answer = HostedNodeAnswer::new();
    let node = answer.machine;
    let target = conversation_training_vault_target(&answer.vault_id()).expect("the target");
    let (fold, entry) = answer.node_carries(AuthorityOp::ConversationTrainingVaultSet(
        ConversationTrainingVaultSet {
            act: OwnerAct::by_owner(
                owner(),
                OwnerActKind::ConversationTraining,
                target,
                ActSurface::ThisInstall,
                [0; 32],
            ),
            machine: node,
            on: true,
            allow_opt_out: true,
        },
    ));
    assert_eq!(
        fold.waiting_owner_choices(),
        &BTreeSet::from([entry]),
        "the vault-wide setting waits for the owner: {:?}",
        fold.issues
    );
}

/// The exemption is the person's own choice only. A choice that names
/// another person as its target fails the entry body's shape check
/// (`ConversationTrainingSet::validate`), which runs on every encode and
/// every decode: the row has no hash, so no store keeps it and no fold reads
/// it, whoever carries it. The same row with the person's own target is
/// well-formed.
#[test]
fn a_training_choice_for_another_person_is_still_refused() {
    let answer = HostedNodeAnswer::new();
    let carried_by_the_node = |op: AuthorityOp| {
        signed(
            Some(answer.vault_id()),
            1,
            vec![hash(&answer.rows[1])],
            op,
            &answer.node,
            &[],
        )
    };
    let own = carried_by_the_node(training_choice(member(), member(), answer.machine));
    let for_another = carried_by_the_node(training_choice(owner(), member(), answer.machine));
    assert!(
        own.validate_shape().is_ok() && authority_entry_hash(&own).is_ok(),
        "a person's own choice is a well-formed entry"
    );
    assert!(
        for_another.validate_shape().is_err(),
        "nobody opts another person out: the entry's shape refuses the target"
    );
    assert!(
        authority_entry_hash(&for_another).is_err(),
        "an entry with no hash is stored and folded nowhere"
    );
}
