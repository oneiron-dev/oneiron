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
//!
//! The door tests at the end run a real vault whose serving install carries
//! the owner's acts: an answer it cannot prove is stored and held, and the
//! owner's answer on an install that holds his key stands and ends the ask.
//! A choice door refuses a choice it cannot prove, storing nothing, only
//! where the vault holds an owner key and this install holds none (ruling
//! CARRIER-CHOICE-DOOR-WAIT-OR-REFUSE = B and the lead's amendment).
//!
//! A person's own choice (rulings CARRIER-PERSON-OPT-OUT = A and
//! CARRIER-PERSON-OPT-BACK-IN = A, the lead's AUTH-4 PERSON-PROOF-RUNG = A):
//! their opt-out of conversation training narrows their own row, so it lands
//! through any carrier. Their opt back in widens it, and a carrier proves
//! only itself: through a machine that is not the owner's it waits where the
//! vault holds an owner key, and the person's door refuses it there.
//!
//! The ratchet (the owner's ruling AUTH-5 = B with his opt-out, 15 Nov
//! 20:15; the lead's WAYBACK-2 and WAYBACK-6 = A): a vault that has ever
//! held an owner key keeps asking for one after the last is removed. The
//! owner's switch back to web sign-in counts only with an owner key's
//! cosign, speaks for the keys it saw, and ends with a key enrolled later or
//! with a later choice to ask for a key again. The tests at the end fold a
//! managed host's vault whose owner enrols device keys by hand-signed rows.

#![cfg(oneiron_test_support)]

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use ed25519_dalek::{Signer, SigningKey};
use oneiron::authority::{
    AUTHORITY_LOG_SCHEMA_VERSION, ActAuthority, ActSurface, AuthorityAttestation,
    AuthorityEntryHash, AuthorityFold, AuthorityKey, AuthorityLogEntry, AuthorityOp,
    AuthoritySignature, AuthorityTier, AuthorityVaultId, CheckpointPolicyView,
    ConfirmedHeldAnswers, ConversationLearningView, DeviceAuthority, GenesisRecoveryStep,
    HeldAnswerListing, HostSlipIssuer, MACHINE_ENCRYPTION_KEY_LEN,
    MACHINE_ENCRYPTION_SUITE_HYBRID_V1, MachineDeviceClass, MachineEncryptionKey,
    MachineEnrolmentRequest, MachineOwnership, MachineProfile, MachineRole, OwnerAct, OwnerActKind,
    ROLE_ADMIN, ROLE_CLOUD, ROLE_OWNER, authority_entry_hash, authority_transcript,
    fold_authority_log, fold_authority_log_for_posture, genesis_vault_id,
    machine_profile_proof_transcript,
};
use oneiron::consent::AuthenticatedOwner;
use oneiron::dreamer_runner::{
    ConsolidationHomePickReceipt, ConsolidationHomePickRequest, consolidation_home_pick_as,
};
use oneiron::error::{OWNER_KEY_REQUIRED, RecordError};
use oneiron::memory::{MEMORY_CODE_INVALID_STATE, MemoryResult};
use oneiron::origin::residence::{OriginAuthority, OriginResidence};
use oneiron::store::GateDecisionId;
use oneiron::test_doors::conversation_training_fold::{leaves_out, training_revision};
use oneiron::test_doors::device_succession_fold::successor;
use oneiron::test_doors::held_answer_confirm::confirming_answer;
use oneiron::test_doors::home_pick_fold::home_pick_in_force;
use oneiron::test_doors::label_writers::embedded_owner;
use oneiron::test_doors::owner_key_release::release_owner_keys;
use oneiron::verbs::{RepoAnchorBindInput, bind_repo_anchor_as};
use oneiron::{EntityId, Error, HostingPrivacyPosture, Vault, VaultConfig};
use oneiron_authority::authority::{
    ConversationTrainingSet, ConversationTrainingVaultSet, HomeNodePick, OWNER_KEY_ENROLLMENT_SEEN,
    OWNER_KEY_POSSESSION_KIND, OwnerKeyEnroll, PolicySetting, PolicySettingSet,
    conversation_training_vault_target, home_pick_target, machine_answer_revision,
    owner_key_enrollment_challenge, owner_key_enrollment_target, policy_setting_revision,
    web_sign_in_value,
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

/// The served name of the repository the origin cutover door tests cut.
const SERVED_REPO: &str = "carried";

/// The retired device the succession door tests name: its client id, and
/// the seed of its device key.
const PREDECESSOR_CLIENT: u64 = 4242;
const PREDECESSOR_SEED: u8 = 67;

/// The machine the held-answer door tests enrol: the seed of its machine
/// key.
const JOINING_SEED: u8 = 68;

/// The owner's device keys the ratchet tests enrol: the seeds of the first
/// and of a later one.
const OWNER_KEY_SEED: u8 = 69;
const LATER_OWNER_KEY_SEED: u8 = 70;

/// A web sign-in value that names no key set: the owner's choice to ask for
/// an owner key again.
const ASKS_FOR_AN_OWNER_KEY: [u8; 32] = [0; 32];

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
    assert_eq!(
        asking(&fold, machine).len(),
        1,
        "the answer is held, not refused: it asks the owner: {:?}",
        fold.issues
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
    assert_eq!(
        fold.waiting_owner_choices().len(),
        1,
        "the pick is stored and asks the owner, not refused: {:?}",
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
    assert_eq!(
        asking(&fold, victim).len(),
        1,
        "the removal is held, not refused: it asks the owner: {:?}",
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
    assert_eq!(
        asking(&fold, machine).len(),
        1,
        "the bare answer is held and asks the owner: {:?}",
        fold.issues
    );
    let answer = HostedNodeAnswer::on_a_hosted_vault();
    let root = answer.root.clone();
    let (fold, machine, node_key) = answer.answer_yours(&[&root]);
    assert!(
        !mine(&fold, machine, &node_key),
        "the host's custodial root proves nothing for the owner: {:?}",
        fold.issues
    );
    assert_eq!(
        asking(&fold, machine),
        BTreeSet::new(),
        "an answer cosigned by a key that proves nothing is a forged entry, not a held one"
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
    assert_eq!(
        asking(&fold, paired.paired_machine).len(),
        1,
        "the pairing is held, not refused: it asks the owner: {:?}",
        fold.issues
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
    assert_eq!(
        asking(&fold, machine),
        BTreeSet::new(),
        "a forged proof is a refused entry, not a held one"
    );
    let answer = HostedNodeAnswer::new();
    let root = answer.root.clone();
    let (fold, machine, node_key) = answer.answer_yours(&[&root, &stranger]);
    assert!(
        !mine(&fold, machine, &node_key),
        "a proven answer carries exactly one cosign"
    );
    assert_eq!(
        asking(&fold, machine),
        BTreeSet::new(),
        "a second cosign is a refused entry, not a held one"
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
    assert_eq!(
        asking(&fold, laptop_machine).len(),
        1,
        "the re-key is held, not refused: it asks the owner: {:?}",
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
    assert_eq!(
        asking(&fold, laptop_machine).len(),
        1,
        "the demote is held, not refused: it asks the owner: {:?}",
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
        "a person's own opt-out never waits for the vault owner's proof"
    );
}

/// The same ruling's other side: the vault-wide training setting is the
/// vault owner's act, so a not-mine carrier's unproven set waits.
#[test]
fn the_owners_vault_wide_training_setting_waits_through_a_not_mine_carrier() {
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

/// The exemption is the person's own choice only: a choice that names
/// another person as its target is no valid entry, whoever carries it.
#[test]
fn a_training_choice_for_another_person_is_still_refused() {
    let answer = HostedNodeAnswer::new();
    let node = answer.machine;
    let issues_before = answer.fold().issues.len();
    let (fold, _) = answer.node_carries(training_choice(owner(), member(), node));
    assert!(
        !leaves_out(&fold, member()),
        "nobody opts another person out"
    );
    assert_eq!(
        fold.waiting_owner_choices(),
        &BTreeSet::new(),
        "a refused entry does not wait either"
    );
    assert!(
        fold.issues.len() > issues_before,
        "a choice for another person is an invalid entry: {:?}",
        fold.issues
    );
}

/// The member's own conversation-training choice `leave_out`, carried by
/// `machine`, having seen the revision `seen` of their live choices.
fn members_own_choice(machine: EntityId, leave_out: bool, seen: [u8; 32]) -> AuthorityOp {
    AuthorityOp::ConversationTrainingSet(ConversationTrainingSet {
        act: OwnerAct::by_owner(
            member(),
            OwnerActKind::ConversationTraining,
            member(),
            ActSurface::ThisInstall,
            seen,
        ),
        machine,
        leave_out,
    })
}

/// The hosted node carries the member's own opt-out on the newest row, with
/// no proof, and it lands. Returns the revision their next choice names as
/// seen.
fn node_carries_the_members_opt_out(answer: &mut HostedNodeAnswer) -> [u8; 32] {
    let newest = hash(answer.rows.last().expect("a row"));
    let opt_out = signed(
        Some(answer.vault_id()),
        1,
        vec![newest],
        members_own_choice(answer.machine, true, [0; 32]),
        &answer.node,
        &[],
    );
    answer.rows.push(opt_out);
    let fold = answer.fold();
    assert!(
        leaves_out(&fold, member()),
        "guard: the member's own opt-out lands: {:?}",
        fold.issues
    );
    training_revision(&fold, member())
}

/// The member opts out through the hosted node, then opts back in over that
/// opt-out: `carrier` carries the opt back in under its install key `key` at
/// `seq`, with one cosign by each of `cosigners`. Returns the fold and the
/// opt back in's entry.
fn member_opts_back_in(
    mut answer: HostedNodeAnswer,
    (carrier, key, seq): (EntityId, &SigningKey, u64),
    cosigners: &[&SigningKey],
) -> (AuthorityFold, AuthorityEntryHash) {
    let seen = node_carries_the_members_opt_out(&mut answer);
    let newest = hash(answer.rows.last().expect("a row"));
    let back_in = signed(
        Some(answer.vault_id()),
        seq,
        vec![newest],
        members_own_choice(carrier, false, seen),
        key,
        cosigners,
    );
    let entry = hash(&back_in);
    answer.rows.push(back_in);
    (answer.fold(), entry)
}

/// The opt back in landed: the member is not left out, and nothing waits.
fn assert_let_back_in(fold: &AuthorityFold) {
    assert!(
        !leaves_out(fold, member()),
        "the opt back in lands: {:?}",
        fold.issues
    );
    assert_eq!(
        fold.waiting_owner_choices(),
        &BTreeSet::new(),
        "a landed opt back in does not wait"
    );
}

/// Ruling CARRIER-PERSON-OPT-BACK-IN = A (the lead's AUTH-4
/// PERSON-PROOF-RUNG = A): a person's opt back in widens their own row, and
/// a carrier proves only itself. Carried with no proof by a machine that is
/// not the owner's, on a vault that holds an owner key, it waits, and the
/// member stays left out. Before: it landed, so any admitted machine could
/// turn a person's training back on in their name.
#[test]
fn a_persons_opt_back_in_through_a_not_mine_carrier_waits() {
    let answer = HostedNodeAnswer::new();
    let (machine, node) = (answer.machine, answer.node.clone());
    let (fold, entry) = member_opts_back_in(answer, (machine, &node, 2), &[]);
    assert_eq!(
        fold.waiting_owner_choices(),
        &BTreeSet::from([entry]),
        "the unproven opt back in waits: {:?}",
        fold.issues
    );
    assert!(
        leaves_out(&fold, member()),
        "the member's opt-out stays in force"
    );
}

/// Guard: the same opt back in with an owner key's proof lands.
#[test]
fn an_owner_key_cosigned_opt_back_in_through_a_not_mine_carrier_lands() {
    let answer = HostedNodeAnswer::new();
    let (machine, node, root) = (answer.machine, answer.node.clone(), answer.root.clone());
    let (fold, _) = member_opts_back_in(answer, (machine, &node, 2), &[&root]);
    assert_let_back_in(&fold);
}

/// Guard: carried by the owner's own machine, the opt back in lands with no
/// cosign.
#[test]
fn a_persons_opt_back_in_carried_by_the_owners_machine_lands() {
    let LaptopBesideNode {
        node,
        laptop,
        laptop_machine,
    } = LaptopBesideNode::new();
    let (fold, _) = member_opts_back_in(node, (laptop_machine, &laptop, 1), &[]);
    assert_let_back_in(&fold);
}

/// Guard: a managed host's vault with no owner device key keeps today's opt
/// back in, since no key there could prove it.
#[test]
fn a_persons_opt_back_in_lands_on_a_hosted_vault_with_no_owner_device_key() {
    let answer = HostedNodeAnswer::on_a_hosted_vault();
    let (machine, node) = (answer.machine, answer.node.clone());
    let (fold, _) = member_opts_back_in(answer, (machine, &node, 2), &[]);
    assert_let_back_in(&fold);
}

/// One vault as a managed host serves it: the Hosted posture, rooted under
/// the test host (a custodial root, so the roster holds no key that proves
/// for the owner), this install profiled `Unanswered`, and the embedded owner
/// authenticated. The vault drops first.
struct ServedVault {
    vault: Vault,
    issuer: HostSlipIssuer,
    owner: AuthenticatedOwner,
    _dir: tempfile::TempDir,
}

impl ServedVault {
    fn hosted() -> Self {
        let dir = tempfile::tempdir().expect("vault directory");
        let mut config = VaultConfig::device();
        config.privacy.posture = HostingPrivacyPosture::Hosted;
        let vault = Vault::open(dir.path(), config).expect("hosted vault");
        vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
        let issuer = oneiron::test_support::provision_engine_machines(&vault);
        vault
            .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
            .expect("this install's machine profile under the host root");
        let (_, owner) = embedded_owner(&vault).expect("authenticated embedded owner");
        Self {
            vault,
            issuer,
            owner,
            _dir: dir,
        }
    }

    /// A self-host vault as its own server starts one: rooted under the
    /// host's root, the owner bound by it, this install profiled.
    fn self_host() -> Self {
        let dir = tempfile::tempdir().expect("vault directory");
        let vault = Vault::open(dir.path(), VaultConfig::device()).expect("self-host vault");
        vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
        let issuer = oneiron::test_support::provision_engine_machines(&vault);
        vault
            .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
            .expect("this install's machine profile under the host root");
        let person = vault.ensure_embedded_owner_actor().expect("the owner");
        oneiron::test_support::bind_host_owner(&vault, &issuer, person)
            .expect("the owner's binding");
        let owner = vault
            .authenticate_owner(person, &person.to_hex(), true, GateDecisionId::now())
            .expect("the owner's proof");
        Self {
            vault,
            issuer,
            owner,
            _dir: dir,
        }
    }

    /// The owner enrols the serving install's own owner signing key, as a
    /// server's `enroll-this-install` route does.
    fn enrol_serving_install_key(&self) -> oneiron::Result<()> {
        self.vault
            .enrol_serving_install_owner_signing_key(
                &ActAuthority::Owner(self.owner.clone(), ActSurface::ThisInstall),
                &self.issuer,
            )
            .map(|_| ())
    }

    /// This install's MACHINE row.
    fn install(&self) -> EntityId {
        self.vault
            .local_machine()
            .expect("read this install")
            .expect("this install is profiled")
            .id
    }

    /// Whether the fold trusts this install as the owner's machine.
    fn install_is_mine(&self) -> bool {
        self.vault
            .authority_fold()
            .expect("authority fold")
            .trusted_machine(self.install())
            .is_some()
    }

    /// The owner enrols this install's owner signing key: the roster then
    /// holds a key that proves for him, and this handle holds it.
    fn enrol_owner_key(&self) {
        self.vault
            .enrol_device_owner_signing_key(
                &ActAuthority::Owner(self.owner.clone(), ActSurface::ThisInstall),
                &self.issuer,
            )
            .expect("the owner enrols this install's owner signing key");
    }

    /// The owner answers through this install that it is his.
    fn answer_this_install_is_mine(&self) {
        self.vault
            .set_machine_role(
                &self.owner,
                ActSurface::ThisInstall,
                self.install(),
                MachineRole::Owned(MachineOwnership::Yours),
                None,
            )
            .expect("the answer door stores the owner's answer");
    }

    /// The entries of the answers about this install that still ask.
    fn asking(&self) -> BTreeSet<AuthorityEntryHash> {
        asking(
            &self.vault.authority_fold().expect("authority fold"),
            self.install(),
        )
    }

    /// How many authority log rows the fold holds valid.
    fn stored_rows(&self) -> usize {
        self.vault
            .authority_fold()
            .expect("authority fold")
            .valid_entries
            .len()
    }

    /// The owner's home pick through this install, as the facade's
    /// `vault.consolidation.home.pick` makes it.
    fn pick_home(&self, node: u64) -> MemoryResult<ConsolidationHomePickReceipt> {
        consolidation_home_pick_as(
            &self.vault,
            &self.owner,
            ActSurface::ThisInstall,
            ConsolidationHomePickRequest {
                node_id: Some(node.to_string()),
                seen: None,
            },
        )
    }

    /// The node the vault's home pick names.
    fn home_pick(&self) -> Option<u64> {
        home_pick_in_force(&self.vault.authority_fold().expect("authority fold"))
    }

    /// The owner's key is held on another install: he enrols it here and
    /// this handle lets it go. The roster keeps a key that proves for him,
    /// and this install holds none.
    fn owner_key_held_on_another_install(&self) {
        self.enrol_owner_key();
        release_owner_keys(&self.vault);
    }

    /// A refused choice left nothing: the fold holds `rows` valid rows as
    /// before it, and no choice waits.
    fn assert_nothing_stored_since(&self, rows: usize) {
        let fold = self.vault.authority_fold().expect("authority fold");
        assert_eq!(fold.valid_entries.len(), rows, "the refusal stores no row");
        assert_eq!(
            fold.waiting_owner_choices(),
            &BTreeSet::new(),
            "nothing waits: the door stored nothing"
        );
    }

    /// The owner clears his checkpoint root choice through this install. A
    /// hosted vault takes no selection without the operator's capability; a
    /// clear is a choice of his all the same.
    fn clear_checkpoint_policy(&self) -> oneiron::Result<CheckpointPolicyView> {
        self.vault.set_checkpoint_policy_as(
            &ActAuthority::Owner(self.owner.clone(), ActSurface::ThisInstall),
            None,
            None,
        )
    }

    /// The vault's checkpoint root policy as the owner's surface shows it.
    fn checkpoint_policy(&self) -> CheckpointPolicyView {
        self.vault
            .checkpoint_policy_view()
            .expect("checkpoint policy view")
    }

    /// The owner sets the vault's training setting through this install.
    fn set_learning(&self, on: bool) -> oneiron::Result<ConversationLearningView> {
        self.vault
            .set_conversation_learning(&self.owner, ActSurface::ThisInstall, on, false, None)
    }

    /// The vault's training setting in force.
    fn learning(&self) -> ConversationLearningView {
        self.vault
            .conversation_learning_status()
            .expect("conversation learning status")
    }

    /// The owner turns training on and lets people opt out, through this
    /// install.
    fn let_people_opt_out(&self) {
        self.vault
            .set_conversation_learning(&self.owner, ActSurface::ThisInstall, true, true, None)
            .expect("the setting that lets people opt out lands");
    }

    /// The authenticated person leaves their own messages out of training,
    /// or lets them back in, through this install. Returns whether they are
    /// left out.
    fn leave_my_messages_out(&self, leave_out: bool) -> oneiron::Result<bool> {
        self.vault
            .set_conversation_training(&self.owner, ActSurface::ThisInstall, leave_out, None)
            .map(|view| view.leave_out)
    }

    /// Whether the authenticated person's own messages are left out.
    fn my_messages_are_left_out(&self) -> bool {
        self.vault
            .conversation_training_view(&self.owner)
            .expect("the person's own training view")
            .leave_out
    }

    /// This install serves one repository bound to a CODE anchor under the
    /// root project: the repository stands under one portable id, so the
    /// owner's cutover signs one cut.
    fn serve_a_repo(&self) {
        self.vault
            .register_served_origin_as_owner(&self.owner, SERVED_REPO, "main")
            .expect("register the served repository");
        let project = self.vault.root_project().expect("root project");
        bind_repo_anchor_as(
            &self.vault,
            &self.owner,
            RepoAnchorBindInput {
                repo: Some(SERVED_REPO.to_owned()),
                local_folder: None,
                project,
                anchor: None,
                editable: None,
            },
        )
        .expect("bind the repository's CODE anchor");
    }

    /// The owner cuts the served repository's authority over to this install
    /// from the epoch `expected_epoch`.
    fn cut_origin(&self, expected_epoch: Option<u64>) -> oneiron::Result<OriginAuthority> {
        self.vault.set_served_origin_authority_as_owner(
            &self.owner,
            ActSurface::ThisInstall,
            SERVED_REPO,
            expected_epoch,
            OriginResidence::LocalVault,
            self.install(),
            false,
        )
    }

    /// The served repository's authority row on this host.
    fn origin_row(&self) -> Option<OriginAuthority> {
        self.vault
            .served_origin_authority(SERVED_REPO)
            .expect("read the origin authority row")
    }

    /// The owner names the retired device as this install's predecessor.
    fn name_predecessor(&self) -> oneiron::Result<()> {
        self.vault.name_device_predecessor_as_owner(
            &self.owner,
            ActSurface::ThisInstall,
            PREDECESSOR_CLIENT,
            signing(PREDECESSOR_SEED).verifying_key().to_bytes(),
        )
    }

    /// The owner's list of the acts that wait for his proof.
    fn held(&self) -> HeldAnswerListing {
        self.vault
            .held_machine_answers(&self.owner)
            .expect("the held answer list")
    }

    /// The entry of every held answer the list names.
    fn held_entries(&self) -> Vec<AuthorityEntryHash> {
        self.held()
            .answers
            .iter()
            .map(|listed| listed.entry)
            .collect()
    }

    /// The owner confirms the held answers `entries` name through this
    /// install.
    fn confirm(&self, entries: &[AuthorityEntryHash]) -> oneiron::Result<ConfirmedHeldAnswers> {
        self.vault
            .confirm_held_machine_answers(&self.owner, ActSurface::ThisInstall, entries)
    }

    /// The owner dismisses the ask of the held answers `entries` name on
    /// this install.
    fn dismiss(&self, entries: &[AuthorityEntryHash]) -> oneiron::Result<HeldAnswerListing> {
        self.vault
            .dismiss_held_machine_answers(&self.owner, entries)
    }

    /// Another machine's request to join this vault: its own keys, and its
    /// own proof over them for this vault.
    fn joining_machine(&self) -> MachineEnrolmentRequest {
        let vault_id = self
            .vault
            .authority_fold()
            .expect("authority fold")
            .vault_id
            .expect("the vault is rooted");
        let machine = EntityId::from_bytes([0x76; 16]).expect("an id");
        let profile = node_profile(
            vault_id,
            machine,
            &signing(JOINING_SEED),
            MachineRole::Unanswered,
            1,
            None,
        );
        MachineEnrolmentRequest {
            vault_id,
            machine,
            machine_key: profile.machine_key,
            device_class: profile.device_class,
            encryption_key: profile.encryption_key,
            machine_proof: profile.machine_proof,
        }
    }

    /// The machine the vault counts as the retired device's successor.
    fn predecessors_successor(&self) -> Option<EntityId> {
        successor(
            &self.vault.authority_fold().expect("authority fold"),
            PREDECESSOR_CLIENT,
            &signing(PREDECESSOR_SEED).verifying_key().to_bytes(),
        )
        .expect("the retired device's succession target")
    }
}

/// What a choice door answers where the vault holds an owner key and this
/// install holds none: the owner-key refusal.
fn assert_owner_key_refusal<T: std::fmt::Debug>(answer: oneiron::Result<T>) {
    assert!(
        matches!(answer, Err(Error::Record(RecordError::OwnerKeyRequired))),
        "the door refuses for the owner's key: {answer:?}"
    );
}

/// The answer door on an install that holds no owner key: the owner's
/// "yours" is stored and held, so an owner device can ask him. Before the
/// door reported a held answer it refused here and stored nothing.
#[test]
fn a_yours_answer_this_install_cannot_prove_is_stored_and_held() {
    let served = ServedVault::hosted();
    served.answer_this_install_is_mine();
    assert_eq!(
        served.asking().len(),
        1,
        "the answer is stored and asks the owner"
    );
    assert!(
        !served.install_is_mine(),
        "a held answer makes no machine the owner's"
    );
    let fold = served.vault.authority_fold().expect("authority fold");
    assert_eq!(
        fold.machine(served.install())
            .and_then(|machine| machine.roster.as_ref())
            .map(|head| head.profile.role),
        Some(MachineRole::Unanswered),
        "the machine stands as it did"
    );
}

/// The confirm is the same door on an install that holds the owner's key:
/// his answer there is proven, stands, and ends the ask of the held one.
#[test]
fn the_owners_answer_on_an_install_that_holds_his_key_stands_and_ends_the_ask() {
    let served = ServedVault::hosted();
    served.answer_this_install_is_mine();
    assert_eq!(served.asking().len(), 1, "guard: the first answer is held");
    served.enrol_owner_key();
    served.answer_this_install_is_mine();
    assert!(
        served.install_is_mine(),
        "the proven answer makes it his machine"
    );
    assert_eq!(
        served.asking(),
        BTreeSet::new(),
        "the owner's answer ends the ask"
    );
}

/// The amendment's first guard, at the home pick door: a vault with no owner
/// key enrolled keeps today's doors, also from an install that is not the
/// owner's machine. Nothing there could ever prove the choice.
#[test]
fn the_home_pick_door_lands_where_the_vault_holds_no_owner_key() {
    let served = ServedVault::hosted();
    assert!(!served.install_is_mine(), "guard: not the owner's machine");
    served
        .pick_home(PICKED_NODE)
        .expect("the pick lands as it does today");
    assert_eq!(served.home_pick(), Some(PICKED_NODE));
}

/// The amendment's second guard, at the home pick door: once the vault holds
/// an owner key that this install does not hold, the same door refuses with
/// the owner-key reason and stores no row; the prior pick stays in force.
#[test]
fn the_home_pick_door_refuses_once_another_install_holds_the_owners_key() {
    let served = ServedVault::hosted();
    served
        .pick_home(PICKED_NODE)
        .expect("guard: the first pick");
    served.enrol_owner_key();
    release_owner_keys(&served.vault);
    let rows = served.stored_rows();
    let refusal = served
        .pick_home(LAPTOPS_PICKED_NODE)
        .err()
        .expect("an unprovable pick is refused");
    assert_eq!(refusal.code, MEMORY_CODE_INVALID_STATE, "{refusal:?}");
    assert_eq!(
        refusal.reason_codes,
        [OWNER_KEY_REQUIRED],
        "the refusal names its stable reason code: {refusal:?}"
    );
    assert_eq!(
        refusal.message,
        "This machine is not the owner's and holds no owner key: decide it on an owner device."
    );
    assert_eq!(served.stored_rows(), rows, "the refusal stores no row");
    assert_eq!(
        served.home_pick(),
        Some(PICKED_NODE),
        "the prior pick stays in force"
    );
    assert_eq!(
        served
            .vault
            .authority_fold()
            .expect("authority fold")
            .waiting_owner_choices(),
        &BTreeSet::new(),
        "nothing waits: the door stored nothing"
    );
}

/// The same pick from an install that holds the owner's key lands: the door
/// adds his proof.
#[test]
fn the_home_pick_door_lands_with_the_owners_key_on_this_install() {
    let served = ServedVault::hosted();
    served.enrol_owner_key();
    served
        .pick_home(PICKED_NODE)
        .expect("the proven pick lands");
    assert_eq!(served.home_pick(), Some(PICKED_NODE));
}

/// The checkpoint policy door under the amendment's first guard: no owner
/// key in the vault, so the owner's clear lands from an install that is not
/// his machine.
#[test]
fn the_checkpoint_policy_door_lands_where_the_vault_holds_no_owner_key() {
    let served = ServedVault::hosted();
    assert!(!served.install_is_mine(), "guard: not the owner's machine");
    let view = served
        .clear_checkpoint_policy()
        .expect("the clear lands as it does today");
    assert_eq!(view.heads.len(), 1, "the clear is the one live choice");
}

/// The checkpoint policy door under the second guard: beside an owner key
/// this install does not hold it refuses and stores nothing; the choices
/// stand as they did.
#[test]
fn the_checkpoint_policy_door_refuses_once_another_install_holds_the_owners_key() {
    let served = ServedVault::hosted();
    served
        .clear_checkpoint_policy()
        .expect("guard: the first clear");
    served.owner_key_held_on_another_install();
    let (rows, policy) = (served.stored_rows(), served.checkpoint_policy());
    assert_owner_key_refusal(served.clear_checkpoint_policy());
    served.assert_nothing_stored_since(rows);
    assert_eq!(
        served.checkpoint_policy(),
        policy,
        "the policy stands as it did"
    );
}

/// The same clear from an install that holds the owner's key lands.
#[test]
fn the_checkpoint_policy_door_lands_with_the_owners_key_on_this_install() {
    let served = ServedVault::hosted();
    served.enrol_owner_key();
    let view = served
        .clear_checkpoint_policy()
        .expect("the proven clear lands");
    assert_eq!(view.heads.len(), 1, "the clear is the one live choice");
}

/// The vault training door under the first guard: no owner key in the
/// vault, so the setting lands from an install that is not his machine.
#[test]
fn the_vault_training_door_lands_where_the_vault_holds_no_owner_key() {
    let served = ServedVault::hosted();
    assert!(!served.install_is_mine(), "guard: not the owner's machine");
    let view = served
        .set_learning(true)
        .expect("the setting lands as it does today");
    assert!(view.on, "the setting is on: {view:?}");
}

/// The vault training door under the second guard: beside an owner key this
/// install does not hold it refuses and stores nothing; the setting stays
/// on.
#[test]
fn the_vault_training_door_refuses_once_another_install_holds_the_owners_key() {
    let served = ServedVault::hosted();
    served.set_learning(true).expect("guard: the first setting");
    served.owner_key_held_on_another_install();
    let (rows, setting) = (served.stored_rows(), served.learning());
    assert!(setting.on, "guard: the setting is on: {setting:?}");
    assert_owner_key_refusal(served.set_learning(false));
    served.assert_nothing_stored_since(rows);
    assert_eq!(served.learning(), setting, "the setting stands as it did");
}

/// The same setting from an install that holds the owner's key lands.
#[test]
fn the_vault_training_door_lands_with_the_owners_key_on_this_install() {
    let served = ServedVault::hosted();
    served.enrol_owner_key();
    let view = served.set_learning(true).expect("the proven setting lands");
    assert!(view.on, "the setting is on: {view:?}");
}

/// The person's own training door, the narrowing (ruling
/// CARRIER-PERSON-OPT-OUT = A): an opt-out lands beside an owner key this
/// install does not hold.
#[test]
fn the_persons_training_door_takes_an_opt_out_beside_an_owner_key_it_does_not_hold() {
    let served = ServedVault::hosted();
    served.let_people_opt_out();
    served.owner_key_held_on_another_install();
    assert!(!served.install_is_mine(), "guard: not the owner's machine");
    let left_out = served
        .leave_my_messages_out(true)
        .expect("the opt-out lands");
    assert!(left_out, "the person is left out");
}

/// The widening (ruling CARRIER-PERSON-OPT-BACK-IN = A): beside an owner key
/// this install does not hold, the door refuses the opt back in and stores
/// nothing, and the person stays left out. Before: the opt back in landed.
#[test]
fn the_persons_training_door_refuses_an_opt_back_in_once_another_install_holds_the_owners_key() {
    let served = ServedVault::hosted();
    served.let_people_opt_out();
    served
        .leave_my_messages_out(true)
        .expect("guard: the opt-out lands");
    served.owner_key_held_on_another_install();
    let rows = served.stored_rows();
    assert_owner_key_refusal(served.leave_my_messages_out(false));
    served.assert_nothing_stored_since(rows);
    assert!(
        served.my_messages_are_left_out(),
        "the person stays left out"
    );
}

/// Guard: no owner key in the vault, so the opt back in lands as it does
/// today from an install that is not the owner's machine.
#[test]
fn the_persons_training_door_takes_an_opt_back_in_where_the_vault_holds_no_owner_key() {
    let served = ServedVault::hosted();
    served.let_people_opt_out();
    served
        .leave_my_messages_out(true)
        .expect("guard: the opt-out lands");
    let left_out = served
        .leave_my_messages_out(false)
        .expect("the opt back in lands as it does today");
    assert!(!left_out, "the person is let back in");
}

/// Guard: from an install that holds the owner's key, the opt back in is
/// proven and lands.
#[test]
fn the_persons_training_door_takes_an_opt_back_in_with_the_owners_key_on_this_install() {
    let served = ServedVault::hosted();
    served.let_people_opt_out();
    served.enrol_owner_key();
    served
        .leave_my_messages_out(true)
        .expect("guard: the opt-out lands");
    let left_out = served
        .leave_my_messages_out(false)
        .expect("the proven opt back in lands");
    assert!(!left_out, "the person is let back in");
}

/// The origin cutover door under the first guard: no owner key in the vault,
/// so the cutover lands from an install that is not his machine, and signs
/// his cut of the repository.
#[test]
fn the_origin_cutover_door_lands_where_the_vault_holds_no_owner_key() {
    let served = ServedVault::hosted();
    assert!(!served.install_is_mine(), "guard: not the owner's machine");
    served.serve_a_repo();
    let rows = served.stored_rows();
    let row = served
        .cut_origin(None)
        .expect("the cutover lands as it does today");
    assert_eq!(row.epoch, 1);
    assert!(
        served.stored_rows() > rows,
        "the cutover signs the owner's cut of the repository"
    );
}

/// The origin cutover door under the second guard: beside an owner key this
/// install does not hold it refuses, stores no cut, and the host's authority
/// row it wrote in the same transaction rolls back with it.
#[test]
fn the_origin_cutover_door_refuses_once_another_install_holds_the_owners_key() {
    let served = ServedVault::hosted();
    served.serve_a_repo();
    served.cut_origin(None).expect("guard: the first cutover");
    served.owner_key_held_on_another_install();
    let (rows, row) = (served.stored_rows(), served.origin_row());
    assert_eq!(
        row.as_ref().map(|row| row.epoch),
        Some(1),
        "guard: the first cutover's row"
    );
    assert_owner_key_refusal(served.cut_origin(Some(1)));
    served.assert_nothing_stored_since(rows);
    assert_eq!(
        served.origin_row(),
        row,
        "the authority row stands as it did"
    );
}

/// The same cutover from an install that holds the owner's key lands.
#[test]
fn the_origin_cutover_door_lands_with_the_owners_key_on_this_install() {
    let served = ServedVault::hosted();
    served.serve_a_repo();
    served.enrol_owner_key();
    let rows = served.stored_rows();
    let row = served.cut_origin(None).expect("the proven cutover lands");
    assert_eq!(row.epoch, 1);
    assert!(
        served.stored_rows() > rows,
        "the cutover signs the owner's cut of the repository"
    );
}

/// The device succession door under the first guard: no owner key in the
/// vault, so the succession lands from an install that is not his machine.
#[test]
fn the_device_succession_door_lands_where_the_vault_holds_no_owner_key() {
    let served = ServedVault::hosted();
    assert!(!served.install_is_mine(), "guard: not the owner's machine");
    served
        .name_predecessor()
        .expect("the succession lands as it does today");
    assert_eq!(served.predecessors_successor(), Some(served.install()));
}

/// The device succession door under the second guard: beside an owner key
/// this install does not hold it refuses and stores nothing; the retired
/// device gains no successor.
#[test]
fn the_device_succession_door_refuses_once_another_install_holds_the_owners_key() {
    let served = ServedVault::hosted();
    served.owner_key_held_on_another_install();
    let rows = served.stored_rows();
    assert_owner_key_refusal(served.name_predecessor());
    served.assert_nothing_stored_since(rows);
    assert_eq!(
        served.predecessors_successor(),
        None,
        "the retired device has no successor"
    );
}

/// The same succession from an install that holds the owner's key lands.
#[test]
fn the_device_succession_door_lands_with_the_owners_key_on_this_install() {
    let served = ServedVault::hosted();
    served.enrol_owner_key();
    served
        .name_predecessor()
        .expect("the proven succession lands");
    assert_eq!(served.predecessors_successor(), Some(served.install()));
}

/// The owner's list names a held answer: its entry, the machine and the
/// role it asks for, how the machine stands, the install that carried it,
/// and that this install cannot confirm it.
#[test]
fn the_held_list_names_the_answer_its_carrier_and_the_standing_role() {
    let served = ServedVault::hosted();
    served.answer_this_install_is_mine();
    let listing = served.held();
    assert_eq!(listing.answers.len(), 1, "one held answer: {listing:?}");
    let listed = &listing.answers[0];
    assert_eq!(BTreeSet::from([listed.entry]), served.asking());
    assert_eq!(listed.answer.profile.machine, served.install());
    assert_eq!(
        listed.answer.profile.role,
        MachineRole::Owned(MachineOwnership::Yours),
        "what the answer asks for"
    );
    assert_eq!(
        listed.standing,
        Some(MachineRole::Unanswered),
        "the machine stands as it did"
    );
    assert_eq!(listed.answer.carrier(), Some(served.install()));
    assert_eq!(listed.carrier_role, Some(MachineRole::Unanswered));
    assert!(!listed.carrier_is_mine, "the carrier is not his machine");
    assert!(!listed.dismissed);
    assert!(
        !listed.replaces_keys,
        "an answer a door wrote names the keys the machine stands under"
    );
    assert!(
        !listing.can_confirm,
        "an install that holds no owner key cannot confirm"
    );
}

/// A confirm promises a proven answer, so on an install that holds no owner
/// key it refuses before it writes: the answer still asks.
#[test]
fn a_confirm_on_an_install_without_the_owners_key_is_refused_and_writes_nothing() {
    let served = ServedVault::hosted();
    served.answer_this_install_is_mine();
    let (rows, entries) = (served.stored_rows(), served.held_entries());
    assert_eq!(entries.len(), 1, "guard: one held answer");
    assert_owner_key_refusal(served.confirm(&entries));
    assert_eq!(
        served.stored_rows(),
        rows,
        "the refused confirm stores no row"
    );
    assert_eq!(served.held_entries(), entries, "the answer still asks");
}

/// The owner's confirm on an install that holds his key: the listed answer
/// becomes his own proven answer, the machine is his, and nothing asks.
#[test]
fn the_owners_confirm_of_the_listed_answers_makes_the_machine_his_and_empties_the_list() {
    let served = ServedVault::hosted();
    served.answer_this_install_is_mine();
    let entries = served.held_entries();
    served.enrol_owner_key();
    assert!(
        served.held().can_confirm,
        "this install holds the owner's key now"
    );
    let confirmed = served.confirm(&entries).expect("the owner's confirm lands");
    assert!(
        served.install_is_mine(),
        "the confirmed answer makes it his machine"
    );
    assert_eq!(confirmed.removed, Vec::new(), "no machine was removed");
    assert_eq!(
        confirmed.listing.answers,
        Vec::new(),
        "nothing asks after the confirm"
    );
    assert_eq!(served.held().answers, Vec::new());
}

/// The strict case at the doors (ruling CARRIER-GRANDFATHER = C): a machine
/// enrolled through an install that holds no owner key has no standing, and
/// the owner's confirm gives it its first.
#[test]
fn the_owners_confirm_of_a_held_enrolment_gives_the_machine_its_first_standing() {
    let served = ServedVault::hosted();
    let request = served.joining_machine();
    let landing = served
        .vault
        .enroll_machine(
            &served.owner,
            ActSurface::ThisInstall,
            &request,
            MachineRole::Owned(MachineOwnership::Yours),
            None,
        )
        .expect("the enrolment is stored");
    assert!(landing.held().is_some(), "guard: the enrolment is held");
    let listing = served.held();
    assert_eq!(listing.answers.len(), 1, "one held answer: {listing:?}");
    assert_eq!(
        listing.answers[0].standing, None,
        "no revision names the machine yet"
    );
    served.enrol_owner_key();
    served
        .confirm(&served.held_entries())
        .expect("the owner's confirm lands");
    let fold = served.vault.authority_fold().expect("authority fold");
    assert!(
        fold.trusted_machine(request.machine).is_some(),
        "the confirmed machine is his"
    );
    assert_eq!(served.held().answers, Vec::new(), "nothing asks");
}

/// A dismissal is this install's own mark: it writes no log row, the answer
/// stays held and makes nothing his, and a later confirm of it still lands.
#[test]
fn a_dismissed_answer_stays_held_and_a_later_confirm_still_lands() {
    let served = ServedVault::hosted();
    served.answer_this_install_is_mine();
    let (rows, entries) = (served.stored_rows(), served.held_entries());
    let listing = served.dismiss(&entries).expect("the dismissal");
    assert_eq!(listing.answers.len(), 1, "the answer stays listed");
    assert!(listing.answers[0].dismissed, "and reads as dismissed here");
    assert_eq!(served.stored_rows(), rows, "a dismissal writes no log row");
    assert_eq!(served.asking().len(), 1, "the answer stays held");
    assert!(!served.install_is_mine(), "and makes nothing his");
    served.enrol_owner_key();
    served
        .confirm(&entries)
        .expect("a dismissed answer still confirms");
    assert!(served.install_is_mine());
}

/// A confirm or a dismissal names what the owner's surface listed: an entry
/// he answered since is stale, and nothing is written for it.
#[test]
fn a_confirm_or_a_dismissal_of_an_answered_entry_is_stale() {
    let served = ServedVault::hosted();
    served.answer_this_install_is_mine();
    let entries = served.held_entries();
    served.enrol_owner_key();
    served.confirm(&entries).expect("guard: the first confirm");
    let rows = served.stored_rows();
    let again = served.confirm(&entries);
    assert!(
        matches!(again, Err(Error::ConcurrentWrite(_))),
        "a second confirm is stale: {again:?}"
    );
    let dismissal = served.dismiss(&entries);
    assert!(
        matches!(dismissal, Err(Error::ConcurrentWrite(_))),
        "a dismissal of it is stale: {dismissal:?}"
    );
    assert_eq!(served.stored_rows(), rows, "neither stores a row");
}

/// The confirm carries a held answer's role and class, never other keys than
/// its machine stands under (review R7 P1). The fold lets an owner key's
/// proof re-key a machine, and a held answer's bytes are its carrier's: a
/// confirm that carried them as they came would hand the machine's identity,
/// and the secrets sealed to it, to whoever wrote the answer. No door of the
/// crate writes such an answer (a class revision keeps both keys), so the
/// case is a pure fold: the hosted node's unproven re-key of the owner's
/// laptop is held, and the confirm of it is refused.
#[test]
fn the_owners_confirm_never_replaces_a_standing_machines_keys() {
    let beside = LaptopBesideNode::new();
    let laptop_machine = beside.laptop_machine;
    let stranger = signing(STRANGER_SEED);
    let fold =
        beside.node_answers_for_the_laptop(MachineRole::Owned(MachineOwnership::Yours), &stranger);
    let held = asking(&fold, laptop_machine);
    assert_eq!(
        held.len(),
        1,
        "guard: the re-key is held: {:?}",
        fold.issues
    );
    let confirm = confirming_answer(&fold, owner(), held.first().expect("the held re-key"));
    assert!(
        confirm.is_err(),
        "the confirm of a held answer that names other keys is refused: {confirm:?}"
    );
}

/// Guard: a held answer under the machine's own keys is confirmed as it was
/// carried. The node's unproven demote of the laptop is held; the confirm
/// carries its role under the laptop's keys, at the next revision above the
/// laptop's standing head.
#[test]
fn the_owners_confirm_of_a_held_demote_keeps_the_machines_keys() {
    let beside = LaptopBesideNode::new();
    let (laptop_machine, laptop_key, laptop) = (
        beside.laptop_machine,
        beside.laptop_key(),
        beside.laptop.clone(),
    );
    let fold = beside
        .node_answers_for_the_laptop(MachineRole::Owned(MachineOwnership::WorkSchool), &laptop);
    let held = asking(&fold, laptop_machine);
    assert_eq!(
        held.len(),
        1,
        "guard: the demote is held: {:?}",
        fold.issues
    );
    let confirm = confirming_answer(&fold, owner(), held.first().expect("the held demote"))
        .expect("the confirm of a held demote is carried");
    assert_eq!(confirm.machine, laptop_machine);
    assert_eq!(
        confirm.role,
        MachineRole::Owned(MachineOwnership::WorkSchool)
    );
    assert_eq!(confirm.machine_key, laptop_key, "the laptop's own key");
    assert_eq!(
        confirm.revision, 2,
        "the next revision above the standing head"
    );
    assert_eq!(confirm.carrier, None, "the writer names the carrier");
}

/// A managed host's server is no owner device (ruling
/// CARRIER-HOSTED-SERVER-OWNER-KEY = A; review R8-a). An enrolled owner key
/// proves the owner acts its install carries, so the serving install of a
/// hosted vault never enrols its own: the refusal names its rule and stores
/// no row, and no key of this install proves afterwards. A device's own
/// enrolment on the same vault still lands.
#[test]
fn a_managed_hosts_serving_install_never_enrols_its_own_owner_key() {
    let served = ServedVault::hosted();
    let rows = served.stored_rows();
    match served.enrol_serving_install_key() {
        Err(Error::Record(RecordError::AuthorityRefused(reason))) => assert_eq!(
            reason,
            "a managed host holds no owner key: enrol one on your own device"
        ),
        other => panic!("a hosted vault's serving install is refused by that rule: {other:?}"),
    }
    assert_eq!(served.stored_rows(), rows, "the refusal stores no row");
    assert!(
        !served.held().can_confirm,
        "no key of this install proves for the owner"
    );
    served.enrol_owner_key();
    assert!(
        served.held().can_confirm,
        "a device's own enrolment on a hosted vault still lands"
    );
}

/// Guard: a self-host server is the owner's own machine, and its serving
/// install enrols its own owner signing key as before.
#[test]
fn a_self_host_serving_install_enrols_its_own_owner_key() {
    let served = ServedVault::self_host();
    assert!(
        !served.held().can_confirm,
        "guard: this handle holds no owner key yet"
    );
    served
        .enrol_serving_install_key()
        .expect("a self-host server's install enrols its own owner signing key");
    assert!(
        served.held().can_confirm,
        "the enrolled key proves the owner acts this install carries"
    );
}

/// A vault whose owner enrols device keys, for the ratchet tests (ruling
/// AUTH-5): the root signs each enrolment and the hosted node carries it, as
/// a managed host's enrol door does. Every row names its parents, so a test
/// can cut two branches. The root has signed at sequences 0 and 1; the node
/// and the owner's keys have signed nothing.
struct OwnerKeyVault {
    answer: HostedNodeAnswer,
}

impl OwnerKeyVault {
    /// A managed host's vault: its root is the host's custodial key.
    fn hosted() -> Self {
        Self {
            answer: HostedNodeAnswer::on_a_hosted_vault(),
        }
    }

    /// A self-host vault: its root is the owner's own key.
    fn self_host() -> Self {
        Self {
            answer: HostedNodeAnswer::new(),
        }
    }

    /// The newest row.
    fn tip(&self) -> AuthorityEntryHash {
        hash(self.answer.rows.last().expect("a row"))
    }

    fn push(&mut self, row: AuthorityLogEntry) -> AuthorityEntryHash {
        let entry = hash(&row);
        self.answer.rows.push(row);
        entry
    }

    fn fold(&self) -> AuthorityFold {
        self.answer.fold()
    }

    /// The owner enrols `key` as his device's owner signing key: the root
    /// signs the enrolment at `root_seq`, and the node carries his act and
    /// holds the key.
    fn enrol(
        &mut self,
        key: &SigningKey,
        root_seq: u64,
        parents: Vec<AuthorityEntryHash>,
    ) -> AuthorityEntryHash {
        let vault_id = self.answer.vault_id();
        let machine = self.answer.machine;
        let public_key = key.verifying_key().to_bytes();
        let challenge = owner_key_enrollment_challenge(&vault_id, machine, &public_key, owner())
            .expect("the key's challenge");
        let enroll = OwnerKeyEnroll {
            act: OwnerAct::by_owner(
                owner(),
                OwnerActKind::OwnerKeyEnrollment,
                owner_key_enrollment_target(&vault_id, &public_key).expect("the key's target"),
                ActSurface::ThisInstall,
                OWNER_KEY_ENROLLMENT_SEEN,
            ),
            machine,
            carrier: machine,
            device: DeviceAuthority {
                key: key_of(key),
                transport_key_binding: [0; 32],
                attestation: AuthorityAttestation {
                    kind: OWNER_KEY_POSSESSION_KIND.to_owned(),
                    evidence: key.sign(&challenge).to_bytes().to_vec(),
                },
                tier: AuthorityTier::Software,
                roles: ROLE_OWNER,
            },
        };
        let row = signed(
            Some(vault_id),
            root_seq,
            parents,
            AuthorityOp::OwnerKeyEnroll(enroll),
            &self.answer.root,
            &[&self.answer.node],
        );
        self.push(row)
    }

    /// `key`, an enrolled owner key that has signed nothing, removes itself.
    fn key_removes_itself(
        &mut self,
        key: &SigningKey,
        parents: Vec<AuthorityEntryHash>,
    ) -> AuthorityEntryHash {
        let row = signed(
            Some(self.answer.vault_id()),
            1,
            parents,
            AuthorityOp::RevokeDevice {
                revoked_key: key_of(key),
            },
            key,
            &[],
        );
        self.push(row)
    }

    /// The node carries the owner's web sign-in act of `value` at
    /// `node_seq`, its `seen` over the setting's `live` acts, with one cosign
    /// by each of `cosigners`.
    fn node_sets_web_sign_in(
        &mut self,
        node_seq: u64,
        parents: Vec<AuthorityEntryHash>,
        value: [u8; 32],
        live: &[AuthorityEntryHash],
        cosigners: &[&SigningKey],
    ) -> AuthorityEntryHash {
        let target = PolicySetting::WebSignIn
            .reserved_target()
            .expect("the setting's target")
            .expect("a vault-wide setting");
        let act = OwnerAct::by_owner(
            owner(),
            OwnerActKind::PolicySetting,
            target,
            ActSurface::ThisInstall,
            policy_setting_revision(live.iter().copied()),
        );
        let row = signed(
            Some(self.answer.vault_id()),
            node_seq,
            parents,
            AuthorityOp::PolicySettingSet(PolicySettingSet {
                act,
                machine: self.answer.machine,
                setting: PolicySetting::WebSignIn,
                prior: [0; 32],
                value: Some(value),
            }),
            &self.answer.node,
            cosigners,
        );
        self.push(row)
    }

    /// The node carries the owner's home pick of [`PICKED_NODE`] at
    /// `node_seq`, with no cosign. No pick is live, so it saw the zero
    /// revision.
    fn node_picks_home(
        &mut self,
        node_seq: u64,
        parents: Vec<AuthorityEntryHash>,
    ) -> AuthorityEntryHash {
        let vault_id = self.answer.vault_id();
        let act = OwnerAct::by_owner(
            owner(),
            OwnerActKind::HomeNodePick,
            home_pick_target(&vault_id).expect("the pick's target"),
            ActSurface::ThisInstall,
            [0; 32],
        );
        let row = signed(
            Some(vault_id),
            node_seq,
            parents,
            AuthorityOp::HomeNodePick(HomeNodePick {
                act,
                machine: self.answer.machine,
                node_id: Some(PICKED_NODE),
            }),
            &self.answer.node,
            &[],
        );
        self.push(row)
    }

    /// The node carries its own answer `Owned(Yours)` at `node_seq`,
    /// cosigned by `proof`: with an owner key's proof the node is the
    /// owner's machine.
    fn node_answers_yours(
        &mut self,
        node_seq: u64,
        parents: Vec<AuthorityEntryHash>,
        proof: &SigningKey,
    ) -> AuthorityEntryHash {
        let vault_id = self.answer.vault_id();
        let machine = self.answer.machine;
        let registration = hash(&self.answer.rows[1]);
        let act = OwnerAct::by_owner(
            owner(),
            OwnerActKind::MachineAnswer,
            machine,
            ActSurface::ThisInstall,
            machine_answer_revision([registration]),
        );
        let row = signed(
            Some(vault_id),
            node_seq,
            parents,
            AuthorityOp::MachineProfile(node_profile(
                vault_id,
                machine,
                &self.answer.node,
                MachineRole::Owned(MachineOwnership::Yours),
                2,
                Some((machine, act)),
            )),
            &self.answer.node,
            &[proof],
        );
        self.push(row)
    }
}

/// The web sign-in value that speaks for exactly `keys`.
fn speaks_for(keys: &[&SigningKey]) -> [u8; 32] {
    let keys: BTreeSet<AuthorityKey> = keys.iter().map(|key| key_of(key)).collect();
    web_sign_in_value(&keys)
}

/// The node's unproven pick `pick` waits for the owner's proof: the vault
/// asks for an owner key.
fn assert_the_pick_waits(fold: &AuthorityFold, pick: AuthorityEntryHash) {
    assert_eq!(
        home_pick_in_force(fold),
        None,
        "the vault asks for an owner key, so a not-mine node's unproven pick waits: {:?}",
        fold.issues
    );
    assert!(
        fold.waiting_owner_choices().contains(&pick),
        "the pick is stored and asks the owner, not refused: {:?}",
        fold.issues
    );
}

/// The node's unproven pick lands: the vault runs on web sign-in.
fn assert_the_pick_lands(fold: &AuthorityFold) {
    assert_eq!(
        home_pick_in_force(fold),
        Some(PICKED_NODE),
        "the vault runs on web sign-in, so the node's unproven pick lands: {:?}",
        fold.issues
    );
}

/// The ratchet (AUTH-5 = B). Base: with the last owner key removed the
/// roster holds no key that proves, and the node's unproven pick lands.
#[test]
fn a_vault_whose_last_owner_key_was_removed_still_asks_for_one() {
    let mut vault = OwnerKeyVault::hosted();
    let key = signing(OWNER_KEY_SEED);
    let enrolled = vault.enrol(&key, 2, vec![vault.tip()]);
    let removed = vault.key_removes_itself(&key, vec![enrolled]);
    let pick = vault.node_picks_home(1, vec![removed]);
    let fold = vault.fold();
    assert!(
        fold.roster
            .get(&key_of(&key))
            .is_some_and(|device| device.revoked),
        "the owner's key was enrolled and then removed: {:?}",
        fold.issues
    );
    assert_the_pick_waits(&fold, pick);
}

/// The ratchet's guard, and the fixture's: beside a live enrolled owner key
/// the node's unproven pick waits, on the base as well.
#[test]
fn a_hosted_nodes_unproven_pick_waits_beside_an_enrolled_owner_key() {
    let mut vault = OwnerKeyVault::hosted();
    let key = signing(OWNER_KEY_SEED);
    let enrolled = vault.enrol(&key, 2, vec![vault.tip()]);
    let pick = vault.node_picks_home(1, vec![enrolled]);
    let fold = vault.fold();
    assert!(
        fold.roster
            .get(&key_of(&key))
            .is_some_and(|device| !device.revoked && device.roles == ROLE_OWNER),
        "the hand-signed enrolment puts the owner's key on the roster: {:?}",
        fold.issues
    );
    assert_the_pick_waits(&fold, pick);
}

/// The owner's opt-out ("Switch back to web sign-in"). Base: the setting
/// means nothing to the fold, so the pick still waits beside the live key.
#[test]
fn the_owners_switch_back_to_web_sign_in_lets_the_node_carry_his_acts() {
    let mut vault = OwnerKeyVault::hosted();
    let key = signing(OWNER_KEY_SEED);
    let enrolled = vault.enrol(&key, 2, vec![vault.tip()]);
    let switched =
        vault.node_sets_web_sign_in(1, vec![enrolled], speaks_for(&[&key]), &[], &[&key]);
    vault.node_picks_home(2, vec![switched]);
    assert_the_pick_lands(&vault.fold());
}

/// The switch back, then the last key's removal, in that order: the vault
/// stays on web sign-in. It lands on the base too, where nothing asks once
/// the key is gone.
#[test]
fn the_switch_back_outlives_the_keys_it_saw() {
    let mut vault = OwnerKeyVault::hosted();
    let key = signing(OWNER_KEY_SEED);
    let enrolled = vault.enrol(&key, 2, vec![vault.tip()]);
    let switched =
        vault.node_sets_web_sign_in(1, vec![enrolled], speaks_for(&[&key]), &[], &[&key]);
    let removed = vault.key_removes_itself(&key, vec![switched]);
    vault.node_picks_home(2, vec![removed]);
    assert_the_pick_lands(&vault.fold());
}

/// Ruled out (AUTH-5): "a web session alone can never turn the ratchet off".
/// After the last key is removed the node carries the switch back with no
/// cosign: it waits, and so does the node's pick. Base: both land.
#[test]
fn a_web_session_alone_never_switches_the_vault_back() {
    let mut vault = OwnerKeyVault::hosted();
    let key = signing(OWNER_KEY_SEED);
    let enrolled = vault.enrol(&key, 2, vec![vault.tip()]);
    let removed = vault.key_removes_itself(&key, vec![enrolled]);
    let switched = vault.node_sets_web_sign_in(1, vec![removed], speaks_for(&[&key]), &[], &[]);
    let pick = vault.node_picks_home(2, vec![switched]);
    let fold = vault.fold();
    assert!(
        fold.waiting_owner_choices().contains(&switched),
        "a switch back with no owner key's cosign waits: {:?}",
        fold.issues
    );
    assert_the_pick_waits(&fold, pick);
}

/// A removed key proves nothing: the switch back it cosigns is a forged
/// entry, and the vault still asks. Base: the entry is forged there too, and
/// the pick lands.
#[test]
fn a_switch_back_cosigned_by_a_removed_owner_key_is_no_entry() {
    let mut vault = OwnerKeyVault::hosted();
    let key = signing(OWNER_KEY_SEED);
    let enrolled = vault.enrol(&key, 2, vec![vault.tip()]);
    let removed = vault.key_removes_itself(&key, vec![enrolled]);
    let forged = vault.node_sets_web_sign_in(1, vec![removed], speaks_for(&[&key]), &[], &[&key]);
    let pick = vault.node_picks_home(2, vec![removed]);
    let fold = vault.fold();
    assert!(
        !fold.valid_entries.contains(&forged),
        "a cosign by a removed key is a forged proof, an invalid entry"
    );
    assert_the_pick_waits(&fold, pick);
}

/// The switch back counts only with an owner key's cosign, whoever carries
/// it: the owner's own machine carries it bare, and it waits. Base: a mine
/// carrier's setting act lands.
#[test]
fn the_owners_own_machine_cannot_switch_back_without_an_owner_keys_cosign() {
    let mut vault = OwnerKeyVault::hosted();
    let key = signing(OWNER_KEY_SEED);
    let enrolled = vault.enrol(&key, 2, vec![vault.tip()]);
    let answered = vault.node_answers_yours(1, vec![enrolled], &key);
    let switched = vault.node_sets_web_sign_in(2, vec![answered], speaks_for(&[&key]), &[], &[]);
    let fold = vault.fold();
    let node_key = vault.answer.node.verifying_key().to_bytes();
    assert!(
        mine(&fold, vault.answer.machine, &node_key),
        "the answer an owner key proved makes the node the owner's machine: {:?}",
        fold.issues
    );
    assert!(
        fold.waiting_owner_choices().contains(&switched),
        "the owner's machine carries the switch back with no owner key's cosign: it waits: {:?}",
        fold.issues
    );
}

/// WAYBACK-6 = A: a key enrolled after the switch back arms the vault again.
/// The switch spoke for the first key alone, so with both keys removed the
/// vault asks. Base: nothing asks once the keys are gone.
#[test]
fn a_key_enrolled_after_the_switch_back_arms_the_vault_again() {
    let mut vault = OwnerKeyVault::hosted();
    let key = signing(OWNER_KEY_SEED);
    let later = signing(LATER_OWNER_KEY_SEED);
    let enrolled = vault.enrol(&key, 2, vec![vault.tip()]);
    let switched =
        vault.node_sets_web_sign_in(1, vec![enrolled], speaks_for(&[&key]), &[], &[&key]);
    let enrolled_later = vault.enrol(&later, 3, vec![switched]);
    let removed = vault.key_removes_itself(&key, vec![enrolled_later]);
    let removed_later = vault.key_removes_itself(&later, vec![removed]);
    let pick = vault.node_picks_home(2, vec![removed_later]);
    assert_the_pick_waits(&vault.fold(), pick);
}

/// A switch back and an enrolment that did not see each other read as the
/// stricter: the vault asks. Base: nothing asks once the keys are gone.
#[test]
fn a_switch_back_and_an_enrolment_on_two_branches_read_as_asking() {
    let mut vault = OwnerKeyVault::hosted();
    let key = signing(OWNER_KEY_SEED);
    let later = signing(LATER_OWNER_KEY_SEED);
    let enrolled = vault.enrol(&key, 2, vec![vault.tip()]);
    let switched =
        vault.node_sets_web_sign_in(1, vec![enrolled], speaks_for(&[&key]), &[], &[&key]);
    let enrolled_beside = vault.enrol(&later, 3, vec![enrolled]);
    let removed = vault.key_removes_itself(&key, vec![switched, enrolled_beside]);
    let removed_later = vault.key_removes_itself(&later, vec![removed]);
    let pick = vault.node_picks_home(2, vec![removed_later]);
    assert_the_pick_waits(&vault.fold(), pick);
}

/// The owner's later choice to ask for an owner key ends the switch back. On
/// a vault that runs on web sign-in any carrier may bring it: it narrows.
/// Base: nothing asks once the key is gone.
#[test]
fn a_later_choice_to_ask_for_an_owner_key_ends_the_switch_back() {
    let mut vault = OwnerKeyVault::hosted();
    let key = signing(OWNER_KEY_SEED);
    let enrolled = vault.enrol(&key, 2, vec![vault.tip()]);
    let switched =
        vault.node_sets_web_sign_in(1, vec![enrolled], speaks_for(&[&key]), &[], &[&key]);
    let removed = vault.key_removes_itself(&key, vec![switched]);
    let asks =
        vault.node_sets_web_sign_in(2, vec![removed], ASKS_FOR_AN_OWNER_KEY, &[switched], &[]);
    let pick = vault.node_picks_home(3, vec![asks]);
    let fold = vault.fold();
    assert!(
        fold.valid_entries.contains(&asks) && !fold.waiting_owner_choices().contains(&asks),
        "on web sign-in the node carries the choice to ask for a key, and it lands: {:?}",
        fold.issues
    );
    assert_the_pick_waits(&fold, pick);
}

/// A value speaks only for the keys the vault held when it was signed. On
/// web sign-in the node carries, with no cosign, a value over the first key
/// and one the owner enrols afterwards: it never comes to speak for both.
/// Base: nothing asks once the keys are gone.
#[test]
fn a_carrier_cannot_speak_for_a_key_the_vault_does_not_hold_yet() {
    let mut vault = OwnerKeyVault::hosted();
    let key = signing(OWNER_KEY_SEED);
    let later = signing(LATER_OWNER_KEY_SEED);
    let enrolled = vault.enrol(&key, 2, vec![vault.tip()]);
    let switched =
        vault.node_sets_web_sign_in(1, vec![enrolled], speaks_for(&[&key]), &[], &[&key]);
    let removed = vault.key_removes_itself(&key, vec![switched]);
    let ahead = vault.node_sets_web_sign_in(
        2,
        vec![removed],
        speaks_for(&[&key, &later]),
        &[switched],
        &[],
    );
    let enrolled_later = vault.enrol(&later, 3, vec![ahead]);
    let removed_later = vault.key_removes_itself(&later, vec![enrolled_later]);
    let pick = vault.node_picks_home(3, vec![removed_later]);
    assert_the_pick_waits(&vault.fold(), pick);
}

/// The switch is a managed host's vault's alone: a self-host vault has no
/// account to fall back to. The owner's own root cosigns the act; it is
/// valid, and the vault asks as before, on the base as well.
#[test]
fn a_self_host_vault_takes_no_switch_back() {
    let mut vault = OwnerKeyVault::self_host();
    let root = vault.answer.root.clone();
    let switched =
        vault.node_sets_web_sign_in(1, vec![vault.tip()], speaks_for(&[&root]), &[], &[&root]);
    let pick = vault.node_picks_home(2, vec![switched]);
    let fold = vault.fold();
    assert!(
        fold.valid_entries.contains(&switched),
        "the root's cosign is a proof on a self-host vault, so the act is a valid entry: {:?}",
        fold.issues
    );
    assert_the_pick_waits(&fold, pick);
}

/// The value's formula, pinned beside the code: BLAKE3 under its context
/// over each key, in order, as a suite byte and the public key.
#[test]
fn the_web_sign_in_value_is_blake3_over_the_owner_keys_in_order() {
    let first = key_of(&signing(OWNER_KEY_SEED));
    let second = key_of(&signing(LATER_OWNER_KEY_SEED));
    let keys = BTreeSet::from([first.clone(), second]);
    let mut hasher = blake3::Hasher::new_derive_key("oneiron web sign-in owner keys v1");
    for key in &keys {
        let (suite, bytes) = match key {
            AuthorityKey::Ed25519(bytes) => (1_u8, bytes.as_slice()),
            AuthorityKey::P256(bytes) => (2_u8, bytes.as_slice()),
        };
        hasher.update(&[suite]);
        hasher.update(bytes);
    }
    assert_eq!(
        web_sign_in_value(&keys),
        *hasher.finalize().as_bytes(),
        "the value is the documented digest of the keys"
    );
    assert_ne!(
        web_sign_in_value(&keys),
        web_sign_in_value(&BTreeSet::from([first])),
        "a later key changes the value"
    );
}
