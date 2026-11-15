//! Row CARRIER-PROOF-OLD-PARENTS (FIX-LIST 26314; Engine RULING 21:09, the lead 21:13):
//! a carrier that is not the owner's, on a hosted vault, names parents from
//! before the first owner key's enrolment, so its unproven act is judged
//! where no proving key exists.
//!
//! Pure folds over hand-signed rows: a genesis custodial root, the root's
//! registration of a hosted node M (and, for the machine test, of a second
//! machine X), the root's fold-only enrolment of owner key K carried by M,
//! and M's own unproven act parented before the enrolment. Each act waits
//! for, or is held for, the owner's proof once the fold judges it where K
//! exists; on the old parents it lands today.
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test carrier_proof_old_parents`.

#![cfg(oneiron_test_support)]

use std::collections::{BTreeMap, BTreeSet};

use ed25519_dalek::{Signer, SigningKey};
use oneiron::authority::{
    AUTHORITY_LOG_SCHEMA_VERSION, ActSurface, AuthorityAttestation, AuthorityEntryHash,
    AuthorityFold, AuthorityKey, AuthorityLogEntry, AuthorityOp, AuthoritySignature, AuthorityTier,
    AuthorityVaultId, DeviceAuthority, GenesisRecoveryStep, MACHINE_ENCRYPTION_KEY_LEN,
    MACHINE_ENCRYPTION_SUITE_HYBRID_V1, MachineDeviceClass, MachineEncryptionKey, MachineProfile,
    MachineRole, OwnerAct, OwnerActKind, ROLE_ADMIN, ROLE_AGENT, ROLE_CLOUD, ROLE_OWNER,
    authority_entry_hash, authority_transcript, fold_authority_log_for_posture, genesis_vault_id,
    machine_profile_proof_transcript,
};
use oneiron::test_doors::conversation_training_fold::training_revision;
use oneiron::test_doors::device_succession_fold::successor;
use oneiron::test_doors::home_pick_fold::home_pick_in_force;
use oneiron::test_doors::owner_key_line::tail_goes_to_the_whole_log;
use oneiron::{EntityId, HostingPrivacyPosture};
use oneiron_authority::authority::{
    AuthorityConfirmAction, AuthorityConfirmKind, CheckpointPolicySet, CheckpointRootChoice,
    ConversationTrainingSet, ConversationTrainingVaultSet, DeviceSuccession, HomeNodePick,
    OWNER_KEY_ENROLLMENT_SEEN, OWNER_KEY_POSSESSION_KIND, OriginCut, OwnerKeyEnroll, PolicySetting,
    PolicySettingSet, checkpoint_policy_target, conversation_training_vault_target,
    device_succession_target, home_pick_target, machine_answer_revision, origin_cut_target,
    owner_key_enrollment_challenge, owner_key_enrollment_target, roster_has_live_owner,
};

const ROOT_SEED: u8 = 61;
const NODE_SEED: u8 = 62;
const VICTIM_SEED: u8 = 63;
const OWNER_KEY_SEED: u8 = 71;

/// The node the home picks name.
const PICKED_NODE: u64 = 7;

/// The retired device the successions name: its client id and device key.
const SUCCESSOR_CLIENT: u64 = 7;
const SUCCESSOR_KEY: [u8; 32] = [77; 32];

/// The repository the origin cuts name, the epoch the carried cut opens, and
/// the epoch its probe opens above it.
const REPO: [u8; 32] = [0x0c; 32];
const CUT_EPOCH: u64 = 1;
const PROBE_EPOCH: u64 = 2;

/// The digests the policy setting act carries: the value it replaced and
/// the value it left.
const POLICY_PRIOR: [u8; 32] = [0; 32];
const POLICY_VALUE: [u8; 32] = [1; 32];

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

fn owner() -> EntityId {
    EntityId::from_bytes([0x71; 16]).expect("an id")
}

/// A person of the vault who is not its owner.
fn member() -> EntityId {
    EntityId::from_bytes([0x75; 16]).expect("an id")
}

/// `who`'s act of `kind` on `target`, decided on this install, having seen
/// the zero revision.
fn act(who: EntityId, kind: OwnerActKind, target: EntityId) -> OwnerAct {
    OwnerAct::by_owner(who, kind, target, ActSurface::ThisInstall, [0; 32])
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
    let proof_transcript = machine_profile_proof_transcript(
        &vault_id,
        machine,
        &machine_key,
        MachineDeviceClass::Computer,
        &encryption_key,
    );
    let machine_proof = node.sign(&proof_transcript).to_bytes();
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

/// The fold of hand-signed rows under the hosted posture.
fn fold_hosted(rows: &[AuthorityLogEntry]) -> AuthorityFold {
    fold_authority_log_for_posture(
        rows,
        &BTreeMap::new(),
        1,
        &BTreeMap::new(),
        HostingPrivacyPosture::Hosted,
    )
}

/// A managed host's vault: a custodial root, its registration of hosted
/// node M, and the root's fold-only enrolment of owner key K carried by M.
/// Replicas fold under the hosted posture.
struct OldParents {
    root: SigningKey,
    node: SigningKey,
    machine: EntityId,
    owner_key: SigningKey,
    root_seq: u64,
    rows: Vec<AuthorityLogEntry>,
}

impl OldParents {
    fn new() -> Self {
        let root = signing(ROOT_SEED);
        let node = signing(NODE_SEED);
        let owner_key = signing(OWNER_KEY_SEED);
        let genesis = genesis_row(
            &root,
            ROLE_OWNER | ROLE_ADMIN | ROLE_CLOUD,
            AuthorityTier::CloudCustodial,
        );
        let vault_id = genesis_vault_id(&genesis).expect("the vault id");
        let machine = EntityId::from_bytes([0x70; 16]).expect("an id");
        let profile = node_profile(vault_id, machine, &node, MachineRole::HostedNode, 1, None);
        let parents = vec![hash(&genesis)];
        let registration = signed(
            Some(vault_id),
            1,
            parents,
            AuthorityOp::MachineProfile(profile),
            &root,
            &[],
        );
        Self {
            root,
            node,
            machine,
            owner_key,
            root_seq: 1,
            rows: vec![genesis, registration],
        }
    }

    fn vault_id(&self) -> AuthorityVaultId {
        genesis_vault_id(&self.rows[0]).expect("the vault id")
    }

    fn owner_authority_key(&self) -> AuthorityKey {
        key_of(&self.owner_key)
    }

    fn fold(&self) -> AuthorityFold {
        fold_hosted(&self.rows)
    }

    /// The root signs `op` on `parents` at its next sequence. Returns the
    /// entry's hash.
    fn push_root_row(
        &mut self,
        parents: Vec<AuthorityEntryHash>,
        op: AuthorityOp,
    ) -> AuthorityEntryHash {
        self.root_seq += 1;
        let seq = self.root_seq;
        let vault_id = self.vault_id();
        let row = signed(Some(vault_id), seq, parents, op, &self.root, &[]);
        let entry = hash(&row);
        self.rows.push(row);
        entry
    }

    /// The root enrols the owner key on the last row, carried by M: the
    /// root signs, M cosigns, the key proves possession. Returns e2.
    fn enrol_owner_key(&mut self) -> AuthorityEntryHash {
        let vault_id = self.vault_id();
        let public_key = self.owner_key.verifying_key().to_bytes();
        let target = owner_key_enrollment_target(&vault_id, &public_key).expect("the target");
        let challenge =
            owner_key_enrollment_challenge(&vault_id, self.machine, &public_key, owner())
                .expect("the challenge");
        let proof = self.owner_key.sign(&challenge).to_bytes().to_vec();
        let op = AuthorityOp::OwnerKeyEnroll(OwnerKeyEnroll {
            act: OwnerAct::by_owner(
                owner(),
                OwnerActKind::OwnerKeyEnrollment,
                target,
                ActSurface::ThisInstall,
                OWNER_KEY_ENROLLMENT_SEEN,
            ),
            machine: self.machine,
            carrier: self.machine,
            device: DeviceAuthority {
                key: AuthorityKey::Ed25519(public_key),
                transport_key_binding: [0; 32],
                attestation: AuthorityAttestation {
                    kind: OWNER_KEY_POSSESSION_KIND.to_owned(),
                    evidence: proof,
                },
                tier: AuthorityTier::Software,
                roles: ROLE_OWNER,
            },
        });
        self.root_seq += 1;
        let seq = self.root_seq;
        let parent = hash(self.rows.last().expect("a parent row"));
        let row = signed(
            Some(vault_id),
            seq,
            vec![parent],
            op,
            &self.root,
            &[&self.node],
        );
        let entry = hash(&row);
        self.rows.push(row);
        entry
    }

    /// The root registers a second machine, an execution node, on the last
    /// row. Returns its key, id and registration hash.
    fn register_second_machine(&mut self) -> (SigningKey, EntityId, AuthorityEntryHash) {
        let key = signing(VICTIM_SEED);
        let machine = EntityId::from_bytes([0x72; 16]).expect("an id");
        let vault_id = self.vault_id();
        let parent = hash(self.rows.last().expect("a parent row"));
        let profile = node_profile(vault_id, machine, &key, MachineRole::ExecutionNode, 1, None);
        let entry = self.push_root_row(vec![parent], AuthorityOp::MachineProfile(profile));
        (key, machine, entry)
    }

    /// M carries `op` on `parents` under its own install key, with no
    /// cosign: its first primary-signed row.
    fn carry(&mut self, parents: Vec<AuthorityEntryHash>, op: AuthorityOp) -> AuthorityEntryHash {
        let vault_id = self.vault_id();
        let row = signed(Some(vault_id), 1, parents, op, &self.node, &[]);
        let entry = hash(&row);
        self.rows.push(row);
        entry
    }

    /// The root enrols `key` as an agent device key on `parent`.
    fn root_enrols_agent_key(
        &mut self,
        parent: AuthorityEntryHash,
        key: AuthorityKey,
    ) -> AuthorityEntryHash {
        let device = DeviceAuthority {
            key,
            transport_key_binding: [7; 32],
            attestation: AuthorityAttestation {
                kind: "SoftwareArgon2id".to_owned(),
                evidence: vec![1, 2, 3],
            },
            tier: AuthorityTier::Software,
            roles: ROLE_AGENT,
        };
        self.push_root_row(vec![parent], AuthorityOp::EnrollDevice { device })
    }
}

/// M carries the owner's checkpoint policy choice of `roots`, having seen
/// no live choice.
fn checkpoint_policy_op(
    vault_id: AuthorityVaultId,
    machine: EntityId,
    roots: Vec<AuthorityKey>,
) -> AuthorityOp {
    let target = checkpoint_policy_target(&vault_id).expect("the choice's target");
    let choice = Some(CheckpointRootChoice {
        roots,
        quorum: 1,
        hardware: false,
    });
    AuthorityOp::CheckpointPolicySet(CheckpointPolicySet {
        act: act(owner(), OwnerActKind::CheckpointPolicy, target),
        machine,
        choice,
    })
}

/// M carries the owner's home pick of `node_id`, having seen no live pick.
fn home_pick_op(vault_id: AuthorityVaultId, machine: EntityId, node_id: u64) -> AuthorityOp {
    let target = home_pick_target(&vault_id).expect("the pick's target");
    AuthorityOp::HomeNodePick(HomeNodePick {
        act: act(owner(), OwnerActKind::HomeNodePick, target),
        machine,
        node_id: Some(node_id),
    })
}

/// M carries the owner's origin cut of `repo` opening `epoch` for `writer`,
/// having seen no live cut of it.
fn origin_cut_op(machine: EntityId, repo: [u8; 32], epoch: u64, writer: EntityId) -> AuthorityOp {
    let target = origin_cut_target(&repo).expect("the cut's target");
    AuthorityOp::OriginCut(OriginCut {
        act: act(owner(), OwnerActKind::OriginCut, target),
        machine,
        repo,
        epoch,
        writer,
    })
}

/// M carries the owner's succession of the device key under `client` to
/// `successor`, having seen no live succession of the pair.
fn succession_op(
    machine: EntityId,
    client: u64,
    device_key: [u8; 32],
    successor: EntityId,
) -> AuthorityOp {
    let target = device_succession_target(client, &device_key).expect("the succession's target");
    AuthorityOp::DeviceSuccession(DeviceSuccession {
        act: act(owner(), OwnerActKind::DeviceSuccession, target),
        machine,
        client,
        device_key,
        successor,
    })
}

/// `person`'s own conversation-training choice for themselves, carried by
/// `machine`, having seen no live choice of theirs.
fn training_op(person: EntityId, machine: EntityId, leave_out: bool) -> AuthorityOp {
    AuthorityOp::ConversationTrainingSet(ConversationTrainingSet {
        act: act(person, OwnerActKind::ConversationTraining, person),
        machine,
        leave_out,
    })
}

/// M carries the vault's conversation-training setting, having seen no live
/// setting choice.
fn vault_training_op(
    vault_id: AuthorityVaultId,
    machine: EntityId,
    on: bool,
    allow_opt_out: bool,
) -> AuthorityOp {
    let target = conversation_training_vault_target(&vault_id).expect("the setting's target");
    AuthorityOp::ConversationTrainingVaultSet(ConversationTrainingVaultSet {
        act: act(owner(), OwnerActKind::ConversationTraining, target),
        machine,
        on,
        allow_opt_out,
    })
}

/// M carries the owner's act on the dreamer wake policy, having seen no
/// live act on it.
fn policy_setting_op(machine: EntityId, prior: [u8; 32], value: Option<[u8; 32]>) -> AuthorityOp {
    let setting = PolicySetting::DreamerWakePolicy;
    let target = setting
        .reserved_target()
        .expect("the target")
        .expect("a vault-wide target");
    AuthorityOp::PolicySettingSet(PolicySettingSet {
        act: act(owner(), OwnerActKind::PolicySetting, target),
        machine,
        setting,
        prior,
        value,
    })
}

/// Whether a probe of the carried kind, naming the zero revision over the
/// carried entry, still folds valid: it does exactly while the carried act
/// never joined its target's live frontier.
fn probe_valid(vault: &OldParents, carried: AuthorityEntryHash, probe: AuthorityOp) -> bool {
    let mut rows = vault.rows.clone();
    let entry = signed(
        Some(vault.vault_id()),
        2,
        vec![carried],
        probe,
        &vault.node,
        &[],
    );
    let probe_hash = hash(&entry);
    rows.push(entry);
    fold_hosted(&rows).valid_entries.contains(&probe_hash)
}

/// Whether the carried checkpoint choice is in force: a probe naming the
/// zero revision is stale exactly then.
fn in_force_checkpoint_policy(vault: &OldParents, carried: AuthorityEntryHash) -> bool {
    let probe = checkpoint_policy_op(
        vault.vault_id(),
        vault.machine,
        vec![vault.owner_authority_key()],
    );
    !probe_valid(vault, carried, probe)
}

/// Whether the carried home pick is in force.
fn in_force_home_pick(fold: &AuthorityFold) -> bool {
    home_pick_in_force(fold) == Some(PICKED_NODE)
}

/// Whether the carried origin cut is in force: a probe opening the next
/// epoch over it is stale exactly then.
fn in_force_origin_cut(vault: &OldParents, carried: AuthorityEntryHash) -> bool {
    let probe = origin_cut_op(vault.machine, REPO, PROBE_EPOCH, vault.machine);
    !probe_valid(vault, carried, probe)
}

/// Whether the carried succession is in force.
fn in_force_succession(fold: &AuthorityFold, machine: EntityId) -> bool {
    successor(fold, SUCCESSOR_CLIENT, &SUCCESSOR_KEY).expect("the succession read") == Some(machine)
}

/// Whether the carried opt back in is in force: the member has a live
/// choice exactly then.
fn in_force_training(fold: &AuthorityFold) -> bool {
    training_revision(fold, member()) != [0; 32]
}

/// Whether the carried vault training setting is in force: a probe naming
/// the zero revision is stale exactly then.
fn in_force_vault_training(vault: &OldParents, carried: AuthorityEntryHash) -> bool {
    let probe = vault_training_op(vault.vault_id(), vault.machine, true, true);
    !probe_valid(vault, carried, probe)
}

/// Whether the carried policy setting act is in force: a probe naming the
/// zero revision is stale exactly then.
fn in_force_policy_setting(vault: &OldParents, carried: AuthorityEntryHash) -> bool {
    let probe = policy_setting_op(vault.machine, POLICY_PRIOR, Some(POLICY_VALUE));
    !probe_valid(vault, carried, probe)
}

/// Whether the carried act waits for the owner's proof.
fn waits(fold: &AuthorityFold, entry: &AuthorityEntryHash) -> bool {
    fold.waiting_owner_choices().contains(entry)
}

/// Whether the carried answer is held for the owner's proof.
fn is_held(fold: &AuthorityFold, machine: EntityId, entry: &AuthorityEntryHash) -> bool {
    fold.held_machine_answers()
        .get(&machine)
        .is_some_and(|held| held.contains_key(entry))
}

/// Whether `key` is a live owner key on the fold's roster.
fn live_owner(fold: &AuthorityFold, key: &AuthorityKey) -> bool {
    roster_has_live_owner(&fold.roster, key)
}

/// The enrolment counts and its key proves for the owner, so no test passes
/// for the wrong reason.
fn assert_enrolment_counted(
    fold: &AuthorityFold,
    enrolment: &AuthorityEntryHash,
    key: &AuthorityKey,
) {
    assert!(
        fold.valid_entries.contains(enrolment),
        "enrolment counts: {enrolment:?}"
    );
    assert!(
        live_owner(fold, key),
        "enrolled key is a live owner key: {key:?}"
    );
}

/// The row's scaffold: the enrolment on e1, then M's unproven act on the
/// row before it. Returns the fold with the enrolment, the key and the act.
fn old_parents_carried(
    vault: &mut OldParents,
    op: AuthorityOp,
) -> (
    AuthorityFold,
    AuthorityEntryHash,
    AuthorityKey,
    AuthorityEntryHash,
) {
    let before = hash(&vault.rows[1]);
    let enrolment = vault.enrol_owner_key();
    let key = vault.owner_authority_key();
    let carried = vault.carry(vec![before], op);
    (vault.fold(), enrolment, key, carried)
}

/// Test 1 of the row. Main: the choice lands.
#[test]
fn an_old_parents_checkpoint_policy_choice_waits() {
    let mut vault = OldParents::new();
    let (vault_id, machine) = (vault.vault_id(), vault.machine);
    let key = vault.owner_authority_key();
    let op = checkpoint_policy_op(vault_id, machine, vec![key.clone()]);
    let (fold, enrolment, key, carried) = old_parents_carried(&mut vault, op);
    assert_enrolment_counted(&fold, &enrolment, &key);
    assert!(
        !in_force_checkpoint_policy(&vault, carried),
        "choice not in force: {:?}",
        fold.issues
    );
    assert!(
        waits(&fold, &carried),
        "old-parents choice waits: {:?}",
        fold.issues
    );
}

/// Test 2 of the row. Main: the pick lands.
#[test]
fn an_old_parents_home_pick_waits() {
    let mut vault = OldParents::new();
    let (vault_id, machine) = (vault.vault_id(), vault.machine);
    let op = home_pick_op(vault_id, machine, PICKED_NODE);
    let (fold, enrolment, key, carried) = old_parents_carried(&mut vault, op);
    assert_enrolment_counted(&fold, &enrolment, &key);
    assert!(
        !in_force_home_pick(&fold),
        "old-parents pick not in force: {:?}",
        fold.issues
    );
    assert!(
        waits(&fold, &carried),
        "old-parents pick waits: {:?}",
        fold.issues
    );
}

/// Test 3 of the row. Main: the cut lands.
#[test]
fn an_old_parents_origin_cut_waits() {
    let mut vault = OldParents::new();
    let machine = vault.machine;
    let op = origin_cut_op(machine, REPO, CUT_EPOCH, machine);
    let (fold, enrolment, key, carried) = old_parents_carried(&mut vault, op);
    assert_enrolment_counted(&fold, &enrolment, &key);
    assert!(
        !in_force_origin_cut(&vault, carried),
        "cut not in force: {:?}",
        fold.issues
    );
    assert!(
        waits(&fold, &carried),
        "old-parents cut waits: {:?}",
        fold.issues
    );
}

/// Test 4 of the row. Main: the succession lands.
#[test]
fn an_old_parents_device_succession_waits() {
    let mut vault = OldParents::new();
    let machine = vault.machine;
    let op = succession_op(machine, SUCCESSOR_CLIENT, SUCCESSOR_KEY, machine);
    let (fold, enrolment, key, carried) = old_parents_carried(&mut vault, op);
    assert_enrolment_counted(&fold, &enrolment, &key);
    assert!(
        !in_force_succession(&fold, machine),
        "succession not in force: {:?}",
        fold.issues
    );
    assert!(
        waits(&fold, &carried),
        "old-parents succession waits: {:?}",
        fold.issues
    );
}

/// Test 5 of the row. Main: the opt back in lands.
#[test]
fn an_old_parents_persons_opt_back_in_waits() {
    let mut vault = OldParents::new();
    let machine = vault.machine;
    let op = training_op(member(), machine, false);
    let (fold, enrolment, key, carried) = old_parents_carried(&mut vault, op);
    assert_enrolment_counted(&fold, &enrolment, &key);
    assert!(
        !in_force_training(&fold),
        "old-parents opt back in not in force: {:?}",
        fold.issues
    );
    assert!(
        waits(&fold, &carried),
        "old-parents opt back in waits: {:?}",
        fold.issues
    );
}

/// Test 6 of the row. Main: the setting lands.
#[test]
fn an_old_parents_vault_training_choice_waits() {
    let mut vault = OldParents::new();
    let (vault_id, machine) = (vault.vault_id(), vault.machine);
    let op = vault_training_op(vault_id, machine, true, true);
    let (fold, enrolment, key, carried) = old_parents_carried(&mut vault, op);
    assert_enrolment_counted(&fold, &enrolment, &key);
    assert!(
        !in_force_vault_training(&vault, carried),
        "setting not in force: {:?}",
        fold.issues
    );
    assert!(
        waits(&fold, &carried),
        "old-parents setting waits: {:?}",
        fold.issues
    );
}

/// Test 7 of the row. Main: the act lands.
#[test]
fn an_old_parents_policy_setting_choice_waits() {
    let mut vault = OldParents::new();
    let machine = vault.machine;
    let op = policy_setting_op(machine, POLICY_PRIOR, Some(POLICY_VALUE));
    let (fold, enrolment, key, carried) = old_parents_carried(&mut vault, op);
    assert_enrolment_counted(&fold, &enrolment, &key);
    assert!(
        !in_force_policy_setting(&vault, carried),
        "act not in force: {:?}",
        fold.issues
    );
    assert!(
        waits(&fold, &carried),
        "old-parents act waits: {:?}",
        fold.issues
    );
}

/// Test 8 of the row. Main: the removal lands, and no later revision brings
/// the machine back.
#[test]
fn an_old_parents_machine_removal_is_held() {
    let mut vault = OldParents::new();
    let (victim_key, victim, registered) = vault.register_second_machine();
    let enrolment = vault.enrol_owner_key();
    let key = vault.owner_authority_key();
    let (vault_id, machine) = (vault.vault_id(), vault.machine);
    // The removal names the registration it answers.
    let removal_act = OwnerAct::by_owner(
        owner(),
        OwnerActKind::MachineRemoval,
        victim,
        ActSurface::ThisInstall,
        machine_answer_revision([registered]),
    );
    let answer = Some((machine, removal_act));
    let profile = node_profile(
        vault_id,
        victim,
        &victim_key,
        MachineRole::Removed,
        2,
        answer,
    );
    let carried = vault.carry(vec![registered], AuthorityOp::MachineProfile(profile));
    let fold = vault.fold();
    assert_enrolment_counted(&fold, &enrolment, &key);
    let head = fold
        .machine(victim)
        .and_then(|folded| folded.roster.as_ref())
        .expect("the registration folds");
    assert_eq!(
        head.profile.role,
        MachineRole::ExecutionNode,
        "not in force: {:?}",
        fold.issues
    );
    assert!(
        head.is_live(),
        "the registration still stands: {:?}",
        fold.issues
    );
    assert_eq!(
        head.entry, registered,
        "old-parents removal moves no head: {:?}",
        fold.issues
    );
    assert!(
        is_held(&fold, victim, &carried),
        "old-parents removal is held: {:?}",
        fold.issues
    );
}

/// Test 9 of the row, the control. On this tree today the choice waits: its
/// parents already enrol the proving key.
#[test]
fn a_choice_after_the_enrolment_still_waits() {
    let mut vault = OldParents::new();
    let enrolment = vault.enrol_owner_key();
    let key = vault.owner_authority_key();
    let (vault_id, machine) = (vault.vault_id(), vault.machine);
    let carried = vault.carry(
        vec![enrolment],
        home_pick_op(vault_id, machine, PICKED_NODE),
    );
    let fold = vault.fold();
    assert_enrolment_counted(&fold, &enrolment, &key);
    assert!(
        !in_force_home_pick(&fold),
        "pick after the enrolment not in force: {:?}",
        fold.issues
    );
    assert!(
        waits(&fold, &carried),
        "pick after the enrolment waits: {:?}",
        fold.issues
    );
}

/// Test 10 of the row (Engine RULING 22:05, OLDPARENTS-ENROL-DODGE = A):
/// the root's agent enrolment of the owner key on old parents is an invalid
/// entry, so it never ends the key. Main: it counts, and the roster merge
/// leaves the key no role.
#[test]
fn an_agent_enrolment_of_an_owner_key_on_old_parents_does_not_end_it() {
    let mut vault = OldParents::new();
    let before = hash(&vault.rows[1]);
    let enrolment = vault.enrol_owner_key();
    let key = vault.owner_authority_key();
    let agent_enrolment = vault.root_enrols_agent_key(before, key.clone());
    let fold = vault.fold();
    assert!(
        fold.valid_entries.contains(&enrolment),
        "enrolment counts: {enrolment:?}"
    );
    assert!(
        !fold.valid_entries.contains(&agent_enrolment),
        "old-parents agent enrolment of the owner key is invalid: {:?}",
        fold.issues
    );
    assert!(
        live_owner(&fold, &key),
        "agent enrolment never ends the owner key: {key:?}"
    );
    let roles = fold.roster.get(&key).map(|device| device.roles);
    assert!(
        roles.is_some_and(|roles| roles & ROLE_OWNER != 0),
        "key keeps owner role: {roles:?}"
    );
}

/// The second owner key (test 11) and the successor root and node (test 12).
const OWNER_KEY_SEED_2: u8 = 72;
const NEW_ROOT_SEED: u8 = 64;
const NEW_NODE_SEED: u8 = 65;

impl OldParents {
    /// The root enrols `owner_key` (held by `holder`, carried by M) on
    /// `parent`: a copy of [`OldParents::enrol_owner_key`] with an explicit
    /// parent, key and holder. The possession challenge binds the HOLDER
    /// machine; the carrier stays M (its install key cosigns).
    fn enrol_owner_key_on(
        &mut self,
        parent: AuthorityEntryHash,
        owner_key: &SigningKey,
        holder: EntityId,
    ) -> AuthorityEntryHash {
        let vault_id = self.vault_id();
        let public_key = owner_key.verifying_key().to_bytes();
        let target = owner_key_enrollment_target(&vault_id, &public_key).expect("the target");
        let challenge = owner_key_enrollment_challenge(&vault_id, holder, &public_key, owner())
            .expect("the challenge");
        let proof = owner_key.sign(&challenge).to_bytes().to_vec();
        let op = AuthorityOp::OwnerKeyEnroll(OwnerKeyEnroll {
            act: OwnerAct::by_owner(
                owner(),
                OwnerActKind::OwnerKeyEnrollment,
                target,
                ActSurface::ThisInstall,
                OWNER_KEY_ENROLLMENT_SEEN,
            ),
            machine: holder,
            carrier: self.machine,
            device: DeviceAuthority {
                key: AuthorityKey::Ed25519(public_key),
                transport_key_binding: [0; 32],
                attestation: AuthorityAttestation {
                    kind: OWNER_KEY_POSSESSION_KIND.to_owned(),
                    evidence: proof,
                },
                tier: AuthorityTier::Software,
                roles: ROLE_OWNER,
            },
        });
        self.root_seq += 1;
        let seq = self.root_seq;
        let row = signed(
            Some(vault_id),
            seq,
            vec![parent],
            op,
            &self.root,
            &[&self.node],
        );
        let entry = hash(&row);
        self.rows.push(row);
        entry
    }

    /// M carries `op` on `parents` under its own install key at `seq`.
    fn carry_with_seq(
        &mut self,
        parents: Vec<AuthorityEntryHash>,
        op: AuthorityOp,
        seq: u64,
    ) -> AuthorityEntryHash {
        let vault_id = self.vault_id();
        let row = signed(Some(vault_id), seq, parents, op, &self.node, &[]);
        let entry = hash(&row);
        self.rows.push(row);
        entry
    }

    /// `signer` signs `op` on `parents` at `seq` with no cosign: for rows
    /// neither the root nor M signs (a successor root, a fresh node).
    fn push_signed_row(
        &mut self,
        parents: Vec<AuthorityEntryHash>,
        op: AuthorityOp,
        signer: &SigningKey,
        seq: u64,
    ) -> AuthorityEntryHash {
        let vault_id = self.vault_id();
        let row = signed(Some(vault_id), seq, parents, op, signer, &[]);
        let entry = hash(&row);
        self.rows.push(row);
        entry
    }
}

/// Test 11 of the row (Sol xhigh review OLD-01, 15 Nov 23:2x): an enrolment
/// the second fold admits has its own line. Branch one carries a home pick T
/// on P and enrols K1 on T; branch two carries a removal R of X on P and
/// enrols K2 (holder X) on R. The first fold refuses E2 (R removed X), the
/// second holds R and admits E2, and only a third fold makes T (outside E2's
/// line) wait.
#[test]
fn an_enrolment_the_second_fold_admits_has_its_own_line() {
    let mut vault = OldParents::new();
    let (victim_key, victim, registered) = vault.register_second_machine();
    let (vault_id, machine) = (vault.vault_id(), vault.machine);
    let t = vault.carry(
        vec![registered],
        home_pick_op(vault_id, machine, PICKED_NODE),
    );
    let k1_signing = signing(OWNER_KEY_SEED);
    let e1 = vault.enrol_owner_key_on(t, &k1_signing, machine);
    let k1 = key_of(&k1_signing);
    let removal_act = OwnerAct::by_owner(
        owner(),
        OwnerActKind::MachineRemoval,
        victim,
        ActSurface::ThisInstall,
        machine_answer_revision([registered]),
    );
    let answer = Some((machine, removal_act));
    let profile = node_profile(
        vault_id,
        victim,
        &victim_key,
        MachineRole::Removed,
        2,
        answer,
    );
    let r = vault.carry_with_seq(vec![registered], AuthorityOp::MachineProfile(profile), 2);
    let k2_signing = signing(OWNER_KEY_SEED_2);
    let e2 = vault.enrol_owner_key_on(r, &k2_signing, victim);
    let k2 = key_of(&k2_signing);
    let fold = vault.fold();
    assert_enrolment_counted(&fold, &e1, &k1);
    assert!(
        fold.valid_entries.contains(&e2),
        "second enrolment counts: {:?}",
        fold.issues
    );
    assert!(
        live_owner(&fold, &k2),
        "second key is a live owner key: {k2:?} {:?}",
        fold.issues
    );
    assert!(
        is_held(&fold, victim, &r),
        "removal outside the first line is held: {:?}",
        fold.issues
    );
    assert!(
        waits(&fold, &t),
        "pick outside the second line waits: {:?}",
        fold.issues
    );
    assert!(
        !in_force_home_pick(&fold),
        "pick outside the second line not in force: {:?}",
        fold.issues
    );
}

/// Test 12 of the row (Sol xhigh review OLD-04, 15 Nov 23:2x): an enrolment
/// a handoff prunes makes no choice wait. E enrols K on P, H re-roots A to B
/// on P, B registers N on H, and N carries a home pick T on its own
/// registration. H settles and retires A on every branch, so E (signed by A
/// outside H's line) is invalid, K proves nowhere, and T lands.
#[test]
fn an_enrolment_a_handoff_prunes_makes_no_choice_wait() {
    let mut vault = OldParents::new();
    let p = hash(&vault.rows[1]);
    let e = vault.enrol_owner_key();
    let k = vault.owner_authority_key();
    let vault_id = vault.vault_id();
    let b_signing = signing(NEW_ROOT_SEED);
    let b_key = key_of(&b_signing);
    let h = vault.push_root_row(
        vec![p],
        AuthorityOp::ReRoot {
            new_device: DeviceAuthority {
                key: b_key,
                transport_key_binding: [7; 32],
                attestation: AuthorityAttestation {
                    kind: "SoftwareArgon2id".to_owned(),
                    evidence: vec![1, 2, 3],
                },
                tier: AuthorityTier::CloudCustodial,
                roles: ROLE_OWNER | ROLE_ADMIN | ROLE_CLOUD,
            },
        },
    );
    let n_signing = signing(NEW_NODE_SEED);
    let n_machine = EntityId::from_bytes([0x74; 16]).expect("an id");
    let n_profile = node_profile(
        vault_id,
        n_machine,
        &n_signing,
        MachineRole::HostedNode,
        1,
        None,
    );
    let n_reg = vault.push_signed_row(
        vec![h],
        AuthorityOp::MachineProfile(n_profile),
        &b_signing,
        1,
    );
    let t = vault.push_signed_row(
        vec![n_reg],
        home_pick_op(vault_id, n_machine, PICKED_NODE),
        &n_signing,
        1,
    );
    let fold = vault.fold();
    assert!(
        fold.valid_entries.contains(&h),
        "handoff counts: {:?}",
        fold.issues
    );
    assert!(
        !fold.valid_entries.contains(&e),
        "pruned enrolment does not count: {:?}",
        fold.issues
    );
    assert!(
        !live_owner(&fold, &k),
        "pruned key is no live owner: {k:?} {:?}",
        fold.issues
    );
    assert!(
        !waits(&fold, &t),
        "choice where no key proves does not wait: {:?}",
        fold.issues
    );
    assert!(
        in_force_home_pick(&fold),
        "choice where no key proves is in force: {:?}",
        fold.issues
    );
}

/// Test 13 of the row (Sol xhigh review OLD-02, 15 Nov 23:2x), a control: two
/// proving enrolments of one key both stand. E1 and E2 enrol the same K with
/// the same holder, carrier and possession proof on sibling branches from P.
/// Both prove in the first fold, so neither is outside the other's line as a
/// refused enrolment; it passes with and without the fix.
#[test]
fn two_proving_enrolments_of_one_key_both_stand() {
    let mut vault = OldParents::new();
    let p = hash(&vault.rows[1]);
    let machine = vault.machine;
    let k_signing = signing(OWNER_KEY_SEED);
    let k = key_of(&k_signing);
    let e1 = vault.enrol_owner_key_on(p, &k_signing, machine);
    let e2 = vault.enrol_owner_key_on(p, &k_signing, machine);
    let fold = vault.fold();
    assert!(
        fold.valid_entries.contains(&e1),
        "first enrolment counts: {:?}",
        fold.issues
    );
    assert!(
        fold.valid_entries.contains(&e2),
        "second enrolment counts: {:?}",
        fold.issues
    );
    assert!(
        live_owner(&fold, &k),
        "key is a live owner: {k:?} {:?}",
        fold.issues
    );
    let roles = fold.roster.get(&k).map(|device| device.roles);
    assert_eq!(
        roles,
        Some(ROLE_OWNER),
        "key keeps owner role: {roles:?} {:?}",
        fold.issues
    );
}

/// Test 14 of the row (Sol delta review DELTA-02, 16 Nov 00:2x): of two
/// enrolments whose keys the other branch enrolled as agent keys first, one
/// stands. From P, D1 enrols K2 as an agent key and E1 enrols K1 on D1; D2
/// enrols K1 as an agent key and E2 enrols K2 on D2; M carries a home pick T
/// on P. Each enrolment's line refuses the other's agent enrolment. With
/// both lines taken at once, both enrolments fell and T waited with no owner
/// key to answer; taken a key at a time, the earlier line refuses the later
/// enrolment's ancestry first, so exactly one enrolment stands, its key is a
/// live owner key, and T waits.
#[test]
fn of_two_enrolments_each_on_the_others_agent_key_one_stands() {
    let mut vault = OldParents::new();
    let p = hash(&vault.rows[1]);
    let (vault_id, machine) = (vault.vault_id(), vault.machine);
    let k1_signing = signing(OWNER_KEY_SEED);
    let k2_signing = signing(OWNER_KEY_SEED_2);
    let (k1, k2) = (key_of(&k1_signing), key_of(&k2_signing));
    let d1 = vault.root_enrols_agent_key(p, k2.clone());
    let e1 = vault.enrol_owner_key_on(d1, &k1_signing, machine);
    let d2 = vault.root_enrols_agent_key(p, k1.clone());
    let e2 = vault.enrol_owner_key_on(d2, &k2_signing, machine);
    let t = vault.carry(vec![p], home_pick_op(vault_id, machine, PICKED_NODE));
    let fold = vault.fold();
    let standing: Vec<&AuthorityKey> = [(e1, &k1), (e2, &k2)]
        .into_iter()
        .filter(|(enrolment, _)| fold.valid_entries.contains(enrolment))
        .map(|(_, key)| key)
        .collect();
    assert_eq!(
        standing.len(),
        1,
        "exactly one enrolment stands: {:?}",
        fold.issues
    );
    assert!(
        live_owner(&fold, standing[0]),
        "the standing key is a live owner key: {:?} {:?}",
        standing[0],
        fold.issues
    );
    assert!(
        waits(&fold, &t),
        "pick outside the standing line waits: {:?}",
        fold.issues
    );
    assert!(
        !in_force_home_pick(&fold),
        "pick outside the standing line not in force: {:?}",
        fold.issues
    );
}

/// The confirm id and nonce the root's federation confirms carry in tests
/// 15 and 16, and the peer vault they name.
const CONFIRM_ID: [u8; 32] = [0xc1; 32];
const CONFIRM_NONCE: [u8; 16] = [0xc2; 16];
const PEER_VAULT: AuthorityVaultId = [0xc3; 32];

/// The root's federation confirm of `confirm_id` under `nonce`.
fn confirm_op(confirm_id: [u8; 32], nonce: [u8; 16]) -> AuthorityOp {
    AuthorityOp::FederationConfirm(AuthorityConfirmAction {
        kind: AuthorityConfirmKind::Accept,
        confirm_id,
        peer_vault_id: PEER_VAULT,
        epoch: 1,
        nonce,
    })
}

impl OldParents {
    /// The root's row of the first op `ops` yields whose row on `parents`,
    /// at the root's next sequence, sorts before `before` in hash order:
    /// the lower of two contending confirms wins. Not pushed.
    fn root_row_before(
        &self,
        parents: &[AuthorityEntryHash],
        before: AuthorityEntryHash,
        ops: impl Iterator<Item = AuthorityOp>,
    ) -> AuthorityLogEntry {
        let vault_id = self.vault_id();
        ops.map(|op| {
            signed(
                Some(vault_id),
                self.root_seq + 1,
                parents.to_vec(),
                op,
                &self.root,
                &[],
            )
        })
        .find(|row| hash(row) < before)
        .expect("a row before the other in hash order")
    }
}

/// Test 15 of the row (Astra review OP-01, 16 Nov 00:5x): a tail of one
/// federation confirm goes to the whole log where the covered log holds an
/// owner key's line. From P (X registered), D enrols K2 as an agent key, the
/// root confirms C on D, and E1 enrols K1 (holder M) on C; M carries a
/// removal R of X on P, and E2 enrols K2 (holder X) on R. The covered fold
/// takes E1 (R holds), then E2, whose line refuses D: D, C and E1 fall, R
/// stays held under E1's line, and E2 stands. A confirm C' of C's id on P,
/// before C in hash order, is fresh against the image's settled confirms;
/// folded with the covered rows it prunes C and E1 before any line exists,
/// so R counts, E2 falls and D stands. Only the whole log judges that tail.
#[test]
fn a_confirm_tail_past_a_covered_line_goes_to_the_whole_log() {
    let mut vault = OldParents::new();
    let (victim_key, victim, registered) = vault.register_second_machine();
    let (vault_id, machine) = (vault.vault_id(), vault.machine);
    let k1_signing = signing(OWNER_KEY_SEED);
    let k2_signing = signing(OWNER_KEY_SEED_2);
    let k2 = key_of(&k2_signing);
    let d = vault.root_enrols_agent_key(registered, k2.clone());
    let c = vault.push_root_row(vec![d], confirm_op(CONFIRM_ID, CONFIRM_NONCE));
    let e1 = vault.enrol_owner_key_on(c, &k1_signing, machine);
    let removal_act = OwnerAct::by_owner(
        owner(),
        OwnerActKind::MachineRemoval,
        victim,
        ActSurface::ThisInstall,
        machine_answer_revision([registered]),
    );
    let profile = node_profile(
        vault_id,
        victim,
        &victim_key,
        MachineRole::Removed,
        2,
        Some((machine, removal_act)),
    );
    let r = vault.carry(vec![registered], AuthorityOp::MachineProfile(profile));
    let e2 = vault.enrol_owner_key_on(r, &k2_signing, victim);
    let covered = vault.fold();
    assert!(
        covered.valid_entries.contains(&e2),
        "E2 stands in the covered fold: {:?}",
        covered.issues
    );
    assert!(
        live_owner(&covered, &k2),
        "K2 is a live owner key in the covered fold: {:?}",
        covered.issues
    );
    assert!(
        [d, c, e1]
            .iter()
            .all(|entry| !covered.valid_entries.contains(entry)),
        "E2's line refuses D, and C and E1 fall with it: {:?}",
        covered.issues
    );
    assert!(
        is_held(&covered, victim, &r),
        "E1's line still holds R: {:?}",
        covered.issues
    );
    let tail = vault.root_row_before(
        &[registered],
        c,
        (1..=u8::MAX).map(|nonce| confirm_op(CONFIRM_ID, [nonce; 16])),
    );
    let c_tail = hash(&tail);
    let mut rows = vault.rows.clone();
    rows.push(tail.clone());
    let whole = fold_hosted(&rows);
    assert!(
        whole.valid_entries.contains(&c_tail) && !whole.valid_entries.contains(&c),
        "C' prunes C in the whole log: {:?}",
        whole.issues
    );
    assert!(
        !whole.valid_entries.contains(&e2) && whole.valid_entries.contains(&d),
        "in the whole log E2 falls and D stands: {:?}",
        whole.issues
    );
    assert!(
        !is_held(&whole, victim, &r),
        "R counts in the whole log: {:?}",
        whole.issues
    );
    assert!(
        tail_goes_to_the_whole_log(&vault.rows, &[tail]).expect("the guard's read"),
        "a fold past the image leaves C' to the whole log"
    );
}

/// Test 16 of the row (Astra review OP-02, 16 Nov 00:5x): an enrolment that
/// a row its own line lets fold prunes keeps its line. From P, the root
/// confirms C1 and E enrols K on C1; M carries a home pick U on P and a
/// second pick V on U, each having seen no live pick, and the root confirms
/// C2 on V with C1's nonce, before C1 in hash order. The first fold takes E
/// (V is stale on U, so C2 has no parent state); E's line makes U wait, so
/// V is fresh and waits too, and C2 counts and prunes C1 and E. The line
/// stays: U and V wait for the owner's proof, which the owner gives with the
/// next key it enrols. A line dropped with E would let the rows that pruned
/// it stand outside it.
#[test]
fn an_enrolment_its_own_line_lets_a_row_prune_keeps_its_line() {
    let mut vault = OldParents::new();
    let p = hash(&vault.rows[1]);
    let (vault_id, machine) = (vault.vault_id(), vault.machine);
    let k_signing = signing(OWNER_KEY_SEED);
    let k = key_of(&k_signing);
    let c1 = vault.push_root_row(vec![p], confirm_op(CONFIRM_ID, CONFIRM_NONCE));
    let e = vault.enrol_owner_key_on(c1, &k_signing, machine);
    let u = vault.carry(vec![p], home_pick_op(vault_id, machine, PICKED_NODE));
    let v = vault.carry_with_seq(vec![u], home_pick_op(vault_id, machine, PICKED_NODE), 2);
    let c2_row = vault.root_row_before(
        &[v],
        c1,
        (1..=u8::MAX).map(|id| confirm_op([id; 32], CONFIRM_NONCE)),
    );
    let c2 = hash(&c2_row);
    vault.root_seq += 1;
    vault.rows.push(c2_row);
    let fold = vault.fold();
    assert!(
        fold.valid_entries.contains(&c2),
        "C2 counts: {:?}",
        fold.issues
    );
    assert!(
        !fold.valid_entries.contains(&c1) && !fold.valid_entries.contains(&e),
        "C2 prunes C1 and E: {:?}",
        fold.issues
    );
    assert!(
        !live_owner(&fold, &k),
        "K is no live owner key: {:?}",
        fold.issues
    );
    assert!(
        waits(&fold, &u) && waits(&fold, &v),
        "U and V wait under E's line: {:?}",
        fold.issues
    );
    assert!(
        !in_force_home_pick(&fold),
        "no pick is in force: {:?}",
        fold.issues
    );
}

/// Test 17 of the row (Astra review OP-03, 16 Nov 01:3x): a covered revoke
/// of an owner key on parents that do not hold it leaves the tail guard the
/// enrolment. From P, E enrols K, and the root's sibling R revokes K on P,
/// where K is absent: R's state holds K with no role, so the merge of E's
/// and R's states strips K's owner role, and the merged roster shows no
/// owner key. M carries an unproven home pick U on P. U lies outside E's
/// line, so the whole log makes it wait, and a fold past the image leaves U
/// to the whole log. R counts at this row's head; row
/// HOSTED-ROOT-REVOKES-OWNER-KEY refuses it (a revoke of a key the parents do
/// not hold needs the owner's proof), and the guard answers the same.
#[test]
fn an_owner_key_revoked_where_absent_leaves_the_tail_to_the_whole_log() {
    let mut vault = OldParents::new();
    let p = hash(&vault.rows[1]);
    let (vault_id, machine) = (vault.vault_id(), vault.machine);
    let k_signing = signing(OWNER_KEY_SEED);
    let k = key_of(&k_signing);
    let e = vault.enrol_owner_key_on(p, &k_signing, machine);
    vault.push_root_row(vec![p], AuthorityOp::RevokeDevice { revoked_key: k });
    let covered = vault.fold();
    assert!(
        covered.valid_entries.contains(&e),
        "E counts in the covered fold: {:?}",
        covered.issues
    );
    let covered_rows = vault.rows.clone();
    let u = vault.carry(vec![p], home_pick_op(vault_id, machine, PICKED_NODE));
    let whole = vault.fold();
    assert!(
        waits(&whole, &u),
        "U waits in the whole log: {:?}",
        whole.issues
    );
    assert!(
        !in_force_home_pick(&whole),
        "no pick is in force: {:?}",
        whole.issues
    );
    let tail = vault.rows.last().expect("U's row").clone();
    assert!(
        tail_goes_to_the_whole_log(&covered_rows, &[tail]).expect("the guard's read"),
        "a fold past the image leaves U to the whole log"
    );
}
