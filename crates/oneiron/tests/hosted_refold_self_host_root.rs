//! A self-host root keeps proving for the owner when its vault's log is
//! folded under the Hosted posture (row HOSTED-REOPEN-REJUDGES-SELF-HOST-ROOT;
//! Engine ANSWER HOSTED-REFOLD-SELF-HOST-ROOT-CUSTODY = A, 17 Nov 00:39), and
//! a Hosted root is stamped for the cloud wherever it is minted (row
//! HOSTED-GENESIS-CLOUD-STAMP-UNCHECKED).
//!
//! The fold takes the posture from the install that opens the vault, for the
//! whole log: a self-host vault reopened with a Hosted config, imported into
//! a hosted vault, restored onto a managed node or linked to a hosted peer is
//! folded as hosted. Host custody comes from the log's cloud stamp: a key is
//! the host's when it, or any key that admitted it, carries `ROLE_CLOUD` or
//! `CloudCustodial`, the stamp every Hosted root and every root move made
//! under Hosted carries (`HostSlipIssuer::root_device`). The host-root
//! attestation alone, which a self-host root carries too, makes no key the
//! host's, so the acts that root signed or cosigned as the owner keep
//! counting. The operator's stamped root, and every key it admitted, still
//! act as nobody (owner ruling 2026-10-18: on our hosted cloud the operator
//! root acts as nobody inside a customer's vault). An install under the
//! Hosted posture never offers a host root it holds as the owner's proof.
//!
//! That writer rule holds on every path that signs for the owner with a held
//! root (the review of #9474, round 1): the vouch for another device's owner
//! key, the pairing bootstrap arm, and the carry of a root-signed answer
//! under a root move. A hosted install pairs a "yours" machine through its
//! carrier, where the answer waits for an owner key's proof; it vouches no
//! key with a self-host root it holds; and its root move to a stamped root
//! lands without signing an owner's answer under that root.
//!
//! Pure folds over hand-signed rows (the scaffold of
//! `hosted_root_human_bind.rs` and `carrier_owner_proof.rs`), and vaults
//! opened as a server opens them.
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test hosted_refold_self_host_root`.

#![cfg(oneiron_test_support)]

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use ed25519_dalek::{Signer, SigningKey};
use oneiron::authority::{
    AUTHORITY_LOG_SCHEMA_VERSION, ActAuthority, ActSurface, ActorBindingStatus,
    AuthorityAttestation, AuthorityEntryHash, AuthorityFold, AuthorityKey, AuthorityLogEntry,
    AuthorityOp, AuthoritySignature, AuthorityTier, AuthorityVaultId, DeviceAuthority,
    DeviceOwnerKeyVouch, GenesisRecoveryStep, HOST_ISSUER_SEED_BYTES, HostSlipIssuer,
    MACHINE_ENCRYPTION_KEY_LEN, MACHINE_ENCRYPTION_SUITE_HYBRID_V1, MachineAnswerLanding,
    MachineDeviceClass, MachineEncryptionKey, MachineEnrolmentRequest, MachineOwnership,
    MachineProfile, MachineRole, OwnerAct, OwnerActKind, OwnerKeyVouchRequest, PairingLink,
    PairingPrincipal, ROLE_ADMIN, ROLE_AGENT, ROLE_CLOUD, ROLE_OWNER, authority_entry_hash,
    authority_transcript, fold_authority_log_for_posture, genesis_vault_id,
    machine_profile_proof_transcript, pairing_binding_transcript_pinned,
};
use oneiron::consent::AuthenticatedOwner;
use oneiron::error::RecordError;
use oneiron::federation::Scope;
use oneiron::store::GateDecisionId;
use oneiron::test_doors::home_pick_fold::home_pick_in_force;
use oneiron::test_doors::label_writers::embedded_owner;
use oneiron::test_doors::root_appointment;
use oneiron::{EntityId, Error, HostingPrivacyPosture, Vault, VaultConfig};
use oneiron_authority::authority::{
    HomeNodePick, OWNER_KEY_ENROLLMENT_SEEN, OWNER_KEY_POSSESSION_KIND, OwnerKeyEnroll,
    home_pick_target, machine_answer_revision, owner_key_enrollment_challenge,
    owner_key_enrollment_target, roster_has_live_owner,
};

const ROOT_SEED: u8 = 101;
const NODE_SEED: u8 = 102;
/// A fresh seed, so no roster row, machine revision, actor binding or anchor
/// ever named the enrolled owner key.
const OWNER_KEY_SEED: u8 = 103;
/// The stamped root a root move under the Hosted posture hands the vault to.
const STAMPED_ROOT_SEED: u8 = 104;
/// A device key the stamped root enrols.
const ADMITTED_SEED: u8 = 105;
/// The seed of the host issuer a root move of a served vault hands it to.
const NEXT_ISSUER_SEED: u8 = 0x5B;
/// The seed of a joining machine's pairing connection key.
const PAIRING_SEED: u8 = 106;
/// The node the owner's home pick names.
const PICKED_NODE: u64 = 7;
/// The actor class of a person's binding.
const HUMAN: &str = "human";
/// The attestation every host root carries, self-hosted or managed
/// (`slip_vault.rs` `HOST_ROOT_ATTESTATION`).
const HOST_ROOT_ATTESTATION: &str = "HostRoot";
/// The roles a self-host root holds: the owner's own key.
const SELF_HOST_ROOT_ROLES: u16 = ROLE_OWNER | ROLE_ADMIN;
/// The roles a Hosted root holds: stamped for the cloud.
const HOSTED_ROOT_ROLES: u16 = ROLE_OWNER | ROLE_ADMIN | ROLE_CLOUD;

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

/// A host root's roster row: key `key`, attested as a host root, with
/// `roles` at `tier`.
fn host_root_device(key: AuthorityKey, roles: u16, tier: AuthorityTier) -> DeviceAuthority {
    DeviceAuthority {
        key,
        transport_key_binding: [7; 32],
        attestation: AuthorityAttestation {
            kind: HOST_ROOT_ATTESTATION.to_owned(),
            evidence: Vec::new(),
        },
        tier,
        roles,
    }
}

/// The vault's owner.
fn owner() -> EntityId {
    EntityId::from_bytes([0x71; 16]).expect("an id")
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

/// A `BindActor` of `person` as a person under `bound` at `epoch`.
fn human_bind(bound: AuthorityKey, person: EntityId, epoch: u64) -> AuthorityOp {
    AuthorityOp::BindActor {
        authority_key: bound,
        actor_ref: person,
        actor_class: HUMAN.to_owned(),
        epoch,
    }
}

/// Whether the fold holds an active `human` binding of `person` under `key`.
fn binds_active(fold: &AuthorityFold, key: &AuthorityKey, person: EntityId) -> bool {
    fold.actor_bindings.get(key).is_some_and(|binding| {
        binding.actor_ref == person
            && binding.actor_class == HUMAN
            && binding.status == ActorBindingStatus::Active
    })
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

/// A vault whose root registered one hosted node: genesis plus registration,
/// folded under the Hosted posture.
struct HostedFold {
    root: SigningKey,
    node: SigningKey,
    machine: EntityId,
    rows: Vec<AuthorityLogEntry>,
}

impl HostedFold {
    /// A self-host vault's log: its root is a host-attested key with no cloud
    /// stamp, as `HostSlipIssuer::root_device` mints it under the
    /// SelfHostLocal posture.
    fn self_host_log() -> Self {
        Self::with_root(SELF_HOST_ROOT_ROLES, AuthorityTier::Software)
    }

    /// A managed host's vault: its root is stamped for the cloud, as
    /// `HostSlipIssuer::root_device` mints it under the Hosted posture.
    fn stamped_root_log() -> Self {
        Self::with_root(HOSTED_ROOT_ROLES, AuthorityTier::CloudCustodial)
    }

    fn with_root(roles: u16, tier: AuthorityTier) -> Self {
        let root = signing(ROOT_SEED);
        let node = signing(NODE_SEED);
        let genesis = signed(
            None,
            0,
            Vec::new(),
            AuthorityOp::Genesis {
                device: host_root_device(key_of(&root), roles, tier),
                genesis_nonce: [198; 32],
                recovery: GenesisRecoveryStep::Saved([1; 32]),
            },
            &root,
            &[],
        );
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
        }
    }

    fn vault_id(&self) -> AuthorityVaultId {
        genesis_vault_id(&self.rows[0]).expect("the vault id")
    }

    /// The registration row's hash: the head every test starts from.
    fn registration(&self) -> AuthorityEntryHash {
        hash(&self.rows[1])
    }

    /// The fold of the rows under the Hosted posture.
    fn fold(&self) -> AuthorityFold {
        fold_authority_log_for_posture(
            &self.rows,
            &BTreeMap::new(),
            1,
            &BTreeMap::new(),
            HostingPrivacyPosture::Hosted,
        )
    }

    /// `op` at `seq` on `parent`, signed by `signer` with one cosign by each
    /// of `cosigners`. Returns its hash.
    fn append(
        &mut self,
        seq: u64,
        parent: AuthorityEntryHash,
        op: AuthorityOp,
        signer: &SigningKey,
        cosigners: &[&SigningKey],
    ) -> AuthorityEntryHash {
        let row = signed(
            Some(self.vault_id()),
            seq,
            vec![parent],
            op,
            signer,
            cosigners,
        );
        let entry = hash(&row);
        self.rows.push(row);
        entry
    }

    /// The node carries its own answer `Owned(Yours)` on the registration,
    /// signed by its own install key, with one cosign by each of
    /// `cosigners`.
    fn node_answers_yours(&mut self, cosigners: &[&SigningKey]) -> AuthorityEntryHash {
        let registration = self.registration();
        let act = OwnerAct::by_owner(
            owner(),
            OwnerActKind::MachineAnswer,
            self.machine,
            ActSurface::ThisInstall,
            machine_answer_revision([registration]),
        );
        let op = AuthorityOp::MachineProfile(node_profile(
            self.vault_id(),
            self.machine,
            &self.node,
            MachineRole::Owned(MachineOwnership::Yours),
            2,
            Some((self.machine, act)),
        ));
        let node = self.node.clone();
        self.append(1, registration, op, &node, cosigners)
    }

    /// The node carries the owner's home pick of [`PICKED_NODE`] on the
    /// registration, signed by its own install key, with one cosign by each
    /// of `cosigners`.
    fn node_picks_home(&mut self, cosigners: &[&SigningKey]) -> AuthorityEntryHash {
        let target = home_pick_target(&self.vault_id()).expect("the pick's target");
        // No pick is live yet, so the pick saw the zero revision.
        let act = OwnerAct::by_owner(
            owner(),
            OwnerActKind::HomeNodePick,
            target,
            ActSurface::ThisInstall,
            [0; 32],
        );
        let op = AuthorityOp::HomeNodePick(HomeNodePick {
            act,
            machine: self.machine,
            node_id: Some(PICKED_NODE),
        });
        let registration = self.registration();
        let node = self.node.clone();
        self.append(1, registration, op, &node, cosigners)
    }

    /// The root enrols `new_key` as an owner key of the owner's at `seq` on
    /// `parent`, carried by the node: the fold-only `OwnerKeyEnroll` row the
    /// fold counts. Returns the enrolment's hash.
    fn enrol_owner_key(
        &mut self,
        seq: u64,
        parent: AuthorityEntryHash,
        new_key: &SigningKey,
    ) -> AuthorityEntryHash {
        let vault_id = self.vault_id();
        let public_key = new_key.verifying_key().to_bytes();
        let target =
            owner_key_enrollment_target(&vault_id, &public_key).expect("the enrolment target");
        let challenge =
            owner_key_enrollment_challenge(&vault_id, self.machine, &public_key, owner())
                .expect("the possession challenge");
        let proof = new_key.sign(&challenge).to_bytes().to_vec();
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
        let root = self.root.clone();
        let node = self.node.clone();
        self.append(seq, parent, op, &root, &[&node])
    }
}

/// Main: the hosted fold takes the self-host root as the host's by its
/// host-root attestation, so its cosign is a forged proof: the answer is an
/// invalid entry and the node is not mine.
#[test]
fn a_self_host_roots_cosign_proves_a_carried_answer_when_its_log_is_folded_as_hosted() {
    let mut log = HostedFold::self_host_log();
    let root = log.root.clone();
    let answer = log.node_answers_yours(&[&root]);
    let fold = log.fold();
    let node_key = log.node.verifying_key().to_bytes();
    assert!(
        fold.valid_entries.contains(&answer),
        "the answer the self-host root proved counts under the hosted posture: {:?}",
        fold.issues
    );
    assert!(
        mine(&fold, log.machine, &node_key),
        "the proven answer makes the node the owner's: {:?}",
        fold.issues
    );
    assert_eq!(
        asking(&fold, log.machine),
        BTreeSet::new(),
        "a proven answer asks nothing"
    );
}

/// Main: the root's cosign is a forged proof under the hosted posture, so
/// the pick is an invalid entry and no pick is in force.
#[test]
fn a_self_host_roots_cosign_lands_a_carried_home_pick_when_its_log_is_folded_as_hosted() {
    let mut log = HostedFold::self_host_log();
    let root = log.root.clone();
    let pick = log.node_picks_home(&[&root]);
    let fold = log.fold();
    assert!(
        fold.valid_entries.contains(&pick),
        "the pick the self-host root proved counts: {:?}",
        fold.issues
    );
    assert_eq!(
        home_pick_in_force(&fold),
        Some(PICKED_NODE),
        "the proven pick is in force: {:?}",
        fold.issues
    );
}

/// The self-host root is the owner's key on a hosted fold too, so the vault
/// asks for its proof, as it does on the owner's own fold. Main: the hosted
/// fold holds no key that proves for the owner, so the not-mine node's pick
/// lands unproven.
#[test]
fn an_unproven_home_pick_waits_for_the_self_host_root_when_its_log_is_folded_as_hosted() {
    let mut log = HostedFold::self_host_log();
    log.node_picks_home(&[]);
    let fold = log.fold();
    assert_eq!(
        home_pick_in_force(&fold),
        None,
        "a not-mine node's pick with no owner key's proof waits: {:?}",
        fold.issues
    );
    assert_eq!(
        fold.waiting_owner_choices().len(),
        1,
        "the pick is stored and asks the owner: {:?}",
        fold.issues
    );
}

/// Main: the root proves nothing under the hosted posture, so its revoke of
/// an owner key carries no owner proof and does not count (row
/// HOSTED-ROOT-REVOKES-OWNER-KEY): a self-host membership move's revoke
/// drops, with every row after it.
#[test]
fn a_self_host_roots_revoke_ends_an_owner_key_when_its_log_is_folded_as_hosted() {
    let mut log = HostedFold::self_host_log();
    let registration = log.registration();
    let owner_key = signing(OWNER_KEY_SEED);
    let enrolment = log.enrol_owner_key(2, registration, &owner_key);
    let root = log.root.clone();
    let revoke = log.append(
        3,
        enrolment,
        AuthorityOp::RevokeDevice {
            revoked_key: key_of(&owner_key),
        },
        &root,
        &[],
    );
    let fold = log.fold();
    assert!(
        fold.valid_entries.contains(&enrolment),
        "the enrolment counts: {:?}",
        fold.issues
    );
    assert!(
        fold.valid_entries.contains(&revoke),
        "the self-host root's revoke counts under the hosted posture: {:?}",
        fold.issues
    );
    assert!(
        !roster_has_live_owner(&fold.roster, &key_of(&owner_key)),
        "the revoked owner key no longer proves: {:?}",
        fold.roster
    );
}

/// Passes on main too: the operator's stamped root proves nothing for the
/// owner. Its cosign is a forged proof, and its revoke of an owner key alone
/// does not count.
#[test]
fn a_stamped_root_proves_nothing_on_a_hosted_fold() {
    let mut log = HostedFold::stamped_root_log();
    let root = log.root.clone();
    let answer = log.node_answers_yours(&[&root]);
    let registration = log.registration();
    let owner_key = signing(OWNER_KEY_SEED);
    let enrolment = log.enrol_owner_key(2, registration, &owner_key);
    let revoke = log.append(
        3,
        enrolment,
        AuthorityOp::RevokeDevice {
            revoked_key: key_of(&owner_key),
        },
        &root,
        &[],
    );
    let fold = log.fold();
    let node_key = log.node.verifying_key().to_bytes();
    assert!(
        !fold.valid_entries.contains(&answer),
        "an answer cosigned by the stamped root is a forged proof: {:?}",
        fold.issues
    );
    assert!(
        !mine(&fold, log.machine, &node_key),
        "the stamped root makes no machine the owner's"
    );
    assert!(
        fold.valid_entries.contains(&enrolment),
        "the enrolment counts: {:?}",
        fold.issues
    );
    assert!(
        !fold.valid_entries.contains(&revoke),
        "the stamped root alone ends no owner key: {:?}",
        fold.issues
    );
    assert!(
        roster_has_live_owner(&fold.roster, &key_of(&owner_key)),
        "the owner key stays live: {:?}",
        fold.roster
    );
}

/// Passes on main too: a root move under the Hosted posture hands the
/// self-host vault to a stamped root, which then acts as nobody: it and the
/// key it enrols are in the host's custody, and neither binds a person
/// alone. The self-host root's own bind before the move still counts. After
/// the handoff the fold keeps only an agent-only `EnrollDevice` (an owner or
/// admin one is a retired device op), so the key it enrols is an agent's;
/// the stamped root's rejected bind is no parent of it, since a rejected
/// row's children wait for good.
#[test]
fn a_stamped_re_root_of_a_self_host_log_takes_the_new_root_into_host_custody() {
    let mut log = HostedFold::self_host_log();
    let registration = log.registration();
    let root = log.root.clone();
    let root_bind = log.append(
        2,
        registration,
        human_bind(key_of(&root), owner(), 1),
        &root,
        &[],
    );
    let stamped = signing(STAMPED_ROOT_SEED);
    let re_root = log.append(
        3,
        root_bind,
        AuthorityOp::ReRoot {
            new_device: host_root_device(
                key_of(&stamped),
                HOSTED_ROOT_ROLES,
                AuthorityTier::CloudCustodial,
            ),
        },
        &root,
        &[],
    );
    let admitted = signing(ADMITTED_SEED);
    let enrolment = log.append(
        1,
        re_root,
        AuthorityOp::EnrollDevice {
            device: DeviceAuthority {
                key: key_of(&admitted),
                transport_key_binding: [9; 32],
                attestation: AuthorityAttestation {
                    kind: "SoftwareArgon2id".to_owned(),
                    evidence: vec![1, 2, 3],
                },
                tier: AuthorityTier::Software,
                roles: ROLE_AGENT,
            },
        },
        &stamped,
        &[],
    );
    let stamped_bind = log.append(
        2,
        enrolment,
        human_bind(key_of(&stamped), owner(), 2),
        &stamped,
        &[],
    );
    let admitted_bind = log.append(
        1,
        enrolment,
        human_bind(key_of(&admitted), owner(), 3),
        &admitted,
        &[],
    );
    let fold = log.fold();
    assert!(
        fold.valid_entries.contains(&root_bind),
        "the self-host root's bind counts: {:?}",
        fold.issues
    );
    assert!(
        fold.valid_entries.contains(&re_root),
        "the root move counts: {:?}",
        fold.issues
    );
    assert!(
        fold.valid_entries.contains(&enrolment),
        "the stamped root enrols an agent key: {:?}",
        fold.issues
    );
    assert!(
        root_appointment::in_host_custody(&fold, &key_of(&stamped)),
        "the stamped root is in the host's custody"
    );
    assert!(
        root_appointment::in_host_custody(&fold, &key_of(&admitted)),
        "a key the stamped root admitted is in the host's custody"
    );
    assert!(
        !fold.valid_entries.contains(&stamped_bind)
            && !binds_active(&fold, &key_of(&stamped), owner()),
        "the stamped root alone binds no person: {:?}",
        fold.actor_bindings
    );
    assert!(
        !fold.valid_entries.contains(&admitted_bind)
            && !binds_active(&fold, &key_of(&admitted), owner()),
        "a key the stamped root admitted binds no person alone: {:?}",
        fold.actor_bindings
    );
}

/// A vault opened as a server opens one, under `posture`, with a device
/// keystore.
fn open_served(path: &std::path::Path, posture: HostingPrivacyPosture) -> Vault {
    open_served_on(
        path,
        posture,
        &Arc::new(oneiron_keystore::MemoryKeystore::default()),
    )
}

/// A vault opened as a server opens one, under `posture`, on `keystore`: the
/// install's device keystore, which outlives the vault handle as a host's
/// platform keystore does, so a reopen on it keeps this install's machine and
/// its keys.
fn open_served_on(
    path: &std::path::Path,
    posture: HostingPrivacyPosture,
    keystore: &Arc<oneiron_keystore::MemoryKeystore>,
) -> Vault {
    let mut config = VaultConfig::device();
    config.privacy.posture = posture;
    let vault = Vault::open(path, config).expect("the vault opens");
    vault.install_device_keystore(keystore.clone());
    vault
}

/// A vault rooted under the test host by a server that serves it under
/// `posture`, with this install profiled: the root is the test host's
/// issuer.
fn rooted_served(posture: HostingPrivacyPosture) -> (tempfile::TempDir, Vault, HostSlipIssuer) {
    rooted_served_on(
        posture,
        &Arc::new(oneiron_keystore::MemoryKeystore::default()),
    )
}

/// [`rooted_served`] on `keystore` ([`open_served_on`]).
fn rooted_served_on(
    posture: HostingPrivacyPosture,
    keystore: &Arc<oneiron_keystore::MemoryKeystore>,
) -> (tempfile::TempDir, Vault, HostSlipIssuer) {
    let dir = tempfile::tempdir().expect("vault directory");
    let vault = open_served_on(dir.path(), posture, keystore);
    let issuer = oneiron::test_support::provision_engine_machines(&vault);
    vault
        .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
        .expect("this install's machine profile under the host root");
    (dir, vault, issuer)
}

/// Whether `vault`'s fold holds `key` in the host's custody.
fn in_host_custody(vault: &Vault, key: &AuthorityKey) -> bool {
    vault
        .authority_key_in_host_custody(key)
        .expect("the custody read")
}

/// Whether `vault`'s roster row of `key` carries the cloud stamp, role and
/// tier both.
fn stamped_for_the_cloud(vault: &Vault, key: &AuthorityKey) -> bool {
    vault
        .authority_fold()
        .expect("the authority fold")
        .roster
        .get(key)
        .is_some_and(|row| row.roles & ROLE_CLOUD != 0 && row.tier == AuthorityTier::CloudCustodial)
}

/// Whether this install, holding `issuer`'s root as its root signer, can
/// confirm the owner's held answers: whether it offers a key as the owner's
/// proof.
fn offers_owner_proof(vault: &Vault, issuer: HostSlipIssuer) -> bool {
    vault.hold_checkpoint_root_signer(Arc::new(issuer));
    let (_, owner) = embedded_owner(vault).expect("authenticated embedded owner");
    vault
        .held_machine_answers(&owner)
        .expect("the held answer list")
        .can_confirm
}

/// Main: the fold marks every host-attested root as the host's, under any
/// posture, so the self-host root is in the host's custody even on the
/// owner's own fold.
#[test]
fn a_self_host_root_is_in_no_host_custody_before_or_after_a_hosted_reopen() {
    let (dir, vault, issuer) = rooted_served(HostingPrivacyPosture::SelfHostLocal);
    let root = issuer.public_key();
    assert!(
        !stamped_for_the_cloud(&vault, &root),
        "a self-host root carries no cloud stamp"
    );
    assert!(
        !in_host_custody(&vault, &root),
        "the self-host root is the owner's key, not the host's"
    );
    drop(vault);
    let hosted = open_served(dir.path(), HostingPrivacyPosture::Hosted);
    assert!(
        !in_host_custody(&hosted, &root),
        "reopened under the Hosted posture, the self-host root is still not the host's"
    );
}

/// Passes on main too (the fold there takes the root as the host's): an
/// install under the Hosted posture never offers a host root it holds as the
/// owner's proof, even one the fold still trusts as the owner's.
#[test]
fn a_hosted_install_never_offers_a_self_host_root_it_holds_as_the_owners_proof() {
    let (dir, vault, issuer) = rooted_served(HostingPrivacyPosture::SelfHostLocal);
    assert!(
        offers_owner_proof(&vault, issuer),
        "guard: the self-host server proves the owner's acts with its own root"
    );
    drop(vault);
    let hosted = open_served(dir.path(), HostingPrivacyPosture::Hosted);
    assert!(
        !offers_owner_proof(&hosted, oneiron::test_support::test_host_issuer()),
        "under the Hosted posture the install holds the root but offers no proof with it"
    );
}

/// Row HOSTED-GENESIS-CLOUD-STAMP-UNCHECKED, a pin (passes on main too):
/// every Hosted root carries the cloud stamp the fold's custody rests on,
/// the genesis root and the root a move under the Hosted posture hands the
/// vault to.
#[test]
fn a_hosted_genesis_and_a_hosted_re_root_are_stamped_for_the_cloud() {
    let (_dir, vault, issuer) = rooted_served(HostingPrivacyPosture::Hosted);
    let root = issuer.public_key();
    assert!(
        stamped_for_the_cloud(&vault, &root),
        "the Hosted genesis root carries the cloud stamp"
    );
    assert!(
        in_host_custody(&vault, &root),
        "the Hosted root is the host's"
    );
    let next = HostSlipIssuer::from_seed(&[NEXT_ISSUER_SEED; HOST_ISSUER_SEED_BYTES])
        .expect("the next host issuer");
    let next_root = next.public_key();
    vault
        .re_root_host(&issuer, &next)
        .expect("the host root moves");
    assert!(
        stamped_for_the_cloud(&vault, &next_root),
        "the root a move under the Hosted posture hands the vault to carries the cloud stamp"
    );
    assert!(
        in_host_custody(&vault, &next_root),
        "the new Hosted root is the host's"
    );
}

/// Passes on main too: a root move under the Hosted posture, the step that
/// closes a move of a self-host vault to a managed host, hands the reopened
/// vault to a stamped root, which is the host's and proves nothing.
#[test]
fn a_hosted_re_root_of_a_reopened_self_host_vault_stamps_the_new_root() {
    let (dir, vault, _) = rooted_served(HostingPrivacyPosture::SelfHostLocal);
    drop(vault);
    let hosted = open_served(dir.path(), HostingPrivacyPosture::Hosted);
    let next = HostSlipIssuer::from_seed(&[NEXT_ISSUER_SEED; HOST_ISSUER_SEED_BYTES])
        .expect("the next host issuer");
    let next_root = next.public_key();
    hosted
        .re_root_host(&oneiron::test_support::test_host_issuer(), &next)
        .expect("the host root moves");
    assert!(
        stamped_for_the_cloud(&hosted, &next_root),
        "the new root carries the cloud stamp"
    );
    assert!(
        in_host_custody(&hosted, &next_root),
        "the new root is the host's"
    );
    assert!(
        !offers_owner_proof(&hosted, next),
        "the stamped root proves nothing for the owner"
    );
}

/// A machine pairing link the owner makes on `vault`, answering "yours".
fn yours_link(vault: &Vault, issuer: &HostSlipIssuer) -> PairingLink {
    let (_, owner) = embedded_owner(vault).expect("authenticated embedded owner");
    vault
        .issue_machine_pairing_link(
            issuer,
            &owner,
            ActSurface::ThisInstall,
            Scope::top(),
            3600,
            PairingPrincipal::default(),
            MachineOwnership::Yours,
        )
        .expect("the owner makes a machine pairing link")
}

/// A fresh machine's own install and its enrolment request for `vault`'s
/// vault.
fn joining_install(vault: &Vault) -> (tempfile::TempDir, Vault, MachineEnrolmentRequest) {
    let vault_id = vault
        .authority_vault_id()
        .expect("the vault's fold")
        .expect("a rooted vault");
    let dir = tempfile::tempdir().expect("vault directory");
    let install = open_served(dir.path(), HostingPrivacyPosture::SelfHostLocal);
    let key = install
        .machine_encryption_key(vault_id)
        .expect("the joining machine's encryption key");
    let request = install
        .machine_enrolment_request(vault_id, key)
        .expect("the joining machine's enrolment request");
    (dir, install, request)
}

/// `vault` redeems `link` for `request`, under a throwaway pairing
/// connection key.
fn redeem_yours(
    vault: &Vault,
    issuer: &HostSlipIssuer,
    link: &PairingLink,
    request: &MachineEnrolmentRequest,
) -> oneiron::Result<MachineAnswerLanding> {
    let connection = signing(PAIRING_SEED);
    let binding_key = connection.verifying_key().to_bytes();
    let holder = request.machine.to_hex();
    let transcript =
        pairing_binding_transcript_pinned(&link.code, &binding_key, &holder, link.pin.as_ref())
            .expect("the binding transcript");
    let binding = connection.sign(&transcript).to_bytes();
    vault
        .redeem_machine_pairing_link(issuer, &link.code, &holder, binding_key, &binding, request)
        .map(|(_, landing)| landing)
}

/// Whether `vault`'s fold holds `machine` as the owner's.
fn machine_is_mine(vault: &Vault, machine: EntityId) -> bool {
    vault
        .authority_fold()
        .expect("the authority fold")
        .machine(machine)
        .is_some_and(|folded| folded.is_mine(None))
}

/// The review of #9474, round 1, P1 on the pairing bootstrap arm (red at
/// e5e73e1874, where the arm signs the answer under the self-host root and
/// the machine stands): reopened under the Hosted posture, an install whose
/// own profile is still unanswered pairs a machine the owner answered
/// "yours" through its carrier. It holds no key it may offer as his proof,
/// so the answer lands held and the machine is not his yet. The install
/// keeps its keystore across the reopen and loads its signing keys from it,
/// as a host does after each open (`Vault::install_default_keystore`):
/// without them it carries nothing, and the redemption refuses before it
/// reaches the carrier (row HOSTED-REOPEN-TEST-DROPS-INSTALL-KEYSTORE).
#[test]
fn a_hosted_install_pairs_a_yours_machine_through_its_carrier_not_the_self_host_root() {
    let keystore = Arc::new(oneiron_keystore::MemoryKeystore::default());
    let (dir, vault, _) = rooted_served_on(HostingPrivacyPosture::SelfHostLocal, &keystore);
    drop(vault);
    let hosted = open_served_on(dir.path(), HostingPrivacyPosture::Hosted, &keystore);
    hosted
        .prepare_install_signing()
        .expect("this install's signing keys load from the keystore it kept");
    let issuer = oneiron::test_support::test_host_issuer();
    let link = yours_link(&hosted, &issuer);
    let (_joining_dir, _joining, request) = joining_install(&hosted);
    let landing = redeem_yours(&hosted, &issuer, &link, &request)
        .expect("the redemption is stored, the answer carried");
    assert!(
        landing.held().is_some(),
        "the owner's answer waits for an owner key's proof: {landing:?}"
    );
    assert!(
        !machine_is_mine(&hosted, request.machine),
        "the self-host root's signature makes no machine the owner's on a hosted install"
    );
}

/// The joining machine's own install of `vault`'s vault, which the owner
/// answered "yours" on `vault` (carried by its serving install, proved by
/// the root it holds), with the vault's authority history taken.
fn yours_device(vault: &Vault, owner: &AuthenticatedOwner) -> (tempfile::TempDir, Vault) {
    let (dir, device, request) = joining_install(vault);
    let landing = vault
        .enroll_machine(
            owner,
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
    device
        .ensure_embedded_owner_actor()
        .expect("the owner on the new device");
    device
        .import_signed_authority_history(
            &vault
                .export_signed_authority_history()
                .expect("the vault's history"),
        )
        .expect("the new device takes the history");
    (dir, device)
}

/// The vouch request `device` makes for its own new owner key.
fn vouch_request(device: &Vault) -> OwnerKeyVouchRequest {
    let person = device
        .ensure_embedded_owner_actor()
        .expect("the owner on the new device");
    let proof = device
        .authenticate_owner(person, &person.to_hex(), true, GateDecisionId::now())
        .expect("an owner proof on the new device");
    match device
        .device_owner_key_vouch_request(
            &ActAuthority::Owner(proof, ActSurface::ThisInstall),
            "Laptop",
        )
        .expect("the new device makes its key's request")
    {
        DeviceOwnerKeyVouch::Request(request) => request,
        DeviceOwnerKeyVouch::Enrolled(receipt) => {
            panic!("the new device's key is not enrolled yet: {receipt:?}")
        }
    }
}

/// The review of #9474, round 1, P1 on the vouch writer (red at
/// e5e73e1874, where the vouch lands under the self-host root): reopened
/// under the Hosted posture and holding the self-host root as its only root
/// signer, the install vouches no key into the owner. The fold still trusts
/// that root as the owner's, but a hosted install never offers a host root
/// as his proof, so the vouch asks for an owner key and writes nothing. The
/// install keeps its keystore across the reopen and loads its signing keys
/// from it, so it carries the owner's acts and the refusal comes from the
/// writer rule, not from a missing carrier (row
/// HOSTED-VOUCH-TEST-DROPS-INSTALL-KEYSTORE).
#[test]
fn a_hosted_install_vouches_for_no_key_with_the_self_host_root_it_holds() {
    let keystore = Arc::new(oneiron_keystore::MemoryKeystore::default());
    let (dir, vault, issuer) = rooted_served_on(HostingPrivacyPosture::SelfHostLocal, &keystore);
    vault.hold_checkpoint_root_signer(Arc::new(issuer));
    let (_, owner) = embedded_owner(&vault).expect("authenticated embedded owner");
    let (_device_dir, device) = yours_device(&vault, &owner);
    let request = vouch_request(&device);
    drop(vault);
    let hosted = open_served_on(dir.path(), HostingPrivacyPosture::Hosted, &keystore);
    let machine = hosted
        .prepare_install_signing()
        .expect("this install's signing keys load from the keystore it kept");
    assert!(
        hosted
            .authority_fold()
            .expect("the authority fold")
            .machine(machine)
            .and_then(|folded| folded.roster.as_ref())
            .is_some_and(|revision| revision.is_live()),
        "guard: reopened under the Hosted posture, this install has a live profile to carry the owner's acts"
    );
    hosted.hold_checkpoint_root_signer(Arc::new(oneiron::test_support::test_host_issuer()));
    let (_, owner) = embedded_owner(&hosted).expect("authenticated embedded owner");
    let rows = hosted
        .export_signed_authority_history()
        .expect("the hosted install's history")
        .len();
    let refused = hosted
        .enrol_vouched_owner_signing_key(
            &ActAuthority::Owner(owner, ActSurface::ThisInstall),
            &request,
        )
        .expect_err("the self-host root vouches for nothing on a hosted install");
    assert!(
        matches!(refused, Error::Record(RecordError::OwnerKeyRequired)),
        "the refusal asks for an owner key: {refused:?}"
    );
    assert!(
        !hosted
            .authority_fold()
            .expect("the authority fold")
            .roster
            .contains_key(&AuthorityKey::Ed25519(request.public_key)),
        "the key is not enrolled"
    );
    assert_eq!(
        hosted
            .export_signed_authority_history()
            .expect("the hosted install's history")
            .len(),
        rows,
        "nothing was written"
    );
}

/// The review of #9474, round 1, P1 on the re-root carry (red at
/// e5e73e1874, where the move signs the answer again under the stamped
/// root, the fold refuses that revision and the whole move rolls back): a
/// machine the self-host root answered "yours" on the bootstrap arm stays
/// the owner's when the vault is reopened under the Hosted posture, and a
/// root move there lands. The stamped successor answers for nobody, so it
/// signs no revision that says the machine is the owner's.
#[test]
fn a_hosted_re_root_lands_over_a_machine_the_self_host_root_answered_yours() {
    let (dir, vault, issuer) = rooted_served(HostingPrivacyPosture::SelfHostLocal);
    let link = yours_link(&vault, &issuer);
    let (_joining_dir, _joining, request) = joining_install(&vault);
    let landing = redeem_yours(&vault, &issuer, &link, &request)
        .expect("the self-host install pairs the machine");
    assert!(
        landing.held().is_none(),
        "guard: the self-host root's answer stands: {landing:?}"
    );
    drop(vault);
    let hosted = open_served(dir.path(), HostingPrivacyPosture::Hosted);
    assert!(
        machine_is_mine(&hosted, request.machine),
        "guard: reopened under the Hosted posture, the machine is still the owner's"
    );
    let next = HostSlipIssuer::from_seed(&[NEXT_ISSUER_SEED; HOST_ISSUER_SEED_BYTES])
        .expect("the next host issuer");
    let next_root = next.public_key();
    hosted
        .re_root_host(&oneiron::test_support::test_host_issuer(), &next)
        .expect("the host root moves");
    assert!(
        stamped_for_the_cloud(&hosted, &next_root),
        "the new root carries the cloud stamp"
    );
    assert!(
        hosted
            .authority_fold()
            .expect("the authority fold")
            .machine(request.machine)
            .and_then(|folded| folded.roster.as_ref())
            .is_none_or(|revision| revision.signer != next_root),
        "the stamped root signs no revision that says the machine is the owner's"
    );
}
