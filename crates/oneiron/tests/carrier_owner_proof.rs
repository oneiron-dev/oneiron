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
//! Pure folds over hand-signed rows: a self-host genesis root key, the root's
//! registration of a hosted node, and the node's own answer.

#![cfg(oneiron_test_support)]

use std::collections::BTreeSet;

use ed25519_dalek::{Signer, SigningKey};
use oneiron::EntityId;
use oneiron::authority::{
    AUTHORITY_LOG_SCHEMA_VERSION, ActSurface, AuthorityAttestation, AuthorityEntryHash,
    AuthorityFold, AuthorityKey, AuthorityLogEntry, AuthorityOp, AuthoritySignature, AuthorityTier,
    AuthorityVaultId, DeviceAuthority, GenesisRecoveryStep, MACHINE_ENCRYPTION_KEY_LEN,
    MACHINE_ENCRYPTION_SUITE_HYBRID_V1, MachineDeviceClass, MachineEncryptionKey, MachineOwnership,
    MachineProfile, MachineRole, OwnerAct, OwnerActKind, ROLE_ADMIN, ROLE_OWNER,
    authority_entry_hash, authority_transcript, fold_authority_log, genesis_vault_id,
    machine_profile_proof_transcript,
};
use oneiron_authority::authority::machine_answer_revision;

const ROOT_SEED: u8 = 61;
const NODE_SEED: u8 = 62;

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

/// A self-host vault whose root registered one hosted node, and that node's
/// own answer `Owned(Yours)` about itself, cosigned by each of `cosigners`.
struct HostedNodeAnswer {
    root: SigningKey,
    node: SigningKey,
    machine: EntityId,
    rows: Vec<AuthorityLogEntry>,
}

impl HostedNodeAnswer {
    fn new() -> Self {
        let root = signing(ROOT_SEED);
        let node = signing(NODE_SEED);
        let genesis = signed(
            None,
            0,
            Vec::new(),
            AuthorityOp::Genesis {
                device: DeviceAuthority {
                    key: key_of(&root),
                    transport_key_binding: [7; 32],
                    attestation: AuthorityAttestation {
                        kind: "SoftwareArgon2id".to_owned(),
                        evidence: vec![1, 2, 3],
                    },
                    tier: AuthorityTier::Software,
                    roles: ROLE_OWNER | ROLE_ADMIN,
                },
                genesis_nonce: [196; 32],
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
        (fold_authority_log(&self.rows), self.machine, node_key)
    }
}

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
