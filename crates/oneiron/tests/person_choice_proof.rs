//! A person proves their own opt back in with their own slip key (row
//! PERSON-TRAINING-CHOICE-PERSON-KEY-PROOF; ruling CARRIER-PERSON-OPT-BACK-IN
//! = A).
//!
//! A person who is not the vault owner signs the fixed choice statement with
//! the binding key K of one of their own live human slips; K's secret lives
//! only on their device. The proof rides in the op, and every replica judges
//! it from the entry's parent state alone. A proved opt back in lands
//! through a carrier that is not the owner's machine; a forged one is an
//! invalid entry, never a waiting one.
//!
//! Fold tests are pure folds over hand-signed rows (fixtures copied from
//! `carrier_owner_proof.rs`, with a hand-minted slip row signed by the
//! roster owner root). Door tests run a real vault as a managed host serves
//! it, the owner key held on another install.

#![cfg(oneiron_test_support)]

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use ed25519_dalek::{Signer, SigningKey};
use oneiron::authority::{
    AUTHORITY_LOG_SCHEMA_VERSION, ActAuthority, ActSurface, AuthorityAttestation,
    AuthorityEntryHash, AuthorityFold, AuthorityFoldIssue, AuthorityKey, AuthorityLogEntry,
    AuthorityOp, AuthoritySignature, AuthorityTier, AuthorityVaultId, DeviceAuthority,
    GenesisRecoveryStep, HostSlipIssuer, MACHINE_ENCRYPTION_KEY_LEN,
    MACHINE_ENCRYPTION_SUITE_HYBRID_V1, MachineDeviceClass, MachineEncryptionKey, MachineOwnership,
    MachineProfile, MachineRole, OwnerAct, OwnerActKind, ROLE_ADMIN, ROLE_CLOUD, ROLE_OWNER,
    SlipClaims, SlipMintAction, authority_entry_hash, authority_transcript, fold_authority_log,
    fold_authority_log_for_posture, genesis_vault_id, machine_profile_proof_transcript,
};
use oneiron::consent::AuthenticatedOwner;
use oneiron::error::RecordError;
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::store::GateDecisionId;
use oneiron::test_doors::conversation_training_fold::{leaves_out, training_revision};
use oneiron::test_doors::label_writers::embedded_owner;
use oneiron::test_doors::owner_key_release::release_owner_keys;
use oneiron::{EntityId, Error, HostingPrivacyPosture, TimeRange, Vault, VaultConfig};
use oneiron_authority::authority::{
    ConversationTrainingSet, PersonChoiceProof, conversation_training_statement,
};
use oneiron_authority::federation::{Scope, ScopeAxis};

const ROOT_SEED: u8 = 61;
const NODE_SEED: u8 = 62;
/// The binding key of the member's own slip.
const MEMBER_SLIP_SEED: u8 = 69;
/// A key that holds no slip here: the forger's.
const FORGER_SEED: u8 = 70;
/// The binding key of another person's slip.
const OTHER_SLIP_SEED: u8 = 71;

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
/// `cosigners`, at the advisory time 1 ([`signed_at`]).
fn signed(
    vault_id: Option<AuthorityVaultId>,
    seq: u64,
    parent_hashes: Vec<AuthorityEntryHash>,
    op: AuthorityOp,
    signer: &SigningKey,
    cosigners: &[&SigningKey],
) -> AuthorityLogEntry {
    signed_at(vault_id, seq, parent_hashes, op, signer, cosigners, 1)
}

/// `signer` signs `op` on `parent_hashes` at the advisory time `ts`, with
/// one cosign by each of `cosigners`. Every key is in the entry before any
/// of them signs, so all of them sign the same transcript.
fn signed_at(
    vault_id: Option<AuthorityVaultId>,
    seq: u64,
    parent_hashes: Vec<AuthorityEntryHash>,
    op: AuthorityOp,
    signer: &SigningKey,
    cosigners: &[&SigningKey],
    ts: u64,
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
        ts,
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

/// A vault whose root registered one hosted node.
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
}

fn owner() -> EntityId {
    EntityId::from_bytes([0x71; 16]).expect("an id")
}

/// A person of the vault who is not its owner.
fn member() -> EntityId {
    EntityId::from_bytes([0x75; 16]).expect("an id")
}

/// Another person of the vault, neither the owner nor the member.
fn another() -> EntityId {
    EntityId::from_bytes([0x77; 16]).expect("an id")
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

/// The member's own conversation-training choice `leave_out`, carried by
/// `machine`, having seen the revision `seen` of their live choices, with
/// the person proof `proof` when they signed one.
fn members_own_choice(
    machine: EntityId,
    leave_out: bool,
    seen: [u8; 32],
    proof: Option<PersonChoiceProof>,
) -> AuthorityOp {
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
        person_proof: proof,
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
        members_own_choice(answer.machine, true, [0; 32], None),
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

/// The hosted node carries the member's opt back in on the newest row, with
/// `proof`, signed by its own install key at the advisory time 1. Returns the
/// entry.
fn carry_opt_back_in(
    answer: &mut HostedNodeAnswer,
    seen: [u8; 32],
    proof: Option<PersonChoiceProof>,
) -> AuthorityEntryHash {
    carry_opt_back_in_at(answer, seen, proof, 1)
}

/// [`carry_opt_back_in`] at the advisory time `ts`, the act's time.
fn carry_opt_back_in_at(
    answer: &mut HostedNodeAnswer,
    seen: [u8; 32],
    proof: Option<PersonChoiceProof>,
    ts: u64,
) -> AuthorityEntryHash {
    let newest = hash(answer.rows.last().expect("a row"));
    let (machine, node) = (answer.machine, answer.node.clone());
    let back_in = signed_at(
        Some(answer.vault_id()),
        2,
        vec![newest],
        members_own_choice(machine, false, seen, proof),
        &node,
        &[],
        ts,
    );
    let entry = hash(&back_in);
    answer.rows.push(back_in);
    entry
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

/// The opt back in is forged: the entry is invalid, nothing waits from it,
/// and the member stays left out.
fn assert_stays_out(fold: &AuthorityFold, entry: AuthorityEntryHash) {
    assert!(
        fold.issues
            .contains(&AuthorityFoldIssue::InvalidEntry(entry)),
        "the forged opt back in is an invalid entry: {:?}",
        fold.issues
    );
    assert_eq!(
        fold.waiting_owner_choices(),
        &BTreeSet::new(),
        "a forged entry waits for nothing"
    );
    assert!(leaves_out(fold, member()), "the member stays left out");
}

/// The claims of `holder`'s own live human slip `slip`, bound to
/// `binding_key`: parentless, with none of the bounds a delegated or
/// special-purpose slip carries.
fn member_slip_claims(
    vault_id: AuthorityVaultId,
    holder: EntityId,
    binding_key: [u8; 32],
    slip: [u8; 32],
) -> SlipClaims {
    SlipClaims {
        slip_id: slip,
        vault_id,
        parent_id: None,
        holder_ref: holder.to_hex(),
        binding_key,
        scope: Scope::top(),
        issued_at: 1,
        expires_at: 1 + 3600,
        ttl_secs: 3600,
        single_use: false,
        records: BTreeSet::new(),
        channels: BTreeSet::new(),
        actor_class: Some("human".to_owned()),
        org_ref: None,
        grant_ref: None,
        invitation_ref: None,
        share_ref: None,
        delegation: None,
        comm: None,
        trusted_contact: None,
        seat_claim: None,
    }
}

/// The roster owner root mints `claims` on the newest row at `seq`. Returns
/// the mint's entry.
fn mint_slip(answer: &mut HostedNodeAnswer, claims: SlipClaims, seq: u64) -> AuthorityEntryHash {
    let newest = hash(answer.rows.last().expect("a row"));
    let root = answer.root.clone();
    let mint = signed(
        Some(answer.vault_id()),
        seq,
        vec![newest],
        AuthorityOp::SlipMint(SlipMintAction {
            claims,
            renews: None,
            minting_member: None,
        }),
        &root,
        &[],
    );
    let entry = hash(&mint);
    answer.rows.push(mint);
    entry
}

/// The roster owner root revokes `slip` on the newest row at `seq`.
fn revoke_slip(answer: &mut HostedNodeAnswer, slip: [u8; 32], seq: u64) {
    let newest = hash(answer.rows.last().expect("a row"));
    let root = answer.root.clone();
    let revoke = signed(
        Some(answer.vault_id()),
        seq,
        vec![newest],
        AuthorityOp::SlipRevoke { slip_id: slip },
        &root,
        &[],
    );
    answer.rows.push(revoke);
}

/// `key`'s person proof of `person`'s choice over `slip`.
fn person_proof(
    vault_id: &AuthorityVaultId,
    person: EntityId,
    leave_out: bool,
    seen: [u8; 32],
    slip: [u8; 32],
    key: &SigningKey,
) -> PersonChoiceProof {
    let statement = conversation_training_statement(vault_id, person, leave_out, seen, slip)
        .expect("a statement");
    PersonChoiceProof {
        slip,
        signature: key.sign(&statement).to_bytes(),
    }
}

/// THE red test (ruling CARRIER-PERSON-OPT-BACK-IN = A, row
/// PERSON-TRAINING-CHOICE-PERSON-KEY-PROOF): the member's opt back in,
/// carried by a machine that is not the owner's, lands when the member
/// proved it with their own slip key. It waits on the base.
#[test]
fn a_members_opt_back_in_with_their_own_slip_key_lands_through_a_not_mine_carrier() {
    let mut answer = HostedNodeAnswer::new();
    let vault_id = answer.vault_id();
    let slip_key = signing(MEMBER_SLIP_SEED);
    let slip = [0x51; 32];
    mint_slip(
        &mut answer,
        member_slip_claims(
            vault_id,
            member(),
            slip_key.verifying_key().to_bytes(),
            slip,
        ),
        2,
    );
    let seen = node_carries_the_members_opt_out(&mut answer);
    let proof = person_proof(&vault_id, member(), false, seen, slip, &slip_key);
    carry_opt_back_in(&mut answer, seen, Some(proof));
    assert_let_back_in(&answer.fold());
}

/// Ruling CARRIER-PERSON-OPT-BACK-IN = A, row
/// PERSON-TRAINING-CHOICE-PERSON-KEY-PROOF: a signature by another key proves
/// nothing, so the opt back in is an invalid entry, nothing waits from it,
/// and the member stays left out.
#[test]
fn a_forged_person_proof_makes_the_opt_back_in_invalid() {
    let mut answer = HostedNodeAnswer::new();
    let vault_id = answer.vault_id();
    let slip_key = signing(MEMBER_SLIP_SEED);
    let slip = [0x51; 32];
    mint_slip(
        &mut answer,
        member_slip_claims(
            vault_id,
            member(),
            slip_key.verifying_key().to_bytes(),
            slip,
        ),
        2,
    );
    let seen = node_carries_the_members_opt_out(&mut answer);
    let proof = person_proof(
        &vault_id,
        member(),
        false,
        seen,
        slip,
        &signing(FORGER_SEED),
    );
    let entry = carry_opt_back_in(&mut answer, seen, Some(proof));
    assert_stays_out(&answer.fold(), entry);
}

/// Ruling CARRIER-PERSON-OPT-BACK-IN = A, row
/// PERSON-TRAINING-CHOICE-PERSON-KEY-PROOF: a proof on another person's slip
/// is no proof of the member's choice, so the opt back in is invalid.
#[test]
fn a_person_proof_on_another_persons_slip_is_invalid() {
    let mut answer = HostedNodeAnswer::new();
    let vault_id = answer.vault_id();
    let other_key = signing(OTHER_SLIP_SEED);
    let slip = [0x52; 32];
    mint_slip(
        &mut answer,
        member_slip_claims(
            vault_id,
            another(),
            other_key.verifying_key().to_bytes(),
            slip,
        ),
        2,
    );
    let seen = node_carries_the_members_opt_out(&mut answer);
    let proof = person_proof(&vault_id, member(), false, seen, slip, &other_key);
    let entry = carry_opt_back_in(&mut answer, seen, Some(proof));
    assert_stays_out(&answer.fold(), entry);
}

/// Ruling CARRIER-PERSON-OPT-BACK-IN = A, row
/// PERSON-TRAINING-CHOICE-PERSON-KEY-PROOF: a proof on a revoked slip is no
/// proof, so the opt back in over the revoke is invalid.
#[test]
fn a_person_proof_on_a_revoked_slip_is_invalid() {
    let mut answer = HostedNodeAnswer::new();
    let vault_id = answer.vault_id();
    let slip_key = signing(MEMBER_SLIP_SEED);
    let slip = [0x51; 32];
    mint_slip(
        &mut answer,
        member_slip_claims(
            vault_id,
            member(),
            slip_key.verifying_key().to_bytes(),
            slip,
        ),
        2,
    );
    let seen = node_carries_the_members_opt_out(&mut answer);
    revoke_slip(&mut answer, slip, 3);
    let proof = person_proof(&vault_id, member(), false, seen, slip, &slip_key);
    let entry = carry_opt_back_in(&mut answer, seen, Some(proof));
    assert_stays_out(&answer.fold(), entry);
}

/// Astra review F1 (row PERSON-TRAINING-CHOICE-PERSON-KEY-PROOF; Engine
/// 23:40): the slip must be live at the act's time, as the person's door
/// judges it at the time it writes. A proof by the key of a slip whose
/// lifetime ended before the act proves no new choice, so the opt back in is
/// invalid and the member stays left out.
#[test]
fn a_person_proof_on_an_expired_slip_is_invalid() {
    let mut answer = HostedNodeAnswer::new();
    let vault_id = answer.vault_id();
    let slip_key = signing(MEMBER_SLIP_SEED);
    let slip = [0x51; 32];
    let claims = member_slip_claims(
        vault_id,
        member(),
        slip_key.verifying_key().to_bytes(),
        slip,
    );
    let expired = claims.expires_at;
    mint_slip(&mut answer, claims, 2);
    let seen = node_carries_the_members_opt_out(&mut answer);
    let proof = person_proof(&vault_id, member(), false, seen, slip, &slip_key);
    let entry = carry_opt_back_in_at(&mut answer, seen, Some(proof), expired);
    assert_stays_out(&answer.fold(), entry);
}

/// Ruling CARRIER-PERSON-OPT-BACK-IN = A, row
/// PERSON-TRAINING-CHOICE-PERSON-KEY-PROOF: a share-view slip of the member's
/// is a slip for one share, not their own human slip, so its key proves no
/// choice of theirs and the opt back in is invalid. The mint itself is valid.
#[test]
fn a_person_proof_on_a_share_view_slip_is_invalid() {
    let mut answer = HostedNodeAnswer::new();
    let vault_id = answer.vault_id();
    let slip_key = signing(MEMBER_SLIP_SEED);
    let slip = [0x53; 32];
    let mut claims = member_slip_claims(
        vault_id,
        member(),
        slip_key.verifying_key().to_bytes(),
        slip,
    );
    claims.share_ref = Some(another().to_hex());
    claims.scope.verbs = ScopeAxis::Some(BTreeSet::from(["vault.shares.view".to_owned()]));
    let mint = mint_slip(&mut answer, claims, 2);
    assert!(
        answer.fold().valid_entries.contains(&mint),
        "guard: the share-view slip's mint is valid: {:?}",
        answer.fold().issues
    );
    let seen = node_carries_the_members_opt_out(&mut answer);
    let proof = person_proof(&vault_id, member(), false, seen, slip, &slip_key);
    let entry = carry_opt_back_in(&mut answer, seen, Some(proof));
    assert_stays_out(&answer.fold(), entry);
}

/// Ruling CARRIER-PERSON-OPT-BACK-IN = A, row
/// PERSON-TRAINING-CHOICE-PERSON-KEY-PROOF: the statement names this choice,
/// so a proof signed for another revision is no proof of it.
#[test]
fn a_person_proof_signed_for_an_earlier_revision_is_invalid() {
    let mut answer = HostedNodeAnswer::new();
    let vault_id = answer.vault_id();
    let slip_key = signing(MEMBER_SLIP_SEED);
    let slip = [0x51; 32];
    mint_slip(
        &mut answer,
        member_slip_claims(
            vault_id,
            member(),
            slip_key.verifying_key().to_bytes(),
            slip,
        ),
        2,
    );
    let seen = node_carries_the_members_opt_out(&mut answer);
    let proof = person_proof(&vault_id, member(), false, [0x99; 32], slip, &slip_key);
    let entry = carry_opt_back_in(&mut answer, seen, Some(proof));
    assert_stays_out(&answer.fold(), entry);
}

/// Guard (ruling CARRIER-PERSON-OPT-BACK-IN = A, row
/// PERSON-TRAINING-CHOICE-PERSON-KEY-PROOF): an opt-out still lands with no
/// person proof.
#[test]
fn an_opt_out_still_lands_with_no_person_proof() {
    let answer = HostedNodeAnswer::new();
    let node = answer.machine;
    let (fold, _) = answer.node_carries(members_own_choice(node, true, [0; 32], None));
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

/// Review fix (row PERSON-TRAINING-CHOICE-PERSON-KEY-PROOF): a person's own
/// opt-out lands with no proof, so the fold never judges a proof on it. One
/// that does not hold (another key's signature over a slip no row minted)
/// still lets the opt-out land, never as an invalid entry.
#[test]
fn an_opt_out_with_a_person_proof_that_does_not_hold_still_lands() {
    let answer = HostedNodeAnswer::new();
    let (vault_id, node) = (answer.vault_id(), answer.machine);
    let proof = person_proof(
        &vault_id,
        member(),
        true,
        [0; 32],
        [0x5A; 32],
        &signing(FORGER_SEED),
    );
    let (fold, entry) = answer.node_carries(members_own_choice(node, true, [0; 32], Some(proof)));
    assert!(
        !fold
            .issues
            .contains(&AuthorityFoldIssue::InvalidEntry(entry)),
        "a proof on an opt-out never makes it invalid: {:?}",
        fold.issues
    );
    assert!(
        leaves_out(&fold, member()),
        "the member's own opt-out lands: {:?}",
        fold.issues
    );
    assert_eq!(
        fold.waiting_owner_choices(),
        &BTreeSet::new(),
        "a person's own opt-out never waits"
    );
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

    /// The owner's key is held on another install: he enrols it here and
    /// this handle lets it go. The roster keeps a key that proves for him,
    /// and this install holds none.
    fn owner_key_held_on_another_install(&self) {
        self.enrol_owner_key();
        release_owner_keys(&self.vault);
    }

    /// How many authority log rows the fold holds valid.
    fn stored_rows(&self) -> usize {
        self.vault
            .authority_fold()
            .expect("authority fold")
            .valid_entries
            .len()
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

    /// The owner turns training on and lets people opt out, through this
    /// install.
    fn let_people_opt_out(&self) {
        self.vault
            .set_conversation_learning(&self.owner, ActSurface::ThisInstall, true, true, None)
            .expect("the setting that lets people opt out lands");
    }

    /// A live PERSON of the vault who is not its owner, authenticated at the
    /// person tier with their own human slip bound as person credential.
    /// Returns the member, their proof, their slip's binding key and its id.
    fn member_with_slip(&self) -> (EntityId, AuthenticatedOwner, SigningKey, [u8; 32]) {
        let member = EntityId::now();
        self.vault
            .put_entity(&member, ENTITY_TYPE_PERSON, range(1), 1, b"member")
            .expect("the member PERSON");
        let slip_key = signing(MEMBER_SLIP_SEED);
        let root = self
            .vault
            .ensure_host_root_slip(&self.issuer)
            .expect("host root");
        let mut claims = root.claims;
        claims.slip_id = slip_id();
        claims.parent_id = None;
        claims.holder_ref = member.to_hex();
        claims.actor_class = Some("human".to_owned());
        claims.binding_key = slip_key.verifying_key().to_bytes();
        // ruling PERSONKEY-SLIP-KEY-GRADE = A: a slip the custodial root minted counts.
        let slip = self
            .vault
            .mint_capability_slip(&self.issuer, claims)
            .expect("the member's own slip");
        let challenge = b"person-choice-proof-member-credential";
        // The slip's own binding key proves the holder, as the member's
        // device does.
        let binding = slip_key
            .sign(&slip.binding_transcript(challenge).expect("transcript"))
            .to_bytes();
        let verified = self
            .vault
            .verify_capability_slip(&self.issuer.public_key(), &slip, challenge, &binding)
            .expect("the slip verifies");
        let proof = self
            .vault
            .authenticate_owner(member, &member.to_hex(), true, GateDecisionId::now())
            .expect("the member's proof");
        let proof = self
            .vault
            .bind_request_credential(proof, verified.clone())
            .expect("bind the request slip");
        let proof = self
            .vault
            .bind_person_credential(proof, verified)
            .expect("bind the person credential");
        (member, proof, slip_key, slip.claims.slip_id)
    }
}

const fn range(at: u64) -> TimeRange {
    TimeRange { start: at, end: at }
}

/// A fresh slip id from two UUIDv7 stamps.
fn slip_id() -> [u8; 32] {
    let first = EntityId::now();
    let second = EntityId::now();
    let mut id = [0_u8; 32];
    id[..16].copy_from_slice(first.as_bytes());
    id[16..].copy_from_slice(second.as_bytes());
    id
}

/// Ruling CARRIER-PERSON-OPT-BACK-IN = A, row
/// PERSON-TRAINING-CHOICE-PERSON-KEY-PROOF: the member's door takes their opt
/// back in with their own slip key, beside an owner key this install does
/// not hold.
#[test]
fn a_members_door_takes_an_opt_back_in_with_their_own_slip_key() {
    let served = ServedVault::hosted();
    served.let_people_opt_out();
    served.owner_key_held_on_another_install();
    let (member, proof, slip_key, slip) = served.member_with_slip();
    let out = served
        .vault
        .set_conversation_training(&proof, ActSurface::ThisInstall, true, None, None)
        .expect("the opt-out lands");
    assert!(out.leave_out, "the member is left out");
    let vault_id = served
        .vault
        .authority_fold()
        .expect("authority fold")
        .vault_id
        .expect("the vault is rooted");
    let seen = served
        .vault
        .conversation_training_view(&proof)
        .expect("the member's view")
        .revision
        .0;
    let back_in = served
        .vault
        .set_conversation_training(
            &proof,
            ActSurface::ThisInstall,
            false,
            None,
            Some(person_proof(
                &vault_id, member, false, seen, slip, &slip_key,
            )),
        )
        .expect("the proven opt back in lands");
    assert!(!back_in.leave_out, "the member is let back in");
}

/// Ruling CARRIER-PERSON-OPT-BACK-IN = A, row
/// PERSON-TRAINING-CHOICE-PERSON-KEY-PROOF: the vault owner proves with the
/// owner key, never a slip key, so their door refuses a person proof with
/// the owner-key reason and stores nothing.
#[test]
fn the_owners_door_refuses_a_person_proof() {
    let served = ServedVault::hosted();
    served.let_people_opt_out();
    served
        .vault
        .set_conversation_training(&served.owner, ActSurface::ThisInstall, true, None, None)
        .expect("guard: the opt-out lands");
    served.owner_key_held_on_another_install();
    let rows = served.stored_rows();
    let answer = served.vault.set_conversation_training(
        &served.owner,
        ActSurface::ThisInstall,
        false,
        None,
        Some(PersonChoiceProof {
            slip: [0xA0; 32],
            signature: [0xA1; 64],
        }),
    );
    assert!(
        matches!(answer, Err(Error::Record(RecordError::OwnerKeyRequired))),
        "the door refuses for the owner's key: {answer:?}"
    );
    served.assert_nothing_stored_since(rows);
    assert!(
        served
            .vault
            .conversation_training_view(&served.owner)
            .expect("the owner's view")
            .leave_out,
        "the owner stays left out"
    );
}

/// Review fix (row PERSON-TRAINING-CHOICE-PERSON-KEY-PROOF): the member's
/// door drops a proof sent with their opt-out unjudged, so one that does not
/// hold never refuses the opt-out.
#[test]
fn a_members_door_takes_an_opt_out_with_a_proof_that_does_not_hold() {
    let served = ServedVault::hosted();
    served.let_people_opt_out();
    served.owner_key_held_on_another_install();
    let (_, proof, _, _) = served.member_with_slip();
    let out = served
        .vault
        .set_conversation_training(
            &proof,
            ActSurface::ThisInstall,
            true,
            None,
            Some(PersonChoiceProof {
                slip: [0xA0; 32],
                signature: [0xA1; 64],
            }),
        )
        .expect("the opt-out lands beside a proof that does not hold");
    assert!(out.leave_out, "the member is left out");
}
