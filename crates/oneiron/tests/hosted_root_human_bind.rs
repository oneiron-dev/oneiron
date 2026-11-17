//! On a hosted vault a `human` actor binding counts only with an owner key's
//! proof (rows OLD-PARENTS-OWNER-BINDING-REVOKE and
//! OLD-PARENTS-OWNER-BINDING-CONFLICT; owner ruling 2026-10-18, "A +
//! support": on our hosted cloud the operator root acts as nobody inside a
//! customer's vault, and being the trust root never makes the operator a
//! person in the vault).
//!
//! Pure folds over hand-signed rows, on the scaffold of
//! `owner_key_revoke_proof.rs`: a genesis root, the root's registration of a
//! hosted node, and the root's fold-only enrolment of an owner device key.
//!
//! No writer binds a person on a hosted vault, so the owner is unbound there
//! and the fold takes an owner no row binds as live on the carrier's word. A
//! binding the custodial root made alone would let the root end the owner's
//! standing on every replica, by revoking that binding or by a conflicting
//! sibling bind, so the fold does not count it. An owner key's signature or
//! cosign lets a bind count, and a self-host root, the owner's own key,
//! still binds alone.
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test hosted_root_human_bind`.

#![cfg(oneiron_test_support)]

use std::collections::{BTreeMap, BTreeSet};

use ed25519_dalek::{Signer, SigningKey};
use oneiron::authority::{
    AUTHORITY_LOG_SCHEMA_VERSION, ActSurface, ActorBindingStatus, AuthorityAttestation,
    AuthorityEntryHash, AuthorityFold, AuthorityKey, AuthorityLogEntry, AuthorityOp,
    AuthoritySignature, AuthorityTier, AuthorityVaultId, DeviceAuthority, GenesisRecoveryStep,
    MACHINE_ENCRYPTION_KEY_LEN, MACHINE_ENCRYPTION_SUITE_HYBRID_V1, MachineDeviceClass,
    MachineEncryptionKey, MachineProfile, MachineRole, OwnerAct, OwnerActKind, ROLE_ADMIN,
    ROLE_AGENT, ROLE_CLOUD, ROLE_OWNER, authority_entry_hash, authority_transcript,
    fold_authority_log, fold_authority_log_for_posture, genesis_vault_id,
    machine_profile_proof_transcript,
};
use oneiron::{EntityId, HostingPrivacyPosture};
use oneiron_authority::authority::{
    OWNER_KEY_ENROLLMENT_SEEN, OWNER_KEY_POSSESSION_KIND, OwnerKeyEnroll,
    owner_key_enrollment_challenge, owner_key_enrollment_target, roster_has_live_owner,
};

const ROOT_SEED: u8 = 81;
const NODE_SEED: u8 = 82;
/// A fresh seed, so no roster row, machine revision, actor binding or anchor
/// ever named the enrolled owner key.
const OWNER_KEY_SEED: u8 = 91;
/// The actor class of a person's binding.
const HUMAN: &str = "human";

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

/// The attestation of a key a host attests as its root, self-hosted or
/// managed (`slip_vault.rs` `HOST_ROOT_ATTESTATION`).
const HOST_ROOT_ATTESTATION: &str = "HostRoot";

/// The genesis row of a vault whose root key `root` holds `roles` at `tier`,
/// attested as `attestation`.
fn genesis_row(
    root: &SigningKey,
    roles: u16,
    tier: AuthorityTier,
    attestation: &str,
) -> AuthorityLogEntry {
    signed(
        None,
        0,
        Vec::new(),
        AuthorityOp::Genesis {
            device: DeviceAuthority {
                key: key_of(root),
                transport_key_binding: [7; 32],
                attestation: AuthorityAttestation {
                    kind: attestation.to_owned(),
                    evidence: vec![1, 2, 3],
                },
                tier,
                roles,
            },
            genesis_nonce: [197; 32],
            recovery: GenesisRecoveryStep::Saved([1; 32]),
        },
        root,
        &[],
    )
}

/// The vault's owner.
fn owner() -> EntityId {
    EntityId::from_bytes([0x71; 16]).expect("an id")
}

/// Another person. Its id sorts after the owner's, so in a merge of two
/// same-epoch bindings of one key the owner's binding is the one kept (the
/// smaller actor wins, `fold_state.rs` `merge_actor_bindings`).
fn other_person() -> EntityId {
    EntityId::from_bytes([0x7f; 16]).expect("an id")
}

/// `node`'s profile of `machine` in `role` at `revision`.
fn node_profile(
    vault_id: AuthorityVaultId,
    machine: EntityId,
    node: &SigningKey,
    role: MachineRole,
    revision: u64,
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
        carrier: None,
        act: None,
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

/// A `RebindActor` of `bound` to `person` as a person at `epoch`.
fn human_rebind(bound: AuthorityKey, person: EntityId, epoch: u64) -> AuthorityOp {
    AuthorityOp::RebindActor {
        authority_key: bound,
        actor_ref: person,
        actor_class: HUMAN.to_owned(),
        epoch,
    }
}

/// A `RevokeActor` of the binding under `bound` at `epoch`.
fn actor_revoke(bound: AuthorityKey, epoch: u64) -> AuthorityOp {
    AuthorityOp::RevokeActor {
        authority_key: bound,
        epoch,
    }
}

/// A vault whose root registered one hosted node: genesis plus registration.
/// The node is the holder and the carrier of the owner key enrolment.
struct OwnerKeyVault {
    root: SigningKey,
    node: SigningKey,
    machine: EntityId,
    rows: Vec<AuthorityLogEntry>,
    /// A managed host's vault: its root is the host's custodial key, and
    /// replicas fold under the hosted posture.
    hosted: bool,
}

impl OwnerKeyVault {
    /// A managed host's vault: its root is the host's custodial key.
    fn on_a_hosted_vault() -> Self {
        Self::with_root(
            ROLE_OWNER | ROLE_ADMIN | ROLE_CLOUD,
            AuthorityTier::CloudCustodial,
            HOST_ROOT_ATTESTATION,
            true,
        )
    }

    /// A self-host vault: its root is an owner-held key.
    fn self_hosted() -> Self {
        Self::with_root(
            ROLE_OWNER | ROLE_ADMIN,
            AuthorityTier::Software,
            "SoftwareArgon2id",
            false,
        )
    }

    /// A vault a self-hosted root rooted, folded under the hosted posture, as
    /// when the vault is opened with a Hosted config or its history is
    /// imported into a hosted vault: its root is a host-attested key with no
    /// cloud stamp.
    fn self_hosted_folded_as_hosted() -> Self {
        Self::with_root(
            ROLE_OWNER | ROLE_ADMIN,
            AuthorityTier::Software,
            HOST_ROOT_ATTESTATION,
            true,
        )
    }

    fn with_root(roles: u16, tier: AuthorityTier, attestation: &str, hosted: bool) -> Self {
        let root = signing(ROOT_SEED);
        let node = signing(NODE_SEED);
        let genesis = genesis_row(&root, roles, tier, attestation);
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

    /// The registration row's hash: the head every test starts from.
    fn registration(&self) -> AuthorityEntryHash {
        hash(&self.rows[1])
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

    /// The root enrols `new_key` as an owner key of the owner's at `seq` on
    /// `parent`, carried by the node: the fold-only `OwnerKeyEnroll` row the
    /// fold counts. Returns the enrolment's hash.
    fn enrol(
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
}

/// Whether any `human` binding of the fold names `person`. The fold reads an
/// owner no binding names as live on the carrier's word, and an owner every
/// binding of whom is revoked or conflicted as removed.
fn binds_person(fold: &AuthorityFold, person: EntityId) -> bool {
    fold.actor_bindings
        .values()
        .any(|binding| binding.actor_ref == person && binding.actor_class == HUMAN)
}

/// Whether the fold holds an active `human` binding of `person` under `key`.
fn binds_active(fold: &AuthorityFold, key: &AuthorityKey, person: EntityId) -> bool {
    fold.actor_bindings.get(key).is_some_and(|binding| {
        binding.actor_ref == person
            && binding.actor_class == HUMAN
            && binding.status == ActorBindingStatus::Active
    })
}

/// Main: the root's bind counts, so the fold binds the owner under the root.
#[test]
fn a_custodial_root_alone_binds_no_person_on_a_hosted_vault() {
    let mut vault = OwnerKeyVault::on_a_hosted_vault();
    let registration = vault.registration();
    let root = vault.root.clone();
    let root_key = key_of(&root);
    let bind = vault.append(
        2,
        registration,
        human_bind(root_key, owner(), 1),
        &root,
        &[],
    );
    let fold = vault.fold();
    assert!(
        fold.valid_entries.contains(&registration),
        "the registration counts, so the test cannot pass for the wrong reason: {registration:?}"
    );
    assert!(
        !fold.valid_entries.contains(&bind),
        "the custodial root's bind of a person alone does not count: {bind:?}"
    );
    assert!(
        !binds_person(&fold, owner()),
        "no binding names the owner: {:?}",
        fold.actor_bindings
    );
}

/// Row OLD-PARENTS-OWNER-BINDING-REVOKE. Main: the root binds the owner on
/// parents from before the owner key's enrolment and revokes that binding,
/// so the merged fold holds the owner's binding revoked and every replica
/// takes the owner as removed.
#[test]
fn a_custodial_root_bind_and_revoke_beside_an_owner_key_leave_the_owner_unbound() {
    let mut vault = OwnerKeyVault::on_a_hosted_vault();
    let registration = vault.registration();
    let key = signing(OWNER_KEY_SEED);
    let enrolment = vault.enrol(2, registration, &key);
    let root = vault.root.clone();
    let root_key = key_of(&root);
    let bind = vault.append(
        3,
        registration,
        human_bind(root_key.clone(), owner(), 1),
        &root,
        &[],
    );
    vault.append(4, bind, actor_revoke(root_key, 1), &root, &[]);
    let fold = vault.fold();
    assert!(
        fold.valid_entries.contains(&enrolment),
        "the owner key's enrolment counts, so the test cannot pass for the wrong reason: {enrolment:?}"
    );
    assert!(
        roster_has_live_owner(&fold.roster, &key_of(&key)),
        "the owner key stays a live owner key"
    );
    assert!(
        !binds_person(&fold, owner()),
        "no binding names the owner, so the root's revoke removes no one: {:?}",
        fold.actor_bindings
    );
}

/// Row OLD-PARENTS-OWNER-BINDING-CONFLICT, the root's own key. Main: the two
/// sibling binds count, the merge keeps the owner's as conflicted, and every
/// replica takes the owner as removed.
#[test]
fn custodial_root_sibling_binds_of_one_key_leave_the_owner_unbound() {
    let mut vault = OwnerKeyVault::on_a_hosted_vault();
    let registration = vault.registration();
    let root = vault.root.clone();
    let root_key = key_of(&root);
    let owners_bind = vault.append(
        2,
        registration,
        human_bind(root_key.clone(), owner(), 1),
        &root,
        &[],
    );
    let others_bind = vault.append(
        3,
        registration,
        human_bind(root_key, other_person(), 1),
        &root,
        &[],
    );
    let fold = vault.fold();
    assert!(
        !fold.valid_entries.contains(&owners_bind) && !fold.valid_entries.contains(&others_bind),
        "neither of the custodial root's binds counts: {owners_bind:?} {others_bind:?}"
    );
    assert!(
        !binds_person(&fold, owner()),
        "no binding names the owner: {:?}",
        fold.actor_bindings
    );
}

/// Row OLD-PARENTS-OWNER-BINDING-CONFLICT, an owner key. Main: the root's
/// same-epoch bind of the owner key to another person counts beside the
/// owner's own binding, the merge marks it conflicted, and the owner's only
/// binding is dead.
#[test]
fn a_custodial_root_sibling_bind_leaves_the_owners_own_binding_active() {
    let mut vault = OwnerKeyVault::on_a_hosted_vault();
    let registration = vault.registration();
    let key = signing(OWNER_KEY_SEED);
    let owner_key = key_of(&key);
    let enrolment = vault.enrol(2, registration, &key);
    let owners_bind = vault.append(
        1,
        enrolment,
        human_bind(owner_key.clone(), owner(), 1),
        &key,
        &[],
    );
    let root = vault.root.clone();
    let others_bind = vault.append(
        3,
        enrolment,
        human_bind(owner_key.clone(), other_person(), 1),
        &root,
        &[],
    );
    let fold = vault.fold();
    assert!(
        fold.valid_entries.contains(&owners_bind),
        "the owner key's bind of the owner counts: {owners_bind:?}"
    );
    assert!(
        !fold.valid_entries.contains(&others_bind),
        "the custodial root's bind of the owner key alone does not count: {others_bind:?}"
    );
    assert!(
        binds_active(&fold, &owner_key, owner()),
        "the owner's own binding stays active: {:?}",
        fold.actor_bindings
    );
}

/// Main: the root's rebind counts, so the owner key speaks for another
/// person.
#[test]
fn a_custodial_root_alone_does_not_rebind_an_owner_key() {
    let mut vault = OwnerKeyVault::on_a_hosted_vault();
    let registration = vault.registration();
    let key = signing(OWNER_KEY_SEED);
    let owner_key = key_of(&key);
    let enrolment = vault.enrol(2, registration, &key);
    let owners_bind = vault.append(
        1,
        enrolment,
        human_bind(owner_key.clone(), owner(), 1),
        &key,
        &[],
    );
    let root = vault.root.clone();
    let rebind = vault.append(
        3,
        owners_bind,
        human_rebind(owner_key.clone(), other_person(), 2),
        &root,
        &[],
    );
    let fold = vault.fold();
    assert!(
        !fold.valid_entries.contains(&rebind),
        "the custodial root's rebind alone does not count: {rebind:?}"
    );
    assert!(
        binds_active(&fold, &owner_key, owner()),
        "the owner key still speaks for the owner: {:?}",
        fold.actor_bindings
    );
}

/// Main: the root's rebind of the owner key to an agent counts, so the
/// owner's binding turns into an agent's and the owner key speaks for no
/// person.
#[test]
fn a_custodial_root_alone_does_not_rebind_the_owners_binding_to_an_agent() {
    let mut vault = OwnerKeyVault::on_a_hosted_vault();
    let registration = vault.registration();
    let key = signing(OWNER_KEY_SEED);
    let owner_key = key_of(&key);
    let enrolment = vault.enrol(2, registration, &key);
    let owners_bind = vault.append(
        1,
        enrolment,
        human_bind(owner_key.clone(), owner(), 1),
        &key,
        &[],
    );
    let root = vault.root.clone();
    let rebind = vault.append(
        3,
        owners_bind,
        AuthorityOp::RebindActor {
            authority_key: owner_key.clone(),
            actor_ref: owner(),
            actor_class: "agent".to_owned(),
            epoch: 2,
        },
        &root,
        &[],
    );
    let fold = vault.fold();
    assert!(
        !fold.valid_entries.contains(&rebind),
        "the custodial root's rebind of the owner's binding alone does not count: {rebind:?}"
    );
    assert!(
        binds_active(&fold, &owner_key, owner()),
        "the owner key still speaks for the owner as a person: {:?}",
        fold.actor_bindings
    );
}

/// Main: after the root revokes the owner's binding, its agent bind of the
/// same key counts and replaces the revoked `human` record, so the fold reads
/// the owner as bound nowhere, live on the carrier's word: the root alone
/// undoes the owner's removal (REVIEW2 #9137 P2-1).
#[test]
fn a_custodial_root_alone_does_not_bind_over_the_owners_revoked_binding() {
    let mut vault = OwnerKeyVault::on_a_hosted_vault();
    let registration = vault.registration();
    let key = signing(OWNER_KEY_SEED);
    let owner_key = key_of(&key);
    let enrolment = vault.enrol(2, registration, &key);
    let owners_bind = vault.append(
        1,
        enrolment,
        human_bind(owner_key.clone(), owner(), 1),
        &key,
        &[],
    );
    let root = vault.root.clone();
    let revoke = vault.append(
        3,
        owners_bind,
        actor_revoke(owner_key.clone(), 1),
        &root,
        &[],
    );
    let rebind = vault.append(
        4,
        revoke,
        AuthorityOp::BindActor {
            authority_key: owner_key.clone(),
            actor_ref: owner(),
            actor_class: "agent".to_owned(),
            epoch: 2,
        },
        &root,
        &[],
    );
    let fold = vault.fold();
    assert!(
        fold.valid_entries.contains(&revoke),
        "a revoke never asks: {revoke:?}"
    );
    assert!(
        !fold.valid_entries.contains(&rebind),
        "the custodial root's bind over the revoked binding alone does not count: {rebind:?}"
    );
    assert!(
        binds_person(&fold, owner()),
        "the owner's revoked binding stays, so the owner reads as removed: {:?}",
        fold.actor_bindings
    );
}

/// Passes on main too: the allowed path the gate keeps.
#[test]
fn an_owner_key_binds_the_owner_on_a_hosted_vault() {
    let mut vault = OwnerKeyVault::on_a_hosted_vault();
    let registration = vault.registration();
    let key = signing(OWNER_KEY_SEED);
    let owner_key = key_of(&key);
    let enrolment = vault.enrol(2, registration, &key);
    let bind = vault.append(
        1,
        enrolment,
        human_bind(owner_key.clone(), owner(), 1),
        &key,
        &[],
    );
    let fold = vault.fold();
    assert!(
        fold.valid_entries.contains(&bind),
        "the owner key's own bind counts: {bind:?}"
    );
    assert!(
        binds_active(&fold, &owner_key, owner()),
        "the owner key speaks for the owner: {:?}",
        fold.actor_bindings
    );
}

/// Passes on main too: an owner key's cosign is the owner's proof.
#[test]
fn an_owner_key_cosign_lets_the_custodial_root_bind_the_owner() {
    let mut vault = OwnerKeyVault::on_a_hosted_vault();
    let registration = vault.registration();
    let key = signing(OWNER_KEY_SEED);
    let owner_key = key_of(&key);
    let enrolment = vault.enrol(2, registration, &key);
    let root = vault.root.clone();
    let bind = vault.append(
        3,
        enrolment,
        human_bind(owner_key.clone(), owner(), 1),
        &root,
        &[&key],
    );
    let fold = vault.fold();
    assert!(
        fold.valid_entries.contains(&bind),
        "the root's bind with the owner key's cosign counts: {bind:?}"
    );
    assert!(
        binds_active(&fold, &owner_key, owner()),
        "the owner key speaks for the owner: {:?}",
        fold.actor_bindings
    );
}

/// Passes on main too: a self-host root is the owner's own key and binds the
/// owner alone, as the transaction that roots such a vault does.
#[test]
fn a_self_host_root_binds_the_owner_alone() {
    let mut vault = OwnerKeyVault::self_hosted();
    let registration = vault.registration();
    let root = vault.root.clone();
    let root_key = key_of(&root);
    let bind = vault.append(
        2,
        registration,
        human_bind(root_key.clone(), owner(), 1),
        &root,
        &[],
    );
    let fold = vault.fold();
    assert!(
        fold.valid_entries.contains(&bind),
        "the self-host root's bind counts: {bind:?}"
    );
    assert!(
        binds_active(&fold, &root_key, owner()),
        "the root speaks for the owner: {:?}",
        fold.actor_bindings
    );
}

/// Passes on main too: the gate reads the cloud stamp, a fact in the log,
/// and not host custody, which takes a host-attested self-host root as the
/// host's on a hosted fold. A self-hosted vault opened as Hosted keeps the
/// bind of the transaction that rooted it, and every row after.
#[test]
fn a_self_host_root_bind_counts_when_its_log_is_folded_as_hosted() {
    let mut vault = OwnerKeyVault::self_hosted_folded_as_hosted();
    let registration = vault.registration();
    let root = vault.root.clone();
    let root_key = key_of(&root);
    let bind = vault.append(
        2,
        registration,
        human_bind(root_key.clone(), owner(), 1),
        &root,
        &[],
    );
    let node_key = key_of(&vault.node);
    let after = vault.append(3, bind, actor_revoke(node_key, 1), &root, &[]);
    let fold = vault.fold();
    assert!(
        fold.valid_entries.contains(&bind),
        "the self-host root's bind counts under the hosted posture: {bind:?}"
    );
    assert!(
        fold.valid_entries.contains(&after),
        "the row after the bind counts too: {after:?}"
    );
    assert!(
        binds_active(&fold, &root_key, owner()),
        "the root speaks for the owner: {:?}",
        fold.actor_bindings
    );
}

/// Row OLD-PARENTS-OWNER-BINDING-CONFLICT, an agent-class sibling (blind
/// review round 1 of #9137, P1, 17 Nov 05:43). The root binds the owner key
/// as another actor's agent key at the owner's epoch on the enrolment, where
/// no binding of the key is a person's, so the bind touches no person there.
/// Main and this row's head before the fix: it counts beside the owner's own
/// binding, the merge marks the key's binding conflicted, and the owner's
/// only binding is dead.
#[test]
fn a_custodial_root_sibling_agent_bind_of_an_owner_key_leaves_the_owners_binding_active() {
    let mut vault = OwnerKeyVault::on_a_hosted_vault();
    let registration = vault.registration();
    let key = signing(OWNER_KEY_SEED);
    let owner_key = key_of(&key);
    let enrolment = vault.enrol(2, registration, &key);
    let owners_bind = vault.append(
        1,
        enrolment,
        human_bind(owner_key.clone(), owner(), 1),
        &key,
        &[],
    );
    let root = vault.root.clone();
    let agent_bind = vault.append(
        3,
        enrolment,
        AuthorityOp::BindActor {
            authority_key: owner_key.clone(),
            actor_ref: other_person(),
            actor_class: "agent".to_owned(),
            epoch: 1,
        },
        &root,
        &[],
    );
    let fold = vault.fold();
    assert!(
        fold.valid_entries.contains(&owners_bind),
        "the owner key's bind of the owner counts: {owners_bind:?}"
    );
    assert!(
        !fold.valid_entries.contains(&agent_bind),
        "the custodial root's agent bind of the owner key alone does not count: {agent_bind:?}"
    );
    assert!(
        binds_active(&fold, &owner_key, owner()),
        "the owner's own binding stays active: {:?}",
        fold.actor_bindings
    );
}

/// Row OLD-PARENTS-OWNER-BINDING-CONFLICT, the root's own key bound as the
/// owner's (blind review round 2 of #9137, P1, 17 Nov 08:58). With an owner
/// key's cosign the root binds its own key as the owner's, as the owner
/// binds from a device of their own; beside that bind, on the same
/// enrolment, the root alone binds its key as another actor's agent key at
/// the owner's epoch. No binding of the key is a person's on those parents,
/// and the root's key is no owner key outside cloud custody. Main and this
/// row's head before the fix: the agent bind counts, the merge marks the
/// key's binding conflicted, and the owner's only binding is dead.
#[test]
fn a_custodial_root_sibling_agent_bind_of_its_own_key_leaves_the_owners_binding_active() {
    let mut vault = OwnerKeyVault::on_a_hosted_vault();
    let registration = vault.registration();
    let key = signing(OWNER_KEY_SEED);
    let enrolment = vault.enrol(2, registration, &key);
    let root = vault.root.clone();
    let root_key = key_of(&root);
    let owners_bind = vault.append(
        3,
        enrolment,
        human_bind(root_key.clone(), owner(), 1),
        &root,
        &[&key],
    );
    let agent_bind = vault.append(
        4,
        enrolment,
        AuthorityOp::BindActor {
            authority_key: root_key.clone(),
            actor_ref: other_person(),
            actor_class: "agent".to_owned(),
            epoch: 1,
        },
        &root,
        &[],
    );
    let fold = vault.fold();
    assert!(
        fold.valid_entries.contains(&owners_bind),
        "the root's bind of the owner with the owner key's cosign counts: {owners_bind:?}"
    );
    assert!(
        !fold.valid_entries.contains(&agent_bind),
        "the custodial root's agent bind of its own key alone does not count: {agent_bind:?}"
    );
    assert!(
        binds_active(&fold, &root_key, owner()),
        "the owner's binding stays active: {:?}",
        fold.actor_bindings
    );
}

/// Passes on main too: a key no person's binding can name, a machine's
/// `ROLE_AGENT` key, binds as an agent on the custodial root's word, as a
/// machine enrolment binds its agent key (`machine_enroll.rs`).
#[test]
fn a_custodial_root_alone_binds_an_agent_key_on_a_hosted_vault() {
    let mut vault = OwnerKeyVault::on_a_hosted_vault();
    let registration = vault.registration();
    let agent = signing(OWNER_KEY_SEED);
    let agent_key = key_of(&agent);
    let root = vault.root.clone();
    let enrolment = vault.append(
        2,
        registration,
        AuthorityOp::EnrollDevice {
            device: DeviceAuthority {
                key: agent_key.clone(),
                transport_key_binding: [0; 32],
                attestation: AuthorityAttestation {
                    kind: "SoftwareArgon2id".to_owned(),
                    evidence: Vec::new(),
                },
                tier: AuthorityTier::Software,
                roles: ROLE_AGENT,
            },
        },
        &root,
        &[],
    );
    let bind = vault.append(
        3,
        enrolment,
        AuthorityOp::BindActor {
            authority_key: agent_key.clone(),
            actor_ref: other_person(),
            actor_class: "agent".to_owned(),
            epoch: 1,
        },
        &root,
        &[&agent],
    );
    let fold = vault.fold();
    assert!(
        fold.valid_entries.contains(&enrolment) && fold.valid_entries.contains(&bind),
        "the root's enrolment and agent bind of a machine's agent key count: {enrolment:?} {bind:?}"
    );
    assert!(
        fold.actor_bindings.get(&agent_key).is_some_and(|binding| {
            binding.actor_ref == other_person()
                && binding.actor_class == "agent"
                && binding.status == ActorBindingStatus::Active
        }),
        "the agent key speaks for its actor: {:?}",
        fold.actor_bindings
    );
}
