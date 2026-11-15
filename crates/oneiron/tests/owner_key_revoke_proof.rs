//! A revoke of an owner key counts only with an owner key's proof (row
//! HOSTED-ROOT-REVOKES-OWNER-KEY; the lead, 15 Nov 20:41: "a revoke of an
//! owner key needs an owner key's signature, never only the custodial root").
//!
//! Pure folds over hand-signed rows: a genesis root, the root's registration
//! of a hosted node, the root's fold-only enrolment of owner device keys
//! (an `OwnerKeyEnroll` row the fold counts: the predecessor root signs,
//! the node's install key cosigns, the new key proves possession), and a
//! `RevokeDevice` of an enrolled key. The node is both holder and carrier.
//!
//! On a hosted vault the custodial root alone never ends an enrolled owner
//! key, neither on the enrolment nor before it; an owner key's cosign, or
//! the key's own signature, lets the revoke count. On a self-host vault the
//! owner-held root still revokes an owner device key alone.
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test owner_key_revoke_proof`.

#![cfg(oneiron_test_support)]

use std::collections::{BTreeMap, BTreeSet};

use ed25519_dalek::{Signer, SigningKey};
use oneiron::authority::{
    AUTHORITY_LOG_SCHEMA_VERSION, ActSurface, AuthorityAttestation, AuthorityEntryHash,
    AuthorityFold, AuthorityKey, AuthorityLogEntry, AuthorityOp, AuthoritySignature,
    AuthorityTier, AuthorityVaultId, DeviceAuthority, GenesisRecoveryStep,
    MACHINE_ENCRYPTION_KEY_LEN, MACHINE_ENCRYPTION_SUITE_HYBRID_V1, MachineDeviceClass,
    MachineEncryptionKey, MachineProfile, MachineRole, OwnerAct, OwnerActKind, ROLE_ADMIN,
    ROLE_CLOUD, ROLE_OWNER, authority_entry_hash, authority_transcript, fold_authority_log,
    fold_authority_log_for_posture, genesis_vault_id, machine_profile_proof_transcript,
};
use oneiron::{EntityId, HostingPrivacyPosture};
use oneiron_authority::authority::{
    OWNER_KEY_ENROLLMENT_SEEN, OWNER_KEY_POSSESSION_KIND, OwnerKeyEnroll,
    owner_key_enrollment_challenge, owner_key_enrollment_target, roster_has_live_owner,
};

const ROOT_SEED: u8 = 61;
const NODE_SEED: u8 = 62;
/// Fresh seeds, so no roster row, machine revision, actor binding or anchor
/// ever named the enrolled owner keys.
const OWNER_KEY_SEED: u8 = 71;
const SECOND_OWNER_KEY_SEED: u8 = 72;

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

/// A vault whose root registered one hosted node: genesis plus registration.
/// The node is the holder and the carrier of every owner key enrolment.
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
    /// A managed host's vault whose only owner key is the host's custodial
    /// root, so no owner device key is enrolled.
    fn on_a_hosted_vault() -> Self {
        Self::with_root(
            ROLE_OWNER | ROLE_ADMIN | ROLE_CLOUD,
            AuthorityTier::CloudCustodial,
            true,
        )
    }

    /// A self-host vault: its root is an owner-held key.
    fn self_hosted() -> Self {
        Self::with_root(ROLE_OWNER | ROLE_ADMIN, AuthorityTier::Software, false)
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

    /// The root enrols `new_key` as an owner key of its own at `seq` on
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
        let row = signed(Some(vault_id), seq, vec![parent], op, &self.root, &[&self.node]);
        let entry = hash(&row);
        self.rows.push(row);
        entry
    }

    /// A `RevokeDevice` of `revoked` at `seq` on `parent`, signed by `signer`
    /// with one cosign by each of `cosigners`. Returns its hash.
    fn revoke(
        &mut self,
        seq: u64,
        parent: AuthorityEntryHash,
        revoked: AuthorityKey,
        signer: &SigningKey,
        cosigners: &[&SigningKey],
    ) -> AuthorityEntryHash {
        let row = signed(
            Some(self.vault_id()),
            seq,
            vec![parent],
            AuthorityOp::RevokeDevice {
                revoked_key: revoked,
            },
            signer,
            cosigners,
        );
        let entry = hash(&row);
        self.rows.push(row);
        entry
    }
}

/// Whether `key` is a live owner key on the fold's roster.
fn live_owner(fold: &AuthorityFold, key: &AuthorityKey) -> bool {
    roster_has_live_owner(&fold.roster, key)
}

/// Whether `key` is revoked on the fold's roster.
fn revoked(fold: &AuthorityFold, key: &AuthorityKey) -> bool {
    fold.roster.get(key).is_some_and(|device| device.revoked)
}

/// Test 1 of the row. Main: the revoke counts, so the key ends revoked.
#[test]
fn a_custodial_root_alone_does_not_revoke_an_enrolled_owner_key() {
    let mut vault = OwnerKeyVault::on_a_hosted_vault();
    let key = signing(OWNER_KEY_SEED);
    let registration = hash(&vault.rows[1]);
    let enrolment = vault.enrol(2, registration, &key);
    let owner_key = key_of(&key);
    let fold = vault.fold();
    assert!(
        fold.valid_entries.contains(&enrolment),
        "the enrolment itself counts, so the test cannot pass for the wrong reason: {enrolment:?}"
    );
    assert!(
        live_owner(&fold, &owner_key),
        "the enrolled key is a live owner key before the revoke: {owner_key:?}"
    );
    let root = vault.root.clone();
    let revoke = vault.revoke(3, enrolment, owner_key.clone(), &root, &[]);
    let fold = vault.fold();
    assert!(
        live_owner(&fold, &owner_key),
        "the custodial root alone never ends an enrolled owner key: {owner_key:?}"
    );
    assert!(
        !fold.valid_entries.contains(&revoke),
        "the root-alone revoke of an owner key is invalid: {revoke:?}"
    );
}

/// Test 2 of the row. Main: the revoke counts.
#[test]
fn an_owner_key_cosign_lets_the_custodial_root_revoke_it() {
    let mut vault = OwnerKeyVault::on_a_hosted_vault();
    let first = signing(OWNER_KEY_SEED);
    let second = signing(SECOND_OWNER_KEY_SEED);
    let registration = hash(&vault.rows[1]);
    let first_enrolment = vault.enrol(2, registration, &first);
    let second_enrolment = vault.enrol(3, first_enrolment, &second);
    let first_key = key_of(&first);
    let second_key = key_of(&second);
    let root = vault.root.clone();
    let revoke = vault.revoke(4, second_enrolment, first_key.clone(), &root, &[&second]);
    let fold = vault.fold();
    assert!(
        fold.valid_entries.contains(&revoke),
        "the custodial root's revoke with an owner key's cosign counts: {revoke:?}"
    );
    assert!(
        revoked(&fold, &first_key),
        "the cosigned revoke ends the revoked owner key: {first_key:?}"
    );
    assert!(
        live_owner(&fold, &second_key),
        "the cosigning owner key stays live: {second_key:?}"
    );
}

/// Test 3 of the row. Main: the self-revoke counts.
#[test]
fn an_owner_key_revokes_itself_on_a_hosted_vault() {
    let mut vault = OwnerKeyVault::on_a_hosted_vault();
    let key = signing(OWNER_KEY_SEED);
    let registration = hash(&vault.rows[1]);
    let enrolment = vault.enrol(2, registration, &key);
    let owner_key = key_of(&key);
    let revoke = vault.revoke(1, enrolment, owner_key.clone(), &key, &[]);
    let fold = vault.fold();
    assert!(
        fold.valid_entries.contains(&revoke),
        "an owner key's self-revoke counts: {revoke:?}"
    );
    assert!(
        revoked(&fold, &owner_key),
        "the self-revoke ends the owner key: {owner_key:?}"
    );
}

/// Test 4 of the row. Main: the revoke counts on its branch, and the merge
/// ends the owner key revoked.
#[test]
fn a_custodial_root_revoke_on_parents_before_the_enrolment_does_not_end_the_owner_key() {
    let mut vault = OwnerKeyVault::on_a_hosted_vault();
    let key = signing(OWNER_KEY_SEED);
    let registration = hash(&vault.rows[1]);
    let enrolment = vault.enrol(2, registration, &key);
    let owner_key = key_of(&key);
    let root = vault.root.clone();
    let revoke = vault.revoke(3, registration, owner_key.clone(), &root, &[]);
    let fold = vault.fold();
    assert!(
        fold.valid_entries.contains(&enrolment),
        "the enrolment counts on its own branch: {enrolment:?}"
    );
    assert!(
        live_owner(&fold, &owner_key),
        "a root-alone revoke parented before the enrolment never ends the owner key: {owner_key:?}"
    );
    assert!(
        !fold.valid_entries.contains(&revoke),
        "the unproved revoke of a key the parents do not hold is invalid: {revoke:?}"
    );
}

/// Test 5 of the row. Main: the revoke counts.
#[test]
fn a_self_host_root_still_revokes_an_owner_device_key() {
    let mut vault = OwnerKeyVault::self_hosted();
    let key = signing(OWNER_KEY_SEED);
    let registration = hash(&vault.rows[1]);
    let enrolment = vault.enrol(2, registration, &key);
    let owner_key = key_of(&key);
    let root = vault.root.clone();
    let revoke = vault.revoke(3, enrolment, owner_key.clone(), &root, &[]);
    let fold = vault.fold();
    assert!(
        fold.valid_entries.contains(&revoke),
        "a self-host root alone still revokes an owner device key: {revoke:?}"
    );
    assert!(
        revoked(&fold, &owner_key),
        "the self-host root's revoke ends the owner key: {owner_key:?}"
    );
}
