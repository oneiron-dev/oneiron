//! FIX [HOSTED-REROOT-FOLD-RULE] option A (Engine RULING
//! HOSTED-REROOT-ADMISSION-DOORS = C, 15 Nov 23:31: "C now, and A as a
//! planned row"): the fold never counts a `ReRoot` signed by a key without
//! the host's stamp (`ROLE_CLOUD` or tier `CloudCustodial`) while the
//! roster holds a live owner key with that stamp, a hosted vault's live host
//! root. Such a move revokes every roster row, the host root included, and
//! every slip the host minted stops verifying (NOTE WAYBACK-REROOT-TRACE,
//! 15 Nov 22:02). The rule sits in the fold, so it reaches every door and
//! every row a vault already holds.
//!
//! Pure folds over hand-signed rows (the fixture of `owner_key_revoke_proof`:
//! a genesis root, its registration of a hosted node, the root's fold-only
//! enrolment of an owner device key), and a hosted vault's own doors: the
//! kit's recovery door and the signed-history import.
//!
//! Red on main 26f4e0c559a2 (main plus this file): the hosted owner-key
//! move counts, the kit door's move lands and the imported move counts, each
//! revoking the host root. The host's own move and the self-hosted moves
//! count on both.
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test hosted_reroot_fold_rule`.

#![cfg(oneiron_test_support)]

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use ed25519_dalek::{Signer, SigningKey};
use oneiron::authority::{
    AUTHORITY_LOG_SCHEMA_VERSION, ActAuthority, ActSurface, AuthorityAttestation,
    AuthorityEntryHash, AuthorityFold, AuthorityKey, AuthorityLogEntry, AuthorityOp,
    AuthoritySignature, AuthorityTier, AuthorityVaultId, DeviceAuthority, GenesisRecoveryStep,
    HostSlipIssuer, MACHINE_ENCRYPTION_KEY_LEN, MACHINE_ENCRYPTION_SUITE_HYBRID_V1,
    MachineDeviceClass, MachineEncryptionKey, MachineProfile, MachineRole, OwnerAct, OwnerActKind,
    OwnerKeyEnrollment, ROLE_ADMIN, ROLE_CLOUD, ROLE_OWNER, authority_entry_hash,
    authority_transcript, decode_authority_log_entry_body, encode_authority_log_entry_body,
    fold_authority_log, fold_authority_log_for_posture, genesis_vault_id,
    machine_profile_proof_transcript,
};
use oneiron::consent::AuthenticatedOwner;
use oneiron::recovery::{
    KitIssue, KitPiece, KitSecretKind, PassphraseCost, PieceHome, RestoredKitSecret,
    issue_recovery_root_kit, restore_kit,
};
use oneiron::store::GateDecisionId;
use oneiron::test_support::{bind_host_owner, provision_engine_machines};
use oneiron::world_keys::RecoveryRootSeed;
use oneiron::{EntityId, HostingPrivacyPosture, Vault, VaultConfig};
use oneiron_authority::authority::{
    OWNER_KEY_ENROLLMENT_SEEN, OWNER_KEY_POSSESSION_KIND, OwnerKeyEnroll,
    owner_key_enrollment_challenge, owner_key_enrollment_target, roster_has_live_owner,
};

/// The pure folds' root and hosted node.
const ROOT_SEED: u8 = 61;
const NODE_SEED: u8 = 62;
/// The owner device key the pure folds' root enrols.
const OWNER_KEY_SEED: u8 = 71;
/// The seed of every move's successor.
const SUCCESSOR_SEED: u8 = 35;
/// The seed of the host's next root, for the host's own move.
const NEXT_HOST_ROOT_SEED: u8 = 36;
/// The seed of the owner's device key a vault door enrols.
const DEVICE_KEY_SEED: u8 = 21;

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

/// `signer` signs `op` on `parent_hashes` at `ts`, with one cosign by each of
/// `cosigners`. Every key is in the entry before any of them signs, so all
/// of them sign the same transcript.
fn signed(
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
    let overlay_seed = oneiron_authority::authority::authority_overlay_seed_for(&op)
        .expect("authority overlay seed");
    let mut row = AuthorityLogEntry {
        schema_version: AUTHORITY_LOG_SCHEMA_VERSION,
        vault_id,
        seq,
        parent_hashes,
        op,
        overlay_seed,
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

/// A device of `seed`'s key holding `roles` at `tier`.
fn device(seed: u8, roles: u16, tier: AuthorityTier) -> DeviceAuthority {
    DeviceAuthority {
        key: key_of(&signing(seed)),
        transport_key_binding: [7; 32],
        attestation: AuthorityAttestation {
            kind: "SoftwareArgon2id".to_owned(),
            evidence: vec![1, 2, 3],
        },
        tier,
        roles,
    }
}

/// The successor every owner-key move names: the owner role alone, within
/// the signer's.
fn successor() -> DeviceAuthority {
    device(SUCCESSOR_SEED, ROLE_OWNER, AuthorityTier::Software)
}

fn owner() -> EntityId {
    EntityId::from_bytes([0x71; 16]).expect("an id")
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
        restored_from: None,
    }
}

/// Hand-signed rows of a vault whose root registered one hosted node, the
/// holder and carrier of every owner key enrolment.
struct HandSignedVault {
    root: SigningKey,
    node: SigningKey,
    machine: EntityId,
    rows: Vec<AuthorityLogEntry>,
    /// A managed host's vault: its root is the host's custodial key, and
    /// replicas fold under the hosted posture.
    hosted: bool,
}

impl HandSignedVault {
    /// A managed host's vault: its root carries the host's stamp.
    fn on_a_hosted_vault() -> Self {
        Self::with_root(
            ROLE_OWNER | ROLE_ADMIN | ROLE_CLOUD,
            AuthorityTier::CloudCustodial,
            true,
        )
    }

    /// A self-host vault: its root is an owner-held key with no stamp.
    fn self_hosted() -> Self {
        Self::with_root(ROLE_OWNER | ROLE_ADMIN, AuthorityTier::Software, false)
    }

    fn with_root(roles: u16, tier: AuthorityTier, hosted: bool) -> Self {
        let root = signing(ROOT_SEED);
        let node = signing(NODE_SEED);
        let genesis = signed(
            None,
            0,
            Vec::new(),
            AuthorityOp::Genesis {
                device: device(ROOT_SEED, roles, tier),
                genesis_nonce: [196; 32],
                recovery: GenesisRecoveryStep::Saved([1; 32]),
            },
            &root,
            &[],
            1,
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
            )),
            &root,
            &[],
            1,
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

    fn registration(&self) -> AuthorityEntryHash {
        hash(&self.rows[1])
    }

    /// The fold of the rows a replica holds, under the hosted posture on a
    /// managed host's vault.
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

    /// The root enrols `new_key` as an owner key at `seq` on `parent`,
    /// carried by the node: the fold-only `OwnerKeyEnroll` row the fold
    /// counts. Returns its hash.
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
        let row = signed(
            Some(vault_id),
            seq,
            vec![parent],
            op,
            &self.root,
            &[&self.node],
            1,
        );
        let entry = hash(&row);
        self.rows.push(row);
        entry
    }

    /// A `ReRoot` to `new_device` at `seq` on `parent`, signed by `signer`
    /// alone. Returns its hash.
    fn re_root(
        &mut self,
        seq: u64,
        parent: AuthorityEntryHash,
        new_device: DeviceAuthority,
        signer: &SigningKey,
    ) -> AuthorityEntryHash {
        let row = signed(
            Some(self.vault_id()),
            seq,
            vec![parent],
            AuthorityOp::ReRoot { new_device },
            signer,
            &[],
            1,
        );
        let entry = hash(&row);
        self.rows.push(row);
        entry
    }
}

fn live_owner(fold: &AuthorityFold, key: &AuthorityKey) -> bool {
    roster_has_live_owner(&fold.roster, key)
}

/// Test 1. Main: the move counts and revokes the host root.
#[test]
fn a_re_root_by_an_owner_key_the_host_does_not_hold_never_counts_on_a_hosted_fold() {
    let mut vault = HandSignedVault::on_a_hosted_vault();
    let key = signing(OWNER_KEY_SEED);
    let registration = vault.registration();
    let enrolment = vault.enrol(2, registration, &key);
    let host_root = key_of(&vault.root);
    let fold = vault.fold();
    assert!(
        fold.valid_entries.contains(&enrolment) && live_owner(&fold, &key_of(&key)),
        "guard: the owner key is enrolled live, so the test cannot pass for the wrong reason"
    );
    let re_root = vault.re_root(1, enrolment, successor(), &key);
    let fold = vault.fold();
    assert!(
        !fold.valid_entries.contains(&re_root),
        "a ReRoot by an owner key without the host's stamp never counts while the host root is live: {re_root:?}"
    );
    assert!(
        live_owner(&fold, &host_root),
        "the host root stays live: {host_root:?}"
    );
    assert!(
        live_owner(&fold, &key_of(&key)),
        "the signer's own key stays live"
    );
    assert!(
        !live_owner(&fold, &successor().key),
        "the move's successor never stands"
    );
}

/// Test 2. Main: the same; the host's own move counts.
#[test]
fn the_hosts_own_re_root_still_counts_on_a_hosted_fold() {
    let mut vault = HandSignedVault::on_a_hosted_vault();
    let registration = vault.registration();
    let host_root = key_of(&vault.root);
    let next = device(
        NEXT_HOST_ROOT_SEED,
        ROLE_OWNER | ROLE_ADMIN | ROLE_CLOUD,
        AuthorityTier::CloudCustodial,
    );
    let next_key = next.key.clone();
    let root = vault.root.clone();
    let re_root = vault.re_root(2, registration, next, &root);
    let fold = vault.fold();
    assert!(
        fold.valid_entries.contains(&re_root),
        "the host's own move, signed by its stamped root, still counts: {re_root:?}"
    );
    assert!(live_owner(&fold, &next_key), "the host's next root stands");
    assert!(
        !live_owner(&fold, &host_root),
        "the move retires the old host root"
    );
}

/// Test 3. Main: the same; a self-host root carries no stamp.
#[test]
fn a_self_hosted_re_root_by_an_owner_key_still_counts() {
    let mut vault = HandSignedVault::self_hosted();
    let key = signing(OWNER_KEY_SEED);
    let registration = vault.registration();
    let enrolment = vault.enrol(2, registration, &key);
    let root = key_of(&vault.root);
    let re_root = vault.re_root(1, enrolment, successor(), &key);
    let fold = vault.fold();
    assert!(
        fold.valid_entries.contains(&re_root),
        "a self-host vault's owner-key move still counts: {re_root:?}"
    );
    assert!(live_owner(&fold, &successor().key), "the successor stands");
    assert!(
        !live_owner(&fold, &root),
        "the move retires the self-host root"
    );
}

fn proof(vault: &Vault, person: EntityId) -> AuthenticatedOwner {
    vault
        .authenticate_owner(person, &person.to_hex(), true, GateDecisionId::now())
        .expect("an owner proof")
}

fn live(vault: &Vault, key: &AuthorityKey) -> bool {
    vault
        .authority_fold()
        .expect("the fold")
        .roster
        .get(key)
        .is_some_and(|device| !device.revoked)
}

/// A vault rooted under `issuer`, with one enrolled owner device key and the
/// kit root's authority key (R) enrolled live, both by the host root.
struct DoorFixture {
    _dir: tempfile::TempDir,
    vault: Vault,
    issuer: HostSlipIssuer,
    vault_id: [u8; 32],
    device_signing: SigningKey,
    root_key: AuthorityKey,
    pieces: Vec<KitPiece>,
}

fn door_fixture(posture: HostingPrivacyPosture) -> DoorFixture {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut config = VaultConfig::device();
    config.privacy.posture = posture;
    let vault = Vault::open(dir.path(), config).expect("the vault");
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    let issuer = provision_engine_machines(&vault);
    let role = if posture == HostingPrivacyPosture::Hosted {
        MachineRole::HostedNode
    } else {
        MachineRole::Unanswered
    };
    vault
        .ensure_serving_install_profile(&issuer, role)
        .expect("this install's live machine profile");
    let person = vault.ensure_embedded_owner_actor().expect("the owner");
    bind_host_owner(&vault, &issuer, person).expect("the owner's binding");
    let vault_id = vault
        .authority_fold()
        .expect("the fold")
        .vault_id
        .expect("a rooted vault");
    let machine = vault
        .prepare_install_signing()
        .expect("this install's machine");
    let authority = ActAuthority::Owner(proof(&vault, person), ActSurface::ThisInstall);

    let device_signing = signing(DEVICE_KEY_SEED);
    let public_key = device_signing.verifying_key().to_bytes();
    let challenge = vault
        .owner_key_enrollment_challenge_as(&authority, machine, &public_key)
        .expect("the challenge");
    vault
        .enrol_owner_signing_key_as_host(
            &authority,
            OwnerKeyEnrollment {
                machine,
                public_key,
                proof: device_signing.sign(&challenge).to_bytes().to_vec(),
            },
            &issuer,
        )
        .expect("the owner enrols a device key");

    let seed = RecoveryRootSeed::generate().expect("a root seed");
    let pieces = issue_recovery_root_kit(
        &KitIssue {
            vault_id,
            homes: [
                PieceHome::ThisMachine,
                PieceHome::OtherMachine(EntityId::now()),
                PieceHome::OtherMachine(EntityId::now()),
            ],
            passphrase: None,
            cost: PassphraseCost::FLOOR,
            only_machine: false,
        },
        &seed.kit_bytes(),
    )
    .expect("the kit")
    .into_pieces();
    let restored =
        RecoveryRootSeed::from_restored_kit(restored_kit(vault_id, &pieces)).expect("the seed");
    let receipt = vault
        .enrol_recovery_authority_key_as_host(&authority, machine, &restored, &issuer)
        .expect("the owner enrols the root's authority key");
    let fixture = DoorFixture {
        _dir: dir,
        vault,
        issuer,
        vault_id,
        device_signing,
        root_key: AuthorityKey::Ed25519(receipt.public_key),
        pieces,
    };
    assert!(
        live(&fixture.vault, &fixture.root_key)
            && live(&fixture.vault, &fixture.issuer.public_key())
            && live(&fixture.vault, &key_of(&fixture.device_signing)),
        "guard: R, the host root and the device key are live"
    );
    fixture
}

/// The kit's secret, from two of its stored `pieces`.
fn restored_kit(vault_id: [u8; 32], pieces: &[KitPiece]) -> RestoredKitSecret {
    restore_kit(
        vault_id,
        KitSecretKind::RecoveryRoot,
        &[&pieces[0], &pieces[1]],
        None,
    )
    .expect("two stored pieces restore the seed")
}

impl DoorFixture {
    fn restored(&self) -> RestoredKitSecret {
        restored_kit(self.vault_id, &self.pieces)
    }

    fn history(&self) -> Vec<AuthorityLogEntry> {
        self.vault
            .export_signed_authority_history()
            .expect("the signed history")
            .iter()
            .map(|row| decode_authority_log_entry_body(row).expect("a row"))
            .collect()
    }

    /// The stored history's heads, which a new main-log entry names.
    fn heads(&self) -> Vec<AuthorityEntryHash> {
        let rows = self.history();
        let parents: BTreeSet<AuthorityEntryHash> = rows
            .iter()
            .flat_map(|row| row.parent_hashes.iter().copied())
            .collect();
        let mut heads: Vec<AuthorityEntryHash> = rows
            .iter()
            .map(hash)
            .filter(|row| !parents.contains(row))
            .collect();
        heads.sort_unstable();
        heads.dedup();
        heads
    }
}

/// Test 4. Main: the kit door's move lands and revokes the host root.
#[test]
fn the_kit_door_never_re_roots_a_hosted_vault_whose_host_root_serves() {
    let fixture = door_fixture(HostingPrivacyPosture::Hosted);
    let before = fixture.history().len();
    let host_root = fixture.issuer.public_key();
    let moved = fixture
        .vault
        .recover_owner_authority_from_kit(fixture.restored(), successor());
    assert!(
        moved.is_err(),
        "the kit's ReRoot on a hosted vault whose host root is live is refused: {moved:?}"
    );
    assert_eq!(
        fixture.history().len(),
        before,
        "the refused move writes nothing"
    );
    assert!(
        live(&fixture.vault, &host_root) && live(&fixture.vault, &fixture.root_key),
        "the host root and R stay live"
    );
    assert!(
        !live(&fixture.vault, &successor().key),
        "the successor never stands"
    );
}

/// Test 5. Main: the import lands the move, which revokes the host root.
#[test]
fn a_re_root_imported_by_an_owner_key_the_host_does_not_hold_never_counts() {
    let fixture = door_fixture(HostingPrivacyPosture::Hosted);
    let host_root = fixture.issuer.public_key();
    let now = fixture.vault.now_recorded_at();
    let row = signed(
        Some(fixture.vault_id),
        1,
        fixture.heads(),
        AuthorityOp::ReRoot {
            new_device: successor(),
        },
        &fixture.device_signing,
        &[],
        now,
    );
    let moved = hash(&row);
    let blob = encode_authority_log_entry_body(&row).expect("the row's bytes");
    // The store door may hold the row or refuse it; either way it never
    // counts.
    let _answer = fixture
        .vault
        .import_signed_authority_history(&[blob], &std::collections::BTreeMap::new());
    let fold = fixture.vault.authority_fold().expect("the fold");
    assert!(
        !fold.valid_entries.contains(&moved),
        "an imported ReRoot by an owner key without the host's stamp never counts: {moved:?}"
    );
    assert!(live(&fixture.vault, &host_root), "the host root stays live");
    assert!(
        !live(&fixture.vault, &successor().key),
        "the successor never stands"
    );
}

/// Test 6. Main: the same; a self-host root carries no stamp.
#[test]
fn the_kit_door_still_re_roots_a_self_hosted_vault() {
    let fixture = door_fixture(HostingPrivacyPosture::SelfHostLocal);
    let moved = fixture
        .vault
        .recover_owner_authority_from_kit(fixture.restored(), successor())
        .expect("the kit still moves a self-hosted vault's authority");
    let fold = fixture.vault.authority_fold().expect("the fold");
    assert!(
        fold.valid_entries.contains(&hash(&moved)),
        "the kit's move counts on a self-hosted vault"
    );
    assert!(
        live(&fixture.vault, &successor().key),
        "the successor stands"
    );
}
