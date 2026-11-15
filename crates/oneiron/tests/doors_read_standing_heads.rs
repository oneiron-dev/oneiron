#![cfg(oneiron_test_support)]
//! Red/green tests for FOREIGN-ANCHOR PR 2 (K2 of Fable design pass 29): the
//! doors read the heads a machine stands under on this install (FIX
//! [FOREIGN-ANCHOR-CHAIN-COUNTS-IN-EVERY-CHAIN-PREDICATES]; Engine RULINGs
//! FOREIGN-ANCHOR-FOLD-JUDGE-RULE = C, 16 Nov 05:10, and 06:15: "a chain is
//! read only by a reader that believes its admitter").
//!
//! Any fresh key publishes an owner root, and that root's anchor marks any
//! machine in its own chain (removed, answered, under other keys). The door
//! predicates below read every chain (`FoldedMachine::chains`,
//! `anchored.values` or `names_key`), so one stranger's mark refused or
//! admitted things on installs that pin no such root. They now read the
//! standing heads (the roster's head, then the head of the chain of the
//! anchor the install pins), plus the accepted roster revisions where the
//! site already read them.
//!
//! Each test serves a self-host vault that pins no root, so a machine stands
//! under the roster's head alone; publishes a stranger's root; stores one of
//! its marks; and drives one door. Every test fails at the base (PR 1, #8673)
//! and passes at the head; each test's doc states the expected red failure.

use std::collections::BTreeSet;
use std::sync::Arc;

use ed25519_dalek::{Signer, SigningKey};
use oneiron::authority::{
    AUTHORITY_LOG_SCHEMA_VERSION, ActSurface, AuthorityEntryHash, AuthorityKey, AuthorityLogEntry,
    AuthorityOp, AuthoritySignature, AuthorityVaultId, HostSlipIssuer, MACHINE_ENCRYPTION_KEY_LEN,
    MACHINE_ENCRYPTION_SUITE_HYBRID_V1, MachineDeviceClass, MachineEncryptionKey,
    MachineEnrolmentRequest, MachineOwnership, MachineProfile, MachineRole, MeshMachineAddress,
    OwnerRootRecord, authority_entry_hash, authority_transcript, machine_profile_proof_transcript,
    pairing_binding_transcript,
};
use oneiron::consent::AuthenticatedOwner;
use oneiron::federation::Scope;
use oneiron::registry::ENTITY_TYPE_MACHINE;
use oneiron::store::GateDecisionId;
#[cfg(feature = "sync")]
use oneiron::test_doors::carrier_proof::carrier_proof_disproves;
use oneiron::test_doors::profiles_other_machine::profiles_other_machine;
use oneiron::world_keys::RecoveryRootSeed;
use oneiron::{EntityId, TimeRange, Vault, VaultConfig};
use oneiron_authority::authority::machine_answer_revision;

/// The seed of the joining machine's machine key.
const JOINING_SEED: u8 = 68;
/// The seed of the machine key a stranger holds for the machine it marks.
const STRANGER_MACHINE_SEED: u8 = 71;
/// The seed of the connection key a pairing redemption binds.
const CONNECTION_SEED: u8 = 83;
/// The seed of a mesh endpoint's transport key.
const TRANSPORT_SEED: u8 = 84;
/// The stored rows' occurred range and learned-at, as the store-door tests use.
const AT: TimeRange = TimeRange { start: 2, end: 2 };
/// The ALPN the mesh test grants.
const MESH_ALPN: &[u8] = b"mesh/test";
/// The custody view's secret name; nothing live holds it, which the view allows.
const PROBE_SECRET: &str = "door-heads-probe";

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

/// The stranger root's owner person, distinct from the vault's owner.
fn stranger_owner() -> EntityId {
    EntityId::from_bytes([0xA1; 16]).expect("an id")
}

/// A self-host vault as its own server starts one: this install serving and
/// profiled under the host root, and the owner bound and authenticated. It
/// pins no root, so a machine stands under the roster's head alone.
struct ServedVault {
    vault: Vault,
    owner: AuthenticatedOwner,
    /// This install, the carrier of every owner act its doors sign.
    carrier: EntityId,
    issuer: HostSlipIssuer,
    _dir: tempfile::TempDir,
}

/// A self-host vault rooted under the host root before its first serving
/// start: no chain profiles this install yet.
fn unprofiled_self_host() -> (Vault, HostSlipIssuer, tempfile::TempDir) {
    let dir = tempfile::tempdir().expect("vault directory");
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("self-host vault");
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    let issuer = oneiron::test_support::provision_engine_machines(&vault);
    (vault, issuer, dir)
}

fn vault_id_of(vault: &Vault) -> AuthorityVaultId {
    vault
        .authority_fold()
        .expect("authority fold")
        .vault_id
        .expect("the vault is rooted")
}

/// The mesh binding transcript both binding proofs sign: the binding domain,
/// the MACHINE row, the endpoint key (`authority/mesh_machine.rs`, copied).
fn mesh_binding_transcript(machine: EntityId, endpoint_key: [u8; 32]) -> Vec<u8> {
    let mut bytes = b"oneiron/mesh-machine-binding/v1\0".to_vec();
    bytes.extend_from_slice(machine.as_bytes());
    bytes.extend_from_slice(&endpoint_key);
    bytes
}

/// A MACHINE row stored as a host stores one, with no profile.
fn machine_row(vault: &Vault) -> EntityId {
    let id = EntityId::now();
    vault
        .batch()
        .put(&id, ENTITY_TYPE_MACHINE, AT, 2, b"system machine")
        .commit()
        .expect("the MACHINE row is stored");
    id
}

impl ServedVault {
    fn self_host() -> Self {
        let (vault, issuer, dir) = unprofiled_self_host();
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
            carrier,
            issuer,
            _dir: dir,
        }
    }

    fn vault_id(&self) -> AuthorityVaultId {
        vault_id_of(&self.vault)
    }

    /// This install's roster head.
    fn carrier_roster(&self) -> oneiron::authority::MachineRevision {
        self.vault
            .authority_fold()
            .expect("authority fold")
            .machine(self.carrier)
            .and_then(|folded| folded.roster.clone())
            .expect("guard: this install has a roster chain")
    }

    /// Another machine's request to join this vault.
    fn joining_machine(&self) -> MachineEnrolmentRequest {
        self.request_for(
            EntityId::from_bytes([0x76; 16]).expect("an id"),
            &signing(JOINING_SEED),
        )
    }

    /// `machine`'s identity under the machine key `node`, with its own proof.
    fn request_for(&self, machine: EntityId, node: &SigningKey) -> MachineEnrolmentRequest {
        let vault_id = self.vault_id();
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
        }
    }

    /// The owner enrols `request` as his own, carried by this install.
    fn enrol(&self, request: &MachineEnrolmentRequest) -> oneiron::Result<()> {
        self.vault
            .enroll_machine(
                &self.owner,
                ActSurface::ThisInstall,
                request,
                MachineRole::Owned(MachineOwnership::Yours),
                None,
            )
            .map(drop)
    }
}

/// A stranger's root published on one held valid row and stored. Returns its
/// anchor signing key and the root row's hash.
fn publish_stranger_root(vault: &Vault) -> (SigningKey, AuthorityEntryHash) {
    let vault_id = vault_id_of(vault);
    let seed = RecoveryRootSeed::generate().expect("a fresh stranger root seed");
    let root = seed
        .public(&vault_id)
        .expect("the stranger root's public half");
    let anchor = seed.anchor();
    let parent = vault
        .authority_fold()
        .expect("authority fold for a parent")
        .valid_entries
        .iter()
        .next()
        .copied()
        .expect("guard: the vault holds a valid row for the root's parent");
    let record = OwnerRootRecord {
        owner: stranger_owner(),
        root: root.id,
        recovery_key: MachineEncryptionKey {
            suite: MACHINE_ENCRYPTION_SUITE_HYBRID_V1,
            key: root.recovery_key.to_bytes(),
        },
        anchor_key: root.anchor_key,
    };
    let entry = signed(
        vault_id,
        1,
        vec![parent],
        AuthorityOp::OwnerRoot(record),
        &anchor,
    );
    let root_hash = hash(&entry);
    vault
        .put_authority_log_entry(&entry, AT, 2)
        .expect("the stranger's root row is stored");
    assert!(
        vault
            .authority_fold()
            .expect("authority fold")
            .valid_entries
            .contains(&root_hash),
        "guard: the stranger's root is in valid_entries"
    );
    (anchor, root_hash)
}

/// The stranger's anchor marks M under M's own keys and proof, and the mark
/// is stored. Returns the mark's hash. No main-log join: the doors under test
/// read the fold, which folds the mark wherever it sits.
fn stranger_mark_with_m_keys(
    vault: &Vault,
    vault_id: AuthorityVaultId,
    root: AuthorityEntryHash,
    anchor: &SigningKey,
    request: &MachineEnrolmentRequest,
    role: MachineRole,
    revision: u64,
) -> AuthorityEntryHash {
    let profile = MachineProfile {
        machine: request.machine,
        owner: stranger_owner(),
        machine_key: request.machine_key,
        device_class: request.device_class,
        encryption_key: request.encryption_key.clone(),
        role,
        revision,
        machine_proof: request.machine_proof,
        seen_world_edits: BTreeSet::new(),
        carrier: None,
        act: None,
    };
    let entry = signed(
        vault_id,
        2,
        vec![root],
        AuthorityOp::MachineProfile(profile),
        anchor,
    );
    let mark = hash(&entry);
    vault
        .put_authority_log_entry(&entry, AT, 2)
        .expect("the stranger's mark is stored");
    mark
}

/// The stranger's anchor marks a machine by cloning `template` (a profile
/// whose proof verifies for its keys) into `role` at `revision` under the
/// stranger owner, and the mark is stored. Returns the mark's hash.
fn stranger_mark_cloning(
    vault: &Vault,
    vault_id: AuthorityVaultId,
    root: AuthorityEntryHash,
    anchor: &SigningKey,
    template: &MachineProfile,
    role: MachineRole,
    revision: u64,
) -> AuthorityEntryHash {
    let profile = MachineProfile {
        owner: stranger_owner(),
        role,
        revision,
        carrier: None,
        act: None,
        ..template.clone()
    };
    let entry = signed(
        vault_id,
        2,
        vec![root],
        AuthorityOp::MachineProfile(profile),
        anchor,
    );
    let mark = hash(&entry);
    vault
        .put_authority_log_entry(&entry, AT, 2)
        .expect("the stranger's mark is stored");
    mark
}

/// Guard: the stranger's mark `mark` of `machine` is valid and folded in the
/// stranger's chain, and the roster's chain stays live.
fn guard_stranger_mark(
    served: &ServedVault,
    machine: EntityId,
    anchor: &SigningKey,
    mark: AuthorityEntryHash,
) {
    let fold = served.vault.authority_fold().expect("authority fold");
    assert!(
        fold.valid_entries.contains(&mark),
        "guard: the stranger's mark is in valid_entries"
    );
    assert!(
        fold.machine(machine)
            .and_then(|folded| folded.anchored.get(&anchor.verifying_key().to_bytes()))
            .is_some(),
        "guard: the stranger's chain holds the mark"
    );
    assert!(
        fold.machine(machine)
            .and_then(|folded| folded.roster.as_ref())
            .is_some_and(|chain| chain.is_live()),
        "guard: the roster chain stays live"
    );
}

/// Site S3: a stranger's removal mark of a machine closes no mesh grant and
/// revokes no mesh binding. M is enrolled, bound and granted; then a stranger
/// removes M in its own chain.
///
/// RED: the `mesh_grant_permits` assert fails, seeing `Ok(false)`: the
/// binding check and the grant check read `machine_removed` over every chain.
/// (The `revoke_removed_machine_mesh` assert would fail next, seeing `true`.)
/// GREEN: the grant still permits and the revoke door reports `false`.
#[test]
fn a_strangers_removal_mark_of_a_machine_closes_no_mesh_grant() {
    let served = ServedVault::self_host();
    let request = served.joining_machine();
    served.enrol(&request).expect("the owner enrols M");
    let machine = request.machine;

    let connection = signing(CONNECTION_SEED);
    let connection_key = connection.verifying_key().to_bytes();
    let link = served
        .vault
        .issue_pairing_link(&served.issuer, Scope::top(), 3600)
        .expect("a pairing link");
    let holder = machine.to_hex();
    let proof = connection
        .sign(
            &pairing_binding_transcript(&link.code, &connection_key, &holder)
                .expect("the binding transcript"),
        )
        .to_bytes();
    let slip = served
        .vault
        .redeem_pairing_link(&served.issuer, &link.code, &holder, connection_key, &proof)
        .expect("M's holder redeems the link");
    let transport = signing(TRANSPORT_SEED);
    let endpoint = transport.verifying_key().to_bytes();
    let address = MeshMachineAddress {
        endpoint_key: endpoint,
        direct_addrs: vec![],
        relay_url: None,
    };
    let transcript = mesh_binding_transcript(machine, endpoint);
    let device_proof = connection.sign(&transcript).to_bytes();
    let transport_proof = transport.sign(&transcript).to_bytes();
    served
        .vault
        .bind_mesh_machine(
            &served.issuer,
            machine,
            address,
            connection_key,
            slip.claims.slip_id,
            [&device_proof, &transport_proof],
        )
        .expect("M's mesh binding lands");
    served
        .vault
        .set_mesh_alpn_grant(&served.issuer, machine, endpoint, MESH_ALPN, true)
        .expect("M's mesh grant lands");
    assert!(
        served
            .vault
            .mesh_grant_permits(machine, endpoint, MESH_ALPN)
            .expect("guard: the grant check reads"),
        "guard: M's mesh grant permits before the stranger's mark"
    );

    let (anchor, root) = publish_stranger_root(&served.vault);
    let mark = stranger_mark_with_m_keys(
        &served.vault,
        served.vault_id(),
        root,
        &anchor,
        &request,
        MachineRole::Removed,
        1,
    );
    guard_stranger_mark(&served, machine, &anchor, mark);
    assert!(
        served
            .vault
            .authority_fold()
            .expect("authority fold")
            .machine(machine)
            .and_then(|folded| folded.anchored.get(&anchor.verifying_key().to_bytes()))
            .is_some_and(|chain| chain.removed),
        "guard: the stranger's chain holds M removed"
    );

    assert!(
        served
            .vault
            .mesh_grant_permits(machine, endpoint, MESH_ALPN)
            .expect("the grant check reads"),
        "a stranger's removal mark of M closed its mesh grant"
    );
    assert!(
        !served
            .vault
            .revoke_removed_machine_mesh(&served.issuer, machine)
            .expect("the revoke check reads"),
        "a stranger's removal mark of M revoked its mesh binding"
    );
}

/// Site S6: the owner's answer `seen` check ignores a stranger root's mark. M
/// is enrolled; a stranger marks M owned in its own chain; the owner removes
/// M naming the roster head's revision, the revision the head computes.
///
/// RED: the `set_machine_role` expect fails with
/// `Error::ConcurrentWrite("the machine's answer changed since it was
/// read")`: the base numbers the revision over every chain's head.
/// GREEN: the removal lands at roster revision 2.
#[test]
fn an_owner_answer_seen_ignores_a_stranger_roots_mark() {
    let served = ServedVault::self_host();
    let request = served.joining_machine();
    served.enrol(&request).expect("the owner enrols M");
    let machine = request.machine;

    let (anchor, root) = publish_stranger_root(&served.vault);
    let mark = stranger_mark_with_m_keys(
        &served.vault,
        served.vault_id(),
        root,
        &anchor,
        &request,
        MachineRole::Owned(MachineOwnership::Yours),
        1,
    );
    guard_stranger_mark(&served, machine, &anchor, mark);

    let roster = served
        .vault
        .authority_fold()
        .expect("authority fold")
        .machine(machine)
        .and_then(|folded| folded.roster.clone())
        .expect("guard: M has a roster chain");
    assert_eq!(
        roster.profile.revision, 1,
        "guard: M's roster head is at revision 1"
    );
    let seen = machine_answer_revision([roster.entry]);
    served
        .vault
        .set_machine_role(
            &served.owner,
            ActSurface::ThisInstall,
            machine,
            MachineRole::Removed,
            Some(seen),
        )
        .expect("the owner's removal lands beside a stranger's mark that moves no revision");

    let roster = served
        .vault
        .authority_fold()
        .expect("authority fold")
        .machine(machine)
        .and_then(|folded| folded.roster.clone())
        .expect("M has a roster chain after the removal");
    assert_eq!(
        roster.profile.role,
        MachineRole::Removed,
        "M's roster head is removed"
    );
    assert_eq!(
        roster.profile.revision, 2,
        "M's roster head is at revision 2"
    );
}

/// Site S7: a stranger's removal mark keeps a machine a custody candidate. M
/// is enrolled and a candidate; then a stranger removes M in its own chain.
///
/// RED: the second candidates assert fails: the view lists no candidate for
/// M, since `live_revisions` empties on any chain's removal.
/// GREEN: M is still a candidate.
#[test]
fn a_strangers_removal_mark_keeps_a_machine_a_custody_candidate() {
    let served = ServedVault::self_host();
    let request = served.joining_machine();
    served.enrol(&request).expect("the owner enrols M");
    let machine = request.machine;

    let view = served
        .vault
        .secret_custody_view(&served.owner, PROBE_SECRET)
        .expect("the custody view reads");
    assert!(
        view.candidates
            .iter()
            .any(|candidate| candidate.permit.machine == machine),
        "guard: M is a custody candidate before the stranger's mark"
    );

    let (anchor, root) = publish_stranger_root(&served.vault);
    let mark = stranger_mark_with_m_keys(
        &served.vault,
        served.vault_id(),
        root,
        &anchor,
        &request,
        MachineRole::Removed,
        1,
    );
    guard_stranger_mark(&served, machine, &anchor, mark);

    let view = served
        .vault
        .secret_custody_view(&served.owner, PROBE_SECRET)
        .expect("the custody view reads");
    assert!(
        view.candidates
            .iter()
            .any(|candidate| candidate.permit.machine == machine),
        "a stranger's removal mark of M dropped it from the custody candidates"
    );
}

/// Site O1: the kit push refuses a live install beside a stranger root's
/// removal. This install's roster profile is live; a stranger removes this
/// install in its own chain; the owner pushes with the kit.
///
/// RED: the message assert fails, seeing
/// `InvalidConfig("the seed's root is not the root this vault pins")`: the
/// base lets the stranger's removal pass the kit gate and falls through to
/// the pin check.
/// GREEN: the door refuses with the live-machine-profile reason.
#[test]
fn a_kit_push_refuses_a_live_install_beside_a_stranger_roots_removal() {
    let served = ServedVault::self_host();
    let (anchor, root) = publish_stranger_root(&served.vault);
    let roster = served.carrier_roster();
    let mark = stranger_mark_cloning(
        &served.vault,
        served.vault_id(),
        root,
        &anchor,
        &roster.profile,
        MachineRole::Removed,
        1,
    );
    guard_stranger_mark(&served, served.carrier, &anchor, mark);

    let seed = RecoveryRootSeed::generate().expect("a kit seed");
    let error = served
        .vault
        .sign_custody_with_anchor(&served.owner, &seed, PROBE_SECRET, &[], 2)
        .expect_err("a live install never pushes with the kit");
    assert!(
        format!("{error:?}").contains("live machine profile"),
        "unexpected kit refusal: {error:?}"
    );
}

/// Site O2: the carrier proof stays unproven beside a stranger root's
/// removal. M is enrolled; a stranger removes M in its own chain; the proof
/// of a key that is neither admitted nor a roster key is read.
///
/// RED: the assert fails, seeing disproven: the removed arm reads every
/// chain.
/// GREEN: the key is unproven.
#[cfg(feature = "sync")]
#[test]
fn a_carrier_proof_stays_unproven_beside_a_stranger_roots_removal() {
    let served = ServedVault::self_host();
    let request = served.joining_machine();
    served.enrol(&request).expect("the owner enrols M");
    let machine = request.machine;

    let (anchor, root) = publish_stranger_root(&served.vault);
    let mark = stranger_mark_with_m_keys(
        &served.vault,
        served.vault_id(),
        root,
        &anchor,
        &request,
        MachineRole::Removed,
        1,
    );
    guard_stranger_mark(&served, machine, &anchor, mark);

    let fold = served.vault.authority_fold().expect("authority fold");
    let probe = signing(STRANGER_MACHINE_SEED).verifying_key().to_bytes();
    assert_ne!(
        probe, request.machine_key,
        "guard: the probe key is not M's own"
    );
    assert!(
        !carrier_proof_disproves(&fold, machine, &probe),
        "a stranger's removal mark of M disproved an unproven key"
    );
}

/// Site O7: the tick release sees a machine beside a stranger root's
/// removal. M is enrolled, so another machine stands; then a stranger removes
/// M in its own chain.
///
/// RED: the second assert fails, seeing `false`: any chain's removal hides M.
/// GREEN: M still counts as another machine.
#[test]
fn the_tick_release_sees_a_machine_beside_a_stranger_roots_removal() {
    let served = ServedVault::self_host();
    let request = served.joining_machine();
    served.enrol(&request).expect("the owner enrols M");
    let machine = request.machine;

    assert!(
        profiles_other_machine(&served.vault, Some(served.carrier))
            .expect("guard: the tick check reads"),
        "guard: M counts as another machine before the stranger's mark"
    );

    let (anchor, root) = publish_stranger_root(&served.vault);
    let mark = stranger_mark_with_m_keys(
        &served.vault,
        served.vault_id(),
        root,
        &anchor,
        &request,
        MachineRole::Removed,
        1,
    );
    guard_stranger_mark(&served, machine, &anchor, mark);

    assert!(
        profiles_other_machine(&served.vault, Some(served.carrier)).expect("the tick check reads"),
        "a stranger's removal mark of M hid it from the tick release"
    );
}

/// Row 14 at `Vault::local_machine` (design pass 29, section 2; the profile
/// `oneiron-server`'s dial standing reads, `device_sync::standing`): a
/// stranger's mark of an install the roster holds no head of gives the
/// install no local profile. A stranger's root marks this install `Yours`
/// under its own keys and proof, before the install's first serving start.
///
/// RED: the `profile.is_none()` assert fails: the base's filter
/// (`FoldedMachine::names_key`) reads every anchor's chain, so the
/// stranger's chain stands as this install's profile, and the dial standing
/// reads it as enrolled live.
/// GREEN: no chain this install reads names its key, so it has no profile.
#[test]
fn a_strangers_mark_of_an_unprofiled_install_gives_it_no_local_profile() {
    let (vault, _issuer, _dir) = unprofiled_self_host();
    let vault_id = vault_id_of(&vault);
    let encryption_key = vault
        .machine_encryption_key(vault_id)
        .expect("this install's encryption key");
    let request = vault
        .machine_enrolment_request(vault_id, encryption_key)
        .expect("this install's enrolment request");
    let (anchor, root) = publish_stranger_root(&vault);
    let mark = stranger_mark_with_m_keys(
        &vault,
        vault_id,
        root,
        &anchor,
        &request,
        MachineRole::Owned(MachineOwnership::Yours),
        1,
    );
    let fold = vault.authority_fold().expect("authority fold");
    assert!(
        fold.valid_entries.contains(&mark),
        "guard: the stranger's mark is in valid_entries"
    );
    let folded = fold
        .machine(request.machine)
        .expect("guard: the fold holds a chain of this install");
    assert!(
        folded.roster.is_none(),
        "guard: the roster holds no head of this install"
    );
    assert!(
        folded
            .anchored
            .get(&anchor.verifying_key().to_bytes())
            .is_some_and(|chain| chain.is_live()),
        "guard: the stranger's chain holds this install live"
    );

    let local = vault
        .local_machine()
        .expect("this install's machine")
        .expect("guard: this install has a machine id");
    assert_eq!(
        local.id, request.machine,
        "guard: the stranger marked this install's own machine id"
    );
    assert!(
        local.profile.is_none(),
        "a stranger's chain stood as this install's profile"
    );
}

/// Row 14 at `Vault::enroll_machine_identity` (a physical machine's install
/// key never becomes a writer): a key only a stranger's chain names, for a
/// machine of the stranger's own, is no machine key here. The stranger marks
/// a machine X under a key K it holds; the host enrols K for a fresh MACHINE
/// row.
///
/// RED: the enrolment expect fails with the door's denial: the base asks
/// `FoldedMachine::names_key` of every machine, which reads every anchor's
/// chain.
/// GREEN: K is enrolled as the MACHINE row's key.
#[test]
fn a_key_only_a_strangers_chain_names_enrols_as_a_machine_identity() {
    let served = ServedVault::self_host();
    let vault_id = served.vault_id();
    let node = signing(STRANGER_MACHINE_SEED);
    let claimed = served.request_for(machine_row(&served.vault), &node);
    let (anchor, root) = publish_stranger_root(&served.vault);
    let mark = stranger_mark_with_m_keys(
        &served.vault,
        vault_id,
        root,
        &anchor,
        &claimed,
        MachineRole::Owned(MachineOwnership::Yours),
        1,
    );
    let fold = served.vault.authority_fold().expect("authority fold");
    assert!(
        fold.valid_entries.contains(&mark),
        "guard: the stranger's mark is in valid_entries"
    );
    assert!(
        fold.machine(claimed.machine).is_some_and(|folded| {
            folded.roster.is_none()
                && folded
                    .anchored
                    .get(&anchor.verifying_key().to_bytes())
                    .is_some_and(|chain| chain.profile.machine_key == claimed.machine_key)
        }),
        "guard: only the stranger's chain names K"
    );

    let row = machine_row(&served.vault);
    served
        .vault
        .enroll_machine_identity(
            &served.issuer,
            row,
            claimed.machine_key,
            [0x54; 32],
            |transcript| Ok(node.sign(transcript).to_bytes()),
        )
        .expect("a key only a stranger's chain names is enrolled as a machine identity");
}

/// Row 14 at `Vault::enroll_machine_identity`, its other arm (a physical
/// machine's row never becomes a writer): a MACHINE row only a stranger's
/// chain profiles is no physical machine here. The stranger marks the
/// MACHINE row itself under a key K it holds; the host enrols K for it.
///
/// RED: the enrolment expect fails with the door's denial: the base refuses
/// any row the fold holds a chain of, and any key a chain names.
/// GREEN: K is enrolled as the MACHINE row's key.
#[test]
fn a_machine_row_only_a_strangers_chain_profiles_enrols_as_a_machine_identity() {
    let served = ServedVault::self_host();
    let vault_id = served.vault_id();
    let node = signing(STRANGER_MACHINE_SEED);
    let row = machine_row(&served.vault);
    let claimed = served.request_for(row, &node);
    let (anchor, root) = publish_stranger_root(&served.vault);
    let mark = stranger_mark_with_m_keys(
        &served.vault,
        vault_id,
        root,
        &anchor,
        &claimed,
        MachineRole::Owned(MachineOwnership::Yours),
        1,
    );
    let fold = served.vault.authority_fold().expect("authority fold");
    assert!(
        fold.valid_entries.contains(&mark),
        "guard: the stranger's mark is in valid_entries"
    );
    assert!(
        fold.machine(row).is_some_and(|folded| {
            folded.roster.is_none()
                && folded
                    .anchored
                    .contains_key(&anchor.verifying_key().to_bytes())
        }),
        "guard: only the stranger's chain profiles the MACHINE row"
    );

    served
        .vault
        .enroll_machine_identity(
            &served.issuer,
            row,
            claimed.machine_key,
            [0x54; 32],
            |transcript| Ok(node.sign(transcript).to_bytes()),
        )
        .expect("a MACHINE row only a stranger's chain profiles is enrolled as a machine identity");
}
