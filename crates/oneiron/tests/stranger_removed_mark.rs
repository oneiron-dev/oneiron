//! FIX [STRANGER-REMOVED-MARK-GLOBAL]: a stranger anchor's removal mark
//! removes no machine from what this install believes, while the owner's
//! own removal still does.
//!
//! The store gate's structure keeps one set of removed machines, and a frontier
//! join a removed machine carries is a stranger's (FIX 7908). The set took a
//! Removed mark from any anchor, a stranger's included: any fresh key
//! publishes an owner root, and its anchor marks any machine in its own
//! chain. So one mark by a root nobody pins made an honest machine's own
//! install joins strangers' rows: they counted against the one shared
//! stranger bound, and the peer settled gate (#9202) did not believe them.
//! The fold reads a foreign anchor's chains only under the pin, and the
//! owner's doors read a stranger's removal mark as no removal (FIX
//! [FOREIGN-ANCHOR-MARK-BLOCKS-MACHINE-DOORS]). The set now takes a removal
//! only when it files as this install's own: a slip issuer, one of this
//! install's own anchors, or an own carrier key signed it.
//!
//! T1 is the attack (red on main, green with the fix); T2 guards the owner's
//! own removal (green on both).
//!
//! Run: `cargo test --locked -p oneiron --all-features --test
//! stranger_removed_mark`.

#![cfg(all(feature = "sync", feature = "test-support"))]

use std::collections::BTreeSet;
use std::sync::Arc;

use ed25519_dalek::{Signer, SigningKey};
use oneiron::authority::{
    AUTHORITY_LOG_SCHEMA_VERSION, ActAuthority, ActSurface, AuthorityEntryHash, AuthorityKey,
    AuthorityLogEntry, AuthorityOp, AuthoritySignature, AuthorityVaultId, HostSlipIssuer,
    MACHINE_ENCRYPTION_KEY_LEN, MACHINE_ENCRYPTION_SUITE_HYBRID_V1, MachineDeviceClass,
    MachineEncryptionKey, MachineEnrolmentRequest, MachineOwnership, MachineProfile, MachineRole,
    OwnerRootRecord, authority_entry_hash, authority_log_entity_id, authority_transcript,
    encode_authority_log_entry_body, machine_profile_proof_transcript,
};
use oneiron::consent::AuthenticatedOwner;
use oneiron::registry::ENTITY_TYPE_AUTHORITY_LOG;
use oneiron::store::GateDecisionId;
use oneiron::sync::client::ImportTier;
use oneiron::sync::peer_route::authority_fold_settled;
use oneiron::sync::replay::{ReplicatedEntity, replay_entity};
use oneiron::world_keys::RecoveryRootSeed;
use oneiron::{EntityId, TimeRange, Vault, VaultConfig};
use oneiron_authority::authority::{
    FrontierJoin, FrontierJoinFamily, FrontierJoinScope, HomeCandidacy,
};

/// The seed of the joining machine's machine key.
const JOINING_SEED: u8 = 68;
/// The stored rows' occurred range and learned-at, as the store-door tests use.
const AT: TimeRange = TimeRange { start: 2, end: 2 };

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
    let transcript = authority_transcript(&row).expect("the transcript signs");
    row.signer.signature = signer.sign(&transcript).to_bytes().to_vec();
    row
}

fn hash(row: &AuthorityLogEntry) -> AuthorityEntryHash {
    authority_entry_hash(row).expect("a row hashes")
}

/// The stranger root's owner person, distinct from the vault's owner.
fn stranger_owner() -> EntityId {
    EntityId::from_bytes([0xA1; 16]).expect("an id parses")
}

/// A self-host vault as its own server starts one: this install serving and
/// profiled under the host root, the owner bound and authenticated, and this
/// install's owner signing key enrolled. It pins no root, so a machine stands
/// under the roster's head alone.
struct ServedVault {
    vault: Vault,
    issuer: HostSlipIssuer,
    owner: AuthenticatedOwner,
    _dir: tempfile::TempDir,
}

impl ServedVault {
    fn self_host() -> Self {
        let dir = tempfile::tempdir().expect("vault directory");
        let vault = Vault::open(dir.path(), VaultConfig::device()).expect("self-host vault");
        vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::new()));
        let issuer = oneiron::test_support::provision_engine_machines(&vault);
        vault
            .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
            .expect("this install's machine profile under the host root")
            .roster
            .expect("guard: this install has a roster chain");
        let person = vault.ensure_embedded_owner_actor().expect("the owner");
        oneiron::test_support::bind_host_owner(&vault, &issuer, person)
            .expect("the owner's binding");
        let owner = vault
            .authenticate_owner(person, &person.to_hex(), true, GateDecisionId::now())
            .expect("the owner's proof");
        let served = Self {
            vault,
            issuer,
            owner,
            _dir: dir,
        };
        served
            .vault
            .enrol_device_owner_signing_key(
                &ActAuthority::Owner(served.owner.clone(), ActSurface::ThisInstall),
                &served.issuer,
            )
            .expect("the owner enrols this install's owner signing key");
        served
    }

    fn vault_id(&self) -> AuthorityVaultId {
        self.vault
            .authority_fold()
            .expect("authority fold reads")
            .vault_id
            .expect("the vault is rooted")
    }

    /// Machine M's request to join this vault, with its own proof.
    fn joining_machine(&self) -> MachineEnrolmentRequest {
        let vault_id = self.vault_id();
        let machine = EntityId::from_bytes([0x76; 16]).expect("an id parses");
        let node = signing(JOINING_SEED);
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

    /// The entry of M's live roster head.
    fn roster_head(&self, machine: EntityId) -> AuthorityEntryHash {
        let fold = self.vault.authority_fold().expect("authority fold reads");
        let roster = fold
            .machine(machine)
            .and_then(|folded| folded.roster.as_ref())
            .expect("guard: M has a roster chain");
        roster.entry
    }
}

/// A self-host vault with machine M enrolled as the owner's at roster
/// revision 1, its peer route settled.
fn enrolled_self_host() -> (ServedVault, MachineEnrolmentRequest) {
    let served = ServedVault::self_host();
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
        .expect("the owner's enrolment of M lands");
    assert!(landing.held().is_none(), "guard: the enrolment is not held");
    let fold = served.vault.authority_fold().expect("authority fold reads");
    let roster = fold
        .machine(request.machine)
        .and_then(|folded| folded.roster.as_ref())
        .expect("guard: M has a roster chain");
    assert!(roster.is_live(), "guard: M's roster is live");
    assert!(
        authority_fold_settled(&served.vault).expect("the settled read"),
        "guard: the enrolment leaves the history whole"
    );
    (served, request)
}

/// A stranger's root published on one held valid row and stored. Returns its
/// anchor signing key and the root row's hash.
fn publish_stranger_root(served: &ServedVault) -> (SigningKey, AuthorityEntryHash) {
    let vault_id = served.vault_id();
    let seed = RecoveryRootSeed::generate().expect("a fresh stranger root seed");
    let root = seed
        .public(&vault_id)
        .expect("the stranger root's public half");
    let anchor = seed.anchor();
    let parent = served
        .vault
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
    served
        .vault
        .put_authority_log_entry(&entry, AT, 2)
        .expect("the stranger's root row is stored");
    assert!(
        served
            .vault
            .authority_fold()
            .expect("authority fold reads")
            .valid_entries
            .contains(&root_hash),
        "guard: the stranger's root is in valid_entries, so its anchor vouches"
    );
    (anchor, root_hash)
}

/// The stranger's anchor marks M removed under M's own keys and proof, on its
/// root row, and the mark is stored. Returns the mark's hash.
fn strangers_removal_mark(
    served: &ServedVault,
    request: &MachineEnrolmentRequest,
    anchor: &SigningKey,
    root_hash: AuthorityEntryHash,
) -> AuthorityEntryHash {
    let profile = MachineProfile {
        machine: request.machine,
        owner: stranger_owner(),
        machine_key: request.machine_key,
        device_class: request.device_class,
        encryption_key: request.encryption_key.clone(),
        role: MachineRole::Removed,
        revision: 1,
        machine_proof: request.machine_proof,
        seen_world_edits: BTreeSet::new(),
        carrier: None,
        act: None,
    };
    let entry = signed(
        served.vault_id(),
        2,
        vec![root_hash],
        AuthorityOp::MachineProfile(profile),
        anchor,
    );
    let mark = hash(&entry);
    served
        .vault
        .put_authority_log_entry(&entry, AT, 2)
        .expect("the stranger's removal mark is stored");
    mark
}

/// Delivers `entry` to `vault` through the replicated ingest door a sync peer's
/// row takes: the public explicit-tier replay (`sync::replay::replay_entity`
/// with `ImportTier::OwnDevice`), which runs the replicated authority
/// validator and the store door.
fn deliver_via_replicated(vault: &Vault, entry: &AuthorityLogEntry) -> oneiron::Result<()> {
    let body = encode_authority_log_entry_body(entry).expect("the row encodes");
    let id = authority_log_entity_id(entry).expect("the row's content id");
    replay_entity(
        vault,
        ReplicatedEntity {
            id,
            entity_type: ENTITY_TYPE_AUTHORITY_LOG,
            occurred: AT,
            learned_at: 2,
            row_version: 0,
            body: &body,
        },
        ImportTier::OwnDevice,
    )
}

/// M's own install join J of `head` and its home candidacy P, which rests on
/// `candidacy_parent` and which M keeps. Delivers J alone through replicated
/// ingest and checks that J stored with P missing. Returns P's hash.
fn deliver_join_over_withheld_candidacy(
    served: &ServedVault,
    machine: EntityId,
    head: AuthorityEntryHash,
    candidacy_parent: AuthorityEntryHash,
) -> AuthorityEntryHash {
    let vault_id = served.vault_id();
    let node = signing(JOINING_SEED);
    let declaration = HomeCandidacy {
        machine,
        node_id: 1,
        always_on: false,
        primary: false,
        macro_ready: true,
        cloud: false,
    };
    let withheld = signed(
        vault_id,
        1,
        vec![candidacy_parent],
        AuthorityOp::HomeCandidacy(declaration),
        &node,
    );
    let withheld_hash = hash(&withheld);
    let mut parents = vec![head, withheld_hash];
    parents.sort_unstable();
    let join = signed(
        vault_id,
        2,
        parents,
        AuthorityOp::FrontierJoin(FrontierJoin {
            family: FrontierJoinFamily::Install(machine),
            scope: FrontierJoinScope::Main,
        }),
        &node,
    );
    let join_id = authority_log_entity_id(&join).expect("J's content-derived id");
    deliver_via_replicated(&served.vault, &join).expect("J lands through replicated ingest");
    assert!(
        served
            .vault
            .get_authority_log_entry(&join_id)
            .expect("J reads back")
            .is_some(),
        "setup: J is stored, so M's join reached the log"
    );
    assert!(
        served
            .vault
            .authority_missing_history()
            .expect("the history read")
            .missing
            .contains(&withheld_hash),
        "setup: the fetch request names P, so delivery can fetch it"
    );
    withheld_hash
}

/// T1 the attack: a stranger's anchor marks the owner's machine M removed,
/// and M then delivers its own install join J over its withheld candidacy P.
/// J is M's row under M's live roster key, so this install believes it: the
/// believed history names P and the peer route stays unsettled. RED on main
/// (the stranger's mark made J a stranger's row: P is not believed missing
/// and the route reads settled), GREEN with the fix.
#[test]
fn a_strangers_removal_mark_leaves_the_machines_own_join_believed() {
    let (served, request) = enrolled_self_host();
    let machine = request.machine;
    let (anchor, root_hash) = publish_stranger_root(&served);
    let mark = strangers_removal_mark(&served, &request, &anchor, root_hash);
    let fold = served.vault.authority_fold().expect("authority fold reads");
    assert!(
        fold.valid_entries.contains(&mark),
        "guard: the stranger's removal mark is in valid_entries"
    );
    let roster = fold
        .machine(machine)
        .and_then(|folded| folded.roster.as_ref())
        .expect("guard: M has a roster chain");
    assert!(
        roster.is_live(),
        "guard: the stranger's mark leaves M's roster chain live"
    );
    assert!(
        authority_fold_settled(&served.vault).expect("the settled read"),
        "guard: the stranger's root and mark alone stall no peer route"
    );
    let head = served.roster_head(machine);
    let withheld = deliver_join_over_withheld_candidacy(&served, machine, head, mark);
    assert!(
        served
            .vault
            .authority_missing_believed_history()
            .expect("the believed history read")
            .missing
            .contains(&withheld),
        "a stranger's removal mark made M's own join a stranger's row: the history this \
         install believes it lacks leaves out P"
    );
    assert!(
        !authority_fold_settled(&served.vault).expect("the settled read"),
        "M's believed join over its withheld candidacy must keep peer serving unsettled"
    );
}

/// T2 the guard: the owner removes M through his own door, and M then
/// delivers its own install join J over its withheld candidacy P. The removal
/// is this install's own, so J is a removed machine's join, a stranger's row
/// (FIX 7908): the believed history leaves out P and the peer route stays
/// settled. GREEN on main and with the fix.
#[test]
fn the_owners_removal_makes_the_machines_join_a_strangers() {
    let (served, request) = enrolled_self_host();
    let machine = request.machine;
    let (_anchor, root_hash) = publish_stranger_root(&served);
    let landing = served
        .vault
        .set_machine_role(
            &served.owner,
            ActSurface::ThisInstall,
            machine,
            MachineRole::Removed,
            None,
        )
        .expect("the owner's removal of M lands");
    assert!(
        landing.held().is_none(),
        "guard: the removal stands, it is not held"
    );
    let fold = served.vault.authority_fold().expect("authority fold reads");
    let roster = fold
        .machine(machine)
        .and_then(|folded| folded.roster.as_ref())
        .expect("guard: M has a roster chain after the removal");
    assert_eq!(
        roster.profile.role,
        MachineRole::Removed,
        "guard: M's roster head is removed"
    );
    assert!(
        authority_fold_settled(&served.vault).expect("the settled read"),
        "guard: the removal leaves the history whole"
    );
    let head = served.roster_head(machine);
    let withheld = deliver_join_over_withheld_candidacy(&served, machine, head, root_hash);
    assert!(
        !served
            .vault
            .authority_missing_believed_history()
            .expect("the believed history read")
            .missing
            .contains(&withheld),
        "a machine the owner removed: its join is a stranger's row, so the history this \
         install believes it lacks leaves out P"
    );
    assert!(
        authority_fold_settled(&served.vault).expect("the settled read"),
        "a removed machine's withheld parent must stall no peer route"
    );
}
