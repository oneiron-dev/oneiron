//! OWNER-ENROL (Engine TASK 14 Nov 16:10), part 1: a member whose Owner
//! standing ends keeps no owner key and no `human` binding on the shared
//! vault's authority log, whatever role they keep, and neither does a member
//! who leaves (OWNER-ENROL-TRANSFER-REVOKE = A, the lead 16:2x). A co-Owner
//! may enrol an owner signing key of their own: the door admits every live
//! Owner, and the key lands on the roster as an owner root. On main nothing
//! revoked it. A removed Owner, or one who handed ownership on and stayed as
//! Admin, kept that live root, which signs any authority entry, and with a
//! binding on it they kept every owner verb. Now the membership move that
//! ends their Owner standing revokes each live key whose enrolment names
//! them, which ends the binding on it, and each other live `human` binding
//! that names them, under the issuer that signs the move.
//!
//! Red on main: `a_removed_owner_keeps_no_owner_key_or_binding` and
//! `an_owner_who_hands_ownership_on_and_stays_as_admin_keeps_no_owner_key`
//! (the key stays live, and the owner verb still passes). Guard, which passes
//! on main too: `removing_another_owner_leaves_an_owners_key_and_binding`.
//! A move no host root signs cannot revoke them, so it is refused while the
//! member holds either (REVIEW-7931); red before that refusal (the removal ran
//! unsigned and left the key live):
//! `a_removal_no_host_root_signs_is_refused_while_the_owner_holds_an_owner_key`.
//! An Owner whose standing returns is bound again: the embedded owner, whom
//! the host root binds, hands ownership on and gets it back, and the host
//! root binds them again in the handover that returns it (REVIEW-7931 round
//! 2). Red before it (they stayed unbound, and their owner key enrolment was
//! refused): `the_embedded_owner_whose_standing_returns_is_bound_again`.
//!
//! Part 2: an added Owner's first owner key binds them as `human` in the
//! enrolment's transaction, signed by the enrolment's predecessor, on a
//! self-hosted vault (BIND-TIMING, BIND-SIGNER and OP-SHAPE = A, the Engine
//! 16:23; KEY-ORIGIN = A, the lead 16:2x). Red before it:
//! `an_added_owners_first_owner_key_binds_them` (the added Owner's owner verb
//! answers OWNER_BINDING_REQUIRED). Guard: an Owner a binding names already,
//! the embedded owner included, gains no second one.
//!
//! Part 3 (REVOKED-OWNER-ROOT-SIBLING-ENROL, Engine RULING 14 Nov 19:50): a
//! revoked key's rows count only inside its revocation's own ancestry. A
//! removed co-Owner's key signs a row on the heads before their removal and
//! holds it back; the removal revokes the key, and the row then arrives by
//! sync. Before the fence the row landed as signed on its own branch. Red
//! before it: `a_revoked_keys_concurrent_enrolment_synced_late_lands_refused`
//! (the enrolled agent key is live),
//! `a_revoked_keys_withheld_revocation_of_another_owner_key_lands_refused`
//! (the other key is revoked), and the two replica tests, where the row
//! arrives before the removal and the fold, not the door, must drop it.
//! `a_revoked_keys_withheld_handoff_installs_no_root` runs red or as a guard.
//! Guard: `an_enrolment_the_revocation_saw_stands`. The fold's refold of a
//! world or owner choice above a refused row never folds back a choice the
//! fence refuses for its own signer (REVIEW-7987); red before that:
//! `a_revoked_install_keys_choices_stay_refused_through_the_refold` (the
//! second choice folds again).
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test owner_enrol`.
#![cfg(oneiron_test_support)]

use std::collections::BTreeSet;
use std::sync::Arc;

use ed25519_dalek::{Signer, SigningKey};
use oneiron::authority::{
    AUTHORITY_LOG_SCHEMA_VERSION, ActAuthority, ActSurface, ActorBindingStatus,
    AuthorityAttestation, AuthorityEntryHash, AuthorityKey, AuthorityLogEntry, AuthorityOp,
    AuthoritySignature, AuthorityTier, CheckpointRootChoice, DeviceAuthority, HostSlipIssuer,
    MachineRole, OwnerKeyEnrollment, ROLE_AGENT, authority_entry_hash, authority_transcript,
    decode_authority_log_entry_body, encode_authority_log_entry_body,
};
use oneiron::consent::AuthenticatedOwner;
use oneiron::federation::{FederationGrantRole as Role, InitialSharedMember};
use oneiron::memory::MEMORY_CODE_OWNER_BINDING_REQUIRED;
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::store::GateDecisionId;
use oneiron::temporal::TimeRange;
use oneiron::test_support::bind_host_owner;
use oneiron::{EdgeActorClass, EntityId, ErrorKind, Vault, VaultConfig};

const SHARED: u64 = 44;
/// The seed of the co-Owner's own owner key ([`Shared::bound_co_owner_key`]).
const CO_OWNER_SEED: u8 = 7;

fn person(vault: &Vault) -> EntityId {
    let id = EntityId::now();
    vault
        .put_entity(
            &id,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"human",
        )
        .expect("a live person");
    id
}

fn proof(vault: &Vault, person: EntityId) -> AuthenticatedOwner {
    vault
        .authenticate_owner(person, &person.to_hex(), true, GateDecisionId::now())
        .expect("a person proof")
}

/// A rooted shared vault whose embedded owner the host root binds, with a
/// second Owner the owner added.
struct Shared {
    _dir: tempfile::TempDir,
    vault: Vault,
    issuer: HostSlipIssuer,
    owner: EntityId,
    co_owner: EntityId,
}

fn shared() -> Shared {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("vault");
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    let issuer = oneiron::test_support::provision_engine_machines(&vault);
    // An owner key enrolment is carried by this install's live machine
    // profile, as every owner act is.
    vault
        .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
        .expect("this install's live machine profile");
    let owner = vault.ensure_embedded_owner_actor().expect("owner");
    bind_host_owner(&vault, &issuer, owner).expect("the owner's binding");
    vault
        .initialize_shared_vault(
            &proof(&vault, owner),
            SHARED,
            None,
            &[InitialSharedMember {
                member_ref: owner,
                role: Some(Role::Owner),
            }],
            1,
        )
        .expect("a shared vault");
    let co_owner = add_owner(&vault, &issuer, owner);
    Shared {
        _dir: dir,
        vault,
        issuer,
        owner,
        co_owner,
    }
}

/// A new person `owner` adds as an Owner; the add is instant.
fn add_owner(vault: &Vault, issuer: &HostSlipIssuer, owner: EntityId) -> EntityId {
    let added = person(vault);
    let owner_proof = proof(vault, owner);
    let act = vault
        .propose_add_owner(&owner_proof, SHARED, added)
        .expect("the owner starts add_owner");
    vault
        .execute_completed_shared_act(&owner_proof, &act.id, Some(issuer))
        .expect("add_owner runs at once");
    added
}

impl Shared {
    /// The owner removes `target`, who leaves the vault.
    fn remove_owner(&self, target: EntityId) {
        let owner_proof = proof(&self.vault, self.owner);
        let act = self
            .vault
            .propose_remove_owner(&owner_proof, SHARED, target, None, None, false)
            .expect("the owner starts remove_owner");
        self.vault
            .execute_completed_shared_act(&owner_proof, &act.id, Some(&self.issuer))
            .expect("remove_owner runs at once");
    }

    /// `person` enrols an owner signing key of their own, made from `seed`,
    /// through the owner-signing-key door, which signs with this host's root
    /// as its predecessor. Answers the key.
    fn enrol_owner_key(&self, person: EntityId, seed: u8) -> [u8; 32] {
        let key = SigningKey::from_bytes(&[seed; 32]);
        let public_key = key.verifying_key().to_bytes();
        let machine = self
            .vault
            .prepare_install_signing()
            .expect("this install's machine");
        let authority = ActAuthority::Owner(proof(&self.vault, person), ActSurface::ThisInstall);
        let challenge = self
            .vault
            .owner_key_enrollment_challenge_as(&authority, machine, &public_key)
            .expect("the enrolment challenge");
        let input = OwnerKeyEnrollment {
            machine,
            public_key,
            proof: key.sign(&challenge).to_bytes().to_vec(),
        };
        self.vault
            .enrol_owner_signing_key_as_host(&authority, input, &self.issuer)
            .expect("an Owner enrols an owner key of their own");
        public_key
    }

    fn key_is_live(&self, public_key: [u8; 32]) -> bool {
        self.vault
            .enrolled_owner_keys()
            .expect("the enrolled keys")
            .into_iter()
            .find(|key| key.public_key == public_key)
            .expect("the key is listed")
            .live
    }

    /// The person a live `human` binding on `public_key` names, if any.
    fn bound_to(&self, public_key: [u8; 32]) -> Option<EntityId> {
        self.vault
            .authority_fold()
            .expect("the fold")
            .actor_bindings
            .get(&AuthorityKey::Ed25519(public_key))
            .filter(|binding| {
                binding.status == ActorBindingStatus::Active && binding.actor_class == "human"
            })
            .map(|binding| binding.actor_ref)
    }

    fn passes_owner_verbs(&self, person: EntityId) -> bool {
        match self
            .vault
            .memory(person, EdgeActorClass::Human)
            .verify_owner()
        {
            Ok(()) => true,
            Err(error) => {
                assert_eq!(error.code, MEMORY_CODE_OWNER_BINDING_REQUIRED, "{error:?}");
                false
            }
        }
    }

    /// The co-Owner's own key, enrolled, which binds them.
    fn bound_co_owner_key(&self) -> [u8; 32] {
        let key = self.enrol_owner_key(self.co_owner, CO_OWNER_SEED);
        assert!(self.key_is_live(key), "the enrolled key is live");
        assert!(
            self.passes_owner_verbs(self.co_owner),
            "a bound co-Owner passes the owner verbs"
        );
        key
    }
}

#[test]
fn a_removed_owner_keeps_no_owner_key_or_binding() {
    let shared = shared();
    let key = shared.bound_co_owner_key();

    shared.remove_owner(shared.co_owner);

    assert!(
        !shared.key_is_live(key),
        "the removed Owner's own owner key is revoked with the removal"
    );
    assert!(
        !shared.passes_owner_verbs(shared.co_owner),
        "the removed Owner's binding ends with their key"
    );
    assert!(
        shared.passes_owner_verbs(shared.owner),
        "the Owner who stays keeps the host root's binding"
    );
}

#[test]
fn removing_another_owner_leaves_an_owners_key_and_binding() {
    let shared = shared();
    let key = shared.bound_co_owner_key();
    let third = add_owner(&shared.vault, &shared.issuer, shared.owner);

    shared.remove_owner(third);

    assert!(
        shared.key_is_live(key),
        "the co-Owner who stays keeps their key"
    );
    assert!(
        shared.passes_owner_verbs(shared.co_owner),
        "the co-Owner who stays keeps their binding"
    );
    assert!(
        shared.passes_owner_verbs(shared.owner),
        "the embedded owner keeps the host root's binding"
    );
}

#[test]
fn an_owner_who_hands_ownership_on_and_stays_as_admin_keeps_no_owner_key() {
    let shared = shared();
    let key = shared.bound_co_owner_key();
    let successor = person(&shared.vault);
    let co_owner_proof = proof(&shared.vault, shared.co_owner);
    let act = shared
        .vault
        .propose_transfer_ownership(&co_owner_proof, SHARED, successor, Some(Role::Admin))
        .expect("the co-Owner starts transfer_ownership");
    shared
        .vault
        .execute_completed_shared_act(&co_owner_proof, &act.id, Some(&shared.issuer))
        .expect("transfer_ownership runs at once");

    assert!(
        !shared.key_is_live(key),
        "the former Owner's own owner key retires with their Owner standing"
    );
    assert!(
        !shared.passes_owner_verbs(shared.co_owner),
        "the former Owner, now an Admin, passes no owner verb"
    );
    assert!(
        shared.passes_owner_verbs(shared.owner),
        "the Owner who stays keeps the host root's binding"
    );
}

#[test]
fn an_added_owners_first_owner_key_binds_them() {
    let shared = shared();
    assert!(
        !shared.passes_owner_verbs(shared.co_owner),
        "an added Owner holds no binding before their first owner key"
    );

    let key = shared.enrol_owner_key(shared.co_owner, 7);

    assert_eq!(
        shared.bound_to(key),
        Some(shared.co_owner),
        "the added Owner's first owner key is bound to them"
    );
    assert!(
        shared.passes_owner_verbs(shared.co_owner),
        "the added Owner passes the owner verbs"
    );
    assert!(
        shared.passes_owner_verbs(shared.owner),
        "the first owner keeps the host root's binding"
    );
    let second = shared.enrol_owner_key(shared.co_owner, 8);
    assert!(shared.key_is_live(second), "a second owner key enrols");
    assert_eq!(
        shared.bound_to(second),
        None,
        "an Owner a live binding names gains no second one"
    );
}

#[test]
fn the_embedded_owners_enrolled_key_binds_no_one() {
    let shared = shared();

    let key = shared.enrol_owner_key(shared.owner, 9);

    assert!(shared.key_is_live(key), "the embedded owner's key enrols");
    assert_eq!(
        shared.bound_to(key),
        None,
        "the host root binds the embedded owner already"
    );
    assert!(shared.passes_owner_verbs(shared.owner));
}

/// A removal no host root signs could not revoke the removed Owner's owner
/// key or binding, so it is refused while they hold either (REVIEW-7931):
/// this install's keystore holds no host root seed, and the key and the
/// binding stay as they were.
#[test]
fn a_removal_no_host_root_signs_is_refused_while_the_owner_holds_an_owner_key() {
    let shared = shared();
    let key = shared.bound_co_owner_key();
    let owner_proof = proof(&shared.vault, shared.owner);
    let act = shared
        .vault
        .propose_remove_owner(&owner_proof, SHARED, shared.co_owner, None, None, false)
        .expect("the owner starts remove_owner");
    // This install loses its host root's seed: no issuer signs the run.
    shared
        .vault
        .install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));

    let refusal = shared
        .vault
        .execute_completed_shared_act(&owner_proof, &act.id, None)
        .expect_err("a removal no host root signs is refused");

    assert_eq!(refusal.kind(), ErrorKind::AuthorityRefused, "{refusal}");
    assert!(
        refusal.to_string().contains("the vault's host"),
        "the refusal names where the move runs: {refusal}"
    );
    assert!(shared.key_is_live(key), "their owner key stays live");
    assert!(
        shared.passes_owner_verbs(shared.co_owner),
        "nothing moved: the Owner keeps their binding"
    );
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("a clock after 1970")
        .as_secs()
}

fn device(public_key: [u8; 32], roles: u16) -> DeviceAuthority {
    DeviceAuthority {
        key: AuthorityKey::Ed25519(public_key),
        transport_key_binding: [7; 32],
        attestation: AuthorityAttestation {
            kind: "SoftwareArgon2id".to_owned(),
            evidence: vec![1, 2, 3],
        },
        tier: AuthorityTier::Software,
        roles,
    }
}

fn public_key(seed: u8) -> [u8; 32] {
    SigningKey::from_bytes(&[seed; 32])
        .verifying_key()
        .to_bytes()
}

/// An enrolment of a fresh agent key made from `seed`.
fn enrol_agent(seed: u8) -> AuthorityOp {
    AuthorityOp::EnrollDevice {
        device: device(public_key(seed), ROLE_AGENT),
    }
}

fn on_roster_live(vault: &Vault, public_key: [u8; 32]) -> bool {
    vault
        .authority_fold()
        .expect("the fold")
        .roster
        .get(&AuthorityKey::Ed25519(public_key))
        .is_some_and(|device| !device.revoked)
}

impl Shared {
    fn history(&self) -> Vec<Vec<u8>> {
        self.vault
            .export_signed_authority_history()
            .expect("the signed history")
    }

    /// The authority log's heads: the rows no row names as a parent.
    fn heads(&self) -> Vec<AuthorityEntryHash> {
        let rows: Vec<AuthorityLogEntry> = self
            .history()
            .iter()
            .map(|bytes| decode_authority_log_entry_body(bytes).expect("a row"))
            .collect();
        let parents: BTreeSet<AuthorityEntryHash> = rows
            .iter()
            .flat_map(|row| row.parent_hashes.iter().copied())
            .collect();
        rows.iter()
            .map(|row| authority_entry_hash(row).expect("a hash"))
            .filter(|hash| !parents.contains(hash))
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect()
    }

    /// The co-Owner's owner key signs `op` as its first row, parented on the
    /// heads, and holds it back: the signed bytes a sync delivers later.
    fn withheld_co_owner_row(&self, op: AuthorityOp) -> Vec<u8> {
        let signing = SigningKey::from_bytes(&[CO_OWNER_SEED; 32]);
        let signer = AuthorityKey::Ed25519(signing.verifying_key().to_bytes());
        let mut row = AuthorityLogEntry {
            schema_version: AUTHORITY_LOG_SCHEMA_VERSION,
            vault_id: self.vault.authority_fold().expect("the fold").vault_id,
            seq: 1,
            parent_hashes: self.heads(),
            op,
            signer: AuthoritySignature {
                suite: signer.suite(),
                public_key: signer,
                signature: vec![0; 64],
            },
            cosigns: Vec::new(),
            ts: now_secs(),
        };
        let transcript = authority_transcript(&row).expect("the transcript");
        row.signer.signature = signing.sign(&transcript).to_bytes().to_vec();
        encode_authority_log_entry_body(&row).expect("the signed bytes")
    }

    fn on_roster_live(&self, public_key: [u8; 32]) -> bool {
        on_roster_live(&self.vault, public_key)
    }
}

/// A second install that holds a copy of the vault's authority log.
struct Replica {
    _dir: tempfile::TempDir,
    vault: Vault,
    held: BTreeSet<Vec<u8>>,
}

impl Replica {
    fn holding(history: Vec<Vec<u8>>) -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let vault = Vault::open(dir.path(), VaultConfig::device()).expect("replica");
        vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
        let mut replica = Self {
            _dir: dir,
            vault,
            held: BTreeSet::new(),
        };
        replica.take(history);
        replica
    }

    /// Imports the rows of `history` this replica does not hold yet.
    fn take(&mut self, history: Vec<Vec<u8>>) {
        let new: Vec<Vec<u8>> = history
            .into_iter()
            .filter(|row| !self.held.contains(row))
            .collect();
        self.vault
            .import_signed_authority_history(&new)
            .expect("the replica takes the rows");
        self.held.extend(new);
    }

    fn on_roster_live(&self, public_key: [u8; 32]) -> bool {
        on_roster_live(&self.vault, public_key)
    }
}

/// The removed co-Owner's key enrols an agent key on the heads before the
/// removal and holds the row back. After the removal revoked the key, the
/// sync door refuses the row, and the agent key is not on the roster.
#[test]
fn a_revoked_keys_concurrent_enrolment_synced_late_lands_refused() {
    let shared = shared();
    let key = shared.bound_co_owner_key();
    let late = shared.withheld_co_owner_row(enrol_agent(31));
    shared.remove_owner(shared.co_owner);
    assert!(!shared.key_is_live(key), "the removal revokes the key");

    let arrival = shared.vault.import_signed_authority_history(&[late]);

    assert!(
        !shared.on_roster_live(public_key(31)),
        "the revoked key's withheld enrolment enrols no one: {arrival:?}"
    );
    assert!(
        arrival.is_err(),
        "the sync door refuses a row the revoked key signed outside its revocation's ancestry"
    );
}

/// The removed co-Owner's key revokes the owner's second owner key on the
/// heads before the removal and holds the row back. After the removal, that
/// revocation counts for nothing: the owner's key stays live.
#[test]
fn a_revoked_keys_withheld_revocation_of_another_owner_key_lands_refused() {
    let shared = shared();
    shared.bound_co_owner_key();
    let owners_second = shared.enrol_owner_key(shared.owner, 9);
    let late = shared.withheld_co_owner_row(AuthorityOp::RevokeDevice {
        revoked_key: AuthorityKey::Ed25519(owners_second),
    });
    shared.remove_owner(shared.co_owner);

    let arrival = shared.vault.import_signed_authority_history(&[late]);

    assert!(
        shared.key_is_live(owners_second),
        "the owner's second key stays live: {arrival:?}"
    );
    assert!(
        arrival.is_err(),
        "the sync door refuses the withheld revocation"
    );
}

/// The removed co-Owner's key hands the vault to a new key of its own on
/// the heads before the removal and holds the row back. The door refuses it
/// after the removal, and the fold of both rows, in either arrival order,
/// installs no new root: the handoff and the removal's revocation fence each
/// other (Engine ASK REVOKE-FENCE-CYCLE, A).
#[test]
fn a_revoked_keys_withheld_handoff_installs_no_root() {
    let shared = shared();
    let key = shared.bound_co_owner_key();
    let roles =
        shared.vault.authority_fold().expect("the fold").roster[&AuthorityKey::Ed25519(key)].roles;
    let late = shared.withheld_co_owner_row(AuthorityOp::ReRoot {
        new_device: device(public_key(33), roles),
    });
    shared.remove_owner(shared.co_owner);
    let mut rows: Vec<AuthorityLogEntry> = shared
        .history()
        .iter()
        .map(|bytes| decode_authority_log_entry_body(bytes).expect("a row"))
        .collect();
    rows.push(decode_authority_log_entry_body(&late).expect("the handoff"));

    let arrival = shared.vault.import_signed_authority_history(&[late]);

    assert!(
        !shared.on_roster_live(public_key(33)),
        "the withheld handoff installs no root: {arrival:?}"
    );
    for _ in 0..2 {
        let fold = oneiron::authority::fold_authority_log(&rows);
        assert!(
            fold.roster
                .get(&AuthorityKey::Ed25519(public_key(33)))
                .is_none_or(|device| device.revoked),
            "no arrival order installs the withheld handoff's key"
        );
        rows.reverse();
    }
}

/// An enrolment the co-Owner's key signed and synced before their removal
/// is in the removal's ancestry, so it stands after the key is revoked.
#[test]
fn an_enrolment_the_revocation_saw_stands() {
    let shared = shared();
    let key = shared.bound_co_owner_key();
    let row = shared.withheld_co_owner_row(enrol_agent(32));
    shared
        .vault
        .import_signed_authority_history(&[row])
        .expect("the co-Owner's live key enrols an agent key");
    assert!(
        shared.on_roster_live(public_key(32)),
        "the agent key is live"
    );

    shared.remove_owner(shared.co_owner);

    assert!(!shared.key_is_live(key), "the removal revokes the key");
    assert!(
        shared.on_roster_live(public_key(32)),
        "an enrolment the revocation saw stands"
    );
}

/// A replica that took the withheld enrolment before the removal drops it
/// when the removal arrives: the fold, not only the door, refuses it.
#[test]
fn a_replica_holding_a_revoked_keys_enrolment_drops_it_when_the_revocation_arrives() {
    let shared = shared();
    shared.bound_co_owner_key();
    let history = shared.history();
    let late = shared.withheld_co_owner_row(enrol_agent(34));
    shared.remove_owner(shared.co_owner);
    let mut replica = Replica::holding(history);
    replica.take(vec![late]);
    assert!(
        replica.on_roster_live(public_key(34)),
        "precondition: the replica folds the enrolment live before the removal arrives"
    );

    replica.take(shared.history());

    assert!(
        !replica.on_roster_live(public_key(34)),
        "the revoked key's enrolment drops out when its revocation arrives"
    );
}

/// A replica that took the withheld revocation of the owner's second key
/// before the removal: when the removal arrives, the revocation yields to
/// its fence, and the owner's key is live again, as on the install that saw
/// the removal first.
#[test]
fn a_replica_holding_a_revoked_keys_revocation_drops_it_when_the_removal_arrives() {
    let shared = shared();
    shared.bound_co_owner_key();
    let owners_second = shared.enrol_owner_key(shared.owner, 9);
    let history = shared.history();
    let late = shared.withheld_co_owner_row(AuthorityOp::RevokeDevice {
        revoked_key: AuthorityKey::Ed25519(owners_second),
    });
    shared.remove_owner(shared.co_owner);
    let mut replica = Replica::holding(history);
    assert!(
        replica.on_roster_live(owners_second),
        "precondition: the replica folds the owner's second key live"
    );
    replica.take(vec![late]);
    assert!(
        !replica.on_roster_live(owners_second),
        "precondition: the replica folds the withheld revocation before the removal arrives"
    );

    replica.take(shared.history());

    assert!(
        replica.on_roster_live(owners_second),
        "the withheld revocation counts for nothing once the removal arrives"
    );
}

impl Shared {
    /// The one row the history gained since `before`.
    fn row_since(&self, before: &[Vec<u8>]) -> AuthorityEntryHash {
        let held: BTreeSet<&Vec<u8>> = before.iter().collect();
        let new: Vec<AuthorityEntryHash> = self
            .history()
            .iter()
            .filter(|row| !held.contains(row))
            .map(|row| {
                authority_entry_hash(&decode_authority_log_entry_body(row).expect("a row"))
                    .expect("a hash")
            })
            .collect();
        assert_eq!(new.len(), 1, "one new row: {new:?}");
        new[0]
    }

    fn is_valid(&self, hash: &AuthorityEntryHash) -> bool {
        self.vault
            .authority_fold()
            .expect("the fold")
            .valid_entries
            .contains(hash)
    }
}

/// The host install's key carries two checkpoint policy choices of the
/// owner, the second on the first. A host-root revocation of that key,
/// signed on the heads before both, arrives after them. Its fence refuses
/// both for their own signer, and the fold's refold of a choice above a
/// refused row folds neither back (REVIEW-7987).
#[test]
fn a_revoked_install_keys_choices_stay_refused_through_the_refold() {
    let shared = shared();
    let revocation =
        oneiron::test_doors::install_key_revocation::withheld_revocation_of_this_install(
            &shared.vault,
            &shared.issuer,
        )
        .expect("the withheld revocation of the host install's key");
    let owner = ActAuthority::Owner(proof(&shared.vault, shared.owner), ActSurface::ThisInstall);
    let before = shared.history();
    shared
        .vault
        .set_checkpoint_policy_as(
            &owner,
            Some(CheckpointRootChoice {
                roots: vec![shared.issuer.public_key()],
                quorum: 1,
                hardware: false,
            }),
            None,
        )
        .expect("the first choice");
    let first = shared.row_since(&before);
    let before = shared.history();
    shared
        .vault
        .set_checkpoint_policy_as(&owner, None, None)
        .expect("the second choice");
    let second = shared.row_since(&before);
    assert!(
        shared.is_valid(&first) && shared.is_valid(&second),
        "precondition: both choices fold before the revocation arrives"
    );

    shared
        .vault
        .import_signed_authority_history(&[revocation])
        .expect("the revocation arrives");

    assert!(
        !shared.is_valid(&first),
        "the fence refuses the first choice, signed by the revoked key off its line"
    );
    assert!(
        !shared.is_valid(&second),
        "the refold does not fold the second choice back above the refused first"
    );
}

/// The embedded owner hands ownership to a new Owner and stays as Admin,
/// which revokes the host root's binding of them; the new Owner hands it
/// back. The host root binds the embedded owner again in that handover, at a
/// new epoch above the revoked one, and their owner verbs pass.
#[test]
fn the_embedded_owner_whose_standing_returns_is_bound_again() {
    let shared = shared();
    let successor = person(&shared.vault);
    let owner_proof = proof(&shared.vault, shared.owner);
    let away = shared
        .vault
        .propose_transfer_ownership(&owner_proof, SHARED, successor, Some(Role::Admin))
        .expect("the owner starts transfer_ownership");
    shared
        .vault
        .execute_completed_shared_act(&owner_proof, &away.id, Some(&shared.issuer))
        .expect("the transfer runs at once");
    assert!(
        !shared.passes_owner_verbs(shared.owner),
        "precondition: the former Owner, now an Admin, passes no owner verb"
    );

    let successor_proof = proof(&shared.vault, successor);
    let back = shared
        .vault
        .propose_transfer_ownership(&successor_proof, SHARED, shared.owner, Some(Role::Admin))
        .expect("the new Owner starts the transfer back");
    shared
        .vault
        .execute_completed_shared_act(&successor_proof, &back.id, Some(&shared.issuer))
        .expect("the transfer back runs at once");

    assert!(
        shared.passes_owner_verbs(shared.owner),
        "the embedded owner whose Owner standing returned passes owner verbs again"
    );
    assert!(
        !shared.passes_owner_verbs(successor),
        "the Owner who handed it back passes none"
    );
}
