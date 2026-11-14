//! ROLES-CHECKIN P2.5, row 2k5a (ARCH-0082 #act-table "Delete items",
//! #role-defaults and #owner-own-acts; Engine ruling P25-SHAPE Q1 = A, 14 Nov
//! 13:39): `vault.delete`, the door a person reaches by role (ARCH-0043
//! DEL-2), takes the writer judge (2i) before the delete's rail.
//!
//! - The Owner's delete is never gated: it goes on their own proof, and its
//!   receipt records that decision. A `check_in_ref` on it is refused as a
//!   bad request and deletes nothing.
//! - A Deputy's delete in scope goes on their own judgment (`sure`); an
//!   Admin's delete in scope and a Member's delete of the NOTE it wrote never
//!   ask. Each receipt names the role and why the delete went.
//! - A Steward's delete of another's item in scope always asks (the
//!   table's Steward cell is "propose"; the Steward holds the power, so it
//!   waits): the door commits the pending check-in alone, deletes nothing and
//!   answers `CHECK_IN_PENDING` naming it; a repeat names the same one.
//!   Before the Owner approves, the named check-in deletes nothing. Once
//!   approved, the call that names it deletes, spends it and its receipt
//!   names it.
//! - A Steward's delete of its own NOTE goes at once with basis `own_item`,
//!   as a Member's does (Engine ruling STEWARD-DELETE-WAIT = B, 14 Nov 16:11:
//!   no role has less than a Member's "go, own items").
//!
//! The vault is rooted, and its human binding is the owner's (H149), so each
//! other person deletes by the live `human` credential this host mints them,
//! as a transport binds it (as delete_authority.rs does). A NOTE is written
//! while the fixture binds the host key to its author, then the key goes back
//! to the owner.
//!
//! On the base (d6ad09c4191) this file does not build: a delete's receipt has
//! no `check_in`, and the memory handle no `safe_delete_with_check_in`.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test check_in_delete_effects`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};

use oneiron::authority::{HostSlipIssuer, VerifiedSlip};
use oneiron::check_in::CheckInDecision;
use oneiron::consent::AuthenticatedOwner;
use oneiron::federation::{FederationGrantRole as Role, InitialSharedMember};
use oneiron::memory::{
    CHECK_IN_PENDING_REASON_PREFIX, DeleteReceipt, MEMORY_CODE_BAD_REQUEST,
    MEMORY_CODE_CHECK_IN_PENDING, MemoryResult, SafeDeleteReason,
};
use oneiron::note::TakeTarget;
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::store::GateDecisionId;
use oneiron::task_verb::sdk::invoke;
use oneiron::temporal::TimeRange;
use oneiron::test_support::{bind_host_actor, bind_host_owner};
use oneiron::{EdgeActorClass, EntityId, Vault, VaultConfig};
use serde_json::json;

const SHARED: u64 = 43;

fn person(vault: &Vault, id: EntityId) {
    vault
        .put_entity(
            &id,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"human",
        )
        .expect("a live person");
}

fn proof(vault: &Vault, person: EntityId) -> AuthenticatedOwner {
    vault
        .authenticate_owner(person, &person.to_hex(), true, GateDecisionId::now())
        .expect("a person proof")
}

/// `member` accepts its founding invitation to the shared vault at `role`.
fn accept(vault: &Vault, member: EntityId, role: Role) {
    let member_proof = proof(vault, member);
    let invitation = vault
        .shared_invitations(&member_proof, SHARED)
        .expect("invitations")
        .into_iter()
        .find(|open| open.role == role)
        .expect("the founding invitation");
    vault
        .accept_shared_invitation(&member_proof, SHARED, &invitation.id)
        .expect("the member accepts");
}

/// A distinct slip id for each credential a test mints.
fn next_slip_id() -> [u8; 32] {
    static NEXT: AtomicU8 = AtomicU8::new(1);
    [NEXT.fetch_add(1, Ordering::Relaxed); 32]
}

/// A rooted shared vault: its owner, a Deputy, an Admin, a Steward and a
/// Member, each of whom accepted, and a subject PERSON the NOTEs are about.
struct Org {
    _dir: tempfile::TempDir,
    vault: Vault,
    issuer: HostSlipIssuer,
    owner: EntityId,
    deputy: EntityId,
    admin: EntityId,
    steward: EntityId,
    member: EntityId,
    subject: EntityId,
}

impl Org {
    fn new() -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let vault = Vault::open(dir.path(), VaultConfig::device()).expect("vault");
        // A delete signs its receipt with this install's key.
        vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
        let issuer = oneiron::test_support::provision_engine_machines(&vault);
        let owner = vault.ensure_embedded_owner_actor().expect("owner");
        bind_host_owner(&vault, &issuer, owner).expect("the owner's binding");
        let [deputy, admin, steward, member, subject] = std::array::from_fn(|_| EntityId::now());
        for id in [deputy, admin, steward, member, subject] {
            person(&vault, id);
        }
        let founding = |member_ref, role| InitialSharedMember {
            member_ref,
            role: Some(role),
        };
        vault
            .initialize_shared_vault(
                &proof(&vault, owner),
                SHARED,
                None,
                &[
                    founding(owner, Role::Owner),
                    founding(deputy, Role::Deputy),
                    founding(admin, Role::Admin),
                    founding(steward, Role::Steward),
                    founding(member, Role::Member),
                ],
                1,
            )
            .expect("a shared vault with a Deputy, an Admin, a Steward and a Member");
        accept(&vault, deputy, Role::Deputy);
        accept(&vault, admin, Role::Admin);
        accept(&vault, steward, Role::Steward);
        accept(&vault, member, Role::Member);
        Self {
            _dir: dir,
            vault,
            issuer,
            owner,
            deputy,
            admin,
            steward,
            member,
            subject,
        }
    }

    /// A NOTE the Member writes about the subject, by its full hex ref.
    fn member_note(&self) -> String {
        bind_host_actor(&self.vault, &self.issuer, self.member, "human")
            .expect("the host key bound to the Member for its write");
        let note = self
            .vault
            .memory(self.member, EdgeActorClass::Human)
            .author_take(
                TakeTarget::Subject(self.subject),
                "a take about the subject",
            )
            .expect("the Member writes a NOTE")
            .id_hex;
        bind_host_owner(&self.vault, &self.issuer, self.owner).expect("the owner's binding again");
        note
    }

    /// The live `human` credential this host mints `person`, verified as a
    /// transport verifies the slip a request presents.
    fn credential(&self, person: EntityId) -> VerifiedSlip {
        let root = self
            .vault
            .ensure_host_root_slip(&self.issuer)
            .expect("the host root slip");
        let issued_at = self.vault.capability_slip_now().expect("slip clock");
        let mut claims = root.claims;
        claims.slip_id = next_slip_id();
        claims.holder_ref = person.to_hex();
        claims.actor_class = Some("human".into());
        claims.issued_at = issued_at;
        claims.expires_at = issued_at + 3_600;
        claims.ttl_secs = 3_600;
        let slip = self
            .vault
            .mint_capability_slip(&self.issuer, claims)
            .expect("the person's credential");
        let challenge = b"check-in-delete";
        let proof = self
            .issuer
            .binding_proof(&slip, challenge)
            .expect("binding proof");
        self.vault
            .verify_capability_slip(&self.issuer.public_key(), &slip, challenge, &proof)
            .expect("a verified credential")
    }

    /// `person`'s `vault.delete` of `note`: the owner's on the in-process
    /// handle, anyone else's over their own credential.
    fn delete(
        &self,
        person: EntityId,
        note: &str,
        check_in_ref: Option<&str>,
    ) -> MemoryResult<DeleteReceipt> {
        let memory = self.vault.memory(person, EdgeActorClass::Human);
        if person == self.owner {
            return memory.safe_delete_with_check_in(
                note,
                SafeDeleteReason::UserDelete,
                check_in_ref,
            );
        }
        let credential = self.credential(person);
        memory
            .with_transport_invocation()
            .with_read_proof(&credential)
            .safe_delete_with_check_in(note, SafeDeleteReason::UserDelete, check_in_ref)
    }

    fn deleted(&self, note: &str) -> bool {
        self.vault
            .is_deleted_shell(&EntityId::from_hex(note).expect("note id"))
            .expect("shell read")
    }

    /// The Owner approves pending check-in `id` over the effect it waits on,
    /// through `vault.check_in.answer`.
    fn owner_approves(&self, id: &str) {
        let row = self
            .vault
            .pending_check_in(&EntityId::from_hex(id).expect("a check-in id"))
            .expect("read the check-in")
            .expect("the check-in is stored");
        let digest: String = row
            .effect_digest
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        let settled = invoke(
            &self.vault.memory(self.owner, EdgeActorClass::Human),
            "vault.check_in.answer",
            json!({ "handle": id, "answer": "approve", "effect_digest": digest }),
        )
        .expect("the Owner answers");
        assert_eq!(
            settled["eligible"].as_str(),
            Some("approved"),
            "the Owner's approval makes the delete eligible: {settled}"
        );
    }

    /// Whether check-in `id` is spent.
    fn spent(&self, id: &str) -> bool {
        self.vault
            .pending_check_in(&EntityId::from_hex(id).expect("a check-in id"))
            .expect("read the check-in")
            .expect("stored")
            .consumed_at
            .is_some()
    }
}

/// The check-in a waiting delete names.
fn pending_id(result: MemoryResult<DeleteReceipt>) -> String {
    let refused = result.expect_err("the delete waits on a check-in");
    assert_eq!(
        refused.code, MEMORY_CODE_CHECK_IN_PENDING,
        "the delete waits: {refused:?}"
    );
    refused
        .reason_codes
        .first()
        .and_then(|code| code.strip_prefix(CHECK_IN_PENDING_REASON_PREFIX))
        .expect("the reason code names the check-in")
        .to_owned()
}

fn decision(
    role: &str,
    mode: Option<&str>,
    basis: &str,
    check_in: Option<&str>,
) -> CheckInDecision {
    CheckInDecision {
        act_class: "delete".to_owned(),
        role: role.to_owned(),
        mode: mode.map(str::to_owned),
        basis: basis.to_owned(),
        check_in: check_in.map(str::to_owned),
        requester: None,
    }
}

#[test]
fn the_owners_delete_goes_on_their_own_proof_and_records_it() {
    let org = Org::new();
    let note = org.member_note();
    let refused = org
        .delete(org.owner, &note, Some(&EntityId::now().to_hex()))
        .expect_err("an Owner's delete names no check-in");
    assert_eq!(refused.code, MEMORY_CODE_BAD_REQUEST, "{refused:?}");
    assert!(!org.deleted(&note), "the refused delete deletes nothing");

    let receipt = org
        .delete(org.owner, &note, None)
        .expect("the Owner deletes");
    assert!(receipt.existed);
    assert!(org.deleted(&note), "the NOTE is a deleted shell");
    assert_eq!(
        receipt.check_in,
        Some(decision("owner", None, "own_proof", None)),
        "the Owner's delete records their own proof"
    );
}

#[test]
fn a_deputy_an_admin_and_a_member_delete_at_once_and_record_why() {
    let org = Org::new();
    let cases = [
        (org.deputy, "deputy", "auto", "sure"),
        (org.admin, "admin", "full-access", "never_ask"),
        (org.member, "member", "full-access", "never_ask"),
    ];
    for (person, role, mode, basis) in cases {
        let note = org.member_note();
        let receipt = org
            .delete(person, &note, None)
            .unwrap_or_else(|error| panic!("the {role}'s delete goes at once: {error:?}"));
        assert!(receipt.existed, "the {role}'s NOTE existed");
        assert!(org.deleted(&note), "the {role}'s delete applied");
        assert_eq!(
            receipt.check_in,
            Some(decision(role, Some(mode), basis, None)),
            "the {role}'s receipt names the role and why it went"
        );
    }
}

#[test]
fn a_stewards_delete_of_its_own_note_goes_at_once_as_own_item() {
    let org = Org::new();
    let note = org.member_note();
    org.vault
        .change_shared_member_role(
            &proof(&org.vault, org.owner),
            SHARED,
            org.member,
            Role::Steward,
            None,
        )
        .expect("the Owner makes the NOTE's author a Steward");
    let receipt = org
        .delete(org.member, &note, None)
        .expect("the Steward's own NOTE goes at once");
    assert!(receipt.existed);
    assert!(org.deleted(&note), "the Steward's own delete applied");
    assert_eq!(
        receipt.check_in,
        Some(decision("steward", Some("full-access"), "own_item", None)),
        "the receipt names its own item as why it went"
    );
}

#[test]
fn a_stewards_delete_waits_on_the_owner_and_the_approved_recall_runs_once() {
    let org = Org::new();
    let note = org.member_note();
    let first = pending_id(org.delete(org.steward, &note, None));
    assert!(!org.deleted(&note), "a waiting delete deletes nothing");
    assert_eq!(
        pending_id(org.delete(org.steward, &note, None)),
        first,
        "a repeat names the same check-in"
    );
    assert!(
        org.delete(org.steward, &note, Some(&first)).is_err(),
        "an unanswered check-in runs nothing"
    );
    assert!(!org.deleted(&note), "the early recall deletes nothing");

    org.owner_approves(&first);
    let other = org.member_note();
    assert!(
        org.delete(org.steward, &other, Some(&first)).is_err(),
        "the approval covers the NOTE it was asked for only"
    );
    assert!(!org.deleted(&other), "the other NOTE stays");
    assert!(!org.spent(&first), "a refused call leaves it unspent");
    let receipt = org
        .delete(org.steward, &note, Some(&first))
        .expect("the approved recall deletes");
    assert!(receipt.existed);
    assert!(org.deleted(&note), "the Steward's delete applied");
    assert!(org.spent(&first), "the delete spent its check-in");
    assert_eq!(
        receipt.check_in,
        Some(decision(
            "steward",
            Some("manual"),
            "approved",
            Some(&first)
        )),
        "the receipt names the check-in the delete spent"
    );
}
