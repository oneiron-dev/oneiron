//! ROLES-CHECKIN P2.5, row 2k8f2 (ARCH-0082 #act-table "Widen another's
//! grant", #role-defaults and #owner-own-acts; Engine rulings P25-SHAPE Q1
//! = A, 14 Nov 13:39, and MEMBER-SHARE-OWN = B, 19:33):
//! `vault.mail.threads.share`, the door a person reaches by role, takes the
//! widen judge (2k8f) after every check that refuses the call and before
//! the write.
//!
//! - The Owner's share is never gated: it goes on their own proof, and its
//!   receipt records that decision. A `check_in_ref` on it is refused as a
//!   bad request and shares nothing.
//! - A Deputy's share of another's thread goes on their own judgment
//!   (`sure`); an Admin's never asks. Each receipt names the role and why
//!   the share went.
//! - A Member's share of another's thread always asks: the door commits the
//!   pending check-in alone, shares nothing and answers `CHECK_IN_PENDING`
//!   naming it; a repeat names the same one. Before the Owner approves, the
//!   named check-in runs nothing. Once approved, the call that names it
//!   shares, spends it and its receipt names it.
//! - A Member's share of its own thread (its source's reader) goes at once
//!   with basis `own_item`.
//! - A Steward holds no content write here, so it shares nothing, as on
//!   main: refused at the write check before the judge, with no check-in.
//!
//! The vault is rooted, and its human binding is the owner's, so each other
//! person shares while the fixture binds the host key to them, then the key
//! goes back to the owner. The Mail & Calendar pack is installed after the
//! vault is shared, by the Owner's `put_pack`.
//!
//! On its base, 2k8f's head (d2d80254a10), this file does not build: the
//! share request has no `check_in_ref`, and its receipt no `check_in`.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test check_in_mail_thread_share_effects`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use oneiron::authority::HostSlipIssuer;
use oneiron::check_in::CheckInDecision;
use oneiron::consent::AuthenticatedOwner;
use oneiron::federation::{FederationGrantRole as Role, InitialSharedMember};
use oneiron::mail_pack::{
    MailThreadShareReceipt, MailThreadShareRequest, mail_calendar_pack_files,
};
use oneiron::memory::{
    CHECK_IN_PENDING_REASON_PREFIX, MEMORY_CODE_BAD_REQUEST, MEMORY_CODE_CHECK_IN_PENDING,
    MemoryResult,
};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::store::GateDecisionId;
use oneiron::task_verb::sdk::invoke;
use oneiron::temporal::TimeRange;
use oneiron::test_doors::source_audience_binding::thread_bound_row;
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

/// A rooted shared vault: its owner, a Deputy, an Admin, a Steward and a
/// Member, each of whom accepted, with the Mail & Calendar pack installed.
struct Org {
    _dir: tempfile::TempDir,
    vault: Vault,
    issuer: HostSlipIssuer,
    owner: EntityId,
    deputy: EntityId,
    admin: EntityId,
    steward: EntityId,
    member: EntityId,
}

impl Org {
    fn new() -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let vault = Vault::open(dir.path(), VaultConfig::device()).expect("vault");
        vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
        let issuer = oneiron::test_support::provision_engine_machines(&vault);
        let owner = vault.ensure_embedded_owner_actor().expect("owner");
        bind_host_owner(&vault, &issuer, owner).expect("the owner's binding");
        let [deputy, admin, steward, member] = std::array::from_fn(|_| EntityId::now());
        for id in [deputy, admin, steward, member] {
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
        vault
            .put_pack(&proof(&vault, owner), mail_calendar_pack_files())
            .expect("the Owner installs the Mail & Calendar pack");
        Self {
            _dir: dir,
            vault,
            issuer,
            owner,
            deputy,
            admin,
            steward,
            member,
        }
    }

    /// `person`'s `vault.mail.threads.share` of `record` with `target`,
    /// naming `check_in_ref` when given: the owner's on the in-process
    /// handle, anyone else's while the host key is bound to them.
    fn share(
        &self,
        person: EntityId,
        record: &str,
        target: &str,
        check_in_ref: Option<&str>,
    ) -> MemoryResult<MailThreadShareReceipt> {
        let request = MailThreadShareRequest {
            record_ref: record.to_owned(),
            person_ref: target.to_owned(),
            check_in_ref: check_in_ref.map(str::to_owned),
        };
        let call = || {
            self.vault
                .memory(person, EdgeActorClass::Human)
                .mail_threads_share(&request)
        };
        if person == self.owner {
            return call();
        }
        bind_host_actor(&self.vault, &self.issuer, person, "human")
            .expect("the host key bound to the caller for their share");
        let answer = call();
        bind_host_owner(&self.vault, &self.issuer, self.owner).expect("the owner's binding again");
        answer
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
            "the Owner's approval makes the share eligible: {settled}"
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

/// The check-in a waiting share names.
fn pending_id(result: MemoryResult<MailThreadShareReceipt>) -> String {
    let refused = result.expect_err("the share waits on a check-in");
    assert_eq!(
        refused.code, MEMORY_CODE_CHECK_IN_PENDING,
        "the share waits: {refused:?}"
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
        act_class: "grant_widen".to_owned(),
        role: role.to_owned(),
        mode: mode.map(str::to_owned),
        basis: basis.to_owned(),
        check_in: check_in.map(str::to_owned),
        requester: None,
    }
}

#[test]
fn an_owners_thread_is_shared_by_role_and_a_members_share_waits_for_the_owner() {
    let org = Org::new();
    let (row, _source, _thread) =
        thread_bound_row(&org.vault, org.owner, org.vault.now_recorded_at())
            .expect("an Owner's thread");
    let record = row.to_hex();
    // The Owner shares with each member on their own proof; the Steward's
    // share is setup for its refusal below, so it reads.
    for (target, role) in [
        (org.deputy, "Deputy"),
        (org.admin, "Admin"),
        (org.member, "Member"),
        (org.steward, "Steward"),
    ] {
        let receipt = org
            .share(org.owner, &record, &target.to_hex(), None)
            .unwrap_or_else(|error| panic!("the Owner shares with the {role}: {error:?}"));
        assert!(receipt.shared, "the {role} reads after the Owner's share");
        assert!(receipt.changed, "the Owner's share with the {role} changed");
        assert_eq!(
            receipt.check_in,
            Some(decision("owner", None, "own_proof", None)),
            "the Owner's share records their own proof"
        );
    }
    // One fresh PERSON per widen, so no share pre-shares another's target.
    let [newcomer_d, newcomer_a, newcomer_m, newcomer_s] = std::array::from_fn(|_| EntityId::now());
    for id in [newcomer_d, newcomer_a, newcomer_m, newcomer_s] {
        person(&org.vault, id);
    }
    let deputy = org
        .share(org.deputy, &record, &newcomer_d.to_hex(), None)
        .expect("the Deputy shares");
    assert!(deputy.changed, "the Deputy's share applied");
    assert_eq!(
        deputy.check_in,
        Some(decision("deputy", Some("auto"), "sure", None)),
        "the Deputy's receipt names their own judgment"
    );
    let admin = org
        .share(org.admin, &record, &newcomer_a.to_hex(), None)
        .expect("the Admin shares");
    assert!(admin.changed, "the Admin's share applied");
    assert_eq!(
        admin.check_in,
        Some(decision("admin", Some("full-access"), "never_ask", None)),
        "the Admin's receipt names why it went"
    );
    let steward = org
        .share(org.steward, &record, &newcomer_s.to_hex(), None)
        .expect_err("a Steward shares nothing here");
    assert_ne!(
        steward.code, MEMORY_CODE_CHECK_IN_PENDING,
        "a Steward is refused at the write check, as on main, and asks nothing: {steward:?}"
    );

    let first = pending_id(org.share(org.member, &record, &newcomer_m.to_hex(), None));
    let probe = org
        .share(org.owner, &record, &org.deputy.to_hex(), None)
        .expect("the Owner re-shares with the Deputy");
    assert!(
        probe.shared_with.contains(&newcomer_d.to_hex())
            && probe.shared_with.contains(&newcomer_a.to_hex()),
        "the Deputy's and the Admin's shares applied: {:?}",
        probe.shared_with
    );
    assert!(
        !probe.shared_with.contains(&newcomer_m.to_hex()),
        "a waiting share widens nothing: {:?}",
        probe.shared_with
    );
    assert_eq!(
        pending_id(org.share(org.member, &record, &newcomer_m.to_hex(), None)),
        first,
        "a repeat names the same check-in"
    );
    assert!(
        org.share(org.member, &record, &newcomer_m.to_hex(), Some(&first))
            .is_err(),
        "an unanswered check-in runs nothing"
    );

    org.owner_approves(&first);
    let receipt = org
        .share(org.member, &record, &newcomer_m.to_hex(), Some(&first))
        .expect("the approved share runs");
    assert!(
        receipt.shared,
        "the newcomer reads after the approved share"
    );
    assert!(receipt.changed, "the approved share applied");
    assert!(
        receipt.shared_with.contains(&newcomer_m.to_hex()),
        "the approved share widened: {:?}",
        receipt.shared_with
    );
    assert!(org.spent(&first), "the share spent its check-in");
    assert_eq!(
        receipt.check_in,
        Some(decision("member", Some("manual"), "approved", Some(&first))),
        "the receipt names the check-in the share spent"
    );
}

#[test]
fn a_member_shares_its_own_thread_at_once_as_own_item() {
    let org = Org::new();
    let (row, _source, _thread) =
        thread_bound_row(&org.vault, org.member, org.vault.now_recorded_at())
            .expect("a Member's thread");
    let newcomer = EntityId::now();
    person(&org.vault, newcomer);
    let receipt = org
        .share(org.member, &row.to_hex(), &newcomer.to_hex(), None)
        .expect("the Member shares its own thread at once");
    assert!(receipt.shared, "the newcomer reads");
    assert!(receipt.changed, "the share applied");
    assert_eq!(
        receipt.check_in,
        Some(decision("member", Some("full-access"), "own_item", None)),
        "the receipt names its own item as why it went"
    );
}

#[test]
fn an_owners_share_naming_a_check_in_is_refused_and_shares_nothing() {
    let org = Org::new();
    let (row, _source, _thread) =
        thread_bound_row(&org.vault, org.owner, org.vault.now_recorded_at())
            .expect("an Owner's thread");
    let record = row.to_hex();
    let newcomer = EntityId::now();
    person(&org.vault, newcomer);
    let named = EntityId::now().to_hex();
    let refused = org
        .share(org.owner, &record, &newcomer.to_hex(), Some(&named))
        .expect_err("an Owner's share names no check-in");
    assert_eq!(refused.code, MEMORY_CODE_BAD_REQUEST, "{refused:?}");

    let receipt = org
        .share(org.owner, &record, &newcomer.to_hex(), None)
        .expect("the Owner shares");
    assert!(receipt.changed, "the refused share shared nothing");
    assert_eq!(
        receipt.check_in,
        Some(decision("owner", None, "own_proof", None)),
        "the Owner's share records their own proof"
    );
}
