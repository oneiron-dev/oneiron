//! ROLES-CHECKIN P2.4b, piece 2i (ARCH-0082 #composing and #role-defaults;
//! Engine ruling P24-SHAPE Q3, Q4, Q5, Q6 and Q9 = A, 13 Nov 19:32): the
//! membership doors check in before they apply.
//!
//! - An Owner's and an Admin's add, move and remove go at once, and the
//!   change's receipt records the decision: the act class, the role, the
//!   mode and why it went (Q9).
//! - A Deputy's add goes on the person's own judgment (`sure`), and so does
//!   a Member's raise to Admin; a Deputy's remove, and any other move, waits
//!   for an Owner (Q3, Q5). The door commits the pending check-in alone,
//!   changes nothing and refuses with `CHECK_IN_PENDING`, whose reason code
//!   names the check-in (Q4); a repeat names the same one.
//! - Once the Owner approves, the call that names it as `check_in_ref` runs
//!   the change, spends the check-in in the same writer and records it; a
//!   ref before the answer, or over another effect, runs nothing.
//!
//! On the base (P2.4a) this file does not build: the receipt has no
//! `check_in` field, and `remove_shared_member_with_check_in`,
//! `SharedMemberRemoveRequest` and `Error::CheckInPending` do not exist.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test check_in_membership_effects`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use oneiron::check_in::CheckInDecision;
use oneiron::consent::AuthenticatedOwner;
use oneiron::federation::{FederationGrantRole as Role, InitialSharedMember};
use oneiron::memory::{CHECK_IN_PENDING_REASON_PREFIX, MEMORY_CODE_CHECK_IN_PENDING};
use oneiron::registry::{ENTITY_TYPE_FEDERATION_GRANT, ENTITY_TYPE_PERSON};
use oneiron::store::GateDecisionId;
use oneiron::task_verb::sdk::invoke;
use oneiron::verbs::{SharedMemberRemoveRequest, remove_shared_member_as};
use oneiron::{EdgeActorClass, EntityId, Error, TimeRange, Vault, VaultConfig};
use serde_json::json;

const SHARED: u64 = 43;

struct Org {
    _dir: tempfile::TempDir,
    vault: Vault,
    owner: EntityId,
    deputy: EntityId,
    admin: EntityId,
    member_a: EntityId,
    member_b: EntityId,
}

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

impl Org {
    /// A rooted vault whose shared vault holds the owner, a Deputy, an Admin
    /// and two Members, each of whom accepted.
    fn new() -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let vault = Vault::open(dir.path(), VaultConfig::device()).expect("vault");
        vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
        let issuer = oneiron::test_support::provision_engine_machines(&vault);
        let owner = vault.ensure_embedded_owner_actor().expect("owner");
        oneiron::test_support::bind_host_owner(&vault, &issuer, owner)
            .expect("the owner's binding");
        let [deputy, admin, member_a, member_b] = std::array::from_fn(|_| EntityId::now());
        for id in [deputy, admin, member_a, member_b] {
            person(&vault, id);
        }
        let member = |member_ref, role| InitialSharedMember {
            member_ref,
            role: Some(role),
        };
        vault
            .initialize_shared_vault(
                &proof(&vault, owner),
                SHARED,
                None,
                &[
                    member(owner, Role::Owner),
                    member(deputy, Role::Deputy),
                    member(admin, Role::Admin),
                    member(member_a, Role::Member),
                    member(member_b, Role::Member),
                ],
                1,
            )
            .expect("a shared vault with a Deputy, an Admin and two Members");
        accept(&vault, deputy, Role::Deputy);
        accept(&vault, admin, Role::Admin);
        accept(&vault, member_a, Role::Member);
        accept(&vault, member_b, Role::Member);
        Self {
            _dir: dir,
            vault,
            owner,
            deputy,
            admin,
            member_a,
            member_b,
        }
    }

    /// The role `member` holds in the shared vault now, from its grant rows.
    fn role_of(&self, member: EntityId) -> Option<Role> {
        self.vault
            .entities_by_type(ENTITY_TYPE_FEDERATION_GRANT)
            .expect("grants")
            .into_iter()
            .find_map(|id| {
                let body = self.vault.get(&id).expect("grant row")?;
                let grant = oneiron::federation::decode_federation_grant_body(&body).ok()?;
                (grant.member_ref == member && grant.role != Role::Delegate).then_some(grant.role)
            })
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
            "the Owner's approval makes the act eligible: {settled}"
        );
    }
}

/// The decision a receipt records for an act that went without a check-in.
fn went(act_class: &str, role: &str, mode: &str, basis: &str) -> Option<CheckInDecision> {
    Some(CheckInDecision {
        act_class: act_class.to_owned(),
        role: role.to_owned(),
        mode: Some(mode.to_owned()),
        basis: basis.to_owned(),
        check_in: None,
    })
}

/// The check-in id a waiting act's error names.
fn pending_id<T: std::fmt::Debug>(result: oneiron::Result<T>) -> String {
    match result {
        Err(Error::CheckInPending(id)) => id,
        other => panic!("the act waits on a check-in: {other:?}"),
    }
}

#[test]
fn an_owner_and_an_admin_change_members_at_once_and_the_receipt_records_it() {
    let org = Org::new();
    let removed = org
        .vault
        .remove_shared_member(&proof(&org.vault, org.owner), SHARED, org.member_a, None)
        .expect("the Owner removes a Member");
    assert_eq!(
        removed.check_in,
        went("member_remove", "owner", "full-access", "never_ask"),
        "the Owner's remove goes, and its receipt records why"
    );
    assert_eq!(org.role_of(org.member_a), None, "the Member is gone");
    let moved = org
        .vault
        .change_shared_member_role(
            &proof(&org.vault, org.admin),
            SHARED,
            org.member_b,
            Role::Viewer,
            None,
        )
        .expect("the Admin moves a Member to Viewer");
    assert_eq!(
        moved.check_in,
        went("member_remove", "admin", "full-access", "never_ask"),
        "an Admin's move goes at once"
    );
    assert_eq!(org.role_of(org.member_b), Some(Role::Viewer));
}

#[test]
fn a_deputys_add_and_raise_go_on_their_own_judgment() {
    let org = Org::new();
    let deputy = proof(&org.vault, org.deputy);
    let newcomer = EntityId::now();
    person(&org.vault, newcomer);
    let invited = org
        .vault
        .add_shared_member(&deputy, SHARED, newcomer, Some(Role::Member))
        .expect("the Deputy invites a member");
    assert_eq!(
        invited.check_in,
        went("member_add", "deputy", "auto", "sure"),
        "a Deputy asks when unsure on an add, and a person's own act is sure"
    );
    let raised = org
        .vault
        .change_shared_member_role(&deputy, SHARED, org.member_a, Role::Admin, None)
        .expect("the Deputy raises a Member to Admin");
    assert_eq!(
        raised.check_in,
        went("member_add", "deputy", "auto", "sure"),
        "a Member's raise to Admin is a member add"
    );
    assert_eq!(org.role_of(org.member_a), Some(Role::Admin));
}

#[test]
fn a_deputys_remove_waits_for_the_owner_and_the_approved_recall_runs_once() {
    let org = Org::new();
    let deputy = proof(&org.vault, org.deputy);
    let first = pending_id(
        org.vault
            .remove_shared_member(&deputy, SHARED, org.member_a, None),
    );
    assert_eq!(
        org.role_of(org.member_a),
        Some(Role::Member),
        "a waiting remove changes nothing"
    );
    let refused = remove_shared_member_as(
        &org.vault,
        &deputy,
        None,
        SharedMemberRemoveRequest {
            vault_id: SHARED,
            member: org.member_a.to_hex(),
            check_in_ref: None,
        },
    )
    .expect_err("the verb answers the wait");
    assert_eq!(
        (refused.code.as_str(), refused.reason_codes.clone()),
        (
            MEMORY_CODE_CHECK_IN_PENDING,
            vec![format!("{CHECK_IN_PENDING_REASON_PREFIX}{first}")]
        ),
        "a repeat of the same remove names the same check-in: {refused:?}"
    );
    let early = org.vault.remove_shared_member_with_check_in(
        &deputy,
        SHARED,
        org.member_a,
        None,
        Some(EntityId::from_hex(&first).expect("a check-in id")),
    );
    assert!(
        early.is_err(),
        "no holder answered, so the ref runs nothing: {early:?}"
    );
    assert_eq!(org.role_of(org.member_a), Some(Role::Member));

    org.owner_approves(&first);
    let check_in = EntityId::from_hex(&first).expect("a check-in id");
    let other = org.vault.remove_shared_member_with_check_in(
        &deputy,
        SHARED,
        org.member_b,
        None,
        Some(check_in),
    );
    assert!(
        other.is_err(),
        "the approval is over one effect, not another member's removal: {other:?}"
    );
    assert_eq!(org.role_of(org.member_b), Some(Role::Member));
    let removed = org
        .vault
        .remove_shared_member_with_check_in(&deputy, SHARED, org.member_a, None, Some(check_in))
        .expect("the approved remove runs");
    assert_eq!(
        removed.check_in,
        Some(CheckInDecision {
            act_class: "member_remove".to_owned(),
            role: "deputy".to_owned(),
            mode: Some("manual".to_owned()),
            basis: "approved".to_owned(),
            check_in: Some(first.clone()),
        }),
        "the receipt names the check-in the remove spent"
    );
    assert_eq!(org.role_of(org.member_a), None, "the Member is gone");
    let spent = org
        .vault
        .pending_check_in(&check_in)
        .expect("read the check-in")
        .expect("the check-in is stored");
    assert!(spent.consumed_at.is_some(), "the remove spent the check-in");
}

#[test]
fn a_deputys_demote_waits_for_the_owner() {
    let org = Org::new();
    let deputy = proof(&org.vault, org.deputy);
    pending_id(
        org.vault
            .change_shared_member_role(&deputy, SHARED, org.admin, Role::Member, None),
    );
    assert_eq!(
        org.role_of(org.admin),
        Some(Role::Admin),
        "an Admin's demotion to Member is a member remove, which a Deputy always asks"
    );
}
