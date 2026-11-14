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
//! - The same holds when a Deputy applies a Steward's ask: the ask stays
//!   open while the apply waits, and the approved re-call applies and
//!   closes it, its receipt naming the Steward (review of P2.4b).
//! - A Deputy's remove or move of a house mind is refused at once, as the
//!   door refuses it, and opens no check-in: only the house doors move a
//!   house (review of P2.4b).
//! - So is a Deputy's move of a member to Steward or Deputy: only an Owner
//!   gives those roles (main's #7439), so the move opens no check-in.
//!
//! The vault is rooted, and a rooted vault admits only a writer its
//! authority log binds. The host key holds one live binding, so each
//! person's acts run while the fixture binds the key to that person, and the
//! key goes back to the owner after (`Org::as_person`, as delete_authority.rs
//! does).
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

use oneiron::authority::{HostSlipIssuer, MachineRole};
use oneiron::check_in::CheckInDecision;
use oneiron::consent::AuthenticatedOwner;
use oneiron::error::ClaimError;
use oneiron::federation::{
    FederationGrantRole as Role, InitialSharedMember, MemberAskChange, MemberAskStatus,
};
use oneiron::memory::{CHECK_IN_PENDING_REASON_PREFIX, MEMORY_CODE_CHECK_IN_PENDING};
use oneiron::registry::{ENTITY_TYPE_FEDERATION_GRANT, ENTITY_TYPE_ORG, ENTITY_TYPE_PERSON};
use oneiron::store::GateDecisionId;
use oneiron::task_verb::sdk::invoke;
use oneiron::test_support::{bind_host_actor, bind_host_owner};
use oneiron::verbs::{SharedMemberRemoveRequest, remove_shared_member_as};
use oneiron::workspace_roster::{WorkCompanionPolicy, WorkspaceRosterPreset};
use oneiron::{EdgeActorClass, EntityId, Error, TimeRange, Vault, VaultConfig};
use serde_json::json;

const SHARED: u64 = 43;
/// The stored workspace whose house the house cases bind.
const HOUSE_WORKSPACE: &str = "check-in-membership-workspace";

struct Org {
    _dir: tempfile::TempDir,
    vault: Vault,
    issuer: HostSlipIssuer,
    owner: EntityId,
    deputy: EntityId,
    admin: EntityId,
    steward: EntityId,
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

/// `person`'s proof. An Admin's or a Deputy's membership act stands on an
/// MFA step-up (L7-17); these people hold no slip, so each proof carries a
/// managed supervisor's `mfa_verified` claim. Only the org-admin step-up
/// reads it, and an Owner needs none.
fn proof(vault: &Vault, person: EntityId) -> AuthenticatedOwner {
    let proof = vault
        .authenticate_owner(person, &person.to_hex(), true, GateDecisionId::now())
        .expect("a person proof");
    vault
        .bind_managed_mfa_verified(proof)
        .expect("the supervisor's MFA claim binds")
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

/// The role `member` holds in the shared vault now, from its grant rows.
fn role_in(vault: &Vault, member: EntityId) -> Option<Role> {
    vault
        .entities_by_type(ENTITY_TYPE_FEDERATION_GRANT)
        .expect("grants")
        .into_iter()
        .find_map(|id| {
            let body = vault.get(&id).expect("grant row")?;
            let grant = oneiron::federation::decode_federation_grant_body(&body).ok()?;
            (grant.member_ref == member && grant.role != Role::Delegate).then_some(grant.role)
        })
}

impl Org {
    /// A rooted vault whose shared vault holds the owner, a Deputy, an Admin,
    /// a Steward and two Members, each of whom accepted.
    fn new() -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let vault = Vault::open(dir.path(), VaultConfig::device()).expect("vault");
        vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
        let issuer = oneiron::test_support::provision_engine_machines(&vault);
        let owner = vault.ensure_embedded_owner_actor().expect("owner");
        bind_host_owner(&vault, &issuer, owner).expect("the owner's binding");
        let [deputy, admin, steward, member_a, member_b] = std::array::from_fn(|_| EntityId::now());
        for id in [deputy, admin, steward, member_a, member_b] {
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
                    member(steward, Role::Steward),
                    member(member_a, Role::Member),
                    member(member_b, Role::Member),
                ],
                1,
            )
            .expect("a shared vault with a Deputy, an Admin, a Steward and two Members");
        accept(&vault, deputy, Role::Deputy);
        accept(&vault, admin, Role::Admin);
        accept(&vault, steward, Role::Steward);
        accept(&vault, member_a, Role::Member);
        accept(&vault, member_b, Role::Member);
        Self {
            _dir: dir,
            vault,
            issuer,
            owner,
            deputy,
            admin,
            steward,
            member_a,
            member_b,
        }
    }

    /// Runs `act` with the host key bound to `person`, then binds the key
    /// back to the owner: a rooted vault admits only a bound writer, and the
    /// host key holds one live binding.
    fn as_person<T>(&self, person: EntityId, act: impl FnOnce() -> T) -> T {
        bind_host_actor(&self.vault, &self.issuer, person, "human")
            .expect("the host key bound to the person for its act");
        let answer = act();
        bind_host_owner(&self.vault, &self.issuer, self.owner).expect("the owner's binding again");
        answer
    }

    /// The role `member` holds in the shared vault now, from its grant rows.
    fn role_of(&self, member: EntityId) -> Option<Role> {
        role_in(&self.vault, member)
    }

    /// The status of member ask `ask`, as the Owner reads it.
    fn ask_status(&self, ask: &str) -> MemberAskStatus {
        self.vault
            .shared_member_asks(&proof(&self.vault, self.owner), SHARED)
            .expect("the Owner reads the asks")
            .into_iter()
            .find(|open| open.id == ask)
            .expect("the ask is stored")
            .status
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
        requester: None,
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
        .as_person(org.admin, || {
            org.vault.change_shared_member_role(
                &proof(&org.vault, org.admin),
                SHARED,
                org.member_b,
                Role::Viewer,
                None,
            )
        })
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
        .as_person(org.deputy, || {
            org.vault
                .add_shared_member(&deputy, SHARED, newcomer, Some(Role::Member))
        })
        .expect("the Deputy invites a member");
    assert_eq!(
        invited.check_in,
        went("member_add", "deputy", "auto", "sure"),
        "a Deputy asks when unsure on an add, and a person's own act is sure"
    );
    let raised = org
        .as_person(org.deputy, || {
            org.vault
                .change_shared_member_role(&deputy, SHARED, org.member_a, Role::Admin, None)
        })
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
    let first = pending_id(org.as_person(org.deputy, || {
        org.vault
            .remove_shared_member(&deputy, SHARED, org.member_a, None)
    }));
    assert_eq!(
        org.role_of(org.member_a),
        Some(Role::Member),
        "a waiting remove changes nothing"
    );
    let refused = org
        .as_person(org.deputy, || {
            remove_shared_member_as(
                &org.vault,
                &deputy,
                None,
                SharedMemberRemoveRequest {
                    vault_id: SHARED,
                    member: org.member_a.to_hex(),
                    check_in_ref: None,
                },
            )
        })
        .expect_err("the verb answers the wait");
    assert_eq!(
        (refused.code.as_str(), refused.reason_codes.clone()),
        (
            MEMORY_CODE_CHECK_IN_PENDING,
            vec![format!("{CHECK_IN_PENDING_REASON_PREFIX}{first}")]
        ),
        "a repeat of the same remove names the same check-in: {refused:?}"
    );
    let early = org.as_person(org.deputy, || {
        org.vault.remove_shared_member_with_check_in(
            &deputy,
            SHARED,
            org.member_a,
            None,
            Some(EntityId::from_hex(&first).expect("a check-in id")),
        )
    });
    assert!(
        early.is_err(),
        "no holder answered, so the ref runs nothing: {early:?}"
    );
    assert_eq!(org.role_of(org.member_a), Some(Role::Member));

    org.owner_approves(&first);
    let check_in = EntityId::from_hex(&first).expect("a check-in id");
    let other = org.as_person(org.deputy, || {
        org.vault.remove_shared_member_with_check_in(
            &deputy,
            SHARED,
            org.member_b,
            None,
            Some(check_in),
        )
    });
    assert!(
        other.is_err(),
        "the approval is over one effect, not another member's removal: {other:?}"
    );
    assert_eq!(org.role_of(org.member_b), Some(Role::Member));
    let removed = org
        .as_person(org.deputy, || {
            org.vault.remove_shared_member_with_check_in(
                &deputy,
                SHARED,
                org.member_a,
                None,
                Some(check_in),
            )
        })
        .expect("the approved remove runs");
    assert_eq!(
        removed.check_in,
        Some(CheckInDecision {
            act_class: "member_remove".to_owned(),
            role: "deputy".to_owned(),
            mode: Some("manual".to_owned()),
            basis: "approved".to_owned(),
            check_in: Some(first.clone()),
            requester: None,
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
    pending_id(org.as_person(org.deputy, || {
        org.vault
            .change_shared_member_role(&deputy, SHARED, org.admin, Role::Member, None)
    }));
    assert_eq!(
        org.role_of(org.admin),
        Some(Role::Admin),
        "an Admin's demotion to Member is a member remove, which a Deputy always asks"
    );
}

#[test]
fn a_deputys_apply_of_a_stewards_ask_waits_and_the_approved_recall_closes_it() {
    let org = Org::new();
    let ask = org
        .as_person(org.steward, || {
            org.vault.ask_shared_member_change(
                &proof(&org.vault, org.steward),
                SHARED,
                MemberAskChange::Remove {
                    member: org.member_a.to_hex(),
                },
            )
        })
        .expect("the Steward asks to remove a Member");
    let deputy = proof(&org.vault, org.deputy);
    let first = pending_id(org.as_person(org.deputy, || {
        org.vault.apply_shared_member_ask(&deputy, &ask.id, None)
    }));
    assert_eq!(
        org.role_of(org.member_a),
        Some(Role::Member),
        "a waiting apply changes nothing"
    );
    assert_eq!(
        org.ask_status(&ask.id),
        MemberAskStatus::Open,
        "the ask stays open while its apply waits"
    );
    org.owner_approves(&first);
    let check_in = EntityId::from_hex(&first).expect("a check-in id");
    let receipt = org
        .as_person(org.deputy, || {
            org.vault
                .apply_shared_member_ask_with_check_in(&deputy, &ask.id, None, Some(check_in))
        })
        .expect("the approved apply runs");
    assert_eq!(
        receipt.proposer,
        Some(org.steward.to_hex()),
        "the receipt names the Steward who asked"
    );
    assert_eq!(
        receipt
            .check_in
            .as_ref()
            .and_then(|decision| decision.check_in.clone()),
        Some(first),
        "the receipt names the check-in the apply spent"
    );
    assert_eq!(org.role_of(org.member_a), None, "the Member is gone");
    assert!(
        matches!(org.ask_status(&ask.id), MemberAskStatus::Applied { .. }),
        "the apply closed the ask"
    );
}

/// A rooted, profiled vault (as a host starts one) whose shared vault holds
/// the owner and a person Deputy who accepted, and whose stored workspace's
/// house, the seeded `sys.default` agent, the owner binds as a Member. It
/// answers the vault, the Deputy and the house, with the host key bound to
/// the Deputy, who alone acts in the house cases (a rooted vault admits only
/// a bound writer).
fn house_org() -> (tempfile::TempDir, Vault, EntityId, EntityId) {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("vault");
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    let issuer = oneiron::test_support::provision_engine_machines(&vault);
    vault
        .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
        .expect("this install's live machine profile");
    let owner = vault.ensure_embedded_owner_actor().expect("owner");
    bind_host_owner(&vault, &issuer, owner).expect("the owner's binding");
    let owner_proof = proof(&vault, owner);
    let signer = vault
        .owner_project_signer(&issuer)
        .expect("the owner's project signer");
    let root = vault.root_project().expect("the root project");
    vault
        .sign_owner_project(&owner_proof, &signer, root)
        .expect("the root's first signature");
    let deputy = EntityId::now();
    person(&vault, deputy);
    vault
        .initialize_shared_vault(
            &owner_proof,
            SHARED,
            None,
            &[
                InitialSharedMember {
                    member_ref: owner,
                    role: Some(Role::Owner),
                },
                InitialSharedMember {
                    member_ref: deputy,
                    role: Some(Role::Deputy),
                },
            ],
            1,
        )
        .expect("a shared vault with a Deputy");
    accept(&vault, deputy, Role::Deputy);
    let org = EntityId::now();
    vault
        .put_entity(
            &org,
            ENTITY_TYPE_ORG,
            TimeRange { start: 1, end: 1 },
            1,
            b"check-in membership org",
        )
        .expect("org row");
    let (house, _) = vault
        .get_seeded_agent_definition_by_logical_id("sys.default")
        .expect("read the seeded agents")
        .expect("sys.default is seeded on open");
    let preset = WorkspaceRosterPreset {
        workspace_ref: HOUSE_WORKSPACE.to_owned(),
        workspace_vault_id: SHARED,
        org_ref: org,
        venture_name: "Garden Works".to_owned(),
        house_display_name: None,
        house_actor_ref: house,
        house_identity_ref: None,
    };
    vault
        .establish_workspace_preset(&preset, WorkCompanionPolicy::Choose, &owner_proof)
        .expect("the owner stores the workspace");
    vault
        .bind_workspace_house_leader(HOUSE_WORKSPACE, Role::Member, &owner_proof, &signer)
        .expect("the owner binds the house as a Member");
    bind_host_actor(&vault, &issuer, deputy, "human").expect("the host key bound to the Deputy");
    (dir, vault, deputy, house)
}

#[test]
fn a_deputys_remove_or_move_of_a_house_is_refused_and_opens_no_check_in() {
    let (_dir, vault, deputy, house) = house_org();
    assert_eq!(
        role_in(&vault, house),
        Some(Role::Member),
        "the house is bound as a Member"
    );
    let deputy = proof(&vault, deputy);
    let removed = vault.remove_shared_member(&deputy, SHARED, house, None);
    assert!(
        matches!(removed, Err(Error::InvalidConfig(_))),
        "only the house doors move a house, so the remove is refused, not asked: {removed:?}"
    );
    let moved = vault.change_shared_member_role(&deputy, SHARED, house, Role::Viewer, None);
    assert!(
        matches!(moved, Err(Error::InvalidConfig(_))),
        "a move to Viewer is a member remove, refused before any ask: {moved:?}"
    );
    assert_eq!(
        role_in(&vault, house),
        Some(Role::Member),
        "the house keeps its role"
    );
}

#[test]
fn a_deputys_move_to_a_role_only_an_owner_gives_is_refused_and_opens_no_check_in() {
    let org = Org::new();
    let deputy = proof(&org.vault, org.deputy);
    for role in [Role::Steward, Role::Deputy] {
        let moved = org.as_person(org.deputy, || {
            org.vault
                .change_shared_member_role(&deputy, SHARED, org.member_a, role, None)
        });
        assert!(
            matches!(
                moved,
                Err(Error::Claim(ClaimError::ActorLacksClaimAuthority {
                    reason: "only an owner of the vault gives the Steward or Deputy role"
                }))
            ),
            "only an Owner gives {role:?}, so the move is refused, not asked: {moved:?}"
        );
    }
    assert_eq!(
        org.role_of(org.member_a),
        Some(Role::Member),
        "the Member keeps its role"
    );
}
