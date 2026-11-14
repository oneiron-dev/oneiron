//! ROLES-CHECKIN P2.5, row 2k8f (ARCH-0082 #act-table "Widen another's
//! grant", #role-defaults and #owner-own-acts; Engine rulings P25-SHAPE Q1
//! = A, 14 Nov 13:39, and MEMBER-SHARE-OWN = B, 19:33):
//! `vault.rooms.pins.policy.set` judges a person who opens an ordinary
//! room's pins to every member.
//!
//! - The Owner's opening is never gated: it goes on their own proof, and the
//!   reply records that decision. A `check_in_ref` on it is refused and
//!   changes nothing.
//! - A member who runs a room another created is judged under their
//!   membership role. A Deputy's opening goes on their own judgment (`sure`)
//!   and an Admin's at once (`never_ask`). A Steward's and a Member's wait:
//!   the set commits the pending check-in alone, changes nothing and answers
//!   `CHECK_IN_PENDING` naming it; a repeat names the same one. Before the
//!   Owner approves it, the call that names it changes nothing. Once
//!   approved, that call opens the pins, spends it, and its reply names it.
//! - A Member opens the pins of the room it created at once, with basis
//!   `own_item`.
//! - Narrowing the pins to the managers is not judged, as on main: its reply
//!   records no decision.
//!
//! The vault is rooted, and the host key holds one live binding: the fixture
//! binds it to each person for their call, then back to the owner. Only a
//! room's Owner or Admin sets its policy, so the owner makes each other
//! person an Admin of the rooms they run.
//!
//! On its base, 2k8e3's head (572efa77a1e), this file does not build: the
//! pin policy set has no `check_in_ref`, and its reply is the request type,
//! with no `check_in`.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test check_in_room_pins_policy_effects`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use oneiron::authority::HostSlipIssuer;
use oneiron::check_in::CheckInDecision;
use oneiron::consent::AuthenticatedOwner;
use oneiron::conversation::{ConversationBody, ConversationKind, RoomPinPolicy, RoomRole};
use oneiron::federation::{FederationGrantRole as Role, InitialSharedMember};
use oneiron::memory::{CHECK_IN_PENDING_REASON_PREFIX, MEMORY_CODE_CHECK_IN_PENDING, MemoryResult};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::store::GateDecisionId;
use oneiron::task_verb::sdk::invoke;
use oneiron::temporal::TimeRange;
use oneiron::test_support::{bind_host_actor, bind_host_owner};
use oneiron::workspace_roster::{RoomPinPolicyReply, RoomPinPolicySet};
use oneiron::{EdgeActorClass, EntityId, Vault, VaultConfig, WriteActor};
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
/// Member, each of whom accepted, and two ordinary rooms: one the owner
/// created, where each other person is a room Admin, and one the Member
/// created, where the Member is.
struct Org {
    _dir: tempfile::TempDir,
    vault: Vault,
    issuer: HostSlipIssuer,
    owner: EntityId,
    deputy: EntityId,
    admin: EntityId,
    steward: EntityId,
    member: EntityId,
    owners_room: EntityId,
    members_room: EntityId,
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

        let as_owner = WriteActor::new(owner, EdgeActorClass::Human);
        let room = |members: Vec<EntityId>| ConversationBody {
            kind: ConversationKind::Group,
            member_ids: members,
            ..Default::default()
        };
        let owners_room = EntityId::now();
        vault
            .create_conversation(
                owners_room,
                &room(vec![deputy, admin, steward, member]),
                as_owner,
                vault.now_recorded_at(),
            )
            .expect("the owner creates a room");
        for id in [deputy, admin, steward, member] {
            vault
                .set_room_role(owners_room, id, RoomRole::Admin, as_owner)
                .expect("the owner makes each person an Admin of its room");
        }
        let members_room = EntityId::now();
        bind_host_actor(&vault, &issuer, member, "human")
            .expect("the host key bound to the Member for its create");
        vault
            .create_conversation(
                members_room,
                &room(vec![member]),
                WriteActor::new(member, EdgeActorClass::Human),
                vault.now_recorded_at(),
            )
            .expect("the Member creates a room");
        bind_host_owner(&vault, &issuer, owner).expect("the owner's binding again");
        vault
            .set_room_role(members_room, member, RoomRole::Admin, as_owner)
            .expect("the owner makes the Member an Admin of its own room");
        Self {
            _dir: dir,
            vault,
            issuer,
            owner,
            deputy,
            admin,
            steward,
            member,
            owners_room,
            members_room,
        }
    }

    /// `person`'s `vault.rooms.pins.policy.set` of `room` to `policy`, the
    /// host key bound to them for the call.
    fn set(
        &self,
        person: EntityId,
        room: EntityId,
        policy: RoomPinPolicy,
        check_in_ref: Option<&str>,
    ) -> MemoryResult<RoomPinPolicyReply> {
        if person != self.owner {
            bind_host_actor(&self.vault, &self.issuer, person, "human")
                .expect("the host key bound to the person for its call");
        }
        let reply = self
            .vault
            .memory(person, EdgeActorClass::Human)
            .rooms_pins_policy_set(&RoomPinPolicySet {
                room,
                policy,
                check_in_ref: check_in_ref.map(str::to_owned),
            });
        bind_host_owner(&self.vault, &self.issuer, self.owner).expect("the owner's binding again");
        reply
    }

    /// The owner narrows `room`'s pins to its managers: not judged.
    fn narrow(&self, room: EntityId) {
        let reply = self
            .set(self.owner, room, RoomPinPolicy::Managers, None)
            .expect("the owner narrows the pins");
        assert_eq!(reply.policy, RoomPinPolicy::Managers);
        assert_eq!(reply.check_in, None, "a narrowing is not judged");
    }

    fn policy(&self, room: EntityId) -> RoomPinPolicy {
        self.vault
            .conversation_body(room)
            .expect("the room body")
            .pin_policy
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
            "the Owner's approval makes the opening eligible: {settled}"
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

/// The check-in a waiting set names.
fn pending_id(result: MemoryResult<RoomPinPolicyReply>) -> String {
    let refused = result.expect_err("the set waits on a check-in");
    assert_eq!(
        refused.code, MEMORY_CODE_CHECK_IN_PENDING,
        "the set waits: {refused:?}"
    );
    refused
        .reason_codes
        .first()
        .and_then(|code| code.strip_prefix(CHECK_IN_PENDING_REASON_PREFIX))
        .expect("the reason code names the check-in")
        .to_owned()
}

fn decision(role: &str, mode: Option<&str>, basis: &str) -> CheckInDecision {
    CheckInDecision {
        act_class: "grant_widen".to_owned(),
        role: role.to_owned(),
        mode: mode.map(str::to_owned),
        basis: basis.to_owned(),
        check_in: None,
        requester: None,
    }
}

#[test]
fn the_owners_opening_goes_on_their_own_proof_and_takes_no_check_in() {
    let org = Org::new();
    org.narrow(org.owners_room);
    assert!(
        org.set(
            org.owner,
            org.owners_room,
            RoomPinPolicy::Members,
            Some(&EntityId::now().to_hex()),
        )
        .is_err(),
        "an Owner's opening waits on no check-in"
    );
    assert_eq!(org.policy(org.owners_room), RoomPinPolicy::Managers);
    let reply = org
        .set(org.owner, org.owners_room, RoomPinPolicy::Members, None)
        .expect("the Owner opens the pins");
    assert_eq!(reply.policy, RoomPinPolicy::Members);
    assert_eq!(
        reply.check_in,
        Some(decision("owner", None, "own_proof")),
        "the Owner's opening records their own proof"
    );
}

#[test]
fn a_deputys_and_an_admins_opening_go_at_once_and_record_why() {
    let org = Org::new();
    let cases = [
        (org.deputy, "deputy", "auto", "sure"),
        (org.admin, "admin", "full-access", "never_ask"),
    ];
    for (holder, name, mode, basis) in cases {
        org.narrow(org.owners_room);
        let reply = org
            .set(holder, org.owners_room, RoomPinPolicy::Members, None)
            .unwrap_or_else(|error| panic!("the {name} opens the pins at once: {error:?}"));
        assert_eq!(reply.policy, RoomPinPolicy::Members);
        assert_eq!(
            reply.check_in,
            Some(decision(name, Some(mode), basis)),
            "the {name}'s reply names the role and why it went"
        );
    }
}

#[test]
fn a_stewards_and_a_members_opening_of_anothers_room_waits_until_approved() {
    let org = Org::new();
    org.narrow(org.owners_room);
    let steward = pending_id(org.set(org.steward, org.owners_room, RoomPinPolicy::Members, None));
    assert_eq!(
        pending_id(org.set(org.steward, org.owners_room, RoomPinPolicy::Members, None)),
        steward,
        "a repeat finds the same check-in"
    );
    let member = pending_id(org.set(org.member, org.owners_room, RoomPinPolicy::Members, None));
    assert_ne!(member, steward, "each person asks on their own");
    assert_eq!(
        org.policy(org.owners_room),
        RoomPinPolicy::Managers,
        "a waiting opening changes nothing"
    );

    assert!(
        org.set(
            org.member,
            org.owners_room,
            RoomPinPolicy::Members,
            Some(&member)
        )
        .is_err(),
        "an unanswered check-in opens nothing"
    );
    assert_eq!(org.policy(org.owners_room), RoomPinPolicy::Managers);
    assert!(!org.spent(&member));

    org.owner_approves(&member);
    let reply = org
        .set(
            org.member,
            org.owners_room,
            RoomPinPolicy::Members,
            Some(&member),
        )
        .expect("the approved opening goes");
    assert_eq!(reply.policy, RoomPinPolicy::Members);
    assert_eq!(
        reply.check_in,
        Some(CheckInDecision {
            check_in: Some(member.clone()),
            ..decision("member", Some("manual"), "approved")
        }),
        "the reply names the check-in it spent"
    );
    assert!(org.spent(&member), "the opening spends its check-in");
    assert!(!org.spent(&steward), "the Steward's ask still waits");
}

#[test]
fn a_member_opens_the_room_it_created_as_its_own_item() {
    let org = Org::new();
    let narrowed = org
        .set(org.member, org.members_room, RoomPinPolicy::Managers, None)
        .expect("the Member narrows its own room's pins");
    assert_eq!(narrowed.check_in, None, "a narrowing is not judged");
    let reply = org
        .set(org.member, org.members_room, RoomPinPolicy::Members, None)
        .expect("the Member opens its own room's pins at once");
    assert_eq!(reply.policy, RoomPinPolicy::Members);
    assert_eq!(
        reply.check_in,
        Some(decision("member", Some("full-access"), "own_item")),
        "the creator's opening is its own item's"
    );
}
