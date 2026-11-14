//! ROLES-CHECKIN P2.5, row 2k8e3 (ARCH-0082 #act-table "Widen another's
//! grant", #role-defaults and #owner-own-acts; Engine rulings P25-SHAPE Q1
//! = A, 14 Nov 13:39, and P25-2K8-SCOPE Q5 = A, 19:32): two doors a person
//! reaches by role take the writer judge (2i), `vault.members.delegate` and
//! `vault.shared.policy.propose`. Neither door waits for any role that
//! reaches it, so neither request names a check-in.
//!
//! - The Owner's Delegate mint is never gated: it goes on their own proof,
//!   and the answer records that decision.
//! - A Deputy's mint goes on their own judgment (`sure`) and an Admin's at
//!   once (`never_ask`, the parent grant naming the power); each answer names
//!   the role and why it went.
//! - A Steward's and a Member's parent grant delegates nothing, as on main.
//! - The Owner's shared policy proposal goes on their own proof: the change
//!   records that decision, and so does the stored change read back.
//! - An Admin, no editor of any row, proposes nothing, as on main.
//!
//! On its base, 2k8e2's head, this file does not build: neither the
//! Delegate answer nor the policy change has a `check_in`.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test check_in_delegate_shared_policy_effects`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use oneiron::check_in::CheckInDecision;
use oneiron::consent::AuthenticatedOwner;
use oneiron::federation::{
    FederationGrantRole as Role, InitialSharedMember, SharedActPolicyChangeState,
    decode_federation_grant_body,
};
use oneiron::registry::{ENTITY_TYPE_FEDERATION_GRANT, ENTITY_TYPE_PERSON};
use oneiron::store::GateDecisionId;
use oneiron::temporal::TimeRange;
use oneiron::test_support::bind_host_owner;
use oneiron::verbs::{
    FederationDelegateRequest, FederationMemberGrant, SharedActPolicyChangeRequest,
    SharedActPolicyProposeRequest, create_federation_delegate_as, propose_shared_act_policy_change,
    read_shared_act_policy_change,
};
use oneiron::{EntityId, Vault, VaultConfig};

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

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_secs()
}

/// A rooted shared vault: its owner, a Deputy, an Admin, a Steward and a
/// Member, each of whom accepted, and a newcomer PERSON each delegates to.
struct Org {
    _dir: tempfile::TempDir,
    vault: Vault,
    owner: EntityId,
    deputy: EntityId,
    admin: EntityId,
    steward: EntityId,
    member: EntityId,
    newcomer: EntityId,
}

impl Org {
    fn new() -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let vault = Vault::open(dir.path(), VaultConfig::device()).expect("vault");
        vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
        let issuer = oneiron::test_support::provision_engine_machines(&vault);
        let owner = vault.ensure_embedded_owner_actor().expect("owner");
        bind_host_owner(&vault, &issuer, owner).expect("the owner's binding");
        let [deputy, admin, steward, member, newcomer] = std::array::from_fn(|_| EntityId::now());
        for id in [deputy, admin, steward, member, newcomer] {
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
            owner,
            deputy,
            admin,
            steward,
            member,
            newcomer,
        }
    }

    /// `person`'s membership grant on the shared vault, at `role`.
    fn grant_of(&self, person: EntityId, role: Role) -> EntityId {
        self.vault
            .entities_by_type(ENTITY_TYPE_FEDERATION_GRANT)
            .expect("grants")
            .into_iter()
            .find(|id| {
                self.vault
                    .get(id)
                    .expect("grant row")
                    .map(|body| decode_federation_grant_body(&body).expect("a grant"))
                    .is_some_and(|grant| grant.member_ref == person && grant.role == role)
            })
            .expect("the member's grant")
    }

    /// `holder` delegates from their `role` grant to the newcomer through
    /// the verb, narrowed to the ceiling an unscoped mint reads back.
    fn delegate(&self, holder: EntityId, role: Role) -> Result<FederationMemberGrant, String> {
        let parent = self.grant_of(holder, role);
        let holder_proof = proof(&self.vault, holder);
        let now = now_secs();
        let ceiling = self
            .vault
            .create_federation_delegate(&holder_proof, parent, self.newcomer, now, now + 3600)
            .map_err(|error| format!("{error:?}"))?;
        let body = self
            .vault
            .get(&ceiling)
            .expect("delegate row")
            .expect("a stored delegate");
        let authority_scope = decode_federation_grant_body(&body)
            .expect("a delegate grant")
            .authority_scope;
        create_federation_delegate_as(
            &self.vault,
            &holder_proof,
            FederationDelegateRequest {
                parent_grant: parent,
                member_ref: self.newcomer,
                authority_scope,
                expires_at: now + 3600,
            },
        )
        .map_err(|error| format!("{error:?}"))
    }

    /// `proposer` proposes doubling the `erase` row's wait, against the
    /// rows the Owner reads now.
    fn propose_longer_erase_wait(
        &self,
        proposer: EntityId,
    ) -> oneiron::memory::MemoryResult<oneiron::federation::SharedActPolicyChange> {
        let view = self
            .vault
            .shared_act_policies(&proof(&self.vault, self.owner), SHARED)
            .expect("the Owner reads the rows");
        let mut row = view.effective["erase"].clone();
        row.wait_secs *= 2;
        propose_shared_act_policy_change(
            &self.vault,
            &proof(&self.vault, proposer),
            SharedActPolicyProposeRequest {
                vault_id: SHARED,
                act: "erase".to_owned(),
                policy: Some(row),
                expected_policy_hash: view.policy_hash,
            },
        )
    }
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
fn the_owners_delegate_goes_on_their_own_proof_and_records_it() {
    let org = Org::new();
    let grant = org
        .delegate(org.owner, Role::Owner)
        .expect("the Owner delegates");
    assert_eq!(grant.role, Role::Delegate);
    assert_eq!(grant.member_ref, org.newcomer);
    assert_eq!(grant.delegated_by, Some(org.owner));
    assert_eq!(
        grant.check_in,
        Some(decision("owner", None, "own_proof")),
        "the Owner's mint records their own proof"
    );
}

#[test]
fn a_deputys_and_an_admins_delegate_go_at_once_and_record_why() {
    let org = Org::new();
    let cases = [
        (org.deputy, Role::Deputy, "deputy", "auto", "sure"),
        (org.admin, Role::Admin, "admin", "full-access", "never_ask"),
    ];
    for (holder, role, name, mode, basis) in cases {
        let grant = org
            .delegate(holder, role)
            .unwrap_or_else(|error| panic!("the {name} delegates at once: {error}"));
        assert_eq!(
            grant.role,
            Role::Delegate,
            "the {name}'s mint is a Delegate"
        );
        assert_eq!(grant.delegated_by, Some(holder));
        assert_eq!(
            grant.check_in,
            Some(decision(name, Some(mode), basis)),
            "the {name}'s answer names the role and why it went"
        );
    }
}

#[test]
fn a_stewards_and_a_members_grant_delegates_nothing_as_on_main() {
    let org = Org::new();
    for (holder, role) in [(org.steward, Role::Steward), (org.member, Role::Member)] {
        assert!(
            org.delegate(holder, role).is_err(),
            "a {role:?} grant parents no delegate"
        );
    }
}

#[test]
fn the_owners_policy_proposal_goes_on_their_own_proof_and_the_change_keeps_it() {
    let org = Org::new();
    let change = org
        .propose_longer_erase_wait(org.owner)
        .expect("the Owner proposes");
    assert_eq!(
        change.state,
        SharedActPolicyChangeState::Applied,
        "the sole live editor's change applies at once"
    );
    let own_proof = Some(decision("owner", None, "own_proof"));
    assert_eq!(
        change.check_in, own_proof,
        "the proposal records the Owner's own proof"
    );
    let stored = read_shared_act_policy_change(
        &org.vault,
        &proof(&org.vault, org.owner),
        SharedActPolicyChangeRequest {
            change_id: change.id.clone(),
        },
    )
    .expect("the Owner reads the change back");
    assert_eq!(
        stored.check_in, own_proof,
        "the stored change keeps the decision"
    );
    assert_eq!(stored, change);
}

#[test]
fn an_admins_policy_proposal_is_refused_as_on_main() {
    let org = Org::new();
    assert!(
        org.propose_longer_erase_wait(org.admin).is_err(),
        "an Admin edits no row"
    );
}
