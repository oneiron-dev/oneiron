//! An Admin never gives the Steward role, to itself or to anyone (lead
//! 10 Nov 06:5x; ARCH-0043's Admin row: "Cannot self-grant blanket access";
//! federation:27: admin power is a fixed allowlist of named powers). Steward
//! is a named grant preset that only an owner of the vault gives.
//!
//! An Admin acts here on a session that passed MFA (L7-17), so each refusal
//! is the role's, never the missing step-up's.
//!
//! Runs on public paths: `cargo test -p oneiron --all-features --test
//! admin_is_not_steward`.
#[path = "admin_step_up/fixture.rs"]
mod admin_step_up;

use oneiron::consent::AuthenticatedOwner;
use oneiron::federation::{FederationGrantRole as Role, InitialSharedMember};
use oneiron::registry::{ENTITY_TYPE_FEDERATION_GRANT, ENTITY_TYPE_PERSON};
use oneiron::store::GateDecisionId;
use oneiron::temporal::TimeRange;
use oneiron::{EntityId, Vault, VaultConfig};

const SHARED: u64 = 42;

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

/// The role `member` holds in the shared vault now, read from its grant rows.
fn role_of(vault: &Vault, member: EntityId) -> Option<Role> {
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

/// A shared vault whose roster holds its embedded owner as Owner and
/// `admin` as an Admin who has accepted its founding invitation.
fn shared_with_admin(vault: &Vault, admin: EntityId) -> EntityId {
    let owner = vault.ensure_embedded_owner_actor().expect("owner");
    person(vault, admin);
    vault
        .initialize_shared_vault(
            &proof(vault, owner),
            SHARED,
            None,
            &[
                InitialSharedMember {
                    member_ref: owner,
                    role: Some(Role::Owner),
                },
                InitialSharedMember {
                    member_ref: admin,
                    role: Some(Role::Admin),
                },
            ],
            1,
        )
        .expect("a shared vault with an Admin");
    let admin_proof = proof(vault, admin);
    let invitation = vault
        .shared_invitations(&admin_proof, SHARED)
        .expect("the Admin's invitations")
        .into_iter()
        .find(|open| open.role == Role::Admin)
        .expect("the Admin's founding invitation");
    vault
        .accept_shared_invitation(&admin_proof, SHARED, &invitation.id)
        .expect("the Admin accepts");
    assert_eq!(role_of(vault, admin), Some(Role::Admin));
    owner
}

#[test]
fn an_admin_cannot_make_itself_a_steward() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (vault, issuer, _) = admin_step_up::rooted_vault(dir.path());
    let admin = EntityId::now();
    shared_with_admin(&vault, admin);
    admin_step_up::bind_human_writer(&vault, &issuer, admin);
    let admin_proof = admin_step_up::stepped_up_proof(&vault, &issuer, admin);

    let refused = vault.change_shared_member_role(&admin_proof, SHARED, admin, Role::Steward, None);
    assert!(
        refused.is_err(),
        "an Admin's AssignRole must not reach the Steward preset: {refused:?}"
    );
    assert_eq!(role_of(&vault, admin), Some(Role::Admin));
}

#[test]
fn an_admin_cannot_give_the_steward_role_but_the_owner_can() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (vault, issuer, _) = admin_step_up::rooted_vault(dir.path());
    let admin = EntityId::now();
    let owner = shared_with_admin(&vault, admin);
    let member = EntityId::now();
    person(&vault, member);
    admin_step_up::bind_human_writer(&vault, &issuer, admin);
    let admin_proof = admin_step_up::stepped_up_proof(&vault, &issuer, admin);

    // An Admin's AddMember stops at Steward ...
    let refused = vault.add_shared_member(&admin_proof, SHARED, member, Some(Role::Steward));
    assert!(
        refused.is_err(),
        "an Admin's AddMember must not invite a Steward: {refused:?}"
    );
    // ... while the same power still adds a Member, so the refusal is the
    // role's, not a missing power.
    vault
        .add_shared_member(&admin_proof, SHARED, member, Some(Role::Member))
        .expect("an Admin adds a Member");

    // The owner gives Steward: the Admin becomes one through the owner's act,
    // the host key bound to the owner again.
    oneiron::test_support::bind_host_owner(&vault, &issuer, owner).expect("the owner's binding");
    vault
        .change_shared_member_role(&proof(&vault, owner), SHARED, admin, Role::Steward, None)
        .expect("the owner gives the Steward role");
    assert_eq!(role_of(&vault, admin), Some(Role::Steward));
}

/// A shared vault whose roster holds its embedded owner and `co_owner` as
/// Owners, the second having accepted its founding invitation (FABLE-6988-1).
fn shared_with_two_owners(vault: &Vault, co_owner: EntityId) -> EntityId {
    let owner = vault.ensure_embedded_owner_actor().expect("owner");
    person(vault, co_owner);
    vault
        .initialize_shared_vault(
            &proof(vault, owner),
            SHARED,
            None,
            &[
                InitialSharedMember {
                    member_ref: owner,
                    role: Some(Role::Owner),
                },
                InitialSharedMember {
                    member_ref: co_owner,
                    role: Some(Role::Owner),
                },
            ],
            1,
        )
        .expect("a shared vault with two owners");
    let co_owner_proof = proof(vault, co_owner);
    let invitation = vault
        .shared_invitations(&co_owner_proof, SHARED)
        .expect("the co-owner's invitations")
        .into_iter()
        .find(|open| open.role == Role::Owner)
        .expect("the co-owner's founding invitation");
    vault
        .accept_shared_invitation(&co_owner_proof, SHARED, &invitation.id)
        .expect("the co-owner accepts");
    assert_eq!(role_of(vault, co_owner), Some(Role::Owner));
    owner
}

/// FABLE-6988-1: acceptance judges the inviter again, so an invitation at
/// Steward stands only while its inviter is an Owner. An Owner invites a
/// person at Steward, the other Owner makes the inviter an Admin through
/// `remove_owner`, and the invitee's acceptance is refused.
#[test]
fn a_steward_invitation_is_refused_once_its_inviter_is_no_owner() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Vault::open(dir.path(), VaultConfig::default()).expect("vault");
    let co_owner = EntityId::now();
    let owner = shared_with_two_owners(&vault, co_owner);
    let member = EntityId::now();
    person(&vault, member);

    vault
        .add_shared_member(
            &proof(&vault, co_owner),
            SHARED,
            member,
            Some(Role::Steward),
        )
        .expect("an Owner invites a Steward");

    let owner_proof = proof(&vault, owner);
    let act = vault
        .propose_remove_owner(
            &owner_proof,
            SHARED,
            co_owner,
            None,
            Some(Role::Admin),
            false,
        )
        .expect("the other Owner starts remove_owner, the inviter keeping Admin");
    vault
        .execute_completed_shared_act(&owner_proof, &act.id, None)
        .expect("remove_owner runs at once under its zero wait");
    assert_eq!(
        role_of(&vault, co_owner),
        Some(Role::Admin),
        "the inviter is an Admin now"
    );

    let member_proof = proof(&vault, member);
    let invitation = vault
        .shared_invitations(&member_proof, SHARED)
        .expect("the invitee's invitations")
        .into_iter()
        .find(|open| open.role == Role::Steward)
        .expect("the Steward invitation is still pending");
    let accepted = vault.accept_shared_invitation(&member_proof, SHARED, &invitation.id);
    assert!(
        accepted.is_err(),
        "a Steward invitation must be refused once its inviter is an Admin: {accepted:?}"
    );
    assert_eq!(
        role_of(&vault, member),
        None,
        "the refused acceptance writes no membership"
    );
}
