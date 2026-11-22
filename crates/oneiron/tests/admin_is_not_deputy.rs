//! An Admin never gives the Deputy role, to itself or to anyone (Engine
//! ruling C1-DEPUTY-GIVER, 13 Nov 14:39; ARCH-0082: a Deputy is Admin plus
//! the delegated Owner Grant). Only an Owner of the vault gives Deputy, as
//! the house door already refuses it (HOUSE-UNBIND-AUTHORITY = A).
//!
//! An Admin acts here on a session that passed MFA (L7-17), so each refusal
//! is the role's, never the missing step-up's.
//!
//! Runs on public paths: `cargo test -p oneiron --all-features --test
//! admin_is_not_deputy`.
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

/// `member` accepts its one open invitation at `role`.
fn accept_invitation(vault: &Vault, member: EntityId, role: Role) {
    let member_proof = proof(vault, member);
    let invitation = vault
        .shared_invitations(&member_proof, SHARED)
        .expect("the member's invitations")
        .into_iter()
        .find(|open| open.role == role)
        .expect("an open invitation at the role");
    vault
        .accept_shared_invitation(&member_proof, SHARED, &invitation.id)
        .expect("the member accepts");
}

/// Whether `member` holds an open invitation at `role`.
fn invited_at(vault: &Vault, member: EntityId, role: Role) -> bool {
    vault
        .shared_invitations(&proof(vault, member), SHARED)
        .expect("the member's invitations")
        .into_iter()
        .any(|open| open.role == role)
}

/// A shared vault whose roster holds its embedded owner as Owner and
/// `second` at `role`, the second having accepted its founding invitation.
fn shared_with(vault: &Vault, second: EntityId, role: Role) -> EntityId {
    let owner = vault.ensure_embedded_owner_actor().expect("owner");
    person(vault, second);
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
                    member_ref: second,
                    role: Some(role),
                },
            ],
            1,
        )
        .expect("a shared vault with a second member");
    accept_invitation(vault, second, role);
    assert_eq!(role_of(vault, second), Some(role));
    owner
}

#[test]
fn an_admin_cannot_make_itself_a_deputy() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (vault, issuer, _) = admin_step_up::rooted_vault(dir.path());
    let admin = EntityId::now();
    shared_with(&vault, admin, Role::Admin);
    admin_step_up::bind_human_writer(&vault, &issuer, admin);
    let admin_proof = admin_step_up::stepped_up_proof(&vault, &issuer, admin);

    let refused = vault.change_shared_member_role(&admin_proof, SHARED, admin, Role::Deputy, None);
    assert!(
        refused.is_err(),
        "an Admin's AssignRole must not reach the Deputy role: {refused:?}"
    );
    assert_eq!(role_of(&vault, admin), Some(Role::Admin));
}

#[test]
fn an_admin_cannot_give_the_deputy_role_to_a_member() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (vault, issuer, _) = admin_step_up::rooted_vault(dir.path());
    let admin = EntityId::now();
    shared_with(&vault, admin, Role::Admin);
    let member = EntityId::now();
    person(&vault, member);
    admin_step_up::bind_human_writer(&vault, &issuer, admin);
    let admin_proof = admin_step_up::stepped_up_proof(&vault, &issuer, admin);

    // An Admin's AddMember stops at Deputy, and no invitation is written ...
    let refused = vault.add_shared_member(&admin_proof, SHARED, member, Some(Role::Deputy));
    assert!(
        refused.is_err(),
        "an Admin's AddMember must not invite a Deputy: {refused:?}"
    );
    assert!(
        !invited_at(&vault, member, Role::Deputy),
        "the refused AddMember writes no Deputy invitation"
    );
    // ... while the same power still adds a Member, so the refusal is the
    // role's, not a missing power.
    vault
        .add_shared_member(&admin_proof, SHARED, member, Some(Role::Member))
        .expect("an Admin adds a Member");
    accept_invitation(&vault, member, Role::Member);
    assert_eq!(role_of(&vault, member), Some(Role::Member));

    // An Admin's AssignRole stops at Deputy for another member too.
    let refused = vault.change_shared_member_role(&admin_proof, SHARED, member, Role::Deputy, None);
    assert!(
        refused.is_err(),
        "an Admin's AssignRole must not make a Member a Deputy: {refused:?}"
    );
    assert_eq!(role_of(&vault, member), Some(Role::Member));
}

#[test]
fn the_owner_gives_the_deputy_role() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Vault::open(dir.path(), VaultConfig::default()).expect("vault");
    let admin = EntityId::now();
    let owner = shared_with(&vault, admin, Role::Admin);
    let owner_proof = proof(&vault, owner);

    // The owner's AssignRole makes the Admin a Deputy ...
    vault
        .change_shared_member_role(&owner_proof, SHARED, admin, Role::Deputy, None)
        .expect("the owner gives the Deputy role");
    assert_eq!(role_of(&vault, admin), Some(Role::Deputy));

    // ... and the owner's AddMember invites a Deputy who accepts.
    let member = EntityId::now();
    person(&vault, member);
    vault
        .add_shared_member(&owner_proof, SHARED, member, Some(Role::Deputy))
        .expect("the owner invites a Deputy");
    accept_invitation(&vault, member, Role::Deputy);
    assert_eq!(role_of(&vault, member), Some(Role::Deputy));
}

/// Acceptance judges the inviter again (FABLE-6988-1), so an invitation at
/// Deputy stands only while its inviter is an Owner. An Owner invites a
/// person at Deputy, the other Owner makes the inviter an Admin through
/// `remove_owner`, and the invitee's acceptance is refused.
#[test]
fn a_deputy_invitation_is_refused_once_its_inviter_is_no_owner() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Vault::open(dir.path(), VaultConfig::default()).expect("vault");
    let co_owner = EntityId::now();
    let owner = shared_with(&vault, co_owner, Role::Owner);
    let member = EntityId::now();
    person(&vault, member);

    vault
        .add_shared_member(&proof(&vault, co_owner), SHARED, member, Some(Role::Deputy))
        .expect("an Owner invites a Deputy");

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
        .find(|open| open.role == Role::Deputy)
        .expect("the Deputy invitation is still pending");
    let accepted = vault.accept_shared_invitation(&member_proof, SHARED, &invitation.id);
    assert!(
        accepted.is_err(),
        "a Deputy invitation must be refused once its inviter is an Admin: {accepted:?}"
    );
    assert_eq!(
        role_of(&vault, member),
        None,
        "the refused acceptance writes no membership"
    );
}
