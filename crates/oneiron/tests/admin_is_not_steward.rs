//! An Admin never gives the Steward role, to itself or to anyone (lead
//! 10 Nov 06:5x; ARCH-0043's Admin row: "Cannot self-grant blanket access";
//! federation:27: admin power is a fixed allowlist of named powers). Steward
//! is a named grant preset that only an owner of the vault gives.
//!
//! Runs on public paths: `cargo test -p oneiron --all-features --test
//! admin_is_not_steward`.
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
    let vault = Vault::open(dir.path(), VaultConfig::default()).expect("vault");
    let admin = EntityId::now();
    shared_with_admin(&vault, admin);

    let refused =
        vault.change_shared_member_role(&proof(&vault, admin), SHARED, admin, Role::Steward, None);
    assert!(
        refused.is_err(),
        "an Admin's AssignRole must not reach the Steward preset: {refused:?}"
    );
    assert_eq!(role_of(&vault, admin), Some(Role::Admin));
}

#[test]
fn an_admin_cannot_give_the_steward_role_but_the_owner_can() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Vault::open(dir.path(), VaultConfig::default()).expect("vault");
    let admin = EntityId::now();
    let owner = shared_with_admin(&vault, admin);
    let member = EntityId::now();
    person(&vault, member);
    let admin_proof = proof(&vault, admin);

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

    // The owner gives Steward: the Admin becomes one through the owner's act.
    vault
        .change_shared_member_role(&proof(&vault, owner), SHARED, admin, Role::Steward, None)
        .expect("the owner gives the Steward role");
    assert_eq!(role_of(&vault, admin), Some(Role::Steward));
}
