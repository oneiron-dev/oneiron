//! The Steward role (untangle 6.3a; ARCH-0043's seventh role, owner 9 Nov):
//! it never widens a grant, and a shared-vault Steward never reads a
//! member's personal vault, which is another root.
//!
//! Runs on public paths: `cargo test -p oneiron --all-features --test
//! steward_role`.
use std::collections::BTreeSet;

use oneiron::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject, PointRead,
    ScopedReadActorKey,
};
use oneiron::consent::AuthenticatedOwner;
use oneiron::edge::EdgeActorClass;
use oneiron::federation::{
    FederationGrant, FederationGrantPreset, FederationGrantRole as Role, InitialSharedMember,
    OrgAdminPower, Scope, ScopeAxis, SharedVaultWrite, decode_federation_grant_body,
};
use oneiron::registry::{ENTITY_TYPE_FEDERATION_GRANT, ENTITY_TYPE_PERSON};
use oneiron::store::GateDecisionId;
use oneiron::temporal::TimeRange;
use oneiron::write_envelope::WriteActor;
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

/// A shared vault whose roster holds its embedded owner and `steward` as a
/// Steward; the Steward's grant, as the shipped policy gave it.
fn shared_with_steward(vault: &Vault, steward: EntityId) -> (EntityId, FederationGrant) {
    let owner = vault.ensure_embedded_owner_actor().expect("owner");
    person(vault, steward);
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
                    member_ref: steward,
                    role: Some(Role::Steward),
                },
            ],
            1,
        )
        .expect("a shared vault with a Steward");
    // A founding member other than the creator joins by invitation (OF-531):
    // the Steward accepts its own, and its grant is written then.
    let steward_proof = proof(vault, steward);
    let invitation = vault
        .shared_invitations(&steward_proof, SHARED)
        .expect("the Steward's invitations")
        .into_iter()
        .find(|open| open.role == Role::Steward)
        .expect("the Steward's founding invitation");
    vault
        .accept_shared_invitation(&steward_proof, SHARED, &invitation.id)
        .expect("the Steward accepts");
    vault
        .entities_by_type(ENTITY_TYPE_FEDERATION_GRANT)
        .expect("grants")
        .into_iter()
        .find_map(|id| {
            let body = vault.get(&id).expect("grant row")?;
            let grant = decode_federation_grant_body(&body).expect("a grant");
            (grant.member_ref == steward).then_some((id, grant))
        })
        .expect("the Steward's grant")
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_secs()
}

#[test]
fn a_steward_cannot_widen_a_grant() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Vault::open(dir.path(), VaultConfig::default()).expect("vault");
    let steward = EntityId::now();
    let other = EntityId::now();
    let (grant_id, grant) = shared_with_steward(&vault, steward);
    person(&vault, other);

    // The shipped policy gives the role its default: read, derive, archive
    // and delete. No admin power, no `write`.
    assert_eq!(grant.role, Role::Steward);
    assert_eq!(grant.preset, FederationGrantPreset::Steward);
    assert_eq!(
        grant.authority_scope.verbs,
        ScopeAxis::Some(BTreeSet::from(
            ["read", "derive", "archive", "delete"].map(str::to_owned)
        ))
    );
    assert!(!grant.is_admin());

    // Membership acts, owner acts and general content writes all refuse.
    let writer = WriteActor::new(steward, EdgeActorClass::Human);
    for target in [
        SharedVaultWrite::Admin(OrgAdminPower::AddMember),
        SharedVaultWrite::Admin(OrgAdminPower::RemoveMember),
        SharedVaultWrite::Admin(OrgAdminPower::AssignRole),
        SharedVaultWrite::Admin(OrgAdminPower::ResetSharedProjectAccess),
        SharedVaultWrite::RuleConflict,
        SharedVaultWrite::WorkspaceSettings,
        SharedVaultWrite::OrgRoot,
        SharedVaultWrite::PersonalVault,
        SharedVaultWrite::Veto,
        SharedVaultWrite::Content(Scope::top()),
    ] {
        assert!(
            vault
                .authorize_shared_vault_write(SHARED, &writer, &target)
                .is_err(),
            "a Steward may not {target:?}"
        );
    }
    let steward_proof = proof(&vault, steward);
    assert!(
        vault
            .add_shared_member(&steward_proof, SHARED, other, None)
            .is_err()
    );

    // It cannot parent a delegate, so it cannot pass its reach on.
    let now = now_secs();
    assert!(FederationGrant::attenuated_delegate(&grant, other, now, now + 60).is_err());
    assert!(
        vault
            .create_federation_delegate(&steward_proof, grant_id, other, now, now + 60)
            .is_err()
    );

    // A grant that reads as a Steward never carries an admin's role.
    let mut raised = grant.clone();
    raised.role = Role::Admin;
    assert!(raised.validate().is_err());
    assert!(grant.validate().is_ok());
}

#[test]
fn a_shared_vault_steward_cannot_read_a_members_personal_vault() {
    let shared_dir = tempfile::tempdir().expect("tempdir");
    let shared = Vault::open(shared_dir.path(), VaultConfig::default()).expect("shared vault");
    let personal_dir = tempfile::tempdir().expect("tempdir");
    let personal =
        Vault::open(personal_dir.path(), VaultConfig::default()).expect("personal vault");
    let steward = EntityId::now();
    shared_with_steward(&shared, steward);

    // The member's personal vault is another root. It knows the same
    // person, and keeps a belief of its own.
    person(&personal, steward);
    let subject = EntityId::now();
    person(&personal, subject);
    let mut body = ClaimBody::new(
        "profile.note",
        ClaimSubject::Entity(subject),
        rmpv::Value::from("kept in the personal vault"),
        1.0,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
    )
    .expect("a claim body");
    body.source = Some(ClaimSource::UserStated);
    let claim = EntityId::now();
    personal
        .put_claim(&claim, &body, TimeRange { start: 2, end: 2 }, 2)
        .expect("the member's belief");

    // No grant there names the Steward.
    for id in personal
        .entities_by_type(ENTITY_TYPE_FEDERATION_GRANT)
        .expect("grants")
    {
        if let Some(body) = personal.get(&id).expect("grant row") {
            let grant = decode_federation_grant_body(&body).expect("a grant");
            assert_ne!(grant.member_ref, steward);
        }
    }

    // So the Steward's read there withholds the member's belief.
    let read = personal.scoped_read(
        ScopedReadActorKey::with_actor_class(
            steward.to_hex(),
            EdgeActorClass::Human.gate_actor_class(),
        )
        .expect("the Steward's key")
        .require_access_grants(Some(steward)),
    );
    assert_eq!(
        read.read(&[PointRead::id(claim)], None)
            .expect("the Steward's read")
            .value,
        vec![None]
    );
}
