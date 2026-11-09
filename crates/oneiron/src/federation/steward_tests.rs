//! The Steward role (ARCH-0043's seventh role, owner 9 Nov 2026): it reads
//! and organises its own vault root, never widens a grant, and never reaches
//! a member's personal vault, which is another root.
//!
//! Written by reading: the oneiron lib test target does not compile on main
//! (26 Oct decree).
use super::*;
use crate::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject,
    ScopedReadActorKey, encode_claim_body,
};
use crate::edge::EdgeActorClass;
use crate::ports::PointRead;
use crate::registry::{ENTITY_TYPE_CLAIM, ENTITY_TYPE_FEDERATION_GRANT, ENTITY_TYPE_PERSON};
use crate::write_envelope::WriteActor;
use crate::{EntityId, TimeRange, Vault};
use std::collections::BTreeSet;

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
        .unwrap();
}

/// A Steward's live membership grant over the shared vault, at the scope
/// the vault's shipped policy resolves for the role.
fn install_steward(vault: &Vault, steward: EntityId) -> (EntityId, FederationGrant) {
    let scope = {
        let txn = vault.store.env.read_txn().unwrap();
        vault
            .grant_default_scope_in_txn(&txn, FederationGrantRole::Steward, SHARED, steward)
            .unwrap()
    };
    let mut grant = FederationGrant::new(
        FederationGrantScope::vault(SHARED),
        steward,
        FederationGrantRole::Steward,
        FederationGrantPreset::Steward,
    );
    grant.authority_scope = scope;
    let id = EntityId::now();
    vault
        .batch()
        .put_replicated(
            &id,
            ENTITY_TYPE_FEDERATION_GRANT,
            TimeRange { start: 1, end: 1 },
            1,
            &encode_federation_grant_body(&grant).unwrap(),
        )
        .commit()
        .unwrap();
    (id, grant)
}

fn steward_verbs() -> ScopeAxis<String> {
    ScopeAxis::Some(
        grant_scope::STEWARD_VERBS
            .iter()
            .map(|verb| (*verb).to_owned())
            .collect(),
    )
}

#[test]
fn a_steward_cannot_widen_a_grant() {
    let (_dir, vault) =
        crate::test_util::open_test_vault_with(crate::test_util::embedding_test_config());
    let steward = EntityId::now();
    let other = EntityId::now();
    person(&vault, steward);
    person(&vault, other);
    let (steward_grant_id, steward_grant) = install_steward(&vault, steward);

    // The shipped policy gives the role its preset: read and derive across
    // the root, archive and delete in scope. No admin power, no `write`.
    assert_eq!(steward_grant.authority_scope.verbs, steward_verbs());
    assert!(!steward_grant.is_admin());
    assert!(!FederationGrantRole::Steward.is_admin());
    assert!(!FederationGrantRole::Steward.is_guest());

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

    // It cannot parent a delegate, so it cannot pass its reach on.
    let now = vault.store.clock.now_recorded_at();
    assert!(FederationGrant::attenuated_delegate(&steward_grant, other, now, now + 60).is_err());
    let steward_proof = vault
        .authenticate_owner(
            steward,
            &steward.to_hex(),
            true,
            crate::store::GateDecisionId::now(),
        )
        .unwrap();
    assert!(
        vault
            .create_federation_delegate(&steward_proof, steward_grant_id, other, now, now + 60)
            .is_err()
    );

    // No policy row raises it: a role default and a holder row naming every
    // verb still meet the Steward's structural ceiling.
    let rows = [
        grant_policy::GrantPolicyRow::PrecedenceNestedNarrowing,
        grant_policy::GrantPolicyRow::RoleDefault {
            role: FederationGrantRole::Steward,
            scope: Scope::top(),
        },
        grant_policy::GrantPolicyRow::HolderOverride {
            role: FederationGrantRole::Steward,
            vault_id: SHARED,
            holder: steward,
            scope: Scope::top(),
        },
    ];
    let resolved =
        grant_policy::resolved_scope(&rows, FederationGrantRole::Steward, SHARED, steward).unwrap();
    assert_eq!(resolved.verbs, steward_verbs());
    for power in ["admin", "write", "org:add-member", "org:assign-role"] {
        assert!(!resolved.verbs.contains(&power.to_owned()));
    }

    // A Steward rides only the Steward envelope, and the Steward envelope
    // carries only a Steward: neither an Admin envelope nor a raised role
    // stands.
    let mut admin_envelope = steward_grant.clone();
    admin_envelope.preset = FederationGrantPreset::Admin;
    assert!(admin_envelope.validate().is_err());
    let mut owner_envelope = steward_grant.clone();
    owner_envelope.preset = FederationGrantPreset::Owner;
    assert!(owner_envelope.validate().is_err());
    let mut raised = steward_grant.clone();
    raised.role = FederationGrantRole::Admin;
    assert!(raised.validate().is_err());
    assert!(steward_grant.validate().is_ok());
}

#[test]
fn a_shared_vault_steward_cannot_read_a_members_personal_vault() {
    let (_shared_dir, shared) =
        crate::test_util::open_test_vault_with(crate::test_util::embedding_test_config());
    let (_personal_dir, personal) =
        crate::test_util::open_test_vault_with(crate::test_util::embedding_test_config());
    assert_ne!(shared.vault_id(), personal.vault_id());
    let steward = EntityId::now();
    person(&shared, steward);
    let (grant_id, _) = install_steward(&shared, steward);

    // In the shared vault the Steward stands on the roster, as a Steward.
    {
        let txn = shared.store.env.read_txn().unwrap();
        assert_eq!(
            shared
                .membership_standing_in_txn(&txn, SHARED, &steward)
                .unwrap(),
            Some(MembershipStanding::Member {
                grant: grant_id,
                role: FederationGrantRole::Steward,
            })
        );
    }

    // The member's personal vault is another root. It knows the same
    // person, and keeps a belief of its own.
    person(&personal, steward);
    let mut body = ClaimBody::new(
        "profile.note",
        ClaimSubject::Entity(EntityId::now()),
        rmpv::Value::from("kept in the personal vault"),
        1.0,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
    )
    .unwrap();
    body.source = Some(ClaimSource::UserStated);
    let claim = EntityId::now();
    personal
        .batch()
        .put_replicated(
            &claim,
            ENTITY_TYPE_CLAIM,
            TimeRange { start: 2, end: 2 },
            2,
            &encode_claim_body(&body).unwrap(),
        )
        .commit()
        .unwrap();

    // No grant there names the Steward: no standing under the shared
    // vault's id, and no FEDERATION_GRANT row for it at all.
    {
        let txn = personal.store.env.read_txn().unwrap();
        assert_eq!(
            personal
                .membership_standing_in_txn(&txn, SHARED, &steward)
                .unwrap(),
            None
        );
        let mut named = BTreeSet::new();
        for id in crate::ports::EntityStoreRead::port_entity_ids_by_type(
            &personal.store,
            &txn,
            ENTITY_TYPE_FEDERATION_GRANT,
            None,
        )
        .unwrap()
        {
            let id = id.unwrap();
            let raw = personal.get_raw(&id).unwrap().unwrap();
            named.insert(
                decode_federation_grant_body(&raw[crate::batch::ENTITY_METADATA_HEADER_LEN..])
                    .unwrap()
                    .member_ref,
            );
        }
        assert!(!named.contains(&steward));
    }

    // So the Steward's read there withholds the member's belief.
    let read = personal.scoped_read(
        ScopedReadActorKey::with_actor_class(
            steward.to_hex(),
            EdgeActorClass::Human.gate_actor_class(),
        )
        .unwrap()
        .require_access_grants(Some(steward)),
    );
    let withheld = read.read(&[PointRead::id(claim)], None).unwrap();
    assert_eq!(withheld.value, vec![None]);
}
