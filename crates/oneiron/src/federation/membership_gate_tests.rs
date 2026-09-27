use super::*;
use crate::edge::EdgeActorClass;
use crate::registry::ENTITY_TYPE_PERSON;
use crate::write_envelope::WriteActor;
use crate::{EntityId, TimeRange, Vault};
use std::collections::BTreeSet;

fn person(vault: &Vault) -> EntityId {
    let id = EntityId::now();
    vault
        .put_entity(
            &id,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"human",
        )
        .unwrap();
    id
}
fn writer(id: EntityId) -> WriteActor {
    WriteActor::new(id, EdgeActorClass::Human)
}
fn install(vault: &Vault, actor: EntityId, role: FederationGrantRole, scope: Scope) {
    let preset = match role {
        FederationGrantRole::Owner => FederationGrantPreset::Owner,
        FederationGrantRole::Admin => FederationGrantPreset::Admin,
        FederationGrantRole::Member => FederationGrantPreset::Member,
        FederationGrantRole::Viewer => FederationGrantPreset::ReadOnly,
        _ => unreachable!(),
    };
    let mut grant = FederationGrant::new(FederationGrantScope::vault(42), actor, role, preset);
    grant.authority_scope = scope;
    vault
        .batch()
        .put_replicated(
            &EntityId::now(),
            crate::registry::ENTITY_TYPE_FEDERATION_GRANT,
            TimeRange { start: 1, end: 1 },
            1,
            &encode_federation_grant_body(&grant).unwrap(),
        )
        .commit()
        .unwrap();
}
#[test]
fn equal_owners_and_role_verbs_are_checked_at_the_stored_write_gate() {
    let (_dir, vault) =
        crate::test_util::open_test_vault_with(crate::test_util::embedding_test_config());
    let first = person(&vault);
    let second = person(&vault);
    let admin = person(&vault);
    let viewer = person(&vault);
    for owner in [first, second] {
        install(&vault, owner, FederationGrantRole::Owner, Scope::top());
    }
    install(
        &vault,
        admin,
        FederationGrantRole::Admin,
        grant_scope::membership_preset(FederationGrantRole::Admin),
    );
    install(
        &vault,
        viewer,
        FederationGrantRole::Viewer,
        grant_scope::membership_preset(FederationGrantRole::Viewer),
    );
    for owner in [first, second] {
        assert!(
            vault
                .authorize_shared_vault_write(42, &writer(owner), &SharedVaultWrite::Veto)
                .is_ok()
        );
        assert!(
            vault
                .authorize_shared_vault_write(
                    42,
                    &writer(owner),
                    &SharedVaultWrite::Content(Scope::top())
                )
                .is_ok()
        );
    }
    for target in [
        SharedVaultWrite::OrgRoot,
        SharedVaultWrite::PersonalVault,
        SharedVaultWrite::Veto,
    ] {
        assert!(
            vault
                .authorize_shared_vault_write(42, &writer(admin), &target)
                .is_err()
        );
    }
    assert!(
        vault
            .authorize_shared_vault_write(
                42,
                &writer(viewer),
                &SharedVaultWrite::Content(Scope::top())
            )
            .is_err()
    );
    assert!(
        vault
            .authorize_shared_vault_write(43, &writer(first), &SharedVaultWrite::Veto)
            .is_err()
    );
}
#[test]
fn member_scope_and_missing_named_admin_power_fail_closed() {
    let (_dir, vault) =
        crate::test_util::open_test_vault_with(crate::test_util::embedding_test_config());
    let member = person(&vault);
    let admin = person(&vault);
    let project = ScopeId(EntityId::now());
    let mut scoped = grant_scope::membership_preset(FederationGrantRole::Member);
    scoped.audience = ScopeAxis::Some(BTreeSet::from([project]));
    install(&vault, member, FederationGrantRole::Member, scoped);
    let mut authorized = Scope::top();
    authorized.audience = ScopeAxis::Some(BTreeSet::from([project]));
    assert!(
        vault
            .authorize_shared_vault_write(
                42,
                &writer(member),
                &SharedVaultWrite::Content(authorized)
            )
            .is_ok()
    );
    assert!(
        vault
            .authorize_shared_vault_write(
                42,
                &writer(member),
                &SharedVaultWrite::Content(Scope::top())
            )
            .is_err()
    );
    assert!(
        vault
            .authorize_shared_vault_write(
                42,
                &writer(member),
                &SharedVaultWrite::Content(Scope::default())
            )
            .is_err()
    );
    let mut limited = grant_scope::membership_preset(FederationGrantRole::Admin);
    limited.verbs = ScopeAxis::Some(BTreeSet::from([
        "read".into(),
        "write".into(),
        "admin".into(),
    ]));
    install(&vault, admin, FederationGrantRole::Admin, limited);
    assert!(
        vault
            .authorize_shared_vault_write(
                42,
                &writer(admin),
                &SharedVaultWrite::Admin(OrgAdminPower::AddMember)
            )
            .is_err()
    );
    assert!(
        vault
            .authorize_shared_vault_write(42, &writer(admin), &SharedVaultWrite::RuleConflict)
            .is_ok()
    );
}

#[test]
fn legacy_auditor_bytes_map_to_viewer_and_guest_cannot_enter_the_roster() {
    let viewer = FederationGrant::new(
        FederationGrantScope::vault(42),
        EntityId::now(),
        FederationGrantRole::Viewer,
        FederationGrantPreset::ReadOnly,
    );
    let encoded = encode_federation_grant_body(&viewer).unwrap();
    let rmpv::Value::Map(mut entries) = rmpv::decode::read_value(&mut encoded.as_slice()).unwrap()
    else {
        panic!("grant map")
    };
    for (key, value) in &mut entries {
        if key.as_str() == Some("role") {
            *value = rmpv::Value::from("auditor");
        }
        if key.as_str() == Some("preset") {
            *value = rmpv::Value::from("audit");
        }
    }
    let mut bytes = Vec::new();
    rmpv::encode::write_value(&mut bytes, &rmpv::Value::Map(entries)).unwrap();
    let mapped = decode_federation_grant_body(&bytes).unwrap();
    assert_eq!(mapped.role, FederationGrantRole::Viewer);
    assert_eq!(mapped.preset, FederationGrantPreset::ReadOnly);
    assert_eq!(encode_federation_grant_body(&mapped).unwrap(), encoded);
    let guest = FederationGrant::new(
        FederationGrantScope::vault(42),
        EntityId::now(),
        FederationGrantRole::Guest,
        FederationGrantPreset::Owner,
    );
    assert!(encode_federation_grant_body(&guest).is_err());
    let mut noncanonical = viewer;
    noncanonical.role = FederationGrantRole::Auditor;
    noncanonical.preset = FederationGrantPreset::Audit;
    assert!(encode_federation_grant_body(&noncanonical).is_err());
}

#[test]
fn default_delegate_does_not_inherit_parent_write_or_admin_verbs() {
    let dir = tempfile::tempdir().unwrap();
    let vault = Vault::open(dir.path(), crate::VaultConfig::default()).unwrap();
    let owner = person(&vault);
    let admin = person(&vault);
    let delegate_member = person(&vault);
    let owner_proof = vault
        .authenticate_owner(
            owner,
            &owner.to_hex(),
            true,
            crate::store::GateDecisionId::now(),
        )
        .unwrap();
    let admin_proof = vault
        .authenticate_owner(
            admin,
            &admin.to_hex(),
            true,
            crate::store::GateDecisionId::now(),
        )
        .unwrap();
    let created = vault
        .initialize_shared_vault(
            &owner_proof,
            42,
            Some(super::SharedVaultPreset::Team),
            &[super::InitialSharedMember {
                member_ref: admin,
                role: Some(FederationGrantRole::Admin),
            }],
            1,
        )
        .unwrap();
    let parent_id = created
        .grant_refs
        .iter()
        .find_map(|hex| {
            let id = EntityId::from_hex(hex).unwrap();
            let raw = vault.get_raw(&id).unwrap().unwrap();
            (decode_federation_grant_body(&raw[crate::batch::ENTITY_METADATA_HEADER_LEN..])
                .unwrap()
                .member_ref
                == admin)
                .then_some(id)
        })
        .unwrap();
    let parent_raw = vault.get_raw(&parent_id).unwrap().unwrap();
    let parent =
        decode_federation_grant_body(&parent_raw[crate::batch::ENTITY_METADATA_HEADER_LEN..])
            .unwrap();
    let bare = FederationGrant::attenuated_delegate(&parent, delegate_member, 2, 10).unwrap();
    assert!(bare.authority_scope.verbs.is_bottom());
    let id = vault
        .create_federation_delegate(&admin_proof, parent_id, delegate_member, 2, 10)
        .unwrap();
    let raw = vault.get_raw(&id).unwrap().unwrap();
    let delegate =
        decode_federation_grant_body(&raw[crate::batch::ENTITY_METADATA_HEADER_LEN..]).unwrap();
    assert!(!super::membership_gate::grant_allows_content_write(
        &delegate,
        &Scope::top()
    ));
    assert!(
        !delegate
            .authority_scope
            .verbs
            .contains(&"org:add-member".to_owned())
    );
    assert!(!delegate.is_admin());
}
