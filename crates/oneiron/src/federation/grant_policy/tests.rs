use super::*;
use crate::federation::{
    FederationGrantRole, InitialSharedMember, ScopeAxis, decode_federation_grant_body,
};
use crate::registry::ENTITY_TYPE_PERSON;
use crate::{TimeRange, Vault, VaultConfig};

fn fixture() -> (tempfile::TempDir, Vault, EntityId, EntityId, EntityId) {
    let dir = tempfile::tempdir().unwrap();
    let vault = Vault::open(dir.path(), VaultConfig::default()).unwrap();
    let mut people = Vec::new();
    for _ in 0..3 {
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
        people.push(id);
    }
    (dir, vault, people[0], people[1], people[2])
}
fn policy_rows(vault: &Vault, owner: EntityId, mut change: impl FnMut(&mut Vec<Value>)) {
    let id = crate::gate::default_policy_manifest_id().unwrap();
    let raw = vault.get_raw(&id).unwrap().unwrap();
    let Value::Map(mut entries) =
        rmpv::decode::read_value(&mut &raw[crate::batch::ENTITY_METADATA_HEADER_LEN..]).unwrap()
    else {
        panic!("manifest map")
    };
    let rows = entries
        .iter_mut()
        .find(|(key, _)| key.as_str() == Some(ROWS_KEY))
        .unwrap();
    let Value::Array(values) = &mut rows.1 else {
        panic!("policy rows")
    };
    change(values);
    let mut bytes = Vec::new();
    rmpv::encode::write_value(&mut bytes, &Value::Map(entries)).unwrap();
    let proof = vault
        .authenticate_owner(
            owner,
            &owner.to_hex(),
            true,
            crate::store::GateDecisionId::now(),
        )
        .unwrap();
    vault
        .with_write_txn(|txn| {
            vault.write_owner_policy_manifest_in_txn(&proof, txn, id, bytes.clone(), 1)
        })
        .unwrap();
}
fn grant(vault: &Vault, refs: &[String], holder: EntityId) -> crate::federation::FederationGrant {
    refs.iter()
        .find_map(|hex| {
            let id = EntityId::from_hex(hex).unwrap();
            let raw = vault.get_raw(&id).unwrap().unwrap();
            let row =
                decode_federation_grant_body(&raw[crate::batch::ENTITY_METADATA_HEADER_LEN..])
                    .unwrap();
            (row.member_ref == holder).then_some(row)
        })
        .unwrap()
}

#[test]
fn admin_default_is_vault_resident_and_missing_add_member_is_not_implicit() {
    let (_dir, vault, owner, admin, _) = fixture();
    let proof = vault
        .authenticate_owner(
            owner,
            &owner.to_hex(),
            true,
            crate::store::GateDecisionId::now(),
        )
        .unwrap();
    policy_rows(&vault, owner, |rows| {
        let row = rows
            .iter_mut()
            .find(|value| {
                let Value::Map(entries) = value else {
                    return false;
                };
                entries.iter().any(|(key, value)| {
                    key.as_str() == Some("kind") && value.as_str() == Some("role_default")
                }) && entries.iter().any(|(key, value)| {
                    key.as_str() == Some("role") && value.as_str() == Some("admin")
                })
            })
            .unwrap();
        let Value::Map(entries) = row else {
            unreachable!()
        };
        let scope = entries
            .iter_mut()
            .find(|(key, _)| key.as_str() == Some("scope"))
            .unwrap();
        let mut narrowed = Scope::top();
        narrowed.verbs = ScopeAxis::Some(["read".to_owned(), "write".to_owned()].into());
        scope.1 = super::super::scope_codec::encode_scope_value(&narrowed).unwrap();
    });
    let created = vault
        .initialize_shared_vault(
            &proof,
            42,
            None,
            &[
                InitialSharedMember {
                    member_ref: owner,
                    role: Some(FederationGrantRole::Owner),
                },
                InitialSharedMember {
                    member_ref: admin,
                    role: Some(FederationGrantRole::Admin),
                },
            ],
            1,
        )
        .unwrap();
    let stored = grant(&vault, &created.grant_refs, admin);
    assert!(
        !stored
            .authority_scope
            .verbs
            .contains(&"org:add-member".to_owned())
    );
    assert!(stored.authority_scope.verbs.contains(&"write".to_owned()));
    assert!(
        vault
            .authorize_shared_vault_write(
                42,
                &crate::WriteActor::new(admin, crate::EdgeActorClass::Human),
                &crate::federation::SharedVaultWrite::Admin(
                    crate::federation::OrgAdminPower::AddMember
                ),
            )
            .is_err()
    );
}

#[test]
fn delegate_holder_policy_is_nested_under_vault_and_parent() {
    let (_dir, vault, owner, admin, delegate) = fixture();
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
            None,
            &[
                InitialSharedMember {
                    member_ref: owner,
                    role: Some(FederationGrantRole::Owner),
                },
                InitialSharedMember {
                    member_ref: admin,
                    role: Some(FederationGrantRole::Admin),
                },
            ],
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
    policy_rows(&vault, owner, |rows| {
        let mut default = Scope::top();
        default.verbs = ScopeAxis::Some(["read".to_owned(), "write".to_owned()].into());
        let mut vault_scope = Scope::top();
        vault_scope.verbs = ScopeAxis::Some(["read".to_owned(), "write".to_owned()].into());
        let mut holder_scope = Scope::top();
        holder_scope.verbs = ScopeAxis::Some(["write".to_owned()].into());
        rows.iter_mut()
            .filter_map(|value| {
                let Value::Map(entries) = value else {
                    return None;
                };
                if entries.iter().any(|(key, value)| {
                    key.as_str() == Some("kind") && value.as_str() == Some("role_default")
                }) && entries.iter().any(|(key, value)| {
                    key.as_str() == Some("role") && value.as_str() == Some("delegate")
                }) {
                    entries
                        .iter_mut()
                        .find(|(key, _)| key.as_str() == Some("scope"))
                        .map(|(_, value)| value)
                } else {
                    None
                }
            })
            .for_each(|scope| {
                *scope = super::super::scope_codec::encode_scope_value(&default).unwrap();
            });
        rows.push(
            encode_row(&GrantPolicyRow::VaultOverride {
                role: Role::Delegate,
                vault_id: 42,
                scope: vault_scope,
            })
            .unwrap(),
        );
        rows.push(
            encode_row(&GrantPolicyRow::HolderOverride {
                role: Role::Delegate,
                vault_id: 42,
                holder: delegate,
                scope: holder_scope,
            })
            .unwrap(),
        );
    });
    let created_id = vault
        .create_federation_delegate(&admin_proof, parent_id, delegate, 2, 10)
        .unwrap();
    let raw = vault.get_raw(&created_id).unwrap().unwrap();
    let grant =
        decode_federation_grant_body(&raw[crate::batch::ENTITY_METADATA_HEADER_LEN..]).unwrap();
    // The holder override narrows the role and vault defaults to write only.
    assert!(!grant.authority_scope.verbs.contains(&"read".to_owned()));
    assert!(grant.authority_scope.verbs.contains(&"write".to_owned()));
    assert!(!grant.authority_scope.verbs.contains(&"admin".to_owned()));
    assert!(super::super::membership_gate::grant_allows_content_write(
        &grant,
        &Scope::top()
    ));

    // A later holder may ask for write under the SAME manifest, but cannot
    // exceed an Admin parent that was narrowed to read/admin in the roster.
    let next_member = EntityId::now();
    vault
        .put_entity(
            &next_member,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"human",
        )
        .unwrap();
    let parent_raw = vault.get_raw(&parent_id).unwrap().unwrap();
    let mut narrowed =
        decode_federation_grant_body(&parent_raw[crate::batch::ENTITY_METADATA_HEADER_LEN..])
            .unwrap();
    narrowed.authority_scope.verbs =
        ScopeAxis::Some(["read".to_owned(), "admin".to_owned()].into());
    vault
        .batch()
        .put_replicated(
            &parent_id,
            crate::registry::ENTITY_TYPE_FEDERATION_GRANT,
            TimeRange { start: 1, end: 1 },
            1,
            &super::super::encode_federation_grant_body(&narrowed).unwrap(),
        )
        .commit()
        .unwrap();
    let next_id = vault
        .create_federation_delegate(&admin_proof, parent_id, next_member, 3, 11)
        .unwrap();
    let next_raw = vault.get_raw(&next_id).unwrap().unwrap();
    let next = decode_federation_grant_body(&next_raw[crate::batch::ENTITY_METADATA_HEADER_LEN..])
        .unwrap();
    assert!(!next.authority_scope.verbs.contains(&"write".to_owned()));
    assert!(next.authority_scope.verbs.contains(&"read".to_owned()));
    assert!(!super::super::membership_gate::grant_allows_content_write(
        &next,
        &Scope::top()
    ));
}

#[test]
fn vault_override_caps_holder_override_under_precedence_row() {
    let holder = EntityId::now();
    let with_verbs = |verbs: &[&str]| {
        let mut scope = Scope::top();
        scope.verbs = ScopeAxis::Some(verbs.iter().map(|verb| (*verb).to_owned()).collect());
        scope
    };
    let rows = vec![
        GrantPolicyRow::PrecedenceNestedNarrowing,
        GrantPolicyRow::RoleDefault {
            role: Role::Member,
            scope: with_verbs(&["read", "write"]),
        },
        GrantPolicyRow::VaultOverride {
            role: Role::Member,
            vault_id: 42,
            scope: with_verbs(&["read"]),
        },
        GrantPolicyRow::HolderOverride {
            role: Role::Member,
            vault_id: 42,
            holder,
            scope: with_verbs(&["read", "write"]),
        },
    ];
    let effective = resolved_scope(&rows, Role::Member, 42, holder).unwrap();
    assert!(effective.verbs.contains(&"read".to_owned()));
    assert!(!effective.verbs.contains(&"write".to_owned()));
    let without_precedence = &rows[1..];
    assert!(resolved_scope(without_precedence, Role::Member, 42, holder).is_err());
}
