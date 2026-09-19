use super::*;
use crate::consent::AuthenticatedOwner;
use crate::error::Result;
use crate::{EntityId, TimeRange, Vault};
fn fixture() -> (
    tempfile::TempDir,
    Vault,
    AuthenticatedOwner,
    AuthenticatedOwner,
) {
    let (dir, vault) =
        crate::test_util::open_test_vault_with(crate::test_util::embedding_test_config());
    let mut owners = Vec::new();
    for _ in 0..2 {
        let id = EntityId::now();
        vault
            .put_entity(
                &id,
                crate::registry::ENTITY_TYPE_PERSON,
                TimeRange { start: 1, end: 1 },
                1,
                b"human",
            )
            .unwrap();
        owners.push(
            vault
                .authenticate_owner(id, &id.to_hex(), true, crate::store::GateDecisionId::now())
                .unwrap(),
        );
    }
    (dir, vault, owners.remove(0), owners.remove(0))
}
#[test]
fn every_preset_persists_explicit_grants_and_policy_once() -> Result<()> {
    for preset in [
        SharedVaultPreset::Personal,
        SharedVaultPreset::Family,
        SharedVaultPreset::Team,
        SharedVaultPreset::Org,
        SharedVaultPreset::Community,
    ] {
        let (dir, vault, owner, member) = fixture();
        let creation = vault.initialize_shared_vault(
            &owner,
            42,
            Some(preset),
            &[InitialSharedMember {
                member_ref: member.actor(),
                role: None,
            }],
            10,
        )?;
        assert_eq!(creation.grant_refs.len(), 2);
        let member_grants = creation
            .grant_refs
            .iter()
            .map(|id| {
                let raw = vault
                    .get_raw(&EntityId::from_hex(id).unwrap())
                    .unwrap()
                    .unwrap();
                decode_federation_grant_body(&raw[crate::batch::ENTITY_METADATA_HEADER_LEN..])
                    .unwrap()
            })
            .collect::<Vec<_>>();
        assert!(
            member_grants
                .iter()
                .any(|g| g.member_ref == member.actor() && g.role == preset.default_member_role())
        );
        assert!(
            vault
                .get_raw(&EntityId::from_hex(
                    creation.policy_ref.as_deref().unwrap()
                )?)?
                .is_some()
        );
        assert!(
            vault
                .initialize_shared_vault(&owner, 42, Some(preset), &[], 11)
                .is_err()
        );
        drop(vault);
        let reopened = Vault::open(dir.path(), crate::test_util::embedding_test_config())?;
        assert_eq!(reopened.shared_vault_creation()?, Some(creation));
    }
    let (_dir, vault, owner, member) = fixture();
    let explicit = vault.initialize_shared_vault(
        &owner,
        42,
        None,
        &[InitialSharedMember {
            member_ref: member.actor(),
            role: Some(FederationGrantRole::Viewer),
        }],
        1,
    )?;
    assert_eq!(explicit.grant_refs.len(), 1);
    assert_eq!(explicit.policy_ref, None);
    Ok(())
}
#[test]
fn equal_admins_keep_both_rulings_and_newest_wins_in_any_fold_order() -> Result<()> {
    let (_dir, vault, owner, admin) = fixture();
    vault.initialize_shared_vault(
        &owner,
        42,
        None,
        &[
            InitialSharedMember {
                member_ref: owner.actor(),
                role: Some(FederationGrantRole::Admin),
            },
            InitialSharedMember {
                member_ref: admin.actor(),
                role: Some(FederationGrantRole::Admin),
            },
        ],
        1,
    )?;
    let a = vault.append_admin_ruling(&owner, 42, "review:12", serde_json::json!("keep"), 2)?;
    let b = vault.append_admin_ruling(&admin, 42, "review:12", serde_json::json!("replace"), 3)?;
    assert_eq!(b.previous_ruling, Some(a.ruling.id.clone()));
    assert_eq!(b.previous_holder, Some(owner.actor().to_hex()));
    assert_eq!(b.previous_value, Some(serde_json::json!("keep")));
    assert_eq!(vault.admin_ruling_receipts(42)?.len(), 2);
    assert_eq!(
        vault.live_admin_ruling(42, "review:12")?,
        Some(b.ruling.clone())
    );
    assert_eq!(
        fold_admin_rulings(&[a.ruling.clone(), b.ruling.clone()], 42, "review:12"),
        Some(&b.ruling)
    );
    assert_eq!(
        fold_admin_rulings(&[b.ruling.clone(), a.ruling], 42, "review:12"),
        Some(&b.ruling)
    );
    Ok(())
}

fn replay_entity_between(source: &Vault, target: &Vault, id: EntityId) -> Result<()> {
    let raw = source.get_raw(&id)?.expect("replicated entity");
    let header = crate::batch::EntityMetadataHeader::parse(&raw).unwrap();
    target
        .batch()
        .put_replicated(
            &id,
            header.entity_type,
            TimeRange {
                start: header.occurred_start,
                end: header.occurred_end,
            },
            header.learned_at,
            &raw[crate::batch::ENTITY_METADATA_HEADER_LEN..],
        )
        .commit()?;
    for edge in source.edges_out(&id)? {
        target.put_edge(&id, edge.kind, &edge.target, edge.weight)?;
    }
    Ok(())
}

#[test]
fn concurrent_admin_rulings_merge_through_replicated_claims() -> Result<()> {
    let (_dir, left, owner, admin) = fixture();
    let (_other_dir, right) =
        crate::test_util::open_test_vault_with(crate::test_util::embedding_test_config());
    let creation = left.initialize_shared_vault(
        &owner,
        42,
        None,
        &[
            InitialSharedMember {
                member_ref: owner.actor(),
                role: Some(FederationGrantRole::Admin),
            },
            InitialSharedMember {
                member_ref: admin.actor(),
                role: Some(FederationGrantRole::Admin),
            },
        ],
        1,
    )?;
    for id in [owner.actor(), admin.actor()] {
        replay_entity_between(&left, &right, id)?;
    }
    for id in &creation.grant_refs {
        replay_entity_between(&left, &right, EntityId::from_hex(id)?)?;
    }
    let remote_admin = right.authenticate_owner(
        admin.actor(),
        &admin.actor().to_hex(),
        true,
        crate::store::GateDecisionId::now(),
    )?;
    let a = left.append_admin_ruling(&owner, 42, "review:12", serde_json::json!("keep"), 2)?;
    let b = right.append_admin_ruling(
        &remote_admin,
        42,
        "review:12",
        serde_json::json!("replace"),
        3,
    )?;
    let anchor = super::rulings::ruling_anchor_id(42)?;
    replay_entity_between(&left, &right, anchor)?;
    replay_entity_between(&left, &right, EntityId::from_hex(&a.ruling.id)?)?;
    replay_entity_between(&right, &left, EntityId::from_hex(&b.ruling.id)?)?;
    assert_eq!(
        left.admin_ruling_receipts(42)?,
        right.admin_ruling_receipts(42)?
    );
    let rows = left.admin_ruling_receipts(42)?;
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[1].previous_ruling, Some(rows[0].ruling.id.clone()));
    assert_eq!(rows[1].previous_holder, Some(rows[0].ruling.holder.clone()));
    assert_eq!(rows[1].previous_value, Some(rows[0].ruling.value.clone()));
    assert_eq!(
        left.live_admin_ruling(42, "review:12")?,
        right.live_admin_ruling(42, "review:12")?
    );
    let next =
        left.append_admin_ruling(&owner, 42, "review:12", serde_json::json!("after merge"), 1)?;
    assert_eq!(next.ruling.ledger_order, 2); // Causal order wins over a skewed wall clock.
    assert_eq!(left.live_admin_ruling(42, "review:12")?, Some(next.ruling));
    Ok(())
}
