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
