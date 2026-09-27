//! First-open installed inventory and inert built-in provenance.
use super::*;
use crate::{VaultConfig, error::Result};

#[test]
fn fresh_vault_lists_four_engine_versioned_connector_packs() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), VaultConfig::default())?;
    let packs = vault.installed_packs()?;
    assert_eq!(packs.len(), PACKS.len());
    for (name, markdown) in PACKS {
        let receipt = vault
            .installed_pack(&format!("oneiron.{name}"))?
            .expect("built-in installed");
        assert_eq!(receipt.status, PackInstallStatus::Active);
        assert_eq!(receipt.kind, PackKind::Connector);
        assert_eq!(receipt.adapter, Some(PackAdapter::Builtin(name.to_owned())));
        assert_eq!(
            receipt.engine_version.as_deref(),
            Some(env!("CARGO_PKG_VERSION"))
        );
        assert_eq!(receipt.pin_type, "engine_version");
        assert_eq!(receipt.pin_value, env!("CARGO_PKG_VERSION"));
        assert_eq!(receipt.hub_ref, format!("built-in:{name}"));
        assert!(!receipt.permissions.grants.is_empty());
        assert!(!receipt.permissions.wakes.is_empty());
        // Embedded Rust adapters are not script-qualified and carry no runtime recipe.
        assert_eq!(receipt.qualification_report_hash, None);
        assert_eq!(receipt.runtime, None);
        let source = vault
            .get_pack_source(&EntityId::from_hex(&receipt.source_id)?)?
            .expect("exact source");
        assert_eq!(
            source.files(),
            &[HubFile::new("PACK.md", markdown.as_bytes())]
        );
        assert_eq!(receipt.content_hash, source.content_hash().to_hex());
        assert_eq!(
            receipt.permissions.grants,
            source
                .manifest()
                .requested_grants
                .iter()
                .cloned()
                .collect::<Vec<_>>()
        );
        assert_eq!(
            receipt.permissions.wakes,
            source
                .manifest()
                .wake_subscriptions
                .iter()
                .cloned()
                .collect::<Vec<_>>()
        );
        assert!(receipt.predicates.is_empty());
        assert!(receipt.kinds.is_empty());
    }
    let before = vault.installed_packs()?;
    drop(vault);
    let reopened = Vault::open(dir.path(), VaultConfig::default())?;
    assert_eq!(reopened.installed_packs()?, before);
    Ok(())
}

#[test]
fn deleted_builtin_source_stays_deleted_on_reopen() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), VaultConfig::default())?;
    let source_id = EntityId::from_hex(&vault.installed_pack("oneiron.slack")?.unwrap().source_id)?;
    assert!(vault.delete_entity(&source_id)?);
    drop(vault);
    let vault = Vault::open(dir.path(), VaultConfig::default())?;
    assert!(
        vault
            .installed_packs()?
            .iter()
            .all(|pack| pack.pack_name != "oneiron.slack")
    );
    assert!(vault.get_pack_source(&source_id)?.is_none());
    Ok(())
}

#[test]
fn first_seed_skips_prior_deleted_or_occupied_source_id() -> Result<()> {
    let source = PackSource::from_files(vec![HubFile::new("PACK.md", PACKS[0].1.as_bytes())])?;
    let id = source.entity_id()?;
    for deleted in [false, true] {
        let dir = tempfile::tempdir()?;
        let vault = Vault::open_unseeded_for_test(dir.path(), VaultConfig::default())?;
        crate::test_util::put_policy_manifest_bytes(
            &vault,
            crate::gate::default_policy_manifest_id()?,
            &crate::gate::default_policy_manifest(),
        )?;
        if deleted {
            vault.stage_pack_source(&source, TimeRange { start: 1, end: 1 }, 1)?;
            assert!(vault.delete_entity(&id)?);
        } else {
            vault.put_entity(
                &id,
                crate::registry::ENTITY_TYPE_PERSON,
                TimeRange { start: 1, end: 1 },
                1,
                b"prior owner",
            )?;
        }
        drop(vault);
        let vault = Vault::open(dir.path(), VaultConfig::default())?;
        assert!(vault.installed_pack("oneiron.slack")?.is_none());
        assert_eq!(vault.installed_packs()?.len(), 3);
        if deleted {
            assert!(vault.get_pack_source(&id)?.is_none());
        } else {
            assert_eq!(
                vault.get_entity_type(&id)?,
                Some(crate::registry::ENTITY_TYPE_PERSON)
            );
        }
    }
    Ok(())
}
