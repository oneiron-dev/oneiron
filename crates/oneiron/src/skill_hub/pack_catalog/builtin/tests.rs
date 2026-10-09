//! First-open installed inventory and inert built-in provenance.
use super::*;
use crate::{VaultConfig, error::Result};

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
            &crate::gate::default_policy_manifest().unwrap(),
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
