use super::*;
use crate::registry::ENTITY_TYPE_SKILL;
use crate::skill_hub::{LocalDirSkillHubAdapter, SkillHubAdapter};

#[test]
fn bootstrap_is_active_versioned_and_does_not_rewrite_on_reopen() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), crate::VaultConfig::default())?;
    let ids = vault.entities_by_type(ENTITY_TYPE_SKILL)?;
    assert_eq!(ids.len(), 4);
    let mut before = Vec::new();
    for (name, markdown) in FILES {
        let id = stable_id(name)?;
        assert!(ids.contains(&id));
        let mut record = vault.get_skill_record(&id)?.expect("seeded skill");
        assert_eq!(record.lifecycle_status, SkillLifecycle::Active);
        assert_eq!(record.version, env!("CARGO_PKG_VERSION"));
        assert_eq!(
            record.provenance,
            package(name, markdown)?.record.provenance
        );
        // Reopen must preserve an owner's lifecycle decision.
        record.lifecycle_status = SkillLifecycle::Stale;
        vault.update_skill_record(&id, &record, TimeRange { start: 1, end: 1 }, 1)?;
        before.push((id, vault.get_raw(&id)?));
    }
    let count = vault.count_entities_by_type(ENTITY_TYPE_SKILL)?;
    drop(vault);
    let vault = Vault::open(dir.path(), crate::VaultConfig::default())?;
    assert_eq!(vault.count_entities_by_type(ENTITY_TYPE_SKILL)?, count);
    for (id, raw) in before {
        assert_eq!(vault.get_raw(&id)?, raw);
    }
    Ok(())
}

#[test]
fn all_shipped_files_conform_and_import_unchanged() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), crate::VaultConfig::default())?;
    let mut adapter = LocalDirSkillHubAdapter::new(stable_id("hub")?);
    for (name, markdown) in FILES {
        let package = package(name, markdown)?;
        let pin = HubPin::ContentHash(package.content_hash()?.to_hex());
        let hub_ref = HubRef::new(adapter.hub_id(), name, pin.clone())?;
        adapter.insert_package(name, pin, package.clone());
        let imported = vault.import_skill_from_adapter(
            &adapter,
            &hub_ref,
            TimeRange { start: 1, end: 1 },
            1,
        )?;
        assert_eq!(imported, stable_id(name)?);
        assert_eq!(
            adapter.fetch_package(&hub_ref)?.export_files()?,
            package.files
        );
        assert_eq!(
            vault
                .get_skill_record(&imported)?
                .expect("imported")
                .content_hash,
            Some(package.content_hash()?)
        );
    }
    assert!(package("bad", "# Not a skill").is_err());
    Ok(())
}

#[test]
fn bootstrap_does_not_reactivate_changed_or_non_seed_records() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), crate::VaultConfig::default())?;
    let id = stable_id("judge")?;
    let mut record = vault.get_skill_record(&id)?.expect("seeded");
    record.lifecycle_status = SkillLifecycle::Stale;
    vault.update_skill_record(&id, &record, TimeRange { start: 1, end: 1 }, 1)?;
    let before = vault.get_raw(&id)?;
    record.lifecycle_status = SkillLifecycle::Active;
    record.desc.push_str(" changed");
    assert!(
        vault
            .update_skill_record(&id, &record, TimeRange { start: 2, end: 2 }, 2)
            .is_err()
    );
    let outsider = EntityId::now();
    let package = package(
        "outside",
        "---\nname: outside\ndescription: fixture\n---\nOutside the bootstrap set.\n",
    )?;
    let reference = HubRef::new(EntityId::now(), "outside", HubPin::None)?;
    vault.import_skill_from_hub_with_id(
        &reference,
        &package,
        outsider,
        TimeRange { start: 3, end: 3 },
        3,
    )?;
    seed_bootstrap_skills(&vault)?;
    assert_eq!(vault.get_raw(&id)?, before);
    assert_eq!(
        vault.get_skill_record(&outsider)?.unwrap().lifecycle_status,
        SkillLifecycle::Candidate
    );
    Ok(())
}
