use super::*;
use crate::registry::ENTITY_TYPE_SKILL;
use crate::skill_hub::{HubIndexEntry, LocalDirSkillHubAdapter, SkillHubAdapter};
use crate::test_util::put_policy_manifest_bytes;

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

// Import judge before a malformed policy defers the first seeded open. The
// fail-closed manifest also blocks ordinary hub imports, so the earlier import
// must happen while the policy is healthy.
fn deferred_judge_import_with_capability(
    with_capability: bool,
) -> Result<(tempfile::TempDir, EntityId, Vec<u8>)> {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open_unseeded_for_test(dir.path(), crate::VaultConfig::default())?;
    put_policy_manifest_bytes(
        &vault,
        crate::gate::default_policy_manifest_id()?,
        &crate::gate::default_policy_manifest()?,
    )?;
    let imported = EntityId::now();
    let (name, markdown) = FILES[1];
    let package = package(name, markdown)?;
    let reference = HubRef::new(
        EntityId::now(),
        format!("external/{name}"),
        HubPin::ContentHash(package.content_hash()?.to_hex()),
    )?;
    assert_eq!(
        vault.import_skill_from_hub_with_id(
            &reference,
            &package,
            imported,
            TimeRange { start: 1, end: 1 },
            1,
        )?,
        imported,
    );
    if with_capability {
        vault.with_write_txn(|txn| {
            vault.write_admitted_capability_surface_in_txn(
                txn,
                &imported,
                &crate::skill_hub::SkillCapabilitySurface::default().with_bin("existing-bin"),
            )
        })?;
    }
    let before = vault.get_raw(&imported)?.expect("imported judge bytes");
    let manifest = EntityId::now();
    put_policy_manifest_bytes(&vault, manifest, b"not-a-manifest")?;
    drop(vault);

    let vault = Vault::open(dir.path(), crate::VaultConfig::default())?;
    assert!(!SEEDED.contains(&vault.store, &vault.store.env.read_txn()?, &())?);
    vault.with_write_txn(|wtxn| {
        crate::batch::deindex_entity_for_test(&vault.store, wtxn, &manifest)
    })?;
    drop(vault);
    Ok((dir, imported, before))
}

fn deferred_judge_import() -> Result<(tempfile::TempDir, EntityId, Vec<u8>)> {
    deferred_judge_import_with_capability(false)
}

#[test]
fn bootstrap_skips_preexisting_holder_without_metadata_or_capability_mutation() -> Result<()> {
    let (dir, imported, before) = deferred_judge_import_with_capability(true)?;
    let vault = Vault::open_unseeded_for_test(dir.path(), crate::VaultConfig::default())?;
    let provenance_before = vault.skill_hub_provenance_count(&imported)?;
    drop(vault);
    let vault = Vault::open(dir.path(), crate::VaultConfig::default())?;
    assert_eq!(vault.get_raw(&imported)?, Some(before));
    assert_eq!(
        vault.skill_hub_provenance_count(&imported)?,
        provenance_before
    );
    // The existing admitted capability remains in force: the default embedded
    // package still conflicts when offered through the ordinary import door.
    let (name, markdown) = FILES[1];
    let package = package(name, markdown)?;
    let source = HubRef::new(
        EntityId::now(),
        "different-source",
        HubPin::ContentHash(package.content_hash()?.to_hex()),
    )?;
    assert!(matches!(
        vault.import_skill_from_hub_with_id(
            &source,
            &package,
            EntityId::now(),
            TimeRange { start: 2, end: 2 },
            2,
        ),
        Err(Error::Artifact(ArtifactError::InvalidSkillBody(_)))
    ));
    assert!(vault.get_skill_record(&stable_id("judge")?)?.is_none());
    Ok(())
}

#[test]
fn open_succeeds_when_an_earlier_import_holds_a_seed_under_another_id() -> Result<()> {
    let (dir, imported, _) = deferred_judge_import()?;
    let vault = Vault::open(dir.path(), crate::VaultConfig::default())?;
    assert_ne!(imported, stable_id("judge")?);
    assert!(vault.get_skill_record(&imported)?.is_some());
    assert!(SEEDED.contains(&vault.store, &vault.store.env.read_txn()?, &())?);
    assert_eq!(
        vault.count_entities_by_type(ENTITY_TYPE_SKILL)?,
        FILES.len() as u64
    );
    Ok(())
}

#[test]
fn a_seed_held_under_another_id_is_not_rewritten() -> Result<()> {
    let (dir, imported, before) = deferred_judge_import()?;
    let vault = Vault::open(dir.path(), crate::VaultConfig::default())?;
    assert_eq!(vault.get_raw(&imported)?, Some(before));
    assert_eq!(
        vault
            .get_skill_record(&imported)?
            .expect("imported judge")
            .lifecycle_status,
        SkillLifecycle::Candidate,
    );
    Ok(())
}

#[test]
fn bootstrap_duplicate_leaves_existing_hub_provenance_unchanged() -> Result<()> {
    let (dir, imported, before) = deferred_judge_import()?;
    let vault = Vault::open_unseeded_for_test(dir.path(), crate::VaultConfig::default())?;
    let provenance_before = vault.skill_hub_provenance_count(&imported)?;
    drop(vault);
    let vault = Vault::open(dir.path(), crate::VaultConfig::default())?;
    assert_eq!(vault.get_raw(&imported)?, Some(before));
    assert_eq!(
        vault.skill_hub_provenance_count(&imported)?,
        provenance_before
    );
    Ok(())
}

#[test]
fn foreign_import_at_seed_id_is_not_activated_or_rewritten_on_open() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open_unseeded_for_test(dir.path(), crate::VaultConfig::default())?;
    put_policy_manifest_bytes(
        &vault,
        crate::gate::default_policy_manifest_id()?,
        &crate::gate::default_policy_manifest()?,
    )?;
    let (name, markdown) = FILES[1];
    let id = stable_id(name)?;
    let package = package(name, markdown)?;
    let hash = package.content_hash()?;
    let mut adapter = LocalDirSkillHubAdapter::new(EntityId::now());
    let source = HubRef::new(
        adapter.hub_id(),
        "external/judge",
        HubPin::ContentHash(hash.to_hex()),
    )?;
    adapter.insert_package(&source.ref_string, source.pin.clone(), package.clone());
    let entry = HubIndexEntry {
        name: package.record.skill_id.clone(),
        description: package.record.desc.clone(),
        version: package.record.version,
        content_hash: hash,
        ref_string: source.ref_string.clone(),
    };
    assert_eq!(
        vault.ingest_skill_from_adapter_checked(
            &adapter,
            &entry,
            id,
            TimeRange { start: 1, end: 1 },
            1
        )?,
        id,
    );
    let before = vault.get_raw(&id)?;
    let lifecycle = vault
        .get_skill_record(&id)?
        .expect("foreign holder")
        .lifecycle_status;
    assert_eq!(lifecycle, SkillLifecycle::Candidate);
    let count = vault.skill_hub_provenance_count(&id)?;
    let saved = vault.stored_hub_package_in_txn(&vault.store.env.read_txn()?, &id)?;
    let receipt = vault
        .hub_import_receipt(&id, &source)?
        .expect("foreign receipt");
    let bootstrap_source =
        HubRef::new(stable_id("hub")?, name, HubPin::ContentHash(hash.to_hex()))?;
    assert!(vault.hub_import_receipt(&id, &bootstrap_source)?.is_none());
    drop(vault);

    let vault = Vault::open(dir.path(), crate::VaultConfig::default())?;
    assert_eq!(vault.get_raw(&id)?, before);
    assert_eq!(
        vault
            .get_skill_record(&id)?
            .expect("foreign holder")
            .lifecycle_status,
        lifecycle
    );
    assert_eq!(vault.skill_hub_provenance_count(&id)?, count);
    assert_eq!(
        vault.stored_hub_package_in_txn(&vault.store.env.read_txn()?, &id)?,
        saved
    );
    assert_eq!(vault.hub_import_receipt(&id, &source)?, Some(receipt));
    assert!(vault.hub_import_receipt(&id, &bootstrap_source)?.is_none());
    assert!(SEEDED.contains(&vault.store, &vault.store.env.read_txn()?, &())?);
    Ok(())
}
