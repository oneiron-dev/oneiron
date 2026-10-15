use super::*;
use crate::registry::ENTITY_TYPE_SKILL;
use crate::skill_hub::{HubIndexEntry, LocalDirSkillHubAdapter, SkillHubAdapter};
use crate::test_util::put_policy_manifest_bytes;

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
        &crate::gate::default_policy_manifest().unwrap(),
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
        &crate::gate::default_policy_manifest().unwrap(),
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

#[test]
fn different_content_at_seed_id_does_not_prevent_open_or_rewrite_holder() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open_unseeded_for_test(dir.path(), crate::VaultConfig::default())?;
    put_policy_manifest_bytes(
        &vault,
        crate::gate::default_policy_manifest_id()?,
        &crate::gate::default_policy_manifest().unwrap(),
    )?;
    let id = stable_id("judge")?;
    let other = package(
        "different-skill",
        "---\nname: different-skill\ndescription: earlier import\n---\nDifferent files.\n",
    )?;
    let hash = other.content_hash()?;
    assert_ne!(hash, package("judge", FILES[1].1)?.content_hash()?);
    let mut adapter = LocalDirSkillHubAdapter::new(EntityId::now());
    let source = HubRef::new(
        adapter.hub_id(),
        "external/different",
        HubPin::ContentHash(hash.to_hex()),
    )?;
    adapter.insert_package(&source.ref_string, source.pin.clone(), other.clone());
    let entry = HubIndexEntry {
        name: other.record.skill_id.clone(),
        description: other.record.desc.clone(),
        version: other.record.version,
        content_hash: hash,
        ref_string: source.ref_string.clone(),
    };
    assert_eq!(
        vault.ingest_skill_from_adapter_checked(
            &adapter,
            &entry,
            id,
            TimeRange { start: 1, end: 1 },
            1,
        )?,
        id,
    );
    let before = vault.get_raw(&id)?;
    let provenance_before = vault.skill_hub_provenance_count(&id)?;
    let receipt_before = vault.hub_import_receipt(&id, &source)?;
    drop(vault);

    let vault = Vault::open(dir.path(), crate::VaultConfig::default())?;
    assert_eq!(vault.get_raw(&id)?, before);
    assert_eq!(vault.skill_hub_provenance_count(&id)?, provenance_before);
    assert_eq!(vault.hub_import_receipt(&id, &source)?, receipt_before);
    assert_eq!(
        vault.get_skill_record(&id)?.unwrap().skill_id,
        "different-skill"
    );
    assert_eq!(
        vault.count_entities_by_type(ENTITY_TYPE_SKILL)?,
        FILES.len() as u64
    );
    assert!(SEEDED.contains(&vault.store, &vault.store.env.read_txn()?, &())?);
    Ok(())
}

fn restore_owner(vault: &Vault) -> Result<crate::consent::AuthenticatedOwner> {
    let actor = EntityId::now();
    vault.put_entity(
        &actor,
        crate::registry::ENTITY_TYPE_PERSON,
        TimeRange { start: 1, end: 1 },
        1,
        b"restore owner",
    )?;
    vault.authenticate_owner(
        actor,
        "principal:skill-restore",
        true,
        crate::store::GateDecisionId::now(),
    )
}

#[test]
fn delete_then_restore_defaults_mints_candidate_with_pinned_hash() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), crate::VaultConfig::default())?;
    let name = "judge";
    let old = stable_id(name)?;
    let hash = package(name, FILES[1].1)?.content_hash()?;
    assert!(vault.delete_entity(&old)?);
    drop(vault);
    let vault = Vault::open(dir.path(), crate::VaultConfig::default())?;
    assert!(vault.get_skill_record(&old)?.is_none());
    let owner = restore_owner(&vault)?;
    let restored = vault.restore_default_skills(&owner, TimeRange { start: 2, end: 2 }, 2)?;
    assert_eq!(restored.len(), 1);
    let id = restored[0];
    assert_ne!(id, old);
    let record = vault.get_skill_record(&id)?.expect("restored candidate");
    assert_eq!(record.content_hash, Some(hash));
    assert_eq!(record.lifecycle_status, SkillLifecycle::Candidate);
    let source = HubRef::new(stable_id("hub")?, name, HubPin::ContentHash(hash.to_hex()))?;
    assert_eq!(
        vault
            .hub_import_receipt(&id, &source)?
            .unwrap()
            .content_hash,
        hash.to_hex()
    );
    assert_eq!(
        vault.restore_default_skills(&owner, TimeRange { start: 3, end: 3 }, 3)?,
        Vec::<EntityId>::new()
    );
    Ok(())
}

#[test]
fn later_normal_import_keeps_the_fresh_restored_source_holder() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open_unseeded_for_test(dir.path(), crate::VaultConfig::default())?;
    put_policy_manifest_bytes(
        &vault,
        crate::gate::default_policy_manifest_id()?,
        &crate::gate::default_policy_manifest().unwrap(),
    )?;
    let (name, markdown) = FILES[1];
    let package = package(name, markdown)?;
    let hash = package.content_hash()?;
    let source = HubRef::new(stable_id("hub")?, name, HubPin::ContentHash(hash.to_hex()))?;
    // The retired UUID sorts strictly before a restored clock UUID, so the
    // previous first-imported-row selector would return the wrong holder.
    let mut bytes = [0_u8; 16];
    bytes[6] = 0x80;
    bytes[8] = 0x80;
    let old = EntityId::from_bytes(bytes)?;
    assert_eq!(
        vault.import_skill_from_hub_with_id(
            &source,
            &package,
            old,
            TimeRange { start: 1, end: 1 },
            1
        )?,
        old
    );
    let mut record = vault.get_skill_record(&old)?.unwrap();
    record.lifecycle_status = SkillLifecycle::Active;
    let data = crate::skill::encode_skill_record(&record)?;
    vault.with_write_txn(|txn| {
        vault.admit_hub_skill_record_in_txn(
            txn,
            TimeRange { start: 2, end: 2 },
            2,
            data.clone(),
            HubAdmissionProof::bootstrap(old, &data),
        )
    })?;
    record.lifecycle_status = SkillLifecycle::Stale;
    vault.update_skill_record(&old, &record, TimeRange { start: 3, end: 3 }, 3)?;
    let owner = restore_owner(&vault)?;
    let restored = vault.restore_default_skills(&owner, TimeRange { start: 4, end: 4 }, 4)?;
    let replacement = restored
        .into_iter()
        .find(|id| {
            vault
                .get_skill_record(id)
                .ok()
                .flatten()
                .is_some_and(|row| row.skill_id == name)
        })
        .expect("restored judge");
    assert_ne!(replacement, old);
    assert!(old.as_bytes() < replacement.as_bytes());
    assert_eq!(
        vault.import_skill_from_hub(&source, &package, TimeRange { start: 5, end: 5 }, 5)?,
        replacement
    );
    assert_eq!(
        vault.get_skill_record(&old)?.unwrap().lifecycle_status,
        SkillLifecycle::Stale
    );
    assert_eq!(vault.skill_hub_provenance_count(&replacement)?, 1);
    assert_eq!(
        vault.restore_default_skills(&owner, TimeRange { start: 6, end: 6 }, 6)?,
        Vec::<EntityId>::new()
    );
    Ok(())
}

#[test]
fn restore_refuses_owner_who_is_no_longer_active() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), crate::VaultConfig::default())?;
    let owner = restore_owner(&vault)?;
    let old = stable_id("judge")?;
    assert!(vault.delete_entity(&old)?);
    assert!(vault.delete_entity(&owner.actor())?);
    let before = vault.count_entities_by_type(ENTITY_TYPE_SKILL)?;
    assert!(
        vault
            .restore_default_skills(&owner, TimeRange { start: 2, end: 2 }, 2)
            .is_err()
    );
    assert_eq!(vault.count_entities_by_type(ENTITY_TYPE_SKILL)?, before);
    Ok(())
}
