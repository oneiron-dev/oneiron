use super::*;
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::{EntityId, TimeRange, Vault, VaultConfig};

fn person(vault: &Vault, body: &[u8]) -> EntityId {
    let id = EntityId::now();
    vault
        .put_entity(
            &id,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            body,
        )
        .unwrap();
    id
}

fn plan(root: &Path, keep: usize) -> BackupPlan {
    let vault = root.join("vault");
    BackupPlan::new(&vault, root.join("vault.backups"), keep)
}

#[test]
fn take_prunes_to_keep_and_leaves_other_files_alone() {
    let root = tempfile::tempdir().unwrap();
    let plan = plan(root.path(), 2);
    let vault = Vault::open_owned(root.path().join("vault"), VaultConfig::default()).unwrap();
    std::fs::create_dir_all(&plan.dir).unwrap();
    let foreign = [
        "other-20200101T000000.000Z-abcdef12.oneiron-backup",
        "vault-not-a-stamp-abcdef12.oneiron-backup",
        ".vault-20200101T000000.000Z.partial",
        "notes.txt",
    ];
    for name in foreign {
        std::fs::write(plan.dir.join(name), b"x").unwrap();
    }
    let mut taken = Vec::new();
    for _ in 0..3 {
        std::thread::sleep(std::time::Duration::from_millis(3));
        taken.push(take(&vault, &plan).unwrap());
    }
    assert_eq!(taken[2].pruned, vec![taken[0].backup.file.clone()]);
    let listed = list(&plan).unwrap();
    assert_eq!(
        listed.iter().map(|r| &r.file).collect::<Vec<_>>(),
        vec![&taken[1].backup.file, &taken[2].backup.file]
    );
    for name in foreign {
        assert!(plan.dir.join(name).exists(), "{name} must survive pruning");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&taken[2].backup.path)
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o077, 0, "a backup holds private data");
    }
}

#[test]
fn rehearsal_reports_the_backup_and_restore_brings_it_back() {
    let root = tempfile::tempdir().unwrap();
    let vault_path = root.path().join("vault");
    let plan = plan(root.path(), 7);
    let vault = Vault::open_owned(&vault_path, VaultConfig::default()).unwrap();
    let kept = person(&vault, b"in the backup");
    let at_backup = kind_counts(&vault).unwrap();
    let outcome = take(&vault, &plan).unwrap();
    let later = person(&vault, b"after the backup");
    drop(vault);

    let rehearsal = rehearse(&outcome.backup.path, VaultConfig::default(), None).unwrap();
    assert!(rehearsal.verified);
    assert!(!rehearsal.kept);
    assert_eq!(rehearsal.checkpoint_id, outcome.checkpoint_id);
    assert_eq!(rehearsal.kinds, at_backup);
    assert!(!rehearsal.restored_into.exists());

    let restored = restore_over(&outcome.backup.path, &vault_path, VaultConfig::default()).unwrap();
    assert_eq!(restored.kinds, at_backup);
    assert_eq!(restored.durability_warning, None);
    let vault = Vault::open_owned(&vault_path, VaultConfig::default()).unwrap();
    assert!(vault.get(&kept).unwrap().is_some());
    assert!(vault.get(&later).unwrap().is_none());
    drop(vault);
    let previous = Vault::open_owned(&restored.previous_vault, VaultConfig::default()).unwrap();
    assert!(
        previous.get(&later).unwrap().is_some(),
        "the old vault is kept whole"
    );
}

#[test]
fn a_failed_sync_after_the_swap_still_reports_the_restore_and_the_previous_vault() {
    let root = tempfile::tempdir().unwrap();
    let vault_path = root.path().join("vault");
    let plan = plan(root.path(), 7);
    let vault = Vault::open_owned(&vault_path, VaultConfig::default()).unwrap();
    let kept = person(&vault, b"in the backup");
    let outcome = take(&vault, &plan).unwrap();
    let later = person(&vault, b"after the backup");
    drop(vault);

    let restored = restore_over_syncing(
        &outcome.backup.path,
        &vault_path,
        VaultConfig::default(),
        |_| Err(anyhow::anyhow!("fsync: input/output error")),
    )
    .expect("the swap happened, so the restore succeeded");
    let warning = restored.durability_warning.as_deref().expect("a warning");
    assert!(warning.contains("input/output error"), "{warning}");
    assert!(
        warning.contains(&restored.previous_vault.display().to_string()),
        "{warning}"
    );
    let vault = Vault::open_owned(&vault_path, VaultConfig::default()).unwrap();
    assert!(vault.get(&kept).unwrap().is_some());
    assert!(vault.get(&later).unwrap().is_none());
    drop(vault);
    let previous = Vault::open_owned(&restored.previous_vault, VaultConfig::default()).unwrap();
    assert!(previous.get(&later).unwrap().is_some());
}

#[test]
fn restore_refuses_a_running_vault_and_leaves_it_alone() {
    let root = tempfile::tempdir().unwrap();
    let vault_path = root.path().join("vault");
    let plan = plan(root.path(), 7);
    let vault = Vault::open_owned(&vault_path, VaultConfig::default()).unwrap();
    let outcome = take(&vault, &plan).unwrap();
    let later = person(&vault, b"after the backup");
    assert!(restore_over(&outcome.backup.path, &vault_path, VaultConfig::default()).is_err());
    assert!(vault.get(&later).unwrap().is_some());
    let siblings: Vec<_> = std::fs::read_dir(root.path())
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|name| name.contains("restore"))
        .collect();
    assert!(siblings.is_empty(), "{siblings:?}");
}

#[test]
fn vaults_sharing_a_backup_directory_never_prune_each_other() {
    let root = tempfile::tempdir().unwrap();
    let shared = root.path().join("backups");
    let open_at = |parent: &str| {
        let path = root.path().join(parent).join("vault");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let vault = Vault::open_owned(&path, VaultConfig::default()).unwrap();
        (BackupPlan::new(&path, shared.clone(), 1), vault)
    };
    let (plan_a, vault_a) = open_at("a");
    let (plan_b, vault_b) = open_at("b");
    assert_ne!(plan_a.label, plan_b.label, "same name, different vaults");
    let kept_b = take(&vault_b, &plan_b).unwrap();
    for _ in 0..2 {
        std::thread::sleep(std::time::Duration::from_millis(3));
        take(&vault_a, &plan_a).unwrap();
    }
    assert_eq!(list(&plan_a).unwrap().len(), 1);
    assert_eq!(list(&plan_b).unwrap(), vec![kept_b.backup]);
}

#[test]
fn a_failed_rehearsal_removes_only_what_it_created() {
    let root = tempfile::tempdir().unwrap();
    let scratch = root.path().join("scratch");
    // Custody left by an earlier vault of the same name is not the rehearsal's.
    let custody = root.path().join(".scratch.gate-decision-keys");
    std::fs::create_dir(&custody).unwrap();
    std::fs::write(custody.join("key"), b"not ours").unwrap();
    let bogus = root.path().join("not-a-backup");
    std::fs::write(&bogus, b"garbage").unwrap();
    assert!(rehearse(&bogus, VaultConfig::default(), Some(&scratch)).is_err());
    assert!(!scratch.exists());
    assert_eq!(std::fs::read(custody.join("key")).unwrap(), b"not ours");
}

#[test]
fn a_clock_that_stepped_back_never_prunes_the_backup_just_taken() {
    let root = tempfile::tempdir().unwrap();
    let plan = plan(root.path(), 2);
    let vault = Vault::open_owned(root.path().join("vault"), VaultConfig::default()).unwrap();
    // Two backups stamped in the future: the clock has since stepped back.
    let mut older = Vec::new();
    for _ in 0..2 {
        let taken = take(&vault, &plan).unwrap();
        let future = taken
            .backup
            .file
            .replace(&file_stamp(taken.backup.taken_ms), "20991231T235959.999Z");
        std::fs::rename(&taken.backup.path, plan.dir.join(&future)).unwrap();
        older.push(future);
    }
    let newest = take(&vault, &plan).unwrap();
    assert!(newest.backup.path.exists(), "the backup just taken is kept");
    assert_eq!(newest.pruned, vec![older[0].clone()]);
    let listed: Vec<_> = list(&plan).unwrap().into_iter().map(|r| r.file).collect();
    assert_eq!(listed, vec![older[1].clone(), newest.backup.file.clone()]);
    assert!(newest.backup.sequence > 2, "{}", newest.backup.file);
}

/// A backup named before sequences (`<label>-<stamp>-<id8>`, as #1301
/// shipped) still lists, older than every sequenced one, and is pruned first.
#[test]
fn a_backup_named_before_sequences_lists_first_and_is_pruned_first() {
    let root = tempfile::tempdir().unwrap();
    let plan = plan(root.path(), 2);
    let vault = Vault::open_owned(root.path().join("vault"), VaultConfig::default()).unwrap();
    let first = take(&vault, &plan).unwrap().backup;
    let legacy = format!("{}-20991231T235959.999Z-abcdef12{FILE_SUFFIX}", plan.label);
    std::fs::rename(&first.path, plan.dir.join(&legacy)).unwrap();
    let listed = list(&plan).unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(
        (listed[0].file.as_str(), listed[0].sequence),
        (legacy.as_str(), 0)
    );

    let second = take(&vault, &plan).unwrap();
    assert_eq!(second.backup.sequence, 1);
    assert!(second.pruned.is_empty());
    let third = take(&vault, &plan).unwrap();
    assert_eq!(third.pruned, vec![legacy]);
}
