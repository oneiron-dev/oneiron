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
    let root = oneiron::test_support::restore_tempdir();
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
    let root = oneiron::test_support::restore_tempdir();
    let vault_path = root.path().join("vault");
    let plan = plan(root.path(), 7);
    let vault = Vault::open_owned(&vault_path, VaultConfig::default()).unwrap();
    let kept = person(&vault, b"in the backup");
    let at_backup = kind_counts(&vault).unwrap();
    let outcome = take(&vault, &plan).unwrap();
    let later = person(&vault, b"after the backup");
    drop(vault);

    let source = SideRestoreSource::read(&vault_path).unwrap();
    let rehearsal = rehearse_in(
        root.path(),
        &outcome.backup.path,
        VaultConfig::default(),
        None,
        &source,
    )
    .unwrap();
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
    let root = oneiron::test_support::restore_tempdir();
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
        exchange,
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

/// A vault path that is a symlink to the vault's directory: the restore
/// swaps that directory, so the path still names the live restored vault,
/// and the vault set aside is the one archived.
#[cfg(unix)]
#[test]
fn a_restore_over_a_symlinked_vault_path_swaps_the_directory_it_names() {
    let root = oneiron::test_support::restore_tempdir();
    let directory = root.path().join("data").join("vault");
    let vault = Vault::open_owned(&directory, VaultConfig::default()).unwrap();
    let kept = person(&vault, b"in the backup");
    let outcome = take(&vault, &plan(root.path(), 7)).unwrap();
    let later = person(&vault, b"after the backup");
    drop(vault);
    let link = root.path().join("vault");
    std::os::unix::fs::symlink(&directory, &link).unwrap();

    let restored = restore_over(&outcome.backup.path, &link, VaultConfig::default()).unwrap();
    assert!(
        std::fs::symlink_metadata(&link)
            .unwrap()
            .file_type()
            .is_symlink()
    );
    let vault = Vault::open_owned(&link, VaultConfig::default()).unwrap();
    assert!(vault.get(&kept).unwrap().is_some());
    assert!(vault.get(&later).unwrap().is_none());
    person(&vault, b"the restored vault is live");
    drop(vault);
    let previous = Vault::open_owned(&restored.previous_vault, VaultConfig::default()).unwrap();
    assert!(previous.get(&later).unwrap().is_some());
    assert!(
        previous
            .put_entity(
                &EntityId::now(),
                ENTITY_TYPE_PERSON,
                TimeRange { start: 1, end: 1 },
                1,
                b"the previous vault is archived",
            )
            .is_err()
    );
}

/// A swap the engine cannot confirm once the directories were exchanged
/// removes nothing: the staging directory may hold the previous vault, and
/// the vault at the vault path stays the live one (Astra re-check: a failure
/// after the exchange must not run the cleanup of a failure before it).
#[test]
fn a_restore_whose_swap_cannot_be_confirmed_removes_nothing() {
    let root = oneiron::test_support::restore_tempdir();
    let vault_path = root.path().join("vault");
    let vault = Vault::open_owned(&vault_path, VaultConfig::default()).unwrap();
    let outcome = take(&vault, &plan(root.path(), 7)).unwrap();
    let later = person(&vault, b"after the backup");
    drop(vault);

    // The exchange happens, and is undone before the engine checks it.
    let error = restore_over_syncing(
        &outcome.backup.path,
        &vault_path,
        VaultConfig::default(),
        |a, b| {
            exchange(a, b)?;
            exchange(a, b)
        },
        |_| Ok(()),
    )
    .expect_err("the engine finds the replacement out of place");
    assert!(
        format!("{error:#}").contains("nothing was removed"),
        "{error:#}"
    );
    let staging = std::fs::read_dir(root.path())
        .unwrap()
        .filter(|entry| {
            entry
                .as_ref()
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(".vault.restore-")
        })
        .count();
    assert_eq!(staging, 1, "the staging directory is kept");
    let vault = Vault::open_owned(&vault_path, VaultConfig::default()).unwrap();
    assert!(vault.get(&later).unwrap().is_some());
    person(&vault, b"the vault in place is live");
}

/// C8 review r1 (Sol F1, Astra F3): a staging directory is opened by name
/// after it is made. A directory moved in under that name before the open is
/// held only if it could be the one made, empty and owner-only; any other is
/// refused and left whole, so no removal reaches what the restore never made.
/// Review r2 (Sol F5, Astra F4): one that does not open is left too.
#[cfg(unix)]
#[test]
fn a_directory_moved_in_before_the_open_is_never_held() {
    use std::os::unix::fs::PermissionsExt;
    let root = oneiron::test_support::restore_tempdir();
    let private = |name: &str, mode: u32| {
        let dir = root.path().join(name);
        std::fs::create_dir(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(mode)).unwrap();
        dir
    };
    let foreign = private("foreign", 0o700);
    std::fs::write(foreign.join("keep.txt"), b"not the restore's").unwrap();
    assert!(Owned::hold(foreign.clone()).is_err());
    assert_eq!(
        std::fs::read(foreign.join("keep.txt")).unwrap(),
        b"not the restore's"
    );
    let shared = private("shared", 0o755);
    assert!(Owned::hold(shared.clone()).is_err());
    assert!(shared.is_dir(), "a refused directory is left");
    if !rustix::process::geteuid().is_root() {
        let locked = private("locked", 0o000);
        assert!(Owned::hold(locked.clone()).is_err());
        assert!(locked.is_dir(), "a directory that does not open is left");
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o700)).unwrap();
    }

    // Control: an empty owner-only directory is held, and removed.
    let fresh = private("fresh", 0o700);
    Owned::hold(fresh.clone()).unwrap().remove();
    assert!(!fresh.exists());
}

/// C8: a swap that fails removes the staging directory the restore made,
/// and only it. A directory, or a link to one, put under the staging name
/// while the swap ran is not the restore's: it is left whole, and so is the
/// staging directory it displaced.
#[cfg(unix)]
#[test]
fn a_failed_swap_removes_only_the_staging_directory_it_made() {
    for occupant in ["directory", "link"] {
        let root = oneiron::test_support::restore_tempdir();
        let vault_path = root.path().join("vault");
        let vault = Vault::open_owned(&vault_path, VaultConfig::default()).unwrap();
        let outcome = take(&vault, &plan(root.path(), 7)).unwrap();
        let later = person(&vault, b"after the backup");
        drop(vault);
        let (moved, foreign) = (root.path().join("moved"), root.path().join("foreign"));
        std::fs::create_dir(&foreign).unwrap();
        std::fs::write(foreign.join("keep.txt"), b"not the restore's").unwrap();
        let staging = std::cell::RefCell::new(PathBuf::new());

        let error = restore_over_syncing(
            &outcome.backup.path,
            &vault_path,
            VaultConfig::default(),
            |restored, _| {
                let name = restored.parent().unwrap();
                std::fs::rename(name, &moved)?;
                if occupant == "link" {
                    std::os::unix::fs::symlink(&foreign, name)?;
                } else {
                    std::fs::rename(&foreign, name)?;
                }
                *staging.borrow_mut() = name.to_path_buf();
                Err(std::io::ErrorKind::Unsupported.into())
            },
            |_| Ok(()),
        )
        .expect_err("the swap failed");
        assert!(
            format!("{error:#}").contains("nothing was moved"),
            "{occupant}: {error:#}"
        );
        let staging = staging.into_inner();
        let left = std::fs::symlink_metadata(&staging).expect("the occupant is left");
        assert_eq!(left.file_type().is_symlink(), occupant == "link");
        assert_eq!(
            std::fs::read(staging.join("keep.txt")).unwrap(),
            b"not the restore's"
        );
        assert!(moved.join("vault").is_dir(), "{occupant}: the copy is left");
        let vault = Vault::open_owned(&vault_path, VaultConfig::default()).unwrap();
        assert!(vault.get(&later).unwrap().is_some());
        person(&vault, b"the vault in place is live");
    }
}

#[test]
fn restore_refuses_a_running_vault_and_leaves_it_alone() {
    let root = oneiron::test_support::restore_tempdir();
    let vault_path = root.path().join("vault");
    let plan = plan(root.path(), 7);
    let vault = Vault::open_owned(&vault_path, VaultConfig::default()).unwrap();
    let outcome = take(&vault, &plan).unwrap();
    let later = person(&vault, b"after the backup");
    let refused = restore_over(&outcome.backup.path, &vault_path, VaultConfig::default())
        .map(|_| ())
        .unwrap_err()
        .to_string();
    // The running vault's refusal, not the path's (C8 review r8).
    assert!(!refused.contains("another user"), "{refused}");
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
    let root = oneiron::test_support::restore_tempdir();
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
    let root = oneiron::test_support::restore_tempdir();
    let scratch = root.path().join("scratch");
    // Custody left by an earlier vault of the same name is not the rehearsal's.
    let custody = root.path().join(".scratch.gate-decision-keys");
    std::fs::create_dir(&custody).unwrap();
    std::fs::write(custody.join("key"), b"not ours").unwrap();
    let bogus = root.path().join("not-a-backup");
    std::fs::write(&bogus, b"garbage").unwrap();
    drop(Vault::open_owned(root.path().join("vault"), VaultConfig::default()).unwrap());
    let source = SideRestoreSource::read(&root.path().join("vault")).unwrap();
    assert!(rehearse(&bogus, VaultConfig::default(), Some(&scratch), &source).is_err());
    assert!(!scratch.exists());
    assert_eq!(std::fs::read(custody.join("key")).unwrap(), b"not ours");
}

#[test]
fn a_clock_that_stepped_back_never_prunes_the_backup_just_taken() {
    let root = oneiron::test_support::restore_tempdir();
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
    let root = oneiron::test_support::restore_tempdir();
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

#[test]
fn pruning_preserves_contents_of_same_label_malformed_stamp_files() {
    let root = oneiron::test_support::restore_tempdir();
    let plan = plan(root.path(), 1);
    let vault = Vault::open_owned(root.path().join("vault"), VaultConfig::default()).unwrap();
    std::fs::create_dir_all(&plan.dir).unwrap();
    let mut malformed = Vec::new();
    for stamp in [
        "",
        "20261008T123456Z",
        "20261332T123456.789Z",
        "20260230T123456.789Z",
        "2026100xT123456.789Z",
    ] {
        let path = plan.dir.join(format!(
            "{}-0000000000-{stamp}-abcdef12.oneiron-backup",
            plan.label
        ));
        let contents = format!("owner-sentinel:{stamp}").into_bytes();
        std::fs::write(&path, &contents).unwrap();
        malformed.push((path, contents));
    }
    let first = take(&vault, &plan).unwrap();
    assert!(first.pruned.is_empty());
    for (path, contents) in &malformed {
        assert_eq!(std::fs::read(path).unwrap(), *contents);
    }
    let second = take(&vault, &plan).unwrap();
    assert_eq!(second.pruned, vec![first.backup.file]);
    assert!(!first.backup.path.exists());
    let listed = list(&plan).unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].file, second.backup.file);
    for (path, contents) in &malformed {
        assert_eq!(std::fs::read(path).unwrap(), *contents);
    }
}

/// C8 review r4 (Sol F2): a restore over a vault whose directory another user
/// could move an entry in is refused before anything is made or opened: no
/// staging directory beside it, and the vault is never opened, so its writer
/// lock is not made again. Control: once no one else may write there, the
/// same restore goes ahead.
#[cfg(unix)]
#[test]
fn a_restore_where_another_user_could_move_entries_opens_nothing() {
    use std::os::unix::fs::PermissionsExt;
    let root = oneiron::test_support::restore_tempdir();
    let parent = root.path().join("shared");
    std::fs::create_dir(&parent).unwrap();
    let vault_path = parent.join("vault");
    let backup = {
        let vault = Vault::open_owned(&vault_path, VaultConfig::default()).unwrap();
        take(&vault, &plan(root.path(), 7)).unwrap().backup.path
    };
    let lock = vault_path.join(oneiron::VAULT_WRITER_LOCK_FILE);
    std::fs::remove_file(&lock).unwrap();
    let set_mode = |mode| {
        std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(mode)).unwrap();
    };
    set_mode(0o777);
    let error = restore_over(&backup, &vault_path, VaultConfig::default()).expect_err("refused");
    assert!(
        format!("{error:#}").contains("another user could move entries"),
        "{error:#}"
    );
    assert!(!lock.exists(), "the vault is never opened");
    let names: Vec<_> = std::fs::read_dir(&parent)
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect();
    assert_eq!(names, ["vault"], "nothing is made beside it");
    // A rehearsal reads the vault there and goes ahead, naming the directory:
    // the vault opens and writes there as it is (Engine ruling on review r5).
    let source = SideRestoreSource::read(&vault_path).unwrap();
    let rehearsal =
        rehearse_in(root.path(), &backup, VaultConfig::default(), None, &source).unwrap();
    let warning = rehearsal.shared_path.expect("the directory is reported");
    assert_eq!(warning.directory, parent.canonicalize().unwrap());
    assert!(warning.fix.contains("chmod go-w"), "{}", warning.fix);
    set_mode(0o755);
    restore_over(&backup, &vault_path, VaultConfig::default()).expect("restore");
}
