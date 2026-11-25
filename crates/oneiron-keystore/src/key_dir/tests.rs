use super::*;

#[test]
fn a_temporary_files_name_gives_its_stem_and_pid() {
    assert_eq!(
        temp_name_parts(".0707.0303.machine-encryption.41.17.tmp"),
        Some(("0707.0303.machine-encryption", 41))
    );
    assert_eq!(
        temp_name_parts(".device-pin-key.sealed.9.1.tmp"),
        Some(("device-pin-key.sealed", 9))
    );
    for other in [
        "temp-writers.lock",
        "CACHEDIR.TAG",
        "0707.machine-encryption.key",
        ".stem.41.17",
        "stem.41.17.tmp",
        "..41.17.tmp",
        ".a..b.41.17.tmp",
        ".stem.4x.17.tmp",
        ".stem.41..tmp",
        ".stem.41.tmp",
        ".stem.99999999999.17.tmp",
    ] {
        assert_eq!(temp_name_parts(other), None, "{other}");
    }
}

/// A path whose directories do not exist yet resolves part by part:
/// through a link wherever it lies, also one reached past a missing part
/// and a `..`, and with `..` taking back a part not yet made.
#[test]
fn a_path_resolves_as_it_will_once_made() {
    let root = tempfile::tempdir().expect("a temporary directory");
    let base = root.path().canonicalize().expect("the root resolves");
    fs::create_dir(base.join("vault")).expect("the vault directory");
    assert_eq!(
        resolved(&base.join("vault")).expect("an existing path"),
        base.join("vault")
    );
    assert_eq!(
        resolved(&base.join("a/b/../c/./keys")).expect("a missing path"),
        base.join("a/c/keys")
    );
    assert_eq!(
        resolved(&base.join("vault/../absent/..")).expect("a missing path"),
        base
    );
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(base.join("vault"), base.join("link"))
            .expect("a link to the vault");
        assert_eq!(
            resolved(&base.join("link/keys")).expect("a path through a link"),
            base.join("vault/keys")
        );
        assert_eq!(
            resolved(&base.join("gap/../link/keys")).expect("a link past a missing part"),
            base.join("vault/keys")
        );
    }
    // Windows takes `..` by name before any lookup, as joining onto a
    // canonical path already does.
    #[cfg(unix)]
    {
        fs::write(base.join("file"), b"").expect("a file");
        assert!(
            resolved(&base.join("file/../keys")).is_err(),
            "a file has no `..`"
        );
    }
}

/// FIX FILE-KEYSTORE-CREATES-DIR-BEFORE-VAULT-CHECK: a key directory at
/// or inside a vault directory, also one reached through a link or one
/// inside a vault directory not made yet, is refused before anything is
/// made.
#[test]
fn a_key_directory_inside_a_vault_is_refused_before_it_is_made() {
    let root = tempfile::tempdir().expect("a temporary directory");
    let vault = root.path().join("vault");
    fs::create_dir(&vault).expect("the vault directory");
    let later = root.path().join("later-vault");
    let refused = [
        (vault.clone(), &vault),
        (vault.join("keys"), &vault),
        (vault.join("a/b/keys"), &vault),
        (root.path().join("x/../vault/keys"), &vault),
        (later.join("keys"), &later),
    ];
    for (dir, vault_dir) in &refused {
        let made = create_key_dir(dir, &[vault_dir.as_path()], |d| fs::create_dir_all(d));
        assert_eq!(
            made,
            Err(KeystoreError::Unavailable(INSIDE_A_VAULT)),
            "{}",
            dir.display()
        );
    }
    #[cfg(unix)]
    {
        let link = root.path().join("link");
        std::os::unix::fs::symlink(&vault, &link).expect("a link to the vault");
        assert_eq!(
            create_key_dir(&link.join("keys"), &[&vault], |d| fs::create_dir_all(d)),
            Err(KeystoreError::Unavailable(INSIDE_A_VAULT)),
            "a key directory reached through a link"
        );
    }
    assert_eq!(
        fs::read_dir(&vault).expect("the vault lists").count(),
        0,
        "a refused key directory was made inside the vault"
    );
    assert!(!later.exists(), "a refusal made the later vault directory");
    assert!(
        !root.path().join("x").exists(),
        "a refusal made a directory"
    );

    let keys = root.path().join("keys");
    let made = create_key_dir(&keys, &[&vault, &later], |d| fs::create_dir_all(d))
        .expect("a key directory outside every vault");
    assert_eq!(made, keys.canonicalize().expect("the made directory"));
}

/// Review of #10420: a link reached past a missing part and a `..`
/// (`gap/../link/keys`, the link naming the vault directory) is refused
/// before anything is made: neither the missing part nor a directory
/// inside the vault.
#[cfg(unix)]
#[test]
fn a_key_directory_through_a_link_past_a_missing_part_is_refused_before_it_is_made() {
    let root = tempfile::tempdir().expect("a temporary directory");
    let vault = root.path().join("vault");
    fs::create_dir(&vault).expect("the vault directory");
    std::os::unix::fs::symlink(&vault, root.path().join("link")).expect("a link to the vault");
    let dir = root.path().join("gap").join("..").join("link").join("keys");
    assert_eq!(
        create_key_dir(&dir, &[&vault], |d| fs::create_dir_all(d)),
        Err(KeystoreError::Unavailable(INSIDE_A_VAULT))
    );
    assert_eq!(
        fs::read_dir(&vault).expect("the vault lists").count(),
        0,
        "a refused key directory was made inside the vault"
    );
    assert!(
        !root.path().join("gap").exists(),
        "a refusal made a directory"
    );
}

/// Review of #10420: a vault directory reached through a dangling link
/// (one whose target is missing) stands for that target as it will be
/// made, so a key directory inside it is refused before anything is
/// made. Also when the vault directory leaves that target by `..`
/// (`alias/..`, the link naming `store/keys`), which makes it `store` once
/// `store/keys` exists.
#[cfg(unix)]
#[test]
fn a_key_directory_inside_a_vault_behind_a_dangling_link_is_refused_before_it_is_made() {
    let root = tempfile::tempdir().expect("a temporary directory");
    let base = root.path().canonicalize().expect("the root resolves");
    let vault = base.join("vault-link");
    std::os::unix::fs::symlink(base.join("x/y"), &vault).expect("a link to a missing vault");
    assert_eq!(
        create_key_dir(&base.join("x/y/keys"), &[&vault], |d| fs::create_dir_all(d)),
        Err(KeystoreError::Unavailable(INSIDE_A_VAULT))
    );
    assert!(!base.join("x").exists(), "a refusal made a directory");

    fs::create_dir(base.join("store")).expect("a directory");
    std::os::unix::fs::symlink(base.join("store/keys"), base.join("alias"))
        .expect("a link to a missing directory");
    let vault = base.join("alias/..");
    let keys = base.join("store/keys");
    assert_eq!(
        create_key_dir(&keys, &[&vault], |d| fs::create_dir_all(d)),
        Err(KeystoreError::Unavailable(INSIDE_A_VAULT))
    );
    assert!(!keys.exists(), "a refusal made a directory");
}

/// Review of #10420: a vault directory may come to name a directory only
/// once that directory is made, as `vault` names `VAULT` on a volume that
/// ignores case. Here the vault directory's link appears as `x/y` is made.
/// That directory is refused as soon as it exists, nothing is made inside
/// it, and the directories made are removed.
#[cfg(unix)]
#[test]
fn a_directory_that_a_vault_names_once_made_is_refused_and_removed() {
    let root = tempfile::tempdir().expect("a temporary directory");
    let base = root.path().canonicalize().expect("the root resolves");
    let vault = base.join("vault-link");
    let named = base.join("x/y");
    let make = |d: &Path| -> io::Result<()> {
        fs::create_dir_all(d)?;
        if named.exists() && fs::symlink_metadata(&vault).is_err() {
            std::os::unix::fs::symlink(&named, &vault)?;
        }
        Ok(())
    };
    assert_eq!(
        create_key_dir(&base.join("x/y/keys"), &[&vault], make),
        Err(KeystoreError::Unavailable(INSIDE_A_VAULT))
    );
    assert!(
        !base.join("x").exists(),
        "a refusal left a directory it made"
    );
}

/// Review of #10420: a path may pass through a vault directory and leave
/// it by `..`, but a directory it would make inside the vault directory on
/// the way is refused before it is made. Unix only: Windows takes `..` by
/// name before any lookup, so it makes nothing on the way.
#[cfg(unix)]
#[test]
fn a_path_through_a_vault_makes_nothing_inside_it() {
    let root = tempfile::tempdir().expect("a temporary directory");
    let base = root.path().canonicalize().expect("the root resolves");
    let vault = base.join("vault");
    fs::create_dir(&vault).expect("the vault directory");
    assert_eq!(
        create_key_dir(&vault.join("a/../../keys"), &[&vault], |d| {
            fs::create_dir_all(d)
        }),
        Err(KeystoreError::Unavailable(INSIDE_A_VAULT))
    );
    assert_eq!(
        fs::read_dir(&vault).expect("the vault lists").count(),
        0,
        "a directory was made inside the vault"
    );
    assert!(!base.join("keys").exists(), "a refusal made a directory");
    assert_eq!(
        create_key_dir(&vault.join("../keys"), &[&vault], |d| fs::create_dir_all(d)),
        Ok(base.join("keys"))
    );
}

/// Review of #10420: a stale file the sweep cannot remove is reported,
/// and the sweep still removes every other one.
#[test]
fn a_sweep_reports_a_stale_file_it_could_not_remove() {
    let root = tempfile::tempdir().expect("a temporary directory");
    let dir = root.path();
    // A pid no process has: above every Unix pid limit, and every
    // Windows pid is a multiple of four.
    let stuck = dir.join(".slot.4294967295.1.tmp");
    fs::create_dir(&stuck).expect("a directory under a temporary file's name");
    fs::write(stuck.join("inner"), [2; 32]).expect("a file inside it");
    let stale = dir.join(".slot.4294967295.2.tmp");
    fs::write(&stale, [2; 32]).expect("a stale file");
    assert!(
        sweep_temps(dir, Some("slot")).is_err(),
        "the sweep reported no failure"
    );
    assert!(!stale.exists(), "the sweep stopped at the failure");
}

/// While one writer holds the directory, the open-time sweep keeps every
/// temporary file; once the hold ends, a sweep removes another process's
/// stale file and leaves every other file.
#[test]
fn a_sweep_removes_stale_temporary_files_only_while_no_writer_holds_the_directory() {
    let root = tempfile::tempdir().expect("a temporary directory");
    let dir = root.path();
    let (writing, written) = write_temp(dir, "slot", &[1; 32], None, |_| Ok(()));
    written.expect("the temporary file is written");
    // A pid no process has, so the open-time sweep never takes it for
    // this process's own.
    let stale = dir.join(".slot.4294967295.1.tmp");
    let other = dir.join(".other.sealed.4294967295.1.tmp");
    let kept = dir.join("slot.key");
    for path in [&stale, &other, &kept] {
        fs::write(path, [2; 32]).expect("a file is written");
    }
    sweep_temps(dir, None).expect("the open-time sweep");
    assert!(stale.exists() && other.exists(), "a sweep did not wait");
    fs::remove_file(&writing.path).expect("the writer removes its file");
    drop(writing);
    sweep_temps(dir, Some("slot")).expect("the stem's sweep");
    assert!(!stale.exists(), "the stem's sweep kept a stale file");
    assert!(
        other.exists(),
        "the stem's sweep removed another stem's file"
    );
    sweep_temps(dir, None).expect("the open-time sweep");
    assert!(!other.exists(), "the open-time sweep kept a stale file");
    assert!(
        kept.exists(),
        "a sweep removed a file that is not temporary"
    );
}

/// `refuse_new` stops the write before the bytes reach the file.
#[test]
fn a_refused_temporary_file_gets_no_bytes() {
    let root = tempfile::tempdir().expect("a temporary directory");
    let (tmp, written) = write_temp(root.path(), "slot", &[1; 32], None, |_| {
        Err(io::Error::from(ErrorKind::PermissionDenied))
    });
    assert_eq!(
        written.map_err(|e| e.kind()),
        Err(ErrorKind::PermissionDenied)
    );
    assert_eq!(fs::read(&tmp.path).expect("the file was made"), b"");
}

/// Review of #10420, round 2: the vault check compares directories, not
/// only their spellings. A path that names a vault directory under
/// another spelling, which its canonical path keeps (`VAULT` for `vault`
/// on a Linux volume that ignores case), is refused. A link stands for
/// that spelling here, since the check takes the path as given.
#[cfg(unix)]
#[test]
fn the_vault_check_compares_directories_not_only_their_spellings() {
    let root = tempfile::tempdir().expect("a temporary directory");
    let base = root.path().canonicalize().expect("the root resolves");
    let vault = base.join("vault");
    fs::create_dir(&vault).expect("the vault directory");
    let alias = base.join("alias");
    std::os::unix::fs::symlink(&vault, &alias).expect("another name for the vault");
    for dir in [
        alias.clone(),
        alias.join("keys"),
        alias.join("a").join("keys"),
    ] {
        assert_eq!(
            refuse_inside_vaults(&dir, &[&vault]),
            Err(KeystoreError::Unavailable(INSIDE_A_VAULT)),
            "{}",
            dir.display()
        );
    }
    assert_eq!(refuse_inside_vaults(&base.join("keys"), &[&vault]), Ok(()));
}

/// Review of #10420, round 2: where the volume ignores case, `VAULT/keys`
/// lies inside the vault directory `vault` as soon as `VAULT` is made,
/// whatever spelling the system's canonical path keeps. It is refused,
/// and the directory made is removed. A volume that keeps case apart
/// (most Linux ones) has nothing to show, and the test checks nothing there.
#[test]
fn a_key_directory_under_another_case_of_a_vault_is_refused_where_the_volume_ignores_case() {
    let root = tempfile::tempdir().expect("a temporary directory");
    let base = root.path().canonicalize().expect("the root resolves");
    fs::create_dir(base.join("probe")).expect("a directory");
    if !base.join("PROBE").exists() {
        // The temporary volume keeps case apart: nothing to show here.
        return;
    }
    let vault = base.join("vault");
    assert_eq!(
        create_key_dir(&base.join("VAULT").join("keys"), &[&vault], |d| {
            fs::create_dir(d)
        }),
        Err(KeystoreError::Unavailable(INSIDE_A_VAULT))
    );
    assert!(!vault.exists(), "a refusal left the directory it made");
}

/// Review of #10420, round 2: a write over an old value keeps its sweep's
/// exclusive hold until its new file is in place, so no other writer
/// takes its shared hold, and writes a copy, in between.
#[test]
fn a_write_over_an_old_value_keeps_its_sweeps_hold_until_its_file_is_in_place() {
    let root = tempfile::tempdir().expect("a temporary directory");
    let dir = root.path();
    let writer_holds = || {
        OpenOptions::new()
            .read(true)
            .write(true)
            .open(dir.join(TEMP_WRITERS_LOCK))
            .expect("the lock file opens")
            .try_lock_shared()
            .is_ok()
    };
    let stale = dir.join(".slot.4294967295.1.tmp");
    fs::write(&stale, [2; 32]).expect("a stale file");
    let swept = sweep_and_hold(dir, "slot").expect("the stem's sweep");
    assert!(!stale.exists(), "the sweep kept a stale file");
    assert!(!writer_holds(), "a writer took its hold after the sweep");
    let (tmp, written) = write_temp(dir, "slot", &[1; 32], Some(swept), |_| Ok(()));
    written.expect("the temporary file is written");
    assert!(!writer_holds(), "a writer took its hold during the write");
    fs::rename(&tmp.path, dir.join("slot.key")).expect("the file goes in place");
    assert!(
        !writer_holds(),
        "a writer took its hold before the hold ended"
    );
    drop(tmp);
    assert!(writer_holds(), "the hold outlived the write");
}

/// Review of #10420, round 2 (Sol read of the fix): a vault directory is
/// compared as a directory also as it resolves, so one named past a
/// missing part and a `..` (`gap/../vault`, which the system cannot stat)
/// is still seen under another spelling of the key path.
#[cfg(unix)]
#[test]
fn the_vault_check_compares_a_vault_directory_as_it_resolves() {
    let root = tempfile::tempdir().expect("a temporary directory");
    let base = root.path().canonicalize().expect("the root resolves");
    let vault = base.join("vault");
    fs::create_dir(&vault).expect("the vault directory");
    let alias = base.join("alias");
    std::os::unix::fs::symlink(&vault, &alias).expect("another name for the vault");
    let named = base.join("gap").join("..").join("vault");
    assert_eq!(
        refuse_inside_vaults(&alias.join("keys"), &[&named]),
        Err(KeystoreError::Unavailable(INSIDE_A_VAULT))
    );
}

/// Review of #10420, round 2 (Sol read of the fix): a write handed a
/// sweep's hold that holds nothing, as one whose key directory was gone,
/// takes its own shared hold, so a sweep of a key directory made since
/// cannot run beside it.
#[test]
fn a_write_after_a_sweep_that_holds_nothing_takes_its_own_hold() {
    let root = tempfile::tempdir().expect("a temporary directory");
    let dir = root.path().join("keys");
    let swept = sweep_and_hold(&dir, "slot").expect("a key directory that is gone");
    fs::create_dir(&dir).expect("the key directory is made again");
    let (tmp, written) = write_temp(&dir, "slot", &[1; 32], Some(swept), |_| Ok(()));
    written.expect("the temporary file is written");
    // The lock file as a sweep opens it, made if no writer made it.
    let sweep_holds = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(dir.join(TEMP_WRITERS_LOCK))
        .expect("the lock file opens")
        .try_lock()
        .is_ok();
    assert!(!sweep_holds, "a sweep took its hold beside a writer");
    fs::remove_file(&tmp.path).expect("the writer removes its file");
}
