//! Removing a held directory (ARCH-0038 #restore-path-open: each child's
//! identity is checked inside `remove_held_directory`).

use super::{
    arm_after_directory_made, arm_before_child_directory_unlink, make_vault_root_all,
    remove_held_directory,
};
use std::fs::{self, File};
use std::os::unix::fs::PermissionsExt;

#[test]
fn a_child_directory_swapped_before_its_unlink_refuses_the_removal() {
    let base = tempfile::tempdir().unwrap();
    let doomed = base.path().join("doomed");
    fs::create_dir_all(doomed.join("inner")).unwrap();
    fs::write(doomed.join("inner").join("page.bin"), b"rows").unwrap();
    let held = File::open(&doomed).unwrap();
    let moved = base.path().join("inner-moved");
    let (inner, moved_to) = (doomed.join("inner"), moved.clone());
    // Once `inner` is emptied, it moves out and an empty directory that is
    // not the tree's takes its name.
    arm_before_child_directory_unlink(move |name| {
        if name.to_bytes() == b"inner" {
            fs::rename(&inner, &moved_to).unwrap();
            fs::create_dir(&inner).unwrap();
        }
    });

    let removed = remove_held_directory(&doomed, &held);

    assert!(moved.is_dir(), "the hook never moved the emptied directory");
    assert!(
        removed.is_err(),
        "a removal unlinked a directory that took an emptied one's name: {removed:?}"
    );
    assert!(
        doomed.join("inner").is_dir(),
        "the directory that took the emptied one's name was removed"
    );
}

#[test]
fn a_held_tree_is_removed_with_every_directory_in_it() {
    let base = tempfile::tempdir().unwrap();
    let doomed = base.path().join("doomed");
    fs::create_dir_all(doomed.join("outer").join("inner")).unwrap();
    fs::write(doomed.join("outer").join("inner").join("page.bin"), b"rows").unwrap();
    fs::write(doomed.join("top.bin"), b"rows").unwrap();
    std::os::unix::fs::symlink(base.path(), doomed.join("link")).unwrap();
    let held = File::open(&doomed).unwrap();

    remove_held_directory(&doomed, &held).unwrap();

    assert!(!doomed.exists(), "the held directory is still there");
    assert!(
        base.path().is_dir(),
        "the removal followed a link out of the tree"
    );
}

/// The mode bits group or other users hold on `path`, as a restore's
/// shared-path guard reads them.
fn group_or_other_bits(path: &std::path::Path) -> u32 {
    fs::metadata(path).unwrap().permissions().mode() & 0o077
}

/// The owner's mode bits on `path`.
fn owner_bits(path: &std::path::Path) -> u32 {
    fs::metadata(path).unwrap().permissions().mode() & 0o700
}

/// FIX [LIB-RESTORE-INNER-DIRS-UMASK-DEPENDENT]: a vault opened at a new
/// path makes its root, and each directory missing above it, owner-only
/// whatever the umask, so the vault's own restore never refuses its root as
/// shared. Red on main 71fffbfb0699 under any umask that leaves group or
/// other bits (the fleet runs at 000, a login at 022): the root was made by
/// `create_dir_all`.
#[test]
fn a_vault_opened_at_a_new_path_makes_its_root_owner_only() {
    let base = crate::test_support::restore_tempdir();
    let root = base.path().join("above").join("vault");
    let _vault = crate::Vault::open(&root, crate::VaultConfig::device()).unwrap();
    for made in [base.path().join("above"), root.clone()] {
        assert_eq!(
            group_or_other_bits(&made),
            0,
            "{} is not owner-only",
            made.display()
        );
        assert_eq!(
            owner_bits(&made),
            0o700,
            "{} is not open to its owner",
            made.display()
        );
    }
    assert!(
        crate::store::refuse_shared_path(&root).is_ok(),
        "a restore refuses the vault's own new root"
    );
}

/// The process-owned open makes its root by its own call: owner-only too.
#[test]
fn an_owned_open_at_a_new_path_makes_its_root_owner_only() {
    let base = crate::test_support::restore_tempdir();
    let root = base.path().join("owned");
    let _vault = crate::Vault::open_owned(&root, crate::VaultConfig::device()).unwrap();
    assert_eq!(
        group_or_other_bits(&root),
        0,
        "{} is not owner-only",
        root.display()
    );
}

/// All nine permission bits of `path`, or `None` when it cannot be read.
fn permission_bits(path: &std::path::Path) -> Option<u32> {
    fs::metadata(path)
        .ok()
        .map(|metadata| metadata.permissions().mode() & 0o777)
}

/// Review r2 of #9658 (P1 3): a directory that whoever may move entries in
/// the parent puts at the new root's name, between its make and its open,
/// keeps its mode. Red on the round-1 head 3ee0d357be00: it set whatever the
/// name held to 0700.
#[test]
fn a_directory_moved_to_a_new_root_name_before_its_open_keeps_its_mode() {
    let base = crate::test_support::restore_tempdir();
    let shared = base.path().join("shared");
    fs::create_dir(&shared).unwrap();
    fs::set_permissions(&shared, fs::Permissions::from_mode(0o755)).unwrap();
    let root = base.path().join("vault");
    let (moved, to) = (shared.clone(), root.clone());
    arm_after_directory_made(move |_| fs::rename(&moved, &to).unwrap());

    let made = make_vault_root_all(&root);

    assert!(!shared.exists(), "the hook never moved the directory");
    assert!(
        made.is_ok(),
        "a directory at the root's name refused the open: {made:?}"
    );
    assert_eq!(
        permission_bits(&root),
        Some(0o755),
        "the make set a directory it did not make"
    );
}

/// Review r2 of #9658 (P1 2): a new root is made under a parent its owner may
/// write and search but not read, as `mkdir` makes it there. Red on the
/// round-1 head 3ee0d357be00 for any user but root (who reads every
/// directory): it opened the parent for reading.
#[cfg(target_os = "linux")]
#[test]
fn a_vault_root_is_made_under_a_parent_its_owner_may_not_read() {
    let base = crate::test_support::restore_tempdir();
    let parent = base.path().join("write-and-search-only");
    fs::create_dir(&parent).unwrap();
    fs::set_permissions(&parent, fs::Permissions::from_mode(0o300)).unwrap();
    let root = parent.join("vault");

    let made = make_vault_root_all(&root);

    fs::set_permissions(&parent, fs::Permissions::from_mode(0o700)).unwrap();
    assert!(
        made.is_ok(),
        "no root was made under a parent its owner may not read: {made:?}"
    );
    assert_eq!(permission_bits(&root), Some(0o700));
}

/// The root the umask child below makes, handed over by its parent test.
const OWNER_CLOSED_UMASK_ROOT: &str = "ONEIRON_TEST_OWNER_CLOSED_UMASK_ROOT";

/// Child of the test below, in a process of its own because the umask is the
/// whole process's: makes the root it is handed under umask 0700, which takes
/// every owner bit, and prints the result.
#[cfg(target_os = "linux")]
#[test]
fn vault_root_made_under_an_owner_closed_umask_child() {
    let Some(root) = std::env::var_os(OWNER_CLOSED_UMASK_ROOT) else {
        return;
    };
    rustix::process::umask(rustix::fs::Mode::from_raw_mode(0o700));
    let made = make_vault_root_all(std::path::Path::new(&root));
    println!("MADE {made:?}");
}

/// Review r2 of #9658 (P1 1): under a umask that takes the owner's own bits,
/// `mkdir` makes each directory 000; each one is still made exactly 0700
/// before the next is made inside it. Red on the round-1 head 3ee0d357be00
/// for any user but root (who opens every directory): it opened the new
/// directory for reading before it set its mode.
#[cfg(target_os = "linux")]
#[test]
fn a_vault_root_made_under_a_umask_closed_to_its_owner_is_owner_only() {
    let base = crate::test_support::restore_tempdir();
    let above = base.path().join("above");
    let root = above.join("vault");
    let child = std::process::Command::new(std::env::current_exe().expect("test binary"))
        .args([
            "--exact",
            "store::root_directory::tests::vault_root_made_under_an_owner_closed_umask_child",
            "--nocapture",
        ])
        .env(OWNER_CLOSED_UMASK_ROOT, &root)
        .output()
        .expect("run the umask child");
    let stdout = String::from_utf8_lossy(&child.stdout);
    let modes = [permission_bits(&above), permission_bits(&root)];
    // A refused make leaves `above` closed to its owner: open it again so the
    // temporary directory can be removed.
    let _ = fs::set_permissions(&above, fs::Permissions::from_mode(0o700));

    assert!(child.status.success(), "the umask child failed:\n{stdout}");
    assert!(
        stdout.contains("MADE Ok(())"),
        "no root was made under umask 0700:\n{stdout}"
    );
    assert_eq!(
        modes,
        [Some(0o700), Some(0o700)],
        "a directory made under umask 0700 is not exactly 0700"
    );
}
