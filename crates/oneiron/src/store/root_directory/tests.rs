//! Removing a held directory (ARCH-0038 #restore-path-open: each child's
//! identity is checked inside `remove_held_directory`).

use super::{arm_before_child_directory_unlink, remove_held_directory};
use std::fs::{self, File};

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
    use std::os::unix::fs::PermissionsExt;
    fs::metadata(path).unwrap().permissions().mode() & 0o077
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
