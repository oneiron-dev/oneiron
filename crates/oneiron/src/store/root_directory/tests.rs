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
