//! The Windows DPAPI tier's key directory: a directory inside a vault
//! directory is refused before it is made (FIX
//! FILE-KEYSTORE-CREATES-DIR-BEFORE-VAULT-CHECK), and a dead writer's
//! temporary file is swept (FIX WINDOWS-KEYSTORE-TEMP-FILES-NEVER-SWEPT).
//! Only a Windows box runs these cases; the cross-target check compiles them.
#![cfg(windows)]

use std::fs::{self, OpenOptions};
use std::os::windows::fs::OpenOptionsExt;

use oneiron_keystore::{
    DeviceKeystore, KeystoreError, KeystoreSlot, SealedBytesName, SlotKind, WindowsDpapiKeystore,
};

fn slot() -> KeystoreSlot {
    KeystoreSlot {
        vault_id: [7; 32],
        install: [3; 16],
        kind: SlotKind::MachineEncryption,
    }
}

#[test]
fn a_key_directory_refused_inside_a_vault_is_never_made() {
    let root = tempfile::tempdir().expect("a temporary directory");
    let vault = root.path().join("vault");
    fs::create_dir(&vault).expect("the vault directory");
    let later = root.path().join("later-vault");
    for (dir, vault_dir) in [
        (vault.join("keys"), &vault),
        (vault.join("a").join("keys"), &vault),
        (later.join("keys"), &later),
    ] {
        assert_eq!(
            WindowsDpapiKeystore::open(&dir, &[vault_dir.as_path()]).expect_err("refused"),
            KeystoreError::Unavailable("the key directory is inside a vault directory"),
            "{}",
            dir.display()
        );
    }
    assert_eq!(
        fs::read_dir(&vault).expect("the vault lists").count(),
        0,
        "a refused key directory was made inside the vault"
    );
    assert!(
        !later.exists(),
        "a refused key directory made the vault directory"
    );
}

/// Review of #10420: NTFS ignores case, so `VAULT` names the vault directory
/// `vault`, which is not made yet. The key directory under it is refused, and
/// the refusal leaves neither name behind.
#[test]
fn a_key_directory_under_a_vault_named_in_another_case_is_never_made() {
    let root = tempfile::tempdir().expect("a temporary directory");
    // A directory set to tell case apart makes `VAULT` another directory than
    // `vault`, and leaves nothing to refuse.
    fs::create_dir(root.path().join("probe")).expect("a probe directory");
    if !root.path().join("PROBE").exists() {
        return;
    }
    let vault = root.path().join("vault");
    assert_eq!(
        WindowsDpapiKeystore::open(&root.path().join("VAULT").join("keys"), &[&vault])
            .expect_err("refused"),
        KeystoreError::Unavailable("the key directory is inside a vault directory")
    );
    assert!(!vault.exists(), "a refusal left the vault directory made");
}

/// Review of #10420: Windows locks each handle apart, so a dead writer's
/// copy under the pid this process now has is stale too, and the slot's
/// delete removes it.
#[test]
fn delete_removes_a_dead_writers_copy_under_this_process_pid() {
    let root = tempfile::tempdir().expect("a temporary directory");
    let dir = root.path().join("keys");
    let keys = WindowsDpapiKeystore::open(&dir, &[]).expect("the key directory opens");
    keys.create(&slot(), &[1; 32]).expect("the slot is filled");
    let copy = dir.join(format!(".{}.{}.1.tmp", slot().name(), std::process::id()));
    fs::copy(dir.join(format!("{}.dpapi", slot().name())), &copy).expect("the copy");
    keys.delete(&slot()).expect("the slot is emptied");
    assert!(
        !copy.exists(),
        "the dead writer's copy under this process's pid is removed"
    );
}

/// Review of #10420: replacing the slot removes a dead writer's copy of the
/// old slot, so the old key is gone once the new one is in place.
#[test]
fn replace_removes_a_dead_writers_copy_of_the_old_slot() {
    let root = tempfile::tempdir().expect("a temporary directory");
    let dir = root.path().join("keys");
    let keys = WindowsDpapiKeystore::open(&dir, &[]).expect("the key directory opens");
    keys.create(&slot(), &[1; 32]).expect("the slot is filled");
    let copy = dir.join(format!(".{}.1.1.tmp", slot().name()));
    fs::copy(dir.join(format!("{}.dpapi", slot().name())), &copy).expect("the copy");
    assert!(
        keys.replace(&slot(), &[2; 32])
            .expect("the slot is replaced")
    );
    assert!(
        !copy.exists(),
        "the dead writer's copy of the old slot is removed"
    );
}

/// Review of #10420: a stale copy that a reader holds open without sharing
/// its delete stays, and the delete says so; once the reader is gone, the
/// next delete removes it.
#[test]
fn delete_reports_a_copy_a_reader_holds_open() {
    // FILE_SHARE_READ alone: the reader shares no delete.
    const FILE_SHARE_READ: u32 = 0x1;
    let root = tempfile::tempdir().expect("a temporary directory");
    let dir = root.path().join("keys");
    let keys = WindowsDpapiKeystore::open(&dir, &[]).expect("the key directory opens");
    keys.create(&slot(), &[1; 32]).expect("the slot is filled");
    let copy = dir.join(format!(".{}.1.1.tmp", slot().name()));
    fs::copy(dir.join(format!("{}.dpapi", slot().name())), &copy).expect("the copy");
    let reader = OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ)
        .open(&copy)
        .expect("a reader of the copy");
    assert!(
        matches!(keys.delete(&slot()), Err(KeystoreError::Platform("io", _))),
        "a delete that left a copy reported success"
    );
    drop(reader);
    keys.delete(&slot()).expect("the copy is removed");
    assert!(!copy.exists(), "the second delete kept the copy");
}

/// A writer killed between its link and its unlink left a copy of the slot's
/// DPAPI file. The slot's delete removes it, since no writer holds the key
/// directory.
#[test]
fn delete_removes_a_dead_writers_copy_of_the_slot() {
    let root = tempfile::tempdir().expect("a temporary directory");
    let dir = root.path().join("keys");
    let keys = WindowsDpapiKeystore::open(&dir, &[]).expect("the key directory opens");
    keys.create(&slot(), &[1; 32]).expect("the slot is filled");
    let copy = dir.join(format!(".{}.1.1.tmp", slot().name()));
    fs::copy(dir.join(format!("{}.dpapi", slot().name())), &copy).expect("the copy");
    keys.delete(&slot()).expect("the slot is emptied");
    assert!(
        !copy.exists(),
        "the dead writer's copy of the slot is removed"
    );
}

/// The same for a sealed value, at its delete.
#[test]
fn delete_sealed_removes_a_dead_writers_copy_of_the_value() {
    let root = tempfile::tempdir().expect("a temporary directory");
    let dir = root.path().join("keys");
    let keys = WindowsDpapiKeystore::open(&dir, &[]).expect("the key directory opens");
    let home = keys.sealed_bytes().expect("the Windows tier's home");
    let name = SealedBytesName::DevicePinKey;
    home.put_sealed(&name, b"sealed")
        .expect("the value is kept");
    let copy = dir.join(format!(".{}.sealed.1.1.tmp", name.name()));
    fs::copy(dir.join(format!("{}.sealed", name.name())), &copy).expect("the copy");
    home.delete_sealed(&name).expect("the value is removed");
    assert!(
        !copy.exists(),
        "the dead writer's copy of the sealed value is removed"
    );
}

/// The open-time sweep does not wait for a writer in flight: while one holds
/// the key directory's lock file shared, every temporary file stays, and the
/// next open after the hold ends removes a stale one.
#[test]
fn the_open_time_sweep_keeps_every_temporary_file_while_a_writer_holds_the_directory() {
    let root = tempfile::tempdir().expect("a temporary directory");
    let dir = root.path().join("keys");
    WindowsDpapiKeystore::open(&dir, &[]).expect("the key directory opens");
    let stale = dir.join(format!(".{}.1.1.tmp", slot().name()));
    fs::write(&stale, [2; 32]).expect("a stale file");
    let hold = OpenOptions::new()
        .read(true)
        .write(true)
        .open(dir.join("temp-writers.lock"))
        .expect("the open made the lock file");
    hold.lock_shared().expect("a writer's hold");
    WindowsDpapiKeystore::open(&dir, &[]).expect("the key directory opens");
    assert!(
        stale.exists(),
        "a sweep removed a file while a writer held the directory"
    );
    drop(hold);
    WindowsDpapiKeystore::open(&dir, &[]).expect("the key directory opens");
    assert!(
        !stale.exists(),
        "the open after the writer's hold ended kept a stale file"
    );
}
