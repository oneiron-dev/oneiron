//! The Windows DPAPI tier's key directory: a directory inside a vault
//! directory is refused before it is made (FIX
//! FILE-KEYSTORE-CREATES-DIR-BEFORE-VAULT-CHECK), and a dead writer's
//! temporary file is swept (FIX WINDOWS-KEYSTORE-TEMP-FILES-NEVER-SWEPT).
//! Only a Windows box runs these cases; the cross-target check compiles them.
#![cfg(windows)]

use std::fs::{self, OpenOptions};

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
