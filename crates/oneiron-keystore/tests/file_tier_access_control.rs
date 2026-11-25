//! The file tier on Apple (MACOS-UNSIGNED-FILE-KEYSTORE): macOS keeps a
//! file's access control list apart from its mode bits, so a 0700 key
//! directory or a 0600 slot file may still let another user read it. A grant
//! to another user on the slot or on the directory is refused, and a slot
//! whose new file would inherit the directory's grant never receives a seed.
//! Only an Apple device runs these tests.
#![cfg(target_vendor = "apple")]
#![allow(
    clippy::disallowed_methods,
    reason = "macOS sets an access control list through chmod +a"
)]

use std::path::Path;
use std::process::Command;

use oneiron_keystore::{DeviceKeystore, KeystoreError, KeystoreSlot, LocalFileKeystore, SlotKind};

fn slot(vault: u8) -> KeystoreSlot {
    KeystoreSlot {
        vault_id: [vault; 32],
        install: [3; 16],
        kind: SlotKind::MachineEncryption,
    }
}

/// `chmod +a <rule> <path>`: one access control entry on `path`.
fn grant(path: &Path, rule: &str) {
    let status = Command::new("/bin/chmod")
        .arg("+a")
        .arg(rule)
        .arg(path)
        .status()
        .expect("chmod runs");
    assert!(status.success(), "chmod +a {rule:?}");
}

#[test]
fn an_access_control_list_on_the_directory_or_a_file_is_refused() {
    let root = tempfile::tempdir().expect("a temporary directory");
    let dir = root.path().join("keys");
    let keys = LocalFileKeystore::open(&dir, &[]).expect("the key directory opens");
    keys.create(&slot(7), &[1; 32]).expect("the slot is filled");
    grant(
        &dir.join(format!("{}.key", slot(7).name())),
        "everyone allow read",
    );
    assert_eq!(
        keys.get(&slot(7)).unwrap_err(),
        KeystoreError::Corrupt("the slot file is open to others through an access control list")
    );
    grant(&dir, "everyone allow list,search,file_inherit");
    assert_eq!(
        LocalFileKeystore::open(&dir, &[]).unwrap_err(),
        KeystoreError::Corrupt(
            "the key directory is open to others through an access control list"
        )
    );
    assert!(
        keys.create(&slot(8), &[2; 32]).is_err(),
        "a new slot file inherited the directory's grant and was filled"
    );
    assert_eq!(keys.get(&slot(8)).expect("the slot reads"), None);
}
