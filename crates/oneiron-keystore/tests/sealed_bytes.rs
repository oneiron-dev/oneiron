//! Row OCS-OWNER-PIN, the keystore's home for bytes the caller sealed: each
//! name keeps its own value, a put replaces the value whole, a value out of
//! bounds is refused with nothing written, and a keystore that names no
//! home has none.
//!
//! The file tier: one private file per name beside the slot files, which no
//! slot reads and which reads no slot; no temporary file is left behind; a
//! file open to others, an empty one and one past the cap are refused.
//!
//! The Windows tier, which only a Windows box runs: one file per name beside
//! the slot files, sealed by DPAPI; a slot's file and a sealed value's file
//! do not open as each other, nor one value's file under another's name; a
//! file this home did not write is refused.
//!
//! The two Apple tiers, which only an Apple device runs: both name a home,
//! and a value out of bounds is refused before the keychain is asked. The
//! cases that reach the keychain (one item per name beside the slot items; a
//! slot and the sealed value under its name do not read each other; the
//! hardware tier's values rest apart from the platform tier's) are ignored
//! by default, because the data-protection keychain answers only a signed
//! build with a keychain access group.

use oneiron_keystore::{
    DeviceKeystore, KeystoreError, KeystoreLocality, KeystoreSlot, MemoryKeystore,
    SEALED_BYTES_MAX, SealedBytesName, SealedBytesStore, SlotKind,
};
use zeroize::Zeroizing;

/// The owner signing slot of the vault whose id is all `vault`.
fn owner_slot(vault: u8) -> KeystoreSlot {
    KeystoreSlot {
        vault_id: [vault; 32],
        install: [3; 16],
        kind: SlotKind::OwnerSigning,
    }
}

/// Put, get, replace and delete under three names, on any home.
fn each_name_keeps_its_own_value(home: &dyn SealedBytesStore) {
    let device = SealedBytesName::DevicePinKey;
    let first = SealedBytesName::Slot(owner_slot(7));
    let second = SealedBytesName::Slot(owner_slot(8));
    for name in [&device, &first, &second] {
        assert_eq!(
            home.get_sealed(name),
            Ok(None),
            "an empty home held a value"
        );
    }

    home.put_sealed(&device, b"device pin key, sealed")
        .expect("the device PIN key is kept");
    home.put_sealed(&first, b"first owner seed, sealed")
        .expect("the first seed is kept");
    assert_eq!(
        home.get_sealed(&device),
        Ok(Some(b"device pin key, sealed".to_vec()))
    );
    assert_eq!(
        home.get_sealed(&first),
        Ok(Some(b"first owner seed, sealed".to_vec()))
    );
    assert_eq!(
        home.get_sealed(&second),
        Ok(None),
        "one slot's name read another's"
    );

    // A put replaces the value whole, a longer one by a shorter one too.
    home.put_sealed(&first, b"resealed")
        .expect("the seed is replaced");
    assert_eq!(home.get_sealed(&first), Ok(Some(b"resealed".to_vec())));
    assert_eq!(
        home.get_sealed(&device),
        Ok(Some(b"device pin key, sealed".to_vec())),
        "a put under one name changed another"
    );

    let longest = vec![0xA5; SEALED_BYTES_MAX];
    home.put_sealed(&second, &longest)
        .expect("a value at the cap is kept");
    assert_eq!(home.get_sealed(&second), Ok(Some(longest)));

    home.delete_sealed(&first).expect("the seed is removed");
    home.delete_sealed(&first)
        .expect("removing none is not an error");
    assert_eq!(home.get_sealed(&first), Ok(None));
    assert_eq!(
        home.get_sealed(&device),
        Ok(Some(b"device pin key, sealed".to_vec())),
        "a delete under one name removed another"
    );
    home.delete_sealed(&device)
        .expect("the device PIN key is removed");
    home.delete_sealed(&second)
        .expect("the second seed is removed");
}

/// An empty value and one past the cap are refused, and what was kept
/// before stays.
fn a_value_out_of_bounds_is_refused(home: &dyn SealedBytesStore) {
    let name = SealedBytesName::DevicePinKey;
    let too_long = vec![0x5A; SEALED_BYTES_MAX + 1];
    for refused in [&[][..], &too_long[..]] {
        assert!(
            matches!(
                home.put_sealed(&name, refused),
                Err(KeystoreError::Unsupported(_))
            ),
            "a value of {} bytes was kept",
            refused.len()
        );
        assert_eq!(
            home.get_sealed(&name),
            Ok(None),
            "a refused value was written"
        );
    }
    home.put_sealed(&name, b"kept")
        .expect("a value in bounds is kept");
    assert!(matches!(
        home.put_sealed(&name, &too_long),
        Err(KeystoreError::Unsupported(_))
    ));
    assert_eq!(
        home.get_sealed(&name),
        Ok(Some(b"kept".to_vec())),
        "a refused value replaced the one kept before"
    );
    home.delete_sealed(&name).expect("the value is removed");
}

#[test]
fn the_memory_tier_keeps_each_sealed_value_under_its_own_name() {
    let keys = MemoryKeystore::new();
    let home = keys
        .sealed_bytes()
        .expect("the memory tier has a home for sealed bytes");
    each_name_keeps_its_own_value(home);
    a_value_out_of_bounds_is_refused(home);

    // A slot and the sealed value under its name do not read each other.
    let slot = owner_slot(7);
    keys.create(&slot, &[1; 32]).expect("the slot is filled");
    assert_eq!(home.get_sealed(&SealedBytesName::Slot(slot)), Ok(None));
    home.put_sealed(&SealedBytesName::Slot(slot), b"sealed")
        .expect("the sealed value is kept");
    keys.delete(&slot).expect("the slot is emptied");
    assert_eq!(
        home.get_sealed(&SealedBytesName::Slot(slot)),
        Ok(Some(b"sealed".to_vec()))
    );
}

/// A keystore that keeps slots only.
struct SlotsOnly;

impl DeviceKeystore for SlotsOnly {
    fn get(&self, _slot: &KeystoreSlot) -> oneiron_keystore::Result<Option<Zeroizing<[u8; 32]>>> {
        Ok(None)
    }

    fn create(&self, _slot: &KeystoreSlot, _secret: &[u8; 32]) -> oneiron_keystore::Result<()> {
        Ok(())
    }

    fn delete(&self, _slot: &KeystoreSlot) -> oneiron_keystore::Result<()> {
        Ok(())
    }

    fn locality(&self) -> KeystoreLocality {
        KeystoreLocality::ProcessOnly
    }
}

#[test]
fn a_keystore_that_names_no_home_for_sealed_bytes_has_none() {
    assert!(SlotsOnly.sealed_bytes().is_none());
}

#[test]
fn the_device_pin_key_and_a_slot_never_share_a_name() {
    assert_eq!(SealedBytesName::DevicePinKey.name(), "device-pin-key");
    let slot = owner_slot(7);
    assert_eq!(SealedBytesName::Slot(slot).name(), slot.name());
    assert_ne!(
        SealedBytesName::Slot(slot).name(),
        SealedBytesName::DevicePinKey.name()
    );
}

/// The names of the files in a key directory, sorted.
#[cfg(any(all(unix, not(target_vendor = "apple")), windows))]
fn file_names(dir: &std::path::Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .expect("the key directory lists")
        .map(|entry| {
            entry
                .expect("a directory entry")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .collect();
    names.sort();
    names
}

#[cfg(all(unix, not(target_vendor = "apple")))]
mod file_tier {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};

    use oneiron_keystore::{
        DeviceKeystore, KeystoreError, LocalFileKeystore, SEALED_BYTES_MAX, SealedBytesName,
    };

    use super::{
        a_value_out_of_bounds_is_refused, each_name_keeps_its_own_value, file_names, owner_slot,
    };

    /// A file keystore in a new directory, and that directory.
    fn file_keystore(root: &Path) -> (LocalFileKeystore, PathBuf) {
        let dir = root.join("keys");
        let keys = LocalFileKeystore::open(&dir, &[]).expect("the key directory opens");
        (keys, dir)
    }

    fn sealed_file(dir: &Path, name: &SealedBytesName) -> PathBuf {
        dir.join(format!("{}.sealed", name.name()))
    }

    #[test]
    fn the_file_tier_keeps_each_sealed_value_in_a_private_file_of_its_own() {
        let root = tempfile::tempdir().expect("a temporary directory");
        let (keys, dir) = file_keystore(root.path());
        let home = keys
            .sealed_bytes()
            .expect("the file tier has a home for sealed bytes");
        each_name_keeps_its_own_value(home);
        a_value_out_of_bounds_is_refused(home);
        assert_eq!(
            file_names(&dir),
            ["CACHEDIR.TAG"],
            "the home left a file behind after every value was removed"
        );

        let device = SealedBytesName::DevicePinKey;
        home.put_sealed(&device, b"device pin key, sealed")
            .expect("the device PIN key is kept");
        home.put_sealed(&device, b"device pin key, resealed")
            .expect("the device PIN key is replaced");
        assert_eq!(
            file_names(&dir),
            ["CACHEDIR.TAG", "device-pin-key.sealed"],
            "a put left a temporary file, or named its file otherwise"
        );
        let mode = fs::metadata(sealed_file(&dir, &device))
            .expect("the sealed file")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600, "the sealed file is open to others");
        assert_eq!(
            fs::read(sealed_file(&dir, &device)).expect("the sealed file reads"),
            b"device pin key, resealed",
            "the file holds other bytes than the caller sealed"
        );
    }

    #[test]
    fn a_slot_and_the_sealed_value_under_its_name_do_not_read_each_other() {
        let root = tempfile::tempdir().expect("a temporary directory");
        let (keys, dir) = file_keystore(root.path());
        let home = keys.sealed_bytes().expect("the file tier's home");
        let slot = owner_slot(7);
        let name = SealedBytesName::Slot(slot);

        keys.create(&slot, &[1; 32]).expect("the slot is filled");
        assert_eq!(
            home.get_sealed(&name),
            Ok(None),
            "a slot read as a sealed value"
        );
        home.put_sealed(&name, b"owner seed, sealed")
            .expect("the sealed value is kept");
        assert_eq!(
            keys.get(&slot).expect("the slot reads").as_deref(),
            Some(&[1; 32]),
            "a sealed value changed the slot under its name"
        );

        keys.delete(&slot).expect("the slot is emptied");
        assert_eq!(keys.get(&slot).expect("the slot reads"), None);
        assert_eq!(
            home.get_sealed(&name),
            Ok(Some(b"owner seed, sealed".to_vec())),
            "emptying a slot removed the sealed value under its name"
        );
        assert_eq!(
            file_names(&dir),
            [format!("{}.sealed", slot.name()), "CACHEDIR.TAG".to_owned()],
            "the slot's hex name sorts before the tag file"
        );

        home.delete_sealed(&name)
            .expect("the sealed value is removed");
        keys.create(&slot, &[2; 32]).expect("the slot fills again");
        home.delete_sealed(&name)
            .expect("removing none is not an error");
        assert_eq!(
            keys.get(&slot).expect("the slot reads").as_deref(),
            Some(&[2; 32]),
            "removing a sealed value emptied the slot under its name"
        );
    }

    #[test]
    fn a_sealed_file_that_is_open_to_others_empty_or_past_the_cap_is_refused() {
        let root = tempfile::tempdir().expect("a temporary directory");
        let (keys, dir) = file_keystore(root.path());
        let home = keys.sealed_bytes().expect("the file tier's home");
        let name = SealedBytesName::DevicePinKey;
        let path = sealed_file(&dir, &name);

        home.put_sealed(&name, b"sealed")
            .expect("the value is kept");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o640))
            .expect("the file's mode changes");
        assert!(
            matches!(home.get_sealed(&name), Err(KeystoreError::Corrupt(_))),
            "a sealed file its group can read was read"
        );
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
            .expect("the file's mode changes back");
        assert_eq!(home.get_sealed(&name), Ok(Some(b"sealed".to_vec())));

        // Bytes that did not come through `put_sealed`.
        fs::write(&path, vec![0x5A; SEALED_BYTES_MAX + 1]).expect("the file is written");
        assert!(
            matches!(home.get_sealed(&name), Err(KeystoreError::Corrupt(_))),
            "a sealed file past the cap was read"
        );
        fs::write(&path, b"").expect("the file is emptied");
        assert!(
            matches!(home.get_sealed(&name), Err(KeystoreError::Corrupt(_))),
            "an empty sealed file was read"
        );

        // A put replaces the bad file with a good one.
        home.put_sealed(&name, b"sealed again")
            .expect("the value is kept");
        assert_eq!(home.get_sealed(&name), Ok(Some(b"sealed again".to_vec())));
    }
}

/// The Windows tier. Only a Windows box runs these cases: the cross-target
/// check compiles them (scripts/ci/check_keystore_windows_target.sh).
#[cfg(windows)]
mod windows_tier {
    use std::fs;
    use std::path::{Path, PathBuf};

    use oneiron_keystore::{
        DeviceKeystore, KeystoreError, KeystoreSlot, SEALED_BYTES_MAX, SealedBytesName,
        WindowsDpapiKeystore,
    };

    use super::{
        a_value_out_of_bounds_is_refused, each_name_keeps_its_own_value, file_names, owner_slot,
    };

    /// A DPAPI keystore in a new directory, and that directory.
    fn dpapi_keystore(root: &Path) -> (WindowsDpapiKeystore, PathBuf) {
        let dir = root.join("keys");
        let keys = WindowsDpapiKeystore::open(&dir, &[]).expect("the key directory opens");
        (keys, dir)
    }

    fn sealed_file(dir: &Path, name: &SealedBytesName) -> PathBuf {
        dir.join(format!("{}.sealed", name.name()))
    }

    fn slot_file(dir: &Path, slot: &KeystoreSlot) -> PathBuf {
        dir.join(format!("{}.dpapi", slot.name()))
    }

    #[test]
    fn the_windows_tier_keeps_each_sealed_value_in_a_file_of_its_own_that_dpapi_sealed() {
        let root = tempfile::tempdir().expect("a temporary directory");
        let (keys, dir) = dpapi_keystore(root.path());
        let home = keys
            .sealed_bytes()
            .expect("the Windows tier has a home for sealed bytes");
        each_name_keeps_its_own_value(home);
        a_value_out_of_bounds_is_refused(home);
        assert!(
            file_names(&dir).is_empty(),
            "the home left a file behind after every value was removed"
        );

        let device = SealedBytesName::DevicePinKey;
        home.put_sealed(&device, b"device pin key, sealed")
            .expect("the device PIN key is kept");
        home.put_sealed(&device, b"device pin key, resealed")
            .expect("the device PIN key is replaced");
        assert_eq!(
            file_names(&dir),
            ["device-pin-key.sealed"],
            "a put left a temporary file, or named its file otherwise"
        );
        let on_disk = fs::read(sealed_file(&dir, &device)).expect("the sealed file reads");
        assert!(
            !on_disk
                .windows(b"resealed".len())
                .any(|part| part == b"resealed"),
            "the file holds the caller's bytes outside a DPAPI blob"
        );
    }

    #[test]
    fn a_slot_and_the_sealed_value_under_its_name_do_not_open_as_each_other() {
        let root = tempfile::tempdir().expect("a temporary directory");
        let (keys, dir) = dpapi_keystore(root.path());
        let home = keys.sealed_bytes().expect("the Windows tier's home");
        let slot = owner_slot(7);
        let name = SealedBytesName::Slot(slot);

        keys.create(&slot, &[1; 32]).expect("the slot is filled");
        assert_eq!(
            home.get_sealed(&name),
            Ok(None),
            "a slot read as a sealed value"
        );
        home.put_sealed(&name, b"owner seed, sealed")
            .expect("the sealed value is kept");
        assert_eq!(
            keys.get(&slot).expect("the slot reads").as_deref(),
            Some(&[1; 32]),
            "a sealed value changed the slot under its name"
        );
        assert_eq!(
            file_names(&dir),
            [
                format!("{}.dpapi", slot.name()),
                format!("{}.sealed", slot.name())
            ]
        );

        // Each file under the other's name: DPAPI's entropy tells them apart.
        fs::copy(slot_file(&dir, &slot), sealed_file(&dir, &name))
            .expect("the slot's file is copied");
        assert!(
            matches!(home.get_sealed(&name), Err(KeystoreError::Corrupt(_))),
            "a slot's file opened as a sealed value"
        );
        home.put_sealed(&name, b"owner seed, sealed")
            .expect("a put replaces the file that does not open");
        fs::copy(sealed_file(&dir, &name), slot_file(&dir, &slot))
            .expect("the sealed value's file is copied");
        assert!(
            matches!(keys.get(&slot), Err(KeystoreError::Corrupt(_))),
            "a sealed value's file opened as a slot"
        );

        keys.delete(&slot).expect("the slot is emptied");
        assert_eq!(keys.get(&slot).expect("the slot reads"), None);
        assert_eq!(
            home.get_sealed(&name),
            Ok(Some(b"owner seed, sealed".to_vec())),
            "emptying a slot removed the sealed value under its name"
        );
        home.delete_sealed(&name)
            .expect("the sealed value is removed");
        keys.create(&slot, &[2; 32]).expect("the slot fills again");
        home.delete_sealed(&name)
            .expect("removing none is not an error");
        assert_eq!(
            keys.get(&slot).expect("the slot reads").as_deref(),
            Some(&[2; 32]),
            "removing a sealed value emptied the slot under its name"
        );
    }

    #[test]
    fn a_sealed_file_this_home_did_not_write_under_that_name_is_refused() {
        let root = tempfile::tempdir().expect("a temporary directory");
        let (keys, dir) = dpapi_keystore(root.path());
        let home = keys.sealed_bytes().expect("the Windows tier's home");
        let name = SealedBytesName::DevicePinKey;
        let other = SealedBytesName::Slot(owner_slot(7));
        let path = sealed_file(&dir, &name);

        home.put_sealed(&name, b"sealed")
            .expect("the value is kept");
        home.put_sealed(&other, b"another value, sealed")
            .expect("the other value is kept");
        fs::copy(sealed_file(&dir, &other), &path).expect("the other value's file is copied");
        assert!(
            matches!(home.get_sealed(&name), Err(KeystoreError::Corrupt(_))),
            "one value's file opened under another value's name"
        );

        // Bytes that did not come through `put_sealed`.
        fs::write(&path, b"not sealed by DPAPI").expect("the file is written");
        assert!(
            matches!(home.get_sealed(&name), Err(KeystoreError::Corrupt(_))),
            "a file DPAPI did not seal was read"
        );
        fs::write(&path, vec![0x5A; 2 * SEALED_BYTES_MAX + 1]).expect("the file is written");
        assert!(
            matches!(home.get_sealed(&name), Err(KeystoreError::Corrupt(_))),
            "a sealed file past the cap was read"
        );
        fs::write(&path, b"").expect("the file is emptied");
        assert!(
            matches!(home.get_sealed(&name), Err(KeystoreError::Corrupt(_))),
            "an empty sealed file was read"
        );

        // A put replaces the bad file with a good one.
        home.put_sealed(&name, b"sealed again")
            .expect("the value is kept");
        assert_eq!(home.get_sealed(&name), Ok(Some(b"sealed again".to_vec())));
        assert_eq!(
            home.get_sealed(&other),
            Ok(Some(b"another value, sealed".to_vec())),
            "a copy of one value's file changed that value"
        );
    }
}

/// The two Apple tiers. Only an Apple device runs these cases: the
/// cross-target check compiles them
/// (scripts/ci/check_keystore_apple_target.sh). The cases that reach the
/// keychain are ignored by default: the data-protection keychain answers only
/// a signed build with a keychain access group, and a test binary that cargo
/// built has none. Run them from such a build with `--ignored`.
#[cfg(target_vendor = "apple")]
mod apple_tier {
    use oneiron_keystore::{
        AppleKeychain, DeviceKeystore, KeystoreError, SEALED_BYTES_MAX, SealedBytesName,
        SecureEnclaveKeychain,
    };

    use super::{a_value_out_of_bounds_is_refused, each_name_keeps_its_own_value, owner_slot};

    /// A keychain service of one case of one test process: never the service
    /// an install keeps its keys under.
    fn test_service(case: &str) -> String {
        format!("oneiron-keystore-test.{case}.{}", std::process::id())
    }

    /// Removes every item a case kept under its service when the case ends,
    /// also when it fails: the three names the shared cases use, and the one
    /// slot. Removing a slot's item asks for no enclave key.
    struct RemovedAtEnd<'a, K: DeviceKeystore>(&'a K);

    impl<K: DeviceKeystore> Drop for RemovedAtEnd<'_, K> {
        fn drop(&mut self) {
            if let Some(home) = self.0.sealed_bytes() {
                for name in [
                    SealedBytesName::DevicePinKey,
                    SealedBytesName::Slot(owner_slot(7)),
                    SealedBytesName::Slot(owner_slot(8)),
                ] {
                    let _ = home.delete_sealed(&name);
                }
            }
            let _ = self.0.delete(&owner_slot(7));
        }
    }

    /// Runs on every Apple device, in a signed build or not: neither answer
    /// reaches the keychain, and nothing is kept.
    #[test]
    fn both_apple_tiers_name_a_home_that_refuses_a_value_out_of_bounds_before_the_keychain() {
        let service = test_service("bounds");
        let platform = AppleKeychain::new(&service).expect("a keychain service name");
        let hardware = SecureEnclaveKeychain::new(&service).expect("a keychain service name");
        let tiers: [&dyn DeviceKeystore; 2] = [&platform, &hardware];
        let too_long = vec![0x5A; SEALED_BYTES_MAX + 1];
        for keys in tiers {
            let home = keys
                .sealed_bytes()
                .expect("the Apple tier has a home for sealed bytes");
            for refused in [&[][..], &too_long[..]] {
                assert!(
                    matches!(
                        home.put_sealed(&SealedBytesName::DevicePinKey, refused),
                        Err(KeystoreError::Unsupported(_))
                    ),
                    "a value of {} bytes was not refused before the keychain was asked",
                    refused.len()
                );
            }
        }
    }

    #[test]
    #[ignore = "needs a signed build with a keychain access group"]
    fn the_platform_tier_keeps_each_sealed_value_in_a_keychain_item_of_its_own() {
        let keys =
            AppleKeychain::new(&test_service("platform-home")).expect("a keychain service name");
        let _removed = RemovedAtEnd(&keys);
        let home = keys
            .sealed_bytes()
            .expect("the platform tier has a home for sealed bytes");
        each_name_keeps_its_own_value(home);
        a_value_out_of_bounds_is_refused(home);
    }

    #[test]
    #[ignore = "needs a signed build with a keychain access group"]
    fn a_slot_and_the_sealed_value_under_its_name_do_not_read_each_other() {
        let keys =
            AppleKeychain::new(&test_service("slot-and-value")).expect("a keychain service name");
        let _removed = RemovedAtEnd(&keys);
        let home = keys.sealed_bytes().expect("the platform tier's home");
        let slot = owner_slot(7);
        let name = SealedBytesName::Slot(slot);

        keys.create(&slot, &[1; 32]).expect("the slot is filled");
        assert_eq!(
            home.get_sealed(&name),
            Ok(None),
            "a slot read as a sealed value"
        );
        home.put_sealed(&name, b"owner seed, sealed")
            .expect("the sealed value is kept");
        assert_eq!(
            keys.get(&slot).expect("the slot reads").as_deref(),
            Some(&[1; 32]),
            "a sealed value changed the slot under its name"
        );

        keys.delete(&slot).expect("the slot is emptied");
        assert_eq!(keys.get(&slot).expect("the slot reads"), None);
        assert_eq!(
            home.get_sealed(&name),
            Ok(Some(b"owner seed, sealed".to_vec())),
            "emptying a slot removed the sealed value under its name"
        );

        home.delete_sealed(&name)
            .expect("the sealed value is removed");
        keys.create(&slot, &[2; 32]).expect("the slot fills again");
        home.delete_sealed(&name)
            .expect("removing none is not an error");
        assert_eq!(
            keys.get(&slot).expect("the slot reads").as_deref(),
            Some(&[2; 32]),
            "removing a sealed value emptied the slot under its name"
        );
    }

    #[test]
    #[ignore = "needs a signed build with a keychain access group"]
    fn the_hardware_tier_keeps_its_sealed_values_apart_from_the_platform_tier_s() {
        let service = test_service("hardware-home");
        let hardware = SecureEnclaveKeychain::new(&service).expect("a keychain service name");
        let platform = AppleKeychain::new(&service).expect("a keychain service name");
        let _removed_hardware = RemovedAtEnd(&hardware);
        let _removed_platform = RemovedAtEnd(&platform);
        let hardware_home = hardware
            .sealed_bytes()
            .expect("the hardware tier has a home for sealed bytes");
        let platform_home = platform.sealed_bytes().expect("the platform tier's home");
        each_name_keeps_its_own_value(hardware_home);
        a_value_out_of_bounds_is_refused(hardware_home);

        // One name on both tiers of one service: each tier reads its own.
        let name = SealedBytesName::DevicePinKey;
        hardware_home
            .put_sealed(&name, b"kept on the hardware tier")
            .expect("the hardware tier keeps the value");
        assert_eq!(
            platform_home.get_sealed(&name),
            Ok(None),
            "the platform tier read the hardware tier's sealed value"
        );
        platform_home
            .put_sealed(&name, b"kept on the platform tier")
            .expect("the platform tier keeps the value");
        assert_eq!(
            hardware_home.get_sealed(&name),
            Ok(Some(b"kept on the hardware tier".to_vec())),
            "a put on the platform tier changed the hardware tier's sealed value"
        );
        platform_home
            .delete_sealed(&name)
            .expect("the platform tier's value is removed");
        assert_eq!(
            hardware_home.get_sealed(&name),
            Ok(Some(b"kept on the hardware tier".to_vec())),
            "a delete on the platform tier removed the hardware tier's sealed value"
        );
    }
}
