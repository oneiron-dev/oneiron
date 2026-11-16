//! A this-device-only home for bytes the caller sealed (row OCS-OWNER-PIN).
//!
//! A device with no unlock prompt confirms with a device PIN, and that PIN
//! guards keys: the device PIN key, and under it a slot's secret. The engine
//! seals them. This home keeps the sealed bytes on this device and never
//! sees a key or a PIN. It is a sibling of the 32-byte slots under names of
//! its own, so no tier reads a sealed value as a slot, or a slot as a sealed
//! value.

use crate::{KeystoreSlot, Result};

/// The longest sealed value a home takes, in bytes. The sealed form of a
/// 32-byte secret is a few hundred.
pub const SEALED_BYTES_MAX: usize = 4096;

const DEVICE_PIN_KEY_NAME: &str = "device-pin-key";

/// Which sealed value: its name in the home.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SealedBytesName {
    /// This device's PIN key, sealed under the device PIN. One per device,
    /// whatever vaults it holds.
    DevicePinKey,
    /// One slot's secret, sealed under the device PIN key. The slot itself
    /// stays empty while its secret rests here.
    Slot(KeystoreSlot),
}

impl SealedBytesName {
    /// The backend's name for the value: `device-pin-key`, or the slot's
    /// [`KeystoreSlot::name`], which never equals it. It carries no secret.
    #[must_use]
    pub fn name(&self) -> String {
        match self {
            Self::DevicePinKey => DEVICE_PIN_KEY_NAME.to_owned(),
            Self::Slot(slot) => slot.name(),
        }
    }
}

/// A this-device-only home for bytes the caller sealed. A keystore that has
/// one hands it out through [`crate::DeviceKeystore::sealed_bytes`]. Its
/// methods carry `sealed` in their names, so a keystore that is both homes
/// never has two methods of one name.
pub trait SealedBytesStore: Send + Sync + 'static {
    /// The sealed value under `name`, or `None` when there is none.
    fn get_sealed(&self, name: &SealedBytesName) -> Result<Option<Vec<u8>>>;
    /// Keeps `sealed` under `name`, in place of any value there, in one
    /// step: a reader sees the old value or the new one, never a part of
    /// either, and never none where one was.
    ///
    /// # Errors
    /// [`crate::KeystoreError::Unsupported`], with nothing written, when
    /// `sealed` is empty or longer than [`SEALED_BYTES_MAX`].
    fn put_sealed(&self, name: &SealedBytesName, sealed: &[u8]) -> Result<()>;
    /// Removes the value under `name`. None there is not an error.
    fn delete_sealed(&self, name: &SealedBytesName) -> Result<()>;
}

/// Refuses a value no home keeps: an empty one, and one longer than
/// [`SEALED_BYTES_MAX`].
#[cfg(any(
    all(unix, not(target_vendor = "apple")),
    test,
    feature = "test-keystore",
    oneiron_test_support
))]
pub(crate) fn check_sealed_len(sealed: &[u8]) -> Result<()> {
    if sealed.is_empty() {
        return Err(crate::KeystoreError::Unsupported(
            "an empty sealed value is not kept",
        ));
    }
    if sealed.len() > SEALED_BYTES_MAX {
        return Err(crate::KeystoreError::Unsupported(
            "the sealed value is longer than a home keeps",
        ));
    }
    Ok(())
}
