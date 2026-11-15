//! A secret this device's secure hardware releases only for an auth value
//! (row OCS-OWNER-PIN, the hardware tier).
//!
//! Where the keystore is a TPM, the device PIN key rests in the chip under
//! an auth value the engine derives from the device PIN. The chip compares
//! the value itself and counts the wrong ones; after enough of them it takes
//! none for a while, a right one included. This crate never sees the PIN,
//! and it has no way to check an auth value but to ask the chip.
//!
//! One secret per keystore: a device has one PIN and one PIN key, whatever
//! vaults it holds.

use zeroize::Zeroizing;

use crate::{KeystoreError, Result};

/// The most bytes an auth value has: the digest size of SHA-256, the name
/// algorithm of the TPM tier's sealed objects.
pub const AUTH_VALUE_MAX: usize = 32;

/// Why an auth-bound secret did not open. No secret and no auth value
/// appears in these errors.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum AuthBoundError {
    /// The auth value is not the one the secret was sealed under. The
    /// hardware compared it and counted the try.
    #[error("the auth value is not the sealed secret's")]
    WrongAuth,
    /// The hardware takes no auth value now, a right one included: it
    /// counted too many wrong ones, for this secret or for anything else it
    /// guards the same way. `wait_secs` is how long until it takes one
    /// more, at most, while the device stays on: the hardware's own figure
    /// where it gives one, else [`crate::DEVICE_PIN_WAIT_SECS`].
    #[error("the secure hardware takes no auth value for up to {wait_secs} s")]
    LockedOut {
        /// Seconds until the hardware takes one more auth value, at most.
        wait_secs: u64,
    },
    /// Any other failure, as the keystore's own error.
    #[error(transparent)]
    Keystore(#[from] KeystoreError),
}

/// One 32-byte secret that this device's secure hardware releases only for
/// the auth value it was sealed under, and whose wrong tries the hardware
/// counts. A keystore that has one hands it out through
/// [`crate::DeviceKeystore::auth_bound_secret`]. Its methods carry
/// `auth_bound` in their names, so a keystore that is also a home for slots
/// and for sealed bytes never has two methods of one name.
pub trait AuthBoundSecretStore: Send + Sync + 'static {
    /// Whether a secret rests here. It asks the hardware nothing and spends
    /// no try.
    fn holds_auth_bound(&self) -> Result<bool>;
    /// Seals `secret` under `auth`, in place of any secret here, in one
    /// step: a reader finds the old secret or the new one, never none where
    /// one was. A new auth value for the same secret is a second call with
    /// that secret; the hardware is never asked to change an auth value in
    /// place.
    ///
    /// # Errors
    /// [`KeystoreError::Unsupported`], with nothing sealed or written, when
    /// `auth` is empty, longer than [`AUTH_VALUE_MAX`], or zeros only (the
    /// hardware drops trailing zeros, so that value is its empty one).
    fn put_auth_bound(&self, auth: &[u8], secret: &[u8; 32]) -> Result<()>;
    /// The secret, when `auth` is the value it was sealed under. `None`
    /// when no secret rests here.
    ///
    /// # Errors
    /// - [`AuthBoundError::WrongAuth`] for another value: the hardware
    ///   counted the try.
    /// - [`AuthBoundError::LockedOut`] while the hardware takes none.
    /// - [`KeystoreError::Unsupported`], with the hardware not asked, for an
    ///   auth value [`Self::put_auth_bound`] refuses.
    fn open_auth_bound(
        &self,
        auth: &[u8],
    ) -> std::result::Result<Option<Zeroizing<[u8; 32]>>, AuthBoundError>;
    /// Removes the secret. None here is not an error. It takes no auth
    /// value: removing only loses.
    fn delete_auth_bound(&self) -> Result<()>;
}

/// Refuses an auth value no hardware holds as given: an empty one, one
/// longer than [`AUTH_VALUE_MAX`], and one of zeros only.
#[cfg(any(
    target_os = "linux",
    test,
    feature = "test-keystore",
    oneiron_test_support
))]
pub(crate) fn check_auth_value(auth: &[u8]) -> Result<()> {
    if auth.is_empty() || auth.len() > AUTH_VALUE_MAX {
        return Err(KeystoreError::Unsupported("an auth value is 1 to 32 bytes"));
    }
    if auth.iter().all(|byte| *byte == 0) {
        return Err(KeystoreError::Unsupported(
            "an auth value of zeros only is the empty one",
        ));
    }
    Ok(())
}

/// `auth` as the hardware compares it: without its trailing zero bytes.
#[cfg(any(test, feature = "test-keystore", oneiron_test_support))]
pub(crate) fn without_trailing_zeros(auth: &[u8]) -> &[u8] {
    let len = auth
        .iter()
        .rposition(|byte| *byte != 0)
        .map_or(0, |last| last + 1);
    &auth[..len]
}
