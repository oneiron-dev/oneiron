//! The device PIN key of the TPM tier (row OCS-OWNER-PIN): one sealed object
//! under an auth value that the TPM counts, kept as `device-pin-key.tpm2`.
//! What the TPM does with a wrong auth value and in lockout is in the tier's
//! own module documentation.

use std::fs;
use std::io::ErrorKind;

use zeroize::Zeroizing;

use super::{DEVICE_PIN_KEY, LinuxTpmKeystore, Refusal, io};
use crate::auth_bound::check_auth_value;
use crate::key_dir;
use crate::{AuthBoundError, AuthBoundSecretStore, DEVICE_PIN_WAIT_SECS, Result, SealedBytesName};

impl AuthBoundSecretStore for LinuxTpmKeystore {
    fn holds_auth_bound(&self) -> Result<bool> {
        match fs::symlink_metadata(self.device_pin_key_path()) {
            Ok(_) => Ok(true),
            Err(e) if e.kind() == ErrorKind::NotFound => Ok(false),
            Err(e) => Err(io(e)),
        }
    }

    /// Seals `secret` in the TPM under `auth`, writes a private temporary
    /// file, then renames it into place: one rename, so a reader opens the
    /// old file or the new one, and a crash leaves one of the two whole. A
    /// stale copy of an earlier object, which its own auth value opens, goes
    /// first, and one that stays is an error before anything is sealed.
    fn put_auth_bound(&self, auth: &[u8], secret: &[u8; 32]) -> Result<()> {
        check_auth_value(auth)?;
        let stem = SealedBytesName::DevicePinKey.name();
        key_dir::sweep_temps(self.files.dir(), Some(&stem)).map_err(io)?;
        let sealed = self.seal(&DEVICE_PIN_KEY, auth, secret)?;
        let (tmp, written) = self.files.write_temp(&stem, &sealed);
        let renamed = written.and_then(|()| fs::rename(&tmp.path, self.device_pin_key_path()));
        if renamed.is_err() {
            let _ = fs::remove_file(&tmp.path);
        }
        renamed.map_err(io)?;
        self.sync_dir()
    }

    /// Asks the TPM to unseal the file's object for `auth`. A wrong value is
    /// counted by the TPM; in lockout the wait is the TPM's recovery
    /// interval, or [`DEVICE_PIN_WAIT_SECS`] when it gives none.
    fn open_auth_bound(
        &self,
        auth: &[u8],
    ) -> std::result::Result<Option<Zeroizing<[u8; 32]>>, AuthBoundError> {
        check_auth_value(auth)?;
        let Some(sealed) = self.read_sealed(&DEVICE_PIN_KEY, &self.device_pin_key_path())? else {
            return Ok(None);
        };
        match self.unseal(&DEVICE_PIN_KEY, &sealed, auth) {
            Ok(secret) => Ok(Some(secret)),
            Err(Refusal::WrongAuth) => Err(AuthBoundError::WrongAuth),
            Err(Refusal::Lockout { interval_secs }) => Err(AuthBoundError::LockedOut {
                wait_secs: interval_secs.unwrap_or(DEVICE_PIN_WAIT_SECS),
            }),
            Err(Refusal::Other(error)) => Err(AuthBoundError::Keystore(error)),
        }
    }

    /// Removes the file, and then every stale temporary copy of it, also
    /// when the file is gone already; a copy that stays is an error. The TPM
    /// keeps nothing of the object, so nothing is asked of it.
    fn delete_auth_bound(&self) -> Result<()> {
        match fs::remove_file(self.device_pin_key_path()) {
            Ok(()) => {}
            Err(e) if e.kind() == ErrorKind::NotFound => {}
            Err(e) => return Err(io(e)),
        }
        let stem = SealedBytesName::DevicePinKey.name();
        self.files
            .sync_erase(key_dir::sweep_temps(self.files.dir(), Some(&stem)))
    }
}
