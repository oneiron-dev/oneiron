//! Linux, hardware tier: each slot's secret sealed in this machine's TPM 2.0
//! (OF-168). A slot is a TPM sealed data object made under the owner
//! hierarchy's storage primary key: the standard ECC P-256 storage key,
//! which the TPM derives again from its owner seed at each use and never
//! releases. The object's public and private areas are kept as one 0600
//! file in the key directory (`<slot>.tpm2`, beside the platform tier's
//! `<slot>.key` files, which this tier never reads). The private area is
//! encrypted and integrity-protected by the storage key, and the object is
//! `fixedTPM` and `fixedParent`, so a copy of the file opens in no other
//! TPM: the stored bytes open only here.
//!
//! - The engine talks to the TPM through the kernel's resource manager,
//!   `/dev/tpmrm0`, with its own command client: no TPM software stack is
//!   needed to build or run it. The user needs access to that device (the
//!   `tss` group on most distributions).
//! - Each operation opens the device, derives the storage key, loads or
//!   creates the sealed object, and flushes what it loaded; the resource
//!   manager flushes anything left when the device closes.
//! - Authorization is the empty password, for the owner hierarchy (an owner
//!   password set on this TPM makes the tier unavailable) and for each
//!   slot's object. The slots are `noDA`, so a failed use never counts
//!   toward the TPM's dictionary-attack lockout. The secret crosses the bus
//!   to the TPM unencrypted when it is sealed and unsealed.
//! - Switching tiers reads nothing the other tier wrote: the install starts
//!   empty slots, as a new machine does.
//!
//! The device PIN key (row OCS-OWNER-PIN) is one more sealed object of the
//! same kind, kept as `device-pin-key.tpm2` ([`AuthBoundSecretStore`]):
//! - Its authorization is an auth value the engine derives from the device
//!   PIN, given as the password when it is unsealed. It crosses the bus
//!   unencrypted, as the secrets do.
//! - It is not `noDA`: the TPM counts each wrong auth value toward its
//!   dictionary-attack lockout, across restarts, in the one counter it keeps
//!   for everything it guards that way. A right value does not clear the
//!   count; the TPM forgets one failure each recovery interval.
//! - While the TPM is in lockout it takes no auth value for this object, a
//!   right one included. The slots still open: they are `noDA`.
//! - A new auth value is a new object in place of the old file. The TPM is
//!   never asked to change an object's auth value.
//!
//! The bytes the engine sealed under the device PIN key rest in the same
//! directory, as the platform tier keeps them (`<name>.sealed`,
//! [`SealedBytesStore`]). The engine sealed them; the TPM did not.

use std::fs::{self, File, OpenOptions};
use std::io::{ErrorKind, Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use zeroize::Zeroizing;

use crate::file::LocalFileKeystore;
use crate::{
    AuthBoundSecretStore, DeviceKeystore, KeystoreAssurance, KeystoreError, KeystoreLocality,
    KeystoreSlot, Result, SealedBytesName, SealedBytesStore,
};

use command_client::Tpm;
use wire::Reader;

mod command_client;
mod device_pin_key;
mod wire;

/// The kernel's TPM 2.0 resource manager.
const TPM_DEVICE: &str = "/dev/tpmrm0";

/// The largest command or response a TPM 2.0 exchanges (`MAX_COMMAND_SIZE`
/// and `MAX_RESPONSE_SIZE` of the PC Client platform profile).
const TPM_BUFFER: usize = 4096;

/// A sealed slot file: this tag, then the object's `TPM2B_PUBLIC` and
/// `TPM2B_PRIVATE` as the TPM returned them. The tag's last byte names the
/// storage key template (1: the ECC P-256 storage key below).
const SEALED_TAG: &[u8; 8] = b"OTPM2\x00\x01\x01";

/// The sealed device PIN key's file: the same layout under a tag of its own,
/// so a slot's file is never read as it, nor it as a slot's.
const AUTH_BOUND_TAG: &[u8; 8] = b"OTPM2\x00\x02\x01";

/// The most bytes a sealed file may hold: its tag and two areas, each at
/// most one TPM buffer.
const SEALED_MAX: usize = SEALED_TAG.len() + 2 * TPM_BUFFER;

/// One kind of sealed file: its tag, whether the TPM counts a failed use of
/// its object, and its words in an error.
struct SealedKind {
    tag: &'static [u8; 8],
    /// `TPMA_OBJECT.noDA`: a failed use is not counted toward the lockout.
    no_da: bool,
    open_to_others: &'static str,
    too_long: &'static str,
    unparsed: &'static str,
    foreign: &'static str,
    wrong_size: &'static str,
}

/// A slot's file, `<slot>.tpm2`.
const SLOT: SealedKind = SealedKind {
    tag: SEALED_TAG,
    no_da: true,
    open_to_others: "the slot file is open to others",
    too_long: "the sealed slot is too long",
    unparsed: "the sealed slot does not parse",
    foreign: FOREIGN_SLOT,
    wrong_size: "the sealed slot is not 32 bytes",
};

/// The device PIN key's file, `device-pin-key.tpm2`.
const DEVICE_PIN_KEY: SealedKind = SealedKind {
    tag: AUTH_BOUND_TAG,
    no_da: false,
    open_to_others: "the device PIN key file is open to others",
    too_long: "the sealed device PIN key is too long",
    unparsed: "the sealed device PIN key does not parse",
    foreign: "the sealed device PIN key does not load in this machine's TPM",
    wrong_size: "the sealed device PIN key is not 32 bytes",
};

/// What an object that fails its integrity check is called until its kind
/// is known.
const FOREIGN_SLOT: &str = "the sealed slot does not load in this machine's TPM";

/// Slots sealed in this machine's TPM, their files in one key directory.
#[derive(Debug)]
pub struct LinuxTpmKeystore {
    /// The key directory: its checks, its backup tag and its temporary-file
    /// sweep are the platform tier's own.
    files: LocalFileKeystore,
    endpoint: TpmEndpoint,
}

/// Where the TPM answers.
#[derive(Debug)]
enum TpmEndpoint {
    /// The kernel's resource manager, a character device.
    Device(PathBuf),
    /// A Unix stream socket: a software TPM in a test.
    #[cfg(any(test, feature = "test-keystore", oneiron_test_support))]
    Socket(PathBuf),
}

impl LinuxTpmKeystore {
    /// Opens the key directory as the platform tier does (0700, outside every
    /// vault directory in `vault_dirs`), then proves the TPM answers: its
    /// resource manager opens and its owner hierarchy makes the storage key.
    /// Without one the tier is `Unavailable`, never served by a weaker one.
    pub fn open(dir: &Path, vault_dirs: &[&Path]) -> Result<Self> {
        Self::open_at(
            dir,
            vault_dirs,
            TpmEndpoint::Device(PathBuf::from(TPM_DEVICE)),
        )
    }

    /// As [`Self::open`], with a TPM that answers on the Unix stream socket
    /// at `socket` in place of the kernel's resource manager: a software TPM
    /// in a test. Each operation connects, sends its commands and closes, as
    /// it opens and closes the device. No resource manager stands between,
    /// so the TPM keeps what an operation loaded and did not flush.
    #[cfg(any(test, feature = "test-keystore", oneiron_test_support))]
    pub fn open_on_socket(dir: &Path, vault_dirs: &[&Path], socket: &Path) -> Result<Self> {
        Self::open_at(dir, vault_dirs, TpmEndpoint::Socket(socket.to_path_buf()))
    }

    fn open_at(dir: &Path, vault_dirs: &[&Path], endpoint: TpmEndpoint) -> Result<Self> {
        let files = LocalFileKeystore::open(dir, vault_dirs)?;
        let this = Self { files, endpoint };
        let mut tpm = this.tpm()?;
        let primary = tpm.create_primary().map_err(|error| match error {
            KeystoreError::Denied => {
                KeystoreError::Unavailable("the TPM owner hierarchy refused the empty password")
            }
            error => error,
        })?;
        tpm.flush(primary);
        Ok(this)
    }

    fn path(&self, slot: &KeystoreSlot) -> PathBuf {
        self.files.dir().join(format!("{}.tpm2", slot.name()))
    }

    /// The sealed device PIN key's file: under the name the sealed-bytes
    /// home gives that key, which no slot has.
    fn device_pin_key_path(&self) -> PathBuf {
        self.files
            .dir()
            .join(format!("{}.tpm2", SealedBytesName::DevicePinKey.name()))
    }

    fn tpm(&self) -> Result<Tpm> {
        match &self.endpoint {
            TpmEndpoint::Device(device) => Tpm::on_device(device),
            #[cfg(any(test, feature = "test-keystore", oneiron_test_support))]
            TpmEndpoint::Socket(socket) => Tpm::on_socket(socket),
        }
    }

    /// `secret` sealed in this TPM under `auth`, as a file of `kind`: that
    /// file's bytes. The TPM checks no auth value of the new object here,
    /// only its parent's, so nothing is counted.
    fn seal(&self, kind: &SealedKind, auth: &[u8], secret: &[u8; 32]) -> Result<Vec<u8>> {
        let mut tpm = self.tpm()?;
        let primary = tpm.create_primary()?;
        let created = tpm.create_sealed(primary, kind.no_da, auth, secret);
        tpm.flush(primary);
        let (public, private) = created?;
        let mut sealed = Vec::with_capacity(kind.tag.len() + public.len() + private.len());
        sealed.extend_from_slice(kind.tag);
        sealed.extend_from_slice(&public);
        sealed.extend_from_slice(&private);
        Ok(sealed)
    }

    /// The secret that a file of `kind` holds, unsealed by this TPM for
    /// `auth`. Only the unseal itself answers a wrong auth value or a
    /// lockout: a refusal of the storage key or of the load is the
    /// keystore's own error, never a wrong auth value. Everything loaded is
    /// flushed on every path.
    fn unseal(
        &self,
        kind: &SealedKind,
        sealed: &[u8],
        auth: &[u8],
    ) -> Answered<Zeroizing<[u8; 32]>> {
        let (public, private) = sealed_areas(kind, sealed)?;
        let mut tpm = self.tpm()?;
        let primary = tpm.create_primary()?;
        let loaded = tpm.load(primary, private, public);
        tpm.flush(primary);
        let object = loaded.map_err(|error| match error {
            KeystoreError::Corrupt(_) => KeystoreError::Corrupt(kind.foreign),
            error => error,
        })?;
        let data = tpm.unseal(object, auth);
        tpm.flush(object);
        let data = match data {
            Ok(data) => data,
            // The TPM says how long its lockout lasts on this connection.
            Err(Refusal::Lockout { .. }) => {
                return Err(Refusal::Lockout {
                    interval_secs: tpm.lockout_interval_secs(),
                });
            }
            Err(refusal) => return Err(refusal),
        };
        if data.len() != 32 {
            return Err(KeystoreError::Corrupt(kind.wrong_size).into());
        }
        let mut secret = Zeroizing::new([0u8; 32]);
        secret.copy_from_slice(&data);
        Ok(secret)
    }

    /// The bytes of the file of `kind` at `path`, or `None` when there is
    /// none.
    fn read_sealed(&self, kind: &SealedKind, path: &Path) -> Result<Option<Vec<u8>>> {
        let mut file = match File::open(path) {
            Ok(file) => file,
            Err(e) if e.kind() == ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(io(e)),
        };
        let meta = file.metadata().map_err(io)?;
        if !meta.is_file() || meta.permissions().mode() & 0o077 != 0 {
            return Err(KeystoreError::Corrupt(kind.open_to_others));
        }
        let mut sealed = Vec::new();
        Read::by_ref(&mut file)
            .take(SEALED_MAX as u64 + 1)
            .read_to_end(&mut sealed)
            .map_err(io)?;
        if sealed.len() > SEALED_MAX {
            return Err(KeystoreError::Corrupt(kind.too_long));
        }
        Ok(Some(sealed))
    }

    /// A private temporary file holding `sealed`, beside the file it will
    /// become, named as the platform tier names its own so one sweep clears
    /// both. `stem` is that file's name without its suffix.
    fn write_temp(&self, stem: &str, sealed: &[u8]) -> (PathBuf, std::io::Result<()>) {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        let tmp = self
            .files
            .dir()
            .join(format!(".{stem}.{}.{nanos}.tmp", std::process::id()));
        let written = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp)
            .and_then(|mut file| {
                file.write_all(sealed)?;
                file.sync_all()
            });
        (tmp, written)
    }

    fn sync_dir(&self) -> Result<()> {
        File::open(self.files.dir())
            .and_then(|d| d.sync_all())
            .map_err(io)
    }
}

impl DeviceKeystore for LinuxTpmKeystore {
    fn get(&self, slot: &KeystoreSlot) -> Result<Option<Zeroizing<[u8; 32]>>> {
        match self.read_sealed(&SLOT, &self.path(slot))? {
            Some(sealed) => self
                .unseal(&SLOT, &sealed, &[])
                .map(Some)
                .map_err(KeystoreError::from),
            None => Ok(None),
        }
    }

    /// Seals `secret` in the TPM, writes a private temporary file, then links
    /// it into place. A crash leaves either no slot or a whole one, and the
    /// link never replaces a filled slot.
    fn create(&self, slot: &KeystoreSlot, secret: &[u8; 32]) -> Result<()> {
        self.files.sweep_temps(Some(slot));
        let path = self.path(slot);
        if fs::symlink_metadata(&path).is_ok() {
            return Err(KeystoreError::AlreadyExists);
        }
        let sealed = self.seal(&SLOT, &[], secret)?;
        let (tmp, written) = self.write_temp(&slot.name(), &sealed);
        let linked = written.and_then(|()| fs::hard_link(&tmp, &path));
        let _ = fs::remove_file(&tmp);
        match linked {
            Ok(()) => self.sync_dir(),
            Err(e) if e.kind() == ErrorKind::AlreadyExists => Err(KeystoreError::AlreadyExists),
            Err(e) => Err(io(e)),
        }
    }

    fn delete(&self, slot: &KeystoreSlot) -> Result<()> {
        let removed = fs::remove_file(self.path(slot));
        self.files.sweep_temps(Some(slot));
        match removed {
            Ok(()) => self.sync_dir(),
            Err(e) if e.kind() == ErrorKind::NotFound => Ok(()),
            Err(e) => Err(io(e)),
        }
    }

    /// Seals `secret` in the TPM, writes a private temporary file, then
    /// renames it over the filled slot: one rename, so a reader opens the old
    /// file or the new one, never none. An empty slot is `Ok(false)` and
    /// nothing is sealed or written.
    fn replace(&self, slot: &KeystoreSlot, secret: &[u8; 32]) -> Result<bool> {
        let path = self.path(slot);
        match fs::symlink_metadata(&path) {
            Ok(meta) if meta.is_file() => {}
            Ok(_) => return Err(KeystoreError::Corrupt("the slot is not a file")),
            Err(e) if e.kind() == ErrorKind::NotFound => return Ok(false),
            Err(e) => return Err(io(e)),
        }
        let sealed = self.seal(&SLOT, &[], secret)?;
        let (tmp, written) = self.write_temp(&slot.name(), &sealed);
        let renamed = written.and_then(|()| fs::rename(&tmp, &path));
        if renamed.is_err() {
            let _ = fs::remove_file(&tmp);
        }
        renamed.map_err(io)?;
        self.sync_dir()?;
        Ok(true)
    }

    fn locality(&self) -> KeystoreLocality {
        KeystoreLocality::ThisDeviceOnly
    }

    fn assurance(&self) -> KeystoreAssurance {
        KeystoreAssurance::Hardware
    }

    /// The platform tier's files in the same key directory: the engine
    /// sealed these bytes, the TPM did not.
    fn sealed_bytes(&self) -> Option<&dyn SealedBytesStore> {
        Some(&self.files)
    }

    fn auth_bound_secret(&self) -> Option<&dyn AuthBoundSecretStore> {
        Some(self)
    }
}

/// Why the TPM refused a command, before it is told as a slot's error or as
/// the device PIN key's.
#[derive(Debug, PartialEq, Eq)]
enum Refusal {
    /// The auth value given is not the entity's: `TPM_RC_AUTH_FAIL`, which
    /// the TPM counted, or `TPM_RC_BAD_AUTH`, which it did not.
    WrongAuth,
    /// The TPM is in dictionary-attack lockout. `interval_secs` is its
    /// recovery interval, once it has been asked.
    Lockout { interval_secs: Option<u64> },
    /// Any other failure, as the keystore's error.
    Other(KeystoreError),
}

/// A TPM command's answer, or why the TPM refused it.
type Answered<T> = std::result::Result<T, Refusal>;

impl From<KeystoreError> for Refusal {
    fn from(error: KeystoreError) -> Self {
        Self::Other(error)
    }
}

/// A refusal as a slot's error: an authorization refused or a lockout is
/// `Denied`.
impl From<Refusal> for KeystoreError {
    fn from(refusal: Refusal) -> Self {
        match refusal {
            Refusal::WrongAuth | Refusal::Lockout { .. } => Self::Denied,
            Refusal::Other(error) => error,
        }
    }
}

/// The `TPM2B_PUBLIC` and `TPM2B_PRIVATE` bodies of a sealed file of `kind`,
/// after its tag; nothing may follow them. A file of another kind does not
/// parse.
fn sealed_areas<'s>(kind: &SealedKind, sealed: &'s [u8]) -> Result<(&'s [u8], &'s [u8])> {
    let corrupt = || KeystoreError::Corrupt(kind.unparsed);
    let body = sealed
        .strip_prefix(kind.tag.as_slice())
        .ok_or_else(corrupt)?;
    let mut reader = Reader::new(body);
    let public = reader.sized().ok_or_else(corrupt)?;
    let private = reader.sized().ok_or_else(corrupt)?;
    if !reader.rest().is_empty() {
        return Err(corrupt());
    }
    Ok((public, private))
}

fn io(e: std::io::Error) -> KeystoreError {
    KeystoreError::Platform("io", e.raw_os_error().map_or(-1, i64::from))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_file_of_one_kind_is_not_read_as_the_other() {
        let file = |tag: &[u8; 8]| {
            let mut bytes = tag.to_vec();
            // A public area of one byte, a private area of two.
            bytes.extend_from_slice(&[0x00, 0x01, 0xaa, 0x00, 0x02, 0xbb, 0xcc]);
            bytes
        };
        let slot = file(SEALED_TAG);
        let key = file(AUTH_BOUND_TAG);
        let public: &[u8] = &[0xaa];
        let private: &[u8] = &[0xbb, 0xcc];
        let areas = Ok((public, private));
        assert_eq!(sealed_areas(&SLOT, &slot), areas);
        assert_eq!(sealed_areas(&DEVICE_PIN_KEY, &key), areas);
        assert_eq!(
            sealed_areas(&SLOT, &key),
            Err(KeystoreError::Corrupt("the sealed slot does not parse"))
        );
        assert_eq!(
            sealed_areas(&DEVICE_PIN_KEY, &slot),
            Err(KeystoreError::Corrupt(
                "the sealed device PIN key does not parse"
            ))
        );
        // Bytes after the two areas are not a sealed file.
        let mut longer = key;
        longer.push(0);
        assert_eq!(
            sealed_areas(&DEVICE_PIN_KEY, &longer),
            Err(KeystoreError::Corrupt(
                "the sealed device PIN key does not parse"
            ))
        );
    }
}
