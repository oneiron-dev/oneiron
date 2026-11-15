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

use crate::auth_bound::check_auth_value;
use crate::file::LocalFileKeystore;
use crate::{
    AuthBoundError, AuthBoundSecretStore, DEVICE_PIN_WAIT_SECS, DeviceKeystore, KeystoreAssurance,
    KeystoreError, KeystoreLocality, KeystoreSlot, Result, SealedBytesName, SealedBytesStore,
};

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

const TPM_ST_NO_SESSIONS: u16 = 0x8001;
const TPM_ST_SESSIONS: u16 = 0x8002;

const TPM_CC_CREATE_PRIMARY: u32 = 0x0000_0131;
const TPM_CC_CREATE: u32 = 0x0000_0153;
const TPM_CC_LOAD: u32 = 0x0000_0157;
const TPM_CC_UNSEAL: u32 = 0x0000_015e;
const TPM_CC_FLUSH_CONTEXT: u32 = 0x0000_0165;
const TPM_CC_GET_CAPABILITY: u32 = 0x0000_017a;

/// `TPM_CAP_TPM_PROPERTIES`, and the property that holds the seconds after
/// which the TPM forgets one counted failure (`TPM_PT_LOCKOUT_INTERVAL`).
const TPM_CAP_TPM_PROPERTIES: u32 = 0x0000_0006;
const TPM_PT_LOCKOUT_INTERVAL: u32 = 0x0000_0210;

const TPM_RH_OWNER: u32 = 0x4000_0001;
/// The password authorization session.
const TPM_RS_PW: u32 = 0x4000_0009;
/// `TPMA_SESSION.continueSession`.
const SESSION_CONTINUE: u8 = 0x01;

const TPM_ALG_AES: u16 = 0x0006;
const TPM_ALG_KEYEDHASH: u16 = 0x0008;
const TPM_ALG_SHA256: u16 = 0x000b;
const TPM_ALG_NULL: u16 = 0x0010;
const TPM_ALG_ECC: u16 = 0x0023;
const TPM_ALG_CFB: u16 = 0x0043;
const TPM_ECC_NIST_P256: u16 = 0x0003;

/// `TPMA_OBJECT` bits.
const FIXED_TPM: u32 = 1 << 1;
const FIXED_PARENT: u32 = 1 << 4;
const SENSITIVE_DATA_ORIGIN: u32 = 1 << 5;
const USER_WITH_AUTH: u32 = 1 << 6;
const NO_DA: u32 = 1 << 10;
const RESTRICTED: u32 = 1 << 16;
const DECRYPT: u32 = 1 << 17;

/// Format-one response codes, by their error number with the format bit.
const RC_FMT1: u32 = 0x080;
const RC_AUTH_FAIL: u32 = RC_FMT1 + 0x00e;
const RC_INTEGRITY: u32 = RC_FMT1 + 0x01f;
const RC_BAD_AUTH: u32 = RC_FMT1 + 0x022;
/// The TPM is in dictionary-attack lockout.
const RC_LOCKOUT: u32 = 0x921;

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
    /// old file or the new one, and a crash leaves one of the two whole.
    fn put_auth_bound(&self, auth: &[u8], secret: &[u8; 32]) -> Result<()> {
        check_auth_value(auth)?;
        let sealed = self.seal(&DEVICE_PIN_KEY, auth, secret)?;
        let stem = SealedBytesName::DevicePinKey.name();
        let (tmp, written) = self.write_temp(&stem, &sealed);
        let renamed = written.and_then(|()| fs::rename(&tmp, self.device_pin_key_path()));
        if renamed.is_err() {
            let _ = fs::remove_file(&tmp);
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

    /// Removes the file. The TPM keeps nothing of the object, so nothing is
    /// asked of it.
    fn delete_auth_bound(&self) -> Result<()> {
        match fs::remove_file(self.device_pin_key_path()) {
            Ok(()) => self.sync_dir(),
            Err(e) if e.kind() == ErrorKind::NotFound => Ok(()),
            Err(e) => Err(io(e)),
        }
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

/// One open connection to a TPM.
struct Tpm {
    channel: Channel,
}

/// The byte stream a TPM answers on.
enum Channel {
    /// The kernel's resource manager.
    Device(File),
    /// A software TPM's socket, in a test.
    #[cfg(any(test, feature = "test-keystore", oneiron_test_support))]
    Socket(std::os::unix::net::UnixStream),
}

impl Channel {
    fn send(&mut self, command: &[u8]) -> std::io::Result<()> {
        match self {
            Self::Device(file) => file.write_all(command),
            #[cfg(any(test, feature = "test-keystore", oneiron_test_support))]
            Self::Socket(stream) => stream.write_all(command),
        }
    }

    fn receive(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Self::Device(file) => file.read(buffer),
            #[cfg(any(test, feature = "test-keystore", oneiron_test_support))]
            Self::Socket(stream) => stream.read(buffer),
        }
    }
}

impl Tpm {
    /// A connection to the kernel's resource manager at `device`.
    fn on_device(device: &Path) -> Result<Self> {
        match OpenOptions::new().read(true).write(true).open(device) {
            Ok(file) => Ok(Self {
                channel: Channel::Device(file),
            }),
            Err(e) if e.kind() == ErrorKind::NotFound => Err(KeystoreError::Unavailable(
                "no TPM 2.0 resource manager at /dev/tpmrm0",
            )),
            Err(e) if e.kind() == ErrorKind::PermissionDenied => Err(KeystoreError::Unavailable(
                "this user may not open the TPM resource manager /dev/tpmrm0",
            )),
            Err(e) => Err(io(e)),
        }
    }

    /// A connection to the software TPM that listens at `socket`. A TPM that
    /// stops answering fails the call after a wait instead of holding it.
    #[cfg(any(test, feature = "test-keystore", oneiron_test_support))]
    fn on_socket(socket: &Path) -> Result<Self> {
        let wait = Some(std::time::Duration::from_secs(30));
        let stream = std::os::unix::net::UnixStream::connect(socket).map_err(io)?;
        stream.set_read_timeout(wait).map_err(io)?;
        stream.set_write_timeout(wait).map_err(io)?;
        Ok(Self {
            channel: Channel::Socket(stream),
        })
    }

    /// Sends one command and reads its whole response; a response code other
    /// than success is this command's refusal.
    fn call(&mut self, command: &Command, name: &'static str) -> Answered<Zeroizing<Vec<u8>>> {
        self.channel.send(&command.finish()).map_err(io)?;
        let mut response = Zeroizing::new(vec![0u8; TPM_BUFFER]);
        let mut read = 0;
        // The resource manager answers whole in one read. A socket may
        // answer in parts: read on until the size in the header is here.
        while read < response.len()
            && response_size(&response[..read]).is_none_or(|size| read < size)
        {
            match self.channel.receive(&mut response[read..]).map_err(io)? {
                0 => break,
                part => read += part,
            }
        }
        response.truncate(read);
        let mut header = Reader::new(&response);
        let (Some(_tag), Some(size), Some(code)) = (header.u16(), header.u32(), header.u32())
        else {
            return Err(KeystoreError::Platform(name, -1).into());
        };
        if usize::try_from(size).ok() != Some(response.len()) {
            return Err(KeystoreError::Platform(name, -1).into());
        }
        if code != 0 {
            return Err(response_refusal(name, code));
        }
        Ok(response)
    }

    /// The owner hierarchy's ECC P-256 storage key (the TCG standard storage
    /// key template), made again from the owner seed: the same key each time.
    fn create_primary(&mut self) -> Result<u32> {
        let mut command = Command::new(TPM_ST_SESSIONS, TPM_CC_CREATE_PRIMARY);
        command.u32(TPM_RH_OWNER);
        command.password_session(&[]);
        // inSensitive: no auth value, no data.
        command.sized(&[0, 0, 0, 0]);
        command.sized(&storage_key_template());
        // outsideInfo, creationPCR.
        command.u16(0);
        command.u32(0);
        let response = self.call(&command, "tpm2 create primary")?;
        response_handle(&response, "tpm2 create primary")
    }

    /// `secret` as a sealed data object under `parent`, its auth value
    /// `auth` (empty for a slot): its `TPM2B_PUBLIC` and `TPM2B_PRIVATE`,
    /// each with its size.
    fn create_sealed(
        &mut self,
        parent: u32,
        no_da: bool,
        auth: &[u8],
        secret: &[u8; 32],
    ) -> Result<(Vec<u8>, Vec<u8>)> {
        let command = create_command(parent, no_da, auth, secret);
        let response = self.call(&command, "tpm2 create")?;
        let mut reader = Reader::new(&response);
        let malformed = || KeystoreError::Platform("tpm2 create", -1);
        // The header, then parameterSize.
        reader.skip(10 + 4).ok_or_else(malformed)?;
        let private = reader.sized_raw().ok_or_else(malformed)?.to_vec();
        let public = reader.sized_raw().ok_or_else(malformed)?.to_vec();
        Ok((public, private))
    }

    /// Loads a sealed object's areas under `parent`: its transient handle.
    fn load(&mut self, parent: u32, private: &[u8], public: &[u8]) -> Result<u32> {
        let mut command = Command::new(TPM_ST_SESSIONS, TPM_CC_LOAD);
        command.u32(parent);
        command.password_session(&[]);
        command.sized(private);
        command.sized(public);
        let response = self.call(&command, "tpm2 load")?;
        response_handle(&response, "tpm2 load")
    }

    /// The data a loaded sealed object holds, for its auth value `auth`
    /// (empty for a slot).
    fn unseal(&mut self, object: u32, auth: &[u8]) -> Answered<Zeroizing<Vec<u8>>> {
        let mut command = Command::new(TPM_ST_SESSIONS, TPM_CC_UNSEAL);
        command.u32(object);
        command.password_session(auth);
        let response = self.call(&command, "tpm2 unseal")?;
        let mut reader = Reader::new(&response);
        let malformed = || Refusal::Other(KeystoreError::Platform("tpm2 unseal", -1));
        // The header, then parameterSize.
        reader.skip(10 + 4).ok_or_else(malformed)?;
        let data = reader.sized().ok_or_else(malformed)?;
        Ok(Zeroizing::new(data.to_vec()))
    }

    /// The TPM's recovery interval in seconds: it forgets one counted
    /// failure each interval, so a TPM in lockout takes one more auth value
    /// after at most this long while it stays powered. `None` when the TPM
    /// does not say, or says zero.
    fn lockout_interval_secs(&mut self) -> Option<u64> {
        let response = self
            .call(&lockout_interval_command(), "tpm2 get capability")
            .ok()?;
        lockout_interval_of(&response)
    }

    /// Frees a transient object. A failure leaves it to the resource
    /// manager, which flushes it when the device closes.
    fn flush(&mut self, handle: u32) {
        let mut command = Command::new(TPM_ST_NO_SESSIONS, TPM_CC_FLUSH_CONTEXT);
        command.u32(handle);
        let _ = self.call(&command, "tpm2 flush context");
    }
}

/// The handle a command that makes an object answers with: the first field
/// after the response header.
fn response_handle(response: &[u8], name: &'static str) -> Result<u32> {
    let mut reader = Reader::new(response);
    reader
        .skip(10)
        .and_then(|()| reader.u32())
        .ok_or(KeystoreError::Platform(name, -1))
}

/// A response code as a refusal: an auth value refused, a lockout, an
/// object that fails its integrity check (another TPM's, or altered), which
/// is `Corrupt`, and any other code, which is the TPM's failure by command
/// and code. A format-one code is compared by its error number, whichever
/// handle, session or parameter it names.
fn response_refusal(name: &'static str, code: u32) -> Refusal {
    let format_one = (code & RC_FMT1 != 0).then_some(RC_FMT1 | (code & 0x03f));
    match format_one {
        Some(RC_AUTH_FAIL | RC_BAD_AUTH) => Refusal::WrongAuth,
        Some(RC_INTEGRITY) => Refusal::Other(KeystoreError::Corrupt(FOREIGN_SLOT)),
        _ if code == RC_LOCKOUT => Refusal::Lockout {
            interval_secs: None,
        },
        _ => Refusal::Other(KeystoreError::Platform(name, i64::from(code))),
    }
}

/// The size a response's header gives, once enough of it is read.
fn response_size(read: &[u8]) -> Option<usize> {
    let size = read.get(2..6)?.try_into().ok().map(u32::from_be_bytes)?;
    usize::try_from(size).ok()
}

/// `TPM2_Create` for a sealed data object under `parent` that holds
/// `secret`, with `auth` as its auth value (empty for a slot).
fn create_command(parent: u32, no_da: bool, auth: &[u8], secret: &[u8; 32]) -> Command {
    let mut command = Command::new(TPM_ST_SESSIONS, TPM_CC_CREATE);
    command.u32(parent);
    // The parent's authorization: the storage key has the empty password.
    command.password_session(&[]);
    // inSensitive: the object's auth value, the secret as its data.
    let mut sensitive = Zeroizing::new(Vec::with_capacity(4 + auth.len() + secret.len()));
    push_sized(&mut sensitive, auth);
    push_sized(&mut sensitive, secret);
    command.sized(&sensitive);
    command.sized(&sealed_object_template(no_da));
    // outsideInfo, creationPCR.
    command.u16(0);
    command.u32(0);
    command
}

/// `TPM2_GetCapability` for the one property `TPM_PT_LOCKOUT_INTERVAL`.
fn lockout_interval_command() -> Command {
    let mut command = Command::new(TPM_ST_NO_SESSIONS, TPM_CC_GET_CAPABILITY);
    command.u32(TPM_CAP_TPM_PROPERTIES);
    command.u32(TPM_PT_LOCKOUT_INTERVAL);
    // propertyCount.
    command.u32(1);
    command
}

/// The recovery interval a `TPM2_GetCapability` response holds, in seconds.
/// `None` when its first property is another one, or its value is zero (a
/// TPM whose dictionary-attack protection is off).
fn lockout_interval_of(response: &[u8]) -> Option<u64> {
    let mut reader = Reader::new(response);
    // The header, then moreData.
    reader.skip(10 + 1)?;
    let capability = reader.u32()?;
    let count = reader.u32()?;
    let property = reader.u32()?;
    let value = reader.u32()?;
    let found =
        capability == TPM_CAP_TPM_PROPERTIES && count >= 1 && property == TPM_PT_LOCKOUT_INTERVAL;
    (found && value != 0).then_some(u64::from(value))
}

/// The TCG standard ECC P-256 storage key template (`TPMT_PUBLIC`): a
/// restricted decryption key, AES-128-CFB for its children, its unique field
/// two 32-byte zero coordinates.
fn storage_key_template() -> Vec<u8> {
    let mut public = Vec::with_capacity(90);
    public.extend_from_slice(&TPM_ALG_ECC.to_be_bytes());
    public.extend_from_slice(&TPM_ALG_SHA256.to_be_bytes());
    let attributes = FIXED_TPM
        | FIXED_PARENT
        | SENSITIVE_DATA_ORIGIN
        | USER_WITH_AUTH
        | NO_DA
        | RESTRICTED
        | DECRYPT;
    public.extend_from_slice(&attributes.to_be_bytes());
    // authPolicy: none.
    public.extend_from_slice(&0u16.to_be_bytes());
    // symmetric: AES-128-CFB.
    public.extend_from_slice(&TPM_ALG_AES.to_be_bytes());
    public.extend_from_slice(&128u16.to_be_bytes());
    public.extend_from_slice(&TPM_ALG_CFB.to_be_bytes());
    // scheme, curve, kdf.
    public.extend_from_slice(&TPM_ALG_NULL.to_be_bytes());
    public.extend_from_slice(&TPM_ECC_NIST_P256.to_be_bytes());
    public.extend_from_slice(&TPM_ALG_NULL.to_be_bytes());
    // unique: x and y, 32 zero bytes each.
    for _ in 0..2 {
        public.extend_from_slice(&32u16.to_be_bytes());
        public.extend_from_slice(&[0u8; 32]);
    }
    public
}

/// A sealed data object's template (`TPMT_PUBLIC`): a keyed-hash object
/// with no scheme, neither signing nor decrypting, its data supplied by the
/// caller, fixed to this TPM and its parent, opened by its auth value.
/// `no_da` exempts it from the dictionary-attack count: a slot, whose auth
/// value is empty. Without it the TPM counts each wrong auth value.
fn sealed_object_template(no_da: bool) -> Vec<u8> {
    let mut public = Vec::with_capacity(14);
    public.extend_from_slice(&TPM_ALG_KEYEDHASH.to_be_bytes());
    public.extend_from_slice(&TPM_ALG_SHA256.to_be_bytes());
    let mut attributes = FIXED_TPM | FIXED_PARENT | USER_WITH_AUTH;
    if no_da {
        attributes |= NO_DA;
    }
    public.extend_from_slice(&attributes.to_be_bytes());
    // authPolicy: none.
    public.extend_from_slice(&0u16.to_be_bytes());
    // scheme: none.
    public.extend_from_slice(&TPM_ALG_NULL.to_be_bytes());
    // unique: empty; the TPM fills it.
    public.extend_from_slice(&0u16.to_be_bytes());
    public
}

/// Appends `value` with its 16-bit size before it (a `TPM2B`).
fn push_sized(bytes: &mut Vec<u8>, value: &[u8]) {
    let size = u16::try_from(value.len()).unwrap_or(u16::MAX);
    bytes.extend_from_slice(&size.to_be_bytes());
    bytes.extend_from_slice(value);
}

/// A TPM command's bytes: its header, then its fields in order. The header's
/// size is filled when it is sent. Held zeroized: a create carries the
/// secret, and a create or an unseal may carry an auth value.
struct Command {
    bytes: Zeroizing<Vec<u8>>,
}

impl Command {
    fn new(tag: u16, code: u32) -> Self {
        let mut bytes = Zeroizing::new(Vec::with_capacity(128));
        bytes.extend_from_slice(&tag.to_be_bytes());
        bytes.extend_from_slice(&0u32.to_be_bytes());
        bytes.extend_from_slice(&code.to_be_bytes());
        Self { bytes }
    }

    fn u16(&mut self, value: u16) {
        self.bytes.extend_from_slice(&value.to_be_bytes());
    }

    fn u32(&mut self, value: u32) {
        self.bytes.extend_from_slice(&value.to_be_bytes());
    }

    /// `value` with its 16-bit size before it (a `TPM2B`).
    fn sized(&mut self, value: &[u8]) {
        push_sized(&mut self.bytes, value);
    }

    /// The authorization area of one password session whose password is
    /// `auth`: the handle's authorization for a command with one. Empty for
    /// the owner hierarchy, the storage key and a slot.
    fn password_session(&mut self, auth: &[u8]) {
        // authorizationSize, then TPMS_AUTH_COMMAND: the session handle, an
        // empty nonce, its attributes and the password.
        self.u32(9 + u32::try_from(auth.len()).unwrap_or(u32::MAX));
        self.u32(TPM_RS_PW);
        self.u16(0);
        self.bytes.push(SESSION_CONTINUE);
        self.sized(auth);
    }

    /// The command's bytes with its size in the header.
    fn finish(&self) -> Zeroizing<Vec<u8>> {
        let mut bytes = self.bytes.clone();
        let size = u32::try_from(bytes.len()).unwrap_or(u32::MAX);
        bytes[2..6].copy_from_slice(&size.to_be_bytes());
        bytes
    }
}

/// Reads big-endian fields from a response or a slot file, front to back.
struct Reader<'b> {
    bytes: &'b [u8],
}

impl<'b> Reader<'b> {
    fn new(bytes: &'b [u8]) -> Self {
        Self { bytes }
    }

    fn take(&mut self, len: usize) -> Option<&'b [u8]> {
        if self.bytes.len() < len {
            return None;
        }
        let (head, rest) = self.bytes.split_at(len);
        self.bytes = rest;
        Some(head)
    }

    fn skip(&mut self, len: usize) -> Option<()> {
        self.take(len).map(drop)
    }

    fn u16(&mut self) -> Option<u16> {
        self.take(2)?.try_into().ok().map(u16::from_be_bytes)
    }

    fn u32(&mut self) -> Option<u32> {
        self.take(4)?.try_into().ok().map(u32::from_be_bytes)
    }

    /// A `TPM2B`'s body, its size read first.
    fn sized(&mut self) -> Option<&'b [u8]> {
        let len = self.u16()?;
        self.take(usize::from(len))
    }

    /// A `TPM2B` whole: its size and its body.
    fn sized_raw(&mut self) -> Option<&'b [u8]> {
        let whole = self.bytes;
        let len = usize::from(self.u16()?);
        self.take(len)?;
        whole.get(..2 + len)
    }

    fn rest(&self) -> &'b [u8] {
        self.bytes
    }
}

fn io(e: std::io::Error) -> KeystoreError {
    KeystoreError::Platform("io", e.raw_os_error().map_or(-1, i64::from))
}

#[cfg(test)]
mod tests {
    use super::*;

    const AUTH: [u8; 32] = [0xa5; 32];
    const SECRET: [u8; 32] = [0x5a; 32];

    /// The storage key's authorization in a command: one password session
    /// with the empty password.
    const EMPTY_PASSWORD_SESSION: [u8; 13] = [
        0x00, 0x00, 0x00, 0x09, 0x40, 0x00, 0x00, 0x09, 0x00, 0x00, 0x01, 0x00, 0x00,
    ];

    /// A slot's object is exempt from the TPM's count of wrong auth values,
    /// and the device PIN key's is not: `noDA`, the one bit that differs.
    #[test]
    fn only_a_slots_template_is_exempt_from_the_lockout_count() {
        assert_eq!(
            sealed_object_template(true),
            [
                0x00, 0x08, 0x00, 0x0b, 0x00, 0x00, 0x04, 0x52, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00
            ]
        );
        assert_eq!(
            sealed_object_template(false),
            [
                0x00, 0x08, 0x00, 0x0b, 0x00, 0x00, 0x00, 0x52, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00
            ]
        );
    }

    /// The whole `TPM2_Create` for the device PIN key: its auth value and
    /// the secret in `inSensitive`, then the counted template.
    #[test]
    fn a_create_carries_the_auth_value_before_the_secret() {
        let mut expected = vec![0x80, 0x02, 0x00, 0x00, 0x00, 0x77, 0x00, 0x00, 0x01, 0x53];
        expected.extend_from_slice(&[0x80, 0x00, 0x00, 0x00]);
        expected.extend_from_slice(&EMPTY_PASSWORD_SESSION);
        expected.extend_from_slice(&[0x00, 0x44, 0x00, 0x20]);
        expected.extend_from_slice(&AUTH);
        expected.extend_from_slice(&[0x00, 0x20]);
        expected.extend_from_slice(&SECRET);
        expected.extend_from_slice(&[0x00, 0x0e]);
        expected.extend_from_slice(&sealed_object_template(false));
        // outsideInfo, creationPCR.
        expected.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        assert_eq!(
            create_command(0x8000_0000, false, &AUTH, &SECRET)
                .finish()
                .to_vec(),
            expected
        );
    }

    /// A slot's `TPM2_Create` is byte for byte what it was before this row:
    /// no auth value, the exempt template.
    #[test]
    fn a_slots_create_carries_no_auth_value() {
        let mut expected = vec![0x80, 0x02, 0x00, 0x00, 0x00, 0x57, 0x00, 0x00, 0x01, 0x53];
        expected.extend_from_slice(&[0x80, 0x00, 0x00, 0x00]);
        expected.extend_from_slice(&EMPTY_PASSWORD_SESSION);
        expected.extend_from_slice(&[0x00, 0x24, 0x00, 0x00, 0x00, 0x20]);
        expected.extend_from_slice(&SECRET);
        expected.extend_from_slice(&[0x00, 0x0e]);
        expected.extend_from_slice(&sealed_object_template(true));
        expected.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        assert_eq!(
            create_command(0x8000_0000, true, &[], &SECRET)
                .finish()
                .to_vec(),
            expected
        );
    }

    /// An unseal gives the object's auth value as the password of its one
    /// session; a slot's unseal gives the empty one, as before.
    #[test]
    fn an_unseal_gives_the_auth_value_as_its_password() {
        let unseal = |auth: &[u8]| {
            let mut command = Command::new(TPM_ST_SESSIONS, TPM_CC_UNSEAL);
            command.u32(0x8000_0001);
            command.password_session(auth);
            command.finish().to_vec()
        };
        let mut expected = vec![0x80, 0x02, 0x00, 0x00, 0x00, 0x3b, 0x00, 0x00, 0x01, 0x5e];
        expected.extend_from_slice(&[0x80, 0x00, 0x00, 0x01]);
        // authorizationSize, the password session, no nonce, continued.
        expected.extend_from_slice(&[0x00, 0x00, 0x00, 0x29, 0x40, 0x00, 0x00, 0x09, 0x00, 0x00]);
        expected.extend_from_slice(&[0x01, 0x00, 0x20]);
        expected.extend_from_slice(&AUTH);
        assert_eq!(unseal(&AUTH), expected);

        let mut expected = vec![0x80, 0x02, 0x00, 0x00, 0x00, 0x1b, 0x00, 0x00, 0x01, 0x5e];
        expected.extend_from_slice(&[0x80, 0x00, 0x00, 0x01]);
        expected.extend_from_slice(&EMPTY_PASSWORD_SESSION);
        assert_eq!(unseal(&[]), expected);
    }

    #[test]
    fn each_response_code_is_its_own_refusal() {
        // TPM_RC_AUTH_FAIL and TPM_RC_BAD_AUTH, bare and as the first
        // session's.
        for code in [0x08e, 0x98e, 0x0a2, 0x9a2] {
            assert_eq!(
                response_refusal("tpm2 unseal", code),
                Refusal::WrongAuth,
                "code {code:#x}"
            );
        }
        assert_eq!(
            response_refusal("tpm2 unseal", 0x921),
            Refusal::Lockout {
                interval_secs: None
            }
        );
        // TPM_RC_INTEGRITY as the first parameter's.
        assert_eq!(
            response_refusal("tpm2 load", 0x1df),
            Refusal::Other(KeystoreError::Corrupt(FOREIGN_SLOT))
        );
        // TPM_RC_RETRY, a warning the keystore has no word for, and
        // TPM_RC_LOCKOUT's number in another format.
        for code in [0x922, 0x0a1] {
            assert_eq!(
                response_refusal("tpm2 unseal", code),
                Refusal::Other(KeystoreError::Platform("tpm2 unseal", i64::from(code))),
                "code {code:#x}"
            );
        }
        // To a slot, a refused auth value and a lockout are `Denied`.
        assert_eq!(
            KeystoreError::from(Refusal::WrongAuth),
            KeystoreError::Denied
        );
        assert_eq!(
            KeystoreError::from(Refusal::Lockout {
                interval_secs: Some(600)
            }),
            KeystoreError::Denied
        );
    }

    #[test]
    fn the_recovery_interval_is_one_property_of_the_capability_answer() {
        assert_eq!(
            lockout_interval_command().finish().to_vec(),
            [
                0x80, 0x01, 0x00, 0x00, 0x00, 0x16, 0x00, 0x00, 0x01, 0x7a, 0x00, 0x00, 0x00, 0x06,
                0x00, 0x00, 0x02, 0x10, 0x00, 0x00, 0x00, 0x01
            ]
        );
        let answer = |property: u32, value: u32| {
            // The header, then moreData.
            let mut bytes = vec![
                0x80, 0x01, 0x00, 0x00, 0x00, 0x1b, 0x00, 0x00, 0x00, 0x00, 0x00,
            ];
            for field in [TPM_CAP_TPM_PROPERTIES, 1, property, value] {
                bytes.extend_from_slice(&field.to_be_bytes());
            }
            bytes
        };
        assert_eq!(
            lockout_interval_of(&answer(TPM_PT_LOCKOUT_INTERVAL, 7200)),
            Some(7200)
        );
        // Zero: the TPM's protection is off. Another property: the TPM has
        // not this one. A short answer: none.
        assert_eq!(
            lockout_interval_of(&answer(TPM_PT_LOCKOUT_INTERVAL, 0)),
            None
        );
        assert_eq!(
            lockout_interval_of(&answer(TPM_PT_LOCKOUT_INTERVAL + 1, 7200)),
            None
        );
        assert_eq!(
            lockout_interval_of(&answer(TPM_PT_LOCKOUT_INTERVAL, 7200)[..26]),
            None
        );
    }

    #[test]
    fn a_response_is_whole_when_the_size_in_its_header_is_read() {
        assert_eq!(response_size(&[0x80, 0x01, 0x00, 0x00, 0x00]), None);
        assert_eq!(
            response_size(&[0x80, 0x01, 0x00, 0x00, 0x00, 0x0a]),
            Some(10)
        );
        assert_eq!(
            response_size(&[0x80, 0x01, 0x00, 0x00, 0x01, 0x00, 0xff, 0xff]),
            Some(256)
        );
    }

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
        let areas = Ok((&[0xaa][..], &[0xbb, 0xcc][..]));
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
