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
//!   object. The objects are `noDA`, so a failed use never counts toward the
//!   TPM's dictionary-attack lockout. The secret crosses the bus to the TPM
//!   unencrypted when it is sealed and unsealed.
//! - Switching tiers reads nothing the other tier wrote: the install starts
//!   empty slots, as a new machine does.

use std::fs::{self, File, OpenOptions};
use std::io::{ErrorKind, Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use zeroize::Zeroizing;

use crate::file::LocalFileKeystore;
use crate::{
    DeviceKeystore, KeystoreAssurance, KeystoreError, KeystoreLocality, KeystoreSlot, Result,
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

/// The most bytes a sealed slot file may hold: its tag and two areas, each
/// at most one TPM buffer.
const SEALED_MAX: usize = SEALED_TAG.len() + 2 * TPM_BUFFER;

const TPM_ST_NO_SESSIONS: u16 = 0x8001;
const TPM_ST_SESSIONS: u16 = 0x8002;

const TPM_CC_CREATE_PRIMARY: u32 = 0x0000_0131;
const TPM_CC_CREATE: u32 = 0x0000_0153;
const TPM_CC_LOAD: u32 = 0x0000_0157;
const TPM_CC_UNSEAL: u32 = 0x0000_015e;
const TPM_CC_FLUSH_CONTEXT: u32 = 0x0000_0165;

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
    device: PathBuf,
}

impl LinuxTpmKeystore {
    /// Opens the key directory as the platform tier does (0700, outside every
    /// vault directory in `vault_dirs`), then proves the TPM answers: its
    /// resource manager opens and its owner hierarchy makes the storage key.
    /// Without one the tier is `Unavailable`, never served by a weaker one.
    pub fn open(dir: &Path, vault_dirs: &[&Path]) -> Result<Self> {
        let files = LocalFileKeystore::open(dir, vault_dirs)?;
        let this = Self {
            files,
            device: PathBuf::from(TPM_DEVICE),
        };
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

    fn tpm(&self) -> Result<Tpm> {
        match OpenOptions::new().read(true).write(true).open(&self.device) {
            Ok(file) => Ok(Tpm { file }),
            Err(e) if e.kind() == ErrorKind::NotFound => Err(KeystoreError::Unavailable(
                "no TPM 2.0 resource manager at /dev/tpmrm0",
            )),
            Err(e) if e.kind() == ErrorKind::PermissionDenied => Err(KeystoreError::Unavailable(
                "this user may not open the TPM resource manager /dev/tpmrm0",
            )),
            Err(e) => Err(io(e)),
        }
    }

    /// `secret` sealed in this TPM: the slot file's bytes.
    fn seal(&self, secret: &[u8; 32]) -> Result<Vec<u8>> {
        let mut tpm = self.tpm()?;
        let primary = tpm.create_primary()?;
        let created = tpm.create_sealed(primary, secret);
        tpm.flush(primary);
        let (public, private) = created?;
        let mut sealed = Vec::with_capacity(SEALED_TAG.len() + public.len() + private.len());
        sealed.extend_from_slice(SEALED_TAG);
        sealed.extend_from_slice(&public);
        sealed.extend_from_slice(&private);
        Ok(sealed)
    }

    /// The secret a slot file's bytes seal, unsealed by this TPM.
    fn unseal(&self, sealed: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
        let (public, private) = sealed_areas(sealed)?;
        let mut tpm = self.tpm()?;
        let primary = tpm.create_primary()?;
        let loaded = tpm.load(primary, private, public);
        tpm.flush(primary);
        let object = loaded?;
        let data = tpm.unseal(object);
        tpm.flush(object);
        let data = data?;
        if data.len() != 32 {
            return Err(KeystoreError::Corrupt("the sealed slot is not 32 bytes"));
        }
        let mut secret = Zeroizing::new([0u8; 32]);
        secret.copy_from_slice(&data);
        Ok(secret)
    }

    /// The slot file's bytes, or `None` when the slot is empty.
    fn read_sealed(&self, slot: &KeystoreSlot) -> Result<Option<Vec<u8>>> {
        let mut file = match File::open(self.path(slot)) {
            Ok(file) => file,
            Err(e) if e.kind() == ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(io(e)),
        };
        let meta = file.metadata().map_err(io)?;
        if !meta.is_file() || meta.permissions().mode() & 0o077 != 0 {
            return Err(KeystoreError::Corrupt("the slot file is open to others"));
        }
        let mut sealed = Vec::new();
        Read::by_ref(&mut file)
            .take(SEALED_MAX as u64 + 1)
            .read_to_end(&mut sealed)
            .map_err(io)?;
        if sealed.len() > SEALED_MAX {
            return Err(KeystoreError::Corrupt("the sealed slot is too long"));
        }
        Ok(Some(sealed))
    }

    /// A private temporary file holding `sealed`, beside the slot's file,
    /// named as the platform tier names its own so one sweep clears both.
    fn write_temp(&self, slot: &KeystoreSlot, sealed: &[u8]) -> (PathBuf, std::io::Result<()>) {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        let tmp = self.files.dir().join(format!(
            ".{}.{}.{nanos}.tmp",
            slot.name(),
            std::process::id()
        ));
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
        match self.read_sealed(slot)? {
            Some(sealed) => self.unseal(&sealed).map(Some),
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
        let sealed = self.seal(secret)?;
        let (tmp, written) = self.write_temp(slot, &sealed);
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
        let sealed = self.seal(secret)?;
        let (tmp, written) = self.write_temp(slot, &sealed);
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
}

/// A sealed slot file's `TPM2B_PUBLIC` and `TPM2B_PRIVATE` bodies, after the
/// tag; nothing may follow them.
fn sealed_areas(sealed: &[u8]) -> Result<(&[u8], &[u8])> {
    let corrupt = || KeystoreError::Corrupt("the sealed slot does not parse");
    let body = sealed
        .strip_prefix(SEALED_TAG.as_slice())
        .ok_or_else(corrupt)?;
    let mut reader = Reader::new(body);
    let public = reader.sized().ok_or_else(corrupt)?;
    let private = reader.sized().ok_or_else(corrupt)?;
    if !reader.rest().is_empty() {
        return Err(corrupt());
    }
    Ok((public, private))
}

/// One open TPM resource-manager connection.
struct Tpm {
    file: File,
}

impl Tpm {
    /// Sends one command and reads its whole response; a response code other
    /// than success is this command's error.
    fn call(&mut self, command: &Command, name: &'static str) -> Result<Zeroizing<Vec<u8>>> {
        self.file.write_all(&command.finish()).map_err(io)?;
        let mut response = Zeroizing::new(vec![0u8; TPM_BUFFER]);
        let read = self.file.read(&mut response).map_err(io)?;
        response.truncate(read);
        let mut header = Reader::new(&response);
        let (Some(_tag), Some(size), Some(code)) = (header.u16(), header.u32(), header.u32())
        else {
            return Err(KeystoreError::Platform(name, -1));
        };
        if usize::try_from(size).ok() != Some(response.len()) {
            return Err(KeystoreError::Platform(name, -1));
        }
        if code != 0 {
            return Err(response_error(name, code));
        }
        Ok(response)
    }

    /// The owner hierarchy's ECC P-256 storage key (the TCG standard storage
    /// key template), made again from the owner seed: the same key each time.
    fn create_primary(&mut self) -> Result<u32> {
        let mut command = Command::new(TPM_ST_SESSIONS, TPM_CC_CREATE_PRIMARY);
        command.u32(TPM_RH_OWNER);
        command.password_session();
        // inSensitive: no auth value, no data.
        command.sized(&[0, 0, 0, 0]);
        command.sized(&storage_key_template());
        // outsideInfo, creationPCR.
        command.u16(0);
        command.u32(0);
        let response = self.call(&command, "tpm2 create primary")?;
        response_handle(&response, "tpm2 create primary")
    }

    /// `secret` as a sealed data object under `parent`: its `TPM2B_PUBLIC` and
    /// `TPM2B_PRIVATE`, each with its size.
    fn create_sealed(&mut self, parent: u32, secret: &[u8; 32]) -> Result<(Vec<u8>, Vec<u8>)> {
        let mut command = Command::new(TPM_ST_SESSIONS, TPM_CC_CREATE);
        command.u32(parent);
        command.password_session();
        // inSensitive: no auth value, the secret as its data.
        let mut sensitive = Zeroizing::new(Vec::with_capacity(4 + secret.len()));
        sensitive.extend_from_slice(&0u16.to_be_bytes());
        sensitive.extend_from_slice(&(secret.len() as u16).to_be_bytes());
        sensitive.extend_from_slice(secret);
        command.sized(&sensitive);
        command.sized(&sealed_object_template());
        // outsideInfo, creationPCR.
        command.u16(0);
        command.u32(0);
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
        command.password_session();
        command.sized(private);
        command.sized(public);
        let response = self.call(&command, "tpm2 load")?;
        response_handle(&response, "tpm2 load")
    }

    /// The data a loaded sealed object holds.
    fn unseal(&mut self, object: u32) -> Result<Zeroizing<Vec<u8>>> {
        let mut command = Command::new(TPM_ST_SESSIONS, TPM_CC_UNSEAL);
        command.u32(object);
        command.password_session();
        let response = self.call(&command, "tpm2 unseal")?;
        let mut reader = Reader::new(&response);
        let malformed = || KeystoreError::Platform("tpm2 unseal", -1);
        // The header, then parameterSize.
        reader.skip(10 + 4).ok_or_else(malformed)?;
        let data = reader.sized().ok_or_else(malformed)?;
        Ok(Zeroizing::new(data.to_vec()))
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

/// A response code as the keystore's error: an authorization refused or a
/// lockout is `Denied`, an object that fails its integrity check (another
/// TPM's, or altered) is `Corrupt`, and any other code is the TPM's failure
/// by command and code.
fn response_error(name: &'static str, code: u32) -> KeystoreError {
    let format_one = (code & RC_FMT1 != 0).then_some(RC_FMT1 | (code & 0x03f));
    match format_one {
        Some(RC_AUTH_FAIL | RC_BAD_AUTH) => KeystoreError::Denied,
        Some(RC_INTEGRITY) => {
            KeystoreError::Corrupt("the sealed slot does not load in this machine's TPM")
        }
        _ if code == RC_LOCKOUT => KeystoreError::Denied,
        _ => KeystoreError::Platform(name, i64::from(code)),
    }
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
/// caller, fixed to this TPM and its parent.
fn sealed_object_template() -> Vec<u8> {
    let mut public = Vec::with_capacity(14);
    public.extend_from_slice(&TPM_ALG_KEYEDHASH.to_be_bytes());
    public.extend_from_slice(&TPM_ALG_SHA256.to_be_bytes());
    let attributes = FIXED_TPM | FIXED_PARENT | USER_WITH_AUTH | NO_DA;
    public.extend_from_slice(&attributes.to_be_bytes());
    // authPolicy: none.
    public.extend_from_slice(&0u16.to_be_bytes());
    // scheme: none.
    public.extend_from_slice(&TPM_ALG_NULL.to_be_bytes());
    // unique: empty; the TPM fills it.
    public.extend_from_slice(&0u16.to_be_bytes());
    public
}

/// A TPM command's bytes: its header, then its fields in order. The header's
/// size is filled when it is sent. Held zeroized: a create carries the
/// secret.
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
        self.u16(u16::try_from(value.len()).unwrap_or(u16::MAX));
        self.bytes.extend_from_slice(value);
    }

    /// The authorization area of one password session with the empty
    /// password: the handle's authorization for a command with one.
    fn password_session(&mut self) {
        // authorizationSize, then TPMS_AUTH_COMMAND: the session handle, an
        // empty nonce, its attributes and an empty password.
        self.u32(9);
        self.u32(TPM_RS_PW);
        self.u16(0);
        self.bytes.push(SESSION_CONTINUE);
        self.u16(0);
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
