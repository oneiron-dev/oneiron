//! The TPM tier's own TPM 2.0 command client: one connection to the TPM, the
//! commands the tier sends over it, the templates of the objects it makes,
//! and what each response code means.

use std::fs::{File, OpenOptions};
use std::io::{ErrorKind, Read, Write};
use std::path::Path;

use zeroize::Zeroizing;

use super::wire::{Command, Reader, push_sized};
use super::{Answered, FOREIGN_SLOT, Refusal, TPM_BUFFER, io};
use crate::{KeystoreError, Result};

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

/// One open connection to a TPM.
pub(super) struct Tpm {
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
    pub(super) fn on_device(device: &Path) -> Result<Self> {
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
    pub(super) fn on_socket(socket: &Path) -> Result<Self> {
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
    pub(super) fn create_primary(&mut self) -> Result<u32> {
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
    pub(super) fn create_sealed(
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
    pub(super) fn load(&mut self, parent: u32, private: &[u8], public: &[u8]) -> Result<u32> {
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
    pub(super) fn unseal(&mut self, object: u32, auth: &[u8]) -> Answered<Zeroizing<Vec<u8>>> {
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
    pub(super) fn lockout_interval_secs(&mut self) -> Option<u64> {
        let response = self
            .call(&lockout_interval_command(), "tpm2 get capability")
            .ok()?;
        lockout_interval_of(&response)
    }

    /// Frees a transient object. A failure leaves it to the resource
    /// manager, which flushes it when the device closes.
    pub(super) fn flush(&mut self, handle: u32) {
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
}
