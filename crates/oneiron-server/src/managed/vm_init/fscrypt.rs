//! The fscrypt v2 ioctls a vault VM's root bootstrap needs
//! (`linux/fscrypt.h`): add the vault's key to its filesystem's keyring,
//! read and set a directory's policy, and remove the key again. Each call
//! takes a held descriptor. The keyring calls take one on the unencrypted
//! vault root, never an inode in the encrypted tree, which would leave a
//! later removal busy. No key is kept or returned: the kernel answers with
//! its identifier.

use oneiron_vault_contract::vm_provision::{VM_FSCRYPT_KEY_LEN, VmFscryptKey};
use std::{fs::File, io, os::fd::AsRawFd};
use zeroize::Zeroize;

/// An fscrypt v2 master key identifier: 16 bytes the kernel derives from the
/// key itself, so a directory and a key cannot pair by mistake.
pub(super) type KeyIdentifier = [u8; 16];

// The request numbers, fixed ABI: _IOR('f', 19, policy_v1) (the kernel reads
// a v2 policy's version byte first), _IOWR('f', 22, __u8[9]),
// _IOWR('f', 23, add_key_arg) and _IOWR('f', 24, remove_key_arg).
const FS_IOC_SET_ENCRYPTION_POLICY: libc::c_ulong = 0x800c_6613;
const FS_IOC_GET_ENCRYPTION_POLICY_EX: libc::c_ulong = 0xc009_6616;
const FS_IOC_ADD_ENCRYPTION_KEY: libc::c_ulong = 0xc050_6617;
const FS_IOC_REMOVE_ENCRYPTION_KEY: libc::c_ulong = 0xc040_6618;

const KEY_SPEC_TYPE_IDENTIFIER: u32 = 2;
const KEY_REMOVAL_STATUS_FLAG_FILES_BUSY: u32 = 0x1;
const POLICY_V2: u8 = 2;
const MODE_AES_256_XTS: u8 = 1;
const MODE_AES_256_CTS: u8 = 4;
const POLICY_FLAGS_PAD_32: u8 = 0x03;
/// A v2 policy's size; a v1 policy is 12 bytes.
const POLICY_V2_SIZE: u64 = 24;

#[repr(C)]
struct KeySpecifier {
    kind: u32,
    reserved: u32,
    /// The union's 32 bytes; an identifier fills the first 16.
    identifier: [u8; 32],
}

impl KeySpecifier {
    fn of(identifier: Option<&KeyIdentifier>) -> Self {
        let mut spec = Self {
            kind: KEY_SPEC_TYPE_IDENTIFIER,
            reserved: 0,
            identifier: [0; 32],
        };
        if let Some(identifier) = identifier {
            spec.identifier[..identifier.len()].copy_from_slice(identifier);
        }
        spec
    }

    fn identifier(&self) -> KeyIdentifier {
        let mut identifier = KeyIdentifier::default();
        let len = identifier.len();
        identifier.copy_from_slice(&self.identifier[..len]);
        identifier
    }
}

#[repr(C)]
struct AddKeyArg {
    key_spec: KeySpecifier,
    raw_size: u32,
    key_id: u32,
    reserved: [u32; 8],
    /// The kernel's flexible array, sized for the one key this adds.
    raw: [u8; VM_FSCRYPT_KEY_LEN],
}

impl Drop for AddKeyArg {
    fn drop(&mut self) {
        self.raw.zeroize();
    }
}

#[repr(C)]
struct RemoveKeyArg {
    key_spec: KeySpecifier,
    removal_status_flags: u32,
    reserved: [u32; 5],
}

#[repr(C)]
struct PolicyV2 {
    version: u8,
    contents_encryption_mode: u8,
    filenames_encryption_mode: u8,
    flags: u8,
    log2_data_unit_size: u8,
    reserved: [u8; 3],
    master_key_identifier: KeyIdentifier,
}

impl PolicyV2 {
    /// The one policy this bootstrap sets, the process supervisor's too: v2,
    /// AES-256-XTS contents, AES-256-CTS names, 32-byte name padding.
    fn ours(identifier: &KeyIdentifier) -> Self {
        Self {
            version: POLICY_V2,
            contents_encryption_mode: MODE_AES_256_XTS,
            filenames_encryption_mode: MODE_AES_256_CTS,
            flags: POLICY_FLAGS_PAD_32,
            log2_data_unit_size: 0,
            reserved: [0; 3],
            master_key_identifier: *identifier,
        }
    }

    fn is_ours(&self) -> bool {
        let ours = Self::ours(&self.master_key_identifier);
        (
            self.version,
            self.contents_encryption_mode,
            self.filenames_encryption_mode,
            self.flags,
            self.log2_data_unit_size,
        ) == (
            ours.version,
            ours.contents_encryption_mode,
            ours.filenames_encryption_mode,
            ours.flags,
            ours.log2_data_unit_size,
        )
    }
}

/// The GET_EX argument: the policy's size, then the v1/v2 policy union, of
/// which v2 is the larger.
#[repr(C)]
struct GetPolicyExArg {
    size: u64,
    policy: PolicyV2,
}

/// What a directory's fscrypt policy is.
pub(super) enum Policy {
    /// None: a plaintext directory.
    Plaintext,
    /// Exactly the policy this bootstrap sets, under this key identifier.
    Ours(KeyIdentifier),
    /// Another v1 or v2 policy.
    Other,
}

/// What removing the key did.
#[derive(Debug)]
pub(super) enum Removal {
    Removed,
    /// The key is gone, but files in the tree were still open; the kernel
    /// evicts them once they close.
    FilesBusy,
    /// The keyring did not hold it.
    Absent,
}

/// One fscrypt ioctl on `fd`.
///
/// # Safety
///
/// `arg` must be the `repr(C)` argument of exactly the size and layout that
/// `request` names in `linux/fscrypt.h`.
unsafe fn ioctl<T>(fd: &File, request: libc::c_ulong, arg: &mut T) -> io::Result<()> {
    // SAFETY: `fd` is live for the call, and `arg` is an exclusively borrowed
    // value of the layout `request` names (this function's contract), so the
    // kernel reads and writes only within it.
    let rc = unsafe { libc::ioctl(fd.as_raw_fd(), request, std::ptr::from_mut(arg)) };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Whether `error` means this filesystem or kernel cannot do fscrypt (ext4
/// without its `encrypt` feature, or a kernel without fscrypt), as opposed
/// to a failure of the call.
pub(super) fn unsupported(error: &io::Error) -> bool {
    matches!(error.raw_os_error(), Some(libc::EOPNOTSUPP | libc::ENOTTY))
}

/// Adds `key` to the keyring of the filesystem `root` lies on, and returns
/// the identifier the kernel computed for it. The argument's copy of the key
/// is wiped before this returns. `root` must be the unencrypted vault root.
pub(super) fn add_key(root: &File, key: &VmFscryptKey) -> io::Result<KeyIdentifier> {
    let mut arg = AddKeyArg {
        key_spec: KeySpecifier::of(None),
        raw_size: VM_FSCRYPT_KEY_LEN as u32,
        key_id: 0,
        reserved: [0; 8],
        raw: [0; VM_FSCRYPT_KEY_LEN],
    };
    arg.raw.copy_from_slice(key.as_bytes());
    // SAFETY: `AddKeyArg` is `struct fscrypt_add_key_arg` with its flexible
    // array sized for `raw_size` bytes, as FS_IOC_ADD_ENCRYPTION_KEY takes.
    unsafe { ioctl(root, FS_IOC_ADD_ENCRYPTION_KEY, &mut arg) }?;
    Ok(arg.key_spec.identifier())
}

/// Removes the key `identifier` names from the keyring of the filesystem
/// `root` lies on. `root` must be the unencrypted vault root.
pub(super) fn remove_key(root: &File, identifier: &KeyIdentifier) -> io::Result<Removal> {
    let mut arg = RemoveKeyArg {
        key_spec: KeySpecifier::of(Some(identifier)),
        removal_status_flags: 0,
        reserved: [0; 5],
    };
    // SAFETY: `RemoveKeyArg` is `struct fscrypt_remove_key_arg`, as
    // FS_IOC_REMOVE_ENCRYPTION_KEY takes.
    match unsafe { ioctl(root, FS_IOC_REMOVE_ENCRYPTION_KEY, &mut arg) } {
        Ok(()) if arg.removal_status_flags & KEY_REMOVAL_STATUS_FLAG_FILES_BUSY != 0 => {
            Ok(Removal::FilesBusy)
        }
        Ok(()) => Ok(Removal::Removed),
        Err(error) if error.raw_os_error() == Some(libc::ENOKEY) => Ok(Removal::Absent),
        Err(error) => Err(error),
    }
}

/// The fscrypt policy of the directory `dir` holds. Reading it needs no key.
pub(super) fn policy(dir: &File) -> io::Result<Policy> {
    let mut arg = GetPolicyExArg {
        size: POLICY_V2_SIZE,
        policy: PolicyV2::ours(&KeyIdentifier::default()),
    };
    // SAFETY: `GetPolicyExArg` is `struct fscrypt_get_policy_ex_arg` with its
    // union sized for the larger, v2 policy, which `size` states.
    match unsafe { ioctl(dir, FS_IOC_GET_ENCRYPTION_POLICY_EX, &mut arg) } {
        Ok(()) if arg.size == POLICY_V2_SIZE && arg.policy.is_ours() => {
            Ok(Policy::Ours(arg.policy.master_key_identifier))
        }
        Ok(()) => Ok(Policy::Other),
        Err(error) if error.raw_os_error() == Some(libc::ENODATA) => Ok(Policy::Plaintext),
        Err(error) => Err(error),
    }
}

/// Sets this bootstrap's v2 policy under `identifier` on the empty directory
/// `dir` holds. The key must be in the keyring.
pub(super) fn set_policy(dir: &File, identifier: &KeyIdentifier) -> io::Result<()> {
    let mut arg = PolicyV2::ours(identifier);
    // SAFETY: `PolicyV2` is `struct fscrypt_policy_v2`, which
    // FS_IOC_SET_ENCRYPTION_POLICY reads after its version byte.
    unsafe { ioctl(dir, FS_IOC_SET_ENCRYPTION_POLICY, &mut arg) }
}
