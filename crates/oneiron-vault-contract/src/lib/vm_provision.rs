//! A vault VM's provision connection (FIX 6308): what its root bootstrap,
//! `oneiron-vm-init`, takes from the host before any engine runs.
//!
//! On a cold boot the guest's first connection to
//! [`VM_BOOT_PORT`](crate::vm::VM_BOOT_PORT) is this one, dialled by the
//! root bootstrap. The host writes one [`VmProvision`] line naming the vault
//! and its binding, then exactly [`VM_FSCRYPT_KEY_LEN`] bytes of the vault's
//! name-bound fscrypt v2 master key ([`VmFscryptKey`]), and half-closes. The
//! guest installs the key, checks that the kernel's identifier for it is the
//! binding's, lays out its encrypted storage and its UID table, and answers
//! one [`VmProvisionReply`] line: the binding echoed back, or a typed
//! [`VmProvisionFailure`]. Then the connection closes and the engine's own
//! credential connection follows, unchanged. A provisioned reply is not
//! readiness: only the engine's ready byte is.
//!
//! The guest chooses nothing here: the vault, its UID, its disk and its key
//! are the host's. The key travels only as that raw frame, never in JSON, on
//! a disk, in argv, the environment or a log. A snapshot restore resumes an
//! already provisioned guest and runs no second provision.

use crate::valid_vault_name;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::io::Read;
use zeroize::Zeroizing;

/// The provision connection's revision. A host and an image agree on it
/// through the image's build floor, not through `CONTRACT_VERSION`.
pub const VM_PROVISION_REVISION: u32 = 1;

/// The fscrypt v2 master key's length, the key frame's exact size.
pub const VM_FSCRYPT_KEY_LEN: usize = 64;

/// Where the guest keeps the binding its vault disk was provisioned for:
/// root-owned, mode 0600, under the root-only `/vault/control`. It holds the
/// vault, the UID, the disk UUID and the key identifier, never a key byte. A
/// later cold boot under another binding is refused against it.
pub const VM_PROVISION_RECORD: &str = "/vault/control/vm-provision.json";

/// The most characters a refusal's detail keeps, so its line stays within
/// the boot channel's frame bound.
const MAX_DETAIL_CHARS: usize = 160;

/// What the host binds a vault VM's provisioning to, none of it secret: the
/// vault's dedicated UID (the host-stamped one, used as its GID too), its
/// derivation owner, its vault disk's filesystem UUID, and the identifier of
/// the fscrypt v2 key its storage is encrypted under.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VmProvisionBinding {
    /// The non-root UID the guest's engine runs as, and its GID.
    pub guest_uid: u32,
    /// The vault's derivation owner (`--derivation-owner`): a 32-byte
    /// account or organization id, as 64 lowercase hex digits.
    pub derivation_owner: String,
    /// The vault disk's ext4 filesystem UUID, `8-4-4-4-12` lowercase hex.
    pub vault_disk_uuid: String,
    /// The fscrypt v2 master key identifier the kernel computes for the
    /// vault's key, as 32 lowercase hex digits.
    pub fscrypt_key_identifier: String,
}

impl VmProvisionBinding {
    /// Why this binding cannot provision a vault, if it cannot: a UID of 0
    /// (root) or `u32::MAX` (no UID), or a field not in its form.
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.guest_uid == 0 || self.guest_uid == u32::MAX {
            return Err("the guest UID is root or no UID");
        }
        if !lower_hex(&self.derivation_owner, 64) {
            return Err("the derivation owner is not 64 lowercase hex digits");
        }
        if !uuid_form(&self.vault_disk_uuid) {
            return Err("the vault disk UUID is not 8-4-4-4-12 lowercase hex");
        }
        if !lower_hex(&self.fscrypt_key_identifier, 32) {
            return Err("the fscrypt key identifier is not 32 lowercase hex digits");
        }
        Ok(())
    }
}

fn lower_hex(text: &str, len: usize) -> bool {
    text.len() == len && text.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

fn uuid_form(text: &str) -> bool {
    let mut groups = text.split('-');
    [8, 4, 4, 4, 12]
        .into_iter()
        .all(|len| groups.next().is_some_and(|group| lower_hex(group, len)))
        && groups.next().is_none()
}

/// The provision connection's first frame, host to guest: one line naming
/// the vault and its binding. Exactly [`VM_FSCRYPT_KEY_LEN`] key bytes
/// follow it, then the host's half-close.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VmProvision {
    /// [`VM_PROVISION_REVISION`].
    pub revision: u32,
    /// The vault the VM runs, as `--vault-name` takes it.
    pub vault: String,
    pub binding: VmProvisionBinding,
}

impl VmProvision {
    /// The failure a guest answers for a frame of another revision, or one
    /// whose vault name or binding is not in form, and why.
    pub fn validate(&self) -> Result<(), (VmProvisionFailure, &'static str)> {
        if self.revision != VM_PROVISION_REVISION {
            return Err((
                VmProvisionFailure::UnsupportedRevision,
                "the provision frame is of another revision",
            ));
        }
        if !valid_vault_name(&self.vault) {
            return Err((
                VmProvisionFailure::MalformedBinding,
                "the provision frame's vault name is invalid",
            ));
        }
        self.binding
            .validate()
            .map_err(|fault| (VmProvisionFailure::MalformedBinding, fault))
    }
}

/// A vault's name-bound fscrypt v2 master key, the provision connection's
/// key frame: exactly [`VM_FSCRYPT_KEY_LEN`] bytes, wiped when dropped. It
/// has no serde form, no clone and no printable body; its bytes leave it only
/// as the raw frame and the guest kernel's add-key call.
pub struct VmFscryptKey(Zeroizing<[u8; VM_FSCRYPT_KEY_LEN]>);

impl VmFscryptKey {
    pub fn new(bytes: Zeroizing<[u8; VM_FSCRYPT_KEY_LEN]>) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; VM_FSCRYPT_KEY_LEN] {
        &self.0
    }

    /// Reads exactly the key from `reader`, then requires its end: a short
    /// frame or a trailing byte is refused, and partial key bytes are wiped.
    pub fn read_from(mut reader: impl Read) -> anyhow::Result<Self> {
        let mut key = Zeroizing::new([0u8; VM_FSCRYPT_KEY_LEN]);
        if let Err(error) = reader.read_exact(&mut key[..]) {
            anyhow::bail!("fscrypt key frame short read: {error}");
        }
        let mut trailing = [0u8; 1];
        loop {
            match reader.read(&mut trailing) {
                Ok(0) => return Ok(Self(key)),
                Ok(_) => anyhow::bail!("fscrypt key frame carried trailing bytes"),
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                Err(error) => anyhow::bail!("fscrypt key frame EOF check failed: {error}"),
            }
        }
    }
}

impl fmt::Debug for VmFscryptKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("VmFscryptKey(..)")
    }
}

/// The provision connection's answer, guest to host: one line, then the
/// guest closes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum VmProvisionReply {
    /// The key is installed under the binding's identifier, the storage and
    /// the UID table are laid out, and the engine starts next. The guest
    /// echoes what it was sent; the host compares the echo with what it sent.
    Provisioned {
        revision: u32,
        vault: String,
        binding: VmProvisionBinding,
    },
    /// The guest refused this provisioning and starts no engine.
    Refused {
        revision: u32,
        code: VmProvisionFailure,
        detail: String,
    },
}

impl VmProvisionReply {
    /// A refusal under this revision. Its detail keeps at most 160
    /// characters and no control characters, so the line fits its frame; a
    /// detail never holds key bytes.
    pub fn refused(code: VmProvisionFailure, detail: &str) -> Self {
        Self::Refused {
            revision: VM_PROVISION_REVISION,
            code,
            detail: detail
                .chars()
                .filter(|c| !c.is_control())
                .take(MAX_DETAIL_CHARS)
                .collect(),
        }
    }
}

/// Why a guest refused its provisioning.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VmProvisionFailure {
    /// The frame's revision is not [`VM_PROVISION_REVISION`].
    UnsupportedRevision,
    /// The metadata frame or the key frame is not in its form.
    MalformedBinding,
    /// The binding names another vault or owner than the guest's boot
    /// arguments do.
    ContradictoryBinding,
    /// The disk mounted at `/vault` is not the vault drive, or its
    /// filesystem UUID is not the binding's.
    DiskMismatch,
    /// The vault disk's filesystem or the guest kernel cannot do fscrypt v2.
    FscryptUnavailable,
    /// The kernel's identifier for the key is not the binding's.
    KeyMismatch,
    /// The disk's storage, key directory or provision record does not match:
    /// a plaintext tree with content, another policy, another owner or mode,
    /// or another binding.
    StorageMismatch,
    /// Provisioning failed for another reason; the detail says which.
    ProvisionFailed,
}

impl VmProvisionFailure {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::UnsupportedRevision => "unsupported_revision",
            Self::MalformedBinding => "malformed_binding",
            Self::ContradictoryBinding => "contradictory_binding",
            Self::DiskMismatch => "disk_mismatch",
            Self::FscryptUnavailable => "fscrypt_unavailable",
            Self::KeyMismatch => "key_mismatch",
            Self::StorageMismatch => "storage_mismatch",
            Self::ProvisionFailed => "provision_failed",
        }
    }
}

impl fmt::Display for VmProvisionFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}
