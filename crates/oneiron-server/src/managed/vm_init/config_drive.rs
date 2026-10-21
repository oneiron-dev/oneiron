//! The vault VM's config drive as the root bootstrap reads it: only the typed
//! files the contract names below
//! [`VM_GUEST_CONFIG_DIR`](oneiron_vault_contract::vm::VM_GUEST_CONFIG_DIR)
//! (the network plan, and the managed profile's five files of
//! [`super::profile`]), each read whole, at most [`MAX_VM_CONFIG_FILE_BYTES`],
//! once per boot that serves and before the vault's key goes in. The drive's
//! other files (its settings, its seal files, the host's addresses) reach the
//! engine as the image's init maps them; nothing here lists the drive or
//! reads a file the contract does not name.
//!
//! A known file that is not there (ENOENT) is a choice not made. One that is
//! there but cannot be read, is not a regular file, is over the bound or is
//! not in its form refuses the boot; it is never read as absent. No error
//! carries a file's bytes.

use super::profile::VmManagedProfile;
use oneiron_vault_contract::vm::{
    MAX_VM_CONFIG_FILE_BYTES, VM_GUEST_NETWORK_FILE, VmGuestNetworkConfig,
};
use std::io::Read as _;
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::{Path, PathBuf};

/// What the guest's form says a network file is, for a refusal.
const NETWORK_FORM: &str =
    "not one JSON object of exactly guest_mac, guest_ipv4, prefix_len, gateway and dns_servers";

/// What the config drive's typed files say, each `None` when its file is not
/// there.
#[derive(Default)]
pub(super) struct VmGuestConfig {
    /// [`VM_GUEST_NETWORK_FILE`]: the guest NIC to set up.
    pub(super) network: Option<VmGuestNetworkConfig>,
    /// The managed profile's five files (FIX 6809): the engine's own
    /// managed-profile flags.
    pub(super) profile: VmManagedProfile,
}

/// Why a known file on the config drive refused the boot.
#[derive(Debug, thiserror::Error)]
pub(super) enum VmConfigFileError {
    #[error("reading the config drive's {}", path.display())]
    Read {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("the config drive's {} is not a regular file", path.display())]
    NotRegular { path: PathBuf },
    #[error("the config drive's {} is over {max} bytes", path.display())]
    TooLong { path: PathBuf, max: usize },
    #[error("the config drive's {} is malformed: {fault}", path.display())]
    Malformed { path: PathBuf, fault: &'static str },
}

impl VmGuestConfig {
    /// Reads each known file once from the config drive the image's init
    /// mounted, or nothing when it mounted none (`mounted` false).
    pub(super) fn load(mounted: bool) -> Result<Self, VmConfigFileError> {
        if !mounted {
            return Ok(Self::default());
        }
        Ok(Self {
            network: network()?,
            profile: VmManagedProfile::load()?,
        })
    }
}

/// [`VM_GUEST_NETWORK_FILE`], when it is there: decoded strictly, then
/// checked with the contract's own validation.
fn network() -> Result<Option<VmGuestNetworkConfig>, VmConfigFileError> {
    let Some(bytes) = read_known(VM_GUEST_NETWORK_FILE)? else {
        return Ok(None);
    };
    let malformed = |fault| VmConfigFileError::Malformed {
        path: VM_GUEST_NETWORK_FILE.into(),
        fault,
    };
    let network: VmGuestNetworkConfig =
        serde_json::from_slice(&bytes).map_err(|_| malformed(NETWORK_FORM))?;
    network.validate().map_err(malformed)?;
    Ok(Some(network))
}

/// One known file's bytes, or `None` when it is not there: looked at without
/// following a link, so a device, a pipe or a link is refused before it is
/// opened, then read to at most the bound.
pub(super) fn read_known(path: &str) -> Result<Option<Vec<u8>>, VmConfigFileError> {
    let path = Path::new(path);
    let read = |source| VmConfigFileError::Read {
        path: path.to_owned(),
        source,
    };
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_file() => {}
        Ok(_) => {
            return Err(VmConfigFileError::NotRegular {
                path: path.to_owned(),
            });
        }
        Err(error) if error.raw_os_error() == Some(libc::ENOENT) => return Ok(None),
        Err(error) => return Err(read(error)),
    }
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(read)?;
    let mut bytes = Vec::new();
    file.take(MAX_VM_CONFIG_FILE_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(read)?;
    if bytes.len() > MAX_VM_CONFIG_FILE_BYTES {
        return Err(VmConfigFileError::TooLong {
            path: path.to_owned(),
            max: MAX_VM_CONFIG_FILE_BYTES,
        });
    }
    Ok(Some(bytes))
}
