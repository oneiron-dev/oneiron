//! A vault VM's cold restore handoff (FIX 6584): `--vm-restore-revision`,
//! which only the image's `oneiron-vm-init` passes, beside `--restore` and
//! the two pipes it made and carries over the host's restore channel. The
//! flag grants nothing by itself: the bootstrap checked the live channel
//! and the vault's binding before it started the engine, and the restore
//! still proves each pipe's end before it reads a byte. A `--vsock-guest`
//! start without it takes no restore pipes, as before.
//!
//! Its custody anchor handoff (FIX 6517) is the same kind:
//! `--vm-anchor-revision`, and with it the URL the host bound, the socket
//! that reaches it, and the pipe the bootstrap carries the credential into
//! (`--vm-anchor-url`, `--vm-anchor-socket`, `--custody-anchor-credentials-fd`).
//! None of them is the owner's authority: the native reader still proves the
//! pipe and decodes its one object, and a credential is taken only for the
//! URL the vault's own settings name. Without the handoff a `--vsock-guest`
//! start takes no credential pipe, as before.

use std::fmt;
use std::os::fd::RawFd;
use std::path::{Path, PathBuf};

use oneiron_vault_contract::vm_anchor::{VM_ANCHOR_WIRE_REVISION, VM_GUEST_ANCHOR_SOCKET};
use oneiron_vault_contract::vm_restore::VM_RESTORE_WIRE_REVISION;

use crate::config::ServeArgs;

use super::{ManagedError, VSOCK_NO_PIPE_REASON};

/// Whether argv carries a vault VM's restore handoff, checked whole: a
/// vault VM's `--restore` start, on a channel revision this build speaks.
pub(super) fn restore_handoff(args: &ServeArgs) -> Result<bool, ManagedError> {
    let Some(revision) = args.vm_restore_revision else {
        return Ok(false);
    };
    if !args.vsock_guest || !args.restore {
        return Err(ManagedError::ConflictingFlag {
            flag: "vm-restore-revision",
            reason: "it hands a vault VM's --restore start its pipes, and this is no such start",
        });
    }
    if revision != VM_RESTORE_WIRE_REVISION {
        return Err(ManagedError::RestoreFlagsRejected {
            reason: "--vm-restore-revision names a restore channel revision this build does not speak",
        });
    }
    Ok(true)
}

/// Refuses a vault VM's two restore pipes when they name one descriptor:
/// each has its own owner, which closes what it holds.
pub(super) fn refuse_pipe_alias(input_fd: RawFd, result_fd: RawFd) -> Result<(), ManagedError> {
    if input_fd == result_fd {
        return Err(ManagedError::AliasedFd {
            first: "--restore-input-fd",
            second: "--restore-result-fd",
            fd: input_fd,
        });
    }
    Ok(())
}

/// A vault VM's custody anchor handoff from its bootstrap, checked whole
/// (FIX 6517): the URL the host bound the boot to and the socket that
/// reaches it, when the host bound one. Its URL is never printed.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct VmAnchorHandoff {
    route: Option<(String, PathBuf)>,
}

impl fmt::Debug for VmAnchorHandoff {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VmAnchorHandoff")
            .field("url", &self.route.as_ref().map(|_| "<bound>"))
            .field("socket", &self.route.as_ref().map(|(_, socket)| socket))
            .finish()
    }
}

impl VmAnchorHandoff {
    /// The URL the host bound, exactly as configured, and the bootstrap's
    /// socket that reaches it.
    pub(crate) fn route(&self) -> Option<(&str, &Path)> {
        self.route
            .as_ref()
            .map(|(url, socket)| (url.as_str(), socket.as_path()))
    }
}

/// The custody anchor handoff argv carries, checked whole: a vault VM's,
/// on an exchange revision this build speaks, its URL and socket together,
/// and the credential pipe only beside a URL and apart from the restore's
/// pipes. A vault VM start without it takes no credential pipe.
pub(super) fn anchor_handoff(args: &ServeArgs) -> Result<Option<VmAnchorHandoff>, ManagedError> {
    let Some(revision) = args.vm_anchor_revision else {
        if args.vsock_guest && args.custody_anchor_credentials_fd.is_some() {
            return Err(ManagedError::ConflictingFlag {
                flag: "custody-anchor-credentials-fd",
                reason: VSOCK_NO_PIPE_REASON,
            });
        }
        return Ok(None);
    };
    if !args.vsock_guest {
        return Err(ManagedError::ConflictingFlag {
            flag: "vm-anchor-revision",
            reason: "it hands a vault VM's engine its custody anchor, and this is no vault VM",
        });
    }
    if revision != VM_ANCHOR_WIRE_REVISION {
        return Err(ManagedError::CustodyAnchorCredentialsRejected {
            reason: "--vm-anchor-revision is not an exchange revision this build speaks".into(),
        });
    }
    let route = match (&args.vm_anchor_url, &args.vm_anchor_socket) {
        (Some(url), Some(socket)) if socket == Path::new(VM_GUEST_ANCHOR_SOCKET) => {
            Some((url.clone(), socket.clone()))
        }
        (None, None) => None,
        _ => {
            return Err(ManagedError::ConflictingFlag {
                flag: "vm-anchor-socket",
                reason: "a vault VM's anchor URL comes with its bootstrap's own socket to it, and neither without the other",
            });
        }
    };
    if let Some(anchor) = args.custody_anchor_credentials_fd {
        if route.is_none() {
            return Err(ManagedError::ConflictingFlag {
                flag: "custody-anchor-credentials-fd",
                reason: "a vault VM's custody anchor credential is for the URL its host bound, and it bound none",
            });
        }
        for (second, fd) in [
            ("--restore-input-fd", args.restore_input_fd),
            ("--restore-result-fd", args.restore_result_fd),
        ] {
            if fd == Some(anchor) {
                return Err(ManagedError::AliasedFd {
                    first: "--custody-anchor-credentials-fd",
                    second,
                    fd: anchor,
                });
            }
        }
    }
    Ok(Some(VmAnchorHandoff { route }))
}
