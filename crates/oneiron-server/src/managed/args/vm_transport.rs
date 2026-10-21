//! A vault VM's cold restore handoff (FIX 6584): `--vm-restore-revision`,
//! which only the image's `oneiron-vm-init` passes, beside `--restore` and
//! the two pipes it made and carries over the host's restore channel. The
//! flag grants nothing by itself: the bootstrap checked the live channel
//! and the vault's binding before it started the engine, and the restore
//! still proves each pipe's end before it reads a byte. A `--vsock-guest`
//! start without it takes no restore pipes, as before.

use std::os::fd::RawFd;

use oneiron_vault_contract::vm_restore::VM_RESTORE_WIRE_REVISION;

use crate::config::ServeArgs;

use super::ManagedError;

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
