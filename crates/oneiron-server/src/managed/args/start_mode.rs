//! How a managed process starts: an ordinary open or a cold restore.

use std::os::fd::RawFd;

use crate::config::ServeArgs;

use super::{ManagedError, require_fd};

/// How a managed process starts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManagedStartMode {
    /// It opens the vault at `--data-dir`, as every start before restore did.
    Open,
    /// It restores the vault the plan on `input_fd` names into `--data-dir`
    /// first, and reports on `result_fd` (`--restore`, LC FIX 5384/5385).
    Restore { input_fd: RawFd, result_fd: RawFd },
}

impl ManagedStartMode {
    /// The start mode argv names: a cold restore with both its pipes, or
    /// the ordinary open. Its pipes alone, or a restore in a vault VM, which
    /// inherits no descriptors, are refused.
    pub(super) fn of(args: &ServeArgs) -> Result<Self, ManagedError> {
        if !args.restore {
            if args.restore_input_fd.is_some() || args.restore_result_fd.is_some() {
                return Err(ManagedError::RestoreFlagsRejected {
                    reason: "--restore-input-fd and --restore-result-fd belong to a --restore start",
                });
            }
            return Ok(Self::Open);
        }
        if args.vsock_guest {
            return Err(ManagedError::ConflictingFlag {
                flag: "restore",
                reason: "a vault VM inherits no descriptors, and its vsock boot channel carries no restore pipes",
            });
        }
        Ok(Self::Restore {
            input_fd: require_fd(args.restore_input_fd, "restore-input-fd")?,
            result_fd: require_fd(args.restore_result_fd, "restore-result-fd")?,
        })
    }
}
