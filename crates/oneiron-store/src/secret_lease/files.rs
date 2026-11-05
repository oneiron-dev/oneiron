//! T2 file policy, owner-only write, the armed cleanup guard, and teardown.
//!
//! Custody follows the file the vault wrote, not the path string (C9). On
//! unix the target's directory is reached one component at a time through
//! descriptors that never follow a symlink, the file is opened relative to
//! that directory, and its device and inode are recorded on the registration
//! row. Re-materialization writes only into that same file, and teardown
//! unlinks only that same file, and only while it has no other name. Anything
//! else at the name is refused and left in place. A second walk after the
//! open refuses a write whose directory has left the path meanwhile.

use std::fs;
use std::path::Path;

use oneiron_base::error::Error;
use oneiron_base::error::Result;
use oneiron_base::error::SecretError;

pub fn refused(path: &Path, reason: &'static str) -> Error {
    Error::Secret(SecretError::SecretLeasePathRefused {
        path: path.display().to_string(),
        reason,
    })
}

/// Names what occupies `path` after an open or create refused it. Only the
/// refusal's reason is read from the path; the operation has already failed
/// closed. `file_reason` names a regular file that was already there.
#[cfg(unix)]
pub fn refuse_occupant(path: &Path, error: std::io::Error, file_reason: &'static str) -> Error {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            refused(path, "target is a symlink (the vault never follows)")
        }
        Ok(metadata) if !metadata.file_type().is_file() => {
            refused(path, "target exists and is not a regular file")
        }
        Ok(_) if error.kind() == std::io::ErrorKind::AlreadyExists => refused(path, file_reason),
        _ => error.into(),
    }
}

#[cfg(any(test, feature = "test-support"))]
pub mod file_write_fault_hook {
    //! One-shot test-only fault injection after the T2 file opens, proving
    //! the guard is armed before a file write can fail.

    use std::cell::Cell;

    thread_local! {
        static FILE_WRITE_FAILURE: Cell<bool> = const { Cell::new(false) };
    }

    /// Arms a one-shot file-write failure on the current thread.
    pub fn arm_file_write_failure() {
        FILE_WRITE_FAILURE.with(|c| c.set(true));
    }

    /// Returns and clears the armed flag (one-shot).
    pub fn take_file_write_failure() -> bool {
        FILE_WRITE_FAILURE.with(|c| c.replace(false))
    }
}

#[cfg(all(any(test, feature = "test-support"), unix))]
pub mod path_swap_hook {
    //! One-shot test-only seams in a T2 file write, the windows a racing local
    //! process would use.

    use std::cell::RefCell;

    /// Where in the write a seam runs.
    #[derive(Clone, Copy, PartialEq, Eq)]
    pub enum Stage {
        /// After the target's directory is resolved, before its file opens:
        /// an ancestor can be swapped here.
        BeforeOpen,
        /// After the file opens, before it is checked: it can gain a name here.
        AfterOpen,
    }

    type Swap = Box<dyn FnOnce()>;

    thread_local! {
        static SWAP: RefCell<Option<(Stage, Swap)>> = const { RefCell::new(None) };
    }

    /// Runs `swap` once, at `stage` of the next T2 file write on this thread.
    pub fn arm(stage: Stage, swap: impl FnOnce() + 'static) {
        SWAP.with_borrow_mut(|armed| *armed = Some((stage, Box::new(swap))));
    }

    pub fn fire(stage: Stage) {
        let swap = SWAP.with_borrow_mut(|armed| match armed.take() {
            Some((at, swap)) if at == stage => Some(swap),
            other => {
                *armed = other;
                None
            }
        });
        if let Some(swap) = swap {
            swap();
        }
    }
}
