//! The per-job directories root makes on the machine's own tree before the
//! job's view is built, and takes away after the job: the exchange directory
//! (`exec.json` and the two gate pipes) and the payload's bind source.
//!
//! The unit binds the payload from `<PAYLOAD_ROOT>/<instance>`, a bind mount
//! of the very directory the prepare step opened and checked, under a
//! directory only root can enter (review r2 R2-12). The service manager
//! resolves a bind source by its path and follows links in it, and the
//! engine owns the payload's own path, so that path is never the source.

use std::ffi::{CString, OsStr};
use std::io;
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt as _;
use std::path::Path;

use super::records::ExecFile;
use super::safe_fs::{
    self, borrow, make_dir_beneath, make_fifo_beneath, open_dir_beneath, open_dir_path,
    remove_beneath, write_beneath,
};
use super::step::StepContext;
use super::{EXCHANGE_ROOT, EXEC_FILE_NAME, GO_PIPE_NAME, PAYLOAD_ROOT, REPORT_PIPE_NAME};

/// Makes the job's exchange directory fresh (root, mode 0750, the job
/// account's group): `exec.json` and the two gate pipes.
///
/// # Errors
///
/// A step that failed.
pub fn write_exchange(context: &StepContext, exec: &ExecFile) -> Result<(), String> {
    let root = root_dir(EXCHANGE_ROOT, 0o755).map_err(|why| format!("exchange_root: {why}"))?;
    let name = exec.instance.as_str();
    if let Ok(stale) = open_dir_beneath(borrow(&root), OsStr::new(name)) {
        for file in [EXEC_FILE_NAME, REPORT_PIPE_NAME, GO_PIPE_NAME] {
            remove_beneath(borrow(&stale), file).map_err(|error| error.to_string())?;
        }
        drop(stale);
        let c = CString::new(name).map_err(|error| error.to_string())?;
        // SAFETY: c is NUL terminated; AT_REMOVEDIR removes an empty dir.
        if unsafe { libc::unlinkat(root.as_raw_fd(), c.as_ptr(), libc::AT_REMOVEDIR) } < 0 {
            return Err(format!(
                "exchange_not_fresh: {}",
                io::Error::last_os_error()
            ));
        }
    }
    let exchange = make_dir_beneath(borrow(&root), name, 0o750, (0, context.job_gid))
        .map_err(|error| format!("exchange_dir: {error}"))?;
    let bytes = serde_json::to_vec_pretty(exec).map_err(|error| error.to_string())?;
    write_beneath(
        borrow(&exchange),
        EXEC_FILE_NAME,
        &bytes,
        0o640,
        Some((0, context.job_gid)),
    )
    .map_err(|error| format!("exec_file: {error}"))?;
    make_fifo_beneath(borrow(&exchange), REPORT_PIPE_NAME, 0o620, context.job_gid)
        .map_err(|error| format!("report_pipe: {error}"))?;
    make_fifo_beneath(borrow(&exchange), GO_PIPE_NAME, 0o640, context.job_gid)
        .map_err(|error| format!("go_pipe: {error}"))?;
    Ok(())
}

/// A root directory under `/run` ([`EXCHANGE_ROOT`] or [`PAYLOAD_ROOT`]),
/// made root's with `mode` when absent, and then opened.
///
/// # Errors
///
/// It could not be made, it is not root's alone, or it does not open.
pub fn root_dir(path: &str, mode: u32) -> Result<OwnedFd, String> {
    let path = Path::new(path);
    if !path.exists() {
        std::fs::create_dir(path).map_err(|error| error.to_string())?;
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
            .map_err(|error| error.to_string())?;
    }
    safe_fs::require_root_owned(path)?;
    open_dir_path(path).map_err(|error| error.to_string())
}

/// Publishes `payload`, the payload directory the prepare step opened and
/// checked, as the unit's bind source `<PAYLOAD_ROOT>/<instance>`: a bind
/// mount of that directory through its descriptor, on a mount point under a
/// directory only root can enter (mode 0700).
///
/// # Errors
///
/// The mount point exists already, or a step failed.
pub fn publish_payload(instance: &str, payload: &OwnedFd) -> Result<(), String> {
    let root = root_dir(PAYLOAD_ROOT, 0o700).map_err(|why| format!("payload_root: {why}"))?;
    drop(
        make_dir_beneath(borrow(&root), instance, 0o700, (0, 0))
            .map_err(|error| format!("payload_not_fresh: {error}"))?,
    );
    let source = CString::new(format!("/proc/self/fd/{}", payload.as_raw_fd()))
        .map_err(|error| error.to_string())?;
    let target = CString::new(
        Path::new(PAYLOAD_ROOT)
            .join(instance)
            .as_os_str()
            .as_bytes(),
    )
    .map_err(|error| error.to_string())?;
    // SAFETY: both strings are NUL terminated. The source is the descriptor's
    // own directory (the kernel resolves the /proc link to it), bound without
    // its submounts onto a mount point only root reaches.
    let mounted = unsafe {
        libc::mount(
            source.as_ptr(),
            target.as_ptr(),
            std::ptr::null(),
            libc::MS_BIND,
            std::ptr::null(),
        )
    };
    if mounted != 0 {
        return Err(format!(
            "payload_not_published: {}",
            io::Error::last_os_error()
        ));
    }
    Ok(())
}

/// Takes away the payload's bind source and the exchange directory of
/// `instance` (a checked job instance). A step that fails is skipped: a
/// bind source left behind is under a directory only root enters, and goes
/// at the next boot.
pub fn withdraw(instance: &str) {
    let target = Path::new(PAYLOAD_ROOT).join(instance);
    if let Ok(c) = CString::new(target.as_os_str().as_bytes()) {
        // SAFETY: c is NUL terminated; the mount point is never followed as a
        // link, and a lazy detach leaves the job's own view alone.
        let _ = unsafe { libc::umount2(c.as_ptr(), libc::MNT_DETACH | libc::UMOUNT_NOFOLLOW) };
    }
    let _ = std::fs::remove_dir(&target);
    let exchange = Path::new(EXCHANGE_ROOT).join(instance);
    if let Ok(dir) = open_dir_path(&exchange) {
        for name in [EXEC_FILE_NAME, REPORT_PIPE_NAME, GO_PIPE_NAME] {
            let _ = remove_beneath(borrow(&dir), name);
        }
        drop(dir);
        let _ = std::fs::remove_dir(&exchange);
    }
}
