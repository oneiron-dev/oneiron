//! The per-job directories root makes on the machine's own tree before the
//! job's view is built, and takes away after the job: the exchange directory
//! (`exec.json`, and the gate's socket while the gate waits) and the
//! payload's bind source.
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
    self, borrow, make_dir_beneath, open_dir_beneath, open_dir_path, remove_beneath, write_beneath,
};
use super::step::StepContext;
use super::{EXCHANGE_ROOT, EXEC_FILE_NAME, GATE_SOCKET_NAME, PAYLOAD_ROOT};

/// Makes the job's exchange directory fresh (root, mode 0750, the job
/// account's group) with `exec.json` in it. The gate binds its socket there
/// once it runs ([`super::gate`]).
///
/// # Errors
///
/// A step that failed.
pub fn write_exchange(context: &StepContext, exec: &ExecFile) -> Result<(), String> {
    let root = root_dir(EXCHANGE_ROOT, 0o755).map_err(|why| format!("exchange_root: {why}"))?;
    let name = exec.instance.as_str();
    if let Ok(stale) = open_dir_beneath(borrow(&root), OsStr::new(name)) {
        for file in EXCHANGE_FILES {
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
    Ok(())
}

/// Every name the exchange directory may hold, with `exec.json`'s staging
/// name (review r3 R3-10), and the two report and go pipes a binary from
/// before the gate's socket made there. Those two are only ever removed,
/// never made or opened, so an exchange that an older binary left behind in
/// `/run` (an interrupted job, then an update in place) does not fail the
/// next prepare as not fresh (review r7 R7-05).
const EXCHANGE_FILES: [&str; 5] = [
    EXEC_FILE_NAME,
    EXEC_STAGING_NAME,
    GATE_SOCKET_NAME,
    LEGACY_REPORT_PIPE_NAME,
    LEGACY_GO_PIPE_NAME,
];

/// The report pipe of a binary from before the gate's socket.
const LEGACY_REPORT_PIPE_NAME: &str = "report";

/// The go pipe of a binary from before the gate's socket.
const LEGACY_GO_PIPE_NAME: &str = "go";

/// `exec.json` while [`write_beneath`] writes it.
const EXEC_STAGING_NAME: &str = "exec.json.new";

/// A root directory under `/run` ([`EXCHANGE_ROOT`] or [`PAYLOAD_ROOT`]),
/// made when absent (a second maker at once is no error), opened, and given
/// `mode` on the opened directory every time, so a root that was there
/// before with a wider mode is narrowed (review r3 R3-07).
///
/// # Errors
///
/// It could not be made, it is not root's alone, or it does not open.
pub fn root_dir(path: &str, mode: u32) -> Result<OwnedFd, String> {
    let c = CString::new(path).map_err(|error| error.to_string())?;
    // SAFETY: c is NUL terminated; the umask can only narrow the mode.
    if unsafe { libc::mkdir(c.as_ptr(), mode as libc::mode_t) } != 0 {
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::AlreadyExists {
            return Err(format!("{path}: {error}"));
        }
    }
    let path = Path::new(path);
    safe_fs::require_root_owned(path)?;
    let dir = open_dir_path(path).map_err(|error| error.to_string())?;
    let found = safe_fs::facts(borrow(&dir)).map_err(|error| error.to_string())?;
    if found.uid != 0 {
        return Err(format!("{}: not root's", path.display()));
    }
    // SAFETY: dir is the root-owned directory this call opened.
    if unsafe { libc::fchmod(dir.as_raw_fd(), mode as libc::mode_t) } != 0 {
        return Err(format!(
            "{}: {}",
            path.display(),
            io::Error::last_os_error()
        ));
    }
    Ok(dir)
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
    super::job_cache::withdraw(instance);
    let target = Path::new(PAYLOAD_ROOT).join(instance);
    if let Ok(c) = CString::new(target.as_os_str().as_bytes()) {
        // SAFETY: c is NUL terminated; the mount point is never followed as a
        // link, and a lazy detach leaves the job's own view alone.
        let _ = unsafe { libc::umount2(c.as_ptr(), libc::MNT_DETACH | libc::UMOUNT_NOFOLLOW) };
    }
    let _ = std::fs::remove_dir(&target);
    let exchange = Path::new(EXCHANGE_ROOT).join(instance);
    if let Ok(dir) = open_dir_path(&exchange) {
        for name in EXCHANGE_FILES {
            if let Err(error) = remove_beneath(borrow(&dir), name) {
                journal_line!("{}/{name}: not removed: {error}", exchange.display());
            }
        }
        drop(dir);
        if let Err(error) = std::fs::remove_dir(&exchange)
            && error.kind() != io::ErrorKind::NotFound
        {
            journal_line!("{}: not removed: {error}", exchange.display());
        }
    }
}
