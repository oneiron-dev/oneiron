//! Linux-only PID-1 setup, isolated execution, and final-delivery custody.
//!
//! Rootfs must provide /proc, /sys, /dev, /run, /tmp and /mnt directories.
//! Kernel needs procfs, sysfs, devtmpfs, tmpfs, OverlayFS, cgroup v2 with pids,
//! virtio block/ext4, and virtio-vsock. There is no non-VM fallback here.

use crate::{Error, Result, filesystem::Workspace, protocol::Session, runtime};
use std::{
    ffi::CStr,
    fs::{self, File},
    os::fd::{AsRawFd, FromRawFd},
    path::Path,
};

const UID: u32 = 65534;
const GID: u32 = 65534;
const CGROUP: &str = "/sys/fs/cgroup/oneiron";

/// Boots the production agent. Refuses all callers except root Linux PID 1.
///
/// PID 1 receives the trusted snapshot, mounts its lower tree read-only, then
/// forks before constructing Wasmtime. The child joins pids.max, drops groups
/// and all saved IDs, and sets no-new-privileges. PID 1 sends finish only AFTER
/// reaping the child, then remains alive until the host kills the owned VM.
pub fn run() -> Result<()> {
    // SAFETY: getpid/geteuid have no pointer or ownership preconditions.
    if unsafe { libc::getpid() != 1 || libc::geteuid() != 0 } {
        return Err(Error::Runtime("production agent requires root Linux PID 1"));
    }
    mount_system()?;
    let mut session = Session::new(connect_vsock()?);
    let preparation: Result<_> = (|| {
        let input = session.receive()?;
        prepare_workspace(&input.files)?;
        prepare_pids(input.pids)?;
        let workspace = Workspace::open(Path::new("/mnt/workspace"))?;
        let signals = block_sigchld()?;
        Ok((input, workspace, signals))
    })();
    let (input, workspace, signals) = match preparation {
        Ok(value) => value,
        Err(error) => {
            let _ = session.finish(1);
            // No reboot/poweroff race with the final vsock bytes.
            let signals = block_sigchld()?;
            drop(error);
            await_host_shutdown(&signals);
        }
    };
    // SAFETY: PID 1 has created no worker threads, Wasmtime engine, or signal
    // handlers before fork. Both branches exclusively own their copied state.
    let child = unsafe { libc::fork() };
    if child == 0 {
        let status = match restrict_child(input.pids) {
            Ok(()) => {
                let (_, outcome) = runtime::execute(session, input, workspace);
                i32::from(outcome.is_err())
            }
            Err(_) => 1,
        };
        // SAFETY: this is the fork child. No unwinding or inherited runtime
        // cleanup runs; kernel closes descriptors. PID 1 owns final delivery.
        unsafe { libc::_exit(status) };
    }
    let status = if child < 0 { 1 } else { wait_child(child) };
    let _ = session.finish(status);
    await_host_shutdown(&signals);
}

fn mount_system() -> Result<()> {
    mount(None, c"/", None, libc::MS_REC | libc::MS_PRIVATE, None)?;
    mount(
        Some(c"proc"),
        c"/proc",
        Some(c"proc"),
        libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
        None,
    )?;
    mount(
        Some(c"sysfs"),
        c"/sys",
        Some(c"sysfs"),
        libc::MS_RDONLY | libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
        None,
    )?;
    mount_devices()?;
    mount(
        Some(c"tmpfs"),
        c"/run",
        Some(c"tmpfs"),
        libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
        Some(c"size=128m,nr_inodes=65536,mode=0755"),
    )?;
    mount(
        Some(c"tmpfs"),
        c"/tmp",
        Some(c"tmpfs"),
        libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
        Some(c"size=16m,nr_inodes=1024,mode=1777"),
    )?;
    mount(
        Some(c"tmpfs"),
        c"/mnt",
        Some(c"tmpfs"),
        libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
        Some(c"size=1m,nr_inodes=32,mode=0755"),
    )?;
    mount(
        Some(c"cgroup2"),
        c"/sys/fs/cgroup",
        Some(c"cgroup2"),
        libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
        None,
    )
}

// CONFIG_DEVTMPFS_MOUNT kernels mount /dev before invoking PID 1. devtmpfs
// refuses a second mount with EBUSY; harden that existing mount instead. Never
// accept an unrelated filesystem at this privileged device mountpoint.
fn mount_devices() -> Result<()> {
    let mountinfo = fs::read_to_string("/proc/self/mountinfo")?;
    let mut flags = libc::MS_NOSUID | libc::MS_NOEXEC;
    for line in mountinfo.lines() {
        let Some((fields, filesystem)) = line.split_once(" - ") else {
            return Err(Error::Runtime("invalid kernel mount table"));
        };
        if fields.split_whitespace().nth(4) == Some("/dev") {
            if filesystem.split_whitespace().next() != Some("devtmpfs") {
                return Err(Error::Runtime("unexpected device filesystem"));
            }
            flags |= libc::MS_REMOUNT;
        }
    }
    mount(
        Some(c"devtmpfs"),
        c"/dev",
        Some(c"devtmpfs"),
        flags,
        Some(c"mode=0755"),
    )
}

fn prepare_workspace(files: &crate::protocol::Snapshot) -> Result<()> {
    for directory in [
        "/run/oneiron",
        "/run/oneiron/lower",
        "/run/oneiron/upper",
        "/run/oneiron/work",
        "/mnt/workspace",
    ] {
        fs::create_dir(directory)?;
    }
    let lower = Workspace::open(Path::new("/run/oneiron/lower"))?;
    lower.seed(files)?;
    lower.set_owner(UID, GID)?;
    drop(lower);
    std::os::unix::fs::chown("/run/oneiron/upper", Some(UID), Some(GID))?;
    // Bind-remount isolates the seeded subtree's mount flags from the writable
    // state tmpfs that also holds upper and work directories.
    mount(
        Some(c"/run/oneiron/lower"),
        c"/run/oneiron/lower",
        None,
        libc::MS_BIND,
        None,
    )?;
    mount(
        None,
        c"/run/oneiron/lower",
        None,
        libc::MS_BIND
            | libc::MS_REMOUNT
            | libc::MS_RDONLY
            | libc::MS_NOSUID
            | libc::MS_NODEV
            | libc::MS_NOEXEC,
        None,
    )?;
    mount(
        Some(c"overlay"),
        c"/mnt/workspace",
        Some(c"overlay"),
        libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
        Some(c"lowerdir=/run/oneiron/lower,upperdir=/run/oneiron/upper,workdir=/run/oneiron/work"),
    )
}

fn prepare_pids(pids: u32) -> Result<()> {
    if !(1..=4096).contains(&pids) {
        return Err(Error::Runtime("guest pids limit"));
    }
    let controllers = fs::read_to_string("/sys/fs/cgroup/cgroup.controllers")?;
    if !controllers.split_whitespace().any(|name| name == "pids") {
        return Err(Error::Runtime("pids controller unavailable"));
    }
    fs::write("/sys/fs/cgroup/cgroup.subtree_control", "+pids")?;
    fs::create_dir(CGROUP)?;
    fs::write(format!("{CGROUP}/pids.max"), pids.to_string())?;
    Ok(())
}

fn restrict_child(pids: u32) -> Result<()> {
    // Joining precedes dropping privilege. Every later runtime thread inherits
    // this cgroup. PID 1 remains outside it so it can always reap the child.
    fs::write(format!("{CGROUP}/cgroup.procs"), "0")?;
    limit(libc::RLIMIT_NPROC, u64::from(pids))?;
    limit(libc::RLIMIT_NOFILE, 64)?;
    limit(libc::RLIMIT_CORE, 0)?;
    limit(libc::RLIMIT_FSIZE, crate::protocol::MAX_FILE as u64)?;
    // SAFETY: these process-local operations run only in the single fork child;
    // setgroups receives an empty list, IDs are fixed non-root IDs, and prctl
    // arguments match the documented integer-only options.
    let result = unsafe {
        libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0
            && libc::prctl(libc::PR_SET_KEEPCAPS, 0, 0, 0, 0) == 0
            && libc::setgroups(0, std::ptr::null()) == 0
            && libc::setresgid(GID, GID, GID) == 0
            && libc::setresuid(UID, UID, UID) == 0
            && libc::getuid() == UID
            && libc::geteuid() == UID
            && libc::getgid() == GID
            && libc::getegid() == GID
            && libc::prctl(libc::PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) == 1
    };
    if !result {
        return Err(Error::Runtime("child privilege drop failed"));
    }
    Ok(())
}

#[cfg(target_env = "musl")]
type LimitResource = libc::c_int;
#[cfg(not(target_env = "musl"))]
type LimitResource = libc::__rlimit_resource_t;

fn limit(resource: LimitResource, maximum: u64) -> Result<()> {
    let limit = libc::rlimit {
        rlim_cur: maximum as libc::rlim_t,
        rlim_max: maximum as libc::rlim_t,
    };
    // SAFETY: limit is initialized and this is the child process's own resource.
    if unsafe { libc::setrlimit(resource, &limit) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}

fn mount(
    source: Option<&CStr>,
    target: &CStr,
    kind: Option<&CStr>,
    flags: libc::c_ulong,
    data: Option<&CStr>,
) -> Result<()> {
    // SAFETY: each optional argument is either NULL or a valid C string for
    // the duration of mount; the flags and filesystem options are trusted.
    if unsafe {
        libc::mount(
            source.map_or(std::ptr::null(), CStr::as_ptr),
            target.as_ptr(),
            kind.map_or(std::ptr::null(), CStr::as_ptr),
            flags,
            data.map_or(std::ptr::null(), |value| value.as_ptr().cast()),
        )
    } != 0
    {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}

fn connect_vsock() -> Result<File> {
    // SAFETY: socket has no pointer arguments and returns a new owned fd.
    let fd = unsafe { libc::socket(libc::AF_VSOCK, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    // SAFETY: successful socket returned an owned descriptor, now managed by File.
    let socket = unsafe { File::from_raw_fd(fd) };
    // SAFETY: zero is valid padding/reserved initialization for sockaddr_vm.
    let mut address: libc::sockaddr_vm = unsafe { std::mem::zeroed() };
    address.svm_family = libc::AF_VSOCK as libc::sa_family_t;
    address.svm_cid = 2;
    address.svm_port = 52;
    // SAFETY: address is initialized and length exactly matches sockaddr_vm.
    if unsafe {
        libc::connect(
            socket.as_raw_fd(),
            (&raw const address).cast(),
            std::mem::size_of_val(&address) as libc::socklen_t,
        )
    } != 0
    {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(socket)
}

fn wait_child(child: libc::pid_t) -> i32 {
    let mut status = 0;
    loop {
        // SAFETY: child is our positive fork result; status points to writable int.
        let result = unsafe { libc::waitpid(child, &mut status, 0) };
        if result == child {
            return if libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0 {
                0
            } else {
                1
            };
        }
        if result < 0 && std::io::Error::last_os_error().kind() != std::io::ErrorKind::Interrupted {
            return 1;
        }
    }
}

fn block_sigchld() -> Result<libc::sigset_t> {
    let mut signals = std::mem::MaybeUninit::<libc::sigset_t>::uninit();
    // SAFETY: sigemptyset initializes signals before sigaddset/sigprocmask use it.
    let result = unsafe {
        libc::sigemptyset(signals.as_mut_ptr()) == 0
            && libc::sigaddset(signals.as_mut_ptr(), libc::SIGCHLD) == 0
            && libc::sigprocmask(libc::SIG_BLOCK, signals.as_ptr(), std::ptr::null_mut()) == 0
    };
    if !result {
        return Err(std::io::Error::last_os_error().into());
    }
    // SAFETY: sigemptyset and sigaddset both succeeded.
    Ok(unsafe { signals.assume_init() })
}

fn await_host_shutdown(signals: &libc::sigset_t) -> ! {
    loop {
        let mut status = 0;
        // SAFETY: PID 1 owns reaping of all adopted children. WNOHANG prevents
        // a live adopted child from blocking reaping other already dead children.
        while unsafe { libc::waitpid(-1, &mut status, libc::WNOHANG) } > 0 {}
        // SAFETY: SIGCHLD is blocked and signals is initialized. No mutable
        // global signal handler is needed; this atomically waits for next reap.
        unsafe { libc::sigwaitinfo(signals, std::ptr::null_mut()) };
    }
}
