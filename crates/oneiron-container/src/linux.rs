//! Linux UAPI used on both sides of the seccomp listener.

use std::ffi::CString;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};

pub(crate) const CONTINUE: u32 = 1;
const NOTIF_RECV: libc::c_ulong = 0xc050_2100;
const NOTIF_SEND: libc::c_ulong = 0xc018_2101;
const NOTIF_VALID: libc::c_ulong = 0x4008_2102;
const NOTIF_ADDFD: libc::c_ulong = 0x4018_2103;

// Linux asm-generic/fcntl.h commands that libc does not expose on every target.
const F_SETSIG: u32 = 10;
const F_SETOWN_EX: u32 = 15;

#[repr(C)]
#[derive(Default, Clone, Copy)]
pub(crate) struct Data {
    pub nr: i32,
    pub arch: u32,
    pub ip: u64,
    pub args: [u64; 6],
}
#[repr(C)]
#[derive(Default, Clone, Copy)]
pub(crate) struct Notification {
    pub id: u64,
    pub pid: u32,
    pub flags: u32,
    pub data: Data,
}
#[repr(C)]
#[derive(Default)]
struct Response {
    id: u64,
    value: i64,
    error: i32,
    flags: u32,
}
#[repr(C)]
struct AddFd {
    id: u64,
    flags: u32,
    srcfd: u32,
    newfd: u32,
    newfd_flags: u32,
}

pub(crate) fn receive(listener: RawFd) -> io::Result<Notification> {
    let mut notification = Notification::default();
    // SAFETY: notification has the exact Linux seccomp_notif layout.
    if unsafe { libc::ioctl(listener, NOTIF_RECV, &mut notification) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(notification)
}
pub(crate) fn valid(listener: RawFd, id: u64) -> io::Result<()> {
    // SAFETY: the ioctl reads a live u64 notification id.
    if unsafe { libc::ioctl(listener, NOTIF_VALID, &id) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}
pub(crate) fn respond(
    listener: RawFd,
    id: u64,
    value: i64,
    errno: i32,
    flags: u32,
) -> io::Result<()> {
    let response = Response {
        id,
        value,
        error: -errno.abs(),
        flags,
    };
    // SAFETY: response has the exact seccomp_notif_resp layout.
    if unsafe { libc::ioctl(listener, NOTIF_SEND, &response) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}
pub(crate) fn inject(listener: RawFd, id: u64, fd: RawFd, cloexec: bool) -> io::Result<i32> {
    // SEND atomically adds the fd and completes the call with it as the
    // result: socket(), and accept() of a virtual loopback connection. The
    // fence never swaps an occupied fd (SETFD could, but dup aliases and
    // epoll registrations would keep the old socket).
    let add = AddFd {
        id,
        flags: 2,
        srcfd: fd as u32,
        newfd: 0,
        newfd_flags: if cloexec { libc::O_CLOEXEC as u32 } else { 0 },
    };
    // SAFETY: add has the exact seccomp_notif_addfd layout.
    let result = unsafe { libc::ioctl(listener, NOTIF_ADDFD, &add) };
    if result < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(result)
    }
}

const READ: u64 = (1 << 0) | (1 << 2) | (1 << 3);
const WRITE: u64 = ((1 << 15) - 1) & !READ;
pub(crate) const PATHS: &[(&str, bool)] = &[
    ("/usr", false),
    ("/bin", false),
    ("/sbin", false),
    ("/lib", false),
    ("/lib64", false),
    ("/etc", false),
    ("/proc", false),
    ("/sys", false),
    ("/srv", false),
    ("/mnt", false),
    ("/tmp", true),
    ("/dev/shm", true),
    ("/dev/null", true),
    ("/dev/zero", false),
    ("/dev/urandom", false),
    ("/dev/random", false),
];

pub(crate) fn ruleset_hash() -> String {
    let bytes = serde_json::to_vec(&(3, READ | WRITE, PATHS)).expect("static fence rules");
    blake3::hash(&bytes).to_hex().to_string()
}

pub(crate) fn landlock() -> io::Result<i32> {
    #[repr(C)]
    struct Ruleset {
        handled_access_fs: u64,
    }
    #[repr(C, packed)]
    struct PathRule {
        allowed_access: u64,
        parent_fd: i32,
    }
    // SAFETY: version query takes null attributes and zero size.
    let abi = unsafe { libc::syscall(libc::SYS_landlock_create_ruleset, 0, 0, 1) } as i32;
    if abi < 3 {
        return Err(io::Error::other("Landlock ABI 3 is required"));
    }
    let attr = Ruleset {
        handled_access_fs: READ | WRITE,
    };
    // SAFETY: attr has the ABI-3 landlock_ruleset_attr prefix and exact size.
    let fd = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            &attr,
            std::mem::size_of_val(&attr),
            0,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: successful create_ruleset returns an owned descriptor.
    let ruleset = unsafe { OwnedFd::from_raw_fd(fd as i32) };
    for &(path, writable) in PATHS {
        let path = CString::new(path).map_err(io::Error::other)?;
        // SAFETY: path is NUL terminated; O_PATH obtains only a path handle.
        let fd = unsafe { libc::open(path.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) };
        if fd < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::NotFound {
                continue;
            }
            return Err(error);
        }
        // SAFETY: open returned a new owned descriptor.
        let parent = unsafe { OwnedFd::from_raw_fd(fd) };
        let metadata = std::fs::metadata(path.to_str().map_err(io::Error::other)?)?;
        let mut rights = if writable { READ | WRITE } else { READ };
        if !metadata.is_dir() {
            rights &= (1 << 0) | (1 << 1) | (1 << 2) | (1 << 14);
        }
        let rule = PathRule {
            allowed_access: rights,
            parent_fd: parent.as_raw_fd(),
        };
        // SAFETY: rule has the packed landlock_path_beneath_attr layout.
        if unsafe {
            libc::syscall(
                libc::SYS_landlock_add_rule,
                ruleset.as_raw_fd(),
                1,
                &rule,
                0,
            )
        } < 0
        {
            return Err(io::Error::last_os_error());
        }
    }
    // SAFETY: these syscalls restrict only this process and its descendants.
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0
        || unsafe { libc::syscall(libc::SYS_landlock_restrict_self, ruleset.as_raw_fd(), 0) } < 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(abi)
}

fn stmt(code: u16, k: u32) -> libc::sock_filter {
    libc::sock_filter {
        code,
        jt: 0,
        jf: 0,
        k,
    }
}
fn jump(k: u32, jt: u8, jf: u8) -> libc::sock_filter {
    libc::sock_filter {
        code: 0x15,
        jt,
        jf,
        k,
    }
}

fn filter(parent: u32, bootstrap_fd: i32) -> Vec<libc::sock_filter> {
    #[cfg(target_arch = "x86_64")]
    let arch = 0xc000_003e;
    #[cfg(target_arch = "aarch64")]
    let arch = 0xc000_00b7;
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    let arch = 0;
    let mut out = vec![
        stmt(0x20, 4),
        jump(arch, 1, 0),
        stmt(0x06, 0x8000_0000),
        stmt(0x20, 0),
    ];
    // x32 must not bypass the native syscall numbers.
    out.extend([
        libc::sock_filter {
            code: 0x45,
            jt: 0,
            jf: 1,
            k: 0x4000_0000,
        },
        stmt(0x06, 0x8000_0000),
    ]);
    // Only this CLOEXEC bootstrap channel can transfer the listener before
    // the parent has it. It disappears at exec and carries no host socket.
    out.extend([
        jump(libc::SYS_sendmsg as u32, 0, 4),
        stmt(0x20, 16),
        jump(bootstrap_fd as u32, 0, 1),
        stmt(0x06, 0x7fff_0000),
        stmt(0x20, 0),
    ]);
    // Namespace creation would hide syscall arguments from the parent broker.
    out.extend([
        jump(libc::SYS_clone as u32, 0, 4),
        stmt(0x20, 16),
        libc::sock_filter {
            code: 0x45,
            jt: 0,
            jf: 1,
            k: 0x7e02_0000,
        },
        stmt(0x06, 0x0005_0000 | libc::EPERM as u32),
        stmt(0x20, 0),
    ]);
    out.extend([
        jump(libc::SYS_clone3 as u32, 0, 1),
        stmt(0x06, 0x0005_0000 | libc::ENOSYS as u32),
    ]);
    for nr in [
        libc::SYS_socket,
        libc::SYS_connect,
        libc::SYS_sendto,
        libc::SYS_sendmsg,
        libc::SYS_sendmmsg,
        libc::SYS_recvfrom,
        libc::SYS_recvmsg,
        libc::SYS_recvmmsg,
        libc::SYS_getpeername,
        libc::SYS_getsockname,
        libc::SYS_setsockopt,
        libc::SYS_getsockopt,
        // Guest-loopback listeners; a native socket's call continues.
        libc::SYS_bind,
        libc::SYS_listen,
        libc::SYS_accept,
        libc::SYS_accept4,
    ] {
        out.extend([jump(nr as u32, 0, 1), stmt(0x06, 0x7fc0_0000)]);
    }
    // Only network and supervisor-escape mechanisms are refused. Ordinary
    // computation is not a syscall allowlist.
    for nr in [
        libc::SYS_ptrace,
        libc::SYS_process_vm_readv,
        libc::SYS_process_vm_writev,
        libc::SYS_pidfd_getfd,
        libc::SYS_pidfd_send_signal,
        libc::SYS_io_uring_setup,
        libc::SYS_bpf,
        libc::SYS_setns,
        libc::SYS_unshare,
        libc::SYS_mount,
        libc::SYS_setpgid,
        libc::SYS_setsid,
        libc::SYS_setuid,
        libc::SYS_setgid,
        libc::SYS_setresuid,
        libc::SYS_setresgid,
        libc::SYS_tkill,
    ] {
        out.extend([
            jump(nr as u32, 0, 1),
            stmt(0x06, 0x0005_0000 | libc::EPERM as u32),
        ]);
    }
    for nr in [
        libc::SYS_kill,
        libc::SYS_tgkill,
        libc::SYS_rt_sigqueueinfo,
        libc::SYS_rt_tgsigqueueinfo,
    ] {
        out.extend([
            jump(nr as u32, 0, 7),
            stmt(0x20, 16),
            jump(parent, 3, 0),
            jump(0, 2, 0),
            libc::sock_filter {
                code: 0x45,
                jt: 1,
                jf: 0,
                k: 0x8000_0000,
            },
            stmt(0x06, 0x7fff_0000),
            stmt(0x06, 0x0005_0000 | libc::EPERM as u32),
            stmt(0x20, 0),
        ]);
    }
    out.extend([
        jump(libc::SYS_fcntl as u32, 0, 8),
        stmt(0x20, 24),
        jump(libc::F_SETOWN as u32, 4, 0),
        jump(F_SETSIG, 3, 0),
        jump(F_SETOWN_EX, 2, 0),
        stmt(0x06, 0x7fff_0000),
        stmt(0x20, 0),
        stmt(0x06, 0x0005_0000 | libc::EPERM as u32),
        stmt(0x20, 0),
    ]);
    out.extend([
        jump(libc::SYS_ioctl as u32, 0, 6),
        stmt(0x20, 24),
        jump(0x8901, 2, 0),
        jump(0x8902, 1, 0),
        stmt(0x06, 0x7fff_0000),
        stmt(0x06, 0x0005_0000 | libc::EPERM as u32),
        stmt(0x20, 0),
    ]);
    // Keep descendants inspectable by the unprivileged parent supervisor.
    out.extend([
        jump(libc::SYS_prctl as u32, 0, 4),
        stmt(0x20, 16),
        jump(libc::PR_SET_DUMPABLE as u32, 0, 1),
        stmt(0x06, 0x0005_0000),
        stmt(0x06, 0x7fff_0000),
    ]);
    out.push(stmt(0x06, 0x7fff_0000));
    out
}

pub(crate) fn filter_hash(parent: u32, bootstrap_fd: i32) -> String {
    let mut hash = blake3::Hasher::new();
    for op in filter(parent, bootstrap_fd) {
        hash.update(&op.code.to_le_bytes());
        hash.update(&[op.jt, op.jf]);
        hash.update(&op.k.to_le_bytes());
    }
    hash.finalize().to_hex().to_string()
}

pub(crate) fn install(parent: u32, bootstrap_fd: i32) -> io::Result<OwnedFd> {
    let mut code = filter(parent, bootstrap_fd);
    let program = libc::sock_fprog {
        len: code.len() as u16,
        filter: code.as_mut_ptr(),
    };
    // SAFETY: program points to a live, bounded classic BPF instruction array.
    let fd = unsafe { libc::syscall(libc::SYS_seccomp, 1, 8, &program) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: NEW_LISTENER returns a new owned fd.
    Ok(unsafe { OwnedFd::from_raw_fd(fd as i32) })
}
