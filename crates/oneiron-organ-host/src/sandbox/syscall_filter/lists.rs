//! The calls each organ's allow-list names (FIX [ORGAN-SECCOMP-ALLOW-LIST]).
//! Traced on the fleet (x86_64, glibc) with the recorder in
//! `sandbox::syscall_trace`, through each organ's own suites, and widened to
//! each call's family, so a list from one C library and kernel does not kill
//! an organ on another: the stat calls, poll and ppoll, the dup calls, the
//! sleeps, exit and exit_group. A call an organ never makes costs nothing on
//! its list; a call it makes that its list misses kills it.
//!
//! `clone`, `clone3`, `tgkill`, `prlimit64` and `fcntl` are not on any list:
//! the program checks them, and the arguments of the last three, before the
//! list (`super::SyscallFilter::for_organ`). The legacy spellings x86_64
//! keeps (`open`, `stat`, `poll`, ...) are in the `*_X86_64` lists; aarch64's
//! table has only the modern ones.

use libc::c_long;

/// Every organ's calls: the exec (the filter is installed before it), the
/// loader and the C and Rust runtime start, the organ runtime's socket
/// (fd 3), regions (memfd, maps; their seals are `fcntl`) and worker
/// threads, time, random bytes and exit. A crash's signal to its own
/// thread (`tgkill`) is checked before the list.
pub(super) const RUNTIME: &[c_long] = &[
    // The organ runtime's own: the protocol socket, its waits and regions.
    libc::SYS_futex,
    libc::SYS_recvmsg,
    libc::SYS_sendmsg,
    libc::SYS_recvfrom,
    libc::SYS_sendto,
    libc::SYS_ppoll,
    libc::SYS_read,
    libc::SYS_write,
    libc::SYS_writev,
    libc::SYS_close,
    libc::SYS_memfd_create,
    libc::SYS_fstat,
    libc::SYS_dup,
    libc::SYS_dup3,
    // Memory.
    libc::SYS_mmap,
    libc::SYS_munmap,
    libc::SYS_mremap,
    libc::SYS_mprotect,
    libc::SYS_madvise,
    libc::SYS_brk,
    // Time and scheduling.
    libc::SYS_clock_gettime,
    libc::SYS_clock_getres,
    libc::SYS_clock_nanosleep,
    libc::SYS_nanosleep,
    libc::SYS_gettimeofday,
    libc::SYS_sched_yield,
    libc::SYS_sched_getaffinity,
    // Thread start and exit.
    libc::SYS_set_robust_list,
    libc::SYS_rseq,
    libc::SYS_set_tid_address,
    libc::SYS_sigaltstack,
    libc::SYS_rt_sigaction,
    libc::SYS_rt_sigprocmask,
    libc::SYS_rt_sigreturn,
    libc::SYS_gettid,
    libc::SYS_getpid,
    libc::SYS_exit,
    libc::SYS_exit_group,
    // The exec and the loader.
    libc::SYS_execve,
    libc::SYS_openat,
    libc::SYS_pread64,
    libc::SYS_newfstatat,
    libc::SYS_statx,
    libc::SYS_lseek,
    libc::SYS_readlinkat,
    libc::SYS_faccessat,
    libc::SYS_faccessat2,
    libc::SYS_getrandom,
];

/// [`RUNTIME`]'s legacy x86_64 spellings.
#[cfg(target_arch = "x86_64")]
pub(super) const RUNTIME_X86_64: &[c_long] = &[
    libc::SYS_poll,
    libc::SYS_dup2,
    libc::SYS_arch_prctl,
    libc::SYS_access,
    libc::SYS_open,
    libc::SYS_stat,
    libc::SYS_lstat,
    libc::SYS_readlink,
    libc::SYS_time,
];
#[cfg(not(target_arch = "x86_64"))]
pub(super) const RUNTIME_X86_64: &[c_long] = &[];

/// The probe's own calls (the host's diagnostics organ, tests only):
/// `probe.fork` and `probe.ptrace {in_child}` fork (with `clone`, which
/// the probe may make with any flags) and wait; a forked child pauses; the
/// hostile modes poll for and write signal files.
pub(super) const PROBE: &[c_long] = &[libc::SYS_wait4, libc::SYS_rt_sigsuspend, libc::SYS_unlinkat];

/// [`PROBE`]'s legacy x86_64 spellings.
#[cfg(target_arch = "x86_64")]
pub(super) const PROBE_X86_64: &[c_long] = &[libc::SYS_fork, libc::SYS_pause, libc::SYS_unlink];
#[cfg(not(target_arch = "x86_64"))]
pub(super) const PROBE_X86_64: &[c_long] = &[];

/// The image organ's own calls: none past [`RUNTIME`]. It decodes, edits
/// and encodes bytes the host lends it and opens no file.
pub(super) const IMAGE: &[c_long] = &[];

/// The seal organ's own calls: none past [`RUNTIME`]. Its fetches and
/// signatures are asks over the protocol socket, and its nonce is
/// `getrandom`.
pub(super) const SEAL: &[c_long] = &[];

/// The fixed tier list's own calls (RULING ORGAN-SECCOMP-THIRD-PARTY-LIST =
/// A): an organ the engine has no traced list for, a third-party organ or a
/// pack build its operator trusts as first party, runs under [`RUNTIME`]
/// and these, the file calls of reading the files its fence lets it read
/// and of working in its scratch dir. No spec adds a call. It forks nothing,
/// execs nothing after its own start, opens no socket and traces nothing.
pub(super) const FENCED_FILES: &[c_long] = &[
    libc::SYS_readv,
    libc::SYS_pwrite64,
    libc::SYS_getdents64,
    libc::SYS_getcwd,
    libc::SYS_mkdirat,
    libc::SYS_unlinkat,
    libc::SYS_renameat2,
    libc::SYS_ftruncate,
    libc::SYS_fallocate,
    libc::SYS_fsync,
    libc::SYS_fdatasync,
    libc::SYS_flock,
    libc::SYS_fstatfs,
    libc::SYS_utimensat,
    libc::SYS_umask,
    libc::SYS_uname,
];

/// [`FENCED_FILES`]'s legacy x86_64 spellings.
#[cfg(target_arch = "x86_64")]
pub(super) const FENCED_FILES_X86_64: &[c_long] = &[
    libc::SYS_getdents,
    libc::SYS_mkdir,
    libc::SYS_unlink,
    libc::SYS_rename,
    libc::SYS_renameat,
    libc::SYS_rmdir,
];
#[cfg(not(target_arch = "x86_64"))]
pub(super) const FENCED_FILES_X86_64: &[c_long] = &[];

/// Calls no list may name: the deny-list's (`super::DENIED`) and these, an
/// organ's way to a network or to another process (a signal, a priority,
/// a scheduling or memory policy, a comparison or a reclaim of another
/// process's). Checked when this crate compiles.
pub(super) const NEVER: &[c_long] = &[
    libc::SYS_socket,
    libc::SYS_socketpair,
    libc::SYS_connect,
    libc::SYS_bind,
    libc::SYS_listen,
    libc::SYS_accept,
    libc::SYS_accept4,
    libc::SYS_kill,
    libc::SYS_tkill,
    libc::SYS_rt_sigqueueinfo,
    libc::SYS_rt_tgsigqueueinfo,
    libc::SYS_setpriority,
    libc::SYS_ioprio_set,
    libc::SYS_sched_setaffinity,
    libc::SYS_sched_setscheduler,
    libc::SYS_sched_setparam,
    libc::SYS_sched_setattr,
    libc::SYS_migrate_pages,
    libc::SYS_move_pages,
    libc::SYS_process_madvise,
    libc::SYS_process_mrelease,
    libc::SYS_kcmp,
    libc::SYS_seccomp,
    libc::SYS_prctl,
    libc::SYS_unshare,
    libc::SYS_setns,
    libc::SYS_clone,
    libc::SYS_clone3,
    libc::SYS_execveat,
    libc::SYS_pidfd_open,
    libc::SYS_pidfd_getfd,
    libc::SYS_pidfd_send_signal,
];
