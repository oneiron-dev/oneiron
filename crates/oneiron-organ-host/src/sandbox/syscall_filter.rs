//! The syscall filter on Linux (ARCH-0075 "Syscalls", FIX
//! [ORGAN-SECCOMP-ALLOW-LIST]): a seccomp allow-list that every organ starts
//! under. The image and seal organs, and the host's own probe, each run
//! under the calls their traced list names (`lists`); every other organ, a
//! third-party one or a pack build its operator trusts as first party, runs
//! under one fixed tier list the engine ships (RULING
//! ORGAN-SECCOMP-THIRD-PARTY-LIST = A). No spec field adds a call. Any other
//! call kills the whole organ (`SECCOMP_RET_KILL_PROCESS`, which its parent
//! sees as SIGSYS), as does a call made through another syscall table
//! (another audit arch, or x32 on x86_64). `clone3`, whose flags the filter
//! cannot read, answers ENOSYS, so the C library starts a thread with
//! `clone`; `clone` is allowed for a thread, and for any process only on the
//! probe's list. Four calls an organ makes can reach past it by an
//! argument, so the program checks that argument before the list
//! ([`ARGUMENT_CHECKED`]): `tgkill` signals only the organ's own process;
//! `prlimit64` only reads the organ's own limits, and setting one answers
//! EPERM, so no organ lifts the limits its grant set; `fcntl` never makes a
//! descriptor signal its owner, which the organ could make another process
//! (`F_SETOWN`, `F_SETOWN_EX`, `F_SETSIG`), nor takes a lease that stalls
//! another process's open (`F_SETLEASE`); `prctl` only names the calling
//! thread or reads its name, as a thread pool's start does. The calls the
//! deny-list of census L4-09 named ([`DENIED`]), and an organ's ways to a
//! network or another process (`lists::NEVER`), are on no list: the crate
//! does not compile if one is.
//!
//! The program is built before the fork. The child writes its own pid into
//! it, which exec keeps, and installs it after `no_new_privs`, which an
//! unprivileged filter needs, as its last step before exec, so each list
//! holds the exec, the loader and the C and Rust runtime start; it holds
//! across exec and for every process the organ starts. A filter the kernel
//! refuses fails the start, so the organ never runs unfiltered.

use std::io;

mod lists;

use crate::spec::{OrganSpec, OrganTier};

/// The calls census L4-09's deny-list named, each of which reaches past the
/// organ's own process and namespaces: ptrace and process_vm_*; the mount
/// family (the organ holds a user namespace of its own, so the new mount
/// API too); bpf; kexec; module load; perf_event_open; the kernel keyring;
/// userfaultfd. No list names one; a trace run still kills them.
const DENIED: &[libc::c_long] = &[
    libc::SYS_ptrace,
    libc::SYS_process_vm_readv,
    libc::SYS_process_vm_writev,
    libc::SYS_mount,
    libc::SYS_umount2,
    libc::SYS_pivot_root,
    libc::SYS_open_tree,
    libc::SYS_move_mount,
    libc::SYS_fsopen,
    libc::SYS_fsconfig,
    libc::SYS_fsmount,
    libc::SYS_fspick,
    libc::SYS_mount_setattr,
    libc::SYS_bpf,
    libc::SYS_kexec_load,
    libc::SYS_kexec_file_load,
    libc::SYS_init_module,
    libc::SYS_finit_module,
    libc::SYS_delete_module,
    libc::SYS_perf_event_open,
    libc::SYS_keyctl,
    libc::SYS_add_key,
    libc::SYS_request_key,
    libc::SYS_userfaultfd,
];

/// The audit arch of this build's own syscall table (linux/audit.h): the
/// ELF machine with the 64-bit and little-endian flags.
#[cfg(target_arch = "x86_64")]
const AUDIT_ARCH: Option<u32> = Some(0xc000_003e);
#[cfg(target_arch = "aarch64")]
const AUDIT_ARCH: Option<u32> = Some(0xc000_00b7);
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
const AUDIT_ARCH: Option<u32> = None;

/// x86_64's x32 table: the same audit arch, with this bit in the number.
const X32_SYSCALL_BIT: u32 = 0x4000_0000;

/// Where `struct seccomp_data` holds the call's number and audit arch.
const NUMBER_OFFSET: u32 = std::mem::offset_of!(libc::seccomp_data, nr) as u32;
const ARCH_OFFSET: u32 = std::mem::offset_of!(libc::seccomp_data, arch) as u32;

/// The classic BPF instructions the program is made of.
const LOAD_WORD: u16 = (libc::BPF_LD | libc::BPF_W | libc::BPF_ABS) as u16;
const JUMP_IF_EQUAL: u16 = (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16;
const JUMP_IF_BITS: u16 = (libc::BPF_JMP | libc::BPF_JSET | libc::BPF_K) as u16;
const RETURN: u16 = (libc::BPF_RET | libc::BPF_K) as u16;

/// Where `struct seccomp_data` holds the low word of the call's first and
/// second arguments (both tables here are little-endian). Each of these
/// checked here is a 32-bit `int` or `unsigned int` in the kernel, which
/// reads only this word.
const FIRST_ARGUMENT_OFFSET: u32 = std::mem::offset_of!(libc::seccomp_data, args) as u32;
const SECOND_ARGUMENT_OFFSET: u32 = FIRST_ARGUMENT_OFFSET + 8;
/// The low and high words of the call's third argument, a pointer.
const THIRD_ARGUMENT_OFFSET: u32 = FIRST_ARGUMENT_OFFSET + 16;
const THIRD_ARGUMENT_HIGH_OFFSET: u32 = THIRD_ARGUMENT_OFFSET + 4;

/// The calls [`argument_rows`] checks before the list, each of which can
/// reach past the organ by an argument: no list names one.
const ARGUMENT_CHECKED: &[libc::c_long] = &[
    libc::SYS_tgkill,
    libc::SYS_prlimit64,
    libc::SYS_fcntl,
    libc::SYS_prctl,
];

/// `fcntl` commands libc 0.2 does not name on Linux (uapi
/// asm-generic/fcntl.h, which x86_64 and aarch64 both use): a descriptor's
/// signal, and its owner by thread, process or group.
const F_SETSIG: u32 = 10;
const F_SETOWN_EX: u32 = 15;

/// A seccomp program, built before the fork.
pub(super) struct SyscallFilter {
    program: Vec<libc::sock_filter>,
    /// `program`'s length as the kernel takes it.
    len: libc::c_ushort,
    /// The rows of `program` that compare an argument with the organ's own
    /// pid, which the child writes there before it installs the program.
    own_pid_rows: Vec<usize>,
    /// A recording filter's bootstrap socket, in a trace run only
    /// (`syscall_trace`): the child sends the filter's listener over it.
    #[cfg(oneiron_test_support)]
    bootstrap: Option<std::os::fd::RawFd>,
}

impl std::fmt::Debug for SyscallFilter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SyscallFilter")
            .field("instructions", &self.len)
            .finish()
    }
}

fn statement(code: u16, k: u32) -> libc::sock_filter {
    libc::sock_filter {
        code,
        jt: 0,
        jf: 0,
        k,
    }
}

fn jump(code: u16, k: u32, jt: u8, jf: u8) -> libc::sock_filter {
    libc::sock_filter { code, jt, jf, k }
}

impl SyscallFilter {
    /// `spec`'s allow-list as a seccomp program for this build's syscall
    /// table: a first-party image or seal organ, or the probe, under its own
    /// list; every other organ under the fixed tier list. A call under
    /// another audit arch, an x32 call, a `clone` that starts no thread
    /// (save the probe's), a call whose arguments [`argument_rows`]
    /// refuses, or a call its list does not name kills the process;
    /// `clone3` answers ENOSYS, and a `prlimit64` that sets a limit EPERM.
    ///
    /// # Errors
    /// This build's architecture has no audit arch here, so no program can
    /// tell its calls apart: the start fails rather than run the organ
    /// unfiltered.
    pub(super) fn for_organ(spec: &OrganSpec) -> io::Result<Self> {
        let first_party = spec.tier == OrganTier::FirstParty;
        let (own, own_x86_64, forks): (&[libc::c_long], &[libc::c_long], bool) =
            match spec.name.as_str() {
                PROBE_ORGAN if first_party => (lists::PROBE, lists::PROBE_X86_64, true),
                crate::image::IMAGE_ORGAN if first_party => (lists::IMAGE, &[], false),
                crate::seal::SEAL_ORGAN if first_party => (lists::SEAL, &[], false),
                _ => (lists::FENCED_FILES, lists::FENCED_FILES_X86_64, false),
            };
        let mut program = native_table_only()?;
        program.extend(clone_rows(forks));
        let (rows, own_pid_rows) = argument_rows();
        let own_pid_rows: Vec<usize> = own_pid_rows.map(|row| program.len() + row).into();
        program.extend(rows);
        let allow = statement(RETURN, libc::SECCOMP_RET_ALLOW);
        let mut allowed: Vec<libc::c_long> = Vec::new();
        for &number in [lists::RUNTIME, lists::RUNTIME_X86_64, own, own_x86_64]
            .into_iter()
            .flatten()
        {
            if !allowed.contains(&number) {
                allowed.push(number);
                // Each is a small positive index into the native table.
                program.extend([jump(JUMP_IF_EQUAL, number as u32, 0, 1), allow]);
            }
        }
        program.push(statement(RETURN, libc::SECCOMP_RET_KILL_PROCESS));
        let mut filter = Self::of(program)?;
        filter.own_pid_rows = own_pid_rows;
        Ok(filter)
    }

    /// The recording filter of a trace run (`syscall_trace`): a call under
    /// another audit arch, an x32 call, or a denied call kills the process,
    /// as in every organ's filter; the child's `sendmsg` on `bootstrap`, the
    /// one that hands the listener over, is allowed; every other call waits
    /// for the recorder (`SECCOMP_RET_USER_NOTIF`).
    ///
    /// # Errors
    /// As [`Self::for_organ`].
    #[cfg(oneiron_test_support)]
    pub(super) fn recording(bootstrap: std::os::fd::RawFd) -> io::Result<Self> {
        let mut program = native_table_only()?;
        program.extend(kill_denied());
        program.extend([
            jump(JUMP_IF_EQUAL, libc::SYS_sendmsg as u32, 0, 3),
            statement(LOAD_WORD, FIRST_ARGUMENT_OFFSET),
            jump(JUMP_IF_EQUAL, bootstrap as u32, 0, 1),
            statement(RETURN, libc::SECCOMP_RET_ALLOW),
            statement(RETURN, libc::SECCOMP_RET_USER_NOTIF),
        ]);
        let mut filter = Self::of(program)?;
        filter.bootstrap = Some(bootstrap);
        Ok(filter)
    }

    /// `program` as the kernel takes it.
    fn of(program: Vec<libc::sock_filter>) -> io::Result<Self> {
        let len = libc::c_ushort::try_from(program.len()).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "the organ's syscall filter is too long for the kernel",
            )
        })?;
        Ok(Self {
            program,
            len,
            own_pid_rows: Vec::new(),
            #[cfg(oneiron_test_support)]
            bootstrap: None,
        })
    }

    /// Installs the program on this process, with this process's pid
    /// written into the rows that compare an argument with it. It needs
    /// `no_new_privs`, set before it, and binds this process and everything
    /// it starts, across exec. A getpid and one prctl over memory made
    /// before the fork, and no allocation, so a child may run it between
    /// fork and exec. In a trace run it installs the recording filter and
    /// hands its listener to the recorder instead (`install_recording`).
    ///
    /// # Errors
    /// The kernel refused the filter.
    pub(super) fn install(&mut self) -> io::Result<()> {
        let own = std::process::id();
        for &row in &self.own_pid_rows {
            if let Some(instruction) = self.program.get_mut(row) {
                instruction.k = own;
            }
        }
        let program = libc::sock_fprog {
            len: self.len,
            filter: self.program.as_ptr().cast_mut(),
        };
        #[cfg(oneiron_test_support)]
        if let Some(bootstrap) = self.bootstrap {
            return install_recording(&program, bootstrap);
        }
        let zero: libc::c_ulong = 0;
        // SAFETY: prctl reads `program` and the instructions it points at,
        // both alive for the call, and writes neither; the filter binds
        // only this process and its descendants.
        let installed = unsafe {
            libc::prctl(
                libc::PR_SET_SECCOMP,
                libc::c_ulong::from(libc::SECCOMP_MODE_FILTER),
                &raw const program,
                zero,
                zero,
            )
        };
        if installed == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }
}

/// The first rows of every program: a call under another audit arch, or an
/// x32 call on x86_64, kills the process; the call's number is then loaded.
///
/// # Errors
/// This build's architecture has no audit arch here.
fn native_table_only() -> io::Result<Vec<libc::sock_filter>> {
    let Some(arch) = AUDIT_ARCH else {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "the organ's syscall filter has no table for this architecture",
        ));
    };
    let kill = statement(RETURN, libc::SECCOMP_RET_KILL_PROCESS);
    let mut program = vec![
        statement(LOAD_WORD, ARCH_OFFSET),
        jump(JUMP_IF_EQUAL, arch, 1, 0),
        kill,
        statement(LOAD_WORD, NUMBER_OFFSET),
    ];
    if cfg!(target_arch = "x86_64") {
        program.extend([jump(JUMP_IF_BITS, X32_SYSCALL_BIT, 0, 1), kill]);
    }
    Ok(program)
}

/// The rows for `clone3` and `clone`, before the list's: `clone3`, whose
/// flags sit behind a pointer the filter cannot read, answers ENOSYS, and
/// the C library then starts a thread with `clone`. `clone` is allowed for
/// a thread (`CLONE_THREAD` in its flags) and, where `forks`, for any
/// process; any other kills.
fn clone_rows(forks: bool) -> Vec<libc::sock_filter> {
    let allow = statement(RETURN, libc::SECCOMP_RET_ALLOW);
    let mut rows = vec![
        jump(JUMP_IF_EQUAL, libc::SYS_clone3 as u32, 0, 1),
        statement(
            RETURN,
            libc::SECCOMP_RET_ERRNO | (libc::ENOSYS as u32 & libc::SECCOMP_RET_DATA),
        ),
    ];
    if forks {
        rows.extend([jump(JUMP_IF_EQUAL, libc::SYS_clone as u32, 0, 1), allow]);
    } else {
        // The flags replace the number in the accumulator, so both
        // outcomes return here.
        rows.extend([
            jump(JUMP_IF_EQUAL, libc::SYS_clone as u32, 0, 4),
            statement(LOAD_WORD, FIRST_ARGUMENT_OFFSET),
            jump(JUMP_IF_BITS, libc::CLONE_THREAD as u32, 0, 1),
            allow,
            statement(RETURN, libc::SECCOMP_RET_KILL_PROCESS),
        ]);
    }
    rows
}

/// The rows for [`ARGUMENT_CHECKED`], before the list's, and the indexes
/// among them of the rows that compare an argument with the organ's own
/// pid, which is not known before the fork (`SyscallFilter::install` writes
/// it there):
/// - `tgkill` only at the organ's own process, the way `abort` signals its
///   own thread;
/// - `prlimit64` only at itself, pid 0 (as the C library calls it) or its
///   own pid, and only to read: one that sets a limit (a new limit that is
///   not NULL) answers EPERM, since a first-party organ's hard limits are
///   open and its grant is the soft one;
/// - `fcntl` with every command but those that make a descriptor signal its
///   owner when it is ready (`F_SETOWN`, `F_SETOWN_EX`, `F_SETSIG`), since
///   the owner could be another process, and a lease (`F_SETLEASE`), which
///   holds another process's open of the file;
/// - `prctl` only to name the calling thread or read its name
///   (`PR_SET_NAME`, `PR_GET_NAME`).
///
/// Any other kills. Each loads an argument over the number, so every
/// outcome returns here.
fn argument_rows() -> (Vec<libc::sock_filter>, [usize; 2]) {
    let allow = statement(RETURN, libc::SECCOMP_RET_ALLOW);
    let kill = statement(RETURN, libc::SECCOMP_RET_KILL_PROCESS);
    let refuse = statement(
        RETURN,
        libc::SECCOMP_RET_ERRNO | (libc::EPERM as u32 & libc::SECCOMP_RET_DATA),
    );
    // The organ's own pid, which `SyscallFilter::install` writes here.
    let own_pid = 0;
    let rows = vec![
        // 0: tgkill(tgid, ...) with tgid the organ's own pid.
        jump(JUMP_IF_EQUAL, libc::SYS_tgkill as u32, 0, 4),
        statement(LOAD_WORD, FIRST_ARGUMENT_OFFSET),
        jump(JUMP_IF_EQUAL, own_pid, 0, 1),
        allow,
        kill,
        // 5: prlimit64(pid, resource, new, old) with pid 0 or the organ's
        // own, and new NULL (both words).
        jump(JUMP_IF_EQUAL, libc::SYS_prlimit64 as u32, 0, 10),
        statement(LOAD_WORD, FIRST_ARGUMENT_OFFSET),
        jump(JUMP_IF_EQUAL, 0, 1, 0),
        jump(JUMP_IF_EQUAL, own_pid, 0, 6),
        statement(LOAD_WORD, THIRD_ARGUMENT_OFFSET),
        jump(JUMP_IF_EQUAL, 0, 0, 3),
        statement(LOAD_WORD, THIRD_ARGUMENT_HIGH_OFFSET),
        jump(JUMP_IF_EQUAL, 0, 0, 1),
        allow,
        refuse,
        kill,
        // 16: fcntl(fd, cmd, ...) with cmd no owner, signal or lease.
        jump(JUMP_IF_EQUAL, libc::SYS_fcntl as u32, 0, 7),
        statement(LOAD_WORD, SECOND_ARGUMENT_OFFSET),
        jump(JUMP_IF_EQUAL, libc::F_SETOWN as u32, 4, 0),
        jump(JUMP_IF_EQUAL, F_SETOWN_EX, 3, 0),
        jump(JUMP_IF_EQUAL, F_SETSIG, 2, 0),
        jump(JUMP_IF_EQUAL, libc::F_SETLEASE as u32, 1, 0),
        allow,
        kill,
        // 24: prctl(option, ...) with option a thread name's.
        jump(JUMP_IF_EQUAL, libc::SYS_prctl as u32, 0, 5),
        statement(LOAD_WORD, FIRST_ARGUMENT_OFFSET),
        jump(JUMP_IF_EQUAL, libc::PR_SET_NAME as u32, 1, 0),
        jump(JUMP_IF_EQUAL, libc::PR_GET_NAME as u32, 0, 1),
        allow,
        kill,
    ];
    (rows, [2, 8])
}

/// The probe's name: the host's diagnostics organ, which only tests install.
const PROBE_ORGAN: &str = "probe";

/// Whether `list` names any call of `calls`.
const fn names_any(list: &[libc::c_long], calls: &[libc::c_long]) -> bool {
    let mut i = 0;
    while i < list.len() {
        let mut j = 0;
        while j < calls.len() {
            if list[i] == calls[j] {
                return true;
            }
            j += 1;
        }
        i += 1;
    }
    false
}

// No list names a denied call, a way to a network or another process, or
// a call checked before the list (`clone`, `clone3` and
// [`ARGUMENT_CHECKED`]).
const _: () = {
    let all = [
        lists::RUNTIME,
        lists::RUNTIME_X86_64,
        lists::PROBE,
        lists::PROBE_X86_64,
        lists::IMAGE,
        lists::SEAL,
        lists::FENCED_FILES,
        lists::FENCED_FILES_X86_64,
    ];
    let mut i = 0;
    while i < all.len() {
        assert!(
            !names_any(all[i], DENIED)
                && !names_any(all[i], lists::NEVER)
                && !names_any(all[i], ARGUMENT_CHECKED),
            "an organ's syscall list names a call no list may name"
        );
        i += 1;
    }
};

/// One kill per denied call, over the loaded number.
#[cfg(oneiron_test_support)]
fn kill_denied() -> impl Iterator<Item = libc::sock_filter> {
    let kill = statement(RETURN, libc::SECCOMP_RET_KILL_PROCESS);
    // Each is a small positive index into the native table.
    DENIED
        .iter()
        .flat_map(move |&number| [jump(JUMP_IF_EQUAL, number as u32, 0, 1), kill])
}

/// Installs a recording filter with a new listener and sends the listener
/// over `bootstrap` (a trace run only, `syscall_trace`). Allocation-free, so
/// a child may run it between fork and exec; the listener closes at exec
/// (the kernel makes it close-on-exec: kernel/seccomp.c,
/// `get_unused_fd_flags(O_CLOEXEC)`). Once the filter is in place every
/// call but that `sendmsg` waits for a recorder that has no listener yet,
/// so a failure from there on cannot be reported: the child ends itself by
/// a denied call, which the filter kills, and its parent sees it die.
///
/// # Errors
/// The kernel refused the filter (none is installed).
#[cfg(oneiron_test_support)]
fn install_recording(program: &libc::sock_fprog, bootstrap: std::os::fd::RawFd) -> io::Result<()> {
    let zero: libc::c_long = 0;
    // SAFETY: seccomp(2) reads `program` and the instructions it points at,
    // both alive for the call; the filter binds only this process and its
    // descendants, and its listener is a new descriptor of this process.
    let listener = unsafe {
        libc::syscall(
            libc::SYS_seccomp,
            libc::c_long::from(libc::SECCOMP_SET_MODE_FILTER),
            libc::SECCOMP_FILTER_FLAG_NEW_LISTENER as libc::c_long,
            std::ptr::from_ref(program),
            zero,
        )
    };
    if listener < 0 {
        return Err(io::Error::last_os_error());
    }
    let Ok(listener) = libc::c_int::try_from(listener) else {
        end_by_the_filter()
    };
    let mut byte = [0_u8];
    let mut iov = libc::iovec {
        iov_base: byte.as_mut_ptr().cast(),
        iov_len: 1,
    };
    let mut control = [0_usize; 8];
    loop {
        // SAFETY: sendmsg(2) reads the live buffers on this stack; the
        // control message carries one descriptor of this process
        // (SCM_RIGHTS).
        let sent = unsafe {
            let mut message: libc::msghdr = std::mem::zeroed();
            message.msg_iov = &raw mut iov;
            message.msg_iovlen = 1;
            message.msg_control = control.as_mut_ptr().cast();
            message.msg_controllen =
                libc::CMSG_SPACE(std::mem::size_of::<libc::c_int>() as u32) as usize;
            let header = libc::CMSG_FIRSTHDR(&raw const message);
            (*header).cmsg_level = libc::SOL_SOCKET;
            (*header).cmsg_type = libc::SCM_RIGHTS;
            (*header).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<libc::c_int>() as u32) as usize;
            std::ptr::write_unaligned(libc::CMSG_DATA(header).cast::<libc::c_int>(), listener);
            libc::sendmsg(bootstrap, &raw const message, libc::MSG_NOSIGNAL)
        };
        if sent == 1 {
            return Ok(());
        }
        if io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
            end_by_the_filter();
        }
    }
}

/// Ends this process by a denied call, which the recording filter kills
/// before it runs: the way out once no call can be made unrecorded.
#[cfg(oneiron_test_support)]
fn end_by_the_filter() -> ! {
    let zero: libc::c_long = 0;
    loop {
        // SAFETY: the recording filter kills ptrace before the kernel runs
        // it (`kill_denied`), so this call makes no change.
        unsafe {
            libc::syscall(libc::SYS_ptrace, zero, zero, zero, zero);
        }
    }
}
