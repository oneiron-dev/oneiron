//! The syscall filter on Linux (census L4-09, ARCH-0075 "Syscalls"): a
//! seccomp deny-list that every organ starts under. Calls no document organ
//! makes, each of which reaches past the organ's own process and
//! namespaces, kill the whole organ (`SECCOMP_RET_KILL_PROCESS`, which its
//! parent sees as SIGSYS): ptrace and process_vm_*; the mount family (the
//! organ holds a user namespace of its own, so the new mount API too); bpf;
//! kexec; module load; perf_event_open; the kernel keyring; userfaultfd. A
//! call made through another syscall table (another audit arch, or x32 on
//! x86_64) kills it too, so no second table gets around the list. Every
//! other call is allowed: the canon's traced allow-list is FIX
//! [ORGAN-SECCOMP-ALLOW-LIST].
//!
//! The program is built before the fork. The child installs it after
//! `no_new_privs`, which an unprivileged filter needs; it holds across exec
//! and for every process the organ starts. A filter the kernel refuses
//! fails the start, so the organ never runs unfiltered.

use std::io;

/// The calls that kill an organ.
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

/// A seccomp program, built before the fork.
pub(super) struct SyscallFilter {
    program: Vec<libc::sock_filter>,
    /// `program`'s length as the kernel takes it.
    len: libc::c_ushort,
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
    /// The deny-list as a seccomp program for this build's syscall table:
    /// a call under another audit arch, an x32 call, or a denied call kills
    /// the process; every other call is allowed.
    ///
    /// # Errors
    /// This build's architecture has no audit arch here, so no program can
    /// tell its calls apart: the start fails rather than run the organ
    /// unfiltered.
    pub(super) fn deny_list() -> io::Result<Self> {
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
        for &number in DENIED {
            // Each is a small positive index into the native table.
            program.extend([jump(JUMP_IF_EQUAL, number as u32, 0, 1), kill]);
        }
        program.push(statement(RETURN, libc::SECCOMP_RET_ALLOW));
        let len = libc::c_ushort::try_from(program.len()).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "the organ's syscall filter is too long for the kernel",
            )
        })?;
        Ok(Self { program, len })
    }

    /// Installs the program on this process. It needs `no_new_privs`, set
    /// before it, and binds this process and everything it starts, across
    /// exec. One prctl over memory made before the fork, and no
    /// allocation, so a child may run it between fork and exec.
    ///
    /// # Errors
    /// The kernel refused the filter.
    pub(super) fn install(&self) -> io::Result<()> {
        let program = libc::sock_fprog {
            len: self.len,
            filter: self.program.as_ptr().cast_mut(),
        };
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
