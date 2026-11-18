//! The probe's single calls that check an organ's sandbox (Linux): each is
//! made the way an organ reaching past its sandbox would make it, and
//! answers how it ended (FIX [ORGAN-SECCOMP-ALLOW-LIST]). Its own file so
//! the probe stays under the giant-file bar.

use oneiron_organ_protocol::Value;

/// One ptrace call, as an organ escaping its sandbox would make:
/// `PTRACE_PEEKDATA` of pid 0, which nothing traces, so where the call
/// is allowed it fails with ESRCH and changes nothing. Answered as
/// [`one_call`] answers.
pub(super) fn ptrace(in_child: bool) -> Value {
    one_call(in_child, || {
        let request = libc::c_long::from(libc::PTRACE_PEEKDATA);
        let zero: libc::c_long = 0;
        // SAFETY: PTRACE_PEEKDATA of pid 0 reads nothing: no process
        // is pid 0's tracee, so the kernel answers ESRCH.
        unsafe { libc::syscall(libc::SYS_ptrace, request, zero, zero, zero) }
    })
}

/// One inet socket, as an organ reaching for the network would open
/// one: the host hands an organ its one socket on fd 3, so no organ's
/// syscall allow-list holds `socket`. Where the call is allowed, the
/// socket is closed at once. Answered as [`one_call`] answers.
pub(super) fn inet_socket(in_child: bool) -> Value {
    one_call(in_child, || {
        let protocol: libc::c_long = 0;
        // SAFETY: socket(2) with constant arguments; close(2) of the
        // descriptor it just returned, which nothing else holds.
        unsafe {
            let fd = libc::syscall(
                libc::SYS_socket,
                libc::c_long::from(libc::AF_INET),
                libc::c_long::from(libc::SOCK_STREAM | libc::SOCK_CLOEXEC),
                protocol,
            );
            if let Ok(fd) = libc::c_int::try_from(fd)
                && fd >= 0
            {
                libc::close(fd);
            }
            fd
        }
    })
}

/// One call aimed at process `pid` (the probe's own when absent), as an
/// organ reaching past itself would make it; where the call is allowed
/// it changes nothing. `signal`: signal 0, which only checks permission,
/// with `tgkill`. `limits`: a read of the process's open-file limit with
/// `prlimit64`. `owner`: `pid` as the owner of a new memfd's signals
/// with `fcntl(F_SETOWN)` (a memfd raises none). `priority`: the
/// process's nice value set to `nice`, its current one, with
/// `setpriority`. And at the probe itself, whatever `pid`:
/// `set_limits`: its open-file limit set to what it reads, with
/// `prlimit64`. `name`: the calling thread named with
/// `prctl(PR_SET_NAME)`. `dumpable`: a read of its dumpable flag with
/// `prctl(PR_GET_DUMPABLE)`. Answers the call's return and errno, as
/// [`one_call`] does in the organ itself.
pub(super) fn reach_process(which: &str, pid: Option<i64>, nice: i64) -> Value {
    let target = pid.unwrap_or_else(|| i64::from(std::process::id()));
    let target = libc::c_long::try_from(target).unwrap_or(-1);
    let nice = libc::c_long::try_from(nice).unwrap_or(0);
    let zero: libc::c_long = 0;
    let mut descriptor = -1;
    // SAFETY: each call reads and writes only memory on this stack, and
    // none changes anything where it is allowed but a thread's name:
    // signal 0 sends nothing, a limit read is only read and a limit set
    // is the one just read, the memfd is this process's own (closed
    // below), the nice value set is the current one, and the dumpable
    // flag is only read.
    let returned = unsafe {
        match which {
            "signal" => libc::syscall(libc::SYS_tgkill, target, target, zero),
            "limits" => {
                let mut old = [0_u64; 2];
                libc::syscall(
                    libc::SYS_prlimit64,
                    target,
                    libc::c_long::from(libc::RLIMIT_NOFILE),
                    std::ptr::null::<u64>(),
                    old.as_mut_ptr(),
                )
            }
            "owner" => {
                descriptor = libc::memfd_create(c"probe-owner".as_ptr(), libc::MFD_CLOEXEC);
                libc::syscall(
                    libc::SYS_fcntl,
                    libc::c_long::from(descriptor),
                    libc::c_long::from(libc::F_SETOWN),
                    target,
                )
            }
            "priority" => libc::syscall(
                libc::SYS_setpriority,
                libc::c_long::from(libc::PRIO_PROCESS),
                target,
                nice,
            ),
            "set_limits" => {
                let mut limits = [0_u64; 2];
                let read = libc::syscall(
                    libc::SYS_prlimit64,
                    zero,
                    libc::c_long::from(libc::RLIMIT_NOFILE),
                    std::ptr::null::<u64>(),
                    limits.as_mut_ptr(),
                );
                if read == 0 {
                    libc::syscall(
                        libc::SYS_prlimit64,
                        zero,
                        libc::c_long::from(libc::RLIMIT_NOFILE),
                        limits.as_ptr(),
                        std::ptr::null_mut::<u64>(),
                    )
                } else {
                    read
                }
            }
            "name" => libc::syscall(
                libc::SYS_prctl,
                libc::c_long::from(libc::PR_SET_NAME),
                c"probe-named".as_ptr(),
            ),
            "dumpable" => libc::syscall(libc::SYS_prctl, libc::c_long::from(libc::PR_GET_DUMPABLE)),
            _ => -1,
        }
    };
    let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
    if descriptor >= 0 {
        // SAFETY: close(2) of the memfd made above, which nothing else
        // holds.
        unsafe {
            libc::close(descriptor);
        }
    }
    Value::Map(vec![
        ("returned".into(), i64::from(returned).into()),
        ("errno".into(), i64::from(errno).into()),
    ])
}

/// `make`'s one call. In the organ itself it answers the call's return
/// and errno. With `in_child`, a forked child makes the call and exits
/// 0, and the answer is how the child ended: `signal` (0 if it exited)
/// and `exit` (-1 if a signal ended it). `make` makes only
/// async-signal-safe calls.
fn one_call(in_child: bool, make: fn() -> libc::c_long) -> Value {
    if !in_child {
        let returned = make();
        let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
        return Value::Map(vec![
            ("returned".into(), i64::from(returned).into()),
            ("errno".into(), i64::from(errno).into()),
        ]);
    }
    #[expect(
        clippy::disallowed_methods,
        reason = "a hostile organ's own fork, outside the server"
    )]
    // SAFETY: the child makes `make`'s async-signal-safe call and
    // _exit(2), and touches no memory of the parent's.
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        make();
        // SAFETY: _exit(2) ends the child without running the
        // parent's exit handlers.
        unsafe { libc::_exit(0) };
    }
    let mut status: libc::c_int = 0;
    // SAFETY: waitpid on the child just forked, into a local.
    let waited = unsafe { libc::waitpid(pid, &raw mut status, 0) };
    let (signal, exit) = if waited != pid {
        (0, -2)
    } else if libc::WIFSIGNALED(status) {
        (libc::WTERMSIG(status), -1)
    } else {
        (0, libc::WEXITSTATUS(status))
    };
    Value::Map(vec![
        ("signal".into(), i64::from(signal).into()),
        ("exit".into(), i64::from(exit).into()),
    ])
}
