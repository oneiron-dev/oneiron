//! `oneiron job-exec <id>` (the job account, the unit's `ExecStart=`): it
//! applies `exec.json` and nothing else (pass 33, 7.6). It proves each bound
//! it can from inside the unit, reports them to the root gate, and becomes
//! the workload only after the gate's go. The service manager applies some
//! settings only where the kernel allows and is silent when it cannot, so a
//! bound the template requires and the proof does not find refuses the job
//! before any workload process exists (pass 34, 2.2: any other bound is
//! recorded unproven).
//!
//! Order: make this process not dumpable; catch the checkpoint signals;
//! connect to the gate's socket (the gate takes this process's connection
//! alone: FIX EXEC-UNIT-ONE-JOB-ACCOUNT); check that the job cannot take disk
//! with no write ([`disk_allocation_refused`], review r13 R13-06 of #10512);
//! prove the device policy (before the
//! file wall, so a refusal is the device policy's and not the wall's); apply
//! the inner file wall (Landlock); prove the wall, the protected paths, the
//! network, the hidden processes and the cgroup limits; report (one line, the
//! connection kept open); wait for the go; start the log writer
//! ([`super::log_writer`]: descriptors 1 and 2 become its pipes); close every
//! descriptor above 2 at the exec; write the exec mark; `execve`. The
//! connection closes with a successful exec; a failed one writes why on it
//! after the mark, so the gate records that the workload never started
//! (review r2 R2-02; the mark: FIX EXEC-UNIT-GATE-EXEC-RACE). A log writer
//! that does not start is said on the connection without the mark: the
//! workload never started either. In probe mode (`execution-node check`) the
//! step stays connected after its report until root closes the connection, so
//! root's check of the peer finds it alive, and then ends.
//!
//! Not dumpable: every job runs as the one job account, so where Yama's
//! `ptrace_scope` is 0 and another job runs without Landlock, that job could
//! attach to this process and speak for it on the gate's connection. A
//! process that is not dumpable cannot be attached to or have its memory
//! opened by a process of the same account. The window left is the few
//! system calls between this binary's exec and its first statement; the
//! workload's own exec makes it dumpable again, and the wider exposure of
//! one job to another under one account is FIX EXEC-UNIT-CROSS-JOB-SAME-UID
//! (review r7 R7-01).
//!
//! The checkpoint signals (design 7.1 `Signal`; the template's
//! `checkpoint_signal`) reach the unit's main process. The control handler
//! sends one only once the unit is active, after the workload's exec
//! (review r6 R6-06). As a second guard `job-exec` catches them, from its
//! first statement, with a handler that does nothing, and the exec resets
//! that handler, so a notice that reaches `job-exec` anyway is lost, as a
//! notice may be, and does not end the job.

use std::collections::BTreeMap;
use std::ffi::CString;
use std::io::{self, Write};
use std::os::fd::{AsFd as _, AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use super::super::node_settings::CHECKPOINT_SIGNALS;
use super::log_writer::{self, WorkloadStreams};
use super::records::{
    BoundReport, BoundRequirement, ExecFile, PROVED_INSIDE, ScopeBound, ScopeReport,
    enforced_by_kernel, first_unmet, not_enforced,
};
use super::{
    EXCHANGE_ROOT, EXEC_FILE_NAME, EXEC_MARK, GATE_GO, GATE_SOCKET_NAME, REPORT_FRAME_END,
    exec_status, is_job_instance,
};

mod disk_allocation;
use disk_allocation::disk_allocation_refused;

/// How long `job-exec` waits for the gate's socket, and then for its go.
const GATE_WAIT: Duration = Duration::from_secs(45);

/// The step. Returns its exit status when it does not become the workload.
#[must_use]
pub fn run(args: &[String]) -> i32 {
    let off: libc::c_ulong = 0;
    // SAFETY: PR_SET_DUMPABLE with 0 takes no pointer and only clears this
    // process's dumpable flag.
    if unsafe { libc::prctl(libc::PR_SET_DUMPABLE, off, off, off, off) } != 0 {
        journal_line!(
            "job-exec: not made undumpable: {}",
            io::Error::last_os_error()
        );
        return exec_status::GATE_SOCKET;
    }
    catch_checkpoint_signals();
    let [instance] = args else {
        journal_line!("job-exec: usage: job-exec <instance>");
        return exec_status::EXEC_FILE;
    };
    if !is_job_instance(instance) {
        journal_line!("job-exec: {instance:?} is not a job instance");
        return exec_status::EXEC_FILE;
    }
    let exchange = Path::new(EXCHANGE_ROOT).join(instance);
    let exec = match read_exec_file(&exchange, instance) {
        Ok(exec) => exec,
        Err(why) => {
            journal_line!("job-exec: {why}");
            return exec_status::EXEC_FILE;
        }
    };
    let gate = match connect_to_gate(&exchange) {
        Ok(gate) => gate,
        Err(why) => {
            journal_line!("job-exec: {why}");
            return exec_status::GATE_SOCKET;
        }
    };
    let allocation = disk_allocation_refused(&exec.cwd.join("tmp"))
        .err()
        .map(|why| format!("disk_allocation_not_refused: {why}"));
    let mut proofs = BTreeMap::new();
    proofs.insert(ScopeBound::DeviceClosure, prove_device_closure(&exec));
    let wall = apply_file_wall(&exec);
    let wall_error = wall.as_ref().err().cloned();
    proofs.insert(
        ScopeBound::FileWall,
        match &wall {
            Ok(()) => prove_file_wall(&exec, &exchange),
            Err(why) => not_enforced(format!("Landlock not applied: {why}")),
        },
    );
    proofs.insert(ScopeBound::NetworkClosed, prove_network_closed(&exec));
    proofs.insert(ScopeBound::ProcessesHidden, prove_processes_hidden(&exec));
    let (memory, write_rate) = prove_cgroup_limits();
    proofs.insert(ScopeBound::MemoryCap, memory);
    proofs.insert(ScopeBound::WriteRateCap, write_rate);
    let inside: Vec<BoundRequirement> = exec
        .require
        .iter()
        .copied()
        .filter(|requirement| PROVED_INSIDE.contains(&requirement.bound))
        .collect();
    let unmet = first_unmet(&inside, &proofs);
    let refusal = allocation.clone().or_else(|| {
        unmet.map(|requirement| {
            let evidence = proofs
                .get(&requirement.bound)
                .map_or("not proved from inside", |proof| proof.evidence.as_str());
            format!("required_bound_not_proved: {requirement}: {evidence}")
        })
    });
    let report = ScopeReport {
        instance: instance.clone(),
        proofs,
        refusal: refusal.clone(),
    };
    if let Err(error) = send_report(&gate, &report) {
        journal_line!("job-exec: the report did not reach the gate: {error}");
        return exec_status::GATE_SOCKET;
    }
    if exec.probe {
        // Root sends no go to a probe: it closes the connection once it read
        // the report.
        let _ = wait_for_go(&gate);
        return exec_status::PROBE_DONE;
    }
    if let Some(why) = refusal {
        journal_line!("job-exec: refused before the workload: {why}");
        if allocation.is_some() {
            return exec_status::DISK_ALLOCATION;
        }
        let wall_unmet = unmet.is_some_and(|requirement| requirement.bound == ScopeBound::FileWall);
        return if wall_error.is_some() && wall_unmet {
            exec_status::FILE_WALL
        } else {
            exec_status::REQUIRED_BOUND
        };
    }
    if let Err(why) = wait_for_go(&gate) {
        journal_line!("job-exec: no go from the gate: {why}");
        return exec_status::GATE_REFUSED;
    }
    let mut gate = gate;
    let streams = match log_writer::start(&exec.cwd.join("log"), exec.log_max_bytes) {
        Ok(streams) => streams,
        Err(why) => {
            return exec_failed(&mut gate, None, &format!("log_writer_not_started: {why}"));
        }
    };
    become_workload(&exec, gate, streams)
}

/// The signal number of a checkpoint signal's name.
fn checkpoint_signal_number(name: &str) -> Option<libc::c_int> {
    Some(match name {
        "HUP" => libc::SIGHUP,
        "INT" => libc::SIGINT,
        "USR1" => libc::SIGUSR1,
        "USR2" => libc::SIGUSR2,
        "WINCH" => libc::SIGWINCH,
        _ => return None,
    })
}

extern "C" fn checkpoint_notice_before_the_workload(_signal: libc::c_int) {}

/// Catches each checkpoint signal with a handler that does nothing, until
/// the exec resets it (module doc).
fn catch_checkpoint_signals() {
    for name in CHECKPOINT_SIGNALS {
        let Some(number) = checkpoint_signal_number(name) else {
            continue;
        };
        let handler: extern "C" fn(libc::c_int) = checkpoint_notice_before_the_workload;
        // SAFETY: a zeroed sigaction is valid; the handler is an extern "C"
        // function that touches nothing, so it is async-signal-safe.
        unsafe {
            let mut action: libc::sigaction = std::mem::zeroed();
            action.sa_sigaction = handler as libc::sighandler_t;
            action.sa_flags = libc::SA_RESTART;
            libc::sigemptyset(&raw mut action.sa_mask);
            if libc::sigaction(number, &raw const action, std::ptr::null_mut()) != 0 {
                journal_line!(
                    "job-exec: SIG{name} not caught: {}",
                    io::Error::last_os_error()
                );
            }
        }
    }
}

fn read_exec_file(exchange: &Path, instance: &str) -> Result<ExecFile, String> {
    let path = exchange.join(EXEC_FILE_NAME);
    let bytes = std::fs::read(&path).map_err(|error| format!("{}: {error}", path.display()))?;
    let exec: ExecFile =
        serde_json::from_slice(&bytes).map_err(|error| format!("{}: {error}", path.display()))?;
    if exec.instance != instance {
        return Err(format!("{} is another instance's", path.display()));
    }
    Ok(exec)
}

/// The connection to the gate's socket (close-on-exec, blocking once made).
/// The gate starts after this step's own exec (`ExecStartPost=`), so the
/// socket is missing, refuses, or is not yet the job account's for a moment:
/// each of those is waited out. Each try connects without blocking, so a
/// full listen queue (`EAGAIN`) is waited out under the same deadline too
/// (review r7 R7-07).
fn connect_to_gate(exchange: &Path) -> Result<UnixStream, String> {
    let path = exchange.join(GATE_SOCKET_NAME);
    let address = rustix::net::SocketAddrUnix::new(path.as_path())
        .map_err(|error| format!("gate socket {}: {error}", path.display()))?;
    let started = Instant::now();
    loop {
        match connect_once(&address) {
            Ok(gate) => return Ok(gate),
            Err(error)
                if matches!(
                    error.raw_os_error(),
                    Some(libc::ENOENT | libc::ECONNREFUSED | libc::EACCES | libc::EAGAIN)
                ) =>
            {
                if started.elapsed() >= GATE_WAIT {
                    return Err(format!("the gate never took a connection: {error}"));
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(error) => return Err(format!("gate socket: {error}")),
        }
    }
}

/// How long the clients wait before trying a connection again.
const CONNECT_RETRY: Duration = Duration::from_millis(20);

/// Connects without blocking, retrying a full listen queue or an interrupted
/// attempt until `deadline`. No try starts once `deadline` has passed, the
/// first one included (review r2 of #10579), and a connection that completes
/// after it is dropped and reported as `TimedOut` (review r1 of #10579, P1).
/// The stream is blocking once connected.
///
/// # Errors
///
/// `TimedOut` if the listener did not take a connection in time, or if a
/// connection completed after `deadline`; the original error if the attempt
/// failed for another reason.
pub(super) fn connect_by_deadline(
    address: &rustix::net::SocketAddrUnix,
    deadline: Instant,
) -> io::Result<UnixStream> {
    loop {
        // The deadline holds before every try, the first one too: a request
        // whose deadline passed before it connected queues no connection, so
        // the socket starts no handler for it (review r2 of #10579, P1).
        if Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "the handler's deadline passed before a connection was tried",
            ));
        }
        match connect_once(address) {
            Ok(stream) => {
                if Instant::now() > deadline {
                    drop(stream);
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "the handler's connection came after its deadline",
                    ));
                }
                return Ok(stream);
            }
            Err(error) if matches!(error.raw_os_error(), Some(libc::EAGAIN | libc::EINTR)) => {
                let left = deadline.saturating_duration_since(Instant::now());
                if left.is_zero() {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        format!("the handler took no connection in time: {error}"),
                    ));
                }
                std::thread::sleep(CONNECT_RETRY.min(left));
                if Instant::now() > deadline {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        format!("the handler took no connection in time: {error}"),
                    ));
                }
            }
            Err(error) => return Err(error),
        }
    }
}

/// One connection try that does not block, then the connection made
/// blocking.
pub(super) fn connect_once(address: &rustix::net::SocketAddrUnix) -> io::Result<UnixStream> {
    use rustix::net::{AddressFamily, SocketFlags, SocketType};
    let socket = rustix::net::socket_with(
        AddressFamily::UNIX,
        SocketType::STREAM,
        SocketFlags::NONBLOCK | SocketFlags::CLOEXEC,
        None,
    )?;
    rustix::net::connect(&socket, address)?;
    rustix::io::ioctl_fionbio(&socket, false)?;
    Ok(UnixStream::from(socket))
}

fn open_raw(path: &Path, flags: libc::c_int) -> io::Result<OwnedFd> {
    let c = CString::new(path.as_os_str().as_bytes()).map_err(io::Error::other)?;
    // SAFETY: c is NUL terminated.
    let fd = unsafe { libc::open(c.as_ptr(), flags) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: open returned a new descriptor.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// The device policy (`DevicePolicy=closed`, `DeviceAllow=` per claim):
/// each allowed device opens, and a device outside the allow-list fails
/// with the device policy's EPERM. Run before the file wall, which would
/// refuse it first with its own error.
fn prove_device_closure(exec: &ExecFile) -> BoundReport {
    for path in &exec.devices_allowed {
        if let Err(error) = open_raw(path, libc::O_RDONLY | libc::O_NONBLOCK | libc::O_CLOEXEC) {
            return not_enforced(format!(
                "the leased device {} does not open: {error}",
                path.display()
            ));
        }
    }
    let Some(other) = exec.devices_denied.first() else {
        return enforced_by_kernel("DevicePolicy=closed; no other device exists here to try");
    };
    match open_raw(other, libc::O_RDONLY | libc::O_NONBLOCK | libc::O_CLOEXEC) {
        Ok(_) => not_enforced(format!(
            "{} opened: the device policy did not apply",
            other.display()
        )),
        Err(error) if error.raw_os_error() == Some(libc::EPERM) => enforced_by_kernel(format!(
            "{} refused by the device policy (EPERM); {} leased device(s) open",
            other.display(),
            exec.devices_allowed.len()
        )),
        Err(error) => not_enforced(format!(
            "{} failed with {error}, not the device policy's EPERM",
            other.display()
        )),
    }
}

fn apply_file_wall(exec: &ExecFile) -> Result<(), String> {
    if oneiron_container::landlock_abi() < 3 {
        return Err(format!(
            "the kernel's Landlock ABI is {}, below 3",
            oneiron_container::landlock_abi()
        ));
    }
    let ruleset = oneiron_container::landlock_ruleset(&exec.read, &exec.write)
        .map_err(|error| error.to_string())?;
    oneiron_container::landlock_restrict(ruleset.as_fd()).map_err(|error| error.to_string())
}

/// The inner wall holds: the job writes its own `out`, cannot write the
/// private `/tmp` the kernel would let it write, cannot read its own
/// exchange directory again, and cannot open any protected path.
fn prove_file_wall(exec: &ExecFile, exchange: &Path) -> BoundReport {
    let out_probe = exec.cwd.join("out").join(".oneiron-wall-probe");
    match std::fs::File::create(&out_probe) {
        Ok(_) => {
            let _ = std::fs::remove_file(&out_probe);
        }
        Err(error) => return not_enforced(format!("out/ is not writable: {error}")),
    }
    let outside = Path::new("/tmp/.oneiron-wall-probe");
    if std::fs::File::create(outside).is_ok() {
        let _ = std::fs::remove_file(outside);
        return not_enforced("/tmp was writable: the wall did not apply".to_owned());
    }
    if std::fs::read(exchange.join(EXEC_FILE_NAME)).is_ok() {
        return not_enforced(
            "the exchange directory was readable: the wall did not apply".to_owned(),
        );
    }
    for path in &exec.protected {
        if open_raw(path, libc::O_RDONLY | libc::O_NONBLOCK | libc::O_CLOEXEC).is_ok() {
            return not_enforced(format!("{} opened", path.display()));
        }
    }
    enforced_by_kernel(format!(
        "Landlock ABI {}: /tmp and the exchange directory refused; {} protected path(s) refused",
        oneiron_container::landlock_abi(),
        exec.protected.len()
    ))
}

/// The job is alone with its loopback in a network namespace that is not
/// the machine's (review r2 R2-06): `/proc/self/ns/net` names another
/// namespace than the one root read from process 1, and `/proc/net/dev`
/// lists `lo` alone. Either check that cannot be made proves nothing.
fn prove_network_closed(exec: &ExecFile) -> BoundReport {
    if exec.host_network_namespace.is_empty() {
        return not_enforced("the machine's network namespace is unknown");
    }
    let own = match std::fs::read_link("/proc/self/ns/net") {
        Ok(link) => link.display().to_string(),
        Err(error) => return not_enforced(format!("/proc/self/ns/net unreadable: {error}")),
    };
    if own == exec.host_network_namespace {
        return not_enforced(format!("the machine's own network namespace {own}"));
    }
    let text = match std::fs::read_to_string("/proc/net/dev") {
        Ok(text) => text,
        Err(error) => return not_enforced(format!("/proc/net/dev unreadable: {error}")),
    };
    let interfaces: Vec<&str> = text
        .lines()
        .skip(2)
        .filter_map(|line| line.split(':').next())
        .map(str::trim)
        .collect();
    if interfaces == ["lo"] {
        enforced_by_kernel(format!("a private network namespace {own}: only lo"))
    } else {
        not_enforced(format!("interfaces {}", interfaces.join(" ")))
    }
}

/// Process 1 and the engine's processes are not visible under `/proc`.
fn prove_processes_hidden(exec: &ExecFile) -> BoundReport {
    for pid in &exec.hidden_pids {
        if Path::new("/proc").join(pid.to_string()).exists() {
            return not_enforced(format!("process {pid} is visible under /proc"));
        }
    }
    enforced_by_kernel(format!(
        "ProtectProc=invisible: {} process(es) of root and the engine are not visible",
        exec.hidden_pids.len()
    ))
}

/// The unit's own cgroup limits, read from inside: `memory.max` and
/// `io.max`.
fn prove_cgroup_limits() -> (BoundReport, BoundReport) {
    let Some(group) = own_cgroup() else {
        let none = || not_enforced("this process's cgroup v2 group is unknown");
        return (none(), none());
    };
    let read = |name: &str| std::fs::read_to_string(group.join(name)).ok();
    let memory = match read("memory.max").map(|text| text.trim().to_owned()) {
        Some(value) if value != "max" && value.parse::<u64>().is_ok() => {
            enforced_by_kernel(format!("memory.max {value}"))
        }
        Some(value) => not_enforced(format!("memory.max {value}")),
        None => not_enforced("memory.max unreadable"),
    };
    let write_rate = match read("io.max") {
        Some(text) if text.contains("wbps=") && !text.contains("wbps=max") => {
            enforced_by_kernel(format!("io.max {}", text.trim()))
        }
        Some(text) => not_enforced(format!("io.max has no write rate: {:?}", text.trim())),
        None => not_enforced("io.max unreadable"),
    };
    (memory, write_rate)
}

fn own_cgroup() -> Option<PathBuf> {
    let text = std::fs::read_to_string("/proc/self/cgroup").ok()?;
    let path = text.lines().find_map(|line| line.strip_prefix("0::"))?;
    Some(Path::new("/sys/fs/cgroup").join(path.trim().trim_start_matches('/')))
}

/// Writes the report as one line. The connection stays open: it closes with
/// the workload's exec, or carries the exec's failure.
fn send_report(mut gate: &UnixStream, report: &ScopeReport) -> io::Result<()> {
    let mut bytes = serde_json::to_vec(report).map_err(io::Error::other)?;
    bytes.push(REPORT_FRAME_END);
    gate.write_all(&bytes)?;
    gate.flush()
}

/// Waits for the gate's go on the connection. Its close, or a read that
/// fails, is no go.
fn wait_for_go(gate: &UnixStream) -> Result<(), String> {
    let started = Instant::now();
    let mut got = Vec::new();
    let mut buffer = [0_u8; 16];
    loop {
        let left = GATE_WAIT.saturating_sub(started.elapsed());
        if left.is_zero() {
            return Err("no go in time".to_owned());
        }
        let mut poll = libc::pollfd {
            fd: gate.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        let millis = libc::c_int::try_from(left.as_millis()).unwrap_or(libc::c_int::MAX);
        // SAFETY: one valid pollfd.
        let ready = unsafe { libc::poll(&raw mut poll, 1, millis) };
        if ready <= 0 {
            continue;
        }
        // SAFETY: buffer is writable for its length; poll said the
        // connection is readable, so the read does not wait.
        let read =
            unsafe { libc::read(gate.as_raw_fd(), buffer.as_mut_ptr().cast(), buffer.len()) };
        if read > 0 {
            got.extend_from_slice(&buffer[..usize::try_from(read).unwrap_or(0)]);
            if got.as_slice() == GATE_GO {
                return Ok(());
            }
            if got.len() >= GATE_GO.len() {
                return Err("the gate wrote something other than its go".to_owned());
            }
        } else if read == 0 {
            return Err("the gate closed the connection without its go".to_owned());
        } else {
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::Interrupted {
                return Err(format!("the gate connection: {error}"));
            }
        }
    }
}

/// Puts the log pipes on descriptors 1 and 2, marks every descriptor above
/// 2 close-on-exec, enters the payload directory and becomes the workload's
/// program. Just before the exec it writes [`EXEC_MARK`] on the gate
/// connection, and the connection closes with the exec; when the exec fails,
/// why goes on it after the mark ([`exec_failed`]). Returns only when the
/// exec failed.
fn become_workload(exec: &ExecFile, gate: UnixStream, streams: WorkloadStreams) -> i32 {
    use std::os::unix::process::CommandExt as _;
    let mut report = gate;
    // Descriptor 2 becomes the workload's log pipe below, so a failure says
    // why on this close-on-exec copy of the journal (review r6 R6-04).
    // SAFETY: descriptor 2 is open; F_DUPFD_CLOEXEC returns a new one.
    let journal = unsafe { libc::fcntl(2, libc::F_DUPFD_CLOEXEC, 3) };
    if journal < 0 {
        return exec_failed(
            &mut report,
            None,
            &format!("the journal's descriptor: {}", io::Error::last_os_error()),
        );
    }
    // SAFETY: fcntl returned a new descriptor that nothing else owns.
    let mut journal = std::fs::File::from(unsafe { OwnedFd::from_raw_fd(journal) });
    for (stream, target) in [(&streams.stdout, 1), (&streams.stderr, 2)] {
        // SAFETY: both descriptors are open; dup2 makes `target` a copy of
        // the pipe's write end, without close-on-exec.
        if unsafe { libc::dup2(stream.as_raw_fd(), target) } != target {
            return exec_failed(
                &mut report,
                Some(&mut journal),
                &format!(
                    "log pipe on descriptor {target}: {}",
                    io::Error::last_os_error()
                ),
            );
        }
    }
    drop(streams);
    // SAFETY: CLOSE_RANGE_CLOEXEC marks descriptors 3 and up close-on-exec;
    // it closes nothing this process still reads before the exec.
    let marked = unsafe {
        libc::syscall(
            libc::SYS_close_range,
            3_u32,
            u32::MAX,
            libc::CLOSE_RANGE_CLOEXEC,
        )
    };
    if marked != 0 {
        return exec_failed(
            &mut report,
            Some(&mut journal),
            &format!(
                "descriptors above 2 could not be closed: {}",
                io::Error::last_os_error()
            ),
        );
    }
    let Some((program, args)) = exec.argv.split_first() else {
        return exec_failed(
            &mut report,
            Some(&mut journal),
            "exec.json names no program",
        );
    };
    // Without the mark the gate records that the workload never started, so
    // no exec follows a mark that did not reach it. That holds when the gate
    // is gone too (EPIPE): it may have judged `no_exec_in_time` already, and
    // an exec then would run a workload its record says never started. Not
    // to exec leaves at worst a record that says started for a workload that
    // never ran, the safe side for a retry (review r5 R5-01, pushed back).
    // Likewise a death between the mark and the execve, a window of a few
    // system calls, counts as started (r5 R5-02).
    if let Err(error) = report.write_all(EXEC_MARK) {
        return exec_failed(
            &mut report,
            Some(&mut journal),
            &format!("the exec mark did not reach the gate: {error}"),
        );
    }
    let error = std::process::Command::new(program)
        .args(args)
        .env_clear()
        .envs(&exec.env)
        .current_dir(&exec.cwd)
        .exec();
    exec_failed(
        &mut report,
        Some(&mut journal),
        &format!("{program}: {error}"),
    )
}

/// Tells the gate on its connection why the workload's exec failed, as one
/// line, then says it in the journal, and returns the status for it. The
/// gate is told first and the journal line goes to `journal`, the copy of
/// descriptor 2 from before it became the log pipe (None: descriptor 2 is
/// still the journal). PIPE is ignored again first: the standard library
/// resets it to its default for the exec and leaves it so when the exec
/// fails, and a write to a connection the gate closed would end `job-exec`
/// before the gate is told (review r6 R6-04).
fn exec_failed(report: &mut dyn Write, journal: Option<&mut std::fs::File>, why: &str) -> i32 {
    // SAFETY: SIG_IGN is a valid disposition for PIPE.
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_IGN);
    }
    let told = writeln!(report, "{}", why.replace('\n', " "));
    let line = match &told {
        Ok(()) => format!("job-exec: {why}"),
        Err(error) => format!("job-exec: {why}; the gate was not told: {error}"),
    };
    match journal {
        Some(journal) => {
            let _ = writeln!(journal, "{line}");
        }
        None => journal_line!("{line}"),
    }
    exec_status::EXEC_FAILED
}

#[cfg(test)]
mod tests {
    use std::os::unix::net::UnixListener;
    use std::time::{Duration, Instant};

    use super::{CHECKPOINT_SIGNALS, checkpoint_signal_number, connect_by_deadline};

    #[test]
    fn every_checkpoint_signal_a_template_may_name_is_caught_before_the_exec() {
        for name in CHECKPOINT_SIGNALS {
            assert!(checkpoint_signal_number(name).is_some(), "{name}");
        }
        assert_eq!(checkpoint_signal_number("TERM"), None);
    }

    #[test]
    fn a_connection_made_after_its_deadline_is_refused() {
        let dir = tempfile::tempdir().expect("a socket directory");
        let path = dir.path().join("gate.sock");
        let _listener = UnixListener::bind(&path).expect("a listening socket");
        let address = rustix::net::SocketAddrUnix::new(path.as_path()).expect("a unix address");
        // testkit-lint: allow(wall-clock) a deadline already past on the real clock
        let past = Instant::now()
            .checked_sub(Duration::from_millis(1))
            .expect("a past deadline");
        let refused =
            connect_by_deadline(&address, past).expect_err("a late connection is refused");
        assert_eq!(refused.kind(), std::io::ErrorKind::TimedOut, "{refused}");
        // testkit-lint: allow(wall-clock) a deadline ahead on the real clock
        let ahead = Instant::now() + Duration::from_secs(5);
        connect_by_deadline(&address, ahead).expect("a connection within its deadline");
    }

    /// A deadline that passed before the first try queues no connection
    /// (review r2 of #10579): the socket's listen queue stays empty, so no
    /// handler starts for a request that is already late.
    #[test]
    fn no_connection_is_tried_once_its_deadline_has_passed() {
        let dir = tempfile::tempdir().expect("a socket directory");
        let path = dir.path().join("gate.sock");
        let listener = UnixListener::bind(&path).expect("a listening socket");
        listener
            .set_nonblocking(true)
            .expect("a listener that does not block");
        let address = rustix::net::SocketAddrUnix::new(path.as_path()).expect("a unix address");
        // testkit-lint: allow(wall-clock) a deadline already past on the real clock
        let past = Instant::now()
            .checked_sub(Duration::from_millis(1))
            .expect("a past deadline");
        let refused = connect_by_deadline(&address, past).expect_err("a late request is refused");
        assert_eq!(refused.kind(), std::io::ErrorKind::TimedOut, "{refused}");
        match listener.accept() {
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
            other => panic!("a late request queued a connection: {other:?}"),
        }
    }
}
