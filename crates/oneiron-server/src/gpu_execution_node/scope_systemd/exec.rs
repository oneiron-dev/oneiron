//! `oneiron job-exec <id>` (the job account, the unit's `ExecStart=`): it
//! applies `exec.json` and nothing else (pass 33, 7.6). It proves each bound
//! it can from inside the unit, reports them to the root gate, and becomes
//! the workload only after the gate's go. The service manager applies some
//! settings only where the kernel allows and is silent when it cannot, so a
//! bound the template requires and the proof does not find refuses the job
//! before any workload process exists (pass 34, 2.2: any other bound is
//! recorded unproven).
//!
//! Order: open the two gate pipes; prove the device policy (before the file
//! wall, so a refusal is the device policy's and not the wall's); apply the
//! inner file wall (Landlock); prove the wall, the protected paths, the
//! network, the hidden processes and the cgroup limits; report; wait for the
//! go; close every descriptor above 2; `execve`.

use std::collections::BTreeMap;
use std::ffi::CString;
use std::io::{self, Write as _};
use std::os::fd::{AsFd as _, AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt as _;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use super::records::{BoundProof, ExecFile, ScopeReport, bound};
use super::{EXCHANGE_ROOT, EXEC_FILE_NAME, GATE_GO, GO_PIPE_NAME, REPORT_PIPE_NAME, exec_status, is_job_instance};

/// How long `job-exec` waits for the gate's read end, and then for its go.
const GATE_WAIT: Duration = Duration::from_secs(45);

/// The step. Returns its exit status when it does not become the workload.
#[must_use]
pub fn run(args: &[String]) -> i32 {
    let [instance] = args else {
        eprintln!("job-exec: usage: job-exec <instance>");
        return exec_status::EXEC_FILE;
    };
    if !is_job_instance(instance) {
        eprintln!("job-exec: {instance:?} is not a job instance");
        return exec_status::EXEC_FILE;
    }
    let exchange = Path::new(EXCHANGE_ROOT).join(instance);
    let exec = match read_exec_file(&exchange, instance) {
        Ok(exec) => exec,
        Err(why) => {
            eprintln!("job-exec: {why}");
            return exec_status::EXEC_FILE;
        }
    };
    let (report_pipe, go_pipe) = match open_gate_pipes(&exchange) {
        Ok(pipes) => pipes,
        Err(why) => {
            eprintln!("job-exec: {why}");
            return exec_status::GATE_PIPES;
        }
    };
    let mut proofs = BTreeMap::new();
    proofs.insert(bound::DEVICE_CLOSURE.to_owned(), prove_device_closure(&exec));
    let wall = apply_file_wall(&exec);
    let wall_error = wall.as_ref().err().cloned();
    proofs.insert(
        bound::FILE_WALL.to_owned(),
        match &wall {
            Ok(()) => prove_file_wall(&exec, &exchange),
            Err(why) => BoundProof::none(format!("Landlock not applied: {why}")),
        },
    );
    proofs.insert(bound::NETWORK_CLOSED.to_owned(), prove_network_closed());
    proofs.insert(bound::PROCESSES_HIDDEN.to_owned(), prove_processes_hidden(&exec));
    let (memory, write_rate) = prove_cgroup_limits();
    proofs.insert(bound::MEMORY_CAP.to_owned(), memory);
    proofs.insert(bound::WRITE_RATE_CAP.to_owned(), write_rate);
    let refusal = exec
        .require
        .iter()
        .find(|name| !proofs.get(name.as_str()).is_some_and(BoundProof::holds))
        .map(|name| {
            let evidence = proofs
                .get(name.as_str())
                .map_or("not proved from inside", |proof| proof.evidence.as_str());
            format!("required_bound_not_proved: {name}: {evidence}")
        });
    let report = ScopeReport {
        instance: instance.clone(),
        proofs,
        refusal: refusal.clone(),
    };
    if let Err(error) = send_report(report_pipe, &report) {
        eprintln!("job-exec: the report did not reach the gate: {error}");
        return exec_status::GATE_PIPES;
    }
    if exec.probe {
        return exec_status::PROBE_DONE;
    }
    if let Some(why) = refusal {
        eprintln!("job-exec: refused before the workload: {why}");
        return if wall_error.is_some() && why.contains(bound::FILE_WALL) {
            exec_status::FILE_WALL
        } else {
            exec_status::REQUIRED_BOUND
        };
    }
    if let Err(why) = wait_for_go(&go_pipe) {
        eprintln!("job-exec: no go from the gate: {why}");
        return exec_status::GATE_REFUSED;
    }
    drop(go_pipe);
    become_workload(&exec)
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

/// The report pipe's write end (it opens once the gate holds the read end)
/// and the go pipe's read end.
fn open_gate_pipes(exchange: &Path) -> Result<(OwnedFd, OwnedFd), String> {
    let go = open_raw(
        &exchange.join(GO_PIPE_NAME),
        libc::O_RDONLY | libc::O_NONBLOCK | libc::O_CLOEXEC,
    )
    .map_err(|error| format!("go pipe: {error}"))?;
    let started = Instant::now();
    loop {
        match open_raw(
            &exchange.join(REPORT_PIPE_NAME),
            libc::O_WRONLY | libc::O_NONBLOCK | libc::O_CLOEXEC,
        ) {
            Ok(report) => return Ok((report, go)),
            Err(error) if error.raw_os_error() == Some(libc::ENXIO) => {
                if started.elapsed() >= GATE_WAIT {
                    return Err("the gate never opened the report pipe".to_owned());
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(error) => return Err(format!("report pipe: {error}")),
        }
    }
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
fn prove_device_closure(exec: &ExecFile) -> BoundProof {
    for path in &exec.devices_allowed {
        if let Err(error) = open_raw(path, libc::O_RDONLY | libc::O_NONBLOCK | libc::O_CLOEXEC) {
            return BoundProof::none(format!("the leased device {} does not open: {error}", path.display()));
        }
    }
    let Some(other) = exec.devices_denied.first() else {
        return BoundProof::kernel("DevicePolicy=closed; no other device exists here to try");
    };
    match open_raw(other, libc::O_RDONLY | libc::O_NONBLOCK | libc::O_CLOEXEC) {
        Ok(_) => BoundProof::none(format!("{} opened: the device policy did not apply", other.display())),
        Err(error) if error.raw_os_error() == Some(libc::EPERM) => BoundProof::kernel(format!(
            "{} refused by the device policy (EPERM); {} leased device(s) open",
            other.display(),
            exec.devices_allowed.len()
        )),
        Err(error) => BoundProof::none(format!(
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
fn prove_file_wall(exec: &ExecFile, exchange: &Path) -> BoundProof {
    let out_probe = exec.cwd.join("out").join(".oneiron-wall-probe");
    match std::fs::File::create(&out_probe) {
        Ok(_) => {
            let _ = std::fs::remove_file(&out_probe);
        }
        Err(error) => return BoundProof::none(format!("out/ is not writable: {error}")),
    }
    let outside = Path::new("/tmp/.oneiron-wall-probe");
    if std::fs::File::create(outside).is_ok() {
        let _ = std::fs::remove_file(outside);
        return BoundProof::none("/tmp was writable: the wall did not apply".to_owned());
    }
    if std::fs::read(exchange.join(EXEC_FILE_NAME)).is_ok() {
        return BoundProof::none("the exchange directory was readable: the wall did not apply".to_owned());
    }
    for path in &exec.protected {
        if open_raw(path, libc::O_RDONLY | libc::O_NONBLOCK | libc::O_CLOEXEC).is_ok() {
            return BoundProof::none(format!("{} opened", path.display()));
        }
    }
    BoundProof::kernel(format!(
        "Landlock ABI {}: /tmp and the exchange directory refused; {} protected path(s) refused",
        oneiron_container::landlock_abi(),
        exec.protected.len()
    ))
}

/// The job is alone with its loopback: `/proc/net/dev` lists the job's own
/// network namespace.
fn prove_network_closed() -> BoundProof {
    let text = match std::fs::read_to_string("/proc/net/dev") {
        Ok(text) => text,
        Err(error) => return BoundProof::none(format!("/proc/net/dev unreadable: {error}")),
    };
    let interfaces: Vec<&str> = text
        .lines()
        .skip(2)
        .filter_map(|line| line.split(':').next())
        .map(str::trim)
        .collect();
    if interfaces == ["lo"] {
        BoundProof::kernel("a private network namespace: only lo")
    } else {
        BoundProof::none(format!("interfaces {}", interfaces.join(" ")))
    }
}

/// Process 1 and the engine's processes are not visible under `/proc`.
fn prove_processes_hidden(exec: &ExecFile) -> BoundProof {
    for pid in &exec.hidden_pids {
        if Path::new("/proc").join(pid.to_string()).exists() {
            return BoundProof::none(format!("process {pid} is visible under /proc"));
        }
    }
    BoundProof::kernel(format!(
        "ProtectProc=invisible: {} process(es) of root and the engine are not visible",
        exec.hidden_pids.len()
    ))
}

/// The unit's own cgroup limits, read from inside: `memory.max` and
/// `io.max`.
fn prove_cgroup_limits() -> (BoundProof, BoundProof) {
    let Some(group) = own_cgroup() else {
        let none = || BoundProof::none("this process's cgroup v2 group is unknown");
        return (none(), none());
    };
    let read = |name: &str| std::fs::read_to_string(group.join(name)).ok();
    let memory = match read("memory.max").map(|text| text.trim().to_owned()) {
        Some(value) if value != "max" && value.parse::<u64>().is_ok() => {
            BoundProof::kernel(format!("memory.max {value}"))
        }
        Some(value) => BoundProof::none(format!("memory.max {value}")),
        None => BoundProof::none("memory.max unreadable"),
    };
    let write_rate = match read("io.max") {
        Some(text) if text.contains("wbps=") && !text.contains("wbps=max") => {
            BoundProof::kernel(format!("io.max {}", text.trim()))
        }
        Some(text) => BoundProof::none(format!("io.max has no write rate: {:?}", text.trim())),
        None => BoundProof::none("io.max unreadable"),
    };
    (memory, write_rate)
}

fn own_cgroup() -> Option<PathBuf> {
    let text = std::fs::read_to_string("/proc/self/cgroup").ok()?;
    let path = text.lines().find_map(|line| line.strip_prefix("0::"))?;
    Some(Path::new("/sys/fs/cgroup").join(path.trim().trim_start_matches('/')))
}

fn send_report(pipe: OwnedFd, report: &ScopeReport) -> io::Result<()> {
    // SAFETY: the pipe stays open for this call; clearing O_NONBLOCK makes
    // the write wait for the reader instead of failing on a full pipe.
    unsafe {
        let flags = libc::fcntl(pipe.as_raw_fd(), libc::F_GETFL);
        if flags >= 0 {
            libc::fcntl(pipe.as_raw_fd(), libc::F_SETFL, flags & !libc::O_NONBLOCK);
        }
    }
    let bytes = serde_json::to_vec(report).map_err(io::Error::other)?;
    let mut file = std::fs::File::from(pipe);
    file.write_all(&bytes)?;
    file.flush()
}

fn wait_for_go(go: &OwnedFd) -> Result<(), String> {
    let started = Instant::now();
    let mut got = Vec::new();
    let mut buffer = [0_u8; 16];
    loop {
        let left = GATE_WAIT.saturating_sub(started.elapsed());
        if left.is_zero() {
            return Err("no go in time".to_owned());
        }
        let mut poll = libc::pollfd {
            fd: go.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        let millis = libc::c_int::try_from(left.as_millis()).unwrap_or(libc::c_int::MAX);
        // SAFETY: one valid pollfd.
        let ready = unsafe { libc::poll(&raw mut poll, 1, millis) };
        if ready <= 0 {
            continue;
        }
        // SAFETY: buffer is writable for its length.
        let read = unsafe { libc::read(go.as_raw_fd(), buffer.as_mut_ptr().cast(), buffer.len()) };
        if read > 0 {
            got.extend_from_slice(&buffer[..usize::try_from(read).unwrap_or(0)]);
            if got.as_slice() == GATE_GO {
                return Ok(());
            }
            if got.len() >= GATE_GO.len() {
                return Err("the gate wrote something other than its go".to_owned());
            }
        } else if read == 0 || poll.revents & libc::POLLHUP != 0 {
            return Err("the gate closed the go pipe without its go".to_owned());
        }
    }
}

/// Closes every descriptor above 2, enters the payload directory and
/// becomes the workload's program. Returns only when `execve` failed.
fn become_workload(exec: &ExecFile) -> i32 {
    use std::os::unix::process::CommandExt as _;
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
        eprintln!(
            "job-exec: descriptors above 2 could not be closed: {}",
            io::Error::last_os_error()
        );
        return exec_status::EXEC_FAILED;
    }
    let Some((program, args)) = exec.argv.split_first() else {
        eprintln!("job-exec: exec.json names no program");
        return exec_status::EXEC_FAILED;
    };
    let error = std::process::Command::new(program)
        .args(args)
        .env_clear()
        .envs(&exec.env)
        .current_dir(&exec.cwd)
        .exec();
    eprintln!("job-exec: {program}: {error}");
    exec_status::EXEC_FAILED
}
