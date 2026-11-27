//! FIX EXEC-NODE-PROBE-AFTER-HANDOVER (R6's first job, mel, 26 Nov 15:28):
//! after the device hand-over only the job account's group opens the card,
//! so the engine's GPU probe reads the cards through the job control socket,
//! whose root handler runs the query as the job account.
//!
//! The stand-in `nvidia-smi` answers only when it runs as the job account the
//! handler was given (its uid, its group, its `USER` and `LOGNAME`) and
//! otherwise refuses as NVML did on mel ("Insufficient Permissions", exit
//! 4). A test cannot switch to another uid without root, so here the job
//! account is this process's own uid and gid under its own name; the uid
//! switch itself is std's, proven on the field host by T40's engine probe
//! check (`check_device_handoff.sh --engine-account`).
//!
//! Review r1 of #10540: the engine's connection is bounded by the query's
//! deadline, a socket file no handler listens on leaves the query to the
//! tool run here, and a refused query answers the driver's own words.
//!
//! Review r2 of #10540: a query its kill cannot end holds the machine's
//! query lock until it ends, so later handlers refuse and start nothing
//! meanwhile; and a socket this account may not connect to leaves the query
//! to the tool run here.
//!
//! The Engine's review of #10540 after its merge: every handler locks the
//! one same file, in a directory only root writes, made at install. A
//! handler refuses an entry at the lock's name that is not that file, and
//! never opens, removes or makes it again; a lock directory another account
//! may write, or one reached through a link, is refused too. Here this
//! process's account stands in for root.
//!
//! Review r1 of #10541: the lock install makes is empty with mode 0600
//! whatever the umask, and a file at its name with another mode or with
//! content is not it; install refuses an engine's directory that overlaps
//! the lock's directory.
//!
//! Review r2 of #10541 and the Engine's review after it: install refuses any
//! entry where the version before this one (#10540) kept its lock, and
//! never opens, locks or removes it; it changes the mode of no lock
//! directory that was there; and it refuses an oneiron binary beneath that
//! directory.
#![cfg(target_os = "linux")]

use std::ffi::CString;
use std::io::{BufRead as _, BufReader, Write as _};
use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd};
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::{FileTypeExt as _, MetadataExt as _, PermissionsExt as _};
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use oneiron_server::gpu_execution_node::jobs::JobKeyId;
use oneiron_server::gpu_execution_node::scope_systemd::device_query::{
    DEVICE_QUERY_LOCK_FILE, DeviceQueryError, DeviceQuerySettings,
};
use oneiron_server::gpu_execution_node::scope_systemd::{control, device_query};
use oneiron_server::gpu_execution_node::{
    DeviceToolAccount, GPU_QUERY_TIMEOUT, GpuProbeError, NvidiaSmiQuery, NvidiaSmiRoute,
    parse_compute_process_lines, parse_device_lines, parse_sample_lines,
};

const JOB_ACCOUNT: &str = "oneiron-job-standin";
const CARD: &str = "GPU-cb30cb3d-5547-c5ae-4990-85433256f138";
/// What NVML said on mel when the engine's account ran the tool.
const NVML_REFUSAL: &str = "Failed to initialize NVML: Insufficient Permissions";

fn own_ids() -> (u32, u32) {
    (
        rustix::process::getuid().as_raw(),
        rustix::process::getgid().as_raw(),
    )
}

fn job_account() -> DeviceToolAccount {
    let (uid, gid) = own_ids();
    DeviceToolAccount {
        name: JOB_ACCOUNT.to_owned(),
        uid,
        gid,
    }
}

/// A directory of this process's account's, mode 0700, in `/tmp`, below
/// directories that are root's: a place the query lock may be in, as root's
/// directory is on an installed machine. tempfile makes it with the umask's
/// mode (0755 under 022), and install takes a lock directory that is there
/// only at mode 0700 (review r2 of #10541), so its mode is set here (FIX
/// EXEC-NODE-QUERY-LOCK-FIXTURE-DIR-MODE).
fn private_dir() -> tempfile::TempDir {
    let dir = tempfile::Builder::new()
        .prefix("oneiron-device-query")
        .tempdir_in("/tmp")
        .expect("a directory in /tmp");
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700))
        .expect("the directory's mode 0700");
    dir
}

/// The handler's settings for `account`, with the machine's query lock made
/// in `lock_dir` as install makes it (a path with no link on the way, as the
/// handler opens it).
fn settings_in(lock_dir: &Path, account: DeviceToolAccount) -> DeviceQuerySettings {
    let lock_dir = lock_dir
        .canonicalize()
        .expect("the lock directory's own path");
    device_query::provision_lock(&lock_dir).expect("make the query lock as install does");
    DeviceQuerySettings { account, lock_dir }
}

/// The stand-in `nvidia-smi`s. One directory for every test, written before
/// any of them starts a process: a script written while another thread
/// forks can be held open for writing in that child and refuse its own exec
/// (ETXTBSY).
struct Standins {
    /// Opens the card only as the job account: a card after the hand-over.
    job_account_only: PathBuf,
    /// Opens the card for whoever runs it: a card before the hand-over.
    before_hand_over: PathBuf,
    /// Refuses on its output, as NVML may, after a flood of error output
    /// past any pipe's buffer.
    refusing_loudly: PathBuf,
    /// Answers, and the first time leaves behind a process outside the
    /// query's process group that keeps the query's descriptors: a query the
    /// group's kill cannot end, as one wedged in a driver call is. That
    /// process's id is in [`ESCAPED_PID_FILE`] beside it before it answers.
    escaping: PathBuf,
    /// Keeps running past the deadline, with its id in [`SLOW_PID_FILE`].
    slow: PathBuf,
}

/// The file the escaping stand-in writes its left-behind process's id to.
const ESCAPED_PID_FILE: &str = "escaped.pid";

/// The file the slow stand-in writes its own process id to.
const SLOW_PID_FILE: &str = "slow.pid";

fn standins() -> &'static Standins {
    static STANDINS: OnceLock<(tempfile::TempDir, Standins)> = OnceLock::new();
    &STANDINS
        .get_or_init(|| {
            let dir = tempfile::tempdir().expect("tempdir");
            let standins = write_standins(dir.path());
            (dir, standins)
        })
        .1
}

fn write_standins(dir: &Path) -> Standins {
    let (uid, gid) = own_ids();
    let answers = format!(
        r#"case "$1 $2" in
  "--query-gpu=uuid,name,memory.total --format=csv,noheader,nounits")
    echo "{CARD}, NVIDIA GeForce RTX 4090, 24564" ;;
  "--query-compute-apps=gpu_uuid,pid --format=csv,noheader,nounits") ;;
  "--query-gpu=uuid,temperature.gpu,power.draw,memory.used --format=csv,noheader,nounits")
    echo "{CARD}, 41, 21.53, 2" ;;
  *) echo "unknown query $*" >&2; exit 2 ;;
esac
"#
    );
    let job_account_only = format!(
        r#"#!/bin/sh
if [ "$USER" != "{JOB_ACCOUNT}" ] || [ "$LOGNAME" != "{JOB_ACCOUNT}" ] || [ "$(id -u)" != "{uid}" ] || [ "$(id -g)" != "{gid}" ]; then
  echo "{NVML_REFUSAL}" >&2
  exit 4
fi
{answers}"#
    );
    let before_hand_over = format!("#!/bin/sh\n{answers}");
    let refusing_loudly = format!(
        r#"#!/bin/sh
echo "{NVML_REFUSAL}"
head -c 1048576 /dev/zero | tr '\0' x >&2
exit 4
"#
    );
    let escaping = format!(
        r#"#!/bin/sh
pid_file="$(dirname "$0")/{ESCAPED_PID_FILE}"
if [ ! -e "$pid_file" ]; then
  setsid sh -c 'echo $$ > "$1.new" && mv "$1.new" "$1" && exec sleep 600' sh "$pid_file" < /dev/null > /dev/null 2>&1 &
  until [ -s "$pid_file" ]; do :; done
fi
echo "{CARD}, NVIDIA GeForce RTX 4090, 24564"
"#
    );
    let slow = format!(
        r#"#!/bin/sh
trap '' TERM
echo "$$" > "$(dirname "$0")/{SLOW_PID_FILE}"
exec sleep 60
"#
    );
    Standins {
        job_account_only: write_script(dir, "nvidia-smi", &job_account_only),
        before_hand_over: write_script(dir, "nvidia-smi-before-hand-over", &before_hand_over),
        refusing_loudly: write_script(dir, "nvidia-smi-refusing-loudly", &refusing_loudly),
        escaping: write_script(dir, "nvidia-smi-escaping", &escaping),
        slow: write_script(dir, "nvidia-smi-slow", &slow),
    }
}

fn write_script(dir: &Path, name: &str, body: &str) -> PathBuf {
    let path = dir.join(name);
    std::fs::write(&path, body).expect("write the stand-in");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).expect("chmod");
    path
}

/// A job control socket at `socket` whose handler serves `connections`
/// device queries as the root handler does past its caller check: the
/// request line, the query of `program` as the settings' account under
/// their query lock, the reply.
fn serve_device_queries(
    socket: &Path,
    program: PathBuf,
    settings: DeviceQuerySettings,
    connections: usize,
) -> std::thread::JoinHandle<()> {
    let listener = UnixListener::bind(socket).expect("bind the stand-in control socket");
    std::thread::spawn(move || {
        for _ in 0..connections {
            let (mut stream, _) = listener.accept().expect("accept");
            let mut line = String::new();
            BufReader::new(&stream)
                .read_line(&mut line)
                .expect("the request line");
            let answer = match device_query::parse_request(line.as_bytes()) {
                Some(Ok(query)) => device_query::answer(query, &program, &settings).map(Some),
                Some(Err(why)) => Err(why),
                None => Err("not a device query".to_owned()),
            };
            stream
                .write_all(&control::render_reply(&answer))
                .expect("the reply");
        }
    })
}

#[test]
fn after_the_hand_over_the_probe_reads_the_cards_through_the_job_control_socket_as_the_job_account()
{
    let dir = private_dir();
    let program = standins().job_account_only.clone();
    let socket = dir.path().join("job-control.sock");
    let handler = serve_device_queries(
        &socket,
        program.clone(),
        settings_in(dir.path(), job_account()),
        3,
    );
    let route = NvidiaSmiRoute::JobControl {
        socket: socket.clone(),
        fallback_program: program.clone(),
    };

    let devices = parse_device_lines(
        &route
            .query(NvidiaSmiQuery::Devices)
            .expect("the devices through the job account"),
    )
    .expect("readable device lines");
    assert_eq!(devices.len(), 1);
    assert_eq!(devices[0].device_id, CARD);
    assert_eq!(devices[0].model, "NVIDIA GeForce RTX 4090");
    assert_eq!(devices[0].memory_total_mib, 24_564);
    let processes = parse_compute_process_lines(
        &route
            .query(NvidiaSmiQuery::ComputeProcesses)
            .expect("the compute processes through the job account"),
    )
    .expect("readable process lines");
    assert!(processes.is_empty(), "{processes:?}");
    let samples = parse_sample_lines(
        &route
            .query(NvidiaSmiQuery::Samples)
            .expect("the samples through the job account"),
    )
    .expect("readable sample lines");
    assert_eq!(samples.len(), 1);
    assert_eq!(samples[0].temperature_c, Some(41));
    assert_eq!(samples[0].power_mw, Some(21_530));
    handler.join().expect("the handler");

    // Main's probe on the same machine: the engine runs the tool as its own
    // account, and the card refuses it, as on mel.
    match (NvidiaSmiRoute::Direct { program }).query(NvidiaSmiQuery::Devices) {
        Err(GpuProbeError::Unavailable { reason }) => {
            assert!(reason.contains("exited with exit status: 4"), "{reason}");
        }
        other => panic!("the engine's own run is refused, got {other:?}"),
    }
}

#[test]
fn a_refused_query_answers_the_drivers_own_words_on_one_bounded_line() {
    // NVML's reason on the error output reaches the engine's error, as it
    // reaches the readiness check's drain.
    let refused_here = NvidiaSmiRoute::Direct {
        program: standins().job_account_only.clone(),
    };
    match refused_here.query(NvidiaSmiQuery::Devices) {
        Err(GpuProbeError::Unavailable { reason }) => assert!(
            reason.ends_with(&format!("exited with exit status: 4: {NVML_REFUSAL}")),
            "{reason}"
        ),
        other => panic!("the engine's own run is refused, got {other:?}"),
    }
    // On the output, after an error output past any pipe's buffer: the query
    // is read to its end, not killed at the deadline (that error would say
    // it did not answer in time, not how it exited), and its error carries a
    // bounded part of each.
    let loud = NvidiaSmiRoute::Direct {
        program: standins().refusing_loudly.clone(),
    };
    match loud.query(NvidiaSmiQuery::Devices) {
        Err(GpuProbeError::Unavailable { reason }) => {
            assert!(reason.contains("exited with exit status: 4: x"), "{reason}");
            assert!(reason.ends_with(&format!(" {NVML_REFUSAL}")), "{reason}");
            assert!(reason.len() < 700, "{} bytes: {reason}", reason.len());
            assert!(!reason.contains('\n'), "{reason}");
        }
        other => panic!("a refusal on the output is refused, got {other:?}"),
    }
}

#[test]
fn a_query_the_card_refuses_reaches_the_probe_as_unavailable_with_the_tools_reason() {
    let dir = private_dir();
    let socket = dir.path().join("job-control.sock");
    let mut not_the_job_account = job_account();
    not_the_job_account.name = "oneiron".to_owned();
    let handler = serve_device_queries(
        &socket,
        standins().job_account_only.clone(),
        settings_in(dir.path(), not_the_job_account),
        1,
    );
    // A handler's refusal stays a refusal: the tool run here, which would
    // answer, is not asked.
    let route = NvidiaSmiRoute::JobControl {
        socket,
        fallback_program: standins().before_hand_over.clone(),
    };
    match route.query(NvidiaSmiQuery::Devices) {
        Err(GpuProbeError::Unavailable { reason }) => {
            assert!(
                reason.starts_with("job control refused the nvidia-devices query: "),
                "{reason}"
            );
            assert!(
                reason.ends_with(&format!("exited with exit status: 4: {NVML_REFUSAL}")),
                "{reason}"
            );
            // The handler's reason does not name the error's class again.
            assert!(!reason.contains("gpu_probe.unavailable"), "{reason}");
        }
        other => panic!("a refused query is unavailable, got {other:?}"),
    }
    handler.join().expect("the handler");
}

#[test]
fn a_socket_file_no_handler_listens_on_leaves_the_query_to_the_tool_run_here() {
    let dir = tempfile::tempdir().expect("tempdir");
    // A file the socket unit left behind: the listener is gone, its file is
    // not, and it still looks usable.
    let socket = dir.path().join("job-control.sock");
    drop(UnixListener::bind(&socket).expect("bind"));
    assert!(control::control_socket_usable(&socket));
    let route = NvidiaSmiRoute::JobControl {
        socket: socket.clone(),
        fallback_program: standins().before_hand_over.clone(),
    };
    let devices = parse_device_lines(
        &route
            .query(NvidiaSmiQuery::Devices)
            .expect("the devices from the tool run here"),
    )
    .expect("readable device lines");
    assert_eq!(devices.len(), 1);
    assert_eq!(devices[0].device_id, CARD);
    // The file went away between the route's choice and the connection.
    let gone = NvidiaSmiRoute::JobControl {
        socket: dir.path().join("gone.sock"),
        fallback_program: standins().before_hand_over.clone(),
    };
    assert!(
        gone.query(NvidiaSmiQuery::Samples).is_ok(),
        "the samples from the tool run here"
    );
    // After the hand-over the tool run here is refused too, and the error
    // names both.
    let after = NvidiaSmiRoute::JobControl {
        socket: socket.clone(),
        fallback_program: standins().job_account_only.clone(),
    };
    match after.query(NvidiaSmiQuery::Devices) {
        Err(GpuProbeError::Unavailable { reason }) => {
            assert!(
                reason.starts_with(&format!(
                    "no job control handler listens at {}: ",
                    socket.display()
                )),
                "{reason}"
            );
            assert!(reason.contains("; run here: "), "{reason}");
            assert!(reason.ends_with(NVML_REFUSAL), "{reason}");
        }
        other => panic!("both refusals, got {other:?}"),
    }
}

#[test]
fn a_socket_this_account_may_not_connect_to_leaves_the_query_to_the_tool_run_here() {
    if rustix::process::getuid().is_root() {
        // Root passes any file's mode, so it cannot be denied this way.
        return;
    }
    let dir = tempfile::tempdir().expect("tempdir");
    // A listener this account may not connect to: on the field host, a
    // security module that lets it write the socket's file but denies the
    // connection, so the route still takes the socket; here, the file's
    // mode. Both answer EACCES at the connection, before any request.
    let socket = dir.path().join("job-control.sock");
    let _listener = UnixListener::bind(&socket).expect("bind");
    std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o000)).expect("chmod");
    let route = NvidiaSmiRoute::JobControl {
        socket: socket.clone(),
        fallback_program: standins().before_hand_over.clone(),
    };
    let devices = parse_device_lines(
        &route
            .query(NvidiaSmiQuery::Devices)
            .expect("the devices from the tool run here"),
    )
    .expect("readable device lines");
    assert_eq!(devices.len(), 1);
    assert_eq!(devices[0].device_id, CARD);
    // After the hand-over the tool run here is refused too, and the error
    // names both.
    let after = NvidiaSmiRoute::JobControl {
        socket: socket.clone(),
        fallback_program: standins().job_account_only.clone(),
    };
    match after.query(NvidiaSmiQuery::Devices) {
        Err(GpuProbeError::Unavailable { reason }) => {
            assert!(
                reason.starts_with(&format!(
                    "this account may not connect to the job control socket at {}: ",
                    socket.display()
                )),
                "{reason}"
            );
            assert!(reason.contains("; run here: "), "{reason}");
            assert!(reason.ends_with(NVML_REFUSAL), "{reason}");
        }
        other => panic!("both refusals, got {other:?}"),
    }
}

/// Runs one test in its own process and checks that its assertions ran.
fn run_isolated_device_query_test(test: &str, flag: &str, marker: &str) {
    let dir = private_dir();
    let child = std::process::Command::new(std::env::current_exe().expect("this test binary"))
        .args(["--exact", test, "--nocapture", "--test-threads", "1"])
        .env(flag, "1")
        .env("TMPDIR", dir.path())
        .env_remove("USER")
        .env_remove("LOGNAME")
        .output()
        .expect("run the isolated test");
    let stdout = String::from_utf8_lossy(&child.stdout);
    let stderr = String::from_utf8_lossy(&child.stderr);
    assert!(
        child.status.success() && stdout.contains(marker),
        "the isolated test exited with {}:\n{stdout}{stderr}",
        child.status
    );
}

/// Makes `connect` return EPERM on this x86-64 test thread and its children.
#[cfg(target_arch = "x86_64")]
fn deny_connect_with_eperm() {
    use libc::{BPF_ABS, BPF_JEQ, BPF_JMP, BPF_K, BPF_LD, BPF_RET, BPF_W, sock_filter};

    const AUDIT_ARCH_X86_64: u32 = 0xC000_003E;
    let statement = |code, k| sock_filter {
        code,
        jt: 0,
        jf: 0,
        k,
    };
    let jump_if_equal = |k, jf| sock_filter {
        code: (BPF_JMP | BPF_JEQ | BPF_K) as u16,
        jt: 0,
        jf,
        k,
    };
    let load_word = (BPF_LD | BPF_W | BPF_ABS) as u16;
    let ret = (BPF_RET | BPF_K) as u16;
    let mut filters = [
        statement(load_word, 4), // seccomp_data.arch
        jump_if_equal(AUDIT_ARCH_X86_64, 3),
        statement(load_word, 0), // seccomp_data.nr
        jump_if_equal(libc::SYS_connect as u32, 1),
        statement(ret, libc::SECCOMP_RET_ERRNO | libc::EPERM as u32),
        statement(ret, libc::SECCOMP_RET_ALLOW),
    ];
    let program = libc::sock_fprog {
        len: filters.len().try_into().expect("the filter length"),
        filter: filters.as_mut_ptr(),
    };
    let one: libc::c_ulong = 1;
    let zero: libc::c_ulong = 0;
    // SAFETY: these are the integer arguments required for PR_SET_NO_NEW_PRIVS.
    let no_new_privs = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, one, zero, zero, zero) };
    assert_eq!(
        no_new_privs,
        0,
        "prctl: {}",
        std::io::Error::last_os_error()
    );
    // SAFETY: program points to the initialized filter array for this call.
    let installed = unsafe {
        libc::syscall(
            libc::SYS_seccomp,
            libc::SECCOMP_SET_MODE_FILTER,
            0_u32,
            &raw const program,
        )
    };
    assert_eq!(installed, 0, "seccomp: {}", std::io::Error::last_os_error());
}

/// Off x86-64 there is no filter to make `connect` answer EPERM (the one
/// above checks the x86-64 audit arch), so the run lists this case as
/// ignored, with that reason.
#[cfg(not(target_arch = "x86_64"))]
#[test]
#[ignore = "the seccomp filter that makes connect answer EPERM is written for x86-64 only"]
fn a_socket_whose_connect_answers_eperm_leaves_the_query_to_the_tool_run_here() {}

#[cfg(target_arch = "x86_64")]
#[test]
fn a_socket_whose_connect_answers_eperm_leaves_the_query_to_the_tool_run_here() {
    const CHILD: &str = "ONEIRON_TEST_CONNECT_EPERM";
    const MARKER: &str = "eperm-child-ran";
    if std::env::var_os(CHILD).is_none() {
        run_isolated_device_query_test(
            "a_socket_whose_connect_answers_eperm_leaves_the_query_to_the_tool_run_here",
            CHILD,
            MARKER,
        );
        return;
    }
    deny_connect_with_eperm();

    let dir = private_dir();
    let socket = dir.path().join("job-control.sock");
    let _listener = UnixListener::bind(&socket).expect("bind");
    std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600)).expect("chmod");
    match NvidiaSmiRoute::of_machine(&socket) {
        NvidiaSmiRoute::JobControl {
            socket: selected, ..
        } => assert_eq!(selected, socket),
        other => panic!("the socket looks usable before connect, got {other:?}"),
    }

    let route = NvidiaSmiRoute::JobControl {
        socket: socket.clone(),
        fallback_program: standins().before_hand_over.clone(),
    };
    let devices = parse_device_lines(
        &route
            .query(NvidiaSmiQuery::Devices)
            .expect("the devices from the tool run here"),
    )
    .expect("readable device lines");
    assert_eq!(devices.len(), 1);
    assert_eq!(devices[0].device_id, CARD);

    let after = NvidiaSmiRoute::JobControl {
        socket: socket.clone(),
        fallback_program: standins().job_account_only.clone(),
    };
    match after.query(NvidiaSmiQuery::Devices) {
        Err(GpuProbeError::Unavailable { reason }) => {
            assert!(
                reason.starts_with(&format!(
                    "this account may not connect to the job control socket at {}: ",
                    socket.display()
                )),
                "{reason}"
            );
            let eperm = std::io::Error::from_raw_os_error(libc::EPERM).to_string();
            assert!(reason.contains(&eperm), "{reason}");
            assert!(reason.contains("; run here: "), "{reason}");
            assert!(reason.ends_with(NVML_REFUSAL), "{reason}");
        }
        other => panic!("both refusals, got {other:?}"),
    }
    println!("{MARKER}");
}

#[test]
fn a_query_its_kill_cannot_end_holds_the_machines_query_lock_until_it_ends() {
    let dir = private_dir();
    let socket = dir.path().join("job-control.sock");
    let settings = settings_in(dir.path(), job_account());
    let lock_file = settings.lock_dir.join(DEVICE_QUERY_LOCK_FILE);
    let handler = serve_device_queries(&socket, standins().escaping.clone(), settings, 3);
    let route = NvidiaSmiRoute::JobControl {
        socket,
        fallback_program: standins().before_hand_over.clone(),
    };

    // The first query answers, and a process of it lives on out of the
    // reach of its group's kill, with the query's descriptors.
    let devices = parse_device_lines(
        &route
            .query(NvidiaSmiQuery::Devices)
            .expect("the first query answers"),
    )
    .expect("readable device lines");
    assert_eq!(devices[0].device_id, CARD);
    let escaped: i32 =
        std::fs::read_to_string(standins().escaping.with_file_name(ESCAPED_PID_FILE))
            .expect("the left-behind process's id")
            .trim()
            .parse()
            .expect("a process id");

    // While it lives, the next handler refuses and starts no query.
    match route.query(NvidiaSmiQuery::Devices) {
        Err(GpuProbeError::Unavailable { reason }) => assert!(
            reason.starts_with("job control refused the nvidia-devices query: query_stuck"),
            "{reason}"
        ),
        other => panic!("a query while an earlier one lives is refused, got {other:?}"),
    }

    // Once it ends, the lock is free, and the next query is served.
    rustix::process::kill_process(
        rustix::process::Pid::from_raw(escaped).expect("a process id"),
        rustix::process::Signal::KILL,
    )
    .expect("kill the left-behind process");
    let (freed, free) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let taken = std::fs::File::open(&lock_file).and_then(|file| file.lock());
        let _ = freed.send(taken.map_err(|error| error.to_string()));
    });
    free.recv_timeout(Duration::from_secs(10))
        .expect("the lock is free once the left-behind process has ended")
        .expect("the lock");
    let devices = parse_device_lines(
        &route
            .query(NvidiaSmiQuery::Devices)
            .expect("the query after the earlier one ended is served"),
    )
    .expect("readable device lines");
    assert_eq!(devices[0].device_id, CARD);
    handler.join().expect("the handler");
}

#[test]
fn a_query_past_its_deadline_is_refused_and_its_killed_process_frees_the_lock() {
    // Keep the query runner's unreaped-process count separate from other tests.
    const CHILD: &str = "ONEIRON_TEST_DEVICE_QUERY_DEADLINE";
    const MARKER: &str = "deadline-child-ran";
    if std::env::var_os(CHILD).is_none() {
        run_isolated_device_query_test(
            "a_query_past_its_deadline_is_refused_and_its_killed_process_frees_the_lock",
            CHILD,
            MARKER,
        );
        return;
    }

    let dir = private_dir();
    let socket = dir.path().join("job-control.sock");
    let settings = settings_in(dir.path(), job_account());
    let lock_file = settings.lock_dir.join(DEVICE_QUERY_LOCK_FILE);
    let program = &standins().slow;
    let handler = serve_device_queries(&socket, program.clone(), settings, 1);
    let route = NvidiaSmiRoute::JobControl {
        socket,
        fallback_program: standins().before_hand_over.clone(),
    };

    // testkit-lint: allow(wall-clock) measures the real query deadline
    let started = Instant::now();
    let answer = route.query(NvidiaSmiQuery::Devices);
    let elapsed = started.elapsed();
    match answer {
        Err(GpuProbeError::Unavailable { reason }) => {
            assert!(
                reason.starts_with("job control refused the nvidia-devices query: "),
                "{reason}"
            );
            assert!(
                reason.contains(&format!("{} did not answer within 10 s", program.display())),
                "{reason}"
            );
        }
        other => panic!("a query past its deadline is refused, got {other:?}"),
    }
    assert!(
        (GPU_QUERY_TIMEOUT..=GPU_QUERY_TIMEOUT + Duration::from_secs(6)).contains(&elapsed),
        "the query took {elapsed:?}, expected the 10 s deadline plus at most 6 s"
    );

    let raw_pid: i32 = std::fs::read_to_string(program.with_file_name(SLOW_PID_FILE))
        .expect("the slow stand-in's pid file")
        .trim()
        .parse()
        .expect("a process id");
    assert!(raw_pid > 0, "not a process id: {raw_pid}");
    let pid = rustix::process::Pid::from_raw(raw_pid).expect("a process id");
    // testkit-lint: allow(wall-clock) bounds both real process cleanup checks
    let deadline = Instant::now() + Duration::from_secs(10);
    let (freed, free) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let taken = std::fs::File::open(&lock_file).and_then(|file| file.lock());
        let _ = freed.send(taken);
    });
    // testkit-lint: allow(wall-clock) the same process cleanup deadline
    let remaining = deadline.saturating_duration_since(Instant::now());
    free.recv_timeout(remaining)
        .expect("the lock is free once the timed-out query's process is killed")
        .expect("the lock");
    loop {
        match rustix::process::test_kill_process(pid) {
            Err(rustix::io::Errno::SRCH) => break,
            other => other.expect("check whether the timed-out query's process exists"),
        }
        // testkit-lint: allow(wall-clock) the same process cleanup deadline
        let within_deadline = Instant::now() < deadline;
        assert!(
            within_deadline,
            "the timed-out query's process still exists"
        );
        // testkit-lint: allow(sleep) poll for the reaper to collect the real child
        std::thread::sleep(Duration::from_millis(10));
    }
    handler.join().expect("the handler");
    println!("{MARKER}");
}

#[test]
fn a_query_whose_output_passes_the_cap_is_refused_early_and_its_group_ends() {
    // Reap the orphaned sleep here instead of relying on PID 1. Run only
    // this test in the subreaper so it adopts no children of other tests.
    const ISOLATED: &str = "ONEIRON_TEST_DEVICE_QUERY_OUTPUT_CAP";
    if std::env::var_os(ISOLATED).is_none() {
        let child = std::process::Command::new(std::env::current_exe().expect("this test binary"))
            .args([
                "--exact",
                "a_query_whose_output_passes_the_cap_is_refused_early_and_its_group_ends",
                "--nocapture",
            ])
            .env(ISOLATED, "1")
            .output()
            .expect("run the isolated test");
        let stdout = String::from_utf8_lossy(&child.stdout);
        let stderr = String::from_utf8_lossy(&child.stderr);
        assert!(
            child.status.success() && stdout.contains("1 passed"),
            "the isolated test: {stdout}{stderr}"
        );
        return;
    }
    rustix::process::set_child_subreaper(Some(rustix::process::getpid()))
        .expect("adopt orphaned query children");

    let dir = private_dir();
    let settings = settings_in(dir.path(), job_account());
    let program = write_script(
        dir.path(),
        "nvidia-smi-overflow",
        r#"#!/bin/sh
sleep 30 &
echo "$!" > "$(dirname "$0")/overflow.pid"
head -c 2097152 /dev/zero
sleep 30
"#,
    );
    // testkit-lint: allow(wall-clock) measures the real query timeout
    let started = Instant::now();
    let result = device_query::answer(NvidiaSmiQuery::Devices, &program, &settings);
    let elapsed = started.elapsed();

    let raw_pid: i32 = std::fs::read_to_string(dir.path().join("overflow.pid"))
        .expect("the background sleep's pid file")
        .trim()
        .parse()
        .expect("a process id");
    assert!(raw_pid > 0, "not a process id: {raw_pid}");
    let pid = rustix::process::Pid::from_raw(raw_pid).expect("a process id");
    // testkit-lint: allow(wall-clock) bounds the wait for the orphan to exit
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        // SAFETY: a positive PID selects only this child, and a null
        // status pointer discards its status. It may not be adopted yet.
        let _ = unsafe { libc::waitpid(raw_pid, std::ptr::null_mut(), libc::WNOHANG) };
        match rustix::process::test_kill_process(pid) {
            Err(rustix::io::Errno::SRCH) => break,
            other => other.expect("check whether the background sleep exists"),
        }
        // testkit-lint: allow(wall-clock) the same process-exit deadline
        let within_deadline = Instant::now() < deadline;
        assert!(within_deadline, "the background sleep still exists");
        // testkit-lint: allow(sleep) poll for adoption and exit of a real child
        std::thread::sleep(Duration::from_millis(10));
    }

    let reason = result.expect_err("the query exceeded the output cap");
    assert!(
        reason.starts_with("device_query_output_too_long:"),
        "{reason}"
    );
    assert!(
        elapsed < Duration::from_secs(10),
        "the query took {elapsed:?}"
    );
}

/// What a test puts at the query lock's name in place of the lock install
/// makes.
#[derive(Debug, Clone, Copy)]
enum LockEntry {
    Absent,
    /// A link to a file outside the lock's directory.
    Link,
    /// A second name of a file outside the lock's directory.
    HardLink,
    Directory,
    Pipe,
    /// The lock's own kind of file, empty, but mode 0666.
    OtherMode,
    /// The lock's own kind of file, mode 0600, but with a byte in it.
    WithContent,
}

impl LockEntry {
    const ALL: [Self; 7] = [
        Self::Absent,
        Self::Link,
        Self::HardLink,
        Self::Directory,
        Self::Pipe,
        Self::OtherMode,
        Self::WithContent,
    ];

    fn make(self, at: &Path, outside: &Path) {
        match self {
            Self::Absent => {}
            Self::Link => std::os::unix::fs::symlink(outside, at).expect("a link"),
            Self::HardLink => std::fs::hard_link(outside, at).expect("a hard link"),
            Self::Directory => std::fs::create_dir(at).expect("a directory"),
            Self::Pipe => {
                let name = CString::new(at.as_os_str().as_bytes()).expect("a path with no NUL");
                // SAFETY: name is NUL terminated.
                let made = unsafe { libc::mkfifo(name.as_ptr(), 0o600) };
                assert_eq!(made, 0, "mkfifo: {}", std::io::Error::last_os_error());
            }
            Self::OtherMode => write_with_mode(at, b"", 0o666),
            Self::WithContent => write_with_mode(at, b"x", 0o600),
        }
    }

    /// Whether the entry at `at` is still the one [`Self::make`] put there.
    fn is_as_made(self, at: &Path, outside: &Path) -> bool {
        let found = std::fs::symlink_metadata(at);
        match (self, found) {
            (Self::Absent, Err(error)) => error.kind() == std::io::ErrorKind::NotFound,
            (Self::Link, Ok(meta)) => {
                meta.file_type().is_symlink()
                    && std::fs::read_link(at).is_ok_and(|target| target == outside)
            }
            (Self::HardLink, Ok(meta)) => meta.is_file() && meta.nlink() == 2,
            (Self::Directory, Ok(meta)) => meta.is_dir(),
            (Self::Pipe, Ok(meta)) => meta.file_type().is_fifo(),
            (Self::OtherMode, Ok(meta)) => {
                meta.is_file() && meta.mode() & 0o7777 == 0o666 && meta.len() == 0
            }
            (Self::WithContent, Ok(meta)) => {
                meta.is_file() && meta.mode() & 0o7777 == 0o600 && meta.len() == 1
            }
            _ => false,
        }
    }

    fn remove(self, at: &Path) {
        match self {
            Self::Absent => {}
            Self::Directory => std::fs::remove_dir(at).expect("remove the directory"),
            Self::Link | Self::HardLink | Self::Pipe | Self::OtherMode | Self::WithContent => {
                std::fs::remove_file(at).expect("remove the entry");
            }
        }
    }
}

/// Writes `bytes` to a new file at `at`, then gives it `mode`.
fn write_with_mode(at: &Path, bytes: &[u8], mode: u32) {
    std::fs::write(at, bytes).expect("write the entry");
    std::fs::set_permissions(at, std::fs::Permissions::from_mode(mode)).expect("chmod");
}

/// The opens of one file, by any of its names: inotify watches the file,
/// not a name, so an open through a hard link counts too.
struct OpenWatch {
    inotify: OwnedFd,
}

impl OpenWatch {
    fn new(file: &Path) -> Self {
        // SAFETY: inotify_init1 has no preconditions.
        let raw = unsafe { libc::inotify_init1(libc::IN_NONBLOCK | libc::IN_CLOEXEC) };
        assert!(
            raw >= 0,
            "inotify_init1: {}",
            std::io::Error::last_os_error()
        );
        // SAFETY: the kernel just returned this descriptor.
        let inotify = unsafe { OwnedFd::from_raw_fd(raw) };
        let name = CString::new(file.as_os_str().as_bytes()).expect("a path with no NUL");
        // SAFETY: inotify is an inotify descriptor; name is NUL terminated.
        let watch =
            unsafe { libc::inotify_add_watch(inotify.as_raw_fd(), name.as_ptr(), libc::IN_OPEN) };
        assert!(
            watch >= 0,
            "inotify_add_watch: {}",
            std::io::Error::last_os_error()
        );
        Self { inotify }
    }

    /// The file's opens since the last count: a watch on a file gives each
    /// open one event with no name.
    fn opens(&self) -> usize {
        let mut events = [0_u8; 4096];
        let mut opens = 0;
        loop {
            // SAFETY: events is valid for writes of its whole length.
            let read = unsafe {
                libc::read(
                    self.inotify.as_raw_fd(),
                    events.as_mut_ptr().cast(),
                    events.len(),
                )
            };
            let Ok(read) = usize::try_from(read) else {
                break;
            };
            if read == 0 {
                break;
            }
            opens += read / std::mem::size_of::<libc::inotify_event>();
        }
        opens
    }
}

#[test]
fn a_query_lock_entry_that_is_not_the_lock_install_made_is_refused_never_opened_and_left_as_it_is()
{
    let outside_dir = private_dir();
    let outside = outside_dir
        .path()
        .canonicalize()
        .expect("the outside directory's own path")
        .join("outside");
    std::fs::write(&outside, b"outside").expect("write the outside file");
    let program = standins().before_hand_over.clone();
    for entry in LockEntry::ALL {
        let dir = private_dir();
        let lock_dir = dir
            .path()
            .canonicalize()
            .expect("the lock directory's own path");
        let lock = lock_dir.join(DEVICE_QUERY_LOCK_FILE);
        entry.make(&lock, &outside);
        let settings = DeviceQuerySettings {
            account: job_account(),
            lock_dir: lock_dir.clone(),
        };
        let watch = OpenWatch::new(&outside);
        let reason = device_query::answer(NvidiaSmiQuery::Devices, &program, &settings)
            .expect_err("no query runs without the lock install made");
        assert!(
            reason.starts_with(&format!("device_query_lock: {}: ", lock.display())),
            "{entry:?}: {reason}"
        );
        let said = match entry {
            LockEntry::Absent => "absent; `oneiron execution-node install` makes it",
            _ => "; refused and left as it is",
        };
        assert!(reason.contains(said), "{entry:?}: {reason}");
        assert_eq!(watch.opens(), 0, "{entry:?}: the outside file was opened");
        assert!(
            entry.is_as_made(&lock, &outside),
            "{entry:?}: the entry changed"
        );
        // The watch sees an open.
        drop(std::fs::File::open(&outside).expect("open the outside file"));
        assert_eq!(watch.opens(), 1, "{entry:?}: the watch saw no open");
        assert_eq!(
            std::fs::read(&outside).expect("read the outside file"),
            b"outside"
        );

        // Install refuses the entry too, for its maker to remove; then it
        // makes the lock, once, and the query runs under it.
        if !matches!(entry, LockEntry::Absent) {
            let refused = device_query::provision_lock(&lock_dir)
                .expect_err("install leaves an entry it did not make");
            assert!(
                refused.contains("remove it, then install again"),
                "{entry:?}: {refused}"
            );
            assert!(
                entry.is_as_made(&lock, &outside),
                "{entry:?}: install changed it"
            );
            entry.remove(&lock);
        }
        assert!(device_query::provision_lock(&lock_dir).expect("install makes the lock"));
        assert!(!device_query::provision_lock(&lock_dir).expect("a second install"));
        device_query::answer(NvidiaSmiQuery::Devices, &program, &settings)
            .expect("the query runs under the lock install made");
    }
}

#[test]
fn a_query_lock_directory_another_account_may_write_or_reached_through_a_link_is_refused() {
    let dir = private_dir();
    let settings = settings_in(dir.path(), job_account());
    let lock = settings.lock_dir.join(DEVICE_QUERY_LOCK_FILE);
    let mode = |path: &Path| {
        std::fs::metadata(path)
            .expect("the entry's facts")
            .permissions()
            .mode()
            & 0o7777
    };
    // Install's lock: an empty file of its own, mode 0600, in a directory of
    // its own, mode 0700.
    assert_eq!(mode(&settings.lock_dir), 0o700);
    assert_eq!(mode(&lock), 0o600);
    assert_eq!(std::fs::metadata(&lock).expect("the lock's facts").len(), 0);
    let program = standins().before_hand_over.clone();
    let inode = |path: &Path| std::fs::metadata(path).expect("the lock's facts").ino();
    let lock_inode = inode(&lock);
    for open_to_others in [0o770, 0o707, 0o1777] {
        std::fs::set_permissions(
            &settings.lock_dir,
            std::fs::Permissions::from_mode(open_to_others),
        )
        .expect("chmod");
        let reason = device_query::answer(NvidiaSmiQuery::Devices, &program, &settings)
            .expect_err("a lock directory another account may write is refused");
        assert!(
            reason.starts_with("device_query_lock: ") && reason.contains("writable by group or"),
            "mode {open_to_others:o}: {reason}"
        );
        // Install changes the mode of no directory that was there: it
        // refuses and leaves it as it is (review r2 of #10541). Its owner
        // gives it 0700 back, and the lock stays the same file.
        let refused = device_query::provision_lock(&settings.lock_dir)
            .expect_err("install refuses a lock directory another account may write");
        assert!(refused.contains("move it aside"), "{refused}");
        assert_eq!(mode(&settings.lock_dir), open_to_others);
        let own = std::fs::Permissions::from_mode(0o700);
        std::fs::set_permissions(&settings.lock_dir, own).expect("chmod 0700");
        let changed = device_query::provision_lock(&settings.lock_dir).expect("install again");
        assert!(!changed, "install finds its lock as it made it");
        assert_eq!(inode(&lock), lock_inode);
        device_query::answer(NvidiaSmiQuery::Devices, &program, &settings)
            .expect("the query runs once the directory is its owner's alone");
    }
    // The handler opens each directory on the way itself, never through a
    // link.
    let links = private_dir();
    let through_link = links
        .path()
        .canonicalize()
        .expect("the links directory's own path")
        .join("lock-dir");
    std::os::unix::fs::symlink(&settings.lock_dir, &through_link).expect("a link");
    let linked = DeviceQuerySettings {
        account: job_account(),
        lock_dir: through_link,
    };
    let reason = device_query::answer(NvidiaSmiQuery::Devices, &program, &linked)
        .expect_err("a lock directory reached through a link is refused");
    assert!(
        reason.starts_with("device_query_lock: ") && reason.contains("a link"),
        "{reason}"
    );
}

/// Set by [`install_makes_the_query_lock_mode_0600_whatever_the_umask`] for
/// its child process alone: the lock directory the child makes.
const UMASK_CHILD_LOCK_DIR: &str = "ONEIRON_TEST_UMASK_0277_LOCK_DIR";

#[test]
fn install_makes_the_query_lock_mode_0600_whatever_the_umask() {
    let dir = private_dir();
    let lock_dir = dir
        .path()
        .canonicalize()
        .expect("the directory's own path")
        .join("lock");
    // The umask is the whole process's: the make runs in a child of its own,
    // this test binary running only the test below.
    let ran = std::process::Command::new(std::env::current_exe().expect("this test binary"))
        .args([
            "--exact",
            "provision_lock_under_umask_0277",
            "--ignored",
            "--test-threads",
            "1",
        ])
        .env(UMASK_CHILD_LOCK_DIR, &lock_dir)
        .output()
        .expect("run the child");
    let said = format!(
        "{}{}",
        String::from_utf8_lossy(&ran.stdout),
        String::from_utf8_lossy(&ran.stderr)
    );
    assert!(
        ran.status.success() && said.contains("1 passed"),
        "the child: {said}"
    );
    let facts = |path: &Path| std::fs::metadata(path).expect("the entry's facts");
    assert_eq!(facts(&lock_dir).permissions().mode() & 0o7777, 0o700);
    let lock = facts(&lock_dir.join(DEVICE_QUERY_LOCK_FILE));
    assert!(lock.is_file());
    assert_eq!(lock.permissions().mode() & 0o7777, 0o600);
    assert_eq!(lock.len(), 0);
}

/// The umask takes the write bits and every group and other bit, so the
/// directory is made 0500 and the lock 0400 until install sets their modes.
/// Not 0777: this account stands in for root, and only root opens the
/// directory a 0777 umask makes mode 000 before install sets its mode (FIX
/// EXEC-NODE-QUERY-LOCK-UMASK-TEST-NONROOT).
#[test]
#[ignore = "the child of install_makes_the_query_lock_mode_0600_whatever_the_umask"]
fn provision_lock_under_umask_0277() {
    let Some(lock_dir) = std::env::var_os(UMASK_CHILD_LOCK_DIR) else {
        return;
    };
    // SAFETY: umask has no preconditions.
    unsafe { libc::umask(0o277) };
    assert!(
        device_query::provision_lock(Path::new(&lock_dir)).expect("install under umask 0277"),
        "install made the lock"
    );
}

#[test]
fn install_refuses_an_engines_directory_that_is_holds_or_lies_beneath_the_query_locks() {
    let lock_dir = Path::new(device_query::DEVICE_QUERY_LOCK_DIR);
    let check = |what: &str, dir: &str| {
        device_query::require_apart_from_lock_dir(what, Path::new(dir), lock_dir)
    };
    for refused in [
        "/var/lib/oneiron-job-control",
        "/var/lib/oneiron-job-control/state",
        "/var/lib/oneiron-job-control/./work/payloads",
        "/var/lib",
        "/",
    ] {
        let reason = check("state directory", refused)
            .expect_err("an engine's directory that overlaps the lock's is refused");
        assert!(
            reason.starts_with(&format!("the state directory {refused} must not be")),
            "{refused}: {reason}"
        );
    }
    for apart in [
        "/var/lib/oneiron",
        "/var/lib/oneiron-job-control-state",
        "/var/lib/oneiron-job",
        "/srv/oneiron/state",
    ] {
        assert_eq!(check("payload directory", apart), Ok(()), "{apart}");
    }
}

#[test]
fn install_refuses_any_entry_at_the_old_locks_place_and_changes_nothing() {
    let dir = private_dir();
    let state_dir = dir
        .path()
        .canonicalize()
        .expect("the state directory's own path");
    let old = state_dir.join(device_query::STATE_DIR_LOCK_FILE);
    // Nothing there, or no state directory yet: install goes on.
    assert_eq!(
        device_query::require_no_old_state_dir_lock(&state_dir),
        Ok(())
    );
    assert_eq!(
        device_query::require_no_old_state_dir_lock(&state_dir.join("absent")),
        Ok(())
    );

    // Any entry there is refused with the steps by hand, and install opens,
    // locks and removes none of it.
    let outside_dir = private_dir();
    let outside = outside_dir
        .path()
        .canonicalize()
        .expect("the outside directory's own path")
        .join("outside");
    std::fs::write(&outside, b"outside").expect("write the outside file");
    for entry in LockEntry::ALL {
        if matches!(entry, LockEntry::Absent) {
            continue;
        }
        entry.make(&old, &outside);
        let watch = OpenWatch::new(&outside);
        let refused = device_query::require_no_old_state_dir_lock(&state_dir)
            .expect_err("install refuses an entry at the old lock's place");
        assert!(
            refused.starts_with(&format!("{}: ", old.display()))
                && refused.contains("oneiron-job-control.socket")
                && refused.contains("then install again"),
            "{entry:?}: {refused}"
        );
        assert_eq!(watch.opens(), 0, "{entry:?}: the outside file was opened");
        assert!(
            entry.is_as_made(&old, &outside),
            "{entry:?}: the entry changed"
        );
        entry.remove(&old);
    }

    // The lock as that version's handler made it, held by a query of it.
    write_with_mode(&old, b"", 0o600);
    let inode = std::fs::metadata(&old).expect("the old lock").ino();
    let query = std::fs::File::open(&old).expect("open the old lock");
    query.lock().expect("the old query holds the lock");
    let refused = device_query::require_no_old_state_dir_lock(&state_dir);
    assert!(refused.is_err(), "the old lock is refused");
    assert_eq!(
        std::fs::metadata(&old).expect("the old lock is left").ino(),
        inode
    );
    drop(query);
    let refused = device_query::require_no_old_state_dir_lock(&state_dir);
    assert!(refused.is_err(), "the old lock is refused once free, too");
}

#[test]
fn install_changes_the_mode_of_no_query_lock_directory_that_was_there() {
    let parent = private_dir();
    let lock_dir = parent
        .path()
        .canonicalize()
        .expect("the parent's own path")
        .join("oneiron-job-control");
    std::fs::create_dir(&lock_dir).expect("a directory that was there");
    let open = std::fs::Permissions::from_mode(0o755);
    std::fs::set_permissions(&lock_dir, open).expect("mode 0755");
    let refused = device_query::provision_lock(&lock_dir)
        .expect_err("install refuses a lock directory that was there with another mode");
    assert!(
        refused.contains("mode 755, not 700") && refused.contains("move it aside"),
        "{refused}"
    );
    let meta = std::fs::metadata(&lock_dir).expect("the directory");
    assert_eq!(meta.mode() & 0o7777, 0o755, "its mode is left");
    let lock = lock_dir.join(device_query::DEVICE_QUERY_LOCK_FILE);
    let made = std::fs::symlink_metadata(&lock).is_ok();
    assert!(!made, "no lock is made in it");
}

#[test]
fn install_refuses_an_oneiron_binary_beneath_the_query_locks_directory() {
    let lock_dir = Path::new(device_query::DEVICE_QUERY_LOCK_DIR);
    let check = |binary: &str| {
        device_query::require_install_paths_apart(
            Path::new("/var/lib/oneiron/state"),
            Path::new("/var/lib/oneiron/work"),
            Path::new(binary),
            lock_dir,
        )
    };
    let refused = check("/var/lib/oneiron-job-control/oneiron")
        .expect_err("a binary the job unit runs beneath the lock's directory is refused");
    assert!(
        refused.starts_with("the oneiron binary /var/lib/oneiron-job-control/oneiron must not"),
        "{refused}"
    );
    assert_eq!(check("/usr/local/bin/oneiron"), Ok(()));
}

/// A full listen queue. Keep both the listener and its queued clients open.
fn full_queue_listener(dir: &Path) -> (PathBuf, (OwnedFd, Vec<OwnedFd>)) {
    use rustix::net::{AddressFamily, SocketAddrUnix, SocketFlags, SocketType};
    let socket = dir.join("job-control.sock");
    let address = SocketAddrUnix::new(&socket).expect("the socket's address");
    // A listener with no accept backlog that never accepts, its queue full.
    let listener =
        rustix::net::socket(AddressFamily::UNIX, SocketType::STREAM, None).expect("a socket");
    rustix::net::bind(&listener, &address).expect("bind");
    rustix::net::listen(&listener, 0).expect("listen with no backlog");
    let mut waiting = Vec::new();
    loop {
        let client = rustix::net::socket_with(
            AddressFamily::UNIX,
            SocketType::STREAM,
            SocketFlags::NONBLOCK | SocketFlags::CLOEXEC,
            None,
        )
        .expect("a socket");
        match rustix::net::connect(&client, &address) {
            Ok(()) => waiting.push(client),
            Err(rustix::io::Errno::AGAIN) => break,
            Err(other) => panic!("filling the queue: {other}"),
        }
        assert!(waiting.len() < 64, "the queue never filled");
    }
    (socket, (listener, waiting))
}

#[test]
fn a_listener_that_takes_no_connection_holds_the_probe_no_longer_than_its_deadline() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (socket, _guards) = full_queue_listener(dir.path());
    let wait = Duration::from_secs(1);
    let (answered, answer) = std::sync::mpsc::channel();
    let asked = socket.clone();
    std::thread::spawn(move || {
        let _ = answered.send(device_query::request_within(
            &asked,
            NvidiaSmiQuery::Devices,
            wait,
        ));
    });
    match answer.recv_timeout(wait + Duration::from_secs(5)) {
        Ok(Err(DeviceQueryError::Unavailable(GpuProbeError::Unavailable { reason }))) => {
            assert!(
                reason.contains("the handler took no connection in time"),
                "{reason}"
            );
        }
        Ok(other) => panic!("a full queue is no answer in time, got {other:?}"),
        Err(_) => panic!("the probe still waited to connect 5 s past its 1 s deadline"),
    }
}

#[test]
fn a_listener_that_takes_no_connection_holds_a_job_request_no_longer_than_its_deadline() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (socket, _guards) = full_queue_listener(dir.path());
    let wait = Duration::from_secs(1);
    let (answered, answer) = std::sync::mpsc::channel();
    let asked = socket.clone();
    std::thread::spawn(move || {
        let id = JobKeyId::for_key("k");
        let _ = answered.send(control::request_at(
            &asked,
            control::ControlVerb::Stop,
            &id,
            wait,
        ));
    });
    let reason = answer
        .recv_timeout(wait + Duration::from_secs(5))
        .expect("the job request still waited to connect 5 s past its 1 s deadline")
        .expect_err("the listener took no connection");
    assert!(
        reason.starts_with(&format!("{}: ", socket.display()))
            && reason.contains("the handler took no connection in time"),
        "{reason}"
    );
}

#[test]
fn a_probe_with_no_job_control_socket_it_may_use_runs_the_tool_itself() {
    let dir = tempfile::tempdir().expect("tempdir");
    assert!(!control::control_socket_usable(
        &dir.path().join("absent.sock")
    ));
    let plain = dir.path().join("plain-file");
    std::fs::write(&plain, b"").expect("write");
    assert!(!control::control_socket_usable(&plain));
    let socket = dir.path().join("job-control.sock");
    let _listener = UnixListener::bind(&socket).expect("bind");
    assert!(control::control_socket_usable(&socket));
    if !rustix::process::getuid().is_root() {
        // Root may write to any file; anyone else needs the socket's group.
        std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o440)).expect("chmod");
        assert!(!control::control_socket_usable(&socket));
    }
}

#[test]
fn the_handlers_reply_carries_the_output_with_its_length_and_a_refusal_on_one_line() {
    assert_eq!(control::render_reply(&Ok(None)), b"ok\n");
    assert_eq!(
        control::render_reply(&Ok(Some(b"a, b\nc, d\n".to_vec()))),
        b"ok 10\na, b\nc, d\n"
    );
    assert_eq!(
        control::render_reply(&Err("tool said\nno\r".to_owned())),
        b"refused tool said no \n"
    );
}
