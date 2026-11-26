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
#![cfg(target_os = "linux")]

use std::io::{BufRead as _, BufReader, Write as _};
use std::os::unix::fs::PermissionsExt as _;
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use oneiron_server::gpu_execution_node::scope_systemd::device_query::DeviceQueryError;
use oneiron_server::gpu_execution_node::scope_systemd::{control, device_query};
use oneiron_server::gpu_execution_node::{
    DeviceToolAccount, GpuProbeError, NvidiaSmiQuery, NvidiaSmiRoute, parse_compute_process_lines,
    parse_device_lines, parse_sample_lines,
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
}

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
    Standins {
        job_account_only: write_script(dir, "nvidia-smi", &job_account_only),
        before_hand_over: write_script(dir, "nvidia-smi-before-hand-over", &before_hand_over),
        refusing_loudly: write_script(dir, "nvidia-smi-refusing-loudly", &refusing_loudly),
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
/// request line, the query of `program` as `account`, the reply.
fn serve_device_queries(
    socket: &Path,
    program: PathBuf,
    account: DeviceToolAccount,
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
                Some(Ok(query)) => device_query::answer(query, &program, &account).map(Some),
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
    let dir = tempfile::tempdir().expect("tempdir");
    let program = standins().job_account_only.clone();
    let socket = dir.path().join("job-control.sock");
    let handler = serve_device_queries(&socket, program.clone(), job_account(), 3);
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
    // is read to its end, not killed at the deadline, and its error carries
    // a bounded part of each.
    let loud = NvidiaSmiRoute::Direct {
        program: standins().refusing_loudly.clone(),
    };
    let started = Instant::now();
    match loud.query(NvidiaSmiQuery::Devices) {
        Err(GpuProbeError::Unavailable { reason }) => {
            assert!(reason.contains("exited with exit status: 4: x"), "{reason}");
            assert!(reason.ends_with(&format!(" {NVML_REFUSAL}")), "{reason}");
            assert!(reason.len() < 700, "{} bytes: {reason}", reason.len());
            assert!(!reason.contains('\n'), "{reason}");
        }
        other => panic!("a refusal on the output is refused, got {other:?}"),
    }
    assert!(
        started.elapsed() < Duration::from_secs(9),
        "the loud refusal was read to its end, in {:?}",
        started.elapsed()
    );
}

#[test]
fn a_query_the_card_refuses_reaches_the_probe_as_unavailable_with_the_tools_reason() {
    let dir = tempfile::tempdir().expect("tempdir");
    let socket = dir.path().join("job-control.sock");
    let mut not_the_job_account = job_account();
    not_the_job_account.name = "oneiron".to_owned();
    let handler = serve_device_queries(
        &socket,
        standins().job_account_only.clone(),
        not_the_job_account,
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
fn a_listener_that_takes_no_connection_holds_the_probe_no_longer_than_its_deadline() {
    use rustix::net::{AddressFamily, SocketAddrUnix, SocketFlags, SocketType};
    let dir = tempfile::tempdir().expect("tempdir");
    let socket = dir.path().join("job-control.sock");
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
    drop((waiting, listener));
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
