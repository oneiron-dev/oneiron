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
#![cfg(target_os = "linux")]

use std::io::{BufRead as _, BufReader, Write as _};
use std::os::unix::fs::PermissionsExt as _;
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use oneiron_server::gpu_execution_node::scope_systemd::{control, device_query};
use oneiron_server::gpu_execution_node::{
    DeviceToolAccount, GpuProbeError, NvidiaSmiQuery, NvidiaSmiRoute, parse_compute_process_lines,
    parse_device_lines, parse_sample_lines,
};

const JOB_ACCOUNT: &str = "oneiron-job-standin";
const CARD: &str = "GPU-cb30cb3d-5547-c5ae-4990-85433256f138";

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

/// An `nvidia-smi` that opens the card only as the job account. One file for
/// every test, written before any of them starts a process: a script written
/// while another thread forks can be held open for writing in that child and
/// refuse its own exec (ETXTBSY).
fn standin_nvidia_smi() -> PathBuf {
    static STANDIN: OnceLock<(tempfile::TempDir, PathBuf)> = OnceLock::new();
    STANDIN
        .get_or_init(|| {
            let dir = tempfile::tempdir().expect("tempdir");
            let path = write_standin(dir.path());
            (dir, path)
        })
        .1
        .clone()
}

fn write_standin(dir: &Path) -> PathBuf {
    let (uid, gid) = own_ids();
    let path = dir.join("nvidia-smi");
    std::fs::write(
        &path,
        format!(
            r#"#!/bin/sh
if [ "$USER" != "{JOB_ACCOUNT}" ] || [ "$LOGNAME" != "{JOB_ACCOUNT}" ] || [ "$(id -u)" != "{uid}" ] || [ "$(id -g)" != "{gid}" ]; then
  echo "Failed to initialize NVML: Insufficient Permissions" >&2
  exit 4
fi
case "$1 $2" in
  "--query-gpu=uuid,name,memory.total --format=csv,noheader,nounits")
    echo "{CARD}, NVIDIA GeForce RTX 4090, 24564" ;;
  "--query-compute-apps=gpu_uuid,pid --format=csv,noheader,nounits") ;;
  "--query-gpu=uuid,temperature.gpu,power.draw,memory.used --format=csv,noheader,nounits")
    echo "{CARD}, 41, 21.53, 2" ;;
  *) echo "unknown query $*" >&2; exit 2 ;;
esac
"#
        ),
    )
    .expect("write the stand-in");
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
    let program = standin_nvidia_smi();
    let socket = dir.path().join("job-control.sock");
    let handler = serve_device_queries(&socket, program.clone(), job_account(), 3);
    let route = NvidiaSmiRoute::JobControl {
        socket: socket.clone(),
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
fn a_query_the_card_refuses_reaches_the_probe_as_unavailable_with_the_tools_reason() {
    let dir = tempfile::tempdir().expect("tempdir");
    let program = standin_nvidia_smi();
    let socket = dir.path().join("job-control.sock");
    let mut not_the_job_account = job_account();
    not_the_job_account.name = "oneiron".to_owned();
    let handler = serve_device_queries(&socket, program, not_the_job_account, 1);
    match (NvidiaSmiRoute::JobControl { socket }).query(NvidiaSmiQuery::Devices) {
        Err(GpuProbeError::Unavailable { reason }) => {
            assert!(
                reason.starts_with("job control refused the nvidia-devices query: "),
                "{reason}"
            );
            assert!(reason.contains("exited with exit status: 4"), "{reason}");
        }
        other => panic!("a refused query is unavailable, got {other:?}"),
    }
    handler.join().expect("the handler");
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
