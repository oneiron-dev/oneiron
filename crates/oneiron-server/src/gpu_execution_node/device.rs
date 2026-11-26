//! The GPUs this machine has and what runs on them now, read live from the
//! NVIDIA driver at each ask. Nothing here keeps a reading: the slot table
//! asks again at every availability answer, reservation and launch
//! recheck, so a card is never offered from an old reading.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use oneiron::job_workload::{
    DeviceClosure, DeviceFacts, DeviceIdSource, DeviceKind, DeviceMemory, DeviceState,
};
use serde::{Deserialize, Serialize};

pub use oneiron::machine_capacity::GpuDevice;

/// The driver's command-line query tool.
pub(crate) const NVIDIA_SMI: &str = "nvidia-smi";

/// The vendor of every GPU [`NVIDIA_SMI`] lists.
const NVIDIA: &str = "nvidia";

/// The compute feature every GPU [`NVIDIA_SMI`] lists offers.
const CUDA: &str = "cuda";

/// The longest one driver query may take before it counts as failed, so a
/// hung driver never holds the slot table.
pub const GPU_QUERY_TIMEOUT: Duration = Duration::from_secs(10);

/// How often a running query is checked for its end.
const QUERY_POLL: Duration = Duration::from_millis(10);

/// One compute process the driver reports on a card.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GpuComputeProcess {
    /// The card it runs on (the driver's UUID).
    pub device_id: String,
    /// Its process id, when the driver gives one.
    pub pid: Option<u32>,
}

/// One device's condition now, as the driver reports it: what a breadcrumb
/// line carries while a key runs (pass 34, 7.3). A figure the driver does
/// not give is `None`, never zero.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceSample {
    /// The device (the driver's UUID).
    pub device_id: String,
    /// Its temperature, in degrees Celsius.
    pub temperature_c: Option<i32>,
    /// Its power draw, in milliwatts.
    pub power_mw: Option<u64>,
    /// The device memory in use, in MiB.
    pub memory_used_mib: Option<u64>,
}

/// Why this machine could not say what its GPUs are, what runs on them,
/// which of them another booker holds, whether it is drained, or what its
/// jobs' disk holds.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
#[serde(tag = "error", rename_all = "snake_case")]
pub enum GpuProbeError {
    #[error("gpu_probe.unavailable: the GPU driver could not be queried: {reason}")]
    Unavailable { reason: String },
    #[error("gpu_probe.unreadable: the GPU driver answered a line this probe cannot read: {line}")]
    Unreadable { line: String },
    #[error(
        "gpu_probe.withheld_unreadable: the list of GPUs another booker holds could not be read: {reason}"
    )]
    WithheldUnreadable { reason: String },
    #[error("gpu_probe.drain_unreadable: the GPU drain file could not be read: {reason}")]
    DrainUnreadable { reason: String },
    #[error("gpu_probe.disk_unreadable: the GPU jobs' disk could not be read: {reason}")]
    DiskUnreadable { reason: String },
    /// A lease and its launch recheck find their GPU by id, so a reading
    /// that lists one id on two lines cannot say which line is that GPU.
    #[error(
        "gpu_probe.repeated_device: the GPU driver listed device {device_id} on more than one line"
    )]
    RepeatedDevice { device_id: String },
}

/// What the slot table asks of this machine's GPU driver, at each ask.
pub trait GpuDeviceProbe: Send + Sync {
    /// Each GPU's device id, model and memory.
    ///
    /// # Errors
    ///
    /// [`GpuProbeError`] when the driver cannot be queried or answers a
    /// line it cannot read.
    fn devices(&self) -> Result<Vec<GpuDevice>, GpuProbeError>;

    /// Every compute process on every GPU now.
    ///
    /// # Errors
    ///
    /// [`GpuProbeError`] when the driver cannot be queried or answers a
    /// line it cannot read.
    fn compute_processes(&self) -> Result<Vec<GpuComputeProcess>, GpuProbeError>;

    /// Each device's temperature, power draw and memory in use now, where
    /// the driver gives them. The default reads none: a probe that cannot
    /// read them reports nothing, never zero.
    ///
    /// # Errors
    ///
    /// [`GpuProbeError`] when the driver cannot be queried or answers a
    /// line it cannot read.
    fn samples(&self) -> Result<Vec<DeviceSample>, GpuProbeError> {
        Ok(Vec::new())
    }
}

/// The shipped probe: `nvidia-smi`, one query per ask, on this machine's
/// [`NvidiaSmiRoute`] at that ask. Each query runs in its own process
/// group, and its output is read on the asking thread up to the query's
/// deadline; past it the pipe's read end is closed and the group killed, so
/// no helper that keeps the pipe open (even one in a session of its own)
/// holds a thread or a descriptor of this server. While a killed query of
/// any probe in this process is still unreaped, every query is refused, so
/// a stuck driver never piles up waiting threads. Through the job control
/// socket the root handler runs the query by these same rules, and this
/// process waits on the socket no longer than the query's deadline and a
/// margin.
#[derive(Debug, Clone, Copy, Default)]
pub struct NvidiaSmiProbe;

impl GpuDeviceProbe for NvidiaSmiProbe {
    fn devices(&self) -> Result<Vec<GpuDevice>, GpuProbeError> {
        parse_device_lines(&NvidiaSmiRoute::of_this_machine().query(NvidiaSmiQuery::Devices)?)
    }

    fn compute_processes(&self) -> Result<Vec<GpuComputeProcess>, GpuProbeError> {
        parse_compute_process_lines(
            &NvidiaSmiRoute::of_this_machine().query(NvidiaSmiQuery::ComputeProcesses)?,
        )
    }

    fn samples(&self) -> Result<Vec<DeviceSample>, GpuProbeError> {
        parse_sample_lines(&NvidiaSmiRoute::of_this_machine().query(NvidiaSmiQuery::Samples)?)
    }
}

/// One query of [`NVIDIA_SMI`] the probe asks. The list is closed, so root,
/// which runs a query as the job account for the engine, never runs a
/// program or an argument the engine chose (FIX
/// EXEC-NODE-PROBE-AFTER-HANDOVER).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NvidiaSmiQuery {
    /// Each GPU's UUID, model and memory ([`parse_device_lines`]).
    Devices,
    /// Every compute process on every GPU ([`parse_compute_process_lines`]).
    ComputeProcesses,
    /// Each GPU's temperature, power draw and memory in use
    /// ([`parse_sample_lines`]).
    Samples,
}

impl NvidiaSmiQuery {
    /// Every query.
    pub const ALL: [Self; 3] = [Self::Devices, Self::ComputeProcesses, Self::Samples];

    /// Its word on the job control socket.
    #[must_use]
    pub fn word(self) -> &'static str {
        match self {
            Self::Devices => "nvidia-devices",
            Self::ComputeProcesses => "nvidia-compute-processes",
            Self::Samples => "nvidia-samples",
        }
    }

    /// The query `word` names; `None` for any other word.
    #[must_use]
    pub fn from_word(word: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|query| query.word() == word)
    }

    /// The tool's arguments.
    #[must_use]
    pub fn args(self) -> [&'static str; 2] {
        let fields = match self {
            Self::Devices => "--query-gpu=uuid,name,memory.total",
            Self::ComputeProcesses => "--query-compute-apps=gpu_uuid,pid",
            Self::Samples => "--query-gpu=uuid,temperature.gpu,power.draw,memory.used",
        };
        [fields, "--format=csv,noheader,nounits"]
    }
}

/// Where the probe's queries run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NvidiaSmiRoute {
    /// `program`, run by this process as its own account: a machine where
    /// this process may not use a job control socket, or has none
    /// (`execution-node install` never ran there).
    Direct { program: PathBuf },
    /// Through the job control socket at `socket`: its root handler runs
    /// each query as the job account. After the device hand-over (runbook
    /// 1.9 step 3, T40) only the job account's group opens the card's
    /// files, and the engine's account cannot open them, by design (FIX
    /// EXEC-NODE-PROBE-AFTER-HANDOVER).
    JobControl { socket: PathBuf },
}

impl NvidiaSmiRoute {
    /// This machine's route now: through the job control socket while it
    /// listens and this process may connect to it (the engine's account, or
    /// root), else [`NVIDIA_SMI`] run here.
    #[must_use]
    pub fn of_this_machine() -> Self {
        #[cfg(target_os = "linux")]
        {
            use super::scope_systemd::control::{CONTROL_SOCKET_PATH, control_socket_usable};
            if control_socket_usable(Path::new(CONTROL_SOCKET_PATH)) {
                return Self::JobControl {
                    socket: PathBuf::from(CONTROL_SOCKET_PATH),
                };
            }
        }
        Self::Direct {
            program: PathBuf::from(NVIDIA_SMI),
        }
    }

    /// Runs `query` on this route and answers the tool's output.
    ///
    /// # Errors
    ///
    /// [`GpuProbeError::Unavailable`] when the tool fails, does not answer in
    /// time, or the job control socket's handler refuses or does not answer.
    pub fn query(&self, query: NvidiaSmiQuery) -> Result<String, GpuProbeError> {
        match self {
            Self::Direct { program } => run_device_tool_as(program, &query.args(), None),
            #[cfg(target_os = "linux")]
            Self::JobControl { socket } => {
                super::scope_systemd::device_query::request(socket, query)
            }
            #[cfg(not(target_os = "linux"))]
            Self::JobControl { .. } => Err(GpuProbeError::Unavailable {
                reason: "the job control socket is on Linux only".to_owned(),
            }),
        }
    }
}

/// The account a device tool query runs as when root runs it for the
/// engine: the job account, never root or the engine's.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceToolAccount {
    /// Its name, the query's `USER` and `LOGNAME`.
    pub name: String,
    pub uid: u32,
    /// Its own group (`install` makes the account with `--user-group`): the
    /// group the device hand-over opens the card's files to.
    pub gid: u32,
}

/// What placement reads about `device`, a GPU the driver listed, in `state`
/// (pass 34, 2.1): found by its vendor UUID, with its own memory and CUDA,
/// for one claimant. Its closure is closed: the driver lists every compute
/// process on it, and the slot table refuses a launch beside one it did not
/// start.
#[must_use]
pub fn gpu_device_facts(device: &GpuDevice, state: DeviceState) -> DeviceFacts {
    DeviceFacts {
        id: device.device_id.clone(),
        id_source: DeviceIdSource::VendorUuid,
        kind: DeviceKind::Gpu,
        vendor: NVIDIA.to_owned(),
        model: device.model.clone(),
        memory: DeviceMemory::Dedicated {
            mib: device.memory_total_mib,
        },
        features: vec![CUDA.to_owned()],
        closure: DeviceClosure::Closed,
        state,
        max_claimants: 1,
    }
}

/// This machine's GPUs as the capacity probe records them: empty where the
/// driver is absent or fails, as on a machine with no NVIDIA GPU.
#[must_use]
pub fn recorded_gpu_devices() -> Vec<GpuDevice> {
    NvidiaSmiProbe.devices().unwrap_or_default()
}

/// Reads `nvidia-smi --query-gpu=uuid,name,memory.total
/// --format=csv,noheader,nounits` lines: the UUID first, the memory last,
/// the model between them (a model name may itself hold a comma).
///
/// # Errors
///
/// [`GpuProbeError::Unreadable`] for a line with no UUID, model or memory
/// count.
pub fn parse_device_lines(text: &str) -> Result<Vec<GpuDevice>, GpuProbeError> {
    text.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(|line| {
            let unreadable = || GpuProbeError::Unreadable {
                line: line.to_owned(),
            };
            let (device_id, rest) = line.split_once(',').ok_or_else(unreadable)?;
            let (model, memory) = rest.rsplit_once(',').ok_or_else(unreadable)?;
            let device_id = plain_device_id(device_id).ok_or_else(unreadable)?;
            let model = model.trim();
            if model.is_empty() {
                return Err(unreadable());
            }
            Ok(GpuDevice {
                device_id,
                model: model.to_owned(),
                memory_total_mib: memory.trim().parse().map_err(|_| unreadable())?,
            })
        })
        .collect()
}

/// Reads `nvidia-smi --query-compute-apps=gpu_uuid,pid
/// --format=csv,noheader,nounits` lines. A line whose process id the driver
/// does not give still names a process on its card.
///
/// # Errors
///
/// [`GpuProbeError::Unreadable`] for a line with no card UUID.
pub fn parse_compute_process_lines(text: &str) -> Result<Vec<GpuComputeProcess>, GpuProbeError> {
    text.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(|line| {
            let unreadable = || GpuProbeError::Unreadable {
                line: line.to_owned(),
            };
            let (device_id, pid) = line.split_once(',').unwrap_or((line, ""));
            Ok(GpuComputeProcess {
                device_id: plain_device_id(device_id).ok_or_else(unreadable)?,
                pid: pid.trim().parse().ok(),
            })
        })
        .collect()
}

/// Reads `nvidia-smi --query-gpu=uuid,temperature.gpu,power.draw,memory.used
/// --format=csv,noheader,nounits` lines. A figure the driver does not give
/// (`[N/A]`, `[Not Supported]`) or writes in a form this reader does not
/// know is `None`: the samples are evidence, not a gate.
///
/// # Errors
///
/// [`GpuProbeError::Unreadable`] for a line with no device UUID or with
/// other than four fields.
pub fn parse_sample_lines(text: &str) -> Result<Vec<DeviceSample>, GpuProbeError> {
    text.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(|line| {
            let unreadable = || GpuProbeError::Unreadable {
                line: line.to_owned(),
            };
            let fields: Vec<&str> = line.split(',').map(str::trim).collect();
            let [device_id, temperature, power, memory] = fields.as_slice() else {
                return Err(unreadable());
            };
            Ok(DeviceSample {
                device_id: plain_device_id(device_id).ok_or_else(unreadable)?,
                temperature_c: temperature.parse().ok(),
                power_mw: milli_units(power),
                memory_used_mib: memory.parse().ok(),
            })
        })
        .collect()
}

/// A decimal figure such as `123.45` in thousandths (`123450`); `None` for
/// anything that is not digits with at most one point.
fn milli_units(text: &str) -> Option<u64> {
    let (whole, fraction) = text.split_once('.').unwrap_or((text, ""));
    let digits = |part: &str| part.bytes().all(|byte| byte.is_ascii_digit());
    if whole.is_empty() || !digits(whole) || !digits(fraction) {
        return None;
    }
    let thousandths: String = fraction
        .chars()
        .chain(std::iter::repeat('0'))
        .take(3)
        .collect();
    whole
        .parse::<u64>()
        .ok()?
        .checked_mul(1_000)?
        .checked_add(thousandths.parse().ok()?)
}

/// A device id as the driver writes it: not empty, no whitespace or
/// control characters.
pub(super) fn plain_device_id(id: &str) -> Option<String> {
    let id = id.trim();
    (!id.is_empty() && !id.chars().any(|c| c.is_whitespace() || c.is_control()))
        .then(|| id.to_owned())
}

/// Driver queries killed past their deadline and not yet reaped, in this
/// whole process: every probe's queries refuse while there is one.
static UNREAPED_QUERIES: AtomicUsize = AtomicUsize::new(0);

/// Runs one query of `program`, a device driver's command-line tool, as
/// this process's own account: [`run_device_tool_as`].
pub(super) fn run_device_tool(program: &str, args: &[&str]) -> Result<String, GpuProbeError> {
    run_device_tool_as(Path::new(program), args, None)
}

/// Runs one query of `program`, a device driver's command-line tool, and
/// answers its output, within [`GPU_QUERY_TIMEOUT`]. The output is read
/// without blocking on this thread while the query runs, so a long answer
/// never fills the pipe. At the deadline the pipe's read end is closed, the
/// query is killed with its process group and reaped off the caller's path;
/// no thread waits on the pipe, whoever holds its write end.
///
/// With `account` (root only: the job control socket's handler), the query
/// runs as that account: its uid, its own group, no supplementary group
/// (std clears them when root sets the uid), and an environment of its own
/// with nothing of root's.
pub(crate) fn run_device_tool_as(
    program: &Path,
    args: &[&str],
    account: Option<&DeviceToolAccount>,
) -> Result<String, GpuProbeError> {
    let unavailable = |reason: String| GpuProbeError::Unavailable { reason };
    let program_name = program.display();
    if UNREAPED_QUERIES.load(Ordering::Acquire) > 0 {
        return Err(unavailable(
            "an earlier device tool query was killed and has not ended yet".to_owned(),
        ));
    }
    let mut command = oneiron_spawn::command(program);
    command
        .args(args)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null());
    #[cfg(unix)]
    if let Some(account) = account {
        std::os::unix::process::CommandExt::uid(&mut command, account.uid);
        std::os::unix::process::CommandExt::gid(&mut command, account.gid);
        command
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("USER", &account.name)
            .env("LOGNAME", &account.name)
            .env("LANG", "C");
    }
    #[cfg(not(unix))]
    if account.is_some() {
        return Err(unavailable(format!(
            "{program_name} runs as another account on Unix only"
        )));
    }
    // Its own process group, so whatever it starts is killed with it.
    #[cfg(unix)]
    std::os::unix::process::CommandExt::process_group(&mut command, 0);
    let mut child = command
        .spawn()
        .map_err(|error| unavailable(format!("{program_name} did not start: {error}")))?;
    let Some(mut stdout) = child.stdout.take() else {
        abandon(child);
        return Err(unavailable(format!("{program_name} gave no output pipe")));
    };
    #[cfg(unix)]
    if let Err(error) = rustix::io::ioctl_fionbio(&stdout, true) {
        abandon(child);
        return Err(unavailable(format!(
            "{program_name}'s output pipe could not be read without blocking: {error}"
        )));
    }
    #[cfg(not(unix))]
    {
        abandon(child);
        return Err(unavailable(format!(
            "{program_name} is queried on Unix only"
        )));
    }
    let deadline = Instant::now() + GPU_QUERY_TIMEOUT;
    let mut output = Vec::new();
    let mut chunk = [0_u8; 4096];
    let mut ended = false;
    let mut exited = None;
    let status = loop {
        let mut moved = false;
        if !ended {
            match stdout.read(&mut chunk) {
                Ok(0) => ended = true,
                Ok(n) => {
                    output.extend_from_slice(&chunk[..n]);
                    moved = true;
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                    ) => {}
                Err(error) => {
                    drop(stdout);
                    abandon(child);
                    return Err(unavailable(format!("{program_name}'s output: {error}")));
                }
            }
        }
        if exited.is_none() {
            match child.try_wait() {
                Ok(now) => exited = now,
                Err(error) => {
                    drop(stdout);
                    abandon(child);
                    return Err(unavailable(format!(
                        "{program_name} could not be waited on: {error}"
                    )));
                }
            }
        }
        if ended && let Some(status) = exited {
            break status;
        }
        if Instant::now() >= deadline {
            // Closing the read end first: no write end left open, by the
            // query or a helper it started, holds anything of this server.
            drop(stdout);
            abandon(child);
            return Err(unavailable(format!(
                "{program_name} did not answer within {} s",
                GPU_QUERY_TIMEOUT.as_secs()
            )));
        }
        if !moved {
            std::thread::sleep(QUERY_POLL);
        }
    };
    let text = String::from_utf8(output)
        .map_err(|error| unavailable(format!("{program_name}'s output: {error}")))?;
    if !status.success() {
        return Err(unavailable(format!("{program_name} exited with {status}")));
    }
    Ok(text)
}

/// Kills every process left in the query's process group, so the pipe its
/// reader waits on closes.
fn kill_group(group: u32) {
    #[cfg(unix)]
    if let Some(group) = i32::try_from(group)
        .ok()
        .and_then(rustix::process::Pid::from_raw)
    {
        let _ = rustix::process::kill_process_group(group, rustix::process::Signal::KILL);
    }
    #[cfg(not(unix))]
    let _ = group;
}

/// Kills a query no longer waited for, with its process group, and reaps it
/// on its own thread, so a driver call that never returns holds that
/// thread, not the caller. Until it is reaped, every query refuses.
fn abandon(mut child: std::process::Child) {
    kill_group(child.id());
    if let Err(error) = child.kill() {
        tracing::debug!(%error, "the GPU driver query had already ended");
    }
    UNREAPED_QUERIES.fetch_add(1, Ordering::AcqRel);
    std::thread::spawn(move || {
        if let Err(error) = child.wait() {
            tracing::debug!(%error, "the GPU driver query could not be reaped");
        }
        UNREAPED_QUERIES.fetch_sub(1, Ordering::AcqRel);
    });
}
