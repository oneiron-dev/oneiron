//! What every root step of the unit starts from: its instance, the
//! root-owned node file, the two accounts, and the key's control directory
//! opened beneath the engine's state directory, never through a link.

use std::ffi::OsStr;
use std::os::fd::{BorrowedFd, OwnedFd};
use std::path::{Path, PathBuf};

use super::super::node_settings::ExecutionNodeSettings;
use super::safe_fs::{self, account, borrow, facts, open_dir_beneath, open_dir_path};
use super::{EXCHANGE_ROOT, is_job_instance};

/// The arguments the unit template gives every root step:
/// `--node-file <path> --engine-account <name> [--after-exec] [--stop-at <boot ns>] <instance>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StepArgs {
    pub node_file: PathBuf,
    pub engine_account: String,
    pub instance: String,
    /// `job-prepare --after-exec`: the gate.
    pub after_exec: bool,
    /// Why the step could not enter process 1's mount namespace
    /// ([`enter_host_mount_namespace`]); `None` when it works on the
    /// machine's own tree.
    pub host_namespace_error: Option<String>,
    /// `job-cutoff --stop-at <boot ns>`: the stop time the firing cutoff
    /// timer was armed for, so a timer a session's renewal superseded stops
    /// nothing (row W1). `None` from a timer armed before sessions: it
    /// stops the unit.
    pub stop_at_boot_ns: Option<u64>,
}

impl StepArgs {
    /// Parses a root step's arguments (after the step's name).
    ///
    /// # Errors
    ///
    /// A missing or unknown argument.
    pub fn parse(args: &[String]) -> Result<Self, String> {
        let mut node_file = None;
        let mut engine_account = None;
        let mut instance = None;
        let mut after_exec = false;
        let mut stop_at_boot_ns = None;
        let mut rest = args.iter();
        while let Some(arg) = rest.next() {
            match arg.as_str() {
                "--node-file" => node_file = rest.next().map(PathBuf::from),
                "--engine-account" => engine_account = rest.next().cloned(),
                "--after-exec" => after_exec = true,
                "--stop-at" => {
                    let value = rest.next().ok_or("--stop-at needs a boot-clock time")?;
                    stop_at_boot_ns =
                        Some(value.parse().map_err(|_| {
                            format!("--stop-at {value:?} is not a boot-clock time")
                        })?);
                }
                other if other.starts_with('-') => return Err(format!("unknown argument {other}")),
                other if instance.is_none() => instance = Some(other.to_owned()),
                other => return Err(format!("a second instance {other}")),
            }
        }
        Ok(Self {
            node_file: node_file.ok_or("--node-file is required")?,
            engine_account: engine_account.ok_or("--engine-account is required")?,
            instance: instance.ok_or("the unit's instance is required")?,
            after_exec,
            host_namespace_error: None,
            stop_at_boot_ns,
        })
    }
}

/// Moves this process into process 1's mount namespace, unless it is there
/// already (review r2 R2-03, qualification q1 on systemd 262: the service
/// manager gives a unit's `+` steps the unit's `BindPaths=`,
/// `BindReadOnlyPaths=` and `TemporaryFileSystem=` too). Inside the unit a
/// root step would see the job's read-only view of the exchange and payload
/// roots, and could make neither; every root step works on the machine's own
/// tree instead. Called first, while the process has one thread: `setns`
/// refuses a new mount namespace to a process whose threads share its
/// file-system attributes.
///
/// # Errors
///
/// A namespace could not be read, or the kernel refused the move.
pub fn enter_host_mount_namespace() -> Result<(), String> {
    use std::os::fd::AsRawFd as _;
    use std::os::unix::fs::MetadataExt as _;
    let identity = |path: &str| {
        std::fs::metadata(path)
            .map(|found| (found.dev(), found.ino()))
            .map_err(|error| format!("{path}: {error}"))
    };
    if identity("/proc/self/ns/mnt")? == identity("/proc/1/ns/mnt")? {
        return Ok(());
    }
    let host = std::fs::File::open("/proc/1/ns/mnt")
        .map_err(|error| format!("/proc/1/ns/mnt: {error}"))?;
    // SAFETY: host is an open namespace descriptor for the whole call.
    if unsafe { libc::setns(host.as_raw_fd(), libc::CLONE_NEWNS) } != 0 {
        return Err(format!("setns: {}", std::io::Error::last_os_error()));
    }
    Ok(())
}

/// The opened state of one root step.
#[derive(Debug)]
pub struct StepContext {
    pub args: StepArgs,
    pub settings: ExecutionNodeSettings,
    pub engine_uid: u32,
    pub engine_gid: u32,
    pub engine_home: PathBuf,
    pub job_uid: u32,
    pub job_gid: u32,
    /// The key's control directory, `<state_dir>/control/<instance>`.
    pub control: OwnedFd,
}

impl StepContext {
    /// Opens the step: the instance is a job id, the node file and its
    /// directories are root's alone, both accounts exist, and the control
    /// directory is the engine's and no link.
    ///
    /// # Errors
    ///
    /// The first check that failed, in words.
    pub fn open(args: StepArgs) -> Result<Self, String> {
        if !is_job_instance(&args.instance) {
            return Err(format!("{:?} is not a job instance", args.instance));
        }
        safe_fs::require_root_owned(&args.node_file)?;
        let settings = ExecutionNodeSettings::read(&args.node_file)?
            .ok_or_else(|| format!("{}: no node file", args.node_file.display()))?;
        let (engine_uid, engine_gid, engine_home) = account(&args.engine_account)
            .map_err(|error| format!("engine account {}: {error}", args.engine_account))?;
        let (job_uid, job_gid, _) = account(&settings.job_account)
            .map_err(|error| format!("job account {}: {error}", settings.job_account))?;
        if job_uid == 0 || job_uid == engine_uid {
            return Err("the job account must be neither root nor the engine's".to_owned());
        }
        let state = open_dir_path(&settings.state_dir).map_err(|error| error.to_string())?;
        owned_by(borrow(&state), engine_uid, &settings.state_dir)?;
        let control_root = open_dir_beneath(borrow(&state), OsStr::new("control"))
            .map_err(|error| format!("{}/control: {error}", settings.state_dir.display()))?;
        let control = open_dir_beneath(borrow(&control_root), OsStr::new(&args.instance))
            .map_err(|error| format!("control/{}: {error}", args.instance))?;
        owned_by(
            borrow(&control),
            engine_uid,
            &settings.state_dir.join("control").join(&args.instance),
        )?;
        Ok(Self {
            args,
            settings,
            engine_uid,
            engine_gid,
            engine_home,
            job_uid,
            job_gid,
            control,
        })
    }

    /// The job's unit name.
    #[must_use]
    pub fn unit(&self) -> String {
        format!("oneiron-job@{}.service", self.args.instance)
    }

    /// The job's exchange directory, `/run/oneiron-jobs/<instance>`.
    #[must_use]
    pub fn exchange_path(&self) -> PathBuf {
        Path::new(EXCHANGE_ROOT).join(&self.args.instance)
    }

    /// Writes one of root's records into the control directory, readable by
    /// the engine.
    ///
    /// # Errors
    ///
    /// The write failed.
    pub fn write_record<T: serde::Serialize>(&self, name: &str, record: &T) -> Result<(), String> {
        let bytes = serde_json::to_vec_pretty(record).map_err(|error| error.to_string())?;
        safe_fs::write_beneath(borrow(&self.control), name, &bytes, 0o644, None)
            .map_err(|error| format!("{name}: {error}"))
    }

    /// Reads one of root's records from the control directory.
    ///
    /// # Errors
    ///
    /// It exists and does not read or parse.
    pub fn read_record<T: serde::de::DeserializeOwned>(
        &self,
        name: &str,
    ) -> Result<Option<T>, String> {
        // A record root wrote is root-owned; one the engine put in its place
        // is not root's and is refused.
        let Some(bytes) =
            safe_fs::read_beneath(borrow(&self.control), name, RECORD_MAX_BYTES, Some(0))
                .map_err(|error| format!("{name}: {error}"))?
        else {
            return Ok(None);
        };
        serde_json::from_slice(&bytes)
            .map(Some)
            .map_err(|error| format!("{name}: {error}"))
    }
}

/// The largest record or `launch.json` a root step reads.
pub const RECORD_MAX_BYTES: u64 = 256 * 1024;

fn owned_by(fd: BorrowedFd<'_>, uid: u32, path: &Path) -> Result<(), String> {
    let found = facts(fd).map_err(|error| format!("{}: {error}", path.display()))?;
    if found.uid != uid {
        return Err(format!(
            "{}: owned by uid {}, not the engine's account (uid {uid})",
            path.display(),
            found.uid
        ));
    }
    Ok(())
}
