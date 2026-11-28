//! The job units' place in the host's control groups (row
//! NODE-JOB-SLICE-AND-WEIGHT; FLEET-TOOL-PARITY.md, kind 11): the
//! `[execution_node.job_cgroup]` table of the node's file, read fresh at
//! each prepare step like the rest of it.
//!
//! - `slice`: the top-level system slice every job unit runs in, as the
//!   `Slice=` line of the template `install` writes. Absent: no such line,
//!   and systemd places each unit in its own slice for the template, as
//!   before this table. Set, the prepare step refuses a unit whose
//!   effective slice is another one (`install` was not run again).
//! - `slice_cpu_weight`: the slice's own CPU weight, which the prepare step
//!   sets at each launch, so the whole slice yields to the rest of the host
//!   (a host whose GPU jobs still run outside Oneiron). Absent: the slice
//!   keeps the weight its own unit gives it.
//! - `device_job_cpu_weight` and `cpu_job_cpu_weight`: each job's own weight
//!   inside its slice, by whether the launch leases a device, so a job that
//!   leases none yields to one that does.
//!
//! A weight is a share, not a cap (systemd.resource-control(5),
//! `CPUWeight=`): under contention a unit gets CPU in proportion to its
//! weight among its siblings, and an idle host gives a weight-10 job all of
//! its CPU. The cap stays `CPUQuota=`, from the template's `cpu_threads`.
//!
//! A system unit cannot join a user manager's slice, such as a fleet's
//! `guests.slice` under one account's `user@.service`: a host that throttles
//! its guests when it runs hot names this slice too.

use serde::{Deserialize, Serialize};

/// Default of `device_job_cpu_weight`: systemd's own default weight, so a
/// job that leases a device keeps the CPU share it had before this table.
pub const DEVICE_JOB_CPU_WEIGHT_DEFAULT: u64 = 100;

/// Default of `cpu_job_cpu_weight`, chosen by OPUS-LE-ARMS 28 Nov: a job
/// that leases no device gets 1/11 of the contended CPU against one job that
/// leases a device in the same slice, so CPU jobs yield to GPU jobs
/// (FLEET-TOOL-PARITY.md, row NODE-JOB-SLICE-AND-WEIGHT).
pub const CPU_JOB_CPU_WEIGHT_DEFAULT: u64 = 10;

/// The least `CPUWeight=` systemd takes.
pub const CPU_WEIGHT_MIN: u64 = 1;

/// The most `CPUWeight=` systemd takes.
pub const CPU_WEIGHT_MAX: u64 = 10_000;

/// The longest unit name systemd takes (`UNIT_NAME_MAX`).
const UNIT_NAME_MAX: usize = 255;

/// systemd's own top-level slices: a job slice of one of these would move
/// the CPU weight of every unit in it.
const SYSTEMD_SLICES: [&str; 3] = ["system.slice", "user.slice", "machine.slice"];

/// The `[execution_node.job_cgroup]` table, checked as it reads
/// ([`JobCgroupSettings::validate`]), so a node file with a bad table does
/// not read at all.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "JobCgroupTable")]
pub struct JobCgroupSettings {
    /// The top-level system slice of every job unit; `None`: systemd's own
    /// slice for the template.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub slice: Option<String>,
    /// The slice's own CPU weight, set at each launch; only with `slice`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub slice_cpu_weight: Option<u64>,
    /// The CPU weight of a job that leases a device.
    pub device_job_cpu_weight: u64,
    /// The CPU weight of a job that leases no device.
    pub cpu_job_cpu_weight: u64,
}

/// The table as the file holds it, before its check.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct JobCgroupTable {
    #[serde(default)]
    slice: Option<String>,
    #[serde(default)]
    slice_cpu_weight: Option<u64>,
    #[serde(default = "device_job_cpu_weight_default")]
    device_job_cpu_weight: u64,
    #[serde(default = "cpu_job_cpu_weight_default")]
    cpu_job_cpu_weight: u64,
}

impl TryFrom<JobCgroupTable> for JobCgroupSettings {
    type Error = String;

    fn try_from(table: JobCgroupTable) -> Result<Self, String> {
        let settings = Self {
            slice: table.slice,
            slice_cpu_weight: table.slice_cpu_weight,
            device_job_cpu_weight: table.device_job_cpu_weight,
            cpu_job_cpu_weight: table.cpu_job_cpu_weight,
        };
        settings.validate()?;
        Ok(settings)
    }
}

fn device_job_cpu_weight_default() -> u64 {
    DEVICE_JOB_CPU_WEIGHT_DEFAULT
}
fn cpu_job_cpu_weight_default() -> u64 {
    CPU_JOB_CPU_WEIGHT_DEFAULT
}

impl Default for JobCgroupSettings {
    fn default() -> Self {
        Self {
            slice: None,
            slice_cpu_weight: None,
            device_job_cpu_weight: DEVICE_JOB_CPU_WEIGHT_DEFAULT,
            cpu_job_cpu_weight: CPU_JOB_CPU_WEIGHT_DEFAULT,
        }
    }
}

impl JobCgroupSettings {
    /// The CPU weight of a job, by whether its launch leases a device.
    #[must_use]
    pub fn job_cpu_weight(&self, leases_device: bool) -> u64 {
        if leases_device {
            self.device_job_cpu_weight
        } else {
            self.cpu_job_cpu_weight
        }
    }

    /// Checks the table: each weight within systemd's range, the slice a
    /// top-level slice of the node's own, and a slice weight only with a
    /// slice.
    ///
    /// # Errors
    ///
    /// Why the table does not validate, naming its key.
    pub fn validate(&self) -> Result<(), String> {
        let weights = [
            ("device_job_cpu_weight", Some(self.device_job_cpu_weight)),
            ("cpu_job_cpu_weight", Some(self.cpu_job_cpu_weight)),
            ("slice_cpu_weight", self.slice_cpu_weight),
        ];
        for (name, weight) in weights {
            if weight.is_some_and(|weight| !(CPU_WEIGHT_MIN..=CPU_WEIGHT_MAX).contains(&weight)) {
                return Err(format!(
                    "execution_node.job_cgroup.{name} must be {CPU_WEIGHT_MIN} to {CPU_WEIGHT_MAX}"
                ));
            }
        }
        match &self.slice {
            Some(slice) => slice_name_refusal(slice).map_or(Ok(()), |why| {
                Err(format!("execution_node.job_cgroup.slice {slice:?}: {why}"))
            }),
            None if self.slice_cpu_weight.is_some() => Err(
                "execution_node.job_cgroup.slice_cpu_weight needs execution_node.job_cgroup.slice"
                    .to_owned(),
            ),
            None => Ok(()),
        }
    }
}

/// Why `name` cannot be the job units' slice, or `None` when it can: a
/// slice unit name of at most [`UNIT_NAME_MAX`] bytes, of letters, digits,
/// `_`, `.` and `:`, ending in `.slice`, with no `-` (a dash nests a slice
/// inside another, systemd.slice(5), so its weight would act only among its
/// siblings there), and none of systemd's own top-level slices.
#[must_use]
pub fn slice_name_refusal(name: &str) -> Option<&'static str> {
    let Some(stem) = name.strip_suffix(".slice") else {
        return Some("a slice unit name ends in \".slice\"");
    };
    if stem.is_empty() || name.len() > UNIT_NAME_MAX {
        return Some("a slice unit name is 1 to 249 bytes before \".slice\"");
    }
    if name.contains('-') {
        return Some("a top-level slice has no '-': a dash nests it inside another slice");
    }
    if !name
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b':'))
    {
        return Some("a slice unit name holds only letters, digits, '_', '.' and ':'");
    }
    if SYSTEMD_SLICES.contains(&name) {
        return Some("systemd's own slice holds other units: name one of the node's own");
    }
    None
}
