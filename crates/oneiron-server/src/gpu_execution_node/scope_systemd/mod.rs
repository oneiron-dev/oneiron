//! The first launch scope (pass 33, `33-exec-node/DESIGN.md` sections 7.6
//! and 7.8; pass 34, `34-compute-general/DESIGN.md` section 2.2): a job runs
//! as one instance of a root-owned systemd unit template, under its own OS
//! account, and the service manager, not the engine, kills it, ends it at its
//! maximum and records how it ended.
//!
//! The parts, by who runs them:
//! - `oneiron execution-node install` ([`install`], root, once): the job
//!   account, the unit template ([`unit_file`]) and the job control socket
//!   ([`control`]), through which the engine's account starts and stops
//!   instances of that template and nothing else.
//! - `oneiron job-control` ([`control`], root, one per connection to the
//!   control socket): checks the caller and the instance name, then starts
//!   or stops that one job unit.
//! - the engine ([`systemd_unit`]): R3a's [`JobUnit`] over the control socket
//!   and `systemctl show`, and the machine's capability report; its GPU
//!   probe reads the cards through the same socket, as the job account
//!   ([`device_query`]), since after the device hand-over only the job
//!   account's group opens them.
//! - the unit's own steps, fixed in the template:
//!   - `oneiron job-prepare <id>` ([`prepare`], root, `ExecStartPre=+`):
//!     checks `launch.json` against the root-owned node file, sets this job's
//!     limits on the unit and arms the cutoff, before any workload process
//!     exists;
//!   - `oneiron job-exec <id>` ([`exec`], the job account, `ExecStart=`):
//!     the inner file wall, then the proof of each bound from the inside,
//!     reported to the root gate;
//!   - `oneiron job-prepare --after-exec <id>` ([`gate`], root,
//!     `ExecStartPost=+`): the gate. It records `job-exec`'s report and only
//!     then lets the workload start, so whether the workload ever started is
//!     a root record the workload cannot write;
//!   - `oneiron job-cutoff <id>` ([`cutoff`], root, the cutoff timer's
//!     command): marks the cutoff and stops the unit;
//!   - `oneiron job-ended <id>` ([`ended`], root, `ExecStopPost=+`): writes
//!     the end record after every process of the unit is gone.
//!
//! Every file a root step reads or writes in a directory the engine's
//! account owns is opened beneath a directory descriptor and never through a
//! link ([`safe_fs`]): the engine is not trusted with root.
//!
//! The service manager gives the `+` steps the unit's bind mounts and
//! temporary file systems too, so each root step first enters process 1's
//! mount namespace ([`step::enter_host_mount_namespace`]) and works on the
//! machine's own tree; the job's view is built from what they made there
//! ([`exchange`]), and its bind sources are optional (`-`), so a step that
//! runs before they exist still starts.

/// One line to standard error, which the service manager files in the
/// journal under the step's unit: the steps' diagnostics.
macro_rules! journal_line {
    ($($arg:tt)*) => {{
        use ::std::io::Write as _;
        let _ = ::std::writeln!(::std::io::stderr().lock(), $($arg)*);
    }};
}

/// One line to standard output: what `install` and `check` tell the
/// operator.
macro_rules! stdout_line {
    ($($arg:tt)*) => {{
        use ::std::io::Write as _;
        let _ = ::std::writeln!(::std::io::stdout().lock(), $($arg)*);
    }};
}

pub mod capabilities;
pub mod control;
pub mod cutoff;
pub mod device_files;
pub mod device_query;
pub mod ended;
pub mod exchange;
pub mod exec;
pub mod gate;
pub mod install;
pub mod log_writer;
pub mod prepare;
pub mod probe_unit;
pub mod records;
pub mod renew;
pub mod safe_fs;
pub mod step;
pub mod systemd_unit;
pub mod unit_file;

pub use systemd_unit::SystemdJobUnit;

use super::jobs::JobUnit;

/// The root-owned directory of the per-job exchange directories: each holds
/// `exec.json` and, while the gate waits, the gate's socket, readable by the
/// job account alone (mode 0750, group the job account's).
pub const EXCHANGE_ROOT: &str = "/run/oneiron-jobs";

/// The root-owned directory (mode 0700) of the payload bind sources: the
/// prepare step bind-mounts the payload directory it opened and checked at
/// `<PAYLOAD_ROOT>/<instance>`, and the unit binds that, not the engine's
/// path, at `<work_dir>/<instance>` (review r2 R2-12).
pub const PAYLOAD_ROOT: &str = "/run/oneiron-payloads";

/// The byte that ends `job-exec`'s report on the gate connection: the report
/// is one JSON line, and the connection stays open after it until the
/// workload's `execve` closes it (review r2 R2-02).
pub const REPORT_FRAME_END: u8 = b'\n';

/// `job-exec`'s parameters, written by the prepare step (root) into the
/// job's exchange directory.
pub const EXEC_FILE_NAME: &str = "exec.json";

/// The gate's Unix stream socket in the job's exchange directory (root's,
/// group the job account's, mode 0660). `job-exec` connects to it, and the
/// report, the go, the exec mark and the close at the exec all travel on
/// that one connection. The gate takes the connection of the unit's main
/// process alone, by its peer credentials, so another process of the job
/// account (another job's workload) cannot answer for it (FIX
/// EXEC-UNIT-ONE-JOB-ACCOUNT).
pub const GATE_SOCKET_NAME: &str = "gate.sock";

/// The one line the gate writes to let the workload start.
pub const GATE_GO: &[u8] = b"go\n";

/// The line `job-exec` writes on the gate connection after the go, just
/// before its `execve` (FIX EXEC-UNIT-GATE-EXEC-RACE). The connection is
/// close-on-exec, so the gate reads: a close with no mark is `job-exec`'s
/// exit before the exec; the mark and then a close is the exec; the mark and
/// more words is a failed exec. No process state is read after the close,
/// so a workload that ends at once is still recorded as started.
pub const EXEC_MARK: &[u8] = b"exec\n";

/// The smallest memory cap of a job unit, in MiB (FIX
/// EXEC-UNIT-STEPS-IN-MEMORY-CAP). The unit's own steps (job-prepare and the
/// gate, `job-exec` before its exec, job-ended) are this binary and run in
/// the job's cgroup, so they count against `MemoryMax`. Qualification q3
/// (nelly, 25 Nov) saw a 64 MiB cap end the unit by the OOM killer before
/// the gate's record, while every unit under a 256 MiB cap peaked at 83 to
/// 85 MiB. A smaller request gets this cap, and `prepared.json` names it.
pub const UNIT_MEMORY_FLOOR_MIB: u64 = 256;

/// What the prepare step applied, in the key's control directory.
pub const PREPARED_FILE_NAME: &str = "prepared.json";

/// The gate's record of `job-exec`'s report and its verdict, in the key's
/// control directory. Its `released` is the root record that the workload
/// was allowed to start.
pub const SCOPE_FILE_NAME: &str = "scope.json";

/// The cutoff's mark, in the key's control directory: the cutoff timer
/// stopped the unit.
pub const CUTOFF_FILE_NAME: &str = "cutoff.json";

/// The prefix of the cutoff timer's transient unit: `oneiron-job-cutoff-<id>`.
/// The engine's account may not stop it: the control socket takes only job
/// unit instances.
pub const CUTOFF_UNIT_PREFIX: &str = "oneiron-job-cutoff-";

/// The prefix of the sleep inhibitor's transient unit, bound to the job unit:
/// `oneiron-job-awake-<id>`.
pub const AWAKE_UNIT_PREFIX: &str = "oneiron-job-awake-";

/// The prefix of `execution-node check`'s probe units.
pub const PROBE_UNIT_PREFIX: &str = "oneiron-job-probe-";

/// The unit template's file, as `install` writes it.
pub const UNIT_TEMPLATE_PATH: &str = "/etc/systemd/system/oneiron-job@.service";

/// The scope report `execution-node check` writes beside the node file
/// (`<node file>.scope.json`), root-owned; [`SystemdJobUnit::probe`] reads it.
pub const CHECK_REPORT_SUFFIX: &str = ".scope.json";

/// `job-exec`'s exit statuses before the workload exists. The service
/// manager's own codes for a sandbox it could not build are 200 to 243
/// (`systemd.exec(5)`, "Process Exit Codes"); these sit below them.
pub mod exec_status {
    /// `exec.json` was missing, unreadable or not this job's.
    pub const EXEC_FILE: i32 = 150;
    /// The gate's socket could not be reached, or `job-exec` could not be
    /// made undumpable before it speaks on it (review r7 R7-01).
    pub const GATE_SOCKET: i32 = 151;
    /// The inner file wall could not be applied.
    pub const FILE_WALL: i32 = 152;
    /// A bound the template requires is not proved.
    pub const REQUIRED_BOUND: i32 = 153;
    /// The gate did not let the workload start.
    pub const GATE_REFUSED: i32 = 154;
    /// The workload's program could not be started.
    pub const EXEC_FAILED: i32 = 155;
    /// The probe of `execution-node check` ended.
    pub const PROBE_DONE: i32 = 0;
}

/// The end record's refusal for a `job-exec` status before the workload, or
/// for a service-manager status the sandbox setup gave; `None` for any other
/// status.
#[must_use]
pub fn refusal_of_exit_status(status: i32) -> Option<&'static str> {
    Some(match status {
        exec_status::EXEC_FILE => "unit: exec_file",
        exec_status::GATE_SOCKET => "unit: gate_socket",
        exec_status::FILE_WALL => "unit: file_wall_not_applied",
        exec_status::REQUIRED_BOUND => "unit: required_bound_not_proved",
        exec_status::GATE_REFUSED => "unit: gate_refused",
        exec_status::EXEC_FAILED => "unit: workload_exec_failed",
        200 => "unit: chdir",
        201 => "unit: nice",
        202 => "unit: fds",
        203 => "unit: exec",
        204 => "unit: memory",
        205 => "unit: limits",
        206 => "unit: oom_adjust",
        207 => "unit: signal_mask",
        208 => "unit: stdin",
        209 => "unit: stdout",
        210 => "unit: chroot",
        211 => "unit: ioprio",
        212 => "unit: timerslack",
        213 => "unit: secure_bits",
        214 => "unit: setscheduler",
        215 => "unit: cpu_affinity",
        216 => "unit: group",
        217 => "unit: user",
        218 => "unit: capabilities",
        219 => "unit: cgroup",
        220 => "unit: setsid",
        221 => "unit: apparmor",
        222 => "unit: address_families",
        223 => "unit: personality",
        224 => "unit: selinux_context",
        225 => "unit: network_namespace",
        226 => "unit: mount_namespace",
        227 => "unit: no_new_privileges",
        228 => "unit: seccomp",
        229 => "unit: selinux_context",
        230 => "unit: personality",
        231 => "unit: apparmor_profile",
        232 => "unit: address_families",
        233 => "unit: runtime_directory",
        234 => "unit: chown",
        235 => "unit: smack_process_label",
        236 => "unit: keyring",
        237 => "unit: state_directory",
        238 => "unit: cache_directory",
        239 => "unit: logs_directory",
        240 => "unit: configuration_directory",
        241 => "unit: numa_policy",
        242 => "unit: credentials",
        243 => "unit: bpf",
        _ => return None,
    })
}

/// Whether `id` names a job: exactly the 32 lower-hex digits of a
/// [`super::jobs::JobKeyId`]. Every root step checks its instance name with
/// it before it builds a path from it.
#[must_use]
pub fn is_job_instance(id: &str) -> bool {
    super::jobs::JobKeyId::parse(id).is_some()
}

const _: fn(&SystemdJobUnit) -> &dyn JobUnit = |unit| unit;

/// The unit's own steps, run by the `oneiron` binary before anything else
/// (no runtime, no logging set-up, no configuration but the node file):
/// `job-prepare`, `job-exec`, `job-cutoff`, `job-ended`, and the control
/// socket's handler `job-control`. `None` when `args` (the whole command
/// line) names none of them.
#[must_use]
pub fn run_unit_step(args: &[String]) -> Option<i32> {
    let (name, rest) = match args {
        [_, name, rest @ ..] => (name.as_str(), rest),
        _ => return None,
    };
    let status = match name {
        "job-exec" => exec::run(rest),
        "job-control" => control::run(rest),
        "job-prepare" | "job-cutoff" | "job-ended" => {
            // First, while this process has one thread.
            let entered = step::enter_host_mount_namespace();
            match step::StepArgs::parse(rest) {
                Ok(mut parsed) => {
                    parsed.host_namespace_error = entered.err();
                    match name {
                        "job-prepare" => prepare::run(parsed),
                        "job-cutoff" => cutoff::run(parsed),
                        _ => ended::run(parsed),
                    }
                }
                Err(why) => {
                    journal_line!("{name}: {why}");
                    2
                }
            }
        }
        _ => return None,
    };
    Some(status)
}
