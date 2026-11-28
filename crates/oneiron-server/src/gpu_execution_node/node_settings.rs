//! The node's own configuration (pass 33, `33-exec-node/DESIGN.md` section
//! 5.2): the `[execution_node]` file and its templates, each named by its
//! digest, and the template check of an admission (section 7.3, reserve step
//! 5).
//!
//! The file is root-owned and is read fresh at each admission, at each
//! `Node` answer and at each authority tick: no verb writes it, and nothing
//! of it is cached. A machine with no file runs no jobs. A file that does not
//! read or does not validate runs none either, and says why.
//!
//! Every number in it is a setting with today's recommended default (policy
//! as settings, lead 25 Nov 00:04): the disk reserve, the state directory's
//! floor, the staging limit, a template's ceilings and its write rate. The
//! node's drain is the GPU slot table's (`[gpu_jobs.devices]`
//! `drain_after_failures` and `drain_file`): one drain per machine.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Component, Path, PathBuf};

use oneiron::EntityId;
use oneiron::job_workload::{BoundRequirement, DevicePlacement, ScopeBound};
use oneiron_contracts::fingerprint::ContentHash;
use serde::{Deserialize, Serialize};

use super::wire::{NetworkMode, ScopeClass, TemplateOffer, WorkloadPin};

/// Where the node's file is when neither the server's configuration nor
/// [`EXECUTION_NODE_FILE_ENV`] names one.
pub const EXECUTION_NODE_FILE_DEFAULT: &str = "/etc/oneiron/execution-node.toml";

/// The environment variable that names the node's file for `oneiron serve`
/// and `oneiron execution-node`.
pub const EXECUTION_NODE_FILE_ENV: &str = "ONEIRON_EXECUTION_NODE_FILE";

/// Default of `disk_reserve_gib`: the disk every booking leaves free on the
/// payload disk (mel: 50 on root and on `/data`).
pub const DISK_RESERVE_GIB_DEFAULT: u64 = 50;

/// Default of `state_floor_mib`: the free space the state directory keeps
/// for the journal, so a full payload disk cannot stop it.
pub const STATE_FLOOR_MIB_DEFAULT: u64 = 1_024;

/// Default of `receipt_keep_days`: longer than an allocation period, so a
/// job of the current generation is always listed (section 7.1, `Keys`).
pub const RECEIPT_KEEP_DAYS_DEFAULT: u32 = 30;

/// Default of `staging_limit_secs`: the longest a key may stage before its
/// launch.
pub const STAGING_LIMIT_SECS_DEFAULT: u64 = 600;

/// Default of `readiness_every_secs` (`jobs.readiness.every_secs`, pass 34
/// 6.3): how often a node with no attempt running checks itself. The owner's
/// key has the same default.
pub const READINESS_EVERY_SECS_DEFAULT: u64 = oneiron::machine_policy::READINESS_EVERY_SECS_DEFAULT;

/// Default of `job_account`.
pub const JOB_ACCOUNT_DEFAULT: &str = "oneiron-job";

/// Default of a template's `write_mib_per_sec`: the kernel's cap on the
/// unit's write rate to the payload device.
pub const WRITE_MIB_PER_SEC_DEFAULT: u64 = 200;

/// Default of a template's `max_devices`: the devices one pin may claim,
/// of every kind together.
pub const MAX_DEVICES_DEFAULT: u32 = 1;

/// Default of `stop_grace_secs`: the job unit's stop grace (TERM, then KILL
/// after it), inside each maximum (section 7.6).
pub const STOP_GRACE_SECS_DEFAULT: u64 = 10;

/// Default of `unit_start_timeout_secs`: the longest a job unit's start (the
/// prepare step, the proofs from inside, the gate) may take.
pub const UNIT_START_TIMEOUT_SECS_DEFAULT: u64 = 60;

/// Default of `disk_check_secs`: how often the engine compares each running
/// key's payload directory with its disk request (section 7.9).
pub const DISK_CHECK_SECS_DEFAULT: u64 = 5;

/// Default of a template's `tasks_max`: the job unit's task ceiling.
pub const TASKS_MAX_DEFAULT: u64 = 4_096;

/// The least a template's `tasks_max` may say. The unit's own processes
/// count against the ceiling: as the workload starts, `job-exec`, the root
/// gate, the log writer and the writer's parent, which leaves at once, are
/// four tasks, and the log writer then holds one for the whole run (review
/// r6 R6-02). The workload has the rest.
pub const TASKS_MAX_FLOOR: u64 = 4;

/// Default of a template's `log_max_mib`: each of a run's two log files
/// (stdout, stderr) keeps at most this many MiB (pass 34, 7.2).
pub const LOG_MAX_MIB_DEFAULT: u32 = 64;

/// The most a template's `log_max_mib` may say.
pub const LOG_MAX_MIB_CEILING: u32 = 4_096;

/// Default of a template's `cpu_threads`: the threads a run may use at once,
/// which a request's 0 takes and no request exceeds.
pub const CPU_THREADS_DEFAULT: u32 = 4;

/// Default of a template's `require`: a workload stays out of the vault and
/// off the network.
pub const REQUIRE_DEFAULT: [BoundRequirement; 2] = [
    BoundRequirement {
        bound: ScopeBound::FileWall,
        kernel: false,
    },
    BoundRequirement {
        bound: ScopeBound::NetworkClosed,
        kernel: false,
    },
];

/// The longest template name, in bytes.
const TEMPLATE_NAME_MAX: usize = 64;

/// The largest compiled parameter pattern, in bytes.
const PARAM_PATTERN_SIZE_MAX: usize = 1 << 16;

/// The file: one `[execution_node]` table.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExecutionNodeFile {
    execution_node: ExecutionNodeSettings,
}

/// The node's `[execution_node]` table. An engine refuses a file with a key
/// it does not know (`deny_unknown_fields`): set `readiness_every_secs` or
/// `drain_clear_by` only on a machine whose engine has pass 34 row Q4.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionNodeSettings {
    /// Whether this machine runs jobs at all. Default false.
    #[serde(default)]
    pub enabled: bool,
    /// The machines that may reserve, submit, read or stop a job here:
    /// exactly one in this release (section 8.7, one issuer).
    #[serde(default)]
    pub issuers: Vec<EntityId>,
    /// The journal and the control files: the engine's account only.
    pub state_dir: PathBuf,
    /// The payload directories: checkout, out, tmp, logs.
    pub work_dir: PathBuf,
    #[serde(default = "disk_reserve_gib_default")]
    pub disk_reserve_gib: u64,
    #[serde(default = "state_floor_mib_default")]
    pub state_floor_mib: u64,
    #[serde(default = "receipt_keep_days_default")]
    pub receipt_keep_days: u32,
    #[serde(default = "staging_limit_secs_default")]
    pub staging_limit_secs: u64,
    /// The scope kinds this machine permits.
    #[serde(default = "host_scope")]
    pub scopes: Vec<ScopeClass>,
    /// The OS account the job unit runs as.
    #[serde(default = "job_account_default")]
    pub job_account: String,
    /// `jobs.readiness.every_secs`: how often the node checks itself while
    /// no attempt runs (pass 34, 7.3). The owner's row may shorten it (row
    /// P0).
    #[serde(default = "readiness_every_secs_default")]
    pub readiness_every_secs: u64,
    /// `machines.drain.clear_by`: who clears the node's drain (pass 34,
    /// 2.4). The owner's row may keep the drain for the box (row P0).
    #[serde(default)]
    pub drain_clear_by: DrainClearBy,
    /// The workloads this machine may run, by name.
    #[serde(default)]
    pub templates: BTreeMap<String, NodeTemplate>,
    #[serde(default = "stop_grace_secs_default")]
    pub stop_grace_secs: u64,
    #[serde(default = "unit_start_timeout_secs_default")]
    pub unit_start_timeout_secs: u64,
    #[serde(default = "disk_check_secs_default")]
    pub disk_check_secs: u64,
    /// The files of each device a job may lease, by the device's id: the
    /// job unit's device policy opens these and no others. A card the NVIDIA
    /// driver lists needs no entry (its node and the driver's control nodes
    /// are found by its UUID).
    #[serde(default)]
    pub device_files: BTreeMap<String, Vec<PathBuf>>,
    /// Whether the node obeys the owner's machine policy rows (pass 34 2.4, row P0) as well as
    /// this file, the stricter of the two applying. Default true; false keeps the node to this
    /// file alone.
    #[serde(default = "owner_policy_default")]
    pub owner_policy: bool,
    /// The host's quiet marker, an absolute path (row GPU-QUIET-LEASE, `jobs::quiet_lease`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quiet_tag: Option<PathBuf>,
    /// The most memory the node's jobs hold at once, in GiB. Absent: the machine's total.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub job_memory_gib: Option<u64>,
    /// The most threads one job uses, a ceiling over every template's `cpu_threads`. Absent: the
    /// machine's cores.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub job_threads: Option<u32>,
}

/// Who clears a node's drain (`machines.drain.clear_by`, pass 34 2.4). The
/// box file accepts these two. The owner's row (row P0) of `owner` or
/// `grants` reads here as `person_at_box`, since no owner act reaches the
/// node's own drain yet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DrainClearBy {
    /// The machine itself, once its readiness check passes (the default;
    /// CG-2 row 9).
    #[default]
    AfterReadinessCheck,
    /// A person at the box (`oneiron execution-node resume`), as pass 33
    /// had it.
    PersonAtBox,
}

/// One `[execution_node.templates.<name>]`: what a pin of it may run, and
/// within which ceilings. A pin names it by [`NodeTemplate::digest`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeTemplate {
    /// A host-local mirror: the code comes only from here.
    pub repo: PathBuf,
    /// The entry paths a pin may name, relative to the checkout; `*` and
    /// `?` match within one path segment.
    pub entries: Vec<String>,
    /// The interpreter and its leading arguments.
    pub interpreter: Vec<String>,
    /// Paths the job reads, read-only.
    #[serde(default)]
    pub read: Vec<PathBuf>,
    /// Shared paths the job writes: none in this release.
    #[serde(default)]
    pub write: Vec<PathBuf>,
    #[serde(default = "write_mib_per_sec_default")]
    pub write_mib_per_sec: u64,
    #[serde(default)]
    pub env: BTreeMap<String, String>,
    /// The network modes a pin may ask for.
    #[serde(default = "no_network")]
    pub network: Vec<NetworkMode>,
    /// The scope kinds a pin of this template may ask for; the machine's
    /// `scopes` bound them too.
    #[serde(default = "host_scope")]
    pub scopes: Vec<ScopeClass>,
    /// The outputs that may travel to the issuer.
    #[serde(default)]
    pub returnable: Vec<String>,
    /// The arguments a pin may pass, by name, each with the pattern its
    /// whole value matches. Absent: the arguments are not checked by name;
    /// declared, even empty, every argument must be one of them.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub params: Option<BTreeMap<String, String>>,
    /// The longest run of a job, and the longest chunk of a session, in
    /// seconds.
    pub max_secs: u64,
    /// The job's memory ceiling.
    pub memory_gib: u64,
    /// The job's disk ceiling on the payload disk.
    pub disk_gib: u64,
    /// The bounds the job's scope must give, else the job is blocked
    /// (pass 34, section 2.2): `file_wall` at any strength,
    /// `memory_cap:kernel` only from the kernel. Every other bound the scope
    /// does not enforce is recorded on the run as unproven.
    #[serde(default = "require_default")]
    pub require: Vec<BoundRequirement>,
    /// The devices one pin may claim, the counts of all its claims together.
    #[serde(default = "max_devices_default")]
    pub max_devices: u32,
    /// The job unit's task ceiling, at least [`TASKS_MAX_FLOOR`]: the
    /// workload's tasks and the unit's own log writer count against it.
    #[serde(default = "tasks_max_default")]
    pub tasks_max: u64,
    /// A run has the host to itself (row GPU-QUIET-LEASE, `jobs::quiet_lease`).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub quiet: bool,
    /// The power limit, in watts, the prepare step sets on each leased card (`gpu_power`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gpu_power_watts: Option<u32>,
    /// The operating-system signal a checkpoint notice delivers to the
    /// workload (design 7.1 `Signal`), one of [`CHECKPOINT_SIGNALS`]. None:
    /// the notice is a no-op. Absent from the digest when unset, so a
    /// template without it keeps its digest.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checkpoint_signal: Option<String>,
    /// The MiB each of a run's log files keeps (pass 34, 7.2): past it, the
    /// first half of the cap and the newest bytes. None:
    /// [`LOG_MAX_MIB_DEFAULT`]. Absent from the digest when unset, so a
    /// template without it keeps its digest.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub log_max_mib: Option<u32>,
    /// The threads a run may use at once: a request's 0 takes this many, and
    /// no request asks more.
    #[serde(default = "cpu_threads_default")]
    pub cpu_threads: u32,
    /// What a run of this template is (pass 34, 2.5): a finite `job`, cut
    /// off at its maximum, or a `session`, whose one run continues through
    /// the paid chunks its issuer renews (row W1). Absent from the digest as
    /// a job, so a template without it keeps its digest.
    #[serde(default, skip_serializing_if = "TemplateKind::is_job")]
    pub kind: TemplateKind,
    /// A session's longest run across its renewals, in seconds, from its
    /// launch: no renewal moves the cutoff past it, and the job unit's
    /// backstop covers it. Applies only to a `session`; None:
    /// [`SESSION_MAX_SECS_DEFAULT`]. Absent from the digest when unset, so
    /// a template without it keeps its digest.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_max_secs: Option<u64>,
}

/// What a run of a template is: the wire's [`TemplateKind`], which a
/// template states and its offer carries.
pub use super::wire::TemplateKind;

/// Default of a session template's `session_max_secs`: seven days.
pub const SESSION_MAX_SECS_DEFAULT: u64 = 7 * 24 * 60 * 60;

/// The longest `session_max_secs`: the job unit's `RuntimeMaxSec` backstop
/// takes it, and systemd holds that in microseconds.
pub const SESSION_MAX_SECS_CEILING: u64 = u64::MAX / 1_000_000;

/// The signals a template may name as its checkpoint notice: each one a
/// workload can catch and none that stops it.
pub const CHECKPOINT_SIGNALS: &[&str] = &["HUP", "INT", "USR1", "USR2", "WINCH"];

fn disk_reserve_gib_default() -> u64 {
    DISK_RESERVE_GIB_DEFAULT
}
fn state_floor_mib_default() -> u64 {
    STATE_FLOOR_MIB_DEFAULT
}
fn receipt_keep_days_default() -> u32 {
    RECEIPT_KEEP_DAYS_DEFAULT
}
fn staging_limit_secs_default() -> u64 {
    STAGING_LIMIT_SECS_DEFAULT
}
fn readiness_every_secs_default() -> u64 {
    READINESS_EVERY_SECS_DEFAULT
}
fn job_account_default() -> String {
    JOB_ACCOUNT_DEFAULT.to_owned()
}
fn write_mib_per_sec_default() -> u64 {
    WRITE_MIB_PER_SEC_DEFAULT
}
fn max_devices_default() -> u32 {
    MAX_DEVICES_DEFAULT
}
fn require_default() -> Vec<BoundRequirement> {
    REQUIRE_DEFAULT.to_vec()
}
fn cpu_threads_default() -> u32 {
    CPU_THREADS_DEFAULT
}
fn stop_grace_secs_default() -> u64 {
    STOP_GRACE_SECS_DEFAULT
}
fn unit_start_timeout_secs_default() -> u64 {
    UNIT_START_TIMEOUT_SECS_DEFAULT
}
fn disk_check_secs_default() -> u64 {
    DISK_CHECK_SECS_DEFAULT
}
fn tasks_max_default() -> u64 {
    TASKS_MAX_DEFAULT
}
fn owner_policy_default() -> bool {
    true
}
fn host_scope() -> Vec<ScopeClass> {
    vec![ScopeClass::Host]
}
fn no_network() -> Vec<NetworkMode> {
    vec![NetworkMode::None]
}

impl ExecutionNodeSettings {
    /// Reads and validates the node's file at `path`: `Ok(None)` when there
    /// is none.
    ///
    /// # Errors
    ///
    /// Why the file does not read or does not validate.
    pub fn read(path: &Path) -> Result<Option<Self>, String> {
        let text = match std::fs::read_to_string(path) {
            Ok(text) => text,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(format!("{}: {error}", path.display())),
        };
        Self::parse(&text)
            .map(Some)
            .map_err(|why| format!("{}: {why}", path.display()))
    }

    /// Parses and validates the text of a node's file.
    ///
    /// # Errors
    ///
    /// Why the text does not parse or does not validate.
    pub fn parse(text: &str) -> Result<Self, String> {
        let file: ExecutionNodeFile = toml::from_str(text).map_err(|error| error.to_string())?;
        let settings = file.execution_node;
        settings.validate()?;
        Ok(settings)
    }

    fn validate(&self) -> Result<(), String> {
        if self.enabled && self.issuers.len() != 1 {
            return Err(format!(
                "execution_node.issuers must name exactly one MACHINE id (one issuer, design 8.7); it names {}",
                self.issuers.len()
            ));
        }
        if self.issuers.iter().collect::<BTreeSet<_>>().len() != self.issuers.len() {
            return Err("execution_node.issuers names a machine twice".to_owned());
        }
        for (name, dir) in [("state_dir", &self.state_dir), ("work_dir", &self.work_dir)] {
            if !dir.is_absolute() {
                return Err(format!("execution_node.{name} must be an absolute path"));
            }
        }
        if self.scopes.is_empty() {
            return Err("execution_node.scopes must permit at least one scope kind".to_owned());
        }
        if self
            .quiet_tag
            .as_ref()
            .is_some_and(|tag| !tag.is_absolute())
        {
            return Err("execution_node.quiet_tag must be an absolute path".to_owned());
        }
        if self.job_memory_gib == Some(0) {
            return Err("execution_node.job_memory_gib must be at least 1 when set".to_owned());
        }
        if self.job_threads == Some(0) {
            return Err("execution_node.job_threads must be at least 1 when set".to_owned());
        }
        if self.job_account.trim().is_empty() {
            return Err("execution_node.job_account must name an OS account".to_owned());
        }
        for (name, template) in &self.templates {
            template
                .validate()
                .map_err(|why| format!("execution_node.templates.{name}: {why}"))?;
            if !plain_name(name, TEMPLATE_NAME_MAX) {
                return Err(format!(
                    "execution_node.templates.{name}: a template name is 1 to {TEMPLATE_NAME_MAX} of a-z, A-Z, 0-9, '.', '_' and '-'"
                ));
            }
        }
        Ok(())
    }

    /// Whether `machine` is one of this node's issuers.
    #[must_use]
    pub fn names_issuer(&self, machine: EntityId) -> bool {
        self.issuers.contains(&machine)
    }

    /// The disk every booking leaves free, in bytes.
    #[must_use]
    pub fn disk_reserve_bytes(&self) -> u64 {
        self.disk_reserve_gib.saturating_mul(1 << 30)
    }

    /// The templates as `Node` offers them: each with its digest, the scope
    /// kinds both it and this machine permit, its network modes and its
    /// returnable outputs.
    ///
    /// # Errors
    ///
    /// A template that does not encode.
    pub fn template_offers(&self) -> Result<Vec<TemplateOffer>, String> {
        self.templates
            .iter()
            .map(|(name, template)| {
                Ok(TemplateOffer {
                    name: name.clone(),
                    digest: template.digest()?,
                    scopes: template
                        .scopes
                        .iter()
                        .copied()
                        .filter(|scope| self.scopes.contains(scope))
                        .collect(),
                    network: template.network.clone(),
                    returnable: template.returnable.clone(),
                    require: template.require.clone(),
                    kind: template.kind,
                })
            })
            .collect()
    }

    /// The digest of the template named `name`, or `None` when this node
    /// holds no such template.
    #[must_use]
    pub fn template_digest(&self, name: &str) -> Option<String> {
        self.templates.get(name)?.digest().ok()
    }

    /// Design 7.3, reserve step 5: the template exists and its digest
    /// equals the pin's; the entry is relative, has no `..` and matches one
    /// of the template's entries; the scope kind and the network mode are
    /// ones the template and this machine permit; every returnable output is
    /// on the template's list; the request fits the template's ceilings;
    /// when the template declares `params`, every argument is `name=value`
    /// with a declared name and a value its pattern matches; and last, the
    /// pin has the shape the issuer's pin door checks
    /// ([`WorkloadPin::check_shape`]: lower-hex digests, relative paths,
    /// bounded arguments and outputs, and at most `REQUEST_DEVICE_CLAIMS_MAX`
    /// device claims, each of at least one device), since the node places
    /// what its issuer sent. Both the reserve and the job unit's root prepare
    /// step run this one check.
    ///
    /// # Errors
    ///
    /// The refusal reason, for the key's end.
    pub fn admit_pin(&self, pin: &WorkloadPin) -> Result<(), String> {
        let Some(template) = self.templates.get(&pin.template) else {
            return Err("template_unknown".to_owned());
        };
        if template.digest()? != pin.template_digest {
            return Err("template_digest_changed".to_owned());
        }
        let scope = ScopeClass::of(&pin.scope);
        if !template.scopes.contains(&scope) || !self.scopes.contains(&scope) {
            return Err("scope_not_permitted".to_owned());
        }
        template.admit_pin(pin)?;
        // Last, so each refusal the template judges keeps its own reason; a
        // claim of no device adds nothing to the template's devices ceiling,
        // and only the shape bounds the claims a pin carries.
        pin.check_shape()
            .map_err(|why| format!("pin_shape_invalid: {why}"))
    }

    /// The launch commit's fit of `pin`'s placement (pass 34, section 2.1,
    /// the sum rule): on a device that shares the host's memory, the claim's
    /// memory and the request's own draw on one pool, so the host memory the
    /// placement leases is within the template's memory ceiling. The pin
    /// passed [`Self::admit_pin`].
    ///
    /// # Errors
    ///
    /// The refusal reason, for the key's end.
    pub fn admit_placement(
        &self,
        pin: &WorkloadPin,
        placement: &DevicePlacement,
    ) -> Result<(), String> {
        let Some(template) = self.templates.get(&pin.template) else {
            return Err("template_unknown".to_owned());
        };
        if placement.host_memory_mib > template.memory_gib.saturating_mul(1024) {
            return Err("request_above_ceiling: host_memory_mib".to_owned());
        }
        Ok(())
    }
}

impl NodeTemplate {
    /// The template's digest: the content hash (BLAKE3, lower hex) of its
    /// canonical JSON form, made as a pin's digest is made, so one door
    /// names both. A pin names it; an edit of any field changes it.
    ///
    /// # Errors
    ///
    /// The template does not encode.
    pub fn digest(&self) -> Result<String, String> {
        // A session's default longest run, stated or not, is one template.
        let mut canonical = self.clone();
        if canonical.session_max_secs == Some(SESSION_MAX_SECS_DEFAULT) {
            canonical.session_max_secs = None;
        }
        let bytes = oneiron::llm::canonical_json_bytes(&canonical)
            .map_err(|error| format!("template_unencodable: {error}"))?;
        Ok(ContentHash::of(&bytes).to_hex())
    }

    /// A session's longest run from its launch, in seconds; `None` for a
    /// job, whose run ends at its submit's maximum.
    #[must_use]
    pub fn session_max_secs(&self) -> Option<u64> {
        match self.kind {
            TemplateKind::Job => None,
            TemplateKind::Session => {
                Some(self.session_max_secs.unwrap_or(SESSION_MAX_SECS_DEFAULT))
            }
        }
    }

    /// The bytes each of a run's log files keeps.
    #[must_use]
    pub fn log_max_bytes(&self) -> u64 {
        u64::from(self.log_max_mib.unwrap_or(LOG_MAX_MIB_DEFAULT)) << 20
    }

    fn validate(&self) -> Result<(), String> {
        if !self.repo.is_absolute() {
            return Err("repo must be an absolute path".to_owned());
        }
        if self.entries.is_empty() {
            return Err("entries must list at least one entry".to_owned());
        }
        for entry in &self.entries {
            if !relative_inside(entry) {
                return Err(format!(
                    "entry {entry:?} must be a relative path with no '..'"
                ));
            }
        }
        match self.interpreter.first() {
            Some(program) if Path::new(program).is_absolute() => {}
            _ => return Err("interpreter must start with an absolute program path".to_owned()),
        }
        if !self.write.is_empty() {
            return Err(
                "write must be empty in this release: a job writes only its payload directory"
                    .to_owned(),
            );
        }
        if self.network.is_empty() {
            return Err("network must permit at least one mode".to_owned());
        }
        if self.cpu_threads == 0 {
            return Err("cpu_threads must be at least 1".to_owned());
        }
        if self.gpu_power_watts == Some(0) {
            return Err("gpu_power_watts must be at least 1 when set".to_owned());
        }
        match (self.kind, self.session_max_secs) {
            (TemplateKind::Job, Some(_)) => {
                return Err("session_max_secs applies only to kind = \"session\"".to_owned());
            }
            (TemplateKind::Session, _) => {
                let longest = self.session_max_secs.unwrap_or(SESSION_MAX_SECS_DEFAULT);
                if longest > SESSION_MAX_SECS_CEILING {
                    return Err(format!(
                        "session_max_secs {longest} must be at most {SESSION_MAX_SECS_CEILING}"
                    ));
                }
                if longest < self.max_secs {
                    return Err(format!(
                        "session_max_secs {longest} must be at least max_secs {}",
                        self.max_secs
                    ));
                }
            }
            (TemplateKind::Job, None) => {}
        }
        if self.tasks_max < TASKS_MAX_FLOOR {
            return Err(format!(
                "tasks_max {} must be at least {TASKS_MAX_FLOOR}: the job unit's own processes count against it",
                self.tasks_max
            ));
        }
        if self.scopes.is_empty() {
            return Err("scopes must permit at least one scope kind".to_owned());
        }
        for name in &self.returnable {
            if !plain_name(name, 255) {
                return Err(format!("returnable {name:?} must be a plain file name"));
            }
        }
        if let Some(signal) = &self.checkpoint_signal
            && !CHECKPOINT_SIGNALS.contains(&signal.as_str())
        {
            return Err(format!(
                "checkpoint_signal {signal:?} must be one of {CHECKPOINT_SIGNALS:?}"
            ));
        }
        if let Some(mib) = self.log_max_mib
            && !(1..=LOG_MAX_MIB_CEILING).contains(&mib)
        {
            return Err(format!(
                "log_max_mib {mib} must be 1 to {LOG_MAX_MIB_CEILING}"
            ));
        }
        for (name, pattern) in self.params.iter().flatten() {
            if name.is_empty() || name.contains('=') {
                return Err(format!(
                    "params name {name:?} must be non-empty with no '='"
                ));
            }
            param_pattern(pattern).map_err(|why| format!("params.{name}: {why}"))?;
        }
        Ok(())
    }

    /// The rest of reserve step 5 for a pin of this template: entry,
    /// network, outputs, ceilings and parameters.
    fn admit_pin(&self, pin: &WorkloadPin) -> Result<(), String> {
        if !relative_inside(&pin.entry) {
            return Err("entry_not_relative".to_owned());
        }
        if !self
            .entries
            .iter()
            .any(|pattern| segment_glob(pattern, &pin.entry))
        {
            return Err("entry_not_listed".to_owned());
        }
        if !relative_inside(&pin.contract_path) {
            return Err("contract_path_not_relative".to_owned());
        }
        if !self.network.contains(&pin.network) {
            return Err("network_not_permitted".to_owned());
        }
        if let Some(output) = pin
            .outputs
            .iter()
            .find(|output| output.returnable && !self.returnable.contains(&output.name))
        {
            return Err(format!("output_not_returnable: {}", output.name));
        }
        let request = &pin.request;
        let devices = request.devices.iter().fold(0_u64, |sum, claim| {
            sum.saturating_add(u64::from(claim.count))
        });
        for (field, asked, ceiling) in [
            ("devices", devices, u64::from(self.max_devices)),
            (
                "cpu_threads",
                u64::from(request.cpu_threads),
                u64::from(self.cpu_threads),
            ),
            ("maximum_secs", request.maximum_secs, self.max_secs),
            (
                "memory_mib",
                request.memory_mib,
                self.memory_gib.saturating_mul(1024),
            ),
            (
                "disk_mib",
                request.disk_mib,
                self.disk_gib.saturating_mul(1024),
            ),
        ] {
            if asked > ceiling {
                return Err(format!("request_above_ceiling: {field}"));
            }
        }
        if let Some(params) = &self.params {
            for arg in &pin.args {
                let Some((name, value)) = arg.split_once('=') else {
                    return Err("arg_not_name_value".to_owned());
                };
                let Some(pattern) = params.get(name) else {
                    return Err(format!("arg_not_declared: {name}"));
                };
                let matches = param_pattern(pattern).is_ok_and(|pattern| pattern.is_match(value));
                if !matches {
                    return Err(format!("arg_pattern_mismatch: {name}"));
                }
            }
        }
        Ok(())
    }
}

/// `pattern` compiled to match a whole value. The pattern must compile on
/// its own first, so its text cannot close the group it is placed in.
fn param_pattern(pattern: &str) -> Result<regex::Regex, String> {
    let alone = |source: &str| {
        regex::RegexBuilder::new(source)
            .size_limit(PARAM_PATTERN_SIZE_MAX)
            .build()
            .map_err(|error| error.to_string())
    };
    alone(pattern)?;
    alone(&format!(r"\A(?:{pattern})\z"))
}

/// Whether `path` is relative, non-empty, and every one of its segments is
/// a plain name: no root, no `.` or `..`, no empty segment, no backslash.
fn relative_inside(path: &str) -> bool {
    !path.is_empty()
        && !path.contains('\\')
        && !path.split('/').any(str::is_empty)
        && Path::new(path)
            .components()
            .all(|component| matches!(component, Component::Normal(_)))
        && !path
            .split('/')
            .any(|segment| segment == "." || segment == "..")
}

/// Whether `text` matches `pattern` segment by segment: the same count of
/// `/`-separated segments, `*` matching any run and `?` any one character
/// within a segment.
fn segment_glob(pattern: &str, text: &str) -> bool {
    let patterns: Vec<&str> = pattern.split('/').collect();
    let segments: Vec<&str> = text.split('/').collect();
    patterns.len() == segments.len()
        && patterns
            .iter()
            .zip(&segments)
            .all(|(pattern, segment)| glob_segment(pattern.as_bytes(), segment.as_bytes()))
}

/// Whether one segment `text` matches one segment `pattern`, in time
/// linear in their product: the classic greedy match, which returns to the
/// last `*` when a later byte fails.
fn glob_segment(pattern: &[u8], text: &[u8]) -> bool {
    let (mut at_pattern, mut at_text) = (0, 0);
    let mut last_star: Option<(usize, usize)> = None;
    while at_text < text.len() {
        match pattern.get(at_pattern) {
            Some(b'*') => {
                last_star = Some((at_pattern, at_text));
                at_pattern += 1;
            }
            Some(byte) if *byte == b'?' || *byte == text[at_text] => {
                at_pattern += 1;
                at_text += 1;
            }
            _ => match last_star {
                Some((star, matched)) => {
                    at_pattern = star + 1;
                    at_text = matched + 1;
                    last_star = Some((star, matched + 1));
                }
                None => return false,
            },
        }
    }
    pattern[at_pattern..].iter().all(|byte| *byte == b'*')
}

/// Whether `name` is 1 to `max` bytes of `a-z A-Z 0-9 . _ -`, and not `.`
/// or `..`.
fn plain_name(name: &str, max: usize) -> bool {
    (1..=max).contains(&name.len())
        && name != "."
        && name != ".."
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}
