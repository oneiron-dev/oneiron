//! The job protocols' messages (pass 33, `33-exec-node/DESIGN.md` sections
//! 5.3 and 7.1). The issuer, the machine that holds the job rows, asks a
//! node, the machine that runs the job, over two mesh protocols, one message
//! each way per stream in the organ codec
//! ([`oneiron_mesh_transport::message`]):
//!
//! - [`JOB_ALPN`] admits new work: [`JobRequest`], answered by
//!   [`JobAnswer`];
//! - [`JOB_STATUS_ALPN`] serves keys the node already holds:
//!   [`JobStatusRequest`], answered by [`JobStatusAnswer`].
//!
//! A grant is per protocol (EM-1 = A): revoking `oneiron/job/1` stops new
//! work and leaves the route that collects the receipts of the jobs it
//! stopped.
//!
//! The wire never carries a program: a job names a template the node holds,
//! by its digest, inside a [`WorkloadPin`]. The interpreter, the
//! environment, every host path and the limits are the node's own.

use oneiron::EntityId;
pub use oneiron::job_workload::{
    BoundRequirement, DeviceClaim, JOB_ALPN, JOB_STATUS_ALPN, NetworkMode, OutputDecl,
    ResourceRequest, ScopeCapabilities, ScopeKind, WorkloadPin,
};
use oneiron::machine_readiness::ReadinessStreak;
use oneiron::machine_signature::{MachineSignatureError, MachineSignatures};
/// The warm keys of an issuer's open orders that may run on the node it
/// asks (row P2): one type with the issuer's pass.
pub use oneiron::warm_key::WarmWanted;
use oneiron_contracts::register::Register;
use serde::{Deserialize, Serialize};

use super::availability::GpuAvailability;
use super::device::DeviceSample;

/// The protocols' name in a codec error.
pub const JOB_PROTOCOL: &str = "job mesh";
/// The domain the issuer's machine key signs a [`JobSubmit`] under.
pub const JOB_SUBMIT_DOMAIN: &[u8] = b"oneiron/job-submit/v1\0";
/// The domain the node's machine key signs a [`JobReceipt`] under.
pub const JOB_RECEIPT_DOMAIN: &[u8] = b"oneiron/job-receipt/v1\0";
/// The most bytes one [`JobStatusRequest::Fetch`] answers: one transport
/// piece under the 1 MiB message bound.
pub const FETCH_MAX_BYTES: u64 = 1_044_480;
/// The most log bytes one [`JobStatusRequest::Tail`] answers, whatever its
/// `max`: one transport piece, as [`FETCH_MAX_BYTES`].
pub const TAIL_MAX_BYTES: u32 = 1_044_480;

/// Who started a job, as the submit states it and the receipt repeats it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Starter {
    /// The vault owner under their own proof.
    Owner,
    /// An agent under this live owner Grant.
    Grant { grant: EntityId },
}

/// The money a job's seconds are held under: the reservation and its
/// allocation generation, so a receipt links to the hold.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HoldRef {
    pub reservation: String,
    pub generation: u64,
}

/// The kind of a scope without its image: what a template permits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScopeClass {
    Host,
    Container,
}

impl ScopeClass {
    /// The class of `scope`.
    #[must_use]
    pub fn of(scope: &ScopeKind) -> Self {
        match scope {
            ScopeKind::Host => Self::Host,
            ScopeKind::Container { .. } => Self::Container,
        }
    }
}

/// A request on [`JOB_ALPN`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JobRequest {
    /// What the node offers now: [`JobAnswer::Node`].
    Node,
    /// A fresh sample of the node's GPUs: [`JobAnswer::Availability`]. A
    /// reading, not a hold.
    Availability,
    /// Hold a key and its disk space, never a device: answered by the
    /// key's receipt in state `Held`, or the key's existing receipt, or
    /// `Busy`. Journaled before it is answered; a reserve never starts a
    /// process.
    Reserve(JobReserve),
    /// Withdraw a `Held` key that has no accepted submit: answered by its
    /// `Withdrawn` receipt; anything later is refused.
    Release { key: String },
    /// Run a key the node holds as `Held`: answered by its `Accepted`
    /// receipt, or the key's existing receipt, or `Busy`.
    Submit(SignedJobSubmit),
    /// [`JobRequest::Node`] from an issuer whose open orders may run here,
    /// with the warm keys they list (pass 34, row P2): answered as `Node`.
    /// The node's cache budget removes none of them while this list is
    /// newer than its wanted hold, and no cache at all while an ask that
    /// left keys out for its bound holds. A node before row P2 cannot read
    /// it and closes the stream: the issuer then asks `Node`.
    NodeWanting(WarmWanted),
}

/// Which of the node's GPUs a key may take: the selectors of a GPU slot
/// request. The node forms the whole request from the key, these selectors
/// and the pin's resource request (its device claims and its `disk_mib`), so
/// a slot never disagrees with its pin.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SlotSelector {
    /// This GPU only, by the driver's device id (the vendor's UUID).
    pub device_id: Option<String>,
    /// A GPU of this model only, as the driver names it.
    pub model: Option<String>,
}

/// A reserve: the key, the pin it will run, and the GPU slot it may take.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JobReserve {
    pub key: String,
    pub pin: WorkloadPin,
    pub slot: SlotSelector,
    pub issuer: EntityId,
    pub starter: Starter,
    pub issued_at_ms: u64,
    pub not_after_ms: u64,
}

/// The issuer's order to run one chunk of a job under a key the node holds.
/// It travels inside a [`SignedJobSubmit`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JobSubmit {
    pub key: String,
    /// The issuer's `GPU_JOB` row.
    pub job: EntityId,
    pub chunk: u32,
    /// The key's reserve named the same pin and slot; a submit that names
    /// another is a key conflict.
    pub pin: WorkloadPin,
    pub slot: SlotSelector,
    /// The cutoff the node arms, at most the pin's maximum.
    pub maximum_secs: u64,
    pub issued_at_ms: u64,
    pub not_after_ms: u64,
    pub issuer: EntityId,
    pub starter: Starter,
    pub hold: HoldRef,
    /// The issuer's authority main-log heads when it signed (EM-11 = B),
    /// lower-hex entry hashes. The node launches once its own fold holds
    /// every one, so a revoke the issuer had folded stops the launch; else
    /// the key ends `LaunchRefused { authority_stale }` at the staging
    /// limit.
    pub authority_heads: Vec<String>,
    /// A session's renewal (pass 34, 2.5; row W1): the first key of the run
    /// this submit pays one more chunk of. The key is then a paid slice of
    /// that run: it needs no reserve, never starts a process and never
    /// holds a lease, and its chunk begins where the run's paid time ends.
    /// Absent from the encoding when `None`, so a submit without it signs
    /// the same bytes as before. A node that predates it decodes a renewal
    /// without it, so the signature it checks fails
    /// (`SubmitSignatureInvalid`): it journals and starts nothing. A
    /// renewal's `chunk` stays the issuer's own chunk counter, as for any
    /// submit; its place in the run is its receipt's `slice.renewal`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub continues: Option<String>,
    /// The warm keys the work reads, from the order (pass 34, row P2): at
    /// most [`oneiron::warm_key::ATTEMPT_WARM_KEYS_MAX`]. Each one the
    /// template maps to a path that is not a cache must be present before
    /// the launch. Left out when empty, so a submit without warm keys
    /// signs the bytes it signed before.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warm: Vec<String>,
}

/// A submit with the issuer's machine-key signature under
/// [`JOB_SUBMIT_DOMAIN`] over the codec encoding of `submit`. The node
/// verifies it against the proven peer. Every retry resends the same bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedJobSubmit {
    pub submit: JobSubmit,
    #[serde(with = "serde_bytes")]
    pub signature: [u8; 64],
}

/// The answer on [`JOB_ALPN`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JobAnswer {
    Node(NodeAnswer),
    /// The node's GPUs now, as OPUS-LE-FLEET's slot table reads them.
    Availability(GpuAvailability),
    /// The key's receipt: the one the request made, or the one it already
    /// had.
    Receipt(SignedJobReceipt),
    /// A condition that will pass (recovering, the engine stopping): try
    /// again after this long. Nothing was written.
    Busy {
        retry_after_ms: u64,
    },
    /// Refused before any key was journaled.
    Refused(JobRefusal),
}

/// What a node offers, as it answers [`JobRequest::Node`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeAnswer {
    /// Whether this node runs jobs at all (`[execution_node] enabled`).
    pub enabled: bool,
    /// Why it takes no new work now, while paused at the box.
    pub paused: Option<String>,
    /// Why it takes no new work until a person clears its drain.
    pub drained: Option<String>,
    pub templates: Vec<TemplateOffer>,
    /// The launch scopes this node starts runs in, each with what it can
    /// enforce now (pass 34, section 2.2). A scope that does not meet the
    /// minimum contract is listed and runs nothing.
    pub scopes: Vec<ScopeReport>,
    pub disk_free_bytes: u64,
    /// The disk the held keys have booked.
    pub disk_reserved_bytes: u64,
    /// The disk every booking leaves free.
    pub disk_reserve_bytes: u64,
    /// The journal's random id, which every receipt carries; `None` while
    /// the node keeps no journal.
    pub epoch: Option<String>,
    /// False until the start-up reconciliation has ended.
    pub swept: bool,
    pub boot_id: String,
    pub engine_version: String,
    /// The warm keys this node holds or has used (pass 34, row P2): every
    /// key a template maps, then those remembered from use alone.
    #[serde(default)]
    pub warm: Vec<WarmKeyFact>,
    /// What the node's last idle readiness check found (pass 34, 4.1 and
    /// 7.3); `None` while the node keeps no journal.
    #[serde(default)]
    pub readiness: Option<NodeReadiness>,
}

/// One check of a node's idle readiness check (pass 34, 7.3). Its names
/// ([`Register::name`]) are the wire spelling.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Register,
)]
#[serde(rename_all = "snake_case")]
#[register("jobs.readiness.check")]
pub enum ReadinessCheck {
    /// The launch scope meets the minimum contract.
    Scope,
    /// The devices answer a fresh reading.
    Devices,
    /// The payload disk keeps its reserve, and the state directory its
    /// floor.
    Disk,
    /// Each template's mirror is a readable directory.
    Mirrors,
    /// The wall clock kept step with the boot clock since the last check.
    Clock,
    /// No job unit runs that no key launched.
    Units,
}

/// What a node's last readiness check found.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReadinessState {
    /// No check has run yet.
    #[default]
    Unchecked,
    Ready,
    /// The first check that failed, and why. The node takes no new work
    /// (`Drained`) until a check passes.
    NotReady {
        check: ReadinessCheck,
        why: String,
    },
}

/// One readiness check's result, as the node keeps it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReadinessResult {
    /// When the check ran, on the node's wall clock.
    pub at_ms: u64,
    pub state: ReadinessState,
}

impl ReadinessResult {
    /// The result on one line: `<at_ms> ready`, or `<at_ms> <check>: <why>`.
    #[must_use]
    pub fn line(&self) -> String {
        match &self.state {
            ReadinessState::Unchecked => format!("{} unchecked", self.at_ms),
            ReadinessState::Ready => format!("{} ready", self.at_ms),
            ReadinessState::NotReady { check, why } => {
                format!("{} {}: {why}", self.at_ms, check.name())
            }
        }
    }
}

/// A node's readiness, as `Node` reports it (pass 34, 4.1 and 7.3): the
/// facts the issuer escalates on (16, practice 6).
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct NodeReadiness {
    pub state: ReadinessState,
    /// When the last check ran, on the node's wall clock; `None` before the
    /// first.
    pub checked_at_ms: Option<u64>,
    /// Checks failed in a row; 0 once one passes.
    pub failed_in_a_row: u32,
    /// When the first check of the current run of failures ran: the
    /// streak's identity. `None` while the last check passed.
    pub failing_since_ms: Option<u64>,
    /// The newest results, oldest first: at most
    /// `jobs.readiness.results_kept`.
    pub results: Vec<ReadinessResult>,
}

impl NodeReadiness {
    /// The run of failed checks this fact reports, as the issuer escalates
    /// it ([`oneiron::Vault::raise_machine_readiness_ask`]) for `machine`;
    /// `None` while the last check passed, or before any ran.
    #[must_use]
    pub fn streak(&self, machine: EntityId) -> Option<ReadinessStreak> {
        let ReadinessState::NotReady { check, why } = &self.state else {
            return None;
        };
        Some(ReadinessStreak {
            machine,
            failed_in_a_row: self.failed_in_a_row,
            failing_since_ms: self.failing_since_ms.or(self.checked_at_ms)?,
            check: check.name().to_owned(),
            why: why.clone(),
            results: self.results.iter().map(ReadinessResult::line).collect(),
        })
    }
}

/// One line the node writes every tick while a key runs (pass 34, 7.3):
/// what a host reset leaves behind, on the `Lost` receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Breadcrumb {
    pub boot_id: String,
    pub boot_ns: u64,
    pub wall_ms: u64,
    /// The key's devices, as the probe sampled them; empty where it gives
    /// nothing.
    pub devices: Vec<DeviceSample>,
}

/// What a run of a template is (pass 34, 2.5).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TemplateKind {
    /// A finite workload: its run ends at the submit's maximum.
    #[default]
    Job,
    /// A long-running harness or service: its run goes on while its issuer
    /// pays each next chunk before the current one ends (row W1).
    Session,
}

impl TemplateKind {
    /// Whether this is the default kind, a job.
    #[must_use]
    pub fn is_job(&self) -> bool {
        *self == Self::Job
    }
}

/// One warm key, as [`NodeAnswer`] reports it. Nothing about the key's
/// content is read or sent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WarmKeyFact {
    pub key: String,
    /// A template maps the key to a path, and the path exists now.
    pub present: bool,
    /// A template maps the key to a path; a key no template maps is
    /// remembered from use alone, a hint.
    pub mapped: bool,
    /// Its path is a cache: absent is a cold start, and the cache budget
    /// may remove it.
    pub cache: bool,
    /// What its path held at the last cache pass; 0 when not measured.
    pub bytes: u64,
    /// When an attempt that listed it last ended with exit 0, or when the
    /// node first found its path.
    pub last_used_ms: Option<u64>,
    /// How many attempts that listed it ended with exit 0.
    pub uses: u64,
}

/// One template a node holds, as [`NodeAnswer`] names it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TemplateOffer {
    pub name: String,
    /// The content hash (BLAKE3, lower hex) of the template's canonical
    /// JSON form, made as a pin's digest is made; a pin names it.
    pub digest: String,
    pub scopes: Vec<ScopeClass>,
    pub network: Vec<NetworkMode>,
    /// The outputs that may travel to the issuer.
    pub returnable: Vec<String>,
    /// The bounds a run of this template needs from its scope: a scope that
    /// lacks one does not fit. Every bound not listed that the scope does
    /// not enforce is recorded on the run as unproven.
    pub require: Vec<BoundRequirement>,
    /// What a run of the template is (pass 34, 2.5; row W1): only a
    /// `session`'s run takes a renewal. Absent for a job, as before, so an
    /// issuer reads a node that predates sessions as offering jobs alone.
    #[serde(default, skip_serializing_if = "TemplateKind::is_job")]
    pub kind: TemplateKind,
}

/// One launch scope a node starts runs in, and what it can enforce now.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScopeReport {
    pub class: ScopeClass,
    pub capabilities: ScopeCapabilities,
}

/// Why a node refused a request before journaling any key. A refusal the
/// issuer may treat as final for a key is written down instead, as that
/// key's `Ended { Refused }` receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JobRefusal {
    /// This node runs no jobs.
    NotEnabled,
    /// The asker is not proven for this protocol now.
    PeerNotProven,
    /// The asker is not one of this node's issuers.
    NotIssuer,
    /// This node's own job grant is not live in its fold.
    OwnGrantEnded,
    /// The issuer's standing is not live in this node's fold.
    IssuerStandingEnded,
    /// Paused at the box, with why.
    Paused { why: String },
    /// Drained until a person clears it, with why.
    Drained { why: String },
    /// A release of a key that is no longer `Held` with no accepted submit.
    NotReleasable { state: JobState },
    /// The node lost the journal that could have held a key: it admits
    /// nothing until `reset-history` at the box.
    HistoryLost,
    /// A submit under a known key with another pin or slot: nothing
    /// changed.
    KeyConflict,
    /// The request names a key the journal recorded for another issuer.
    NotTheKeysIssuer,
    /// The submit's signature is not its issuer's.
    SubmitSignatureInvalid,
    /// The node's GPUs could not be read now, with why.
    DevicesUnreadable { why: String },
    /// `Fetch` of an output the node does not hand out: not one of the
    /// key's hashed returnable outputs, cleaned, or changed since it was
    /// hashed, with why. Nothing was read for the issuer.
    OutputNotFetchable { why: String },
    /// `Ack` of a key that has not ended: nothing changed.
    NotAcknowledgeable { state: JobState },
    /// `Tail` of a log the node does not read: the payload is cleaned, or
    /// the file or its drop record is not what the unit writes, with why.
    LogNotReadable { why: String },
}

/// A request on [`JOB_STATUS_ALPN`]. Every request that names a key is
/// answered only to the issuer the journal recorded for it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JobStatusRequest {
    /// The key's newest receipt: `Known`, `Absent`, `HistoryLost`, or
    /// `Busy` while the node has not swept.
    Find { key: String },
    /// As `Find`.
    Status { key: String },
    /// A checkpoint notice to the workload; a no-op unless its template
    /// names a signal.
    Signal { key: String, signal: String },
    /// Closes a key that has not launched (also one the node never saw);
    /// ends one that has. Answered by the key's receipt.
    Stop { key: String },
    /// One page of the keys of the asker the journal still holds, live and
    /// ended: the first page with no `after`, then each next page from the
    /// `next` of the page before.
    Keys { after: Option<String> },
    /// The bytes of one returnable output, at most [`FETCH_MAX_BYTES`].
    Fetch { key: String, name: String },
    /// The issuer holds every returnable output it wants; only then may the
    /// node clean the key's `out/`.
    Ack { key: String },
    /// Bytes of a key's log from an offset (pass 34, 7.2).
    Tail(LogTailRequest),
}

/// A [`JobStatusRequest::Tail`]: at most `max` bytes (and at most
/// [`TAIL_MAX_BYTES`]) of the key's `stream` from the logical `offset`,
/// while the key runs and after it ended, until its payload is cleaned. The
/// reader keeps its own offset: after a dropped connection it asks again
/// from the last `next_offset` it holds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogTailRequest {
    pub key: String,
    pub stream: LogStream,
    pub offset: u64,
    pub max: u32,
}

/// One of a key's two log files.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LogStream {
    Stdout,
    Stderr,
}

impl LogStream {
    /// The file's name under the payload's `log/`.
    #[must_use]
    pub const fn file_name(self) -> &'static str {
        match self {
            Self::Stdout => "stdout",
            Self::Stderr => "stderr",
        }
    }
}

/// The answer to a [`JobStatusRequest::Tail`]. Offsets are logical: they
/// count every byte the workload wrote to the stream, also the bytes the
/// cap dropped later.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogTail {
    /// The stream's bytes from `offset` plus the bytes `truncated` skipped.
    #[serde(with = "serde_bytes")]
    pub bytes: Vec<u8>,
    /// Where the next `Tail` asks from: `offset`, plus the bytes skipped,
    /// plus `bytes`' length. Never past the stream's end.
    pub next_offset: u64,
    /// The key ended and nothing follows `next_offset`: the stream is
    /// whole.
    pub ended: bool,
    /// The cap dropped bytes the reader asked for: `bytes` begin after them.
    pub truncated: Option<LogTruncation>,
}

/// The bytes the log cap removed between the asked offset and the first
/// byte answered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogTruncation {
    pub dropped: u64,
}

/// The answer on [`JOB_STATUS_ALPN`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JobStatusAnswer {
    /// The node holds this key: its newest receipt.
    Known(SignedJobReceipt),
    /// The key is not in this journal, named by its epoch.
    Absent {
        epoch: String,
    },
    /// The journal that could have held the key is lost. Never "not found".
    HistoryLost,
    /// Not answerable yet (the node has not swept): try again after this
    /// long.
    Busy {
        retry_after_ms: u64,
    },
    Keys(KeyPage),
    Output {
        #[serde(with = "serde_bytes")]
        bytes: Vec<u8>,
    },
    /// The signal or the acknowledgement is recorded.
    Acknowledged,
    Refused(JobRefusal),
    /// The bytes of a `Tail`.
    Tail(LogTail),
}

/// One page of a [`JobStatusRequest::Keys`] listing. A page stays under the
/// transport's 1 MiB message bound. The issuer has every key only once it
/// has read a page with no `next`; until then it has not reconciled.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyPage {
    pub entries: Vec<KeyEntry>,
    /// The cursor of the next page, opaque to the issuer; `None` on the last
    /// page.
    pub next: Option<String>,
}

/// One key in a [`KeyPage`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyEntry {
    pub key: String,
    pub state: JobState,
    /// The terminal receipt, once the key has ended.
    pub ended: Option<SignedJobReceipt>,
}

/// The states of a key on a node (section 7.2). A key never moves back, and
/// `Ended` is final.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JobState {
    Held,
    Accepted,
    Staging,
    Launching,
    Running,
    Ending,
    Ended,
}

/// How a key ended.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JobEnd {
    Exited {
        code: i32,
    },
    Signalled {
        signal: i32,
    },
    /// The node ended it at its maximum.
    TimeLimit,
    /// A session's paid slice whose time ran out while the run went on under
    /// the next chunk's key (pass 34, 2.5; row W1). The run itself has not
    /// ended: its process and leases stay with its first key.
    Continued,
    /// The node ended it over its memory request.
    MemoryLimit,
    /// The node ended it over its disk request.
    DiskLimit,
    /// The issuer asked, after the launch commit.
    Stopped,
    /// The node saw a grant or a machine end (EN-4).
    Revoked,
    /// Stopped before the launch commit: never started.
    Withdrawn,
    /// An admission refusal the node wrote down: never started.
    Refused {
        reason: String,
    },
    /// A check inside the launch commit failed: never started.
    LaunchRefused {
        reason: String,
    },
    /// A host reset, or a launch that left no trace.
    Lost {
        reason: String,
        last_tick_boot_ns: u64,
        /// The key's last breadcrumb lines before it was lost, oldest
        /// first: the evidence of a reset (pass 34, 7.3).
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        breadcrumbs: Vec<Breadcrumb>,
    },
}

/// The occupied interval, from the launch commit to the unit empty, on the
/// node's boot clock inside one boot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Occupied {
    pub boot_id: String,
    pub start_boot_ns: u64,
    pub end_boot_ns: Option<u64>,
}

/// Whether the node has given the job's device back.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeviceRelease {
    /// The key never held a device.
    NotHeld,
    Held,
    /// The unit was seen empty and the device clean.
    Confirmed {
        at_ms: u64,
    },
    /// The release check could not pass: the device stays out.
    Unconfirmed {
        why: String,
    },
}

/// The job's outputs, as the node hashed them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OutputsState {
    Pending,
    Hashed(Vec<OutputDigest>),
    Failed { why: String },
}

/// One output file the node hashed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutputDigest {
    pub name: String,
    /// Lower hex.
    pub sha256: String,
    pub bytes: u64,
    pub returnable: bool,
}

/// What the node proved about the scope the workload ran in.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScopeFacts {
    pub kind: ScopeClass,
    /// The OS account the unit ran as.
    pub account: String,
    /// The device nodes the unit's device policy admitted.
    pub devices: Vec<String>,
    /// The namespaces the unit ran in.
    pub namespaces: Vec<String>,
    /// The filesystem fence's read and write paths.
    pub fence: Vec<String>,
    /// The bounds the template required, each proven from inside the scope
    /// before the workload existed.
    pub required: Vec<BoundRequirement>,
    /// Each bound as the scope enforced it for this run: kernel, supervised
    /// or none. A bound outside `required` at none is unproven.
    pub bounds: ScopeCapabilities,
}

/// What a node observed about a key. It travels inside a
/// [`SignedJobReceipt`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JobReceipt {
    pub key: String,
    /// The node.
    pub machine: EntityId,
    pub epoch: String,
    /// The GPU the key leased; `None` before the launch commit, and for a
    /// key that never launched.
    pub device_id: Option<String>,
    pub issuer: EntityId,
    /// Who started the job, as its reserve stated it; `None` only for a key
    /// the node closed before any reserve of it arrived (a `Stop` of a key
    /// it never saw), whose starter it never learned.
    pub starter: Option<Starter>,
    /// The money the submit named; `None` before a submit was accepted.
    pub hold: Option<HoldRef>,
    /// The digest the node computed from the pin it holds; `None` exactly
    /// when `starter` is.
    pub workload: Option<String>,
    pub state: JobState,
    /// False: the workload process never existed and never can.
    pub started: bool,
    pub end: Option<JobEnd>,
    pub occupied: Option<Occupied>,
    /// The occupied seconds as the node measured them on its boot clock,
    /// rounded up: so far while the key is `Launching`, `Running` or
    /// `Ending`, final once it is `Ended`. The issuer never subtracts the
    /// node's boot times itself. `None` before the launch commit, and for an
    /// unknown interval (a lost box), never zero.
    pub measured_secs: Option<u64>,
    pub cutoff_at_ms: Option<u64>,
    pub release: DeviceRelease,
    pub outputs: OutputsState,
    /// `None` until the unit's prepare step proved its scope.
    pub scope: Option<ScopeFacts>,
    /// Processes the node did not start, seen on the device at the end
    /// probe.
    pub other_compute_pids: Vec<u32>,
    /// The journal's sequence: a later receipt of a key has a higher one,
    /// also after a reboot.
    pub seq: u64,
    pub boot_id: String,
    pub reported_at_ms: u64,
    /// The paid slice of a session's run this receipt reports (pass 34,
    /// 2.5; row W1); `None` for a key whose run was never renewed. Absent
    /// from the encoding when `None`, so such a receipt signs the same bytes
    /// as before.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub slice: Option<ReceiptSlice>,
}

/// One chunk's paid bounds inside a session's run, on the node's boot clock
/// of the run's launch: from the end of the chunk before (the launch, for the
/// first chunk) to this chunk's cutoff. `occupied` says how much of it the
/// run used; the slices of one run never overlap and leave no gap.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReceiptSlice {
    /// The key the run was launched under, which holds its process and
    /// leases.
    pub first_key: String,
    /// The slice's place in the run: 0 for the first key's own slice, `n`
    /// for its `n`th renewal. Not the submit's `chunk`, the issuer's own
    /// counter.
    pub renewal: u32,
    pub from_boot_ns: u64,
    pub to_boot_ns: u64,
}

/// A receipt with the node's machine-key signature under
/// [`JOB_RECEIPT_DOMAIN`] over the codec encoding of `receipt`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedJobReceipt {
    pub receipt: JobReceipt,
    #[serde(with = "serde_bytes")]
    pub signature: [u8; 64],
}

/// The codec encoding of `value`, which a machine signature covers.
fn signed_message<T: Serialize>(value: &T) -> Result<Vec<u8>, MachineSignatureError> {
    oneiron_organ_protocol::to_vec(value)
        .map_err(|error| MachineSignatureError::Encode(error.to_string()))
}

/// Signs as `signers`' machine, which must be `named`.
fn sign_as<T: Serialize>(
    signers: &dyn MachineSignatures,
    named: EntityId,
    domain: &[u8],
    value: &T,
) -> Result<[u8; 64], MachineSignatureError> {
    let (local, signature) = signers.sign(domain, &signed_message(value)?)?;
    if local == named {
        Ok(signature)
    } else {
        Err(MachineSignatureError::NotThisMachine { named, local })
    }
}

impl SignedJobSubmit {
    /// `submit` signed by this install, which must be its `issuer`.
    ///
    /// # Errors
    /// As [`MachineSignatures::sign`]; `NotThisMachine` when this install
    /// is not `submit.issuer`.
    pub fn sign(
        submit: JobSubmit,
        signers: &dyn MachineSignatures,
    ) -> Result<Self, MachineSignatureError> {
        let signature = sign_as(signers, submit.issuer, JOB_SUBMIT_DOMAIN, &submit)?;
        Ok(Self { submit, signature })
    }

    /// `Ok` when the submit's `issuer` signed it, by its MACHINE row.
    ///
    /// # Errors
    /// As [`MachineSignatures::verify`].
    pub fn verify(&self, signers: &dyn MachineSignatures) -> Result<(), MachineSignatureError> {
        signers.verify(
            self.submit.issuer,
            JOB_SUBMIT_DOMAIN,
            &signed_message(&self.submit)?,
            &self.signature,
        )
    }
}

impl SignedJobReceipt {
    /// `receipt` signed by this install, which must be its `machine`.
    ///
    /// # Errors
    /// As [`MachineSignatures::sign`]; `NotThisMachine` when this install
    /// is not `receipt.machine`.
    pub fn sign(
        receipt: JobReceipt,
        signers: &dyn MachineSignatures,
    ) -> Result<Self, MachineSignatureError> {
        let signature = sign_as(signers, receipt.machine, JOB_RECEIPT_DOMAIN, &receipt)?;
        Ok(Self { receipt, signature })
    }

    /// `Ok` when the receipt's `machine` signed it, by its MACHINE row.
    ///
    /// # Errors
    /// As [`MachineSignatures::verify`].
    pub fn verify(&self, signers: &dyn MachineSignatures) -> Result<(), MachineSignatureError> {
        signers.verify(
            self.receipt.machine,
            JOB_RECEIPT_DOMAIN,
            &signed_message(&self.receipt)?,
            &self.signature,
        )
    }
}
