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
pub use oneiron::job_workload::{NetworkMode, OutputDecl, ResourceRequest, ScopeKind, WorkloadPin};
use serde::{Deserialize, Serialize};

/// The mesh ALPN that admits new work on a node: [`JobRequest`].
pub const JOB_ALPN: &[u8] = b"oneiron/job/1";
/// The mesh ALPN that serves the keys a node already holds:
/// [`JobStatusRequest`].
pub const JOB_STATUS_ALPN: &[u8] = b"oneiron/job-status/1";
/// The protocols' name in a codec error.
pub const JOB_PROTOCOL: &str = "job mesh";
/// The domain the issuer's machine key signs a [`JobSubmit`] under.
pub const JOB_SUBMIT_DOMAIN: &[u8] = b"oneiron/job-submit/v1";
/// The domain the node's machine key signs a [`JobReceipt`] under.
pub const JOB_RECEIPT_DOMAIN: &[u8] = b"oneiron/job-receipt/v1";
/// The most bytes one [`JobStatusRequest::Fetch`] answers: one transport
/// piece under the 1 MiB message bound.
pub const FETCH_MAX_BYTES: u64 = 1_044_480;

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
}

/// A reserve: the key, the pin it will run, and the device if the issuer
/// chose one. The node forms the device slot request from the key, the
/// pin's resource request and `device_id`, so a slot never disagrees with
/// its pin.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JobReserve {
    pub key: String,
    pub pin: WorkloadPin,
    pub device_id: Option<String>,
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
    pub pin: WorkloadPin,
    pub device_id: Option<String>,
    /// The cutoff the node arms, at most the pin's maximum.
    pub maximum_secs: u64,
    pub issued_at_ms: u64,
    pub not_after_ms: u64,
    pub issuer: EntityId,
    pub starter: Starter,
    pub hold: HoldRef,
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
}

/// One template a node holds, as [`NodeAnswer`] names it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TemplateOffer {
    pub name: String,
    /// The sha256 (lower hex) of the template's canonical form, which a pin
    /// names.
    pub digest: String,
    pub scopes: Vec<ScopeClass>,
    pub network: Vec<NetworkMode>,
    /// The outputs that may travel to the issuer.
    pub returnable: Vec<String>,
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
    /// Every key of the asker the journal still holds, live and ended.
    Keys,
    /// The bytes of one returnable output, at most [`FETCH_MAX_BYTES`].
    Fetch { key: String, name: String },
    /// The issuer holds every returnable output it wants; only then may the
    /// node clean the key's `out/`.
    Ack { key: String },
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
    Keys(Vec<KeyEntry>),
    Output {
        #[serde(with = "serde_bytes")]
        bytes: Vec<u8>,
    },
    /// The signal or the acknowledgement is recorded.
    Acknowledged,
    Refused(JobRefusal),
}

/// One key in a [`JobStatusAnswer::Keys`] list.
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
}

/// What a node observed about a key. It travels inside a
/// [`SignedJobReceipt`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JobReceipt {
    pub key: String,
    /// The node.
    pub machine: EntityId,
    pub epoch: String,
    pub device_id: Option<String>,
    pub issuer: EntityId,
    pub starter: Starter,
    /// The money the submit named; `None` before a submit was accepted.
    pub hold: Option<HoldRef>,
    /// The digest the node computed from the pin it holds.
    pub workload: String,
    pub state: JobState,
    /// False: the workload process never existed and never can.
    pub started: bool,
    pub end: Option<JobEnd>,
    pub occupied: Option<Occupied>,
    /// The occupied interval in whole seconds, rounded up; `None` is
    /// unknown (a lost box), never zero.
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
}

/// A receipt with the node's machine-key signature under
/// [`JOB_RECEIPT_DOMAIN`] over the codec encoding of `receipt`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedJobReceipt {
    pub receipt: JobReceipt,
    #[serde(with = "serde_bytes")]
    pub signature: [u8; 64],
}
