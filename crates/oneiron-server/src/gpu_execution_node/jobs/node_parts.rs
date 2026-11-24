//! What the node's job service takes from the rest of the server, each
//! behind one trait so the journal and the launch commit are tested with
//! scripted parts (design pass 33, section 11: R3a runs against a scripted
//! unit manager and needs no privilege):
//! - [`NodeAdmission`]: the node's own configuration and controls, read
//!   fresh at each use (row R1's `[execution_node]`, its template check and
//!   its fold reads);
//! - [`NodeDevices`]: the machine's GPU slot table (OPUS-LE-FLEET);
//! - [`oneiron_organ_host::MachineFloor`]: the machine's memory line, the
//!   floor a launched job's memory is taken from;
//! - [`AuthorityPosition`]: whether the node's own authority fold holds the
//!   position the issuer signed the submit at (EM-11 = B);
//! - [`Stager`]: the checkout and the contract check (row R3c);
//! - [`oneiron::machine_signature::MachineSignatures`]: the one machine-key
//!   signing path, for the receipt and the submit check;
//! - [`super::job_unit::JobUnit`] and [`super::job_unit::NodeClock`].

use std::path::PathBuf;
use std::sync::Arc;

use oneiron::EntityId;
use oneiron::machine_signature::MachineSignatures;
use oneiron_organ_host::MachineFloor;

pub use oneiron_organ_host::{
    GpuDeviceLease, GpuDeviceProcesses, GpuJobEnd, GpuSlotRefusal, GpuSlotRequest,
};

use super::job_unit::{JobKeyId, JobUnit, NodeClock};
use crate::gpu_execution_node::wire::WorkloadPin;

/// The node's local controls, read at one moment under the admission lock.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct NodeControls {
    /// `[execution_node] enabled`.
    pub enabled: bool,
    /// Why the node takes no new work while paused at the box.
    pub paused: Option<String>,
    /// Why the node takes no new work until a person clears its drain.
    pub drained: Option<String>,
}

impl NodeControls {
    /// The refusal reason when the node takes no new work now.
    #[must_use]
    pub fn refusal(&self) -> Option<String> {
        if !self.enabled {
            return Some("node_disabled".to_owned());
        }
        if let Some(why) = &self.paused {
            return Some(format!("node_paused: {why}"));
        }
        if let Some(why) = &self.drained {
            return Some(format!("node_drained: {why}"));
        }
        None
    }
}

/// The node's own configuration and authority, as the job service reads
/// them. Row R1's job service implements it over `[execution_node]` and the
/// node's own fold. Every call reads fresh: nothing is cached across an
/// admission.
pub trait NodeAdmission: Send + Sync {
    /// The local controls now.
    fn controls(&self) -> NodeControls;

    /// Whether the node's own job grant, the issuer's job grant and the
    /// issuer's standing are live in the node's own fold now, and the issuer
    /// is one of the node's `issuers`.
    ///
    /// # Errors
    ///
    /// The refusal reason, for the key's end.
    fn issuer_live(&self, issuer: EntityId) -> Result<(), String>;

    /// Design 7.3 reserve step 5: the template exists and its digest equals
    /// the pin's; the entry, the scope, the network, the returnable outputs,
    /// the request's ceilings and the parameters fit the template.
    ///
    /// # Errors
    ///
    /// The refusal reason, for the key's end.
    fn admit_pin(&self, pin: &WorkloadPin) -> Result<(), String>;

    /// The template's digest now; `None` when the node holds no such
    /// template.
    fn template_digest(&self, template: &str) -> Option<String>;

    /// Design 7.3 reserve step 6: the payload disk's free space, less what
    /// live keys booked (`booked_mib`), covers `request_mib` plus the disk
    /// reserve, and `state_dir` keeps its own floor.
    ///
    /// # Errors
    ///
    /// The refusal reason, for the key's end.
    fn disk_room(&self, booked_mib: u64, request_mib: u64) -> Result<(), String>;

    /// Drains the node: new reserves are refused until a person clears it
    /// at the box (`oneiron execution-node resume`). Recovery calls it when
    /// a job unit runs that no key of the journal started.
    fn drain(&self, why: &str);

    /// The longest staging may take before the launch, in seconds (600).
    fn staging_limit_secs(&self) -> u64 {
        600
    }
}

/// The machine's GPUs, as the job service leases them. The server's
/// implementation is OPUS-LE-FLEET's GPU slot table.
pub trait NodeDevices: Send + Sync {
    /// Design 7.3 reserve step 7: a device that could take `request` exists
    /// now (offered, not withheld, not quarantined, enough memory). A look,
    /// not a hold.
    ///
    /// # Errors
    ///
    /// The refusal reason, for the key's end.
    fn could_take(&self, request: &GpuSlotRequest) -> Result<(), String>;

    /// Design 7.5 step 4: leases a device under `request.key` from a fresh
    /// reading, and confirms the launch at once: offered, not withheld, no
    /// compute process on it. A refusal holds nothing.
    ///
    /// # Errors
    ///
    /// [`GpuSlotRefusal`]: why no device was leased or confirmed.
    fn lease_for_launch(
        &self,
        request: &GpuSlotRequest,
    ) -> Result<Box<dyn GpuDeviceLease>, GpuSlotRefusal>;

    /// Design 7.7: after an engine restart, a launched key takes its device
    /// again under its key, before the gate opens.
    ///
    /// # Errors
    ///
    /// [`GpuSlotRefusal`]: the device could not be taken again.
    fn reattach(&self, key: &str, device_id: &str) -> Result<(), GpuSlotRefusal>;

    /// The compute processes on the key's device now, from a fresh reading.
    ///
    /// # Errors
    ///
    /// [`GpuSlotRefusal`] when the driver cannot be read: never an empty
    /// list.
    fn end_check(&self, key: &str) -> Result<GpuDeviceProcesses, GpuSlotRefusal>;

    /// Gives the key's device back and records how its job ended.
    fn finish(&self, key: &str, end: &GpuJobEnd);
}

/// Whether the node's own authority fold holds the position an issuer
/// signed a submit at (EM-11 = B: the submit carries the issuer's main-log
/// heads, and the node launches once its fold holds every one).
pub trait AuthorityPosition: Send + Sync {
    /// Whether the node's fold holds every one of `heads`.
    fn folded(&self, heads: &[String]) -> bool;
}

/// One key's staging order.
#[derive(Debug, Clone)]
pub struct StageOrder {
    pub key: String,
    pub id: JobKeyId,
    pub pin: WorkloadPin,
    /// The key's payload directory under `work_dir`.
    pub payload_dir: PathBuf,
}

/// Why staging did not complete.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum StageFailure {
    /// The key ends as `LaunchRefused { reason }` (e.g. `commit_missing`).
    #[error("job_stage.refused: {0}")]
    Refused(String),
    /// The key was closed while staging ran.
    #[error("job_stage.closed: the key was closed during staging")]
    Closed,
}

/// The node's staging (row R3c): the code from the template's mirror and the
/// contract check, into the key's payload directory. It runs outside the
/// admission lock, as the engine's account, and asks `closed` before each
/// step.
pub trait Stager: Send + Sync {
    /// Stages `order`.
    ///
    /// # Errors
    ///
    /// [`StageFailure`]: the key does not launch.
    fn stage(&self, order: &StageOrder, closed: &dyn Fn() -> bool) -> Result<(), StageFailure>;
}

/// The stager until row R3c lands: it stages nothing and refuses every
/// launch, so no workload runs without its code and contract checked.
#[derive(Debug, Clone, Copy, Default)]
pub struct StagingNotBuilt;

impl Stager for StagingNotBuilt {
    fn stage(&self, _order: &StageOrder, _closed: &dyn Fn() -> bool) -> Result<(), StageFailure> {
        Err(StageFailure::Refused("staging_not_built".to_owned()))
    }
}

/// Every part the job service takes.
#[derive(Clone)]
pub struct NodeJobParts {
    /// This node's MACHINE id: every receipt names it, and `signer` signs
    /// as it.
    pub machine: EntityId,
    pub admission: Arc<dyn NodeAdmission>,
    pub devices: Arc<dyn NodeDevices>,
    pub floor: Arc<dyn MachineFloor>,
    pub units: Arc<dyn JobUnit>,
    pub clock: Arc<dyn NodeClock>,
    pub signer: Arc<dyn MachineSignatures>,
    pub stager: Arc<dyn Stager>,
    pub authority: Arc<dyn AuthorityPosition>,
}

impl std::fmt::Debug for NodeJobParts {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("NodeJobParts")
            .finish_non_exhaustive()
    }
}

/// Where the node keeps its journal and its payloads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeJobPaths {
    /// The journal, the epoch and the control directories: the engine's
    /// account only.
    pub state_dir: PathBuf,
    /// The payload directories.
    pub work_dir: PathBuf,
}
