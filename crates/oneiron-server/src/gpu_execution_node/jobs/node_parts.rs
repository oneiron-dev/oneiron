//! What the node's job service takes from the rest of the server, each
//! behind one trait so the journal and the launch commit are tested with
//! scripted parts (design pass 33, section 11: R3a runs against a scripted
//! unit manager and needs no privilege):
//! - [`NodeAdmission`]: the node's own configuration and controls, read
//!   fresh at each use (row R1's [`ExecutionNode`]: `[execution_node]`, its
//!   template check and its fold reads);
//! - [`NodeDevices`]: the machine's GPU slot table (OPUS-LE-FLEET's
//!   [`GpuSlotTable`]), whose drain is the node's drain;
//! - [`oneiron_organ_host::MachineFloor`]: the machine's memory line, the
//!   floor a launched job's memory is taken from;
//! - [`AuthorityPosition`]: whether the node's own authority fold holds the
//!   position the issuer signed the submit at (EM-11 = B);
//! - [`Stager`]: the checkout and the contract check (row R3c);
//! - [`oneiron::machine_signature::MachineSignatures`]: the one machine-key
//!   signing path, for the receipt and the submit check;
//! - [`super::job_unit::JobUnit`] and [`super::job_unit::NodeClock`].
//!
//! The server's parts implement these traits here, each method a call of
//! the same name: [`ExecutionNode`] is the [`NodeAdmission`] and the
//! [`AuthorityPosition`], [`GpuSlotTable`] the [`NodeDevices`], and
//! [`super::NodeJobs`] is R1's [`NodeKeys`].

use std::path::PathBuf;
use std::sync::Arc;

use oneiron::EntityId;
use oneiron::machine_signature::MachineSignatures;
use oneiron_organ_host::MachineFloor;

pub use oneiron_organ_host::{
    GpuDeviceLease, GpuDeviceProcesses, GpuLeaseEnd, GpuSlotRefusal, GpuSlotRequest,
};

use super::job_unit::{JobKeyId, JobUnit, NodeClock};
pub use crate::gpu_execution_node::node::NodeControls;
use crate::gpu_execution_node::node::{AuthorityEnded, ExecutionNode, NodeKeys};
use crate::gpu_execution_node::slots::GpuSlotTable;
use crate::gpu_execution_node::wire::{
    FETCH_MAX_BYTES, JobAnswer, JobRefusal, JobReserve, JobStatusAnswer, SignedJobSubmit,
    WorkloadPin,
};

/// The `jobs.*` settings this service reads (pass 34, section 6), each with
/// the engine's default. Policy is a setting, never a constant in this code
/// (lead 25 Nov 00:04). Until row P0 a node obeys its box file only (EM-17 =
/// A): R1's `[execution_node]` file sets `staging_limit_secs`, and every
/// other key takes its default. Read once per use, through
/// [`NodeAdmission::job_settings`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeJobSettings {
    /// `jobs.submit.skew_secs`: how far before its `issued_at_ms` a reserve
    /// may arrive, as two machines' clocks differ. Default 120.
    pub submit_skew_secs: u64,
    /// `jobs.staging.limit_secs`: the longest staging may take before the
    /// launch commit. Default 600.
    pub staging_limit_secs: u64,
    /// `jobs.outputs.hash_limit_secs`: the longest the hashing of one key's
    /// outputs takes in all. Default 60.
    pub output_hash_limit_secs: u64,
    /// `jobs.outputs.returnable_max_bytes`: the most bytes an output may
    /// hold and still travel to the issuer. Default, and ceiling, one
    /// message piece ([`FETCH_MAX_BYTES`], 1,044,480): a wire bound.
    pub returnable_max_bytes: u64,
    /// `jobs.drain.fast_exit_secs`: an end this soon after the launch counts
    /// against the machine's drain guard. Default 5.
    pub fast_exit_secs: u64,
    /// `jobs.receipts.keep_days`: how long an acknowledged key's payload
    /// stays on the node before the cleaning removes it (design 7.6 step 5).
    /// Default 30, longer than an allocation period.
    pub receipt_keep_days: u64,
}

impl Default for NodeJobSettings {
    fn default() -> Self {
        Self {
            submit_skew_secs: 120,
            staging_limit_secs: 600,
            output_hash_limit_secs: 60,
            returnable_max_bytes: FETCH_MAX_BYTES,
            fast_exit_secs: 5,
            receipt_keep_days: 30,
        }
    }
}

impl NodeJobSettings {
    /// The returnable bound in force: the setting, never above one message
    /// piece.
    #[must_use]
    pub fn returnable_bound(&self) -> u64 {
        self.returnable_max_bytes.min(FETCH_MAX_BYTES)
    }
}

/// Why the node's own fold does not authorise an issuer's work now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssuerNotLive {
    /// What a reserve or a submit is answered with. Nothing is journaled
    /// for it, as the gate journals nothing.
    pub refusal: JobRefusal,
    /// The reason a key that reached the launch commit ends with.
    pub reason: String,
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
    /// [`IssuerNotLive`]: the refusal and the reason.
    fn issuer_live(&self, issuer: EntityId) -> Result<(), IssuerNotLive>;

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

    /// The node's `jobs.*` settings now.
    fn job_settings(&self) -> NodeJobSettings;

    /// The operating-system signal the template delivers as a checkpoint
    /// notice (design 7.1 `Signal`); `None`, the default: the notice is a
    /// no-op for this template.
    fn template_signal(&self, template: &str) -> Option<String> {
        let _ = template;
        None
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
    fn finish(&self, key: &str, end: &GpuLeaseEnd);

    /// Drains the machine: it takes no new GPU job until a person clears it
    /// at the box (`oneiron execution-node resume`). One drain per machine:
    /// the slot table's. Recovery calls it when a job unit runs that no key
    /// of the journal started.
    fn drain(&self, why: &str);
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

impl NodeAdmission for ExecutionNode {
    fn controls(&self) -> NodeControls {
        ExecutionNode::controls(self)
    }

    fn issuer_live(&self, issuer: EntityId) -> Result<(), IssuerNotLive> {
        ExecutionNode::issuer_live(self, issuer).map_err(|reason| {
            let refusal = match self.authority_for(issuer) {
                Err(AuthorityEnded::OwnGrant) => JobRefusal::OwnGrantEnded,
                Err(AuthorityEnded::IssuerStanding { .. }) => JobRefusal::IssuerStandingEnded,
                Ok(()) => JobRefusal::NotIssuer,
            };
            IssuerNotLive { refusal, reason }
        })
    }

    fn admit_pin(&self, pin: &WorkloadPin) -> Result<(), String> {
        ExecutionNode::admit_pin(self, pin)
    }

    fn template_digest(&self, template: &str) -> Option<String> {
        ExecutionNode::template_digest(self, template)
    }

    fn disk_room(&self, booked_mib: u64, request_mib: u64) -> Result<(), String> {
        ExecutionNode::disk_room(self, booked_mib, request_mib)
    }

    fn job_settings(&self) -> NodeJobSettings {
        NodeJobSettings {
            staging_limit_secs: ExecutionNode::staging_limit_secs(self),
            receipt_keep_days: ExecutionNode::receipt_keep_days(self),
            ..NodeJobSettings::default()
        }
    }

    fn template_signal(&self, template: &str) -> Option<String> {
        ExecutionNode::template_signal(self, template)
    }
}

impl AuthorityPosition for ExecutionNode {
    fn folded(&self, heads: &[String]) -> bool {
        ExecutionNode::folded(self, heads)
    }
}

impl NodeDevices for GpuSlotTable {
    fn could_take(&self, request: &GpuSlotRequest) -> Result<(), String> {
        use crate::gpu_execution_node::availability::GpuDeviceState;
        let availability = self
            .availability(oneiron_base::unix_millis_now())
            .map_err(|error| format!("devices_unreadable: {error}"))?;
        if let Some(why) = &availability.paused {
            return Err(format!("node_paused: {why}"));
        }
        if let Some(why) = &availability.drained {
            return Err(format!("node_drained: {why}"));
        }
        let open = availability.devices.iter().any(|device| {
            request.admits(&device.device)
                && !matches!(
                    device.state,
                    GpuDeviceState::NotOffered
                        | GpuDeviceState::Withheld
                        | GpuDeviceState::Quarantined { .. }
                )
        });
        if open {
            Ok(())
        } else {
            Err("no_device".to_owned())
        }
    }

    fn lease_for_launch(
        &self,
        request: &GpuSlotRequest,
    ) -> Result<Box<dyn GpuDeviceLease>, GpuSlotRefusal> {
        let mut lease = self.lease(request, oneiron_base::unix_millis_now())?;
        // A refused confirmation drops the lease: the GPU goes back.
        lease.confirm_launch()?;
        Ok(Box::new(lease))
    }

    fn reattach(&self, key: &str, device_id: &str) -> Result<(), GpuSlotRefusal> {
        GpuSlotTable::reattach(self, key, device_id, oneiron_base::unix_millis_now()).map(drop)
    }

    fn end_check(&self, key: &str) -> Result<GpuDeviceProcesses, GpuSlotRefusal> {
        GpuSlotTable::end_check(self, key)
    }

    fn finish(&self, key: &str, end: &GpuLeaseEnd) {
        GpuSlotTable::finish(self, key, end);
    }

    fn drain(&self, why: &str) {
        GpuSlotTable::drain(self, why.to_owned());
    }
}

impl NodeKeys for super::NodeJobs {
    fn reserve(&self, peer: EntityId, reserve: JobReserve) -> JobAnswer {
        super::NodeJobs::reserve(self, peer, reserve)
    }

    fn release(&self, peer: EntityId, key: &str) -> JobAnswer {
        super::NodeJobs::release(self, peer, key)
    }

    fn submit(&self, peer: EntityId, signed: SignedJobSubmit) -> JobAnswer {
        super::NodeJobs::submit(self, peer, signed)
    }

    fn swept(&self) -> bool {
        super::NodeJobs::swept(self)
    }

    fn epoch(&self) -> Option<String> {
        super::NodeJobs::epoch(self).map(|epoch| epoch.to_hex())
    }

    fn booked_disk_mib(&self) -> u64 {
        super::NodeJobs::booked_disk_mib(self)
    }

    fn revoke_live_keys(&self, issuer: Option<EntityId>, why: &str) {
        super::NodeJobs::revoke_live_keys(self, issuer, why);
    }

    fn stop_live_keys(&self) {
        super::NodeJobs::stop_live_keys(self);
    }

    fn find(&self, peer: EntityId, key: &str) -> JobStatusAnswer {
        super::NodeJobs::find(self, peer, key)
    }

    fn stop(&self, peer: EntityId, key: &str) -> JobStatusAnswer {
        super::NodeJobs::stop(self, peer, key)
    }

    fn keys_page(&self, peer: EntityId, after: Option<&str>) -> JobStatusAnswer {
        super::NodeJobs::keys_page(self, peer, after)
    }

    fn signal(&self, peer: EntityId, key: &str, signal: &str) -> JobStatusAnswer {
        super::NodeJobs::signal(self, peer, key, signal)
    }

    fn fetch(&self, peer: EntityId, key: &str, name: &str) -> JobStatusAnswer {
        super::NodeJobs::fetch(self, peer, key, name)
    }

    fn acknowledge(&self, peer: EntityId, key: &str) -> JobStatusAnswer {
        super::NodeJobs::acknowledge(self, peer, key)
    }
}
