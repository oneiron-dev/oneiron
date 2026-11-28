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
//! [`NodeJobsAttachment`] is R1's [`NodeKeys`]: a weak handle, since the
//! service holds the node.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Weak};

use oneiron::EntityId;
use oneiron::job_workload::{BoundRequirement, DevicePlacement, HeldDevice};
use oneiron::machine_signature::MachineSignatures;
use oneiron_organ_host::MachineFloor;

pub use oneiron_organ_host::{
    GpuDeviceLease, GpuDeviceProcesses, GpuLeaseEnd, GpuSlotRefusal, GpuSlotRequest,
};

use super::job_unit::{JobKeyId, JobUnit, NodeClock};
use crate::gpu_execution_node::device::DeviceSample;
pub use crate::gpu_execution_node::node::NodeControls;
use crate::gpu_execution_node::node::{AuthorityEnded, ExecutionNode, NodeKeys};
use crate::gpu_execution_node::node_settings::{
    DrainClearBy, ExecutionNodeSettings, NodeCacheSettings, READINESS_EVERY_SECS_DEFAULT,
};
use crate::gpu_execution_node::slots::GpuSlotTable;
use crate::gpu_execution_node::wire::{
    FETCH_MAX_BYTES, JobAnswer, JobRefusal, JobReserve, JobStatusAnswer, LogTailRequest,
    NodeReadiness, ScopeReport, SignedJobSubmit, WarmKeyFact, WarmWanted, WorkloadPin,
};

/// The `jobs.*` settings this service reads (pass 34, section 6), each with
/// the engine's default. Policy is a setting, never a constant in this code
/// (lead 25 Nov 00:04). R1's `[execution_node]` file sets
/// `staging_limit_secs`, `receipt_keep_days`, `readiness_every_secs` and
/// `drain_clear_by`; the owner's machine policy rows (row P0) may shorten
/// the readiness period and keep the drain for the box, the stricter of the
/// two applying; every other key takes its default. Read once per use,
/// through [`NodeAdmission::job_settings`].
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
    /// `jobs.readiness.every_secs`: how often the node checks itself while
    /// no attempt runs (pass 34, 7.3), the shorter of the box's and the
    /// owner's. Default 900.
    pub readiness_every_secs: u64,
    /// `jobs.readiness.results_kept`: how many check results `Node`
    /// reports. Default 5.
    pub readiness_results_kept: u64,
    /// `machines.drain.clear_by`: who clears the node's drain (pass 34,
    /// 2.4), the stricter of the box's and the owner's. Default: the
    /// machine, once its readiness check passes.
    pub drain_clear_by: DrainClearBy,
    /// `jobs.incidents.keep`: how many incident records the node keeps.
    /// Default 200.
    pub incidents_keep: u64,
    /// `jobs.breadcrumbs.keep`: how many breadcrumb lines a running key
    /// keeps, which a `Lost` receipt carries. Default 20.
    pub breadcrumbs_keep: u64,
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
            readiness_every_secs: READINESS_EVERY_SECS_DEFAULT,
            readiness_results_kept: 5,
            drain_clear_by: DrainClearBy::AfterReadinessCheck,
            incidents_keep: 200,
            breadcrumbs_keep: 20,
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

    /// The local controls and the owner's machine policy now, from one read,
    /// for one readiness tick (row READINESS-NOT-RUN-AT-OFFER). The default
    /// reads the controls alone, with no file and no policy.
    fn readiness_snapshot(&self) -> crate::gpu_execution_node::node::NodeSnapshot {
        crate::gpu_execution_node::node::NodeSnapshot {
            settings: Ok(None),
            controls: self.controls(),
            policy: None,
        }
    }

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

    /// The scope bounds the template requires now (its `require`, pass 34
    /// section 2.2); `None` when the node holds no such template.
    fn template_requires(&self, template: &str) -> Option<Vec<BoundRequirement>>;

    /// The launch commit's fit of the pin's placement on this node (pass 34
    /// section 2.1, the sum rule): the host memory the placement leases is
    /// within the template's memory ceiling; and, with the box file and the
    /// owner's machine policy (row P0), every placed device is offered, the
    /// memory with `held_mib` that launched keys hold fits the memory work
    /// may hold, and the run's threads fit.
    ///
    /// # Errors
    ///
    /// The refusal reason, for the key's end.
    fn admit_placement(
        &self,
        pin: &WorkloadPin,
        placement: &DevicePlacement,
        held_mib: u64,
    ) -> Result<(), String>;

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

    /// Each template's host-local mirror, by template name: what the
    /// readiness check reads (pass 34, 7.3). The default names none.
    fn template_mirrors(&self) -> Vec<(String, PathBuf)> {
        Vec::new()
    }

    /// A session template's longest run from its launch, in seconds (pass
    /// 34, 2.5; row W1): only a run of such a template takes a renewal.
    /// `None` for a job template or a template the node does not hold, and
    /// by default.
    fn template_session_max_secs(&self, template: &str) -> Option<u64> {
        let _ = template;
        None
    }

    /// The template's job cache, when the node's file lets runs write one
    /// and the template names one (FLEET-TOOL-PARITY row 5); `None`: a run
    /// of it gets no cache.
    fn template_job_cache(
        &self,
        template: &str,
    ) -> Option<crate::gpu_execution_node::node_settings::JobCacheTarget> {
        let _ = template;
        None
    }

    /// The job unit's stop grace, in seconds: the cutoff stops a unit this
    /// long before its cutoff time, so a renewal must come before then.
    fn stop_grace_secs(&self) -> u64 {
        crate::gpu_execution_node::node_settings::STOP_GRACE_SECS_DEFAULT
    }
}

/// The machine's devices, as the job service places and leases them. The
/// server's implementation is OPUS-LE-FLEET's GPU slot table.
pub trait NodeDevices: Send + Sync {
    /// Every device of the machine now, from a fresh reading, with the
    /// sharing of each claim that holds it: what
    /// `ResourceRequest::place_devices` reads (pass 34, 2.1). A look, not a
    /// hold.
    ///
    /// # Errors
    ///
    /// The refusal reason, for the key's end: the devices cannot be read,
    /// or the table is paused or drained.
    fn devices(&self) -> Result<Vec<HeldDevice>, String>;

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

    /// Puts the device out of every reserve and launch until
    /// [`NodeDevices::clear_quarantine`]: the journal's quarantine of a
    /// key's device, as it is written and as recovery replays it (design
    /// 7.6). The slot table keeps it in memory only.
    fn quarantine(&self, device_id: &str, why: &str);

    /// Ends the device's quarantine, at its key's clean release.
    fn clear_quarantine(&self, device_id: &str);

    /// Drains the machine: it takes no new GPU job until its drain is
    /// cleared, by a passed readiness check or at the box (`oneiron
    /// execution-node resume`), as `machines.drain.clear_by` says. One drain
    /// per machine: the slot table's. Recovery calls it when a job unit runs
    /// that no key of the journal started; a failed readiness check calls
    /// it too.
    fn drain(&self, why: &str);

    /// Clears the machine's drain: the DRAIN rule's clear after a passed
    /// readiness check (pass 34, 7.3).
    ///
    /// # Errors
    ///
    /// Why the drain still stands.
    fn clear_drain(&self) -> Result<(), String>;

    /// The readiness check's device probe: a fresh reading of every device
    /// answers, whether the machine is paused or drained (a look, not a
    /// hold).
    ///
    /// # Errors
    ///
    /// Why the devices cannot be read.
    fn probe(&self) -> Result<(), String>;

    /// The readiness check's device probe on the withheld list it was given:
    /// a fresh reading of every device answers, whether the machine is
    /// paused or drained (a look, not a hold). The default judges the
    /// devices as [`NodeDevices::probe`] does and ignores the list.
    ///
    /// # Errors
    ///
    /// Why the devices cannot be read, or why the given list did not read.
    fn probe_with_withheld(
        &self,
        withheld: Result<BTreeSet<String>, String>,
    ) -> Result<(), String> {
        let _ = withheld;
        self.probe()
    }

    /// The devices another booker withholds now, read without probing the
    /// driver. The default withholds none.
    ///
    /// # Errors
    ///
    /// Why the withheld list could not be read.
    fn booker_withheld(&self) -> Result<BTreeSet<String>, String> {
        Ok(BTreeSet::new())
    }

    /// The temperature, power draw and memory in use of each of
    /// `device_ids` now, where the probe gives them, for a breadcrumb line.
    /// The default samples nothing.
    fn samples(&self, device_ids: &[String]) -> Vec<DeviceSample> {
        let _ = device_ids;
        Vec::new()
    }
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
    /// The warm keys the signed submit lists (pass 34, row P2).
    pub warm: Vec<String>,
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

    /// Removes what [`Stager::stage`] left in `payload_dir` for `key` when
    /// the key does not launch after it (a stop, the staging limit, a stale
    /// authority, a launch refusal, or a restart that ended the key), and at
    /// the release check of a key that launched. The recovery at each start
    /// calls it again for every key that ended before its launch, so it
    /// makes nothing and may find nothing to remove. The default has nothing
    /// to remove.
    fn unstage(&self, _key: &str, _payload_dir: &Path) {}
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

    fn readiness_snapshot(&self) -> crate::gpu_execution_node::node::NodeSnapshot {
        ExecutionNode::snapshot(self)
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

    fn template_requires(&self, template: &str) -> Option<Vec<BoundRequirement>> {
        let settings = ExecutionNode::settings(self).ok().flatten()?;
        settings
            .templates
            .get(template)
            .map(|held| held.require.clone())
    }

    fn admit_placement(
        &self,
        pin: &WorkloadPin,
        placement: &DevicePlacement,
        held_mib: u64,
    ) -> Result<(), String> {
        ExecutionNode::admit_placement(self, pin, placement, held_mib)
    }

    fn disk_room(&self, booked_mib: u64, request_mib: u64) -> Result<(), String> {
        ExecutionNode::disk_room(self, booked_mib, request_mib)
    }

    fn job_settings(&self) -> NodeJobSettings {
        // One read of the box file for every key; with none, or one that
        // does not parse, each key keeps its default.
        let file = ExecutionNode::settings(self).ok().flatten();
        let defaults = NodeJobSettings::default();
        let (readiness_every_secs, drain_clear_by) = file.as_ref().map_or(
            (defaults.readiness_every_secs, defaults.drain_clear_by),
            |file| ExecutionNode::readiness_settings(self, file),
        );
        NodeJobSettings {
            staging_limit_secs: file
                .as_ref()
                .map_or(defaults.staging_limit_secs, |file| file.staging_limit_secs),
            receipt_keep_days: file.as_ref().map_or(defaults.receipt_keep_days, |file| {
                u64::from(file.receipt_keep_days)
            }),
            readiness_every_secs,
            drain_clear_by,
            ..defaults
        }
    }

    fn template_signal(&self, template: &str) -> Option<String> {
        ExecutionNode::template_signal(self, template)
    }

    fn template_session_max_secs(&self, template: &str) -> Option<u64> {
        let settings = ExecutionNode::settings(self).ok().flatten()?;
        settings
            .templates
            .get(template)
            .and_then(crate::gpu_execution_node::node_settings::NodeTemplate::session_max_secs)
    }

    fn template_job_cache(
        &self,
        template: &str,
    ) -> Option<crate::gpu_execution_node::node_settings::JobCacheTarget> {
        ExecutionNode::settings(self)
            .ok()
            .flatten()?
            .job_cache_target(template)
    }

    fn stop_grace_secs(&self) -> u64 {
        ExecutionNode::settings(self).ok().flatten().map_or(
            crate::gpu_execution_node::node_settings::STOP_GRACE_SECS_DEFAULT,
            |settings| settings.stop_grace_secs,
        )
    }

    fn template_mirrors(&self) -> Vec<(String, PathBuf)> {
        ExecutionNode::settings(self)
            .ok()
            .flatten()
            .map(|settings| {
                settings
                    .templates
                    .into_iter()
                    .map(|(name, template)| (name, template.repo))
                    .collect()
            })
            .unwrap_or_default()
    }
}

impl AuthorityPosition for ExecutionNode {
    fn folded(&self, heads: &[String]) -> bool {
        ExecutionNode::folded(self, heads)
    }
}

impl NodeDevices for GpuSlotTable {
    fn devices(&self) -> Result<Vec<HeldDevice>, String> {
        self.held_devices(oneiron_base::unix_millis_now())
            .map_err(|refusal| match refusal {
                GpuSlotRefusal::Paused { reason } => format!("node_paused: {reason}"),
                GpuSlotRefusal::Drained { reason } => format!("node_drained: {reason}"),
                GpuSlotRefusal::Unmeasured { reason } => format!("devices_unreadable: {reason}"),
                other => format!("devices_unreadable: {other}"),
            })
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
        GpuSlotTable::reattach(self, key, device_id, 0, oneiron_base::unix_millis_now()).map(drop)
    }

    fn end_check(&self, key: &str) -> Result<GpuDeviceProcesses, GpuSlotRefusal> {
        GpuSlotTable::end_check(self, key)
    }

    fn finish(&self, key: &str, end: &GpuLeaseEnd) {
        GpuSlotTable::finish(self, key, end);
    }

    fn quarantine(&self, device_id: &str, why: &str) {
        GpuSlotTable::quarantine(self, device_id, why.to_owned());
    }

    fn clear_quarantine(&self, device_id: &str) {
        GpuSlotTable::clear_quarantine(self, device_id);
    }

    fn drain(&self, why: &str) {
        GpuSlotTable::drain(self, why.to_owned());
    }

    fn clear_drain(&self) -> Result<(), String> {
        GpuSlotTable::clear_drain(self).map_err(|error| format!("drain_not_cleared: {error}"))
    }

    fn probe(&self) -> Result<(), String> {
        self.availability(oneiron_base::unix_millis_now())
            .map(drop)
            .map_err(|error| format!("devices_unreadable: {error}"))
    }

    fn probe_with_withheld(
        &self,
        withheld: Result<BTreeSet<String>, String>,
    ) -> Result<(), String> {
        match withheld {
            Ok(withheld) => self
                .availability_with_withheld(oneiron_base::unix_millis_now(), withheld)
                .map(drop)
                .map_err(|error| format!("devices_unreadable: {error}")),
            Err(why) => Err(format!("devices_unreadable: {why}")),
        }
    }

    fn booker_withheld(&self) -> Result<BTreeSet<String>, String> {
        GpuSlotTable::booker_withheld(self).map_err(|error| error.to_string())
    }

    fn samples(&self, device_ids: &[String]) -> Vec<DeviceSample> {
        match GpuSlotTable::samples(self) {
            Ok(samples) => samples
                .into_iter()
                .filter(|sample| device_ids.contains(&sample.device_id))
                .collect(),
            Err(error) => {
                tracing::debug!(%error, "device samples not read; the breadcrumb line carries none");
                Vec::new()
            }
        }
    }
}

/// The job service as R1's node holds it ([`ExecutionNode::attach_keys`]):
/// a weak handle. The service holds the node as its admission and its
/// authority, so a strong handle back would keep both alive, and the
/// journal's writer lock with them, after the server dropped the service.
/// The server keeps the strong [`super::NodeJobs`]; once it is gone, every
/// request answers `NotEnabled`, as a node with no keys attached does, and
/// the journal's directory can be opened again.
#[derive(Debug, Clone)]
pub struct NodeJobsAttachment {
    service: Weak<super::NodeJobsShared>,
}

impl NodeJobsAttachment {
    /// The service while it lives and the server serves it: a closed
    /// service that a staging worker still holds answers as no service.
    fn service(&self) -> Option<super::NodeJobs> {
        self.service
            .upgrade()
            .map(|shared| super::NodeJobs { shared })
            .filter(|jobs| !jobs.service_closed())
    }
}

impl super::NodeJobs {
    /// The handle to attach to R1's node: it answers for this service while
    /// the service lives and is not closed, and never keeps it alive.
    #[must_use]
    pub fn attachment(&self) -> Arc<dyn NodeKeys> {
        Arc::new(NodeJobsAttachment {
            service: Arc::downgrade(&self.shared),
        })
    }
}

fn not_enabled() -> JobAnswer {
    JobAnswer::Refused(JobRefusal::NotEnabled)
}

fn status_not_enabled() -> JobStatusAnswer {
    JobStatusAnswer::Refused(JobRefusal::NotEnabled)
}

impl NodeKeys for NodeJobsAttachment {
    fn reserve(&self, peer: EntityId, reserve: JobReserve) -> JobAnswer {
        self.service()
            .map_or_else(not_enabled, |jobs| jobs.reserve(peer, reserve))
    }

    fn release(&self, peer: EntityId, key: &str) -> JobAnswer {
        self.service()
            .map_or_else(not_enabled, |jobs| jobs.release(peer, key))
    }

    fn submit(&self, peer: EntityId, signed: SignedJobSubmit) -> JobAnswer {
        self.service()
            .map_or_else(not_enabled, |jobs| jobs.submit(peer, signed))
    }

    fn swept(&self) -> bool {
        self.service().is_some_and(|jobs| jobs.swept())
    }

    fn epoch(&self) -> Option<String> {
        self.service()
            .and_then(|jobs| jobs.epoch())
            .map(|epoch| epoch.to_hex())
    }

    fn booked_disk_mib(&self) -> u64 {
        self.service().map_or(0, |jobs| jobs.booked_disk_mib())
    }

    fn live_issuers(&self) -> BTreeSet<EntityId> {
        self.service()
            .map(|jobs| jobs.live_issuers())
            .unwrap_or_default()
    }

    fn revoke_live_keys(&self, issuer: Option<EntityId>, why: &str) {
        if let Some(jobs) = self.service() {
            jobs.revoke_live_keys(issuer, why);
        }
    }

    fn stop_live_keys(&self) {
        if let Some(jobs) = self.service() {
            jobs.stop_live_keys();
        }
    }

    fn scopes(&self) -> Vec<ScopeReport> {
        self.service().map(|jobs| jobs.scopes()).unwrap_or_default()
    }

    fn find(&self, peer: EntityId, key: &str) -> JobStatusAnswer {
        self.service()
            .map_or_else(status_not_enabled, |jobs| jobs.find(peer, key))
    }

    fn stop(&self, peer: EntityId, key: &str) -> JobStatusAnswer {
        self.service()
            .map_or_else(status_not_enabled, |jobs| jobs.stop(peer, key))
    }

    fn keys_page(&self, peer: EntityId, after: Option<&str>) -> JobStatusAnswer {
        self.service()
            .map_or_else(status_not_enabled, |jobs| jobs.keys_page(peer, after))
    }

    fn signal(&self, peer: EntityId, key: &str, signal: &str) -> JobStatusAnswer {
        self.service()
            .map_or_else(status_not_enabled, |jobs| jobs.signal(peer, key, signal))
    }

    fn fetch(&self, peer: EntityId, key: &str, name: &str) -> JobStatusAnswer {
        self.service()
            .map_or_else(status_not_enabled, |jobs| jobs.fetch(peer, key, name))
    }

    fn acknowledge(&self, peer: EntityId, key: &str) -> JobStatusAnswer {
        self.service()
            .map_or_else(status_not_enabled, |jobs| jobs.acknowledge(peer, key))
    }

    fn warm_wanted(&self, peer: EntityId, wanted: &WarmWanted) {
        if let Some(jobs) = self.service() {
            jobs.warm_wanted(peer, wanted);
        }
    }

    fn warm_facts(
        &self,
        settings: &ExecutionNodeSettings,
        cache: &NodeCacheSettings,
    ) -> Vec<WarmKeyFact> {
        self.service()
            .map(|jobs| jobs.warm_facts(settings, cache))
            .unwrap_or_default()
    }

    fn cache_pass_if_due(
        &self,
        settings: &ExecutionNodeSettings,
        cache: &NodeCacheSettings,
        settings_now: super::warm::SettingsRead,
    ) {
        if let Some(jobs) = self.service() {
            jobs.cache_pass_if_due(settings, cache, settings_now);
        }
    }

    fn tail(&self, peer: EntityId, request: &LogTailRequest) -> JobStatusAnswer {
        self.service()
            .map_or_else(status_not_enabled, |jobs| jobs.tail(peer, request))
    }

    fn readiness(&self) -> Option<NodeReadiness> {
        self.service().map(|jobs| jobs.readiness())
    }
}

impl super::NodeJobs {
    /// The launch scope this service's job unit starts runs in, with what
    /// it can enforce now, as its probe reads it: `Node`'s `scopes`.
    #[must_use]
    pub fn scopes(&self) -> Vec<ScopeReport> {
        let units = &self.parts().units;
        vec![ScopeReport {
            class: units.class(),
            capabilities: units.probe(),
        }]
    }
}
