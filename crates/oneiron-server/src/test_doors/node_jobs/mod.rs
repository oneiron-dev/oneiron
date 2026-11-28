//! Scripted parts for the node's job service (pass 33, `33-exec-node/DESIGN.md`
//! section 11: the journal's tests run against a scripted unit manager and
//! need no privilege). A test builds a [`ScriptedNode`] on a temporary
//! directory, opens [`NodeJobs`] on it, and steps the node with
//! [`NodeJobs::tick`]. Opening a second [`NodeJobs`] on the same parts is an
//! engine restart; [`ScriptedNodeClock::reboot`] is a host reset.
//!
//! - [`ScriptedJobUnits`]: the service manager. A started unit runs until the
//!   test ends it; the end step writes `ended.json` as root would.
//! - [`ScriptedDevices`]: the GPU slot table, with a device probe the test
//!   can fail and compute processes it can place on a device.
//! - [`ScriptedAdmission`], [`ScriptedFloor`], [`ScriptedSigner`],
//!   [`ScriptedAuthority`], [`ScriptedStager`].

mod devices;
mod parts;
mod units;

use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use oneiron::EntityId;

use crate::gpu_execution_node::jobs::{NodeClock, NodeJobParts, NodeJobPaths, NodeJobs};
pub use crate::gpu_execution_node::wire::CheckpointRecord;
pub use devices::ScriptedDevices;
pub use parts::{
    ScriptedAdmission, ScriptedAuthority, ScriptedFloor, ScriptedSigner, ScriptedStager,
};
pub use units::{ScriptedJobUnits, ScriptedStart};

fn locked<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The node's boot and clocks, as a test sets them.
#[derive(Debug)]
pub struct ScriptedNodeClock {
    boot_id: Mutex<String>,
    boot_ns: AtomicU64,
    wall_ms: AtomicU64,
}

impl ScriptedNodeClock {
    /// A clock in boot `boot-1`, ten seconds after the boot, at
    /// `wall_ms`.
    #[must_use]
    pub fn new(wall_ms: u64) -> Arc<Self> {
        Arc::new(Self {
            boot_id: Mutex::new("boot-1".to_owned()),
            boot_ns: AtomicU64::new(10_000_000_000),
            wall_ms: AtomicU64::new(wall_ms),
        })
    }

    /// Moves both clocks on by `millis`.
    pub fn advance_ms(&self, millis: u64) {
        self.boot_ns
            .fetch_add(millis.saturating_mul(1_000_000), Ordering::SeqCst);
        self.wall_ms.fetch_add(millis, Ordering::SeqCst);
    }

    /// A step of the wall clock alone, by `millis` forward: a clock set
    /// by hand or by a time server, as the readiness check sees it.
    pub fn step_wall_ms(&self, millis: u64) {
        self.wall_ms.fetch_add(millis, Ordering::SeqCst);
    }

    /// A host reset: a new boot id, the boot clock starts again.
    pub fn reboot(&self, boot_id: &str) {
        *locked(&self.boot_id) = boot_id.to_owned();
        self.boot_ns.store(5_000_000_000, Ordering::SeqCst);
        self.wall_ms.fetch_add(60_000, Ordering::SeqCst);
    }
}

impl NodeClock for ScriptedNodeClock {
    fn boot_id(&self) -> String {
        locked(&self.boot_id).clone()
    }

    fn boot_ns(&self) -> u64 {
        self.boot_ns.load(Ordering::SeqCst)
    }

    fn wall_ms(&self) -> u64 {
        self.wall_ms.load(Ordering::SeqCst)
    }
}

/// Every scripted part of one node, on one directory.
#[derive(Debug, Clone)]
pub struct ScriptedNode {
    pub paths: NodeJobPaths,
    pub clock: Arc<ScriptedNodeClock>,
    pub units: Arc<ScriptedJobUnits>,
    pub devices: Arc<ScriptedDevices>,
    pub admission: Arc<ScriptedAdmission>,
    pub floor: Arc<ScriptedFloor>,
    pub signer: Arc<ScriptedSigner>,
    pub authority: Arc<ScriptedAuthority>,
    pub stager: Arc<ScriptedStager>,
}

impl ScriptedNode {
    /// A node `machine` on `root` (its `state` and `work` directories), one
    /// 24 GiB device `GPU-scripted-0`, 26 GiB of job memory, and `template`
    /// at `digest`.
    #[must_use]
    pub fn new(root: &Path, machine: EntityId, template: &str, digest: &str, wall_ms: u64) -> Self {
        let paths = NodeJobPaths {
            state_dir: root.join("state"),
            work_dir: root.join("work"),
        };
        let clock = ScriptedNodeClock::new(wall_ms);
        let devices = ScriptedDevices::one("GPU-scripted-0", 24 * 1024);
        Self {
            units: ScriptedJobUnits::new(&paths.state_dir, Arc::clone(&clock)),
            paths,
            clock,
            admission: ScriptedAdmission::new(template, digest, Arc::clone(&devices)),
            devices,
            floor: ScriptedFloor::new(26 * 1024),
            signer: ScriptedSigner::new(machine),
            authority: ScriptedAuthority::new(),
            stager: ScriptedStager::new(),
        }
    }

    /// The parts, as [`NodeJobs::open`] takes them.
    #[must_use]
    pub fn parts(&self) -> NodeJobParts {
        NodeJobParts {
            machine: self.signer.machine(),
            admission: self.admission.clone(),
            devices: self.devices.clone(),
            floor: self.floor.clone(),
            units: self.units.clone(),
            clock: self.clock.clone(),
            signer: self.signer.clone(),
            stager: self.stager.clone(),
            authority: self.authority.clone(),
        }
    }

    /// Opens the node's job service: its first start, or an engine restart.
    /// A restart waits, up to 10 s, until every handle of the service before
    /// it is gone (its staging workers' too) and the journal's writer lock
    /// is free.
    ///
    /// # Panics
    ///
    /// The service did not open.
    #[must_use]
    pub fn open(&self) -> NodeJobs {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        loop {
            match self.try_open() {
                Ok(jobs) => return jobs,
                Err(error)
                    if error.kind() == std::io::ErrorKind::WouldBlock
                        && std::time::Instant::now() < deadline =>
                {
                    std::thread::sleep(std::time::Duration::from_millis(10));
                }
                Err(error) => panic!("the node's job service did not open: {error}"),
            }
        }
    }

    /// Opens the node's job service once, never waiting.
    ///
    /// # Errors
    ///
    /// As [`NodeJobs::open`].
    pub fn try_open(&self) -> std::io::Result<NodeJobs> {
        NodeJobs::open(self.paths.clone(), self.parts())
    }
}

/// Sets the hook that fails the journal's next appends between their write
/// and their sync (`None` clears it).
pub fn fail_journal_sync(jobs: &NodeJobs, failing: bool) {
    let fault: Option<crate::gpu_execution_node::jobs::journal_file::JournalAppendFault> = failing
        .then(|| {
            let injected = || -> std::io::Result<()> {
                Err(std::io::Error::other("injected: the sync failed"))
            };
            Arc::new(injected) as crate::gpu_execution_node::jobs::journal_file::JournalAppendFault
        });
    jobs.set_journal_append_fault(fault);
}
