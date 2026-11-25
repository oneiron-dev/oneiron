//! The node's job service as the server runs it (row R3a, FIX
//! R3A-NODE-JOBS-ATTACH). The mesh listener of a machine whose
//! `[execution_node]` file enables it opens one [`NodeJobs`] on the file's
//! `state_dir` and `work_dir` before it serves the job protocols, attaches
//! it to the node ([`ExecutionNode::attach_keys`]), and steps it on its
//! tick ([`NodeJobs::tick`]).
//!
//! Beside the tick, a thread of its own runs the disk check
//! ([`NodeJobs::check_payload_disk`]) every `disk_check_secs` of the node's
//! file (design 7.9: the listener's tick is 30 s, the check 5 s), each pass
//! planned from the one before it, not from its end. It holds the service
//! only during a pass, and ends once this service is dropped. A service
//! whose disk check did not start is not opened.
//!
//! The parts are the server's own: the node is the admission and the
//! authority, the server's GPU slot table leases the devices, the machine's
//! one memory line is the floor, the systemd unit runs each job (row R3b),
//! the template's host-local mirror stages its code (row R3c), and the vault
//! signs each receipt with this install's machine key. Linux only: the job
//! unit is systemd's (pass 34, section 2.2).
//!
//! One served node per machine: `execution-node install` makes one job
//! account, one unit template and one control socket for the machine, and
//! the start-up reconciliation stops every `oneiron-job@*` unit its journal
//! does not name, as started outside the journal, and drains the node
//! (design 7.7). A second server with an enabled node file on the same
//! machine is outside that design; the control socket refuses every caller
//! but the engine's account and root.

use std::sync::mpsc::{self, RecvTimeoutError};
use std::sync::{Arc, Mutex, PoisonError, Weak};
use std::time::{Duration, Instant};

use oneiron::Vault;
use oneiron_organ_host::MachineFloor;

use super::{MirrorStager, NodeJobParts, NodeJobPaths, NodeJobs, NodeJobsShared, SystemNodeClock};
use crate::gpu_execution_node::scope_systemd::SystemdJobUnit;
use crate::gpu_execution_node::{ExecutionNode, GpuSlotTable};

/// The node's job service on a server: opened once it can be, attached to
/// the node, and stepped on the listener's tick. The node holds a weak
/// handle ([`NodeJobs::attachment`]); this holds the strong one the server
/// keeps. Dropping this, at the listener's stop or at a start that failed
/// after the opening, closes the service ([`NodeJobs::close`]): no launch
/// commit begins after it, the node answers as one with no keys, and the
/// journal's writer lock frees once the last staging worker, which holds a
/// handle of its own, has returned at its next step.
pub struct ServedNodeJobs {
    node: ExecutionNode,
    vault: Arc<Vault>,
    slots: Arc<GpuSlotTable>,
    floor: Arc<dyn MachineFloor>,
    /// The service, once it opened.
    jobs: Mutex<Option<NodeJobs>>,
    /// Held while the disk check's thread may run: dropping it, with this
    /// service, ends the thread at once.
    disk_check: Mutex<Option<mpsc::Sender<()>>>,
}

impl std::fmt::Debug for ServedNodeJobs {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ServedNodeJobs")
            .field("node", &self.node)
            .finish_non_exhaustive()
    }
}

impl ServedNodeJobs {
    /// The job service of `node`, on the vault, the GPU slot table and the
    /// machine memory floor of the server that serves it. Nothing opens
    /// until [`Self::open`] or [`Self::tick`].
    #[must_use]
    pub fn new(
        node: ExecutionNode,
        vault: Arc<Vault>,
        slots: Arc<GpuSlotTable>,
        floor: Arc<dyn MachineFloor>,
    ) -> Self {
        Self {
            node,
            vault,
            slots,
            floor,
            jobs: Mutex::new(None),
            disk_check: Mutex::new(None),
        }
    }

    /// Opens the job service and attaches it to the node, unless it is open
    /// already. It blocks: the opening runs the start-up reconciliation
    /// (design 7.7), which asks the service manager and the slot table.
    ///
    /// # Errors
    ///
    /// Why it did not open: the node's file does not read or names no node,
    /// this install has no MACHINE id yet, the journal's writer lock is held
    /// (another service on the same `state_dir` lives) or could not be
    /// taken, or the node already holds other keys. Nothing was attached.
    pub fn open(&self) -> Result<(), String> {
        let mut jobs = self.jobs.lock().unwrap_or_else(PoisonError::into_inner);
        if jobs.is_some() {
            return Ok(());
        }
        // A service the node would not take is never opened: its start-up
        // reconciliation would act on the machine's job units for nothing.
        if self.node.keys().is_some() {
            return Err("the node already holds other keys".to_owned());
        }
        let settings = self
            .node
            .settings()?
            .ok_or_else(|| "the node's file names no execution node".to_owned())?;
        let machine = self
            .vault
            .local_machine()
            .map_err(|error| format!("this install's MACHINE id does not read: {error}"))?
            .ok_or_else(|| "this install has no MACHINE id yet".to_owned())?
            .id;
        let disk_check_every = Duration::from_secs(settings.disk_check_secs);
        let paths = NodeJobPaths {
            state_dir: settings.state_dir,
            work_dir: settings.work_dir,
        };
        let node = Arc::new(self.node.clone());
        let parts = NodeJobParts {
            machine,
            admission: Arc::<ExecutionNode>::clone(&node),
            devices: Arc::<GpuSlotTable>::clone(&self.slots),
            floor: Arc::clone(&self.floor),
            units: Arc::new(SystemdJobUnit::new(
                self.node.file().to_path_buf(),
                paths.state_dir.clone(),
            )),
            clock: Arc::new(SystemNodeClock),
            signer: Arc::<Vault>::clone(&self.vault),
            stager: Arc::new(MirrorStager::new(Arc::<ExecutionNode>::clone(&node))),
            authority: node,
        };
        // No job runs unchecked for disk: the check's thread starts before
        // the opening, whose start-up reconciliation may open the gate and
        // launch a restaged key at once, and takes the service once it has
        // opened (review r12 R12-08, r14 R14-03). A thread that did not
        // start opens nothing.
        let handover = self.start_disk_check(disk_check_every)?;
        let opened = match NodeJobs::open(paths, parts) {
            Ok(opened) => opened,
            Err(error) => {
                self.stop_disk_check();
                return Err(format!("the job journal did not open: {error}"));
            }
        };
        // A service the check did not take, or the node did not attach, is
        // closed before it is dropped, and the next tick opens it again. Its
        // opening may already have started staging workers, which hold the
        // service themselves: closed, none of them commits a launch (review
        // r13 R13-11). The node attaches no service while it holds another,
        // which the check above found none of.
        let why = if handover.send(Arc::downgrade(&opened.shared)).is_err() {
            Some("the disk check's thread ended before the service opened")
        } else if self.node.attach_keys(opened.attachment()).is_err() {
            Some("the node already holds other keys")
        } else {
            None
        };
        if let Some(why) = why {
            opened.close();
            self.stop_disk_check();
            return Err(why.to_owned());
        }
        *jobs = Some(opened);
        Ok(())
    }

    /// Ends the disk check's thread, at once.
    fn stop_disk_check(&self) {
        self.disk_check
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
    }

    /// Starts the disk check's thread: it waits for the service the
    /// returned sender hands it, then runs one pass every `every`, until
    /// this service is dropped. Between passes it holds the service weakly,
    /// so a dropped service is not kept by it (review r12 R12-07). A sender
    /// dropped with nothing sent ends it.
    ///
    /// # Errors
    ///
    /// The thread did not start.
    fn start_disk_check(
        &self,
        every: Duration,
    ) -> Result<mpsc::Sender<Weak<NodeJobsShared>>, String> {
        let (keep, kept) = mpsc::channel::<()>();
        let (handover, handed) = mpsc::channel::<Weak<NodeJobsShared>>();
        // The first pass's time is known before the thread starts, so a
        // period no clock can add fails here (review r13 R13-14); the node
        // file bounds it anyway (`disk_check_secs` at most an hour).
        let first = Instant::now()
            .checked_add(every)
            .ok_or_else(|| format!("disk_check_secs {} s is past the clock", every.as_secs()))?;
        std::thread::Builder::new()
            .name("oneiron-node-disk-check".to_owned())
            .spawn(move || {
                let Ok(service) = handed.recv() else {
                    return;
                };
                // Each pass is planned from the one before it, so a slow
                // pass does not stretch the period (review r12 R12-03).
                let mut next = first;
                // Only a timeout runs a pass: the sender's drop, at this
                // service's, ends the thread.
                while let Err(RecvTimeoutError::Timeout) =
                    kept.recv_timeout(next.saturating_duration_since(Instant::now()))
                {
                    let Some(shared) = service.upgrade() else {
                        break;
                    };
                    NodeJobs { shared }.check_payload_disk();
                    let now = Instant::now();
                    next = next.checked_add(every).unwrap_or(now).max(now);
                }
            })
            .map_err(|error| format!("the disk check's thread did not start: {error}"))?;
        *self
            .disk_check
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = Some(keep);
        Ok(handover)
    }

    /// One pass of the listener's tick. It blocks. A service that has not
    /// opened yet is opened (the next tick steps it); an open one takes one
    /// step: the start-up reconciliation it still owes, the end handling and
    /// the release checks of launched keys, and the receipts it keeps.
    pub fn tick(&self) {
        let open = self
            .jobs
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        match open {
            Some(jobs) => jobs.tick(),
            None => {
                if let Err(why) = self.open() {
                    tracing::warn!(%why, "the execution node's job service is not open; the next tick tries again");
                }
            }
        }
    }
}

impl Drop for ServedNodeJobs {
    fn drop(&mut self) {
        let jobs = self
            .jobs
            .get_mut()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        if let Some(jobs) = jobs {
            jobs.close();
        }
        // The disk check's thread ends at once; a pass it is in stops
        // before its next measure, as the service is closed.
        self.disk_check
            .get_mut()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
    }
}
