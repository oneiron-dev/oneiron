//! The node's job service as the server runs it (row R3a, FIX
//! R3A-NODE-JOBS-ATTACH). The mesh listener of a machine whose
//! `[execution_node]` file enables it opens one [`NodeJobs`] on the file's
//! `state_dir` and `work_dir` before it serves the job protocols, attaches
//! it to the node ([`ExecutionNode::attach_keys`]), and steps it on its
//! tick ([`NodeJobs::tick`]).
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

use std::sync::{Arc, Mutex, PoisonError};

use oneiron::Vault;
use oneiron_organ_host::MachineFloor;

use super::{MirrorStager, NodeJobParts, NodeJobPaths, NodeJobs, SystemNodeClock};
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
        let opened = NodeJobs::open(paths, parts)
            .map_err(|error| format!("the job journal did not open: {error}"))?;
        self.node
            .attach_keys(opened.attachment())
            .map_err(|_| "the node already holds other keys".to_owned())?;
        *jobs = Some(opened);
        Ok(())
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
    }
}
