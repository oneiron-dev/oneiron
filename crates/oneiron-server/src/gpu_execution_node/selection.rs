//! The home's choice of a GPU slot among the vault's machines. A machine is
//! a candidate when it is admitted (the caller names the admitted machines)
//! and its `machine.capacity` record lists a GPU that meets the request.
//! That record says only what the cards are. Whether a card is free comes
//! from the machine's own answer now: a machine that does not answer is not
//! live, and stale data never admits. The slot is then held atomically on
//! the chosen machine (its slot table's hold), and an uncertain hold is
//! never rerouted.

use std::sync::Arc;

use oneiron::{EntityId, Vault};

use super::device::GpuDevice;
use super::slots::{GpuAvailability, GpuSlotHold, GpuSlotRefusal, GpuSlotRequest, GpuSlotTable};

/// How the home reaches a machine's GPU slots. The authenticated peer
/// transport implements it for other machines; [`LocalGpuSlotPeer`]
/// answers for this install's own GPUs.
pub trait GpuSlotPeer: Send + Sync {
    /// What `machine`'s GPUs are doing now.
    ///
    /// # Errors
    ///
    /// [`GpuSlotPeerError`]: an unreachable or uncertain answer means the
    /// machine is not live now.
    fn availability(&self, machine: EntityId) -> Result<GpuAvailability, GpuSlotPeerError>;

    /// Holds a GPU on `machine` under `request.key`, ahead of the job's
    /// start.
    ///
    /// # Errors
    ///
    /// [`GpuSlotPeerError`]; `Uncertain` means the hold may stand.
    fn hold(
        &self,
        machine: EntityId,
        request: &GpuSlotRequest,
    ) -> Result<GpuSlotHold, GpuSlotPeerError>;

    /// Ends the hold under `key` on `machine` before any call took it.
    ///
    /// # Errors
    ///
    /// [`GpuSlotPeerError`] when the machine did not take the release.
    fn release(&self, machine: EntityId, key: &str) -> Result<(), GpuSlotPeerError>;
}

/// Why a machine's GPU slot call did not answer.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum GpuSlotPeerError {
    /// The machine answered and refused; nothing took effect.
    #[error(transparent)]
    Refused(#[from] GpuSlotRefusal),
    /// The request never reached the machine; nothing took effect.
    #[error("gpu_slots.unreachable: the machine did not take the request: {reason}")]
    Unreachable { reason: String },
    /// The answer was lost after the request was sent: it may have taken
    /// effect.
    #[error(
        "gpu_slots.uncertain: the machine's answer was lost, and the request may have taken effect: {reason}"
    )]
    Uncertain { reason: String },
}

/// This install's own GPU slots, reached with no transport.
#[derive(Debug, Clone)]
pub struct LocalGpuSlotPeer {
    machine: EntityId,
    table: Arc<GpuSlotTable>,
}

impl LocalGpuSlotPeer {
    /// The slots of `table`, which is the table of this install's machine
    /// `machine`.
    #[must_use]
    pub fn new(machine: EntityId, table: Arc<GpuSlotTable>) -> Self {
        Self { machine, table }
    }

    fn own(&self, machine: EntityId) -> Result<(), GpuSlotPeerError> {
        if machine == self.machine {
            Ok(())
        } else {
            Err(GpuSlotPeerError::Unreachable {
                reason: format!(
                    "this install answers only for its own GPUs, not for machine {}",
                    machine.to_hex()
                ),
            })
        }
    }
}

impl GpuSlotPeer for LocalGpuSlotPeer {
    fn availability(&self, machine: EntityId) -> Result<GpuAvailability, GpuSlotPeerError> {
        self.own(machine)?;
        self.table
            .availability(oneiron_base::unix_millis_now())
            .map_err(|probe| {
                GpuSlotRefusal::Unmeasured {
                    reason: probe.to_string(),
                }
                .into()
            })
    }

    fn hold(
        &self,
        machine: EntityId,
        request: &GpuSlotRequest,
    ) -> Result<GpuSlotHold, GpuSlotPeerError> {
        self.own(machine)?;
        Ok(self.table.hold(request, oneiron_base::unix_millis_now())?)
    }

    fn release(&self, machine: EntityId, key: &str) -> Result<(), GpuSlotPeerError> {
        self.own(machine)?;
        self.table.release(key);
        Ok(())
    }
}

/// An admitted machine and the GPUs its capacity record lists.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GpuNodeCandidate {
    pub machine: EntityId,
    /// What its cards are: never whether they are free.
    pub inventory: Vec<GpuDevice>,
}

/// The admitted machines whose capacity record lists a GPU, in machine id
/// order. `admitted` comes from whatever admits a machine to run jobs.
///
/// # Errors
///
/// What reading a capacity record returns.
pub fn gpu_node_candidates(
    vault: &Vault,
    admitted: &[EntityId],
) -> oneiron::Result<Vec<GpuNodeCandidate>> {
    let mut machines = admitted.to_vec();
    machines.sort();
    machines.dedup();
    let mut candidates = Vec::new();
    for machine in machines {
        if let Some(capacity) = vault.machine_capacity(machine)?
            && !capacity.gpus.is_empty()
        {
            candidates.push(GpuNodeCandidate {
                machine,
                inventory: capacity.gpus,
            });
        }
    }
    Ok(candidates)
}

/// The GPU the home holds: on which machine, and the hold.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GpuSlotPlacement {
    pub machine: EntityId,
    pub hold: GpuSlotHold,
}

/// Why no GPU was held.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum GpuSelectionRefusal {
    #[error("gpu_slots.no_candidate: no admitted machine records a GPU that meets the request")]
    NoCandidate,
    #[error("gpu_slots.none_live: no admitted machine with a matching GPU answered now")]
    NoneLive,
    #[error("gpu_slots.none_free: no admitted machine that answered has a matching GPU free now")]
    NoneFree,
    /// The caller's assignment for `machine` failed, so it was not asked.
    #[error("gpu_slots.assignment_failed: the assignment to machine {} was not written ({})", .machine.to_hex(), .reason)]
    AssignmentFailed { machine: EntityId, reason: String },
    /// The hold on `machine` may stand: ask that machine again under the
    /// same key, never another machine.
    #[error(
        "gpu_slots.uncertain: the hold on machine {} may stand ({}); ask that machine again under the same key",
        .machine.to_hex(),
        .reason
    )]
    Uncertain { machine: EntityId, reason: String },
}

/// Holds one GPU for `request` among `candidates`:
/// 1. a candidate whose record lists no GPU that meets the request is never
///    asked;
/// 2. every other candidate is asked what its GPUs are doing now, and one
///    that does not answer is not live. A machine whose answer shows the
///    request's key already taking a GPU is asked to hold it again (the same
///    key answers the same hold), so one key never holds GPUs on two
///    machines;
/// 3. before each machine is asked to hold, `assign` runs with that
///    machine and the request as it will be sent: the caller writes its
///    durable assignment there, so a retry after an uncertain hold asks the
///    same machine, also after the home restarts. An assignment that fails
///    stops the selection there;
/// 4. the free matching GPUs those answers show are tried in best-fit order
///    (the least memory first, then machine id, then device id), each held
///    by its device id under the request's key. A refusal (the GPU was
///    taken in between, or the disk is under its reserve) or an unreachable
///    machine moves to the next. An uncertain answer stops there and names
///    its machine, so the GPU is never held twice.
///
/// # Errors
///
/// [`GpuSelectionRefusal`]: why no GPU was held.
pub fn select_gpu_slot(
    candidates: &[GpuNodeCandidate],
    peer: &dyn GpuSlotPeer,
    request: &GpuSlotRequest,
    assign: &mut dyn FnMut(EntityId, &GpuSlotRequest) -> Result<(), String>,
) -> Result<GpuSlotPlacement, GpuSelectionRefusal> {
    let matching: Vec<EntityId> = candidates
        .iter()
        .filter(|candidate| {
            candidate
                .inventory
                .iter()
                .any(|device| request.admits(device))
        })
        .map(|candidate| candidate.machine)
        .collect();
    if matching.is_empty() {
        return Err(GpuSelectionRefusal::NoCandidate);
    }
    let mut live = false;
    let mut free: Vec<(EntityId, GpuDevice)> = Vec::new();
    for machine in matching {
        match peer.availability(machine) {
            Ok(answer) => {
                live = true;
                if answer
                    .devices
                    .iter()
                    .any(|device| device.state.key() == Some(request.key.as_str()))
                {
                    // The key already takes a GPU there (a retry, or a twin
                    // call): that machine answers it again, and no other
                    // machine is asked.
                    assign(machine, request).map_err(|reason| {
                        GpuSelectionRefusal::AssignmentFailed { machine, reason }
                    })?;
                    return peer
                        .hold(machine, request)
                        .map(|hold| GpuSlotPlacement { machine, hold })
                        .map_err(|error| GpuSelectionRefusal::Uncertain {
                            machine,
                            reason: error.to_string(),
                        });
                }
                free.extend(
                    answer
                        .free_matching(request)
                        .map(|device| (machine, device.clone())),
                );
            }
            // It answered: it is live, and it offers nothing now.
            Err(GpuSlotPeerError::Refused(_)) => live = true,
            Err(GpuSlotPeerError::Unreachable { .. } | GpuSlotPeerError::Uncertain { .. }) => {}
        }
    }
    if !live {
        return Err(GpuSelectionRefusal::NoneLive);
    }
    free.sort_by(|(a_machine, a), (b_machine, b)| {
        a.memory_total_mib
            .cmp(&b.memory_total_mib)
            .then_with(|| a_machine.cmp(b_machine))
            .then_with(|| a.device_id.cmp(&b.device_id))
    });
    for (machine, device) in free {
        let pinned = GpuSlotRequest {
            device_id: Some(device.device_id),
            ..request.clone()
        };
        assign(machine, &pinned)
            .map_err(|reason| GpuSelectionRefusal::AssignmentFailed { machine, reason })?;
        match peer.hold(machine, &pinned) {
            Ok(hold) => return Ok(GpuSlotPlacement { machine, hold }),
            Err(GpuSlotPeerError::Refused(_) | GpuSlotPeerError::Unreachable { .. }) => {}
            Err(GpuSlotPeerError::Uncertain { reason }) => {
                return Err(GpuSelectionRefusal::Uncertain { machine, reason });
            }
        }
    }
    Err(GpuSelectionRefusal::NoneFree)
}
