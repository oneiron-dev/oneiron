//! A read that picks a machine's GPU for a GPU job, before its quote. A
//! machine is a candidate when it is admitted (the caller names the admitted
//! machines) and its `machine.capacity` record lists a GPU that meets the
//! request. That record says only what the cards are. Whether a card is free
//! comes from the machine's own answer now: a machine that does not answer is
//! not live, and stale data never admits. Only an availability answer
//! crosses machines; the lease itself is local to the node. The read takes
//! nothing on any machine: the quote fixes the machine, and the node leases
//! its GPU inside the launch commit.

use std::sync::Arc;

use oneiron::{EntityId, Vault};

use super::availability::GpuAvailability;
use super::device::GpuDevice;
use super::slots::{GpuSlotRefusal, GpuSlotRequest, GpuSlotTable};

/// How the home reads a machine's GPU availability. The authenticated peer
/// transport implements it for other machines; [`LocalGpuSlotPeer`]
/// answers for this install's own GPUs.
pub trait GpuSlotPeer: Send + Sync {
    /// What `machine`'s GPUs are doing now.
    ///
    /// # Errors
    ///
    /// [`GpuSlotPeerError`]: an unreachable answer means the machine is not
    /// live now.
    fn availability(&self, machine: EntityId) -> Result<GpuAvailability, GpuSlotPeerError>;
}

/// Why a machine's GPU availability did not answer.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum GpuSlotPeerError {
    /// The machine answered and refused; it is live and offers nothing now.
    #[error(transparent)]
    Refused(#[from] GpuSlotRefusal),
    /// The request never reached the machine; nothing took effect.
    #[error("gpu_slots.unreachable: the machine did not take the request: {reason}")]
    Unreachable { reason: String },
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

/// The GPU the caller picks: on which machine, and the device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GpuSlotPlacement {
    pub machine: EntityId,
    pub device: GpuDevice,
}

/// Why no GPU was picked.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum GpuSelectionRefusal {
    #[error("gpu_slots.no_candidate: no admitted machine records a GPU that meets the request")]
    NoCandidate,
    #[error("gpu_slots.none_live: no admitted machine with a matching GPU answered now")]
    NoneLive,
    #[error("gpu_slots.none_free: no admitted machine that answered has a matching GPU free now")]
    NoneFree,
}

/// Picks one GPU for `request` among `candidates`, taking nothing:
/// 1. a candidate whose record lists no GPU that meets the request is never
///    asked;
/// 2. every other candidate is asked what its GPUs are doing now, and one
///    that does not answer is not live. The first machine whose answer shows
///    the request's key already taking a GPU is chosen with that GPU, and no
///    other machine is asked after it;
/// 3. otherwise the free matching GPUs those answers show are picked in
///    best-fit order (the least memory first, then machine id, then device
///    id). The caller quotes that machine, and the node leases the GPU inside
///    its launch commit.
///
/// # Errors
///
/// [`GpuSelectionRefusal`]: why no GPU was picked.
pub fn select_gpu_slot(
    candidates: &[GpuNodeCandidate],
    peer: &dyn GpuSlotPeer,
    request: &GpuSlotRequest,
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
                if let Some(device) = answer
                    .devices
                    .iter()
                    .find(|device| device.state.key() == Some(request.key.as_str()))
                {
                    // The key already takes a GPU there (a retry, or a twin
                    // call): that machine answers it, and no other machine
                    // is asked.
                    return Ok(GpuSlotPlacement {
                        machine,
                        device: device.device.clone(),
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
            Err(GpuSlotPeerError::Unreachable { .. }) => {}
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
    free.into_iter()
        .next()
        .map(|(machine, device)| GpuSlotPlacement { machine, device })
        .ok_or(GpuSelectionRefusal::NoneFree)
}
