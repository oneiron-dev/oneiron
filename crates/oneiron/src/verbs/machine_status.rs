//! `vault.machines.status` (design pass 34 section 5 and row Q2): every machine of the owner's,
//! with what the vault keeps about it and, when asked, what its execution node answers now. The
//! "My machines" panel and an agent's program read the same answer.
//!
//! Two halves, each figure with its age:
//! - from the vault: the built list ([`list_machines_as`]: class, role, whether it stands live,
//!   the name it is shown by) and the machine's latest capacity claim (cores, memory, GPU
//!   memory, disk, power, the agents it can run, and when the machine measured them), listed as
//!   a producer of the answer. The capacity claim is the machine's own sample, written by it and
//!   carried to every replica, so it stands for the last thing the machine said even while it
//!   does not answer;
//! - from the node, only on `refresh`: the issuer asks each machine its `Node` answer on
//!   `oneiron/job/1` with the call timeout, and says what came back. A machine that does not
//!   answer is `unknown`: never idle, never stopped (pass 34 invariant I3). The answer is a
//!   sample, not a vault row: nothing is stored.
//!
//! The machine facts of pass 34 section 4.1 (devices, room, pressure, running keys) join the node
//! half as the node's answers gain them (row R1), and the owner's machine policy rows join with
//! row P0.

use serde::{Deserialize, Serialize};

use crate::consent::AuthenticatedOwner;
use crate::entity_id::EntityId;
use crate::job_workload::{BoundRequirement, NetworkMode, ScopeCapabilities};
use crate::machine_capacity::{MachineCapacity, MachinePower};
use crate::memory::{Memory, MemoryResult};

use super::machine_names::{MachineListItem, list_machines_as};

/// The verb's registered name.
pub const MACHINE_STATUS_VERB: &str = "vault.machines.status";

/// `vault.machines.status`'s input.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MachineStatusRequest {
    /// Ask each machine's execution node for its answer now, each within the issuer's call
    /// timeout. Without it the answer holds only what the vault keeps.
    #[serde(default)]
    pub refresh: bool,
}

/// `vault.machines.status`'s answer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MachineStatusReply {
    /// Every machine the vault's authority names, this install's first.
    pub machines: Vec<MachineStatusItem>,
    /// When this answer was read, on this install's clock: every age below is counted to it.
    pub read_at_ms: u64,
}

/// One machine.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MachineStatusItem {
    /// The machine as `vault.machines.list` shows it.
    pub machine: MachineListItem,
    /// Its latest capacity claim; absent while it has recorded none.
    pub capacity: Option<MachineCapacityView>,
    /// What its execution node answered.
    pub node: MachineNodeView,
}

/// A machine's latest capacity claim, as the machine measured it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MachineCapacityView {
    /// When the machine measured it.
    pub measured_at_ms: u64,
    /// How old the measurement is at `read_at_ms`.
    pub age_ms: u64,
    pub cores: u64,
    /// 0 where the platform does not say.
    pub memory_total_bytes: u64,
    pub memory_reserve_bytes: u64,
    pub memory_available_bytes: u64,
    /// Each GPU's memory in MiB.
    pub gpu_memory_mib: Vec<u64>,
    pub disk_total_bytes: u64,
    pub disk_free_bytes: u64,
    /// `mains`, `battery` or `unknown`.
    pub power: String,
    pub agent_memory_budget_bytes: u64,
    /// The agents it can run: available memory after the reserve, over the per-agent budget.
    pub agents: u64,
}

impl MachineCapacityView {
    /// `capacity` as read at `read_at_ms`.
    #[must_use]
    pub fn of(capacity: &MachineCapacity, read_at_ms: u64) -> Self {
        let measured_at_ms = capacity.measured_at.saturating_mul(1_000);
        Self {
            measured_at_ms,
            age_ms: read_at_ms.saturating_sub(measured_at_ms),
            cores: capacity.cores,
            memory_total_bytes: capacity.memory_total_bytes,
            memory_reserve_bytes: capacity.memory_reserve_bytes,
            memory_available_bytes: capacity.memory_available_bytes,
            gpu_memory_mib: capacity.gpu_memory_mib.clone(),
            disk_total_bytes: capacity.disk_total_bytes,
            disk_free_bytes: capacity.disk_free_bytes,
            power: match capacity.power {
                MachinePower::Mains => "mains",
                MachinePower::Battery => "battery",
                MachinePower::Unknown => "unknown",
            }
            .to_owned(),
            agent_memory_budget_bytes: capacity.agent_memory_budget_bytes,
            agents: capacity.agents,
        }
    }
}

/// What a machine's execution node said.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MachineNodeView {
    /// `not_asked` (no `refresh`, this install itself, a removed machine, or a server that is
    /// not the vault's issuer), `answered`, `refused` (it answered, and refused this issuer:
    /// `refusal` says why), or `unknown` (no answer in time, or it could not be reached:
    /// `error` says which).
    pub state: String,
    /// Why it was not asked, for `not_asked`.
    pub not_asked: Option<String>,
    /// When the issuer asked, on its clock.
    pub asked_at_ms: Option<u64>,
    pub answer: Option<MachineNodeAnswer>,
    pub refusal: Option<String>,
    pub error: Option<String>,
}

impl MachineNodeView {
    /// A machine that was not asked, and why.
    #[must_use]
    pub fn not_asked(why: &str) -> Self {
        Self {
            state: "not_asked".to_owned(),
            not_asked: Some(why.to_owned()),
            asked_at_ms: None,
            answer: None,
            refusal: None,
            error: None,
        }
    }

    /// A node that answered at `asked_at_ms`.
    #[must_use]
    pub fn answered(answer: MachineNodeAnswer, asked_at_ms: u64) -> Self {
        Self {
            state: "answered".to_owned(),
            not_asked: None,
            asked_at_ms: Some(asked_at_ms),
            answer: Some(answer),
            refusal: None,
            error: None,
        }
    }

    /// A node that answered with a refusal.
    #[must_use]
    pub fn refused(refusal: String, asked_at_ms: u64) -> Self {
        Self {
            state: "refused".to_owned(),
            not_asked: None,
            asked_at_ms: Some(asked_at_ms),
            answer: None,
            refusal: Some(refusal),
            error: None,
        }
    }

    /// A node that gave no answer: its state is unknown.
    #[must_use]
    pub fn unknown(error: String, asked_at_ms: u64) -> Self {
        Self {
            state: "unknown".to_owned(),
            not_asked: None,
            asked_at_ms: Some(asked_at_ms),
            answer: None,
            refusal: None,
            error: Some(error),
        }
    }
}

/// A node's `Node` answer (pass 33 section 7.1), as the status shows it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MachineNodeAnswer {
    /// Whether the node runs jobs at all.
    pub enabled: bool,
    /// Why it takes no new work now, while paused at the box.
    pub paused: Option<String>,
    /// Why it takes no new work until a person clears its drain.
    pub drained: Option<String>,
    /// The templates it holds, each with its digest.
    pub templates: Vec<MachineTemplateOffer>,
    /// The launch scopes it starts runs in, each with what it can enforce
    /// now.
    pub scopes: Vec<MachineScopeReport>,
    pub disk_free_bytes: u64,
    /// The disk its held keys have booked.
    pub disk_reserved_bytes: u64,
    /// The disk every booking leaves free.
    pub disk_reserve_bytes: u64,
    /// Its journal's id; absent while it keeps none.
    pub epoch: Option<String>,
    /// False until its start-up reconciliation has ended.
    pub swept: bool,
    pub boot_id: String,
    pub engine_version: String,
    /// Its warm keys (pass 34, 4.1; row P2), each with what the node knows
    /// of its path; nothing about a key's content. Left out when empty, so
    /// an answer without warm keys reads as before.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warm: Vec<MachineWarmKeyFact>,
}

/// One warm key a node reports (pass 34, 4.1; row P2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MachineWarmKeyFact {
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
    /// A run here holds this job cache kept now (FLEET-TOOL-PARITY row 5):
    /// a run of its template that starts now runs cold. Absent from an
    /// answer before it: not held.
    #[serde(default)]
    pub held: bool,
}

/// One template a node holds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MachineTemplateOffer {
    pub name: String,
    /// The template's content hash, lower hex, as a pin names it.
    pub digest: String,
    pub scopes: Vec<MachineScopeClass>,
    pub network: Vec<NetworkMode>,
    /// The outputs that may travel back to the issuer.
    pub returnable: Vec<String>,
    /// The bounds a run of it needs from its scope.
    pub require: Vec<BoundRequirement>,
}

/// One launch scope a node starts runs in, and what it can enforce now.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MachineScopeReport {
    pub class: MachineScopeClass,
    pub capabilities: ScopeCapabilities,
}

/// The kind of a launch scope.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MachineScopeClass {
    Host,
    Container,
}

/// The vault's half of `vault.machines.status` under the owner's proof: every machine with its
/// latest capacity claim, each node `not_asked` with `why`. Each capacity claim read is listed
/// as a producer of the answer on `memory`, when its host collects them.
///
/// # Errors
///
/// Every refusal of [`list_machines_as`]; a store read failure.
pub fn machine_status_from_vault(
    memory: &Memory<'_>,
    owner: &AuthenticatedOwner,
    read_at_ms: u64,
    why: &str,
) -> MemoryResult<MachineStatusReply> {
    let vault = memory.vault();
    let mut machines = Vec::new();
    for machine in list_machines_as(vault, owner)?.machines {
        let claim = match EntityId::from_hex(&machine.machine) {
            Ok(id) => vault.machine_capacity_claim(id)?,
            Err(_) => None,
        };
        let capacity = claim.map(|(claim, capacity)| {
            memory.produced_from([claim]);
            MachineCapacityView::of(&capacity, read_at_ms)
        });
        machines.push(MachineStatusItem {
            machine,
            capacity,
            node: MachineNodeView::not_asked(why),
        });
    }
    Ok(MachineStatusReply {
        machines,
        read_at_ms,
    })
}
