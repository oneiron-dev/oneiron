//! `vault.machines.execution.get` (pass 33 door 11, `33-exec-node/DESIGN.md`
//! section 6): what each machine the vault holds a job grant for offers its
//! GPU jobs now, as the machine itself answers the serving machine. It writes
//! nothing and ranks nothing.
//!
//! The engine half is here: who may read it (the owner under their own
//! proof, or an agent whose own live Grant lists the verb), and, in the same
//! snapshot, which machines to ask, with the two job grants this vault holds
//! for each and the name each is shown by ([`machine_execution_targets_as`]).
//! The server asks each machine over the job protocols and fills the answer
//! below; these are the answer's own types, so the SDK's shape does not move
//! when the mesh wire does. A machine's hourly capacity is never shown as its
//! availability: availability is what its driver read when it was asked.

use serde::{Deserialize, Serialize};

use crate::EntityId;
use crate::consent::AuthenticatedOwner;
use crate::job_workload::{
    BoundRequirement, JOB_ALPN, JOB_STATUS_ALPN, NetworkMode, ScopeCapabilities,
};
use crate::machine_capacity::GpuDevice;
use crate::memory::{Memory, MemoryResult};
use crate::ports::EntityStoreRead;
use crate::registry::ENTITY_TYPE_MACHINE;
use oneiron_verb_wire::verbs::secret_custody::entity_id;

/// The verb's name, as its row and its reader check name it.
pub const MACHINES_EXECUTION_GET_VERB: &str = "vault.machines.execution.get";

/// `vault.machines.execution.get`'s input.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MachineExecutionRequest {
    /// One MACHINE row, 32 hex, answered whether or not the vault holds a
    /// job grant for it. Absent: every machine the vault holds either job
    /// grant for.
    #[serde(default)]
    pub machine: Option<String>,
}

/// `vault.machines.execution.get`'s answer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MachineExecutionReply {
    pub machines: Vec<MachineExecution>,
}

/// One machine, as the serving machine read it from the machine itself.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MachineExecution {
    /// The MACHINE row, 32 hex.
    pub machine: String,
    /// The name it is shown by, as `vault.machines.list` shows it; null for
    /// an id the vault's authority names no machine by.
    pub name: Option<String>,
    /// Whether it is the machine serving this read, which asks no machine
    /// of itself.
    pub this_install: bool,
    /// Whether this vault holds its live grant on `oneiron/job/1`, the
    /// protocol of new work.
    pub job_grant: bool,
    /// Whether this vault holds its live grant on `oneiron/job-status/1`,
    /// the protocol of the keys it holds.
    pub job_status_grant: bool,
    /// When the serving machine asked it, in Unix milliseconds; null when it
    /// asked nothing (no job grant, or this install).
    pub asked_at_ms: Option<u64>,
    /// Its answer on `oneiron/job/1` to what it offers.
    pub node: Option<MachineNodeOffer>,
    /// Its GPUs as its driver read them when it was asked.
    pub availability: Option<MachineGpuAvailability>,
    /// The keys it holds that have not ended.
    pub live_keys: Option<Vec<MachineLiveKey>>,
    /// Why an answer above is missing although its grant is held: the first
    /// ask that got none.
    pub unreachable: Option<MachineUnreachable>,
}

/// The ask that got no answer, and why.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MachineUnreachable {
    pub ask: MachineAsk,
    /// What the call or the machine said: no answer in time, the reason it
    /// could not be reached, or the machine's refusal code.
    pub reason: String,
}

/// One of the asks the serving machine makes of a machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MachineAsk {
    /// What it offers, on `oneiron/job/1`.
    Node,
    /// Its GPUs, on `oneiron/job/1`.
    Availability,
    /// The keys it holds, on `oneiron/job-status/1`.
    Keys,
}

/// What a machine offers GPU jobs, as it answers for itself.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MachineNodeOffer {
    /// Whether it runs jobs at all (its `[execution_node] enabled`).
    pub enabled: bool,
    /// Why it takes no new work now, while paused at the box.
    pub paused: Option<String>,
    /// Why it takes no new work until a person clears its drain.
    pub drained: Option<String>,
    pub templates: Vec<MachineTemplateOffer>,
    /// The launch scopes it starts runs in, each with what it can enforce
    /// now.
    pub scopes: Vec<MachineScopeReport>,
    pub disk_free_bytes: u64,
    /// The disk the keys it holds have booked.
    pub disk_reserved_bytes: u64,
    /// The disk every booking leaves free.
    pub disk_reserve_bytes: u64,
    /// False until its start-up reconciliation has ended.
    pub swept: bool,
    pub engine_version: String,
}

/// One template a machine holds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MachineTemplateOffer {
    pub name: String,
    /// The template's content hash, lower hex, as a pin names it.
    pub digest: String,
    pub scopes: Vec<MachineScopeClass>,
    pub network: Vec<NetworkMode>,
    /// The outputs that may travel back.
    pub returnable: Vec<String>,
    /// The bounds a run of it needs from its scope.
    pub require: Vec<BoundRequirement>,
}

/// One launch scope a machine starts runs in.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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

/// A machine's GPUs as its driver read them when it was asked.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MachineGpuAvailability {
    /// When the driver was read, in Unix milliseconds.
    pub measured_at_ms: u64,
    /// While it is paused, why: it takes no new GPU work.
    pub paused: Option<String>,
    /// While it is drained, why: it takes no GPU work.
    pub drained: Option<String>,
    /// What its jobs' disk holds now, when it books on one.
    pub disk: Option<MachineDiskReading>,
    pub devices: Vec<MachineGpuDevice>,
}

/// What the disk a machine's GPU jobs write on holds now.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MachineDiskReading {
    /// The bytes an unprivileged writer may still use there.
    pub free_bytes: u64,
    /// The free bytes no work takes.
    pub reserve_bytes: u64,
    /// The bytes work in flight has claimed past the reserve.
    pub claimed_bytes: u64,
}

/// One GPU of a machine and what it is doing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MachineGpuDevice {
    pub device: GpuDevice,
    pub state: MachineGpuState,
}

/// What one GPU is doing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum MachineGpuState {
    /// Offered, not withheld, untaken, and no compute process runs on it.
    Free,
    /// A compute process its machine did not launch runs on it.
    Busy { pids: Vec<u32> },
    /// It takes no new job until cleared; `key` still takes it, if any.
    Quarantined { why: String, key: Option<String> },
    /// The job under `key` leased it, and its process has not started.
    Leased { key: String },
    /// The job under `key` runs on it.
    Launched { key: String },
    /// Another booker holds it.
    Withheld,
    /// Its machine does not offer it.
    NotOffered,
}

/// One key a machine holds that has not ended.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MachineLiveKey {
    pub key: String,
    pub state: MachineKeyState,
}

/// Where a key that has not ended stands on its machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MachineKeyState {
    Held,
    Accepted,
    Staging,
    Launching,
    Running,
    Ending,
}

/// One machine the server asks, as the engine read it for the caller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MachineExecutionTarget {
    pub machine: EntityId,
    /// The name it is shown by; `None` for an id the authority names no
    /// machine by.
    pub name: Option<String>,
    /// Whether it is this install's own machine.
    pub this_install: bool,
    pub job_grant: bool,
    pub job_status_grant: bool,
}

impl MachineExecutionTarget {
    /// Whether the server asks it anything: a held job grant, on another
    /// machine.
    #[must_use]
    pub const fn asked(&self) -> bool {
        !self.this_install && (self.job_grant || self.job_status_grant)
    }

    /// Its row in the answer before any ask.
    #[must_use]
    pub fn unasked(&self) -> MachineExecution {
        MachineExecution {
            machine: self.machine.to_hex(),
            name: self.name.clone(),
            this_install: self.this_install,
            job_grant: self.job_grant,
            job_status_grant: self.job_status_grant,
            asked_at_ms: None,
            node: None,
            availability: None,
            live_keys: None,
            unreachable: None,
        }
    }
}

/// `vault.machines.execution.get`'s engine read as `memory`'s caller, in one
/// snapshot: admits the caller (the owner under `owner`, else an agent whose
/// own live Grant lists the verb), then names the machines to ask, each with
/// the two job grants this vault holds for it now and the name it is shown
/// by. Without `input.machine`, a machine with neither grant is left out.
///
/// # Errors
///
/// `forbidden` for a caller it does not admit; `bad_request` for a
/// `machine` that is not 32 hex; a store read failure.
pub fn machine_execution_targets_as(
    memory: &Memory<'_>,
    owner: Option<&AuthenticatedOwner>,
    input: &MachineExecutionRequest,
) -> MemoryResult<Vec<MachineExecutionTarget>> {
    let named = input
        .machine
        .as_deref()
        .map(|machine| entity_id("machine", machine))
        .transpose()?;
    let vault = memory.vault();
    let txn = vault.store.env.read_txn().map_err(crate::Error::from)?;
    memory.verb_grant_caller_admits_in_txn(&txn, owner, MACHINES_EXECUTION_GET_VERB)?;
    let this = vault.serving_machine_in_txn(&txn)?;
    let machines = match named {
        Some(machine) => vec![machine],
        None => {
            EntityStoreRead::port_entity_ids_by_type(&vault.store, &txn, ENTITY_TYPE_MACHINE, None)?
                .collect::<crate::error::Result<Vec<_>>>()?
        }
    };
    let mut targets = Vec::with_capacity(machines.len());
    for machine in machines {
        let job_grant = vault.mesh_machine_granted_in_txn(&txn, machine, JOB_ALPN)?;
        let job_status_grant = vault.mesh_machine_granted_in_txn(&txn, machine, JOB_STATUS_ALPN)?;
        if named.is_none() && !job_grant && !job_status_grant {
            continue;
        }
        targets.push(MachineExecutionTarget {
            machine,
            name: vault.machine_shown_name_in_txn(&txn, machine)?,
            this_install: this == Some(machine),
            job_grant,
            job_status_grant,
        });
    }
    Ok(targets)
}
