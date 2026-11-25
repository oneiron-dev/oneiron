//! `vault.machines.execution.get` (pass 33 door 11, `33-exec-node/DESIGN.md`
//! section 6): what each machine the vault holds a job grant for offers its
//! GPU jobs now, as the machine itself answers the vault's issuer. It writes
//! nothing and ranks nothing.
//!
//! The engine half is here: who may read it (the owner under their own
//! proof, or an agent whose own live Grant lists the verb), and, in the same
//! snapshot, which machines to ask, with the two job grants this vault holds
//! for each and the name each is shown by ([`machine_execution_targets_as`]).
//! The issuer then asks each machine and fills the answer. Each ask is shown
//! in the form `vault.machines.status` shows the node's answer
//! ([`MachineNodeView`]: `not_asked` with why, `answered`, `refused` with the
//! machine's code, or `unknown` with the call's error, each with when it was
//! asked). A machine's hourly capacity is never shown as its availability:
//! availability is what its driver read when it was asked.

use serde::{Deserialize, Serialize};

use super::machine_status::MachineNodeView;
use crate::EntityId;
use crate::consent::AuthenticatedOwner;
use crate::job_workload::{JOB_ALPN, JOB_STATUS_ALPN};
use crate::machine_capacity::GpuDevice;
use crate::memory::{MEMORY_CODE_NOT_FOUND, Memory, MemoryError, MemoryResult};
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

/// One machine, as the vault's issuer read it from the machine itself.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MachineExecution {
    /// The MACHINE row, 32 hex.
    pub machine: String,
    /// The name it is shown by, as `vault.machines.list` shows it.
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
    /// What it offers, asked on `oneiron/job/1`.
    pub node: MachineNodeView,
    /// Its GPUs, asked on `oneiron/job/1` once it answered its offer.
    pub availability: MachineGpuView,
    /// The keys it holds that have not ended, asked on
    /// `oneiron/job-status/1`.
    pub live_keys: MachineKeysView,
}

/// A machine's GPUs as one ask got them, in the form of [`MachineNodeView`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MachineGpuView {
    /// `not_asked`, `answered`, `refused` or `unknown`, as for the node.
    pub state: String,
    /// Why it was not asked, for `not_asked`.
    pub not_asked: Option<String>,
    /// When the issuer asked, on its clock.
    pub asked_at_ms: Option<u64>,
    pub answer: Option<MachineGpuAvailability>,
    pub refusal: Option<String>,
    pub error: Option<String>,
}

/// The keys a machine holds as one read got them, in the form of
/// [`MachineNodeView`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MachineKeysView {
    /// `not_asked`, `answered`, `refused` or `unknown`, as for the node.
    pub state: String,
    /// Why it was not asked, for `not_asked`.
    pub not_asked: Option<String>,
    /// When the issuer asked, on its clock.
    pub asked_at_ms: Option<u64>,
    pub answer: Option<Vec<MachineLiveKey>>,
    pub refusal: Option<String>,
    pub error: Option<String>,
}

impl MachineGpuView {
    /// GPUs that were not asked, and why.
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

    /// GPUs the machine answered at `asked_at_ms`.
    #[must_use]
    pub fn answered(answer: MachineGpuAvailability, asked_at_ms: u64) -> Self {
        Self {
            state: "answered".to_owned(),
            not_asked: None,
            asked_at_ms: Some(asked_at_ms),
            answer: Some(answer),
            refusal: None,
            error: None,
        }
    }

    /// GPUs the machine refused to read for this issuer.
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

    /// GPUs the ask got no answer about.
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

impl MachineKeysView {
    /// Keys that were not asked, and why.
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

    /// Every key the machine holds that has not ended, read from
    /// `asked_at_ms` to its last page.
    #[must_use]
    pub fn answered(answer: Vec<MachineLiveKey>, asked_at_ms: u64) -> Self {
        Self {
            state: "answered".to_owned(),
            not_asked: None,
            asked_at_ms: Some(asked_at_ms),
            answer: Some(answer),
            refusal: None,
            error: None,
        }
    }

    /// Keys the machine refused to list for this issuer.
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

    /// Keys the read did not get to the last page of: none is shown.
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

/// The machines the issuer asks, as the engine read them for the caller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MachineExecutionTargets {
    /// This install's own machine, which the issuer check compares.
    pub serving_machine: Option<EntityId>,
    pub targets: Vec<MachineExecutionTarget>,
}

/// One machine the issuer asks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MachineExecutionTarget {
    pub machine: EntityId,
    /// The name it is shown by.
    pub name: Option<String>,
    /// Whether it is this install's own machine.
    pub this_install: bool,
    pub job_grant: bool,
    pub job_status_grant: bool,
}

impl MachineExecutionTarget {
    /// Whether the issuer asks it what it offers (and then its GPUs): a held
    /// job grant, on another machine.
    #[must_use]
    pub const fn asks_offer(&self) -> bool {
        !self.this_install && self.job_grant
    }

    /// Whether the issuer asks it the keys it holds: a held status grant, on
    /// another machine.
    #[must_use]
    pub const fn asks_keys(&self) -> bool {
        !self.this_install && self.job_status_grant
    }

    /// Its row with no ask made, each ask's view saying why.
    #[must_use]
    pub fn unasked(&self) -> MachineExecution {
        let why_offer = if self.this_install {
            "this_install"
        } else if self.job_grant {
            "not_reached"
        } else {
            "no_job_grant"
        };
        let why_keys = if self.this_install {
            "this_install"
        } else if self.job_status_grant {
            "not_reached"
        } else {
            "no_job_status_grant"
        };
        MachineExecution {
            machine: self.machine.to_hex(),
            name: self.name.clone(),
            this_install: self.this_install,
            job_grant: self.job_grant,
            job_status_grant: self.job_status_grant,
            node: MachineNodeView::not_asked(why_offer),
            availability: MachineGpuView::not_asked(why_offer),
            live_keys: MachineKeysView::not_asked(why_keys),
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
/// `machine` that is not 32 hex; `not_found` for one the vault's authority
/// names no machine by; a store read failure.
pub fn machine_execution_targets_as(
    memory: &Memory<'_>,
    owner: Option<&AuthenticatedOwner>,
    input: &MachineExecutionRequest,
) -> MemoryResult<MachineExecutionTargets> {
    let named = input
        .machine
        .as_deref()
        .map(|machine| entity_id("machine", machine))
        .transpose()?;
    let vault = memory.vault();
    let txn = vault.store.env.read_txn().map_err(crate::Error::from)?;
    memory.verb_grant_caller_admits_in_txn(&txn, owner, MACHINES_EXECUTION_GET_VERB)?;
    let serving_machine = vault.serving_machine_in_txn(&txn)?;
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
        let name = vault.machine_shown_name_in_txn(&txn, machine)?;
        if named.is_some() && name.is_none() {
            return Err(MemoryError::new(
                MEMORY_CODE_NOT_FOUND,
                "the vault's authority names no machine by this id",
                &["List the machines with vault.machines.list."],
            ));
        }
        targets.push(MachineExecutionTarget {
            machine,
            name,
            this_install: serving_machine == Some(machine),
            job_grant,
            job_status_grant,
        });
    }
    Ok(MachineExecutionTargets {
        serving_machine,
        targets,
    })
}
