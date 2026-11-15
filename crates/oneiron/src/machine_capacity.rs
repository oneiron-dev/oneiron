//! What this install's machine measured itself to hold (CROSS-ARCH-0024
//! #my-network 05: "Capacity is measured. A probe records cores, RAM, GPU,
//! disk and power. Agents it can run = free RAM after a reserve ÷ the M2.19
//! per-agent budget."), recorded on the install's own MACHINE entity
//! (#my-network 01: the view reads those entities, and nothing lives only in
//! the control plane).
//!
//! One engine-owned claim, [`PREDICATE_MACHINE_CAPACITY`], about the MACHINE
//! row, carries the latest measurement. The `machine` namespace is
//! engine-owned and reserved, so the public claim door refuses it and no
//! agent can state a machine's capacity: the host's probe writes it through
//! the reserved door. It replicates with the owner's other claims, so every
//! machine of the owner reads every machine's record. A measurement attests
//! nothing, so it is no authority op. A whole-vault archive import omits it
//! (the `machine` namespace is local history there): a restored image is
//! another install, which measures itself.

use rmpv::Value;

use crate::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject,
};
use crate::error::{Error, Result};
use crate::ports::{EntityStoreRead, TombstoneStoreRead};
use crate::registry::ENTITY_TYPE_MACHINE;
use crate::{EntityId, TimeRange, Vault};

/// The predicate of a MACHINE's measured capacity.
pub const PREDICATE_MACHINE_CAPACITY: &str = "machine.capacity";

/// The memory one active agent is taken to need: about 0.45 GiB, from the
/// RAM budget table of CROSS-ARCH-0024 ("Agents | about 0.45 GiB per active
/// agent"). M2.19's measured budget replaces it.
pub const AGENT_MEMORY_BUDGET_BYTES: u64 = (1 << 30) * 45 / 100;

/// The evidence every record carries: where the numbers came from.
const EVIDENCE: &str = "measured by this install's capacity probe";

const CORES: &str = "cores";
const MEMORY_TOTAL_BYTES: &str = "memory_total_bytes";
const MEMORY_RESERVE_BYTES: &str = "memory_reserve_bytes";
const MEMORY_AVAILABLE_BYTES: &str = "memory_available_bytes";
const GPU_MEMORY_MIB: &str = "gpu_memory_mib";
const DISK_TOTAL_BYTES: &str = "disk_total_bytes";
const DISK_FREE_BYTES: &str = "disk_free_bytes";
const POWER: &str = "power";
const AGENT_MEMORY_BUDGET: &str = "agent_memory_budget_bytes";
const AGENTS: &str = "agents";
const MEASURED_AT: &str = "measured_at";

/// Where the machine draws its power from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MachinePower {
    /// Mains power, or a machine with no battery.
    Mains,
    /// Its battery.
    Battery,
    /// The platform does not say.
    Unknown,
}

impl MachinePower {
    const fn wire(self) -> &'static str {
        match self {
            Self::Mains => "mains",
            Self::Battery => "battery",
            Self::Unknown => "unknown",
        }
    }

    fn from_wire(wire: &str) -> Option<Self> {
        [Self::Mains, Self::Battery, Self::Unknown]
            .into_iter()
            .find(|power| power.wire() == wire)
    }
}

/// One reading of the machine, as its host's probe takes it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MachineMeasurement {
    /// Logical cores the host process may run on.
    pub cores: u64,
    /// Physical memory; 0 where the platform does not say.
    pub memory_total_bytes: u64,
    /// Memory the host can take now without paging, container limits
    /// counted; 0 where it cannot be read.
    pub memory_available_bytes: u64,
    /// Each GPU's memory in MiB; empty where none is known.
    pub gpu_memory_mib: Vec<u64>,
    /// The size of the disk the vault lives on.
    pub disk_total_bytes: u64,
    /// The bytes an unprivileged writer may still use on that disk.
    pub disk_free_bytes: u64,
    /// Where it draws its power from.
    pub power: MachinePower,
}

/// A machine's measured capacity: one measurement, the memory reserve and
/// per-agent budget it was judged by, and the agents it can run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MachineCapacity {
    /// Logical cores the host process may run on.
    pub cores: u64,
    /// Physical memory; 0 where the platform does not say.
    pub memory_total_bytes: u64,
    /// The free memory no work takes on a machine of this size
    /// ([`crate::host_memory::memory_reserve`]).
    pub memory_reserve_bytes: u64,
    /// Memory the host could take at the measurement.
    pub memory_available_bytes: u64,
    /// Each GPU's memory in MiB; empty where none is known.
    pub gpu_memory_mib: Vec<u64>,
    /// The size of the disk the vault lives on.
    pub disk_total_bytes: u64,
    /// The bytes an unprivileged writer could still use on it.
    pub disk_free_bytes: u64,
    /// Where it drew its power from.
    pub power: MachinePower,
    /// The memory one active agent was taken to need.
    pub agent_memory_budget_bytes: u64,
    /// The agents it can run: available memory after the reserve, over the
    /// per-agent budget, rounded down.
    pub agents: u64,
    /// When it was measured, in Unix seconds.
    pub measured_at: u64,
}

/// Available memory after the reserve, over the per-agent budget.
fn agents_it_can_run(available: u64, reserve: u64, budget: u64) -> u64 {
    available
        .saturating_sub(reserve)
        .checked_div(budget)
        .unwrap_or(0)
}

fn invalid_value() -> Error {
    Error::InvalidClaimBody("machine capacity value is not a capacity record")
}

impl MachineCapacity {
    /// The capacity `measured` shows at `measured_at`: its reserve is the one
    /// every memory admission keeps on a machine of its size, and its agent
    /// budget is [`AGENT_MEMORY_BUDGET_BYTES`].
    #[must_use]
    pub fn from_measurement(measured: MachineMeasurement, measured_at: u64) -> Self {
        let memory_reserve_bytes = crate::host_memory::memory_reserve(measured.memory_total_bytes);
        Self {
            cores: measured.cores,
            memory_total_bytes: measured.memory_total_bytes,
            memory_reserve_bytes,
            memory_available_bytes: measured.memory_available_bytes,
            gpu_memory_mib: measured.gpu_memory_mib,
            disk_total_bytes: measured.disk_total_bytes,
            disk_free_bytes: measured.disk_free_bytes,
            power: measured.power,
            agent_memory_budget_bytes: AGENT_MEMORY_BUDGET_BYTES,
            agents: agents_it_can_run(
                measured.memory_available_bytes,
                memory_reserve_bytes,
                AGENT_MEMORY_BUDGET_BYTES,
            ),
            measured_at,
        }
    }

    /// Whether a total, the power source, the agent budget or the agent
    /// count differs from `recorded`: the moves that write a new record.
    /// Free disk, free memory and the time alone write none.
    #[must_use]
    pub fn moved_from(&self, recorded: &Self) -> bool {
        self.cores != recorded.cores
            || self.memory_total_bytes != recorded.memory_total_bytes
            || self.gpu_memory_mib != recorded.gpu_memory_mib
            || self.disk_total_bytes != recorded.disk_total_bytes
            || self.power != recorded.power
            || self.agent_memory_budget_bytes != recorded.agent_memory_budget_bytes
            || self.agents != recorded.agents
    }

    /// The claim value: a MessagePack map with one key per field.
    #[must_use]
    pub fn to_value(&self) -> Value {
        let count = |name: &str, value: u64| (Value::from(name), Value::from(value));
        Value::Map(vec![
            count(CORES, self.cores),
            count(MEMORY_TOTAL_BYTES, self.memory_total_bytes),
            count(MEMORY_RESERVE_BYTES, self.memory_reserve_bytes),
            count(MEMORY_AVAILABLE_BYTES, self.memory_available_bytes),
            (
                Value::from(GPU_MEMORY_MIB),
                Value::Array(
                    self.gpu_memory_mib
                        .iter()
                        .copied()
                        .map(Value::from)
                        .collect(),
                ),
            ),
            count(DISK_TOTAL_BYTES, self.disk_total_bytes),
            count(DISK_FREE_BYTES, self.disk_free_bytes),
            (Value::from(POWER), Value::from(self.power.wire())),
            count(AGENT_MEMORY_BUDGET, self.agent_memory_budget_bytes),
            count(AGENTS, self.agents),
            count(MEASURED_AT, self.measured_at),
        ])
    }

    /// Reads a claim value [`Self::to_value`] wrote. Each field is present
    /// once, and the agent count is the one its own memory and budget give.
    /// A key it does not know is passed over, so a later field is additive.
    pub(crate) fn from_value(value: &Value) -> Result<Self> {
        let Value::Map(entries) = value else {
            return Err(invalid_value());
        };
        let field = |name: &str| -> Result<&Value> {
            let mut found = entries
                .iter()
                .filter(|(key, _)| key.as_str() == Some(name))
                .map(|(_, value)| value);
            match (found.next(), found.next()) {
                (Some(value), None) => Ok(value),
                _ => Err(invalid_value()),
            }
        };
        let count = |name: &str| field(name)?.as_u64().ok_or_else(invalid_value);
        let Value::Array(gpus) = field(GPU_MEMORY_MIB)? else {
            return Err(invalid_value());
        };
        let capacity = Self {
            cores: count(CORES)?,
            memory_total_bytes: count(MEMORY_TOTAL_BYTES)?,
            memory_reserve_bytes: count(MEMORY_RESERVE_BYTES)?,
            memory_available_bytes: count(MEMORY_AVAILABLE_BYTES)?,
            gpu_memory_mib: gpus
                .iter()
                .map(|gpu| gpu.as_u64().ok_or_else(invalid_value))
                .collect::<Result<_>>()?,
            disk_total_bytes: count(DISK_TOTAL_BYTES)?,
            disk_free_bytes: count(DISK_FREE_BYTES)?,
            power: field(POWER)?
                .as_str()
                .and_then(MachinePower::from_wire)
                .ok_or_else(invalid_value)?,
            agent_memory_budget_bytes: count(AGENT_MEMORY_BUDGET)?,
            agents: count(AGENTS)?,
            measured_at: count(MEASURED_AT)?,
        };
        let agents = agents_it_can_run(
            capacity.memory_available_bytes,
            capacity.memory_reserve_bytes,
            capacity.agent_memory_budget_bytes,
        );
        if capacity.agent_memory_budget_bytes == 0 || capacity.agents != agents {
            return Err(Error::InvalidClaimBody(
                "machine capacity agent count is not its memory over its budget",
            ));
        }
        Ok(capacity)
    }
}

/// The shape every `machine.capacity` claim keeps, local or replicated: about
/// an entity, a capacity value, confidence 1.0, `auto`, and `observed`, as
/// the probe writes it. A cross-vault import restamps a foreign claim's
/// source to `imported`, so another vault's record never lands here.
pub(crate) fn validate_machine_capacity_claim_structure(body: &ClaimBody) -> Result<()> {
    if !matches!(body.subject, ClaimSubject::Entity(_)) {
        return Err(Error::InvalidClaimBody(
            "machine capacity must be about a MACHINE entity",
        ));
    }
    MachineCapacity::from_value(&body.value)?;
    if body.confidence != 1.0 {
        return Err(Error::InvalidClaimBody(
            "machine capacity claim confidence must be 1.0",
        ));
    }
    if body.approval != ClaimApprovalStatus::Auto {
        return Err(Error::InvalidClaimBody(
            "machine capacity approval must be auto",
        ));
    }
    if body.source != Some(ClaimSource::Observed) {
        return Err(Error::InvalidClaimBody(
            "machine capacity source must be observed",
        ));
    }
    Ok(())
}

/// What [`Vault::record_machine_capacity`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MachineCapacityWrite {
    /// A new record landed: the claim's id. The record it replaced, if any,
    /// is superseded.
    Recorded(EntityId),
    /// The standing record already says this (no total, power source or
    /// agent count moved): its id.
    Unchanged(EntityId),
    /// This install has no live MACHINE row (it was never enrolled), so
    /// there is nothing to record it on. Its first enrolled start records it.
    NoMachine,
}

/// This install's own MACHINE row, when it has a live one.
fn local_machine_row_in_txn(vault: &Vault, txn: &heed::RoTxn<'_>) -> Result<Option<EntityId>> {
    let Some(machine) = crate::identity::read_machine_id_in_txn(vault, txn)? else {
        return Ok(None);
    };
    let visibility = TombstoneStoreRead::port_deletion_state(&vault.store, txn, &machine)?;
    if visibility.deleted || visibility.archived || visibility.stale {
        return Ok(None);
    }
    Ok(
        EntityStoreRead::port_entity_record(&vault.store, txn, &machine)?
            .filter(|row| row.entity_type == ENTITY_TYPE_MACHINE)
            .map(|_| machine),
    )
}

/// The active `machine.capacity` claims about `machine`.
fn capacity_heads_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    machine: EntityId,
) -> Result<Vec<(EntityId, ClaimBody)>> {
    let mut heads = Vec::new();
    for id in vault.claims_for_subject_in_txn(txn, &machine)? {
        if let Some(body) = vault.get_claim_in_txn(txn, &id)?
            && body.predicate == PREDICATE_MACHINE_CAPACITY
            && body.lifecycle == ClaimLifecycleStatus::Active
        {
            heads.push((id, body));
        }
    }
    Ok(heads)
}

/// The latest measurement among `heads`, with its claim's id.
fn latest_capacity(heads: &[(EntityId, ClaimBody)]) -> Option<(EntityId, MachineCapacity)> {
    heads
        .iter()
        .filter_map(|(id, body)| Some((*id, MachineCapacity::from_value(&body.value).ok()?)))
        .max_by_key(|(_, capacity)| capacity.measured_at)
}

impl Vault {
    /// Records `capacity` on this install's own MACHINE entity, as the
    /// engine-owned claim [`PREDICATE_MACHINE_CAPACITY`]. A record that
    /// already says it ([`MachineCapacity::moved_from`]) stands and nothing
    /// is written, so a probe writes one revision per change, not one per
    /// reading. A new record supersedes the one it replaces in the same
    /// transaction. Only this install's host calls it, with what it measured.
    pub fn record_machine_capacity(
        &self,
        capacity: &MachineCapacity,
    ) -> Result<MachineCapacityWrite> {
        self.with_write_txn_grouped(|txn| {
            let Some(machine) = local_machine_row_in_txn(self, txn)? else {
                return Ok(MachineCapacityWrite::NoMachine);
            };
            let heads = capacity_heads_in_txn(self, txn, machine)?;
            if let Some((standing, recorded)) = latest_capacity(&heads)
                && !capacity.moved_from(&recorded)
            {
                return Ok(MachineCapacityWrite::Unchanged(standing));
            }
            let now = self.store.clock.now_recorded_at();
            let mut body = ClaimBody::new(
                PREDICATE_MACHINE_CAPACITY,
                ClaimSubject::Entity(machine),
                capacity.to_value(),
                1.0,
                ClaimApprovalStatus::Auto,
                ClaimLifecycleStatus::Active,
            )?;
            body.evidence = Some(Value::from(EVIDENCE));
            body.valid_from = Some(now);
            body.source = Some(ClaimSource::Observed);
            let id = self.store.clock.entity_id()?;
            self.put_reserved_claim_in_txn(
                txn,
                &id,
                &body,
                TimeRange {
                    start: now,
                    end: now,
                },
                now,
            )?;
            for (replaced, _) in heads {
                self.supersede_reserved_claim_in_txn(txn, &id, &replaced, now)?;
            }
            Ok(MachineCapacityWrite::Recorded(id))
        })
    }

    /// The latest recorded capacity of `machine`, this install's or another
    /// machine of the owner's, or `None` while it has recorded none.
    pub fn machine_capacity(&self, machine: EntityId) -> Result<Option<MachineCapacity>> {
        let txn = self.store.env.read_txn()?;
        Ok(
            latest_capacity(&capacity_heads_in_txn(self, &txn, machine)?)
                .map(|(_, capacity)| capacity),
        )
    }
}
