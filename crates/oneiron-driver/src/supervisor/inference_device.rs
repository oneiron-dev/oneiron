//! One physical device's memory ledger (DESIGN-V2 §7, INFERENCE R2/R4):
//! declarations and measured residency, transient holds, class budgets, and
//! the atomic check-and-reserve used by device admission.
//!
//! The ledger does not order work or stop workers: [`DeviceAdmission`](super::DeviceAdmission)
//! owns that queue. A declared envelope is a plan, never a measurement, and
//! it is never shown as resident memory. A size no source gave stays `None`,
//! never zero, and a total over rows is known only when every row's part is.
//! Unknown capacity admits and records under the R4 ruling; a known capacity
//! with an incomplete declaration does not invent room.
use std::collections::{BTreeMap, HashMap};
use std::sync::{Mutex, PoisonError};
use std::time::SystemTime;

use oneiron::llm::ResourceClass;

/// What a worker declared it would hold on its device, in MiB, part by part.
/// A part the declaration left out is `None`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DeclaredEnvelope {
    pub weights_mib: Option<u64>,
    pub kv_mib: Option<u64>,
    pub workspace_mib: Option<u64>,
    /// The extra a load holds for a moment beyond what stays resident.
    pub load_transient_mib: Option<u64>,
}

impl DeclaredEnvelope {
    /// Every part summed, when every part was declared.
    #[must_use]
    pub fn total_mib(&self) -> Option<u64> {
        [
            self.weights_mib,
            self.kv_mib,
            self.workspace_mib,
            self.load_transient_mib,
        ]
        .into_iter()
        .try_fold(0_u64, |total, part| {
            part.map(|part| total.saturating_add(part))
        })
    }
}

/// Incremental memory one call adds after its worker's weights and KV pool
/// have been charged once. No part is a measurement of total device use.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct WorkEnvelope {
    pub kv_increment_mib: Option<u64>,
    pub workspace_mib: Option<u64>,
}

impl WorkEnvelope {
    /// The qualified total, when both incremental parts were declared.
    #[must_use]
    pub fn total_mib(&self) -> Option<u64> {
        self.kv_increment_mib.and_then(|kv| {
            self.workspace_mib
                .map(|workspace| kv.saturating_add(workspace))
        })
    }

    /// The declared parts summed for a wire grant. An incomplete envelope is
    /// not qualified for a known-capacity reservation; unknown-capacity work
    /// still admits and records the parts it has.
    #[must_use]
    pub fn known_total_mib(&self) -> u64 {
        self.kv_increment_mib
            .unwrap_or(0)
            .saturating_add(self.workspace_mib.unwrap_or(0))
    }
}

/// Where a resident-memory figure came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResidentSource {
    /// The worker's own report of what it holds on the device.
    WorkerReport,
    /// The device's own accounting of the worker's process.
    DeviceQuery,
}

/// What a worker held on its device when it was measured.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResidentReport {
    pub resident_mib: u64,
    pub source: ResidentSource,
    pub observed_at: SystemTime,
}

/// One worker's row: its declaration, and its last measurement if any.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceRow {
    pub worker_id: String,
    pub declared: DeclaredEnvelope,
    pub resident: Option<ResidentReport>,
    /// The class budget this worker's steady reservation counts against.
    pub class: Option<ResourceClass>,
    /// False records work sharing the device without this host's mediation.
    pub mediated: bool,
}

/// The ledger as it stands: each row by worker id, and the totals, each
/// known only when every contributing row's part is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceSnapshot {
    pub device: String,
    pub capacity_mib: Option<u64>,
    pub rows: Vec<DeviceRow>,
    pub declared_mib: Option<u64>,
    pub resident_mib: Option<u64>,
    pub holds_mib: u64,
    pub class_used_mib: Option<HashMap<ResourceClass, u64>>,
}

/// The result of an atomic admission reservation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TryReserveOutcome {
    Admitted,
    AdmittedUnknown,
    NoRoom,
}

#[derive(Debug, Clone, Copy)]
struct DeviceHold {
    mib: u64,
    class: Option<ResourceClass>,
}

#[derive(Debug)]
struct LedgerState {
    capacity_mib: Option<u64>,
    rows: BTreeMap<String, DeviceRow>,
    holds: BTreeMap<String, DeviceHold>,
    class_budgets_mib: HashMap<ResourceClass, u64>,
}

/// One physical device's ledger, shared by the supervisors of the workers
/// on it. One lock covers every committed byte so check-and-reserve cannot
/// race a report, a transient hold, or another grant.
#[derive(Debug)]
pub struct DeviceLedger {
    device: String,
    state: Mutex<LedgerState>,
}

impl DeviceLedger {
    /// An empty ledger for `device`, whose capacity is `capacity_mib` when a
    /// source gave it.
    #[must_use]
    pub fn new(device: impl Into<String>, capacity_mib: Option<u64>) -> Self {
        Self {
            device: device.into(),
            state: Mutex::new(LedgerState {
                capacity_mib,
                rows: BTreeMap::new(),
                holds: BTreeMap::new(),
                class_budgets_mib: HashMap::new(),
            }),
        }
    }

    /// The device's name.
    #[must_use]
    pub fn device(&self) -> &str {
        &self.device
    }

    /// Sets the device's measured capacity. `None` means unknown and admits
    /// under the R4 ruling; it never means zero.
    pub fn set_capacity(&self, capacity_mib: Option<u64>) {
        self.state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .capacity_mib = capacity_mib;
    }

    /// The capacity currently known to this ledger.
    #[must_use]
    pub fn capacity(&self) -> Option<u64> {
        self.state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .capacity_mib
    }

    /// Sets or removes a class's steady-plus-incremental MiB budget.
    pub fn set_class_budget(&self, class: ResourceClass, budget_mib: Option<u64>) {
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        match budget_mib {
            Some(budget) => state.class_budgets_mib.insert(class, budget),
            None => state.class_budgets_mib.remove(&class),
        };
    }

    /// Records that `worker_id` runs on this device with `declared`. A row
    /// already there keeps its measurement, class and mediation evidence.
    pub fn reserve(&self, worker_id: &str, declared: DeclaredEnvelope) {
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        reserve_row(&mut state, worker_id, declared, None);
    }

    /// Records that `worker_id` no longer runs here: its row goes. Work and
    /// transient holds remain until their own owners release or reap them.
    pub fn release(&self, worker_id: &str) {
        self.state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .rows
            .remove(worker_id);
    }

    /// Records what `worker_id` holds now, as `report` measured it. A worker
    /// with no row gets one with nothing declared.
    pub fn report(&self, worker_id: &str, report: ResidentReport) {
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        state
            .rows
            .entry(worker_id.to_owned())
            .or_insert_with(|| empty_row(worker_id))
            .resident = Some(report);
    }

    /// Forgets one stale measurement without erasing any declaration, hold,
    /// grant, class charge, or mediation commitment.
    pub fn invalidate_report(&self, worker_id: &str) {
        if let Some(row) = self
            .state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .rows
            .get_mut(worker_id)
        {
            row.resident = None;
        }
    }

    /// Records unmediated shared-device work. It is admitted and visible,
    /// never refused; a device query may supply its resident measurement.
    pub fn note_unmediated(&self, worker_id: &str, resident_mib: Option<u64>) {
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        let row = state.rows.entry(worker_id.to_owned()).or_insert_with(|| {
            let mut row = empty_row(worker_id);
            row.mediated = false;
            row
        });
        row.mediated = false;
        if let Some(resident_mib) = resident_mib {
            row.resident = Some(ResidentReport {
                resident_mib,
                source: ResidentSource::DeviceQuery,
                observed_at: SystemTime::now(),
            });
        }
    }

    /// Records that `holder` takes `mib` on this device for a moment, beyond
    /// every row: a later hold by the same holder replaces it.
    pub fn hold(&self, holder: &str, mib: u64) {
        self.state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .holds
            .insert(holder.to_owned(), DeviceHold { mib, class: None });
    }

    /// Atomically checks capacity and class budget and records incremental
    /// work only on fit. Unknown capacity always admits and records.
    pub fn try_reserve(
        &self,
        holder: &str,
        envelope: &WorkEnvelope,
        class: ResourceClass,
    ) -> TryReserveOutcome {
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        if state.holds.contains_key(holder) {
            return TryReserveOutcome::NoRoom;
        }
        let known_capacity = state.capacity_mib.is_some();
        if known_capacity {
            let Some(mib) = envelope.total_mib() else {
                return TryReserveOutcome::NoRoom;
            };
            if !class_fits(&state, class, mib)
                || room_mib_locked(&state, super::inference_admission::DEVICE_HEADROOM_MIB)
                    .is_none_or(|room| room < mib)
            {
                return TryReserveOutcome::NoRoom;
            }
        }
        state.holds.insert(
            holder.to_owned(),
            DeviceHold {
                mib: envelope.known_total_mib(),
                class: Some(class),
            },
        );
        if known_capacity {
            TryReserveOutcome::Admitted
        } else {
            TryReserveOutcome::AdmittedUnknown
        }
    }

    /// Whether this exact transient or incremental hold still exists.
    #[must_use]
    pub fn has_hold(&self, holder: &str) -> bool {
        self.state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .holds
            .contains_key(holder)
    }

    /// Records that `holder`'s transient or incremental hold ended.
    pub fn release_hold(&self, holder: &str) {
        self.state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .holds
            .remove(holder);
    }

    /// Promotes a successful load to its steady row and drops its transient
    /// load hold in the same critical section. Load-transient bytes are not
    /// charged again in the steady declaration.
    pub fn mark_loaded(
        &self,
        worker_id: &str,
        mut declared: DeclaredEnvelope,
        class: ResourceClass,
        load_holder: &str,
    ) {
        declared.load_transient_mib = Some(0);
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        reserve_row(&mut state, worker_id, declared, Some(class));
        state.holds.remove(load_holder);
    }

    /// What this device has left past `headroom_mib`, in MiB. `None` when
    /// capacity or a committed row is unknown, and `Some(0)` under pressure.
    #[must_use]
    pub fn room_mib(&self, headroom_mib: u64) -> Option<u64> {
        let state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        room_mib_locked(&state, headroom_mib)
    }

    /// Every row and hold, with totals only where every contributing part is
    /// known. Copies state; never probes a device or a worker.
    #[must_use]
    pub fn snapshot(&self) -> DeviceSnapshot {
        let state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        let rows: Vec<DeviceRow> = state.rows.values().cloned().collect();
        let declared_mib = rows.iter().try_fold(0_u64, |total, row| {
            row.declared
                .total_mib()
                .map(|mib| total.saturating_add(mib))
        });
        let resident_mib = rows.iter().try_fold(0_u64, |total, row| {
            row.resident
                .map(|resident| total.saturating_add(resident.resident_mib))
        });
        DeviceSnapshot {
            device: self.device.clone(),
            capacity_mib: state.capacity_mib,
            rows,
            declared_mib,
            resident_mib,
            holds_mib: state
                .holds
                .values()
                .fold(0_u64, |total, hold| total.saturating_add(hold.mib)),
            class_used_mib: class_used_mib(&state),
        }
    }
}

fn empty_row(worker_id: &str) -> DeviceRow {
    DeviceRow {
        worker_id: worker_id.to_owned(),
        declared: DeclaredEnvelope::default(),
        resident: None,
        class: None,
        mediated: true,
    }
}

fn reserve_row(
    state: &mut LedgerState,
    worker_id: &str,
    declared: DeclaredEnvelope,
    class: Option<ResourceClass>,
) {
    let row = state.rows.entry(worker_id.to_owned()).or_insert_with(|| {
        let mut row = empty_row(worker_id);
        row.class = class;
        row
    });
    row.declared = declared;
    if class.is_some() {
        row.class = class;
    }
}

fn row_mib(row: &DeviceRow) -> Option<u64> {
    let declared = row.declared.total_mib();
    let resident = row.resident.map(|resident| resident.resident_mib);
    match (declared, resident) {
        (Some(declared), Some(resident)) => Some(declared.max(resident)),
        (Some(size), None) | (None, Some(size)) => Some(size),
        (None, None) => None,
    }
}

fn committed_mib(state: &LedgerState) -> Option<u64> {
    let rows = state
        .rows
        .values()
        .try_fold(0_u64, |total, row| match row_mib(row) {
            Some(mib) => Some(total.saturating_add(mib)),
            None if !row.mediated => Some(total),
            None => None,
        })?;
    Some(
        state
            .holds
            .values()
            .fold(rows, |total, hold| total.saturating_add(hold.mib)),
    )
}

fn room_mib_locked(state: &LedgerState, headroom_mib: u64) -> Option<u64> {
    Some(
        state
            .capacity_mib?
            .saturating_sub(committed_mib(state)?)
            .saturating_sub(headroom_mib),
    )
}

fn class_used_mib(state: &LedgerState) -> Option<HashMap<ResourceClass, u64>> {
    let mut used = HashMap::new();
    for row in state.rows.values() {
        if let Some(class) = row.class {
            let Some(mib) = row_mib(row) else {
                if row.mediated {
                    return None;
                }
                continue;
            };
            let total = used.entry(class).or_insert(0_u64);
            *total = total.saturating_add(mib);
        }
    }
    for hold in state.holds.values() {
        if let Some(class) = hold.class {
            let total = used.entry(class).or_insert(0_u64);
            *total = total.saturating_add(hold.mib);
        }
    }
    Some(used)
}

fn class_fits(state: &LedgerState, class: ResourceClass, additional_mib: u64) -> bool {
    let Some(budget) = state.class_budgets_mib.get(&class) else {
        return true;
    };
    class_used_mib(state).is_some_and(|used| {
        used.get(&class)
            .copied()
            .unwrap_or(0)
            .saturating_add(additional_mib)
            <= *budget
    })
}
