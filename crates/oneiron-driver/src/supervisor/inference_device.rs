//! One physical device's memory ledger (DESIGN-V2 §7, INFERENCE R2): what
//! each worker on it declared it would hold, and what each last reported it
//! holds, with where that report came from and when.
//!
//! Accounting only. Nothing here admits, refuses, waits for or unloads
//! anything, and nothing reads it to decide: the admission queue that will
//! is R4's. A declared envelope is a plan, never a measurement, and it is
//! never shown as resident memory. A size no source gave stays `None`, never
//! zero, and a total over rows is known only when every row's part is. The
//! ledger promises no cache owner, affinity or residency (HOLD 8319).
use std::collections::BTreeMap;
use std::sync::{Mutex, PoisonError};
use std::time::SystemTime;

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
}

/// The ledger as it stands: each row by worker id, and the totals, each
/// known only when every row's part is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceSnapshot {
    pub device: String,
    pub capacity_mib: Option<u64>,
    pub rows: Vec<DeviceRow>,
    pub declared_mib: Option<u64>,
    pub resident_mib: Option<u64>,
}

/// One physical device's ledger, shared by the supervisors of the workers
/// on it.
#[derive(Debug)]
pub struct DeviceLedger {
    device: String,
    capacity_mib: Option<u64>,
    rows: Mutex<BTreeMap<String, DeviceRow>>,
}

impl DeviceLedger {
    /// An empty ledger for `device`, whose capacity is `capacity_mib` when a
    /// source gave it.
    #[must_use]
    pub fn new(device: impl Into<String>, capacity_mib: Option<u64>) -> Self {
        Self {
            device: device.into(),
            capacity_mib,
            rows: Mutex::new(BTreeMap::new()),
        }
    }

    /// The device's name.
    #[must_use]
    pub fn device(&self) -> &str {
        &self.device
    }

    /// Records that `worker_id` runs on this device with `declared`. A row
    /// already there keeps its last measurement until the next report.
    /// Accounting only: it never refuses.
    pub fn reserve(&self, worker_id: &str, declared: DeclaredEnvelope) {
        let mut rows = self.rows.lock().unwrap_or_else(PoisonError::into_inner);
        rows.entry(worker_id.to_owned())
            .and_modify(|row| row.declared = declared)
            .or_insert_with(|| DeviceRow {
                worker_id: worker_id.to_owned(),
                declared,
                resident: None,
            });
    }

    /// Records that `worker_id` no longer runs here: its row goes.
    pub fn release(&self, worker_id: &str) {
        self.rows
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(worker_id);
    }

    /// Records what `worker_id` holds now, as `report` measured it. A worker
    /// with no row gets one with nothing declared.
    pub fn report(&self, worker_id: &str, report: ResidentReport) {
        let mut rows = self.rows.lock().unwrap_or_else(PoisonError::into_inner);
        rows.entry(worker_id.to_owned())
            .or_insert_with(|| DeviceRow {
                worker_id: worker_id.to_owned(),
                declared: DeclaredEnvelope::default(),
                resident: None,
            })
            .resident = Some(report);
    }

    /// Every row, by worker id, with the totals.
    #[must_use]
    pub fn snapshot(&self) -> DeviceSnapshot {
        let rows: Vec<DeviceRow> = self
            .rows
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .values()
            .cloned()
            .collect();
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
            capacity_mib: self.capacity_mib,
            rows,
            declared_mib,
            resident_mib,
        }
    }
}
