//! One whole pre-dispatch reservation, rebuilt only after its phase unwinds.

use super::render::PdfPreparationError;
use oneiron_docedit::resource::{ResourceAllocation, ResourceRefusal, Resources};
use std::sync::{Arc, Mutex, PoisonError};

type Result<T> = std::result::Result<T, PdfPreparationError>;

#[derive(Clone)]
pub struct EsignInputBudget(Arc<Budget>);

struct Budget {
    resources: Resources,
    planned: u64,
    used: Mutex<Usage>,
    allocation: Mutex<Box<dyn ResourceAllocation>>,
}

#[derive(Default)]
struct Usage {
    bytes: u64,
    measured: u64,
}

fn lock<T>(value: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    value.lock().unwrap_or_else(PoisonError::into_inner)
}

fn resource_error(error: ResourceRefusal) -> PdfPreparationError {
    match error {
        ResourceRefusal::MemoryFloor { needed, available } => {
            PdfPreparationError::MemoryFloor { needed, available }
        }
        ResourceRefusal::Deadline => PdfPreparationError::Deadline,
    }
}

impl EsignInputBudget {
    /// `measured` is the actual requested prefix from the preceding build;
    /// reservation-step rounding is never a measured allocation.
    pub fn new(resources: &Resources, planned: u64, measured: u64) -> Result<Self> {
        resources.checkpoint().map_err(resource_error)?;
        let mut allocation = resources.allocation();
        allocation
            .grow(planned, measured.min(planned))
            .map_err(resource_error)?;
        Ok(Self(Arc::new(Budget {
            resources: resources.clone(),
            planned,
            used: Mutex::new(Usage::default()),
            allocation: Mutex::new(allocation),
        })))
    }

    /// Admit the full next allocation while its old allocation still lives.
    /// No underlying resource growth or wait occurs here.
    pub fn take(&self, bytes: u64) -> Result<()> {
        self.take_estimate(bytes, bytes)
    }

    fn take_estimate(&self, bytes: u64, measured: u64) -> Result<()> {
        self.0.resources.checkpoint().map_err(resource_error)?;
        let mut used = lock(&self.0.used);
        let needed = used
            .bytes
            .checked_add(bytes)
            .ok_or(PdfPreparationError::Limit)?;
        let measured = used
            .measured
            .checked_add(measured.min(bytes))
            .ok_or(PdfPreparationError::Limit)?;
        if needed > self.0.planned {
            return Err(PdfPreparationError::InputReservation { needed, measured });
        }
        *used = Usage {
            bytes: needed,
            measured,
        };
        Ok(())
    }

    /// Return bytes only after their actual buffer or region has been freed.
    pub fn release(&self, bytes: u64) {
        self.release_estimate(bytes, bytes);
    }

    fn release_estimate(&self, bytes: u64, measured: u64) {
        let mut used = lock(&self.0.used);
        used.bytes = used.bytes.saturating_sub(bytes);
        used.measured = used.measured.saturating_sub(measured.min(bytes));
    }

    fn extra_capacity(&self, bytes: u64) {
        let mut used = lock(&self.0.used);
        used.bytes = used.bytes.saturating_add(bytes);
        used.measured = used.measured.saturating_add(bytes);
    }

    /// Settle an allocator's actual capacity without another resource wait.
    /// An excess requests a full rebuild before dispatch.
    pub fn allocated(&self, reserved: u64, actual: u64) -> Result<()> {
        if actual < reserved {
            self.release(reserved - actual);
        } else {
            self.extra_capacity(actual - reserved);
        }
        self.take(0)
    }

    /// Call only after the parser/model has dropped: the remaining byte
    /// vectors and lent regions now have their actual capacities recorded.
    pub fn materialized(&self) -> Result<()> {
        self.take(0)?;
        let used = lock(&self.0.used).bytes;
        lock(&self.0.allocation).materialized(used);
        Ok(())
    }
}

/// A suffix buffer. A finished buffer's charge stays with the whole input;
/// temporary object bodies return theirs when they are actually freed.
pub(super) struct InputBytes {
    bytes: Vec<u8>,
    budget: Option<EsignInputBudget>,
    charged: u64,
}

impl InputBytes {
    pub(super) fn new(budget: Option<&EsignInputBudget>) -> Self {
        Self {
            bytes: Vec::new(),
            budget: budget.cloned(),
            charged: 0,
        }
    }

    pub(super) fn reserve(&mut self, additional: usize) -> Result<()> {
        let needed = self
            .bytes
            .len()
            .checked_add(additional)
            .ok_or(PdfPreparationError::Limit)?;
        if needed <= self.bytes.capacity() {
            return Ok(());
        }
        let target = u64::try_from(needed).map_err(|_| PdfPreparationError::Limit)?;
        if let Some(budget) = &self.budget {
            budget.take(target)?;
        }
        if self
            .bytes
            .try_reserve_exact(needed - self.bytes.len())
            .is_err()
        {
            if let Some(budget) = &self.budget {
                budget.release(target);
            }
            return Err(PdfPreparationError::Limit);
        }
        let actual = self.bytes.capacity() as u64;
        if let Some(budget) = &self.budget {
            budget.release(self.charged);
            budget.extra_capacity(actual.saturating_sub(target));
        }
        self.charged = actual;
        Ok(())
    }

    pub(super) fn extend_from_slice(&mut self, bytes: &[u8]) -> Result<()> {
        self.reserve(bytes.len())?;
        self.bytes.extend_from_slice(bytes);
        Ok(())
    }

    pub(super) fn push(&mut self, byte: u8) -> Result<()> {
        self.reserve(1)?;
        self.bytes.push(byte);
        Ok(())
    }

    pub(super) fn zeros(&mut self, count: usize) -> Result<()> {
        self.reserve(count)?;
        self.bytes.resize(self.bytes.len() + count, b'0');
        Ok(())
    }

    pub(super) fn len(&self) -> usize {
        self.bytes.len()
    }

    pub(super) fn finish(mut self) -> Vec<u8> {
        self.charged = 0;
        std::mem::take(&mut self.bytes)
    }
}

impl std::ops::Deref for InputBytes {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.bytes
    }
}
impl std::ops::DerefMut for InputBytes {
    fn deref_mut(&mut self) -> &mut [u8] {
        &mut self.bytes
    }
}
impl Drop for InputBytes {
    fn drop(&mut self) {
        // Free the actual buffer before returning its charge.
        drop(std::mem::take(&mut self.bytes));
        if let Some(budget) = &self.budget {
            budget.release(self.charged);
        }
    }
}

/// Keeps the original typed cause while actually cancelling the parser to
/// unwind it. Cancelled without this marker is never a reservation request.
pub(super) struct PoolAdmission {
    budget: EsignInputBudget,
    held: Mutex<Usage>,
    refusal: Mutex<Option<PdfPreparationError>>,
    decoded: std::sync::atomic::AtomicU64,
}

impl PoolAdmission {
    pub(super) fn new(budget: &EsignInputBudget) -> Self {
        Self {
            budget: budget.clone(),
            held: Mutex::new(Usage::default()),
            refusal: Mutex::new(None),
            decoded: std::sync::atomic::AtomicU64::new(0),
        }
    }
    pub(super) fn take_refusal(&self) -> Option<PdfPreparationError> {
        lock(&self.refusal).take()
    }
    pub(super) fn max_decoded(&self) -> u64 {
        self.decoded.load(std::sync::atomic::Ordering::Relaxed)
    }

    fn admit_bytes(
        &self,
        bytes: usize,
        measured: usize,
    ) -> std::result::Result<(), lopdf::DecodeAdmissionError> {
        let measured = measured.min(bytes) as u64;
        match self.budget.take_estimate(bytes as u64, measured) {
            Ok(()) => {
                let mut held = lock(&self.held);
                held.bytes = held.bytes.saturating_add(bytes as u64);
                held.measured = held.measured.saturating_add(measured);
                Ok(())
            }
            Err(error) => {
                let mut refusal = lock(&self.refusal);
                if refusal.is_none() {
                    *refusal = Some(error);
                }
                Err(lopdf::DecodeAdmissionError::Cancelled)
            }
        }
    }
}

impl lopdf::DecodeAdmission for PoolAdmission {
    fn admit(&self, bytes: usize) -> std::result::Result<(), lopdf::DecodeAdmissionError> {
        self.admit_bytes(bytes, bytes)
    }
    fn admit_estimate(
        &self,
        bytes: usize,
        measured: usize,
    ) -> std::result::Result<(), lopdf::DecodeAdmissionError> {
        self.admit_bytes(bytes, measured)
    }
    fn allocated(
        &self,
        reserved: usize,
        actual: usize,
    ) -> std::result::Result<(), lopdf::DecodeAdmissionError> {
        {
            let mut held = lock(&self.held);
            held.bytes = held
                .bytes
                .saturating_sub(reserved as u64)
                .saturating_add(actual as u64);
            held.measured = held
                .measured
                .saturating_sub(reserved as u64)
                .saturating_add(actual as u64);
        }
        self.budget
            .allocated(reserved as u64, actual as u64)
            .map_err(|error| {
                let mut refusal = lock(&self.refusal);
                if refusal.is_none() {
                    *refusal = Some(error);
                }
                lopdf::DecodeAdmissionError::Cancelled
            })
    }
    fn release(&self, bytes: usize) {
        // The native release channel returns actual Vec allocations. Map
        // and codec-state estimates stay until this parser scope drops.
        let mut held = lock(&self.held);
        let bytes = (bytes as u64).min(held.bytes);
        let measured = bytes.min(held.measured);
        held.bytes -= bytes;
        held.measured -= measured;
        self.budget.release_estimate(bytes, measured);
    }
    fn decoded(&self, bytes: usize) {
        self.decoded
            .fetch_max(bytes as u64, std::sync::atomic::Ordering::Relaxed);
    }
}
impl Drop for PoolAdmission {
    fn drop(&mut self) {
        let held = self.held.get_mut().unwrap_or_else(PoisonError::into_inner);
        self.budget.release_estimate(held.bytes, held.measured);
    }
}
