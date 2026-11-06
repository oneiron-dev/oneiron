//! Scoped copies of the existing meter's prepared model-call settlements.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, PoisonError};

use oneiron::EntityId;

use super::VaultUsage;

type Rows = Arc<Mutex<Vec<Vec<u8>>>>;
pub(super) type PriceCaptures = BTreeMap<EntityId, BTreeMap<EntityId, Rows>>;

/// A capture belongs to one run and is removed even when its caller unwinds.
/// It does not change, replay or wait for the native ledger writes.
pub(crate) struct ModelPriceCapture {
    meter: Arc<VaultUsage>,
    instance: EntityId,
    id: EntityId,
    rows: Rows,
}

impl ModelPriceCapture {
    pub(crate) fn finish(self) -> Vec<Vec<u8>> {
        self.detach();
        let rows = {
            let mut kept = self.rows.lock().unwrap_or_else(PoisonError::into_inner);
            std::mem::take(&mut *kept)
        };
        rows
    }

    fn detach(&self) {
        let mut captures = self
            .meter
            .price_captures
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if let Some(run) = captures.get_mut(&self.instance) {
            run.remove(&self.id);
            if run.is_empty() {
                captures.remove(&self.instance);
            }
        }
    }
}

impl Drop for ModelPriceCapture {
    fn drop(&mut self) {
        self.detach();
    }
}

impl VaultUsage {
    /// Captures this run's native prepared settlements until the guard drops.
    /// Callers must match the captured event to their actual physical call.
    pub(crate) fn capture_model_prices(self: &Arc<Self>, instance: EntityId) -> ModelPriceCapture {
        let rows = Arc::new(Mutex::new(Vec::new()));
        let id = EntityId::now();
        self.price_captures
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .entry(instance)
            .or_default()
            .insert(id, Arc::clone(&rows));
        ModelPriceCapture {
            meter: Arc::clone(self),
            instance,
            id,
            rows,
        }
    }

    pub(super) fn capture_prepared_price(&self, instance: EntityId, raw: &[u8]) {
        let captures = self
            .price_captures
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if let Some(run) = captures.get(&instance) {
            for rows in run.values() {
                rows.lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .push(raw.to_vec());
            }
        }
    }
}
