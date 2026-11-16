//! Moved from `crates/oneiron/src/llm/registry/backend.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::llm::registry::ModelRegistryRow;
use oneiron_base::error::Result;
pub use oneiron_verb_wire::llm::registry::backend::ModelBackendPin;
pub use oneiron_verb_wire::llm::registry::backend::ModelCostReceipt;
pub use oneiron_verb_wire::llm::registry::backend::PricedModelBackend;
pub use oneiron_verb_wire::llm::registry::backend::catalog_usage_cost;
use oneiron_verb_wire::llm::registry::invalid;

impl ModelRegistryRow {
    /// Hosts register serving offers under catalog.metadata.backends. No backend
    /// is inferred from an upstream model name, and no quality is inferred here.
    pub fn backends(&self) -> Result<Vec<PricedModelBackend>> {
        let rows: Vec<PricedModelBackend> = self
            .catalog
            .metadata
            .get("backends")
            .map(|value| serde_json::from_value(value.clone()))
            .transpose()
            .map_err(|error| invalid(error.to_string()))?
            .unwrap_or_default();
        let mut seen = std::collections::BTreeSet::new();
        for row in &rows {
            row.validate()?;
            if row.pin.model != self.catalog.model
                || row.pin.context_window_tokens > self.catalog.context_window_tokens
                || !seen.insert(&row.pin.backend)
            {
                return Err(invalid("invalid or duplicate registry backend"));
            }
        }
        Ok(rows)
    }

    pub fn backend(&self, pin: &ModelBackendPin) -> Result<PricedModelBackend> {
        self.backends()?
            .into_iter()
            .find(|row| &row.pin == pin)
            .ok_or_else(|| invalid("model backend is not registered at this serving revision"))
    }
}
