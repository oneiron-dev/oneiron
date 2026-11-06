//! The completed Big reading's catalog price, not the seat's requested route.

use oneiron::llm::registry::catalog_usage_cost;
use oneiron::{LlmUsage, ModelId};

use super::BigModel;

impl BigModel {
    pub(super) fn completion_cost(&self, model: &ModelId, usage: &LlmUsage) -> Option<f64> {
        let row = self.vault.model_registry_row(model).ok()??;
        let price = row.catalog.cost.as_ref()?;
        price.currency.as_ref()?;
        // These replies read a prompt and generate an answer. Some adapters use
        // zero for an unreported counter; that is not a measured free call.
        if usage.input.total == 0 || usage.output.total == 0 {
            return None;
        }
        // One DecisionCall reads one typed question over one state. Paired
        // readings share that measurement, as in the held-out trial receipts.
        let per_thousand = catalog_usage_cost(price, usage).ok()? * 1_000.0;
        per_thousand.is_finite().then_some(per_thousand)
    }
}
