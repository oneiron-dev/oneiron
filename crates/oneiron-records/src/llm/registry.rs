//! Moved from `crates/oneiron/src/llm/registry.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use crate::llm::registry::description::DescriptionClass;
pub use crate::llm::registry::description::DescriptionContribution;
pub use crate::llm::registry::description::ModelDescription;
use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;
use oneiron_model::llm::LlmCatalogEntry;
pub use oneiron_store::model_description_rows::ModelWireFormat;
pub use oneiron_store::model_score_diff::ModelScoreDiff;
pub use oneiron_verb_wire::llm::registry::ScoreObservation;
pub use oneiron_verb_wire::llm::registry::ScoreSnapshot;
pub use oneiron_verb_wire::llm::registry::backend::ModelBackendPin;
pub use oneiron_verb_wire::llm::registry::backend::ModelCostReceipt;
pub use oneiron_verb_wire::llm::registry::backend::PricedModelBackend;
pub use oneiron_verb_wire::llm::registry::backend::catalog_usage_cost;
pub(super) use oneiron_verb_wire::llm::registry::invalid;
use oneiron_verb_wire::llm::registry::price;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ModelRegistryRow {
    pub version: u8,
    pub wire: ModelWireFormat,
    pub catalog: LlmCatalogEntry,
    #[serde(default)]
    pub scores: BTreeMap<String, BTreeMap<String, f64>>,
    #[serde(default)]
    pub fetched_at: BTreeMap<String, u64>,
    /// Tokens this model's tokenizer counts per o200k token of the same
    /// text, measured by the host on a fixed prompt-shaped passage (OF-577);
    /// `None` until measured. A row an earlier host measured holds the ratio
    /// of one fixed prose passage here and no
    /// [`Self::answer_tokens_per_o200k`]; the host measures it again. A
    /// refresh that changes the catalog entry clears it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tokens_per_o200k: Option<f64>,
    /// The same ratio on a fixed answer-shaped passage, measured and stored
    /// together with [`Self::tokens_per_o200k`] (ARCH-0053:341): a training
    /// offer scales a seat's output tokens by it and its prompt tokens by
    /// the other. `None` until measured; a refresh that changes the catalog
    /// entry clears it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub answer_tokens_per_o200k: Option<f64>,
    /// When the model's provider retired it (FIX 4472): a pack refresh that
    /// no longer ships it, or the host's own mark. The row is kept, never
    /// deleted, so the agent lists and receipts that name it still read it;
    /// no seat is born on it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stale_since: Option<u64>,
    /// The rows this row's entry, scores and marks were derived from (FIX
    /// 5760): the installed pack's source for a row the pack shipped, and
    /// each score snapshot's evidence. `None`, unknown, for a row whose
    /// producer named none, such as one the owner or a mesh peer wrote.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_rows: Option<Vec<EntityId>>,
}

impl ModelRegistryRow {
    /// Whether the model's provider retired it ([`Self::stale_since`]).
    #[must_use]
    pub fn is_stale(&self) -> bool {
        self.stale_since.is_some()
    }

    /// Descriptions stay alongside the model entry; older host-created rows have no evidence.
    pub fn description(&self) -> Result<ModelDescription> {
        self.catalog.metadata.get("description").map_or_else(
            || Ok(ModelDescription::default()),
            |value| serde_json::from_value(value.clone()).map_err(|e| invalid(e.to_string())),
        )
    }

    pub fn validate(&self) -> Result<()> {
        self.description()?.validate()?;
        self.backends()?;
        let entry = &self.catalog;
        if self.version != 1
            || entry.display_name.trim().is_empty()
            || entry.context_window_tokens == 0
            || entry.max_output_tokens == Some(0)
            || [self.tokens_per_o200k, self.answer_tokens_per_o200k]
                .into_iter()
                .flatten()
                .any(|ratio| !(ratio.is_finite() && ratio > 0.0))
        {
            return Err(invalid("invalid model registry row"));
        }
        let cost = entry
            .cost
            .as_ref()
            .ok_or_else(|| invalid("model price per million is required"))?;
        if !price(&cost.input_per_million)
            || !price(&cost.output_per_million)
            || cost
                .cache_read_per_million
                .as_ref()
                .is_some_and(|v| !price(v))
            || cost
                .cache_write_per_million
                .as_ref()
                .is_some_and(|v| !price(v))
        {
            return Err(invalid("invalid per-million model price"));
        }
        if self.scores.iter().any(|(source, values)| {
            source.trim().is_empty()
                || values
                    .iter()
                    .any(|(name, score)| name.trim().is_empty() || !score.is_finite())
        }) {
            return Err(invalid("invalid registry benchmark score"));
        }
        Ok(())
    }
}
pub mod backend;
pub mod description;
