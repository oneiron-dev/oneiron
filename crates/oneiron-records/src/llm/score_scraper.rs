//! Moved from `crates/oneiron/src/llm/score_scraper.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_base::error::Result;
use oneiron_model::llm::ModelId;
use oneiron_verb_wire::llm::registry::invalid;
use serde::Deserialize;
use serde::Serialize;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScoreSourceConfig {
    pub id: String,
    pub url: String,
    pub rows_pointer: String,
    pub model_pointer: String,
    pub score_pointer: String,
    pub benchmark: String,
    /// External model spelling to the registry's revisioned identity. Data only.
    pub model_bindings: std::collections::BTreeMap<String, ModelId>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScoreScraperConfig {
    pub version: u8,
    pub fetch_interval_secs: u64,
    pub sources: Vec<ScoreSourceConfig>,
}

impl ScoreScraperConfig {
    pub fn validate(&self) -> Result<()> {
        if self.version != 1 || self.fetch_interval_secs == 0 || self.sources.is_empty() {
            return Err(invalid("invalid score scraper schedule"));
        }
        let mut ids = std::collections::BTreeSet::new();
        for source in &self.sources {
            if source.id.trim().is_empty()
                || source.id.len() > 128
                || !ids.insert(&source.id)
                || !source.url.starts_with("https://")
                || source.benchmark.trim().is_empty()
                || source.benchmark.len() > 128
                || source.model_bindings.is_empty()
            {
                return Err(invalid("invalid benchmark source"));
            }
        }
        Ok(())
    }
}
