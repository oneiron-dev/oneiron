//! Config-driven benchmark scraping. Fetch transport is injected; results only nominate.
use super::{
    ModelId,
    registry::{ModelScoreDiff, ScoreObservation, ScoreSnapshot, invalid},
};
use crate::{Vault, error::Result};
use serde::{Deserialize, Serialize};
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
pub trait ScoreFetch {
    fn fetch(&mut self, source: &ScoreSourceConfig) -> Result<serde_json::Value>;
}
pub struct ScoreScraper<F> {
    config: ScoreScraperConfig,
    fetcher: F,
    last_fetch: Option<u64>,
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
impl<F: ScoreFetch> ScoreScraper<F> {
    pub fn new(config: ScoreScraperConfig, fetcher: F) -> Result<Self> {
        config.validate()?;
        Ok(Self {
            config,
            fetcher,
            last_fetch: None,
        })
    }
    pub fn refresh(&mut self, vault: &Vault, now: u64) -> Result<Vec<ModelScoreDiff>> {
        if self
            .last_fetch
            .is_some_and(|last| now.saturating_sub(last) < self.config.fetch_interval_secs)
        {
            return Ok(Vec::new());
        }
        let mut diffs = Vec::new();
        for source in &self.config.sources {
            let document = self.fetcher.fetch(source)?;
            let rows = document
                .pointer(&source.rows_pointer)
                .and_then(serde_json::Value::as_array)
                .ok_or_else(|| invalid("benchmark rows missing"))?;
            let mut observations = Vec::new();
            for row in rows {
                let name = row
                    .pointer(&source.model_pointer)
                    .and_then(serde_json::Value::as_str)
                    .ok_or_else(|| invalid("benchmark model missing"))?;
                let Some(model) = source.model_bindings.get(name) else {
                    continue;
                };
                let score = row
                    .pointer(&source.score_pointer)
                    .and_then(serde_json::Value::as_f64)
                    .ok_or_else(|| invalid("benchmark score missing"))?;
                observations.push(ScoreObservation {
                    model: model.clone(),
                    benchmark: source.benchmark.clone(),
                    score,
                });
            }
            diffs.extend(vault.apply_model_scores(&ScoreSnapshot {
                source: source.id.clone(),
                fetched_at: now,
                observations,
            })?);
        }
        self.last_fetch = Some(now);
        Ok(diffs)
    }
    /// Scores nominate a candidate identity. No answerer binding or trial door
    /// is present in this type, so scraping cannot switch a question's answerer.
    pub fn nominate(
        &self,
        vault: &Vault,
        source: &str,
        benchmark: &str,
    ) -> Result<Option<ModelId>> {
        Ok(vault
            .model_registry_rows()?
            .into_iter()
            .filter_map(|row| {
                row.scores
                    .get(source)
                    .and_then(|s| s.get(benchmark))
                    .copied()
                    .map(|score| (score, row.catalog.model))
            })
            .max_by(|a, b| a.0.total_cmp(&b.0))
            .map(|(_, model)| model))
    }
}
