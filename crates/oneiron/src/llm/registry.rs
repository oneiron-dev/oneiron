//! Vault-persisted, priced model catalogs. Scores are evidence, never routing authority.
use super::{LlmCatalogEntry, ModelId};
use crate::side_table::{self, LegacyJson, SideTable};
use crate::{
    Vault,
    error::{Error, Result},
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// One priced model registry row. Key: string (model id).
const REGISTRY_ROW: SideTable<String, ModelRegistryRow, LegacyJson> =
    SideTable::new(&side_table::LLM_REGISTRY_ROW);
/// Bounded recent benchmark-score change history for one model. Key: string (model id) + NUL.
const SCORE_DIFFS: SideTable<String, Vec<ModelScoreDiff>, LegacyJson> =
    SideTable::new(&side_table::LLM_SCORE_DIFFS);

/// The `SCORE_DIFFS` key for `model`: its id, NUL-terminated, exactly as the pre-migration byte
/// key spelled it.
fn score_diffs_key(model: &ModelId) -> String {
    format!("{}\0", model.as_str())
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ModelWireFormat {
    OpenaiCompat,
    AnthropicMessages,
    Gemini,
    OwnServer,
    Local,
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelRegistryRow {
    pub version: u8,
    pub wire: ModelWireFormat,
    pub catalog: LlmCatalogEntry,
    #[serde(default)]
    pub scores: BTreeMap<String, BTreeMap<String, f64>>,
    #[serde(default)]
    pub fetched_at: BTreeMap<String, u64>,
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CatalogSeed {
    pub version: u8,
    pub rows: Vec<ModelRegistryRow>,
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ModelScoreDiff {
    pub model: ModelId,
    pub source: String,
    pub benchmark: String,
    pub previous: Option<f64>,
    pub score: f64,
    pub fetched_at: u64,
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ScoreObservation {
    pub model: ModelId,
    pub benchmark: String,
    pub score: f64,
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ScoreSnapshot {
    pub source: String,
    pub fetched_at: u64,
    pub observations: Vec<ScoreObservation>,
}
pub(super) fn invalid(message: impl Into<String>) -> Error {
    Error::InvalidConfig(message.into())
}
fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    serde_json::to_vec(value).map_err(|e| invalid(e.to_string()))
}
fn price(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value.bytes().all(|c| c.is_ascii_digit() || c == b'.')
        && value.bytes().filter(|c| *c == b'.').count() <= 1
        && value.bytes().any(|c| c.is_ascii_digit())
}
impl ModelRegistryRow {
    pub fn validate(&self) -> Result<()> {
        let entry = &self.catalog;
        if self.version != 1
            || entry.display_name.trim().is_empty()
            || entry.context_window_tokens == 0
            || entry.max_output_tokens == Some(0)
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
impl CatalogSeed {
    pub fn from_json(bytes: &[u8]) -> Result<Self> {
        let seed: Self = serde_json::from_slice(bytes).map_err(|e| invalid(e.to_string()))?;
        if seed.version != 1 {
            return Err(invalid("unsupported catalog seed version"));
        }
        let mut ids = std::collections::BTreeSet::new();
        for row in &seed.rows {
            row.validate()?;
            if !ids.insert(&row.catalog.model)
                || !row.scores.is_empty()
                || !row.fetched_at.is_empty()
            {
                return Err(invalid("duplicate seed model or seeded benchmark metadata"));
            }
        }
        Ok(seed)
    }
    pub fn bundled() -> Result<Self> {
        Self::from_json(include_bytes!("catalog-seed.json"))
    }
}
impl Vault {
    pub fn put_model_registry_row(&self, row: &ModelRegistryRow) -> Result<()> {
        row.validate()?;
        let key = row.catalog.model.as_str().to_owned();
        let mut txn = self.store.env.write_txn()?;
        let previous = REGISTRY_ROW.get(&self.store, &txn, &key)?;
        if let Some(old) = &previous {
            old.validate()?;
        }
        if previous.as_ref().map_or(
            !row.scores.is_empty() || !row.fetched_at.is_empty(),
            |old| old.scores != row.scores || old.fetched_at != row.fetched_at,
        ) {
            return Err(invalid("scores must change through snapshot diff"));
        }
        REGISTRY_ROW.put(&self.store, &mut txn, &key, row)?;
        txn.commit()?;
        Ok(())
    }
    pub fn model_registry_row(&self, model: &ModelId) -> Result<Option<ModelRegistryRow>> {
        let txn = self.store.env.read_txn()?;
        let Some(row) = REGISTRY_ROW.get(&self.store, &txn, &model.as_str().to_owned())? else {
            return Ok(None);
        };
        row.validate()?;
        Ok(Some(row))
    }
    pub fn model_registry_rows(&self) -> Result<Vec<ModelRegistryRow>> {
        let txn = self.store.env.read_txn()?;
        let mut rows = Vec::new();
        for (_, row) in REGISTRY_ROW.scan(&self.store, &txn)? {
            row.validate()?;
            rows.push(row);
        }
        Ok(rows)
    }
    pub fn model_catalog_entries(&self, wire: ModelWireFormat) -> Result<Vec<LlmCatalogEntry>> {
        Ok(self
            .model_registry_rows()?
            .into_iter()
            .filter(|r| r.wire == wire)
            .map(|r| r.catalog)
            .collect())
    }
    /// Atomic, insert-only seed. Existing host prices and scraped scores survive reseeding.
    pub fn seed_model_catalog(&self, seed: &CatalogSeed) -> Result<()> {
        let checked = CatalogSeed::from_json(&encode(seed)?)?;
        let mut txn = self.store.env.write_txn()?;
        for row in checked.rows {
            let key = row.catalog.model.as_str().to_owned();
            if !REGISTRY_ROW.contains(&self.store, &txn, &key)? {
                REGISTRY_ROW.put(&self.store, &mut txn, &key, &row)?;
            }
        }
        txn.commit()?;
        Ok(())
    }
    pub fn apply_model_scores(&self, snapshot: &ScoreSnapshot) -> Result<Vec<ModelScoreDiff>> {
        self.apply_model_score_snapshots(std::slice::from_ref(snapshot))
    }
    pub(super) fn apply_model_score_snapshots(
        &self,
        snapshots: &[ScoreSnapshot],
    ) -> Result<Vec<ModelScoreDiff>> {
        let mut txn = self.store.env.write_txn()?;
        let mut diffs = Vec::new();
        for snapshot in snapshots {
            if snapshot.source.trim().is_empty() || snapshot.source.len() > 128 {
                return Err(invalid("invalid benchmark source"));
            }
            let mut seen = std::collections::BTreeSet::new();
            let mut prior_watermarks = BTreeMap::new();
            for observation in &snapshot.observations {
                if observation.benchmark.trim().is_empty()
                    || observation.benchmark.len() > 128
                    || !observation.score.is_finite()
                    || !seen.insert((&observation.model, &observation.benchmark))
                {
                    return Err(invalid("invalid or duplicate benchmark observation"));
                }
                let key = observation.model.as_str().to_owned();
                let mut row = REGISTRY_ROW
                    .get(&self.store, &txn, &key)?
                    .ok_or_else(|| invalid("score model is not registered"))?;
                row.validate()?;
                let prior_watermark = *prior_watermarks
                    .entry(observation.model.clone())
                    .or_insert_with(|| row.fetched_at.get(&snapshot.source).copied());
                if prior_watermark.is_some_and(|at| at > snapshot.fetched_at) {
                    return Err(invalid("stale benchmark snapshot"));
                }
                let scores = row.scores.entry(snapshot.source.clone()).or_default();
                let previous = scores.get(&observation.benchmark).copied();
                if prior_watermark == Some(snapshot.fetched_at)
                    && previous.is_some_and(|score| score != observation.score)
                {
                    return Err(invalid("conflicting equal-time benchmark snapshot"));
                }
                if previous == Some(observation.score) {
                    // Observation recency is independent of score changes. An
                    // identical newer snapshot still fences out older replays,
                    // but must not append a spurious change record.
                    row.fetched_at
                        .insert(snapshot.source.clone(), snapshot.fetched_at);
                    REGISTRY_ROW.put(&self.store, &mut txn, &key, &row)?;
                    continue;
                }
                scores.insert(observation.benchmark.clone(), observation.score);
                row.fetched_at
                    .insert(snapshot.source.clone(), snapshot.fetched_at);
                let diff = ModelScoreDiff {
                    model: observation.model.clone(),
                    source: snapshot.source.clone(),
                    benchmark: observation.benchmark.clone(),
                    previous,
                    score: observation.score,
                    fetched_at: snapshot.fetched_at,
                };
                let diffs_key = score_diffs_key(&observation.model);
                let mut prior = SCORE_DIFFS
                    .get(&self.store, &txn, &diffs_key)?
                    .unwrap_or_default();
                prior.push(diff.clone());
                if prior.len() > 64 {
                    prior.remove(0);
                }
                SCORE_DIFFS.put(&self.store, &mut txn, &diffs_key, &prior)?;
                REGISTRY_ROW.put(&self.store, &mut txn, &key, &row)?;
                diffs.push(diff);
            }
        }
        txn.commit()?;
        Ok(diffs)
    }
    pub fn model_score_diffs(&self, model: &ModelId) -> Result<Vec<ModelScoreDiff>> {
        let txn = self.store.env.read_txn()?;
        Ok(SCORE_DIFFS
            .get(&self.store, &txn, &score_diffs_key(model))?
            .unwrap_or_default())
    }
}

#[cfg(test)]
mod tests;
