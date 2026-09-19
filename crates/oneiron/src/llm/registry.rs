//! Vault-persisted, priced model catalogs. Scores are evidence, never routing authority.
use super::{LlmCatalogEntry, ModelId};
use crate::{
    Vault,
    error::{Error, Result},
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
const ROW_PREFIX: &[u8] = b"llm:registry:v1:";
const DIFF_PREFIX: &[u8] = b"llm:scores:v1:";
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
fn row_key(model: &ModelId) -> Vec<u8> {
    [ROW_PREFIX, model.as_str().as_bytes()].concat()
}
fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    serde_json::to_vec(value).map_err(|e| invalid(e.to_string()))
}
fn decode(bytes: &[u8]) -> Result<ModelRegistryRow> {
    let row: ModelRegistryRow =
        serde_json::from_slice(bytes).map_err(|e| invalid(e.to_string()))?;
    row.validate()?;
    Ok(row)
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
            if !ids.insert(&row.catalog.model) || !row.scores.is_empty() {
                return Err(invalid("duplicate seed model or seeded benchmark scores"));
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
        let key = row_key(&row.catalog.model);
        let mut txn = self.store.env.write_txn()?;
        let previous = self
            .store
            .vault_meta
            .get(&txn, &key)?
            .map(|bytes| decode(&bytes))
            .transpose()?;
        if previous.as_ref().map_or(
            !row.scores.is_empty() || !row.fetched_at.is_empty(),
            |old| old.scores != row.scores || old.fetched_at != row.fetched_at,
        ) {
            return Err(invalid("scores must change through snapshot diff"));
        }
        self.store.vault_meta.put(&mut txn, &key, &encode(row)?)?;
        txn.commit()?;
        Ok(())
    }
    pub fn model_registry_row(&self, model: &ModelId) -> Result<Option<ModelRegistryRow>> {
        let txn = self.store.env.read_txn()?;
        self.store
            .vault_meta
            .get(&txn, &row_key(model))?
            .map(|bytes| decode(&bytes))
            .transpose()
    }
    pub fn model_registry_rows(&self) -> Result<Vec<ModelRegistryRow>> {
        let txn = self.store.env.read_txn()?;
        let mut rows = Vec::new();
        for item in self.store.vault_meta.prefix_iter(&txn, ROW_PREFIX)? {
            let (_, bytes) = item?;
            rows.push(decode(&bytes)?);
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
            let key = row_key(&row.catalog.model);
            if self.store.vault_meta.get(&txn, &key)?.is_none() {
                self.store.vault_meta.put(&mut txn, &key, &encode(&row)?)?;
            }
        }
        txn.commit()?;
        Ok(())
    }
    pub fn apply_model_scores(&self, snapshot: &ScoreSnapshot) -> Result<Vec<ModelScoreDiff>> {
        if snapshot.source.trim().is_empty() || snapshot.source.len() > 128 {
            return Err(invalid("invalid benchmark source"));
        }
        let mut seen = std::collections::BTreeSet::new();
        let mut txn = self.store.env.write_txn()?;
        let mut diffs = Vec::new();
        let mut prior_watermarks = BTreeMap::new();
        for observation in &snapshot.observations {
            if observation.benchmark.trim().is_empty()
                || observation.benchmark.len() > 128
                || !observation.score.is_finite()
                || !seen.insert((&observation.model, &observation.benchmark))
            {
                return Err(invalid("invalid or duplicate benchmark observation"));
            }
            let key = row_key(&observation.model);
            let bytes = self
                .store
                .vault_meta
                .get(&txn, &key)?
                .ok_or_else(|| invalid("score model is not registered"))?;
            let mut row = decode(&bytes)?;
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
                self.store.vault_meta.put(&mut txn, &key, &encode(&row)?)?;
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
            let prefix = [DIFF_PREFIX, observation.model.as_str().as_bytes(), b"\0"].concat();
            let mut prior: Vec<ModelScoreDiff> = self
                .store
                .vault_meta
                .get(&txn, &prefix)?
                .map(|b| serde_json::from_slice(&b).map_err(|e| invalid(e.to_string())))
                .transpose()?
                .unwrap_or_default();
            prior.push(diff.clone());
            if prior.len() > 64 {
                prior.remove(0);
            }
            self.store
                .vault_meta
                .put(&mut txn, &prefix, &encode(&prior)?)?;
            self.store.vault_meta.put(&mut txn, &key, &encode(&row)?)?;
            diffs.push(diff);
        }
        txn.commit()?;
        Ok(diffs)
    }
    pub fn model_score_diffs(&self, model: &ModelId) -> Result<Vec<ModelScoreDiff>> {
        let txn = self.store.env.read_txn()?;
        let key = [DIFF_PREFIX, model.as_str().as_bytes(), b"\0"].concat();
        self.store
            .vault_meta
            .get(&txn, &key)?
            .map(|b| serde_json::from_slice(&b).map_err(|e| invalid(e.to_string())))
            .transpose()
            .map(Option::unwrap_or_default)
    }
}

#[cfg(test)]
mod tests;
