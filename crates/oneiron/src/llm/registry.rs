//! Vault-persisted, priced model catalogs. Scores are evidence, never routing authority.
mod backend;
mod description;
pub use backend::{ModelBackendPin, ModelCostReceipt, PricedModelBackend};
mod installed_pack;
pub use description::{DescriptionClass, DescriptionContribution, ModelDescription};

use super::{LlmCatalogEntry, ModelId};
use crate::entity_id::EntityId;
use crate::side_table::{self, LegacyJson, SideTable};
use crate::skill_optimize::union_source_rows;
use crate::{
    Vault,
    error::{Error, Result},
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum ModelWireFormat {
    OpenaiCompat,
    AnthropicMessages,
    Gemini,
    OwnServer,
    Local,
}
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
    /// text, measured by the host on one fixed passage (OF-577); `None`
    /// until measured. A refresh that changes the catalog entry clears it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tokens_per_o200k: Option<f64>,
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
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CatalogSeed {
    pub version: u8,
    pub rows: Vec<ModelRegistryRow>,
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ModelScoreDiff {
    pub model: ModelId,
    pub source: String,
    pub benchmark: String,
    pub previous: Option<f64>,
    pub score: f64,
    pub fetched_at: u64,
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ScoreObservation {
    pub model: ModelId,
    pub benchmark: String,
    pub score: f64,
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ScoreSnapshot {
    pub source: String,
    pub fetched_at: u64,
    pub observations: Vec<ScoreObservation>,
    /// The rows the observations were read from (FIX 5760): none for a
    /// public benchmark fetch. `None`, unknown, for a snapshot whose
    /// producer named none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_rows: Option<Vec<EntityId>>,
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
            || self
                .tokens_per_o200k
                .is_some_and(|ratio| !(ratio.is_finite() && ratio > 0.0))
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
            if !row.catalog.metadata.contains_key("description")
                || row.catalog.capabilities.is_empty()
                || row
                    .catalog
                    .capabilities
                    .iter()
                    .enumerate()
                    .any(|(index, flag)| row.catalog.capabilities[..index].contains(flag))
                || !ids.insert(&row.catalog.model)
                || !row.scores.is_empty()
                || !row.fetched_at.is_empty()
                || row.stale_since.is_some()
            {
                return Err(invalid("invalid seed fields or seeded benchmark metadata"));
            }
        }
        Ok(seed)
    }
}
/// Read the registry in the caller's snapshot. Binding may already hold a
/// read transaction; opening another LMDB reader on the same thread fails.
pub(super) fn read_model_registry_row(
    store: &crate::store::Store,
    txn: &heed::RoTxn<'_>,
    model: &ModelId,
) -> Result<Option<ModelRegistryRow>> {
    let Some(row) = REGISTRY_ROW.get(store, txn, &model.as_str().to_owned())? else {
        return Ok(None);
    };
    row.validate()?;
    Ok(Some(row))
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
        // Scores change only through a snapshot, so the row keeps the
        // evidence its stored scores were read from (FIX 5760).
        let mut row = row.clone();
        if let Some(old) = previous.as_ref().filter(|old| !old.scores.is_empty()) {
            row.source_rows =
                union_source_rows([row.source_rows.as_deref(), old.source_rows.as_deref()]);
        }
        REGISTRY_ROW.put(self, &mut txn, &key, &row)?;
        txn.commit()?;
        Ok(())
    }
    /// Stores `ratio`, the host's measured [`ModelRegistryRow::tokens_per_o200k`],
    /// on `measured`'s stored row while that row still holds the catalog entry
    /// it was measured on. `Ok(false)` when there is no such row: none is
    /// stored, or a refresh changed it since. The row keeps its source rows
    /// (FIX 5760): the ratio is measured from that same entry and a fixed
    /// passage, and reads no other row.
    ///
    /// # Errors
    ///
    /// A ratio that is not finite and positive, or storage errors.
    pub fn set_model_token_ratio(&self, measured: &ModelRegistryRow, ratio: f64) -> Result<bool> {
        let key = measured.catalog.model.as_str().to_owned();
        let mut txn = self.store.env.write_txn()?;
        let Some(mut row) = REGISTRY_ROW.get(&self.store, &txn, &key)? else {
            return Ok(false);
        };
        if row.catalog != measured.catalog {
            return Ok(false);
        }
        row.tokens_per_o200k = Some(ratio);
        row.validate()?;
        REGISTRY_ROW.put(self, &mut txn, &key, &row)?;
        txn.commit()?;
        Ok(true)
    }
    /// The installed model catalog pack's source row, when one is installed:
    /// the record [`Self::model_registry_row`] reads a model's row from when
    /// the registry holds none for it. A host lists it beside an answer
    /// priced from the catalog (DEC-0005).
    ///
    /// # Errors
    ///
    /// A read failure, or an install whose source is no id.
    pub fn model_catalog_source(&self) -> Result<Option<crate::entity_id::EntityId>> {
        let Some(receipt) = self.installed_pack(crate::skill_hub::MODEL_PACK_NAME)? else {
            return Ok(None);
        };
        Ok(Some(crate::entity_id::EntityId::from_hex(
            &receipt.source_id,
        )?))
    }

    pub fn model_registry_row(&self, model: &ModelId) -> Result<Option<ModelRegistryRow>> {
        let stored = {
            let txn = self.store.env.read_txn()?;
            read_model_registry_row(&self.store, &txn, model)?
        };
        if stored.is_some() {
            return Ok(stored);
        }
        if self
            .installed_pack(crate::skill_hub::MODEL_PACK_NAME)?
            .is_some()
        {
            return Ok(CatalogSeed::from_installed_pack(self)?
                .rows
                .into_iter()
                .find(|row| &row.catalog.model == model));
        }
        Ok(None)
    }
    /// [`Self::model_registry_row`] in the caller's snapshot, for a reader
    /// that already holds a transaction (a launch statement's USD quote).
    pub fn model_registry_row_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        model: &ModelId,
    ) -> Result<Option<ModelRegistryRow>> {
        if let Some(row) = read_model_registry_row(&self.store, txn, model)? {
            return Ok(Some(row));
        }
        if self
            .installed_pack_in_txn(txn, crate::skill_hub::MODEL_PACK_NAME)?
            .is_some()
        {
            return Ok(CatalogSeed::from_installed_pack_in_txn(self, txn)?
                .rows
                .into_iter()
                .find(|row| &row.catalog.model == model));
        }
        Ok(None)
    }
    /// Removes the stored row for `row`'s model while it still holds `row`,
    /// for the source that wrote it and has withdrawn it (a mesh node that
    /// stopped offering the model). `Ok(false)` when the stored row is gone
    /// or changed since.
    ///
    /// # Errors
    ///
    /// Storage errors.
    pub fn remove_model_registry_row(&self, row: &ModelRegistryRow) -> Result<bool> {
        let key = row.catalog.model.as_str().to_owned();
        let mut txn = self.store.env.write_txn()?;
        if REGISTRY_ROW.get(&self.store, &txn, &key)?.as_ref() != Some(row) {
            return Ok(false);
        }
        REGISTRY_ROW.delete(&self.store, &mut txn, &key)?;
        txn.commit()?;
        Ok(true)
    }
    pub fn model_registry_rows(&self) -> Result<Vec<ModelRegistryRow>> {
        let txn = self.store.env.read_txn()?;
        self.model_registry_rows_in_txn(&txn)
    }
    pub(super) fn model_registry_rows_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
    ) -> Result<Vec<ModelRegistryRow>> {
        let mut rows = Vec::new();
        for (_, row) in REGISTRY_ROW.scan(&self.store, txn)? {
            row.validate()?;
            rows.push(row);
        }
        Ok(rows)
    }
    pub fn model_catalog_entries(&self, wire: ModelWireFormat) -> Result<Vec<LlmCatalogEntry>> {
        let mut rows = self.model_registry_rows()?;
        if self
            .installed_pack(crate::skill_hub::MODEL_PACK_NAME)?
            .is_some()
        {
            // Installed pack data is visible to adapters even before it is copied
            // into the priced registry. Local overrides and scores keep precedence.
            let existing: std::collections::BTreeSet<_> =
                rows.iter().map(|row| row.catalog.model.clone()).collect();
            let additional = CatalogSeed::from_installed_pack(self)?
                .rows
                .into_iter()
                .filter(|row| !existing.contains(&row.catalog.model))
                .collect::<Vec<_>>();
            rows.extend(additional);
        }
        Ok(rows
            .into_iter()
            .filter(|row| row.wire == wire)
            .map(|row| row.catalog)
            .collect())
    }
    /// Atomic, insert-only seed. Existing host prices and scraped scores survive reseeding.
    pub fn seed_model_catalog(&self, seed: &CatalogSeed) -> Result<()> {
        let mut txn = self.store.env.write_txn()?;
        self.refresh_model_catalog_in_txn(&mut txn, seed, None)?;
        txn.commit()?;
        Ok(())
    }
    /// A pack refresh: a new model is inserted; a row still equal to what the
    /// prior pack shipped takes the new catalog and keeps its scores; a row
    /// the host edited stays as it is. With no prior pack this is the seed.
    /// A model the prior pack shipped and this one does not goes stale, its
    /// row kept; a model this pack ships is not stale.
    pub(crate) fn refresh_model_catalog_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        seed: &CatalogSeed,
        prior: Option<&CatalogSeed>,
    ) -> Result<()> {
        let checked = CatalogSeed::from_json(&encode(seed)?)?;
        // The rows the seed was read from: a retirement it marks derives
        // from them (FIX 5760).
        let seed_sources =
            union_source_rows(checked.rows.iter().map(|row| row.source_rows.as_deref()));
        let shipped: BTreeMap<&str, &ModelRegistryRow> = prior
            .map(|prior| {
                prior
                    .rows
                    .iter()
                    .map(|row| (row.catalog.model.as_str(), row))
                    .collect()
            })
            .unwrap_or_default();
        let ships: BTreeSet<String> = checked
            .rows
            .iter()
            .map(|row| row.catalog.model.as_str().to_owned())
            .collect();
        for row in checked.rows {
            let key = row.catalog.model.as_str().to_owned();
            match REGISTRY_ROW.get(&self.store, txn, &key)? {
                None => REGISTRY_ROW.put(&self.store, txn, &key, &row)?,
                Some(existing)
                    if shipped.get(key.as_str()).is_some_and(|old| {
                        old.wire == existing.wire && old.catalog == existing.catalog
                    }) =>
                {
                    // A changed entry may name another tokenizer: its ratio
                    // is measured again.
                    let tokens_per_o200k = if row.catalog == existing.catalog {
                        existing.tokens_per_o200k
                    } else {
                        row.tokens_per_o200k
                    };
                    // The new entry is the seed's, the kept scores their
                    // snapshots' (FIX 5760).
                    let source_rows = union_source_rows([
                        existing.source_rows.as_deref(),
                        row.source_rows.as_deref(),
                    ]);
                    let refreshed = ModelRegistryRow {
                        version: row.version,
                        wire: row.wire,
                        catalog: row.catalog,
                        tokens_per_o200k,
                        stale_since: None,
                        source_rows,
                        ..existing
                    };
                    REGISTRY_ROW.put(&self.store, txn, &key, &refreshed)?;
                }
                Some(mut existing) if existing.is_stale() => {
                    existing.stale_since = None;
                    existing.source_rows = union_source_rows([
                        existing.source_rows.as_deref(),
                        row.source_rows.as_deref(),
                    ]);
                    REGISTRY_ROW.put(&self.store, txn, &key, &existing)?;
                }
                Some(_) => {}
            }
        }
        let retired: Vec<String> = shipped
            .keys()
            .filter(|model| !ships.contains(**model))
            .map(|model| (*model).to_owned())
            .collect();
        if retired.is_empty() {
            return Ok(());
        }
        let now = crate::ports::recorded_at_in_txn(&self.store, txn)?;
        for key in retired {
            if let Some(mut existing) = REGISTRY_ROW.get(&self.store, txn, &key)?
                && !existing.is_stale()
            {
                existing.stale_since = Some(now);
                existing.source_rows =
                    union_source_rows([existing.source_rows.as_deref(), seed_sources.as_deref()]);
                REGISTRY_ROW.put(&self.store, txn, &key, &existing)?;
            }
        }
        Ok(())
    }
    /// Marks `model`'s stored row retired by its provider since `at`, for a
    /// host that learns of a retirement outside a pack refresh; `None`
    /// clears the mark. The row stays. `Ok(false)` when no row is stored or
    /// it already reads so.
    ///
    /// # Errors
    ///
    /// Storage errors.
    pub fn mark_model_row_stale(&self, model: &ModelId, at: Option<u64>) -> Result<bool> {
        let key = model.as_str().to_owned();
        let mut txn = self.store.env.write_txn()?;
        let Some(mut row) = REGISTRY_ROW.get(&self.store, &txn, &key)? else {
            return Ok(false);
        };
        if row.stale_since == at {
            return Ok(false);
        }
        row.stale_since = at;
        REGISTRY_ROW.put(self, &mut txn, &key, &row)?;
        txn.commit()?;
        Ok(true)
    }
    pub fn apply_model_scores(&self, snapshot: &ScoreSnapshot) -> Result<Vec<ModelScoreDiff>> {
        self.apply_model_score_snapshots(std::slice::from_ref(snapshot))
    }
    pub(super) fn apply_model_score_snapshots(
        &self,
        snapshots: &[ScoreSnapshot],
    ) -> Result<Vec<ModelScoreDiff>> {
        let mut txn = self.store.env.write_txn()?;
        let diffs = self.apply_model_score_snapshots_in_txn(&mut txn, snapshots)?;
        txn.commit()?;
        Ok(diffs)
    }
    pub(super) fn apply_model_score_snapshots_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        snapshots: &[ScoreSnapshot],
    ) -> Result<Vec<ModelScoreDiff>> {
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
                    .get(&self.store, txn, &key)?
                    .ok_or_else(|| invalid("score model is not registered"))?;
                row.validate()?;
                let prior_watermark = *prior_watermarks
                    .entry(observation.model.clone())
                    .or_insert_with(|| row.fetched_at.get(&snapshot.source).copied());
                if prior_watermark.is_some_and(|at| at > snapshot.fetched_at) {
                    return Err(invalid("stale benchmark snapshot"));
                }
                // Every write below reads this snapshot's evidence too (FIX
                // 5760).
                row.source_rows = union_source_rows([
                    row.source_rows.as_deref(),
                    snapshot.source_rows.as_deref(),
                ]);
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
                    REGISTRY_ROW.put(&self.store, txn, &key, &row)?;
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
                    .get(&self.store, txn, &diffs_key)?
                    .unwrap_or_default();
                prior.push(diff.clone());
                if prior.len() > 64 {
                    prior.remove(0);
                }
                SCORE_DIFFS.put(&self.store, txn, &diffs_key, &prior)?;
                REGISTRY_ROW.put(&self.store, txn, &key, &row)?;
                diffs.push(diff);
            }
        }
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
