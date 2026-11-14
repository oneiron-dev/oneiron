//! The operator knob: weights, threshold, its row codec and the Vault read/write doors.

use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::error::{Error, Result};
use crate::side_table::{self, Named, SideTable};

use super::score::{
    PREFILTER_FEATURE_ENTITY_DENSITY, PREFILTER_FEATURE_LEN, PREFILTER_FEATURE_NOVELTY,
    PREFILTER_FEATURE_ROLE, PREFILTER_FEATURE_TTR,
};

// ---------------------------------------------------------------------------
// Keyspace (module-local, on `vault_meta` — the `dreamer_consolidation`
// support.rs prefix precedent; `dreamer:prefilter:` was a free namespace)
// ---------------------------------------------------------------------------

/// Single active config row (the `retr_blend_weights:v0:active` precedent). Key: ().
const CONFIG: SideTable<(), PrefilterConfigRow, Named> =
    SideTable::new(&side_table::PREFILTER_CONFIG);

const PREFILTER_CONFIG_VERSION: u8 = 1;

#[doc(hidden)]
pub use oneiron_records::dreamer_prefilter::config::{PrefilterConfig, PrefilterWeights};

/// The durable row shape. The public value type carries no `version` field so
/// callers never have to know one; the row does, so an unknown schema is
/// refused instead of silently reinterpreted.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
struct PrefilterConfigRow {
    version: u8,
    enabled: bool,
    threshold: f32,
    weights: PrefilterWeights,
}

pub(super) fn invalid_prefilter_config(reason: impl Into<String>) -> Error {
    Error::InvalidConfig(reason.into())
}

/// Refuses a config that cannot produce a meaningful score.
///
/// Non-finite (NaN/±Inf) and out-of-`[0, 1]` thresholds, negative or
/// non-finite weights, an overflowing total, and an all-zero vector are rejected —
/// BEFORE the row is encoded, so a refused config is never persisted.
///
/// # Errors
///
/// [`Error::InvalidConfig`] naming the offending field.
pub fn validate_prefilter_config(config: &PrefilterConfig) -> Result<()> {
    if !config.threshold.is_finite() {
        return Err(invalid_prefilter_config(
            "dreamer prefilter threshold must be finite",
        ));
    }
    if !(0.0..=1.0).contains(&config.threshold) {
        return Err(invalid_prefilter_config(format!(
            "dreamer prefilter threshold must be within [0, 1], got {}",
            config.threshold
        )));
    }
    for (name, weight) in config.weights.axes() {
        if !weight.is_finite() {
            return Err(invalid_prefilter_config(format!(
                "dreamer prefilter {name} weight must be finite"
            )));
        }
        if weight < 0.0 {
            return Err(invalid_prefilter_config(format!(
                "dreamer prefilter {name} weight must be non-negative, got {weight}"
            )));
        }
    }
    let total = config.weights.total();
    if !total.is_finite() || total <= 0.0 {
        return Err(invalid_prefilter_config(
            "dreamer prefilter weights must have finite positive total mass",
        ));
    }
    Ok(())
}

/// The validation a landed row gets on the way OUT as well as on the way in:
/// the setter is the only sanctioned writer, but a corrupt or foreign row
/// must not be able to hand the planner a NaN threshold.
fn prefilter_config_from_row(row: PrefilterConfigRow) -> Result<PrefilterConfig> {
    if row.version != PREFILTER_CONFIG_VERSION {
        return Err(invalid_prefilter_config(
            "unsupported dreamer prefilter config schema",
        ));
    }
    let config = PrefilterConfig {
        enabled: row.enabled,
        threshold: row.threshold,
        weights: row.weights,
    };
    validate_prefilter_config(&config)?;
    Ok(config)
}

impl Vault {
    /// Reads the active screening policy; an absent row IS the compiled
    /// [`PrefilterConfig::default`].
    ///
    /// # Errors
    ///
    /// Storage errors, or [`Error::InvalidConfig`] when the landed row is
    /// undecodable, of an unknown schema, or out of range.
    pub fn prefilter_config(&self) -> Result<PrefilterConfig> {
        let rtxn = self.store.env.read_txn()?;
        let Some(row) = CONFIG.get(&self.store, &rtxn, &())? else {
            return Ok(PrefilterConfig::default());
        };
        prefilter_config_from_row(row)
    }

    /// [`Vault::prefilter_config`] through a caller-owned write transaction,
    /// so the in-transaction session-close planner screens under exactly the
    /// policy its own commit will be judged by.
    pub(super) fn prefilter_config_in_txn(&self, txn: &heed::RoTxn<'_>) -> Result<PrefilterConfig> {
        let Some(row) = CONFIG.get(&self.store, txn, &())? else {
            return Ok(PrefilterConfig::default());
        };
        prefilter_config_from_row(row)
    }

    /// Persists a screening policy. Validation runs FIRST and a refused
    /// config never reaches the store, so a bad tuning attempt leaves the
    /// previous policy live rather than wedging the planner.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidConfig`] on a non-finite or out-of-range threshold, a
    /// non-finite or negative weight, or a zero-mass weight vector; storage
    /// errors otherwise.
    pub fn set_prefilter_config(&self, config: PrefilterConfig) -> Result<()> {
        validate_prefilter_config(&config)?;
        let row = PrefilterConfigRow {
            version: PREFILTER_CONFIG_VERSION,
            enabled: config.enabled,
            threshold: config.threshold,
            weights: config.weights,
        };
        let mut wtxn = self.store.env.write_txn()?;
        CONFIG.put(&self.store, &mut wtxn, &(), &row)?;
        wtxn.commit()?;
        Ok(())
    }
}
