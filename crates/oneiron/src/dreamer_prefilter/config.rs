//! The operator knob: weights, threshold, its row codec and the Vault read/write doors.

use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::error::{Error, Result};

use super::score::{
    PREFILTER_FEATURE_ENTITY_DENSITY, PREFILTER_FEATURE_LEN, PREFILTER_FEATURE_NOVELTY,
    PREFILTER_FEATURE_ROLE, PREFILTER_FEATURE_TTR,
};

// ---------------------------------------------------------------------------
// Keyspace (module-local, on `vault_meta` — the `dreamer_consolidation`
// support.rs prefix precedent; `dreamer:prefilter:` was a free namespace)
// ---------------------------------------------------------------------------

/// Single active config row (the `retr_blend_weights:v0:active` precedent).
const PREFILTER_CONFIG_KEY: &[u8] = b"dreamer:prefilter:config:v1";

const PREFILTER_CONFIG_VERSION: u8 = 1;

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

/// Relative pull of each screening axis. Every weight is finite and
/// non-negative and the total mass is positive; the score is the weighted mean
/// of the axes, so it stays in `[0, 1]` whatever the weights are.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct PrefilterWeights {
    /// How much sheer length is worth.
    pub len: f32,
    /// How much lexical variety is worth.
    pub ttr: f32,
    /// How much naming specific things is worth.
    pub entity_density: f32,
    /// How much saying something not just said is worth.
    pub novelty: f32,
    /// How much the speaker's role is worth.
    pub role: f32,
}

impl Default for PrefilterWeights {
    /// Entity density and novelty carry the most weight because they are the
    /// two axes that separate "a fact was stated" from "words were emitted";
    /// length and variety are supporting evidence; role is a small tilt toward
    /// the owner's own turns.
    fn default() -> Self {
        Self {
            len: 0.20,
            ttr: 0.15,
            entity_density: 0.30,
            novelty: 0.25,
            role: 0.10,
        }
    }
}

impl PrefilterWeights {
    /// The axes in receipt/feature order, for validation and scoring.
    pub(super) fn axes(&self) -> [(&'static str, f32); 5] {
        [
            (PREFILTER_FEATURE_LEN, self.len),
            (PREFILTER_FEATURE_TTR, self.ttr),
            (PREFILTER_FEATURE_ENTITY_DENSITY, self.entity_density),
            (PREFILTER_FEATURE_NOVELTY, self.novelty),
            (PREFILTER_FEATURE_ROLE, self.role),
        ]
    }

    /// Total weight mass. Validation requires this to be finite and positive.
    #[must_use]
    pub fn total(&self) -> f32 {
        self.len + self.ttr + self.entity_density + self.novelty + self.role
    }
}

/// Durable screening policy, read from `vault_meta` on every planning round so
/// a threshold change takes effect without a recompile or a restart.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct PrefilterConfig {
    /// `false` disables the screen entirely: the planners take their input
    /// unchanged and read nothing extra (invariant I4).
    pub enabled: bool,
    /// Score at or above which a turn is kept, in `[0, 1]`. `0.0` keeps
    /// everything — the shipped default.
    pub threshold: f32,
    /// Relative pull of each axis.
    pub weights: PrefilterWeights,
}

impl Default for PrefilterConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            threshold: 0.0,
            weights: PrefilterWeights::default(),
        }
    }
}

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

pub(super) fn decode_prefilter_config(raw: &[u8]) -> Result<PrefilterConfig> {
    let row: PrefilterConfigRow = rmp_serde::from_slice(raw)
        .map_err(|_| invalid_prefilter_config("dreamer prefilter config row is undecodable"))?;
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
    // A landed row is validated on the way OUT as well as on the way in: the
    // setter is the only sanctioned writer, but a corrupt or foreign row must
    // not be able to hand the planner a NaN threshold.
    validate_prefilter_config(&config)?;
    Ok(config)
}

pub(super) fn encode_prefilter_config(config: &PrefilterConfig) -> Result<Vec<u8>> {
    rmp_serde::to_vec_named(&PrefilterConfigRow {
        version: PREFILTER_CONFIG_VERSION,
        enabled: config.enabled,
        threshold: config.threshold,
        weights: config.weights,
    })
    .map_err(|_| invalid_prefilter_config("dreamer prefilter config row encode failed"))
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
        let Some(raw) = self.store.vault_meta.get(&rtxn, PREFILTER_CONFIG_KEY)? else {
            return Ok(PrefilterConfig::default());
        };
        decode_prefilter_config(&raw)
    }

    /// [`Vault::prefilter_config`] through a caller-owned write transaction,
    /// so the in-transaction session-close planner screens under exactly the
    /// policy its own commit will be judged by.
    pub(super) fn prefilter_config_in_txn(&self, txn: &heed::RwTxn<'_>) -> Result<PrefilterConfig> {
        let Some(raw) = self.store.vault_meta.get(txn, PREFILTER_CONFIG_KEY)? else {
            return Ok(PrefilterConfig::default());
        };
        decode_prefilter_config(&raw)
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
        let encoded = encode_prefilter_config(&config)?;
        let mut wtxn = self.store.env.write_txn()?;
        self.store
            .vault_meta
            .put(&mut wtxn, PREFILTER_CONFIG_KEY, &encoded)?;
        wtxn.commit()?;
        Ok(())
    }
}
