//! Moved from `crates/oneiron/src/dreamer_prefilter/config.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::dreamer_prefilter::score::PREFILTER_FEATURE_ENTITY_DENSITY;
use crate::dreamer_prefilter::score::PREFILTER_FEATURE_LEN;
use crate::dreamer_prefilter::score::PREFILTER_FEATURE_NOVELTY;
use crate::dreamer_prefilter::score::PREFILTER_FEATURE_ROLE;
use crate::dreamer_prefilter::score::PREFILTER_FEATURE_TTR;
use serde::Deserialize;
use serde::Serialize;

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
    pub fn axes(&self) -> [(&'static str, f32); 5] {
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
