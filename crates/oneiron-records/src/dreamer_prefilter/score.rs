//! Moved from `crates/oneiron/src/dreamer_prefilter/score.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

/// Feature name: normalized token count.
pub const PREFILTER_FEATURE_LEN: &str = "len";

/// Feature name: type/token ratio (lexical variety).
pub const PREFILTER_FEATURE_TTR: &str = "ttr";

/// Feature name: entity-mention density.
pub const PREFILTER_FEATURE_ENTITY_DENSITY: &str = "entity_density";

/// Feature name: novelty against the recent-turn window.
pub const PREFILTER_FEATURE_NOVELTY: &str = "novelty";

/// Feature name: speaker-role weight.
pub const PREFILTER_FEATURE_ROLE: &str = "role";
