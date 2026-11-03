//! Default speculative retrieval fire counts and result limits.

/// Reduced per-fire result limit (E7 "fast lane, reduced limit").
pub const SPECULATIVE_FIRE_LIMIT_DEFAULT: usize = 8;

/// Max speculative fires per utterance (E7: cap ~4 fires/utterance).
pub const SPECULATIVE_FIRE_CAP_DEFAULT: u8 = 4;
