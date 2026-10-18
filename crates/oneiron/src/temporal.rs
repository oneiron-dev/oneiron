//! `TimeRange`, temporal expressions/parsing, granularity/anchor enums.
//!
//! Everything but [`TemporalAnchorMode`] is defined in `oneiron-contracts` and
//! re-exported here, so every `oneiron::temporal` path is unchanged. The anchor mode
//! stays in this crate with the retrieval scoring that matches it exhaustively:
//! `#[non_exhaustive]` permits exhaustive matches only inside the defining crate.

pub use oneiron_contracts::temporal::{
    OpenPhrase, QueryTemporalHints, TEMPORAL_MAX_REFERENCE_SECS, TemporalExpression,
    TemporalExpressionParseError, TemporalGranularity, TemporalHintReport, TemporalHintStatus,
    TemporalPhraseSpan, TemporalPhraseStep, TemporalUnit, TimeRange, WeekdayRelation,
    parse_temporal_expression, temporal_hints_from_query, temporal_phrase_spans,
    temporal_phrase_steps,
};

/// Temporal anchor intent for bitemporal scoring.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, Default, serde::Serialize, serde::Deserialize,
    schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum TemporalAnchorMode {
    Occurred,
    Learned,
    Both,
    #[default]
    Auto,
}
