//! Moved from `crates/oneiron/src/temporal.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use oneiron_contracts::temporal::OpenPhrase;
pub use oneiron_contracts::temporal::QueryTemporalHints;
pub use oneiron_contracts::temporal::TEMPORAL_MAX_REFERENCE_SECS;
pub use oneiron_contracts::temporal::TemporalExpression;
pub use oneiron_contracts::temporal::TemporalExpressionParseError;
pub use oneiron_contracts::temporal::TemporalGranularity;
pub use oneiron_contracts::temporal::TemporalHintReport;
pub use oneiron_contracts::temporal::TemporalHintStatus;
pub use oneiron_contracts::temporal::TemporalPhraseSpan;
pub use oneiron_contracts::temporal::TemporalPhraseStep;
pub use oneiron_contracts::temporal::TemporalUnit;
pub use oneiron_contracts::temporal::TimeRange;
pub use oneiron_contracts::temporal::WeekdayRelation;
pub use oneiron_contracts::temporal::parse_temporal_expression;
pub use oneiron_contracts::temporal::temporal_hints_from_query;
pub use oneiron_contracts::temporal::temporal_phrase_spans;
pub use oneiron_contracts::temporal::temporal_phrase_steps;

/// Temporal anchor intent for bitemporal scoring.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    Default,
    serde::Serialize,
    serde::Deserialize,
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
