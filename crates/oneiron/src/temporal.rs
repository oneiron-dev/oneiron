//! `TimeRange`, temporal expressions/parsing, granularity/anchor enums.
//!
//! Everything but [`TemporalAnchorMode`] is defined in `oneiron-contracts` and
//! re-exported here, so every `oneiron::temporal` path is unchanged. The anchor mode
//! stays in this crate with the retrieval scoring that matches it exhaustively:
//! `#[non_exhaustive]` permits exhaustive matches only inside the defining crate.

pub use oneiron_contracts::temporal::{
    TemporalExpression, TemporalExpressionParseError, TemporalGranularity, TimeRange,
    parse_temporal_expression, temporal_expression_from_query,
};

/// Temporal anchor intent for bitemporal scoring.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[non_exhaustive]
pub enum TemporalAnchorMode {
    Occurred,
    Learned,
    Both,
    #[default]
    Auto,
}
