//! The usage and provider names, one line per row, generated from
//! `scripts/ratchet/hand_name_tables.py --names --only <file>` on the R0 head before these
//! enums became Registers (Fable pass 25, the register conversion wave), for:
//! - `crates/oneiron-server/src/config/models/provider.rs`
//! - `crates/oneiron-server/src/usage/meters.rs`
//! - `crates/oneiron-server/src/usage/model.rs`
//!
//! Green on the hand tables and on the adoption (the derive), so no stored or sent name
//! changed (M-1 keep). The second test of each enum pins each name to serde's; where the
//! adoption rewrites a parser's body, a third reads every name back through it.

use oneiron_server::config::models::OutputLimitField;
use oneiron_server::usage::{OperationalMetric, UsageMode};
use serde_json::Value;

/// Every `OperationalMetric` row, as the hand `as_str` table spelled it.
const OPERATIONAL_METRIC_ROWS: [(OperationalMetric, &str); 4] = [
    (OperationalMetric::IngestTokens, "ingest_tokens"),
    (OperationalMetric::EmbedTokens, "embed_tokens"),
    (OperationalMetric::RetrievalQueries, "retrieval_queries"),
    (OperationalMetric::AssetGbDays, "asset_gb_days"),
];

#[test]
fn every_operational_metric_keeps_its_name() {
    assert_eq!(OperationalMetric::IngestTokens.as_str(), "ingest_tokens");
    assert_eq!(OperationalMetric::EmbedTokens.as_str(), "embed_tokens");
    assert_eq!(
        OperationalMetric::RetrievalQueries.as_str(),
        "retrieval_queries"
    );
    assert_eq!(OperationalMetric::AssetGbDays.as_str(), "asset_gb_days");
}

#[test]
fn every_operational_metric_name_is_its_serde_name() {
    for (row, name) in OPERATIONAL_METRIC_ROWS {
        let written = serde_json::to_value(row).expect("a operational metric serializes");
        assert_eq!(written, Value::String(name.to_owned()), "{row:?}");
        let read: OperationalMetric =
            serde_json::from_value(Value::String(name.to_owned())).expect("serde reads the name");
        assert_eq!(read, row, "{name}");
    }
}

/// Every `UsageMode` row, as the hand `as_str` table spelled it.
const USAGE_MODE_ROWS: [(UsageMode, &str); 3] = [
    (UsageMode::Local, "local"),
    (UsageMode::Byo, "byo"),
    (UsageMode::OneironCloud, "oneiron_cloud"),
];

#[test]
fn every_usage_mode_keeps_its_name() {
    assert_eq!(UsageMode::Local.as_str(), "local");
    assert_eq!(UsageMode::Byo.as_str(), "byo");
    assert_eq!(UsageMode::OneironCloud.as_str(), "oneiron_cloud");
}

#[test]
fn every_usage_mode_name_is_its_serde_name() {
    for (row, name) in USAGE_MODE_ROWS {
        let written = serde_json::to_value(row).expect("a usage mode serializes");
        assert_eq!(written, Value::String(name.to_owned()), "{row:?}");
        let read: UsageMode =
            serde_json::from_value(Value::String(name.to_owned())).expect("serde reads the name");
        assert_eq!(read, row, "{name}");
    }
}

/// Every `OutputLimitField` row, as the hand `key` table spelled it.
const OUTPUT_LIMIT_FIELD_ROWS: [(OutputLimitField, &str); 2] = [
    (OutputLimitField::MaxTokens, "max_tokens"),
    (
        OutputLimitField::MaxCompletionTokens,
        "max_completion_tokens",
    ),
];

#[test]
fn every_output_limit_field_keeps_its_name() {
    assert_eq!(OutputLimitField::MaxTokens.key(), "max_tokens");
    assert_eq!(
        OutputLimitField::MaxCompletionTokens.key(),
        "max_completion_tokens"
    );
}

#[test]
fn every_output_limit_field_name_is_its_serde_name() {
    for (row, name) in OUTPUT_LIMIT_FIELD_ROWS {
        let read: OutputLimitField =
            serde_json::from_value(Value::String(name.to_owned())).expect("serde reads the name");
        assert_eq!(read, row, "{name}");
    }
}
