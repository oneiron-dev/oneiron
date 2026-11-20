//! The runtime mode names, one line per row, generated from
//! `scripts/ratchet/hand_name_tables.py --names --only <file>` on the R0 head before these
//! enums became Registers (Fable pass 25, the register conversion wave), for:
//! - `crates/oneiron-server/src/config/oneironer/runtime.rs`
//! - `crates/oneiron-server/src/runtime/mode.rs`
//!
//! Green on the hand tables and on the adoption (the derive), so no stored or sent name
//! changed (M-1 keep). The second test of each enum pins each name to serde's; where the
//! adoption rewrites a parser's body, a third reads every name back through it.

use oneiron_server::config::oneironer::OneironerRuntime;
use oneiron_server::runtime::{RuntimeMode, RuntimeProviderKind, RuntimeRole};
use serde_json::Value;

/// Every `RuntimeMode` row, as the hand `as_str` table spelled it.
const RUNTIME_MODE_ROWS: [(RuntimeMode, &str); 3] = [
    (RuntimeMode::LocalFree, "local_free"),
    (RuntimeMode::ByoCloudKey, "byo_cloud_key"),
    (RuntimeMode::OneironCloud, "oneiron_cloud"),
];

#[test]
fn every_runtime_mode_keeps_its_name() {
    assert_eq!(RuntimeMode::LocalFree.as_str(), "local_free");
    assert_eq!(RuntimeMode::ByoCloudKey.as_str(), "byo_cloud_key");
    assert_eq!(RuntimeMode::OneironCloud.as_str(), "oneiron_cloud");
}

#[test]
fn every_runtime_mode_name_is_its_serde_name() {
    for (row, name) in RUNTIME_MODE_ROWS {
        let written = serde_json::to_value(row).expect("a runtime mode serializes");
        assert_eq!(written, Value::String(name.to_owned()), "{row:?}");
        let read: RuntimeMode =
            serde_json::from_value(Value::String(name.to_owned())).expect("serde reads the name");
        assert_eq!(read, row, "{name}");
    }
}

/// Every `RuntimeProviderKind` row, as the hand `as_str` table spelled it.
const RUNTIME_PROVIDER_KIND_ROWS: [(RuntimeProviderKind, &str); 3] = [
    (RuntimeProviderKind::Local, "local"),
    (RuntimeProviderKind::ByoCloud, "byo_cloud"),
    (RuntimeProviderKind::OneironCloud, "oneiron_cloud"),
];

#[test]
fn every_runtime_provider_kind_keeps_its_name() {
    assert_eq!(RuntimeProviderKind::Local.as_str(), "local");
    assert_eq!(RuntimeProviderKind::ByoCloud.as_str(), "byo_cloud");
    assert_eq!(RuntimeProviderKind::OneironCloud.as_str(), "oneiron_cloud");
}

#[test]
fn every_runtime_provider_kind_name_is_its_serde_name() {
    for (row, name) in RUNTIME_PROVIDER_KIND_ROWS {
        let written = serde_json::to_value(row).expect("a runtime provider kind serializes");
        assert_eq!(written, Value::String(name.to_owned()), "{row:?}");
        let read: RuntimeProviderKind =
            serde_json::from_value(Value::String(name.to_owned())).expect("serde reads the name");
        assert_eq!(read, row, "{name}");
    }
}

/// Every `RuntimeRole` row, as the hand `as_str` table spelled it.
const RUNTIME_ROLE_ROWS: [(RuntimeRole, &str); 3] = [
    (RuntimeRole::Orchestrator, "orchestrator"),
    (RuntimeRole::Subagent, "subagent"),
    (RuntimeRole::Summarizer, "summarizer"),
];

#[test]
fn every_runtime_role_keeps_its_name() {
    assert_eq!(RuntimeRole::Orchestrator.as_str(), "orchestrator");
    assert_eq!(RuntimeRole::Subagent.as_str(), "subagent");
    assert_eq!(RuntimeRole::Summarizer.as_str(), "summarizer");
}

#[test]
fn every_runtime_role_name_is_its_serde_name() {
    for (row, name) in RUNTIME_ROLE_ROWS {
        let written = serde_json::to_value(row).expect("a runtime role serializes");
        assert_eq!(written, Value::String(name.to_owned()), "{row:?}");
        let read: RuntimeRole =
            serde_json::from_value(Value::String(name.to_owned())).expect("serde reads the name");
        assert_eq!(read, row, "{name}");
    }
}

/// Every `OneironerRuntime` row, as the hand `as_str` table spelled it.
const ONEIRONER_RUNTIME_ROWS: [(OneironerRuntime, &str); 2] = [
    (OneironerRuntime::Auto, "auto"),
    (OneironerRuntime::Candle, "candle"),
];

#[test]
fn every_oneironer_runtime_keeps_its_name() {
    assert_eq!(OneironerRuntime::Auto.as_str(), "auto");
    assert_eq!(OneironerRuntime::Candle.as_str(), "candle");
}

#[test]
fn every_oneironer_runtime_name_is_its_serde_name() {
    for (row, name) in ONEIRONER_RUNTIME_ROWS {
        let read: OneironerRuntime =
            serde_json::from_value(Value::String(name.to_owned())).expect("serde reads the name");
        assert_eq!(read, row, "{name}");
    }
}

#[test]
fn every_oneironer_runtime_name_reads_back() {
    for (row, name) in ONEIRONER_RUNTIME_ROWS {
        assert_eq!(name.parse::<OneironerRuntime>(), Ok(row), "{name}");
    }
    assert_eq!(
        "not-a-name".parse::<OneironerRuntime>(),
        Err("oneironer runtime must be auto or candle".to_owned())
    );
}
