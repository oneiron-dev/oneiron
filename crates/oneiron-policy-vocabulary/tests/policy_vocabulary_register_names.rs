//! The names of 2 name lists in `oneiron-policy-vocabulary`, one line per row, generated from
//! `scripts/ratchet/hand_name_tables.py --names --only <file>` before each list became a Register
//! (Fable pass 25, the Register wave): the names each hand table wrote. Green on the hand tables and
//! on the derive, so no stored or sent name changed (M-1 keep). Each name is also pinned to the one
//! serde reads and writes, and each kept reverse fn to its rows.
//!
//! - `crates/oneiron-policy-vocabulary/src/policy_model/contract.rs`
//! - `crates/oneiron-policy-vocabulary/src/policy_model/pattern.rs`

use oneiron_policy_vocabulary::policy_model::contract::PolicyOutputContract;
use oneiron_policy_vocabulary::policy_model::pattern::PolicyPatternRole;
use serde_json::Value;

/// Every row of `PolicyOutputContract`, as its hand table spelled it.
const POLICY_OUTPUT_CONTRACT_ROWS: [(PolicyOutputContract, &str); 3] = [
    (PolicyOutputContract::Binary, "binary"),
    (PolicyOutputContract::CategoryJson, "category_json"),
    (PolicyOutputContract::RationaleJson, "rationale_json"),
];

#[test]
fn every_policy_output_contract_keeps_its_name() {
    assert_eq!(PolicyOutputContract::Binary.as_str(), "binary");
    assert_eq!(PolicyOutputContract::CategoryJson.as_str(), "category_json");
    assert_eq!(
        PolicyOutputContract::RationaleJson.as_str(),
        "rationale_json"
    );
}

#[test]
fn every_policy_output_contract_name_is_its_serde_name() {
    for (row, name) in POLICY_OUTPUT_CONTRACT_ROWS {
        let written = serde_json::to_value(row).expect("a row serializes");
        assert_eq!(written, Value::String(name.to_owned()), "{row:?}");
        let read: PolicyOutputContract =
            serde_json::from_value(Value::String(name.to_owned())).expect("serde reads the name");
        assert_eq!(read, row, "{name}");
    }
}

#[test]
fn policy_output_contract_parse_reads_each_name_back() {
    for (row, name) in POLICY_OUTPUT_CONTRACT_ROWS {
        assert_eq!(PolicyOutputContract::parse(name), Some(row), "{name}");
    }
    assert_eq!(PolicyOutputContract::parse("not.a.row"), None);
}

/// Every row of `PolicyPatternRole`, as its hand table spelled it.
const POLICY_PATTERN_ROLE_ROWS: [(PolicyPatternRole, &str); 3] = [
    (PolicyPatternRole::Escalate, "escalate"),
    (PolicyPatternRole::Decide, "decide"),
    (PolicyPatternRole::Log, "log"),
];

#[test]
fn every_policy_pattern_role_keeps_its_name() {
    assert_eq!(PolicyPatternRole::Escalate.as_str(), "escalate");
    assert_eq!(PolicyPatternRole::Decide.as_str(), "decide");
    assert_eq!(PolicyPatternRole::Log.as_str(), "log");
}

#[test]
fn every_policy_pattern_role_name_is_its_serde_name() {
    for (row, name) in POLICY_PATTERN_ROLE_ROWS {
        let written = serde_json::to_value(row).expect("a row serializes");
        assert_eq!(written, Value::String(name.to_owned()), "{row:?}");
        let read: PolicyPatternRole =
            serde_json::from_value(Value::String(name.to_owned())).expect("serde reads the name");
        assert_eq!(read, row, "{name}");
    }
}

#[test]
fn policy_pattern_role_parse_reads_each_name_back() {
    for (row, name) in POLICY_PATTERN_ROLE_ROWS {
        assert_eq!(PolicyPatternRole::parse(name), Some(row), "{name}");
    }
    assert_eq!(PolicyPatternRole::parse("not.a.row"), None);
}
