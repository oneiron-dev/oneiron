//! Doors for tests/msgpack_lib_rows_b.rs (PLAN-UC-08 PR 5b). Compiled only under
//! --cfg oneiron_test_support; never API.

use rmpv::Value;

use crate::error::Result;

/// The value a proposal artifact record, or one of its spans, holds under `key`.
pub fn proposal_field(entries: &[(Value, Value)], key: &str) -> Result<Option<Value>> {
    crate::edit_distance::proposal_field_for_test(entries, key)
}

/// The value a blob artifact settlement record, or one of its anchors, holds under `key`.
pub fn settlement_field(entries: &[(Value, Value)], key: &str) -> Result<Option<Value>> {
    crate::edit_settle::settlement_field_for_test(entries, key)
}

/// The value a workspace roster row (preset, roster member or onboarding journal) holds
/// under `key`.
pub fn roster_required(entries: &[(Value, Value)], key: &str) -> Result<Value> {
    crate::workspace_roster::roster_required_for_test(entries, key)
}
