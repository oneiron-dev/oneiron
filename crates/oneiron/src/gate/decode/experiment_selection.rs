//! Strict POLICY_MANIFEST experiment-selection row decoder.
use rmpv::Value;

use crate::autoreason_campaign::selection::SelectionPolicyRow;

pub(super) fn parse_experiment_selection(value: &Value) -> Option<Vec<SelectionPolicyRow>> {
    let mut bytes = Vec::new();
    rmpv::encode::write_value(&mut bytes, value).ok()?;
    let rows: Vec<SelectionPolicyRow> = rmp_serde::from_slice(&bytes).ok()?;
    if rows.len() > 1024 || rows.iter().any(|row| !row.valid()) {
        return None;
    }
    Some(rows)
}
