//! Thin wrappers over the native conflict-resolution build doors.

use serde_json::Value;

use crate::{Result, Vault};

/// Builds, without writing, the claim native's merge of the one conflict
/// `operands` form on `attempt` at `now_ms` would land with kept member
/// `kept` and merged value `value`, and returns the claim id with the
/// prepared claim body's fields plus the replaced head.
///
/// `kept` is an index into `operands` in operand order. Calls the real
/// assembly, the shared kept recompute, the real `merged_candidate`, the
/// real seal for that one output, and the real promotion preparation with
/// native provenance. No model is asked, and nothing is written.
///
/// # Errors
///
/// The vault's, operands the bound read refuses, operands that form
/// anything but one native conflict, a kept member the set does not name,
/// a null value, an output that seals to anything but one write, a native
/// promotion refusal, and a claim that does not encode.
pub fn build_native_merge(
    vault: &Vault,
    attempt: &str,
    now_ms: u64,
    operands: &[Value],
    kept: usize,
    value: &Value,
) -> Result<Value> {
    crate::dreamer_consolidation::open_conflict_door::build_native_merge_json(
        vault, attempt, now_ms, operands, kept, value,
    )
}

/// Builds, without writing, the claim native's skip of the one conflict
/// `operands` form on `attempt` at `now_ms` would land, and returns the
/// claim id with the prepared claim body's fields plus the replaced head.
/// The supplied `confidence` stamps the member before the seal.
///
/// Calls the real assembly, native's skip rule, the real seal for that one
/// output, and the real promotion preparation with native provenance. No
/// model is asked, and nothing is written.
///
/// # Errors
///
/// The vault's, operands the bound read refuses, operands that form
/// anything but one native conflict, a set native's skip rule refuses, an
/// output that seals to anything but one write, a native promotion
/// refusal, and a claim that does not encode.
pub fn build_native_skip(
    vault: &Vault,
    attempt: &str,
    now_ms: u64,
    operands: &[Value],
    confidence: f32,
) -> Result<Value> {
    crate::dreamer_consolidation::open_conflict_door::build_native_skip_json(
        vault, attempt, now_ms, operands, confidence,
    )
}
