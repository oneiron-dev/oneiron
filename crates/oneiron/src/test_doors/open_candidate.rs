//! Thin wrapper over the native outside-set candidate door.

use serde_json::Value;

use crate::{Result, Vault};

/// Builds, without writing, the claim the one outside-set candidate
/// `operand` on `attempt` at `now_ms` would land as, and returns the claim
/// id with the prepared claim body's fields.
///
/// Calls the real assembly, the real outside-set seal and the real
/// promotion preparation with native provenance. No model is asked, and
/// nothing is written.
///
/// # Errors
///
/// The vault's, operands the bound read refuses, operands that form a
/// native conflict or seal to anything but one write, a native promotion
/// refusal, and a claim that does not encode.
pub fn build_native_candidate(
    vault: &Vault,
    attempt: &str,
    now_ms: u64,
    operand: &Value,
) -> Result<Value> {
    crate::dreamer_consolidation::resources::open_candidate_door::build_native_candidate_json(
        vault, attempt, now_ms, operand,
    )
}
