//! Thin read-only wrapper over the native extraction routing door.

use serde_json::Value;

use crate::{Result, Vault};

/// Returns native ready, held, judge, correction and outside-set write choices.
///
/// Calls the real assembly and sealed-write path without minting or landing.
pub fn native_routes(
    vault: &Vault,
    attempt: &str,
    now_ms: u64,
    operands: &[Value],
) -> Result<Value> {
    crate::dreamer_consolidation::extraction_routing_door::routing_choices_json(
        vault, attempt, now_ms, operands,
    )
}
