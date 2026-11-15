//! Thin wrappers over the native open-conflict marker doors.

use serde_json::Value;

use crate::{Result, Vault};

/// Parks the one native conflict `operands` form on `attempt` at `now_ms`,
/// and returns the marker id, the member claims and the prior heads.
///
/// Calls the real assembly and the branch's own open-conflict write under
/// its fence. No model is asked.
///
/// # Errors
///
/// The vault's, operands the bound read refuses, and operands that form no
/// native conflict or more than one.
pub fn park_native_open_conflict(
    vault: &Vault,
    attempt: &str,
    now_ms: u64,
    operands: &[Value],
) -> Result<Value> {
    crate::dreamer_consolidation::open_conflict_door::park_open_conflict_json(
        vault, attempt, now_ms, operands,
    )
}

/// Builds, without writing, the marker the one native conflict `operands`
/// form on `attempt` at `now_ms` would park, and returns the marker id, the
/// member claims, the prior heads, and the marker claim's predicate,
/// subject, value and evidence envelope.
///
/// Calls the real assembly and the shared marker builder with native's
/// provenance. No model is asked, and nothing is written.
///
/// # Errors
///
/// As `park_native_open_conflict`, and a marker claim that does not encode.
pub fn build_native_open_conflict(
    vault: &Vault,
    attempt: &str,
    now_ms: u64,
    operands: &[Value],
) -> Result<Value> {
    crate::dreamer_consolidation::open_conflict_door::build_open_conflict_json(
        vault, attempt, now_ms, operands,
    )
}
