//! Reason-aware delete result type and its missing() constructor.

use crate::entity_id::EntityId;

/// Result for a reason-aware delete request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeleteEntityOutcome {
    pub existed: bool,
    pub receipt_id: Option<EntityId>,
    pub sweep_key: Option<Vec<u8>>,
    /// The turn-program rows the purge removed whole because they did not decode (FIX 5736,
    /// FIX 5775): the same `turn_program.undecodable_rows_removed:N` details the gated hard
    /// purge names on its gate decision. Empty when none did, or when no hard purge ran.
    pub turn_program_details: Vec<String>,
}

impl DeleteEntityOutcome {
    /// A delete that erased nothing: no scope, no receipt, no sweep, no details.
    pub(crate) fn missing() -> Self {
        Self {
            existed: false,
            receipt_id: None,
            sweep_key: None,
            turn_program_details: Vec::new(),
        }
    }
}

/// Optional cascade/purge choice for the user delete door. The default is a
/// propagated tombstone with a local shell, not irreversible erasure.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DeleteEntityOptions {
    pub purge: bool,
}
