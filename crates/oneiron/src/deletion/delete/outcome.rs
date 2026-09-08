//! Reason-aware delete result type and its missing() constructor.

use crate::entity_id::EntityId;

/// Result for a reason-aware delete request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeleteEntityOutcome {
    pub existed: bool,
    pub receipt_id: Option<EntityId>,
    pub sweep_key: Option<Vec<u8>>,
}

impl DeleteEntityOutcome {
    pub(crate) const fn missing() -> Self {
        Self {
            existed: false,
            receipt_id: None,
            sweep_key: None,
        }
    }
}
