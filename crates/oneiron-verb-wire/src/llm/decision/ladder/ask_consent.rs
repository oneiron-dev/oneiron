//! Moved from `crates/oneiron/src/llm/decision/ladder/ask_consent.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::vault_shape::grant::ShapeGrantBound;
use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;
use oneiron_store::consent_bound::GrantBound;
use oneiron_store::model_decision::invalid;
use serde::Deserialize;
use serde::Serialize;

/// A requirement's plain form; one with no plain form (a contact clearance's Scope
/// envelope) cannot ride an ask.
pub fn plain(bound: &GrantBound) -> Result<ShapeGrantBound> {
    ShapeGrantBound::of(bound)
        .ok_or_else(|| invalid("an ask carries a requirement only in its plain form"))
}

/// `hex` as an entity id, when it is one.
pub fn entity(hex: Option<&str>) -> Result<Option<EntityId>> {
    hex.map(|hex| {
        EntityId::from_hex(hex).map_err(|_| invalid("an ask names a place by entity id hex"))
    })
    .transpose()
}
