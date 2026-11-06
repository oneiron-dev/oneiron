//! Owned native conversation-write receipt lift for opaque JSON (FIX 12936).

use super::{Lift, OneironError, WireJson};

impl Lift<oneiron::core_write::CoreEntityWriteReceipt> for crate::CoreEntityWriteReceipt {
    fn lift(receipt: oneiron::core_write::CoreEntityWriteReceipt) -> Result<Self, OneironError> {
        let oneiron::core_write::CoreEntityWriteReceipt {
            id,
            entity_type,
            learned_at,
            body,
        } = receipt;
        let body = WireJson::lift(body)?;
        Ok(Self {
            id,
            entity_type,
            learned_at,
            body,
        })
    }
}
