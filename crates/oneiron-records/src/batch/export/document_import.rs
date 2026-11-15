//! Moved from `crates/oneiron/src/batch/export/document_import.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_base::error::Error;
use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;

pub fn invalid(reason: &str) -> Error {
    Error::InvalidConfig(format!("whole-vault import: {reason}"))
}

pub fn parse_id(text: &str) -> Result<EntityId> {
    let id = EntityId::from_hex(text)?;
    if id.to_hex() != text {
        return Err(invalid("entity ID must be lowercase hex"));
    }
    Ok(id)
}
