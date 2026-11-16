//! Moved from `crates/oneiron/src/ingest/history/land.rs` (lib split R3: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;

pub fn derive(domain: &[u8], parts: &[&str]) -> Result<EntityId> {
    let parts: Vec<&[u8]> = parts.iter().map(|part| part.as_bytes()).collect();
    EntityId::derive(domain, &parts)
}
