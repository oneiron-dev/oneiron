//! Moved from `crates/oneiron/src/memory/authorship.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_base::error::Error;
use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;

// EntityId deliberately has no global serde implementation.
pub mod entity_serde {
    use oneiron_contracts::entity_id::EntityId;
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(id: &EntityId, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&id.to_hex())
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<EntityId, D::Error> {
        let text = String::deserialize(deserializer)?;
        EntityId::from_hex(&text).map_err(serde::de::Error::custom)
    }
}
