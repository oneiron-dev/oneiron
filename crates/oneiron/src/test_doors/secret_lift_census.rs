//! Doors for `tests/connector_key_public_secret_shape.rs` (FIX
//! SCREENING-PER-TOOL-SKIP, PR C2): the secret lift census's read of one
//! stored entity row, as the sweep reads each record it walks.

use crate::Vault;
use crate::batch::ENTITY_METADATA_HEADER_LEN;
use crate::entity_id::EntityId;
use crate::error::Result;

/// The census's reason for a hit in a stored row of type `entity_type`
/// whose body is `body`, under an id the vault holds no index or staged text
/// for; `None` when the census leaves the row as it is.
pub fn census_hit(vault: &Vault, entity_type: u8, body: &[u8]) -> Result<Option<&'static str>> {
    let mut raw = vec![0u8; ENTITY_METADATA_HEADER_LEN];
    raw[0] = entity_type;
    raw.extend_from_slice(body);
    let id = EntityId::from_bytes([0x5c; 16])?;
    let txn = vault.store.env.read_txn()?;
    crate::batch::secret_scan::census_hit_in_txn(vault, &txn, &id, &raw)
}
