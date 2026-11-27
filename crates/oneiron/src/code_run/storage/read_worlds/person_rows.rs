//! The code-run read ledger's minimum outbound classification.

use super::{HEADERS, HeaderKey, ROW_SCOPES, scopes_prefix};
use crate::{EntityId, Result, Vault, registry};

/// Registry types that carry authority or policy, not a person's words.
/// Anything absent from this list, including an unresolved type, counts.
const NON_PERSON_ROW_TYPES: &[u8] = &[
    registry::ENTITY_TYPE_ACCESS_GRANT,
    registry::ENTITY_TYPE_FEDERATION_GRANT,
    registry::ENTITY_TYPE_OUTBOUND_GRANT,
    registry::ENTITY_TYPE_POLICY_MANIFEST,
];

impl Vault {
    /// Whether a canonical code run was served a row that can carry a
    /// person's words. An open epoch alone does not count: a live run has
    /// one while making this call.
    pub(crate) fn run_was_served_person_rows_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        run: EntityId,
    ) -> Result<bool> {
        if HEADERS
            .get(&self.store, txn, &HeaderKey(run))?
            .is_some_and(|header| !header.unknown.is_empty())
        {
            return Ok(true);
        }
        for key in ROW_SCOPES.scan_keys(&self.store, txn, &scopes_prefix(run))? {
            let entity_type = crate::batch::stored_entity_type(&self.store, txn, &key.row)?;
            if !entity_type.is_some_and(|entity_type| NON_PERSON_ROW_TYPES.contains(&entity_type)) {
                return Ok(true);
            }
        }
        Ok(false)
    }
}
