//! Shared quota-bound diagnostic replay for Observer B and forward rematerialization.

use super::quota;
use crate::Vault;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::self_heal::validate_diagnostic_event_body_bytes;
use crate::temporal::TimeRange;

pub(super) fn ingest_diagnostic_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    id: &EntityId,
    blob: &[u8],
    lease_vault_id: u64,
) -> Result<bool> {
    let header =
        EntityMetadataHeader::parse(blob).ok_or(Error::CorruptedIndex("entity metadata"))?;
    let data = &blob[ENTITY_METADATA_HEADER_LEN..];
    validate_diagnostic_event_body_bytes(data)?;
    if let Some(existing) = vault.store.entities.get(&*wtxn, id.as_bytes())?
        && *existing == *blob
    {
        return Ok(false);
    }
    let debit = quota::try_accept_maintenance_ingest_peer_in_txn(
        vault,
        wtxn,
        quota::peer_key_from_diagnostic_stream(lease_vault_id),
        crate::unix_seconds_now(),
    )?;
    let result = vault
        .batch_in()
        .put_replicated(
            id,
            header.entity_type,
            TimeRange {
                start: header.occurred_start,
                end: header.occurred_end,
            },
            header.learned_at,
            data,
        )
        .apply(wtxn);
    if let Err(err) = result {
        // Observer B quarantines remote failures and commits its siblings in
        // this same transaction. Restore the debit before returning the error.
        // Forward rematerialization also aborts its per-row transaction.
        if let Some(debit) = debit {
            quota::rollback_maintenance_ingest_debit_in_txn(vault, wtxn, debit)?;
        }
        return Err(err);
    }
    Ok(true)
}
