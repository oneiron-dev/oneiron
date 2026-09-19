//! Diagnostic observations are account-local; peers cannot author detector output.
use crate::{EntityId, Result, Vault};
pub(super) fn ingest_diagnostic_in_txn(
    _vault: &Vault,
    _txn: &mut heed::RwTxn<'_>,
    _id: &EntityId,
    _blob: &[u8],
    _vault_id: u64,
) -> Result<bool> {
    Ok(false)
}
