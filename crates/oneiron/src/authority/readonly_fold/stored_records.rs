//! The vault id a vault read off its disk folds to (PAD-1, FIX 11293): the
//! AUTHORITY_LOG records a read-only door took in the transaction that read
//! its custody and its pad objects, folded as [`fold_authority_log`] folds a
//! log, with no `Store`, no cache and no write. A vault's id is its genesis
//! root, so no posture, pin or clock of the install it is open in changes
//! which vault the rows name. No checkpoint image the vault adopted is read:
//! a vault that holds its genesis only through one folds to none here.

use super::*;

/// The vault id `records` fold to: each an AUTHORITY_LOG record as the type
/// index names it, its id key and its stored bytes (header and signed body).
/// `None` when they fold to no one vault: no valid genesis among them, or
/// more than one root.
///
/// # Errors
///
/// A record of another type, or a header or an entry that does not decode.
pub(crate) fn folded_vault_id_of_records(
    records: &[(Vec<u8>, Vec<u8>)],
) -> Result<Option<AuthorityVaultId>> {
    let mut entries = Vec::with_capacity(records.len());
    for (_, raw) in records {
        let header =
            EntityMetadataHeader::parse(raw).ok_or(Error::CorruptedIndex("entity header"))?;
        if header.entity_type != ENTITY_TYPE_AUTHORITY_LOG {
            return Err(Error::CorruptedIndex("type index row kind mismatch"));
        }
        let body = raw
            .get(ENTITY_METADATA_HEADER_LEN..)
            .ok_or(Error::CorruptedIndex("entity header"))?;
        entries.push(decode_authority_log_entry_body(body)?);
    }
    Ok(fold_authority_log(&entries).vault_id)
}
