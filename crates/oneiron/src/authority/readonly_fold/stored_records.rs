//! The vault id a vault read off its disk folds to (PAD-1, FIX 11293): the
//! AUTHORITY_LOG records a read-only door took in the transaction that read
//! its custody and its pad objects, folded as [`fold_authority_log`] folds a
//! log, with no `Store`, no cache and no write. A vault's id is its genesis
//! root, so no posture, pin or clock of the install it is open in changes
//! which vault the rows name. A vault that adopted a checkpoint image, and
//! may hold its genesis only through it, folds from that image as the live
//! fold does (FIX 11823): its stored pin row and the image bytes it names,
//! read in the same transaction, verified as a stored adoption is.

use super::*;

/// The vault id `records` fold to: each an AUTHORITY_LOG record as the type
/// index names it, its id key and its stored bytes (header and signed body).
/// A vault that adopted a checkpoint image (`adopted_pin`, its stored pin
/// row, and `adopted_image`, the stored bytes of the image that row names)
/// folds from it, as the live fold does: the pin verified against the image
/// ([`crate::authority::checkpoint_adopt::verified_adoption_of_rows`]), the
/// image's vault id seeded, then the records above it, the ones it does not
/// cover, folded for another root. `None` when they fold to no one vault: no
/// valid genesis among them and no adopted image, or more than one root.
///
/// # Errors
///
/// A record of another type, or a header or an entry that does not decode;
/// a pin row that does not decode, or an adoption whose image is missing or
/// no longer verifies.
pub(crate) fn folded_vault_id_of_records(
    records: &[(Vec<u8>, Vec<u8>)],
    adopted_pin: Option<&[u8]>,
    adopted_image: Option<&[u8]>,
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
    let Some(pin_row) = adopted_pin else {
        return Ok(fold_authority_log(&entries).vault_id);
    };
    let verified =
        crate::authority::checkpoint_adopt::verified_adoption_of_rows(pin_row, adopted_image);
    let adopted = match verified {
        Ok(adopted) => adopted,
        // A pin that does not verify, or names no image here, folds as the
        // paired read did before it took the pin: from the records alone.
        Err(error) => {
            tracing::warn!(
                kind = ?error.kind(),
                "a disk source's adopted checkpoint pin did not verify; its vault id folds \
                 from its records alone"
            );
            return Ok(fold_authority_log(&entries).vault_id);
        }
    };
    let image = adopted.image();
    let mut above = Vec::new();
    for entry in entries {
        if !image.rows.contains_key(&authority_entry_hash(&entry)?) {
            above.push(entry);
        }
    }
    // A genesis above the image roots another vault: more than one root.
    let fold = fold_authority_log(&above);
    let another_root = match fold.vault_id {
        Some(root) => root != image.vault_id,
        None => fold.vault_root_is_conflicted(),
    };
    Ok((!another_root).then_some(image.vault_id))
}
