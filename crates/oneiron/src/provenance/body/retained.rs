//! The side rows a kept body stands on (FIX 8850). A left environment's purge
//! keeps a held record and every side row whose key names it; a descriptor's
//! digest-keyed rows name no owner, so this spells them from the owner's own
//! descriptors, before the purge removes a row. Only the owner's occurrence
//! is kept: another holder of the same bytes keeps nothing here, and a digest
//! is never a read permit.

use std::collections::HashSet;

use heed::RoTxn;

use super::{BODY_DIGEST, owned_bodies_in_txn};
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::side_table;
use crate::store::{BODY_INSTANCES, BODY_KEYS, Store, remembered_body_instances_in_txn};

/// Adds to `keys` the full `vault_meta` keys of the rows `owner`'s bodies
/// stand on. For each descriptor that holds bytes, a complete body or an
/// incomplete one's retained part: its own digest holder row, the digest's
/// key row and every instance row remembered under it, the result body row
/// of that digest, and this occurrence's result taint and secret marks. A
/// descriptor that holds no bytes needs none of them; its own row names the
/// owner. A key with no row behind it keeps nothing. Nothing is opened,
/// decrypted, published or repaired.
///
/// # Errors
///
/// Storage errors, and a descriptor that does not decode.
pub(crate) fn retained_body_side_keys_in_txn(
    store: &Store,
    txn: &RoTxn<'_>,
    owner: &EntityId,
    keys: &mut HashSet<Vec<u8>>,
) -> Result<()> {
    for body in owned_bodies_in_txn(store, txn, owner)? {
        let Some(held) = body.state.held() else {
            continue;
        };
        let digest = held.blake3;
        keys.insert(BODY_DIGEST.key_bytes(&(digest, body.occurrence)));
        keys.insert(BODY_KEYS.key_bytes(&digest));
        for instance in remembered_body_instances_in_txn(store, txn, &digest)? {
            keys.insert(BODY_INSTANCES.key_bytes(&(digest, instance)));
        }
        let row = crate::code_run::code_run_body_row_key(&digest);
        if let Some(handle) = row
            .strip_prefix(side_table::CODE_RUN_RAW_OUTPUT.prefix)
            .and_then(|handle| std::str::from_utf8(handle).ok())
        {
            // The marks of this occurrence alone, keyed as
            // `ResultOccurrence::mark_key` spells them: a MESSAGE that keeps
            // a run's result carries them under its own occurrence.
            let mark = format!(
                "{}{}",
                crate::code_run::ResultOccurrence::marks_prefix(handle),
                body.occurrence.to_hex()
            );
            for decl in [
                &side_table::CODE_RUN_RAW_OUTPUT_TAINT,
                &side_table::CODE_RUN_RAW_OUTPUT_SECRET,
            ] {
                let mut key = decl.prefix.to_vec();
                key.extend_from_slice(mark.as_bytes());
                keys.insert(key);
            }
        }
        keys.insert(row);
    }
    Ok(())
}
