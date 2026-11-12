//! FIX 7789: lose one NOTE posting, then run the real deindex self-heal.

use crate::store::text_index::codec::{PostingLookup, find_posting_dup, posting_key};
use crate::store::text_index::deindex_text;
use crate::{EntityId, Error, Result, Vault};

/// Drops one posting duplicate before deindexing in the same transaction.
///
/// # Errors
///
/// The posting is absent, or the store or deindex rejects the operation.
pub fn deindex_after_lost_posting(vault: &Vault, id: &EntityId, term: &str) -> Result<()> {
    let mut wtxn = vault.store.env.write_txn()?;
    let entry = match find_posting_dup(&vault.store, &wtxn, term, id)? {
        PostingLookup::Found(entry) => entry,
        _ => {
            return Err(Error::InvalidConfig(format!(
                "missing posting duplicate for term {term:?}"
            )));
        }
    };
    if !vault.store.text_postings.delete_one_duplicate(
        &mut wtxn,
        posting_key(term).as_bytes(),
        &entry,
    )? {
        return Err(Error::InvalidConfig(format!(
            "posting duplicate vanished for term {term:?}"
        )));
    }
    deindex_text(&vault.store, &mut wtxn, id)?;
    wtxn.commit()?;
    Ok(())
}
