//! A mail's header-only revisions go once its body lands (FIX 15413).
//!
//! The importer lands a listed message's headers first, as one MESSAGE, and
//! the whole message later, as the next revision of the same TURN. Both
//! stayed bound and searchable, so one mail answered a search twice. The
//! landing that moves a message from its headers to its body lists the
//! header revisions it supersedes as owed, in its own transaction; each then
//! goes through the ordinary user delete and leaves the list once its delete
//! returns. A landing that finds revisions still owed (a crash, a refused
//! delete) deletes them first. The occurrence keeps every revision's id and
//! content hash, so a later listing of the same headers lands nothing, and
//! the body revision's rows keep the audience binding their landing gave.

use super::state::OCCURRENCES;
use crate::deletion::DeleteReason;
use crate::{EntityId, Error, Result, Vault};

/// The delete a superseded header revision takes: the ordinary user delete,
/// as a "forget too" provider delete uses, so every device drops it and a
/// restore can bring it back (CALLS FIX-15413-header-retire).
const SUPERSEDED_HEADER_DELETE: DeleteReason = DeleteReason::UserDelete;

/// Deletes each header revision the occurrence at `key` owes, and drops
/// each from the owed list once its delete returns. A delete that fails is
/// logged and stays owed for the next landing; the landing goes on either
/// way.
pub(super) fn retire_superseded_headers(vault: &Vault, key: &(EntityId, [u8; 32])) {
    if let Err(error) = retire(vault, key) {
        tracing::warn!(%error, "a mail's superseded header revision stays owed its delete");
    }
}

fn retire(vault: &Vault, key: &(EntityId, [u8; 32])) -> Result<()> {
    let owed = {
        let txn = vault.store.env.read_txn()?;
        OCCURRENCES
            .get(&vault.store, &txn, key)?
            .map(|occurrence| occurrence.superseded_headers)
            .unwrap_or_default()
    };
    if owed.is_empty() {
        return Ok(());
    }
    let mut deleted = Vec::new();
    let mut failure = None;
    for message in &owed {
        match vault.delete_entity_with_reason(message, SUPERSEDED_HEADER_DELETE) {
            // A revision an erase or the owner took already owes nothing.
            Ok(_) | Err(Error::EntityNotFound) => deleted.push(*message),
            Err(error) => {
                failure = Some(error);
                break;
            }
        }
    }
    if !deleted.is_empty() {
        vault.with_write_txn_grouped(|txn| {
            let Some(mut current) = OCCURRENCES.get(&vault.store, txn, key)? else {
                return Ok(());
            };
            current
                .superseded_headers
                .retain(|message| !deleted.contains(message));
            OCCURRENCES.put(&vault.store, txn, key, &current)
        })?;
    }
    failure.map_or(Ok(()), Err)
}
