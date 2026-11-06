//! A mail's header-only revisions go once its body lands (FIX 15413).
//!
//! The importer lands a listed message's headers first, as one MESSAGE, and
//! the whole message later, as the next revision of the same TURN. Both
//! stayed bound and searchable, so one mail answered a search twice. The
//! landing that moves a message from its headers to its body owes each
//! header revision it supersedes a delete, in its own transaction
//! ([`super::state::owe_header_retirements_in_txn`]); each then goes through
//! the ordinary user delete, and its owed row leaves once that delete
//! returns. Every import step of the source first deletes what is still
//! owed (a crash, a refused delete), whether or not the provider lists the
//! message again. The occurrence keeps every revision's id and content hash,
//! so a later listing of the same headers lands nothing, and the body
//! revision's rows keep the audience binding their landing gave.

use super::state::HEADER_RETIREMENTS;
use crate::deletion::DeleteReason;
use crate::{EntityId, Error, Result, Vault};

/// The delete a superseded header revision takes: the ordinary user delete,
/// as a "forget too" provider delete uses, so every device drops it and a
/// restore can bring it back (CALLS FIX-15413-header-retire).
const SUPERSEDED_HEADER_DELETE: DeleteReason = DeleteReason::UserDelete;

/// Deletes each header revision `source` owes, and drops its owed row once
/// its delete returns. A delete that fails is logged and stays owed for the
/// source's next step; the caller goes on either way.
pub(super) fn retire_superseded_headers(vault: &Vault, source: EntityId) {
    if let Err(error) = retire(vault, source) {
        tracing::warn!(%error, "a mail's superseded header revision stays owed its delete");
    }
}

fn retire(vault: &Vault, source: EntityId) -> Result<()> {
    let owed = {
        let txn = vault.store.env.read_txn()?;
        HEADER_RETIREMENTS.scan_keys(&vault.store, &txn, source.as_bytes())?
    };
    let mut failure = None;
    for key in owed {
        match vault.delete_entity_with_reason(&key.2, SUPERSEDED_HEADER_DELETE) {
            // A revision an erase or the owner took already owes nothing.
            Ok(_) | Err(Error::EntityNotFound) => {
                vault.with_write_txn_grouped(|txn| {
                    HEADER_RETIREMENTS
                        .delete(&vault.store, txn, &key)
                        .map(|_| ())
                })?;
            }
            Err(error) => failure = Some(error),
        }
    }
    failure.map_or(Ok(()), Err)
}
