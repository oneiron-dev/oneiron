//! Node-local record of the Gmail messages a mailbox run set aside (FIX 6007).
//!
//! A message that cannot be admitted for a reason of its own (ids or metadata
//! that do not normalize, an envelope the adapter refuses, a routing rejection
//! that names that message alone) is written here before its page goes on, so
//! one poison message never stalls the mailbox and never vanishes unseen. The
//! row keeps the evidence across restarts; a retried page writes it once.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::side_table::{self, Named, SideTable};
use crate::store::Store;

const SKIPPED_MESSAGES: SideTable<(EntityId, [u8; 32]), GmailSkippedMessage, Named> =
    SideTable::new(&side_table::GMAIL_MAILBOX_SKIPPED);

#[doc(hidden)]
pub use oneiron_records::channel_identity_provider::mailbox_skipped::{
    GmailSkipStage, GmailSkippedMessage,
};

fn message_key(identity_id: EntityId, message_id: &str) -> (EntityId, [u8; 32]) {
    (identity_id, Sha256::digest(message_id.as_bytes()).into())
}

/// Persists `skipped` for `identity_id`'s mailbox unless a row for the same
/// message already stands, which it keeps, and returns the row as stored. A
/// stored row that no longer decodes is written again.
///
/// # Errors
///
/// Store or encode failure; the caller's page stops there.
pub(super) fn record_gmail_skipped_message(
    vault: &Vault,
    identity_id: EntityId,
    skipped: GmailSkippedMessage,
) -> Result<GmailSkippedMessage> {
    let key = message_key(identity_id, &skipped.message_id);
    vault.try_with_write_txn_grouped(|txn| {
        if let Some(stored) = SKIPPED_MESSAGES.get_lenient(&vault.store, txn, &key)? {
            return Ok(stored);
        }
        SKIPPED_MESSAGES.put(&vault.store, txn, &key, &skipped)?;
        Ok(skipped)
    })
}

/// Every message a run set aside from `identity_id`'s mailbox, with its stage
/// and full reason, in key order. A restart keeps them.
///
/// # Errors
///
/// Store failure or a row that does not decode.
pub fn gmail_skipped_messages(
    vault: &Vault,
    identity_id: EntityId,
) -> Result<Vec<GmailSkippedMessage>> {
    let txn = vault.store.env.read_txn()?;
    Ok(SKIPPED_MESSAGES
        .scan_from(&vault.store, &txn, identity_id.as_bytes())?
        .into_iter()
        .map(|(_, skipped)| skipped)
        .collect())
}

/// Drops every message set aside from `identity_id`'s mailbox, in the
/// transaction that deletes the identity: a deleted identity leaves no
/// skipped-message evidence behind.
///
/// # Errors
///
/// Store failure, which fails the deletion with it.
pub(crate) fn drop_skipped_messages_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    identity_id: &EntityId,
) -> Result<()> {
    SKIPPED_MESSAGES.delete_from(store, txn, identity_id.as_bytes())?;
    Ok(())
}
