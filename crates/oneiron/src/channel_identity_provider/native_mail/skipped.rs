//! Node-local record of the native mail messages an inbox poll set aside.
//!
//! A message whose own failure stops its inbox poll after poll
//! ([`NATIVE_MAIL_SET_ASIDE_AFTER_STOPS`] polls in a row) is written here and
//! the poll goes past it, so one poison message never stalls the mailbox and
//! never vanishes unseen. A transport or storage failure says nothing about
//! the message and never counts. The row keeps the evidence across restarts;
//! a retried page writes it once.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::side_table::{self, Named, SideTable};
use crate::store::Store;

/// How many polls in a row one message's own failure stops before the poll
/// sets it aside and reads on.
pub const NATIVE_MAIL_SET_ASIDE_AFTER_STOPS: u32 = 3;

const SKIPPED_MESSAGES: SideTable<(EntityId, [u8; 32]), NativeMailSkippedMessage, Named> =
    SideTable::new(&side_table::NATIVE_MAIL_MAILBOX_SKIPPED);

/// One native mail message set aside so its inbox could go on: what it was,
/// why it stopped and how often, never its bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativeMailSkippedMessage {
    /// Lower-case hex id of the native mail identity whose inbox was read.
    pub identity_ref: String,
    /// The identity's mailbox address.
    pub mailbox_address: String,
    /// The server's JMAP email id, exactly as it returned it.
    pub message_id: String,
    /// The full error of the poll that set it aside.
    pub reason: String,
    /// The polls in a row the message stopped.
    pub polls: u32,
    /// When a poll first set it aside; a retried page keeps this time.
    pub skipped_at: u64,
}

fn message_key(identity_id: EntityId, message_id: &str) -> (EntityId, [u8; 32]) {
    (identity_id, Sha256::digest(message_id.as_bytes()).into())
}

/// Persists `skipped` for `identity_id`'s inbox unless a row for the same
/// message already stands, which it keeps, and returns the row as stored. A
/// stored row that no longer decodes is written again.
///
/// # Errors
///
/// Store or encode failure; the caller's poll stops there.
pub(crate) fn record_native_mail_skipped_message(
    vault: &Vault,
    identity_id: EntityId,
    skipped: NativeMailSkippedMessage,
) -> Result<NativeMailSkippedMessage> {
    let key = message_key(identity_id, &skipped.message_id);
    vault.try_with_write_txn_grouped(|txn| {
        if let Some(stored) = SKIPPED_MESSAGES.get_lenient(&vault.store, txn, &key)? {
            return Ok(stored);
        }
        SKIPPED_MESSAGES.put(&vault.store, txn, &key, &skipped)?;
        Ok(skipped)
    })
}

/// Every message a poll set aside from `identity_id`'s inbox, with its full
/// reason, in key order. A restart keeps them.
///
/// # Errors
///
/// Store failure or a row that does not decode.
pub fn native_mail_skipped_messages(
    vault: &Vault,
    identity_id: EntityId,
) -> Result<Vec<NativeMailSkippedMessage>> {
    let txn = vault.store.env.read_txn()?;
    Ok(SKIPPED_MESSAGES
        .scan_from(&vault.store, &txn, identity_id.as_bytes())?
        .into_iter()
        .map(|(_, skipped)| skipped)
        .collect())
}

/// Drops every message set aside from `identity_id`'s inbox, in the
/// transaction that deletes the identity.
///
/// # Errors
///
/// Store failure, which fails the deletion with it.
pub(crate) fn drop_native_mail_skipped_messages_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    identity_id: &EntityId,
) -> Result<()> {
    SKIPPED_MESSAGES.delete_from(store, txn, identity_id.as_bytes())?;
    Ok(())
}
