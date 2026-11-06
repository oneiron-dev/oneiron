//! Node-local record of the native mail messages an inbox poll set aside.
//!
//! A message whose own failure stops its inbox poll after poll
//! ([`NATIVE_MAIL_SET_ASIDE_AFTER_STOPS`] polls in a row) is written here and
//! the poll goes past it, so one poison message never stalls the mailbox and
//! never vanishes unseen. A transport or storage failure says nothing about
//! the message and never counts. The row keeps the evidence across restarts;
//! a retried page writes it once.
//!
//! The count before that is kept here too (FIX 12104): the message an
//! inbox's polls stop at has a row short of the set-aside count, one per
//! identity, so a restart goes on counting from it. The poll that reads the
//! message drops that row, and a stop at another message replaces it.

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

/// One native mail message set aside so its inbox could go on, or, while
/// [`Self::is_set_aside`] says no, the message its inbox's polls stop at:
/// what it was, why it stopped and how often, never its bytes.
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
    /// While the message is not set aside, when a poll last stopped at it.
    pub skipped_at: u64,
}

impl NativeMailSkippedMessage {
    /// Whether the message is set aside: its own failure stopped
    /// [`NATIVE_MAIL_SET_ASIDE_AFTER_STOPS`] polls in a row.
    #[must_use]
    pub const fn is_set_aside(&self) -> bool {
        self.polls >= NATIVE_MAIL_SET_ASIDE_AFTER_STOPS
    }
}

fn message_key(identity_id: EntityId, message_id: &str) -> (EntityId, [u8; 32]) {
    (identity_id, Sha256::digest(message_id.as_bytes()).into())
}

/// Persists `skipped` for `identity_id`'s inbox unless a set-aside row for
/// the same message already stands, which it keeps, and returns the row as
/// stored. The message's stop count row, or a stored row that no longer
/// decodes, is written over.
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
        if let Some(stored) = SKIPPED_MESSAGES.get_lenient(&vault.store, txn, &key)?
            && stored.is_set_aside()
        {
            return Ok(stored);
        }
        SKIPPED_MESSAGES.put(&vault.store, txn, &key, &skipped)?;
        Ok(skipped)
    })
}

/// How many polls in a row message `message_id` of `identity_id`'s inbox
/// stopped on its own failure, as its row keeps the count across restarts;
/// 0 when it has no row.
///
/// # Errors
///
/// Store failure.
pub(crate) fn native_mail_message_stops(
    vault: &Vault,
    identity_id: EntityId,
    message_id: &str,
) -> Result<u32> {
    let txn = vault.store.env.read_txn()?;
    Ok(SKIPPED_MESSAGES
        .get_lenient(&vault.store, &txn, &message_key(identity_id, message_id))?
        .map_or(0, |row| row.polls))
}

/// The message `identity_id`'s inbox polls stop at, short of being set
/// aside, if one is. A row that does not decode is skipped, so one
/// damaged row never stops the inbox's poll.
///
/// # Errors
///
/// Store failure.
pub(crate) fn native_mail_stopping_message(
    vault: &Vault,
    identity_id: EntityId,
) -> Result<Option<NativeMailSkippedMessage>> {
    let txn = vault.store.env.read_txn()?;
    let rows = SKIPPED_MESSAGES.iter_from(&vault.store, &txn, identity_id.as_bytes())?;
    for row in rows {
        match row {
            Ok((_, stopping)) if !stopping.is_set_aside() => return Ok(Some(stopping)),
            Ok(_) => {}
            Err(error) => {
                tracing::warn!(
                    identity = %identity_id.to_hex(),
                    %error,
                    "native mail stopping message row does not decode; skipped"
                );
            }
        }
    }
    Ok(None)
}

/// Keeps `stopping`, short of being set aside, as the one message
/// `identity_id`'s inbox polls stop at: another message's stop count row
/// goes, and a set-aside row for the same message is kept as it stands.
///
/// # Errors
///
/// Store or encode failure; the caller's poll stops there.
pub(crate) fn record_native_mail_stopping_message(
    vault: &Vault,
    identity_id: EntityId,
    stopping: &NativeMailSkippedMessage,
) -> Result<()> {
    let key = message_key(identity_id, &stopping.message_id);
    vault.try_with_write_txn_grouped(|txn| {
        for (other, row) in SKIPPED_MESSAGES.scan_from(&vault.store, txn, identity_id.as_bytes())? {
            if other != key && !row.is_set_aside() {
                SKIPPED_MESSAGES.delete(&vault.store, txn, &other)?;
            }
        }
        if SKIPPED_MESSAGES
            .get_lenient(&vault.store, txn, &key)?
            .is_some_and(|stored| stored.is_set_aside())
        {
            return Ok(());
        }
        SKIPPED_MESSAGES.put(&vault.store, txn, &key, stopping)
    })
}

/// Drops message `message_id`'s stop count row from `identity_id`'s inbox:
/// a poll read the message. A set-aside row stays.
///
/// # Errors
///
/// Store failure; the caller's poll stops there.
pub(crate) fn clear_native_mail_stopping_message(
    vault: &Vault,
    identity_id: EntityId,
    message_id: &str,
) -> Result<()> {
    let key = message_key(identity_id, message_id);
    vault.try_with_write_txn_grouped(|txn| {
        if SKIPPED_MESSAGES
            .get_lenient(&vault.store, txn, &key)?
            .is_some_and(|stored| !stored.is_set_aside())
        {
            SKIPPED_MESSAGES.delete(&vault.store, txn, &key)?;
        }
        Ok(())
    })
}

/// Every message a poll set aside from `identity_id`'s inbox, with its full
/// reason, in key order. A restart keeps them. The message the polls stop
/// at, short of being set aside, is not one.
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
        .filter(NativeMailSkippedMessage::is_set_aside)
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
