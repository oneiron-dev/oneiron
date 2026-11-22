//! A message deleted at the provider (MAIL-DELETE = A, 2026-11-03): the
//! source's own setting decides. "Keep in memory", the default, takes it out
//! of the live inbox and keeps it as a labelled source-deleted copy, still
//! searchable by its readers. "Forget too" forgets every revision of it in
//! the vault through the ordinary user delete, and keeps only the provider id
//! as a fence, so a later listing never brings it back: its sender, subject
//! and labels go from the pack's own rows too. A message moved to trash or
//! spam counts as deleted at the provider; one taken out of the trash or
//! spam again is live again, when its copy was kept.
//!
//! A forget is owed before its first row goes (fix list row 18084): the
//! writer that scrubs the copy records the rows it still deletes, and each
//! step resumes an owed forget a failure stopped part-way, so no TURN or
//! CONVERSATION of a forgotten message stays behind.
//!
//! A kept copy's claims are checked again (FIX 15414): the writer that marks
//! it source-deleted moves its presence generation on and owes the re-check
//! in that write ([`super::claim_recheck`]); a restore moves the generation
//! on too, and a re-check still waiting for the old one goes moot.

use serde::{Deserialize, Serialize};

use super::source::{MailProviderDeleteSetting, MailSourceRow};
use super::state::{
    BODY_QUEUE, MailPresence, MailStage, OCCURRENCES, SYNC, THREAD_EPOCHS, body_queue_key,
    occurrence_key, thread_hash,
};
use crate::deletion::DeleteReason;
use crate::side_table::{self, Named, SideTable};
use crate::{EntityId, Result, Vault};

/// The forgets a source still owes, by the source and the BLAKE3 of the
/// provider's id: recorded in the writer that scrubs the copy, cleared once
/// every row it names is deleted.
const FORGET_OWED: SideTable<(EntityId, [u8; 32]), MailForgetOwed, Named> =
    SideTable::new(&side_table::MAIL_PACK_FORGET_OWED);

/// What the forget of one message still deletes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct MailForgetOwed {
    /// Its opened attachments' artifacts, its MESSAGE revisions and its
    /// TURN, in the order they go: the attachment rows name the artifacts,
    /// and a MESSAGE's erase removes those rows.
    rows: Vec<EntityId>,
    /// Its thread's CONVERSATION: it goes once no other message of the
    /// source is left in that thread.
    conversation: EntityId,
    /// The BLAKE3 of its thread key, whose epoch moves on when the
    /// CONVERSATION goes.
    thread: [u8; 32],
    /// Whether this is the thread's last message, its epoch moved on: the
    /// CONVERSATION's delete is what is left.
    closing: bool,
    at: u64,
}

/// What applying one provider delete did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ProviderDeleteOutcome {
    /// The vault holds no such message, or it was deleted at the provider
    /// already.
    Nothing,
    Kept,
    Forgotten,
}

/// Applies the provider's delete of `provider_id` under `row`'s setting.
/// A forget that fails part-way stays owed, and the next step resumes it.
pub(super) fn apply_provider_delete(
    vault: &Vault,
    source: EntityId,
    row: &MailSourceRow,
    provider_id: &str,
    at: u64,
) -> Result<ProviderDeleteOutcome> {
    let key = occurrence_key(source, provider_id);
    let occurrence = {
        let txn = vault.store.env.read_txn()?;
        OCCURRENCES.get(&vault.store, &txn, &key)?
    };
    let Some(occurrence) = occurrence.filter(|row| row.presence == MailPresence::Present) else {
        return Ok(ProviderDeleteOutcome::Nothing);
    };
    let forget = row.on_provider_delete == MailProviderDeleteSetting::ForgetToo;
    let artifacts = if forget {
        let artifacts = super::attachments::message_artifacts(vault, source, provider_id)?;
        // A held record refuses before anything goes: a forget a cooperative
        // restriction stops leaves the copy whole and live, for the next try,
        // never half erased. The thread's CONVERSATION counts when this is
        // its last message.
        let txn = vault.store.env.read_txn()?;
        let mut held = artifacts.clone();
        held.extend(occurrence.messages.iter().copied());
        held.push(occurrence.turn);
        if !conversation_holds_others_in(vault, &txn, &key, &occurrence.conversation)? {
            held.push(occurrence.conversation);
        }
        vault.store.reject_restricted_records_in_txn(&txn, &held)?;
        artifacts
    } else {
        Vec::new()
    };
    let applied = vault.with_write_txn_grouped(|txn| {
        let Some(mut current) = OCCURRENCES.get(&vault.store, txn, &key)? else {
            return Ok(false);
        };
        // Settled meanwhile.
        if current.presence != MailPresence::Present {
            return Ok(false);
        }
        BODY_QUEUE.delete(
            &vault.store,
            txn,
            &body_queue_key(source, current.received_at, provider_id),
        )?;
        if forget {
            // The forget is owed before its first row goes, with the rows
            // the copy names in this writer.
            let mut rows = artifacts;
            rows.extend(current.messages.iter().copied());
            rows.push(current.turn);
            let owed = MailForgetOwed {
                rows,
                conversation: current.conversation,
                thread: thread_hash(&current.thread_key),
                closing: false,
                at,
            };
            FORGET_OWED.put(&vault.store, txn, &key, &owed)?;
            current.scrub(at);
        } else {
            current.presence = MailPresence::SourceDeleted { at };
            current.presence_generation += 1;
            current.updated_at = at;
            super::claim_recheck::owe_in_txn(vault, txn, &key, &current, at)?;
        }
        OCCURRENCES.put(&vault.store, txn, &key, &current)?;
        let mut sync = SYNC.get(&vault.store, txn, &source)?.unwrap_or_default();
        sync.deleted_at_provider += 1;
        SYNC.put(&vault.store, txn, &source, &sync)?;
        Ok(true)
    })?;
    if !applied {
        return Ok(ProviderDeleteOutcome::Nothing);
    }
    if !forget {
        return Ok(ProviderDeleteOutcome::Kept);
    }
    resume_forget(vault, &key)?;
    Ok(ProviderDeleteOutcome::Forgotten)
}

/// Resumes each forget `source` still owes, at the start of its step. One
/// that fails again stays owed for the next step; the first failure is
/// answered in words, for the source's owner.
pub(super) fn resume_owed_forgets(vault: &Vault, source: EntityId) -> Result<Option<String>> {
    let keys = {
        let txn = vault.store.env.read_txn()?;
        FORGET_OWED.scan_keys(&vault.store, &txn, source.as_bytes())?
    };
    let mut failure = None;
    for key in keys {
        if let Err(error) = resume_forget(vault, &key)
            && failure.is_none()
        {
            failure = Some(format!(
                "a forgotten message is not fully erased yet: {error}"
            ));
        }
    }
    Ok(failure)
}

/// Deletes what the forget of the message keyed `key` still owes, then its
/// thread's CONVERSATION when no other message of the source is left in it,
/// and clears the debt. Each delete is the ordinary user delete; a row
/// already gone deletes nothing more, so a resumed forget redoes nothing.
fn resume_forget(vault: &Vault, key: &(EntityId, [u8; 32])) -> Result<()> {
    let owed = {
        let txn = vault.store.env.read_txn()?;
        FORGET_OWED.get(&vault.store, &txn, key)?
    };
    let Some(owed) = owed else {
        return Ok(());
    };
    for row in &owed.rows {
        vault.delete_entity_with_reason(row, DeleteReason::UserDelete)?;
    }
    // One writer decides whether another message still holds the thread:
    // then this debt retires in it. The last keeps its debt until the
    // CONVERSATION's delete is done, so two forgets that end together never
    // both leave it to the other. The last moves the thread's epoch on in
    // that writer: a message landing in the thread from then on opens a new
    // CONVERSATION, and one read before it is refused in its own writer and
    // lands at the next step (`landing.rs`), so the delete takes no live
    // message with it.
    let last = vault.with_write_txn_grouped(|txn| {
        let Some(mut current) = FORGET_OWED.get(&vault.store, txn, key)? else {
            return Ok(false);
        };
        if current.closing {
            return Ok(true);
        }
        if conversation_holds_others_in(vault, txn, key, &current.conversation)? {
            FORGET_OWED.delete(&vault.store, txn, key)?;
            return Ok(false);
        }
        let thread = (key.0, current.thread);
        let epoch = THREAD_EPOCHS.get(&vault.store, txn, &thread)?.unwrap_or(0);
        THREAD_EPOCHS.put(&vault.store, txn, &thread, &(epoch + 1))?;
        current.closing = true;
        FORGET_OWED.put(&vault.store, txn, key, &current)?;
        Ok(true)
    })?;
    if last {
        vault.delete_entity_with_reason(&owed.conversation, DeleteReason::UserDelete)?;
        vault.with_write_txn_grouped(|txn| FORGET_OWED.delete(&vault.store, txn, key).map(drop))?;
    }
    Ok(())
}

/// Whether a message of `key`'s source other than `key` holds
/// `conversation`: one not forgotten, or one whose forget still owes rows.
/// The CONVERSATION goes with the last of them.
fn conversation_holds_others_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    key: &(EntityId, [u8; 32]),
    conversation: &EntityId,
) -> Result<bool> {
    let source = key.0;
    for row in OCCURRENCES.iter_from(&vault.store, txn, source.as_bytes())? {
        let (other, occurrence) = row?;
        if other != *key
            && occurrence.conversation == *conversation
            && !matches!(occurrence.presence, MailPresence::Forgotten { .. })
        {
            return Ok(true);
        }
    }
    for row in FORGET_OWED.iter_from(&vault.store, txn, source.as_bytes())? {
        let (other, owed) = row?;
        if other != *key && owed.conversation == *conversation {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Records a message's new provider labels, when it is still present.
pub(super) fn update_labels(
    vault: &Vault,
    source: EntityId,
    provider_id: &str,
    labels: &[String],
    at: u64,
) -> Result<()> {
    let key = occurrence_key(source, provider_id);
    vault.with_write_txn_grouped(|txn| {
        let Some(mut current) = OCCURRENCES.get(&vault.store, txn, &key)? else {
            return Ok(());
        };
        if current.labels.as_slice() == labels {
            return Ok(());
        }
        current.labels = labels.to_vec();
        current.updated_at = at;
        OCCURRENCES.put(&vault.store, txn, &key, &current)
    })
}

/// Brings back a message the provider took out of its trash or spam again:
/// a kept source-deleted copy is live again, its body queued again when it
/// landed with its headers only, its presence generation moved on and a
/// re-check of its claims still waiting moot (FIX 15414). A forgotten one
/// stays forgotten: its rows are gone, and its fence keeps a listing from
/// bringing it back. Answers whether it was brought back.
pub(super) fn restore_from_provider_trash(
    vault: &Vault,
    source: EntityId,
    provider_id: &str,
    at: u64,
) -> Result<bool> {
    let key = occurrence_key(source, provider_id);
    vault.with_write_txn_grouped(|txn| {
        let Some(mut current) = OCCURRENCES.get(&vault.store, txn, &key)? else {
            return Ok(false);
        };
        if !matches!(current.presence, MailPresence::SourceDeleted { .. }) {
            return Ok(false);
        }
        current.presence = MailPresence::Present;
        current.presence_generation += 1;
        current.updated_at = at;
        super::claim_recheck::obsolete_rechecks_in_txn(&vault.store, txn, &key, at)?;
        if current.stage == MailStage::Headers {
            BODY_QUEUE.put(
                &vault.store,
                txn,
                &body_queue_key(source, current.received_at, provider_id),
                &provider_id.to_owned(),
            )?;
        }
        OCCURRENCES.put(&vault.store, txn, &key, &current)?;
        let mut sync = SYNC.get(&vault.store, txn, &source)?.unwrap_or_default();
        sync.deleted_at_provider = sync.deleted_at_provider.saturating_sub(1);
        SYNC.put(&vault.store, txn, &source, &sync)?;
        Ok(true)
    })
}
