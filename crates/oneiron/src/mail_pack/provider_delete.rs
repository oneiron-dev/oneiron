//! A message deleted at the provider (MAIL-DELETE = A, 2026-11-03): the
//! source's own setting decides. "Keep in memory", the default, takes it out
//! of the live inbox and keeps it as a labelled source-deleted copy, still
//! searchable by its readers. "Forget too" forgets every revision of it in
//! the vault through the ordinary user delete, and keeps only the provider id
//! as a fence, so a later listing never brings it back: its sender, subject
//! and labels go from the pack's own rows too. A message moved to trash or
//! spam counts as deleted at the provider; one taken out of the trash or
//! spam again is live again, when its copy was kept.

use super::source::{MailProviderDeleteSetting, MailSourceRow};
use super::state::{
    BODY_QUEUE, MailPresence, MailStage, OCCURRENCES, SYNC, body_queue_key, occurrence_key,
};
use crate::deletion::DeleteReason;
use crate::{EntityId, Result, Vault};

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
    let outcome = match row.on_provider_delete {
        MailProviderDeleteSetting::KeepInMemory => ProviderDeleteOutcome::Kept,
        MailProviderDeleteSetting::ForgetToo => {
            // The opened attachments' artifacts go first: their rows name
            // them, and the message's erase removes the rows.
            for artifact in super::attachments::message_artifacts(vault, source, provider_id)? {
                vault.delete_entity_with_reason(&artifact, DeleteReason::UserDelete)?;
            }
            for message in &occurrence.messages {
                vault.delete_entity_with_reason(message, DeleteReason::UserDelete)?;
            }
            // One provider message is one TURN; its CONVERSATION stays while
            // the thread holds other messages, and goes with the last.
            vault.delete_entity_with_reason(&occurrence.turn, DeleteReason::UserDelete)?;
            ProviderDeleteOutcome::Forgotten
        }
    };
    vault.with_write_txn_grouped(|txn| {
        let Some(mut current) = OCCURRENCES.get(&vault.store, txn, &key)? else {
            return Ok(());
        };
        match outcome {
            ProviderDeleteOutcome::Forgotten => current.scrub(at),
            _ => {
                current.presence = MailPresence::SourceDeleted { at };
                current.updated_at = at;
            }
        }
        BODY_QUEUE.delete(
            &vault.store,
            txn,
            &body_queue_key(source, current.received_at, provider_id),
        )?;
        OCCURRENCES.put(&vault.store, txn, &key, &current)?;
        let mut sync = SYNC.get(&vault.store, txn, &source)?.unwrap_or_default();
        sync.deleted_at_provider += 1;
        SYNC.put(&vault.store, txn, &source, &sync)
    })?;
    // The thread's CONVERSATION goes with its last message, so "forget too"
    // leaves no thread behind.
    if outcome == ProviderDeleteOutcome::Forgotten
        && !conversation_holds_messages(vault, source, &occurrence.conversation)?
    {
        vault.delete_entity_with_reason(&occurrence.conversation, DeleteReason::UserDelete)?;
    }
    Ok(outcome)
}

/// Whether any message of `source` in `conversation` is not forgotten.
fn conversation_holds_messages(
    vault: &Vault,
    source: EntityId,
    conversation: &EntityId,
) -> Result<bool> {
    let txn = vault.store.env.read_txn()?;
    for row in OCCURRENCES.iter_from(&vault.store, &txn, source.as_bytes())? {
        let (_, occurrence) = row?;
        if occurrence.conversation == *conversation
            && !matches!(occurrence.presence, MailPresence::Forgotten { .. })
        {
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
/// landed with its headers only. A forgotten one stays forgotten: its rows
/// are gone, and its fence keeps a listing from bringing it back. Answers
/// whether it was brought back.
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
        current.updated_at = at;
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
