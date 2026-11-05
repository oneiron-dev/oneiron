//! A message deleted at the provider (MAIL-DELETE = A, 2026-11-03): the
//! source's own setting decides. "Keep in memory", the default, takes it out
//! of the live inbox and keeps it as a labelled source-deleted copy, still
//! searchable by its readers. "Forget too" forgets every revision of it in
//! the vault through the ordinary user delete, and keeps only the provider id
//! as a fence, so a later listing never brings it back: its sender, subject
//! and labels go from the pack's own rows too. A message moved to
//! trash or spam counts as deleted at the provider.

use super::source::{MailProviderDeleteSetting, MailSourceRow};
use super::state::{BODY_QUEUE, MailPresence, OCCURRENCES, SYNC, body_queue_key, occurrence_key};
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
            for message in &occurrence.messages {
                vault.delete_entity_with_reason(message, DeleteReason::UserDelete)?;
            }
            // One provider message is one TURN; its CONVERSATION stays while
            // the thread holds other messages.
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
    Ok(outcome)
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
