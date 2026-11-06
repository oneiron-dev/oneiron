//! The pack's read projections (MAIL-VIEW = A: the inbox, thread and
//! calendar screens are lenses shipped with the pack; their layout is the
//! owner's co-design call): the unified inbox across the mailboxes a reader
//! reads and the threads shared with them, and one thread's messages. They
//! list refs, senders, subjects and times; a message's words read through the
//! ordinary scoped reads, which meet its source audience.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use super::source::{MailSourceRow, SOURCES};
use super::state::{MailOccurrence, MailPresence, MailStage, OCCURRENCES};
use crate::memory::{Memory, MemoryError, MemoryResult};
use crate::{EntityId, Result, Vault, source_audience};

/// The inbox page size when a request names none.
const DEFAULT_INBOX_PAGE: u32 = 50;

/// `vault.mail.inbox`'s input.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MailInboxRequest {
    /// One source only, 32-hex; every source the reader reads when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_ref: Option<String>,
    /// Lists messages deleted at the provider and kept, labelled, too.
    #[serde(default)]
    pub include_source_deleted: bool,
    /// Only the messages after this place in the newest-first order: the
    /// previous page's `next_cursor`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
}

/// One message as the inbox lists it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MailInboxItem {
    pub source_ref: String,
    /// The thread's CONVERSATION, 32-hex.
    pub thread_ref: String,
    /// The message's TURN, 32-hex.
    pub turn_ref: String,
    /// The message's latest revision, 32-hex.
    pub message_ref: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    pub received_at: u64,
    pub labels: Vec<String>,
    pub stage: MailStage,
    pub presence: MailPresence,
    /// Whether the reader reads it through a share of its thread, not as a
    /// reader of its source.
    pub shared_with_reader: bool,
}

/// One inbox page, newest first.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MailInboxPage {
    pub items: Vec<MailInboxItem>,
    /// The `cursor` of the next page; absent on the last.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

/// `vault.mail.threads.read`'s input.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MailThreadRequest {
    /// The thread's CONVERSATION, 32-hex.
    pub thread_ref: String,
}

/// One thread's messages, oldest first.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MailThreadView {
    pub thread_ref: String,
    pub source_ref: String,
    pub messages: Vec<MailInboxItem>,
    /// The people the thread is shared with, 32-hex, to readers of its
    /// source.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub shared_with: Vec<String>,
}

fn item(source: EntityId, occurrence: &MailOccurrence, shared: bool) -> Option<MailInboxItem> {
    let message = occurrence.messages.last()?;
    Some(MailInboxItem {
        source_ref: source.to_hex(),
        thread_ref: occurrence.conversation.to_hex(),
        turn_ref: occurrence.turn.to_hex(),
        message_ref: message.to_hex(),
        from: occurrence.from.clone(),
        subject: occurrence.subject.clone(),
        received_at: occurrence.received_at,
        labels: occurrence.labels.clone(),
        stage: occurrence.stage,
        presence: occurrence.presence,
        shared_with_reader: shared,
    })
}

/// An inbox place: a message's receive time and its TURN, the order the
/// inbox lists newest first by, so two messages received in the same second
/// both list.
type InboxPlace = (u64, EntityId);

fn place_of(item: &MailInboxItem) -> MemoryResult<InboxPlace> {
    Ok((item.received_at, EntityId::from_hex(&item.turn_ref)?))
}

fn cursor_text(place: InboxPlace) -> String {
    format!("{}:{}", place.0, place.1.to_hex())
}

fn parse_cursor(cursor: &str) -> MemoryResult<InboxPlace> {
    let bad = || MemoryError::bad_request("the inbox cursor is not one this inbox gave");
    let (at, turn) = cursor.split_once(':').ok_or_else(bad)?;
    let at = at.parse::<u64>().map_err(|_| bad())?;
    let turn = EntityId::from_hex(turn).map_err(|_| bad())?;
    Ok((at, turn))
}

/// The mailbox sources by their audience policy, for finding a thread's
/// source.
pub(super) fn sources_by_audience_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
) -> Result<BTreeMap<EntityId, (EntityId, MailSourceRow)>> {
    let mut sources = BTreeMap::new();
    for row in SOURCES.iter_from(&vault.store, txn, &[])? {
        let (id, row) = row?;
        if row.kind.is_mailbox() {
            sources.insert(row.audience, (id, row));
        }
    }
    Ok(sources)
}

impl Memory<'_> {
    /// The unified inbox (FIX 12559 row 6): the messages of every mailbox
    /// the bound actor reads, and of the threads shared with it, newest
    /// first. Another person's mailbox is not listed or counted. A message
    /// deleted at the provider and kept is listed only when asked for, with
    /// its presence; a forgotten one never.
    pub fn mail_inbox(&self, input: &MailInboxRequest) -> MemoryResult<MailInboxPage> {
        let only = input
            .source_ref
            .as_deref()
            .map(EntityId::from_hex)
            .transpose()?;
        let limit = input.limit.unwrap_or(DEFAULT_INBOX_PAGE).max(1) as usize;
        let after = input.cursor.as_deref().map(parse_cursor).transpose()?;
        let vault = self.vault();
        let actor = self.actor();
        let txn = vault.store.env.read_txn().map_err(crate::Error::from)?;
        super::pack::require_pack_active_in(vault, &txn)?;
        let mut items = Vec::new();
        for row in SOURCES.iter_from(&vault.store, &txn, &[])? {
            let (source, row) = row?;
            if !row.kind.is_mailbox() || only.is_some_and(|only| only != source) {
                continue;
            }
            let reads_source = source_audience::actor_reads_in(vault, &txn, &row.audience, actor)?;
            let shared = if reads_source {
                BTreeSet::new()
            } else {
                source_audience::threads_shared_with_in(vault, &txn, &row.audience, actor)?
            };
            if !reads_source && shared.is_empty() {
                continue;
            }
            for occurrence in OCCURRENCES.iter_from(&vault.store, &txn, source.as_bytes())? {
                let (_, occurrence) = occurrence?;
                let listed = match occurrence.presence {
                    MailPresence::Present => true,
                    MailPresence::SourceDeleted { .. } => input.include_source_deleted,
                    MailPresence::Forgotten { .. } => false,
                };
                if !listed
                    || after.is_some_and(|after| (occurrence.received_at, occurrence.turn) >= after)
                {
                    continue;
                }
                let by_share = !reads_source;
                if by_share {
                    let thread =
                        source_audience::binding_in(vault, &txn, &occurrence.conversation)?;
                    if !thread.is_some_and(|thread| shared.contains(&thread)) {
                        continue;
                    }
                }
                if let Some(item) = item(source, &occurrence, by_share) {
                    items.push(item);
                }
            }
        }
        items.sort_by(|a, b| (b.received_at, &b.turn_ref).cmp(&(a.received_at, &a.turn_ref)));
        let next_cursor = if items.len() > limit {
            Some(cursor_text(place_of(&items[limit - 1])?))
        } else {
            None
        };
        items.truncate(limit);
        Ok(MailInboxPage { items, next_cursor })
    }

    /// One mail thread's messages, oldest first, to a reader of the thread:
    /// a reader of its source, or someone it was shared with.
    pub fn mail_thread(&self, input: &MailThreadRequest) -> MemoryResult<MailThreadView> {
        let conversation = EntityId::from_hex(&input.thread_ref)?;
        let vault = self.vault();
        let actor = self.actor();
        let unknown = || MemoryError::not_found("no mail thread by that ref");
        let txn = vault.store.env.read_txn().map_err(crate::Error::from)?;
        super::pack::require_pack_active_in(vault, &txn)?;
        let thread =
            source_audience::binding_in(vault, &txn, &conversation)?.ok_or_else(unknown)?;
        if !source_audience::actor_reads_in(vault, &txn, &thread, actor)? {
            return Err(unknown());
        }
        let (source_policy, shared_with) =
            source_audience::thread_shares_in(vault, &txn, &thread)?.ok_or_else(unknown)?;
        let sources = sources_by_audience_in(vault, &txn)?;
        let (source, row) = sources.get(&source_policy).ok_or_else(unknown)?;
        let reads_source = source_audience::actor_reads_in(vault, &txn, &row.audience, actor)?;
        let mut messages = Vec::new();
        for occurrence in OCCURRENCES.iter_from(&vault.store, &txn, source.as_bytes())? {
            let (_, occurrence) = occurrence?;
            if occurrence.conversation != conversation
                || matches!(occurrence.presence, MailPresence::Forgotten { .. })
            {
                continue;
            }
            if let Some(item) = item(*source, &occurrence, !reads_source) {
                messages.push(item);
            }
        }
        messages.sort_by(|a, b| a.received_at.cmp(&b.received_at));
        Ok(MailThreadView {
            thread_ref: conversation.to_hex(),
            source_ref: source.to_hex(),
            messages,
            shared_with: if reads_source {
                shared_with.iter().map(EntityId::to_hex).collect()
            } else {
                Vec::new()
            },
        })
    }
}
