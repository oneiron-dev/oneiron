//! OF-221: the actor-bound inbox page over NOTIFICATION records, and the one
//! write door that marks a notification seen or acknowledged.
//!
//! The page walks the type index in entity-ID order — not creation order —
//! from an exclusive `after` cursor. Every candidate is admitted through the
//! actor's own read lane, then delivered through the context board's
//! recipient predicate; a withheld or undelivered row never fills a slot or
//! becomes the cursor, and a page reads on past them until it fills or the
//! index ends. `next_after` is present only when a further delivered row
//! exists. Listing never marks anything: seen and acknowledged state changes
//! only through [`Memory::inbox_mark`].

use serde::{Deserialize, Serialize};

use super::notification::{
    NotificationBody, NotificationKind, NotificationSource, decode_notification_body,
};
use crate::claim::ClaimReadStatus;
use crate::context_board::{notification_body_json, notification_scoped_to_caller};
use crate::entity_id::EntityId;
use crate::memory::{Memory, MemoryError, MemoryResult};
use crate::registry::ENTITY_TYPE_NOTIFICATION;
use crate::vault::{LiveEntityRow, live_entity_row_in_txn};

/// Rows a page serves when its caller names no limit.
pub const INBOX_PAGE_DEFAULT: usize = 100;

/// The most rows one page serves.
pub const INBOX_PAGE_MAX: usize = 1_000;

/// Type-index rows one admission round reads.
const INBOX_SCAN_WINDOW: usize = 256;

/// What [`Memory::inbox_mark`] records for its caller. Acknowledging also
/// marks seen.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum NotificationMark {
    Seen,
    Acked,
}

/// One delivered notification as its caller reads it: the caller's own seen
/// and acknowledged state, never another caller's.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NotificationRow {
    pub id: String,
    /// When the row was last recorded.
    pub learned_at: u64,
    pub kind: NotificationKind,
    pub source: NotificationSource,
    pub subject_refs: Vec<String>,
    /// When the event happened.
    pub created_at: u64,
    pub origin_conversation: Option<String>,
    pub seen: bool,
    pub acked: bool,
}

/// One inbox page in entity-ID order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NotificationPage {
    pub rows: Vec<NotificationRow>,
    /// Explicit end marker: `None` means no further delivered row exists.
    pub next_after: Option<String>,
}

/// `body` as `caller` reads it.
fn row_for(id: EntityId, learned_at: u64, body: NotificationBody, caller: &str) -> NotificationRow {
    let acked = body.acked_by.get(caller) == Some(&true);
    NotificationRow {
        id: id.to_hex(),
        learned_at,
        kind: body.kind,
        seen: acked || body.seen_by.get(caller) == Some(&true),
        acked,
        source: body.source,
        subject_refs: body.subject_refs,
        created_at: body.created_at,
        origin_conversation: body.origin_conversation,
    }
}

/// The row an admitted entity delivers to `caller`: a typed NOTIFICATION
/// whose recipient markers name them. `None` for anything else.
fn delivered_row(
    id: EntityId,
    entity_type: u8,
    learned_at: u64,
    raw: &[u8],
    caller: &str,
) -> Option<NotificationRow> {
    if entity_type != ENTITY_TYPE_NOTIFICATION {
        return None;
    }
    if !notification_scoped_to_caller(&notification_body_json(raw)?, caller) {
        return None;
    }
    let body = decode_notification_body(raw).ok()?;
    Some(row_for(id, learned_at, body, caller))
}

fn notification_not_found() -> MemoryError {
    MemoryError::not_found("no notification with that id is delivered to this actor")
}

impl Memory<'_> {
    /// One page of the notifications delivered to this actor, in entity-ID
    /// order after the exclusive `after` cursor. A short page or an absent
    /// `next_after` means the inbox ended.
    pub fn inbox_list(&self, after: Option<&str>, limit: usize) -> MemoryResult<NotificationPage> {
        if limit == 0 || limit > INBOX_PAGE_MAX {
            return Err(MemoryError::bad_request_with(
                format!("limit must be between 1 and {INBOX_PAGE_MAX}"),
                &["Request a smaller page and continue from next_after."],
            ));
        }
        let mut start = after
            .map(EntityId::from_hex)
            .transpose()
            .map_err(|_| MemoryError::bad_request("after must be a notification id"))?;
        let caller = self.actor().to_hex();
        let read = self.read_lane(ClaimReadStatus::Recorded)?;
        let mut rows = Vec::new();
        let mut has_more = false;
        'scan: loop {
            let ids = self.vault().entities_by_type_page(
                ENTITY_TYPE_NOTIFICATION,
                start.as_ref(),
                INBOX_SCAN_WINDOW,
            )?;
            if ids.is_empty() {
                break;
            }
            let exhausted = ids.len() < INBOX_SCAN_WINDOW;
            start = ids.last().copied();
            let admitted = read.get_entities_parts_with_receipt(&ids, None)?.value;
            for (id, parts) in ids.into_iter().zip(admitted) {
                let Some((entity_type, learned_at, raw)) = parts else {
                    continue;
                };
                let Some(row) = delivered_row(id, entity_type, learned_at, &raw, &caller) else {
                    continue;
                };
                if rows.len() == limit {
                    has_more = true;
                    break 'scan;
                }
                rows.push(row);
            }
            if exhausted {
                break;
            }
        }
        let next_after = if has_more {
            rows.last().map(|row| row.id.clone())
        } else {
            None
        };
        Ok(NotificationPage { rows, next_after })
    }

    /// Marks one notification delivered to this actor seen or acknowledged,
    /// for this actor only, and returns it as this actor now reads it. The
    /// event's own fields and every other caller's marks are kept.
    pub fn inbox_mark(
        &self,
        notification: &str,
        mark: NotificationMark,
    ) -> MemoryResult<NotificationRow> {
        let id = EntityId::from_hex(notification)
            .map_err(|_| MemoryError::bad_request("notification_ref must be a notification id"))?;
        let caller = self.actor().to_hex();
        // Admission runs in its own snapshot, before the write opens: only a
        // row this actor reads and is delivered to may be marked.
        let lane = self.read_lane(ClaimReadStatus::Recorded)?;
        let admitted = lane
            .get_entities_parts_with_receipt(&[id], None)?
            .value
            .into_iter()
            .next()
            .flatten();
        let Some(current) = admitted.and_then(|(entity_type, learned_at, raw)| {
            delivered_row(id, entity_type, learned_at, &raw, &caller)
        }) else {
            return Err(notification_not_found());
        };
        if current.acked || (current.seen && mark == NotificationMark::Seen) {
            return Ok(current);
        }
        self.with_verified_actor_write_txn(|wtxn| {
            // The same lane judges the row again in the snapshot that writes
            // (FIX 6498): a row it no longer reads answers as one never
            // delivered.
            if lane
                .get_entities_parts_in_txn(wtxn, &[id])?
                .into_iter()
                .next()
                .flatten()
                .is_none()
            {
                return Err(notification_not_found());
            }
            let mut body = match live_entity_row_in_txn(&self.vault().store, &*wtxn, &id)? {
                LiveEntityRow::Live { entity_type, body }
                    if entity_type == ENTITY_TYPE_NOTIFICATION =>
                {
                    decode_notification_body(&body)?
                }
                _ => return Err(notification_not_found()),
            };
            body.seen_by.insert(caller.clone(), true);
            if mark == NotificationMark::Acked {
                body.acked_by.insert(caller.clone(), true);
            }
            let learned_at = self.vault().put_notification_in_txn(wtxn, &id, &body)?;
            Ok(row_for(id, learned_at, body, &caller))
        })
    }
}
