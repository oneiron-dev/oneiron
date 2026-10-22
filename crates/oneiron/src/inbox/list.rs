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
use crate::claim::{ClaimReadStatus, ScopedRead};
use crate::context_board::{
    NotificationRecipientScope, notification_body_json, notification_recipient_scope,
    notification_scoped_to_caller,
};
use crate::entity_id::EntityId;
use crate::memory::{Memory, MemoryError, MemoryResult, verify_actor_binding_in_txn};
use crate::registry::ENTITY_TYPE_NOTIFICATION;
use crate::store::Callback;
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

/// Who [`Memory::inbox_mark`] lets write in a shared vault without a
/// whole-vault content Grant (CALLS `FIX 6510 inbox mark write scope`,
/// accepted by the Engine 10-20): an actor marking its own delivered
/// notification, under a write lane scoped to that one row. A caller the
/// whole-vault check admits keeps that check and nothing else.
#[derive(Clone, Copy)]
enum InboxMarkWriteScope {
    /// The row's recipient markers name the actor, its read lane still reads
    /// the row in the snapshot that writes, and its Grant admits a write at
    /// the row's own stored position.
    OwnRowLane,
}

const INBOX_MARK_WRITE_SCOPE: InboxMarkWriteScope = InboxMarkWriteScope::OwnRowLane;

impl InboxMarkWriteScope {
    /// Whether `memory`'s actor, refused the whole-vault content Grant in
    /// the write snapshot `txn`, may still mark `id` as `caller`. Only a
    /// shared vault asks that Grant: anywhere else the refusal was the
    /// actor's own binding, which no row lifts. The actor is proved again at
    /// the row: its binding, the row's recipient naming it (a row with no
    /// recipient is no one's own), its read lane reading the row (#3441's
    /// check), and its Grant at the row's stored position, the per-record
    /// proof the content writer runs
    /// (`Vault::authorize_shared_content_write_in_txn`). A row stored with
    /// no position admits no one here.
    fn admits_in(
        self,
        memory: &Memory<'_>,
        txn: &heed::RoTxn<'_>,
        lane: &ScopedRead<'_>,
        id: EntityId,
        caller: &str,
    ) -> MemoryResult<bool> {
        match self {
            Self::OwnRowLane => {
                let vault = memory.vault();
                if vault.shared_vault_creation_in_txn(txn)?.is_none() {
                    return Ok(false);
                }
                verify_actor_binding_in_txn(vault, txn, memory.actor(), memory.actor_class())?;
                let Some((entity_type, _, raw)) = lane
                    .get_entities_parts_in_txn(txn, &[id])?
                    .into_iter()
                    .next()
                    .flatten()
                else {
                    return Ok(false);
                };
                let own = entity_type == ENTITY_TYPE_NOTIFICATION
                    && notification_body_json(&raw)
                        .and_then(|body| notification_recipient_scope(&body))
                        .is_some_and(|scope| {
                            matches!(scope, NotificationRecipientScope::Callers(callers)
                                if callers.contains(caller))
                        });
                if !own {
                    return Ok(false);
                }
                vault.authorize_shared_content_write_in_txn(
                    txn,
                    id,
                    &crate::WriteActor::new(memory.actor(), memory.actor_class()),
                )?;
                Ok(true)
            }
        }
    }
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
    /// event's own fields and every other caller's marks are kept. In a
    /// shared vault, an actor whose Grant is narrower than the whole vault
    /// marks only a row whose recipient it is, under that row's write lane
    /// (`INBOX_MARK_WRITE_SCOPE`, FIX 6510).
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
        let Some((entity_type, learned_at, raw)) = admitted else {
            return Err(notification_not_found());
        };
        // FIX 5778: a row its read admits but that is not delivered to this
        // actor may still take an Acked mark when it is an owner's weave due
        // notice and one live Grant the owner gave this agent covers that
        // ack (`delegated_owner_notice_ack`). Delivery keeps winning first.
        let delivered = delivered_row(id, entity_type, learned_at, &raw, &caller);
        let delegated = delivered.is_none()
            && mark == NotificationMark::Acked
            && lane.delegated_owner_notice_ack(self.actor(), self.actor_class(), id);
        let Some(current) = delivered.or_else(|| {
            delegated
                .then(|| decode_notification_body(&raw).ok())
                .flatten()
                .map(|body| row_for(id, learned_at, body, &caller))
        }) else {
            return Err(notification_not_found());
        };
        if current.acked || (current.seen && mark == NotificationMark::Seen) {
            return Ok(current);
        }
        self.vault().write_txn_door(Callback::Audited, |wtxn| {
            // A delegated ack's covering Grant is judged again in the
            // snapshot that writes; it is that ack's row-position scope.
            let covered = delegated
                && lane.delegated_owner_notice_ack_in(wtxn, self.actor(), self.actor_class(), id);
            if delegated && !covered {
                return Err(notification_not_found());
            }
            // The verified actor writer's own check, as before. A caller it
            // refuses may still mark its own row under that row's write lane
            // (FIX 6510); any other meets the refusal it met before.
            if let Err(whole_vault) = self.verify_actor_write_in_txn(wtxn)
                && !matches!(
                    INBOX_MARK_WRITE_SCOPE.admits_in(self, wtxn, &lane, id, &caller),
                    Ok(true)
                )
                && !covered
            {
                return Err(whole_vault);
            }
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
