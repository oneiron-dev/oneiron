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

use crate::inbox::actions::NotificationAction;
use crate::inbox::notification_recipient::NotificationRecipientScope;
use crate::inbox::notification_recipient::notification_body_json;
use crate::inbox::notification_recipient::notification_recipient_scope;
use crate::inbox::notification_recipient::notification_scoped_to_caller;
use crate::write_envelope::claim_body::lexical_query_hint::ScopedRead;
use oneiron_base::registry::ENTITY_TYPE_NOTIFICATION;
use oneiron_contracts::entity_id::EntityId;
use oneiron_contracts::limit_ask::EngineLimit;
use oneiron_contracts::memory::{MemoryError, MemoryResult};

/// Rows a page serves when its caller names no limit.
pub const INBOX_PAGE_DEFAULT: usize = 100;

/// Type-index rows one admission round reads.
pub const INBOX_SCAN_WINDOW: usize = 256;

/// What [`Memory::inbox_mark`] records for its caller. Acknowledging also
/// marks seen.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum NotificationMark {
    Seen,
    Acked,
}

pub fn notification_not_found() -> MemoryError {
    MemoryError::not_found("no notification with that id is delivered to this actor")
}
