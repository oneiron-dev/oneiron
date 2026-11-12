//! Moved from `crates/oneiron/src/inbox/list.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_authority::claim_history_handoff::ScopedRead;
use oneiron_base::registry::ENTITY_TYPE_NOTIFICATION;
use oneiron_contracts::entity_id::EntityId;
use oneiron_contracts::limit_ask::EngineLimit;
use oneiron_contracts::memory::MemoryError;
use oneiron_contracts::memory::MemoryResult;
use oneiron_store::inbox::notification_recipient::NotificationRecipientScope;
use oneiron_store::inbox::notification_recipient::notification_body_json;
use oneiron_store::inbox::notification_recipient::notification_recipient_scope;
use oneiron_store::inbox::notification_recipient::notification_scoped_to_caller;
use serde::Deserialize;
use serde::Serialize;

/// What [`Memory::inbox_mark`] records for its caller. Acknowledging also
/// marks seen.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum NotificationMark {
    Seen,
    Acked,
}
