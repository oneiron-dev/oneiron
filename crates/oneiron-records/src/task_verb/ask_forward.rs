//! Moved from `crates/oneiron/src/task_verb/ask_forward.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;
use oneiron_contracts::entity_id::derived_domains::TASK_ASK_FORWARD_INTENT;
use oneiron_contracts::entity_id::derived_domains::TASK_ASK_FORWARD_RESULT;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeSet;

/// The framing every capability slip token carries.
pub const TOKEN_PREFIX: &str = "v2.slip.";

/// The intent `holder` relays under `intent_key` on the ask `group`.
pub fn intent_id(group: EntityId, holder: EntityId, intent_key: &str) -> Result<EntityId> {
    EntityId::derive(
        TASK_ASK_FORWARD_INTENT,
        &[group.as_bytes(), holder.as_bytes(), intent_key.as_bytes()],
    )
}

/// The admitting node's result for the intent `intent`.
pub fn result_id(intent: EntityId) -> Result<EntityId> {
    EntityId::derive(TASK_ASK_FORWARD_RESULT, &[intent.as_bytes()])
}
