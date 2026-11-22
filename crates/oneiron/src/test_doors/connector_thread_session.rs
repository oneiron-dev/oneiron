//! Doors for `tests/connector_thread_session.rs` (OWN-VOICE-EPOCHS = C;
//! Engine ruling UNBUILT-02-SITTING = A): a connector thread's own SESSION,
//! its turns' numbers there, and the window its log forms.

use crate::compaction::ChatLog;
use crate::memory::MemoryResult;
use crate::surface_event::SurfaceConnectorPayload;
use crate::{EntityId, Result, Vault};

/// The conversation the connector thread `origin` belongs to lands in.
pub fn thread_conversation(origin: &SurfaceConnectorPayload) -> MemoryResult<EntityId> {
    crate::ingest::connector_conversation_id(origin)
}

/// The SESSION the connector thread `conversation` holds its turns in.
pub fn thread_session(conversation: EntityId) -> Result<EntityId> {
    crate::session_lifecycle::thread_session_id(conversation)
}

/// The SESSION `turn` was recorded into, if any.
pub fn turn_session(vault: &Vault, turn: EntityId) -> Result<Option<EntityId>> {
    let txn = vault.store.env.read_txn()?;
    crate::compaction::turn_session_membership_in_txn(&vault.store, &txn, &turn)
}

/// The connector thread `conversation`'s turns in its own SESSION, by their
/// numbers there; `None` when the order does not read.
pub fn thread_turn_order(vault: &Vault, conversation: EntityId) -> Result<Option<Vec<EntityId>>> {
    let txn = vault.store.env.read_txn()?;
    crate::compaction::thread_turn_order_in(&vault.store, &txn, conversation)
}

/// The turns `log`'s compaction window takes, by their numbers; `None` when
/// the log forms no window.
pub fn log_window_turns(log: &ChatLog) -> Option<Vec<EntityId>> {
    log.window.as_ref().map(|window| {
        window
            .messages
            .iter()
            .map(|message| message.turn_id)
            .collect()
    })
}
