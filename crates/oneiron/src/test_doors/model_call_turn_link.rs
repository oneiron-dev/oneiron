//! Doors for `oneiron-server/tests/chat_model_call_turn_link.rs` (UNBUILT3-41,
//! FIX [TURN-MODEL-LINK]): the model-call records a saved reply MESSAGE is
//! linked to, read through the thread reader's own link read
//! (THREAD-PROVENANCE-READ), so the test sees what the verb sees.
//! Compiled only under `--cfg oneiron_test_support`; never API.

use crate::code_run::model_call::{ModelCallRecord, model_calls_for_reply_in_txn};
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::vault::Vault;

/// Every model-call record a stored link row names for the saved reply
/// MESSAGE `reply`, in key order. A link whose call row is gone or does not
/// decode reads as no call.
///
/// # Errors
///
/// A store read failure.
pub fn calls_linked_to_reply(vault: &Vault, reply: EntityId) -> Result<Vec<ModelCallRecord>> {
    let txn = vault.store.env.read_txn()?;
    model_calls_for_reply_in_txn(vault, &txn, &reply)
}
