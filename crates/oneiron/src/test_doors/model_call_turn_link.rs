//! Doors for `oneiron-server/tests/chat_model_call_turn_link.rs` (UNBUILT3-41,
//! FIX [TURN-MODEL-LINK]): the model-call records a saved reply MESSAGE is
//! linked to, read from the stored link rows by their key layout, so one door
//! reads a tree that keeps no link (none) and one that keeps them alike.
//! Compiled only under `--cfg oneiron_test_support`; never API.

use crate::code_run::model_call::{ModelCallRecord, model_call_in_txn};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::vault::Vault;

/// The stored prefix of the reply link rows (`CODE_RUN_MODEL_CALL_REPLY`).
/// Each key goes on with id16(reply MESSAGE) + id16(attempt) + be64(lease
/// generation) + be64(call index).
const REPLY_LINK_PREFIX: &[u8] = b"code_run:model_call_reply:v1:";

/// Every model-call record a stored link row names for the saved reply
/// MESSAGE `reply`, in key order. A link whose call row is gone reads as no
/// call.
///
/// # Errors
///
/// A store read failure, or a link key that is not a call key.
pub fn calls_linked_to_reply(vault: &Vault, reply: EntityId) -> Result<Vec<ModelCallRecord>> {
    let txn = vault.store.env.read_txn()?;
    let mut prefix = REPLY_LINK_PREFIX.to_vec();
    prefix.extend_from_slice(reply.as_bytes());
    let bad = || Error::CorruptedIndex("model-call reply link");
    let mut records = Vec::new();
    for row in vault.store.vault_meta.prefix_iter(&txn, &prefix)? {
        let (key, _) = row?;
        let call = key.get(prefix.len()..).ok_or_else(bad)?;
        let (attempt, rest) = call.split_at_checked(16).ok_or_else(bad)?;
        let (generation, index) = rest.split_at_checked(8).ok_or_else(bad)?;
        let attempt = EntityId::from_bytes(attempt.try_into().map_err(|_| bad())?)?;
        let generation = u64::from_be_bytes(generation.try_into().map_err(|_| bad())?);
        let index = u64::from_be_bytes(index.try_into().map_err(|_| bad())?);
        if let Some(record) = model_call_in_txn(vault, &txn, &(attempt, generation, index))? {
            records.push(record);
        }
    }
    Ok(records)
}
