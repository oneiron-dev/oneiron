//! Remove reaction outbound attempts when the owning record is hard-erased.
use super::encoding::{
    DedupeIndexKeys, decode_record, legacy_dedupe_index_key, ready_at, ready_key,
};
use super::types::AttemptId;
use crate::EntityId;
use crate::error::{Error, Result};
use crate::reaction::{REACTION_OUTBOUND_ATTEMPT_KIND, ReactionOutboundAttempt};
use crate::store::Store;

pub(crate) fn purge_reaction_attempts_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    reaction: EntityId,
) -> Result<()> {
    let mut matches = Vec::new();
    for entry in store.attempt_records.iter(txn)? {
        let (key, raw) = entry?;
        let attempt = decode_record(&raw, AttemptId::from_bytes(&key)?)?;
        if attempt.kind != REACTION_OUTBOUND_ATTEMPT_KIND {
            continue;
        }
        let payload: ReactionOutboundAttempt = rmp_serde::from_slice(&attempt.payload)
            .map_err(|_| Error::CorruptedIndex("reaction outbound attempt"))?;
        if payload.reaction == reaction {
            matches.push(attempt);
        }
    }
    for attempt in matches {
        if attempt.run_id.is_some() || attempt.task_ref.is_some() {
            return Err(Error::CorruptedIndex("reaction attempt has foreign owner"));
        }
        store
            .attempt_ready
            .delete(txn, &ready_key(ready_at(&attempt), attempt.id))?;
        if let Some(dedupe) = attempt.dedupe_key.as_deref() {
            let keys =
                DedupeIndexKeys::new(&attempt.kind, attempt.dedupe_actor_ref.as_deref(), dedupe);
            store.attempt_dedupe.delete(txn, &keys.primary[..])?;
            if attempt.dedupe_actor_ref.is_none() {
                store
                    .attempt_dedupe
                    .delete(txn, &legacy_dedupe_index_key(&attempt.kind, dedupe))?;
            }
        }
        store.attempt_records.delete(txn, attempt.id.as_bytes())?;
    }
    Ok(())
}
