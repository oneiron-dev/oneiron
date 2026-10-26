//! Which agent dispatch rows carry an erased asker's ask (FIX 9181).
//! Entry: `asker_owned`, `asker_erased_in`.
//!
//! A launched spawn's payload holds its asker's ask: a direct spawn's
//! receipt, a planned spawn's plan receipt, and the briefing the ask became.
//! A row is its asker's when a receipt it carries names that asker
//! (`asker_ref`, which the host stamps from the authenticated spawner, never
//! from the call), or when its dedupe key names a planned intent an asker's
//! erase took, as each row of the group a planned intent launched does, its
//! retries included (`planned:<intent key hex>:<role>`). Neither link is
//! authority: each only finds the text an erase takes.

use std::collections::BTreeSet;

use crate::agent_dispatch::{AgentDispatchInput, AgentDispatcher, record_dispatch_input};
use crate::entity_id::EntityId;
use crate::ports::{DeletionMarker, TombstoneStoreRead};
use crate::store::Store;

use super::super::types::AttemptRecord;

/// What a planned launch's dedupe key starts with, before its intent's key.
const PLANNED_DEDUPE_PREFIX: &str = "planned:";

/// The askers `input`'s receipts name.
fn askers(input: &AgentDispatchInput) -> impl Iterator<Item = EntityId> {
    let direct = input
        .direct_spawn
        .as_ref()
        .and_then(|receipt| receipt.asker_ref);
    let planned = input.plan.as_ref().and_then(|plan| plan.asker_ref);
    direct.into_iter().chain(planned)
}

/// The planned intent `record`'s dedupe key names, as its key's hex.
fn planned_intent(record: &AttemptRecord) -> Option<&str> {
    let (intent, _role) = record
        .dedupe_key
        .as_deref()?
        .strip_prefix(PLANNED_DEDUPE_PREFIX)?
        .split_once(':')?;
    Some(intent)
}

/// Whether `record` carries the ask of an asker among `actors`, or of a
/// planned intent among `intents`, the keys of those an asker's erase took.
pub(super) fn asker_owned(
    record: &AttemptRecord,
    actors: &BTreeSet<EntityId>,
    intents: &BTreeSet<String>,
) -> bool {
    planned_intent(record).is_some_and(|intent| intents.contains(intent))
        || record_dispatch_input(record)
            .is_some_and(|input| askers(&input).any(|asker| actors.contains(&asker)))
}

/// Whether a hard erase took the asker `record` carries, read in `txn`: a
/// receipt's asker bears the permanent hard-delete marker, or an asker's
/// erase took the planned intent it launched from. The late write's fence
/// reads it; a marker or intent that does not read is logged without
/// content and reads as none, so the fence never fails its write.
pub(super) fn asker_erased_in(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    record: &AttemptRecord,
) -> bool {
    let intent = planned_intent(record).is_some_and(|intent| {
        AgentDispatcher::intent_asker_erased_in(store, txn, intent).unwrap_or_else(|_| {
            tracing::warn!("attempt payload fence: a planned intent could not be read");
            false
        })
    });
    intent
        || record_dispatch_input(record).is_some_and(|input| {
            askers(&input).any(|asker| {
                store
                    .port_deletion_marked(txn, DeletionMarker::HardDelete, &asker)
                    .unwrap_or_else(|_| {
                        tracing::warn!(
                            "attempt payload fence: an asker's hard-delete marker could not be read"
                        );
                        false
                    })
            })
        })
}
