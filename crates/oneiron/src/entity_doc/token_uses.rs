//! Core half of `entity_doc::token_uses`: its store-layer items live in `oneiron_store::entity_doc::token_uses` and are
//! re-exported here; the items below stay in the engine.

pub(crate) use oneiron_store::entity_doc::token_uses::*;

use super::EntityDoc;
use super::document::{Stamped, parse_stamp};
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::store::Store;
use heed::RwTxn;
use loro::VersionVector;

/// Records the stamp tokens `doc`'s changes past `before` name under
/// `entity`, in the writer's transaction: every change it retains, and its
/// birth's token, when `before` is `None` (a birth or a whole-document
/// write).
///
/// # Errors
///
/// Storage errors.
pub(super) fn record_token_uses_in_txn(
    store: &Store,
    txn: &mut RwTxn<'_>,
    entity: &EntityId,
    doc: &EntityDoc,
    before: Option<&VersionVector>,
) -> Result<()> {
    let mut tokens = crate::provenance::tokens_named_since(&doc.doc, before, engine_stamp_token);
    if before.is_none() {
        tokens.extend(doc.birth().actor.id());
    }
    crate::provenance::record_actor_stamp_uses_in_txn(store, txn, entity, tokens)
}

/// [`record_token_uses_in_txn`] for a fork retained for review: the changes
/// past its encoded `base` frontier, its own commits, under `entity`.
///
/// # Errors
///
/// Storage errors, or a base that is no frontier.
pub(super) fn record_fork_uses_in_txn(
    store: &Store,
    txn: &mut RwTxn<'_>,
    entity: &EntityId,
    fork: &EntityDoc,
    base: &[u8],
) -> Result<()> {
    let base = fork
        .doc
        .frontiers_to_vv(&super::document::decode_frontier(base)?);
    record_token_uses_in_txn(store, txn, entity, fork, base.as_ref())
}

/// [`record_token_uses_in_txn`] for a record's sequence rows, which keep no
/// birth map: the changes `doc` holds past `before`.
///
/// # Errors
///
/// Storage errors.
#[cfg(feature = "sync")]
pub(super) fn record_sequence_uses_in_txn(
    store: &Store,
    txn: &mut RwTxn<'_>,
    entity: &EntityId,
    doc: &loro::LoroDoc,
    before: &VersionVector,
) -> Result<()> {
    let tokens = crate::provenance::tokens_named_since(doc, Some(before), engine_stamp_token);
    crate::provenance::record_actor_stamp_uses_in_txn(store, txn, entity, tokens)
}
