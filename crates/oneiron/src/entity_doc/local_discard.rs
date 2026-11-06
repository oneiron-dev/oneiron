//! The owner's discard of a world copy takes each entity's own document
//! payload off this install (FIX 14534, Engine 11-06 08:34 call 4 = A).
//! Local only: no receipt, marker, fence or Loro operation, and nothing of
//! another record's. The pins other records made of an entity's text are
//! their quotes and stay, and so do the citation floors that hold its
//! history for them, identifier-only frontiers; its own settle and purge
//! receipts stay as identifier-only immutable history.

use std::collections::BTreeSet;

use heed::RwTxn;

use super::citation_floor::ENTITY_DOC_CITATION_FLOOR;
use super::forks::{ENTITY_DOC_FORK, ENTITY_DOC_FORK_SNAPSHOT, ENTITY_DOC_PROPOSAL_BUNDLE};
use super::pins::ENTITY_DOC_PIN;
use super::storage::{ENTITY_DOC_HEAD, drop_document};
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::side_table::HexId;
use crate::store::Store;

/// Drops the document payload of each of `entities` in the caller's write
/// transaction: the document under its own id and the one its head names,
/// its forks and their share of any proposal bundle, the pins it made as a
/// citing record with the floors they held, and its head.
pub(crate) fn discard_local_copies_in_txn(
    store: &Store,
    txn: &mut RwTxn<'_>,
    entities: &BTreeSet<EntityId>,
) -> Result<()> {
    if entities.is_empty() {
        return Ok(());
    }
    for entity in entities {
        let own = entity.to_hex();
        let head = ENTITY_DOC_HEAD.get(store, txn, &HexId(*entity))?;
        drop_document(store, txn, &own)?;
        if let Some(head) = head
            && head.document != own
        {
            drop_document(store, txn, &head.document)?;
        }
        ENTITY_DOC_HEAD.delete(store, txn, &HexId(*entity))?;
    }
    // One scan of each table serves the whole set: forks by their entity,
    // pins and floors keyed cited-then-citer by the citer.
    let hexes: BTreeSet<String> = entities.iter().map(EntityId::to_hex).collect();
    let forks: Vec<_> = ENTITY_DOC_FORK
        .scan(store, txn)?
        .into_iter()
        .map(|(_, fork)| fork)
        .filter(|fork| hexes.contains(&fork.entity))
        .collect();
    let mut proposals = BTreeSet::new();
    for fork in forks {
        ENTITY_DOC_FORK_SNAPSHOT.delete(store, txn, &fork.fork)?;
        ENTITY_DOC_FORK.delete(store, txn, &fork.fork)?;
        proposals.insert(fork.proposal);
    }
    // A bundle keeps its other entities' forks.
    for proposal in proposals {
        let Some(mut bundle) = ENTITY_DOC_PROPOSAL_BUNDLE.get(store, txn, &proposal)? else {
            continue;
        };
        bundle.forks.retain(|row| !hexes.contains(&row.entity));
        if bundle.forks.is_empty() {
            ENTITY_DOC_PROPOSAL_BUNDLE.delete(store, txn, &proposal)?;
        } else {
            ENTITY_DOC_PROPOSAL_BUNDLE.put(store, txn, &proposal, &bundle)?;
        }
    }
    for key in ENTITY_DOC_PIN.scan_keys(store, txn, &[])? {
        if entities.contains(&key.1.0) {
            ENTITY_DOC_PIN.delete(store, txn, &key)?;
        }
    }
    for key in ENTITY_DOC_CITATION_FLOOR.scan_keys(store, txn, &[])? {
        if entities.contains(&key.1.0) {
            ENTITY_DOC_CITATION_FLOOR.delete(store, txn, &key)?;
        }
    }
    Ok(())
}
