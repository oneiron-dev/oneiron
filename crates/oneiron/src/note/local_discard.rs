//! The owner's discard of a world copy takes a NOTE's review workflow text
//! off this install (FIX 14534, Engine 11-06 08:34 call 4 = A): its proposal
//! snapshots and its waiting forks, which carry proposed and merged text.
//! Local only: no receipt, marker, fence or Loro operation. Landing receipts
//! (ids, verdict, actor, time) stay as identifier-only immutable history; a
//! review bundle keeps its other notes' forks, and its free-text explainer,
//! which can quote any member, reads "redacted" once it named a discarded
//! one, as an erase leaves it.

use std::collections::BTreeSet;

use heed::RwTxn;

use super::documents::NOTE_PROPOSAL_DOC;
use super::proposals::{NOTE_FORK, NOTE_PROPOSAL_BUNDLE};
use crate::store::Store;
use crate::{EntityId, Result};

/// Drops the review workflow text of each of `notes` in the caller's write
/// transaction.
pub(crate) fn discard_workflow_in_txn(
    store: &Store,
    txn: &mut RwTxn<'_>,
    notes: &BTreeSet<EntityId>,
) -> Result<()> {
    if notes.is_empty() {
        return Ok(());
    }
    for note in notes {
        let keys =
            NOTE_PROPOSAL_DOC.scan_keys(store, txn, format!("{}:", note.to_hex()).as_bytes())?;
        for key in keys {
            NOTE_PROPOSAL_DOC.delete(store, txn, &key)?;
        }
    }
    let forks: Vec<EntityId> = NOTE_FORK
        .scan(store, txn)?
        .into_iter()
        .filter(|(_, fork)| notes.contains(&fork.note))
        .map(|(key, _)| key)
        .collect();
    for fork in &forks {
        NOTE_FORK.delete(store, txn, fork)?;
    }
    for (key, mut bundle) in NOTE_PROPOSAL_BUNDLE.scan(store, txn)? {
        let named = bundle.waiting.iter().any(|fork| notes.contains(&fork.note))
            || bundle
                .landed
                .iter()
                .any(|receipt| notes.contains(&receipt.note));
        if !named {
            continue;
        }
        bundle.waiting.retain(|fork| !notes.contains(&fork.note));
        if bundle.waiting.is_empty() && bundle.landed.is_empty() {
            NOTE_PROPOSAL_BUNDLE.delete(store, txn, &key)?;
        } else {
            bundle.explainer = "redacted".to_owned();
            NOTE_PROPOSAL_BUNDLE.put(store, txn, &key, &bundle)?;
        }
    }
    Ok(())
}
