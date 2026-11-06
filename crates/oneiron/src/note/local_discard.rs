//! The owner's discard of a world copy takes a NOTE's review workflow text
//! off this install (FIX 14534, Engine 11-06 08:34 call 4 = A): its proposal
//! snapshots and its waiting forks, which carry proposed and merged text.
//! Local only: no receipt, marker, fence or Loro operation. Landing receipts
//! (ids, verdict, actor, time) stay as identifier-only immutable history; a
//! review bundle keeps its other notes' forks. Its free-text explainer can
//! quote any member, so it reads "redacted" once a waiting fork leaves it, as
//! an erase and a carrier leave it (`NoteReviewBundle::carried_here`): no
//! later erase could find the fork that left to redact it then. One whose
//! discarded notes it names by landing receipts only keeps its explainer
//! while a note it names stays, as shared content a later erase still finds
//! by those receipts, and reads "redacted" once every note it names is
//! discarded (call 1 = A).

use std::collections::BTreeSet;

use heed::RwTxn;

use super::documents::NOTE_PROPOSAL_DOC;
use super::proposals::{NOTE_FORK, NOTE_PROPOSAL_BUNDLE, NoteReviewBundle};
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
        let alone = names_only(&bundle, notes);
        let waited = bundle.waiting.len();
        bundle.waiting.retain(|fork| !notes.contains(&fork.note));
        if bundle.waiting.is_empty() && bundle.landed.is_empty() {
            NOTE_PROPOSAL_BUNDLE.delete(store, txn, &key)?;
        } else {
            if alone || bundle.waiting.len() != waited {
                bundle.explainer = REDACTED_EXPLAINER.to_owned();
            }
            NOTE_PROPOSAL_BUNDLE.put(store, txn, &key, &bundle)?;
        }
    }
    Ok(())
}

/// The explainer of each review bundle whose every named note is among
/// `discarded`, the notes all of one owner's discard's writes took: it reads
/// "redacted" once the last of them went in a write of its own, which saw
/// only its own notes (FIX 14534).
pub(crate) fn discard_bundle_explainers_in_txn(
    store: &Store,
    txn: &mut RwTxn<'_>,
    discarded: &BTreeSet<EntityId>,
) -> Result<()> {
    if discarded.is_empty() {
        return Ok(());
    }
    for (key, mut bundle) in NOTE_PROPOSAL_BUNDLE.scan(store, txn)? {
        if bundle.explainer != REDACTED_EXPLAINER && names_only(&bundle, discarded) {
            bundle.explainer = REDACTED_EXPLAINER.to_owned();
            NOTE_PROPOSAL_BUNDLE.put(store, txn, &key, &bundle)?;
        }
    }
    Ok(())
}

/// What a bundle's explainer reads once no note it quotes stays.
const REDACTED_EXPLAINER: &str = "redacted";

/// Whether `bundle` names a note, waiting or landed, and every one it names
/// is among `notes`: its explainer then quotes none that stays.
fn names_only(bundle: &NoteReviewBundle, notes: &BTreeSet<EntityId>) -> bool {
    let mut named = bundle
        .waiting
        .iter()
        .map(|fork| &fork.note)
        .chain(bundle.landed.iter().map(|receipt| &receipt.note))
        .peekable();
    named.peek().is_some() && named.all(|note| notes.contains(note))
}
