//! The retained parent values a pending NOTE fork needs (FIX 8829).
//!
//! A switch moves a NOTE's head to another fork's document and keeps the
//! previous head's; a fork still pending over the earlier head stays valid.
//! The artifact carries exactly the parents such forks need: a pending
//! fork's parent that is not its NOTE's current head, proven the NOTE's
//! original or reached from it by an actual chain of Switch receipts of the
//! same NOTE, each link proven by its receipt's previous head AND head. A
//! value is carried once per (note, head), as its text and title only: a
//! value that is not the head claims no authority. Nothing else stands in:
//! no current head, no other stored document, no guessed text.

use std::collections::{BTreeMap, BTreeSet};

use super::super::canonical::{ByteBudget, CanonicalSnapshot, id};
use super::{CanonicalDocument, NOTE_FORK, NOTE_RECEIPT};
use crate::Vault;
use crate::entity_id::EntityId as Id;
use crate::error::{ArtifactError, Result};
use crate::note::NoteVerdict;

/// One (note, head) a pending fork's parent names.
pub(in crate::recovery) type Place = (Id, Id);

/// Whether `head` is `note`'s original, or reached from it through
/// `switches` (each switched-to head of a NOTE, to its previous head).
fn proven(note: Id, mut head: Id, switches: &BTreeMap<Place, Id>) -> bool {
    let mut seen = BTreeSet::new();
    loop {
        if head == note {
            return true;
        }
        if !seen.insert(head) {
            return false;
        }
        match switches.get(&(note, head)) {
            Some(previous) => head = *previous,
            None => return false,
        }
    }
}

/// The parents `forks` need beside their NOTE's current head (`head_of`),
/// each proven through `switches`.
fn required(
    forks: impl IntoIterator<Item = (Id, Id)>,
    head_of: impl Fn(Id) -> Result<Id>,
    switches: &BTreeMap<Place, Id>,
) -> Result<BTreeSet<Place>> {
    let mut needed = BTreeSet::new();
    for (note, parent) in forks {
        if parent != head_of(note)? && proven(note, parent, switches) {
            needed.insert((note, parent));
        }
    }
    Ok(needed)
}

/// The retained parents the stored pending forks of the NOTEs in `ids`
/// need, proven by the stored Switch receipts.
pub(super) fn stored(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    ids: &BTreeSet<[u8; 16]>,
) -> Result<BTreeSet<Place>> {
    let mut switches = BTreeMap::new();
    for row in NOTE_RECEIPT.iter_from(&vault.store, txn, &[])? {
        let (_, receipt) = row?;
        if receipt.verdict == NoteVerdict::Switch
            && receipt.head == receipt.fork
            && ids.contains(receipt.note.as_bytes())
        {
            switches.insert((receipt.note, receipt.head), receipt.previous_head);
        }
    }
    let mut pending = Vec::new();
    for row in NOTE_FORK.iter_from(&vault.store, txn, &[])? {
        let (_, fork) = row?;
        if !fork.decided && ids.contains(fork.note.as_bytes()) {
            pending.push((fork.note, fork.parent));
        }
    }
    required(
        pending,
        |note| Ok(crate::note::documents::head_in(&vault.store, txn, note)?.0),
        &switches,
    )
}

/// The retained parents the snapshot's own pending forks need, proven by
/// its own Switch receipts.
pub(in crate::recovery) fn carried(snapshot: &CanonicalSnapshot) -> Result<BTreeSet<Place>> {
    let mut switches = BTreeMap::new();
    for row in &snapshot.head_move_receipts {
        let receipt = row.decode()?;
        if receipt.verdict == NoteVerdict::Switch && receipt.head == receipt.fork {
            switches.insert((receipt.note, receipt.head), receipt.previous_head);
        }
    }
    let heads: BTreeMap<_, _> = snapshot
        .document_heads
        .iter()
        .map(|row| (row.entity_id, row.head))
        .collect();
    let pending = snapshot
        .note_forks
        .iter()
        .filter(|fork| !fork.decided)
        .map(|fork| (fork.note, fork.parent));
    required(
        pending,
        |note| match heads.get(note.as_bytes()) {
            Some(head) => id(*head),
            None => Ok(note),
        },
        &switches,
    )
}

/// Captures each value of `needed` for `note`: its text and title as the
/// retained head's own document holds them
/// ([`crate::note::documents::load_retained_head`]), measured as NOTE
/// births are. A value not here is left out: the fork's own check then
/// answers for it, as before.
pub(super) fn capture_note(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    note: [u8; 16],
    needed: &BTreeSet<Place>,
    birth: (Option<[u8; 16]>, u64),
    budget: &mut ByteBudget,
    overrun: &mut Option<ArtifactError>,
) -> Result<Vec<CanonicalDocument>> {
    let owner = id(note)?;
    let mut rows = Vec::new();
    for &(_, head) in needed.iter().filter(|(of, _)| *of == owner) {
        let Some(doc) = crate::note::documents::load_retained_head(vault, txn, owner, head)? else {
            continue;
        };
        let mut row = super::from_doc(note, *head.as_bytes(), &doc, true, birth.0, birth.1)?;
        row.authorship.clear();
        super::take_document(budget, &row, overrun)?;
        rows.push(row);
    }
    Ok(rows)
}
