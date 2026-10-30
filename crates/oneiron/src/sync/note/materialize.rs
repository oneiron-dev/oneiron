//! Peer windows retain erasure markers, never authorize NOTE mutation.
use super::*;
use crate::side_table::{self, Raw, SideTable};

/// Marks a window whose peer-authored NOTE inbox residue was staged
/// (`note_inbox:v1:{window}`). Key: the window key; value: empty marker.
const NOTE_INBOX: SideTable<String, (), Raw> = SideTable::new(&side_table::SYNC_NOTE_INBOX);

pub(crate) fn apply(
    vault: &Vault,
    doc: &LoroDoc,
    mut state: State,
    window: &str,
) -> Result<Vec<EntityId>> {
    let tombstones = TombstoneIndex::build(&doc.get_map("tombstones"));
    vault.with_write_txn_grouped(|txn| {
        let mut dropped = BTreeSet::new();
        for note in state.cores.keys() {
            if blocked(vault, txn, &tombstones, note)?
                || crate::sync::quarantine::unproven_remat_marker_exists_in_txn(
                    vault, txn, window, note,
                )?
            {
                dropped.insert(*note);
            }
        }
        // A bundle's attachment of a NOTE deleted here stages as deleted,
        // whichever window carries that NOTE's core (FIX 8878).
        let judge = super::workflows::Judge {
            vault,
            txn,
            tombstones: &tombstones,
            flagged: &BTreeSet::new(),
            selector: None,
        };
        for note in state.notes() {
            if !state.cores.contains_key(&note) && !judge.attaches(&note)? {
                dropped.insert(note);
            }
        }
        state.drop_deleted(&dropped);
        state.validate()?;
        // Erasure reads this namespace to find and purge workflow residue;
        // proposal review/landing deliberately does not read it.
        // Peer metadata never mints a trusted fork, authorship or receipt.
        NOTE_INBOX.put(&vault.store, txn, &window.to_owned(), &())?;
        Ok(Vec::new()) // Staging is not a canonical healing write.
    })
}
