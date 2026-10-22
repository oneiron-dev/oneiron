//! Layer 1 rebuilt from a canonical snapshot's values, never by importing an
//! old CRDT snapshot. The rows go in section by section, so a recovery can
//! page the rebuild (FIX 8821): each page files the next rows into the one
//! fresh document, and the document is committed once every row is in.

use loro::LoroDoc;

use super::{CanonicalSnapshot, id, insert, pack, peer_origins, row_births, withdrawn_cutoffs};
use crate::error::Result;

/// How many sections a rebuild files, in [`insert_row`]'s order.
const SECTIONS: usize = 17;

/// Where a paged rebuild stands: the section, and the row within it.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct RebuildAt {
    section: usize,
    row: usize,
}

#[cfg(feature = "sync")]
impl RebuildAt {
    /// The window map the next row goes to, and its index there, for a
    /// continuation's cursor.
    pub(crate) fn position(&self) -> String {
        format!("section {}:{}", self.section, self.row)
    }
}

/// Reconstructs Layer 1 from values, not by importing an old CRDT snapshot.
/// Available without `sync`; the sync materialization door consumes this same doc.
pub fn rebuild_vault_window_from_canonical(snapshot: &CanonicalSnapshot) -> Result<LoroDoc> {
    snapshot.validate()?;
    let doc = rebuild_start();
    rebuild_page(&doc, snapshot, &mut RebuildAt::default(), usize::MAX)?;
    doc.commit();
    Ok(doc)
}

/// The fresh document a rebuild files rows into. An explicit document
/// carrier scopes replacement even for an inline NOTE with no document rows;
/// ordinary sync windows have no such carrier.
pub(crate) fn rebuild_start() -> LoroDoc {
    let doc = LoroDoc::new();
    doc.get_map("documents");
    doc
}

/// Files at most `page` more rows of a validated `snapshot` into `doc` from
/// `at`, and moves `at` past them. Returns whether every row is in; the
/// caller then commits `doc`.
pub(crate) fn rebuild_page(
    doc: &LoroDoc,
    snapshot: &CanonicalSnapshot,
    at: &mut RebuildAt,
    page: usize,
) -> Result<bool> {
    let mut left = page.max(1);
    while at.section < SECTIONS {
        while at.row < section_len(snapshot, at.section) {
            if left == 0 {
                return Ok(false);
            }
            insert_row(doc, snapshot, at.section, at.row)?;
            at.row += 1;
            left -= 1;
        }
        at.section += 1;
        at.row = 0;
    }
    Ok(true)
}

fn section_len(snapshot: &CanonicalSnapshot, section: usize) -> usize {
    match section {
        0 => snapshot.entity_blobs.len(),
        1 => snapshot.peer_origins.len(),
        2 => snapshot.row_births.len(),
        3 => snapshot.retained_claim_worlds.len(),
        4 => snapshot.base_edges.len(),
        5 => snapshot.custody_transitions.len(),
        6 => snapshot.room_turns.len(),
        7 => snapshot.room_facts.len(),
        8 => snapshot.document_pins.len(),
        9 => snapshot.withdrawn_cutoffs.len(),
        10 => snapshot.tombstones.len(),
        // Documents are canonical records inside the window; each is
        // reconstructed into its own fresh LoroDoc by the ordinary forward
        // document pass.
        11 => snapshot.doc_snapshots.len(),
        12 => snapshot.entity_documents.len(),
        13 => snapshot.document_heads.len(),
        14 => snapshot.head_move_receipts.len(),
        15 => snapshot.note_forks.len(),
        16 => snapshot.note_proposals.len(),
        _ => 0,
    }
}

fn insert_row(
    doc: &LoroDoc,
    snapshot: &CanonicalSnapshot,
    section: usize,
    at: usize,
) -> Result<()> {
    match section {
        0 => {
            let row = &snapshot.entity_blobs[at];
            insert(doc, "entities", &id(row.id)?.to_hex(), &row.blob)
        }
        1 => peer_origins::rebuild_row(doc, &snapshot.peer_origins[at]),
        2 => row_births::rebuild_row(doc, &snapshot.row_births[at]),
        3 => {
            let row = &snapshot.retained_claim_worlds[at];
            insert(
                doc,
                "retained_claim_worlds",
                &id(row.id)?.to_hex(),
                &row.world,
            )
        }
        4 => {
            let row = &snapshot.base_edges[at];
            insert(doc, "edges", &row.key()?, &row.value)
        }
        5 => {
            let row = &snapshot.custody_transitions[at];
            let key = crate::secret_custody::custody_row_key(id(row.id)?, row.piece);
            insert(doc, "custody", &key, &row.carrier)
        }
        6 => {
            let row = &snapshot.room_turns[at];
            insert(doc, "room_turns", &id(row.id)?.to_hex(), &row.row)
        }
        7 => {
            let row = &snapshot.room_facts[at];
            insert(doc, "room_facts", &row.key, &row.row)
        }
        8 => {
            let row = &snapshot.document_pins[at];
            insert(doc, "document_pins", &row.key, &row.row)
        }
        9 => withdrawn_cutoffs::rebuild_row(doc, &snapshot.withdrawn_cutoffs[at]),
        10 => {
            let row = &snapshot.tombstones[at];
            insert(doc, "tombstones", &id(row.id)?.to_hex(), &row.value)
        }
        11 => {
            let row = &snapshot.doc_snapshots[at];
            insert(doc, "documents", &row.key(), &pack(row)?)
        }
        12 => {
            let row = &snapshot.entity_documents[at];
            insert(
                doc,
                "entity_documents",
                &id(row.entity_id)?.to_hex(),
                &pack(row)?,
            )
        }
        13 => {
            let row = &snapshot.document_heads[at];
            insert(
                doc,
                "document_heads",
                &id(row.entity_id)?.to_hex(),
                &pack(row)?,
            )
        }
        14 => {
            let row = &snapshot.head_move_receipts[at];
            insert(
                doc,
                "head_move_receipts",
                &id(row.id)?.to_hex(),
                &pack(row)?,
            )
        }
        15 => {
            let row = &snapshot.note_forks[at];
            insert(doc, "note_forks", &row.fork.to_hex(), &pack(row)?)
        }
        _ => {
            let row = &snapshot.note_proposals[at];
            insert(doc, "note_proposals", &row.id.to_hex(), &pack(row)?)
        }
    }
}
