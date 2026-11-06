//! Pure row equality of one owned recapture after native pad normalization.

use crate::error::Result;
use crate::recovery::canonical::{CanonicalSnapshot, invalid};

pub(in crate::recovery) struct CanonicalComparison {
    actual: CanonicalSnapshot,
    group: Group,
    next: usize,
}

enum Group {
    Window,
    EntityBlobs,
    RetainedClaimWorlds,
    BaseEdges,
    Tombstones,
    DocSnapshots,
    EntityDocuments,
    DocumentHeads,
    HeadMoveReceipts,
    NoteForks,
    NoteProposals,
    ContainerManifests,
    SchemaManifest,
    SuppressedTasks,
    CustodyTransitions,
    RoomTurns,
    RoomFacts,
    DocumentPins,
    PeerOrigins,
    RowBirths,
    WithdrawnCutoffs,
    AssetBodyRefs,
    Complete,
}

impl CanonicalComparison {
    pub(super) fn new(actual: CanonicalSnapshot) -> Self {
        Self {
            actual,
            group: Group::Window,
            next: 0,
        }
    }

    pub(super) fn advance(&mut self, wanted: &CanonicalSnapshot, max_rows: usize) -> Result<bool> {
        for _ in 0..max_rows.max(1) {
            if self.advance_row(wanted)? {
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn advance_row(&mut self, wanted: &CanonicalSnapshot) -> Result<bool> {
        // Exhaustive: a new snapshot field must join this comparison too.
        let CanonicalSnapshot {
            window,
            entity_blobs,
            retained_claim_worlds,
            base_edges,
            tombstones,
            doc_snapshots,
            entity_documents,
            document_heads,
            head_move_receipts,
            note_forks,
            note_proposals,
            container_manifests,
            schema_manifest,
            suppressed_tasks,
            custody_transitions,
            room_turns,
            room_facts,
            document_pins,
            peer_origins,
            row_births,
            withdrawn_cutoffs,
            asset_body_refs,
        } = &self.actual;
        let (done, next_group) = match self.group {
            Group::Window => {
                compare_value(window, &wanted.window)?;
                (true, Group::EntityBlobs)
            }
            Group::EntityBlobs => (
                compare_rows(entity_blobs, &wanted.entity_blobs, &mut self.next)?,
                Group::RetainedClaimWorlds,
            ),
            Group::RetainedClaimWorlds => (
                compare_rows(
                    retained_claim_worlds,
                    &wanted.retained_claim_worlds,
                    &mut self.next,
                )?,
                Group::BaseEdges,
            ),
            Group::BaseEdges => (
                compare_rows(base_edges, &wanted.base_edges, &mut self.next)?,
                Group::Tombstones,
            ),
            Group::Tombstones => (
                compare_rows(tombstones, &wanted.tombstones, &mut self.next)?,
                Group::DocSnapshots,
            ),
            Group::DocSnapshots => (
                compare_rows(doc_snapshots, &wanted.doc_snapshots, &mut self.next)?,
                Group::EntityDocuments,
            ),
            Group::EntityDocuments => (
                compare_rows(entity_documents, &wanted.entity_documents, &mut self.next)?,
                Group::DocumentHeads,
            ),
            Group::DocumentHeads => (
                compare_rows(document_heads, &wanted.document_heads, &mut self.next)?,
                Group::HeadMoveReceipts,
            ),
            Group::HeadMoveReceipts => (
                compare_rows(
                    head_move_receipts,
                    &wanted.head_move_receipts,
                    &mut self.next,
                )?,
                Group::NoteForks,
            ),
            Group::NoteForks => (
                compare_rows(note_forks, &wanted.note_forks, &mut self.next)?,
                Group::NoteProposals,
            ),
            Group::NoteProposals => (
                compare_rows(note_proposals, &wanted.note_proposals, &mut self.next)?,
                Group::ContainerManifests,
            ),
            Group::ContainerManifests => (
                compare_rows(
                    container_manifests,
                    &wanted.container_manifests,
                    &mut self.next,
                )?,
                Group::SchemaManifest,
            ),
            Group::SchemaManifest => {
                compare_value(schema_manifest, &wanted.schema_manifest)?;
                (true, Group::SuppressedTasks)
            }
            Group::SuppressedTasks => (
                compare_rows(suppressed_tasks, &wanted.suppressed_tasks, &mut self.next)?,
                Group::CustodyTransitions,
            ),
            Group::CustodyTransitions => (
                compare_rows(
                    custody_transitions,
                    &wanted.custody_transitions,
                    &mut self.next,
                )?,
                Group::RoomTurns,
            ),
            Group::RoomTurns => (
                compare_rows(room_turns, &wanted.room_turns, &mut self.next)?,
                Group::RoomFacts,
            ),
            Group::RoomFacts => (
                compare_rows(room_facts, &wanted.room_facts, &mut self.next)?,
                Group::DocumentPins,
            ),
            Group::DocumentPins => (
                compare_rows(document_pins, &wanted.document_pins, &mut self.next)?,
                Group::PeerOrigins,
            ),
            Group::PeerOrigins => (
                compare_rows(peer_origins, &wanted.peer_origins, &mut self.next)?,
                Group::RowBirths,
            ),
            Group::RowBirths => (
                compare_rows(row_births, &wanted.row_births, &mut self.next)?,
                Group::WithdrawnCutoffs,
            ),
            Group::WithdrawnCutoffs => (
                compare_rows(withdrawn_cutoffs, &wanted.withdrawn_cutoffs, &mut self.next)?,
                Group::AssetBodyRefs,
            ),
            Group::AssetBodyRefs => (
                compare_rows(asset_body_refs, &wanted.asset_body_refs, &mut self.next)?,
                Group::Complete,
            ),
            Group::Complete => return Ok(true),
        };
        if done {
            self.group = next_group;
            self.next = 0;
        }
        Ok(matches!(self.group, Group::Complete))
    }
}

fn compare_rows<T: PartialEq>(actual: &[T], wanted: &[T], next: &mut usize) -> Result<bool> {
    compare_value(&actual.len(), &wanted.len())?;
    let Some(value) = actual.get(*next) else {
        return Ok(true);
    };
    compare_value(value, &wanted[*next])?;
    *next += 1;
    Ok(false)
}

fn compare_value<T: PartialEq>(actual: &T, wanted: &T) -> Result<()> {
    if actual != wanted {
        return Err(invalid("recovery materialization is not equivalent"));
    }
    Ok(())
}
