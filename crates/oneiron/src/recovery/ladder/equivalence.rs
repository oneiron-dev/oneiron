//! Pure equality of one owned recapture after native pad normalization.
//! Payload bytes, titles and fields resume one byte per existing work unit.

use crate::error::Result;
use crate::note::NoteFork;
use crate::recovery::canonical::{
    CanonicalEntity, CanonicalEntityDocument, CanonicalSnapshot, invalid,
};
use crate::recovery::{CanonicalDocument, CanonicalHeadMove};

pub(in crate::recovery) struct CanonicalComparison {
    actual: CanonicalSnapshot,
    group: Group,
    next: usize,
    byte: usize,
    payload: PayloadPart,
}

#[derive(PartialEq, Eq)]
enum PayloadPart {
    First,
    Second,
    Third,
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
            byte: 0,
            payload: PayloadPart::First,
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
                compare_entities(
                    entity_blobs,
                    &wanted.entity_blobs,
                    &mut self.next,
                    &mut self.byte,
                )?,
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
                compare_documents(
                    doc_snapshots,
                    &wanted.doc_snapshots,
                    &mut self.next,
                    &mut self.byte,
                    &mut self.payload,
                )?,
                Group::EntityDocuments,
            ),
            Group::EntityDocuments => (
                compare_entity_documents(
                    entity_documents,
                    &wanted.entity_documents,
                    &mut self.next,
                    &mut self.byte,
                    &mut self.payload,
                )?,
                Group::DocumentHeads,
            ),
            Group::DocumentHeads => (
                compare_rows(document_heads, &wanted.document_heads, &mut self.next)?,
                Group::HeadMoveReceipts,
            ),
            Group::HeadMoveReceipts => (
                compare_head_receipts(
                    head_move_receipts,
                    &wanted.head_move_receipts,
                    &mut self.next,
                    &mut self.byte,
                )?,
                Group::NoteForks,
            ),
            Group::NoteForks => (
                compare_note_forks(
                    note_forks,
                    &wanted.note_forks,
                    &mut self.next,
                    &mut self.byte,
                    &mut self.payload,
                )?,
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
            self.byte = 0;
            self.payload = PayloadPart::First;
        }
        Ok(matches!(self.group, Group::Complete))
    }
}

fn compare_entities(
    actual: &[CanonicalEntity],
    wanted: &[CanonicalEntity],
    next: &mut usize,
    byte: &mut usize,
) -> Result<bool> {
    compare_value(&actual.len(), &wanted.len())?;
    let Some(CanonicalEntity { id, blob }) = actual.get(*next) else {
        return Ok(true);
    };
    let CanonicalEntity {
        id: expected_id,
        blob: expected_blob,
    } = &wanted[*next];
    if *byte == 0 {
        compare_value(id, expected_id)?;
    }
    if compare_bytes(blob, expected_blob, byte)? {
        *next += 1;
        *byte = 0;
    }
    Ok(false)
}

fn compare_documents(
    actual: &[CanonicalDocument],
    wanted: &[CanonicalDocument],
    next: &mut usize,
    byte: &mut usize,
    payload: &mut PayloadPart,
) -> Result<bool> {
    compare_value(&actual.len(), &wanted.len())?;
    let Some(CanonicalDocument {
        entity_id,
        head,
        text,
        title,
        birth_actor,
        birth_at,
        authorship,
    }) = actual.get(*next)
    else {
        return Ok(true);
    };
    let CanonicalDocument {
        entity_id: expected_entity,
        head: expected_head,
        text: expected_text,
        title: expected_title,
        birth_actor: expected_birth_actor,
        birth_at: expected_birth_at,
        authorship: expected_authorship,
    } = &wanted[*next];
    if *payload == PayloadPart::First {
        if *byte == 0 {
            compare_value(entity_id, expected_entity)?;
            compare_value(head, expected_head)?;
        }
        if compare_bytes(text.as_bytes(), expected_text.as_bytes(), byte)? {
            *payload = PayloadPart::Second;
            *byte = 0;
        }
        return Ok(false);
    }
    if compare_optional_text(title, expected_title, byte)? {
        compare_value(birth_actor, expected_birth_actor)?;
        compare_value(birth_at, expected_birth_at)?;
        compare_value(authorship, expected_authorship)?;
        *next += 1;
        *byte = 0;
        *payload = PayloadPart::First;
    }
    Ok(false)
}

fn compare_entity_documents(
    actual: &[CanonicalEntityDocument],
    wanted: &[CanonicalEntityDocument],
    next: &mut usize,
    byte: &mut usize,
    payload: &mut PayloadPart,
) -> Result<bool> {
    compare_value(&actual.len(), &wanted.len())?;
    let Some(CanonicalEntityDocument {
        entity_id,
        document_id,
        field,
        text,
        metadata,
        summary_meta,
        record_fields,
        birth_actor,
        birth_at,
        history,
    }) = actual.get(*next)
    else {
        return Ok(true);
    };
    let CanonicalEntityDocument {
        entity_id: expected_entity,
        document_id: expected_document,
        field: expected_field,
        text: expected_text,
        metadata: expected_metadata,
        summary_meta: expected_summary_meta,
        record_fields: expected_record_fields,
        birth_actor: expected_birth_actor,
        birth_at: expected_birth_at,
        history: expected_history,
    } = &wanted[*next];
    if *payload == PayloadPart::First {
        if *byte == 0 {
            compare_value(entity_id, expected_entity)?;
            compare_value(document_id, expected_document)?;
        }
        if compare_optional_text(field, expected_field, byte)? {
            *payload = PayloadPart::Second;
            *byte = 0;
        }
        return Ok(false);
    }
    if compare_bytes(text.as_bytes(), expected_text.as_bytes(), byte)? {
        compare_value(metadata, expected_metadata)?;
        compare_value(summary_meta, expected_summary_meta)?;
        compare_value(record_fields, expected_record_fields)?;
        compare_value(birth_actor, expected_birth_actor)?;
        compare_value(birth_at, expected_birth_at)?;
        compare_value(history, expected_history)?;
        *next += 1;
        *byte = 0;
        *payload = PayloadPart::First;
    }
    Ok(false)
}

fn compare_note_forks(
    actual: &[NoteFork],
    wanted: &[NoteFork],
    next: &mut usize,
    byte: &mut usize,
    payload: &mut PayloadPart,
) -> Result<bool> {
    compare_value(&actual.len(), &wanted.len())?;
    let Some(NoteFork {
        note,
        fork,
        parent,
        frontier,
        recovery_merge,
        actor,
        rewrite,
        proposal,
        decided,
    }) = actual.get(*next)
    else {
        return Ok(true);
    };
    let NoteFork {
        note: expected_note,
        fork: expected_fork,
        parent: expected_parent,
        frontier: expected_frontier,
        recovery_merge: expected_recovery_merge,
        actor: expected_actor,
        rewrite: expected_rewrite,
        proposal: expected_proposal,
        decided: expected_decided,
    } = &wanted[*next];
    if *payload == PayloadPart::First {
        if *byte == 0 {
            compare_value(note, expected_note)?;
            compare_value(fork, expected_fork)?;
            compare_value(parent, expected_parent)?;
        }
        if compare_bytes(frontier, expected_frontier, byte)? {
            *payload = PayloadPart::Second;
            *byte = 0;
        }
        return Ok(false);
    }
    match (recovery_merge, expected_recovery_merge) {
        (Some((parent, merged)), Some((expected_parent, expected_merged))) => {
            if *payload == PayloadPart::Second {
                if compare_bytes(parent.as_bytes(), expected_parent.as_bytes(), byte)? {
                    *payload = PayloadPart::Third;
                    *byte = 0;
                }
                return Ok(false);
            }
            if !compare_bytes(merged.as_bytes(), expected_merged.as_bytes(), byte)? {
                return Ok(false);
            }
        }
        (None, None) => {}
        _ => compare_value(
            &recovery_merge.is_some(),
            &expected_recovery_merge.is_some(),
        )?,
    }
    compare_value(actor, expected_actor)?;
    compare_value(rewrite, expected_rewrite)?;
    compare_value(proposal, expected_proposal)?;
    compare_value(decided, expected_decided)?;
    *next += 1;
    *byte = 0;
    *payload = PayloadPart::First;
    Ok(false)
}

fn compare_head_receipts(
    actual: &[CanonicalHeadMove],
    wanted: &[CanonicalHeadMove],
    next: &mut usize,
    byte: &mut usize,
) -> Result<bool> {
    compare_value(&actual.len(), &wanted.len())?;
    let Some(CanonicalHeadMove {
        id,
        entity_id,
        receipt,
    }) = actual.get(*next)
    else {
        return Ok(true);
    };
    let CanonicalHeadMove {
        id: expected_id,
        entity_id: expected_entity,
        receipt: expected_receipt,
    } = &wanted[*next];
    if *byte == 0 {
        compare_value(id, expected_id)?;
        compare_value(entity_id, expected_entity)?;
    }
    if compare_bytes(receipt, expected_receipt, byte)? {
        *next += 1;
        *byte = 0;
    }
    Ok(false)
}

fn compare_optional_text(
    actual: &Option<String>,
    wanted: &Option<String>,
    next: &mut usize,
) -> Result<bool> {
    match (actual, wanted) {
        (Some(actual), Some(wanted)) => compare_bytes(actual.as_bytes(), wanted.as_bytes(), next),
        (None, None) => Ok(true),
        _ => {
            compare_value(&actual.is_some(), &wanted.is_some())?;
            Ok(false)
        }
    }
}

fn compare_bytes(actual: &[u8], wanted: &[u8], next: &mut usize) -> Result<bool> {
    compare_value(&actual.len(), &wanted.len())?;
    if let Some(value) = actual.get(*next) {
        compare_value(value, &wanted[*next])?;
        *next += 1;
    }
    Ok(*next == actual.len())
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
