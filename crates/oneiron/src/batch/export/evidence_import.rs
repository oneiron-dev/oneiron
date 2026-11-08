//! FIX 7777: the whole-vault import's MESSAGE orchestration. It reads the
//! archive's indexed edges one MESSAGE at a time and hands each row to the
//! witness archive owner (`memory::witness::archive`), which writes it as
//! imported evidence. Nothing here writes a row or decides authority.
//!
//! - Before any row is compared or queued, every TURN and CONVERSATION an
//!   archived MESSAGE joins is marked, so its body comes back stamped
//!   imported (`archived_container_body`).
//! - A MESSAGE waits on its TURN and CONVERSATION, and its archived
//!   `AuthoredBy` targets ride inert in its body (`archived_message_body`).
//! - A NOTE keeps its source author as `NoteActor::Imported`
//!   (`archived_note_body`).
//! - The edge pass leaves a MESSAGE's or NOTE's archived `AuthoredBy`
//!   edges out: an archive never makes a local author.
use std::io::{Read, Seek};

use oneiron_contracts::affect::Vad;

use super::ExportEdge;
use super::archive_index::{ArchiveIndex, IndexedArchive, Loc, Tag, edge_key, id_at};
use crate::Vault;
use crate::edge::EdgeKind;
use crate::entity_id::{ENTITY_ID_LEN, EntityId};
use crate::error::{Error, Result};
use crate::memory::{ArchivedMessage, ArchivedMessageLink};
use crate::ports::{EdgeDirection, EdgeStoreRead};
use crate::registry::{
    ENTITY_TYPE_CONVERSATION, ENTITY_TYPE_MESSAGE, ENTITY_TYPE_NOTE, ENTITY_TYPE_TURN,
};
use crate::temporal::TimeRange;

fn invalid(reason: &str) -> Error {
    Error::InvalidConfig(format!("whole-vault import: {reason}"))
}

/// The targets of `source`'s archived `kind` edges, in index order.
pub(super) fn archived_targets(
    index: &ArchiveIndex<'_>,
    source: &EntityId,
    kind: EdgeKind,
) -> Result<Vec<EntityId>> {
    let mut prefix = source.as_bytes().to_vec();
    prefix.push(kind as u8);
    let mut targets = Vec::new();
    let mut after: Option<Vec<u8>> = None;
    while let Some((key, _)) = index.next(Tag::Edge, &prefix, after.as_deref())? {
        targets.push(id_at(&key, ENTITY_ID_LEN + 1)?);
        after = Some(key);
    }
    Ok(targets)
}

/// The one archived `kind` edge of MESSAGE `id`, to a row archived as
/// `entity_type`, with its value fields.
fn sole_link<R: Read + Seek>(
    archive: &IndexedArchive<'_, R>,
    id: &EntityId,
    kind: EdgeKind,
    entity_type: u8,
) -> Result<ArchivedMessageLink> {
    let mut prefix = id.as_bytes().to_vec();
    prefix.push(kind as u8);
    let mut link = None;
    let mut after: Option<Vec<u8>> = None;
    while let Some((key, value)) = archive.index.next(Tag::Edge, &prefix, after.as_deref())? {
        if link.is_some() {
            return Err(invalid("an archived MESSAGE has two parents of one kind"));
        }
        let target = id_at(&key, ENTITY_ID_LEN + 1)?;
        if archive.entity_at(&target)?.map(|at| at.entity_type) != Some(entity_type) {
            return Err(invalid("an archived MESSAGE's parent is of another type"));
        }
        let edge: ExportEdge = archive.spool.parse(Loc::decode(&value)?)?;
        if edge.provenance.is_some() {
            return Err(invalid(
                "an archived MESSAGE's membership carries provenance",
            ));
        }
        link = Some(ArchivedMessageLink {
            target,
            weight: edge.weight,
            created_at: edge.created_at,
            vad: edge.vad.map_or(Vad::NEUTRAL, |vad| Vad {
                valence: vad[0],
                arousal: vad[1],
                dominance: vad[2],
            }),
        });
        after = Some(key);
    }
    link.ok_or_else(|| invalid("an archived MESSAGE has no turn or conversation"))
}

/// The TURN and CONVERSATION archived MESSAGE `id` joins: one of each, the
/// TURN archived as a child of that CONVERSATION.
fn message_links<R: Read + Seek>(
    archive: &IndexedArchive<'_, R>,
    id: &EntityId,
) -> Result<(ArchivedMessageLink, ArchivedMessageLink)> {
    let turn = sole_link(archive, id, EdgeKind::PartOf, ENTITY_TYPE_TURN)?;
    let conversation = sole_link(archive, id, EdgeKind::BelongsTo, ENTITY_TYPE_CONVERSATION)?;
    let child_of = edge_key(&turn.target, EdgeKind::ChildOf as u8, &conversation.target);
    if !archive.index.contains(Tag::Edge, &child_of)? {
        return Err(invalid(
            "an archived MESSAGE's turn is not in its conversation",
        ));
    }
    Ok((turn, conversation))
}

/// Marks every TURN and CONVERSATION an archived MESSAGE joins, before any
/// row is compared or queued, and checks each MESSAGE's membership.
pub(super) fn index_message_containers<R: Read + Seek>(
    archive: &mut IndexedArchive<'_, R>,
) -> Result<()> {
    let mut after = None;
    while let Some(id) = archive.next_of_type(ENTITY_TYPE_MESSAGE, after.as_ref())? {
        after = Some(id);
        let (turn, conversation) = message_links(archive, &id)?;
        archive
            .index
            .put(Tag::MessageContainer, turn.target.as_bytes(), &[])?;
        archive
            .index
            .put(Tag::MessageContainer, conversation.target.as_bytes(), &[])?;
    }
    Ok(())
}

/// Checks that archived MESSAGE `id`, which matched a row already stored
/// here, has the stored row's membership: its one `PartOf` TURN and one
/// `BelongsTo` CONVERSATION are the archive's, so the edge pass gives it no
/// second parent.
pub(super) fn validate_stored_message<R: Read + Seek>(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    archive: &IndexedArchive<'_, R>,
    id: &EntityId,
) -> Result<()> {
    let (turn, conversation) = message_links(archive, id)?;
    for (kind, target) in [
        (EdgeKind::PartOf, turn.target),
        (EdgeKind::BelongsTo, conversation.target),
    ] {
        let mut stored = Vec::new();
        for edge in vault
            .store
            .port_edges(txn, id, EdgeDirection::Out, Some(kind), None)?
        {
            stored.push(edge?.target);
        }
        if stored != [target] {
            return Err(invalid(
                "an archived MESSAGE's membership differs from the stored row's",
            ));
        }
    }
    Ok(())
}

/// The rows archived MESSAGE `id` waits on: its TURN and CONVERSATION.
pub(super) fn message_dependencies<R: Read + Seek>(
    archive: &IndexedArchive<'_, R>,
    id: &EntityId,
) -> Result<[EntityId; 2]> {
    let (turn, conversation) = message_links(archive, id)?;
    Ok([turn.target, conversation.target])
}

/// Whether the edge `source -kind->` is an archived MESSAGE's or NOTE's
/// byline, which the edge pass leaves out: a MESSAGE's target rides in its
/// `metadata.import.authored_by`, a NOTE's in its imported `author_ref`.
pub(super) fn is_evidence_byline<R: Read + Seek>(
    archive: &IndexedArchive<'_, R>,
    source: &EntityId,
    kind: EdgeKind,
) -> Result<bool> {
    Ok(kind == EdgeKind::AuthoredBy
        && archive
            .entity_at(source)?
            .is_some_and(|at| matches!(at.entity_type, ENTITY_TYPE_MESSAGE | ENTITY_TYPE_NOTE)))
}

/// Restores archived MESSAGE `id`, its imported `body`, through the witness
/// archive owner, with its archived membership.
pub(super) fn restore_message<R: Read + Seek>(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    archive: &IndexedArchive<'_, R>,
    id: &EntityId,
    body: &[u8],
    occurred: TimeRange,
    learned_at: u64,
) -> Result<()> {
    let (turn, conversation) = message_links(archive, id)?;
    vault.restore_archived_message_in_txn(
        wtxn,
        &ArchivedMessage {
            id: *id,
            body,
            occurred,
            learned_at,
            turn,
            conversation,
        },
    )
}
