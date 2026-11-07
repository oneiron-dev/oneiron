//! Source attribution of imported speech (FIX 15412): the PERSON a trusted
//! importer names as the speaker of an imported MESSAGE, and how a reader
//! tells that edge from a native writer's.
//!
//! An imported MESSAGE may carry one `AuthoredBy` edge to a PERSON. For an
//! import that edge says only that the source names this PERSON as the
//! speaker: the importer wrote the row (its `RowBirth`), the source's
//! speaker said the words. It is never writer, delete, GDPR, quote-write or
//! Q&A authority, nor trust or audience. The importer names each MESSAGE's
//! speaker as a [`SourceSpeaker`]; the witness program resolves it once, in
//! the landing's own writer before admission, to the one target admission
//! expects and staging writes. A MESSAGE already stored keeps the edge it
//! was born with, none included.

use super::super::MemoryResult;
use super::codec::{ImportStamp, import_stamp};
use super::validation::sole_edge_target;
use crate::Vault;
use crate::edge::EdgeKind;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::identity_topology::EntityLifecycleState;
use crate::ports::{EdgeDirection, EdgeStoreRead, EntityStoreRead};
use crate::registry::{ENTITY_TYPE_MESSAGE, ENTITY_TYPE_PERSON};
use crate::store::ManifestDbs;

/// Whom the source of an imported turn names as the speaker of its
/// MESSAGEs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SourceAttribution {
    /// The importer names no speaker: no MESSAGE of the turn takes an
    /// `AuthoredBy` edge. Every import but mail.
    Unbound,
    /// One speaker per message, in the turn's message order.
    PerMessage(Vec<SourceSpeaker>),
}

/// The speaker an importer names for one MESSAGE, as data the witness
/// program resolves in the landing's own writer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SourceSpeaker {
    /// The source names no one the vault binds.
    Unknown,
    /// The live PERSON the comm party key (`email:<mailbox>`) names, when
    /// one does. A read: no PERSON is minted and no index is repaired.
    Party(String),
    /// This PERSON, when it is live: a personal mailbox's owner, for the
    /// mail it sent.
    Person(EntityId),
    /// The binding earlier revisions of the same source message landed
    /// with, oldest first: the newest live revision's, none included, at its
    /// one live canonical head. A later revision never takes another
    /// speaker than the first.
    Revisions(Vec<EntityId>),
}

/// The `AuthoredBy` target each MESSAGE of `messages` is admitted with, in
/// plan order, resolved once in the writer `txn` before admission. A
/// MESSAGE already stored keeps the one edge it was born with, none
/// included, so its retry compares that edge and stages nothing. A new
/// MESSAGE takes the live PERSON its [`SourceSpeaker`] names, unless the
/// room `conversation` fenced that PERSON's erasure; else none. An
/// unresolved speaker never refuses the turn.
pub(crate) fn admitted_source_speakers_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    conversation: EntityId,
    messages: &[EntityId],
    speakers: &[SourceSpeaker],
) -> MemoryResult<Vec<Option<EntityId>>> {
    let mut admitted = Vec::with_capacity(messages.len());
    for (message, speaker) in messages.iter().zip(speakers) {
        if vault.store.port_entity_record(txn, message)?.is_some() {
            admitted.push(sole_edge_target(
                &vault.store,
                txn,
                message,
                EdgeKind::AuthoredBy,
                "message",
            )?);
            continue;
        }
        let named = match speaker {
            SourceSpeaker::Unknown => None,
            SourceSpeaker::Party(party) => {
                match crate::comm::resolve_party_ref_in_txn(vault, txn, party) {
                    Ok(found) => found,
                    Err(crate::comm::CommError::Engine(error)) => return Err(error.into()),
                    // A key the comm plane does not accept names no one.
                    Err(_) => None,
                }
            }
            SourceSpeaker::Person(person) => Some(*person),
            SourceSpeaker::Revisions(revisions) => revision_speaker_in_txn(vault, txn, revisions)?,
        };
        let person = match named {
            Some(named) => live_canonical_person_in_txn(vault, txn, &named)?,
            None => None,
        };
        admitted.push(match person {
            Some(person)
                if crate::conversation::room_person_write_allowed(
                    &vault.store,
                    txn,
                    conversation,
                    person,
                )? =>
            {
                Some(person)
            }
            _ => None,
        });
    }
    Ok(admitted)
}

/// The raw binding of the newest live revision among `revisions`, oldest
/// first: its one `AuthoredBy` target, or none. None when no revision is
/// live: a retired or erased revision is no reason to name someone new.
fn revision_speaker_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    revisions: &[EntityId],
) -> MemoryResult<Option<EntityId>> {
    for revision in revisions.iter().rev() {
        if crate::vault::live_entity_row_in_txn(&vault.store, txn, revision)?.live_type()
            == Some(ENTITY_TYPE_MESSAGE)
        {
            return sole_edge_target(&vault.store, txn, revision, EdgeKind::AuthoredBy, "message");
        }
    }
    Ok(None)
}

/// The one live canonical PERSON `id` names: itself while it is a live,
/// unremoved, active PERSON, or, while it is a live, unremoved PERSON merged
/// into another, the one surviving head it resolves to. None when `id`
/// itself is erased (soft or hard), removed or no PERSON, though a soft
/// erase keeps its merge redirect: an erased speaker names no one, not its
/// head. None too for a split (no single head) or a head that is erased,
/// removed or retired.
fn live_canonical_person_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
) -> Result<Option<EntityId>> {
    if !live_unremoved_person_in_txn(vault, txn, id)? {
        return Ok(None);
    }
    let [head] = vault.resolve_entity_in_txn(txn, id)?[..] else {
        return Ok(None);
    };
    let live = live_unremoved_person_in_txn(vault, txn, &head)?
        && vault.entity_lifecycle_state_in_txn(txn, &head)? == EntityLifecycleState::Active;
    Ok(live.then_some(head))
}

/// Whether `id` is a live PERSON row that no deletion removes.
fn live_unremoved_person_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
) -> Result<bool> {
    Ok(
        crate::vault::live_entity_row_in_txn(&vault.store, txn, id)?.live_type()
            == Some(ENTITY_TYPE_PERSON)
            && !crate::ports::removed_in_txn(&vault.store, txn, id)?,
    )
}

/// The PERSON the source names as the speaker of an imported MESSAGE whose
/// `AuthoredBy` targets are `authors`: the one live canonical PERSON of its
/// one target. None for no target, for several, or for one with no single
/// live PERSON head.
pub(crate) fn source_speaker_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    authors: &[EntityId],
) -> Result<Option<EntityId>> {
    match authors {
        [author] => live_canonical_person_in_txn(vault, txn, author),
        _ => Ok(None),
    }
}

/// Whether the stored MESSAGE `message` is imported speech: a TURN or a
/// CONVERSATION it belongs to carries an import stamp (a malformed stamp
/// counts). Its `AuthoredBy` edge, if any, names the source's speaker and
/// never proves a native writer: a reader that asks for writer provenance
/// takes none from it.
pub(crate) fn imported_message_in_txn(
    dbs: &impl ManifestDbs,
    txn: &heed::RoTxn<'_>,
    message: &EntityId,
) -> Result<bool> {
    for kind in [EdgeKind::PartOf, EdgeKind::BelongsTo] {
        for edge in dbs.port_edges(txn, message, EdgeDirection::Out, Some(kind), None)? {
            let container = edge?.target;
            if let Some(record) = dbs.port_entity_record(txn, &container)?
                && import_stamp(&record.body) != ImportStamp::Live
            {
                return Ok(true);
            }
        }
    }
    Ok(false)
}
