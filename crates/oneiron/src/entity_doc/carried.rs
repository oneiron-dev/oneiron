//! A MESSAGE's document between the owner's machines (FIX 853).
//!
//! A window carries a MESSAGE's document beside the message: its head and a
//! snapshot of its history (`sync::message_docs`). Another of the owner's
//! machines installs it under the same head, so the text, a quote's pinned
//! version and its citation floors resolve there as on the machine that
//! wrote it.
//!
//! An owner purge on one machine changes no operation, only the version its
//! history starts at. A head whose floor is newer than this vault's drops the
//! history here to the same floor, as the purge door would (FIX 3552); an
//! older floor never brings dropped history back.

use super::document::decode_frontier;
use super::storage::{self, ENTITY_DOC_HEAD, Head};
use super::{EntityDoc, TextField};
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::error::{ArtifactError, Error, Result};
use crate::ports::{DocumentRow, DocumentRowStore, DocumentSlot, EntityStoreRead};
use crate::side_table::HexId;
use crate::{EntityId, Vault};
use heed::{RoTxn, RwTxn};
use loro::VersionVector;
use serde::{Deserialize, Serialize};

/// What a window carries of a MESSAGE's document beside its snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CarriedDocument {
    pub(crate) entity: String,
    pub(crate) document: String,
    pub(crate) incarnation: String,
    /// The document's version vector, encoded.
    pub(crate) version: Vec<u8>,
    /// The version its history starts at after an owner purge, encoded;
    /// empty while it keeps all of it.
    pub(crate) shallow: Vec<u8>,
}

/// What a head does here whose history floor is newer than this vault's, an
/// owner purge on another machine (a call: canon rules no reconciliation of
/// purge floors between machines).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RemotePurgePolicy {
    /// This vault drops its history to the same floor, where a purge here
    /// could reach it.
    AdvanceIfPinsPermit,
}

/// How a MESSAGE document takes another machine's purge.
const MESSAGE_DOC_REMOTE_PURGE_POLICY: RemotePurgePolicy = RemotePurgePolicy::AdvanceIfPinsPermit;

/// What such a head does when this vault cannot drop its history to exactly
/// that floor: a pin, a citation floor, a receipt, a fork base or a legal
/// hold here keeps older history, or the history here cuts elsewhere (a
/// call).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PurgeConflictPolicy {
    /// The history here stands, and the head stays in the window for a later
    /// merge.
    Defer,
}

/// How a MESSAGE document takes a purge it cannot reach.
const MESSAGE_DOC_PURGE_CONFLICT_POLICY: PurgeConflictPolicy = PurgeConflictPolicy::Defer;

/// What merging a carried document did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DocumentMerge {
    /// The document was installed here, or took new operations.
    Written,
    /// This vault already held all of it.
    Held,
    /// This vault holds another document or incarnation for the message,
    /// and it stands.
    Conflict,
    /// The message has not landed here yet.
    Waiting,
    /// The document does not merge here.
    Refused(&'static str),
    /// The head is a purge this vault does not take yet
    /// ([`MESSAGE_DOC_PURGE_CONFLICT_POLICY`]).
    Deferred(&'static str),
}

impl CarriedDocument {
    /// The message, when every id is in its one spelling and both versions
    /// decode.
    pub(crate) fn message(&self) -> Option<EntityId> {
        let named = |hex: &str| EntityId::from_hex(hex).ok().filter(|id| id.to_hex() == hex);
        named(&self.document)?;
        named(&self.incarnation)?;
        VersionVector::decode(&self.version).ok()?;
        if !self.shallow.is_empty() {
            VersionVector::decode(&self.shallow).ok()?;
        }
        named(&self.entity)
    }

    /// Whether this holds every operation `other` does, of the same
    /// document.
    pub(crate) fn holds(&self, other: &Self) -> bool {
        let (Ok(mine), Ok(theirs)) = (
            VersionVector::decode(&self.version),
            VersionVector::decode(&other.version),
        ) else {
            return false;
        };
        self.document == other.document
            && self.incarnation == other.incarnation
            && mine.includes_vv(&theirs)
    }

    /// [`Self::holds`], from the same history floor: an owner purge on one
    /// side and not the other leaves them apart.
    pub(crate) fn covers(&self, other: &Self) -> bool {
        let floor = |carried: &Self| {
            (!carried.shallow.is_empty())
                .then(|| VersionVector::decode(&carried.shallow).ok())
                .map_or(Some(None), |floor| floor.map(Some))
        };
        self.holds(other) && matches!((floor(self), floor(other)), (Some(a), Some(b)) if a == b)
    }

    /// Whether this head's history starts at a strictly newer version than
    /// `other`'s: an owner purge `other` has not taken. A floor that does
    /// not decode, or one neither includes, is none.
    pub(crate) fn purges(&self, other: &Self) -> bool {
        let floor = |carried: &Self| {
            if carried.shallow.is_empty() {
                Some(VersionVector::default())
            } else {
                VersionVector::decode(&carried.shallow).ok()
            }
        };
        let (Some(mine), Some(theirs)) = (floor(self), floor(other)) else {
            return false;
        };
        mine.includes_vv(&theirs) && !theirs.includes_vv(&mine)
    }
}

fn content() -> TextField {
    TextField::MapField("content".to_owned())
}

/// The head of the content document `message` holds here, as a window
/// carries it; `None` when it holds none.
fn local_in(
    vault: &Vault,
    txn: &RoTxn<'_>,
    message: &EntityId,
) -> Result<Option<(Head, CarriedDocument)>> {
    let Some(head) = ENTITY_DOC_HEAD.get(&vault.store, txn, &HexId(*message))? else {
        return Ok(None);
    };
    if head.entity != message.to_hex() || head.field != content() {
        return Ok(None);
    }
    let slot = DocumentSlot::from_hex(&head.document)?;
    // A stale state vector is marked by its absence.
    let version = match vault
        .store
        .port_document_row(txn, slot, DocumentRow::StateVector)?
    {
        Some(version) => version,
        None => storage::load(&vault.store, txn, &head)?
            .doc
            .oplog_vv()
            .encode(),
    };
    let shallow = vault
        .store
        .port_document_row(txn, slot, DocumentRow::ShallowSince)?
        .unwrap_or_default();
    let carried = CarriedDocument {
        entity: head.entity.clone(),
        document: head.document.clone(),
        incarnation: head.incarnation.clone(),
        version,
        shallow,
    };
    Ok(Some((head, carried)))
}

impl Vault {
    /// The content document MESSAGE `message` holds here, as a window
    /// carries it, in the caller's snapshot (FIX 853).
    pub(crate) fn carried_message_document_in_txn(
        &self,
        txn: &RoTxn<'_>,
        message: &EntityId,
    ) -> Result<Option<CarriedDocument>> {
        Ok(local_in(self, txn, message)?.map(|(_, carried)| carried))
    }

    /// [`Self::carried_message_document_in_txn`] with a snapshot of the
    /// document, for a window to carry.
    pub(crate) fn export_message_document(
        &self,
        message: &EntityId,
    ) -> Result<Option<(CarriedDocument, Vec<u8>)>> {
        let txn = self.store.env.read_txn()?;
        let Some((head, mut carried)) = local_in(self, &txn, message)? else {
            return Ok(None);
        };
        let doc = storage::load(&self.store, &txn, &head)?;
        carried.version = doc.doc.oplog_vv().encode();
        Ok(Some((carried, doc.export_snapshot()?)))
    }

    /// Installs the document `carried` names, from its snapshot `snapshot`,
    /// in the caller's write transaction (FIX 853). Erase wins: a message
    /// this vault erased refuses it. Where this vault holds no document for
    /// the message, the carried one is installed under the carried head,
    /// so its pins and citation floors resolve here. Where it holds the same
    /// document, the snapshot's operations join it, and a newer history floor
    /// drops its history to that floor ([`purged_at_carried_floor`]). Where it
    /// holds another document or incarnation, that one stands.
    pub(crate) fn merge_carried_message_document_in_txn(
        &self,
        txn: &mut RwTxn<'_>,
        carried: &CarriedDocument,
        snapshot: &[u8],
    ) -> Result<DocumentMerge> {
        let Some(message) = carried.message() else {
            return Ok(DocumentMerge::Refused("not a whole head"));
        };
        if crate::ports::removed_in_txn(&self.store, txn, &message)? {
            return Ok(DocumentMerge::Refused("erased here"));
        }
        let Some(raw) = EntityStoreRead::port_entity_raw(&self.store, txn, &message)? else {
            return Ok(DocumentMerge::Waiting);
        };
        if EntityMetadataHeader::parse(&raw)
            .is_none_or(|header| header.entity_type != crate::registry::ENTITY_TYPE_MESSAGE)
        {
            return Ok(DocumentMerge::Refused("not a MESSAGE"));
        }
        if pointer_of(&raw).as_deref() != Some(carried.document.as_str()) {
            return Ok(DocumentMerge::Refused("the message names another document"));
        }
        let local = local_in(self, txn, &message)?;
        if let Some((_, held)) = &local {
            if held.document != carried.document || held.incarnation != carried.incarnation {
                return Ok(DocumentMerge::Conflict);
            }
            if held.holds(carried) && !carried.purges(held) {
                return Ok(DocumentMerge::Held);
            }
        }
        let Ok(incoming) = EntityDoc::from_snapshot(snapshot) else {
            return Ok(DocumentMerge::Refused("snapshot does not decode"));
        };
        if incoming.birth().entity != carried.entity
            || VersionVector::decode(&carried.version).ok() != Some(incoming.doc.oplog_vv())
        {
            return Ok(DocumentMerge::Refused(
                "snapshot is not the one its head names",
            ));
        }
        let slot = DocumentSlot::from_hex(&carried.document)?;
        match local {
            None => {
                let mut head = Head {
                    entity: carried.entity.clone(),
                    incarnation: carried.incarnation.clone(),
                    document: carried.document.clone(),
                    field: content(),
                    generation: 0,
                    pending: 0,
                };
                storage::persist(self, txn, &message, &mut head, &incoming, None)?;
                if incoming.doc.is_shallow() {
                    self.store.port_document_shallow_since_put(
                        txn,
                        slot,
                        &incoming.doc.shallow_since_vv().encode(),
                    )?;
                }
            }
            Some((mut head, held)) => {
                let doc = storage::load(&self.store, txn, &head)?;
                let before = doc.doc.oplog_vv();
                let joined = doc
                    .doc
                    .import(snapshot)
                    .is_ok_and(|status| status.pending.is_none());
                if !joined {
                    return Ok(DocumentMerge::Refused(
                        "snapshot does not join this vault's document",
                    ));
                }
                let purge = match MESSAGE_DOC_REMOTE_PURGE_POLICY {
                    RemotePurgePolicy::AdvanceIfPinsPermit if carried.purges(&held) => {
                        Some(purged_at_carried_floor(
                            self, txn, &message, &head, &doc, carried, &incoming,
                        )?)
                    }
                    RemotePurgePolicy::AdvanceIfPinsPermit => None,
                };
                let moved = doc.doc.oplog_vv() != before;
                match purge {
                    // A replacement snapshot, its updates gone, and its
                    // floor, as the purge door writes them.
                    Some(Ok(shallow)) => {
                        storage::persist(self, txn, &message, &mut head, &shallow, None)?;
                        self.store.port_document_shallow_since_put(
                            txn,
                            slot,
                            &shallow.doc.shallow_since_vv().encode(),
                        )?;
                    }
                    // A purge that waits still takes the operations the
                    // snapshot brought.
                    Some(Err(waits)) if !moved => return Ok(waits),
                    None if !moved => return Ok(DocumentMerge::Held),
                    _ => storage::persist(self, txn, &message, &mut head, &doc, Some(&before))?,
                }
            }
        }
        // The live mirror carries on what this vault held beyond the head.
        crate::batch::queue_committed_rows(self, txn, std::iter::once(message).collect());
        Ok(DocumentMerge::Written)
    }
}

/// `doc`, which has joined snapshot `incoming` of `carried`, with its history
/// dropped to the floor an owner purge on another machine left `carried` at
/// (FIX 3552). The floor reaches only as far as a purge here could: the
/// purge door's own floor and checks, and a held record keeps its history.
/// The operations this vault holds beyond the snapshot stay. Otherwise what
/// the head does instead: a floor its snapshot does not start at is refused,
/// and one this vault cannot reach exactly waits
/// ([`MESSAGE_DOC_PURGE_CONFLICT_POLICY`]).
fn purged_at_carried_floor(
    vault: &Vault,
    txn: &RoTxn<'_>,
    message: &EntityId,
    head: &Head,
    doc: &EntityDoc,
    carried: &CarriedDocument,
    incoming: &EntityDoc,
) -> Result<std::result::Result<EntityDoc, DocumentMerge>> {
    let floor = incoming.doc.shallow_since_vv().to_vv();
    if !incoming.doc.is_shallow()
        || VersionVector::decode(&carried.shallow).ok() != Some(floor.clone())
    {
        return Ok(Err(DocumentMerge::Refused(
            "snapshot floor is not the one its head names",
        )));
    }
    let waits = |reason| match MESSAGE_DOC_PURGE_CONFLICT_POLICY {
        PurgeConflictPolicy::Defer => Ok(Err(DocumentMerge::Deferred(reason))),
    };
    if crate::store::legal_hold::held_in_txn(&vault.store, txn, message.as_bytes())? {
        return waits("a legal hold keeps its history");
    }
    // The purge door's refusals are a floor this vault cannot reach.
    let refused = |error: Error| match error {
        Error::Artifact(ArtifactError::InvalidEditManifest(reason)) => waits(reason),
        error => Err(error),
    };
    let requested = incoming.doc.shallow_since_frontiers().encode();
    let applied = match super::pins::floor(vault, txn, message, &head.incarnation, doc, &requested)
    {
        Ok(applied) => applied,
        Err(error) => return refused(error),
    };
    if decode_frontier(&applied)? != decode_frontier(&requested)? {
        return waits("a pin here keeps older history");
    }
    let shallow =
        match super::pins::shallow_at(vault, txn, message, &head.incarnation, doc, &applied) {
            Ok(shallow) => shallow,
            Err(error) => return refused(error),
        };
    if shallow.doc.shallow_since_vv().to_vv() != floor {
        return waits("the history here does not cut at its floor");
    }
    Ok(Ok(shallow))
}

/// The document a pointer row names, when it is one.
fn pointer_of(raw: &[u8]) -> Option<String> {
    let mut body = raw.get(ENTITY_METADATA_HEADER_LEN..)?;
    let rmpv::Value::Map(fields) = rmpv::decode::read_value(&mut body).ok()? else {
        return None;
    };
    fields
        .into_iter()
        .find(|(key, _)| key.as_str() == Some("entity_doc_ref"))
        .and_then(|(_, value)| value.as_str().map(str::to_owned))
}
