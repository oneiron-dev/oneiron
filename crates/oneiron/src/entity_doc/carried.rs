//! A MESSAGE's document between the owner's machines (FIX 853).
//!
//! A window carries a MESSAGE's document beside the message: its head and a
//! snapshot of its history (`sync::message_docs`). Another of the owner's
//! machines installs it under the same head, so the text, a quote's pinned
//! version and its citation floors resolve there as on the machine that
//! wrote it.

use super::storage::{self, ENTITY_DOC_HEAD, Head};
use super::{EntityDoc, TextField};
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::error::Result;
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
    /// document, the snapshot's operations join it. Where it holds another
    /// document or incarnation, that one stands.
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
            if held.holds(carried) {
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
            Some((mut head, _)) => {
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
                if doc.doc.oplog_vv() == before {
                    return Ok(DocumentMerge::Held);
                }
                storage::persist(self, txn, &message, &mut head, &doc, Some(&before))?;
            }
        }
        // The live mirror carries on what this vault held beyond the head.
        crate::batch::queue_committed_rows(self, txn, std::iter::once(message).collect());
        Ok(DocumentMerge::Written)
    }
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
