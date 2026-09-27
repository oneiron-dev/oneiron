//! Canonical pair identity and resident-owned submission witnesses.
use crate::edge::EdgeKind;
use crate::error::{Error, Result};
use crate::registry::ENTITY_TYPE_NOTE;
use crate::vault::LiveEntityRow;
use crate::{EntityId, Vault};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct DiaryPair {
    pub(super) left: EntityId,
    pub(super) right: EntityId,
}
impl DiaryPair {
    pub(super) fn new(a: EntityId, b: EntityId) -> Option<Self> {
        if a == b {
            return None;
        }
        let (left, right) = if a < b { (a, b) } else { (b, a) };
        Some(Self { left, right })
    }
    pub(super) fn linked_in(self, vault: &Vault, txn: &heed::RoTxn<'_>) -> Result<bool> {
        let key = crate::store::Store::encode_edge_key(&self.left, EdgeKind::SameAs, &self.right);
        Ok(vault.store.edges_out.get(txn, &key)?.is_some())
    }
}

pub(super) fn author_in(vault: &Vault, txn: &heed::RoTxn<'_>, id: EntityId) -> Result<EntityId> {
    let LiveEntityRow::Live {
        entity_type: ENTITY_TYPE_NOTE,
        body,
    } = crate::vault::live_entity_row_in_txn(&vault.store, txn, &id)?
    else {
        return Err(Error::EntityNotFound);
    };
    if vault.archive_tombstone_in_txn(txn, &id)?.is_some() {
        return Err(Error::EntityNotFound);
    }
    let note = super::super::decode_note_body_in_txn(&vault.store, txn, &body)?;
    if note.kind != super::super::NoteKind::Diary {
        return Err(Error::InvalidClaimBody(
            "coreference endpoint is not a diary NOTE",
        ));
    }
    let key = crate::store::Store::encode_edge_key(&id, EdgeKind::AuthoredBy, &note.author_ref);
    if vault.store.edges_out.get(txn, &key)?.is_none() {
        return Err(Error::InvalidClaimBody("diary author edge is missing"));
    }
    Ok(note.author_ref)
}

/// Invalid/absent candidates are not evidence. Storage failures still propagate.
pub(super) fn candidate_author_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
) -> Result<Option<EntityId>> {
    match author_in(vault, txn, id) {
        Ok(author) => Ok(Some(author)),
        Err(
            Error::EntityNotFound
            | Error::InvalidEntityType(_)
            | Error::InvalidClaimBody(_)
            | Error::Record(_),
        ) => Ok(None),
        Err(error) => Err(error),
    }
}

/// Only the resident's own verified NOTE can construct this command witness.
#[derive(Debug, Clone, Copy)]
pub(super) struct OwnedDiaryEndpoint {
    pub(super) pair: DiaryPair,
    pub(super) foreign: EntityId,
}
impl OwnedDiaryEndpoint {
    pub(super) fn admit(
        vault: &Vault,
        txn: &heed::RoTxn<'_>,
        actor: EntityId,
        a: EntityId,
        b: EntityId,
    ) -> Result<Option<Self>> {
        let Some(pair) = DiaryPair::new(a, b) else {
            return Ok(None);
        };
        let owns_a = candidate_author_in(vault, txn, a)? == Some(actor);
        let owns_b = candidate_author_in(vault, txn, b)? == Some(actor);
        Ok((owns_a != owns_b).then_some(Self {
            pair,
            foreign: if owns_a { b } else { a },
        }))
    }
}
