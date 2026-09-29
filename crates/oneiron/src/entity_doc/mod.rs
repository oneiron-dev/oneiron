//! Durable, bounded entity text documents, anchored edits, fork sets and owner purge.
//!
//! The ledger row keeps its immutable core and a document pointer. Text writes
//! commit CRDT operations; only indexed projections may materialize the text.
//! Documents are loaded lazily, snapshot before ordered pending updates.

mod document;
mod forks;
mod message_stream;
mod pins;
mod recovery;
mod registry;
mod side_keys;
mod storage;
pub(crate) use message_stream::{
    append_message_stream_in_txn, authorize_message_continuation_in_txn,
    birth_message_stream_in_txn,
};
pub(crate) use recovery::{capture as capture_canonical, restore as restore_canonical};
mod verbs;

pub use document::{Birth, EntityDoc, TextChange};
pub use forks::{
    DocAuthorization, ForkRecord, ForkRequest, ForkStatus, ProposalBundle, SettleVerb, TextReceipt,
};
pub use pins::{CitationPin, CursorResolution, PurgeReceipt};
pub(crate) use registry::EntityDocRegistry;
pub use registry::RegistryStatus;
pub use storage::TextField;
pub(crate) use storage::{
    erase_in_txn, guard_record_put, has_record_head, record_head_bytes, resolve_record_body,
};
pub use verbs::{AnchoredEdit, EditVerb, TextAnchor, TextUpdateOutcome, TextUpdateRequest};

/// Resolve an active document's identity and live frontier in a caller-owned
/// transaction. An unmigrated row has no document plane.
pub(crate) fn source_frontier_in_txn(
    store: &crate::store::Store,
    txn: &heed::RoTxn<'_>,
    entity: &crate::EntityId,
) -> crate::Result<Option<Vec<u8>>> {
    if !storage::has_record_head(store, txn, entity)? {
        return Ok(None);
    }
    let head = storage::head(store, txn, entity)?;
    let doc = storage::load(store, txn, &head)?;
    let mut pin = head.incarnation.into_bytes();
    pin.extend_from_slice(&doc.frontier());
    Ok(Some(pin))
}

use crate::error::{ArtifactError, Error};

fn invalid(reason: &'static str) -> Error {
    Error::Artifact(ArtifactError::InvalidEditManifest(reason))
}

#[cfg(test)]
mod tests;
