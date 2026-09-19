//! Durable, bounded entity text documents, anchored edits, fork sets and owner purge.
//!
//! The ledger row keeps its immutable core and a document pointer. Text writes
//! commit CRDT operations; only indexed projections may materialize the text.
//! Documents are loaded lazily, snapshot before ordered pending updates.

mod document;
mod forks;
mod message_stream;
mod pins;
mod registry;
mod storage;
pub(crate) use message_stream::{
    append_message_stream_in_txn, authorize_message_continuation_in_txn,
    birth_message_stream_in_txn,
};
mod verbs;

pub use document::{Birth, EntityDoc, TextChange};
pub use forks::{
    DocAuthorization, ForkRecord, ForkRequest, ForkStatus, ProposalBundle, SettleVerb, TextReceipt,
};
pub use pins::{CitationPin, CursorResolution, PurgeReceipt};
pub(crate) use registry::EntityDocRegistry;
pub use registry::RegistryStatus;
pub use storage::TextField;
pub(crate) use storage::{erase_in_txn, guard_record_put, resolve_record_body};
pub use verbs::{AnchoredEdit, EditVerb, TextAnchor, TextUpdateOutcome, TextUpdateRequest};

use crate::error::{ArtifactError, Error};

fn invalid(reason: &'static str) -> Error {
    Error::Artifact(ArtifactError::InvalidEditManifest(reason))
}

#[cfg(test)]
mod tests;
