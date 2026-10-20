//! The owner's view of one signing document on `vault.esign.get` (FIX 6481):
//! its delivery receipts always, beside its trail as it folds or the error
//! that trail reads to. A trail that does not read never hides the receipts
//! of the deliveries that wait on it.
use super::delivery_settlement::EsignDeliveryReceipt;
use super::model::{
    DocumentStatus, EsignDocument, EsignEventRow, EsignState, RecipientState, SignatureRow,
};
use crate::memory::MemoryError;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// A signing document as `vault.esign.get` reads it: its delivery receipts,
/// and its trail as it folds or why it does not read.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EsignDocumentView {
    pub document_ref: String,
    /// The invitations and reminders that ended unsent (FIX 6363), and the
    /// ones still queued that wait unexported on their own (FIX 6455), each
    /// with its `state` and typed `reason`, oldest first. Read whether or not
    /// the document's trail reads, so a `document_unreadable` wait shows here.
    pub delivery_receipts: Vec<EsignDeliveryReceipt>,
    /// `trail`, `readable` or `unreadable`, and what it reads to.
    #[serde(flatten)]
    pub trail: EsignDocumentTrail,
}

/// Whether the document's own trail reads (FIX 6481). Nothing the trail
/// alone proves is shown for one that does not read.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "trail", rename_all = "snake_case")]
pub enum EsignDocumentTrail {
    /// The whole verified chain folds: the document's state and the trail.
    Readable {
        status: DocumentStatus,
        /// An event of the document awaits its owner's answer (a held sign
        /// act); the state shows it folded in, and other acts wait for it.
        awaits_owner_answer: bool,
        /// The draft as it was sent: items, recipients, fields, expiry.
        document: EsignDocument,
        /// Each recipient's delivery, signing and access status, by id.
        recipients: BTreeMap<String, RecipientState>,
        /// The current value of each filled field.
        signatures: Vec<SignatureRow>,
        /// A recipient's decline reason, once one declined.
        rejection: Option<String>,
        /// SHA-256 of each sealed item, hex, once sealed.
        sealed_sha256: Vec<String>,
        /// The hash-chained trail, oldest first: every event, its actor and
        /// time.
        audit: Vec<EsignEventRow>,
    },
    /// The trail does not read or folds to no document: an event that does
    /// not decode or validate, a forked or broken hash chain, a first event
    /// that is no draft, or no event at all. `error` is the error the strict
    /// readers return for it, its code and message kept.
    Unreadable { error: MemoryError },
}

impl EsignDocumentTrail {
    /// The trail of a document whose whole chain folds to `state`, with its
    /// events `audit`, and whether one of them awaits its owner (`held`).
    pub(super) fn readable(state: EsignState, audit: Vec<EsignEventRow>, held: bool) -> Self {
        Self::Readable {
            status: state.status,
            awaits_owner_answer: held,
            document: state.document,
            recipients: state.recipients,
            signatures: state.signatures.into_values().collect(),
            rejection: state.rejection,
            sealed_sha256: state
                .sealed_sha256
                .iter()
                .map(|digest| crate::entity_id::bytes_to_hex_lower(digest.as_slice()))
                .collect(),
            audit,
        }
    }
}
