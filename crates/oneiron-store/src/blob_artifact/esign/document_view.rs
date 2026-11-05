//! The owner's view of one signing document on `vault.esign.get` (FIX 6481)
//! and of its seal on `vault.esign.seal.get` (FIX 6554): its delivery
//! receipts always, beside its trail as it folds or the error that trail
//! reads to. A trail that does not read never hides the receipts of the
//! deliveries that wait on it, nor the seal's own receipts.
use crate::blob_artifact::esign::model::DocumentStatus;
use crate::blob_artifact::esign::model::RecipientState;
use crate::blob_artifact::esign::model::SignatureRow;
use oneiron_contracts::memory::MemoryError;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Whether the document's own trail reads, as `vault.esign.seal.get` shows
/// it (FIX 6554): the seal view reads only the folded status off the trail.
/// The same `trail` tag as [`EsignDocumentTrail`]; nothing the trail alone
/// proves is shown for one that does not read.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "trail", rename_all = "snake_case")]
pub enum EsignSealTrail {
    /// The whole verified chain folds: the document's status.
    Readable { status: DocumentStatus },
    /// The trail does not read or folds to no document, as for
    /// [`EsignDocumentTrail::Unreadable`].
    Unreadable {
        /// The error the strict readers return for it, its code and message
        /// kept: a `MemoryError` object.
        #[schemars(with = "serde_json::Map<String, serde_json::Value>")]
        error: MemoryError,
    },
}
