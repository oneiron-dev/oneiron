//! Core half of `blob_artifact::esign::model`: its store-layer items live in `oneiron_store::blob_artifact::esign::model` and are
//! re-exported here; the items below stay in the engine.

pub use oneiron_store::blob_artifact::esign::model::*;

use crate::Result;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[doc(hidden)]
pub use oneiron_verb_wire::blob_artifact::esign::model::{EsignCommitmentTerm, EsignDocument};

#[doc(hidden)]
pub(super) use oneiron_records::blob_artifact::esign::model::validate_document;
#[doc(hidden)]
pub use oneiron_records::blob_artifact::esign::model::{EsignEvent, EsignEventRow};

#[derive(Debug, Clone, PartialEq)]
pub struct EsignState {
    pub document: EsignDocument,
    pub status: DocumentStatus,
    pub recipients: BTreeMap<String, RecipientState>,
    /// One current signature/value per field, never a duplicate signature row.
    pub signatures: BTreeMap<String, SignatureRow>,
    pub rejection: Option<String>,
    pub sealed_sha256: Vec<[u8; 32]>,
    pub reseal_pending: bool,
    pub reminders: BTreeSet<(String, u32)>,
    pub(super) sent_at: Option<u64>,
    pub(super) reminder_at: BTreeMap<String, u64>,
}
