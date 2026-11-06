//! Stored reader-fold receipts and their occurrence vocabulary.

use crate::side_table::codec::CodecError;
use crate::side_table::codec::RawValue;
use oneiron_base::error::Error;
use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;
use serde::{Deserialize, Serialize};

/// A child that settled short, and why.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReceiptPartial {
    pub task: EntityId,
    pub reason: String,
}

/// A summary made: its task, and its text's occurrence in the job's run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SummaryMemo {
    pub task: EntityId,
    pub owner: EntityId,
    pub path: String,
    pub handle: String,
}

/// The summary memo's row is its JSON form.
impl RawValue for SummaryMemo {
    fn to_raw(&self) -> std::result::Result<Vec<u8>, CodecError> {
        serde_json::to_vec(self).map_err(|_| Error::CorruptedIndex("code-run summary memo").into())
    }

    fn from_raw(bytes: &[u8]) -> std::result::Result<Self, CodecError> {
        serde_json::from_slice(bytes)
            .map_err(|_| Error::CorruptedIndex("code-run summary memo").into())
    }
}
