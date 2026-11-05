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
