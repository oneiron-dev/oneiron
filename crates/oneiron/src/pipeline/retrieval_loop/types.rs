//! Read-only retrieval verbs and their model-facing observations.

use crate::claim::ScopedReadReceipt;
use crate::entity_id::EntityId;
use crate::retrieval_quality::RetrievalQualityReport;
use crate::store::RetrievalState;
use crate::temporal::TimeRange;
use crate::vault::RevisionRef;
use serde::{Deserialize, Serialize};

#[doc(hidden)]
use oneiron_records::pipeline::retrieval_loop::types::serialize_time_range;
#[doc(hidden)]
pub use oneiron_records::pipeline::retrieval_loop::types::{
    RetrievalEvidence, RetrievalHandle, RetrievalLoopAction, RetrievalLoopObservation,
    RetrievalLoopStatus,
};
