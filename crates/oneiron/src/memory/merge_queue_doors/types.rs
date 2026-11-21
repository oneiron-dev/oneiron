//! Merge queue request, batch, pointer and observation records.
//! `MergeQueueRepoRequest` is the first of its records.
//! These are local definitions; `memory::merge_queue_doors` re-exports them.

#[doc(hidden)]
pub use oneiron_verb_wire::memory::merge_queue_doors::types::{
    MergeQueueBatchRequest, MergeQueueEnqueueRequest, MergeQueueObserveRequest,
    MergeQueueRepoRequest,
};

#[doc(hidden)]
pub use oneiron_records::memory::merge_queue_doors::types::{
    MergeQueueBatchView, MergeQueueObservation, MergeQueuePathView, MergeQueuePointersView,
    MergeQueueRequeueView,
};
