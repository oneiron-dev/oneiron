//! The checker doors' wire types (FIX 6868). A request names no argv, plan
//! body, output, actor, green, pass or receipt; the answer names no host
//! path, plan command body or command exhaust.

#[doc(hidden)]
pub use oneiron_verb_wire::memory::merge_queue_doors::checker_types::{
    MergeQueueCheckRequest, MergeQueueCheckStatusRequest, MergeQueueDiagnoseRequest,
    MergeQueueInitializeRequest, QueueCheckPhase,
};

#[doc(hidden)]
pub use oneiron_records::memory::merge_queue_doors::checker_types::{
    MergeQueueCheckState, MergeQueueCheckWorkKind, MergeQueueCheckWorkView,
};
