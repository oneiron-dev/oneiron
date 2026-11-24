//! Pinned workloads (pass 33): the exact things the owner allows to run on
//! the vault's own machines, and the check the start gate makes before a job
//! on one is reserved.
pub mod pin;
pub use pin::*;

mod check;
mod doors;
mod record;
pub(crate) mod tables;
mod wire;

pub use check::{
    TEMPLATE_CHANGED, TEMPLATE_NOT_OFFERED, WorkloadNodeAnswer, WorkloadStartAsk,
    WorkloadStartRefusal, WorkloadStarter,
};
pub use doors::{
    JOB_ADMISSION_ALPN, PIN_ARGS_BYTES_MAX, PIN_ARGS_MAX, PIN_OUTPUTS_MAX, WorkloadAgent,
    WorkloadCaller, WorkloadError, WorkloadVerb,
};
pub(crate) use record::erase_workload_actor_in_txn;
pub use record::{
    JobWorkload, WorkloadApproval, WorkloadApprovedBy, WorkloadRevocation,
};
pub use wire::{
    WorkloadApprovalView, WorkloadApproveRequest, WorkloadChange, WorkloadList,
    WorkloadListRequest, WorkloadPinRequest, WorkloadRef, WorkloadStanding, WorkloadView,
};
