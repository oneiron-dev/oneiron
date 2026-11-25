//! Pinned workloads that one of the vault's machines runs for another (pass
//! 33, `33-exec-node/DESIGN.md`): the pin ([`pin`]) the owner approves and
//! the job submit carries, and the two protocol ids it crosses
//! ([`protocol`]). The pin's resource request is general (pass 34,
//! `34-compute-general/DESIGN.md` sections 2.1 and 2.2): its device claims
//! and the placement rule ([`device`]), and what a launch scope can enforce
//! ([`scope_bounds`]). Then the `JOB_WORKLOAD` table the owner's approvals
//! live in, its doors, and the check the start gate makes before a job on a
//! pinned workload is reserved.

pub mod device;
pub mod pin;
pub mod protocol;
pub mod scope_bounds;

pub use device::*;
pub use pin::*;
pub use protocol::*;
pub use scope_bounds::*;

mod check;
mod doors;
mod pin_shape;
mod record;
pub(crate) mod tables;
mod wire;

pub use check::{
    TEMPLATE_CHANGED, TEMPLATE_NOT_OFFERED, WorkloadNodeAnswer, WorkloadStartAsk,
    WorkloadStartRefusal, WorkloadStarter,
};
pub use doors::{WorkloadAgent, WorkloadCaller, WorkloadError, WorkloadVerb};
pub(crate) use record::erase_workload_actor_in_txn;
pub use record::{JobWorkload, WorkloadApproval, WorkloadApprovedBy, WorkloadRevocation};
pub use wire::{
    WorkloadApprovalView, WorkloadApproveRequest, WorkloadChange, WorkloadList,
    WorkloadListRequest, WorkloadPinRequest, WorkloadRef, WorkloadStanding, WorkloadView,
};
