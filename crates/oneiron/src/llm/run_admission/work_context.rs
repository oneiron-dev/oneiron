//! Host scheduling and physical-custody context for one run-admission handle.
//! Definitions live in oneiron-model so BudgetLease can carry the context.
pub use oneiron_model::llm::{
    WorkCancel, WorkContext, WorkId, WorkPhysical, forget_work_parent, lookup_work_parent,
    record_work_parent, take_work_parent,
};
