//! The run admission (ARCH-0053 `#run-admission`): one door every paid call
//! of a run passes, to a model through `ai.*` or to a paid connector.
//!
//! A run states a [`RunDeclaration`]: the teachers it pinned at its start,
//! with their aliases frozen, the paid connectors it may call and its budget
//! line in a named unit. The [`RunAdmission`] checks each call against that
//! declaration and the host's inputs (the offer binding, the vault's
//! allocation and the account's status) and issues a one-use [`RunPermit`]
//! bound to the run, the model, the route and the locality. The
//! [`GatedBackend`] a host hands the run checks and starts the permit where
//! bytes leave. A paid job with a declared maximum stops there only under the
//! owner's conditions ([`JobMaximum`]). Nothing here is a global list: a run
//! that declares nothing is admitted to any bound offer, and only the run's
//! own rules are enforced.
mod admission;
mod declaration;
mod gate;
mod host;
mod job_maximum;
mod permit;
mod receipt;
mod settle;

pub use admission::{RunAdmission, RunCall, RunCallError, RunDenied};
pub use declaration::{
    BudgetLine, DeclarationEditor, DeclarationError, DeclaredTeachers, LeaseUnit, RunDeclaration,
};
pub use gate::GatedBackend;
pub use host::{
    AccountStatus, Allocation, AllocationGrantError, AllocationRef, AllocationRefusal, HostAccount,
    KeyCustody, OfferBinding, OfferRoute, OfferRouteError, PaidConnector, Payer, UnitRate,
};
pub use job_maximum::{
    AddFundsNotice, CheckpointRef, DeclaredMaximum, JobMaximum, JobSignal, JobStartRefused,
    MaximumShown, MaximumStop, ResumeOffer, ResumeRefused, StopRefused,
};
pub use permit::RunPermit;
pub use receipt::{
    CalledTeacher, MemoryReceipts, PermitFacts, RunEvent, RunReceipt, RunReceiptSink, TeacherReport,
};
pub use settle::CallOutcome;

#[cfg(test)]
mod tests;
