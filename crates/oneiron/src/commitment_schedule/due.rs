//! Due-index consumer types and the vault's read/consume/acknowledge surface.

pub(crate) use crate::store::commitment_due_record::OWNER_MANAGED_PHASE;
pub use crate::store::commitment_due_record::{
    CommitmentDueEntry, CommitmentDueIndexSnapshot, CommitmentDuePhase,
};
