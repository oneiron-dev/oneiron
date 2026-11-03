//! Checkout lease record and repository operations requiring an attempt binding.

use super::attempt_binding::CheckoutAttemptBinding;
use crate::entity_id::EntityId;
use crate::store::code_snapshot::RepoRef;

pub use crate::store::checkout_lease::{
    CHECKOUT_LEASE_KEY_PREFIX, CHECKOUT_LEASE_SCHEMA_VERSION, CHECKOUT_RESULT_ID_DOMAIN,
    CHECKOUT_SETTLEMENT_KEY_PREFIX, CHECKOUT_TOMBSTONE_KEY_PREFIX, CheckoutClaimRequest,
    CheckoutError, CheckoutFactMutation, CheckoutFactSink, CheckoutHolder, CheckoutId,
    CheckoutLeaseFence, CheckoutLeaseGrant, CheckoutLeaseState, CheckoutLiveness,
    CheckoutLivenessPulse, CheckoutMaterializationOptions, CheckoutResult, CheckoutRetainReason,
    CheckoutSettlementDisposition, CheckoutSettlementReceipt, CheckoutSettlementRequest,
    CheckoutTaskClass, CheckoutTeardownInspection, CheckoutTeardownOutcome, GitOid,
    PushedHeadReceipt, TeardownReceiptMatch,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckoutLeaseAct {
    pub checkout_id: CheckoutId,
    pub task_ref: EntityId,
    pub repo_ref: RepoRef,
    pub holder_ref: String,
    pub epoch: u64,
    pub task_class: CheckoutTaskClass,
    pub state: CheckoutLeaseState,
    pub claimed_at: u64,
    pub lease_expires_at: Option<u64>,
    pub updated_at: u64,
    /// The attempt that holds this epoch (FIX 6867, G1 PR3b), when a BYOA
    /// dispatch reserved it; `None` for every other lease, owner's included.
    pub bound_attempt: Option<CheckoutAttemptBinding>,
}
pub trait CheckoutRepoOps {
    fn materialize(&self, lease: &CheckoutLeaseAct) -> CheckoutResult<()>;
    /// Observes the checkout without mutating it.
    ///
    /// Teardown calls this before any lease-state transition and calls it again
    /// on every retry, a resumed collection's included while its tree is
    /// present, so it must be side-effect free and safe to repeat.
    fn inspect_teardown(
        &self,
        lease: &CheckoutLeaseAct,
        receipt: &PushedHeadReceipt,
    ) -> CheckoutResult<CheckoutTeardownInspection>;
    /// Collects (removes) the checkout's working tree.
    ///
    /// **Must be idempotent and re-entrant.** Teardown commits `Settling` before
    /// calling `collect` and resumes from `Settling` on a later retry under the
    /// same fence, so `collect` can be invoked more than once for one
    /// `(checkout_id, epoch)`; a repeat call on an already collected tree must
    /// return `Ok(())` instead of failing.
    fn collect(&self, lease: &CheckoutLeaseAct) -> CheckoutResult<()>;
    /// Whether the checkout's working tree is still present, so a resumed
    /// collection checks it again before removing it (FIX 8654). The default
    /// answers yes: every resume is checked.
    fn tree_present(&self, lease: &CheckoutLeaseAct) -> CheckoutResult<bool> {
        let _ = lease;
        Ok(true)
    }
}
