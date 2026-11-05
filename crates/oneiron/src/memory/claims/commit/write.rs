//! The guarded claim commit: dedupe, supersede, Gate and publication in one write transaction.
//! `Memory::commit_one_guarded_with_birth` is its call surface.
//! `memory::claims::commit` defines `MemoryKey`; `memory::claims` defines the claim inputs.

use super::*;

mod attempt;
mod landing;
mod receipt;
mod resolve;

use self::resolve::refuse_typed_claim_family;

impl Memory<'_> {
    /// Recovers a hook proposal without re-putting an already landed exact
    /// intent over an intervening owner decision. Other cases still propose
    /// through the ordinary guarded writer.
    pub(crate) fn claim_propose_for_hook_replay(
        &self,
        input: &ClaimInput,
    ) -> MemoryResult<CommitReceipt> {
        self.commit_claim_write(
            input,
            false,
            Some(ClaimApprovalStatus::Proposed),
            || {},
            &|_: &heed::RoTxn<'_>| Ok(()),
            None,
            true,
        )
    }

    pub(in crate::memory) fn commit_one_guarded_with_birth(
        &self,
        input: &ClaimInput,
        auto_supersede: bool,
        forced_approval: Option<ClaimApprovalStatus>,
        before_txn: impl FnOnce(),
        in_writer: &dyn Fn(&heed::RoTxn<'_>) -> Result<(), Error>,
        birth: Option<&crate::provenance::birth::RowBirth>,
    ) -> MemoryResult<CommitReceipt> {
        self.commit_claim_write(
            input,
            auto_supersede,
            forced_approval,
            before_txn,
            in_writer,
            birth,
            false,
        )
    }

    fn commit_claim_write(
        &self,
        input: &ClaimInput,
        auto_supersede: bool,
        forced_approval: Option<ClaimApprovalStatus>,
        before_txn: impl FnOnce(),
        in_writer: &dyn Fn(&heed::RoTxn<'_>) -> Result<(), Error>,
        birth: Option<&crate::provenance::birth::RowBirth>,
        skip_exact_hook_replay: bool,
    ) -> MemoryResult<CommitReceipt> {
        refuse_typed_claim_family(input)?;
        let write = self.resolve_claim_write(input, auto_supersede, in_writer, birth)?;
        before_txn();

        let mut approval = forced_approval
            .unwrap_or_else(|| requested_approval(write.source, input.scope.as_ref()));
        // Only a Gate verdict that PENDS an Auto request is resubmitted as
        // Proposed: that write would park for review, so it lands parked. A
        // Gate deny (an unresolved record reference among them, FIX 1220) is
        // never resubmitted; no approval lane makes it land.
        let refused = match self.attempt_claim_write(&write, approval, skip_exact_hook_replay) {
            Ok(refused) => refused,
            Err(err) if approval == ClaimApprovalStatus::Auto && gate_rejection_pends(&err) => {
                approval = ClaimApprovalStatus::Proposed;
                self.attempt_claim_write(&write, approval, skip_exact_hook_replay)
                    .map_err(|err| {
                        write
                            .publication_refusal
                            .take()
                            .unwrap_or_else(|| err.into())
                    })?
            }
            Err(err) => {
                return Err(write
                    .publication_refusal
                    .take()
                    .unwrap_or_else(|| err.into()));
            }
        };
        if let Some(refused_id) = refused {
            return Err(hard_deleted_refusal(&refused_id));
        }
        self.commit_receipt(write.id, write.prior, approval)
    }
}

/// Whether `err` is a Gate write rejection whose outcome is Pending, the one
/// rejection an Auto request may be resubmitted as Proposed after. A Deny,
/// and any error that is not a Gate rejection, is not.
fn gate_rejection_pends(err: &Error) -> bool {
    matches!(
        err,
        Error::Gate(crate::error::GateError::GateWriteRejected { outcome, .. })
            if crate::error::GateDenialOutcome::parse(outcome)
                == Some(crate::error::GateDenialOutcome::Pending)
    )
}
