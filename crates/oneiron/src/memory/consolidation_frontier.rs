//! Typed reference frontiers and the root's immutable evidence-accounting receipts.

#[doc(hidden)]
pub use oneiron_verb_wire::memory::consolidation_frontier::{
    ConsolidationAccountingRequest, ConsolidationAncestor, ConsolidationBucketAccounting,
    ConsolidationChildFrontier, ConsolidationChildReceipt, ConsolidationFrontierRequest,
    ConsolidationJudgement, ConsolidationPinRequest, ConsolidationReference,
    ConsolidationRootAccounting, ConsolidationRootBucket, ConsolidationRootEvidence,
    ConsolidationRootInput,
};

impl super::Memory<'_> {
    fn consolidation_root_owner_in_txn(
        &self,
        owner: &crate::consent::AuthenticatedOwner,
        txn: &heed::RoTxn<'_>,
    ) -> super::MemoryResult<crate::EntityId> {
        let actor = owner.revalidate_in_txn(self.vault, txn)?;
        if actor != self.actor || self.actor_class != crate::EdgeActorClass::Human {
            return Err(super::MemoryError::new(
                super::MEMORY_CODE_FORBIDDEN,
                "consolidation root acts through the owner's own credential",
                &["Present the owner's own verified, unattenuated credential."],
            ));
        }
        Ok(actor)
    }

    /// Pins every bucket and reference, however many (Rule 5, FIX 8698), in
    /// this operation's fair task-work turn, at one frozen revision.
    pub fn consolidation_pin_as_owner(
        &self,
        owner: &crate::consent::AuthenticatedOwner,
        input: &ConsolidationPinRequest,
    ) -> super::MemoryResult<ConsolidationRootAccounting> {
        if !self.has_task_work_turn() {
            return self
                .task_work_memory()
                .consolidation_pin_as_owner(owner, input);
        }
        let read = self.read_lane(crate::claim::ClaimReadStatus::Recorded)?;
        let accounting = crate::dreamer_consolidation::root_evidence::pin_frozen(
            self.vault,
            &read,
            input,
            |txn| self.consolidation_root_owner_in_txn(owner, txn),
        )?;
        self.produced_from(crate::dreamer_consolidation::root_evidence::source_ids(
            &accounting,
        )?);
        Ok(accounting)
    }

    /// Lands every child and citation, however many (Rule 5, FIX 8698), in
    /// this operation's fair task-work turn, against the root's own pins.
    pub fn consolidation_frontier_as_owner(
        &self,
        owner: &crate::consent::AuthenticatedOwner,
        input: &ConsolidationFrontierRequest,
    ) -> super::MemoryResult<ConsolidationRootAccounting> {
        if !self.has_task_work_turn() {
            return self
                .task_work_memory()
                .consolidation_frontier_as_owner(owner, input);
        }
        let read = self.read_lane(crate::claim::ClaimReadStatus::Recorded)?;
        let accounting = crate::dreamer_consolidation::root_evidence::frontier_frozen(
            self.vault,
            &read,
            input,
            |txn| self.consolidation_root_owner_in_txn(owner, txn),
        )?;
        self.produced_from(crate::dreamer_consolidation::root_evidence::source_ids(
            &accounting,
        )?);
        Ok(accounting)
    }

    pub fn consolidation_accounting_as_owner(
        &self,
        owner: &crate::consent::AuthenticatedOwner,
        input: &ConsolidationAccountingRequest,
    ) -> super::MemoryResult<ConsolidationRootAccounting> {
        let read = self.read_lane(crate::claim::ClaimReadStatus::Recorded)?;
        let txn = self
            .vault
            .store
            .env
            .read_txn()
            .map_err(crate::Error::from)?;
        let actor = self.consolidation_root_owner_in_txn(owner, &txn)?;
        let accounting = crate::dreamer_consolidation::root_evidence::accounting_in_txn(
            self.vault,
            &read,
            &txn,
            actor,
            &input.root_ref,
        )?;
        self.produced_from(crate::dreamer_consolidation::root_evidence::source_ids(
            &accounting,
        )?);
        Ok(accounting)
    }
}
