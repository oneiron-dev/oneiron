use super::*;

impl Memory<'_> {
    /// Deletes an entity under a NAMED reason (S7). `user_delete` is the
    /// tombstone path; the other three run the redaction-audit machinery.
    ///
    /// Authority (fail-closed): deletion is an OWNER verb — the named
    /// reasons are `user_*`/compliance erasures. Only a VERIFIED
    /// `human`-class actor may delete (`Self::verified_actor_class`:
    /// the asserted actor must exist and be a PERSON — asserted class
    /// strings are never trusted); `agent`/`system` actors get a typed
    /// denial (agents withdraw their own claims via
    /// [`Self::claim_retract`]).
    ///
    /// The owner gate is evaluated before deletion TXN1. Sync-enabled deletes
    /// durably stage an authority-required marker + request-keyed recovery
    /// sidecar before the tombstone can commit; TXN3 consumes that sidecar
    /// with `append_gate_decision_in_txn` alongside the purge and distinct
    /// REDACTION_AUDIT execution receipt. Sync-disabled builds append directly
    /// on their first local scrub/purge.
    pub fn safe_delete(
        &self,
        entity_ref: &str,
        reason: SafeDeleteReason,
    ) -> MemoryResult<DeleteReceipt> {
        self.safe_delete_checked(entity_ref, reason, |_| Ok(()))
    }

    pub(in crate::memory) fn safe_delete_checked(
        &self,
        entity_ref: &str,
        reason: SafeDeleteReason,
        check: impl Fn(&heed::RoTxn<'_>) -> MemoryResult<()>,
    ) -> MemoryResult<DeleteReceipt> {
        let gate = self.evaluate_deletion_gate()?;
        let id = self.resolve_ref(entity_ref)?;
        // The re-check the destructive transactions re-run against their OWN
        // views (fix-leg 5 item 1). `MemoryError` is a binding-layer type the
        // engine's `Result` cannot carry, so the refusal is PARKED here and the
        // engine is handed the accurate typed stand-in: a concurrent write
        // invalidated the snapshot the gate decided on. `safe_delete` then swaps
        // the parked error back, so a caller sees the EXACT code and message the
        // pre-transaction gate would have produced (FORBIDDEN for a revoked
        // binding, INVALID_STATE for a broken authority log) rather than a
        // second, weaker vocabulary for the same refusal.
        let refusal: std::cell::RefCell<Option<MemoryError>> = std::cell::RefCell::new(None);
        let reverify = |txn: &heed::RoTxn<'_>| -> Result<(), Error> {
            verify_deletion_authority_in_txn(self.vault, txn, self.actor, self.actor_class)
                .and_then(|()| check(txn))
                .map_err(|err| {
                    *refusal.borrow_mut() = Some(err);
                    Error::ConcurrentWrite(
                        "deletion authority changed before the destructive commit",
                    )
                })
        };
        let outcome = self
            .vault
            .delete_entity_with_reason_gated(
                &id,
                reason.delete_reason(),
                crate::deletion::GatedDeletion::new(gate, &reverify),
            )
            .map_err(|err| refusal.take().unwrap_or_else(|| MemoryError::from(err)))?;
        Ok(DeleteReceipt {
            existed: outcome.existed,
            reason: reason.as_str().to_owned(),
            receipt_ref: outcome
                .receipt_id
                .map(|receipt| format!("redaction:{}", receipt.to_hex())),
        })
    }
    // ── internals ───────────────────────────────────────────────────────
}
