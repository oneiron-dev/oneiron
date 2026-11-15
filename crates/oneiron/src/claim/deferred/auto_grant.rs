//! The deferred Auto grant on a caller's transaction.
//!
//! [`Vault::grant_deferred_claim_auto_after_in_txn`] is
//! `grant_deferred_claim_auto_after`'s write body on the transaction the
//! caller opened: the parked-row, stale-binding
//! and critical/attributed refusals, the Auto grant, the closure, the
//! commitment index and the own-rate count. The outer keeps the own-rate read,
//! the checker's turn, the grouped write with its `precheck`/`then` closures
//! and the post-commit metrics. No closure parameter here.
use super::{DeferredAction, attributed, body_hash, load};
use crate::gate::GateReasonCode;
use crate::{EntityId, Error, Result, Vault};

impl Vault {
    /// Grants the parked supersession on `id` Auto and closes its prior in
    /// the caller's write `txn`, as `grant_deferred_claim_auto_after` does in
    /// its own write. `checker` is already admitted (or `None`); the caller
    /// waited for its turn before any write opened. `auto_write_rate` is read
    /// on the calling thread. Answers the two gate receipts for the caller to
    /// count as metrics only after its write commits; never counts inside.
    ///
    /// # Errors
    ///
    /// A missing parked row, a stale binding, the critical/attributed floor,
    /// the grant or closure gate's refusal, and the store's.
    pub(crate) fn grant_deferred_claim_auto_after_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        id: &EntityId,
        now: u64,
        checker: Option<&crate::llm::BoundedAutoChecker>,
        auto_write_rate: crate::store::own_rate_record::OwnRate,
    ) -> Result<(
        Option<crate::gate::RecordedClaimGateDecision>,
        Option<crate::gate::RecordedClaimGateDecision>,
    )> {
        let proposal = load(self, txn, id)?.ok_or(Error::EntityNotFound)?;
        let DeferredAction::Supersede { old, old_hash } = proposal.action else {
            return Err(Error::InvalidClaimBody("not a deferred supersession"));
        };
        let old = EntityId::from_bytes(old)?;
        let prior = self.require_named_claim_target_active_in(txn, &old)?;
        let body = self
            .get_claim_in_txn(txn, id)?
            .ok_or(Error::EntityNotFound)?;
        let policy = crate::gate::resolve_policy_manifest(&self.store, txn)?;
        let parked = self.store.pending_gate_consent_in_txn(txn, id)?;
        // The Dreamer actor that parked this replacement, from the parking
        // decision it wrote; `None` for anything a Dreamer run did not park.
        let dreamer_writer = match parked.as_ref() {
            Some(pending) if pending.dreamer_run_id.is_some() => self
                .store
                .gate_decision_in_txn(txn, pending.decision_id)?
                .and_then(|record| record.actor_ref)
                .and_then(|actor| EntityId::from_hex(&actor).ok()),
            _ => None,
        };
        if proposal.body_hash != body_hash(&body)?
            || proposal.frontier != policy.read_frontier_hash()?
            || old_hash != body_hash(&prior)?
            || parked.is_none()
        {
            return Err(Error::Gate(crate::error::GateError::GateConsentStale {
                claim_id: *id,
            }));
        }
        if proposal.critical || attributed(&prior) || attributed(&body) {
            return Err(Error::Gate(crate::error::GateError::GateWriteRejected {
                outcome: "pending",
                reason_codes: vec![GateReasonCode::PendingCriticalityFloor.as_str()],
            }));
        }
        let decision =
            crate::batch::ClaimMaterialization::apply_deferred_auto_grant(self, txn, id, checker)?;
        // An auto grant names no caller principal, so its close names no one.
        let closure_decision =
            self.complete_deferred_claim_with_checker_in_txn(txn, id, None, now, checker, None)?;
        // FIX 5993: a granted commitment series projects from its grant.
        self.index_consented_commitment_series_in_txn(txn, &body, id, now)?;
        // A Dreamer replacement granted Auto is an Auto write like any the
        // Dreamer lands, through whichever door granted it, so it counts on
        // that actor's own-rate window. The count never holds the grant.
        if let Some(actor) = dreamer_writer {
            crate::own_rate::count_in_txn(
                &self.store,
                txn,
                crate::store::own_rate_record::OwnRateKind::AutoWrite,
                actor,
                self.store.clock.now_recorded_at(),
                auto_write_rate,
            )?;
            #[cfg(test)]
            crate::own_rate::counted_auto_write(crate::own_rate::AutoWriteDoor::DeferredGrant);
        }
        Ok((decision, closure_decision))
    }
}
