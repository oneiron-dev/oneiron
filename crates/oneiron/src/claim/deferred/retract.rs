//! An author's retract of its own claim, parked for the holder's consent
//! (ARCH-0040 `mcp:5`: "destructive supersede/retract defers closure until
//! approval"). When the gate holds the retract, it parks as
//! [`DeferredAction::Retract`] behind a pending decision and its tray row,
//! and the claim stays as it was. The holder approves or declines it with
//! `vault.claims.review` and `vault.claims.settle`.

use super::{DEFERRED, DeferredAction, DeferredClaim, Parker, body_hash, park};
use crate::error::GateError;
use crate::gate::PolicyCriticality;
use crate::store::GateDecisionId;
use crate::{EntityId, Error, Result, Vault, WriteActor};

/// What an author's retract of its own claim did.
pub(crate) enum OwnClaimRetract {
    /// It landed, with the decision of the receipt
    /// [`Vault::retract_claim_in_txn_as`] returns.
    Landed(Option<GateDecisionId>),
    /// It waits for the holder's consent under this pending decision.
    Parked(GateDecisionId),
}

impl Vault {
    /// Whether a retract of `id` waits for the holder: its parked action and
    /// the tray row that shows it.
    pub(crate) fn claim_retract_is_parked_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        id: &EntityId,
    ) -> Result<bool> {
        Ok(self.store.pending_gate_consent_in_txn(txn, id)?.is_some()
            && parked_retract(self, txn, id)?)
    }

    /// Whether the retract parked on `id` keeps the owner's critical
    /// confirm, as a parked critical demotion does.
    pub(crate) fn parked_retract_is_critical_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        id: &EntityId,
    ) -> Result<bool> {
        Ok(DEFERRED
            .get(&self.store, txn, id)?
            .is_some_and(|row| matches!(row.action, DeferredAction::Retract) && row.critical))
    }

    /// `author`'s retract of its own claim `id`, which `author` is checked to
    /// have written. A retract the gate allows lands as
    /// [`Vault::retract_claim_in_txn_as`] lands it. A retract the gate holds
    /// for consent parks for the holder: nothing closes, and the claim keeps
    /// its body until the holder settles it. A class a manifest rule declares
    /// critical parks for the owner's critical confirm, as a parked demotion
    /// does. A repeat retract while one is parked answers the same pending
    /// decision.
    pub(crate) fn retract_own_claim_or_park_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        id: &EntityId,
        now: u64,
        author: WriteActor,
    ) -> Result<OwnClaimRetract> {
        // The tray row a parked retract shows is the holder's to answer; the
        // plain retract below would close it as the retract's own consent.
        if let Some(pending) = self.store.pending_gate_consent_in_txn(&*wtxn, id)?
            && parked_retract(self, &*wtxn, id)?
        {
            return Ok(OwnClaimRetract::Parked(pending.decision_id));
        }
        // The gate's answer alone, from a savepoint that is always rolled
        // back, so the decision it records is gone with it. A retract the
        // gate allows then lands on `wtxn` itself.
        let probe = {
            let mut savepoint = self.store.env.nested_write_txn(wtxn)?;
            let probe = self.retract_claim_in_txn_with(
                &mut savepoint,
                id,
                now,
                Some(author),
                crate::claim::lifecycle::RetractRun::GateAnswerOnly,
            );
            savepoint.abort();
            probe
        };
        match probe {
            Ok(_) => {
                let receipt = self.retract_claim_in_txn_as(wtxn, id, now, Some(author))?;
                return Ok(OwnClaimRetract::Landed(
                    receipt.map(|record| record.decision_id),
                ));
            }
            Err(Error::Gate(GateError::GateWriteRejected {
                outcome: "pending", ..
            })) => {}
            Err(error) => return Err(error),
        }
        let body = self
            .claim_for_restriction_in_txn(&*wtxn, id)?
            .ok_or(Error::EntityNotFound)?;
        let policy = crate::gate::resolve_policy_manifest(&self.store, &*wtxn)?;
        let proposal = DeferredClaim {
            action: DeferredAction::Retract,
            body_hash: body_hash(&body)?,
            frontier: policy.read_frontier_hash()?,
            // The demotion door's own test (`apply_claim_demotion`).
            critical: policy.criticality_for_predicate(&body.predicate)
                == PolicyCriticality::Critical,
        };
        let parker = Parker {
            actor_class: author.actor_class().gate_actor_class().to_owned(),
            actor_ref: Some(author.entity_ref().to_hex()),
            run: None,
            created_at: now,
        };
        park(self, wtxn, id, &body, proposal, parker, now)?;
        let pending = self.store.pending_gate_consent_in_txn(&*wtxn, id)?.ok_or(
            Error::InvariantViolation("a parked retract has no tray row"),
        )?;
        Ok(OwnClaimRetract::Parked(pending.decision_id))
    }

    /// Removes the retract parked on `id`, if one is: the claim closed by
    /// another door, so nothing is left for the holder to consent to.
    pub(crate) fn drop_parked_retract_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        id: &EntityId,
    ) -> Result<()> {
        if parked_retract(self, &*wtxn, id)? {
            DEFERRED.delete(&self.store, wtxn, id)?;
        }
        Ok(())
    }
}

/// Whether the action parked on `id` is a retract.
fn parked_retract(vault: &Vault, txn: &heed::RoTxn<'_>, id: &EntityId) -> Result<bool> {
    Ok(DEFERRED
        .get(&vault.store, txn, id)?
        .is_some_and(|row| matches!(row.action, DeferredAction::Retract)))
}
