//! Saved-policy stock answers in the original switch's committing writer.
//! The native host supplies live route, money and file evidence, not an owner
//! authentication or a remote caller's approval flag. Unknown leaves the offer.

use super::{
    ANSWER, OfferAnswer, OfferAnswerAuthority, OfferAnswerRecord, OfferCandidate, OfferIntent,
    TrainingOffer, measurement, pending_training_offer_in_txn,
};
use crate::llm::registry::ModelRegistryRow;
use crate::skill_optimize::EvalMeasurement;
use crate::{EntityId, Error, Result, Vault};

impl Vault {
    /// Tries only a STOCK switch under the owner's current saved setting.
    /// `current_host_matches` runs inside this writer and must read the actual
    /// constructed bindings, native quotes and captured-worker files. It is a
    /// trusted in-process host seam, never a caller assertion or SDK verb.
    /// False/unknown does not answer, close an ask, train or change a binding.
    pub fn try_autoapprove_stock_offer<F>(
        &self,
        offer: &EntityId,
        expected_digest: &str,
        scorer: &str,
        at: u64,
        current_host_matches: F,
    ) -> Result<Option<OfferAnswerRecord>>
    where
        F: FnOnce(
            &heed::RoTxn<'_>,
            &TrainingOffer,
            &EvalMeasurement,
            &ModelRegistryRow,
            &ModelRegistryRow,
        ) -> Result<bool>,
    {
        self.with_write_txn_grouped(|txn| {
            let policy =
                crate::settings::stock_autoapprove::stock_autoapprove_policy_in_txn(self, txn)?;
            let Some(revision) = policy.revision.filter(|_| policy.enabled) else {
                return Ok(None);
            };
            let Some(row) = pending_training_offer_in_txn(self, txn, offer)? else {
                return Ok(None);
            };
            if row.digest != expected_digest {
                return Ok(None);
            }
            let OfferCandidate::Stock { model, .. } = &row.candidate else {
                return Ok(None);
            };
            match crate::skill_optimize::offer_pilot::validate_stock_offer_in_txn(self, txn, &row) {
                Ok(()) => {}
                Err(Error::InvalidConfig(_) | Error::EntityNotFound) => return Ok(None),
                Err(error) => return Err(error),
            }
            let Some(measured) = measurement::matched_in_txn(self, txn, &row)? else {
                return Ok(None);
            };
            if !measured.card.as_ref().is_some_and(|card| card.approves())
                || !self.offer_measurement_current_in_txn(txn, &measured, scorer)?
            {
                return Ok(None);
            }
            let incumbent = crate::ModelId::new(row.incumbent.model.clone()).map_err(|_| {
                Error::InvalidConfig("the incumbent model id does not parse".into())
            })?;
            let candidate = crate::ModelId::new(model.model.clone()).map_err(|_| {
                Error::InvalidConfig("the candidate model id does not parse".into())
            })?;
            let Some(incumbent) = self.model_registry_row_in_txn(txn, &incumbent)? else {
                return Ok(None);
            };
            let Some(candidate) = self.model_registry_row_in_txn(txn, &candidate)? else {
                return Ok(None);
            };
            if !current_host_matches(txn, &row, &measured, &incumbent, &candidate)? {
                return Ok(None);
            }
            crate::skill_optimize::offer_switch::apply_switch_in_txn(
                self,
                txn,
                crate::skill_optimize::offer_switch::SwitchOwner::StockPolicy(revision),
                offer,
                &row.seat,
                &row.incumbent,
                model,
                at,
            )?;
            let record = OfferAnswerRecord {
                offer: *offer,
                answer: OfferAnswer::ApproveSwitch,
                authority: OfferAnswerAuthority::StockPolicy { revision },
                offer_digest: row.digest.clone(),
                intent: Some(OfferIntent::Switch {
                    seat: row.seat.clone(),
                    from: row.incumbent.clone(),
                    to: model.clone(),
                }),
                at,
            };
            ANSWER.put(&self.store, txn, offer, &record)?;
            crate::task_verb::void_training_offer_asks_in(self, txn, offer, None, at)?;
            Ok(Some(record))
        })
    }
}
