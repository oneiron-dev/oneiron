//! Qualifies a card's native source in the offer's committing snapshot.
//! Losing this optional provenance never rejects an otherwise valid offer.

use super::{OfferCandidate, OfferModelPin, TrainingOffer};
use crate::skill_optimize::{EvalArmPin, MeasurementState};
use crate::{Result, Vault};

fn arm_matches(arm: &EvalArmPin, pin: &OfferModelPin) -> bool {
    arm.model == pin.model && arm.revision == pin.revision && arm.skill_digest.is_none()
}

fn matches_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    offer: &TrainingOffer,
    digest: &[u8; 32],
) -> Result<bool> {
    let OfferCandidate::Stock { model, .. } = &offer.candidate else {
        return Ok(false);
    };
    let Some(measured) = vault.eval_measurement_in_txn(txn, digest)? else {
        return Ok(false);
    };
    let request = &measured.request;
    Ok(measured.state == MeasurementState::Final
        && measured.digest == blake3::Hash::from(*digest).to_hex().as_str()
        && request.seat == offer.seat
        && arm_matches(&request.incumbent, &offer.incumbent)
        && arm_matches(&request.candidate, model)
        && Some(request.cohort) == offer.evidence.cohort
        && Some(&request.rubric_revision) == offer.evidence.rubric_revision.as_ref()
        && measured.settled_at.is_some_and(|at| at <= offer.offered_at)
        && measured.card.is_some()
        && measured.card == offer.evidence.card
        && !measured.exposures.is_empty()
        && measured
            .exposures
            .iter()
            .all(|exposure| offer.evidence.exposures.contains(exposure)))
}

pub(super) fn keep_source_in_txn(vault: &Vault, txn: &heed::RoTxn<'_>, offer: &mut TrainingOffer) {
    let Some(digest) = offer.evidence.paired_measurement else {
        return;
    };
    let matches = match matches_in_txn(vault, txn, offer, &digest) {
        Ok(matches) => matches,
        Err(error) => {
            tracing::warn!(%error, "the offer's paired measurement source did not read");
            false
        }
    };
    if !matches {
        offer.evidence.paired_measurement = None;
    }
}
