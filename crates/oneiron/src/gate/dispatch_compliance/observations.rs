//! Deterministic ranking of recorded jurisdiction claims.

use super::evaluate::normalize_jurisdiction;
use super::rules::CONFIDENCE_MILLIS_SCALE;
use crate::error::Result;
use crate::write_envelope::claim_body::ClaimBody;
use crate::write_envelope::cohort_claims::codec::decode_comm_jurisdiction_value;

/// One ACTIVE `comm.jurisdiction` observation as the gate ranks it: when it
/// was observed, its normalized token, and its confidence in thousandths.
pub(crate) type JurisdictionObservation = (u64, String, Option<u16>);

/// Ranks one `comm.jurisdiction` body. A value that does not decode is an
/// error, which fails the gate closed.
pub(crate) fn rank_jurisdiction_observation(body: &ClaimBody) -> Result<JurisdictionObservation> {
    let value = decode_comm_jurisdiction_value(&body.value)?;
    Ok((
        value.observed_at,
        normalize_jurisdiction(&value.jurisdiction),
        confidence_millis(body.confidence),
    ))
}

/// The jurisdiction and confidence the gate selects from a subject's active
/// observations.
pub(crate) fn select_jurisdiction(
    mut observations: Vec<JurisdictionObservation>,
) -> Option<(String, Option<u16>)> {
    observations
        .sort_unstable_by(|left, right| right.0.cmp(&left.0).then_with(|| left.1.cmp(&right.1)));
    observations
        .into_iter()
        .next()
        .map(|(_, token, confidence)| (token, confidence))
}

/// `ClaimBody::confidence` is a fraction in `[0, 1]`; the pack's floor is in
/// thousandths. A non-finite or out-of-range value is not a confidence.
fn confidence_millis(confidence: f32) -> Option<u16> {
    if !confidence.is_finite() || !(0.0..=1.0).contains(&confidence) {
        return None;
    }
    Some((confidence * CONFIDENCE_MILLIS_SCALE).round() as u16)
}
