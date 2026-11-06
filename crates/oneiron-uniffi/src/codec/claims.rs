//! Owned claim-review output lifts for opaque claim JSON (FIX 12936).

use super::{Lift, OneironError, WireJson, lift_record};

impl Lift<oneiron::memory::ClaimView> for crate::WireClaimView {
    fn lift(view: oneiron::memory::ClaimView) -> Result<Self, OneironError> {
        let oneiron::memory::ClaimView {
            claim_ref,
            short_ref,
            predicate,
            subject_ref,
            value,
            confidence,
            approval,
            lifecycle,
            source,
            world_ref,
            scope,
            claim_scope,
            made_by,
            valid_from,
            valid_to,
            salience,
            stale,
            claim,
        } = view;
        let (value, scope) = lift_json(value, scope)?;
        Ok(Self {
            claim_ref,
            short_ref,
            predicate,
            subject_ref,
            value,
            // Keep the shared serde behavior for f32 widths and non-finite values.
            confidence: lift_record("claim review:confidence", &confidence)?,
            approval,
            lifecycle,
            source,
            world_ref,
            scope,
            claim_scope: lift_record("claim review:claim_scope", &claim_scope)?,
            made_by: lift_record("claim review:made_by", &made_by)?,
            valid_from,
            valid_to,
            salience: lift_record("claim review:salience", &salience)?,
            stale,
            claim: lift_record("claim review:claim", &claim)?,
        })
    }
}

pub(super) fn lift_json(
    value: serde_json::Value,
    scope: Option<serde_json::Value>,
) -> Result<(WireJson, Option<WireJson>), OneironError> {
    // Consume both opaque leaves before propagating an encoding error.
    let value = WireJson::lift(value);
    let scope = match scope {
        None | Some(serde_json::Value::Null) => Ok(None),
        Some(scope) => WireJson::lift(scope).map(Some),
    };
    Ok((value?, scope?))
}

impl Lift<oneiron::memory::ClaimProposalReview> for crate::ClaimProposalReview {
    fn lift(review: oneiron::memory::ClaimProposalReview) -> Result<Self, OneironError> {
        let oneiron::memory::ClaimProposalReview {
            review_id,
            proposal_ref,
            claim,
            opener_ref,
            pending_ref,
        } = review;
        Ok(Self {
            review_id,
            proposal_ref,
            claim: crate::WireClaimView::lift(claim)?,
            opener_ref,
            pending_ref,
        })
    }
}
