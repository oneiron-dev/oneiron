//! Imported reliability history is inert data, not a local posterior or synced base.
use super::{PREDICATE_SKILL_RELIABILITY, codec::invalid};
use crate::{
    claim::{ClaimApprovalStatus, ClaimBody, ClaimSource, ClaimSubject},
    error::Result,
};
use rmpv::Value;

pub(crate) fn imported_reliability_body(body: &ClaimBody) -> Result<ClaimBody> {
    if body.predicate != PREDICATE_SKILL_RELIABILITY
        || !matches!(body.subject, ClaimSubject::Entity(_))
        || body.confidence != 1.0
        || body.scope.is_some()
        || body.world.is_some()
        || body.rel.is_some()
    {
        return Err(invalid("invalid reliability archive shape"));
    }
    if !((body.source == Some(ClaimSource::Observed) && body.approval == ClaimApprovalStatus::Auto)
        || (body.source == Some(ClaimSource::Imported)
            && matches!(
                body.approval,
                ClaimApprovalStatus::Proposed | ClaimApprovalStatus::Rejected
            )))
    {
        return Err(invalid("reliability archive is neither native nor inert"));
    }
    crate::learning::validate_learning_claim_structure(body)?;
    let Some(Value::Array(refs)) = body.evidence.as_ref() else {
        return Err(invalid("reliability archive needs its citations"));
    };
    if refs.iter().any(|r| r.as_str().is_none_or(str::is_empty)) {
        return Err(invalid("invalid reliability archive citations"));
    }
    let mut out = body.clone();
    out.source = Some(ClaimSource::Imported);
    if out.approval != ClaimApprovalStatus::Rejected {
        out.approval = ClaimApprovalStatus::Proposed;
    }
    Ok(out)
}
pub(crate) fn validate_imported_reliability(body: &ClaimBody) -> Result<()> {
    crate::learning::validate_learning_claim_structure(body)?;
    if body.source == Some(ClaimSource::Imported) && imported_reliability_body(body)? != *body {
        return Err(invalid("foreign reliability must remain inert"));
    }
    Ok(())
}
