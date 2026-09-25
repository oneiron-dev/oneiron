//! Imported reliability history is inert data, not a local posterior or synced base.
use super::{
    PREDICATE_SKILL_RELIABILITY, SKILL_RELIABILITY_MAX_CITED_RECEIPTS, SkillReliabilityPosterior,
    codec::invalid,
};
use crate::{
    Vault,
    claim::{ClaimApprovalStatus, ClaimBody, ClaimSource, ClaimSubject},
    entity_id::EntityId,
    error::{Error, Result},
    temporal::TimeRange,
    vault::live_entity_row_in_txn,
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
    let posterior = SkillReliabilityPosterior::from_value(&body.value)?;
    if body.value != posterior.to_value() {
        return Err(invalid(
            "reliability archive requires the exact posterior codec",
        ));
    }
    let Some(Value::Array(refs)) = body.evidence.as_ref() else {
        return Err(invalid("reliability archive needs its citations"));
    };
    if refs.len() > SKILL_RELIABILITY_MAX_CITED_RECEIPTS
        || refs.iter().any(|r| r.as_str().is_none_or(str::is_empty))
    {
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
    if body.source == Some(ClaimSource::Imported) && imported_reliability_body(body)? != *body {
        return Err(invalid("foreign reliability must remain inert"));
    }
    Ok(())
}
impl Vault {
    pub(crate) fn restore_reliability_claim_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        id: &EntityId,
        body: &ClaimBody,
        occurred: TimeRange,
        learned_at: u64,
    ) -> Result<()> {
        if imported_reliability_body(body)? != *body {
            return Err(invalid("reliability restore needs an imported proposal"));
        }
        let ClaimSubject::Entity(skill) = body.subject else {
            return Err(invalid("reliability archive subject"));
        };
        if self.store.off_record_sessions.contains_entity(&skill)?
            || !live_entity_row_in_txn(&self.store, txn, &skill)?.is_live()
        {
            return Err(Error::EntityNotFound);
        }
        let row = self
            .store
            .entities
            .get(txn, skill.as_bytes())?
            .ok_or(Error::EntityNotFound)?;
        let header = crate::batch::EntityMetadataHeader::parse(&row)
            .ok_or(Error::CorruptedIndex("reliability archive skill"))?;
        if header.entity_type != crate::registry::ENTITY_TYPE_SKILL {
            return Err(invalid("reliability archive subject must be SKILL"));
        }
        // No outcome ledger, projection base, confidence cache, floor action,
        // native receipt or existing observed head is changed by archive intake.
        self.put_reserved_claim_in_txn(txn, id, body, occurred, learned_at)
    }
}
