//! Inert restoration of skill amendment-cost history; never a judged local cost.
use super::stored::{MAX_CITED_RECEIPTS, invalid, normalized_scope};
use crate::{
    Vault,
    claim::{ClaimApprovalStatus, ClaimBody, ClaimSource, ClaimSubject, PREDICATE_SKILL_EDIT_COST},
    entity_id::EntityId,
    error::{Error, Result},
    temporal::TimeRange,
    vault::live_entity_row_in_txn,
};
use rmpv::Value;
pub(crate) fn imported_skill_cost_body(body: &ClaimBody) -> Result<ClaimBody> {
    if body.predicate != PREDICATE_SKILL_EDIT_COST
        || !matches!(body.subject, ClaimSubject::Entity(_))
        || body.confidence != 1.0
        || body.world.is_some()
        || body.rel.is_some()
    {
        return Err(invalid("invalid archived skill cost shape"));
    }
    if !((body.source == Some(ClaimSource::Observed) && body.approval == ClaimApprovalStatus::Auto)
        || (body.source == Some(ClaimSource::Imported)
            && matches!(
                body.approval,
                ClaimApprovalStatus::Proposed | ClaimApprovalStatus::Rejected
            )))
    {
        return Err(invalid("skill cost archive is neither native nor inert"));
    }
    let Value::F32(cost) = body.value else {
        return Err(invalid("skill cost archive must be F32"));
    };
    if !cost.is_finite() || !(0.0..=1.0).contains(&cost) {
        return Err(invalid("invalid archived skill cost"));
    }
    let scope = crate::actor_claims::edit_cost_scope_name(body.scope.as_ref())
        .ok_or(invalid("skill cost scope missing"))?;
    if normalized_scope(scope)? != scope
        || body.scope != Some(crate::actor_claims::edit_cost_scope(scope))
    {
        return Err(invalid("skill cost scope is not canonical"));
    }
    let Some(Value::Array(refs)) = body.evidence.as_ref() else {
        return Err(invalid("skill cost citations missing"));
    };
    if refs.is_empty()
        || refs.len() > MAX_CITED_RECEIPTS
        || refs.iter().any(|r| r.as_str().is_none_or(str::is_empty))
    {
        return Err(invalid("invalid archived skill cost citations"));
    }
    let mut out = body.clone();
    out.source = Some(ClaimSource::Imported);
    if out.approval != ClaimApprovalStatus::Rejected {
        out.approval = ClaimApprovalStatus::Proposed;
    }
    Ok(out)
}
pub(crate) fn validate_imported_skill_cost(body: &ClaimBody) -> Result<()> {
    if body.source == Some(ClaimSource::Imported) && imported_skill_cost_body(body)? != *body {
        return Err(invalid("foreign skill cost must remain inert"));
    }
    Ok(())
}
impl Vault {
    pub(crate) fn restore_skill_cost_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        id: &EntityId,
        body: &ClaimBody,
        occurred: TimeRange,
        learned_at: u64,
    ) -> Result<()> {
        if imported_skill_cost_body(body)? != *body {
            return Err(invalid("skill cost restore needs an imported proposal"));
        }
        let ClaimSubject::Entity(skill) = body.subject else {
            return Err(invalid("skill cost subject"));
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
            .ok_or(Error::CorruptedIndex("skill cost archive subject"))?;
        if header.entity_type != crate::registry::ENTITY_TYPE_SKILL {
            return Err(invalid("skill cost archive subject must be SKILL"));
        }
        self.put_reserved_claim_in_txn(txn, id, body, occurred, learned_at)
    }
}
