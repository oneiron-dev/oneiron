//! Domain-owned inert restore of learned actor rows. Not local observation authority.
use super::{
    ACTOR_CLAIM_LINEAGE_KEY, invalid, is_actor_claim_predicate,
    validate::{skill_fit_scope_skill, validate_actor_claim_structure},
};
use crate::{
    Vault,
    claim::{ClaimApprovalStatus, ClaimBody, ClaimSource, ClaimSubject},
    entity_id::EntityId,
    error::{Error, Result},
    registry::{
        ENTITY_TYPE_AGENT_DEF, ENTITY_TYPE_MACHINE, ENTITY_TYPE_PERSON, ENTITY_TYPE_SESSION,
        ENTITY_TYPE_SKILL, ENTITY_TYPE_TURN,
    },
    temporal::TimeRange,
    vault::live_entity_row_in_txn,
};
use rmpv::Value;

pub(crate) fn imported_actor_body(body: &ClaimBody) -> Result<ClaimBody> {
    if !is_actor_claim_predicate(&body.predicate) || body.world.is_some() || body.rel.is_some() {
        return Err(invalid("actor archive must be an unscoped base projection"));
    }
    validate_actor_claim_structure(body)?;
    let mut out = body.clone();
    out.source = Some(ClaimSource::Imported);
    if out.approval != ClaimApprovalStatus::Rejected {
        out.approval = ClaimApprovalStatus::Proposed;
    }
    let Some(Value::Map(scope)) = &mut out.scope else {
        return Err(invalid("actor archive has no lineage"));
    };
    for (key, value) in scope {
        if key.as_str() == Some(ACTOR_CLAIM_LINEAGE_KEY) {
            *value = Value::from("imported");
        }
    }
    validate_actor_claim_structure(&out)?;
    Ok(out)
}

pub(crate) fn imported_actor_dependencies(body: &ClaimBody) -> Result<Vec<EntityId>> {
    let body = imported_actor_body(body)?;
    let ClaimSubject::Entity(actor) = body.subject else {
        return Err(invalid("actor archive subject"));
    };
    let mut refs = vec![actor];
    if let Some(skill) = skill_fit_scope_skill(body.scope.as_ref()) {
        refs.push(skill);
    }
    if let Some(references) = super::actor_archive_references(&body)
        && let Some((session, turns)) = references.chat
    {
        refs.push(session);
        refs.extend(turns);
    }
    Ok(refs)
}
impl Vault {
    pub(crate) fn restore_actor_projection_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        id: &EntityId,
        body: &ClaimBody,
        occurred: TimeRange,
        learned_at: u64,
    ) -> Result<()> {
        if imported_actor_body(body)? != *body {
            return Err(invalid("actor restore requires inert Imported proposal"));
        }
        let ClaimSubject::Entity(actor) = body.subject else {
            return Err(invalid("actor archive subject"));
        };
        require_kind(
            self,
            txn,
            &actor,
            &[
                ENTITY_TYPE_PERSON,
                ENTITY_TYPE_AGENT_DEF,
                ENTITY_TYPE_MACHINE,
            ],
        )?;
        if let Some(skill) = skill_fit_scope_skill(body.scope.as_ref()) {
            require_kind(self, txn, &skill, &[ENTITY_TYPE_SKILL])?;
        }
        if let Some(references) = super::actor_archive_references(body)
            && let Some((session, turns)) = references.chat
        {
            require_kind(self, txn, &session, &[ENTITY_TYPE_SESSION])?;
            for turn in turns {
                require_kind(self, txn, &turn, &[ENTITY_TYPE_TURN])?;
            }
        }
        // Do not invoke the live writer, supersede native heads, stamp receipts,
        // accept foreign judgments or register a distillation job.
        self.put_reserved_claim_in_txn(txn, id, body, occurred, learned_at)
    }
}
fn require_kind(vault: &Vault, txn: &heed::RoTxn<'_>, id: &EntityId, kinds: &[u8]) -> Result<()> {
    if vault.store.off_record_sessions.contains_entity(id)?
        || !live_entity_row_in_txn(&vault.store, txn, id)?.is_live()
    {
        return Err(Error::EntityNotFound);
    }
    let row = vault
        .store
        .entities
        .get(txn, id.as_bytes())?
        .ok_or(Error::EntityNotFound)?;
    let header = crate::batch::EntityMetadataHeader::parse(&row)
        .ok_or(Error::CorruptedIndex("actor archive reference"))?;
    if !kinds.contains(&header.entity_type) {
        return Err(invalid("actor archive reference has wrong kind"));
    }
    Ok(())
}
