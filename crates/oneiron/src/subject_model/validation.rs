use super::{PREDICATE_ACTOR_SUBJECT_REF, PREDICATE_PERSON_SUBSTRATE, PersonSubstrate};
use crate::batch::EntityMetadataHeader;
use crate::claim::{ClaimBody, ClaimSubject};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::registry::{
    ENTITY_TYPE_AGENT_DEF, ENTITY_TYPE_MACHINE, ENTITY_TYPE_ORG, ENTITY_TYPE_PERSON,
};
use crate::store::Store;

const MISSING_PERSON: &str = "person.substrate subject PERSON has not arrived";
const MISSING_ACTOR: &str = "actor.subject_ref actor has not arrived";
const MISSING_ANCHOR: &str = "actor.subject_ref subject PERSON or ORG has not arrived";

pub(crate) fn validate_actor_subject_claim_structure(
    body: &ClaimBody,
) -> Result<(EntityId, EntityId)> {
    let ClaimSubject::Entity(actor) = body.subject else {
        return Err(Error::InvalidClaimBody(
            "actor.subject_ref subject must name an actor entity",
        ));
    };
    let subject = body
        .value
        .as_str()
        .and_then(|hex| EntityId::from_hex(hex).ok())
        .ok_or(Error::InvalidClaimBody(
            "actor.subject_ref value must be an entity ID string",
        ))?;
    Ok((actor, subject))
}

pub(super) fn require_anchor_entities_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    actor: &EntityId,
    subject: &EntityId,
) -> Result<()> {
    let actor_raw = store.entities.get(txn, actor.as_bytes())?;
    let subject_raw = store.entities.get(txn, subject.as_bytes())?;
    require_anchor_headers(actor_raw.as_deref(), subject_raw.as_deref())
}

fn require_anchor_headers(actor_raw: Option<&[u8]>, subject_raw: Option<&[u8]>) -> Result<()> {
    // Validate present rows before classifying absence as retryable. A known
    // wrong type is terminal even if the other dependency has not arrived.
    if let Some(raw) = actor_raw {
        let header = EntityMetadataHeader::parse(raw)
            .ok_or(Error::CorruptedIndex("subject model entity header"))?;
        let class = match header.entity_type {
            ENTITY_TYPE_PERSON | ENTITY_TYPE_AGENT_DEF => crate::edge::EdgeActorClass::Agent,
            ENTITY_TYPE_MACHINE => crate::edge::EdgeActorClass::System,
            _ => {
                return Err(Error::InvalidClaimBody(
                    "actor.subject_ref actor must be authority-bearing",
                ));
            }
        };
        crate::provenance::validate_actor_class(header.entity_type, class)?;
    }
    if let Some(raw) = subject_raw {
        let header = EntityMetadataHeader::parse(raw)
            .ok_or(Error::CorruptedIndex("subject model entity header"))?;
        if !matches!(header.entity_type, ENTITY_TYPE_PERSON | ENTITY_TYPE_ORG) {
            return Err(Error::InvalidClaimBody(
                "actor.subject_ref subject must be a PERSON or ORG",
            ));
        }
    }
    actor_raw.ok_or(Error::InvalidClaimBody(MISSING_ACTOR))?;
    subject_raw.ok_or(Error::InvalidClaimBody(MISSING_ANCHOR))?;
    Ok(())
}

pub(crate) fn validate_person_substrate_claim_structure(body: &ClaimBody) -> Result<EntityId> {
    let ClaimSubject::Entity(person) = body.subject else {
        return Err(Error::InvalidClaimBody(
            "person.substrate subject must name a PERSON entity",
        ));
    };
    if body
        .value
        .as_str()
        .and_then(PersonSubstrate::parse)
        .is_none()
    {
        return Err(Error::InvalidClaimBody(
            "person.substrate value must be exactly meat or model",
        ));
    }
    Ok(person)
}

pub(super) fn require_person_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    person: &EntityId,
) -> Result<()> {
    let raw = store.entities.get(txn, person.as_bytes())?;
    require_person_header(raw.as_deref())
}

fn require_person_header(raw: Option<&[u8]>) -> Result<()> {
    let raw = raw.ok_or(Error::InvalidClaimBody(MISSING_PERSON))?;
    let header = EntityMetadataHeader::parse(raw)
        .ok_or(Error::CorruptedIndex("subject model entity header"))?;
    if header.entity_type != ENTITY_TYPE_PERSON {
        return Err(Error::InvalidClaimBody(
            "person.substrate subject must be a PERSON",
        ));
    }
    Ok(())
}

pub(crate) fn validate_subject_model_claim_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    body: &ClaimBody,
) -> Result<()> {
    if body.predicate == PREDICATE_PERSON_SUBSTRATE {
        let person = validate_person_substrate_claim_structure(body)?;
        // Check the applying transaction, not a preflight snapshot or a future
        // batch op. Replicas may send the claim before its PERSON: reject the
        // write until that row arrives; never store a dangling substrate fact.
        require_person_in_txn(store, txn, &person)?;
    } else if body.predicate == PREDICATE_ACTOR_SUBJECT_REF {
        let (actor, subject) = validate_actor_subject_claim_structure(body)?;
        require_anchor_entities_in_txn(store, txn, &actor, &subject)?;
    }
    Ok(())
}

pub(crate) fn validate_subject_model_claim_in_session(
    view: &crate::store::SessionStoreView<'_>,
    txn: &heed::RoTxn<'_>,
    body: &ClaimBody,
) -> Result<()> {
    if body.predicate == PREDICATE_PERSON_SUBSTRATE {
        let person = validate_person_substrate_claim_structure(body)?;
        let entities = view.entity_rows_for_write()?;
        let raw = entities.get(txn, person.as_bytes())?;
        require_person_header(raw.as_deref())?;
    } else if body.predicate == PREDICATE_ACTOR_SUBJECT_REF {
        let (actor, subject) = validate_actor_subject_claim_structure(body)?;
        // Resolve both endpoints from one segment-aware snapshot, not the
        // logical read view captured before earlier batch puts were staged.
        let entities = view.entity_rows_for_write()?;
        let actor_raw = entities.get(txn, actor.as_bytes())?;
        let subject_raw = entities.get(txn, subject.as_bytes())?;
        require_anchor_headers(actor_raw.as_deref(), subject_raw.as_deref())?;
    }
    Ok(())
}

#[cfg(feature = "sync")]
pub(crate) fn subject_model_dependency_pending(error: &Error) -> bool {
    matches!(
        error,
        Error::InvalidClaimBody(MISSING_PERSON | MISSING_ACTOR | MISSING_ANCHOR)
    )
}
