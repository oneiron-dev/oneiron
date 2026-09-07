use super::{PREDICATE_PERSON_SUBSTRATE, PersonSubstrate};
use crate::batch::EntityMetadataHeader;
use crate::claim::{ClaimBody, ClaimSubject};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::registry::ENTITY_TYPE_PERSON;
use crate::store::Store;

const MISSING_PERSON: &str = "person.substrate subject PERSON has not arrived";

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

pub(crate) fn validate_person_substrate_claim_in_txn(
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
    }
    Ok(())
}

pub(crate) fn validate_person_substrate_claim_in_session(
    view: &crate::store::SessionStoreView<'_>,
    txn: &heed::RoTxn<'_>,
    body: &ClaimBody,
) -> Result<()> {
    if body.predicate == PREDICATE_PERSON_SUBSTRATE {
        let person = validate_person_substrate_claim_structure(body)?;
        let raw = view.entities.get(txn, person.as_bytes())?;
        require_person_header(raw.as_deref())?;
    }
    Ok(())
}

#[cfg(feature = "sync")]
pub(crate) fn substrate_subject_pending(error: &Error) -> bool {
    matches!(error, Error::InvalidClaimBody(MISSING_PERSON))
}
