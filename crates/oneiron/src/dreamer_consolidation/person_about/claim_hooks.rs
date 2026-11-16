//! The PEOPLE `about` hooks the CLAIM doors call, each in the door's own
//! transaction before the row changes: a put that changes a body, a door
//! that drops a fact without a new body (FIX 3196), and the erase (FIX 3155).
//! The drop and the erase also drop the person's vector, which was embedded
//! from its public line (ruling PERSON-VECTOR-CHOICES, D4); a put only hides
//! the line and keeps the vector until the next landing.

use super::PERSON_ABOUT;
use crate::EntityId;
use crate::claim::ClaimSubject;
use crate::error::Result;
use crate::registry::ENTITY_TYPE_CLAIM;

/// The subject of the CLAIM body stored at `claim`; `None` when `claim`
/// holds no CLAIM body.
fn stored_claim_subject(
    store: &crate::store::Store,
    txn: &heed::RoTxn<'_>,
    claim: &EntityId,
) -> Result<Option<ClaimSubject>> {
    let subject = crate::ports::EntityStoreRead::port_entity_raw_wiped(store, txn, claim)?
        .filter(|raw| {
            crate::batch::EntityMetadataHeader::parse(raw)
                .is_some_and(|header| header.entity_type == ENTITY_TYPE_CLAIM)
        })
        .and_then(|raw| {
            crate::claim::decode_claim_body(
                raw.get(crate::batch::ENTITY_METADATA_HEADER_LEN..)?,
                true,
            )
            .ok()
        })
        .map(|stored| stored.subject);
    Ok(subject)
}

/// Hides the `about` lines of the PERSON `subject` names, until a wake pass
/// reads its facts again, and answers that person. Any other subject, or a
/// person with no row, is left as it is and answers `None`.
fn mark_subject_moved_in_txn(
    store: &crate::store::Store,
    txn: &mut heed::RwTxn<'_>,
    subject: ClaimSubject,
) -> Result<Option<EntityId>> {
    let ClaimSubject::Entity(person) = subject else {
        return Ok(None);
    };
    let Some(mut row) = PERSON_ABOUT.get(store, txn, &person)? else {
        return Ok(None);
    };
    if !row.moved {
        row.moved = true;
        PERSON_ABOUT.put(store, txn, &person, &row)?;
    }
    Ok(Some(person))
}

/// Hides the `about` lines of the PERSON a CLAIM is about, and of the one its
/// stored body was about, until a wake pass reads their facts again. Runs in
/// the CLAIM put's transaction, before the new body replaces the stored one.
pub(crate) fn mark_person_about_moved_in_txn(
    store: &crate::store::Store,
    txn: &mut heed::RwTxn<'_>,
    claim: EntityId,
    body: &crate::claim::ClaimBody,
) -> Result<()> {
    let stored = stored_claim_subject(store, txn, &claim)?;
    for subject in std::iter::once(body.subject).chain(stored) {
        mark_subject_moved_in_txn(store, txn, subject)?;
    }
    Ok(())
}

/// The PEOPLE half of a door that drops a CLAIM from the facts a wake pass
/// reads without writing a new body (FIX 3196): an archive, or a use limit
/// on a record a refused privacy erasure kept. Hides the `about` lines of
/// the PERSON its stored body is about, as a body-changing put does, until a
/// wake pass reads that person's facts again, and drops that person's
/// vector, which the dropped fact's words may have shaped (ruling D4). Runs
/// in the door's transaction, before its mark is written. A row that holds
/// no CLAIM body changes nothing.
pub(crate) fn mark_person_about_dropped_in_txn(
    store: &crate::store::Store,
    txn: &mut heed::RwTxn<'_>,
    claim: &EntityId,
) -> Result<()> {
    let Some(subject) = stored_claim_subject(store, txn, claim)? else {
        return Ok(());
    };
    if let Some(person) = mark_subject_moved_in_txn(store, txn, subject)? {
        crate::embed::drop_person_vector_in_txn(store, txn, &person)?;
    }
    Ok(())
}

/// The erase hook's PEOPLE half (FIX 3155): an erased fact takes the
/// `about` lines of the PERSON it was about, and their kept before-image,
/// with it, so no stored line still says what the fact said, and the
/// person's vector, which was embedded from one of those lines (ruling D4);
/// the next wake pass writes new lines from the facts left. An erased PERSON
/// takes its whole row; the tear drops its own vector. Runs in the erasing
/// transaction, before the tear.
pub(crate) fn erase_person_about_in_txn(
    store: &crate::store::Store,
    txn: &mut heed::RwTxn<'_>,
    id: &EntityId,
) -> Result<()> {
    if PERSON_ABOUT.get(store, txn, id)?.is_some() {
        PERSON_ABOUT.delete(store, txn, id)?;
        return Ok(());
    }
    let Some(ClaimSubject::Entity(person)) = stored_claim_subject(store, txn, id)? else {
        return Ok(());
    };
    let Some(mut row) = PERSON_ABOUT.get(store, txn, &person)? else {
        return Ok(());
    };
    row.moved = true;
    row.lines.clear();
    row.previous = None;
    PERSON_ABOUT.put(store, txn, &person, &row)?;
    crate::embed::drop_person_vector_in_txn(store, txn, &person)
}
