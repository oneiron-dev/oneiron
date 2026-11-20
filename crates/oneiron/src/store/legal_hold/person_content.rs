//! The rows whose content is about a PERSON, and the use limit a kept
//! privacy erase of that PERSON puts on them (FIX
//! KEPT-PRIVACY-ERASE-USE-LIMITS-DERIVED-PERSON-CONTENT; Engine ANSWER
//! WITHHELD-PERSON-CONTENT-RULE, 20 Nov).

use heed::RoTxn;
use rmpv::ValueRef;

use super::use_limit::{USE_LIMITS, legal_hold_use_limit_in_txn};
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::claim::ClaimSubject;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::ports::EntityStoreRead;
use crate::registry::{
    ENTITY_TYPE_CLAIM, ENTITY_TYPE_FACET, ENTITY_TYPE_PERSON, ENTITY_TYPE_PERSONA_SNAPSHOT_EXPORT,
    ENTITY_TYPE_PSYCH_PROFILE,
};
use crate::store::ManifestDbs;
use crate::store::persona_snapshot_record::KEY_SUBJECT_REF as PERSONA_SUBJECT_REF;
use crate::write_envelope::claim_body::KEY_SUBJ;
use crate::write_envelope::profile_snapshot::record::KEY_SUBJECT_REF as PSYCH_PROFILE_SUBJECT_REF;

/// Whether stored row `record` is content about a PERSON whose privacy erase
/// a standing customer hold refused (C6): a PSYCH_PROFILE or
/// PERSONA_SNAPSHOT_EXPORT whose subject it is, a FACET scenario mask of it,
/// or a CLAIM whose subject, or either end of whose subject link, it is
/// ([`person_content_subjects`]). Such a row is that person's data, so it is
/// kept from use with the PERSON row, for as long as the PERSON's own limit
/// stands ([`legal_hold_use_limit_in_txn`]); when the last hold lifts, it
/// reads again. Every other row that names the PERSON is judged by its own
/// id: there the id is an opaque reference.
///
/// A vault with no use limit at all answers from one table probe; any other
/// row reads only its header before its kind rules it out.
pub(super) fn kept_person_content_in_txn(
    dbs: &impl ManifestDbs,
    txn: &RoTxn<'_>,
    record: &EntityId,
) -> Result<bool> {
    if USE_LIMITS
        .iter_raw_from(dbs, txn, &[])?
        .next()
        .transpose()?
        .is_none()
    {
        return Ok(false);
    }
    let subjects = EntityStoreRead::port_entity_with_raw(dbs, txn, record, |raw| {
        Ok(person_content_subjects(raw))
    })?
    .unwrap_or_default();
    for subject in subjects.iter().filter(|subject| *subject != record) {
        if legal_hold_use_limit_in_txn(dbs, txn, subject)?.is_some()
            && kept_row_is_person_in_txn(dbs, txn, subject)?
        {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Whether kept row `subject` is a PERSON. A kept row whose header does not
/// read counts as one: its limit then covers the content about it.
fn kept_row_is_person_in_txn(
    dbs: &impl ManifestDbs,
    txn: &RoTxn<'_>,
    subject: &EntityId,
) -> Result<bool> {
    let entity_type = EntityStoreRead::port_entity_with_raw(dbs, txn, subject, |raw| {
        Ok(EntityMetadataHeader::parse(raw).map(|header| header.entity_type))
    })?
    .flatten();
    Ok(entity_type.is_none_or(|entity_type| entity_type == ENTITY_TYPE_PERSON))
}

/// The records stored row `raw` holds content about, as the four kinds whose
/// content follows a PERSON name them: a PSYCH_PROFILE's or
/// PERSONA_SNAPSHOT_EXPORT's `subjectRef`, a FACET scenario mask's PERSON,
/// and a CLAIM's subject, both ends of a subject link. Read without decoding
/// the rest of the body. Empty for every other kind, and for a body whose
/// subject does not read: no reader takes a subject from it, and a door
/// judges it by its own id, as before.
pub(crate) fn person_content_subjects(raw: &[u8]) -> Vec<EntityId> {
    let Some(header) = EntityMetadataHeader::parse(raw) else {
        return Vec::new();
    };
    let body = raw.get(ENTITY_METADATA_HEADER_LEN..).unwrap_or_default();
    match header.entity_type {
        ENTITY_TYPE_CLAIM => match body_entry(body, KEY_SUBJ) {
            Some(ValueRef::Binary(bytes)) => match ClaimSubject::decode(bytes) {
                Ok(ClaimSubject::Entity(subject)) => vec![subject],
                Ok(ClaimSubject::Edge { source, target, .. }) => vec![source, target],
                Err(_) => Vec::new(),
            },
            _ => Vec::new(),
        },
        ENTITY_TYPE_PSYCH_PROFILE => body_entity_ref(body, PSYCH_PROFILE_SUBJECT_REF),
        ENTITY_TYPE_PERSONA_SNAPSHOT_EXPORT => body_entity_ref(body, PERSONA_SUBJECT_REF),
        ENTITY_TYPE_FACET => crate::companion::scenario_mask_person(body)
            .into_iter()
            .collect(),
        _ => Vec::new(),
    }
}

/// The value under `key` in `body`, a stored MessagePack map, read in place;
/// `None` when the body is no map or names no such key.
fn body_entry<'a>(body: &'a [u8], key: &str) -> Option<ValueRef<'a>> {
    let mut cursor = body;
    let ValueRef::Map(entries) = rmpv::decode::read_value_ref(&mut cursor).ok()? else {
        return None;
    };
    entries.into_iter().find_map(|(name, value)| match name {
        ValueRef::String(name) if name.as_str() == Some(key) => Some(value),
        _ => None,
    })
}

/// The record a hex id string under `key` in `body` names, as the profile
/// and persona codecs write `subjectRef`.
fn body_entity_ref(body: &[u8], key: &str) -> Vec<EntityId> {
    match body_entry(body, key) {
        Some(ValueRef::String(text)) => text
            .as_str()
            .and_then(|text| EntityId::from_hex(text).ok())
            .into_iter()
            .collect(),
        _ => Vec::new(),
    }
}
