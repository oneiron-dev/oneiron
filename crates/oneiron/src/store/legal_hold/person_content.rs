//! The rows whose content is about a PERSON: the whole-vault export keeps
//! each out with a PERSON it keeps out (Engine ANSWER
//! WITHHELD-PERSON-CONTENT-RULE, 20 Nov). A legal hold keeps no PERSON
//! after a privacy erase (LEGAL-HOLD-USE = B), so no read door limits such
//! content for a hold.

use rmpv::ValueRef;

use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::claim::ClaimSubject;
use crate::entity_id::EntityId;
use crate::registry::{
    ENTITY_TYPE_CLAIM, ENTITY_TYPE_FACET, ENTITY_TYPE_PERSONA_SNAPSHOT_EXPORT,
    ENTITY_TYPE_PSYCH_PROFILE,
};
use crate::store::persona_snapshot_record::KEY_SUBJECT_REF as PERSONA_SUBJECT_REF;
use crate::write_envelope::claim_body::KEY_SUBJ;
use crate::write_envelope::profile_snapshot::record::KEY_SUBJECT_REF as PSYCH_PROFILE_SUBJECT_REF;

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
