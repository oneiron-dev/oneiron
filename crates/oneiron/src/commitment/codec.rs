//! Commitment claim codec: candidate builders and closed-schema helpers.

use rmpv::Value;

use crate::claim::{ClaimBody, ClaimLifecycleStatus, ClaimSubject};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::write_envelope::ClaimCandidate;

use super::types::{
    COMMITMENT_BIRTH_PROVENANCE_KEYS, COMMITMENT_CLAIM_PREDICATES, COMMITMENT_CONTENT_KEYS,
    COMMITMENT_OBLIGOR_KEYS, COMMITMENT_VALUE_KEYS, COMMITMENT_VALUE_SCHEMA_VERSION,
    CommitmentBirthKind, CommitmentBirthProvenance, CommitmentContent, CommitmentObligor,
    CommitmentObligorKind, CommitmentRecord, CommitmentStatus, CommitmentStrength, KEY_BENEFICIARY,
    KEY_BIRTH_KIND, KEY_BIRTH_PROVENANCE, KEY_BIRTH_REFERENCE, KEY_CONTENT,
    KEY_CONTENT_PAYLOAD_REF, KEY_CONTENT_TEXT, KEY_OBLIGOR, KEY_OBLIGOR_ENTITY_REF,
    KEY_OBLIGOR_KIND, KEY_SCHEDULE, KEY_SCHEMA_VERSION, KEY_STATUS, KEY_STRENGTH,
    PREDICATE_COMMITMENT_RECORD,
};

/// Returns whether `predicate` belongs to the commitment claim family.
#[must_use]
pub fn is_commitment_claim_predicate(predicate: &str) -> bool {
    COMMITMENT_CLAIM_PREDICATES.contains(&predicate)
}

/// Builds a typed `commitment.record` claim candidate for the obligor entity.
pub fn commitment_claim_candidate(record: &CommitmentRecord) -> Result<ClaimCandidate> {
    if record.status != CommitmentStatus::Open {
        return Err(Error::InvalidClaimBody(
            "commitment candidate must be open at birth",
        ));
    }
    commitment_claim_candidate_with_confidence(record, 1.0)
}

/// Encodes a commitment record value in canonical MessagePack field order.
pub fn encode_commitment_value(record: &CommitmentRecord) -> Result<Value> {
    record.validate()?;
    Ok(Value::Map(vec![
        (
            Value::from(KEY_SCHEMA_VERSION),
            Value::from(COMMITMENT_VALUE_SCHEMA_VERSION),
        ),
        (Value::from(KEY_OBLIGOR), encode_obligor(record.obligor)),
        (
            Value::from(KEY_BENEFICIARY),
            Value::from(record.beneficiary.to_hex()),
        ),
        (Value::from(KEY_CONTENT), encode_content(&record.content)),
        (Value::from(KEY_SCHEDULE), record.schedule.clone()),
        (
            Value::from(KEY_STRENGTH),
            Value::from(record.strength.as_str()),
        ),
        (Value::from(KEY_STATUS), Value::from(record.status.as_str())),
        (
            Value::from(KEY_BIRTH_PROVENANCE),
            encode_birth_provenance(&record.birth_provenance),
        ),
    ]))
}

/// Decodes and validates a `commitment.record` value.
pub fn decode_commitment_value(value: &Value) -> Result<CommitmentRecord> {
    let Value::Map(entries) = value else {
        return Err(invalid_commitment_value());
    };
    validate_keys(entries, &COMMITMENT_VALUE_KEYS)?;

    if required_value(entries, KEY_SCHEMA_VERSION)?.as_u64()
        != Some(COMMITMENT_VALUE_SCHEMA_VERSION)
    {
        return Err(invalid_commitment_value());
    }

    let obligor = decode_obligor(required_value(entries, KEY_OBLIGOR)?)?;
    let beneficiary = decode_entity_ref(required_value(entries, KEY_BENEFICIARY)?)?;
    let content = decode_content(required_value(entries, KEY_CONTENT)?)?;
    let schedule = required_value(entries, KEY_SCHEDULE)?.clone();
    let strength = CommitmentStrength::parse(required_string(entries, KEY_STRENGTH)?)
        .ok_or_else(invalid_commitment_value)?;
    let status = CommitmentStatus::parse(required_string(entries, KEY_STATUS)?)
        .ok_or_else(invalid_commitment_value)?;
    let birth_provenance = decode_birth_provenance(required_value(entries, KEY_BIRTH_PROVENANCE)?)?;
    let record = CommitmentRecord {
        obligor,
        beneficiary,
        content,
        schedule,
        strength,
        status,
        birth_provenance,
    };
    record.validate()?;
    Ok(record)
}

/// Decodes a claim body as a commitment when its predicate belongs to this
/// family. Other predicates return `Ok(None)`.
pub fn decode_commitment_claim(body: &ClaimBody) -> Result<Option<CommitmentRecord>> {
    if !is_commitment_claim_predicate(&body.predicate) {
        return Ok(None);
    }
    validate_commitment_claim_structure(body)?;
    decode_commitment_value(&body.value).map(Some)
}

/// Validates one `commitment.*` claim body.
pub(crate) fn validate_commitment_claim_structure(body: &ClaimBody) -> Result<()> {
    if !is_commitment_claim_predicate(&body.predicate) {
        return Err(Error::InvalidClaimBody(
            "unknown commitment claim predicate",
        ));
    }
    let ClaimSubject::Entity(subject) = body.subject else {
        return Err(Error::InvalidClaimBody(
            "commitment claim subject must be an entity",
        ));
    };
    let (Some(valid_from), Some(valid_to)) = (body.valid_from, body.valid_to) else {
        return Err(Error::InvalidClaimBody(
            "commitment claim must carry valid-time from/to",
        ));
    };
    if body.lifecycle == ClaimLifecycleStatus::Active && valid_to < valid_from {
        return Err(Error::InvalidClaimBody(
            "commitment claim valid-time is inverted",
        ));
    }
    let record = decode_commitment_value(&body.value)?;
    if subject != record.obligor.entity_ref {
        return Err(Error::InvalidClaimBody(
            "commitment claim subject must match obligor entity_ref",
        ));
    }
    Ok(())
}

fn commitment_claim_candidate_with_confidence(
    record: &CommitmentRecord,
    confidence: f32,
) -> Result<ClaimCandidate> {
    Ok(ClaimCandidate::new(
        PREDICATE_COMMITMENT_RECORD,
        ClaimSubject::Entity(record.obligor.entity_ref),
        encode_commitment_value(record)?,
        confidence,
    ))
}

pub(super) fn commitment_claim_candidate_from_body(
    body: &ClaimBody,
    record: &CommitmentRecord,
) -> Result<ClaimCandidate> {
    let mut candidate = commitment_claim_candidate_with_confidence(record, body.confidence)?
        .with_validity(body.valid_from, body.valid_to);
    if let Some(salience) = body.salience {
        candidate = candidate.with_salience(salience);
    }
    if let Some(world) = body.world {
        candidate = candidate.with_world(world);
    }
    if let Some(scope) = &body.scope {
        candidate = candidate.with_scope(scope.clone());
    }
    if body.stale {
        candidate = candidate.with_stale(true);
    }
    Ok(candidate)
}

fn encode_obligor(obligor: CommitmentObligor) -> Value {
    Value::Map(vec![
        (
            Value::from(KEY_OBLIGOR_KIND),
            Value::from(obligor.kind.as_str()),
        ),
        (
            Value::from(KEY_OBLIGOR_ENTITY_REF),
            Value::from(obligor.entity_ref.to_hex()),
        ),
    ])
}

fn decode_obligor(value: &Value) -> Result<CommitmentObligor> {
    let Value::Map(entries) = value else {
        return Err(invalid_commitment_value());
    };
    validate_keys(entries, &COMMITMENT_OBLIGOR_KEYS)?;
    let kind = CommitmentObligorKind::parse(required_string(entries, KEY_OBLIGOR_KIND)?)
        .ok_or_else(invalid_commitment_value)?;
    let entity_ref = decode_entity_ref(required_value(entries, KEY_OBLIGOR_ENTITY_REF)?)?;
    Ok(CommitmentObligor { kind, entity_ref })
}

fn encode_content(content: &CommitmentContent) -> Value {
    Value::Map(vec![
        (
            Value::from(KEY_CONTENT_TEXT),
            Value::from(content.text.as_str()),
        ),
        (
            Value::from(KEY_CONTENT_PAYLOAD_REF),
            content
                .payload_ref
                .as_deref()
                .map_or(Value::Nil, Value::from),
        ),
    ])
}

fn decode_content(value: &Value) -> Result<CommitmentContent> {
    let Value::Map(entries) = value else {
        return Err(invalid_commitment_value());
    };
    validate_keys(entries, &COMMITMENT_CONTENT_KEYS)?;
    let text = required_string(entries, KEY_CONTENT_TEXT)?.to_owned();
    let payload_ref_value = required_value(entries, KEY_CONTENT_PAYLOAD_REF)?;
    let payload_ref = if matches!(payload_ref_value, Value::Nil) {
        None
    } else {
        Some(
            payload_ref_value
                .as_str()
                .ok_or_else(invalid_commitment_value)?
                .to_owned(),
        )
    };
    CommitmentContent::new(text, payload_ref)
}

fn encode_birth_provenance(birth: &CommitmentBirthProvenance) -> Value {
    Value::Map(vec![
        (
            Value::from(KEY_BIRTH_KIND),
            Value::from(birth.kind.as_str()),
        ),
        (
            Value::from(KEY_BIRTH_REFERENCE),
            Value::from(birth.reference.as_str()),
        ),
    ])
}

fn decode_birth_provenance(value: &Value) -> Result<CommitmentBirthProvenance> {
    let Value::Map(entries) = value else {
        return Err(invalid_commitment_value());
    };
    validate_keys(entries, &COMMITMENT_BIRTH_PROVENANCE_KEYS)?;
    let kind = CommitmentBirthKind::parse(required_string(entries, KEY_BIRTH_KIND)?)
        .ok_or_else(invalid_commitment_value)?;
    CommitmentBirthProvenance::new(kind, required_string(entries, KEY_BIRTH_REFERENCE)?)
}

fn decode_entity_ref(value: &Value) -> Result<EntityId> {
    value
        .as_str()
        .ok_or_else(invalid_commitment_value)
        .and_then(|hex| EntityId::from_hex(hex).map_err(|_| invalid_commitment_value()))
}

fn required_value<'a>(entries: &'a [(Value, Value)], key: &str) -> Result<&'a Value> {
    entries
        .iter()
        .find_map(|(candidate, value)| (candidate.as_str() == Some(key)).then_some(value))
        .ok_or_else(invalid_commitment_value)
}

fn required_string<'a>(entries: &'a [(Value, Value)], key: &str) -> Result<&'a str> {
    required_value(entries, key)?
        .as_str()
        .ok_or_else(invalid_commitment_value)
}

fn validate_keys(entries: &[(Value, Value)], keys: &[&str]) -> Result<()> {
    let mut seen = vec![false; keys.len()];
    for (key, _) in entries {
        let key = key.as_str().ok_or_else(invalid_commitment_value)?;
        let Some(index) = keys.iter().position(|known| *known == key) else {
            return Err(invalid_commitment_value());
        };
        if seen[index] {
            return Err(invalid_commitment_value());
        }
        seen[index] = true;
    }
    if seen.into_iter().all(|value| value) {
        Ok(())
    } else {
        Err(invalid_commitment_value())
    }
}

pub(super) fn validate_non_empty_bounded(
    value: &str,
    max_bytes: usize,
    reason: &'static str,
) -> Result<()> {
    if value.trim().is_empty() || value.len() > max_bytes {
        Err(Error::InvalidClaimBody(reason))
    } else {
        Ok(())
    }
}

fn invalid_commitment_value() -> Error {
    Error::InvalidClaimBody("commitment record value failed validation")
}
