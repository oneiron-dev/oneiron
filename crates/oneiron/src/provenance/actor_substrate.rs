//! Actor-class validation, legacy evidence transition, and model substrate codec.

use super::EdgeProvenanceClaimBody;
use crate::edge::EdgeActorClass;
use crate::error::{ClaimError, Error, Result};
use crate::registry::{ENTITY_TYPE_AGENT_DEF, ENTITY_TYPE_MACHINE, ENTITY_TYPE_PERSON};
use rmpv::Value;

/// Validates a CALLER-SUPPLIED `actor_class` against the actor entity's
/// kind (D13): PERSON (4) admits `{human=0, agent=1}` — users and AI agents
/// share one table (ARCH-0002), so PERSON alone cannot distinguish them;
/// MACHINE (82) admits `{system=2}`; AGENT_DEF (17) admits `{agent=1}` — a
/// dispatched agent's substantive writes carry its definition's entity id as
/// the envelope actor (N1 resolution 2026-07-10; milestone bookkeeping rides
/// the system/Dreamer envelope instead); every other kind is rejected with
/// [`ClaimError::ActorClassMismatch`](crate::error::ClaimError::ActorClassMismatch). NEVER defaults.
pub fn validate_actor_class(actor_entity_type: u8, actor_class: EdgeActorClass) -> Result<()> {
    let allowed = match actor_entity_type {
        ENTITY_TYPE_PERSON => matches!(actor_class, EdgeActorClass::Human | EdgeActorClass::Agent),
        ENTITY_TYPE_MACHINE => matches!(actor_class, EdgeActorClass::System),
        ENTITY_TYPE_AGENT_DEF => matches!(actor_class, EdgeActorClass::Agent),
        _ => false,
    };
    if allowed {
        Ok(())
    } else {
        Err(Error::Claim(ClaimError::ActorClassMismatch {
            actor_entity_type,
            actor_class: actor_class as u8,
        }))
    }
}

/// LEGACY engine-internal `evid` key that persisted the WRITE-TIME validated
/// `actor_class` on the wrapping Claim BEFORE the ONE-1138 vocabulary bump
/// (see the module docs' "Persisted actor_class" section). Pre-bump claims
/// carrying it still decode; writers now write the `actor_class` BODY key
/// only and leave `evid` to evidence purity.
pub(crate) const EVIDENCE_KEY_ACTOR_CLASS: &str = "actor_class";

/// Encodes the LEGACY persisted actor-class evidence: the engine-owned
/// MessagePack map `{"actor_class": u8}` stored in the wrapping Claim's
/// `evid` field by pre-ONE-1138 writers. Kept so tests can fabricate
/// pre-bump claims; production writers no longer call it.
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "legacy pre-ONE-1138 codec kept for fabricating pre-bump claims in tests"
    )
)]
pub(crate) fn encode_actor_class_evidence(actor_class: EdgeActorClass) -> Value {
    Value::Map(vec![(
        Value::from(EVIDENCE_KEY_ACTOR_CLASS),
        Value::from(actor_class as u8),
    )])
}

/// Decodes the persisted actor-class evidence fail-closed: the value must be
/// exactly the engine-owned map `{"actor_class": u8 <= 2}`. A provenance
/// Claim without it cannot participate in flag refresh — typed error, never
/// a defaulted class (D13).
pub(crate) fn decode_actor_class_evidence(evidence: Option<&Value>) -> Result<EdgeActorClass> {
    let Some(Value::Map(entries)) = evidence else {
        return Err(Error::Claim(ClaimError::InvalidProvenanceBody(
            "provenance claim is missing its persisted actor_class evidence",
        )));
    };
    let mut actor_class: Option<EdgeActorClass> = None;
    for (key, value) in entries {
        if key.as_str() != Some(EVIDENCE_KEY_ACTOR_CLASS) {
            return Err(Error::Claim(ClaimError::InvalidProvenanceBody(
                "unknown key in provenance actor_class evidence",
            )));
        }
        if actor_class.is_some() {
            return Err(Error::Claim(ClaimError::InvalidProvenanceBody(
                "duplicate actor_class evidence key",
            )));
        }
        let parsed = value
            .as_u64()
            .and_then(|raw| u8::try_from(raw).ok())
            .and_then(actor_class_from_u8)
            .ok_or(Error::Claim(ClaimError::InvalidProvenanceBody(
                "actor_class evidence must be an integer u8 <= 2",
            )))?;
        actor_class = Some(parsed);
    }
    actor_class.ok_or(Error::Claim(ClaimError::InvalidProvenanceBody(
        "provenance claim is missing its persisted actor_class evidence",
    )))
}

pub(super) fn actor_class_from_u8(value: u8) -> Option<EdgeActorClass> {
    match value {
        0 => Some(EdgeActorClass::Human),
        1 => Some(EdgeActorClass::Agent),
        2 => Some(EdgeActorClass::System),
        _ => None,
    }
}

/// Resolves the persisted write-time `actor_class` of a stored
/// `edge.provenance` Claim under the pinned ONE-1138 transition semantics:
///
/// * NEW shape — `actor_class` in the value record body, wrapper `evid`
///   absent → the body value wins;
/// * LEGACY shape (pre-bump, never invalidated) — body key absent, the
///   engine-owned `{"actor_class": u8}` map on the wrapper's `evid` →
///   decoded via the unchanged legacy codec;
/// * BOTH places → ambiguous, fails closed
///   ([`ClaimError::InvalidProvenanceBody`](crate::error::ClaimError::InvalidProvenanceBody)) — two sources of truth for a flag
///   refresh are never reconciled silently;
/// * NEITHER place → fails closed the same way — a provenance Claim without
///   a persisted class cannot participate in flag refresh; the class is
///   never defaulted (D13).
pub(crate) fn resolve_persisted_actor_class(
    record: &EdgeProvenanceClaimBody,
    evidence: Option<&Value>,
) -> Result<EdgeActorClass> {
    match (record.actor_class, evidence) {
        (Some(_), Some(_)) => Err(Error::Claim(ClaimError::InvalidProvenanceBody(
            "actor_class present in both the value record and the wrapper evid (ambiguous)",
        ))),
        (Some(class), None) => Ok(class),
        (None, evidence) => decode_actor_class_evidence(evidence),
    }
}

/// MessagePack body key for a MODEL entity's model name (ONE-1138).
const MODEL_BODY_KEY_NAME: &str = "name";

/// MessagePack body key for a MODEL entity's model version (ONE-1138).
const MODEL_BODY_KEY_VERSION: &str = "version";

/// Maximum byte length of a MODEL entity's `name` / `version` string.
pub const MODEL_SUBSTRATE_FIELD_MAX_BYTES: usize = 256;

/// Validates one MODEL substrate descriptor string (`name` / `version`):
/// non-empty UTF-8, at most [`MODEL_SUBSTRATE_FIELD_MAX_BYTES`] bytes.
pub(super) fn validate_model_substrate_field(value: &str, context: &'static str) -> Result<()> {
    if value.is_empty() || value.len() > MODEL_SUBSTRATE_FIELD_MAX_BYTES {
        return Err(Error::Claim(ClaimError::InvalidModelSubstrate(context)));
    }
    Ok(())
}

/// Encodes the engine-authored MODEL entity body (type byte 121): the
/// MessagePack map `{"name": str, "version": str}`. Model name + version
/// live ON the MODEL entity so provenance records dedup to a 16-byte
/// `substrate_ref` instead of inlining them per write (ONE-1138).
pub(super) fn encode_model_entity_body(name: &str, version: &str) -> Result<Vec<u8>> {
    validate_model_substrate_field(name, "model name must be non-empty and at most 256 bytes")?;
    validate_model_substrate_field(
        version,
        "model version must be non-empty and at most 256 bytes",
    )?;
    let value = Value::Map(vec![
        (Value::from(MODEL_BODY_KEY_NAME), Value::from(name)),
        (Value::from(MODEL_BODY_KEY_VERSION), Value::from(version)),
    ]);
    let mut out = Vec::new();
    rmpv::encode::write_value(&mut out, &value)
        .map_err(|_| Error::InvariantViolation("model entity body MessagePack encode failed"))?;
    Ok(out)
}

/// Decodes a stored MODEL entity body fail-closed: exactly one MessagePack
/// map (no trailing bytes) carrying exactly the `name` + `version` string
/// keys, both passing [`validate_model_substrate_field`]. MODEL entities are
/// engine-authored, so a body that fails this decode is on-disk corruption.
pub(crate) fn decode_model_entity_body(bytes: &[u8]) -> Result<(String, String)> {
    let mut cursor = bytes;
    let value = rmpv::decode::read_value(&mut cursor)
        .map_err(|_| Error::CorruptedIndex("model entity body"))?;
    if !cursor.is_empty() {
        return Err(Error::CorruptedIndex("model entity body"));
    }
    let Value::Map(entries) = value else {
        return Err(Error::CorruptedIndex("model entity body"));
    };
    let mut name: Option<String> = None;
    let mut version: Option<String> = None;
    for (key, value) in &entries {
        let slot = match key.as_str() {
            Some(MODEL_BODY_KEY_NAME) => &mut name,
            Some(MODEL_BODY_KEY_VERSION) => &mut version,
            _ => return Err(Error::CorruptedIndex("model entity body")),
        };
        if slot.is_some() {
            return Err(Error::CorruptedIndex("model entity body"));
        }
        let text = value
            .as_str()
            .ok_or(Error::CorruptedIndex("model entity body"))?;
        if text.is_empty() || text.len() > MODEL_SUBSTRATE_FIELD_MAX_BYTES {
            return Err(Error::CorruptedIndex("model entity body"));
        }
        *slot = Some(text.to_owned());
    }
    match (name, version) {
        (Some(name), Some(version)) => Ok((name, version)),
        _ => Err(Error::CorruptedIndex("model entity body")),
    }
}
