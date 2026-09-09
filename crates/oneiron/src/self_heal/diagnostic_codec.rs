//! MessagePack codec and validators for diagnostic event bodies, refs, and tokens.

use std::io::Cursor;

use rmpv::Value;

use super::admission::validate_detector_id;
use super::event::{
    DIAGNOSTIC_ACTOR_CLASSES, DIAGNOSTIC_BODY_KEYS, DIAGNOSTIC_SCHEMA_VERSION,
    DiagnosticCriticality, DiagnosticEvent, DiagnosticEventClass, DiagnosticReplayCoordinate,
    DiagnosticSourceKind, MAX_EVIDENCE_REFS, MAX_REF_LEN, MAX_TOKEN_LEN, invalid_diagnostic,
};
use super::invariant_canonical::{canonical_invariant_field, canonical_invariant_value};
use super::untrusted_text::{
    canonical_untrusted_detail, is_forbidden_text_scalar, validate_untrusted_detail,
};
use crate::entity_id::{EntityId, bytes_to_hex_lower};
use crate::error::{Error, Result};

/// Canonicalizes and encodes one DIAGNOSTIC body from a RAW draft.
///
/// Canonicalization is what makes determinism a property of the DATA rather
/// than of detector discipline: invariant values are rebuilt into one normal
/// form, evidence refs are sorted and deduplicated, and the untrusted leaf is
/// escaped. Two detectors that mean the same thing therefore emit the same
/// bytes and the same id.
///
/// `event.untrusted_detail` is read as RAW author text here, so this door must
/// only ever see a draft. Re-encoding an event that came back out of
/// [`decode_diagnostic_event_body`] belongs to the engine-internal stored-body
/// door instead: its leaf is already the stored canonical one, and escaping it
/// a second time would change the body.
pub fn encode_diagnostic_event_body(event: &DiagnosticEvent) -> Result<Vec<u8>> {
    let untrusted_detail = match event.untrusted_detail.as_deref() {
        Some(raw) => Value::from(canonical_untrusted_detail(raw)?),
        None => Value::Nil,
    };
    encode_body_with_detail(event, untrusted_detail)
}

/// Re-encodes an event whose untrusted leaf is ALREADY the stored canonical
/// one, i.e. one that came out of [`decode_diagnostic_event_body`].
///
/// The leaf is re-validated rather than re-escaped, which is what makes the
/// canonical form a fixed point of decode + re-encode even though
/// [`canonical_untrusted_detail`] is deliberately not idempotent.
pub(super) fn encode_stored_diagnostic_event_body(event: &DiagnosticEvent) -> Result<Vec<u8>> {
    let untrusted_detail = match event.untrusted_detail.as_deref() {
        Some(stored) => {
            validate_untrusted_detail(stored)?;
            Value::from(stored)
        }
        None => Value::Nil,
    };
    encode_body_with_detail(event, untrusted_detail)
}

/// Builds and writes the pinned 17-key body around an already-decided
/// `untrusted_detail` leaf, so the raw door and the stored door cannot drift
/// apart in any other field.
fn encode_body_with_detail(event: &DiagnosticEvent, untrusted_detail: Value) -> Result<Vec<u8>> {
    validate_detector_id(&event.detector_id)?;
    validate_actor_class(&event.actor_class)?;
    validate_validity(event.valid_from, event.valid_to)?;
    let run_ref = canonical_optional_ref(event.replay.run_ref.as_deref())?;
    let checkpoint_ref = canonical_optional_ref(event.replay.checkpoint_ref.as_deref())?;

    let mut evidence_refs = event.evidence_refs.clone();
    evidence_refs.sort_unstable();
    evidence_refs.dedup();
    if evidence_refs.len() > MAX_EVIDENCE_REFS {
        return Err(invalid_diagnostic("too many evidence refs"));
    }
    let evidence: Vec<Value> = evidence_refs.iter().map(entity_ref_value).collect();

    let values = [
        Value::from(DIAGNOSTIC_SCHEMA_VERSION),
        Value::from(event.detector_id.as_str()),
        Value::from(event.event_class.as_str()),
        Value::from(event.actor_class.as_str()),
        event
            .actor_ref
            .as_ref()
            .map_or(Value::Nil, entity_ref_value),
        Value::from(event.source.as_str()),
        Value::from(event.criticality.as_str()),
        canonical_invariant_value(&event.expected)?,
        canonical_invariant_value(&event.actual)?,
        canonical_invariant_value(&event.delta)?,
        Value::from(bytes_to_hex_lower(&event.replay.content_hash)),
        run_ref,
        checkpoint_ref,
        Value::Array(evidence),
        untrusted_detail,
        Value::from(event.valid_from),
        event.valid_to.map_or(Value::Nil, Value::from),
    ];

    let map = Value::Map(
        DIAGNOSTIC_BODY_KEYS
            .iter()
            .zip(values)
            .map(|(key, value)| (Value::from(*key), value))
            .collect(),
    );
    let mut out = Vec::new();
    rmpv::encode::write_value(&mut out, &map)
        .map_err(|_| Error::InvariantViolation("diagnostic body encode failed"))?;
    Ok(out)
}

/// Decodes and fully validates one DIAGNOSTIC body.
///
/// Fails closed on an unknown, missing or duplicate key, trailing bytes, an
/// invalid enum string, a malformed ref or content hash, non-monotonic
/// validity, a non-canonical invariant value or evidence-ref order, and control
/// data hidden in the untrusted leaf.
pub fn decode_diagnostic_event_body(bytes: &[u8]) -> Result<DiagnosticEvent> {
    let mut cursor = Cursor::new(bytes);
    let Ok(value) = rmpv::decode::read_value(&mut cursor) else {
        return Err(invalid_diagnostic("body is not MessagePack"));
    };
    if cursor.position() != bytes.len() as u64 {
        return Err(invalid_diagnostic("trailing bytes after body map"));
    }
    let Value::Map(entries) = &value else {
        return Err(invalid_diagnostic("body must be a MessagePack map"));
    };
    validate_keys(entries)?;

    if required(entries, "schema_version")?.as_u64() != Some(DIAGNOSTIC_SCHEMA_VERSION) {
        return Err(invalid_diagnostic("unsupported schema version"));
    }

    let detector_id = required_str(entries, "detector_id")?;
    validate_detector_id(detector_id)?;
    let event_class = DiagnosticEventClass::from_wire(required_str(entries, "event_class")?)
        .ok_or_else(|| invalid_diagnostic("unknown event class"))?;
    let source = DiagnosticSourceKind::from_wire(required_str(entries, "source")?)
        .ok_or_else(|| invalid_diagnostic("unknown source kind"))?;
    let criticality = DiagnosticCriticality::from_wire(required_str(entries, "criticality")?)
        .ok_or_else(|| invalid_diagnostic("unknown criticality"))?;

    let actor_class = required_str(entries, "actor_class")?.to_owned();
    validate_actor_class(&actor_class)?;

    let from_value = required(entries, "valid_from")?;
    let valid_from = decode_u64(from_value, "valid_from must be an integer")?;
    let valid_to = match required(entries, "valid_to")? {
        Value::Nil => None,
        other => Some(decode_u64(other, "valid_to must be an integer")?),
    };
    validate_validity(valid_from, valid_to)?;

    let untrusted_detail = match required(entries, "untrusted_detail")? {
        Value::Nil => None,
        other => {
            let text = decode_str(other, "untrusted_detail must be a string")?;
            validate_untrusted_detail(text)?;
            Some(text.to_owned())
        }
    };

    Ok(DiagnosticEvent {
        detector_id: detector_id.to_owned(),
        event_class,
        actor_class,
        actor_ref: decode_optional_entity_ref(required(entries, "actor_ref")?)?,
        source,
        criticality,
        expected: canonical_invariant_field(required(entries, "expected")?)?,
        actual: canonical_invariant_field(required(entries, "actual")?)?,
        delta: canonical_invariant_field(required(entries, "delta")?)?,
        replay: DiagnosticReplayCoordinate {
            content_hash: decode_content_hash(required(entries, "replay_content_hash")?)?,
            run_ref: decode_optional_ref(required(entries, "replay_run_ref")?)?,
            checkpoint_ref: decode_optional_ref(required(entries, "replay_checkpoint_ref")?)?,
        },
        evidence_refs: decode_evidence_refs(required(entries, "evidence_refs")?)?,
        untrusted_detail,
        valid_from,
        valid_to,
    })
}

/// Fail-closed body validation for the DIAGNOSTIC write door.
///
/// Decoding is necessary but NOT sufficient: the grammar above constrains the
/// VALUES, while a content-addressed body has to be pinned down to its exact
/// BYTES. So the decoded event is re-encoded and the result must equal the
/// input byte for byte. That closes the whole class of spellings that mean the
/// same thing on the wire — an alternate MessagePack marker for a value that
/// has a shorter one, or any residual re-arrangement — because such a body
/// would decode fine and then re-encode to different bytes than it arrived as.
///
/// Failing closed here is what keeps `(detector_id, canonical body)` a real
/// address: no writer, local or replicated, can store two byte strings that
/// carry one event, and no stored byte string can be one an honest re-encode
/// would not have produced.
pub(super) fn validate_diagnostic_event_body_bytes(bytes: &[u8]) -> Result<DiagnosticEvent> {
    let event = decode_diagnostic_event_body(bytes)?;
    if encode_stored_diagnostic_event_body(&event)?.as_slice() != bytes {
        return Err(invalid_diagnostic("body is not canonically encoded"));
    }
    Ok(event)
}

// ── body-field validation ───────────────────────────────────────────────────

fn validate_actor_class(actor_class: &str) -> Result<()> {
    if DIAGNOSTIC_ACTOR_CLASSES.contains(&actor_class) {
        Ok(())
    } else {
        Err(invalid_diagnostic("actor_class outside Gate vocabulary"))
    }
}

fn validate_validity(valid_from: u64, valid_to: Option<u64>) -> Result<()> {
    if valid_to.is_some_and(|end| end <= valid_from) {
        return Err(invalid_diagnostic("valid_to must follow valid_from"));
    }
    Ok(())
}

fn validate_keys(entries: &[(Value, Value)]) -> Result<()> {
    let mut seen = [false; DIAGNOSTIC_BODY_KEYS.len()];
    for (position, (key, _)) in entries.iter().enumerate() {
        let key = decode_str(key, "body keys must be strings")?;
        let Some(index) = DIAGNOSTIC_BODY_KEYS.iter().position(|known| *known == key) else {
            return Err(invalid_diagnostic("unknown body key"));
        };
        if seen[index] {
            return Err(invalid_diagnostic("duplicate body key"));
        }
        // Key ORDER is part of the body, not a rendering of it: the pinned
        // array IS the encode order, so a map carrying the same 17 pairs in
        // any other order is a DIFFERENT byte string and must not decode as
        // this event. Checked here rather than repaired, for the same reason
        // invariant values are checked rather than normalized.
        if index != position {
            return Err(invalid_diagnostic("body keys are out of canonical order"));
        }
        seen[index] = true;
    }
    if seen.into_iter().all(|present| present) {
        Ok(())
    } else {
        Err(invalid_diagnostic("missing required body key"))
    }
}

fn required<'a>(entries: &'a [(Value, Value)], key: &str) -> Result<&'a Value> {
    entries
        .iter()
        .find_map(|(entry_key, value)| (entry_key.as_str() == Some(key)).then_some(value))
        .ok_or_else(|| invalid_diagnostic("missing required body key"))
}

fn required_str<'a>(entries: &'a [(Value, Value)], key: &str) -> Result<&'a str> {
    decode_str(required(entries, key)?, "body field must be a string")
}

pub(super) fn decode_str<'a>(value: &'a Value, reason: &'static str) -> Result<&'a str> {
    value.as_str().ok_or_else(|| invalid_diagnostic(reason))
}

fn decode_u64(value: &Value, reason: &'static str) -> Result<u64> {
    value.as_u64().ok_or_else(|| invalid_diagnostic(reason))
}

fn entity_ref_value(entity: &EntityId) -> Value {
    Value::from(entity.to_hex())
}

fn decode_entity_ref(value: &Value) -> Result<EntityId> {
    let hex = decode_str(value, "entity ref must be a hex string")?;
    // Lowercase-only, matching `hex_nibble` above and `EntityId::to_hex`, so
    // one id has exactly one spelling on the wire. `EntityId::from_hex` is
    // case-INSENSITIVE by design, which would otherwise let 2^32 spellings of
    // one ref decode to one event under different bytes and different ids.
    if hex.bytes().any(|byte| byte.is_ascii_uppercase()) {
        return Err(invalid_diagnostic("entity ref must be lowercase hex"));
    }
    EntityId::from_hex(hex).map_err(|_| invalid_diagnostic("malformed entity ref"))
}

fn decode_optional_entity_ref(value: &Value) -> Result<Option<EntityId>> {
    match value {
        Value::Nil => Ok(None),
        other => decode_entity_ref(other).map(Some),
    }
}

fn decode_content_hash(value: &Value) -> Result<[u8; 32]> {
    let hex = decode_str(value, "content hash must be a hex string")?;
    if hex.len() != 64 {
        return Err(invalid_diagnostic("content hash must be 32 bytes"));
    }
    let mut out = [0_u8; 32];
    let bytes = hex.as_bytes();
    for (index, slot) in out.iter_mut().enumerate() {
        let hi = hex_nibble(bytes[index * 2]);
        let lo = hex_nibble(bytes[index * 2 + 1]);
        let (Some(hi), Some(lo)) = (hi, lo) else {
            return Err(invalid_diagnostic("malformed content hash"));
        };
        *slot = (hi << 4) | lo;
    }
    Ok(out)
}

/// Lowercase-only, so one hash has exactly one spelling on the wire.
fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

fn decode_optional_ref(value: &Value) -> Result<Option<String>> {
    match value {
        Value::Nil => Ok(None),
        other => {
            let text = decode_str(other, "replay ref must be a string")?;
            validate_ref(text)?;
            Ok(Some(text.to_owned()))
        }
    }
}

fn decode_evidence_refs(value: &Value) -> Result<Vec<EntityId>> {
    let Value::Array(items) = value else {
        return Err(invalid_diagnostic("evidence_refs must be an array"));
    };
    if items.len() > MAX_EVIDENCE_REFS {
        return Err(invalid_diagnostic("too many evidence refs"));
    }
    let mut refs: Vec<EntityId> = Vec::with_capacity(items.len());
    for item in items {
        let entity = decode_entity_ref(item)?;
        // Canonical order is PART of the body, so a re-ordered or duplicated
        // list is a different body that must not decode as this one.
        if refs.last().is_some_and(|previous| *previous >= entity) {
            return Err(invalid_diagnostic("evidence_refs must ascend"));
        }
        refs.push(entity);
    }
    Ok(refs)
}

fn canonical_optional_ref(value: Option<&str>) -> Result<Value> {
    match value {
        None => Ok(Value::Nil),
        Some(text) => {
            validate_ref(text)?;
            Ok(Value::from(text))
        }
    }
}

pub(super) fn validate_ref(text: &str) -> Result<()> {
    if text.is_empty() || text.len() > MAX_REF_LEN {
        return Err(invalid_diagnostic("replay ref is empty or too long"));
    }
    if text.chars().any(is_forbidden_text_scalar) {
        return Err(invalid_diagnostic("replay ref carries control data"));
    }
    Ok(())
}

pub(super) fn validate_token(token: &str, reason: &'static str) -> Result<()> {
    if token.is_empty() || token.len() > MAX_TOKEN_LEN {
        return Err(Error::InvariantViolation(reason));
    }
    if !token.bytes().all(is_token_byte) {
        return Err(Error::InvariantViolation(reason));
    }
    Ok(())
}

fn is_token_byte(byte: u8) -> bool {
    byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_' || byte == b'.'
}
