//! MessagePack codec and validators for diagnostic event bodies, refs, and tokens.

use std::io::Cursor;

use rmpv::Value;

use super::admission::validate_detector_id;
use super::event::{
    DIAGNOSTIC_ACTOR_CLASSES, DIAGNOSTIC_BODY_KEYS, DIAGNOSTIC_SCHEMA_VERSION,
    AgentHealthSignal, DiagnosticCriticality, DiagnosticEvent, DiagnosticEventClass,
    DiagnosticReplayCoordinate,
    DiagnosticSourceKind, MAX_EVIDENCE_REFS, MAX_REF_LEN, MAX_TOKEN_LEN, invalid_diagnostic,
};
use super::invariant_canonical::{canonical_invariant_value, stored_invariant_field};
use super::untrusted_text::{is_forbidden_text_scalar, validate_untrusted_detail};
use crate::entity_id::{EntityId, bytes_to_hex_lower};
use crate::error::{Error, Result};

/// Canonicalizes and encodes one DIAGNOSTIC body.
///
/// Canonicalization is what makes determinism a property of the DATA rather
/// than of detector discipline: invariant values are rebuilt into one normal
/// form and evidence refs are sorted and deduplicated. Two detectors that mean
/// the same thing therefore emit the same bytes and the same id. Encoding an
/// event that came back out of [`decode_diagnostic_event_body`] reproduces its
/// stored bytes.
pub fn encode_diagnostic_event_body(event: &DiagnosticEvent) -> Result<Vec<u8>> {
    validate_detector_id(&event.detector_id)?;
    validate_actor_class(&event.actor_class)?;
    validate_validity(event.valid_from, event.valid_to)?;
    validate_signal(event.event_class, event.signal)?;
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
        event
            .signal
            .map_or(Value::Nil, |signal| Value::from(signal.as_str())),
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
        // The key stays in the pinned body; a diagnostic carries no free text.
        Value::Nil,
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
/// validity, a non-canonical invariant value, and a non-canonical
/// evidence-ref order.
///
/// A body stored before the owner ruling of 2026-10-14 (fix 6) may carry text
/// where its grammar allowed it: the `untrusted_detail` leaf, a string or
/// string-keyed map in `expected` / `actual` / `delta`, a replay ref that is
/// not an id. Decode checks that text against the grammar it was written
/// under and drops it (a text invariant reads as nil, a prose ref as none),
/// so an owner's stored diagnostics keep reading and no decoded event carries
/// text. The body and its id stay as stored. The write door refuses any such
/// body.
pub fn decode_diagnostic_event_body(bytes: &[u8]) -> Result<DiagnosticEvent> {
    decode_body(bytes).map(|decoded| decoded.event)
}

/// One decoded body, and whether decode dropped what only the grammar before
/// the owner ruling of 2026-10-14 allowed: text, or an invariant map.
struct DecodedBody {
    event: DiagnosticEvent,
    dropped_text: bool,
}

fn decode_body(bytes: &[u8]) -> Result<DecodedBody> {
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
    let signal = match required(entries, "signal")? {
        Value::Nil => None,
        stored => Some(
            AgentHealthSignal::from_wire(decode_str(stored, "signal must be a string")?)
                .ok_or_else(|| invalid_diagnostic("unknown agent-health signal"))?,
        ),
    };
    validate_signal(event_class, signal)?;
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

    let mut dropped_text = match required(entries, "untrusted_detail")? {
        Value::Nil => false,
        stored => {
            validate_untrusted_detail(decode_str(stored, "untrusted_detail must be a string")?)?;
            true
        }
    };
    let expected = decode_stored_invariant(required(entries, "expected")?, &mut dropped_text)?;
    let actual = decode_stored_invariant(required(entries, "actual")?, &mut dropped_text)?;
    let delta = decode_stored_invariant(required(entries, "delta")?, &mut dropped_text)?;
    let run_ref = decode_stored_ref(required(entries, "replay_run_ref")?, &mut dropped_text)?;
    let checkpoint_ref = decode_stored_ref(
        required(entries, "replay_checkpoint_ref")?,
        &mut dropped_text,
    )?;

    Ok(DecodedBody {
        event: DiagnosticEvent {
            detector_id: detector_id.to_owned(),
            event_class,
            signal,
            actor_class,
            actor_ref: decode_optional_entity_ref(required(entries, "actor_ref")?)?,
            source,
            criticality,
            expected,
            actual,
            delta,
            replay: DiagnosticReplayCoordinate {
                content_hash: decode_content_hash(required(entries, "replay_content_hash")?)?,
                run_ref,
                checkpoint_ref,
            },
            evidence_refs: decode_evidence_refs(required(entries, "evidence_refs")?)?,
            valid_from,
            valid_to,
        },
        dropped_text,
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
/// would not have produced. A body carrying the text decode drops (see
/// [`decode_diagnostic_event_body`]) is refused here: no new row carries text.
pub(super) fn validate_diagnostic_event_body_bytes(bytes: &[u8]) -> Result<DiagnosticEvent> {
    let decoded = decode_body(bytes)?;
    if decoded.dropped_text {
        return Err(invalid_diagnostic("a diagnostic carries no free text"));
    }
    canonical_bytes(decoded.event, bytes)
}

/// The same check for a body already stored, which a reader re-validates.
///
/// A body stored before the owner ruling of 2026-10-14 reads with its text
/// dropped, so it cannot re-encode to its own bytes; the write door of its
/// day admitted those bytes, and the id still binds them (see
/// `stored_diagnostic_event`). Any other body must re-encode exactly.
pub(super) fn validate_stored_diagnostic_event_body_bytes(bytes: &[u8]) -> Result<DiagnosticEvent> {
    let decoded = decode_body(bytes)?;
    if decoded.dropped_text {
        return Ok(decoded.event);
    }
    canonical_bytes(decoded.event, bytes)
}

fn canonical_bytes(event: DiagnosticEvent, bytes: &[u8]) -> Result<DiagnosticEvent> {
    if encode_diagnostic_event_body(&event)?.as_slice() != bytes {
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

/// An agent-health body names exactly one signal; every other body none.
fn validate_signal(class: DiagnosticEventClass, signal: Option<AgentHealthSignal>) -> Result<()> {
    if (class == DiagnosticEventClass::AgentHealth) == signal.is_some() {
        Ok(())
    } else {
        Err(invalid_diagnostic("a signal rides exactly the agent-health class"))
    }
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
        // array IS the encode order, so a map carrying the same 18 pairs in
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

/// A stored invariant value; text a body stored before the owner ruling of
/// 2026-10-14 carried reads as nil, and sets `dropped_text`.
fn decode_stored_invariant(value: &Value, dropped_text: &mut bool) -> Result<Value> {
    let stored = stored_invariant_field(value)?;
    *dropped_text |= stored.is_none();
    Ok(stored.unwrap_or(Value::Nil))
}

/// A stored replay ref. A body stored before the owner ruling of 2026-10-14
/// may hold prose here, since that grammar took any bounded text without
/// control data; prose reads as no ref, and sets `dropped_text`.
fn decode_stored_ref(value: &Value, dropped_text: &mut bool) -> Result<Option<String>> {
    if value.is_nil() {
        return Ok(None);
    }
    let text = decode_str(value, "replay ref must be a string")?;
    match validate_ref(text) {
        Ok(()) => Ok(Some(text.to_owned())),
        Err(_)
            if !text.is_empty()
                && text.len() <= MAX_REF_LEN
                && !text.chars().any(is_forbidden_text_scalar) =>
        {
            *dropped_text = true;
            Ok(None)
        }
        Err(error) => Err(error),
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

/// A ref is an id, never prose (owner ruling 2026-10-14, fix 6): ASCII
/// letters, digits and `.` `_` `-` `:` `/` `@`. Both codec doors check it, so
/// a DIAGNOSTIC body with a sentence in a replay coordinate neither encodes
/// nor passes the write door, and a stored one reads without it.
pub(super) fn validate_ref(text: &str) -> Result<()> {
    if text.is_empty() || text.len() > MAX_REF_LEN {
        return Err(invalid_diagnostic("replay ref is empty or too long"));
    }
    if !text.bytes().all(is_ref_byte) {
        return Err(invalid_diagnostic("replay ref is not an id"));
    }
    Ok(())
}

fn is_ref_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b':' | b'/' | b'@')
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
