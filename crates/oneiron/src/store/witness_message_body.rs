//! Canonical MESSAGE body vocabulary, encoding, and structural validation.

use rmpv::Value;

use crate::error::{Error, RecordError, Result};
use crate::store::gate_reason::GateReasonCode;

/// The vault owner's own words.
pub(crate) const WITNESS_AUTHOR_USER: &str = "user";
/// The companion persona's words.
pub(crate) const WITNESS_AUTHOR_COMPANION: &str = "companion";
/// Tooling/engine rows. These carry NO `AuthoredBy` edge, which is exactly why
/// the bucket needs authority the other two do not: an unattributed row reads
/// downstream as the engine's own voice.
pub(crate) const WITNESS_AUTHOR_SYSTEM: &str = "system";

/// The canonical MESSAGE body keys, in canonical order.
const BODY_KEY_AUTHOR: &str = "author";
const BODY_KEY_TYPE: &str = "type";
const BODY_KEY_CONTENT: &str = "content";
const BODY_KEY_PARTS: &str = "parts";
const BODY_KEY_METADATA: &str = "metadata";
const BODY_KEY_IS_VISIBLE: &str = "is_visible";
const BODY_KEY_ORDER: &str = "order";

/// The TURN-level grouping key (`memory::witness`'s `speaker` stamp). Listed
/// with the MESSAGE body keys below because metadata that restates it is the
/// same side channel one level up.
const TURN_KEY_SPEAKER: &str = "speaker";

/// Envelope-axis names metadata may not restate, at ANY depth. Metadata is
/// opaque passenger data; a key that shadows an axis the door authorizes is a
/// second, ungated copy of that axis riding inside the first.
const RESERVED_METADATA_KEYS: [&str; 7] = [
    BODY_KEY_AUTHOR,
    BODY_KEY_TYPE,
    BODY_KEY_CONTENT,
    BODY_KEY_METADATA,
    BODY_KEY_IS_VISIBLE,
    BODY_KEY_ORDER,
    TURN_KEY_SPEAKER,
];

/// Message types are a closed set APP-side and opaque here, so the door pins
/// the SHAPE rather than the vocabulary: a bounded, printable, punctuation-only
/// token (`dialogue`, `executor.speak`, `tool_result`). Anything else is an
/// unknown value and fails closed.
const MAX_WITNESS_MESSAGE_TYPE_BYTES: usize = 128;

/// The highest position a message may claim inside one turn. Ordering is a
/// signal readers sort by; an unbounded one is a channel rather than a
/// position.
pub(crate) const MAX_WITNESS_MESSAGE_ORDER: u32 = 65_535;

/// Metadata nesting bound. Depth beyond this is a structure no transcript
/// reader consumes and a decode cost every reader pays.
const MAX_WITNESS_METADATA_DEPTH: usize = 8;

/// Total metadata nodes (keys plus values, recursively).
const MAX_WITNESS_METADATA_NODES: usize = 512;

/// Metadata key length bound.
const MAX_WITNESS_METADATA_KEY_BYTES: usize = 128;

/// One metadata string value may not become a second transcript-sized payload.
/// Counted as UTF-8 bytes, not Unicode scalar values.
const MAX_WITNESS_METADATA_STRING_BYTES: usize = 16 * 1024;

/// Canonical MessagePack bytes for the complete metadata map. The recursive
/// validator first bounds every string and the aggregate key/value text, so
/// checking the exact encoding never allocates in proportion to hostile input.
const MAX_WITNESS_METADATA_BYTES: usize = 64 * 1024;

/// One MESSAGE envelope, exactly as the write door will encode it.
///
/// `metadata` is the rmpv value the body carries (the engine converts JSON to
/// MessagePack before it reaches the door), never the caller's JSON: the door
/// authorizes what will be written.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct WitnessMessageEnvelope<'a> {
    /// `user` | `companion` | `system`; anything else fails closed.
    pub(crate) author: &'a str,
    /// App-closed type token.
    pub(crate) message_type: &'a str,
    /// Text content, BM25-indexed by the caller when non-empty.
    pub(crate) content: &'a str,
    /// Ordered terminal parts owned by the MESSAGE, never its editable text.
    pub(crate) parts: Option<Vec<crate::ContentPart>>,
    /// Opaque passenger data, or `None`.
    pub(crate) metadata: Option<Value>,
    /// Whether the row is part of the visible transcript.
    pub(crate) is_visible: bool,
    /// Position within the turn.
    pub(crate) order: u32,
}

impl WitnessMessageEnvelope<'_> {
    /// The CANONICAL MESSAGE body bytes for this envelope.
    ///
    /// This is the only MESSAGE body encoder in the engine: `memory::witness`
    /// delegates here, and the door below re-runs it to prove the staged bytes
    /// are the authorized ones. Key order is part of the encoding, not an
    /// accident of construction.
    pub(crate) fn encode_body(&self) -> Result<Vec<u8>> {
        let mut entries = vec![
            (Value::from(BODY_KEY_AUTHOR), Value::from(self.author)),
            (Value::from(BODY_KEY_TYPE), Value::from(self.message_type)),
            (Value::from(BODY_KEY_CONTENT), Value::from(self.content)),
        ];
        if let Some(parts) = &self.parts {
            let encoded = rmp_serde::to_vec_named(parts)
                .map_err(|_| Error::InvalidClaimBody("witness message parts are not encodable"))?;
            let value = rmpv::decode::read_value(&mut encoded.as_slice())
                .map_err(|_| Error::InvalidClaimBody("witness message parts are not encodable"))?;
            entries.push((Value::from(BODY_KEY_PARTS), value));
        }
        if let Some(metadata) = &self.metadata {
            entries.push((Value::from(BODY_KEY_METADATA), metadata.clone()));
        }
        entries.push((
            Value::from(BODY_KEY_IS_VISIBLE),
            Value::Boolean(self.is_visible),
        ));
        entries.push((
            Value::from(BODY_KEY_ORDER),
            Value::from(u64::from(self.order)),
        ));
        let mut out = Vec::new();
        rmpv::encode::write_value(&mut out, &Value::Map(entries))
            .map_err(|_| Error::InvalidClaimBody("witness message body is not encodable"))?;
        Ok(out)
    }
}

/// Envelope shape, vocabulary and coherence. Unknown or malformed values fail
/// closed; there is no "pass it through and let the app decide" arm, because
/// the app is exactly who this door does not trust.
pub(crate) fn witness_message_envelope_denial(
    envelope: &WitnessMessageEnvelope<'_>,
    body: &[u8],
) -> Option<GateReasonCode> {
    let malformed = Some(GateReasonCode::DenyWitnessMessageMalformedEnvelope);

    if !matches!(
        envelope.author,
        WITNESS_AUTHOR_USER | WITNESS_AUTHOR_COMPANION | WITNESS_AUTHOR_SYSTEM
    ) {
        return malformed;
    }
    if !valid_message_type(envelope.message_type) {
        return malformed;
    }
    if envelope.order > MAX_WITNESS_MESSAGE_ORDER {
        return malformed;
    }
    // A user's own words are never invisible. `companion`/`system` rows may be
    // hidden (an executor's kept-to-itself reasoning is a real, gated shape);
    // an invisible row attributed to the owner is a forgery with no reader.
    if envelope.author == WITNESS_AUTHOR_USER && !envelope.is_visible {
        return malformed;
    }
    if let Some(metadata) = &envelope.metadata {
        let mut nodes = 0_usize;
        let mut text_bytes = 0_usize;
        if !matches!(metadata, Value::Map(_))
            || !valid_metadata(metadata, 0, &mut nodes, &mut text_bytes)
            || encoded_metadata_len(metadata).is_none_or(|len| len > MAX_WITNESS_METADATA_BYTES)
        {
            return malformed;
        }
    }

    // The BIND. Everything above authorized the AXES; this proves the bytes the
    // caller is about to write are those axes and nothing else — no extra key,
    // no reordered map, no second copy of an axis appended after the encode.
    match envelope.encode_body() {
        Ok(canonical) if canonical == body => None,
        _ => malformed,
    }
}

/// The canonical-envelope verdict for one MESSAGE body, at the storage
/// materialization chokepoint (ONE-1686).
///
/// [`validate_canonical_witness_message_body`] answers with the row's AUTHOR
/// bucket, because that is the axis a door with no actor still has to rule on:
/// a `system` row carries no `AuthoredBy` edge, so nothing downstream can tell
/// it from the engine's own voice.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WitnessMessageBodyAuthor {
    User,
    Companion,
    System,
}

/// Proves MESSAGE bytes are the canonical envelope this module encodes, and
/// returns the author bucket they claim.
///
/// This is the SAME encoder and the SAME envelope floor
/// [`check_witness_message_ceiling`] runs — decoded here rather than supplied,
/// so a door that holds bytes but no actor (a raw put, a replicated carry) can
/// still refuse anything that is not a well-formed transcript row. It is NOT a
/// second authorization path: it answers "are these bytes an envelope", never
/// "may somebody write it", and every local write still passes the ceiling
/// door before it stages.
///
/// # Errors
///
/// [`RecordError::InvalidWitnessMessageBody`](crate::error::RecordError::InvalidWitnessMessageBody) when the bytes are not decodable, are
/// not the canonical key set in canonical order, carry an unknown author or
/// type token, exceed the order ceiling, hide a `user` row, carry malformed
/// metadata, or do not re-encode byte-identically.
pub(crate) fn validate_canonical_witness_message_body(
    body: &[u8],
) -> Result<WitnessMessageBodyAuthor> {
    let malformed = || {
        Error::Record(RecordError::InvalidWitnessMessageBody(
            "MESSAGE body is not a canonical envelope",
        ))
    };
    let mut cursor = body;
    let Ok(Value::Map(entries)) = rmpv::decode::read_value(&mut cursor) else {
        return Err(malformed());
    };
    if !cursor.is_empty() {
        return Err(malformed());
    }
    let mut author: Option<&str> = None;
    let mut message_type: Option<&str> = None;
    let mut content: Option<&str> = None;
    let mut parts: Option<Vec<crate::ContentPart>> = None;
    let mut metadata: Option<Value> = None;
    let mut is_visible: Option<bool> = None;
    let mut order: Option<u32> = None;
    for (key, value) in &entries {
        let Some(key) = key.as_str() else {
            return Err(malformed());
        };
        // Duplicate keys are a second copy of an axis; the canonical encoder
        // emits each exactly once, so a repeat cannot round-trip anyway. It is
        // rejected by name so the failure names the reason.
        let duplicated = match key {
            BODY_KEY_AUTHOR => {
                author = value.as_str();
                author.is_none()
            }
            BODY_KEY_TYPE => {
                message_type = value.as_str();
                message_type.is_none()
            }
            BODY_KEY_CONTENT => {
                content = value.as_str();
                content.is_none()
            }
            BODY_KEY_PARTS => {
                if parts.is_some() {
                    return Err(malformed());
                }
                let mut encoded = Vec::new();
                rmpv::encode::write_value(&mut encoded, value).map_err(|_| malformed())?;
                parts = Some(rmp_serde::from_slice(&encoded).map_err(|_| malformed())?);
                false
            }
            BODY_KEY_METADATA => {
                if metadata.is_some() {
                    return Err(malformed());
                }
                metadata = Some(value.clone());
                false
            }
            BODY_KEY_IS_VISIBLE => {
                is_visible = value.as_bool();
                is_visible.is_none()
            }
            BODY_KEY_ORDER => {
                order = value.as_u64().and_then(|value| u32::try_from(value).ok());
                order.is_none()
            }
            _ => return Err(malformed()),
        };
        if duplicated {
            return Err(malformed());
        }
    }
    let (Some(author), Some(message_type), Some(content), Some(is_visible), Some(order)) =
        (author, message_type, content, is_visible, order)
    else {
        return Err(malformed());
    };
    let envelope = WitnessMessageEnvelope {
        author,
        message_type,
        content,
        parts,
        metadata,
        is_visible,
        order,
    };
    // The SAME floor the ceiling door runs, including the canonical-bytes bind
    // (`encode_body() == body`), which is what makes key ORDER and the absence
    // of any extra byte part of the answer rather than of the parse.
    if witness_message_envelope_denial(&envelope, body).is_some() {
        return Err(malformed());
    }
    Ok(match envelope.author {
        WITNESS_AUTHOR_USER => WitnessMessageBodyAuthor::User,
        WITNESS_AUTHOR_COMPANION => WitnessMessageBodyAuthor::Companion,
        // The floor above already refused every other value.
        _ => WitnessMessageBodyAuthor::System,
    })
}

/// A bounded, printable type token: ASCII alphanumerics plus the separators
/// existing types use. No whitespace, no control bytes, no empty token.
fn valid_message_type(message_type: &str) -> bool {
    !message_type.is_empty()
        && message_type.len() <= MAX_WITNESS_MESSAGE_TYPE_BYTES
        && message_type
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | ':' | '/' | '+'))
}

/// Recursive metadata validation: bounded depth, node count, individual string
/// bytes, and aggregate key/value text bytes; string keys only, no reserved
/// envelope-axis name at any depth, and no opaque value kind.
fn valid_metadata(value: &Value, depth: usize, nodes: &mut usize, text_bytes: &mut usize) -> bool {
    if depth > MAX_WITNESS_METADATA_DEPTH {
        return false;
    }
    *nodes += 1;
    if *nodes > MAX_WITNESS_METADATA_NODES {
        return false;
    }
    match value {
        Value::Nil | Value::Boolean(_) | Value::Integer(_) | Value::F32(_) | Value::F64(_) => true,
        Value::String(text) => text.as_str().is_some_and(|text| {
            text.len() <= MAX_WITNESS_METADATA_STRING_BYTES
                && add_metadata_text_bytes(text_bytes, text.len())
        }),
        // Binary and Ext are byte channels no JSON-shaped metadata can produce;
        // accepting them would reopen the side channel one layer down.
        Value::Binary(_) | Value::Ext(_, _) => false,
        Value::Array(items) => items
            .iter()
            .all(|item| valid_metadata(item, depth + 1, nodes, text_bytes)),
        Value::Map(entries) => entries.iter().all(|(key, entry)| {
            let Some(key) = key.as_str() else {
                return false;
            };
            if key.is_empty()
                || key.len() > MAX_WITNESS_METADATA_KEY_BYTES
                || key.chars().any(char::is_control)
                || RESERVED_METADATA_KEYS.contains(&key)
                || !add_metadata_text_bytes(text_bytes, key.len())
            {
                return false;
            }
            *nodes += 1;
            *nodes <= MAX_WITNESS_METADATA_NODES
                && valid_metadata(entry, depth + 1, nodes, text_bytes)
        }),
    }
}

fn add_metadata_text_bytes(total: &mut usize, bytes: usize) -> bool {
    let Some(next) = total.checked_add(bytes) else {
        return false;
    };
    if next > MAX_WITNESS_METADATA_BYTES {
        return false;
    }
    *total = next;
    true
}

/// Exact canonical encoded size, checked only after the recursive limits above
/// have bounded all allocation-driving values.
fn encoded_metadata_len(metadata: &Value) -> Option<usize> {
    let mut encoded = Vec::new();
    rmpv::encode::write_value(&mut encoded, metadata).ok()?;
    Some(encoded.len())
}
