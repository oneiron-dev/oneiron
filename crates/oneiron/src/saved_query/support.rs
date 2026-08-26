use std::collections::BTreeMap;

use serde_json::{Map as JsonMap, Value};
use sha2::{Digest, Sha256};

use crate::edge::EdgeKind;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};

/// Version token stamped into every [`SavedQueryDerivationEnvelope`]. It names
/// the EVALUATOR, not the definition — the definition's own movement is carried
/// by [`VerdictMemoRow::definition_version`].
pub(super) const EVALUATOR_VERSION: &str = "saved_query.v1";

/// Upper bound for every bounded text field in this module.
pub(super) const MAX_TEXT_BYTES: usize = 512;

/// One unit of cosine similarity expressed in the micros scale.
pub(super) const MICROS_PER_UNIT: u32 = 1_000_000;

/// Domain separator for the evidence hash.
pub(super) const EVIDENCE_HASH_DOMAIN: &[u8] = b"oneiron.saved_query.evidence.v1";

/// Length-prefixes every variable-length field so no two distinct evidence sets
/// can serialize to the same byte stream.
pub(super) fn hash_bytes(hasher: &mut Sha256, bytes: &[u8]) {
    hash_len(hasher, bytes.len());
    hasher.update(bytes);
}

pub(super) fn hash_len(hasher: &mut Sha256, len: usize) {
    hasher.update((len as u64).to_be_bytes());
}

/// Canonical-hex entity reference, mirroring CA-01's one-wire-form-per-identity
/// rule: a non-canonical spelling is rejected rather than normalized.
pub(super) fn parse_entity_ref(value: &Value) -> Result<EntityId> {
    let hex = value
        .as_str()
        .ok_or_else(|| invalid("saved query entity reference must be a hex string"))?;
    let id = EntityId::from_hex(hex)
        .map_err(|_| invalid("saved query entity reference is not a valid entity id"))?;
    if id.to_hex() != hex {
        return Err(invalid("saved query entity reference is not canonical hex"));
    }
    Ok(id)
}

/// Deterministic JSON bytes with recursively sorted object keys.
///
/// The crate builds `serde_json` with `preserve_order`, so its maps are
/// insertion-ordered and `to_vec` alone is NOT canonical. Anything hashed or
/// compared byte-wise has to come through here.
pub(super) fn canonical_json_bytes(value: &Value) -> Result<Vec<u8>> {
    serde_json::to_vec(&canonicalize_json(value))
        .map_err(|_| Error::InvariantViolation("saved query canonical JSON encode failed"))
}

fn canonicalize_json(value: &Value) -> Value {
    match value {
        Value::Array(values) => Value::Array(values.iter().map(canonicalize_json).collect()),
        Value::Object(entries) => {
            let sorted = entries
                .iter()
                .map(|(key, value)| (key.clone(), canonicalize_json(value)))
                .collect::<BTreeMap<String, Value>>();
            Value::Object(sorted.into_iter().collect())
        }
        scalar => scalar.clone(),
    }
}

/// Projects a MessagePack claim value into JSON, INJECTIVELY.
///
/// The projection is what gets hashed into the memo key, so two distinct claim
/// values must never land on the same JSON. Binary, Ext, and non-string-keyed
/// maps therefore carry a `$`-tagged wrapper instead of being flattened into a
/// bare string or silently dropped, and a genuine map key that starts with `$`
/// is escaped by doubling it. Without this, `Binary([0x61])` and the literal
/// string `"61"` produce the same bytes and evidence can change type without
/// moving the hash.
pub(super) fn rmpv_to_json(value: &rmpv::Value) -> Value {
    match value {
        rmpv::Value::Nil => Value::Null,
        rmpv::Value::Boolean(flag) => Value::Bool(*flag),
        rmpv::Value::Integer(number) => number
            .as_i64()
            .map(Value::from)
            .or_else(|| number.as_u64().map(Value::from))
            .or_else(|| {
                number
                    .as_f64()
                    .and_then(serde_json::Number::from_f64)
                    .map(Value::Number)
            })
            .unwrap_or(Value::Null),
        rmpv::Value::F32(number) => json_number(f64::from(*number)),
        rmpv::Value::F64(number) => json_number(*number),
        // A non-UTF-8 MessagePack string is bytes, so it is tagged as bytes
        // rather than collapsing to null alongside every other undecodable
        // value.
        rmpv::Value::String(text) => text.as_str().map_or_else(
            || tagged_json("$bin", Value::String(hex_lower(text.as_bytes()))),
            |text| Value::String(text.to_owned()),
        ),
        rmpv::Value::Binary(bytes) => tagged_json("$bin", Value::String(hex_lower(bytes))),
        rmpv::Value::Array(values) => Value::Array(values.iter().map(rmpv_to_json).collect()),
        rmpv::Value::Map(entries) => rmpv_map_to_json(entries),
        rmpv::Value::Ext(tag, bytes) => tagged_json(
            "$ext",
            Value::Array(vec![Value::from(*tag), Value::String(hex_lower(bytes))]),
        ),
    }
}

fn rmpv_map_to_json(entries: &[(rmpv::Value, rmpv::Value)]) -> Value {
    if entries.iter().all(|(key, _)| key.as_str().is_some()) {
        return Value::Object(
            entries
                .iter()
                .filter_map(|(key, value)| {
                    key.as_str()
                        .map(|key| (escape_json_key(key), rmpv_to_json(value)))
                })
                .collect(),
        );
    }
    // A map with non-string keys has no lossless JSON object form; erasing
    // those entries would let the map change without moving the hash.
    tagged_json(
        "$map",
        Value::Array(
            entries
                .iter()
                .map(|(key, value)| Value::Array(vec![rmpv_to_json(key), rmpv_to_json(value)]))
                .collect(),
        ),
    )
}

fn tagged_json(tag: &str, payload: Value) -> Value {
    let mut wrapper = JsonMap::new();
    wrapper.insert(tag.to_owned(), payload);
    Value::Object(wrapper)
}

/// Doubles a leading `$` so a real key can never impersonate a wrapper tag.
fn escape_json_key(key: &str) -> String {
    if key.starts_with('$') {
        format!("${key}")
    } else {
        key.to_owned()
    }
}

fn json_number(number: f64) -> Value {
    serde_json::Number::from_f64(number).map_or(Value::Null, Value::Number)
}

/// Cosine similarity clamped to `[0, 1]` and scaled to millionths.
///
/// Negative similarity clamps to zero rather than mapping onto a positive
/// range: an anti-correlated embedding is "not similar", and a threshold set at
/// zero must not admit it merely because the scale was recentered.
pub(super) fn cosine_similarity_micros(left: &[f32], right: &[f32]) -> u32 {
    if left.len() != right.len() || left.is_empty() {
        return 0;
    }
    let dot = f64::from(left.iter().zip(right).map(|(l, r)| l * r).sum::<f32>());
    let norm = |values: &[f32]| f64::from(values.iter().map(|v| v * v).sum::<f32>()).sqrt();
    let denominator = norm(left) * norm(right);
    if denominator <= 0.0 {
        return 0;
    }
    let similarity = (dot / denominator).clamp(0.0, 1.0);
    // Rounding to nearest keeps an exact-match pair at exactly 1_000_000.
    (similarity * f64::from(MICROS_PER_UNIT)).round() as u32
}

/// Fingerprint that moves when EITHER vector moves.
pub(super) fn vector_pair_fingerprint(
    subject: &Option<Vec<f32>>,
    exemplar: &Option<Vec<f32>>,
) -> String {
    let mut hasher = Sha256::new();
    for vector in [subject, exemplar] {
        match vector {
            None => hasher.update([0u8]),
            Some(values) => {
                hasher.update([1u8]);
                hash_len(&mut hasher, values.len());
                for value in values {
                    hasher.update(value.to_be_bytes());
                }
            }
        }
    }
    hex_lower(&hasher.finalize())
}

pub(super) fn hex_lower(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut out, byte| {
        use std::fmt::Write as _;
        let _ = write!(out, "{byte:02x}");
        out
    })
}

pub(super) fn validate_bounded_text(value: &str, field: &'static str) -> Result<()> {
    if value.is_empty() || value.len() > MAX_TEXT_BYTES {
        return Err(Error::InvalidConfig(format!(
            "saved query {field} length is invalid"
        )));
    }
    if value.chars().any(char::is_control) {
        return Err(Error::InvalidConfig(format!(
            "saved query {field} has control characters"
        )));
    }
    Ok(())
}

pub(super) fn invalid(reason: &str) -> Error {
    Error::InvalidConfig(reason.to_owned())
}

/// snake_case `EdgeKind` names, the same spelling the facade uses on the wire.
pub(super) fn edge_kind_from_name(value: &str) -> Option<EdgeKind> {
    let kind = match value {
        "authored_by" => EdgeKind::AuthoredBy,
        "scoped_to" => EdgeKind::ScopedTo,
        "part_of" => EdgeKind::PartOf,
        "supersedes" => EdgeKind::Supersedes,
        "belongs_to" => EdgeKind::BelongsTo,
        "claim_of" => EdgeKind::ClaimOf,
        "child_of" => EdgeKind::ChildOf,
        "assigned_to" => EdgeKind::AssignedTo,
        "derived_from" => EdgeKind::DerivedFrom,
        "mentions" => EdgeKind::Mentions,
        "about" => EdgeKind::About,
        "supports" => EdgeKind::Supports,
        "opposes" => EdgeKind::Opposes,
        "participates_in" => EdgeKind::ParticipatesIn,
        "attached" => EdgeKind::Attached,
        "employed_by" => EdgeKind::EmployedBy,
        "has_facet" => EdgeKind::HasFacet,
        "facet_of" => EdgeKind::FacetOf,
        "in_world" => EdgeKind::InWorld,
        "set_in" => EdgeKind::SetIn,
        "merged_into" => EdgeKind::MergedInto,
        "split_into" => EdgeKind::SplitInto,
        _ => return None,
    };
    Some(kind)
}
