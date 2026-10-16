//! The hook's scoped read (ARCH-0080 §6): every row a hook sees comes through
//! the reader's `ScopedRead` lane, then the hook's own grant.

use std::collections::HashSet;

use serde::Deserialize;
use serde_json::{Value, json};

use crate::claim::{ClaimBody, ClaimSubject, PointRead, ScopedRead};
use crate::registry::ENTITY_TYPE_CLAIM;
use crate::{EntityId, Result};

use super::filter::glob_match;
use super::grant::HookGrant;
use super::store::{HookReadPin, HookReadRow};

/// Rows one `claims_about` read answers at most.
const MAX_READ_ROWS: usize = 64;
const DEFAULT_READ_ROWS: usize = 20;
/// Bytes one read answers at most.
const MAX_READ_BYTES: usize = 256 * 1024;
/// Claims about a subject one read considers.
const MAX_ABOUT_SCAN: usize = 512;
const MAX_REQUEST_BYTES: usize = 4 * 1024;
/// Reads one run may make.
pub(super) const MAX_READS: usize = 64;

/// The fact's entity as the hook's grant shows it.
pub(super) struct SeenFact {
    /// The claim, when the entity is one.
    pub(super) claim: Option<ClaimBody>,
    /// The claim in a hook's input shape, or null.
    pub(super) claim_json: Value,
    /// BLAKE3 of the live body.
    pub(super) body_hash: [u8; 32],
}

/// Reads the fact's entity under `lane` and `grant`. `None` is withheld or
/// gone: the hook may not see this fact.
pub(super) fn fact_row(
    lane: &ScopedRead<'_>,
    grant: &HookGrant,
    entity: EntityId,
) -> Result<Option<SeenFact>> {
    let Some(row) = lane
        .read(&[PointRead::id(entity)], None)?
        .value
        .into_iter()
        .next()
        .flatten()
    else {
        return Ok(None);
    };
    let Some(body) = row.body.as_deref() else {
        return Ok(None);
    };
    let body_hash = *blake3::hash(body).as_bytes();
    if row.entity_type != ENTITY_TYPE_CLAIM {
        return Ok(Some(SeenFact {
            claim: None,
            claim_json: Value::Null,
            body_hash,
        }));
    }
    let claim = crate::claim::decode_claim_body(body, true)?;
    if !grant.admits(&claim) {
        return Ok(None);
    }
    Ok(Some(SeenFact {
        claim_json: claim_json(entity, &claim),
        claim: Some(claim),
        body_hash,
    }))
}

#[derive(Deserialize)]
#[serde(untagged)]
enum ReadRequest {
    Claim {
        claim: String,
    },
    About {
        claims_about: String,
        #[serde(default)]
        predicate: Option<String>,
        #[serde(default)]
        limit: Option<usize>,
    },
}

/// Answers one `oneiron.read` and pins what it served. An error reaches the
/// body as a throw.
pub(super) fn answer(
    lane: &ScopedRead<'_>,
    grant: &HookGrant,
    request: &str,
    pins: &mut Vec<HookReadPin>,
) -> std::result::Result<String, String> {
    answer_within(lane, None, grant, request, pins)
}

/// [`answer`], serving only rows `cap` also reads: a verb hook reads under
/// its caller's lane, narrowed to its grant's reader.
pub(super) fn answer_within(
    lane: &ScopedRead<'_>,
    cap: Option<&ScopedRead<'_>>,
    grant: &HookGrant,
    request: &str,
    pins: &mut Vec<HookReadPin>,
) -> std::result::Result<String, String> {
    if request.len() > MAX_REQUEST_BYTES {
        return Err("read request is too large".to_owned());
    }
    if pins.len() >= MAX_READS {
        return Err("read budget is spent".to_owned());
    }
    let parsed: ReadRequest =
        serde_json::from_str(request).map_err(|_| "read request does not parse".to_owned())?;
    let (response, rows) = match parsed {
        ReadRequest::Claim { claim } => read_claim(lane, cap, grant, &claim),
        ReadRequest::About {
            claims_about,
            predicate,
            limit,
        } => read_about(
            lane,
            cap,
            grant,
            &claims_about,
            predicate.as_deref(),
            limit.unwrap_or(DEFAULT_READ_ROWS).min(MAX_READ_ROWS),
        ),
    }
    .map_err(|error| error.to_string())?;
    pins.push(HookReadPin {
        request: request.to_owned(),
        response_hash: blake3::hash(response.as_bytes()).to_hex().to_string(),
        rows,
    });
    Ok(response)
}

fn read_claim(
    lane: &ScopedRead<'_>,
    cap: Option<&ScopedRead<'_>>,
    grant: &HookGrant,
    id: &str,
) -> Result<(String, Vec<HookReadRow>)> {
    let id = EntityId::from_hex(id)?;
    let reads = [PointRead::id(id)];
    let rows = lane.read(&reads, None)?.value;
    let mut served = Vec::new();
    let mut value = Value::Null;
    if let Some(row) = rows.into_iter().next().flatten()
        && row.entity_type == ENTITY_TYPE_CLAIM
        && let Some(body) = row.body.as_deref()
    {
        let claim = crate::claim::decode_claim_body(body, true)?;
        if grant.admits(&claim)
            && visible_to(cap, &reads)?.is_none_or(|seen| seen.contains(&id))
        {
            value = claim_json(id, &claim);
            served.push(HookReadRow {
                id,
                content_hash: row.content_hash,
            });
        }
    }
    Ok((value.to_string(), served))
}

fn read_about(
    lane: &ScopedRead<'_>,
    cap: Option<&ScopedRead<'_>>,
    grant: &HookGrant,
    subject: &str,
    predicate: Option<&str>,
    limit: usize,
) -> Result<(String, Vec<HookReadRow>)> {
    let subject = EntityId::from_hex(subject)?;
    let ids: Vec<EntityId> = lane
        .vault()
        .claims_for_subject(&subject)?
        .into_iter()
        .take(MAX_ABOUT_SCAN)
        .collect();
    let reads: Vec<PointRead<'_>> = ids.iter().map(|id| PointRead::id(*id)).collect();
    let rows = lane.read(&reads, None)?.value;
    let seen = visible_to(cap, &reads)?;
    let mut served = Vec::new();
    let mut values = Vec::new();
    let mut bytes = 2_usize;
    for row in rows.into_iter().flatten() {
        if values.len() >= limit {
            break;
        }
        if seen.as_ref().is_some_and(|seen| !seen.contains(&row.id)) {
            continue;
        }
        let Some(body) = row.body.as_deref() else {
            continue;
        };
        if row.entity_type != ENTITY_TYPE_CLAIM {
            continue;
        }
        let claim = crate::claim::decode_claim_body(body, true)?;
        if !grant.admits(&claim)
            || predicate.is_some_and(|glob| !glob_match(glob, &claim.predicate))
        {
            continue;
        }
        let value = claim_json(row.id, &claim);
        bytes = bytes.saturating_add(value.to_string().len() + 1);
        if bytes > MAX_READ_BYTES {
            break;
        }
        values.push(value);
        served.push(HookReadRow {
            id: row.id,
            content_hash: row.content_hash,
        });
    }
    Ok((Value::Array(values).to_string(), served))
}

/// The ids of `reads` that `cap` reads; `None` with no cap.
fn visible_to(
    cap: Option<&ScopedRead<'_>>,
    reads: &[PointRead<'_>],
) -> Result<Option<HashSet<EntityId>>> {
    let Some(cap) = cap else {
        return Ok(None);
    };
    Ok(Some(
        cap.read(reads, None)?
            .value
            .into_iter()
            .flatten()
            .map(|row| row.id)
            .collect(),
    ))
}

/// A claim in a hook's input shape.
pub(super) fn claim_json(id: EntityId, claim: &ClaimBody) -> Value {
    json!({
        "id": id.to_hex(),
        "subject": subject_json(&claim.subject),
        "predicate": claim.predicate,
        "value": rmpv_to_json(&claim.value),
        "confidence": claim.confidence,
        "source": claim.source.map(crate::ClaimSource::as_str),
        "lifecycle": claim.lifecycle.as_str(),
        "approval": claim.approval.as_str(),
    })
}

fn subject_json(subject: &ClaimSubject) -> Value {
    match subject {
        ClaimSubject::Entity(id) => Value::String(id.to_hex()),
        ClaimSubject::Edge {
            source,
            kind,
            target,
        } => json!({"from": source.to_hex(), "to": target.to_hex(), "edge": kind.name()}),
    }
}

/// A claim value as JSON. Bytes become lowercase hex; a map with other than
/// string keys becomes a list of pairs.
fn rmpv_to_json(value: &rmpv::Value) -> Value {
    match value {
        rmpv::Value::Nil | rmpv::Value::Ext(..) => Value::Null,
        rmpv::Value::Boolean(flag) => Value::Bool(*flag),
        rmpv::Value::Integer(number) => number
            .as_i64()
            .map(Value::from)
            .or_else(|| number.as_u64().map(Value::from))
            .unwrap_or(Value::Null),
        rmpv::Value::F32(number) => float(f64::from(*number)),
        rmpv::Value::F64(number) => float(*number),
        rmpv::Value::String(text) => Value::String(
            text.as_str()
                .map_or_else(|| crate::receipt::hex_lower(text.as_bytes()), str::to_owned),
        ),
        rmpv::Value::Binary(bytes) => Value::String(crate::receipt::hex_lower(bytes)),
        rmpv::Value::Array(values) => Value::Array(values.iter().map(rmpv_to_json).collect()),
        rmpv::Value::Map(entries) => {
            if entries.iter().all(|(key, _)| key.as_str().is_some()) {
                Value::Object(
                    entries
                        .iter()
                        .map(|(key, value)| {
                            (
                                key.as_str().unwrap_or_default().to_owned(),
                                rmpv_to_json(value),
                            )
                        })
                        .collect(),
                )
            } else {
                Value::Array(
                    entries
                        .iter()
                        .map(|(key, value)| {
                            Value::Array(vec![rmpv_to_json(key), rmpv_to_json(value)])
                        })
                        .collect(),
                )
            }
        }
    }
}

fn float(number: f64) -> Value {
    serde_json::Number::from_f64(number).map_or(Value::Null, Value::Number)
}
