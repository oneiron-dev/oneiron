//! The hook's scoped read (ARCH-0080 §6): every row a hook sees comes through
//! the reader's `ScopedRead` lane, then the hook's own grant ([`grant_view`]).
//! A read answers whole (FIX 9233): every row its request selects, however
//! many and however large, with no cut of its own.

pub(super) mod grant_view;

use std::collections::HashSet;

use serde::Deserialize;
use serde_json::{Value, json};

use crate::claim::{ClaimBody, ClaimSubject, PointRead, ScopedRead};
use crate::ports::EdgeDirection;
use crate::registry::ENTITY_TYPE_CLAIM;
use crate::vault::{ReadMode, RevisionRef};
use crate::{EdgeKind, EntityId, Result};

use super::filter::glob_match;
use super::grant::HookGrant;
use super::source::FactEntry;
use super::store::{HookReadPin, HookReadRow};

/// Claims about a subject one step of a `claims_about` read reads before it
/// reads the next (CALLS, FIX 9233): how the walk is scheduled, never how
/// much it answers. A read with a limit stops reading once it has its rows.
const ABOUT_READ_STEP: usize = 256;

/// The fact's entity as the hook's grant shows it.
pub(super) struct SeenFact {
    /// The claim, when the entity is one.
    pub(super) claim: Option<ClaimBody>,
    /// The claim in a hook's input shape, or null.
    pub(super) claim_json: Value,
    /// BLAKE3 of the selected body.
    pub(super) body_hash: [u8; 32],
}

/// Whether a saved dependency is shown, withheld by the current grant, or
/// missing. An expected full body hash keeps a wrong revision from standing
/// in for the saved bytes.
pub(super) enum HistoryAdmission {
    Shown,
    Withheld,
    Missing,
}

pub(super) fn history_admission(
    lane: &ScopedRead<'_>,
    grant: &HookGrant,
    id: EntityId,
    revision: Option<RevisionRef>,
    expected_body_hash: Option<[u8; 32]>,
) -> Result<HistoryAdmission> {
    let point = match revision {
        Some(revision) => PointRead::id(id).at(ReadMode::Pinned(revision)),
        None => PointRead::id(id),
    };
    let Some(row) = lane
        .read(&[point], None)?
        .value
        .into_iter()
        .next()
        .flatten()
    else {
        return Ok(HistoryAdmission::Missing);
    };
    let Some(body) = row.body.as_deref() else {
        return Ok(HistoryAdmission::Missing);
    };
    if expected_body_hash.is_some_and(|expected| expected != *blake3::hash(body).as_bytes()) {
        return Ok(HistoryAdmission::Missing);
    }
    if grant_view::shows_row(grant, &row)? {
        Ok(HistoryAdmission::Shown)
    } else {
        Ok(HistoryAdmission::Withheld)
    }
}

/// Reads the fact's entity under `lane` and `grant`. `None` is withheld or
/// gone: the hook may not see this fact.
pub(super) fn fact_row(
    lane: &ScopedRead<'_>,
    grant: &HookGrant,
    entry: &FactEntry,
) -> Result<Option<SeenFact>> {
    if entry.body_hash.is_some() && entry.revision.is_none() {
        return Ok(None);
    }
    let point = match entry.revision {
        Some(revision) => PointRead::id(entry.entity).at(ReadMode::Pinned(revision)),
        None => PointRead::id(entry.entity),
    };
    let Some(row) = lane
        .read(&[point], None)?
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
    if entry
        .body_hash
        .is_some_and(|expected| expected != body_hash)
    {
        return Ok(None);
    }
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
        claim_json: claim_json(entry.entity, &claim),
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
/// body as a throw. No count of a run's reads refuses one (FIX 9232).
pub(super) fn answer(
    lane: &ScopedRead<'_>,
    grant: &HookGrant,
    request: &str,
    pins: &mut Vec<HookReadPin>,
) -> std::result::Result<String, String> {
    answer_within(lane, None, grant, request, pins)
}

/// [`answer`], serving only rows `cap` also reads: a verb hook reads under
/// its caller's lane, narrowed to its grant's reader. A `claims_about` with
/// no limit answers every claim the lane, the cap and the grant show; one
/// with a limit answers exactly that many at most, zero included.
pub(super) fn answer_within(
    lane: &ScopedRead<'_>,
    cap: Option<&ScopedRead<'_>>,
    grant: &HookGrant,
    request: &str,
    pins: &mut Vec<HookReadPin>,
) -> std::result::Result<String, String> {
    let parsed: ReadRequest =
        serde_json::from_str(request).map_err(|_| "read request does not parse".to_owned())?;
    let (response, rows) = match parsed {
        ReadRequest::Claim { claim } => read_claim(lane, cap, grant, &claim),
        ReadRequest::About {
            claims_about,
            predicate,
            limit,
        } => read_about(lane, cap, grant, &claims_about, predicate.as_deref(), limit),
    }
    .map_err(|error| error.to_string())?;
    pins.push(HookReadPin {
        request: request.to_owned(),
        response_hash: blake3::hash(response.as_bytes()).to_hex().to_string(),
        rows,
    });
    Ok(response)
}

/// Replays one pinned `oneiron.read` from its existing rows only (FIX 2392):
/// the pinned revision's bytes through the current lane and grant. `Ok(None)`
/// is missing history; `Err` is a throw. It never re-enumerates, never falls
/// back to live, and never serves raw bytes.
pub(super) fn answer_pinned(
    lane: &ScopedRead<'_>,
    grant: &HookGrant,
    pin: &HookReadPin,
) -> std::result::Result<Option<String>, String> {
    let parsed: ReadRequest =
        serde_json::from_str(&pin.request).map_err(|_| "read request does not parse".to_owned())?;
    let claim_id = match parsed {
        ReadRequest::Claim { claim } => {
            Some(EntityId::from_hex(&claim).map_err(|error| error.to_string())?)
        }
        ReadRequest::About { claims_about, .. } => {
            EntityId::from_hex(&claims_about).map_err(|error| error.to_string())?;
            None
        }
    };
    if let Some(id) = claim_id {
        if pin.rows.is_empty() {
            return Ok(Some(Value::Null.to_string()));
        }
        if pin.rows.len() != 1 {
            return Ok(None);
        }
        if pin.rows[0].id != id {
            return Ok(None);
        }
    }
    let mut values = Vec::new();
    for row in &pin.rows {
        let revision = {
            let txn = lane
                .vault()
                .store
                .env
                .read_txn()
                .map_err(|error| error.to_string())?;
            crate::vault::entity_revision::revision_for_body_hash_in_txn(
                lane.vault(),
                &txn,
                &row.id,
                &row.body_hash,
            )
            .map_err(|error| error.to_string())?
        };
        let Some(revision) = revision else {
            return Ok(None);
        };
        let point = PointRead::id(row.id).at(ReadMode::Pinned(revision));
        let stored = lane
            .read(&[point], None)
            .map_err(|error| error.to_string())?;
        let Some(read) = stored.value.into_iter().next().flatten() else {
            return Ok(None);
        };
        if read.entity_type != ENTITY_TYPE_CLAIM {
            return Ok(None);
        }
        let Some(body) = read.body.as_deref() else {
            return Ok(None);
        };
        if *blake3::hash(body).as_bytes() != row.body_hash {
            return Ok(None);
        }
        let Ok(claim) = crate::claim::decode_claim_body(body, true) else {
            return Ok(None);
        };
        if !grant.admits(&claim) {
            return Ok(None);
        }
        values.push(claim_json(claim_id.unwrap_or(row.id), &claim));
    }
    if claim_id.is_some() {
        let Some(value) = values.into_iter().next() else {
            return Ok(None);
        };
        return Ok(Some(value.to_string()));
    }
    Ok(Some(Value::Array(values).to_string()))
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
        if grant.admits(&claim) && visible_to(cap, &reads)?.is_none_or(|seen| seen.contains(&id)) {
            value = claim_json(id, &claim);
            served.push(HookReadRow {
                id,
                content_hash: row.content_hash,
                body_hash: *blake3::hash(body).as_bytes(),
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
    limit: Option<usize>,
) -> Result<(String, Vec<HookReadRow>)> {
    let subject = EntityId::from_hex(subject)?;
    // The claims about the subject in the content the lane reads: a room's
    // overlay over base for a lane in a room (WILL L11-01 S01-2c), base
    // alone otherwise. Each still passes the lane, the cap and the grant.
    let ids: Vec<EntityId> = {
        let rtxn = lane.vault().store.env.read_txn()?;
        crate::vault::filtered_edge_peers_in(
            &lane.store_read(),
            &rtxn,
            EdgeDirection::In,
            &subject,
            EdgeKind::ClaimOf,
            Some(ENTITY_TYPE_CLAIM),
        )?
    };
    let mut served = Vec::new();
    let mut values = Vec::new();
    for step in ids.chunks(ABOUT_READ_STEP) {
        if limit.is_some_and(|limit| values.len() >= limit) {
            break;
        }
        let reads: Vec<PointRead<'_>> = step.iter().map(|id| PointRead::id(*id)).collect();
        let rows = lane.read(&reads, None)?.value;
        let seen = visible_to(cap, &reads)?;
        for row in rows.into_iter().flatten() {
            if limit.is_some_and(|limit| values.len() >= limit) {
                break;
            }
            if seen.as_ref().is_some_and(|seen| !seen.contains(&row.id))
                || row.entity_type != ENTITY_TYPE_CLAIM
            {
                continue;
            }
            let Some(body) = row.body.as_deref() else {
                continue;
            };
            let claim = crate::claim::decode_claim_body(body, true)?;
            if !grant.admits(&claim)
                || predicate.is_some_and(|glob| !glob_match(glob, &claim.predicate))
            {
                continue;
            }
            values.push(claim_json(row.id, &claim));
            served.push(HookReadRow {
                id: row.id,
                content_hash: row.content_hash,
                body_hash: *blake3::hash(body).as_bytes(),
            });
        }
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
