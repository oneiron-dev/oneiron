//! The pinned MessagePack codec for type-0 (CLAIM) bodies: the canonical
//! encoder and the single fail-closed decoder every read and write funnels
//! through.

use std::io::Cursor;

use rmpv::Value;

use super::*;
use crate::claim::{base_world_id, scope_stamp};

// Test-only MessagePack decode counter: AC 9 of the D19 unit pins "body
// decoded ONCE per result for gate + projection" — tests assert exact
// decode counts through this counter instead of round-tripping output.
#[cfg(test)]
thread_local! {
    static CLAIM_BODY_DECODE_COUNT: std::cell::Cell<usize> =
        const { std::cell::Cell::new(0) };
}

/// Encodes a [`ClaimBody`] into the pinned MessagePack ABI: a map carrying
/// the present [`CLAIM_BODY_KEYS`] in canonical order. `stale == false` is
/// omitted (absent means `false` on decode). Encoding performs no
/// validation — every write path re-validates the encoded bytes through
/// [`crate::claim::decode_claim_body`], the single validator.
pub(crate) fn encode_claim_body(body: &ClaimBody) -> Result<Vec<u8>> {
    let mut entries: Vec<(Value, Value)> = Vec::with_capacity(CLAIM_BODY_KEYS.len());
    entries.push((Value::from(KEY_PRED), Value::from(body.predicate.as_str())));
    entries.push((Value::from(KEY_VAL), body.value.clone()));
    entries.push((Value::from(KEY_CONF), Value::F32(body.confidence)));
    if let Some(salience) = body.salience {
        entries.push((Value::from(KEY_SAL), Value::F32(salience)));
    }
    if let Some(evidence) = &body.evidence {
        entries.push((Value::from(KEY_EVID), evidence.clone()));
    }
    if let Some(valid_from) = body.valid_from {
        entries.push((Value::from(KEY_FROM), Value::from(valid_from)));
    }
    if let Some(valid_to) = body.valid_to {
        entries.push((Value::from(KEY_TO), Value::from(valid_to)));
    }
    if let Some(source) = body.source {
        entries.push((Value::from(KEY_SRC), Value::from(source.as_str())));
    }
    entries.push((
        Value::from(KEY_WORLD),
        scope_stamp::id_value(body.world.unwrap_or_else(base_world_id)),
    ));
    entries.push((
        Value::from(KEY_REL),
        body.rel.map_or_else(
            || Value::from("all"),
            |id| Value::Array(vec![scope_stamp::id_value(id)]),
        ),
    ));
    entries.push((Value::from(KEY_SUBJ), Value::Binary(body.subject.encode())));
    if let Some(scope) = &body.scope {
        entries.push((Value::from(KEY_SCOPE), scope.clone()));
    }
    entries.push((Value::from(KEY_APPR), Value::from(body.approval.as_str())));
    entries.push((Value::from(KEY_LIFE), Value::from(body.lifecycle.as_str())));
    if body.stale {
        entries.push((Value::from(KEY_STALE), Value::Boolean(true)));
    }
    if let Some(session_tag) = &body.session_tag {
        entries.push((Value::from(KEY_SESSION), Value::from(session_tag.as_str())));
    }

    entries.push((
        "scopeFacetId".into(),
        scope_stamp::id_value(body.scope_facet),
    ));
    entries.push((
        "scopeProjectId".into(),
        scope_stamp::id_value(body.scope_project),
    ));
    entries.push(("scopeVersion".into(), 2u64.into()));
    let mut out = Vec::new();
    rmpv::encode::write_value(&mut out, &Value::Map(entries))
        .map_err(|_| Error::InvariantViolation("claim body MessagePack encode failed"))?;
    Ok(out)
}

/// Decodes and structurally validates a type-0 (CLAIM) body (D18).
///
/// This is the single validator: every write path validates through it (via
/// `validate_claim_body_bytes`) and `Vault::get_claim` decodes through it.
/// Fail-closed rules:
///
/// * the body must be exactly one MessagePack map (no trailing bytes);
/// * keys must be strings drawn from [`CLAIM_BODY_KEYS`], no duplicates;
/// * required: `pred`, `subj`, `val`, `conf`, `appr`, `life`, `world`, `rel`;
/// * `conf` (and `sal` when present) must be finite numbers in `[0, 1]`;
/// * `from`/`to` must be non-negative integers fitting `u64`;
/// * `src`/`appr`/`life` must be the pinned enum strings;
/// * `stale` must be a boolean (absent = `false`);
/// * `world` and `rel` must be the explicit defaults `base` and `all`,
///   respectively, or a 16-byte MessagePack Binary [`EntityId`]; entity
///   existence and type validation belongs to retrieval;
/// * `subj` must be a 16-byte entity id or 33-byte EdgeRef ([`ClaimSubject`]);
/// * `pred` must satisfy the D17 grammar; reserved `edge.*` and `skill.*`
///   predicates are rejected unless `allow_reserved_predicate` is set
///   (crate-private door / read path).
pub fn decode_claim_body(data: &[u8], allow_reserved_predicate: bool) -> Result<ClaimBody> {
    #[cfg(test)]
    CLAIM_BODY_DECODE_COUNT.with(|count| count.set(count.get().saturating_add(1)));

    let mut cursor = Cursor::new(data);
    let value = rmpv::decode::read_value(&mut cursor)
        .map_err(|_| Error::InvalidClaimBody("body is not valid MessagePack"))?;
    if cursor.position() != data.len() as u64 {
        return Err(Error::InvalidClaimBody("trailing bytes after body map"));
    }
    let Value::Map(entries) = value else {
        return Err(Error::InvalidClaimBody("body must be a MessagePack map"));
    };

    let mut predicate: Option<String> = None;
    let mut subject: Option<ClaimSubject> = None;
    let mut claim_value: Option<Value> = None;
    let mut confidence: Option<f32> = None;
    let mut approval: Option<ClaimApprovalStatus> = None;
    let mut lifecycle: Option<ClaimLifecycleStatus> = None;
    let mut salience: Option<f32> = None;
    let mut evidence: Option<Value> = None;
    let mut valid_from: Option<u64> = None;
    let mut valid_to: Option<u64> = None;
    let mut source: Option<ClaimSource> = None;
    let mut world: Option<EntityId> = None;
    let mut rel: Option<EntityId> = None;
    let mut scope: Option<Value> = None;
    let mut session_tag: Option<String> = None;
    let mut stale: Option<bool> = None;
    let mut scope_facet = None;
    let mut scope_project = None;
    let mut scope_version = None;

    let mut seen = [false; CLAIM_BODY_KEYS.len()];
    for (key, value) in entries {
        let Some(key) = key.as_str() else {
            return Err(Error::InvalidClaimBody("body keys must be strings"));
        };
        let Some(index) = CLAIM_BODY_KEYS.iter().position(|known| *known == key) else {
            return Err(Error::InvalidClaimBody(
                "body key is not in the pinned CLAIM_BODY_KEYS set",
            ));
        };
        if seen[index] {
            return Err(Error::InvalidClaimBody("duplicate body key"));
        }
        seen[index] = true;

        match CLAIM_BODY_KEYS[index] {
            "pred" => {
                let Some(pred) = value.as_str() else {
                    return Err(Error::InvalidClaimBody("pred must be a string"));
                };
                predicate = Some(pred.to_owned());
            }
            "val" => claim_value = Some(value),
            "conf" => {
                confidence = Some(
                    unit_interval_f32(&value)
                        .ok_or(Error::InvalidClaimBody("conf must be finite in [0, 1]"))?,
                );
            }
            "sal" => {
                salience = Some(
                    unit_interval_f32(&value)
                        .ok_or(Error::InvalidClaimBody("sal must be finite in [0, 1]"))?,
                );
            }
            "evid" => evidence = Some(value),
            "from" => {
                valid_from = Some(value.as_u64().ok_or(Error::InvalidClaimBody(
                    "from must be a non-negative integer",
                ))?);
            }
            "to" => {
                valid_to = Some(
                    value
                        .as_u64()
                        .ok_or(Error::InvalidClaimBody("to must be a non-negative integer"))?,
                );
            }
            "src" => {
                let parsed =
                    value
                        .as_str()
                        .and_then(ClaimSource::parse)
                        .ok_or(Error::InvalidClaimBody(
                            "src must be one of user_stated|observed|inferred|imported|tool_output|generated",
                        ))?;
                source = Some(parsed);
            }
            "worldId" => world = Some(scope_stamp::scope_id(&value)?),
            "scopeFacetId" => scope_facet = Some(scope_stamp::scope_id(&value)?),
            "scopeProjectId" => scope_project = Some(scope_stamp::scope_id(&value)?),
            "scopeVersion" => scope_version = value.as_u64(),
            "scopeRelationshipId" => {
                if value.as_str() == Some("all") {
                    rel = None;
                } else if let Value::Array(ids) = value {
                    if ids.len() != 1 {
                        return Err(Error::InvalidClaimBody(
                            "relationship scope requires all or one id",
                        ));
                    }
                    rel = Some(scope_stamp::scope_id(&ids[0])?);
                } else {
                    return Err(Error::InvalidClaimBody("invalid relationship scope"));
                }
            }
            "subj" => {
                let Value::Binary(bytes) = &value else {
                    return Err(Error::InvalidClaimBody("subj must be MessagePack binary"));
                };
                subject = Some(ClaimSubject::decode(bytes)?);
            }
            "scope" => scope = Some(value),
            "appr" => {
                let parsed = value.as_str().and_then(ClaimApprovalStatus::parse).ok_or(
                    Error::InvalidClaimBody("appr must be one of auto|proposed|approved|rejected"),
                )?;
                approval = Some(parsed);
            }
            "life" => {
                let parsed = value.as_str().and_then(ClaimLifecycleStatus::parse).ok_or(
                    Error::InvalidClaimBody("life must be one of active|superseded|retracted"),
                )?;
                lifecycle = Some(parsed);
            }
            "stale" => {
                let Value::Boolean(flag) = value else {
                    return Err(Error::InvalidClaimBody("stale must be a boolean"));
                };
                stale = Some(flag);
            }
            "sess" => {
                let Some(tag) = value.as_str() else {
                    return Err(Error::InvalidClaimBody("sess must be a string"));
                };
                validate_session_tag(tag)?;
                session_tag = Some(tag.to_owned());
            }
            _ => unreachable!("index resolved from CLAIM_BODY_KEYS"),
        }
    }

    if scope_version != Some(2) || !seen[9] {
        return Err(Error::InvalidClaimBody(
            "missing required scope stamp/version",
        ));
    }
    let stamped_world = world.ok_or(Error::InvalidClaimBody("missing worldId"))?;
    let world = (stamped_world != base_world_id()).then_some(stamped_world);
    let scope_facet = scope_facet.ok_or(Error::InvalidClaimBody("missing scopeFacetId"))?;
    let scope_project = scope_project.ok_or(Error::InvalidClaimBody("missing scopeProjectId"))?;
    let predicate = predicate.ok_or(Error::InvalidClaimBody("missing required field pred"))?;
    validate_predicate(&predicate, allow_reserved_predicate)?;
    let subject = subject.ok_or(Error::InvalidClaimBody("missing required field subj"))?;
    let claim_value = claim_value.ok_or(Error::InvalidClaimBody("missing required field val"))?;
    let confidence = confidence.ok_or(Error::InvalidClaimBody("missing required field conf"))?;
    let approval = approval.ok_or(Error::InvalidClaimBody("missing required field appr"))?;
    let lifecycle = lifecycle.ok_or(Error::InvalidClaimBody("missing required field life"))?;
    // `scope` stays opaque, but the entries the engine RECOGNIZES inside it
    // are structurally pinned like any other decoded field: a duplicate or
    // malformed corpus id fails closed here rather than reaching a retrieval
    // scope decision. Unknown sibling entries are not inspected.
    validate_known_claim_scope_entries(scope.as_ref())?;

    Ok(ClaimBody {
        predicate,
        subject,
        value: claim_value,
        confidence,
        approval,
        lifecycle,
        salience,
        evidence,
        valid_from,
        valid_to,
        source,
        world,
        rel,
        scope,
        scope_facet,
        scope_project,
        session_tag,
        stale: stale.unwrap_or(false),
    })
}
