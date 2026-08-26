use std::io::Cursor;

use rmpv::Value;

use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::store::GateDecisionId;

use super::bound::{
    ActionClass, ActionEnvelope, ActorBound, AudienceBound, BoundClass, BoundEnvelope,
    BoundSubject, ConsentDomain, DisclosureClass, DisclosureEnvelope, GrantBound,
};
use super::grant::{ConsentGrantRow, ConsentGrantStatus, ConsentOwnerStamp, StandingConsentGrant};
use super::support::{
    SUBJECT_KIND_ACTOR, SUBJECT_KIND_AUDIENCE, hex_to_16_bytes, invalid_row, normalized_ref,
    required_value, validate_keys,
};

/// Body schema version of a persisted standing consent-grant row.
pub const CONSENT_GRANT_SCHEMA_VERSION: u64 = 1;

/// Pinned on-disk MessagePack key set for standing consent-grant rows.
///
/// There is deliberately **no** `expires_at`, `duration`, `ttl`, or any other
/// lifetime field: invariant 9 replaces expiry-guessing with the registry.
pub const CONSENT_GRANT_BODY_KEYS: [&str; 8] = [
    "schema_version",
    "domain",
    "subject",
    "class",
    "envelope",
    "status",
    "owner_stamp",
    "created_at",
];

pub(super) const KEY_SCHEMA_VERSION: &str = CONSENT_GRANT_BODY_KEYS[0];
pub(super) const KEY_DOMAIN: &str = CONSENT_GRANT_BODY_KEYS[1];
pub(super) const KEY_SUBJECT: &str = CONSENT_GRANT_BODY_KEYS[2];
pub(super) const KEY_CLASS: &str = CONSENT_GRANT_BODY_KEYS[3];
pub(super) const KEY_ENVELOPE: &str = CONSENT_GRANT_BODY_KEYS[4];
pub(super) const KEY_STATUS: &str = CONSENT_GRANT_BODY_KEYS[5];
pub(super) const KEY_OWNER_STAMP: &str = CONSENT_GRANT_BODY_KEYS[6];
pub(super) const KEY_CREATED_AT: &str = CONSENT_GRANT_BODY_KEYS[7];

pub(super) const OWNER_STAMP_KEYS: [&str; 3] = ["actor", "principal_ref", "decision_id"];
pub(super) const SUBJECT_KEYS: [&str; 2] = ["kind", "refs"];
pub(super) const ENVELOPE_KEYS: [&str; 4] = ["selectors", "target", "budget", "receipt_required"];

// ---------------------------------------------------------------------------
// Persistence codec
// ---------------------------------------------------------------------------

/// Encodes a standing consent-grant row in canonical MessagePack key order.
pub fn encode_consent_grant_row(row: &ConsentGrantRow) -> Result<Vec<u8>> {
    let bound = row.grant.bound();
    let value = Value::Map(vec![
        (
            Value::from(KEY_SCHEMA_VERSION),
            Value::from(CONSENT_GRANT_SCHEMA_VERSION),
        ),
        (
            Value::from(KEY_DOMAIN),
            Value::from(bound.domain().as_str()),
        ),
        (Value::from(KEY_SUBJECT), encode_subject(bound.subject())),
        (Value::from(KEY_CLASS), Value::from(bound.class().as_str())),
        (Value::from(KEY_ENVELOPE), encode_envelope(bound.envelope())),
        (Value::from(KEY_STATUS), Value::from(row.status.as_str())),
        (
            Value::from(KEY_OWNER_STAMP),
            encode_owner_stamp(&row.owner_stamp),
        ),
        (Value::from(KEY_CREATED_AT), Value::from(row.created_at)),
    ]);

    let mut out = Vec::new();
    rmpv::encode::write_value(&mut out, &value)
        .map_err(|_| Error::InvariantViolation("consent grant row MessagePack encode failed"))?;
    Ok(out)
}

/// Decodes and validates a standing consent-grant row.
///
/// Strict: unknown keys, duplicate keys, a wrong schema version, a crossed
/// domain triple, or a malformed ref are all rejected fail-closed.
pub fn decode_consent_grant_row(bytes: &[u8]) -> Result<ConsentGrantRow> {
    let mut cursor = Cursor::new(bytes);
    let value = rmpv::decode::read_value(&mut cursor).map_err(|_| invalid_row())?;
    if cursor.position() != bytes.len() as u64 {
        return Err(invalid_row());
    }
    let Value::Map(entries) = &value else {
        return Err(invalid_row());
    };
    validate_keys(entries, &CONSENT_GRANT_BODY_KEYS)?;

    if required_value(entries, KEY_SCHEMA_VERSION)?.as_u64() != Some(CONSENT_GRANT_SCHEMA_VERSION) {
        return Err(invalid_row());
    }
    let domain = required_value(entries, KEY_DOMAIN)?
        .as_str()
        .and_then(ConsentDomain::parse)
        .ok_or_else(invalid_row)?;
    let subject = decode_subject(required_value(entries, KEY_SUBJECT)?, domain)?;
    let class_str = required_value(entries, KEY_CLASS)?
        .as_str()
        .ok_or_else(invalid_row)?;
    let class = match domain {
        ConsentDomain::Disclosure => {
            BoundClass::Disclosure(DisclosureClass::new(class_str).map_err(|_| invalid_row())?)
        }
        ConsentDomain::Action => {
            BoundClass::Action(ActionClass::new(class_str).map_err(|_| invalid_row())?)
        }
    };
    let envelope = decode_envelope(required_value(entries, KEY_ENVELOPE)?, domain)?;
    let status = required_value(entries, KEY_STATUS)?
        .as_str()
        .and_then(ConsentGrantStatus::parse)
        .ok_or_else(invalid_row)?;
    let owner_stamp = decode_owner_stamp(required_value(entries, KEY_OWNER_STAMP)?)?;
    let created_at = required_value(entries, KEY_CREATED_AT)?
        .as_u64()
        .ok_or_else(invalid_row)?;

    let bound = GrantBound::new(subject, class, envelope).map_err(|_| invalid_row())?;
    let grant = StandingConsentGrant::from_bound(bound).map_err(|_| invalid_row())?;
    Ok(ConsentGrantRow {
        grant,
        status,
        owner_stamp,
        created_at,
    })
}

fn encode_subject(subject: &BoundSubject) -> Value {
    let (kind, refs) = match subject {
        BoundSubject::Actor(actor) => (
            SUBJECT_KIND_ACTOR,
            vec![
                Value::from(actor.actor_ref.as_str()),
                actor.actor_class.as_deref().map_or(Value::Nil, Value::from),
            ],
        ),
        BoundSubject::Audience(audience) => (
            SUBJECT_KIND_AUDIENCE,
            audience
                .members
                .iter()
                .map(|member| Value::from(member.as_str()))
                .collect(),
        ),
    };
    Value::Map(vec![
        (Value::from(SUBJECT_KEYS[0]), Value::from(kind)),
        (Value::from(SUBJECT_KEYS[1]), Value::Array(refs)),
    ])
}

fn decode_subject(value: &Value, domain: ConsentDomain) -> Result<BoundSubject> {
    let Value::Map(entries) = value else {
        return Err(invalid_row());
    };
    validate_keys(entries, &SUBJECT_KEYS)?;
    let kind = required_value(entries, SUBJECT_KEYS[0])?
        .as_str()
        .ok_or_else(invalid_row)?;
    let Value::Array(refs) = required_value(entries, SUBJECT_KEYS[1])? else {
        return Err(invalid_row());
    };

    match (kind, domain) {
        (SUBJECT_KIND_ACTOR, ConsentDomain::Action) => {
            let [actor_ref, actor_class] = refs.as_slice() else {
                return Err(invalid_row());
            };
            let actor = ActorBound::new(actor_ref.as_str().ok_or_else(invalid_row)?)
                .map_err(|_| invalid_row())?;
            let actor = match actor_class {
                Value::Nil => actor,
                other => actor
                    .with_actor_class(other.as_str().ok_or_else(invalid_row)?)
                    .map_err(|_| invalid_row())?,
            };
            Ok(BoundSubject::Actor(actor))
        }
        (SUBJECT_KIND_AUDIENCE, ConsentDomain::Disclosure) => {
            let members = refs
                .iter()
                .map(|member| member.as_str().map(str::to_owned).ok_or_else(invalid_row))
                .collect::<Result<Vec<_>>>()?;
            Ok(BoundSubject::Audience(
                AudienceBound::new(members).map_err(|_| invalid_row())?,
            ))
        }
        // A stored subject kind that disagrees with the stored domain is a
        // crossed triple on disk: reject rather than reinterpret.
        _ => Err(invalid_row()),
    }
}

fn encode_envelope(envelope: &BoundEnvelope) -> Value {
    let (selectors, target, budget, receipt_required) = match envelope {
        BoundEnvelope::Disclosure(envelope) => (&envelope.selectors, None, None, false),
        BoundEnvelope::Action(envelope) => (
            &envelope.selectors,
            envelope.target.as_deref(),
            envelope.budget,
            envelope.receipt_required,
        ),
    };
    Value::Map(vec![
        (
            Value::from(ENVELOPE_KEYS[0]),
            Value::Array(
                selectors
                    .iter()
                    .map(|selector| Value::from(selector.as_str()))
                    .collect(),
            ),
        ),
        (
            Value::from(ENVELOPE_KEYS[1]),
            target.map_or(Value::Nil, Value::from),
        ),
        (
            Value::from(ENVELOPE_KEYS[2]),
            budget.map_or(Value::Nil, Value::from),
        ),
        (Value::from(ENVELOPE_KEYS[3]), Value::from(receipt_required)),
    ])
}

fn decode_envelope(value: &Value, domain: ConsentDomain) -> Result<BoundEnvelope> {
    let Value::Map(entries) = value else {
        return Err(invalid_row());
    };
    validate_keys(entries, &ENVELOPE_KEYS)?;
    let Value::Array(raw_selectors) = required_value(entries, ENVELOPE_KEYS[0])? else {
        return Err(invalid_row());
    };
    let selectors = raw_selectors
        .iter()
        .map(|selector| selector.as_str().map(str::to_owned).ok_or_else(invalid_row))
        .collect::<Result<Vec<_>>>()?;
    let target_value = required_value(entries, ENVELOPE_KEYS[1])?;
    let budget_value = required_value(entries, ENVELOPE_KEYS[2])?;
    let receipt_required = required_value(entries, ENVELOPE_KEYS[3])?
        .as_bool()
        .ok_or_else(invalid_row)?;

    match domain {
        ConsentDomain::Disclosure => {
            // A disclosure envelope has no target, budget, or receipt
            // obligation; a row carrying one is an action envelope mislabeled.
            if !matches!(target_value, Value::Nil)
                || !matches!(budget_value, Value::Nil)
                || receipt_required
            {
                return Err(invalid_row());
            }
            Ok(BoundEnvelope::Disclosure(
                DisclosureEnvelope::new(selectors).map_err(|_| invalid_row())?,
            ))
        }
        ConsentDomain::Action => {
            let mut envelope = ActionEnvelope::new(selectors).map_err(|_| invalid_row())?;
            if !matches!(target_value, Value::Nil) {
                envelope = envelope
                    .with_target(target_value.as_str().ok_or_else(invalid_row)?)
                    .map_err(|_| invalid_row())?;
            }
            if !matches!(budget_value, Value::Nil) {
                envelope = envelope.with_budget(budget_value.as_u64().ok_or_else(invalid_row)?);
            }
            Ok(BoundEnvelope::Action(
                envelope.with_receipt_required(receipt_required),
            ))
        }
    }
}

fn encode_owner_stamp(stamp: &ConsentOwnerStamp) -> Value {
    Value::Map(vec![
        (
            Value::from(OWNER_STAMP_KEYS[0]),
            Value::from(stamp.actor.to_hex()),
        ),
        (
            Value::from(OWNER_STAMP_KEYS[1]),
            Value::from(stamp.principal_ref.as_str()),
        ),
        (
            Value::from(OWNER_STAMP_KEYS[2]),
            Value::from(stamp.decision_id.to_hex()),
        ),
    ])
}

fn decode_owner_stamp(value: &Value) -> Result<ConsentOwnerStamp> {
    let Value::Map(entries) = value else {
        return Err(invalid_row());
    };
    validate_keys(entries, &OWNER_STAMP_KEYS)?;
    let actor = EntityId::from_hex(
        required_value(entries, OWNER_STAMP_KEYS[0])?
            .as_str()
            .ok_or_else(invalid_row)?,
    )
    .map_err(|_| invalid_row())?;
    let principal_ref = normalized_ref(
        "principal_ref",
        required_value(entries, OWNER_STAMP_KEYS[1])?
            .as_str()
            .ok_or_else(invalid_row)?
            .to_owned(),
    )
    .map_err(|_| invalid_row())?;
    let decision_hex = required_value(entries, OWNER_STAMP_KEYS[2])?
        .as_str()
        .ok_or_else(invalid_row)?;
    let decision_id =
        GateDecisionId::from_bytes(hex_to_16_bytes(decision_hex).ok_or_else(invalid_row)?);
    Ok(ConsentOwnerStamp {
        actor,
        principal_ref,
        decision_id,
    })
}
