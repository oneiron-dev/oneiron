//! The typed error, MessagePack value helpers, vault-meta key/address derivation, envelope/mode value codecs, and the read/action grant-bound builders.

use std::io::Cursor;

use rmpv::Value;

use crate::channel_identity_selection::RelationshipContext;
use crate::consent::{
    ActionClass, ActionEnvelope, ActorBound, AudienceBound, DisclosureClass, DisclosureEnvelope,
    GrantBound,
};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};

use super::types::{
    ChannelIdentityActionEnvelope, ChannelIdentityAutonomyMode, ChannelIdentityAutonomyRung,
    MailboxReadEnvelope, PREDICATE_AUTONOMY_MODE,
};

pub(crate) fn invalid_autonomy() -> Error {
    Error::InvalidConsentBound("channel identity autonomy is absent, mismatched, or unauthorized")
}

pub(super) fn text(value: &Value) -> Result<&str> {
    value.as_str().ok_or_else(invalid_autonomy)
}
pub(super) fn number(value: &Value) -> Result<u64> {
    value.as_u64().ok_or_else(invalid_autonomy)
}
pub(super) fn id_value(id: EntityId) -> Value {
    Value::from(id.to_hex())
}
pub(super) fn id(value: &Value) -> Result<EntityId> {
    EntityId::from_hex(text(value)?)
}
pub(super) fn optional_id(value: &Value) -> Result<Option<EntityId>> {
    if value.is_nil() {
        Ok(None)
    } else {
        id(value).map(Some)
    }
}
pub(super) fn optional_number(value: &Value) -> Result<Option<u64>> {
    if value.is_nil() {
        Ok(None)
    } else {
        number(value).map(Some)
    }
}
pub(super) fn optional_text(value: &Value) -> Result<Option<String>> {
    if value.is_nil() {
        Ok(None)
    } else {
        Ok(Some(text(value)?.to_owned()))
    }
}
pub(super) fn array(value: &Value, len: usize) -> Result<&[Value]> {
    value
        .as_array()
        .filter(|v| v.len() == len)
        .map(Vec::as_slice)
        .ok_or_else(invalid_autonomy)
}
pub(super) fn context(value: &Value) -> Result<RelationshipContext> {
    RelationshipContext::parse(text(value)?).ok_or_else(invalid_autonomy)
}
pub(super) fn token(value: &str) -> Result<()> {
    if value.is_empty() || value.trim() != value || value.len() > 512 {
        return Err(invalid_autonomy());
    }
    Ok(())
}
pub(super) fn encode(value: &Value) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    rmpv::encode::write_value(&mut bytes, value).map_err(|_| invalid_autonomy())?;
    Ok(bytes)
}
pub(super) fn decode(bytes: &[u8]) -> Result<Value> {
    let mut cursor = Cursor::new(bytes);
    let value = rmpv::decode::read_value(&mut cursor).map_err(|_| invalid_autonomy())?;
    if cursor.position() != bytes.len() as u64 {
        return Err(invalid_autonomy());
    }
    Ok(value)
}
pub(super) fn key(kind: &str, suffix: &str) -> Vec<u8> {
    format!("channel_identity_autonomy:v1:{kind}:{suffix}").into_bytes()
}
pub(super) fn address(kind: &str, value: &Value) -> Result<EntityId> {
    let bytes = encode(&Value::Array(vec![Value::from(kind), value.clone()]))?;
    let hash = blake3::hash(&bytes);
    EntityId::from_bytes(
        hash.as_bytes()[..16]
            .try_into()
            .map_err(|_| invalid_autonomy())?,
    )
}
pub(super) fn mode_key(identity: EntityId, context: RelationshipContext) -> Vec<u8> {
    key(
        PREDICATE_AUTONOMY_MODE,
        &format!("{}:{}", identity.to_hex(), context.as_str()),
    )
}
pub(super) fn read_value(e: &MailboxReadEnvelope) -> Result<Value> {
    if e.label_allowlist.is_empty() && e.thread_allowlist.is_empty()
        || e.not_before.zip(e.not_after).is_some_and(|(a, b)| a > b)
    {
        return Err(invalid_autonomy());
    }
    for list in [&e.label_allowlist, &e.thread_allowlist] {
        if list.len() > 256 {
            return Err(invalid_autonomy());
        }
        for item in list {
            token(item)?;
        }
        if list.iter().collect::<std::collections::BTreeSet<_>>().len() != list.len() {
            return Err(invalid_autonomy());
        }
    }
    Ok(Value::Array(vec![
        id_value(e.identity_ref),
        Value::Array(e.label_allowlist.iter().cloned().map(Value::from).collect()),
        Value::Array(
            e.thread_allowlist
                .iter()
                .cloned()
                .map(Value::from)
                .collect(),
        ),
        e.not_before.map_or(Value::Nil, Value::from),
        e.not_after.map_or(Value::Nil, Value::from),
    ]))
}
pub(super) fn read_from(value: &Value) -> Result<MailboxReadEnvelope> {
    let v = array(value, 5)?;
    let strings = |v: &Value| -> Result<Vec<String>> {
        v.as_array()
            .ok_or_else(invalid_autonomy)?
            .iter()
            .map(|v| Ok(text(v)?.to_owned()))
            .collect()
    };
    let e = MailboxReadEnvelope {
        identity_ref: id(&v[0])?,
        label_allowlist: strings(&v[1])?,
        thread_allowlist: strings(&v[2])?,
        not_before: optional_number(&v[3])?,
        not_after: optional_number(&v[4])?,
    };
    read_value(&e)?;
    Ok(e)
}
pub(super) fn action_value(e: &ChannelIdentityActionEnvelope) -> Result<Value> {
    if e.max_actions == 0 || e.window_secs == 0 {
        return Err(invalid_autonomy());
    }
    if let Some(c) = &e.counterparty_class {
        token(c)?;
    }
    Ok(Value::Array(vec![
        id_value(e.identity_ref),
        Value::from(e.relationship_context.as_str()),
        e.counterparty_class.clone().map_or(Value::Nil, Value::from),
        Value::from(e.max_actions),
        Value::from(e.window_secs),
    ]))
}
pub(super) fn action_from(value: &Value) -> Result<ChannelIdentityActionEnvelope> {
    let v = array(value, 5)?;
    let e = ChannelIdentityActionEnvelope {
        identity_ref: id(&v[0])?,
        relationship_context: context(&v[1])?,
        counterparty_class: optional_text(&v[2])?,
        max_actions: u32::try_from(number(&v[3])?).map_err(|_| invalid_autonomy())?,
        window_secs: number(&v[4])?,
    };
    action_value(&e)?;
    Ok(e)
}
pub(super) fn mode_value(m: &ChannelIdentityAutonomyMode) -> Value {
    Value::Array(vec![
        id_value(m.identity_ref),
        Value::from(m.relationship_context.as_str()),
        Value::from(m.rung.as_str()),
        m.read_grant_ref.map_or(Value::Nil, id_value),
        m.action_grant_ref.map_or(Value::Nil, id_value),
    ])
}
pub(super) fn mode_from(value: &Value) -> Result<ChannelIdentityAutonomyMode> {
    let v = array(value, 5)?;
    Ok(ChannelIdentityAutonomyMode {
        identity_ref: id(&v[0])?,
        relationship_context: context(&v[1])?,
        rung: ChannelIdentityAutonomyRung::parse(text(&v[2])?).ok_or_else(invalid_autonomy)?,
        read_grant_ref: optional_id(&v[3])?,
        action_grant_ref: optional_id(&v[4])?,
    })
}

pub(super) fn read_bound(
    actor: EntityId,
    identity: EntityId,
    envelope: EntityId,
) -> Result<GrantBound> {
    GrantBound::disclosure(
        AudienceBound::singleton(actor.to_hex())?,
        DisclosureClass::new("channel_identity.scoped_read")?,
        DisclosureEnvelope::new([
            format!("identity:{}", identity.to_hex()),
            format!("envelope:{}", envelope.to_hex()),
        ])?,
    )
}
pub(super) fn action_bound(
    actor: EntityId,
    reference: EntityId,
    e: &ChannelIdentityActionEnvelope,
    verb: &str,
) -> Result<GrantBound> {
    GrantBound::action(
        ActorBound::new(actor.to_hex())?,
        ActionClass::new(verb)?,
        ActionEnvelope::new([
            format!("identity:{}", e.identity_ref.to_hex()),
            format!("envelope:{}", reference.to_hex()),
            format!("context:{}", e.relationship_context.as_str()),
            format!("window_secs:{}", e.window_secs),
        ])?
        .with_target(e.identity_ref.to_hex())?
        .with_budget(u64::from(e.max_actions))
        .with_receipt_required(true),
    )
}
