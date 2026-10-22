//! The evidence pins of an outline's JSON, as the keep and its freshness
//! read them: each in document order, the spans this engine can address,
//! and the hex they carry.

use serde_json::Value;

use super::CitedClaimLifecycle;
use crate::entity_id::EntityId;
use crate::note::NotePin;

/// A pin this engine can map: a cited CLAIM and a note document by entity
/// id, its frontier and cursors in hex.
pub(super) fn note_pin(pin: &Value) -> Option<NotePin> {
    let text = |key: &str| pin.get(key).and_then(Value::as_str);
    let quote_hash = unhex(text("quote_hash")?)?;
    Some(NotePin {
        claim: EntityId::from_hex(text("claim")?).ok()?,
        document: EntityId::from_hex(text("document")?).ok()?,
        frontier: unhex(text("version")?)?,
        start_cursor: unhex(text("start")?)?,
        end_cursor: unhex(text("end")?)?,
        quote_hash: quote_hash.try_into().ok()?,
        quote_text: text("quote")?.to_owned(),
    })
}

/// A note document span this engine can address, a cited CLAIM named or
/// not: the document (and claim) by entity id, its cursors and quote hash in
/// hex (FIX 9814).
pub(super) struct EngineSpan {
    pub(super) document: EntityId,
    pub(super) claim: Option<EntityId>,
    pub(super) start: Vec<u8>,
    pub(super) end: Vec<u8>,
    pub(super) quote_hash: [u8; 32],
}

pub(super) fn engine_span(pin: &Value) -> Option<EngineSpan> {
    let text = |key: &str| pin.get(key).and_then(Value::as_str);
    let claim = match pin.get("claim") {
        None | Some(Value::Null) => None,
        Some(_) => Some(EntityId::from_hex(text("claim")?).ok()?),
    };
    Some(EngineSpan {
        document: EntityId::from_hex(text("document")?).ok()?,
        claim,
        start: unhex(text("start")?)?,
        end: unhex(text("end")?)?,
        quote_hash: unhex(text("quote_hash")?)?.try_into().ok()?,
    })
}

pub(super) fn cited_lifecycle(status: crate::ClaimLifecycleStatus) -> CitedClaimLifecycle {
    match status {
        crate::ClaimLifecycleStatus::Active => CitedClaimLifecycle::Active,
        crate::ClaimLifecycleStatus::Superseded => CitedClaimLifecycle::Superseded,
        crate::ClaimLifecycleStatus::Retracted => CitedClaimLifecycle::Retracted,
    }
}

/// Every evidence pin in document order: an object with a quote hash.
pub(super) fn pins(value: &Value, visit: &mut impl FnMut(&Value)) {
    match value {
        Value::Object(map) if map.contains_key("quote_hash") => visit(value),
        Value::Object(map) => map.values().for_each(|child| pins(child, visit)),
        Value::Array(items) => items.iter().for_each(|child| pins(child, visit)),
        _ => {}
    }
}

pub(super) fn pins_mut(value: &mut Value, visit: &mut impl FnMut(&mut Value)) {
    match value {
        Value::Object(map) if map.contains_key("quote_hash") => visit(value),
        Value::Object(map) => map.values_mut().for_each(|child| pins_mut(child, visit)),
        Value::Array(items) => items.iter_mut().for_each(|child| pins_mut(child, visit)),
        _ => {}
    }
}

pub(super) fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut out, b| {
        let _ = write!(out, "{b:02x}");
        out
    })
}

pub(super) fn unhex(text: &str) -> Option<Vec<u8>> {
    if text.len() % 2 != 0 {
        return None;
    }
    (0..text.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(text.get(at..at + 2)?, 16).ok())
        .collect()
}
