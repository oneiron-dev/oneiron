//! Who a pending notification is delivered to: the recipient markers its
//! stored body carries, read one way wherever delivery is decided.
use serde_json::Value;
use std::collections::BTreeSet;

/// The body keys that each name the callers a notification is for. Every key
/// a body carries is a condition: a caller receives it only when each one
/// names them.
const RECIPIENT_KEYS: &[&str] = &[
    "caller",
    "caller_id",
    "callerId",
    "recipient",
    "recipient_id",
    "recipientId",
];

/// The callers a notification is delivered to.
#[derive(Debug)]
pub(crate) enum NotificationRecipientScope {
    /// A body with no recipient marker: every caller.
    Everyone,
    /// The callers every recipient marker names; none when they share none.
    Callers(BTreeSet<String>),
}

/// A stored notification body as a JSON object; `None` for bytes that are
/// not a MessagePack map.
pub fn notification_body_json(raw_body: &[u8]) -> Option<Value> {
    let body: Value = rmp_serde::from_slice(raw_body).ok()?;
    body.as_object()?;
    Some(body)
}

/// The callers `body` is delivered to: those every recipient marker it
/// carries names, or everyone when it carries none. `None` for a body that
/// is not an object.
pub(crate) fn notification_recipient_scope(body: &Value) -> Option<NotificationRecipientScope> {
    let object = body.as_object()?;
    let mut callers: Option<BTreeSet<&str>> = None;
    for key in RECIPIENT_KEYS {
        let Some(marker) = object.get(*key) else {
            continue;
        };
        let named = marker_callers(marker);
        callers = Some(match callers {
            Some(held) => held.intersection(&named).copied().collect(),
            None => named,
        });
    }
    Some(match callers {
        None => NotificationRecipientScope::Everyone,
        Some(callers) => {
            NotificationRecipientScope::Callers(callers.into_iter().map(str::to_owned).collect())
        }
    })
}

/// Whether `body` is delivered to `caller`: every recipient marker it carries
/// names them. A body that is not an object is delivered to no one.
pub fn notification_scoped_to_caller(body: &Value, caller: &str) -> bool {
    match notification_recipient_scope(body) {
        Some(NotificationRecipientScope::Everyone) => true,
        Some(NotificationRecipientScope::Callers(callers)) => callers.contains(caller),
        None => false,
    }
}

/// Whether `marker`, a recipient, acknowledgement or surfaced marker, names
/// `caller`.
pub fn caller_marker_contains(marker: Option<&Value>, caller: &str) -> bool {
    marker.is_some_and(|marker| marker_callers(marker).contains(caller))
}

/// The callers one marker names: itself for a string, its string elements
/// for an array, and the keys set to `true` for a map. Any other value names
/// no one.
fn marker_callers(marker: &Value) -> BTreeSet<&str> {
    match marker {
        Value::String(caller) => BTreeSet::from([caller.as_str()]),
        Value::Array(items) => items.iter().filter_map(Value::as_str).collect(),
        Value::Object(map) => map
            .iter()
            .filter(|(_, named)| named.as_bool() == Some(true))
            .map(|(caller, _)| caller.as_str())
            .collect(),
        _ => BTreeSet::new(),
    }
}
