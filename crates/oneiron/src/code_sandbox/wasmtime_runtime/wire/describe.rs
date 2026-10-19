//! How code mode routes a raw `describe` before any typed row: a result
//! the run holds, a secret's handle (OF-560) or a fold of the run's own log.
//! A describe naming more than one target is never routed here: it goes on
//! to its typed row, whose one selector check refuses it (FIX 3256).

use crate::engine_executor::{JsResultRef, JsResultTarget};
use serde_json::Value;

/// The targets a raw describe can name: the typed row's six, and the run's
/// own result selectors (`ref`, `name`).
const TARGETS: [&str; 8] = ["self", "vault", "task_ref", "key", "fold", "handle", "ref", "name"];

/// Whether the run may route raw describe `input` itself: a string, or an
/// object naming at most one target, whose `after` polls a handle it names.
/// Any other describe skips the run's routing, so its typed row refuses it
/// as a bad request instead of answering the first target it reads.
pub(super) fn names_one_target(input: &Value) -> bool {
    let Value::Object(fields) = input else {
        return true;
    };
    let named = |field: &str| {
        fields
            .get(field)
            .is_some_and(|value| !value.is_null() && *value != Value::Bool(false))
    };
    TARGETS.into_iter().filter(|field| named(*field)).count() <= 1
        && (named("handle") || !named("after"))
}

/// The result a `describe` input names, when it names one: a string (a bound
/// name, or a handle, whose colon no name has, either with a range suffix),
/// a result's card by its `ref` or `handle`, or `{name}` with none of a task
/// describe's fields.
pub(super) fn result_ref(input: Value) -> Option<JsResultTarget> {
    const TASK_FIELDS: [&str; 6] = [
        "task_ref",
        "self",
        "session_id",
        "key",
        "frame_epoch",
        "fold",
    ];
    match input {
        Value::String(text) => Some(JsResultTarget::parse(&text)),
        Value::Object(mut fields) => {
            for key in ["ref", "handle"] {
                if let Some(Value::String(reference)) = fields.remove(key) {
                    return Some(JsResultTarget::parse(&reference));
                }
            }
            if TASK_FIELDS.iter().any(|field| fields.contains_key(*field)) {
                return None;
            }
            match fields.remove("name") {
                Some(Value::String(name)) => Some(JsResultTarget {
                    reference: JsResultRef::Name(name),
                    range: None,
                }),
                _ => None,
            }
        }
        _ => None,
    }
}

/// The secret handle a `describe` input names, when it names one (OF-560):
/// `"sc12"`, `{handle: "sc12"}`, `sc12:ab` or the text form `[secret sc12]`.
/// A secret's handle is read before a result bound under the same name.
pub(super) fn secret_handle(input: &Value) -> Option<String> {
    let text = match input {
        Value::String(text) => text.as_str(),
        Value::Object(fields) if fields.len() == 1 => fields.get("handle")?.as_str()?,
        _ => return None,
    };
    crate::secret_custody::parse_secret_handle(text)
        .is_ok()
        .then(|| text.to_owned())
}
