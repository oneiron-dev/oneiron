//! Typed selectors retained in a skill optimization attempt's input.

use crate::EntityId;
use rmpv::Value;

/// Nil is a library-wide attempt; map keys name only the explicit selectors.
/// Invalid shapes remain the worker's ordinary malformed-input error.
pub(crate) fn optimize_target_input(input: &Value) -> Option<(Option<EntityId>, Option<EntityId>)> {
    let Value::Map(fields) = input else {
        return input.is_nil().then_some((None, None));
    };
    if fields.is_empty() {
        return None;
    }
    let (mut resident, mut skill) = (None, None);
    for (key, value) in fields {
        let slot = match key.as_str()? {
            "resident" => &mut resident,
            "skill" => &mut skill,
            _ => return None,
        };
        if slot.is_some() {
            return None;
        }
        *slot = Some(EntityId::from_hex(value.as_str()?).ok()?);
    }
    Some((resident, skill))
}
