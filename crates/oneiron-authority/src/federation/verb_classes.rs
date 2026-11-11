//! The verb classes an owner's agent Grant names beside its exact verbs
//! (FIX 8735, Engine 18:26 = A), in the one codec the Grant body and the
//! owner's signed mint act both use.
//!
//! A class is a name only: which verbs it admits resolves when a door judges
//! the Grant, from the class's own spelling, the built-in outbound class
//! registry and the owner's verb-class rows in the reader's snapshot. A Grant
//! with no class writes no key, so every earlier body and act keeps its
//! bytes. A class name is never the `git_push` verb: only the owner's
//! `git_push` mint confers raw push.

use std::collections::BTreeSet;

use rmpv::Value;

use super::git_push::GIT_PUSH_VERB;

/// The key that carries a Grant's or a mint act's class names; absent when
/// it names none.
pub const KEY_VERB_CLASSES: &str = "verb_classes";

/// Whether `name` may name a verb class: nonempty, with no surrounding
/// whitespace, and never the `git_push` verb.
#[must_use]
pub fn verb_class_name_is_valid(name: &str) -> bool {
    !name.is_empty() && name.trim() == name && name != GIT_PUSH_VERB
}

/// The canonical value of a nonempty class set: an array of its names in
/// ascending order.
#[must_use]
pub fn verb_classes_value(classes: &BTreeSet<String>) -> Value {
    Value::Array(
        classes
            .iter()
            .map(|class| Value::from(class.as_str()))
            .collect(),
    )
}

/// Decodes [`verb_classes_value`]'s form, fail-closed: a nonempty array of
/// valid names in strictly ascending order, nothing else.
#[must_use]
pub fn decode_verb_classes_value(value: &Value) -> Option<BTreeSet<String>> {
    let Value::Array(values) = value else {
        return None;
    };
    if values.is_empty() {
        return None;
    }
    let mut classes = BTreeSet::new();
    let mut previous: Option<&str> = None;
    for value in values {
        let name = value.as_str()?;
        if !verb_class_name_is_valid(name) || previous.is_some_and(|before| before >= name) {
            return None;
        }
        previous = Some(name);
        classes.insert(name.to_owned());
    }
    Some(classes)
}
