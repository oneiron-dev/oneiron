//! Registered verb classes for the credential door. A slip stores class names,
//! not a snapshot of the verbs in each class.
use crate::federation::{Scope, ScopeAxis};

// The registry is resolved at evaluation, not expanded when a slip is minted.
// Only the checkout path mints door.push in production. The other classes
// describe the door's existing operation vocabulary for scoped grants.
const CLASSES: [(&str, &[&str]); 5] = [
    ("door.push", &["receive-pack"]),
    ("door.inject", &["inject"]),
    ("door.lease", &["lease"]),
    ("door.redeem", &["redeem"]),
    ("door.credential", &["inject", "lease", "redeem"]),
];

/// A preset is a six-axis federation Scope, with a CLASS on its verb axis.
pub(super) fn preset(class: &str) -> Option<Scope> {
    CLASSES.iter().find(|(name, _)| *name == class)?;
    Some(Scope {
        verbs: ScopeAxis::Some([class.to_owned()].into()),
        ..Scope::top()
    })
}

/// Resolve membership from the registry on every call. An unknown class or
/// unknown verb confers nothing, even if it appears in an attenuated scope.
pub(super) fn contains(class: &str, verb: &str) -> bool {
    CLASSES
        .iter()
        .find(|(name, _)| *name == class)
        .is_some_and(|(_, verbs)| verbs.contains(&verb))
}

/// Every class the registry says contains this verb, narrowest first.
pub(super) fn classes_for_verb(verb: &str) -> impl Iterator<Item = &'static str> {
    CLASSES
        .iter()
        .filter(move |(_, verbs)| verbs.contains(&verb))
        .map(|(name, _)| *name)
}

/// The narrowest registered class to request when a slip misses a verb.
pub(super) fn class_for_verb(verb: &str) -> Option<&'static str> {
    classes_for_verb(verb).next()
}
