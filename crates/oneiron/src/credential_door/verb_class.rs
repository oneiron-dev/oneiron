//! Scope presets for the credential door's operations.
use crate::federation::{Scope, ScopeAxis};

const PRESETS: [(&str, &[&str]); 4] = [
    ("door.push", &["receive-pack"]),
    ("door.inject", &["inject"]),
    ("door.lease", &["lease"]),
    ("door.redeem", &["redeem"]),
];

pub(super) fn preset(class: &str) -> Option<Scope> {
    let (_, verbs) = PRESETS.iter().find(|(name, _)| *name == class)?;
    Some(Scope {
        verbs: ScopeAxis::Some(verbs.iter().map(|verb| (*verb).to_owned()).collect()),
        ..Scope::top()
    })
}

pub(super) fn class_for_verb(verb: &str) -> Option<&'static str> {
    PRESETS
        .iter()
        .find(|(_, verbs)| verbs.contains(&verb))
        .map(|(name, _)| *name)
}
