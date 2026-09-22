//! Scope presets for the credential door's seven action classes.
use crate::federation::{Scope, ScopeAxis};

const PRESETS: [(&str, &[&str]); 7] = [
    ("door.none", &[]),
    ("door.push", &["receive-pack"]),
    ("door.inject", &["inject"]),
    ("door.lease", &["lease"]),
    ("door.redeem", &["redeem"]),
    ("door.operate", &["receive-pack", "inject", "lease"]),
    (
        "door.delegate",
        &["receive-pack", "inject", "lease", "redeem", "mint"],
    ),
];

pub(super) fn preset(class: &str) -> Option<Scope> {
    let (_, verbs) = PRESETS.iter().find(|(name, _)| *name == class)?;
    Some(Scope {
        verbs: if verbs.is_empty() {
            ScopeAxis::Bottom
        } else {
            ScopeAxis::Some(verbs.iter().map(|verb| (*verb).to_owned()).collect())
        },
        ..Scope::top()
    })
}

pub(super) fn class_for_verb(verb: &str) -> Option<&'static str> {
    PRESETS
        .iter()
        .find(|(_, verbs)| verbs.contains(&verb))
        .map(|(name, _)| *name)
}
