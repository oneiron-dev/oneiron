//! Closed verb-class registry. Slips persist identifiers, never expansions.

pub(crate) fn verb_class_members(class: &str) -> Option<&'static [&'static str]> {
    match class {
        "door.none" => Some(&[]),
        "door.push" => Some(&["receive-pack"]),
        "door.inject" => Some(&["inject"]),
        "door.lease" => Some(&["lease"]),
        "door.redeem" => Some(&["redeem"]),
        "door.operate" => Some(&["receive-pack", "inject", "lease"]),
        "door.delegate" => Some(&["receive-pack", "inject", "lease", "redeem", "mint"]),
        _ => None,
    }
}

pub(super) fn class_for_verb(verb: &str) -> Option<&'static str> {
    match verb {
        "receive-pack" => Some("door.push"),
        "inject" => Some("door.inject"),
        "lease" => Some("door.lease"),
        "redeem" => Some("door.redeem"),
        "mint" => Some("door.delegate"),
        _ => None,
    }
}

#[cfg(test)]
pub(super) fn fixture_class(verbs: &std::collections::BTreeSet<String>) -> String {
    for class in [
        "door.none",
        "door.push",
        "door.inject",
        "door.lease",
        "door.redeem",
        "door.operate",
        "door.delegate",
    ] {
        let members = verb_class_members(class).expect("registry class");
        if members.len() == verbs.len() && members.iter().all(|v| verbs.contains(*v)) {
            return class.to_owned();
        }
    }
    // Preserve hostile floor names so evaluator fixtures prove the floor arm.
    verbs.iter().cloned().collect::<Vec<_>>().join(",")
}
