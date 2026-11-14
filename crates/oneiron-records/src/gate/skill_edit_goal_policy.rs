//! Moved from `crates/oneiron/src/gate/skill_edit_goal_policy.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use rmpv::Value;
use serde::Serialize;
use std::collections::BTreeSet;

pub fn unique_field<'a>(entries: &'a [(Value, Value)], key: &str) -> Option<&'a Value> {
    if entries.iter().any(|(name, _)| name.as_str().is_none()) {
        return None;
    }
    let mut matches = entries
        .iter()
        .filter(|(name, _)| name.as_str() == Some(key));
    let value = &matches.next()?.1;
    matches.next().is_none().then_some(value)
}
