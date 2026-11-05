//! Pure projection of the state carried by this exact document frontier.

use std::collections::BTreeSet;

use rmpv::Value;

use super::super::EntityDoc;
use super::register::read_fact;
use crate::error::{Error, Result};

/// The caller has already admitted this document's native witnesses. This
/// reads only that document, including when it is a retained historical fork.
/// It never substitutes a current Store value for a historical one.
pub(super) fn project_state(doc: &EntityDoc, body: &mut Value) -> Result<()> {
    let Some(fact) = read_fact(doc)? else {
        return Ok(());
    };
    if !fact.names_birth(doc.birth()) {
        return Err(Error::CorruptedIndex("native SKILL state document birth"));
    }
    let Value::Map(fields) = body else {
        return Err(Error::CorruptedIndex("native SKILL state body map"));
    };
    // The immutable body owns its other fields. Do not rebuild a SkillRecord
    // here: that would silently drop fields this reader does not know.
    let mut keys = BTreeSet::new();
    let mut lifecycle = None;
    let mut approval = None;
    for (index, (key, _)) in fields.iter().enumerate() {
        let key = key
            .as_str()
            .ok_or(Error::CorruptedIndex("native SKILL state body key"))?;
        if !keys.insert(key) {
            return Err(Error::CorruptedIndex(
                "duplicate native SKILL state body key",
            ));
        }
        match key {
            "lifecycleStatus" => lifecycle = Some(index),
            "approvalStatus" => approval = Some(index),
            _ => {}
        }
    }
    let lifecycle = lifecycle.ok_or(Error::CorruptedIndex("native SKILL state body lifecycle"))?;
    let approval = approval.ok_or(Error::CorruptedIndex("native SKILL state body approval"))?;
    let (next_lifecycle, next_approval) = fact.state()?;
    fields[lifecycle].1 = Value::from(next_lifecycle.as_str());
    fields[approval].1 = Value::from(next_approval.as_str());
    Ok(())
}
