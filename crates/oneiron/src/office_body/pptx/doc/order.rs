//! A movable list of identities (a body's paragraphs, a table's rows or
//! columns): read in order, and made equal to a target order with the
//! fewest writes, so a concurrent writer's moves, inserts and deletes of
//! other entries merge with these. What the target no longer holds is
//! deleted and a repeat dropped (the first kept); an entry out of place is
//! moved, keeping its list identity, and a new one is inserted.

use super::{invalid, loro};
use crate::error::Result;
use loro::{LoroMovableList, LoroValue, ValueOrContainer};
use std::collections::BTreeSet;

/// The list's identities, in order.
pub(super) fn ids(list: &LoroMovableList) -> Result<Vec<String>> {
    (0..list.len())
        .map(|index| match list.get(index) {
            Some(ValueOrContainer::Value(LoroValue::String(id))) => Ok(id.to_string()),
            _ => Err(invalid("deck body order entry")),
        })
        .collect()
}

/// Make `list` hold exactly `wanted`, in its order.
pub(super) fn sync(list: &LoroMovableList, wanted: &[String]) -> Result<()> {
    let keep: BTreeSet<&str> = wanted.iter().map(String::as_str).collect();
    let held = ids(list)?;
    for (index, id) in held.iter().enumerate().rev() {
        if !keep.contains(id.as_str()) || held[..index].contains(id) {
            list.delete(index, 1).map_err(loro)?;
        }
    }
    let mut held = ids(list)?;
    for (index, id) in wanted.iter().enumerate() {
        if held.get(index) == Some(id) {
            continue;
        }
        match held.iter().position(|other| other == id) {
            Some(from) => {
                list.mov(from, index).map_err(loro)?;
                let moved = held.remove(from);
                held.insert(index, moved);
            }
            None => {
                list.insert(index, id.as_str()).map_err(loro)?;
                held.insert(index, id.clone());
            }
        }
    }
    Ok(())
}
