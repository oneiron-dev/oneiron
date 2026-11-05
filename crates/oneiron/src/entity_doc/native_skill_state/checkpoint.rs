//! Native values carried by an independently authenticated checkpoint source.
//!
//! These checks bind the source's exact document history. They do not grant
//! carrier standing, replay a native door or create a peer ACK.

use loro::{ContainerID, ContainerType, JsonMapOp, JsonOp, JsonOpContent, LoroValue};

use super::super::EntityDoc;
use super::codec::SkillStateFact;
use super::inspect::{NativeMapWrite, inspect};
use super::register::{CURRENT, ROOT};
use crate::EntityId;
use crate::error::{Error, Result};

fn invalid() -> Error {
    Error::CorruptedIndex("checkpoint native SKILL state source")
}

/// This is schema recognition only, never native admission.
pub(in crate::entity_doc) fn is_checkpoint_root(container: &ContainerID) -> bool {
    matches!(container, ContainerID::Root { name, container_type }
        if name.as_str() == ROOT && *container_type == ContainerType::Map)
}

pub(in crate::entity_doc) fn check_checkpoint_insert(key: &str, value: &LoroValue) -> Result<()> {
    if key != CURRENT {
        return Err(invalid());
    }
    let LoroValue::Binary(bytes) = value else {
        return Err(invalid());
    };
    SkillStateFact::decode(bytes.as_slice())?;
    Ok(())
}

pub(in crate::entity_doc) fn check_checkpoint_op(op: &JsonOp) -> Result<()> {
    if !is_checkpoint_root(&op.container) {
        return Err(invalid());
    }
    match &op.content {
        JsonOpContent::Map(JsonMapOp::Insert { key, value }) => check_checkpoint_insert(key, value),
        JsonOpContent::Map(JsonMapOp::Delete { key }) if key == CURRENT => Ok(()),
        _ => Err(invalid()),
    }
}

/// The caller owns these joined rows through the closed checkpoint source.
/// Check every retained raw insert, including overwritten values, and the
/// separate shallow floor. A source's explicit deletions remain deletions.
/// The witness's document coordinate names its original publication source,
/// not a later storage slot selected by SWITCH. Returns that document only
/// when it contains native state or writes, so its caller can check an
/// original fork basis without parsing the history a second time.
pub(in crate::entity_doc) fn validate_checkpoint_history<'a>(
    entity: EntityId,
    rows: impl IntoIterator<Item = &'a [u8]>,
) -> Result<Option<EntityDoc>> {
    let mut rows = rows.into_iter();
    let snapshot = rows.next().ok_or_else(invalid)?;
    let doc = EntityDoc::from_snapshot(snapshot)?;
    for update in rows {
        let imported = doc.doc.import(update).map_err(|_| invalid())?;
        if imported.pending.is_some() {
            return Err(invalid());
        }
    }
    let birth = doc.birth();
    if birth.entity != entity.to_hex() {
        return Err(invalid());
    }
    let check = |fact: &SkillStateFact| {
        if fact.target_birth_is(entity, birth.at) {
            Ok(())
        } else {
            Err(invalid())
        }
    };
    let inventory = inspect(&doc)?;
    let has_native = inventory.current.is_some()
        || !inventory.mutations.is_empty()
        || inventory
            .floor
            .as_ref()
            .is_some_and(|floor| floor.fact.is_some());
    if let Some(current) = &inventory.current {
        check(current)?;
    }
    if let Some(floor) = &inventory.floor
        && let Some(fact) = &floor.fact
    {
        check(fact)?;
    }
    for mutation in inventory.mutations {
        if let NativeMapWrite::Insert(fact) = mutation.write {
            check(&fact)?;
        }
    }
    Ok(has_native.then_some(doc))
}
