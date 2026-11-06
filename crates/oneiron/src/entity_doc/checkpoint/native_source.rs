//! Native document histories derived only from the owned checkpoint source.

use std::collections::BTreeMap;

use super::super::document::decode_frontier;
use super::super::forks::{ENTITY_DOC_FORK, ENTITY_DOC_FORK_SNAPSHOT, ForkRecord};
use super::super::native_skill_state::validate_checkpoint_history;
use super::{documents, loro, tree_entity};
use crate::EntityId;
use crate::error::Result;
use crate::side_table::SideKey;
use crate::store::checkpoint_payload::rows::{self, OpenedOwnerRows, RowLocator, RowPart};

/// Join all native document bytes before any row lands. Ordinary non-document
/// joins still run in their original order in `restore_parts`.
pub(super) fn prepare(opened: &OpenedOwnerRows) -> Result<BTreeMap<RowLocator, Vec<u8>>> {
    let mut rebuilt = documents::join_checked(opened, |entity, bytes| {
        validate_checkpoint_history(entity, bytes.iter().map(Vec::as_slice)).map(|_| ())
    })?;
    for part in &opened.rows {
        let at = part.at();
        if !at.in_table(ENTITY_DOC_FORK_SNAPSHOT.decl()) || held_up(opened, at) {
            continue;
        }
        let entity = tree_entity(opened)?;
        let bytes = match part {
            RowPart::Exact { value, .. } => value.clone(),
            RowPart::NoActor { value, .. } => {
                let parts = opened
                    .actor_parts
                    .iter()
                    .filter(|part| part.content_locator == *at)
                    .collect::<Vec<_>>();
                loro::join_fork_snapshot(&entity, value, &parts)?
            }
            RowPart::ActorKeyed { .. } => return Err(rows::bad_part()),
        };
        super::check(at, &bytes)?;
        if let Some(doc) = validate_checkpoint_history(entity, std::iter::once(bytes.as_slice()))? {
            require_fork_source(opened, entity, at, &doc)?;
        }
        rebuilt.insert(at.clone(), bytes);
    }
    Ok(rebuilt)
}

fn held_up(opened: &OpenedOwnerRows, at: &RowLocator) -> bool {
    opened
        .dependencies
        .iter()
        .any(|dependency| dependency.at == *at && opened.unavailable.contains(&dependency.on))
}

/// A native fork retains its actual source record and causal base. The
/// source parent's slot is historical too; an older native witness need
/// not have been published in that same slot before a legal SWITCH.
fn require_fork_source(
    opened: &OpenedOwnerRows,
    entity: EntityId,
    snapshot: &RowLocator,
    doc: &super::super::EntityDoc,
) -> Result<()> {
    let fork = snapshot
        .key
        .strip_prefix(ENTITY_DOC_FORK_SNAPSHOT.decl().prefix)
        .and_then(String::decode_key)
        .ok_or_else(rows::bad_part)?;
    let mut source = None;
    for part in &opened.rows {
        let at = part.at();
        if !at.in_table(ENTITY_DOC_FORK.decl()) {
            continue;
        }
        let key = at
            .key
            .strip_prefix(ENTITY_DOC_FORK.decl().prefix)
            .and_then(String::decode_key)
            .ok_or_else(rows::bad_part)?;
        if key != fork {
            continue;
        }
        let value = match part {
            RowPart::Exact { value, .. } | RowPart::NoActor { value, .. } => value,
            RowPart::ActorKeyed { .. } => return Err(rows::bad_part()),
        };
        super::check(at, value)?;
        let record: ForkRecord = super::super::storage::decode(value)?;
        if record.fork != fork || record.entity != entity.to_hex() || source.is_some() {
            return Err(rows::bad_part());
        }
        EntityId::from_hex(&record.parent_document)?;
        source = Some(record);
    }
    let source = source.ok_or_else(rows::bad_part)?;
    let base = decode_frontier(&source.base)?;
    if doc.doc.frontiers_to_vv(&base).is_none() {
        return Err(rows::bad_part());
    }
    Ok(())
}
