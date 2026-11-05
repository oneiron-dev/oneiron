//! Native document histories derived only from the owned checkpoint source.

use std::collections::BTreeMap;

use super::super::forks::ENTITY_DOC_FORK_SNAPSHOT;
use super::super::native_skill_state::validate_checkpoint_history;
use super::{documents, loro, tree_entity};
use crate::error::Result;
use crate::store::checkpoint_payload::rows::{self, OpenedOwnerRows, RowLocator, RowPart};

/// Join all native document bytes before any row lands. Ordinary non-document
/// joins still run in their original order in `restore_parts`.
pub(super) fn prepare(opened: &OpenedOwnerRows) -> Result<BTreeMap<RowLocator, Vec<u8>>> {
    let mut rebuilt = documents::join_checked(opened, |entity, bytes| {
        validate_checkpoint_history(entity, bytes.iter().map(Vec::as_slice))
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
        validate_checkpoint_history(entity, std::iter::once(bytes.as_slice()))?;
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
