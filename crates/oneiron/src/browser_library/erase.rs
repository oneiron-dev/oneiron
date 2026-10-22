//! Erasing an actor from the browser library (moved out of
//! `browser_library` whole): the programs its run filed and the retires at
//! its word keep their rows and times, and state [`ERASED_CALL_IDENTITY`].

use super::{LibraryActor, RETIRED, WORKFLOWS, WorkflowRecord};
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;
#[cfg(doc)]
use crate::receipt::ERASED_CALL_IDENTITY;

/// Whether `actor` names an entity that is no actor, so erasing it scans
/// nothing. An id with no record, or one whose header does not parse, still
/// scans.
pub(super) fn is_no_actor(vault: &Vault, txn: &heed::RoTxn<'_>, actor: &EntityId) -> Result<bool> {
    if let Some(raw) = vault.get_raw_in(txn, actor)?
        && let Some(header) = crate::batch::EntityMetadataHeader::parse(&raw)
    {
        return Ok(!matches!(
            header.entity_type,
            crate::registry::ENTITY_TYPE_PERSON
                | crate::registry::ENTITY_TYPE_MACHINE
                | crate::registry::ENTITY_TYPE_AGENT_DEF
        ));
    }
    Ok(false)
}

/// Erasing `actor` from the filed programs: every program its run filed
/// keeps its row and its times, and states [`ERASED_CALL_IDENTITY`] for the
/// actor. One-way, in the erase's own transaction. An id whose entity is no
/// actor scans nothing.
///
/// # Errors
///
/// Storage errors, or a library row that cannot be read.
pub(crate) fn erase_workflow_actor_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    actor: &EntityId,
) -> Result<()> {
    if is_no_actor(vault, wtxn, actor)? {
        return Ok(());
    }
    let mut filed = Vec::new();
    for (key, mut record) in WORKFLOWS.scan(&vault.store, wtxn)? {
        let filer = record.filed_by.is(*actor);
        let scoped = filed_in_scope_of(&record, actor);
        if filer {
            record.filed_by = LibraryActor::Erased;
        }
        // A program filed in the actor's solved group covers it no more
        // (CUA E8a): the group named the actor.
        if scoped {
            super::index::uncover_in_txn(vault, wtxn, &record)?;
            record.filed_scope = None;
        }
        if filer || scoped {
            filed.push((key, record));
        }
    }
    for (key, record) in filed {
        WORKFLOWS.put(vault, wtxn, &key, &record)?;
    }
    Ok(())
}

/// Erasing `actor` from what retires took out: every retire at its word, and
/// every retired program its run filed, keeps its row, its times and its
/// reason, and states [`ERASED_CALL_IDENTITY`] for the actor. One-way, in the
/// erase's own transaction. An id whose entity is no actor scans nothing.
///
/// # Errors
///
/// Storage errors, or a library row that cannot be read.
pub(crate) fn erase_retired_actor_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    actor: &EntityId,
) -> Result<()> {
    if is_no_actor(vault, wtxn, actor)? {
        return Ok(());
    }
    let mut retired = Vec::new();
    for (id, mut trace) in RETIRED.scan(&vault.store, wtxn)? {
        let by = trace.retired_by.is(*actor);
        let filer = trace.record.filed_by.is(*actor);
        let scoped = filed_in_scope_of(&trace.record, actor);
        if by {
            trace.retired_by = LibraryActor::Erased;
        }
        if filer {
            trace.record.filed_by = LibraryActor::Erased;
        }
        if scoped {
            trace.record.filed_scope = None;
        }
        if by || filer || scoped {
            retired.push((id, trace));
        }
    }
    for (id, trace) in retired {
        RETIRED.put(vault, wtxn, &id, &trace)?;
    }
    Ok(())
}

/// Whether `record` was filed in a solved group of `actor`'s scope (CUA
/// E8a).
fn filed_in_scope_of(record: &WorkflowRecord, actor: &EntityId) -> bool {
    record
        .filed_scope
        .as_ref()
        .is_some_and(|filed| filed.scope.actor == *actor)
}
