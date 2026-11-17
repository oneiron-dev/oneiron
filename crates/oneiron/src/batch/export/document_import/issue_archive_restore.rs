//! Owner-only ISSUE recovery, separate from generic maintenance-row admission.
use std::collections::BTreeMap;
use std::io::{Read, Seek};

use super::{OwnerArchiveRestorePermit, invalid, stamp_archived_birth};
use crate::batch::export::archive_index::{IndexedArchive, Tag};
use crate::feedback::{ReportRestoreOutcome, ReportRoute, restorable_archived_report};
use crate::registry::ENTITY_TYPE_ISSUE;
use crate::serialize::ExportSecrets;
use crate::vault::live_entity_row_in_txn;
use crate::{Result, Vault};

/// The filing resolver's artifact route for each distinct subject an archived
/// ISSUE names, resolved before the import's writer opens: the resolver opens
/// read transactions of its own (as `submit_report` resolves before its write).
pub(super) fn artifact_routes<R: Read + Seek>(
    vault: &Vault,
    archive: &IndexedArchive<'_, R>,
    secrets: ExportSecrets,
) -> Result<BTreeMap<String, Option<ReportRoute>>> {
    let mut routes = BTreeMap::new();
    let mut after = None;
    while let Some(id) = archive.next_of_type(ENTITY_TYPE_ISSUE, after.as_ref())? {
        after = Some(id);
        let (_, row) = archive
            .entity(&id)?
            .ok_or_else(|| invalid("missing archived ISSUE"))?;
        let body = row.body.to_bytes_in_with(&archive.files, secrets)?;
        // A body that is no restorable report stays omitted and needs no route.
        let Some(issue) = restorable_archived_report(id, &body) else {
            continue;
        };
        if let std::collections::btree_map::Entry::Vacant(entry) =
            routes.entry(issue.request.subject_ref)
        {
            let route = vault.archived_report_artifact_route(entry.key())?;
            entry.insert(route);
        }
    }
    Ok(routes)
}

/// Restores each archived ISSUE through the feedback writer on the owner's
/// restore only (the permit is the proof), after the same off-record, deletion
/// and collision checks the generic pass makes. Each restored or unchanged id
/// leaves the omitted set; returns the (inserted, unchanged) counts. An ISSUE
/// whose body is no restorable report (`restorable_archived_report`: an
/// export without secrets nulls credential-shaped text) stays omitted, as
/// every ISSUE was before this restore, and the rest of the archive restores.
pub(super) fn restore_in_txn<R: Read + Seek>(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    archive: &mut IndexedArchive<'_, R>,
    _permit: &OwnerArchiveRestorePermit,
    routes: &BTreeMap<String, Option<ReportRoute>>,
    secrets: ExportSecrets,
) -> Result<(usize, usize)> {
    let (mut inserted, mut unchanged) = (0, 0);
    let mut after = None;
    while let Some(id) = archive.next_of_type(ENTITY_TYPE_ISSUE, after.as_ref())? {
        after = Some(id);
        let (_, row) = archive
            .entity(&id)?
            .ok_or_else(|| invalid("missing archived ISSUE"))?;
        let body = row.body.to_bytes_in_with(&archive.files, secrets)?;
        let Some(issue) = restorable_archived_report(id, &body) else {
            continue;
        };
        if vault.store.off_record_sessions.contains_entity(&id)? {
            return Err(invalid("import ID belongs to an off-record overlay"));
        }
        if crate::ports::EntityStoreRead::port_entity_raw(&vault.store, txn, &id)?.is_some() {
            if !live_entity_row_in_txn(&vault.store, txn, &id)?.is_live() {
                return Err(invalid("import ID collides with a deleted entity"));
            }
        } else {
            let state =
                crate::ports::TombstoneStoreRead::port_deletion_state(&vault.store, txn, &id)?;
            if state.deleted
                || state.stale
                || vault.local_hard_delete_marker_exists_in_txn(txn, &id)?
            {
                return Err(invalid("import ID collides with a deleted entity"));
            }
        }
        let route = routes
            .get(&issue.request.subject_ref)
            .ok_or_else(|| invalid("missing archived report route"))?
            .clone();
        match vault.restore_archived_report_in_txn(txn, id, issue, route)? {
            ReportRestoreOutcome::Inserted => {
                archive.index.put(Tag::Inserted, id.as_bytes(), &[])?;
                inserted += 1;
            }
            ReportRestoreOutcome::Unchanged => unchanged += 1,
        }
        stamp_archived_birth(vault, txn, archive, &id)?;
        archive.index.remove(Tag::Omitted, id.as_bytes())?;
    }
    Ok((inserted, unchanged))
}
