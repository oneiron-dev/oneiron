//! Owner restore of archived source-audience policies (SIDE-4c).
//!
//! Two passes, sources then threads, one input-order outcome per envelope.
//! A decoded `SOURCE_AUDIENCE_POLICY` row installs only when every person
//! it names is a live `PERSON` and, for a thread, its source policy is a
//! live source. An installed row re-lays its wake and, for a thread,
//! rebuilds its `THREADS` index entry; event history stays lost (its
//! revision survives in the value). Storage failures propagate; validation
//! stays in the outcomes.

use super::{POLICIES, SourceAudienceKind, SourceAudiencePolicy};
use crate::EntityId;
use crate::Vault;
use crate::batch::export::archive_side_install::{
    ArchivedSideRowOutcome, decode_archived_row, install_archived_row,
};
use crate::batch::export::{
    ArchiveRetainedSideRow, OwnerArchiveRestorePermit, RetainedSideHeldBackReason,
};
use crate::error::Result;
use crate::registry::ENTITY_TYPE_PERSON;
use crate::vault::{LiveEntityRow, live_entity_row_in_txn};
use std::collections::BTreeSet;

/// Lands archived source-audience policies whose people and sources resolve.
///
/// Pass one installs sources; pass two lands threads against live plus
/// pass-one sources, rejecting archived thread parents. Outcomes stay in input
/// order.
pub(crate) fn land_archived_source_audience_rows_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    permit: &OwnerArchiveRestorePermit,
    rows: &[ArchiveRetainedSideRow],
) -> Result<Vec<ArchivedSideRowOutcome>> {
    use ArchivedSideRowOutcome::HeldBack;

    let decoded: Vec<_> = rows
        .iter()
        .map(|row| decode_archived_row(&POLICIES, row))
        .collect();
    let mut outcomes: Vec<_> = decoded
        .iter()
        .map(|row| match row {
            Err(reason) => HeldBack(*reason),
            Ok(_) => HeldBack(RetainedSideHeldBackReason::MissingCompanion),
        })
        .collect();

    // Pass one: sources install before any thread names them.
    for (index, row) in decoded.iter().enumerate() {
        let Ok((key, policy)) = row else {
            continue;
        };
        if !matches!(&policy.kind, SourceAudienceKind::Source { .. }) {
            continue;
        }
        if let Some(reason) = person_holdback_in_txn(vault, txn, policy)? {
            outcomes[index] = HeldBack(reason);
            continue;
        }
        let outcome = install_archived_row(&POLICIES, vault, txn, permit, key, &rows[index])?;
        if matches!(outcome, ArchivedSideRowOutcome::Installed) {
            super::replica::index_thread_in_txn(vault, txn, key, policy)?;
            super::wake::wake_policy_in_txn(vault, txn, key)?;
        }
        outcomes[index] = outcome;
    }

    // Archived threads never satisfy a source, regardless of their input order.
    let archived_threads: BTreeSet<_> = decoded
        .iter()
        .filter_map(|row| match row {
            Ok((key, policy)) if matches!(&policy.kind, SourceAudienceKind::Thread { .. }) => {
                Some(*key)
            }
            _ => None,
        })
        .collect();
    for (index, row) in decoded.iter().enumerate() {
        let Ok((key, policy)) = row else {
            continue;
        };
        let SourceAudienceKind::Thread { source, .. } = &policy.kind else {
            continue;
        };
        if let Some(reason) = person_holdback_in_txn(vault, txn, policy)? {
            outcomes[index] = HeldBack(reason);
            continue;
        }
        let reason = match POLICIES.get(&vault.store, txn, source)? {
            Some(parent) if matches!(&parent.kind, SourceAudienceKind::Source { .. }) => None,
            Some(_) => Some(RetainedSideHeldBackReason::InvalidValue),
            None if archived_threads.contains(source) => {
                Some(RetainedSideHeldBackReason::InvalidValue)
            }
            None => Some(RetainedSideHeldBackReason::MissingCompanion),
        };
        if let Some(reason) = reason {
            outcomes[index] = HeldBack(reason);
            continue;
        }
        let outcome = install_archived_row(&POLICIES, vault, txn, permit, key, &rows[index])?;
        if matches!(outcome, ArchivedSideRowOutcome::Installed) {
            super::replica::index_thread_in_txn(vault, txn, key, policy)?;
            super::wake::wake_policy_in_txn(vault, txn, key)?;
        }
        outcomes[index] = outcome;
    }

    Ok(outcomes)
}

/// The holdback for a person the policy names, or `None` when every named
/// person is a live `PERSON`. Readers first, then the erasable creator.
fn person_holdback_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    policy: &SourceAudiencePolicy,
) -> Result<Option<RetainedSideHeldBackReason>> {
    match &policy.kind {
        SourceAudienceKind::Source { readers, .. } => {
            for person in readers {
                if let Some(reason) = live_person_holdback_in_txn(vault, txn, person)? {
                    return Ok(Some(reason));
                }
            }
        }
        SourceAudienceKind::Thread { shared_with, .. } => {
            for person in shared_with {
                if let Some(reason) = live_person_holdback_in_txn(vault, txn, person)? {
                    return Ok(Some(reason));
                }
            }
        }
    }
    if let Some(created_by) = policy.created_by.as_ref()
        && let Some(reason) = live_person_holdback_in_txn(vault, txn, created_by)?
    {
        return Ok(Some(reason));
    }
    Ok(None)
}

/// The holdback for one named person, or `None` for a live `PERSON`.
fn live_person_holdback_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    person: &EntityId,
) -> Result<Option<RetainedSideHeldBackReason>> {
    use RetainedSideHeldBackReason::{MissingLiveEntity, WrongEntityKind};
    match live_entity_row_in_txn(&vault.store, txn, person)? {
        LiveEntityRow::Live { entity_type, .. } if entity_type == ENTITY_TYPE_PERSON => Ok(None),
        LiveEntityRow::Live { .. } => Ok(Some(WrongEntityKind)),
        LiveEntityRow::Absent | LiveEntityRow::DeletedShell => Ok(Some(MissingLiveEntity)),
    }
}
