//! The NOTE tombstone review (ARCH-0032 stage 3, OF-073; CALLS "FIX 2419
//! NOTE tombstone review"). The first NOTE review of each UTC calendar month
//! proposes a tombstone for each archived NOTE that
//! - has stayed archived past [`TOMBSTONE_RETENTION_MULTIPLIER`] times its
//!   kind's retention (a kind with no finite retention, a Keep kind, is
//!   never proposed);
//! - nothing links to: no inbound edge of any kind, no NOTE citing it and
//!   no entity derived from it;
//! - no one has read since it was archived.
//!
//! A proposal only asks. The owner accepts it through the deletion rail's
//! `user_delete` (`memory/note_tombstone.rs`), whose write rechecks all of
//! it; nothing here tombstones. A declined proposal is not asked again for
//! the same archive. A tombstone is never reverted.

use chrono::Datelike;
use serde::{Deserialize, Serialize};

use crate::deletion::TombstoneReason;
use crate::ports::{
    DeletionFamily, EdgeDirection, EdgeStoreRead, EntityStoreRead, TombstoneStoreRead,
};
use crate::registry::ENTITY_TYPE_NOTE;
use crate::side_table::{self, Named, SideTable};
use crate::{EntityId, Result, Vault};

/// How many times its kind's retention a NOTE stays archived before the
/// review proposes its tombstone.
const TOMBSTONE_RETENTION_MULTIPLIER: u64 = 2;
/// Seconds in one retention day.
const DAY_SECS: u64 = 86_400;

const PROPOSAL: SideTable<EntityId, NoteTombstoneProposal, Named> =
    SideTable::new(&side_table::NOTE_TOMBSTONE_PROPOSAL);
const REVIEWED: SideTable<(), NoteTombstoneReview, Named> =
    SideTable::new(&side_table::NOTE_TOMBSTONE_REVIEW);

/// One proposed NOTE tombstone, for the owner to accept or decline.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NoteTombstoneProposal {
    pub note: EntityId,
    /// The NOTE's kind, whose retention it outlived.
    pub kind: String,
    /// The kind's retention, in days.
    pub retention_days: u32,
    /// Unix seconds the NOTE was archived.
    pub archived_at: u64,
    /// The archive's request id. The proposal holds for this archive only:
    /// a NOTE restored and archived again is a new question.
    pub archive_request: Option<[u8; 16]>,
    /// Unix seconds the review proposed it.
    pub proposed_at: u64,
    /// Unix seconds the owner declined it, if they did.
    pub declined_at: Option<u64>,
}

/// The last month a tombstone review ran.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
struct NoteTombstoneReview {
    /// The UTC calendar month, counted from year 0.
    month: u32,
}

/// The UTC calendar month `secs` falls in, counted from year 0.
fn month_of(secs: u64) -> u32 {
    i64::try_from(secs)
        .ok()
        .and_then(|secs| chrono::DateTime::from_timestamp(secs, 0))
        .map_or(0, |at| {
            u32::try_from(at.year()).unwrap_or(0) * 12 + at.month0()
        })
}

/// Runs this month's tombstone review once: the first call in a UTC
/// calendar month proposes a tombstone for each archived NOTE that
/// qualifies, and later calls that month do nothing. Returns how many it
/// proposed.
pub(crate) fn review_note_tombstones(vault: &Vault) -> Result<usize> {
    let now = vault.now_recorded_at();
    let month = month_of(now);
    let found = {
        let txn = vault.store.env.read_txn()?;
        if !due_in_txn(vault, &txn, month)? {
            return Ok(0);
        }
        let mut archived = Vec::new();
        for row in
            TombstoneStoreRead::port_tombstone_records(&vault.store, &txn, DeletionFamily::Archive)?
        {
            let (note, marker) = row?;
            if marker.reason == Some(TombstoneReason::ArchivedByCleanup) {
                archived.push(note);
            }
        }
        let mut found = Vec::new();
        for note in archived {
            if new_proposal_in_txn(vault, &txn, note, now)?.is_some() {
                found.push(note);
            }
        }
        found
    };
    vault.with_write_txn(|txn| {
        if !due_in_txn(vault, txn, month)? {
            return Ok(0);
        }
        let mut proposed = 0;
        for note in &found {
            // Rechecked in the write: a NOTE restored, linked or read since
            // the scan is not proposed.
            if let Some(proposal) = new_proposal_in_txn(vault, txn, *note, now)? {
                PROPOSAL.put(&vault.store, txn, note, &proposal)?;
                proposed += 1;
            }
        }
        REVIEWED.put(&vault.store, txn, &(), &NoteTombstoneReview { month })?;
        Ok(proposed)
    })
}

/// Whether no tombstone review has run in `month` yet.
fn due_in_txn(vault: &Vault, txn: &heed::RoTxn<'_>, month: u32) -> Result<bool> {
    Ok(REVIEWED
        .get(&vault.store, txn, &())?
        .is_none_or(|done| done.month < month))
}

/// `note`'s proposal when it qualifies and was not asked about in this
/// archive already, whatever the owner answered.
fn new_proposal_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    note: EntityId,
    now: u64,
) -> Result<Option<NoteTombstoneProposal>> {
    let asked = PROPOSAL.get(&vault.store, txn, &note)?;
    Ok(qualifies_in_txn(vault, txn, note, now)?
        .filter(|proposal| asked.is_none_or(|asked| !same_archive(&asked, proposal))))
}

fn same_archive(a: &NoteTombstoneProposal, b: &NoteTombstoneProposal) -> bool {
    a.archived_at == b.archived_at && a.archive_request == b.archive_request
}

/// `note`'s tombstone proposal as of `now`, if it qualifies: archived by
/// cleanup past [`TOMBSTONE_RETENTION_MULTIPLIER`] times its kind's finite
/// retention, linked from nothing, and unread since its archive.
fn qualifies_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    note: EntityId,
    now: u64,
) -> Result<Option<NoteTombstoneProposal>> {
    let Some(marker) = vault.archive_tombstone_in_txn(txn, &note)? else {
        return Ok(None);
    };
    if marker.reason != Some(TombstoneReason::ArchivedByCleanup) {
        return Ok(None);
    }
    let Some(row) = EntityStoreRead::port_entity_record(&vault.store, txn, &note)? else {
        return Ok(None);
    };
    if row.entity_type != ENTITY_TYPE_NOTE
        || vault.local_hard_delete_marker_exists_in_txn(txn, &note)?
        || vault
            .store
            .entity_deletion_present_in_txn(txn, &note, row.learned_at)?
    {
        return Ok(None);
    }
    let Ok(body) = super::decode_note_body_in_txn(&vault.store, txn, &row.body) else {
        return Ok(None);
    };
    let kind = body.kind.as_str().into_owned();
    let Some(descriptor) = super::descriptor_in_txn(&vault.store, txn, &kind)? else {
        return Ok(None);
    };
    let (super::RetentionDefault::ArchiveAfterDays, Some(days @ 1..)) =
        (descriptor.retention, descriptor.archive_after_days)
    else {
        return Ok(None);
    };
    let kept = TOMBSTONE_RETENTION_MULTIPLIER
        .saturating_mul(u64::from(days))
        .saturating_mul(DAY_SECS);
    if now.saturating_sub(marker.deleted_at) <= kept
        || linked_in_txn(vault, txn, note)?
        || super::archive_read::read_since_archive_in_txn(
            &vault.store,
            txn,
            note,
            marker.deleted_at,
            marker.request_id,
        )?
    {
        return Ok(None);
    }
    Ok(Some(NoteTombstoneProposal {
        note,
        kind,
        retention_days: days,
        archived_at: marker.deleted_at,
        archive_request: marker.request_id,
        proposed_at: now,
        declined_at: None,
    }))
}

/// Whether anything links to `note`: an inbound edge of any kind (a claim
/// about it, a mention, a part-of), a NOTE citing it, or an entity derived
/// from it.
fn linked_in_txn(vault: &Vault, txn: &heed::RoTxn<'_>, note: EntityId) -> Result<bool> {
    if EdgeStoreRead::port_edges(&vault.store, txn, &note, EdgeDirection::In, None, None)?
        .next()
        .transpose()?
        .is_some()
    {
        return Ok(true);
    }
    if super::citation_delete_scope_exists(&vault.store, txn, &note)? {
        return Ok(true);
    }
    crate::ports::source_has_dependents_in_txn(&vault.store, txn, &note)
}

/// The proposals the owner has not decided, oldest first.
pub(crate) fn open_tombstone_proposals_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
) -> Result<Vec<NoteTombstoneProposal>> {
    let mut open: Vec<NoteTombstoneProposal> = PROPOSAL
        .scan(&vault.store, txn)?
        .into_iter()
        .map(|(_, proposal)| proposal)
        .filter(|proposal| proposal.declined_at.is_none())
        .collect();
    open.sort_by_key(|proposal| (proposal.proposed_at, proposal.note));
    Ok(open)
}

/// Whether `note`'s tombstone is still the one proposed: the proposal is
/// open, and the NOTE still qualifies in the archive it was proposed in.
pub(crate) fn tombstone_still_proposed_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    note: EntityId,
) -> Result<bool> {
    let Some(asked) = PROPOSAL.get(&vault.store, txn, &note)? else {
        return Ok(false);
    };
    if asked.declined_at.is_some() {
        return Ok(false);
    }
    Ok(qualifies_in_txn(vault, txn, note, vault.now_recorded_at())?
        .is_some_and(|now| same_archive(&asked, &now)))
}

/// After the owner's tombstone of `note` committed: its proposal is spent,
/// and its archive marker goes, so the NOTE reads as tombstoned rather than
/// archived and no restore lists it.
pub(crate) fn tombstone_accepted(vault: &Vault, note: EntityId) -> Result<()> {
    vault.with_write_txn(|txn| {
        PROPOSAL.delete(&vault.store, txn, &note)?;
        vault.clear_archive_tombstone_in_txn(txn, &note)?;
        Ok(())
    })
}

/// Declines `note`'s open proposal: it stays on record, and the review
/// does not ask again while the NOTE stays in that archive. `false` when no
/// open proposal names it.
pub(crate) fn decline_tombstone(vault: &Vault, note: EntityId) -> Result<bool> {
    vault.with_write_txn(|txn| {
        let Some(mut asked) = PROPOSAL.get(&vault.store, txn, &note)? else {
            return Ok(false);
        };
        if asked.declined_at.is_some() {
            return Ok(false);
        }
        asked.declined_at = Some(vault.now_recorded_at());
        PROPOSAL.put(&vault.store, txn, &note, &asked)?;
        Ok(true)
    })
}
