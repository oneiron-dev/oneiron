//! The solved-run index (CUA E8a; DESIGN-2 "The Coach", row E8): group,
//! coverage, failure, dirty and seen rows beside the library's records and
//! the evidence claims. Each is written in the same write as the record or
//! claim it follows, never caught up after; none holds an evidence body.
//!
//! - group: a scoped group's evidence claims, by the group's digest;
//! - coverage: the live programs filed in a scoped group;
//! - failure: each program whose library runs failed, live or retired;
//! - dirty: a group's full key, and the generation it changed to and the
//!   one the Coach processed through;
//! - seen: a candidate program the Coach already proposed;
//! - authority: the source authority each evidence was captured under.
//!
//! Reads walk their rows a page at a time ([`SOLVED_PAGE`]) until the
//! cursor ends: a traversal batch, never a cap on what is read.

pub mod all_groups;

use std::ops::Bound;

use serde::{Deserialize, Serialize};

use super::evidence::{
    SOLVED_RUN_PREDICATE, SavedBrowserCaller, ScopedSolvedGroupKey, SolvedGroupKey,
    SolvedRunEvidence,
};
use super::records::site_key;
use super::{RETIRED, WORKFLOWS, WorkflowRecord, superseded_by};
use crate::Vault;
use crate::claim::{ScopedRead, ScopedReadResult};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::side_table::{self, Named, SideTable};

/// How many rows one page of a solved-run read walks (CUA E8a, CALLS row
/// "pages"): a traversal batch. Every row is reached by following the
/// cursor; nothing is capped.
pub const SOLVED_PAGE: usize = 128;

/// Each evidence claim's source authority. Key: the claim's id.
const AUTHORITY: SideTable<EntityId, SavedBrowserCaller, Named> =
    SideTable::new(&side_table::BROWSER_PROGRAM_AUTHORITY);

/// Each program whose library runs failed. Key: the program's id.
const FAILURES: SideTable<EntityId, FailureMark, Named> =
    SideTable::new(&side_table::BROWSER_PROGRAM_FAILURE);

/// Each candidate the Coach proposed. Key: its input fingerprint.
const SEEN: SideTable<[u8; 32], ProgramSeen, Named> =
    SideTable::new(&side_table::BROWSER_PROGRAM_SEEN);

/// The live programs filed in a group. Key: the group's digest, then the
/// program's id.
const COVERAGE: SideTable<([u8; 32], EntityId), CoverageRef, Named> =
    SideTable::new(&side_table::BROWSER_SOLVED_COVERAGE);

/// Each group's key and generations. Key: the group's digest.
const DIRTY: SideTable<[u8; 32], DirtyRow, Named> =
    SideTable::new(&side_table::BROWSER_SOLVED_DIRTY);

/// A group's evidence claims. Key: the group's digest, then the claim's id.
const GROUP: SideTable<([u8; 32], EntityId), GroupRef, Named> =
    SideTable::new(&side_table::BROWSER_SOLVED_GROUP);

/// Where a failed program's row is, and its group.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct FailureMark {
    /// Its site's hash, as the live record is keyed.
    site: [u8; 32],
    group: Option<[u8; 32]>,
    /// Moves on each failure, refile and retire.
    generation: u64,
}

/// A live program in a group.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct CoverageRef {
    filed_at: u64,
}

/// A group's key and generations.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct DirtyRow {
    key: ScopedSolvedGroupKey,
    changed: u64,
    processed: u64,
}

/// One evidence claim in a group.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct GroupRef {
    run_id: EntityId,
    captured_at_ms: u64,
}

/// Where a paged read goes on from: the last row it walked, exclusive.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PageCursor(Vec<u8>);

/// One page of a read: its rows, and the cursor of the next page, none
/// once the read is done.
#[derive(Debug, Clone)]
pub struct Page<T> {
    pub items: Vec<T>,
    pub next: Option<PageCursor>,
}

/// A group whose evidence, coverage or failures changed past what the
/// Coach processed (CUA E8a).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirtySolvedGroup {
    pub key: ScopedSolvedGroupKey,
    /// The group's digest, as its rows are keyed.
    pub digest: [u8; 32],
    /// The generation it changed to; [`mark_group_clean`] through it.
    pub changed: u64,
    pub processed: u64,
}

/// A program whose library runs failed, live or retired (CUA E8a): its
/// own record's lifetime count, never a successor's.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProgramFailureRef {
    pub id: EntityId,
    pub failures: u64,
    pub retired: bool,
    pub retire_reason: Option<String>,
    pub refs: FailureLineage,
}

/// Where a failed program sits in its lineage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FailureLineage {
    pub site: String,
    pub supersedes: Option<EntityId>,
    /// The program that repaired it, when a retire names one.
    pub successor: Option<EntityId>,
}

/// A candidate program the Coach proposed (CUA E8): its finding, its
/// admission job once one is queued, and the generation it read.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProgramSeen {
    pub finding: EntityId,
    pub job: Option<EntityId>,
    pub generation: u64,
}

fn cursor_bytes<const N: usize>(cursor: &PageCursor) -> Result<[u8; N]> {
    <[u8; N]>::try_from(cursor.0.as_slice()).map_err(|_| Error::InvalidClaimBody("page cursor"))
}

fn cursor_id(cursor: &PageCursor) -> Result<EntityId> {
    EntityId::from_bytes(cursor_bytes(cursor)?)
}

/// The scoped group a program is filed in: none for a filing with no
/// caller scope.
pub(super) fn record_group(record: &WorkflowRecord) -> Option<ScopedSolvedGroupKey> {
    let filed = record.filed_scope.as_ref()?;
    Some(ScopedSolvedGroupKey {
        scope: filed.scope.clone(),
        group: SolvedGroupKey {
            site: record.site.clone(),
            origin: filed.origin.clone(),
            type_ref: record.type_ref.clone(),
            subgoal: record.program.subgoal.clone(),
        },
    })
}

/// Moves `key`'s changed generation on, writing its row the first time.
fn bump_dirty_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    key: &ScopedSolvedGroupKey,
) -> Result<()> {
    let digest = key.digest();
    let row = match DIRTY.get(&vault.store, wtxn, &digest)? {
        Some(mut row) => {
            row.changed = row.changed.saturating_add(1);
            row
        }
        None => DirtyRow {
            key: key.clone(),
            changed: 1,
            processed: 0,
        },
    };
    DIRTY.put(vault, wtxn, &digest, &row)
}

/// Moves the changed generation of the group `digest` keys on, when it
/// has a row.
fn touch_dirty_in_txn(vault: &Vault, wtxn: &mut heed::RwTxn<'_>, digest: &[u8; 32]) -> Result<()> {
    let Some(mut row) = DIRTY.get(&vault.store, wtxn, digest)? else {
        return Ok(());
    };
    row.changed = row.changed.saturating_add(1);
    DIRTY.put(vault, wtxn, digest, &row)
}

/// Indexes a fresh evidence claim in `wtxn`, the claim's own write: its
/// group ref, its source authority and its group's generation.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn index_capture_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    evidence: &SolvedRunEvidence,
    caller: &SavedBrowserCaller,
) -> Result<()> {
    let key = evidence.group();
    let row = GroupRef {
        run_id: evidence.run_id,
        captured_at_ms: evidence.captured_at_ms,
    };
    GROUP.put(vault, wtxn, &(key.digest(), evidence.id), &row)?;
    AUTHORITY.put(vault, wtxn, &evidence.id, caller)?;
    bump_dirty_in_txn(vault, wtxn, &key)
}

/// Indexes a filing in its own write: the group `record` was in before
/// (`prior`, read in this write) loses its coverage when it moved, its
/// group now covers it, and its failure row follows it.
pub(super) fn index_filing_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    prior: Option<&WorkflowRecord>,
    record: &WorkflowRecord,
) -> Result<()> {
    let before = prior.and_then(record_group);
    let after = record_group(record);
    if let Some(old) = &before
        && Some(old) != after.as_ref()
    {
        COVERAGE.delete(&vault.store, wtxn, &(old.digest(), record.id))?;
        bump_dirty_in_txn(vault, wtxn, old)?;
    }
    if let Some(new) = &after {
        let cover = CoverageRef {
            filed_at: record.filed_at,
        };
        COVERAGE.put(vault, wtxn, &(new.digest(), record.id), &cover)?;
        bump_dirty_in_txn(vault, wtxn, new)?;
    }
    if let Some(mut mark) = FAILURES.get(&vault.store, wtxn, &record.id)? {
        mark.group = after.as_ref().map(ScopedSolvedGroupKey::digest);
        mark.generation = mark.generation.saturating_add(1);
        FAILURES.put(vault, wtxn, &record.id, &mark)?;
    }
    Ok(())
}

/// Indexes a library run of `record` that failed, in its own write, its
/// count already moved: its failure row, and its group's generation.
pub(super) fn index_failure_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    record: &WorkflowRecord,
) -> Result<()> {
    let group = record_group(record);
    let generation = FAILURES
        .get(&vault.store, wtxn, &record.id)?
        .map_or(0, |mark| mark.generation)
        .saturating_add(1);
    let mark = FailureMark {
        site: site_key(&record.site),
        group: group.as_ref().map(ScopedSolvedGroupKey::digest),
        generation,
    };
    FAILURES.put(vault, wtxn, &record.id, &mark)?;
    if let Some(group) = &group {
        bump_dirty_in_txn(vault, wtxn, group)?;
    }
    Ok(())
}

/// Takes `record`'s coverage out of its group, moving the group on.
pub(super) fn uncover_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    record: &WorkflowRecord,
) -> Result<()> {
    if let Some(group) = record_group(record) {
        COVERAGE.delete(&vault.store, wtxn, &(group.digest(), record.id))?;
        bump_dirty_in_txn(vault, wtxn, &group)?;
    }
    Ok(())
}

/// Indexes the retire of `record` in its own write: it covers its group no
/// more, and a failure row it has stays, its generation moved on.
pub(super) fn index_retire_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    record: &WorkflowRecord,
) -> Result<()> {
    uncover_in_txn(vault, wtxn, record)?;
    if let Some(mut mark) = FAILURES.get(&vault.store, wtxn, &record.id)? {
        mark.generation = mark.generation.saturating_add(1);
        FAILURES.put(vault, wtxn, &record.id, &mark)?;
    }
    Ok(())
}

/// The evidence claim `id`'s refs, on its purge or soft erase, in that
/// write (CUA E8a): its group ref and its source authority go, and its
/// group moves on. An id that is no evidence claim changes nothing.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn invalidate_solved_source_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    id: &EntityId,
) -> Result<()> {
    let Some(caller) = AUTHORITY.get(&vault.store, wtxn, id)? else {
        return Ok(());
    };
    GROUP.delete(&vault.store, wtxn, &(caller.group, *id))?;
    AUTHORITY.delete(&vault.store, wtxn, id)?;
    touch_dirty_in_txn(vault, wtxn, &caller.group)
}

/// The source authority evidence `id` was captured under, read in `txn`
/// (CUA E8b): none once its claim or its actor was erased.
///
/// # Errors
///
/// Storage errors.
pub(super) fn saved_caller_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
) -> Result<Option<SavedBrowserCaller>> {
    AUTHORITY.get(&vault.store, txn, id)
}

/// Drops the signed binding evidence `id`'s source authority kept, in
/// `wtxn` (CUA E8b): an admission job that used it ended. The reference
/// and the digest stay.
///
/// # Errors
///
/// Storage errors.
pub(super) fn drop_witness_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    id: &EntityId,
) -> Result<()> {
    let Some(mut caller) = AUTHORITY.get(&vault.store, wtxn, id)? else {
        return Ok(());
    };
    if caller.witness.take().is_some() {
        AUTHORITY.put(vault, wtxn, id, &caller)?;
    }
    Ok(())
}

/// A re-delivered capture's refresh of the binding an ended job dropped
/// (FIX 10717), in the row's own scope only: witness and digest stand again.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn refresh_witness_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    id: &EntityId,
    caller: &SavedBrowserCaller,
) -> Result<()> {
    let Some(witness) = caller.witness.clone() else {
        return Ok(());
    };
    let Some(mut kept) = AUTHORITY.get(&vault.store, wtxn, id)? else {
        return Ok(());
    };
    if kept.scope != caller.scope {
        return Ok(());
    }
    kept.witness_digest = caller.witness_digest;
    kept.witness = Some(witness);
    AUTHORITY.put(vault, wtxn, id, &kept)
}

/// A restored evidence claim's re-index (FIX 10514): its group ref and
/// generation come back; authority only for a credential-less capture.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn reindex_restored_source_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    id: &EntityId,
) -> Result<()> {
    let Some(entity_type) = vault.get_entity_type_in_txn(wtxn, id)? else {
        return Ok(());
    };
    let Some(raw) = vault.get_raw_in(wtxn, id)? else {
        return Ok(());
    };
    let Some(evidence) = evidence_of(entity_type, &raw) else {
        return Ok(());
    };
    let key = evidence.group();
    let row = GroupRef {
        run_id: evidence.run_id,
        captured_at_ms: evidence.captured_at_ms,
    };
    GROUP.put(vault, wtxn, &(key.digest(), *id), &row)?;
    if evidence.scope.authority.is_none() {
        let caller = SavedBrowserCaller {
            scope: evidence.scope.clone(),
            group: key.digest(),
            run_id: evidence.run_id,
            call_id: evidence.call_id,
            credential: None,
            witness_digest: None,
            witness: None,
        };
        AUTHORITY.put(vault, wtxn, id, &caller)?;
    }
    bump_dirty_in_txn(vault, wtxn, &key)
}

/// Erasing `actor` from the solved-run index (CUA E8a): each evidence it
/// was captured under loses its source authority and its group ref, so no
/// work is induced or admitted for it; its claims go with their own erase.
/// An id whose entity is no actor scans nothing.
///
/// # Errors
///
/// Storage errors, or an index row that cannot be read.
pub(crate) fn erase_authority_actor_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    actor: &EntityId,
) -> Result<()> {
    if super::erase::is_no_actor(vault, wtxn, actor)? {
        return Ok(());
    }
    let mut taken = Vec::new();
    for (id, caller) in AUTHORITY.scan(&vault.store, wtxn)? {
        if caller.scope.actor == *actor {
            taken.push((id, caller.group));
        }
    }
    for (id, group) in taken {
        GROUP.delete(&vault.store, wtxn, &(group, id))?;
        AUTHORITY.delete(&vault.store, wtxn, &id)?;
    }
    Ok(())
}

/// Erasing `actor` from the dirty groups (CUA E8a): a group in its scope
/// leaves the Coach's work, its key naming the actor no more. An id whose
/// entity is no actor scans nothing.
///
/// # Errors
///
/// Storage errors, or an index row that cannot be read.
pub(crate) fn erase_dirty_actor_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    actor: &EntityId,
) -> Result<()> {
    if super::erase::is_no_actor(vault, wtxn, actor)? {
        return Ok(());
    }
    let mut taken = Vec::new();
    for (digest, row) in DIRTY.scan(&vault.store, wtxn)? {
        if row.key.scope.actor == *actor {
            taken.push(digest);
        }
    }
    for digest in taken {
        DIRTY.delete(&vault.store, wtxn, &digest)?;
    }
    Ok(())
}

/// The groups that changed past what the Coach processed, a page at a
/// time from `after` (CUA E8a), in digest order. Repeat with `next` until
/// it is none.
///
/// # Errors
///
/// Storage errors, or a cursor this read did not give.
pub fn dirty_solved_groups(
    vault: &Vault,
    after: Option<&PageCursor>,
) -> Result<Page<DirtySolvedGroup>> {
    let rtxn = vault.store.env.read_txn()?;
    let start = after.map(cursor_bytes::<32>).transpose()?;
    let from = start.as_ref().map_or(Bound::Unbounded, Bound::Excluded);
    let (mut items, mut walked, mut last) = (Vec::new(), 0, None);
    for row in DIRTY.iter_range(&vault.store, &rtxn, from, Bound::Unbounded)? {
        let (digest, row) = row?;
        walked += 1;
        last = Some(digest);
        if row.changed > row.processed {
            items.push(DirtySolvedGroup {
                key: row.key,
                digest,
                changed: row.changed,
                processed: row.processed,
            });
        }
        if walked == SOLVED_PAGE {
            break;
        }
    }
    let next = last
        .filter(|_| walked == SOLVED_PAGE)
        .map(|digest| PageCursor(digest.to_vec()));
    Ok(Page { items, next })
}

/// The evidence claim ids of the group `digest` keys, from the rows given,
/// one page's worth.
fn page_ids(
    rows: impl Iterator<Item = Result<(([u8; 32], EntityId), GroupRef)>>,
    digest: &[u8; 32],
) -> Result<Vec<EntityId>> {
    let mut ids = Vec::new();
    for row in rows {
        let ((group, id), _) = row?;
        if group != *digest {
            break;
        }
        ids.push(id);
        if ids.len() == SOLVED_PAGE {
            break;
        }
    }
    Ok(ids)
}

/// The solved runs of `key`'s group, a page at a time from `after` (CUA
/// E8a), each read through `read` with its receipt: a claim `read` may not
/// read, or one erased, is left out and the cursor still moves past it.
/// Repeat with `next` until it is none, and compare every pair: the page
/// is a traversal batch, not a sample.
///
/// # Errors
///
/// Storage errors, the read's own refusal, or a cursor this read did not
/// give.
pub fn solved_runs_in_group(
    read: &ScopedRead<'_>,
    key: &ScopedSolvedGroupKey,
    after: Option<&PageCursor>,
) -> Result<ScopedReadResult<Page<SolvedRunEvidence>>> {
    let vault = read.vault();
    let digest = key.digest();
    let ids = {
        let rtxn = vault.store.env.read_txn()?;
        match after.map(cursor_id).transpose()? {
            Some(last) => {
                let from = (digest, last);
                let rows = GROUP.iter_range(
                    &vault.store,
                    &rtxn,
                    Bound::Excluded(&from),
                    Bound::Unbounded,
                )?;
                page_ids(rows, &digest)?
            }
            None => page_ids(GROUP.iter_from(&vault.store, &rtxn, &digest)?, &digest)?,
        }
    };
    let rows = read.get_entities_parts_with_receipt(&ids, None)?;
    let mut items = Vec::new();
    for (id, row) in ids.iter().zip(rows.value) {
        let Some((entity_type, _, body)) = row else {
            continue;
        };
        if let Some(evidence) = evidence_of(entity_type, &body)
            && evidence.id == *id
            && evidence.group().digest() == digest
        {
            items.push(evidence);
        }
    }
    let next = ids
        .last()
        .filter(|_| ids.len() == SOLVED_PAGE)
        .map(|id| PageCursor(id.as_bytes().to_vec()));
    Ok(ScopedReadResult {
        value: Page { items, next },
        receipt: rows.receipt,
    })
}

/// The evidence a `browser.solved_run` claim's body holds.
pub(super) fn evidence_of(entity_type: u8, body: &[u8]) -> Option<SolvedRunEvidence> {
    if entity_type != crate::registry::ENTITY_TYPE_CLAIM {
        return None;
    }
    let claim = crate::claim::decode_claim_body(body, true).ok()?;
    if claim.predicate != SOLVED_RUN_PREDICATE {
        return None;
    }
    serde_json::from_str(claim.value.as_str()?).ok()
}

/// The programs whose library runs failed, live or retired, a page at a
/// time from `after` (CUA E8a), by id: each with its own record's lifetime
/// failures, never resolved to a successor. Repeat with `next` until it is
/// none.
///
/// # Errors
///
/// Storage errors, or a cursor this read did not give.
pub fn programs_with_failures(
    vault: &Vault,
    after: Option<&PageCursor>,
) -> Result<Page<ProgramFailureRef>> {
    let rtxn = vault.store.env.read_txn()?;
    let start = after.map(cursor_id).transpose()?;
    let from = start.as_ref().map_or(Bound::Unbounded, Bound::Excluded);
    let mut marks = Vec::new();
    for row in FAILURES.iter_range(&vault.store, &rtxn, from, Bound::Unbounded)? {
        marks.push(row?);
        if marks.len() == SOLVED_PAGE {
            break;
        }
    }
    let mut items = Vec::new();
    for (id, mark) in &marks {
        let failed = match WORKFLOWS.get(&vault.store, &rtxn, &(mark.site, *id))? {
            Some(record) => (record.failures > 0).then(|| ProgramFailureRef {
                id: *id,
                failures: u64::from(record.failures),
                retired: false,
                retire_reason: None,
                refs: FailureLineage {
                    site: record.site,
                    supersedes: record.supersedes,
                    successor: None,
                },
            }),
            None => RETIRED
                .get(&vault.store, &rtxn, id)?
                .filter(|trace| trace.record.failures > 0)
                .map(|trace| ProgramFailureRef {
                    id: *id,
                    failures: u64::from(trace.record.failures),
                    retired: true,
                    refs: FailureLineage {
                        site: trace.record.site,
                        supersedes: trace.record.supersedes,
                        successor: trace.reason.as_deref().and_then(superseded_by),
                    },
                    retire_reason: trace.reason,
                }),
        };
        items.extend(failed);
    }
    let next = marks
        .last()
        .filter(|_| marks.len() == SOLVED_PAGE)
        .map(|(id, _)| PageCursor(id.as_bytes().to_vec()));
    Ok(Page { items, next })
}

/// Marks `key`'s group processed through generation `through`, in the
/// caller's write (CUA E8a): a change past `through` keeps it dirty.
///
/// # Errors
///
/// Storage errors.
pub fn mark_group_clean(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    key: &ScopedSolvedGroupKey,
    through: u64,
) -> Result<()> {
    let digest = key.digest();
    let Some(mut row) = DIRTY.get(&vault.store, wtxn, &digest)? else {
        return Ok(());
    };
    let processed = row.processed.max(through.min(row.changed));
    if processed == row.processed {
        return Ok(());
    }
    row.processed = processed;
    DIRTY.put(vault, wtxn, &digest, &row)
}

/// The live programs filed in the group `digest` keys (CUA E8a): an
/// active program covers it; a retired one does not.
///
/// # Errors
///
/// Storage errors.
pub fn solved_group_coverage(vault: &Vault, digest: &[u8; 32]) -> Result<Vec<EntityId>> {
    let rtxn = vault.store.env.read_txn()?;
    Ok(COVERAGE
        .scan_keys(&vault.store, &rtxn, digest)?
        .into_iter()
        .map(|(_, id)| id)
        .collect())
}

/// The Coach's mark for the candidate `fingerprint` names (CUA E8), if it
/// proposed it.
///
/// # Errors
///
/// Storage errors.
pub fn program_seen(vault: &Vault, fingerprint: &[u8; 32]) -> Result<Option<ProgramSeen>> {
    let rtxn = vault.store.env.read_txn()?;
    SEEN.get(&vault.store, &rtxn, fingerprint)
}

/// Marks the candidate `fingerprint` names proposed, in the caller's write
/// (CUA E8): the finding's and the job's own.
///
/// # Errors
///
/// Storage errors.
pub fn mark_program_seen_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    fingerprint: &[u8; 32],
    seen: &ProgramSeen,
) -> Result<()> {
    SEEN.put(vault, wtxn, fingerprint, seen)
}
