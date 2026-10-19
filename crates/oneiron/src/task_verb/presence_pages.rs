//! The TASK type index in bounded pages, as the board's presence scan reads
//! it.

use std::collections::{BTreeMap, HashSet};

use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::registry::ENTITY_TYPE_TASK;
use crate::settings::ReadDestination;

#[derive(Debug)]
pub(super) struct TaskEntityPageScan {
    /// Bounded pages in type-index order; page boundaries are retained so
    /// `task_presence` opens exactly one render-state transaction per page.
    pub(super) pages: Vec<Vec<EntityId>>,
    pub(super) scanned_task_entities: usize,
    pub(super) source_exhausted: bool,
    /// Exclusive-after cursor / last processed TASK id from the scan loop.
    /// `None` when nothing was processed (scan_cap == 0 or empty source).
    /// Used under truncation to decide which realizing leftovers are provably
    /// in the scanned prefix (owner ≤ cursor → bare) vs still beyond the cap.
    pub(super) last_scanned_cursor: Option<EntityId>,
}

/// Pure bounded cursor loop over the sanctioned page primitive.
///
/// Production passes `Vault::entities_by_type_page`; tests pass a synthetic
/// pager and small explicit limits. Unpaged `entities_by_type` is never an
/// option here: it materializes the whole TASK index before a `.take(cap)`
/// after it could run.
pub(super) fn scan_task_entity_pages<F>(
    page_size: usize,
    scan_cap: usize,
    mut fetch_page: F,
) -> Result<TaskEntityPageScan>
where
    F: FnMut(Option<&EntityId>, usize) -> Result<Vec<EntityId>>,
{
    // A zero page size would fetch nothing forever; clamping keeps forward
    // progress rather than reporting a false "exhausted".
    let page_size = page_size.max(1);
    let mut pages: Vec<Vec<EntityId>> = Vec::new();
    let mut after: Option<EntityId> = None;
    let mut scanned = 0_usize;
    let mut source_exhausted = false;
    let mut decided = false;

    while scanned < scan_cap {
        let remaining = scan_cap - scanned;
        // The extra row is a sentinel on the final capped page: fetching one
        // more than the budget is how "there is more" is learned without
        // spending scan work on it.
        let requested = page_size.min(remaining.saturating_add(1));
        let mut page = fetch_page(after.as_ref(), requested)?;
        if page.is_empty() {
            source_exhausted = true;
            decided = true;
            break;
        }

        let page_len = page.len();
        let process_count = page_len.min(remaining);
        let has_sentinel = page_len > process_count;
        // Defensive: nothing to process means the cursor cannot advance, so
        // stop rather than spin. The unprocessed rows still prove more exist.
        if process_count == 0 {
            decided = true;
            break;
        }
        page.truncate(process_count);

        // The cursor is an EXCLUSIVE lower bound in type-index order, so a
        // source that fails to advance it would replay rows forever; refusing
        // to continue keeps the walk finite and duplicate-free.
        let cursor = page.last().copied();
        if let (Some(previous), Some(next)) = (after, cursor)
            && next <= previous
        {
            decided = true;
            break;
        }

        scanned += process_count;
        after = cursor;
        pages.push(page);

        if has_sentinel {
            source_exhausted = false;
            decided = true;
            break;
        }
        if page_len < requested {
            source_exhausted = true;
            decided = true;
            break;
        }
    }

    if !decided {
        // The budget ran out on a page that exactly filled its request. One
        // bounded one-row probe past the cursor separates an exact census from
        // a lower bound, so a source that happens to end on the cap boundary
        // is not reported as truncated.
        source_exhausted = match after.as_ref() {
            Some(cursor) => fetch_page(Some(cursor), 1)?.is_empty(),
            // scan_cap == 0: nothing was inspected, so nothing is known.
            None => false,
        };
    }

    Ok(TaskEntityPageScan {
        pages,
        scanned_task_entities: scanned,
        source_exhausted,
        last_scanned_cursor: after,
    })
}

/// One page of up to `limit` TASKs a reader off this device toward
/// `destination` may read (DEC-0005, mesh PR2b). The index is walked past the
/// others on its own cursor, `index_after`, and a page is short only where
/// the index ends. `read` counts every index row read.
pub(super) fn device_admitted_task_page(
    vault: &Vault,
    destination: &ReadDestination,
    index_after: &mut Option<EntityId>,
    limit: usize,
    read: &mut usize,
) -> Result<Vec<EntityId>> {
    let mut page = Vec::new();
    loop {
        let rows = vault.entities_by_type_page(ENTITY_TYPE_TASK, index_after.as_ref(), limit)?;
        *read += rows.len();
        let exhausted = rows.len() < limit;
        let Some(&last) = rows.last() else {
            return Ok(page);
        };
        for id in vault.off_device_readable_for(rows, destination)? {
            if page.len() == limit {
                // The rest of these rows are read again from here.
                return Ok(page);
            }
            *index_after = Some(id);
            page.push(id);
        }
        *index_after = Some(last);
        if exhausted || page.len() == limit {
            return Ok(page);
        }
    }
}

/// Off this device, a job whose TASK a world withheld from `destination`
/// keeps stays withheld with that TASK (DEC-0005, mesh PR2b). Owners the rule
/// lets through, missing ones included, still render as dangling bare jobs.
pub(super) fn retain_readable_owners<J>(
    vault: &Vault,
    destination: &ReadDestination,
    realizing: &mut BTreeMap<String, J>,
) -> Result<()> {
    if !destination.is_off_device() {
        return Ok(());
    }
    let owners = realizing
        .keys()
        .filter_map(|task_hex| EntityId::from_hex(task_hex).ok())
        .collect();
    let readable: HashSet<EntityId> = vault
        .off_device_readable_for(owners, destination)?
        .into_iter()
        .collect();
    realizing.retain(|task_hex, _| match EntityId::from_hex(task_hex) {
        Err(_) => true,
        Ok(owner) => readable.contains(&owner),
    });
    Ok(())
}

/// Every TASK admitted toward `destination`, for a census that must see them
/// all (rule 5): past the threshold row the walk raises the owner's check for
/// `scope` and reads on. `txn` is the caller's, so a crossing is deferred.
pub(super) fn all_admitted_tasks_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    destination: impl Into<crate::settings::ReadDestination>,
    scope: &[u8],
) -> Result<Vec<EntityId>> {
    let mut count = crate::scan_check::ScanCount::start(
        &vault.store,
        txn,
        crate::scan_check::EngineScan::TaskCensusRows,
        scope,
    )?;
    let scan = scan_admitted_tasks_with_limits_in(
        vault,
        txn,
        destination,
        super::presence_scan::TASK_PRESENCE_PAGE_SIZE,
        usize::MAX,
    )?;
    if !scan.source_exhausted {
        return Err(Error::InvariantViolation(
            "an unbounded task census stopped",
        ));
    }
    let tasks: Vec<EntityId> = scan.pages.into_iter().flatten().collect();
    tasks.iter().for_each(|_| count.row());
    count.defer(&vault.store);
    Ok(tasks)
}

/// The admitted-TASK walk under explicit page and cap limits: a TASK a world
/// withholds from a machine `destination` names takes no place in a page or
/// the cap (DEC-0005, mesh PR2b). Tests inject small limits.
pub(super) fn scan_admitted_tasks_with_limits_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    destination: impl Into<crate::settings::ReadDestination>,
    page_size: usize,
    scan_cap: usize,
) -> Result<TaskEntityPageScan> {
    let store = &vault.store;
    let kept = crate::settings::device_local_worlds_for(vault, txn, &destination.into())?;
    let mut index_after = None;
    scan_task_entity_pages(page_size, scan_cap, |_, limit| {
        let mut page = Vec::new();
        loop {
            let rows = crate::ports::EntityStoreRead::port_entity_ids_by_type(
                store,
                txn,
                ENTITY_TYPE_TASK,
                index_after,
            )?
            .take(limit)
            .collect::<Result<Vec<_>>>()?;
            let exhausted = rows.len() < limit;
            let Some(&last) = rows.last() else {
                return Ok(page);
            };
            for id in rows {
                if crate::settings::device_local_keeps_among(store, txn, &kept, &id)? {
                    continue;
                }
                if page.len() == limit {
                    // The rest of these rows are read again from here.
                    return Ok(page);
                }
                index_after = Some(id);
                page.push(id);
            }
            index_after = Some(last);
            if exhausted || page.len() == limit {
                return Ok(page);
            }
        }
    })
}
