//! The TASK type index in bounded pages, as the board's presence scan reads
//! it.

use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::registry::ENTITY_TYPE_TASK;

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
/// option here: it materializes the whole TASK index and returns
/// `IndexOverflow` past `MAX_TYPE_QUERY_RESULTS`, so a `.take(cap)` after it
/// would hard-fail before the iterator ever exists.
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

/// One page of up to `limit` TASKs a reader off this device may read
/// (DEC-0005). The index is walked past the others on its own cursor,
/// `index_after`, and a page is short only where the index ends.
pub(super) fn device_admitted_task_page(
    vault: &Vault,
    index_after: &mut Option<EntityId>,
    limit: usize,
) -> Result<Vec<EntityId>> {
    let mut page = Vec::new();
    loop {
        let rows = vault.entities_by_type_page(ENTITY_TYPE_TASK, index_after.as_ref(), limit)?;
        let exhausted = rows.len() < limit;
        let Some(&last) = rows.last() else {
            return Ok(page);
        };
        for id in vault.off_device_readable(rows)? {
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
