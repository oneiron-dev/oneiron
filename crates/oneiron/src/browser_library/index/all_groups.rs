//! Every solved group, including generations the browser-programs Coach
//! already processed (FIX 7606). Paging and cursors match
//! [`super::dirty_solved_groups`]; only that function's changed/processed
//! filter differs.

use std::ops::Bound;

use super::{DirtySolvedGroup, Page, PageCursor, SOLVED_PAGE, cursor_bytes};
use crate::Vault;
use crate::error::Result;

/// Every group in digest order, whether changed past processed or not, one
/// page at a time from `after`. Repeat with `next` until it is none.
///
/// # Errors
///
/// Storage errors, or a cursor this read did not give.
pub fn all_solved_groups(
    vault: &Vault,
    after: Option<&PageCursor>,
) -> Result<Page<DirtySolvedGroup>> {
    let rtxn = vault.store.env.read_txn()?;
    let start = after.map(cursor_bytes::<32>).transpose()?;
    let from = start.as_ref().map_or(Bound::Unbounded, Bound::Excluded);
    let (mut items, mut walked, mut last) = (Vec::new(), 0, None);
    for row in super::DIRTY.iter_range(&vault.store, &rtxn, from, Bound::Unbounded)? {
        let (digest, row) = row?;
        walked += 1;
        last = Some(digest);
        items.push(DirtySolvedGroup {
            key: row.key,
            digest,
            changed: row.changed,
            processed: row.processed,
        });
        if walked == SOLVED_PAGE {
            break;
        }
    }
    let next = last
        .filter(|_| walked == SOLVED_PAGE)
        .map(|digest| PageCursor(digest.to_vec()));
    Ok(Page { items, next })
}
