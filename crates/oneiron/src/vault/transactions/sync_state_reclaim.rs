//! One page of a host cache's expiry reclaim through the generic host door
//! (FIX 5951): a host table with no expiry index measures a page of its rows
//! at a time and deletes the expired ones, never a live one.

use std::ops::Bound;

use crate::Vault;
use crate::error::{Error, Result};

impl Vault {
    /// Reads at most `limit` rows under `prefix`, in key order, strictly
    /// after `after` (from the prefix's start with `None`), and in the same
    /// writer deletes each row whose value `expired` answers `true` for;
    /// every other row stays as it is. Answers where the next page starts:
    /// the last key read while rows under `prefix` may lie past it, `None`
    /// once the page reached the prefix's end. `prefix` must overlap a
    /// declared `SyncState` table, and a deleted key passes the checks
    /// [`Self::sync_state_delete`] makes. This is the host write door, not
    /// the grouped one, so a host may hold its own cursor's lock across it.
    #[doc(hidden)]
    pub fn sync_state_reclaim_prefix_page(
        &self,
        prefix: &str,
        after: Option<&str>,
        limit: usize,
        mut expired: impl FnMut(&[u8]) -> Result<bool>,
    ) -> Result<Option<String>> {
        crate::side_table::host_declared_sync_state_scan(prefix)?;
        self.with_write_txn(|wtxn| {
            let start = match after {
                Some(after) if after >= prefix => Bound::Excluded(after.as_bytes()),
                _ => Bound::Included(prefix.as_bytes()),
            };
            let mut read = 0;
            let mut last = None;
            let mut more = false;
            let mut doomed = Vec::new();
            for row in self
                .store
                .sync_state
                .range_bytes(wtxn, &(start, Bound::Unbounded))?
            {
                let (key, value) = row?;
                if !key.starts_with(prefix.as_bytes()) {
                    break;
                }
                if read == limit {
                    more = true;
                    break;
                }
                read += 1;
                let key = std::str::from_utf8(&key)
                    .map_err(|_| Error::InvariantViolation("non-UTF-8 key in sync_state"))?;
                crate::side_table::host_declared_sync_state(key)?;
                if expired(&value)? {
                    doomed.push(key.to_owned());
                }
                last = Some(key.to_owned());
            }
            for key in &doomed {
                super::check_generic_sync_state_key(key)?;
                crate::side_table::host_sync_state_delete(&self.store, wtxn, key)?;
            }
            Ok(if more { last } else { None })
        })
    }
}
