//! One page of a host table's rows, read in key order through the generic
//! host door (FIX 10863, FIX 10866): the read-only twin of
//! `sync_state_reclaim_prefix_page`, on a read transaction, so a cursor read
//! of a large family never queues on the vault's writer.
#![cfg(feature = "sync")]

use std::ops::Bound;

use crate::Vault;
use crate::error::{Error, Result};

impl Vault {
    /// Reads at most `limit` rows under `prefix`, in key order, strictly
    /// after `after` (from the prefix's start with `None`), handing each
    /// one's key and value to `visit`, all on one read transaction. Answers
    /// where the next page starts: the last key read while rows under
    /// `prefix` may lie past it, `None` once the page reached the prefix's
    /// end. `prefix` must overlap a declared `SyncState` table and each key
    /// read must be a declared one, as [`Self::sync_state_keys_with_prefix`]
    /// checks them. Nothing is written.
    #[doc(hidden)]
    pub fn sync_state_prefix_page(
        &self,
        prefix: &str,
        after: Option<&str>,
        limit: usize,
        mut visit: impl FnMut(&str, &[u8]) -> Result<()>,
    ) -> Result<Option<String>> {
        crate::side_table::host_declared_sync_state_scan(prefix)?;
        let rtxn = self.store.env.read_txn()?;
        let start = match after {
            Some(after) if after >= prefix => Bound::Excluded(after.as_bytes()),
            _ => Bound::Included(prefix.as_bytes()),
        };
        let mut read = 0;
        let mut last = None;
        for row in self
            .store
            .sync_state
            .range_bytes(&rtxn, &(start, Bound::Unbounded))?
        {
            let (key, value) = row?;
            if !key.starts_with(prefix.as_bytes()) {
                return Ok(None);
            }
            if read == limit {
                return Ok(last);
            }
            read += 1;
            let key = std::str::from_utf8(&key)
                .map_err(|_| Error::InvariantViolation("non-UTF-8 key in sync_state"))?;
            crate::side_table::host_declared_sync_state(key)?;
            visit(key, &value)?;
            last = Some(key.to_owned());
        }
        Ok(None)
    }
}
