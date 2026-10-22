//! The host's typed writes of its row-held responses (KS-2B2, FIX 5683 part
//! B2): an HTTP idempotency entry and a media job, each with the stamps that
//! name its owners in the same grouped write. No write here touches custody:
//! the next checkpoint binds each row lazily, from those stamps.

use crate::Vault;
use crate::error::{Error, Result};
use crate::store::IdempotencyEntry;

impl Vault {
    /// Keeps `entry` as the HTTP idempotency entry `key`, its stamps with it,
    /// in one grouped write.
    ///
    /// # Errors
    ///
    /// Storage errors; a key outside the cache's declared rows.
    #[doc(hidden)]
    pub fn http_idempotency_put(&self, key: &str, entry: &IdempotencyEntry) -> Result<()> {
        if !key
            .as_bytes()
            .starts_with(crate::side_table::HTTP_IDEMPOTENCY_REPLY.prefix)
        {
            return Err(Error::InvariantViolation(
                "an idempotency entry put outside its rows",
            ));
        }
        let raw = entry.encode()?;
        self.with_write_txn_grouped(|wtxn| {
            crate::side_table::host_sync_state_put(self, wtxn, key, &raw)
        })
    }

    /// Settles the HTTP idempotency entry `key` with `entry`, the outcome of
    /// the request whose intent row it holds (FIX 9527), in one grouped
    /// write, and only while that row still stands unerased. An erase that
    /// took the row, or dropped it, stays so: nothing is written and `false`
    /// comes back, so a late outcome never puts erased content back.
    ///
    /// # Errors
    ///
    /// Storage errors; a key outside the cache's declared rows.
    #[doc(hidden)]
    pub fn http_idempotency_settle(&self, key: &str, entry: &IdempotencyEntry) -> Result<bool> {
        if !key
            .as_bytes()
            .starts_with(crate::side_table::HTTP_IDEMPOTENCY_REPLY.prefix)
        {
            return Err(Error::InvariantViolation(
                "an idempotency entry put outside its rows",
            ));
        }
        let raw = entry.encode()?;
        self.with_write_txn_grouped(|wtxn| {
            let standing = match self.sync_state_get_in_write_txn(wtxn, key)? {
                Some(row) => IdempotencyEntry::decode(&row).is_ok_and(|kept| !kept.erased),
                None => false,
            };
            if !standing {
                return Ok(false);
            }
            crate::side_table::host_sync_state_put(self, wtxn, key, &raw)?;
            Ok(true)
        })
    }

    /// Keeps the media job row `row` (the host's named encoding, its stamps
    /// in it) as `key`, each of its clips `parts` beside it, in one grouped
    /// write, unless an erase of an owner took the job already: then nothing
    /// is written and `false` comes back, so a late end, or an end retried
    /// from where the host held it, never puts erased content back.
    ///
    /// # Errors
    ///
    /// Storage errors; a key that is not a job's row, or a part key that is
    /// not one of its clips.
    #[doc(hidden)]
    pub fn media_job_put(
        &self,
        key: &str,
        row: &[u8],
        parts: &[(String, Vec<u8>)],
    ) -> Result<bool> {
        self.with_write_txn_grouped(|wtxn| {
            crate::store::media_job_put_fenced_in_txn(self, wtxn, key, row, parts)
        })
    }
}
