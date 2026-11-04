//! The host's typed writes of its row-held responses (KS-2B2, FIX 5683 part
//! B2): an HTTP idempotency entry and a media job, each with the stamps that
//! name its owners in the same grouped write. No write here touches custody:
//! the next checkpoint binds each row lazily, from those stamps.

use crate::Vault;
use crate::error::{Error, Result};
use crate::store::{IdempotencyEntry, InvocationClaimEntry};

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

    /// Keeps `entry` as the durable invocation claim `key` in one grouped
    /// write. The caller holds the invocation's admission lock.
    ///
    /// # Errors
    ///
    /// Storage errors; a key outside the invocation claim family.
    #[doc(hidden)]
    pub fn invocation_claim_put(&self, key: &str, entry: &InvocationClaimEntry) -> Result<()> {
        if !key
            .as_bytes()
            .starts_with(crate::side_table::INVOCATION_CLAIM.prefix)
        {
            return Err(Error::InvariantViolation(
                "an invocation claim put outside its rows",
            ));
        }
        let raw = entry.encode()?;
        self.with_write_txn_grouped(|wtxn| {
            crate::side_table::host_sync_state_put(self, wtxn, key, &raw)
        })
    }

    /// Settles an open invocation intent, only while that same unerased
    /// intent still stands. A settled, reclaimed, released or erased row is
    /// never overwritten by a late outcome.
    ///
    /// # Errors
    ///
    /// Storage errors; a key outside the invocation claim family.
    #[doc(hidden)]
    pub fn invocation_claim_settle(&self, key: &str, entry: &InvocationClaimEntry) -> Result<bool> {
        if !key
            .as_bytes()
            .starts_with(crate::side_table::INVOCATION_CLAIM.prefix)
        {
            return Err(Error::InvariantViolation(
                "an invocation claim put outside its rows",
            ));
        }
        let raw = entry.encode()?;
        self.with_write_txn_grouped(|wtxn| {
            let standing = match self.sync_state_get_in_write_txn(wtxn, key)? {
                Some(row) => {
                    InvocationClaimEntry::decode(&row).is_ok_and(|kept| kept.is_open_intent())
                }
                None => false,
            };
            if !standing {
                return Ok(false);
            }
            crate::side_table::host_sync_state_put(self, wtxn, key, &raw)?;
            Ok(true)
        })
    }

    /// Reclaims one expired invocation row. An open intent becomes a
    /// reply-not-kept outcome with a fresh TTL, including when its count is
    /// zero; a settled, erased or already reclaimed outcome is deleted. An
    /// undecodable row is left unless it is an opaque retired marker, so a
    /// damaged intent can never turn into a miss that runs the call again.
    ///
    /// # Errors
    ///
    /// Storage errors; a key outside the invocation claim family.
    #[doc(hidden)]
    pub fn invocation_claim_reclaim_expired(
        &self,
        key: &str,
        now_secs: u64,
        ttl_secs: u64,
    ) -> Result<()> {
        if !key
            .as_bytes()
            .starts_with(crate::side_table::INVOCATION_CLAIM.prefix)
        {
            return Err(Error::InvariantViolation(
                "an invocation claim reclaim outside its rows",
            ));
        }
        self.with_write_txn(|wtxn| {
            let Some(raw) = self.sync_state_get_in_write_txn(wtxn, key)? else {
                return Ok(());
            };
            let entry = InvocationClaimEntry::decode(&raw).ok();
            let expired = entry
                .as_ref()
                .is_some_and(|entry| now_secs.saturating_sub(entry.created_at_secs) >= ttl_secs)
                || crate::store::invocation_claim_opaque_retired_at(&raw)
                    .is_some_and(|retired| now_secs.saturating_sub(retired) >= ttl_secs);
            if !expired {
                return Ok(());
            }
            if let Some(entry) = entry.filter(|entry| entry.is_open_intent()) {
                let raw = entry.reclaimed_form(now_secs).encode()?;
                crate::side_table::host_sync_state_put(&self.store, wtxn, key, &raw)?;
            } else {
                crate::side_table::host_sync_state_delete(&self.store, wtxn, key)?;
            }
            Ok(())
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
            crate::store::media_job_put_fenced_in_txn(self, wtxn, key, row, parts, false)
        })
    }

    /// [`Self::media_job_put`] over the job row already kept at `key`, as a
    /// job's end is written (FIX 9511): a row a delete dropped is not
    /// written back, and neither are its clips; `false` comes back for it,
    /// as for a row an erase took.
    ///
    /// # Errors
    ///
    /// Storage errors; a key that is not a job's row, or a part key that is
    /// not one of its clips.
    #[doc(hidden)]
    pub fn media_job_update(
        &self,
        key: &str,
        row: &[u8],
        parts: &[(String, Vec<u8>)],
    ) -> Result<bool> {
        self.with_write_txn_grouped(|wtxn| {
            crate::store::media_job_put_fenced_in_txn(self, wtxn, key, row, parts, true)
        })
    }
}
