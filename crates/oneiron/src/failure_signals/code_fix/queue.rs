//! The sealed code-fix records' export queue: what the host reads and what a
//! delivery acks, moved out of the parent as they were, with the
//! in-transaction halves a carried failure-signal batch's eligibility check
//! and one-writer settlement compose (FIX 6679).

use super::{CodeFixExport, QUEUE, all_public};
use crate::{EntityId, Result, Vault};

/// One record a batch carries: its public id and the worlds its failure
/// touched (local only, never sent).
pub(in crate::failure_signals) type CodeFixShare = (String, Vec<EntityId>);

impl Vault {
    /// Reads up to `limit` sealed records this deployment may still send, in
    /// id order (random, so no age order). Nothing leaves the queue here: the
    /// host delivers what this returns and then acks it, so a failed send
    /// keeps the only copy. A record whose failure touched a world that has
    /// since turned private is dropped, and so is every record once the
    /// deployment stopped exporting.
    pub fn pending_code_fix_records(&self, limit: usize) -> Result<Vec<CodeFixExport>> {
        Ok(self
            .pending_code_fix_rows(limit)?
            .into_iter()
            .map(|(record, _)| record)
            .collect())
    }

    /// [`Self::pending_code_fix_records`], each record with the worlds its
    /// failure touched, which a carried batch keeps (FIX 6679).
    pub(in crate::failure_signals) fn pending_code_fix_rows(
        &self,
        limit: usize,
    ) -> Result<Vec<(CodeFixExport, Vec<EntityId>)>> {
        let exports = self.config.failure_signals.exports();
        let idle = {
            let txn = self.store.env.read_txn()?;
            QUEUE.iter_from(&self.store, &txn, &[])?.next().is_none()
        };
        if idle {
            return Ok(Vec::new());
        }
        self.with_write_txn_grouped(|txn| {
            let rows = QUEUE.scan(&self.store, txn)?;
            if rows.is_empty() {
                return Ok(Vec::new());
            }
            let fold = self.authority_view_readonly_in_txn(txn)?;
            let mut out = Vec::new();
            for (key, row) in rows {
                if !exports || !all_public(&fold, &row.worlds) {
                    QUEUE.delete(&self.store, txn, &key)?;
                } else if out.len() < limit {
                    out.push((row.record, row.worlds));
                }
            }
            Ok(out)
        })
    }

    /// Drops the delivered records `ids` from the queue. An id that is not
    /// queued (already acked, or dropped) is skipped. Returns how many left.
    pub fn ack_code_fix_records(&self, ids: &[&str]) -> Result<usize> {
        let keys = public_keys(ids);
        if keys.is_empty() {
            return Ok(0);
        }
        self.with_write_txn_grouped(|txn| ack_keys_in_txn(self, txn, &keys))
    }
}

/// [`Vault::ack_code_fix_records`] in `txn`, for a settlement that commits
/// with it.
pub(in crate::failure_signals) fn ack_code_fix_records_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    ids: &[&str],
) -> Result<usize> {
    ack_keys_in_txn(vault, txn, &public_keys(ids))
}

fn ack_keys_in_txn(vault: &Vault, txn: &mut heed::RwTxn<'_>, keys: &[[u8; 16]]) -> Result<usize> {
    let mut acked = 0;
    for key in keys {
        if QUEUE.delete(&vault.store, txn, key)? {
            acked += 1;
        }
    }
    Ok(acked)
}

/// Whether each of `records` is still queued and every world it touched
/// still reads everywhere, read in `txn`: a carried batch leaves only while
/// every record in it still may (FIX 6679).
pub(in crate::failure_signals) fn code_fix_still_eligible_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    records: &[CodeFixShare],
) -> Result<bool> {
    if records.is_empty() {
        return Ok(true);
    }
    let fold = vault.authority_view_readonly_in_txn(txn)?;
    for (id, worlds) in records {
        let Some(key) = public_id_key(id) else {
            return Ok(false);
        };
        if !QUEUE.contains(&vault.store, txn, &key)? || !all_public(&fold, worlds) {
            return Ok(false);
        }
    }
    Ok(true)
}

fn public_keys(ids: &[&str]) -> Vec<[u8; 16]> {
    ids.iter().filter_map(|id| public_id_key(id)).collect()
}

/// The queue key behind a record's public id: 32 hex digits.
fn public_id_key(id: &str) -> Option<[u8; 16]> {
    if id.len() != 32 {
        return None;
    }
    let mut key = [0u8; 16];
    for (index, slot) in key.iter_mut().enumerate() {
        *slot = u8::from_str_radix(id.get(index * 2..index * 2 + 2)?, 16).ok()?;
    }
    Some(key)
}
