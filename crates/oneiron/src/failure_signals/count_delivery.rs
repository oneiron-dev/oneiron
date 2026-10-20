//! The tier-1 aggregate's delivery side: the export a batch reads and the
//! subtraction its delivery settles, moved out of the parent as they were,
//! with the in-transaction half a carried batch's one-writer settlement
//! composes (FIX 6679).

use super::{COUNTS, Tier1FailureCount, count_key, count_value, decode_count};
use crate::{Result, Vault};

/// One count a batch carries: the aggregate row it was read from (BLAKE3 of
/// its dimensions' JSON) and the quantity the batch froze. Settlement takes
/// exactly that quantity, so a count recorded into the same row since stays
/// for the next batch.
pub(super) type CountShare = ([u8; 32], u64);

impl Vault {
    /// Export this vault's current content-free tier-1 aggregate: every
    /// count not yet delivered, kept across restarts.
    pub fn export_tier1_failure_counts(&self) -> Result<Vec<Tier1FailureCount>> {
        if !self.config.failure_signals.exports() {
            return Ok(Vec::new());
        }
        let txn = self.store.env.read_txn()?;
        let mut counts = COUNTS
            .iter_from(&self.store, &txn, &[])?
            .map(|row| decode_count(&row?.1))
            .collect::<Result<Vec<_>>>()?;
        counts.sort_by(|a, b| a.dimensions.cmp(&b.dimensions));
        Ok(counts)
    }

    /// Takes counts the host delivered out of the aggregate, so the next
    /// export carries only what was counted since. A count recorded between
    /// the export and this ack stays for the next one.
    pub fn ack_tier1_failure_counts(&self, delivered: &[Tier1FailureCount]) -> Result<()> {
        let shares = count_shares(delivered)?;
        self.with_write_txn_grouped(|txn| subtract_counts_in_txn(self, txn, &shares))
    }
}

/// The aggregate row and quantity of each of `counts`.
pub(super) fn count_shares(counts: &[Tier1FailureCount]) -> Result<Vec<CountShare>> {
    counts
        .iter()
        .map(|row| -> Result<CountShare> { Ok((count_key(&row.dimensions)?.0, row.count)) })
        .collect()
}

/// [`Vault::ack_tier1_failure_counts`] in `txn`: takes each share's quantity
/// out of its row and deletes a row that reaches zero. A row already gone is
/// skipped; a row keeps the dimensions it was stored with.
pub(super) fn subtract_counts_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    shares: &[CountShare],
) -> Result<()> {
    for (key, delivered) in shares {
        let Some(value) = COUNTS.get(&vault.store, &*txn, key)? else {
            continue;
        };
        let left = decode_count(&value)?.count.saturating_sub(*delivered);
        if left == 0 {
            COUNTS.delete(&vault.store, txn, key)?;
        } else {
            let json = value.get(8..).unwrap_or_default();
            COUNTS.put(&vault.store, txn, key, &count_value(left, json))?;
        }
    }
    Ok(())
}
