//! Vault record IO: load, scan, put, drop, and the terminal-state transition.

use super::failure::invalid;
use super::record::{
    StoredGitWireRecord, decode_record, encode_record, receipt_from_stored, record_row_key,
    record_row_prefix,
};
use super::{GitWire, GitWireReceipt, GitWireRecordState, GitWireRepo, GitWireResult};
use crate::error::Result;

impl GitWire<'_> {
    /// The durable record for a key, whatever its state.
    pub fn receipt(
        &self,
        repo: &GitWireRepo,
        record_key: &[u8; 32],
    ) -> GitWireResult<Option<GitWireReceipt>> {
        let Some(stored) = self.load_record(repo, record_key)? else {
            return Ok(None);
        };
        Ok(Some(receipt_from_stored(&stored)?))
    }

    pub(super) fn load_record(
        &self,
        repo: &GitWireRepo,
        key: &[u8; 32],
    ) -> Result<Option<StoredGitWireRecord>> {
        let rtxn = self.vault.store.env.read_txn()?;
        let row = record_row_key(repo.identity(), key);
        let Some(bytes) = self.vault.store.vault_meta.get(&rtxn, &row)? else {
            return Ok(None);
        };
        Ok(Some(decode_record(&bytes)?))
    }

    pub(super) fn prepared_records(&self, repo: &GitWireRepo) -> Result<Vec<StoredGitWireRecord>> {
        let rtxn = self.vault.store.env.read_txn()?;
        let prefix = record_row_prefix(repo.identity());
        let mut rows = Vec::new();
        for row in self.vault.store.vault_meta.prefix_iter(&rtxn, &prefix)? {
            let (_, bytes) = row?;
            let stored = decode_record(&bytes)?;
            if stored.state == GitWireRecordState::Prepared.as_str() {
                rows.push(stored);
            }
        }
        Ok(rows)
    }

    pub(super) fn put_record(
        &self,
        repo: &GitWireRepo,
        record: &StoredGitWireRecord,
    ) -> Result<()> {
        let encoded = encode_record(record)?;
        let row = record_row_key(repo.identity(), &record.record_key);
        self.vault.with_write_txn(|txn| {
            self.vault.store.vault_meta.put(txn, &row, &encoded)?;
            Ok(())
        })
    }

    pub(super) fn drop_record(&self, repo: &GitWireRepo, key: &[u8; 32]) -> Result<()> {
        let row = record_row_key(repo.identity(), key);
        self.vault.with_write_txn(|txn| {
            self.vault.store.vault_meta.delete(txn, &row)?;
            Ok(())
        })
    }

    /// Moves a record to a terminal state exactly once.
    ///
    /// The read and the write share one vault write transaction, so a record
    /// that is already terminal wins: `Failed` can never be overwritten by a
    /// late `Applied`, and two recoverers cannot both claim a transition.
    pub(super) fn transition(
        &self,
        repo: &GitWireRepo,
        next: StoredGitWireRecord,
    ) -> Result<StoredGitWireRecord> {
        let row = record_row_key(repo.identity(), &next.record_key);
        let encoded = encode_record(&next)?;
        self.vault.with_write_txn(move |txn| {
            let current = match self.vault.store.vault_meta.get(txn, &row)? {
                Some(bytes) => decode_record(&bytes)?,
                None => {
                    return Err(invalid("git wire record disappeared before its transition"));
                }
            };
            if GitWireRecordState::parse(&current.state)?.is_terminal() {
                return Ok(current);
            }
            self.vault.store.vault_meta.put(txn, &row, &encoded)?;
            Ok(next)
        })
    }
}
