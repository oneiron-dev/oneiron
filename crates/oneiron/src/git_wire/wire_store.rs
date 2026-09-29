//! Vault record IO: load, scan, put, drop, and the terminal-state transition.

use super::failure::invalid;
use super::record::{StoredGitWireRecord, hex_lower, receipt_from_stored};
use super::{
    GitWire, GitWireReceipt, GitWireRecordState, GitWireRepo, GitWireRepoIdentity, GitWireResult,
};
use crate::error::Result;
use crate::side_table::{self, Named, SideTable};

/// One journaled effect row, keyed by `{repo_hex}:{record_key_hex}` exactly as
/// `record_row_key` used to spell it — a plain `String` key, since no reader
/// ever decodes the stored key back into its parts.
const RECORDS: SideTable<String, StoredGitWireRecord, Named> =
    SideTable::new(&side_table::GIT_WIRE_RECORD);

/// The key suffix (after the table's declared prefix) for one record.
fn record_row_suffix(identity: GitWireRepoIdentity, record_key: &[u8; 32]) -> String {
    format!("{}:{}", identity.as_hex(), hex_lower(record_key))
}

/// The key-prefix bytes selecting every record of one repo.
fn record_row_prefix_suffix(identity: GitWireRepoIdentity) -> Vec<u8> {
    format!("{}:", identity.as_hex()).into_bytes()
}

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
        let row = record_row_suffix(repo.identity(), key);
        RECORDS.get(&self.vault.store, &rtxn, &row)
    }

    pub(super) fn prepared_records(&self, repo: &GitWireRepo) -> Result<Vec<StoredGitWireRecord>> {
        let rtxn = self.vault.store.env.read_txn()?;
        let prefix = record_row_prefix_suffix(repo.identity());
        let mut rows = Vec::new();
        for (_, stored) in RECORDS.scan_from(&self.vault.store, &rtxn, &prefix)? {
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
        let row = record_row_suffix(repo.identity(), &record.record_key);
        self.vault.with_write_txn(|txn| {
            RECORDS.put(&self.vault.store, txn, &row, record)?;
            Ok(())
        })
    }

    pub(super) fn drop_record(&self, repo: &GitWireRepo, key: &[u8; 32]) -> Result<()> {
        let row = record_row_suffix(repo.identity(), key);
        self.vault.with_write_txn(|txn| {
            RECORDS.delete(&self.vault.store, txn, &row)?;
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
        let row = record_row_suffix(repo.identity(), &next.record_key);
        self.vault.with_write_txn(move |txn| {
            let current = match RECORDS.get(&self.vault.store, txn, &row)? {
                Some(current) => current,
                None => {
                    return Err(invalid("git wire record disappeared before its transition"));
                }
            };
            if GitWireRecordState::parse(&current.state)?.is_terminal() {
                return Ok(current);
            }
            RECORDS.put(&self.vault.store, txn, &row, &next)?;
            Ok(next)
        })
    }
}
