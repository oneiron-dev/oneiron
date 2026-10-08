//! A dry run: what an import would do, read from the vault's files with LMDB
//! opened read-only. Nothing opens the vault, so no seeding, recovery or
//! collection runs, no writer lease is taken and the vault's data file is not
//! written. It reads beside a running `serve` as well.

use std::collections::hash_map::Entry;
use std::collections::{BTreeSet, HashMap, HashSet};
use std::path::Path;

use heed::types::Bytes;
use heed::{Database, Env, EnvFlags, EnvOpenOptions};

use super::land::{HistoryImportReport, conversation_body, imported_message, runs};
use super::ledger::{self, LedgerRow, content_hash};
use super::{HistoryConversation, HistorySource};
use crate::batch::secret_scan::{SecretScanMode, scan_write_payload, secret_scan_mode_in_txn};
use crate::error::{Error, GateError, Result};
use crate::memory::witness_message_body;
use crate::overlay_db::{OverlayDb, OverlayStrDb};
use crate::side_table::SideTableDbs;

/// The vault's side-table database, as the store's open gates name it.
const VAULT_META_DB: &str = "vault_meta";

/// A dry run's memory across conversations: the texts it has counted as
/// landing and the conversations it has counted as minted, so a message two
/// conversations carry (a resumed session's copies of the original's lines)
/// counts once, as the import itself would land it.
#[derive(Debug, Default)]
pub struct HistoryDryRun {
    counted: HashMap<String, Vec<String>>,
    minted: HashSet<String>,
}

impl HistoryDryRun {
    /// The texts of one message that have landed or would have by now.
    fn landed(
        &mut self,
        dbs: &impl SideTableDbs,
        txn: &heed::RoTxn<'_>,
        source: HistorySource,
        native_id: &str,
    ) -> Result<&mut Vec<String>> {
        Ok(match self.counted.entry(native_id.to_owned()) {
            Entry::Occupied(counted) => counted.into_mut(),
            Entry::Vacant(slot) => slot.insert(
                ledger::get(dbs, txn, source, native_id)?
                    .map(|row| row.hashes)
                    .unwrap_or_default(),
            ),
        })
    }
}

/// A vault's import ledger, opened read-only for a dry run.
pub struct HistoryLedgerSnapshot {
    env: Env,
    vault_meta: OverlayDb,
}

impl SideTableDbs for HistoryLedgerSnapshot {
    fn side_vault_meta(&self) -> &OverlayDb {
        &self.vault_meta
    }

    fn side_sync_state_opt(&self) -> Option<&OverlayStrDb> {
        None
    }
}

impl HistoryLedgerSnapshot {
    /// Opens the vault at `vault_dir` read-only.
    ///
    /// # Errors
    ///
    /// The directory holds no LMDB environment, or no side-table database.
    pub fn open(vault_dir: &Path) -> Result<Self> {
        let mut options = EnvOpenOptions::new();
        options.max_dbs(1);
        // SAFETY: `READ_ONLY` asks LMDB for a read-only environment; heed
        // documents no further requirement on the flag itself.
        unsafe {
            options.flags(EnvFlags::READ_ONLY);
        }
        // SAFETY: the environment is read-only, so this handle never writes
        // the vault's data file, and LMDB's lock file registers its readers
        // the way it does for any reader beside a live writer. heed refuses a
        // second open of the same path in this process, and a dry run opens
        // no `Vault`.
        let env = unsafe { options.open(vault_dir) }?;
        let txn = env.read_txn()?;
        let database: Database<Bytes, Bytes> = env
            .open_database(&txn, Some(VAULT_META_DB))?
            .ok_or(Error::CorruptedIndex("vault holds no side-table database"))?;
        txn.commit()?;
        Ok(Self {
            env,
            vault_meta: OverlayDb::canonical(database),
        })
    }

    /// How many messages of `source` the ledger holds.
    ///
    /// # Errors
    ///
    /// A storage error reading the ledger.
    pub fn ledger_len(&self, source: HistorySource) -> Result<usize> {
        let txn = self.env.read_txn()?;
        ledger::count(self, &txn, source)
    }

    /// What importing `conversation` would do. The write door's secret scan
    /// is predicted, over the same bytes the import would stage, when the
    /// vault's switch has it on; a refusal from a policy gate is only seen by
    /// the import itself.
    ///
    /// # Errors
    ///
    /// A storage error reading the ledger.
    pub fn plan(
        &self,
        source: HistorySource,
        conversation: &HistoryConversation,
        dry_run: &mut HistoryDryRun,
    ) -> Result<HistoryImportReport> {
        let txn = self.env.read_txn()?;
        let mut report = HistoryImportReport::new(conversation);
        let scanning = secret_scan_mode_in_txn(self, &txn)? == SecretScanMode::On;
        let runs = runs(conversation, &mut report);
        // The conversation row, and the title in its body, is written by the
        // first turn that lands; until one has, every turn would carry it.
        let mut minted = dry_run.minted.contains(&conversation.native_id);
        if !minted {
            for message in runs.iter().flatten() {
                if ledger::get(self, &txn, source, &message.native_id)?
                    .is_some_and(|row| row.conversation == conversation.native_id)
                {
                    minted = true;
                    break;
                }
            }
        }
        let body_refusal = if scanning {
            let body = conversation_body(source, conversation).map_err(|error| {
                Error::InvalidConfig(format!("imported conversation body: {error}"))
            })?;
            secret_refusal(&body)
        } else {
            None
        };
        for run in runs {
            let mut pending = Vec::new();
            for message in run {
                let hash = content_hash(message);
                let landed = dry_run.landed(self, &txn, source, &message.native_id)?;
                if landed.contains(&hash) {
                    report.skipped += 1;
                } else {
                    pending.push((message, hash, !landed.is_empty()));
                }
            }
            // A changed message's metadata names what it revises, as the
            // import's would.
            let previous: Vec<Option<LedgerRow>> = pending
                .iter()
                .map(|(message, _, changed)| {
                    if *changed {
                        ledger::get(self, &txn, source, &message.native_id)
                    } else {
                        Ok(None)
                    }
                })
                .collect::<Result<_>>()?;
            if pending.is_empty() {
                continue;
            }
            let mut reasons = BTreeSet::new();
            if scanning {
                if !minted && let Some(body) = &body_refusal {
                    reasons.extend(body.iter().cloned());
                }
                for ((message, ..), previous) in pending.iter().zip(&previous) {
                    let staged =
                        imported_message(source, conversation, message, previous.as_ref(), None, 0);
                    let body = witness_message_body(&staged).map_err(|error| {
                        Error::InvalidConfig(format!("imported message body: {error}"))
                    })?;
                    reasons.extend(secret_refusal(&body).unwrap_or_default());
                    reasons.extend(secret_refusal(message.text.as_bytes()).unwrap_or_default());
                }
            }
            if !reasons.is_empty() {
                report.refused += u32::try_from(pending.len()).unwrap_or(u32::MAX);
                report.refusal_reasons.extend(reasons);
                continue;
            }
            minted = true;
            for (message, hash, changed) in pending {
                if changed {
                    report.changed += 1;
                } else {
                    report.new += 1;
                }
                dry_run
                    .landed(self, &txn, source, &message.native_id)?
                    .push(hash);
            }
        }
        if minted {
            dry_run.minted.insert(conversation.native_id.clone());
        }
        Ok(report)
    }
}

/// The write door's secret-scan reasons for `payload`, when it would refuse it.
fn secret_refusal(payload: &[u8]) -> Option<Vec<String>> {
    match scan_write_payload(payload) {
        Ok(()) => None,
        Err(Error::Gate(GateError::GateWriteRejected { reason_codes, .. })) => {
            Some(reason_codes.iter().map(|code| (*code).to_owned()).collect())
        }
        Err(_) => Some(vec!["gate.secret_scan.detected".to_owned()]),
    }
}
